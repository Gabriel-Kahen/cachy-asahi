# SPDX-License-Identifier: MIT
"""Native-only recovery episode, appended after the retained normal episode.

Importing this module performs no operation. The Source-owned image producer
calls prepare(), normal_completed(), episode() and close() in that order.
"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import stat

import security_recovery as recovery
import security_recovery_fs as fs
from security_recovery_state import NAME, NEW, PHASE, PROTOCOL, RecoveryPolicy, classify_recovery
from security_recovery_adapter import NativeCommandAdapter
from security_recovery_metadata import MetadataNormalizer
from security_recovery_journal import Journal
from security_interruption_owner import OwnedProcessRunner

PREFIX = Path('/opt/native-security-v1/recovery')
EVIDENCE = Path('/opt/native-security-v1/recovery-evidence.json')
SCOPE = PREFIX / 'native-scope.json'
CAP = 8 * 1024**2


def need(value, reason):
    if not value:
        raise ValueError(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def content(entry):
    return None if entry is None else {k: v for k, v in entry.items() if k not in ('dev', 'ino', 'nlink')}


def _ordinary(path, maximum):
    path = Path(path)
    need(path == path.resolve(), 'canonical native input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_uid == before.st_gid == 0 and 0 < before.st_size <= maximum,
             'ordinary bounded root-owned native input')
        chunks, left = [], before.st_size + 1
        while left:
            b = os.read(fd, min(left, 65536))
            if not b: break
            chunks.append(b); left -= len(b)
        raw = b''.join(chunks)
        key = lambda x: (x.st_dev, x.st_ino, x.st_mode, x.st_nlink, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
        need(len(raw) == before.st_size and key(before) == key(os.fstat(fd)) == key(path.lstat()),
             'native input stable across descriptor/path read')
        return raw
    finally:
        os.close(fd)


def decode_public_armor(raw):
    """Decode the already Source-verified exported public key, including CRC24."""
    need(type(raw) is bytes and 0 < len(raw) <= 65536, 'bounded public key armor')
    rows = raw.decode('ascii').splitlines()
    need(rows[0] == '-----BEGIN PGP PUBLIC KEY BLOCK-----'
         and rows[-1] == '-----END PGP PUBLIC KEY BLOCK-----', 'public key armor framing')
    split = rows.index('')
    need(all(line.startswith(('Version: ', 'Comment: ')) and len(line) <= 256
             for line in rows[1:split]), 'bounded public armor headers')
    need(len(rows) >= 5 and rows[-2].startswith('=') and len(rows[-2]) == 5, 'public key CRC24')
    body = base64.b64decode(''.join(rows[split + 1:-2]), validate=True)
    crc = 0xB704CE
    for b in body:
        crc ^= b << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000: crc ^= 0x1864CFB
    expected = base64.b64decode(rows[-2][1:], validate=True)
    need((crc & 0xFFFFFF).to_bytes(3, 'big') == expected, 'public key armor checksum')
    return body


def _copy_public_trust(source, target):
    """Copy only public trust DB regular files; no sockets, links or secret keys."""
    target.mkdir(mode=0o700)
    for directory, dirs, files in os.walk(source, followlinks=False):
        parent = Path(directory)
        for name in dirs:
            p = parent / name
            need(not p.is_symlink(), 'trust directory alias')
            (target / p.relative_to(source)).mkdir(mode=0o700)
        for name in files:
            p = parent / name; info = p.lstat()
            if stat.S_ISSOCK(info.st_mode): continue
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                 and 'private-keys-v1.d' not in p.parts, 'public trust files only')
            body = _ordinary(p, 1048576)
            q = target / p.relative_to(source); q.write_bytes(body); q.chmod(0o600)


class RecoveryEpisode:
    def __init__(self, helper, commands, archive, prior, paths, prior_paths, fingerprint, public, trust, map_hash):
        self.helper, self.commands = helper, commands
        self.paths, self.prior_paths = paths, prior_paths
        scope_raw = _ordinary(SCOPE, 16384); scope = json.loads(scope_raw)
        self.binding = dict(scope['binding'])
        need(self.binding['map_sha256'] == map_hash, 'owner-staged same map binding')
        self.root_fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.closed = False; self.finalized = False; self.result = None
        self.policy = RecoveryPolicy(self.binding['source'], self.binding['ref'], self.binding['run'],
                                     tuple(sorted(set(paths) | set(prior_paths))))
        self.policy.validate()
        # Owner staged the sole scope file before Docker build; inputs are added here.
        need(set(p.name for p in PREFIX.iterdir()) == {'native-scope.json'}, 'fresh recovery prefix')
        PREFIX.chmod(0o700)
        for label in ('cache', 'empty-hooks', 'owned'): (PREFIX / label).mkdir(mode=0o700)
        self.runner = OwnedProcessRunner(PREFIX / 'owned')
        _copy_public_trust(Path(trust), PREFIX / 'trust')
        config = ('[options]\n' + ''.join(k + ' = ' + v + '\n' for k, v in recovery.OPTIONS.items())).encode()
        (PREFIX / 'pacman.conf').write_bytes(config); (PREFIX / 'pacman.conf').chmod(0o600)
        binary_public = decode_public_armor(_ordinary(public, 65536))
        (PREFIX / 'test-public.gpg').write_bytes(binary_public); (PREFIX / 'test-public.gpg').chmod(0o600)
        for source in (Path(archive), Path(str(archive) + '.sig'), Path(prior), Path(str(prior) + '.sig')):
            target = PREFIX / source.name; target.write_bytes(_ordinary(source, fs.LEAF_CAP)); target.chmod(0o600)
        self.inputs = recovery.Inputs(*(recovery.Pin(**pin(_ordinary(p, fs.LEAF_CAP))) for p in
            (PREFIX / Path(archive).name, PREFIX / (Path(archive).name + '.sig'), PREFIX / 'pacman.conf', PREFIX / 'test-public.gpg')), fingerprint)
        self.prior_pin = recovery.Pin(**pin(_ordinary(PREFIX / Path(prior).name, fs.LEAF_CAP)))
        self.prior_signature = recovery.Pin(**pin(_ordinary(PREFIX / (Path(prior).name + '.sig'), fs.LEAF_CAP)))
        self.journal = Journal.create(PREFIX / 'journal.jsonl', self.binding)
        self.baseline = self.snapshot()
        self.journal.append('BASELINE_RECORDED', dict(snapshot_sha256=fs.snapshot_sha256(self.baseline)))
        self.adapter = NativeCommandAdapter(self.root_fd, self.binding, recovery.Pin(**pin(scope_raw)), self.inputs, journal=self.journal, runner=self.runner)
        self.reference = self.adapter.capture_reference(self.policy.payload_names, self.baseline)
        self.normalizer = MetadataNormalizer(self.reference['reference'])
        self.normal_episode = None

    def snapshot(self):
        return fs.snapshot(self.root_fd, self.policy.payload_names, owner_uid=0, owner_gid=0)

    def normal_completed(self, observation, inventories, records):
        self.normal_episode = dict(observation=pin(encoded(observation)),
            upgraded=copy.deepcopy(inventories['upgraded']), repeated=copy.deepcopy(inventories['repeated']),
            records=pin(encoded(records)), records_count=len(records))
        self.journal.append('NORMAL_EPISODE_PASSED', self.normal_episode)

    def _owned(self, step, argv, *, seconds=180, output_cap=1048576, env=None, pass_fds=(), cwd=None):
        env = env or dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C')
        cwd = str(cwd or PREFIX)
        self.journal.append('COMMAND_INTENT', dict(step=step, argv=list(argv), seconds=seconds,
            output_cap=output_cap, env=env, cwd=cwd))
        value = self.runner.run(argv, env=env, cwd=cwd,
            pass_fds=pass_fds, seconds=seconds, output_cap=output_cap)
        self.journal.append('COMMAND_COMPLETED', dict(step=step, stdout=pin(value['stdout']),
            stderr=pin(value['stderr']), retirement=value['retirement']))
        need(value['retirement']['exit'] == 0 and value['retirement']['natural_exit'] is True,
             'natural native command completion')
        return value

    def compile(self, policy):
        h = self.helper
        source = policy['source'].encode('ascii'); need(pin(source) == policy['source_pin'], 'blocking C source pin')
        home = PREFIX / 'compiler'; home.mkdir(mode=0o700)
        src, shared, header = home / 'alpm-observer.c', home / 'alpm-observer.so', home / 'alpm-observer-provenance.h'
        src.write_bytes(source); src.chmod(0o600)
        installed_header = Path('/usr/include/alpm.h')
        need(pin(_ordinary(installed_header, 1048576)) == policy['header'], 'retained installed ALPM header')
        compiler = Path('/usr/bin/cc').resolve(); q = policy['provenance']
        need(str(compiler) in q['compiler_paths'], 'fixed compiler path set')
        compiler_raw, compiler_info = h.observer_file(compiler, 16 * 1048576, single=False)
        compiler_id = dict(path=str(compiler), **compiler_info)
        inventory = _ordinary(h.SOURCE / 'native/expected349.lock', 1048576)
        versions = dict(line.decode().split(' ', 1) for line in inventory.splitlines())
        packages = {n: versions[n] for n in q['package_versions']}
        need(packages == q['package_versions'], 'same native349 toolchain')
        env = dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
        argv = list(map(str, ['/usr/bin/cc', '-shared', '-fPIC', '-O2', '-Wall', '-Wextra', '-Werror',
                              '-include', header, '-o', shared, src, '-ldl']))
        recipe = dict(argv=argv, cwd=str(home), env=env)
        manifest = dict(schema=1, protocol=q['protocol'], source=policy['source_pin'], header=policy['header'],
            compiler=compiler_id, toolchain=dict(inventory=pin(inventory), packages=packages), recipe=recipe)
        manifest_raw = encoded(manifest); need(len(manifest_raw) <= q['manifest_cap'], 'manifest cap')
        header_raw = h.observer_header(manifest_raw); header.write_bytes(header_raw); header.chmod(0o600)
        value = self._owned('recovery-compile-observer', argv, env=env, cwd=home, seconds=180)
        r = value['retirement']; names = ('pid', 'exit', 'natural_exit', 'group_absent',
            'leader_held_until_group_inspection', 'exit_observed_via_waitpid', 'ownership_lost', 'retirement',
            'forced_cleanup', 'cleanup_member_uids', 'elapsed_seconds')
        legacy = {n: r[n] for n in names}
        shared.chmod(0o500); obj_fd = os.open(shared, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        raw, before = h.observer_file(shared, q['object_cap'], 0o500, descriptor=obj_fd)
        after_compiler, after_stat = h.observer_file(compiler, 16 * 1048576, single=False)
        need(compiler_raw == after_compiler and compiler_info == after_stat, 'compiler unchanged')
        need(_ordinary(src, 16384) == source and _ordinary(header, 131072) == header_raw
             and pin(_ordinary(installed_header, 1048576)) == policy['header'], 'compile inputs unchanged')
        provenance = dict(schema=1, protocol=q['protocol'], scope=q['scope'], manifest=manifest,
            manifest_pin=pin(manifest_raw), generated_header=pin(header_raw), object_base64=base64.b64encode(raw).decode(),
            object=pin(raw), before=before, after=before, compiler_retirement=legacy,
            compile_record=dict(step='compile-upgrade-observer', exit=0, stdout=pin(value['stdout']), stderr=pin(value['stderr']), recipe=recipe),
            inputs_after=dict(source=policy['source_pin'], header=policy['header'], compiler=compiler_id),
            source_binary_semantics='NOT_CLAIMED', upstream_source_binary_correspondence='OPEN')
        return shared, obj_fd, provenance, r

    def episode(self, blocking_policy):
        need(self.normal_episode is not None, 'normal signed episode completed first')
        self.adapter.remove_candidate(self.baseline, self.policy.payload_names)
        need(self.snapshot() == self.baseline, 'second removal restores exact baseline')
        self.journal.append('RECOVERY_BASELINE_RESTORED', dict(snapshot_sha256=fs.snapshot_sha256(self.baseline)))
        self.adapter.install_prior(self.prior_pin, self.prior_signature)
        self.journal.append('PRIOR_INSTALLED', dict(snapshot_sha256=fs.snapshot_sha256(self.snapshot())))
        runtime = {}
        for label, path in (('pacman', Path('/usr/bin/pacman')), ('libalpm', Path('/usr/lib/libalpm.so.16.0.1'))):
            raw = _ordinary(path, 16 * 1048576); info = path.stat()
            runtime[label] = dict(pin(raw), inode=[info.st_dev, info.st_ino])
        need(runtime['libalpm']['sha256'] == blocking_policy['libalpm_sha256'], 'retained ALPM binary for interruption')
        shared, object_fd, provenance, compiler_retirement = self.compile(blocking_policy)
        record = PREFIX / 'checkpoint.jsonl'
        fd = os.open(record, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        nonce = secrets.token_hex(16)
        env = dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1',
            LD_PRELOAD=str(shared), CACHY_SECURITY_OBSERVER_FD=str(fd),
            CACHY_SECURITY_OBSERVER_OWNER=str(os.getpid()), CACHY_SECURITY_OBSERVER_OBJECT_FD=str(object_fd))
        argv = ['/usr/bin/pacman', '--config', '/' + recovery.CONFIG, '--noconfirm', '--noscriptlet', '-U', '/' + recovery.ARCHIVE]
        verified = {}
        def checkpoint(raw, identity):
            rows = [json.loads(line) for line in raw.splitlines()]
            need(len(rows) == 1 and rows[0]['type'] == 'FIRST_UPGRADE_ZERO', 'one genuine interrupted checkpoint; no END fiction')
            point = rows[0]
            need(point['pid'] == identity['pid'] and point['ppid'] == identity['ppid'] == os.getpid(), 'original owned pacman identity')
            snap = self.snapshot()
            need(NEW in snap['db'] and snap['lock'] is not None, 'prepared DB and stale lock captured while blocked')
            cp = dict(type='FIRST_UPGRADE_ZERO', phase=PHASE, package=NAME, pid=identity['pid'], ppid=identity['ppid'],
                starttime=identity['starttime'], event=point['event'], percent=point['percent'], howmany=point['howmany'],
                current=point['current'], prepared_directory=snap['db'][NEW], lock=snap['lock'])
            need(point['lock']['dev'] == snap['lock']['dev'] and point['lock']['ino'] == snap['lock']['ino'], 'callback and snapshot lock inode join')
            observation = dict(observer_source=blocking_policy['source_pin'], observer_compiled=provenance['object'],
                               compiler_retirement=provenance['compiler_retirement'], records=rows, runtime=runtime)
            need(point['pacman_inode'] == runtime['pacman']['inode']
                 and point['libalpm_inode'] == runtime['libalpm']['inode'], 'callback joins actual runtime binaries')
            from security_reader_v1 import validate_recovery_observer_provenance
            validate_recovery_observer_provenance(provenance, observation, blocking_policy,
                _ordinary(self.helper.SOURCE / 'native/expected349.lock', 1048576), [provenance['compile_record']])
            verified.update(snapshot=snap, checkpoint=cp, observation=observation, raw_ascii=raw.decode('ascii'))
            self.journal.append('CHECKPOINT_VERIFIED', dict(snapshot_sha256=fs.snapshot_sha256(snap), checkpoint=cp,
                observation_sha256=pin(encoded(observation))['sha256']))
            return dict(snapshot_sha256=fs.snapshot_sha256(snap), checkpoint=cp)
        self.journal.append('INTERRUPT_INTENT', dict(argv=argv, nonce_sha256=pin(nonce.encode())['sha256']))
        try:
            interrupted = self.runner.interrupt(argv, env=env, cwd=str(PREFIX), record_fd=fd,
                nonce=nonce, verify_checkpoint=checkpoint, seconds=30, output_cap=1048576, pass_fds=(object_fd,))
            actual_raw, actual_after = self.helper.observer_file(shared, blocking_policy['provenance']['object_cap'],
                                                               0o500, descriptor=object_fd)
            need(pin(actual_raw) == provenance['object'] and actual_after == provenance['before'],
                 'compiled blocking object held unchanged through interruption')
            provenance['after'] = actual_after
        finally:
            os.close(fd); os.close(object_fd)
        r = interrupted['retirement']
        retirement = {k: r[k] for k in ('pid', 'starttime', 'method', 'signal', 'reaped', 'group_absent',
            'descendants_absent', 'pid_reserved_until_retirement', 'checkpoint_blocked_until_interrupt')}
        for label, path in (('pacman', Path('/usr/bin/pacman')), ('libalpm', Path('/usr/lib/libalpm.so.16.0.1'))):
            raw = _ordinary(path, 16 * 1048576); info = path.stat()
            need(dict(pin(raw), inode=[info.st_dev, info.st_ino]) == runtime[label], 'runtime binary unchanged through interruption')
        evidence = dict(protocol=PROTOCOL, binding=self.policy.binding(), baseline_sha256=fs.snapshot_sha256(self.baseline),
                        checkpoint=verified['checkpoint'], retirement=retirement)
        classify_recovery(self.baseline, verified['snapshot'], self.policy, evidence)
        interrupt_receipt=dict(retirement=r,channel=interrupted['checkpoint_channel'],verified=interrupted['verified'],stdout=pin(interrupted['stdout']),stderr=pin(interrupted['stderr']))
        self.journal.append('INTERRUPTED_RETIRED', dict(retirement=r, evidence_sha256=pin(encoded(evidence))['sha256'],receipt=pin(encoded(interrupt_receipt))))
        result = recovery.recover(self.root_fd, self.baseline, self.policy, evidence, self.inputs,
            self.reference['candidate_db'], self.reference['candidate_payload'], self.adapter,
            metadata_normalizer=self.normalizer, journal=self.journal)
        self.journal.append('FINALIZED', dict(snapshot_sha256=result['snapshot_sha256']))
        self.journal.close()
        reference = self.reference['reference']
        actual_db = {n: base64.b64encode(fs.read_regular(self.root_fd, 'var/lib/pacman/local/' + n)[0]).decode()
                     for n in reference.raw_files}
        self.result = dict(schema=1, protocol=PROTOCOL, binding=self.binding, baseline=self.baseline,
            interrupted=verified['snapshot'], evidence=evidence, interrupt_receipt=interrupt_receipt, observation=verified['observation'],
            raw_ascii=verified['raw_ascii'], observer_provenance=provenance, compiler_owned_retirement=compiler_retirement,
            reference=dict(snapshot=self.reference['snapshot'], candidate_db=self.reference['candidate_db'],
                candidate_payload=self.reference['candidate_payload'], install_window=reference.install_window,
                metadata=reference.record()),
            actual_db_raw=actual_db, result=result, normal_episode=self.normal_episode,
            command_records=self.adapter.records, journal_ascii=_ordinary(PREFIX / 'journal.jsonl', 1048576).decode('ascii'),
            scope=json.loads(_ordinary(SCOPE, 16384)), upstream_source_binary_correspondence='OPEN',
            physical_M2='NOT_RUN', release='NOT_ADMITTED')
        self.finalized = True
        return self.result

    def close(self):
        if self.closed: return
        self.journal.close()
        try:
            need(not any(p.is_symlink() or stat.S_ISSOCK(p.lstat().st_mode) for p in PREFIX.rglob('*')),
                 'no aliased recovery paths or live GPG sockets')
            info = PREFIX.lstat(); need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0, 'owned recovery prefix')
            before = dict(dev=info.st_dev, ino=info.st_ino, mode=stat.S_IMODE(info.st_mode), uid=info.st_uid, gid=info.st_gid)
            shutil.rmtree(PREFIX)
            need(not os.path.lexists(PREFIX), 'recovery prefix absent')
            cleanup = dict(path=str(PREFIX), before=before, removed=True, absence_errno=2, no_live_sockets=True)
            if self.finalized:
                self.result['private_cleanup'] = cleanup
                raw = encoded(self.result); need(len(raw) <= CAP, 'bounded recovery sidecar under inherited aggregate caps')
                with EVIDENCE.open('xb') as stream: stream.write(raw)
                EVIDENCE.chmod(0o644)
        finally:
            os.close(self.root_fd); self.closed = True


def prepare(*args, **kwargs):
    obj = RecoveryEpisode.__new__(RecoveryEpisode)
    try:
        RecoveryEpisode.__init__(obj, *args, **kwargs)
        return obj
    except BaseException:
        if hasattr(obj, 'journal'): obj.journal.close()
        if hasattr(obj, 'root_fd'): os.close(obj.root_fd)
        raise  # Partial private state/journal refuses reentry; never retry.
