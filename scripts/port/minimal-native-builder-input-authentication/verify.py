#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Explicitly Root-selected offline minimal206 public-input verification only."""
import argparse
import base64
import datetime
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = ROOT / 'scripts/port/minimal-native-builder-inputs'
BUILDER = dict(bytes=1189335, sha256='c5c9f4450575b6c66f7991c48f9bb227e78ea1e605f57df0a46778ba9d4d6f65')
SOURCE_LOCK = dict(bytes=2377, sha256='6fac7419f32e2c370840dc9ee587b0cdf9d265f2dc9b57ff38bb945a468d090f')
ENGINES = {
    'scripts/virtual/owned_process.py': dict(bytes=25140, sha256='83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f'),
    'scripts/ci/native_arm.py': dict(bytes=28877, sha256='8e71ba83e7d5037c6f7772401ec3b872684ccfa8472d855d8d6d3052cb1f41ba'),
    'scripts/checks/package_checks.py': dict(bytes=19289, sha256='314e8b4a0920b3f6d93619fc74ad1d63a6210d1b17b925618451b493d2610a1a'),
}
SIGNER = '68B3537F39A313B3E574D06777193F152BDBE6A6'
SUBKEY = 'EA5AE14634B0DA39F927DC9EA517E8E924321745'
UID = 'Arch Linux ARM Build System <builder@archlinuxarm.org>'
BINARY_KEY = dict(bytes=2228, sha256='9403f923eed777ba0896a0b225e1522d3a7625234694c753ae26b27c29672aae')
TOTAL_BYTES = 1473694724
RUN_CAP = 900
ACTOR_CAP = 60
OUTPUT_CAP = 128 * 1024


def need(ok, why):
    if not ok:
        raise ValueError(why)


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def decode(raw):
    def pairs(rows):
        value = {}
        for key, row in rows:
            need(key not in value, 'duplicate JSON field refuses')
            value[key] = row
        return value
    def constant(value):
        raise ValueError('nonfinite JSON constant refuses')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def identity(s):
    return tuple(getattr(s, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def ordinary(path):
    path = Path(path)
    need(path.is_absolute() and path == path.resolve() and not any(p.is_symlink() for p in (path, *path.parents)), 'absolute canonical nonaliased path')
    return path


class Held:
    """Whole-pin an ordinary leaf, retain its FD and recheck stable identity."""
    def __init__(self, path, expected, *, limit=2 * 1024**3, executable=False, deadline=None):
        self.path = ordinary(path)
        need(type(expected) is dict and set(expected) >= {'bytes', 'sha256'} and type(expected['bytes']) is int
             and 0 <= expected['bytes'] <= limit and re.fullmatch('[0-9a-f]{64}', expected['sha256'] or ''), 'finite whole pin')
        self.expected = {k: expected[k] for k in ('bytes', 'sha256')}
        self.fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            self.before = os.fstat(self.fd)
            need(stat.S_ISREG(self.before.st_mode) and self.before.st_nlink == 1 and self.before.st_size == expected['bytes'], 'exact ordinary single-link leaf')
            need('mode' not in expected or stat.S_IMODE(self.before.st_mode) == expected['mode'], 'exact source mode')
            if executable:
                need(stat.S_IMODE(self.before.st_mode) & 0o111 and not self.before.st_mode & 0o022, 'non-group/world-writable executable')
            self.digest(deadline)
        except BaseException:
            self.close()
            raise

    def stable(self):
        ordinary(self.path)
        need(identity(self.before) == identity(os.fstat(self.fd)) == identity(self.path.lstat()), 'retained whole input identity changed')

    def digest(self, deadline=None):
        self.stable()
        os.lseek(self.fd, 0, os.SEEK_SET)
        h = hashlib.sha256(); total = 0
        while block := os.read(self.fd, 1024**2):
            need(deadline is None or time.monotonic() < deadline, 'whole verification deadline')
            total += len(block)
            need(total <= self.expected['bytes'], 'whole read extent')
            h.update(block)
        need(dict(bytes=total, sha256=h.hexdigest()) == self.expected, 'whole operand size/SHA256 mismatch: ' + self.path.name)
        self.stable()
        os.lseek(self.fd, 0, os.SEEK_SET)

    def raw(self):
        need(self.expected['bytes'] <= 4 * 1024**2, 'small DATA read only')
        self.stable(); os.lseek(self.fd, 0, os.SEEK_SET)
        raw = os.read(self.fd, self.expected['bytes'] + 1)
        need(pin(raw) == self.expected, 'whole small DATA pin')
        self.stable(); os.lseek(self.fd, 0, os.SEEK_SET)
        return raw

    def close(self):
        if self.fd is not None:
            os.close(self.fd); self.fd = None


def read_pinned(path, expected, limit=4 * 1024**2):
    leaf = Held(path, expected, limit=limit)
    try:
        return leaf.raw()
    finally:
        leaf.close()


def module(path, expected, name):
    raw = read_pinned(path, expected)
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    return value


def inputs(d):
    need(d['kind'] == 'SEPARATE_MINIMAL_NATIVE_LIBRARY_BUILDER_INPUTS_V1' and d['metadata_graph_status'] == 'PASS'
         and not d['graph_blockers'] and not d['rootfs_reconciliation']['missing'] and d['signer_fingerprint'] == SIGNER, 'fixed complete builder graph')
    rows = {}; signed = []
    def add(name, size, sha):
        need(type(name) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._+:-]*', name) and name not in rows, 'unique literal operand filename')
        rows[name] = dict(bytes=size, sha256=sha)
    for row in d['packages']:
        a = row['archive']; add(a['filename'], a['bytes'], a['sha256'])
        sig = base64.b64decode(a['signature_b64'], validate=True)
        need(pin(sig) == dict(bytes=a['signature_bytes'], sha256=a['signature_sha256']), 'whole catalog signature payload')
        add(a['filename'] + '.sig', a['signature_bytes'], a['signature_sha256']); signed.append(a['filename'])
    for row in [d['rootfs'], *d['keyring_files'], *d['upstream_sources']]:
        add(row['filename'], row['size'], row['sha256'])
    for row in d['catalogs']:
        add(row['repo'] + '.db', row['bytes'], row['sha256'])
    r = d['rootfs']; add(r['filename'] + '.sig', r['signature_size'], r['signature_sha256']); signed.append(r['filename'])
    need(len(d['packages']) == 206 and len(rows) == 422 and len(set(signed)) == 207
         and sum(row['bytes'] for row in rows.values()) == TOTAL_BYTES, 'complete exact422/207 finite operand set')
    return rows, signed


def namespace(cache, expected):
    ordinary(cache); seen = set()
    for count, path in enumerate(cache.iterdir(), 1):
        need(count <= 422 and path.name in expected, 'missing/extra/partial input namespace refuses')
        seen.add(path.name)
    need(seen == set(expected), 'complete422 input namespace required')


def public_key(raw, trusted, revoked):
    need(trusted == (SIGNER + ':4:\n').encode() and revoked == b'', 'exact official trust/revoked fingerprint files')
    lines = raw.splitlines()
    need(len(raw) == 3098 and len(lines) == 51 and lines[0] == b'-----BEGIN PGP PUBLIC KEY BLOCK-----'
         and lines[1] == b'' and lines[-1] == b'-----END PGP PUBLIC KEY BLOCK-----' and lines[-2] == b'=AIgD', 'fixed public armor only')
    body = base64.b64decode(b''.join(lines[2:-2]), validate=True)
    crc = 0xB704CE
    for byte in body:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    need((crc & 0xFFFFFF).to_bytes(3, 'big') == base64.b64decode(lines[-2][1:], validate=True)
         and pin(body) == BINARY_KEY, 'exact independently pinned public binary keyring/CRC')
    return body


def key_status(text, now):
    need(type(text) is str and len(text.encode()) <= OUTPUT_CAP, 'bounded colon key status')
    rows = [line.split(':') for line in text.splitlines()]
    need([r[0] for r in rows] == ['pub', 'fpr', 'uid', 'sub', 'fpr'], 'one public primary/UID/subkey, no secret/unknown/extra identities')
    pub, primary, uid, sub, secondary = rows
    for row, fingerprint in ((pub, SIGNER), (sub, SUBKEY)):
        need(len(row) >= 13 and row[1] in ('-', 'q', 'f', 'u') and row[2:5] == ['4096', '1', fingerprint[-16:]]
             and row[5].isdigit() and int(row[5]) == 1390085363 <= now and (row[6] == '' or row[6].isdigit() and int(row[6]) > now)
             and 'D' not in row[11], 'usable exact current public key, no revoked/expired/disabled/unknown identity')
    need(len(primary) >= 10 and primary[9] == SIGNER and len(secondary) >= 10 and secondary[9] == SUBKEY, 'exact primary/subkey fingerprints')
    need(len(uid) >= 10 and uid[1] in ('-', 'q', 'f', 'u') and uid[9] == UID, 'exact usable official UID')
    need('s' in pub[11] and 'e' in sub[11] and 's' not in sub[11], 'primary signing anchor and encryption-only subkey')


def signature_algorithms(raw):
    """One bounded original V4 binary RSA signature packet; no packet interpreter."""
    need(4 <= len(raw) <= 4096 and raw[0] & 0x80, 'bounded signature packet')
    if raw[0] & 0x40:
        need(raw[0] & 0x3F == 2, 'only detached signature packet')
        first = raw[1]
        if first < 192:
            size, head = first, 2
        elif first < 224:
            size, head = ((first - 192) << 8) + raw[2] + 192, 3
        else:
            need(first == 255 and len(raw) >= 6, 'no partial signature packet lengths')
            size, head = int.from_bytes(raw[2:6], 'big'), 6
    else:
        need((raw[0] >> 2) & 15 == 2 and raw[0] & 3 != 3, 'one finite old-format signature packet')
        width = 1 << (raw[0] & 3); head = 1 + width
        need(len(raw) >= head, 'complete signature packet header')
        size = int.from_bytes(raw[1:head], 'big')
    body = raw[head:]
    need(len(body) == size and len(body) >= 6 and body[:3] == bytes([4, 0, 1]) and body[3] in (8, 10), 'one complete V4 binary RSA SHA256/SHA512 signature')
    return '1', str(body[3])


def signature_status(text, now, native, algorithms):
    need(type(text) is str and len(text.encode()) <= OUTPUT_CAP, 'bounded verifier machine stdout')
    rows = []
    for line in text.splitlines():
        need(line.startswith('[GNUPG:] ') and len(line) <= 4096 and '\x00' not in line, 'only framed machine status stdout')
        row = line.split()[1:]
        need(row and row[0] in {'NEWSIG', 'KEY_CONSIDERED', 'SIG_ID', 'GOODSIG', 'VALIDSIG'}, 'unknown/error/expired/revoked status refuses')
        rows.append(row)
    need(len(rows) <= 16 and all(sum(r[0] == name for r in rows) == 1 for name in ('NEWSIG', 'SIG_ID', 'GOODSIG', 'VALIDSIG')), 'one complete original signature only')
    for row in rows:
        if row[0] == 'KEY_CONSIDERED':
            need(row == ['KEY_CONSIDERED', SIGNER, '0'], 'only exact usable key considered')
    good = next(r for r in rows if r[0] == 'GOODSIG')
    need(good[1:] == [SIGNER[-16:], *UID.split()], 'exact GOODSIG signer')
    native.valid_signature(text, SIGNER)
    row = next(r for r in rows if r[0] == 'VALIDSIG')
    need(row[3].isdigit() and row[4].isdigit() and 0 < int(row[3]) <= now
         and (int(row[4]) == 0 or int(row[4]) > now) and row[5:10] == ['4', '0', *algorithms, '00'], 'current binary signature matches exact original packet algorithms')
    need(row[2] == datetime.datetime.fromtimestamp(int(row[3]), datetime.timezone.utc).strftime('%Y-%m-%d'), 'coherent signature date')
    need(next(r for r in rows if r[0] == 'NEWSIG') == ['NEWSIG'], 'bare original signature boundary')
    sigid = next(r for r in rows if r[0] == 'SIG_ID')
    need(len(sigid) == 4 and re.fullmatch('[A-Za-z0-9+/=]{20,64}', sigid[1]) and sigid[2:] == [row[2], row[3]], 'coherent signature ID/date/time')


def natural(row):
    need(row['passed'] is True and row['reaped'] is True and row['ownership'] == 'REAPED'
         and type(row['exit']) is int and row['exit'] == 0 and row['timeout'] is False and row['signals'] == []
         and row['error'] is None and row['output_complete'] is True and row['group_census'] == 'EMPTY_TWICE'
         and type(row['seconds']) in (int, float) and math.isfinite(row['seconds']) and 0 <= row['seconds'] < ACTOR_CAP, 'natural verifier retirement and complete original-group census required')


def validate_selection(s, now):
    need(type(s) is dict and set(s) == {'schema', 'issuer', 'status', 'accepted', 'entry', 'builder_lock', 'cache', 'output', 'tools', 'trust_review'}, 'closed Root verification selection schema')
    need(type(s['schema']) is int and s['schema'] == 1 and s['issuer'] == 'Root' and s['status'] == 'ROOT_SELECTED_MINIMAL206_PUBLIC_INPUT_VERIFICATION_ONLY'
         and s['accepted'] is True, 'Root exact verification selection UNISSUED')
    need(type(s['entry']) is dict and set(s['entry']) == {'path', 'bytes', 'sha256'} and s['entry']['path'] == str(HERE / 'verify.py'), 'exact selected entry')
    read_pinned(s['entry']['path'], s['entry'])
    need(s['builder_lock'] == dict(path=str(SOURCE / 'builder.lock.json'), **BUILDER), 'exact e947 builder lock selection')
    need(type(s['tools']) is dict and set(s['tools']) == {'gpg', 'gpgv'}, 'exact two public verification tools')
    for tool in s['tools'].values():
        need(type(tool) is dict and set(tool) == {'path', 'bytes', 'sha256'}, 'whole selected verifier pin')
    review = s['trust_review']
    need(type(review) is dict and set(review) == {'current_official_trust_reviewed', 'reviewed_at_unix', 'valid_until_unix', 'evidence'}, 'closed current Root official trust review')
    need(review['current_official_trust_reviewed'] is True and type(review['reviewed_at_unix']) is int and type(review['valid_until_unix']) is int
         and review['reviewed_at_unix'] <= now < review['valid_until_unix'] <= review['reviewed_at_unix'] + 86400, 'fresh bounded external current official trust review required')
    proof = review['evidence']
    need(type(proof) is dict and set(proof) == {'path', 'bytes', 'sha256'} and type(proof['bytes']) is int and 0 < proof['bytes'] <= 65536, 'whole external public trust evidence')
    read_pinned(proof['path'], proof, 65536)
    cache, output = ordinary(s['cache']), ordinary(s['output'])
    need(cache.is_dir() and cache.stat().st_uid == os.getuid() and stat.S_IMODE(cache.stat().st_mode) == 0o700, 'owned exact700 operand directory')
    need(not output.exists() and output != cache and cache not in output.parents and output not in cache.parents
         and ROOT not in output.parents, 'fresh external output outside source and operand directories')
    parent = output.parent
    need(parent.is_dir() and parent.stat().st_uid == os.getuid() and not parent.stat().st_mode & 0o022, 'owned non-group/world-writable output parent')
    return cache, output


class ActorFence:
    def __init__(self):
        self.command = None

    def __call__(self, event, args):
        if event == 'subprocess.Popen':
            need(self.command is not None and (args[0], args[1], args[2], args[3]) == self.command, 'unselected actor refuses')
            self.command = None
        elif event.startswith(('socket.', 'ctypes.', 'os.exec', 'os.spawn', 'os.fork', 'os.posix_spawn')) or event == 'os.system':
            raise ValueError('no network, FFI or unselected process entry')


def child_limits():
    os.umask(0o077)
    for kind, limit in ((resource.RLIMIT_AS, 512 * 1024**2), (resource.RLIMIT_CPU, 45),
                        (resource.RLIMIT_FSIZE, OUTPUT_CAP), (resource.RLIMIT_NOFILE, 512), (resource.RLIMIT_CORE, 0)):
        resource.setrlimit(kind, (limit, limit))


def verify(selection_path, selection_pin, *, execute=False):
    if not execute:
        return dict(status='HOLD_ROOT_VERIFICATION_SELECTION_UNISSUED', actors=[], native=None, Root_native_authority=None), 2
    started = time.monotonic(); deadline = started + RUN_CAP
    s = decode(read_pinned(selection_path, selection_pin, 65536))
    cache, output = validate_selection(s, int(time.time()))
    # Parent bounds include the422 retained descriptors and finite DATA reports.
    for kind, limit in ((resource.RLIMIT_AS, 1024**3), (resource.RLIMIT_CPU, RUN_CAP),
                        (resource.RLIMIT_FSIZE, 4 * 1024**2), (resource.RLIMIT_NOFILE, 512), (resource.RLIMIT_CORE, 0)):
        current, hard = resource.getrlimit(kind)
        bounded = min(limit, hard) if hard != resource.RLIM_INFINITY else limit
        resource.setrlimit(kind, (bounded, bounded))
    fence = ActorFence(); sys.addaudithook(fence)
    source_lock = json.loads(read_pinned(SOURCE / 'source.lock.json', SOURCE_LOCK))
    need({p.relative_to(SOURCE).as_posix() for p in SOURCE.rglob('*') if p.is_file() or p.is_symlink()} == set(source_lock['files']) | {'source.lock.json'}, 'closed unchanged author family')
    for name, row in source_lock['files'].items():
        read_pinned(SOURCE / name, row)
    d = json.loads(read_pinned(SOURCE / 'builder.lock.json', BUILDER))
    expected, signed = inputs(d)
    for name, row in ENGINES.items():
        read_pinned(ROOT / name, row)
    owned = module(ROOT / 'scripts/virtual/owned_process.py', ENGINES['scripts/virtual/owned_process.py'], 'minimal206_owned_verifier')
    need('package_checks' not in sys.modules, 'fresh isolated maintained dependency namespace')
    sys.modules['package_checks'] = module(ROOT / 'scripts/checks/package_checks.py', ENGINES['scripts/checks/package_checks.py'], 'package_checks')
    native = module(ROOT / 'scripts/ci/native_arm.py', ENGINES['scripts/ci/native_arm.py'], 'minimal206_signature_parser')
    namespace(cache, expected)
    held = {}; tools = {}; binary = None; persist = None
    report = dict(status='FAIL_OR_INCOMPLETE_PUBLIC_VERIFICATION', builder_lock=BUILDER, signer_fingerprint=SIGNER,
                  verification_selection=dict(path=str(selection_path), **selection_pin), materials={}, actors=[], signatures=None,
                  all_verifiers_naturally_retired=False, Root_adoption=None, Root_native_authority=None, native=None, M2=None, old349_admission=None)
    try:
        # No output or actor before the complete422 whole-byte preflight.
        for name, row in sorted(expected.items()):
            held[name] = Held(cache / name, row, deadline=deadline)
            report['materials'][name] = row
        for name, row in s['tools'].items():
            tools[name] = Held(row['path'], row, limit=16 * 1024**2, executable=True, deadline=deadline)
        key = public_key(held['archlinuxarm.gpg'].raw(), held['archlinuxarm-trusted'].raw(), held['archlinuxarm-revoked'].raw())
        algorithms = {name: signature_algorithms(held[name + '.sig'].raw()) for name in signed}
        output.mkdir(mode=0o700); (output / 'logs').mkdir(mode=0o700); home = output / 'public-state'; home.mkdir(mode=0o700)
        def persist():
            report['elapsed_seconds'] = time.monotonic() - started
            path = output / 'verification.DATA.json'
            temp = output / 'verification.DATA.json.partial'
            with temp.open('xb') as stream:
                stream.write(encoded(report))
            temp.replace(path)
        persist()
        path = output / 'public-keyring.gpg'
        with path.open('xb') as stream:
            stream.write(key)
        binary = Held(path, BINARY_KEY, limit=4096)
        environment = dict(HOME=str(home), GNUPGHOME=str(home), PATH='/nonexistent', LC_ALL='C', LANG='C', TZ='UTC')
        def actor(tool, arguments, leaves, label):
            need(time.monotonic() + ACTOR_CAP < deadline and int(time.time()) < s['trust_review']['valid_until_unix'], 'finite whole run/current trust window')
            namespace(cache, expected)
            for leaf in [*held.values(), *tools.values(), binary]:
                leaf.stable()
            exe = tools[tool]; executable = '/proc/self/fd/' + str(exe.fd)
            argv = [s['tools'][tool]['path'], *arguments]
            cwd = str(home); fds = tuple(sorted({exe.fd, *(leaf.fd for leaf in leaves)}))
            record = dict(label=label, tool=s['tools'][tool], argv=argv, retirement=None)
            report['actors'].append(record); persist()
            errpath = output / 'logs' / (str(len(report['actors'])).zfill(3) + '.stderr')
            record['stderr'] = dict(path=str(errpath), bytes=None, sha256=None)
            owned.prepare()
            with errpath.open('xb') as errors:
                fence.command = (executable, argv, cwd, environment)
                try:
                    child = subprocess.Popen(argv, executable=executable, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                             stdout=subprocess.PIPE, stderr=errors, close_fds=True, pass_fds=fds,
                                             start_new_session=True, preexec_fn=child_limits)
                    pid = child.pid
                finally:
                    fence.command = None
                result = owned.supervise(child, cap=ACTOR_CAP, retirement=2, grace=.2, group=True, max_output=OUTPUT_CAP)
            raw = result.pop('output'); record['pid'] = pid; record['retirement'] = result; record['stdout'] = pin(raw)
            size = errpath.stat().st_size
            record['stderr'].update(bytes=size)
            if size <= OUTPUT_CAP:
                record['stderr'].update(pin(errpath.read_bytes()))
            record['status_stdout_b64'] = base64.b64encode(raw).decode(); persist()
            natural(result)
            need(errpath.stat().st_size <= OUTPUT_CAP and not any(home.iterdir()), 'bounded diagnostics and public-only empty state; no agent/keybox/trustdb artifacts')
            for leaf in [*held.values(), *tools.values(), binary]:
                leaf.stable()
            namespace(cache, expected)
            persist()
            return raw.decode('utf-8', errors='strict'), result
        common = ['--no-options', '--batch', '--no-tty', '--no-autostart', '--disable-dirmngr', '--homedir', str(home),
                  '--no-default-keyring', '--keyring', '/proc/self/fd/' + str(binary.fd), '--no-auto-check-trustdb',
                  '--no-auto-key-retrieve', '--no-auto-key-import', '--with-colons', '--fixed-list-mode',
                  '--with-fingerprint', '--with-subkey-fingerprint', '--list-options', 'show-unusable-uids,show-unusable-subkeys', '--show-keys']
        text, _ = actor('gpg', [*common, '/proc/self/fd/' + str(binary.fd)], [binary], 'public-key-current-status')
        key_status(text, int(time.time()))
        records = {}
        for name in signed:
            payload, signature = held[name], held[name + '.sig']
            text, retired = actor('gpgv', ['--homedir', str(home), '--keyring', '/proc/self/fd/' + str(binary.fd), '--status-fd', '1',
                                         '/proc/self/fd/' + str(signature.fd), '/proc/self/fd/' + str(payload.fd)], [binary, signature, payload], name)
            signature_status(text, int(time.time()), native, algorithms[name])
            records[name] = dict(exit_code=retired['exit'], status=text, retirement=retired, input=expected[name], signature=expected[name + '.sig'], algorithms=algorithms[name])
        need(len(records) == 207 and set(records) == set(signed) and len(report['actors']) == 208, 'complete207 transcript and208 actual verifier retirements')
        namespace(cache, expected)
        for leaf in [*held.values(), *tools.values(), binary]:
            leaf.digest(deadline)
        need(int(time.time()) < s['trust_review']['valid_until_unix'], 'current trust window remains valid')
        transcript = output / 'signatures.DATA.json'
        raw = encoded(records); need(len(raw) <= 4 * 1024**2, 'source-worker207 transcript budget')
        proof = dict(path=str(transcript), **pin(raw))
        candidate = json.loads(read_pinned(SOURCE / 'Root-authentication.TEMPLATE.json', source_lock['files']['Root-authentication.TEMPLATE.json']))
        candidate['signatures'] = proof; candidate['all_verifiers_naturally_retired'] = True
        pending_transcript = output / 'signatures.DATA.json.partial'
        with pending_transcript.open('xb') as stream:
            stream.write(raw)
        pending_candidate = output / 'Root-authentication.UNISSUED.json.partial'
        with pending_candidate.open('xb') as stream:
            stream.write(encoded(candidate))
        report.update(status='PASS_PUBLIC_INPUT_CRYPTOGRAPHIC_DATA_ROOT_ADOPTION_UNISSUED', signatures=proof,
                      all_verifiers_naturally_retired=True, whole422_verified_before_and_after=True,
                      current_official_trust_review=s['trust_review'], keyring=BINARY_KEY, actor_census_scope='original groups EMPTY_TWICE, not a global daemon census')
        persist()
        pending_candidate.rename(output / 'Root-authentication.UNISSUED.json')
        # Publish the adoption-consumable transcript last. Partial attempts retain
        # evidence but cannot supply the required final transcript path.
        pending_transcript.rename(transcript)
        return report, 0
    except BaseException as exc:
        report.update(status='FAIL_OR_INCOMPLETE_PUBLIC_VERIFICATION', signatures=None,
                      failure=dict(type=type(exc).__name__, reason=str(exc)[:500]))
        if persist is not None:
            persist()
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        return report, 2
    finally:
        for leaf in [*held.values(), *tools.values(), *([binary] if binary else [])]:
            leaf.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--execute-public-verification', action='store_true')
    p.add_argument('--selection', type=Path)
    p.add_argument('--selection-sha256')
    a = p.parse_args()
    need(__debug__ and sys.flags.isolated and sys.dont_write_bytecode, 'unoptimized Python -I -B required')
    if not a.execute_public_verification:
        result, code = verify(None, None)
    else:
        try:
            need(a.selection is not None and re.fullmatch('[0-9a-f]{64}', a.selection_sha256 or ''), 'external exact Root selection required')
            path = ordinary(a.selection); size = path.stat().st_size
            result, code = verify(path, dict(bytes=size, sha256=a.selection_sha256), execute=True)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            result, code = dict(status='HOLD_PUBLIC_VERIFICATION_PREFLIGHT', reason=str(exc)[:500],
                                Root_native_authority=None, native=None, M2=None, old349_admission=None), 2
    print(json.dumps({k: v for k, v in result.items() if k not in ('materials', 'actors')}, sort_keys=True))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
