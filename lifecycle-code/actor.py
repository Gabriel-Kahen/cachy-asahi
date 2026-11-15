#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""One finite normal-ALPM upgrade/repeat/rollback in the separate Root domain."""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import signal
import stat
import subprocess
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('perl_installed_common', HERE / 'common.py')
C = importlib.util.module_from_spec(spec); spec.loader.exec_module(C)


def file_node(path):
    s = path.lstat()
    node = dict(mode=stat.S_IMODE(s.st_mode), uid=s.st_uid, gid=s.st_gid, mtime_ns=s.st_mtime_ns)
    if stat.S_ISLNK(s.st_mode):
        node.update(type='symlink', target=os.readlink(path))
    elif stat.S_ISDIR(s.st_mode):
        node['type'] = 'directory'
    else:
        C.need(stat.S_ISREG(s.st_mode) and s.st_size <= 64 * 1024**2, 'bounded ordinary installed file')
        # Package hardlinks are legitimate installed files, never input operands.
        h = hashlib.sha256()
        with path.open('rb') as f:
            while part := f.read(65536): h.update(part)
            now = os.fstat(f.fileno())
        C.need((s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
               == (now.st_dev, now.st_ino, now.st_size, now.st_mtime_ns, now.st_ctime_ns), 'installed file changed')
        node.update(type='file', bytes=s.st_size, sha256=h.hexdigest())
    return node


def snapshot(root):
    root = Path(root)
    if not root.exists(): return {}
    result = {'.': file_node(root)}
    C.need(result['.']['type'] == 'directory', 'ordinary snapshot directory')
    for p in sorted(root.rglob('*')):
        C.need(len(result) < 30000, 'bounded snapshot node count')
        result[p.relative_to(root).as_posix()] = file_node(p)
    return result


def package_view(rows):
    result = {}
    for name in rows:
        if name.startswith('.'): continue
        p = Path('/') / name
        result[name] = file_node(p) if os.path.lexists(p) else None
    return result


def check_payload(rows, actual):
    for name, expected in rows.items():
        if name.startswith('.'): continue
        found = actual[name]
        C.need(found is not None, 'installed package path missing: ' + name)
        expected = dict(expected)
        expected.pop('mtime', None); expected.pop('ELF_machine', None)
        if expected['type'] == 'hardlink':
            target = Path('/') / expected.pop('target')
            C.need(os.path.samefile(Path('/') / name, target), 'package hardlink identity: ' + name)
            expected['type'] = 'file'
        C.need(all(found.get(k) == v for k, v in expected.items()), 'installed archive bytes/mode/owner: ' + name)


def normalize_desc(raw):
    parts = raw.decode().splitlines(keepends=True)
    indexes = [i for i, line in enumerate(parts) if line == '%INSTALLDATE%\n']
    C.need(len(indexes) == 1 and parts[indexes[0] + 1].strip().isdigit(), 'one normal ALPM INSTALLDATE')
    original = parts[indexes[0] + 1].strip()
    parts[indexes[0] + 1] = '<NORMAL_ALPM_TRANSACTION_TIME>\n'
    return C.pin(''.join(parts).encode()), original


def database():
    root = Path('/var/lib/pacman/local')
    raw = snapshot(root); normalized = C.decode(C.encode(raw))
    desc = root / 'perl-5.42.3-1/desc'
    date = None
    if desc.exists():
        value, date = normalize_desc(C.read(desc))
        normalized['perl-5.42.3-1/desc'].update(value)
    for name, row in normalized.items():
        if name == '.' or name == 'perl-5.42.3-1' or name.startswith('perl-5.42.3-1/'):
            row.pop('mtime_ns', None)
    return dict(raw=raw, normalized=normalized, perl_install_date=date)


def config(trust):
    C.need(trust in ('/work/baseline-trust', '/work/trust'), 'fixed private public trust domain')
    # The frozen base's ordinary hook configuration stays in force; no HookDir override.
    return ('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\n'
            'GPGDir = ' + trust + '\nLogFile = /var/log/pacman.log\n')


REMOVAL_ARGV = ['/usr/bin/pacman','--config','/work/pacman.conf','--noconfirm','-R','perl']


def removal_diagnostic(stdout, stderr, expected):
    text = (stdout + b'\n' + stderr).decode()
    C.need('failed to prepare transaction' in text and 'could not satisfy dependencies' in text,
           'ordinary dependency-protection transaction refusal required')
    rows = re.findall(r"^:: removing perl breaks dependency '(perl(?:[<>=]+[A-Za-z0-9._+:-]+)?)' required by ([A-Za-z0-9@._+:-]+)$",
                      text, re.MULTILINE)
    C.need(rows and len(rows) <= 349 and len(rows) == len(set(rows))
           and len(rows) == sum(line.startswith(':: removing perl breaks dependency ') for line in text.splitlines())
           and all(name in expected and name != 'perl' for _, name in rows),
           'specific Perl dependency consumers in the exact baseline required')
    return [dict(dependency=dependency, consumer=name) for dependency, name in rows]


def removal_witnesses(stdout, stderr, expected, raw_database, read_desc):
    witnesses = []; total = 0
    for row in removal_diagnostic(stdout, stderr, expected):
        name = row['consumer']; found = []
        for relative in raw_database:
            parts = Path(relative).parts
            if len(parts) != 2 or parts[1] != 'desc' or not parts[0].startswith(name+'-'): continue
            raw = read_desc(relative)
            desc = {p.splitlines()[0].strip('%'): p.splitlines()[1:]
                    for p in raw.decode().split('\n\n') if p.startswith('%')}
            if desc.get('NAME') == [name] and desc.get('VERSION') == [expected[name]]:
                found.append((relative, raw, desc))
        C.need(len(found) == 1, 'unique actual dependent baseline descriptor')
        relative, raw, desc = found[0]; total += len(raw)
        C.need(total <= 1024**2 and row['dependency'] in desc.get('DEPENDS', []),
               'bounded actual declared Perl dependency required')
        node = raw_database[relative]
        C.need(node['type'] == 'file' and C.pin(raw) == {k: node[k] for k in ('bytes','sha256')},
               'dependency witness bound to unchanged baseline local database')
        witnesses.append(dict(**row, desc_path=relative, descriptor=raw.decode()))
    return witnesses


def signature(raw, expected):
    rows = [line.split()[1:] for line in raw.decode().splitlines() if line.startswith('[GNUPG:] ')]
    bad = {'BADSIG','ERRSIG','NO_PUBKEY','EXPKEYSIG','EXPSIG','REVKEYSIG','KEYEXPIRED',
           'SIGEXPIRED','KEYREVOKED','NODATA','FAILURE','TRUST_NEVER','TRUST_UNDEFINED'}
    C.need(not any(row and row[0] in bad for row in rows), 'signature/trust refusal')
    valid = [row for row in rows if row and row[0] == 'VALIDSIG']
    C.need(len(valid) == 1 and len(valid[0]) == 11 and valid[0][-1] == expected,
           'exact admitted primary signer')
    C.need(any(row and row[0] in ('TRUST_FULLY', 'TRUST_ULTIMATE') for row in rows), 'trusted public signer required')


def runtime(domain):
    C.need(platform.system() == 'Linux' and platform.machine() == 'aarch64' and os.getuid() == os.geteuid() == 0
           and os.getgid() == os.getegid() == 0 and Path('/.dockerenv').exists(), 'separate native Root container required')
    C.need(os.sysconf('SC_PAGE_SIZE') == 4096, 'finite native ARM4K domain only')
    controllers = {k: (Path('/sys/fs/cgroup') / k).read_text().strip() for k in domain['cgroup']}
    C.need(controllers == domain['cgroup'], 'actual CPU/memory/swap/PID limits')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines())
    C.need(int(status['CapEff'].strip(), 16) == 0x800400cb
           and int(status['CapPrm'].strip(), 16) == 0x800400cb
           and all(int(status[k].strip(), 16) == 0 for k in ('CapInh', 'CapAmb'))
           and status['NoNewPrivs'].strip() == '1', 'reviewed root ALPM capabilities/NNP')
    mounts = Path('/proc/self/mountinfo').read_text()
    C.need(os.statvfs('/inputs').f_flag & os.ST_RDONLY and not os.statvfs('/').f_flag & os.ST_RDONLY,
           'readonly inputs and separate writable installation root')
    C.need(set(p.name for p in Path('/sys/class/net').iterdir()) == {'lo'}, 'no external network interface')
    C.need(os.statvfs('/work').f_blocks * os.statvfs('/work').f_frsize <= 256 * 1024**2,
           'bounded private work tmpfs')
    return dict(uname=list(os.uname()), page_bytes=4096, uid=0, gid=0, cgroup=controllers,
                status={k: status[k].strip() for k in ('CapEff','CapPrm','CapInh','CapAmb','NoNewPrivs')},
                namespaces={k: os.readlink('/proc/self/ns/' + k) for k in ('user','mnt','net','pid','cgroup')},
                cgroup_membership=Path('/proc/self/cgroup').read_text(), mountinfo=mounts)


def retained_result(parent, uid, gid):
    # Native caller supplies the fixed root-level path and exact Root identity.
    C.need(parent.is_absolute() and parent.name == 'cachy-asahi-perl-lifecycle'
           and parent.parent == parent.parent.resolve(), 'ordinary fixed output root name')
    C.need(not os.path.lexists(parent), 'retained output root must be absent before entry')
    parent.mkdir(mode=0o700)  # Atomic refusal if anything appeared after the absence check.
    out = parent / 'result'
    out.mkdir(mode=0o700)
    device = parent.parent.stat().st_dev
    for path in (parent, out):
        info = path.lstat()
        C.need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
               and info.st_uid == uid and info.st_gid == gid and info.st_dev == device,
               'private owned result on the containing writable filesystem')
    return out


def execute(args):
    C.need(HERE == Path('/inputs'), 'fixed capsule mount only')
    raw = os.environ.get('LIFECYCLE_ADMISSION_JSON', '').encode()
    C.need(C.pin(raw)['sha256'] == args.admission_sha256, 'external admission checksum')
    a = C.decode(raw); C.admission(a, args.source_map_sha256)
    C.source(HERE, args.source_map_sha256)
    C.need(os.environ.get('LIFECYCLE_ADMISSION_SHA256') == args.admission_sha256, 'same outer admission')
    report = dict(schema=1, operation=C.OPERATION, status='FAIL', installation='NOT_ACCEPTED',
                  source_map_sha256=args.source_map_sha256, admission_sha256=args.admission_sha256,
                  commands=[], stages=[], first_failure=None, cleanup=None)
    out = retained_result(Path('/cachy-asahi-perl-lifecycle'), 0, 0)
    report['retained_output'] = dict(parent=str(out.parent), path=str(out), uid=0, gid=0,
        mode=0o700, storage='OWNED_CONTAINER_WRITABLE_LAYER', parent_absent_before_entry=True,
        same_filesystem_as_parent_root=True)
    def save(): (out / 'report.json').write_bytes(C.encode(report))
    deadline = time.monotonic() + 480
    cancelled = []
    def cancel(signum, frame): cancelled.append(signum)
    signal.signal(signal.SIGTERM, cancel); signal.signal(signal.SIGINT, cancel)
    owned = C.load('owned_child.py')
    env = dict(PATH='/usr/bin', HOME='/root', LC_ALL='C', TZ='UTC')
    def run(step, argv, expected=0, limit=1024**2):
        C.need(not cancelled and time.monotonic() < deadline - 30, 'finite lifecycle cancelled/deadline')
        row = dict(step=step, argv=argv, lifecycle={}, expected=expected, success=False)
        try:
            result = owned.run(argv, capture_output=True, timeout=min(90, deadline-time.monotonic()-30),
                               env=env, lifecycle=row['lifecycle'], stdout_limit=limit, stderr_limit=limit,
                               allowed_uids={0, alarm.pw_uid})
            row.update(returncode=result.returncode, stdout=C.pin(result.stdout), stderr=C.pin(result.stderr))
            (out / (step + '.stdout')).write_bytes(result.stdout)
            (out / (step + '.stderr')).write_bytes(result.stderr)
            C.need(C.natural(row['lifecycle']) and row['lifecycle']['exit'] == result.returncode,
                   'natural exact owned command retirement')
            C.need(result.returncode == expected if expected is not None else result.returncode != 0, 'unexpected command status: ' + step)
            row['success'] = True
            return result.stdout, result.stderr
        finally:
            report['commands'].append(row); save()
    alarm = pwd.getpwnam('alarm')
    C.need(alarm.pw_uid != 0 and alarm.pw_gid != 0 and alarm.pw_dir == '/home/alarm', 'preexisting ordinary baseline user')
    user = Path('/home/alarm/.perl5423-lifecycle')
    user_identity = None
    try:
        report['runtime'] = runtime(C.decode(C.read(HERE / 'domain.json')))
        expected = C.inventory(C.read(HERE / 'expected349.lock'))
        candidate = C.decode(C.read(HERE / 'candidate-payload.json'))
        baseline = C.decode(C.read(HERE / 'baseline-payload.json'))
        union = {**baseline, **candidate}
        def installed(version, step=None):
            raw, _ = run(step or 'inventory-' + str(len(report['commands'])), ['/usr/bin/pacman','-Q'])
            target = dict(expected, perl=version)
            C.need(C.inventory(raw, version) == target, 'all349 exact package versions; only Perl substitution')
            return C.pin(raw)
        installed('5.42.3-1')
        original_files = package_view(union); original_db = database()
        accounts = {name: C.pin(C.read('/etc/' + name)) for name in ('passwd','group','shadow','gshadow')}
        home_before = file_node(Path('/home/alarm'))
        log_before = C.read('/var/log/pacman.log', 8*1024**2)
        trust_before = snapshot('/etc/pacman.d/gnupg')
        hooks_before = snapshot('/etc/pacman.d/hooks')
        global_config = C.pin(C.read('/etc/pacman.conf'))
        report['original'] = dict(files=original_files, database=original_db, accounts=accounts,
                                  alarm_home_directory=home_before, pacman_log=C.pin(log_before),
                                  hooks=hooks_before, trust=trust_before, pacman_conf=global_config)
        check_payload(baseline, original_files)
        C.need(not user.exists(), 'fresh ordinary-user fixture only')
        user.mkdir(mode=0o700); user_identity = (user.stat().st_dev, user.stat().st_ino)
        os.chown(user, alarm.pw_uid, alarm.pw_gid)
        run('user-edits', ['/usr/bin/runuser','-u','alarm','--','/usr/bin/python3','-I','-B','-c',
            "from pathlib import Path; p=Path('/home/alarm/.perl5423-lifecycle'); "
            "(p/'site').mkdir(); (p/'site/CachyAsahiLifecycle.pm').write_text('package CachyAsahiLifecycle; sub value {42} 1;\\n'); "
            "(p/'config').write_text('user-owned=preserve\\n')"])
        user_before = snapshot(user)
        Path('/work/baseline.conf').write_text(config('/work/baseline-trust'))
        Path('/work/pacman.conf').write_text(config('/work/trust'))
        for trust, source in [('/work/trust', HERE / 'trust'), ('/work/baseline-trust', Path('/etc/pacman.d/gnupg'))]:
            Path(trust).mkdir(mode=0o700)
            for name in ('pubring.gpg','trustdb.gpg'):
                (Path(trust) / name).write_bytes(C.read(source / name))
            (Path(trust) / 'gpg.conf').write_text('no-auto-key-retrieve\nno-autostart\ndisable-dirmngr\n')
        gpg = ['/usr/bin/gpg','--homedir','/work/trust','--batch','--no-autostart','--no-auto-key-retrieve']
        secret, _ = run('no-secret-keys', gpg + ['--with-colons','--list-secret-keys'])
        C.need(not any(line.startswith((b'sec:', b'ssb:')) for line in secret.splitlines()), 'no signing credentials in actor')
        pub, _ = run('public-certificate', gpg + ['--with-colons','--show-keys','/inputs/test-public.asc'])
        C.need(('fpr:::::::::' + a['test_fingerprint'] + ':').encode() in pub,
               'Root fresh TEST public certificate identity')
        C.need(any(line.startswith(b'uid:') and b'TEST ONLY' in line and b'@test.invalid' in line
                   for line in pub.splitlines()), 'explicit TEST ONLY public UID required')
        for label, name, fingerprint in [('candidate', C.CANDIDATE, a['test_fingerprint']),
                                         ('baseline', C.BASELINE, a['baseline_fingerprint'])]:
            raw, _ = run('signature-' + label, gpg + ['--status-fd=1','--verify','/inputs/' + name + '.sig','/inputs/' + name])
            signature(raw, fingerprint)
        pacman = ['/usr/bin/pacman','--config','/work/pacman.conf','--noconfirm']
        def refusal(step, argv, keywords):
            before = database()
            stdout, stderr = run(step, argv, expected=None)
            C.need(any(word in (stdout+stderr).lower() for word in keywords), 'specific trusted-ALPM refusal diagnostic')
            C.need(database() == before and package_view(union) == original_files, 'refusal changed package/database state')
            installed('5.42.3-1')
        refusal('unknown-test-key', ['/usr/bin/pacman','--config','/work/baseline.conf','--noconfirm','-U','/inputs/' + C.CANDIDATE],
                (b'unknown trust', b'unknown public key', b'required key missing', b'could not be looked up remotely'))
        tamper = Path('/work/tampered'); tamper.mkdir()
        shutil.copyfile(HERE / C.CANDIDATE, tamper / C.CANDIDATE)
        sig = bytearray(C.read(HERE / (C.CANDIDATE + '.sig'))); sig[-1] ^= 1
        (tamper / (C.CANDIDATE + '.sig')).write_bytes(sig)
        refusal('tampered-signature', pacman + ['-U',str(tamper / C.CANDIDATE)], (b'pgp signature', b'invalid or corrupted'))
        def validate(stage, version, rows):
            report['stages'].append(stage); installed(version)
            raw, _ = run('paths-' + stage, ['/usr/bin/pacman','-Qlq','perl'])
            names = {name.lstrip('/').rstrip('/') for name in raw.decode().splitlines()}
            C.need(names == {name for name in rows if not name.startswith('.')}, 'exact ALPM-owned Perl path set')
            actual = package_view(rows); check_payload(rows, actual)
            run('dependencies-' + stage, ['/usr/bin/pacman','-Dk'])
            raw, _ = run('probe-' + stage, ['/usr/bin/perl','/inputs/probe.pl'])
            probe = C.decode(raw)
            if version == '5.42.3-1.3':
                C.need(probe['config']['cf_time'] == 'Sun Aug  2 00:00:00 UTC 2026', 'actual candidate deterministic Config')
            report[stage] = dict(files=actual, probe=probe, database=database(), user=snapshot(user))
            C.need(snapshot(user) == user_before, 'ordinary-user site/config edits preserved')
            run('user-site-' + stage, ['/usr/bin/runuser','-u','alarm','--','/usr/bin/env',
                'PERL5LIB=' + str(user / 'site'),'/usr/bin/perl','-MCachyAsahiLifecycle','-e',
                'exit(CachyAsahiLifecycle::value() == 42 ? 0 : 1)'])
            save()
        validate('baseline', '5.42.3-1', baseline)
        def removal_state(step):
            return dict(inventory=installed('5.42.3-1', step),
                database=C.pin(C.encode(database())), package_owned=C.pin(C.encode(package_view(union))),
                user_fixture=C.pin(C.encode(snapshot(user))), alarm_home=C.pin(C.encode(snapshot('/home/alarm'))),
                accounts={name:C.pin(C.read('/etc/'+name)) for name in accounts},
                trust=C.pin(C.encode(snapshot('/etc/pacman.d/gnupg'))),
                hooks=C.pin(C.encode(snapshot('/etc/pacman.d/hooks'))),
                pacman_conf=C.pin(C.read('/etc/pacman.conf')))
        removal = dict(status='PENDING', before=removal_state('inventory-before-removal-refusal'),
                       alarm_home_before=snapshot('/home/alarm'), full_uninstall='NOT_RUN')
        report['removal_refusal'] = removal; save()
        raw, err = run('dependency-protected-removal', REMOVAL_ARGV, expected=1)
        removal['witnesses'] = removal_witnesses(raw, err, expected, report['baseline']['database']['raw'],
            lambda name: C.read(Path('/var/lib/pacman/local') / name, 131072))
        removal['after'] = removal_state('inventory-after-removal-refusal')
        removal['alarm_home_after'] = snapshot('/home/alarm')
        C.need(removal['before'] == removal['after']
               and removal['alarm_home_before'] == removal['alarm_home_after'],
               'dependency refusal changed inventory/raw database/Perl-owned/user/trust/config state')
        check_payload(baseline, package_view(union))
        removal['baseline_payload_verified_after_refusal'] = True
        removal['status'] = 'PASS_DEPENDENCY_PROTECTED_REMOVAL_REFUSAL'; save()
        run('trusted-upgrade', pacman + ['-U','/inputs/' + C.CANDIDATE])
        validate('upgrade', '5.42.3-1.3', candidate)
        (out / 'upgraded-handoff.json').write_bytes(C.encode(dict(schema=1, kind='READONLY_UPGRADED_PROBE_DATA_ONLY',
            image=None, container=None, source_map_sha256=args.source_map_sha256,
            candidate_archive=C.ARCHIVE, probe=report['upgrade']['probe'], files=report['upgrade']['files'],
            usable_xs_runtime='NOT_CREATED; Root must separately admit a readonly upgraded image')))
        run('trusted-repeat', pacman + ['-U','/inputs/' + C.CANDIDATE])
        validate('repeat', '5.42.3-1.3', candidate)
        before_noop = database()
        raw, err = run('trusted-noop', pacman + ['-U','--needed','/inputs/' + C.CANDIDATE])
        C.need(b'up to date -- skipping' in raw + err and database() == before_noop, 'real --needed no-op unchanged database')
        validate('noop', '5.42.3-1.3', candidate)
        run('trusted-rollback', pacman + ['-U','/inputs/' + C.BASELINE])
        validate('rollback', '5.42.3-1', baseline)
        final = package_view(union); final_db = database()
        # Shared ancestor directories have normal transaction mtimes; all file/link bytes and metadata match.
        def normalized_payload(value):
            value = C.decode(C.encode(value))
            for row in value.values():
                if row and row['type'] == 'directory': row.pop('mtime_ns', None)
            return value
        C.need(normalized_payload(final) == normalized_payload(original_files), 'exact rollback package file/hash metadata')
        C.need(final_db['normalized'] == original_db['normalized'], 'rollback all349 ALPM database except recorded Perl transaction times')
        C.need({name:C.pin(C.read('/etc/'+name)) for name in accounts} == accounts, 'no account residuals')
        final_log = C.read('/var/log/pacman.log', 8*1024**2)
        C.need(final_log.startswith(log_before), 'ordinary ALPM log retained as append-only data')
        C.need(snapshot('/etc/pacman.d/gnupg') == trust_before and snapshot('/etc/pacman.d/hooks') == hooks_before
               and C.pin(C.read('/etc/pacman.conf')) == global_config, 'baseline public trust/hooks/config preserved')
        report['rollback_comparison'] = dict(status='PASS', original_install_date=original_db['perl_install_date'],
            final_install_date=final_db['perl_install_date'], account_residuals=[],
            database_timestamp_differences=[name for name in original_db['raw']
                if original_db['raw'][name] != final_db['raw'].get(name)],
            payload_directory_timestamp_differences=[name for name in final
                if final[name] != original_files.get(name)],
            pacman_log='normal append-only transaction log retained in disposable container',
            pacman_log_final=C.pin(final_log),
            user_fixture='preserved across all transactions; removed during scoped cleanup')
        report.update(status='PASS_FINITE_NATIVE_ARM4K_PERL_INSTALLED_LIFECYCLE', installation='COMPONENT_EVIDENCE_ONLY',
                      native16K='NOT_RUN', M2='NOT_RUN', performance='NOT_RUN', release='NOT_ACCEPTED')
    except BaseException as error:
        report['first_failure'] = dict(type=type(error).__name__, message=str(error)[:1500])
        raise
    finally:
        failures = []
        try:
            if user_identity is not None and user.exists():
                C.need(user.is_dir() and not user.is_symlink()
                       and (user.stat().st_dev, user.stat().st_ino) == user_identity,
                       'owned ordinary-user fixture directory')
                shutil.rmtree(user)
            sockets = [str(p) for trust in ('/work/trust','/work/baseline-trust','/run','/tmp')
                       for p in Path(trust).rglob('*') if stat.S_ISSOCK(p.lstat().st_mode)]
            C.need(not sockets, 'GPG/agent socket remains; no second process authority')
            agents = []
            for p in Path('/proc').iterdir():
                if not p.name.isdecimal(): continue
                try:
                    if (p / 'comm').read_text().strip() in ('gpg-agent','dirmngr'): agents.append(p.name)
                except FileNotFoundError: pass
            C.need(not agents, 'agent remains in the owned container; natural cleanup unqualified')
        except BaseException as error: failures.append(type(error).__name__ + ': ' + str(error))
        report['cleanup'] = dict(user_fixture_absent=not os.path.lexists(user), failures=failures,
                                 alarm_home_directory_final=file_node(Path('/home/alarm')),
                                 private_work='removed only with owned naturally exited container')
        if failures: report.update(status='FAIL', installation='NOT_ACCEPTED')
        save()
    C.need(report['status'].startswith('PASS_') and not report['cleanup']['failures'], 'complete actor success required')


if __name__ == '__main__':
    C.need(__import__('sys').flags.isolated, 'isolated Python required')
    p = argparse.ArgumentParser()
    p.add_argument('--admission-sha256', required=True)
    p.add_argument('--source-map-sha256', required=True)
    execute(p.parse_args())
