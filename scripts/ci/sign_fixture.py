#!/usr/bin/env python3
"""Sign reviewed native integration inputs with a disposable TEST-only container key.

The host never generates/imports private keys, installs packages or runs recipes.
"""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

if Path(__file__).resolve().as_posix() == '/inputs/runner/sign_fixture.py':
    sys.path.insert(0, '/inputs/scripts/checks')
import native_arm as native
from package_checks import package

PURPOSE = 'TEST-ONLY-integration-signatures'
STATUS = 'TEST-SIGNATURES PASS'
LIMIT = 4 * 1024**2
STANDARD_MOUNTS = {
    '/proc': ('proc', {'rw', 'nosuid', 'nodev', 'noexec'}),
    '/dev': ('tmpfs', {'rw', 'nosuid'}),
    '/dev/pts': ('devpts', {'rw', 'nosuid', 'noexec'}),
    '/dev/mqueue': ('mqueue', {'rw', 'nosuid', 'nodev', 'noexec'}),
    '/dev/shm': ('tmpfs', {'rw', 'nosuid', 'nodev', 'noexec'}),
    '/sys': ('sysfs', {'ro', 'nosuid', 'nodev', 'noexec'}),
    '/sys/fs/cgroup': ('cgroup2', {'ro', 'nosuid', 'nodev', 'noexec'}),
    **{p: ('proc', {'ro', 'nosuid', 'nodev', 'noexec'}) for p in
       ('/proc/bus', '/proc/fs', '/proc/irq', '/proc/sys', '/proc/sysrq-trigger')},
    **{p: ('tmpfs', {'ro'}) for p in
       ('/proc/acpi', '/proc/asound', '/proc/scsi', '/sys/firmware', '/sys/devices/virtual/powercap')},
    **{p: ('tmpfs', {'rw', 'nosuid'}) for p in
       ('/proc/interrupts', '/proc/kcore', '/proc/keys', '/proc/latency_stats', '/proc/timer_list', '/proc/timer_stats', '/proc/sched_debug')},
}
STANDARD_DEVICES = {'/dev/null': (1, 3), '/dev/zero': (1, 5), '/dev/full': (1, 7),
                    '/dev/random': (1, 8), '/dev/urandom': (1, 9), '/dev/tty': (5, 0),
                    '/dev/pts/ptmx': (5, 2)}
BIND_FILESYSTEMS = {'ext4', 'xfs', 'btrfs', 'tmpfs', 'overlay', 'fuse-overlayfs'}
CAPABILITY_FIELDS = ('CapEff', 'CapPrm', 'CapBnd', 'CapInh', 'CapAmb')
MASKED_NULL = {'/proc/interrupts', '/proc/kcore', '/proc/keys', '/proc/latency_stats',
               '/proc/timer_list', '/proc/timer_stats', '/proc/sched_debug'}


@contextmanager
def cancellation_scope():
    previous = signal.getsignal(signal.SIGTERM)
    def cancelled(signum, frame):
        raise KeyboardInterrupt('signer cancellation')
    signal.signal(signal.SIGTERM, cancelled)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


def stop_group(process):
    for signum in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, signum)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
            # Descendants can outlive their group leader; kill the remaining group.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            return
        except subprocess.TimeoutExpired:
            continue
    raise ValueError('signer process group did not terminate')


def command_result(command, timeout, log=None):
    """Spool bounded diagnostics and terminate the whole child group on interruption."""
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            process.wait(timeout=timeout)
        except BaseException:
            stop_group(process)
            raise
        finally:
            if log is not None:
                stdout.seek(0); stderr.seek(0)
                content = stdout.read(LIMIT + 1) + stderr.read(LIMIT + 1)
                log.write_bytes(content if len(content) <= LIMIT else b'command diagnostics exceeded public bound\n')
        stdout.seek(0); stderr.seek(0)
        output, diagnostic = stdout.read(LIMIT + 1), stderr.read(LIMIT + 1)
        need(len(output) <= LIMIT and len(diagnostic) <= LIMIT, 'signer command output exceeds bound')
        return subprocess.CompletedProcess(command, process.returncode, output, diagnostic)


def run(command, log=None, timeout=180):
    result = command_result(command, timeout, log)
    need(result.returncode == 0, 'signer command failed; see bounded command evidence')
    return result.stdout.decode('utf-8').strip()


def remove_container(name):
    """Require bounded removal and an independently successful absence query."""
    need(re.fullmatch(r'cachy-asahi-test-signer-[0-9a-f]{32}', name), 'only the owned signer container may be removed')
    attempts = []
    for unused in range(2):
        try:
            query = ['docker', 'container', 'ls', '-a', '--no-trunc',
                     '--filter', 'name=^/' + name + '$', '--format', '{{.Names}}']
            before = command_result(query, 10)
            if before.returncode == 0 and not before.stdout.strip():
                return {'status': 'FAIL' if any(a.get('remove_exit', 0) != 0 for a in attempts) else 'PASS',
                        'container_absent': True, 'attempts': attempts,
                        'already_absent': True}
            removed = command_result(['docker', 'rm', '-f', name], 10)
            absent = command_result(query, 10)
            attempts.append({'remove_exit': removed.returncode, 'query_exit': absent.returncode,
                             'absent': absent.returncode == 0 and not absent.stdout.strip()})
            if removed.returncode == 0 and attempts[-1]['absent']:
                return {'status': 'FAIL' if any(a.get('remove_exit', 0) != 0 for a in attempts) else 'PASS',
                        'container_absent': True, 'attempts': attempts}
            if attempts[-1]['absent']:
                return {'status': 'FAIL', 'container_absent': True, 'attempts': attempts}
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            attempts.append({'error_type': type(error).__name__, 'absent': False})
    return {'status': 'FAIL', 'container_absent': False, 'attempts': attempts}


def host_probe(out):
    record = {'kernel': platform.uname()._asdict(), 'page_size': os.sysconf('SC_PAGE_SIZE'),
              'docker_server_arch': run(['docker', 'info', '--format', '{{.Architecture}}'], timeout=60),
              'docker_version': run(['docker', 'version'], timeout=60), 'cpu': run(['lscpu'], timeout=60),
              'python': sys.version, 'uid': os.getuid(), 'gid': os.getgid(),
              'bootstrap_script_sha256': native.sha(Path(__file__)),
              'native_build': 'NOT RUN', 'hardware_validation': 'NOT RUN'}
    native.save(out / 'runner.json', record)
    need(platform.system() == 'Linux' and platform.machine() in ('aarch64', 'arm64') and
         record['docker_server_arch'] in ('aarch64', 'arm64') and os.getuid() != 0,
         'native non-root Linux ARM host and native local ARM Docker daemon required')
    context = decode_json(run(['docker', 'context', 'inspect'], timeout=60))[0]
    endpoint = context['Endpoints']['docker']['Host']
    local = ('unix:///var/run/docker.sock', 'unix:///run/docker.sock')
    need(endpoint in local and os.environ.get('DOCKER_HOST', endpoint) in local, 'local Docker daemon required')
    record['docker_endpoint'] = endpoint
    native.save(out / 'runner.json', record)
    return record


def need(condition, message):
    if not condition:
        raise ValueError(message)


def decode_json(data):
    def unique(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique, parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def read_json(path, digest):
    data = path.read_bytes()
    need(hashlib.sha256(data).hexdigest() == native.check_pin(digest), 'reviewed JSON hash differs')
    return decode_json(data)


def relative(value):
    need(isinstance(value, str) and value and all(ord(c) >= 32 for c in value), 'invalid relative input path')
    need(not value.startswith('/') and '\\' not in value and all(p not in ('', '.', '..') for p in value.split('/')), 'escaping input path')
    return value


def regular(path):
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'symlink input/output refused')
    need(path.is_file() and path.stat().st_nlink == 1, 'singly linked regular file required')


def validate_manifest(data):
    need(isinstance(data, dict) and data.get('schema_version') == 1 and data.get('purpose') == PURPOSE, 'explicit TEST-only signer manifest required')
    need(re.fullmatch(r'[0-9a-f]{40}', data.get('source_commit', '')), 'accepted source commit required')
    rows = data.get('archives')
    need(isinstance(rows, list) and len(rows) == 8, 'four originals and four changed upgrade fixtures required')
    paths, grouped = set(), {}
    for row in rows:
        need(isinstance(row, dict), 'archive record must be an object')
        path = relative(row.get('path'))
        need(path.endswith(('.pkg.tar.zst', '.pkg.tar.xz', '.pkg.tar.gz')) and path not in paths, 'unique original archive path required')
        paths.add(path)
        need(row.get('name') in native.RECIPES and row.get('role') in ('original', 'upgrade-fixture'), 'unexpected package/role')
        need(re.fullmatch(r'[A-Za-z0-9._+:~-]+', row.get('version', '')), 'exact archive version required')
        native.check_pin(row.get('sha256'))
        grouped.setdefault(row['role'], []).append(row['name'])
    need(all(sorted(grouped.get(role, [])) == sorted(native.RECIPES) for role in ('original', 'upgrade-fixture')), 'each stage must contain all four distinct originals')
    originals = {r['name']: r for r in rows if r['role'] == 'original'}
    for row in rows:
        if row['role'] == 'upgrade-fixture':
            old = originals[row['name']]
            need(row['sha256'] != old['sha256'] and row['version'] != old['version'], 'fixture cannot reuse original bytes/version')
    return rows


def checked(command, label, timeout=60):
    result = command_result(command, timeout)
    need(len(result.stdout) <= LIMIT and len(result.stderr) <= LIMIT, f'{label} output exceeds bound')
    for data in (result.stdout, result.stderr):
        need(b'PRIVATE KEY' not in data and b'export-secret' not in data, f'{label}: private material suppressed')
    if result.returncode:
        diagnostic = result.stderr.decode('utf-8', errors='replace')[:4096]
        raise ValueError(f'{label} exited {result.returncode}: {diagnostic}')
    return result.stdout.decode('utf-8')


@contextmanager
def gpg_home(prefix, directory=None):
    with tempfile.TemporaryDirectory(prefix=prefix, dir=directory) as value:
        home = Path(value); home.chmod(0o700)
        try:
            yield home
        finally:
            checked(['gpgconf', '--homedir', str(home), '--kill', 'all'], 'disposable agent cleanup', 10)


def artifact_bind(path, row):
    need(path.stat().st_size <= 8 * 1024**2, 'configuration archive exceeds signer bound')
    report = package(path)
    need(not report['errors'], 'archive static inspection failed before signing')
    metadata = report['metadata'].get('.PKGINFO', {})
    for key, expected in [('pkgname', [row['name']]), ('pkgver', [row['version']]),
                          ('arch', ['any']), ('license', ['MIT'])]:
        need(metadata.get(key) == expected, 'archive metadata differs from signer manifest: ' + key)
    need('.INSTALL' not in report['members'] and not report.get('elf'), 'only reviewed data/Python configuration archives may be TEST-signed')
    return report


def mount_table(text):
    table = {}
    for row in text.splitlines():
        columns = row.split(); separator = columns.index('-')
        unescape = lambda value: re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), value)
        point = unescape(columns[4])
        need(point not in table, 'duplicate signer mount destination')
        table[point] = {'fs': columns[separator + 1], 'options': columns[5].split(','), 'root': unescape(columns[3])}
    return table


def signer_guard(probe, contract):
    need(set(contract) == {'schema_version', 'purpose', 'nonce', 'image_id', 'manifest_sha256', 'entry_sha256', 'helpers_sha256'}, 'unexpected signer contract fields')
    need(set(contract['helpers_sha256']) == {'runner/native_arm.py', 'scripts/checks/package_checks.py'}, 'complete signer helper pins required')
    for digest in contract['helpers_sha256'].values():
        native.check_pin(digest)
    need(set(probe) == {'arch', 'uid', 'user', 'docker_marker', 'interfaces', 'docker_socket', 'caps', 'capabilities', 'no_new_privs', 'mounts', 'nonce', 'device_nodes', 'sockets'}, 'unexpected signer guard fields')
    need(contract.get('purpose') == PURPOSE and contract.get('schema_version') == 1, 'TEST-only container contract required')
    need(probe.get('arch') == 'aarch64' and probe.get('uid', 0) != 0 and probe.get('user') == 'alarm', 'native non-root alarm required')
    need(probe.get('docker_marker') is True and probe.get('interfaces') == ['lo'] and not probe.get('docker_socket'), 'actual no-network/no-socket Docker container required')
    capabilities = probe['capabilities']
    need(isinstance(capabilities, dict) and set(capabilities) == set(CAPABILITY_FIELDS) and
         all(type(value) is int and value == 0 for value in capabilities.values()), 'all five capability sets must be explicitly zero')
    need(type(probe['caps']) is int and probe['caps'] == capabilities['CapEff'] and
         type(probe['no_new_privs']) is int and probe['no_new_privs'] == 1, 'capability-free no-new-privileges required')
    need(re.fullmatch(r'[0-9a-f]{32}', contract.get('nonce', '')) and probe.get('nonce') == contract['nonce'], 'fresh signer nonce binding required')
    need(re.fullmatch(r'sha256:[0-9a-f]{64}', contract.get('image_id', '')), 'immutable signer image required')
    native.check_pin(contract.get('entry_sha256')); native.check_pin(contract.get('manifest_sha256'))
    table = probe['mounts']
    need(all(isinstance(entry, dict) and set(entry) == {'fs', 'options', 'root'} for entry in table.values()), 'unexpected signer mount record fields')
    for entry in table.values():
        flags = entry['options']
        need(isinstance(flags, list) and all(isinstance(flag, str) for flag in flags) and
             len(set(flags)) == len(flags) and ('ro' in flags) != ('rw' in flags), 'invalid signer mount options')
        need(isinstance(entry['root'], str) and entry['root'].startswith('/') and
             not any(c in entry['root'] for c in ('\n', '\0')), 'invalid signer mount root')
        need(not any(a in flags and b in flags for a, b in
                     (('nosuid', 'suid'), ('nodev', 'dev'), ('noexec', 'exec'))), 'conflicting signer mount security flags')
    need(table.get('/', {}).get('fs') in ('overlay', 'fuse-overlayfs') and 'ro' in table['/']['options'] and table['/']['root'] == '/', 'read-only disposable root required')
    for path in ('/inputs',):
        need(path in table and table[path]['fs'] in BIND_FILESYSTEMS and 'ro' in table[path]['options'], 'read-only signer inputs required')
    need('/out' in table and table['/out']['fs'] in BIND_FILESYSTEMS and 'rw' in table['/out']['options'], 'dedicated public output required')
    need('/tmp' in table and table['/tmp']['fs'] == 'tmpfs' and table['/tmp']['root'] == '/' and {'rw', 'nosuid', 'nodev'} <= set(table['/tmp']['options']), 'private tmpfs key storage required')
    etc = {'/etc/hosts', '/etc/hostname', '/etc/resolv.conf'}
    for path, entry in table.items():
        if path in ('/', '/inputs', '/out', '/tmp'):
            continue
        if path in etc:
            need(entry['fs'] in BIND_FILESYSTEMS, 'unexpected Docker metadata mount')
            continue
        need(path in STANDARD_MOUNTS, 'unexpected signer mount refused')
        fs, flags = STANDARD_MOUNTS[path]
        need(entry['fs'] == fs and flags <= set(entry['options']), 'unexpected standard signer mount filesystem/options')
        expected_root = '/null' if path in MASKED_NULL else path.removeprefix('/proc') if fs == 'proc' and path != '/proc' else '/'
        need(entry['root'] == expected_root, 'standard signer mount cannot expose another subtree')
    need({'/proc', '/dev', '/dev/pts', '/dev/shm', '/dev/mqueue', '/sys', '/sys/fs/cgroup'} <= set(table), 'standard Docker mount set required')
    need(probe['sockets'] == [], 'socket exposure refused')
    devices = probe['device_nodes']
    need(isinstance(devices, dict) and set(devices) == set(STANDARD_DEVICES), 'unexpected/missing signer device exposure')
    for path, numbers in STANDARD_DEVICES.items():
        need(devices[path] == {'kind': 'char', 'major': numbers[0], 'minor': numbers[1]}, 'unexpected signer device identity')


def exposed_nodes():
    devices, sockets, count = {}, [], 0
    for root in ('/dev', '/run', '/tmp', '/inputs', '/out'):
        for directory, dirs, files in os.walk(root, followlinks=False):
            for name in dirs + files:
                path = Path(directory) / name; entry = path.lstat(); count += 1
                need(count <= 4096, 'signer exposed-node inspection exceeds bound')
                if stat.S_ISSOCK(entry.st_mode):
                    sockets.append(str(path))
                if stat.S_ISCHR(entry.st_mode) or stat.S_ISBLK(entry.st_mode):
                    devices[str(path)] = {'kind': 'char' if stat.S_ISCHR(entry.st_mode) else 'block',
                                          'major': os.major(entry.st_rdev), 'minor': os.minor(entry.st_rdev)}
                if stat.S_ISLNK(entry.st_mode) and root == '/dev':
                    links = {'/dev/fd': '/proc/self/fd', '/dev/stdin': '/proc/self/fd/0',
                             '/dev/stdout': '/proc/self/fd/1', '/dev/stderr': '/proc/self/fd/2',
                             '/dev/core': '/proc/kcore', '/dev/ptmx': 'pts/ptmx'}
                    need(str(path) in links and os.readlink(path) == links[str(path)], 'unexpected signer device alias')
    return devices, sorted(sockets)


def environment():
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    marker = Path('/.dockerenv')
    devices, sockets = exposed_nodes()
    capabilities = {key: int(status.get(key, '-1').strip(), 16) for key in CAPABILITY_FIELDS}
    return {'arch': platform.machine(), 'uid': os.geteuid(), 'user': pwd.getpwuid(os.geteuid()).pw_name,
            'docker_marker': marker.is_file() and not marker.is_symlink() and marker.stat().st_uid == 0,
            'interfaces': sorted(p.name for p in Path('/sys/class/net').iterdir()),
            'docker_socket': any(Path(p).exists() for p in ('/run/docker.sock', '/var/run/docker.sock')),
            'caps': capabilities['CapEff'], 'capabilities': capabilities, 'no_new_privs': int(status.get('NoNewPrivs', '0').strip()),
            'mounts': mount_table(Path('/proc/self/mountinfo').read_text()), 'nonce': os.environ.get('CACHY_ASAHI_TEST_SIGNER'),
            'device_nodes': devices, 'sockets': sockets}


def public_certificate(data):
    need(len(data) <= LIMIT and data.startswith(b'-----BEGIN PGP PUBLIC KEY BLOCK-----'), 'public certificate armor required')
    lines = data.decode('ascii').splitlines()
    need(lines[-1] == '-----END PGP PUBLIC KEY BLOCK-----' and lines.count(lines[0]) == 1, 'one public certificate block required')
    start = lines.index('') + 1
    body = ''.join(line for line in lines[start:-1] if not line.startswith('='))
    packets = base64.b64decode(body, validate=True)
    offset, tags = 0, []
    while offset < len(packets):
        header = packets[offset]; offset += 1
        need(header & 128, 'invalid OpenPGP packet header')
        if header & 64:
            tag = header & 63
            need(offset < len(packets), 'truncated public certificate packet')
            length = packets[offset]; offset += 1
            if length < 192:
                size = length
            elif length < 224:
                need(offset < len(packets), 'truncated certificate packet length')
                size = ((length - 192) << 8) + packets[offset] + 192; offset += 1
            elif length == 255:
                need(offset + 4 <= len(packets), 'truncated certificate packet length')
                size = int.from_bytes(packets[offset:offset + 4], 'big'); offset += 4
            else:
                raise ValueError('partial/compressed public certificate packet refused')
        else:
            tag = (header >> 2) & 15
            width = (1, 2, 4, 0)[header & 3]
            need(width and offset + width <= len(packets), 'indeterminate/truncated certificate packet')
            size = int.from_bytes(packets[offset:offset + width], 'big'); offset += width
        need(tag in (2, 6, 13, 14, 17), 'nonpublic/secret/encrypted OpenPGP packet refused')
        need(offset + size <= len(packets), 'truncated certificate packet')
        tags.append(tag); offset += size
    need(tags.count(6) == 1 and 13 in tags and 2 in tags, 'one signed public primary identity required')


def fingerprint(home, certificate=None):
    command = ['gpg', '--batch', '--no-options', '--homedir', str(home), '--with-colons']
    command += ['--show-keys', str(certificate)] if certificate else ['--list-keys']
    lines = checked(command, 'TEST public key inspection').splitlines()
    primaries, identities, expiry = [], [], None
    primary_next = False
    for line in lines:
        fields = line.split(':')
        if fields[0] == 'pub':
            need(fields[1] not in ('r', 'e'), 'revoked/expired TEST public key')
            primary_next = True; expiry = int(fields[6])
        elif fields[0] == 'fpr' and primary_next:
            primaries.append(fields[9]); primary_next = False
        elif fields[0] == 'uid':
            identities.append(fields[9])
    need(len(primaries) == 1 and re.fullmatch(r'[0-9A-F]{40}', primaries[0]), 'one full TEST primary fingerprint required')
    need(identities and all('CACHY-ASAHI TEST ONLY' in value for value in identities), 'unambiguously TEST-only identity required')
    need(expiry is not None and int(time.time()) < expiry <= int(time.time()) + 90000, 'fresh one-day TEST key expiry required')
    return primaries[0], expiry


def inside():
    root, output = Path('/inputs'), Path('/out')
    contract = read_json(root / 'contract.json', os.environ.get('CACHY_ASAHI_SIGNER_CONTRACT_SHA256'))
    observed = environment(); signer_guard(observed, contract)
    need(Path(__file__).resolve() == root / 'runner/sign_fixture.py' and native.sha(Path(__file__)) == contract['entry_sha256'], 'signer entry source drift')
    for name, digest in contract.get('helpers_sha256', {}).items():
        path = root / relative(name); regular(path)
        need(native.sha(path) == native.check_pin(digest), 'signer helper source drift')
    need(set(contract.get('helpers_sha256', {})) == {'runner/native_arm.py', 'scripts/checks/package_checks.py'}, 'complete signer helper source pins required')
    regular(root / 'manifest.json')
    data = read_json(root / 'manifest.json', contract['manifest_sha256']); rows = validate_manifest(data)
    need(not any(output.iterdir()), 'new empty signer output required')
    for row in rows:
        path = root / 'archives' / row['path']; regular(path)
        need(native.sha(path) == row['sha256'], 'archive bytes differ before signing')
        artifact_bind(path, row)
    originals = {r['name']: r for r in rows if r['role'] == 'original'}
    for row in rows:
        if row['role'] == 'upgrade-fixture':
            need(int(checked(['vercmp', row['version'], originals[row['name']]['version']], 'fixture version comparison').strip()) > 0, 'fixture version must be greater than original')
    report = {'status': 'FAIL', 'purpose': PURPOSE, 'contract': contract, 'guard': observed,
              'production_credentials_used': False, 'hardware_status': 'NOT RUN', 'signatures': {}}
    try:
        with gpg_home('cachy-asahi-test-sign-', '/tmp') as home:
            gpg = ['gpg', '--batch', '--no-options', '--homedir', str(home), '--no-auto-key-retrieve']
            uid = 'CACHY-ASAHI TEST ONLY ' + contract['nonce'] + ' <test-only@invalid.example>'
            checked(gpg + ['--pinentry-mode', 'loopback', '--passphrase', '', '--quick-generate-key', uid, 'rsa2048', 'sign', '1d'], 'ephemeral TEST key generation', 120)
            fp, expiry = fingerprint(home)
            certificate = output / 'public-key.asc'
            text = checked(gpg + ['--armor', '--export', fp], 'public certificate export')
            need(text.startswith('-----BEGIN PGP PUBLIC KEY BLOCK-----'), 'public certificate required')
            public_certificate(text.encode('ascii'))
            certificate.write_text(text); certificate.chmod(0o644)
            report.update(fingerprint=fp, expiry=expiry, public_certificate_sha256=native.sha(certificate))
            for row in rows:
                source = root / 'archives' / row['path']
                signature = output / 'signatures' / (row['path'] + '.sig')
                signature.parent.mkdir(parents=True, exist_ok=True)
                checked(gpg + ['--local-user', fp, '--digest-algo', 'SHA256', '--output', str(signature), '--detach-sign', str(source)], 'TEST detached signature')
                status = checked(gpg + ['--status-fd', '1', '--verify', str(signature), str(source)], 'TEST signature verification')
                native.valid_signature(status, fp)
                signature.chmod(0o644)
                report['signatures'][row['path']] = {'archive_sha256': row['sha256'], 'signature_sha256': native.sha(signature), 'status': status}
        report['status'] = STATUS
        return 0
    except (OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        report['error'] = type(error).__name__ + '; diagnostics suppressed'
        return 1
    finally:
        native.save(output / 'result.json', report)
        print(json.dumps({'status': report['status'], 'purpose': PURPOSE, 'hardware_status': 'NOT RUN'}))


def verify_exports(public, inputs, data):
    rows = validate_manifest(data)
    expected = {'result.json', 'public-key.asc'} | {'signatures/' + r['path'] + '.sig' for r in rows}
    found = set()
    directories = {parent.as_posix() for name in expected for parent in Path(name).parents if parent.as_posix() != '.'}
    for path in public.rglob('*'):
        need(not path.is_symlink(), 'symlink signer export refused')
        if path.is_file():
            regular(path); found.add(path.relative_to(public).as_posix())
        else:
            need(path.is_dir() and path.relative_to(public).as_posix() in directories, 'unexpected/nonregular signer export directory')
    need(found == expected, 'unexpected/missing signer public output')
    receipt_bytes = (public / 'result.json').read_bytes()
    need(len(receipt_bytes) <= LIMIT and b'PRIVATE KEY' not in receipt_bytes, 'oversized/private signer receipt')
    report = decode_json(receipt_bytes)
    permitted = {'status', 'purpose', 'contract', 'guard', 'production_credentials_used', 'hardware_status', 'signatures', 'fingerprint', 'expiry', 'public_certificate_sha256'}
    need(isinstance(report, dict) and set(report) == permitted, 'unexpected signer receipt fields')
    need(report.get('status') == STATUS and report.get('purpose') == PURPOSE and report.get('production_credentials_used') is False and report.get('hardware_status') == 'NOT RUN', 'successful TEST-only signing receipt required')
    signer_guard(report['guard'], report['contract'])
    need(set(report['signatures']) == {row['path'] for row in rows}, 'unexpected signature receipt paths')
    cert = public / 'public-key.asc'
    payload = cert.read_bytes()
    need(len(payload) <= LIMIT and payload.startswith(b'-----BEGIN PGP PUBLIC KEY BLOCK-----') and b'PRIVATE KEY' not in payload, 'invalid/private certificate export')
    public_certificate(payload)
    need(native.sha(cert) == report.get('public_certificate_sha256'), 'public certificate hash differs')
    with gpg_home('cachy-asahi-public-verify-') as home:
        fp, expiry = fingerprint(home, cert)
        need(report.get('fingerprint') == fp and report.get('expiry') == expiry, 'TEST identity/expiry differs from certificate')
        gpg = ['gpg', '--batch', '--no-options', '--homedir', str(home), '--no-auto-key-retrieve']
        checked(gpg + ['--import', str(cert)], 'temporary public-only certificate import')
        for row in rows:
            archive = inputs / 'archives' / row['path']; regular(archive)
            need(native.sha(archive) == row['sha256'], 'archive snapshot drift after signing')
            artifact_bind(archive, row)
            signature = public / 'signatures' / (row['path'] + '.sig')
            record = report.get('signatures', {}).get(row['path'], {})
            need(set(record) == {'archive_sha256', 'signature_sha256', 'status'}, 'unexpected signature record fields')
            native.valid_signature(record['status'], fp)
            need(signature.stat().st_size <= 8192 and record.get('archive_sha256') == row['sha256'] and record.get('signature_sha256') == native.sha(signature), 'detached signature/archive binding differs')
            status = checked(gpg + ['--status-fd', '1', '--verify', str(signature), str(archive)], 'independent public-only signature verification')
            native.valid_signature(status, fp)
    return report


def host(args):
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    record = {'status': 'FAIL', 'purpose': PURPOSE, 'hardware_status': 'NOT RUN'}
    name = None
    try:
        host_probe(out)
        need(re.fullmatch(r'sha256:[0-9a-f]{64}', args.image), 'locally present immutable image ID required')
        image = decode_json(run(['docker', 'image', 'inspect', args.image]))[0]
        need(image['Architecture'] == 'arm64' and image['Os'] == 'linux' and image['Id'] == args.image, 'native immutable signer image required')
        need(not any(',' in str(p) or '\n' in str(p) for p in (out, args.manifest.resolve())), 'unsafe bind mount path')
        regular(args.manifest)
        data = read_json(args.manifest, args.manifest_sha256); rows = validate_manifest(data)
        inputs = out / 'inputs'; inputs.mkdir(); (inputs / 'runner').mkdir()
        shutil.copyfile(__file__, inputs / 'runner/sign_fixture.py')
        shutil.copyfile(Path(native.__file__), inputs / 'runner/native_arm.py')
        # native_arm import needs only its trusted static checker dependency at import time.
        checks = inputs / 'scripts/checks'; checks.mkdir(parents=True)
        shutil.copyfile(native.ROOT / 'scripts/checks/package_checks.py', checks / 'package_checks.py')
        (inputs / 'manifest.json').write_bytes(args.manifest.read_bytes())
        need(native.sha(inputs / 'manifest.json') == args.manifest_sha256, 'manifest changed during snapshot')
        for row in rows:
            source = args.manifest.parent / row['path']; regular(source)
            need(native.sha(source) == row['sha256'], 'reviewed archive changed')
            artifact_bind(source, row)
            dest = inputs / 'archives' / row['path']; dest.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(source, dest)
            need(native.sha(dest) == row['sha256'], 'archive changed during snapshot')
        nonce = os.urandom(16).hex(); name = 'cachy-asahi-test-signer-' + nonce
        contract = {'schema_version': 1, 'purpose': PURPOSE, 'nonce': nonce, 'image_id': args.image,
                    'manifest_sha256': args.manifest_sha256, 'entry_sha256': native.sha(inputs / 'runner/sign_fixture.py'),
                    'helpers_sha256': {name: native.sha(inputs / name) for name in ('runner/native_arm.py', 'scripts/checks/package_checks.py')}}
        native.save(inputs / 'contract.json', contract)
        public = out / 'public'; public.mkdir()
        command = ['docker', 'run', '--rm', '--name', name, '--pull=never', '--platform=linux/arm64',
                   '--user', f'{os.getuid()}:{os.getgid()}', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                   '--read-only', '--network=none', '--cgroupns=private', '--pids-limit=128', '--memory=512m', '--cpus=2',
                   '--tmpfs', f'/tmp:rw,nosuid,nodev,exec,size=128m,mode=0700,uid={os.getuid()},gid={os.getgid()}',
                   '--env', f'CACHY_ASAHI_TEST_SIGNER={nonce}',
                   '--env', f'CACHY_ASAHI_SIGNER_CONTRACT_SHA256={native.sha(inputs / "contract.json")}',
                   '--mount', f'type=bind,src={inputs},dst=/inputs,readonly',
                   '--mount', f'type=bind,src={public},dst=/out', '--entrypoint=/usr/bin/python3',
                   args.image, '-B', '/inputs/runner/sign_fixture.py', '--inside']
        record.update(command=command, contract=contract, container=name, manifest_sha256=args.manifest_sha256)
        native.save(out / 'provenance.json', record)
        run(command, out / 'container.log', args.timeout)
        receipt = verify_exports(public, inputs, data)
        need(receipt.get('contract') == contract, 'container signing contract differs')
        record.update(status=STATUS, fingerprint=receipt['fingerprint'], expiry=receipt['expiry'],
                      public_outputs={str(p.relative_to(public)): native.sha(p) for p in public.rglob('*') if p.is_file()})
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        record['error'] = 'signer operation failed (' + type(error).__name__ + '); diagnostics suppressed'
        print(record['error'], file=sys.stderr)
    finally:
        # Repeated termination must not interrupt the bounded final cleanup/evidence.
        old_term, old_int = signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGTERM, signal.SIG_IGN); signal.signal(signal.SIGINT, signal.SIG_IGN)
        try:
            try:
                record['cleanup'] = remove_container(name) if name is not None else {'status': 'NOT RUN', 'container_absent': True}
            except (OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt) as error:
                record['cleanup'] = {'status': 'FAIL', 'container_absent': False, 'error_type': type(error).__name__}
            if record['cleanup']['status'] == 'FAIL':
                record['status'] = 'FAIL'
            native.save(out / 'provenance.json', record)
            print(json.dumps({'status': record['status'], 'purpose': PURPOSE, 'hardware_status': 'NOT RUN'}))
        finally:
            signal.signal(signal.SIGTERM, old_term); signal.signal(signal.SIGINT, old_int)
    return 0 if record['status'] == STATUS else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--image'); parser.add_argument('--manifest', type=Path)
    parser.add_argument('--manifest-sha256'); parser.add_argument('--output', type=Path)
    parser.add_argument('--timeout', type=int, default=180)
    args = parser.parse_args()
    with cancellation_scope():
        if args.inside:
            try:
                return inside()
            except (OSError, ValueError, KeyError, subprocess.SubprocessError, KeyboardInterrupt) as error:
                print(json.dumps({'status': 'FAIL', 'error': type(error).__name__, 'purpose': PURPOSE})); return 1
        need(args.image and args.manifest and args.manifest_sha256 and args.output and 1 <= args.timeout <= 300, 'explicit reviewed inputs/image/new output/timeout required')
        return host(args)


if __name__ == '__main__':
    sys.exit(main())
