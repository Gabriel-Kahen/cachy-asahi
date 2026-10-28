#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Private native KSM DEVELOPMENT TEST signing/container lifecycle worker.

Only fixed guarded container entry points are executable. No host install, key
custody, service activation, writable sysfs or release acceptance is provided.
"""
import argparse
from contextlib import contextmanager, nullcontext, redirect_stdout
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
from types import ModuleType

sys.dont_write_bytecode = True
ROOT = Path('/source')
HERE = 'scripts/port/ksm-lifecycle/worker.py'
BASE = 'scripts/client/stage.py'
GUARD = 'scripts/ci/source_suites.py'
CONTRACT = 'scripts/port/ksm-lifecycle/contract.py'
STAGE = 'scripts/port/ksm-lifecycle/stage.py'
BASE_SHA = '13c2108aa03d76305a16bf1c9d08aa610e51f54f7726e4732c13d0824e5733f5'
GUARD_SHA = '4bfec1387f87768e5b37475d6172bde302ef52c01c68f81297435048be7f2100'
LOCK_SHA = 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
INPUT_SHA = 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'
APPROVED_SHA = 'f933ccfcfb52ca97ea809d904344f6ec72eb5907ef458b5c2e7f7f1797dc1d44'
PURPOSE = 'ksm-diagnostic-development-lifecycle'
SCOPE = 'DEVELOPMENT TEST ONLY'
SAFE_CAPS = 0xcb
LIMIT = 1024 * 1024
TEST_ID = 'KSM DEVELOPMENT TEST ONLY <ksm-test@invalid.invalid>'
CHECKS = {
    'sign': ('guard', 'bindings', 'package-contract', 'baseline', 'sign', 'signature'),
    'lifecycle': ('guard', 'bindings', 'package-contract', 'baseline', 'signature',
                  'install', 'installed-payload', 'probes', 'remove', 'reinstall', 'final-remove', 'user-fixture'),
}
FIELDS = {'schema_version', 'purpose', 'scope', 'phase', 'nonce', 'source_commit', 'run_id',
          'daemon_id', 'image_id', 'uid', 'package', 'approved_inputs_sha256', 'bootstrap_sha256',
          'packages_sha256', 'current_inputs_sha256', 'source_sha256', 'signing'}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path, limit=LIMIT, *, metadata=None):
    path = Path(path).absolute()
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'unsafe-file-path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit, 'unsafe-file')
        if metadata is not None:
            need(all(type(metadata.get(key)) is int for key in ('mode', 'uid', 'gid'))
                 and (stat.S_IMODE(before.st_mode), before.st_uid, before.st_gid) ==
                 (metadata['mode'], metadata['uid'], metadata['gid']), 'captured-file-metadata')
        data = bytearray()
        while block := os.read(fd, min(65536, limit + 1 - len(data))):
            data.extend(block)
            need(len(data) <= limit, 'file-bound')
        after = os.fstat(fd)
        need(len(data) == before.st_size and (before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
             (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'file-changed')
        return bytes(data)
    finally:
        os.close(fd)


def checked(path, pin, limit=LIMIT, *, metadata=None):
    need(isinstance(pin, str) and re.fullmatch('[0-9a-f]{64}', pin), 'invalid-pin')
    data = read(path, limit) if metadata is None else read(path, limit, metadata=metadata)
    need(sha(data) == pin, 'changed-input')
    return data


def decode(data):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate-json-key')
            result[key] = value
        return result
    result = json.loads(data, object_pairs_hook=pairs,
                        parse_constant=lambda _: need(False, 'nonfinite-json'))
    need(isinstance(result, dict), 'object-required')
    return result


_MODULES = {}


def load(name, path, pin, *, data=None):
    path = Path(path).absolute()
    if data is None:
        data = checked(path, pin)
    else:
        need(isinstance(data, bytes) and len(data) <= LIMIT and isinstance(pin, str)
             and re.fullmatch('[0-9a-f]{64}', pin) and sha(data) == pin, 'captured-source-pin')
    key = (str(path), pin)
    if key in _MODULES:
        return _MODULES[key]
    module = ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = ''
    exec(compile(data, str(path), 'exec'), module.__dict__)
    _MODULES[key] = module
    return module


def native_guard(record, guard, uid=0):
    """Root lifecycle validates its actual writable overlay, never a fake record."""
    need(record['arch'] in {'aarch64', 'arm64'} and record['uid'] == uid and record['docker_marker'], 'native-container-required')
    need(record['interfaces'] == ['lo'] and not record['sockets'] and not record['unexpected_devices'], 'runtime-exposure')
    caps = record['capabilities']
    need(set(caps) == set(guard.CAPS) and all(type(v) is int and v >= 0 and v & ~SAFE_CAPS == 0 for v in caps.values()), 'excess-capabilities')
    if uid:
        need(caps['CapBnd'] == SAFE_CAPS and not any(caps[k] for k in ('CapEff', 'CapPrm', 'CapInh', 'CapAmb')), 'probe-capabilities')
    else:
        need(caps['CapEff'] == caps['CapPrm'] == caps['CapBnd'] == SAFE_CAPS and
             caps['CapInh'] == caps['CapAmb'] == 0, 'root-capability-contract')
    need(record['no_new_privs'] == 1 and record['source'] == '/source' and record['output'] == '/out'
         and record['paths_safe'] and record['home_safe'] and record['home'] == '/tmp/ksm-stage', 'worker-paths')
    mounts = record['mounts']
    need(not set(mounts) - (guard.STANDARD_MOUNTS | {'/', '/source', '/out', '/tmp'}), 'unexpected-mount')
    need(guard.READONLY_PROC <= set(mounts), 'missing-protected-proc')
    for point, (kinds, flags) in guard.STANDARD_TYPES.items():
        entry = mounts.get(point, {})
        need(entry.get('fs') in kinds and flags <= set(entry.get('options', [])) and
             not {'ro', 'rw'} <= set(entry['options']), 'runtime-mount')
    for point, mode in (('/', 'rw'), ('/source', 'ro'), ('/out', 'rw')):
        entry = mounts.get(point, {})
        need(entry.get('fs') in ({'overlay', 'fuse-overlayfs'} if point == '/' else guard.DATA_FILESYSTEMS)
             and set(entry.get('options', [])) & {'ro', 'rw'} == {mode}, 'root-or-binding-mount')
    tmp = mounts.get('/tmp', {})
    need(tmp.get('fs') == 'tmpfs' and {'rw', 'nosuid', 'nodev'} <= set(tmp.get('options', []))
         and not {'ro', 'noexec'} & set(tmp['options']), 'private-tmpfs')
    for point in guard.READONLY_PROC:
        entry = mounts[point]
        need(entry['fs'] == 'proc' and {'ro', 'nosuid', 'nodev', 'noexec'} <= set(entry['options'])
             and 'rw' not in entry['options'], 'protected-proc')
    for point in guard.EMPTY_MASKS & set(mounts):
        need(mounts[point]['fs'] == 'tmpfs' and set(mounts[point]['options']) & {'ro', 'rw'} == {'ro'}, 'empty-mask')
    for point in guard.NULL_MASKS & set(mounts):
        need(mounts[point]['fs'] == 'tmpfs' and record['null_masks'].get(point) is True, 'null-mask')
    for point in guard.RUNTIME_FILES:
        entry, info = mounts.get(point, {}), record['runtime_files'].get(point, {})
        need(entry.get('fs') in guard.DATA_FILESYSTEMS and set(entry.get('options', [])) & {'ro', 'rw'} in ({'ro'}, {'rw'})
             and info.get('regular') is True and info.get('uid') == 0 and not info.get('mode', 0o777) & 0o022, 'runtime-file')



def bounded_nodes(roots, required=None):
    required = required or {}
    found, count = {}, 0
    aliases = {'/dev/fd': '/proc/self/fd', '/dev/stdin': '/proc/self/fd/0', '/dev/stdout': '/proc/self/fd/1',
               '/dev/stderr': '/proc/self/fd/2', '/dev/core': '/proc/kcore', '/dev/ptmx': 'pts/ptmx'}
    for root in roots:
        for directory, dirs, files in os.walk(root, followlinks=False):
            for name in dirs + files:
                path = Path(directory) / name
                info = path.lstat()
                count += 1
                need(count <= 4096, 'runtime-node-bound')
                need(not stat.S_ISSOCK(info.st_mode) and not stat.S_ISBLK(info.st_mode), 'runtime-special-node')
                if stat.S_ISCHR(info.st_mode):
                    pair = os.major(info.st_rdev), os.minor(info.st_rdev)
                    need(required.get(str(path)) == pair, 'unexpected-character-device')
                    found[str(path)] = pair
                if stat.S_ISLNK(info.st_mode):
                    need(str(path) in aliases and os.readlink(path) == aliases[str(path)], 'runtime-alias')
    need(found == required, 'missing-standard-device')


def guard_entry(phase, probe=False):
    need(Path(__file__).absolute() == ROOT / HERE, 'fixed-worker-required')
    base = load('ksm_frozen_base', ROOT / BASE, BASE_SHA)
    guard = load('ksm_frozen_guard', ROOT / GUARD, GUARD_SHA)
    uid = os.environ.get('CACHY_ASAHI_CLIENT_UID', '')
    need(re.fullmatch('[1-9][0-9]{0,5}', uid) and int(uid) <= 65535, 'nonroot-uid-required')
    need(os.environ.get('HOME') == '/tmp/ksm-stage', 'fixed-home-required')
    if phase == 'sign':
        need(not probe, 'sign-probe-refused')
        record = guard.environment(ROOT, Path('/out'))
        guard.guard(record)
        need(guard.READONLY_PROC <= set(record['mounts']), 'missing-protected-proc-mount')
        need(os.geteuid() == os.getegid() == int(uid), 'uid-gid-mismatch')
    else:
        record = guard.environment(ROOT, Path('/out'))
        native_guard(record, guard, int(uid) if probe else 0)
        need(os.getegid() == (int(uid) if probe else 0), 'gid-mismatch')
    need(os.getpid() != 1 and os.getppid() == 1 if probe else os.getpid() == 1, 'private-pid-required')
    devices = {'/dev/null': (1, 3), '/dev/zero': (1, 5), '/dev/full': (1, 7), '/dev/random': (1, 8),
               '/dev/urandom': (1, 9), '/dev/tty': (5, 0), '/dev/pts/ptmx': (5, 2)}
    bounded_nodes(('/dev', '/run', '/source', '/out') if probe else ('/dev', '/run', '/source', '/out', '/tmp'), devices)
    if not probe:
        need(not list(Path('/tmp').iterdir()) and not list(Path('/out').iterdir()), 'fresh-private-mounts-required')
    return base


def bindings(phase, pin, *, probe=False):
    record = decode(checked(ROOT / 'inputs.json', pin))
    need(set(record) == FIELDS and type(record['schema_version']) is int and record['schema_version'] == 1
         and record['purpose'] == PURPOSE and record['scope'] == SCOPE and record['phase'] == phase, 'input-schema')
    need(type(record['uid']) is int and 0 < record['uid'] <= 65535 and str(record['uid']) == os.environ['CACHY_ASAHI_CLIENT_UID']
         and record['image_id'] == os.environ.get('CACHY_ASAHI_IMAGE_ID') and re.fullmatch('sha256:[0-9a-f]{64}', record['image_id']), 'identity-binding')
    for field, pattern in {'nonce': '[0-9a-f]{32}', 'source_commit': '[0-9a-f]{40}', 'run_id': '[1-9][0-9]{0,20}',
                           'daemon_id': '[A-Za-z0-9:._-]{1,128}'}.items():
        need(isinstance(record[field], str) and re.fullmatch(pattern, record[field]), 'job-binding')
    pins = record['source_sha256']
    need(isinstance(pins, dict) and set(pins) == {BASE, GUARD, HERE, CONTRACT, STAGE}
         and pins[BASE] == BASE_SHA and pins[GUARD] == GUARD_SHA, 'source-set')
    captured = {path: checked(ROOT / path, checksum) for path, checksum in pins.items()}
    lock = checked(ROOT / 'packages.lock', record['packages_sha256'])
    need(record['packages_sha256'] == LOCK_SHA and read('/builder-packages.lock') == lock, 'builder-lock')
    checked(ROOT / 'current-inputs.json', record['current_inputs_sha256'])
    need(record['current_inputs_sha256'] == INPUT_SHA, 'current-inputs')
    approved = decode(checked(ROOT / 'approved-inputs.json', record['approved_inputs_sha256']))
    need(record['approved_inputs_sha256'] == APPROVED_SHA, 'approved-map')
    bootstrap = decode(checked(ROOT / 'bootstrap.json', record['bootstrap_sha256']))
    need(bootstrap.get('status') == 'image-provisioned' and bootstrap.get('image_id') == record['image_id']
         and bootstrap.get('inputs_sha256') == INPUT_SHA and bootstrap.get('packages_lock_sha256') == LOCK_SHA, 'bootstrap-binding')
    contract = load('ksm_archive_contract', ROOT / CONTRACT, pins[CONTRACT], data=captured[CONTRACT])
    package = record['package']
    need(isinstance(package, dict) and package.get('status') == 'PASS-build-pair-contract', 'package-pair-required')
    filename = package.get('filename', '')
    need(isinstance(filename, str) and '/' not in filename and re.fullmatch('[A-Za-z0-9._+-]{1,160}', filename), 'package-filename')
    archive = read(ROOT / filename, contract.MAX_FILE)
    verified = contract.validate_archive(archive, approved, lock, package['source_date_epoch'], filename)
    for key, value in verified.items():
        need(package.get(key) == value, 'package-identity-mismatch')
    need(package.get('image_id') == record['image_id'] and package.get('expected_packages_sha256') == LOCK_SHA
         and package.get('approved_inputs_sha256') == APPROVED_SHA and isinstance(package.get('comparisons'), dict) and set(package['comparisons']) ==
         {'bytes_equal', 'payload_equal', 'pkginfo_equal', 'buildinfo_equal'}
         and all(value is True for value in package['comparisons'].values()), 'package-pair-bindings')
    if phase == 'sign':
        need(record['signing'] is None, 'sign-input-key-refused')
    else:
        signing = record['signing']
        need(isinstance(signing, dict) and set(signing) == {'fingerprint', 'signature_sha256', 'public_key_sha256'}
             and isinstance(signing['fingerprint'], str) and re.fullmatch('[0-9A-F]{40}', signing['fingerprint']), 'signing-schema')
        checked(ROOT / 'package.sig', signing['signature_sha256'], 65536)
        checked(ROOT / 'public.gpg', signing['public_key_sha256'], 65536)
    return record, contract, lock


def run(command, env, timeout=45, *, pass_fds=()):
    """Bound stdout and stderr together, retain them separately and privately."""
    base = _MODULES.get((str(ROOT / BASE), BASE_SHA))
    need(not base or not base.CANCELLED, 'cancelled-command')
    blocked = {signal.SIGTERM, signal.SIGINT}
    old = signal.pthread_sigmask(signal.SIG_BLOCK, blocked)
    process, data = None, [bytearray(), bytearray()]
    try:
        process = subprocess.Popen([str(v) for v in command], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=env, start_new_session=True, pass_fds=pass_fds,
                                   preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, old))
        signal.pthread_sigmask(signal.SIG_SETMASK, old)
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, 0)
            selector.register(process.stderr, selectors.EVENT_READ, 1)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                need(remaining > 0, 'command-timeout')
                for key, _ in selector.select(min(remaining, .2)):
                    block = os.read(key.fd, 65536)
                    if block:
                        data[key.data].extend(block)
                        need(sum(map(len, data)) <= LIMIT, 'command-output-bound')
                    else:
                        selector.unregister(key.fileobj)
        code = process.wait(timeout=max(.01, deadline - time.monotonic()))
        return code, bytes(data[0]), bytes(data[1])
    finally:
        base = _MODULES.get((str(ROOT / BASE), BASE_SHA))
        with base.defer_signals() if base else nullcontext():
            signal.pthread_sigmask(signal.SIG_SETMASK, old)
            if process:
                try:
                    for signum in (signal.SIGTERM, signal.SIGKILL):
                        try:
                            os.killpg(process.pid, signum)
                        except (ProcessLookupError, PermissionError):
                            pass
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        raise ValueError('private-command-not-reaped') from None
                finally:
                    process.stdout.close()
                    process.stderr.close()


def success(command, env, **kwargs):
    code, stdout, _ = run(command, env, **kwargs)
    need(code == 0, 'command-failed')
    return stdout



def pacman_success(command, env, **kwargs):
    """libalpm can exit zero after ancillary errors; inspect both private streams."""
    need(command and str(command[0]) == '/usr/bin/pacman', 'pacman-command-required')
    code, stdout, stderr = run(command, env, **kwargs)
    need(code == 0, 'pacman-command-failed')
    diagnostics = stdout + b'\n' + stderr
    need(not re.search(rb'(?i)(?:\berror:|could\s+not\s+change\s+(?:the\s+root\s+directory|root(?:\s+directory)?|directory)\b)', diagnostics),
         'pacman-positive-diagnostic-error')
    return stdout


def gpg(home):
    return ['/usr/bin/gpg', '--batch', '--no-options', '--homedir', str(home), '--no-default-keyring',
            '--keyring', str(home / 'pubring.gpg'), '--no-auto-key-retrieve', '--auto-key-locate', 'clear']


def public_identity(listing, expected=None):
    rows = [line.split(':') for line in listing.decode('ascii').splitlines()]
    pubs = [r for r in rows if r[0] == 'pub']
    users = [r[9] for r in rows if r[0] == 'uid' and len(r) > 9]
    fps = [r[9] for r in rows if r[0] == 'fpr' and len(r) > 9]
    need(users == [TEST_ID] and len(pubs) == 1 and len(fps) == 1 and not any(r[0] in {'sub', 'sec', 'ssb'} for r in rows), 'single-public-primary-required')
    pub = pubs[0]
    need(len(pub) > 16 and pub[16] == 'ed25519' and pub[1] not in {'r', 'e', 'd', 'i'} and pub[3] == '22'
         and int(pub[5]) <= time.time() < int(pub[6]) <= int(pub[5]) + 86400
         and 's' in pub[11].lower() and re.fullmatch('[0-9A-F]{40}', fps[0]), 'bounded-ed25519-signing-key-required')
    need(expected is None or expected == fps[0], 'wrong-primary')
    return fps[0]


def signature_status(data, fp):
    rows = [line.split()[1:] for line in data.decode('utf-8').splitlines() if line.startswith('[GNUPG:] ')]
    forbidden = {'EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'BADSIG', 'ERRSIG', 'NO_PUBKEY', 'KEYEXPIRED',
                 'SIGEXPIRED', 'KEYREVOKED', 'FAILURE', 'ERROR', 'NODATA'}
    need(not any(r and r[0] in forbidden for r in rows), 'invalid-signature')
    valid = [r for r in rows if r and r[0] == 'VALIDSIG']
    good = [r for r in rows if r and r[0] == 'GOODSIG']
    need(len(valid) == len(good) == 1 and len(valid[0]) == 11 and valid[0][1] == valid[0][-1] == fp
         and valid[0][7:10] == ['22', '8', '00'] and good[0][1] == fp[-16:]
         and valid[0][3].isdecimal() and 0 <= time.time() - int(valid[0][3]) < 86400
         and valid[0][4] == '0' and valid[0][5:7] == ['4', '0'], 'pinned-primary-sha256-required')


def create_key(home, env):
    home.mkdir(mode=0o700)
    (home / 'gpg.conf').write_text(f'no-default-keyring\nkeyring {home}/pubring.gpg\nno-auto-key-retrieve\nauto-key-locate clear\n')
    success(gpg(home) + ['--pinentry-mode', 'loopback', '--passphrase', '', '--quick-generate-key',
                         TEST_ID, 'ed25519', 'sign', '1d'], env)
    return public_identity(success(gpg(home) + ['--with-colons', '--list-keys'], env))


def sign_package(record, home, env):
    keys = home / 'signer'
    fp = create_key(keys, env)
    package = ROOT / record['package']['filename']
    success(gpg(keys) + ['--local-user', fp, '--digest-algo', 'SHA256', '--output', '/out/package.sig', '--detach-sign', package], env)
    success(gpg(keys) + ['--output', '/out/public.gpg', '--export', fp], env)
    verify_signature(keys, package, Path('/out/package.sig'), Path('/out/public.gpg'), fp, env)
    return {'fingerprint': fp, 'signature_sha256': sha(read('/out/package.sig', 65536)),
            'public_key_sha256': sha(read('/out/public.gpg', 65536))}


def verify_signature(keys, package, signature, public, fp, env):
    public_identity(success(gpg(keys) + ['--with-colons', '--show-keys', public], env), fp)
    status = success(gpg(keys) + ['--status-fd', '1', '--verify', signature, package], env)
    signature_status(status, fp)


def file_state(path):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'fixture-regular-required')
    return (read(path), stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid, info.st_mtime_ns)



def payload_parents(path):
    for parent in path.parents:
        try:
            info = parent.lstat()
        except FileNotFoundError:
            continue
        need(stat.S_ISDIR(info.st_mode), 'payload-parent-not-real-directory')


def absent_payload(package):
    for name in package['payload']:
        path = Path('/') / name
        payload_parents(path)
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        need(False, 'preexisting-or-remaining-payload')


def owned_payload(data, package):
    """Only the five file names and their finite archive ancestor directories."""
    files = {'/' + name for name in package['payload']}
    directories = {str(parent) + '/' for name in files for parent in PurePosixPath(name).parents if str(parent) != '/'}
    seen, actual = set(), set()
    for line in data.decode('ascii').splitlines(keepends=True):
        need(line.endswith('\n'), 'owned-path-line')
        name = line[:-1]
        need(name not in seen and name in files | directories, 'unexpected-owned-path')
        seen.add(name)
        if name in files:
            actual.add(name)
    need(actual == files, 'owned-payload-set')


def hooks_state():
    states = {}
    for directory in ('/usr/share/libalpm/hooks', '/etc/pacman.d/hooks'):
        path = Path(directory)
        payload_parents(path)
        need(not path.is_symlink(), 'hook-directory-alias')
        if not path.exists():
            continue
        need(path.is_dir(), 'hook-directory-required')
        entries = list(path.iterdir())
        need(len(entries) <= 1024, 'hook-count-bound')
        for entry in entries:
            need(re.fullmatch(r'[A-Za-z0-9_.+-]+\.hook', entry.name), 'unexpected-hook-entry')
            if entry.is_symlink():
                need(os.readlink(entry) == '/dev/null', 'unexpected-hook-alias')
                states[str(entry)] = ('null-mask',)
            else:
                states[str(entry)] = file_state(entry)
    return states


def mask_hooks(destination):
    """libalpm's later HookDir disables matching basenames via /dev/null."""
    before = hooks_state()
    for source in before:
        target = destination / Path(source).name
        if not target.is_symlink():
            need(not target.exists(), 'hook-mask-collision')
            target.symlink_to('/dev/null')
        need(os.readlink(target) == '/dev/null', 'wrong-hook-mask')
    need(hooks_state() == before, 'image-hooks-changed')
    return before


def installed_payload(package):
    for name, entry in package['payload'].items():
        path = Path('/') / name
        payload_parents(path)
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == entry['uid'] and info.st_gid == entry['gid']
             and stat.S_IMODE(info.st_mode) == entry['mode'] and sha(read(path)) == entry['sha256'], 'installed-payload-mismatch')


def inventory(data, expected):
    rows = {}
    for line in data.decode('ascii').splitlines(keepends=True):
        need(re.fullmatch('[a-z0-9][a-z0-9@._+-]* [A-Za-z0-9:._+~-]+\n', line), 'invalid-inventory-row')
        name, version = line.rstrip('\n').split(' ')
        need(name not in rows, 'duplicate-package')
        rows[name] = version
    need(rows == expected, 'package-inventory-drift')
    return rows


@contextmanager
def sealed_python(data, base):
    """Expose captured source only through an immutable inherited descriptor."""
    fd = None
    try:
        with base.defer_signals():
            need(isinstance(data, bytes) and 0 < len(data) <= LIMIT, 'sealed-source-bound')
            fd = os.memfd_create('ksm-reviewed-python', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            remaining = memoryview(data)
            while remaining:
                written = os.write(fd, remaining)
                need(written > 0, 'short-sealed-source-write')
                remaining = remaining[written:]
            seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
            need(fcntl.fcntl(fd, fcntl.F_GET_SEALS) == seals, 'unsealed-python-source')
        yield fd
    finally:
        with base.defer_signals():
            if fd is not None:
                os.close(fd)


def probe(pin):
    base = guard_entry('lifecycle', probe=True)
    record, _, _ = bindings('lifecycle', pin, probe=True)
    installed_payload(record['package'])
    home = Path('/tmp/ksm-stage')
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'TMPDIR': str(home / 'tmp'), 'LC_ALL': 'C'}
    executable = '/usr/bin/cachy-asahi-ksmctl'
    source_metadata = record['package']['payload'][executable.lstrip('/')]
    source_pin = source_metadata['sha256']
    captured = checked(executable, source_pin, metadata=source_metadata)
    with sealed_python(captured, base) as fd:
        runner = f"import sys;sys.argv[0]={executable!r};exec(compile(open('/proc/self/fd/{fd}','rb').read(),{executable!r},'exec'),{{'__name__':'__main__','__file__':{executable!r},'__package__':None}})"
        command = [sys.executable, '-I', '-B', '-c', runner]
        for args, expected in ((['--help'], 0), (['--version'], 0), (['--enable'], 2), (['--disable'], 2)):
            need(run([*command, *args], env, pass_fds=(fd,))[0] == expected, 'installed-cli-behavior')
        code, actual, _ = run([*command, '--status', '--json'], env, pass_fds=(fd,))
    need(code in {0, 3}, 'actual-readonly-status-failed')
    if code == 0:
        need(decode(actual).get('management_available') is False, 'unexpected-management')
    fixture = home / 'ksm-fixture'
    before = {p.name: file_state(p) for p in fixture.iterdir()}
    module = load('installed_ksm_fixture', executable, source_pin, data=captured)
    with redirect_stdout(io.StringIO()) as output:
        need(module.main(['--status', '--json'], root=fixture) == 0, 'fixture-status')
    need(decode(output.getvalue()).get('state', {}).get('run') == 1, 'fixture-state')
    for size, mib in ((4096, '0.01171875'), (16384, '0.046875')):
        report = module.report(fixture, page_size=size)
        need(report['page_size_bytes'] == size and report['counters']['pages_sharing']['mib'] == mib
             and report['management_available'] is False, 'fixture-page-conversion')
    need(before == {p.name: file_state(p) for p in fixture.iterdir()}, 'fixture-mutated')
    print(json.dumps({'status': 'PASS', 'actual_status_exit': code, 'fixture_4k': 'PASS', 'fixture_16k': 'PASS'}))
    return 0


def lifecycle(record, contract, lock, home, env, mark, pin):
    expected = contract._inventory(lock)
    keys = home / 'verifier'
    certifier = create_key(keys, env)
    fp = record['signing']['fingerprint']
    public = ROOT / 'public.gpg'
    public_identity(success(gpg(keys) + ['--with-colons', '--show-keys', public], env), fp)
    success(gpg(keys) + ['--import', public], env)
    success(gpg(keys) + ['--local-user', certifier, '--quick-lsign-key', fp], env)
    success(gpg(keys) + ['--check-trustdb'], env)
    package = ROOT / record['package']['filename']
    verify_signature(keys, package, ROOT / 'package.sig', public, fp, env)
    mark('signature')
    transaction = home / 'transaction'
    transaction.mkdir(mode=0o700)
    local = transaction / record['package']['filename']
    local.write_bytes(checked(package, record['package']['sha256'], contract.MAX_FILE))
    Path(str(local) + '.sig').write_bytes(checked(ROOT / 'package.sig', record['signing']['signature_sha256'], 65536))
    package = local
    # No repo sections; only the supplied signed local file can enter this image.
    config = home / 'pacman.conf'
    config.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\n')
    cache, hooks = home / 'cache', home / 'empty-hooks'
    cache.mkdir(); hooks.mkdir()
    base_hooks = mask_hooks(hooks)
    command = ['/usr/bin/pacman', '--config', config, '--dbpath', '/var/lib/pacman', '--cachedir', cache,
               '--gpgdir', keys, '--hookdir', hooks, '--logfile', home / 'pacman.log', '--noconfirm', '--color', 'never']
    name = contract.NAME
    fixture = home / 'user-owned.conf'
    fixture.write_bytes(b'KSM DEVELOPMENT TEST user fixture\n')
    fixture.chmod(0o600); os.chown(fixture, record['uid'], record['uid'])
    os.utime(fixture, ns=(1700000000000000000, 1700000000000000000))
    preserved = file_state(fixture)
    ksm = home / 'ksm-fixture'
    ksm.mkdir(mode=0o700); os.chown(ksm, record['uid'], record['uid'])
    for counter, value in {'run': 1, 'pages_shared': 2, 'pages_sharing': 3, 'general_profit': 4096}.items():
        path = ksm / counter
        path.write_text(str(value) + '\n'); path.chmod(0o600); os.chown(path, record['uid'], record['uid'])
    def state(installed):
        wanted = expected | ({name: contract.VERSION} if installed else {})
        inventory(pacman_success(command + ['-Q'], env), wanted)
        need(file_state(fixture) == preserved, 'user-fixture-changed')
        need(hooks_state() == base_hooks, 'image-owned-hooks-changed')
        if installed:
            installed_payload(record['package'])
            owned_payload(pacman_success(command + ['-Qql', name], env), record['package'])
        else:
            absent_payload(record['package'])
    state(False)
    probe_cmd = ['/usr/bin/setpriv', '--reuid', str(record['uid']), '--regid', str(record['uid']), '--clear-groups',
                 '--no-new-privs', '/usr/bin/python', '-I', ROOT / HERE,
                 '--phase', 'lifecycle', '--probe', '--contract-sha256', pin]
    for repeated in (False, True):
        pacman_success(command + ['-U', '--noscriptlet', package], env, timeout=90)
        state(True)
        if not repeated:
            mark('install'); mark('installed-payload')
        else:
            mark('reinstall')
        result = decode(success(probe_cmd, env))
        need(set(result) == {'status', 'actual_status_exit', 'fixture_4k', 'fixture_16k'} and result['status'] == 'PASS'
             and result['actual_status_exit'] in {0, 3} and result['fixture_4k'] == result['fixture_16k'] == 'PASS', 'probe-receipt')
        if not repeated:
            mark('probes')
        pacman_success(command + ['-R', '--noscriptlet', name], env, timeout=90)
        state(False)
        mark('final-remove' if repeated else 'remove')
    mark('user-fixture')



def cleanup_private(home, base):
    """Attempt both cleanups; different-UID leftovers remain a failing outcome."""
    result = {'processes': 'FAIL', 'tmpfs': 'FAIL'}
    with base.defer_signals():
        try:
            if base.cleanup_processes():
                result['processes'] = 'PASS'
        except (ValueError, OSError):
            pass
        try:
            os.chdir('/tmp')
            shutil.rmtree(home)
            if not list(Path('/tmp').iterdir()):
                result['tmpfs'] = 'PASS'
        except (ValueError, OSError):
            pass
    return result



def persist_receipt(path, report, phase, base, *, existing=False):
    """Set permissions before authoritative bytes; observe cancellation at fsync."""
    path = Path(path)
    flags = os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    if not existing:
        flags |= os.O_CREAT | os.O_EXCL
    with base.defer_signals():
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            info = os.fstat(stream.fileno())
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
                 and info.st_size <= LIMIT, 'receipt-file-contract')
            if not existing and phase == 'lifecycle':
                path.chmod(0o644)
            def reconcile():
                if base.CANCELLED:
                    report.update(status='FAIL', cancelled=True)
            def write():
                data = json.dumps(report, sort_keys=True, indent=2).encode() + b'\n'
                need(len(data) <= LIMIT, 'receipt-byte-bound')
                stream.seek(0); stream.truncate()
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
            reconcile()
            write()
            if base.CANCELLED and (report['status'] != 'FAIL' or report.get('cancelled') is not True):
                reconcile()
                write()


def main_worker(phase, pin, *, completed_report=None):
    base = guard_entry(phase)
    record, contract, lock = bindings(phase, pin)
    home = Path('/tmp/ksm-stage')
    os.umask(0o077)
    home.mkdir(mode=0o700)
    if phase == 'lifecycle':
        os.chown(home, record['uid'], record['uid'])
    env = base.controlled_env(home)
    env.update(CACHY_ASAHI_CLIENT_UID=str(record['uid']), CACHY_ASAHI_IMAGE_ID=record['image_id'])
    for field in ('TMPDIR', 'GNUPGHOME', 'XDG_RUNTIME_DIR', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME'):
        Path(env[field]).mkdir(mode=0o700)
        if phase == 'lifecycle':
            os.chown(env[field], record['uid'], record['uid'])
    os.environ.clear(); os.environ.update(env)
    report = {key: record[key] for key in ('nonce', 'image_id', 'source_commit', 'source_sha256', 'packages_sha256')}
    report.update(schema_version=1, purpose=PURPOSE, scope=SCOPE, phase=phase, status='FAIL',
                  package_sha256=record['package']['sha256'], signing=record['signing'], checks=[],
                  cleanup={'processes': 'FAIL', 'tmpfs': 'FAIL'}, hardware='NOT RUN', management='NOT RUN')
    def mark(name):
        need(name in CHECKS[phase] and not any(r['name'] == name for r in report['checks']), 'check-name')
        report['checks'].append({'name': name, 'status': 'PASS'})
    mark('guard'); mark('bindings'); mark('package-contract')
    aborted = False
    try:
        config = home / 'query.conf'
        config.write_text('[options]\nArchitecture = aarch64\n')
        inventory(pacman_success(['/usr/bin/pacman', '--config', config, '--dbpath', '/var/lib/pacman', '-Q'], env), contract._inventory(lock))
        absent_payload(record['package'])
        mark('baseline')
        if phase == 'sign':
            report['signing'] = sign_package(record, home, env)
            mark('sign'); mark('signature')
        else:
            lifecycle(record, contract, lock, home, env, mark, pin)
            report['signing'] = record['signing']
    except (Exception, base.Cancelled, KeyboardInterrupt):
        aborted = True
    finally:
        report['cleanup'] = cleanup_private(home, base)
    try:
        with base.defer_signals():
            report['status'] = 'PASS' if not base.CANCELLED and len(report['checks']) == len(CHECKS[phase]) and \
                set(report['cleanup'].values()) == {'PASS'} and not aborted else 'FAIL'
            if base.CANCELLED:
                report['cancelled'] = True
            if report['status'] != 'PASS' and phase == 'sign':
                for filename in ('package.sig', 'public.gpg'):
                    (Path('/out') / filename).unlink(missing_ok=True)
                report['signing'] = None
            persist_receipt('/out/worker-receipt.json', report, phase, base)
    except (base.Cancelled, KeyboardInterrupt):
        # Restoring the raising handler can interrupt the deferral's own exit.
        base.CANCELLED = True
        report.update(status='FAIL', cancelled=True)
        persist_receipt('/out/worker-receipt.json', report, phase, base,
                        existing=Path('/out/worker-receipt.json').exists())
    # A cancellation remembered while the final deferral unwinds cannot return PASS.
    if base.CANCELLED and (report['status'] != 'FAIL' or report.get('cancelled') is not True):
        report.update(status='FAIL', cancelled=True)
        persist_receipt('/out/worker-receipt.json', report, phase, base, existing=True)
    if completed_report is not None:
        completed_report['report'] = report
    return 0 if report['status'] == 'PASS' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', choices=('sign', 'lifecycle'), required=True)
    parser.add_argument('--contract-sha256', required=True)
    parser.add_argument('--probe', action='store_true')
    args = parser.parse_args()
    base, completed = None, {}
    try:
        if args.probe:
            need(args.phase == 'lifecycle', 'invalid-probe-phase')
            return probe(args.contract_sha256)
        # Loading a checksum-pinned helper is the sole operation preceding the real guard.
        base = load('ksm_entry_base', ROOT / BASE, BASE_SHA)
        with base.cancellation_handlers():
            # The cached checksum-pinned helper shares the cancellation flag.
            return main_worker(args.phase, args.contract_sha256, completed_report=completed)
    except KeyboardInterrupt:
        # A caller SIGINT handler can raise while cancellation_handlers exits.
        if base is not None and 'report' in completed:
            base.CANCELLED = True
            completed['report'].update(status='FAIL', cancelled=True)
            try:
                persist_receipt('/out/worker-receipt.json', completed['report'], args.phase, base, existing=True)
            except BaseException:
                pass  # A failed rewrite still cannot produce successful exit.
        print('KSM DEVELOPMENT TEST worker cancelled', file=sys.stderr)
        return 1
    except BaseException:
        print('KSM DEVELOPMENT TEST worker refused or failed', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
