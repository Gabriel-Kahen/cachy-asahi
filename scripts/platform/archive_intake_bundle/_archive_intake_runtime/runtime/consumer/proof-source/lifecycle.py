#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real package lifecycle ONLY inside an explicitly contracted disposable Docker root."""
import argparse
import io
import selectors
import signal
import time
import grp
import shutil
import hashlib
import json
import os
import platform
import pwd
import re
import shlex
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

PRIMARY_FILES = {'cachy-asahi-hyprland-settings': 'usr/share/cachy-asahi/hyprland/hyprland.lua',
    'cachy-asahi-fish-config': 'usr/share/cachy-asahi/fish/config.fish',
    'cachy-asahi-zsh-config': 'usr/share/cachy-asahi/zsh/config.zsh',
    'cachy-asahi-setup': 'usr/bin/cachy-asahi-setup'}
PACKAGES = {'cachy-asahi-hyprland-settings': 'hyprland', 'cachy-asahi-fish-config': 'fish',
            'cachy-asahi-zsh-config': 'zsh', 'cachy-asahi-setup': 'setup'}
META = {'.PKGINFO', '.BUILDINFO', '.MTREE', '.Changelog'}
HASH = re.compile(r'[0-9a-f]{64}\Z')
FIXED_HELPER = '/usr/bin/cachy-asahi-setup'
BASELINE_HELPER_SHA256 = 'a6251142b9c7e54796285c1a301fb590599d8aaa1625ea0bfebd7fc21622fdc2'
NULL_MASKS = {'/proc/kcore', '/proc/keys', '/proc/latency_stats', '/proc/timer_list',
              '/proc/timer_stats', '/proc/sched_debug', '/proc/interrupts'}
DIRECTORY_MASKS = {'/proc/acpi', '/proc/scsi', '/proc/asound', '/sys/firmware',
                   '/sys/devices/virtual/powercap'}
PROC_READONLY = {'/proc/bus', '/proc/fs', '/proc/irq', '/proc/sys', '/proc/sysrq-trigger'}
SAFE_CAPS = sum(1 << bit for bit in (0, 1, 3, 5, 6, 7))  # CHOWN, DAC_OVERRIDE, FOWNER, KILL, SETGID, SETUID
INPUT_ROOT = Path('/inputs')
ACCOUNT_FILES = tuple(Path('/etc') / (name + suffix) for name in ('passwd', 'shadow', 'group', 'gshadow', 'subuid', 'subgid') for suffix in ('', '-'))
LIFECYCLE_GATES = {'baseline-installed-exact-inventory', 'upgraded-exact-inventory', 'reinstalled-exact-inventory',
    'fresh-preview-readonly', 'fresh-repeat-idempotent', 'existing-prefix-and-modes', 'base-session-config-preserved',
    'upgrade-refreshes-unmodified-copy', 'upgrade-preserves-edited-copy', 'package-removal-preserves-user-files',
    'fresh-deactivation-removes-owned-files', 'existing-deactivation-surgical', 'existing-edited-desktop-remains',
    'interrupted-activate-recovered', 'interrupted-remove-recovered', 'inside-block-edit-preserved',
    'edited-block-repeat-preserved', 'default-login-shells-unchanged', 'final-base-config-preserved'}


class Error(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Error(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def safe_relative(value):
    require(isinstance(value, str) and value and not any(ord(c) < 32 or ord(c) == 127 for c in value), 'invalid input path')
    parts = value.split('/')
    require(all(p not in ('', '.', '..') for p in parts) and '\\' not in value and not value.startswith('/'), 'escaping input path')
    return value


def regular(path):
    for item in (path, *path.parents):
        require(not item.is_symlink(), 'symlink input refused')
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'input must be a singly linked regular file')


def pinned(root, relative, digest):
    path = root / safe_relative(relative)
    require(isinstance(digest, str) and HASH.fullmatch(digest), 'invalid SHA-256 pin')
    regular(path)
    require(sha(path) == digest, 'input checksum differs from reviewed contract')
    return path


def strict_json(text):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'duplicate contract/state JSON key')
            result[key] = value
        return result
    def constant(value):
        raise Error('nonfinite JSON value refused')
    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def mounts(text):
    result = {}
    for row in text.splitlines():
        columns = row.split()
        require(len(columns) >= 10 and '-' in columns, 'invalid mount inventory')
        separator = columns.index('-')
        point = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), columns[4])
        result[point] = {'options': columns[5].split(','), 'fs': columns[separator + 1]}
    return result


def privilege_status(text):
    rows = dict(row.split(':', 1) for row in text.splitlines() if ':' in row)
    result = {}
    for name in ('CapEff', 'CapPrm', 'CapBnd', 'CapInh', 'CapAmb'):
        value = rows.get(name, '').strip()
        require(re.fullmatch(r'[0-9a-fA-F]+', value), 'missing/malformed capability observation')
        result[name] = int(value, 16)
    value = rows.get('NoNewPrivs', '').strip()
    require(value in ('0', '1'), 'missing/malformed NNP observation')
    result['NoNewPrivs'] = int(value)
    return result


def actual_environment():
    marker = Path('/.dockerenv')
    status = privilege_status(Path('/proc/self/status').read_text())
    devices = any(Path(p).exists() for p in ('/dev/dri', '/dev/snd', '/dev/input', '/dev/mem', '/dev/kvm', '/dev/fuse'))
    devices |= any(stat.S_ISBLK(p.lstat().st_mode) for p in Path('/dev').rglob('*') if not p.is_symlink())
    table = mounts(Path('/proc/self/mountinfo').read_text())
    mask_nodes = {}
    for point in set(table) & (NULL_MASKS | DIRECTORY_MASKS):
        item = Path(point).lstat()
        mask_nodes[point] = {'symlink': stat.S_ISLNK(item.st_mode),
            'kind': 'char' if stat.S_ISCHR(item.st_mode) else 'directory' if stat.S_ISDIR(item.st_mode) else 'other',
            'device': [os.major(item.st_rdev), os.minor(item.st_rdev)] if stat.S_ISCHR(item.st_mode) else None}
    return {'uid': os.geteuid(), 'caps': status['CapEff'], 'privileges': status, 'device_exposure': devices, 'arch': platform.machine(),
            'docker_marker': marker.is_file() and not marker.is_symlink() and marker.stat().st_uid == 0,
            'mounts': table, 'mask_nodes': mask_nodes,
            'interfaces': sorted(p.name for p in Path('/sys/class/net').iterdir()),
            'docker_socket': any(Path(p).exists() for p in ('/run/docker.sock', '/var/run/docker.sock')),
            'nonce': os.environ.get('CACHY_ASAHI_DISPOSABLE_LIFECYCLE'),
            'image_id': os.environ.get('CACHY_ASAHI_IMAGE_ID')}


def mount_role(entry, filesystems, access, security=()):
    options = entry.get('options')
    if not isinstance(options, list) or not all(isinstance(v, str) for v in options):
        return False
    flags = set(options)
    return (entry.get('fs') in filesystems and flags & {'ro', 'rw'} == {access}
            and set(security) <= flags)


def environment_guard(probe, nonce=None, image_id=None):
    require(probe.get('docker_marker') is True, 'actual Docker marker required; host execution refused')
    require(probe.get('uid') == 0 and probe.get('arch') == 'aarch64', 'native aarch64 container root required')
    privileges = probe.get('privileges')
    require(isinstance(privileges, dict) and type(privileges.get('NoNewPrivs')) is int and privileges['NoNewPrivs'] == 1, 'no-new-privileges observation required')
    for name in ('CapEff', 'CapPrm', 'CapBnd', 'CapInh', 'CapAmb'):
        value = privileges.get(name)
        require(type(value) is int and value >= 0 and not value & ~SAFE_CAPS, 'unsafe/missing capability set: ' + name)
    require(privileges['CapEff'] & (1 << 5), 'CAP_KILL required for bounded demoted-child cleanup')
    require(probe.get('caps') == privileges['CapEff'] and probe.get('device_exposure') is False, 'privileged capabilities/device exposure refused')
    require(probe.get('interfaces') == ['lo'] and not probe.get('docker_socket'), 'network/socket exposure refused')
    table = probe['mounts']
    require(mount_role(table.get('/', {}), ('overlay', 'fuse-overlayfs'), 'rw'), 'writable disposable overlay root required')
    require('/inputs' in table and set(table['/inputs']['options']) & {'ro', 'rw'} == {'ro'}, 'read-only /inputs mount required')
    require('/out' in table and set(table['/out']['options']) & {'ro', 'rw'} == {'rw'}, 'explicit /out evidence mount required')
    require('/runner' in table and set(table['/runner']['options']) & {'ro', 'rw'} == {'ro'}, 'read-only /runner mount required')
    require({'/proc', '/sys', '/dev'} <= set(table), 'standard kernel/device mounts required')
    protected = ('/etc', '/usr', '/var', '/home', '/tmp', '/root')
    standard = {'/etc/hosts', '/etc/hostname', '/etc/resolv.conf'}
    for path, entry in table.items():
        if any(path == root or path.startswith(root + '/') for root in protected):
            require(path in standard or (path == '/tmp' and entry['fs'] == 'tmpfs'), 'host/system-path mount refused')
    for path, entry in table.items():
        require(not any(path.startswith(root + '/') for root in ('/inputs', '/runner', '/out')), 'nested input/runner/output mount refused')
        expected = path in {'/', '/inputs', '/out', '/runner', *standard}
        secured = ('nosuid', 'nodev', 'noexec')
        proc = (path == '/proc' and mount_role(entry, ('proc',), 'rw', secured)) or (path in PROC_READONLY and mount_role(entry, ('proc',), 'ro', secured))
        system = (path == '/sys' and mount_role(entry, ('sysfs',), 'ro', secured)) or (path == '/sys/fs/cgroup' and mount_role(entry, ('cgroup', 'cgroup2'), 'ro', secured))
        null_mask = path in NULL_MASKS and entry['fs'] == 'tmpfs' and set(entry['options']) & {'ro', 'rw'} in ({'ro'}, {'rw'})
        directory_mask = path in DIRECTORY_MASKS and mount_role(entry, ('tmpfs',), 'ro')
        if null_mask or directory_mask:
            node = probe.get('mask_nodes', {}).get(path, {})
            require(node.get('symlink') is False, 'mask node identity observation required')
            if null_mask:
                require(node.get('kind') == 'char' and node.get('device') == [1, 3], 'mask must be the null device')
            else:
                require(node.get('kind') == 'directory', 'mask must be a read-only directory')
        device_roles = {'/dev': (('tmpfs',), ('nosuid',)), '/dev/pts': (('devpts',), ('nosuid', 'noexec')),
                        '/dev/shm': (('tmpfs',), secured), '/dev/mqueue': (('mqueue',), secured)}
        device = path in device_roles and mount_role(entry, device_roles[path][0], 'rw', device_roles[path][1])
        temporary = path == '/tmp' and mount_role(entry, ('tmpfs',), 'rw', ('nosuid', 'nodev'))
        require(expected or proc or system or null_mask or directory_mask or device or temporary, 'unexpected external mount refused')
    require(isinstance(probe.get('nonce'), str) and re.fullmatch(r'[0-9a-f]{32}', probe['nonce']), 'explicit disposable-test nonce required')
    require(isinstance(probe.get('image_id'), str) and re.fullmatch(r'sha256:[0-9a-f]{64}', probe['image_id']), 'immutable image identity required')
    if nonce is not None:
        require(probe['nonce'] == nonce and probe['image_id'] == image_id, 'container identity differs from test contract')


def validate_contract(contract):
    require(isinstance(contract, dict) and contract.get('schema_version') == 1, 'unsupported contract schema')
    require(contract.get('execution') == 'native-aarch64-disposable-docker' and contract.get('allow_system_mutation') is True, 'explicit disposable mutation contract required')
    require(contract.get('daemon_arch') == 'aarch64', 'caller must record a native aarch64 Docker daemon')
    require(re.fullmatch(r'[0-9a-f]{32}', contract.get('nonce', '')), 'invalid contract nonce')
    require(re.fullmatch(r'sha256:[0-9a-f]{64}', contract.get('image_id', '')), 'invalid image ID')
    require(re.fullmatch(r'[0-9a-f]{40}', contract.get('source_commit', '')), 'accepted source commit required')
    require(re.fullmatch(r'[0-9A-F]{40}', contract.get('signing_key_fingerprint', '')), 'expected primary signer required')
    require(contract.get('pacman_conf') == 'pacman.conf' and HASH.fullmatch(contract.get('pacman_conf_sha256', '')), 'pinned local pacman configuration required')
    require(contract.get('public_cert') == 'signing/test-key.asc' and HASH.fullmatch(contract.get('public_cert_sha256', '')), 'pinned fixture public certificate required')
    require(isinstance(contract.get('baseline_handoff', False), bool), 'invalid handoff contract')
    for stage in ('baseline', 'upgrade'):
        rows = contract.get(stage)
        require(isinstance(rows, list) and len(rows) == 4 and all(isinstance(r, dict) for r in rows) and {r.get('name') for r in rows} == set(PACKAGES), 'exact four-package transaction required')
        for row in rows:
            require(isinstance(row.get('version'), str) and re.fullmatch(r'[A-Za-z0-9._+:~-]+', row['version']), 'invalid package version')
            path = safe_relative(row.get('archive'))
            require(path.startswith(stage + '/') and path.endswith(('.pkg.tar.zst', '.pkg.tar.xz', '.pkg.tar.gz')), 'archive must be in its pinned stage directory')
            require(HASH.fullmatch(row.get('sha256', '')) and HASH.fullmatch(row.get('signature_sha256', '')), 'archive/signature pins required')
            payload = row.get('payload_sha256')
            require(isinstance(payload, dict) and PRIMARY_FILES[row['name']] in payload, 'complete payload map including primary template/helper required')
            for name, digest in payload.items():
                safe_relative(name)
                require(allowed_file(row['name'], name) and HASH.fullmatch(digest), 'payload escapes package scope or lacks pin')
    baseline = {row['name']: row for row in contract['baseline']}
    require(baseline['cachy-asahi-setup']['payload_sha256'].get('usr/bin/cachy-asahi-setup') == BASELINE_HELPER_SHA256, 'original accepted a625 setup baseline required')
    for row in contract['upgrade']:
        old = baseline[row['name']]
        require(row['sha256'] != old['sha256'] and row['version'] != old['version'], 'upgrade cannot reuse baseline archive/version')
        main = PRIMARY_FILES[row['name']]
        require(row['payload_sha256'][main] != old['payload_sha256'][main], 'changed primary template/helper required for upgrade fixture')


def allowed_file(package, path):
    component = PACKAGES[package]
    prefixes = (f'usr/share/licenses/{package}/', f'usr/share/doc/{package}/')
    if component == 'setup':
        return path == 'usr/bin/cachy-asahi-setup' or path.startswith(prefixes)
    return path.startswith((*prefixes, f'usr/share/cachy-asahi/{component}/'))


def info(text):
    result = {}
    for row in text.splitlines():
        if row.strip() and not row.lstrip().startswith('#'):
            require(' = ' in row, 'malformed package metadata')
            key, value = row.split(' = ', 1)
            result.setdefault(key, []).append(value)
    return result



COMMAND_STDOUT = 4 * 1024 * 1024
COMMAND_STDERR = 1024 * 1024
COMMAND_TIMEOUT = 180
ARCHIVE_STREAM = 64 * 1024 * 1024
ARCHIVE_MEMBERS = 4096
ARCHIVE_TIMEOUT = 30


def cleanup_group(process):
    """Only our start_new_session PID/group; bounded TERM, KILL and direct reap."""
    result = {'term_sent': False, 'kill_sent': False, 'reaped': False, 'errors': []}
    try:
        os.killpg(process.pid, signal.SIGTERM)
        result['term_sent'] = True
    except ProcessLookupError:
        pass
    except OSError as error:
        result['errors'].append(type(error).__name__)
    deadline = time.monotonic() + 0.25
    while time.monotonic() < deadline:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            break
        except OSError:
            break
        process.poll()
        time.sleep(0.01)
    try:
        os.killpg(process.pid, signal.SIGKILL)
        result['kill_sent'] = True
    except ProcessLookupError:
        pass
    except OSError as error:
        result['errors'].append(type(error).__name__)
    try:
        process.wait(timeout=1)
        result['reaped'] = True
    except (subprocess.TimeoutExpired, OSError) as error:
        result['errors'].append(type(error).__name__)
    return result


def bounded_process(argv, *, timeout, stdout_limit, stderr_limit, env=None, preexec_fn=None, stdin=None):
    """Drain both pipes with byte/time limits; always clean the isolated process group."""
    require(timeout > 0 and stdout_limit > 0 and stderr_limit > 0, 'invalid process resource limits')
    started = time.monotonic()
    result = {'reason': 'exit', 'returncode': None, 'stdout': b'', 'stderr': b'', 'pid': None,
              'stdout_seen': 0, 'stderr_seen': 0, 'cleanup': {}}
    process = None
    selector = selectors.DefaultSelector()
    buffers = {'stdout': bytearray(), 'stderr': bytearray()}
    limits = {'stdout': stdout_limit, 'stderr': stderr_limit}
    with tempfile.TemporaryFile() as incoming:
        if stdin is not None:
            data = stdin.encode() if isinstance(stdin, str) else stdin
            require(len(data) <= 1024 * 1024, 'stdin exceeds limit')
            incoming.write(data); incoming.seek(0)
        try:
            process = subprocess.Popen([str(v) for v in argv], stdin=incoming, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=env, preexec_fn=preexec_fn, start_new_session=True)
            result['pid'] = process.pid
            for name in buffers:
                stream = getattr(process, name)
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            deadline = started + timeout
            while selector.get_map() or process.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    result['reason'] = 'timeout'
                    break
                for key, mask in selector.select(min(0.05, remaining)):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    name = key.data
                    result[name + '_seen'] += len(data)
                    capacity = limits[name] - len(buffers[name])
                    buffers[name].extend(data[:max(0, capacity)])
                    if result[name + '_seen'] > limits[name]:
                        result['reason'] = 'output-limit'
                        break
                if result['reason'] != 'exit':
                    break
        except OSError as error:
            result['reason'] = 'launch/io-error'
            message = str(error).encode()[:stderr_limit]
            buffers['stderr'].extend(message[:stderr_limit - len(buffers['stderr'])])
        finally:
            if process is not None:
                result['cleanup'] = cleanup_group(process)
                result['returncode'] = process.returncode
                for name in buffers:
                    stream = getattr(process, name)
                    if not stream.closed:
                        stream.close()
            selector.close()
            result.update({name: bytes(value) for name, value in buffers.items()})
            result['elapsed_seconds'] = time.monotonic() - started
    if result['reason'] == 'exit' and result['cleanup'].get('errors'):
        result['reason'] = 'cleanup-failed'
    return result


def tar_stream_guard(data, deadline):
    """Bound physical headers/extensions before tarfile expands PAX/GNU metadata."""
    require(len(data) <= ARCHIVE_STREAM, 'archive stream exceeds limit')
    offset, count, extension_bytes = 0, 0, 0
    while offset < len(data):
        require(time.monotonic() <= deadline, 'archive parsing deadline exceeded')
        header = data[offset:offset + 512]
        require(len(header) == 512, 'truncated tar header')
        if header == b'\0' * 512:
            require(not any(data[offset:]), 'nonzero data after tar end marker')
            return
        count += 1
        require(count <= ARCHIVE_MEMBERS, 'archive physical member count exceeds limit')
        field = header[124:136].strip(b'\0 ')
        require(field and all(value in b'01234567' for value in field), 'unsupported tar size encoding')
        size = int(field, 8)
        kind = header[156:157]
        require(kind in (b'0', b'\0', b'5', b'x', b'g', b'L', b'K'), 'links/special tar headers refused')
        if kind in (b'x', b'g', b'L', b'K'):
            extension_bytes += size
            require(size <= 64 * 1024 and extension_bytes <= 1024 * 1024, 'tar extension metadata exceeds limit')
        else:
            require(size <= 8 * 1024 * 1024, 'oversized package member')
        offset += 512 + ((size + 511) // 512) * 512
        require(offset <= len(data), 'truncated tar member data')
    raise Error('tar end marker missing')


def inspect_archive(path, row):
    """Bounded decode completes/reaps before tar parsing; never extract onto disk."""
    started = time.monotonic()
    regular(path)
    suffixes = {'.zst': 'zstd', '.xz': 'xz', '.gz': 'gzip'}
    decoder = next((tool for suffix, tool in suffixes.items() if path.name.endswith(suffix)), None)
    if decoder:
        result = bounded_process([decoder, '-dc', '--', path], timeout=ARCHIVE_TIMEOUT,
                                 stdout_limit=ARCHIVE_STREAM, stderr_limit=COMMAND_STDERR,
                                 env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC', 'HOME': '/tmp'})
        require(result['reason'] == 'exit' and result['returncode'] == 0,
                'archive decode failed: ' + result['reason'])
        decoded = result['stdout']
    else:
        require(path.stat().st_size <= ARCHIVE_STREAM, 'archive stream exceeds limit')
        with path.open('rb') as stream:
            decoded = stream.read(ARCHIVE_STREAM + 1)
        require(len(decoded) <= ARCHIVE_STREAM, 'archive stream exceeds limit')
    payload, ownership, seen, metadata, directories = {}, {}, set(), {}, set()
    total = 0
    deadline = started + ARCHIVE_TIMEOUT
    tar_stream_guard(decoded, deadline)
    with tarfile.open(fileobj=io.BytesIO(decoded), mode='r|') as archive:
        for index, member in enumerate(archive, 1):
            require(index <= ARCHIVE_MEMBERS, 'archive member count exceeds limit')
            require(time.monotonic() <= deadline, 'archive parsing deadline exceeded')
            name = str(PurePosixPath(member.name)).removeprefix('./').rstrip('/')
            if name == '.':
                continue
            safe_relative(name)
            require(name not in seen, 'duplicate archive member')
            seen.add(name)
            require(member.uid == member.gid == 0 and not member.mode & 0o6022, 'unsafe package ownership/mode')
            require(member.isdir() or member.isfile(), 'links/special package payloads refused')
            require(0 <= member.size <= 8 * 1024 * 1024, 'oversized package member')
            total += member.size
            require(total <= 32 * 1024 * 1024, 'oversized configuration package')
            if member.isdir():
                directories.add(name)
                continue
            data = archive.extractfile(member).read()
            if name in META:
                if name in ('.PKGINFO', '.BUILDINFO'):
                    metadata[name] = info(data.decode())
            else:
                require(allowed_file(row['name'], name) and not data.startswith(b'\x7fELF'), 'unexpected hook/platform/executable payload')
                payload[name] = hashlib.sha256(data).hexdigest()
                ownership[name] = member.mode
    allowed_directories = {str(parent) for name in payload for parent in PurePosixPath(name).parents if str(parent) != '.'}
    require(directories <= allowed_directories, 'unexpected empty/platform package directory')
    require({'.PKGINFO', '.BUILDINFO', '.MTREE'} <= seen, 'required package metadata missing')
    pkg = metadata['.PKGINFO']
    require(pkg.get('pkgname') == [row['name']] and pkg.get('pkgver') == [row['version']], 'archive package name/version differs')
    require(pkg.get('arch') == ['any'] and pkg.get('license') == ['MIT'], 'expected original MIT data package required')
    require(not any(pkg.get(k) for k in ('provides', 'conflict', 'replaces')), 'unexpected package relations')
    require(payload == row['payload_sha256'], 'archive payload differs from reviewed map')
    return {'files': ownership, 'pkginfo': pkg}

def validate_pacman_conf(text, nonce):
    values = {}
    for row in text.splitlines():
        row = row.strip()
        if not row or row.startswith('#'):
            continue
        if row.startswith('['):
            require(row == '[options]', 'repository/include configuration is not allowed')
            continue
        require('=' in row, 'invalid offline pacman config')
        key, value = (x.strip() for x in row.split('=', 1))
        require(key not in values and key in ('Architecture', 'SigLevel', 'LocalFileSigLevel', 'HookDir', 'GPGDir'), 'unexpected/duplicate pacman option')
        values[key] = value
    require(all(values.get(k) == v for k, v in {'Architecture': 'aarch64', 'SigLevel': 'Required', 'LocalFileSigLevel': 'Required', 'HookDir': '/builder-disabled-hooks', 'GPGDir': '/tmp/cachy-asahi-lifecycle-keyring-' + nonce}.items()), 'mandatory signed local transaction required')
    require(values.get('HookDir', '/builder-disabled-hooks') == '/builder-disabled-hooks' and values.get('GPGDir') == '/tmp/cachy-asahi-lifecycle-keyring-' + nonce, 'unexpected hook/keyring directory')


class Lifecycle:
    def __init__(self, contract, output, probe):
        validate_contract(contract)
        environment_guard(probe, contract['nonce'], contract['image_id'])
        self.contract, self.output, self.probe = contract, output, probe
        self.armed = True
        self.sequence = 0
        self.results = []
        self.archive_audits = {}
        self.fixture_users = []
        self.account_files = ACCOUNT_FILES
        self.keyring = Path('/tmp/cachy-asahi-lifecycle-keyring-' + contract['nonce'])
        self.report = {'schema_version': 1, 'execution': contract['execution'], 'image_id': contract['image_id'],
                       'source_commit': contract['source_commit'], 'status': 'running', 'hardware_status': 'NOT RUN',
                       'classification': 'disposable native ARM Docker package/user-fixture integration; no physical Mac checks',
                       'checks': self.results, 'commands': [], 'baseline_handoff_ready': False,
                       'runtime_arch': platform.machine(), 'kernel': platform.release(),
                       'runtime_page_size': os.sysconf('SC_PAGE_SIZE'), 'daemon_arch_recorded': contract['daemon_arch'],
                       'signing_trust': 'pinned ephemeral fixture public certificate; not production repository trust'}

    def guard(self):
        require(self.armed, 'system execution is not armed')
        environment_guard(actual_environment(), self.contract['nonce'], self.contract['image_id'])

    def command(self, argv, user=None, allowed=(0,), stdin=None):
        self.guard()
        self.sequence += 1
        env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC', 'TERM': 'dumb',
               'PYTHONDONTWRITEBYTECODE': '1', 'HOME': '/root'}
        preexec = None
        if user:
            env.update({'HOME': str(user['home']), 'ZDOTDIR': str(user['home']),
                        'XDG_CONFIG_HOME': str(user['home'] / '.config'),
                        'XDG_DATA_HOME': str(user['home'] / '.local/share'),
                        'XDG_STATE_HOME': str(user['home'] / '.local/state')})
            def demote():
                os.setgroups([])
                os.setgid(user['gid'])
                os.setuid(user['uid'])
            preexec = demote
        logfile = f'{self.sequence:03d}.log'
        receipt_path = self.output / f'{self.sequence:03d}.json'
        receipt = {'argv': [str(v) for v in argv], 'uid': user['uid'] if user else 0,
                   'exit_code': None, 'status': 'starting', 'log': logfile,
                   'timeout_seconds': COMMAND_TIMEOUT, 'stdout_limit': COMMAND_STDOUT, 'stderr_limit': COMMAND_STDERR}
        self.report['commands'].append(receipt)
        receipt_path.write_text(json.dumps(receipt, indent=2) + '\n')
        result = None
        try:
            result = bounded_process(argv, env=env, preexec_fn=preexec, stdin=stdin,
                timeout=COMMAND_TIMEOUT, stdout_limit=COMMAND_STDOUT, stderr_limit=COMMAND_STDERR)
        except subprocess.TimeoutExpired as error:
            # Retain legacy/injected timeout output too; bounded_process normally returns it.
            def partial(value, limit):
                return (value.encode() if isinstance(value, str) else value or b'')[:limit]
            result = {'reason': 'timeout', 'returncode': None, 'stdout': partial(error.output, COMMAND_STDOUT),
                      'stderr': partial(error.stderr, COMMAND_STDERR), 'cleanup': {'errors': ['external timeout exception']}}
        except BaseException as error:
            receipt['status'] = 'interrupted'
            self.report['status'] = 'FAIL'
            raise
        finally:
            if result is not None:
                receipt.update({'status': result['reason'], 'exit_code': result['returncode'],
                    'cleanup': result['cleanup'], 'pid': result.get('pid'),
                    'stdout_seen': result.get('stdout_seen', len(result['stdout'])),
                    'stderr_seen': result.get('stderr_seen', len(result['stderr'])),
                    'elapsed_seconds': result.get('elapsed_seconds')})
                text = result['stdout'].decode(errors='replace') + '\n' + result['stderr'].decode(errors='replace')
                (self.output / logfile).write_text(text)
                (self.output / logfile).chmod(0o644)
            else:
                (self.output / logfile).write_text('Command interrupted before bounded output was available\n')
            receipt_path.write_text(json.dumps(receipt, indent=2) + '\n')
            receipt_path.chmod(0o644)
        if result['reason'] != 'exit' or result['returncode'] not in allowed:
            self.report['status'] = 'FAIL'
            raise Error(f"command {result['reason']} / exit {result['returncode']} (see {logfile})")
        return result['stdout'].decode(errors='replace')

    def check(self, name, condition):
        self.results.append({'check': name, 'status': 'PASS' if condition else 'FAIL'})
        require(condition, 'integration check failed: ' + name)

    def inventory(self, stage):
        text = self.command(['pacman', '-Q'])
        rows = {}
        for line in text.splitlines():
            name, version = line.split(' ', 1)
            require(name not in rows, 'duplicate installed package')
            rows[name] = version
        (self.output / (stage + '-inventory.json')).write_text(json.dumps(rows, indent=2, sort_keys=True) + '\n')
        return rows

    def prepare_keyring(self):
        self.guard()
        certificate = pinned(INPUT_ROOT, self.contract['public_cert'], self.contract['public_cert_sha256'])
        text = certificate.read_text(encoding='ascii').strip()
        require(text.startswith('-----BEGIN PGP PUBLIC KEY BLOCK-----') and text.endswith('-----END PGP PUBLIC KEY BLOCK-----')
                and 'PRIVATE KEY' not in text and certificate.stat().st_size <= 256 * 1024, 'only bounded armored public certificate accepted')
        self.keyring.mkdir(mode=0o700, exist_ok=False)
        description = self.command(['gpg', '--batch', '--homedir', self.keyring, '--with-colons', '--show-keys', certificate])
        rows = [row.split(':') for row in description.splitlines()]
        primary = []
        awaiting = False
        for row in rows:
            require(row[0] not in ('sec', 'ssb'), 'secret key input refused')
            if row[0] == 'pub': awaiting = True
            elif row[0] == 'fpr' and awaiting:
                require(len(row) > 9 and re.fullmatch(r'[0-9A-F]{40}', row[9]), 'malformed public certificate fingerprint')
                primary.append(row[9]); awaiting = False
        self.check('fixture-public-certificate-fingerprint', primary == [self.contract['signing_key_fingerprint']])
        self.command(['gpg', '--batch', '--homedir', self.keyring, '--import', certificate])
        self.command(['gpg', '--batch', '--homedir', self.keyring, '--import-ownertrust'],
                     stdin=self.contract['signing_key_fingerprint'] + ':6:\n')
        self.command(['gpg', '--batch', '--homedir', self.keyring, '--check-trustdb'])

    def directory_state(self, path):
        root = Path(path)
        return {str(p.relative_to(root)): {'sha256': sha(p), 'mode': stat.S_IMODE(p.stat().st_mode)}
                for p in root.rglob('*') if p.is_file() and not p.is_symlink()}

    def snapshot_accounts(self):
        self.guard()
        # Existing account DB bytes stay only in memory, never in evidence/logs.
        self.original_accounts = {}
        for path in self.account_files:
            require(not path.is_symlink(), 'symlink account database refused')
            if not path.exists():
                self.original_accounts[path] = None
                continue
            item = path.stat()
            require(stat.S_ISREG(item.st_mode) and item.st_nlink == 1, 'nonregular account database refused')
            self.original_accounts[path] = {'data': path.read_bytes(), 'mode': stat.S_IMODE(item.st_mode),
                'uid': item.st_uid, 'gid': item.st_gid,
                'xattrs': {key: os.getxattr(path, key) for key in os.listxattr(path)}}

    def restore_accounts(self):
        self.guard()
        for path, original in self.original_accounts.items():
            require(not path.is_symlink(), 'changed account database type refused')
            if original is None:
                if path.exists():
                    # Never delete a base-owned file, even if initially missing.
                    self.command(['pacman', '-Qqo', path], allowed=(1,))
                    path.unlink()
                continue
            fd, temporary = tempfile.mkstemp(prefix='.cachy-asahi-account-', dir=path.parent)
            try:
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(original['data']); stream.flush()
                    os.fchown(stream.fileno(), original['uid'], original['gid'])
                    for key, value in original['xattrs'].items():
                        os.setxattr(stream.fileno(), key, value)
                    os.fchmod(stream.fileno(), original['mode'])
                    os.fsync(stream.fileno())
                os.replace(temporary, path)
            finally:
                if Path(temporary).exists(): Path(temporary).unlink()
        self.check('original-account-databases-restored', all(
            not path.exists() if original is None else path.read_bytes() == original['data']
            and stat.S_IMODE(path.stat().st_mode) == original['mode']
            and path.stat().st_uid == original['uid'] and path.stat().st_gid == original['gid']
            for path, original in self.original_accounts.items()))

    def cleanup(self):
        self.guard()
        for user in self.fixture_users:
            row = pwd.getpwnam(user['name'])
            require(row.pw_uid == user['uid'] and row.pw_dir == str(user['home']) and user['home'].is_relative_to(self.work), 'fixture account changed before cleanup')
            self.command(['userdel', '--remove', user['name']])
            if any(g.gr_name == user['name'] for g in grp.getgrall()):
                self.command(['groupdel', user['name']])
        self.restore_accounts()
        shutil.rmtree(self.work)
        self.command(['gpgconf', '--homedir', self.keyring, '--kill', 'all'])
        shutil.rmtree(self.keyring)
        names = {u['name'] for u in self.fixture_users}
        self.check('fixture-users-and-groups-cleaned', not names & {u.pw_name for u in pwd.getpwall()}
                   and not names & {g.gr_name for g in grp.getgrall()})
        self.check('fixture-homes-journals-keyring-cleaned', not self.work.exists() and not self.keyring.exists())
        self.check('original-alarm-keyring-preserved', self.directory_state('/etc/pacman.d/gnupg') == self.original_keyring)

    def audit_inputs(self):
        config = pinned(INPUT_ROOT, self.contract['pacman_conf'], self.contract['pacman_conf_sha256'])
        validate_pacman_conf(config.read_text(), self.contract['nonce'])
        self.pacman_conf = config
        for directory in ('/usr/share/libalpm/hooks', '/etc/pacman.d/hooks'):
            for hook in Path(directory).glob('*.hook'):
                masked = Path('/builder-disabled-hooks') / hook.name
                require(masked.is_symlink() and os.readlink(masked) == '/dev/null', 'base ALPM hook lacks its disposable-builder mask')
        self.prepare_keyring()
        for stage in ('baseline', 'upgrade'):
            for row in self.contract[stage]:
                path = pinned(INPUT_ROOT, row['archive'], row['sha256'])
                signature = pinned(INPUT_ROOT, row['archive'] + '.sig', row['signature_sha256'])
                status = self.command(['gpg', '--batch', '--no-auto-key-retrieve', '--no-auto-check-trustdb', '--lock-never',
                                       '--homedir', self.keyring, '--status-fd', '1', '--verify', signature, path])
                valid = [line.split() for line in status.splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
                bad = ('BADSIG', 'ERRSIG', 'EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'NO_PUBKEY')
                self.check(stage + '-signer-' + row['name'], len(valid) == 1 and len(valid[0]) >= 12
                           and valid[0][-1] == self.contract['signing_key_fingerprint']
                           and not any('[GNUPG:] ' + marker in status for marker in bad))
                self.archive_audits[(stage, row['name'])] = inspect_archive(path, row)
        baseline = {r['name']: r for r in self.contract['baseline']}
        for row in self.contract['upgrade']:
            comparison = self.command(['vercmp', row['version'], baseline[row['name']]['version']]).strip()
            self.check('upgrade-version-' + row['name'], int(comparison) > 0)
        (self.output / 'archive-audits.json').write_text(json.dumps(
            {stage + '/' + name: audit for (stage, name), audit in self.archive_audits.items()}, indent=2) + '\n')

    def transaction(self, stage, remove=False):
        self.pacman_conf = pinned(INPUT_ROOT, self.contract['pacman_conf'], self.contract['pacman_conf_sha256'])
        validate_pacman_conf(self.pacman_conf.read_text(), self.contract['nonce'])
        if remove:
            argv = ['pacman', '--config', self.pacman_conf, '-R', '--noconfirm', '--noscriptlet', *sorted(PACKAGES)]
        else:
            rows = self.contract[stage]
            for row in rows:
                pinned(INPUT_ROOT, row['archive'], row['sha256'])
                pinned(INPUT_ROOT, row['archive'] + '.sig', row['signature_sha256'])
            argv = ['pacman', '--config', self.pacman_conf, '-U', '--noconfirm', '--noscriptlet',
                    *(INPUT_ROOT / row['archive'] for row in rows)]
        self.command(argv)

    def installed(self, stage, label):
        inventory = self.inventory(label)
        expected = dict(self.base)
        expected.update({r['name']: r['version'] for r in self.contract[stage]})
        self.check(label + '-exact-inventory', inventory == expected)
        for row in self.contract[stage]:
            audit = self.archive_audits[(stage, row['name'])]
            listed = self.command(['pacman', '-Ql', row['name']])
            files = {line.split(' ', 1)[1].lstrip('/') for line in listed.splitlines() if not line.endswith('/')}
            self.check(label + '-ownership-' + row['name'], files == set(row['payload_sha256']))
            for relative, checksum in row['payload_sha256'].items():
                path = Path('/') / relative
                info = path.lstat()
                self.check(label + '-payload-' + relative, stat.S_ISREG(info.st_mode) and sha(path) == checksum
                           and info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == audit['files'][relative])
        self.command(['pacman', '-Qk', *sorted(PACKAGES)])

    def removed(self, stage, label):
        self.check(label + '-base-inventory-restored', self.inventory(label) == self.base)
        self.check(label + '-owned-payload-absent', all(not (Path('/') / p).exists()
                   for row in self.contract[stage] for p in row['payload_sha256']))

    def user(self, label, uid):
        name = 'caa' + self.contract['nonce'][:10] + label
        home = self.work / label
        require(not any(row.pw_uid == uid or row.pw_name == name for row in pwd.getpwall()), 'fixture user collision')
        self.command(['useradd', '--uid', str(uid), '--user-group', '--no-create-home', '--no-log-init', '--home-dir', home, '--shell', '/bin/bash', name])
        row = pwd.getpwnam(name)
        home.mkdir(mode=0o700)
        os.chown(home, row.pw_uid, row.pw_gid)
        user = {'name': name, 'uid': row.pw_uid, 'gid': row.pw_gid, 'home': home}
        self.fixture_users.append(user)
        return user

    def fixture(self, user, relative, data, mode=0o640):
        self.guard()
        require(user['home'].is_relative_to(self.work), 'fixture home escapes disposable work directory')
        path = user['home'] / safe_relative(relative)
        parent = path.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        for directory in (parent, *parent.parents):
            if directory == user['home'] or directory.is_relative_to(user['home']):
                os.chown(directory, user['uid'], user['gid'])
        path.write_bytes(data)
        os.chown(path, user['uid'], user['gid'])
        path.chmod(mode)
        return path

    def helper(self, user, operation, components=(), apply=True, allowed=(0,)):
        argv = [FIXED_HELPER, operation, '--home', user['home']]
        if components:
            argv += ['--components', *components]
        if apply:
            argv += ['--apply']
        return strict_json(self.command(argv, user=user, allowed=allowed))

    def paths(self, user):
        return {component: user['home'] / relative for component, relative in {
            'fish': '.config/fish/config.fish', 'zsh': '.zshrc', 'hyprland': '.config/cachy-asahi/hyprland.lua'}.items()}

    def snapshot(self, user):
        return {str(p.relative_to(user['home'])): {'sha256': sha(p), 'mode': stat.S_IMODE(p.stat().st_mode),
                 'uid': p.stat().st_uid, 'gid': p.stat().st_gid} for p in user['home'].rglob('*') if p.is_file()}

    def interrupt(self, user, operation):
        # Fault injection wraps the actual installed helper; no checkout substitute.
        code = '''import importlib.machinery, importlib.util, os, sys
loader = importlib.machinery.SourceFileLoader('installed_setup', '/usr/bin/cachy-asahi-setup')
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec); loader.exec_module(module)
original = module.Files.atomic
def interrupted(self, path, data, expected, private=False):
    result = original(self, path, data, expected, private)
    if path == '.config/fish/config.fish': os._exit(75)
    return result
module.Files.atomic = interrupted
engine = module.Setup(sys.argv[1])
engine.run(sys.argv[2], ('fish', 'zsh', 'hyprland'), apply=True)
raise SystemExit('fault injection did not run')
'''
        self.command([sys.executable, '-B', '-c', code, user['home'], operation], user=user, allowed=(75,))
        journal = user['home'] / '.local/state/cachy-asahi/setup/journal.json'
        self.check('interrupted-' + operation + '-journal-retained', journal.is_file() and stat.S_IMODE(journal.stat().st_mode) == 0o600)
        before = self.snapshot(user)
        self.helper(user, 'recover', apply=False, allowed=(2,))
        self.check('interrupted-' + operation + '-preview-readonly', self.snapshot(user) == before)
        self.helper(user, 'recover')
        self.check('interrupted-' + operation + '-recovered', not journal.exists())

    def suite(self):
        self.guard()
        self.original_keyring = self.directory_state('/etc/pacman.d/gnupg')
        self.audit_inputs()
        self.base = self.inventory('before')
        self.check('overlay-not-preinstalled', not set(PACKAGES) & set(self.base))
        self.transaction('baseline')
        self.installed('baseline', 'baseline-installed')
        self.work = Path(tempfile.mkdtemp(prefix='cachy-asahi-lifecycle-', dir='/tmp'))
        self.work.chmod(0o755)
        self.snapshot_accounts()
        fresh = self.user('fresh', 22000)
        existing = self.user('existing', 22001)
        components = ('fish', 'zsh', 'hyprland')
        before = self.snapshot(fresh)
        self.helper(fresh, 'activate', components, apply=False)
        self.check('fresh-preview-readonly', self.snapshot(fresh) == before)
        self.helper(fresh, 'activate', components)
        before = self.snapshot(fresh)
        self.helper(fresh, 'activate', components)
        self.check('fresh-repeat-idempotent', self.snapshot(fresh) == before)
        originals = {'fish': b'# existing Fish fixture\n', 'zsh': b'# existing Zsh fixture\n'}
        for component, data in originals.items():
            self.fixture(existing, str(self.paths(existing)[component].relative_to(existing['home'])), data)
        base_rc = self.fixture(existing, '.config/hypr/hyprland.lua', b'-- existing base config fixture\n')
        self.helper(existing, 'activate', components)
        self.check('existing-prefix-and-modes', all(self.paths(existing)[c].read_bytes().startswith(data)
                   and stat.S_IMODE(self.paths(existing)[c].stat().st_mode) == 0o640 for c, data in originals.items()))
        self.check('base-session-config-preserved', base_rc.read_bytes() == b'-- existing base config fixture\n')
        expected_shells = {}
        for component, data in originals.items():
            path = self.paths(existing)[component]
            path.write_bytes(b'# user-added prefix\n' + path.read_bytes() + b'# user-added suffix\n')
            expected_shells[component] = b'# user-added prefix\n' + data + b'# user-added suffix\n'
        desktop = self.paths(existing)['hyprland']
        desktop.write_bytes(desktop.read_bytes() + b'\n-- user edit retained across upgrades\n')
        edited_desktop = desktop.read_bytes()
        self.transaction('upgrade')
        self.installed('upgrade', 'upgraded')
        self.helper(fresh, 'activate', components)
        self.helper(existing, 'activate', components, allowed=(2,))
        self.check('upgrade-refreshes-unmodified-copy', sha(self.paths(fresh)['hyprland']) == sha('/usr/share/cachy-asahi/hyprland/hyprland.lua'))
        self.check('upgrade-preserves-edited-copy', desktop.read_bytes() == edited_desktop)
        homes = [self.snapshot(user) for user in (fresh, existing)]
        self.transaction('upgrade', remove=True)
        self.removed('upgrade', 'removed-before-reinstall')
        self.check('package-removal-preserves-user-files', homes == [self.snapshot(user) for user in (fresh, existing)])
        for user in (fresh, existing):
            fish = 'source ' + shlex.quote(str(self.paths(user)['fish'])) + '; functions -q caa_ll; and exit 3; exit 0'
            self.command(['fish', '--no-config', '--private', '--interactive', '--command', fish], user=user)
            zsh = 'source ' + shlex.quote(str(self.paths(user)['zsh'])) + '; [[ -z ${_CACHY_ASAHI_ZSH_LOADED:-} ]]'
            self.command(['zsh', '-dfi', '-c', zsh], user=user)
        self.transaction('upgrade')
        self.installed('upgrade', 'reinstalled')
        self.helper(fresh, 'remove')
        self.check('fresh-deactivation-removes-owned-files', all(not p.exists() for p in self.paths(fresh).values()))
        self.helper(existing, 'remove', allowed=(2,))
        self.check('existing-deactivation-surgical', all(self.paths(existing)[c].read_bytes() == data
                   and stat.S_IMODE(self.paths(existing)[c].stat().st_mode) == 0o640 for c, data in expected_shells.items()))
        self.check('existing-edited-desktop-remains', desktop.read_bytes() == edited_desktop)
        self.interrupt(fresh, 'activate')
        self.check('interrupt-activation-all-components-restored', all(p.exists() for p in self.paths(fresh).values()))
        self.interrupt(fresh, 'remove')
        self.check('interrupt-removal-all-components-removed', all(not p.exists() for p in self.paths(fresh).values()))
        self.helper(fresh, 'activate', ('fish', 'zsh'))
        fish_path = self.paths(fresh)['fish']
        original_fish = fish_path.read_bytes()
        edited_fish = original_fish.replace(b'    source ', b'    # fixture disabled source ')
        self.check('inside-block-fixture-really-changed', edited_fish != original_fish)
        fish_path.write_bytes(edited_fish)
        self.helper(fresh, 'remove', allowed=(2,))
        self.check('inside-block-edit-preserved', fish_path.read_bytes() == edited_fish)
        self.helper(fresh, 'activate', ('fish',), allowed=(2,))
        self.check('edited-block-repeat-preserved', fish_path.read_bytes() == edited_fish)
        # Explicit fixture repair, then normal owned-block removal.
        fish_path.write_bytes(original_fish)
        self.helper(fresh, 'remove')
        self.check('default-login-shells-unchanged', all(pwd.getpwnam(u['name']).pw_shell == '/bin/bash' for u in (fresh, existing)))
        self.check('final-base-config-preserved', base_rc.read_bytes() == b'-- existing base config fixture\n')
        self.finish()

    def finish(self):
        self.guard()
        require(LIFECYCLE_GATES <= {c['check'] for c in self.results if c['status'] == 'PASS'}
                and all(c['status'] == 'PASS' for c in self.results), 'lifecycle gates incomplete; handoff refused')
        self.transaction('upgrade', remove=True)
        self.removed('upgrade', 'final')
        if self.contract.get('baseline_handoff', False):
            self.transaction('baseline')
            self.installed('baseline', 'baseline-handoff')
            self.check('baseline-handoff-original-helper', sha(FIXED_HELPER) == BASELINE_HELPER_SHA256)
        self.cleanup()
        if self.contract.get('baseline_handoff', False):
            self.installed('baseline', 'clean-baseline-handoff')
            self.report['baseline_handoff_ready'] = True
            self.report['handoff_package_versions'] = {r['name']: r['version'] for r in self.contract['baseline']}
            self.report['handoff_payload_sha256'] = {r['name']: r['payload_sha256'] for r in self.contract['baseline']}
        else:
            self.removed('upgrade', 'clean-final')
        self.report['status'] = 'PASS'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-disposable-container', action='store_true')
    parser.add_argument('--baseline-handoff', action='store_true', help='leave original baseline packages installed only after clean successful fixture teardown')
    parser.add_argument('--contract', type=Path, required=True)
    parser.add_argument('--contract-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    runner = None
    created = False
    try:
        require(args.execute_disposable_container, 'explicit disposable-container execution switch required')
        probe = actual_environment()
        environment_guard(probe)  # Refuse host execution before reading inputs or creating output.
        require(args.contract == INPUT_ROOT / 'lifecycle.json' and args.output == Path('/out/lifecycle'), 'fixed isolated mount paths required')
        contract_path = pinned(INPUT_ROOT, 'lifecycle.json', args.contract_sha256)
        contract = strict_json(contract_path.read_text())
        require(args.baseline_handoff == contract.get('baseline_handoff', False), 'handoff flag differs from reviewed contract')
        runner = Lifecycle(contract, args.output, probe)
        args.output.mkdir(mode=0o755, exist_ok=False)
        created = True
        runner.report['contract_sha256'] = args.contract_sha256
        runner.suite()
        return 0
    except (Error, OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError, tarfile.TarError) as error:
        if runner:
            runner.report.update({'status': 'FAIL', 'error': str(error)})
        print(json.dumps({'status': 'FAIL', 'error': str(error), 'hardware_status': 'NOT RUN'}), file=sys.stderr)
        return 1
    finally:
        if created:
            (args.output / 'result.json').write_text(json.dumps(runner.report, indent=2, sort_keys=True) + '\n')
            (args.output / 'result.json').chmod(0o644)


if __name__ == '__main__':
    sys.exit(main())
