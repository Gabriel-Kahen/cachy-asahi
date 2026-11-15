#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Closed TEST contract and host-x86 Docker guard; no native ARM admission.

Reuse lifecycle observations, capability limits and mount-role definitions
without changing or invoking its architecture-specific lifecycle admission.
"""
import importlib.util
from pathlib import Path, PurePosixPath
import re

HERE = Path(__file__).resolve().parent
LIFECYCLE = HERE / 'lifecycle.py' if (HERE / 'lifecycle.py').is_file() else HERE.parent / 'lifecycle.py'
spec = importlib.util.spec_from_file_location('install_handoff_finite_lifecycle', LIFECYCLE)
L = importlib.util.module_from_spec(spec)
spec.loader.exec_module(L)
PACKAGE_SHA = 'cf34935122855ca6aaa02f4c11987d53530e0e729c03698fa03aa1586ffac59e'
PACKAGE_BYTES = 184625
RUNTIME_SHA = '335029521a25eb2627651a2c32c9e9c648f384ea15f62ca8d4084b1dcf4743f4'
HEX = re.compile(r'[0-9a-f]{64}\Z')
FPR = re.compile(r'[0-9A-F]{40}\Z')
LAUNCHER = 'usr/bin/cachy-asahi-install-handoff'
PREFIXES = ('usr/lib/cachy-asahi/install-handoff/', 'usr/share/doc/cachy-asahi-install-handoff/',
            'usr/share/licenses/cachy-asahi-install-handoff/')
STANDARD_DEVICES = {'/dev/null': (1, 3), '/dev/zero': (1, 5), '/dev/full': (1, 7),
                    '/dev/random': (1, 8), '/dev/urandom': (1, 9), '/dev/tty': (5, 0)}


class Error(ValueError):
    pass


def need(ok, message):
    if not ok:
        raise Error(message)


def pin(value):
    return type(value) is str and HEX.fullmatch(value) is not None


def relative(value):
    need(type(value) is str and 0 < len(value) <= 512 and not any(c in value for c in '\\\0\n\r'),
         'CONTRACT_RELATIVE_PATH')
    path = PurePosixPath(value)
    need(path.parts and not path.is_absolute() and path.as_posix() == value and
         all(part not in ('', '.', '..') for part in path.parts), 'CONTRACT_RELATIVE_PATH')
    return path


def validate_contract(value):
    keys = {'schema_version', 'purpose', 'execution', 'image_id', 'nonce', 'package',
            'signer', 'handoff', 'payload', 'source_files'}
    need(type(value) is dict and set(value) == keys and type(value['schema_version']) is int
         and value['schema_version'] == 1, 'CONTRACT_SCHEMA')
    need(value['purpose'] == 'TEST-signed-install-handoff-host-container' and
         value['execution'] == 'host-x86_64-disposable-docker', 'CONTRACT_SCOPE')
    need(type(value['image_id']) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', value['image_id']),
         'CONTRACT_IMAGE')
    need(type(value['nonce']) is str and re.fullmatch('[0-9a-f]{32}', value['nonce']), 'CONTRACT_NONCE')
    package = value['package']
    need(type(package) is dict and set(package) == {'path', 'sha256', 'bytes', 'signature_sha256', 'signature_bytes'} and
         package['path'] == 'package.pkg.tar.zst' and package['sha256'] == PACKAGE_SHA and
         type(package['bytes']) is int and package['bytes'] == PACKAGE_BYTES and pin(package['signature_sha256']) and
         type(package['signature_bytes']) is int and 0 < package['signature_bytes'] <= 65536, 'CONTRACT_PACKAGE')
    signer = value['signer']
    need(type(signer) is dict and set(signer) == {'fingerprint', 'certificate_sha256', 'certificate_bytes'} and
         type(signer['fingerprint']) is str and FPR.fullmatch(signer['fingerprint']) and pin(signer['certificate_sha256']) and
         type(signer['certificate_bytes']) is int and 0 < signer['certificate_bytes'] <= 1024**2, 'CONTRACT_SIGNER')
    handoff = value['handoff']
    need(type(handoff) is dict and set(handoff) == {'receipt_sha256', 'selection_sha256', 'runtime_sha256',
         'archive_certificate_fingerprint', 'archive_certificate_sha256', 'files', 'symlinks'}, 'CONTRACT_HANDOFF')
    need(all(pin(handoff[key]) for key in ('receipt_sha256', 'selection_sha256', 'archive_certificate_sha256')) and
         handoff['runtime_sha256'] == RUNTIME_SHA and type(handoff['archive_certificate_fingerprint']) is str and
         FPR.fullmatch(handoff['archive_certificate_fingerprint']), 'CONTRACT_HANDOFF_PINS')
    files, aliases = handoff['files'], handoff['symlinks']
    need(type(files) is dict and 0 < len(files) <= 4096 and type(aliases) is dict and len(aliases) <= 1024 and
         len(files) + len(aliases) <= 4096 and not set(files) & set(aliases), 'CONTRACT_HANDOFF_BOUND')
    for name, digest in files.items():
        relative(name)
        need(pin(digest), 'CONTRACT_HANDOFF_FILE_PIN')
    for name, target in aliases.items():
        path = relative(name)
        relative(target)
        need('/' not in target and str(path.parent / target) in files, 'CONTRACT_HANDOFF_ALIAS')
    payload = value['payload']
    need(type(payload) is dict and len(payload) == 39 and LAUNCHER in payload, 'CONTRACT_PAYLOAD_SET')
    for name, row in payload.items():
        relative(name)
        need(name == LAUNCHER or name.startswith(PREFIXES), 'CONTRACT_PAYLOAD_SCOPE')
        need(type(row) is dict and set(row) == {'sha256', 'bytes', 'mode'} and pin(row['sha256']) and
             type(row['bytes']) is int and 0 < row['bytes'] <= 4 * 1024**2 and
             type(row['mode']) is int and row['mode'] in (0o644, 0o755), 'CONTRACT_PAYLOAD_ROW')
    sources = value['source_files']
    need(type(sources) is dict and set(sources) == {'guest.py', 'controls.py', 'lifecycle.py'} and
         all(pin(digest) for digest in sources.values()), 'CONTRACT_SOURCE_SET')
    return value


def guard(probe, contract):
    """Validate real lifecycle facts under a separate explicit host-only scope."""
    validate_contract(contract)
    need(type(probe) is dict and probe.get('docker_marker') is True, 'ENV_DOCKER_MARKER')
    need(type(probe.get('uid')) is int and probe['uid'] == 0 and probe.get('arch') == 'x86_64', 'ENV_HOST_X86_ROOT')
    privileges = probe.get('privileges')
    need(type(privileges) is dict and type(privileges.get('NoNewPrivs')) is int and
         privileges['NoNewPrivs'] == 1, 'ENV_NO_NEW_PRIVILEGES')
    for name in ('CapEff', 'CapPrm', 'CapBnd', 'CapInh', 'CapAmb'):
        bits = privileges.get(name)
        need(type(bits) is int and bits >= 0 and not bits & ~L.SAFE_CAPS, 'ENV_CAPABILITIES: ' + name)
    need(privileges['CapEff'] & (1 << 5), 'ENV_CAP_KILL')
    need(type(probe.get('caps')) is int and probe['caps'] == privileges['CapEff'] and
         probe.get('device_exposure') is False, 'ENV_DEVICES_CAPS')
    need(probe.get('interfaces') == ['lo'] and probe.get('docker_socket') is False, 'ENV_NETWORK_SOCKET')
    need(probe.get('nonce') == contract['nonce'] and probe.get('image_id') == contract['image_id'], 'ENV_IDENTITY')
    table = probe.get('mounts')
    need(type(table) is dict and {'/', '/inputs', '/runner', '/out', '/tmp', '/proc', '/sys', '/dev'} <= set(table),
         'ENV_MOUNT_SET')
    for point, row in table.items():
        need(type(point) is str and type(row) is dict and set(row) == {'options', 'fs'} and
             type(row['fs']) is str and type(row['options']) is list and
             all(type(option) is str for option in row['options']) and len(row['options']) == len(set(row['options'])) and
             set(row['options']) & {'ro', 'rw'} in ({'ro'}, {'rw'}), 'ENV_MOUNT_ROW')
        flags = set(row['options'])
        need(not any(first in flags and second in flags for first, second in
                     (('suid', 'nosuid'), ('dev', 'nodev'), ('exec', 'noexec'))), 'ENV_MOUNT_ROW')
    need(L.mount_role(table['/'], ('overlay', 'fuse-overlayfs'), 'rw'), 'ENV_ROOT_OVERLAY')
    for point, access in (('/inputs', 'ro'), ('/runner', 'ro'), ('/out', 'rw')):
        need(set(table[point]['options']) & {'ro', 'rw'} == {access}, 'ENV_SELECTED_MOUNT: ' + point)
    need(L.mount_role(table['/tmp'], ('tmpfs',), 'rw', ('nosuid', 'nodev')), 'ENV_TMPFS')
    standard = {'/etc/hosts', '/etc/hostname', '/etc/resolv.conf'}
    masks = probe.get('mask_nodes')
    need(type(masks) is dict, 'ENV_MASK_SET')
    standard_devices = probe.get('standard_devices', {})
    need(type(standard_devices) is dict and set(standard_devices) <= set(STANDARD_DEVICES),
         'ENV_STANDARD_DEVICE_SET')
    for point, node in standard_devices.items():
        need(type(node) is dict and set(node) == {'symlink', 'kind', 'device'} and
             node['symlink'] is False and node['kind'] == 'char' and type(node['device']) is list and
             len(node['device']) == 2 and all(type(part) is int for part in node['device']) and
             tuple(node['device']) == STANDARD_DEVICES[point], 'ENV_STANDARD_DEVICE_IDENTITY: ' + point)
    device_roles = {'/dev': (('tmpfs',), ('nosuid',)), '/dev/pts': (('devpts',), ('nosuid', 'noexec')),
                    '/dev/shm': (('tmpfs',), ('nosuid', 'nodev', 'noexec')),
                    '/dev/mqueue': (('mqueue',), ('nosuid', 'nodev', 'noexec'))}
    for point, row in table.items():
        need(not any(point.startswith(root + '/') for root in ('/inputs', '/runner', '/out')), 'ENV_NESTED_MOUNT')
        secured = ('nosuid', 'nodev', 'noexec')
        selected = point in {'/', '/inputs', '/runner', '/out', '/tmp', *standard}
        proc = (point == '/proc' and L.mount_role(row, ('proc',), 'rw', secured)) or (
            point in L.PROC_READONLY and L.mount_role(row, ('proc',), 'ro', secured))
        system = (point == '/sys' and L.mount_role(row, ('sysfs',), 'ro', secured)) or (
            point == '/sys/fs/cgroup' and L.mount_role(row, ('cgroup', 'cgroup2'), 'ro', secured))
        null = point in L.NULL_MASKS and (row['fs'] == 'tmpfs' or
            L.mount_role(row, ('devtmpfs',), 'rw', ('nosuid',)))
        directory = point in L.DIRECTORY_MASKS and L.mount_role(row, ('tmpfs',), 'ro')
        if null or directory:
            node = masks.get(point, {})
            need(type(node) is dict and set(node) == {'symlink', 'kind', 'device'} and
                 node['symlink'] is False, 'ENV_MASK_IDENTITY')
            exact_null = (node['kind'] == 'char' and type(node['device']) is list and len(node['device']) == 2 and
                          all(type(part) is int for part in node['device']) and node['device'] == [1, 3])
            need(exact_null if null else node['kind'] == 'directory' and node['device'] is None,
                 'ENV_MASK_IDENTITY')
        device = point in device_roles and L.mount_role(row, device_roles[point][0], 'rw', device_roles[point][1])
        standard_device = point in STANDARD_DEVICES
        if standard_device:
            need(point in standard_devices and L.mount_role(row, ('devtmpfs',), 'rw', ('nosuid',)),
                 'ENV_STANDARD_DEVICE_MOUNT: ' + point)
        need(selected or proc or system or null or directory or device or standard_device,
             'ENV_UNKNOWN_MOUNT: ' + point)
