# SPDX-License-Identifier: MIT
"""Closed public control DATA and separate fresh Root execution declarations.

Validation authenticates joins, not a signer or the external custody assertion.
No image, credential, quota, process or network operation occurs on import.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import time

HERE = Path(__file__).resolve().parent
OP = 'NO_PACKAGE_BOOT_LOGIN_LOGOUT_CONTROL_V1'
METADATA_SECONDS = 120
READER_PIN = dict(bytes=12810, sha256='94a755ab24b940a809f53a78faf90a851ded9f14d28c0fdb9cf75f5e01c59f23')
END = None
TOOLS = ('/usr/bin/python3', '/usr/bin/cp', '/usr/bin/debugfs', '/usr/bin/e2fsck',
         '/usr/bin/qemu-img', '/usr/bin/qemu-system-aarch64')
LIMITS = ('prepare_seconds', 'boot_seconds', 'cleanup_seconds', 'baseline_raw_bytes',
    'baseline_allocated_bytes', 'clone_allocated_cap_bytes', 'overlay_cap_bytes',
    'readback_allocated_cap_bytes', 'logs_cap_bytes', 'reserve_bytes', 'physical_free_bytes',
    'quota_initial_headroom_bytes', 'quota_live_reserve_bytes', 'guest_memory_bytes',
    'owner_memory_bytes', 'host_reserve_bytes', 'host_MemAvailable_bytes', 'cpus', 'pids',
    'output_device', 'host_uid')
ENFORCEMENT = 'ROOT_CUSLS_WHOLE_PROCESS_MEMORY_CPU_PID_QUOTA_OUTPUT_AND_CANONICAL_EXCLUSIVE_CUSTODY'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def keys(value, expected, label='DATA'):
    need(type(value) is dict and set(value) == set(expected), label+' exact fields')


def positive(value):
    return type(value) is int and 0 < value < 2**63


def sha(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def pin_shape(value):
    keys(value, ('bytes', 'sha256'), 'pin')
    need(positive(value['bytes']) and sha(value['sha256']), 'positive bounded byte/SHA256 pin')
    return value


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+'\n').encode()


def bytes_pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def json_pin(value):
    return bytes_pin(canonical(value))


def path_shape(value):
    need(type(value) is str and 0 < len(value) <= 4096 and value.startswith('/') and
         not any(ord(c) < 32 or ord(c) == 127 for c in value) and
         all(p not in ('', '.', '..') for p in value[1:].split('/')), 'literal canonical absolute path')
    return Path(value)


def ordinary(value):
    path = path_shape(str(value) if isinstance(value, Path) else value)
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary path without aliases')
    return path


def _consume(value, cap, keep):
    """One bounded stable ordinary-file read through nofollow directory FDs."""
    path = path_shape(str(value) if isinstance(value, Path) else value)
    need(positive(cap), 'positive read cap')
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent = os.open('/', flags | os.O_DIRECTORY)
    fd = None
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
                           s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, flags | os.O_DIRECTORY, dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(path.name, flags | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= cap,
             'bounded nonempty ordinary single-link DATA')
        raw = bytearray() if keep else None
        total = 0
        digest = hashlib.sha256()
        while block := os.read(fd, min(65536, cap+1-total)):
            need(END is None or time.monotonic() < END, 'finite DATA read deadline')
            total += len(block)
            need(total <= cap, 'DATA read byte cap')
            digest.update(block)
            if keep:
                raw.extend(block)
        after = os.fstat(fd)
        current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        need(identity(before) == identity(after) == identity(current) and total == before.st_size,
             'stable ordinary DATA identity and bytes')
        return bytes(raw) if keep else dict(bytes=total, sha256=digest.hexdigest())
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def read_bytes(value, cap=4*1024**2):
    return _consume(value, cap, True)


def pin(value, cap=4*1024**3):
    return _consume(value, cap, False)


def load(value, cap=1024**2):
    raw = read_bytes(value, cap)
    def unique(rows):
        result = {}
        for key, item in rows:
            need(key not in result, 'duplicate JSON field')
            result[key] = item
        return result
    def invalid(_):
        raise ValueError('integer finite JSON DATA required')
    parsed = json.loads(raw, object_pairs_hook=unique, parse_float=invalid, parse_constant=invalid)
    need(type(parsed) is dict and raw == canonical(parsed), 'canonical JSON object required')
    return parsed


def local(name):
    spec = importlib.util.spec_from_file_location('control_contract_'+name, HERE/(name+'.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def declaration(value, kind):
    need(value['kind'] == kind and value['issued_by'] == 'Root' and value['accepted'] is True,
         'explicit accepted Root public declaration required')


def resources(value, source, now=None, phase=None, output=None):
    keys(value, set(LIMITS) | {'quota_guard'}, 'resources')
    pin_shape(source)
    home = type(value['quota_guard']) is dict and value['quota_guard'].get('method') == 'READ_ONLY_HOME_BTRFS_ENOSYS_FSTATVFS'
    quota_fields = ('quota_initial_headroom_bytes', 'quota_live_reserve_bytes')
    need(all(positive(value[n]) for n in LIMITS if not home or n not in quota_fields), 'explicit finite resource integers')
    need(value['host_uid'] < 2**32 and value['output_device'] < 2**64 and
         5 <= value['prepare_seconds'] <= 3600 and 60 <= value['cleanup_seconds'] <= 600 and
         value['cleanup_seconds'] < value['boot_seconds'] <= 3600, 'finite constructor/boot/cleanup envelope')
    baseline = local('plan').BASELINE
    need(value['baseline_raw_bytes'] == baseline['raw']['bytes'] and
         value['baseline_allocated_bytes'] <= value['baseline_raw_bytes'] and
         value['readback_allocated_cap_bytes'] >= value['baseline_allocated_bytes'], 'original raw/readback allocation geometry')
    need(all(value[n] <= 4*1024**3 for n in ('clone_allocated_cap_bytes', 'overlay_cap_bytes', 'readback_allocated_cap_bytes')) and
         65536 <= value['logs_cap_bytes'] <= 64*1024**2, 'finite image and serial/output caps')
    peak = sum(value[n] for n in ('clone_allocated_cap_bytes', 'overlay_cap_bytes', 'readback_allocated_cap_bytes', 'logs_cap_bytes', 'reserve_bytes'))
    need(value['physical_free_bytes'] >= peak, 'simultaneous allocation plus physical reserve')
    need(128*1024**2 <= value['guest_memory_bytes'] <= 8*1024**3 and value['guest_memory_bytes'] % 1024**2 == 0 and
         value['owner_memory_bytes'] >= value['guest_memory_bytes'] and
         value['host_MemAvailable_bytes'] >= value['owner_memory_bytes']+value['host_reserve_bytes'] and
         value['cpus'] <= 64 and 16 <= value['pids'] <= 4096, 'finite guest/host RAM CPU and PID bounds')
    if home:
        local('support').legacy('home_btrfs').profile(value['quota_guard'], value, source, phase, output, now)
    else:
        need(value['quota_initial_headroom_bytes'] >= peak and value['quota_live_reserve_bytes'] >= value['reserve_bytes'],
             'finite own-UID quota headroom and live reserve')
        expected = dict(issued_by='Root', method='READ_ONLY_Q_GETQUOTA', whole_actor=True, read_only=True,
            uid=value['host_uid'], device=value['output_device'], initial_headroom_bytes=value['quota_initial_headroom_bytes'],
            live_reserve_bytes=value['quota_live_reserve_bytes'], on_unknown_or_exhausted='HOLD_AND_OWNED_CLEANUP')
        keys(value['quota_guard'], expected, 'quota guard')
        need(value['quota_guard'] == expected and value['quota_guard']['whole_actor'] is value['quota_guard']['read_only'] is True,
             'exact read-only own-UID quota guard declaration')
        need(all(type(value['quota_guard'][n]) is int for n in ('uid', 'device', 'initial_headroom_bytes', 'live_reserve_bytes')),
             'integer quota identity and reserve fields')
    return value


def inputs(value, source, now=None):
    keys(value, ('kind', 'nonce', 'baseline_nonce', 'baseline', 'kernel', 'tool_image', 'reader', 'actor_tools',
                 'resources', 'idle_seconds', 'source_lock', 'comparison_source65', 'timing'), 'control packet')
    need(value['kind'] == 'ROOT_NO_PACKAGE_CONTROL_INPUTS_V1', 'control packet kind')
    for name in ('nonce', 'baseline_nonce'):
        need(type(value[name]) is str and re.fullmatch('[0-9a-f]{32}', value[name]) is not None, 'literal public nonce')
    need(value['nonce'] != value['baseline_nonce'], 'fresh control nonce differs from original baseline nonce')
    pin_shape(source)
    need(value['source_lock'] == source, 'exact new control Source join')
    plan = local('plan')
    need(value['comparison_source65'] == plan.SOURCE65['lock'], 'immutable Source65 comparison lock')
    baseline = value['baseline']
    keys(baseline, ('kind', 'issued_by', 'accepted', 'raw', 'prepared', 'certificate'), 'original baseline declaration')
    declaration(baseline, 'ROOT_ACCEPTED_ORIGINAL_PAM_BASELINE_DECLARATION_V1')
    need({n: baseline[n] for n in plan.BASELINE} == plan.BASELINE, 'exact original accepted baseline pins')
    kernel = value['kernel']
    keys(kernel, ('kind', 'issued_by', 'accepted', 'Image', 'config'), 'case14 kernel declaration')
    declaration(kernel, 'ROOT_ACCEPTED_CASE14_KERNEL_DECLARATION_V1')
    for name, cap in (('Image', 128*1024**2), ('config', 4*1024**2)):
        pin_shape(kernel[name])
        need(kernel[name]['bytes'] <= cap, 'bounded Root-selected case14 kernel pin')
    need(type(value['tool_image']) is str and re.fullmatch('sha256:[0-9a-f]{64}', value['tool_image']) is not None, 'immutable tool image ID')
    pin_shape(value['reader'])
    need(value['reader']['bytes'] <= 1024**2, 'bounded public metadata reader source')
    need(value['reader'] == READER_PIN, 'exact integrated public metadata reader pin')
    keys(value['actor_tools'], TOOLS, 'six fixed actor tools')
    for tool in value['actor_tools'].values():
        pin_shape(tool)
        need(tool['bytes'] <= 64*1024**2, 'bounded fixed actor tool pin')
    resources(value['resources'], source, now)
    keys(value['timing'], ('login_seconds', 'proof_seconds', 'probe_seconds', 'logout_seconds'), 'serial timing')
    need(all(type(n) is int and 5 <= n <= 600 for n in value['timing'].values()) and
         type(value['idle_seconds']) is int and 0 <= value['idle_seconds'] <= 600, 'finite serial and idle envelopes')
    timing = value['timing']
    seconds = (3*timing['login_seconds']+timing['proof_seconds']+2*timing['probe_seconds']+
               timing['logout_seconds']+value['idle_seconds']+3*value['resources']['cleanup_seconds']+30+2*METADATA_SECONDS)
    need(value['resources']['boot_seconds'] >= seconds,
         'whole boot covers two metadata reads three login waits proof two probes idle logout readback fsck and cleanup')
    return value


packet = inputs


def fresh(value, packet_pin, packet, source, out, now, uid, starting=True):
    pin_shape(packet_pin)
    need(packet_pin == json_pin(packet), 'exact canonical control packet pin')
    inputs(packet, source, now)
    need(type(now) is int and type(uid) is int and 0 < uid < 2**32 and packet['resources']['host_uid'] == uid,
         'ordinary exact resource UID and integer time')
    need(value['issued_by'] == 'Root' and value['accepted'] is True and value['operation'] == OP and
         value['packet'] == packet_pin and value['source_lock'] == source and value['output'] == str(out) and
         type(value['uid']) is int and value['uid'] == uid, 'exact Root operation packet Source output UID')
    path_shape(value['output'])
    need(type(value['created_utc']) is type(value['expires_utc']) is int and
         0 <= now-value['created_utc'] <= 3600 and now < value['expires_utc'] <= value['created_utc']+3600,
         'fresh at-most-hour Root grant')
    need(type(starting) is bool, 'explicit grant validation stage')
    if starting:
        need(now+packet['resources']['boot_seconds']+packet['resources']['cleanup_seconds'] <= value['expires_utc'],
             'Root grant validity covers requested boot and cleanup')
    need(value['resources'] == json_pin(packet['resources']), 'exact finite resources pin')
    resources(packet['resources'], source, now, 'boot', out)


def admission(value, packet_pin, packet, source, out, now, uid, starting=True):
    keys(value, ('kind', 'issued_by', 'accepted', 'operation', 'packet', 'source_lock', 'output', 'uid',
                 'created_utc', 'expires_utc', 'resources', 'enforcement'), 'external Root admission')
    need(value['kind'] == 'ROOT_NO_PACKAGE_CONTROL_ADMISSION_V1' and value['enforcement'] == ENFORCEMENT,
         'explicit external Root custody and resource assertion')
    fresh(value, packet_pin, packet, source, out, now, uid, starting)
    return value


def authority(value, packet_pin, packet, source, out, now, uid, starting=True):
    keys(value, ('kind', 'issued_by', 'accepted', 'operation', 'packet', 'source_lock', 'reader', 'output', 'uid',
                 'created_utc', 'expires_utc', 'image', 'kernel', 'baseline', 'credentials', 'docker_endpoint',
                 'docker_cli', 'quota_device', 'actor_tools', 'resources', 'external_admission'), 'control authority')
    need(value['kind'] == 'ROOT_NO_PACKAGE_CONTROL_AUTHORITY_V1', 'control authority kind')
    fresh(value, packet_pin, packet, source, out, now, uid, starting)
    need(value['image'] == packet['tool_image'] and value['reader'] == packet['reader'] and
         value['kernel'] == packet['kernel'] and value['baseline'] == packet['baseline'] and
         value['actor_tools'] == packet['actor_tools'], 'exact input image reader kernel baseline tools joins')
    pin_shape(value['credentials'])
    pin_shape(value['external_admission'])
    need(type(value['docker_endpoint']) is str and re.fullmatch('unix:///run/user/'+str(uid)+'/[A-Za-z0-9_./-]+', value['docker_endpoint']) is not None and
         '..' not in value['docker_endpoint'], 'explicit own-UID local rootless Docker endpoint')
    cli = value['docker_cli']
    keys(cli, ('path', 'bytes', 'sha256', 'uid', 'gid', 'mode', 'device', 'inode', 'nlink'), 'Docker CLI descriptor')
    path_shape(cli['path'])
    pin_shape({n: cli[n] for n in ('bytes', 'sha256')})
    need(all(type(cli[n]) is int and 0 <= cli[n] < 2**64 for n in ('uid', 'gid', 'mode', 'device', 'inode', 'nlink')) and
         cli['uid'] in (0, uid) and cli['device'] > 0 and cli['inode'] > 0 and cli['nlink'] == 1 and
         cli['mode'] <= 0o777 and cli['mode'] & 0o111 and not cli['mode'] & 0o022,
         'ordinary pinned root/own-UID nonwritable executable CLI descriptor')
    if packet['resources']['quota_guard']['method'] == 'READ_ONLY_HOME_BTRFS_ENOSYS_FSTATVFS':
        need(value['quota_device'] is None, 'HOME unsupported quota has no device-path operand')
    else:
        need(type(value['quota_device']) is str and re.fullmatch('/dev/[A-Za-z0-9_/-]+', value['quota_device']) is not None,
             'explicit quota mount directory operand')
        path_shape(value['quota_device'])
    return value


def input_template():
    """Unissued public choices; nulls require explicit later Root selection."""
    return dict(kind='ROOT_NO_PACKAGE_CONTROL_INPUTS_V1', nonce=None, baseline_nonce=None,
        baseline=dict(kind='ROOT_ACCEPTED_ORIGINAL_PAM_BASELINE_DECLARATION_V1', issued_by='Root',
            accepted=None, **local('plan').BASELINE),
        kernel=dict(kind='ROOT_ACCEPTED_CASE14_KERNEL_DECLARATION_V1', issued_by='Root', accepted=None, Image=None, config=None),
        tool_image=None, reader=None, actor_tools=dict.fromkeys(TOOLS), resources=dict.fromkeys((*LIMITS, 'quota_guard')),
        idle_seconds=None, source_lock=None, comparison_source65=local('plan').SOURCE65['lock'],
        timing=dict.fromkeys(('login_seconds', 'proof_seconds', 'probe_seconds', 'logout_seconds')))


def admission_template():
    value = dict.fromkeys(('packet', 'source_lock', 'output', 'uid', 'created_utc', 'expires_utc', 'resources'))
    return dict(kind='ROOT_NO_PACKAGE_CONTROL_ADMISSION_V1', issued_by='Root', accepted=None,
        operation=OP, enforcement=ENFORCEMENT, **value)


def authority_template():
    value = dict.fromkeys(('packet', 'source_lock', 'reader', 'output', 'uid', 'created_utc', 'expires_utc', 'image',
        'kernel', 'baseline', 'credentials', 'docker_endpoint', 'docker_cli', 'quota_device', 'actor_tools', 'resources', 'external_admission'))
    return dict(kind='ROOT_NO_PACKAGE_CONTROL_AUTHORITY_V1', issued_by='Root', accepted=None, operation=OP, **value)
