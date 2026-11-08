# SPDX-License-Identifier: MIT
"""Shared finite DATA contract; no actor or network entry points."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat

BOUNDS = dict(owner_seconds=240, VM_seconds=180, command_seconds=20,
              command_output_bytes=65536, UART_bytes=1048576, report_bytes=65536,
              rootfs_bytes=268435456, rootfs_files=8192, kernel_bytes=268435456,
              initramfs_bytes=314572800, memory_MiB=1024, CPUs=1)
OPERATION = 'platform-namespace-vm-probe-v1'
NAMESPACES = ('user', 'mnt', 'net', 'pid', 'ipc', 'uts')
CAPS = ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')
BWRAP = ['/usr/bin/bwrap', '--die-with-parent', '--ro-bind', '/', '/', '--unshare-net',
         '--dev', '/dev', '--tmpfs', '/home', '--chdir', '/tmp', '--tmpfs', '/var/lib/pacman',
         '--', '/usr/bin/python3', '-I', '-B', '/probe/inside.py']
ENV = dict(PATH='/usr/bin:/bin', HOME='/tmp', TMPDIR='/tmp', LANG='C', LC_ALL='C',
           PYTHONDONTWRITEBYTECODE='1')
WRAPPER = ['/usr/bin/python3', '-I', '-B', '/probe/probe_exec.py']
STDERR_PREVIEW_BYTES = 16384


def need(value, reason):
    if not value:
        raise ValueError(reason)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def stderr_preview(raw):
    need(type(raw) is bytes and len(raw) <= BOUNDS['command_output_bytes'], 'bounded child stderr DATA')
    return dict(schema=1, encoding='base64', **pin(raw),
                prefix_b64=base64.b64encode(raw[:STDERR_PREVIEW_BYTES]).decode('ascii'),
                truncated=len(raw) > STDERR_PREVIEW_BYTES)


def validate_stderr(value):
    whole, preview, command = value['stderr'], value['stderr_preview'], value['command']
    need(type(whole) is dict and set(whole) == {'bytes', 'sha256'} and
         type(whole['bytes']) is int and 0 <= whole['bytes'] <= BOUNDS['command_output_bytes'] and
         type(whole['sha256']) is str and re.fullmatch('[0-9a-f]{64}', whole['sha256']), 'exact child stderr whole pin')
    need(type(command['stderr_bytes']) is int and command['stderr_bytes'] == whole['bytes'] and
         command['stderr_sha256'] == whole['sha256'], 'same actual command stderr whole pin')
    need(type(preview) is dict and set(preview) == {'schema', 'encoding', 'bytes', 'sha256', 'prefix_b64', 'truncated'} and
         type(preview['schema']) is int and preview['schema'] == 1 and preview['encoding'] == 'base64' and
         type(preview['bytes']) is int and preview['bytes'] == whole['bytes'] and preview['sha256'] == whole['sha256'] and
         type(preview['truncated']) is bool and preview['truncated'] is (whole['bytes'] > STDERR_PREVIEW_BYTES) and
         type(preview['prefix_b64']) is str and len(preview['prefix_b64']) <= 4 * ((STDERR_PREVIEW_BYTES + 2) // 3),
         'exact bounded version1 child stderr prefix')
    try:
        raw = base64.b64decode(preview['prefix_b64'], validate=True)
    except (ValueError, TypeError):
        raise ValueError('canonical child stderr base64') from None
    need(len(raw) == min(whole['bytes'], STDERR_PREVIEW_BYTES) and
         base64.b64encode(raw).decode('ascii') == preview['prefix_b64'], 'canonical exact child stderr prefix length')
    if not preview['truncated']:
        need(pin(raw) == whole, 'complete child stderr whole hash')
    # A truncated prefix cannot independently establish the unexported suffix; source/command provenance remains required.
    return raw


def decode(raw):
    def unique(rows):
        out = {}
        for key, value in rows:
            need(key not in out, 'duplicate JSON key')
            out[key] = value
        return out
    def constant(_):
        raise ValueError('nonfinite JSON')
    return json.loads(raw, object_pairs_hook=unique, parse_constant=constant)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def read(path, cap=1048576):
    path = Path(path)
    need(path.is_absolute() and path == path.resolve(), 'canonical absolute input required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= cap,
             'bounded ordinary single-link input required')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(cap + 1)
        key = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_uid,
                         s.st_gid, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(len(raw) == before.st_size and key(before) == key(os.fstat(fd)) == key(path.lstat()),
             'whole stable descriptor/path required')
        return raw
    finally:
        os.close(fd)


def relative(name):
    need(type(name) is str and name and not name.startswith('/') and
         len(name) <= 4096 and
         all(x not in ('', '.', '..') for x in name.split('/')) and '\\' not in name and
         all(33 <= ord(c) <= 126 for c in name), 'canonical relative DATA path')
    return name


def pinned(path, row, cap):
    need(type(row) is dict and set(row) == {'bytes', 'sha256'} and type(row['bytes']) is int and
         0 < row['bytes'] <= cap and re.fullmatch('[0-9a-f]{64}', row['sha256'] or ''), 'exact bounded pin')
    raw = read(path, cap)
    need(pin(raw) == row, 'pinned input differs')
    return raw


def defaults():
    return dict(schema=1, operation=OPERATION, status='UNBOUND_INPUTS_NOT_EXECUTABLE',
                bounds=dict(BOUNDS), kernel=None, rootfs=None, QEMU=None,
                actual_source=None, actual_ref=None, actual_run=None, issuer=None,
                input_reviewed=None, native_permission=False)


def bound(value):
    need(set(value) == set(defaults()) and type(value['schema']) is int and value['schema'] == 1 and
         value['operation'] == OPERATION and value['bounds'] == BOUNDS, 'exact versioned probe contract')
    need(all(type(v) is int for v in value['bounds'].values()), 'literal integer bounds, no booleans')
    need(value['status'] == 'ROOT_BOUND_GENERIC16K_NAMESPACE_PROBE_INPUTS' and value['issuer'] == 'Root' and
         value['input_reviewed'] is True and value['native_permission'] is False, 'UNBOUND Root input review; no actors')
    need(re.fullmatch('[0-9a-f]{40}', value['actual_source'] or '') and
         re.fullmatch('codex/[A-Za-z0-9._/-]+', value['actual_ref'] or '') and
         type(value['actual_run']) is int and value['actual_run'] > 0, 'genuine actual Source/run selectors required')
    for role, keys in [('kernel', {'Image', 'config', 'qualification', 'release', 'source', 'run'}),
                       ('rootfs', {'archive', 'manifest', 'qualification', 'source', 'run'})]:
        row = value[role]
        need(type(row) is dict and set(row) == keys and re.fullmatch('[0-9a-f]{40}', row['source'] or '') and
             type(row['run']) is int and row['run'] > 0, 'Root-provided genuine immutable ' + role + ' provenance')
    need(re.fullmatch('[A-Za-z0-9_.+-]{1,128}', value['kernel']['release'] or ''), 'literal expected kernel release')
    return value


def context_shape(value, release, outer=True):
    need(all(type(value[k]) is int for k in ('page_size', 'uid', 'euid', 'gid', 'egid', 'NoNewPrivs', 'pid', 'pgid', 'sid')),
         'literal observed identity integers')
    need(value['machine'] == 'aarch64' and value['kernel'] == release and value['page_size'] == 16384,
         'observed generic ARM64/16K/kernel identity')
    need(value['uid'] == value['euid'] >= 0 and value['gid'] == value['egid'] >= 0 and value['groups'] == [] and
         value['NoNewPrivs'] == 1 and set(value['capabilities']) == set(CAPS) and
         all(type(value['capabilities'][k]) is int and 0 <= value['capabilities'][k] < 2**64 for k in CAPS),
         'ordinary unprivileged guest identity and explicit capability observations')
    if outer:
        need(value['uid'] == value['gid'] == 23001 and all(value['capabilities'][k] == 0 for k in CAPS),
             'fixed UID23001 zero-capability outer guest required')
    need(set(value['namespaces']) == set(NAMESPACES) and all(re.fullmatch(k + r':\[[0-9]+\]', value['namespaces'][k])
         for k in NAMESPACES), 'complete actual namespace links')
    for key in ('uid_map', 'gid_map'):
        need(type(value[key]) is list and 1 <= len(value[key]) <= 16 and all(type(r) is list and len(r) == 3 and
             all(type(n) is int and n >= 0 for n in r) for r in value[key]), 'bounded actual namespace ID maps')
    if not outer:
        for identity, mapping in (('uid', 'uid_map'), ('gid', 'gid_map')):
            matches = [r for r in value[mapping] if r[2] > 0 and r[0] <= value[identity] < r[0] + r[2]]
            need(len(matches) == 1, 'one actual immediate-parent mapping for the inner identity')


def validate_inner_packet(evidence):
    need(type(evidence) is dict and set(evidence) == {'schema', 'transport', 'payload', 'packet', 'credentials',
         'observer', 'records', 'flags'} and type(evidence['schema']) is int and evidence['schema'] == 1 and
         evidence['transport'] == 'AF_UNIX_SEQPACKET_SCM_CREDENTIALS' and
         type(evidence['records']) is int and evidence['records'] == 1 and
         type(evidence['flags']) is int and evidence['flags'] in (0, 128), 'one untruncated kernel credential observation')
    payload = evidence['payload']
    need(type(payload) is dict and set(payload) == {'schema', 'nonce', 'release', 'context'} and
         type(payload['schema']) is int and payload['schema'] == 1 and type(payload['context']) is dict,
         'exact raw inner context envelope')
    raw = encoded(payload)
    need(len(raw) <= 12288 and evidence['packet'] == pin(raw), 'whole canonical inner context packet pin')
    credentials = evidence['credentials']
    need(type(credentials) is dict and set(credentials) == {'pid', 'uid', 'gid'} and
         all(type(credentials[k]) is int and credentials[k] >= 0 for k in credentials) and credentials['pid'] > 1,
         'typed kernel sending-task credentials')
    return payload


def context_valid(value, release, outer=True, evidence=None, observer=None, nonce=None):
    context_shape(value, release, outer)
    if not outer:
        payload = validate_inner_packet(evidence)
        need(payload['nonce'] == nonce and payload['release'] == release and payload['context'] == value,
             'same exact nonce/release/raw context from kernel-witnessed sender')
        need(evidence['observer'] == dict(uid=observer['uid'], euid=observer['euid'], gid=observer['gid'],
             egid=observer['egid'], user_namespace=observer['namespaces']['user'],
             pid_namespace=observer['namespaces']['pid']) and
             observer['uid'] == observer['euid'] == observer['gid'] == observer['egid'] == 23001,
             'credential observer remains in the original unprivileged outer user namespace')
        need(evidence['credentials'] == dict(pid=value['pid'], uid=23001, gid=23001) and
             value['namespaces']['pid'] == observer['namespaces']['pid'],
             'kernel projects the same actual inner sender to outer UID/GID23001 and PID namespace')


def validate_report(value, nonce, release):
    need(type(value['schema']) is int and value['schema'] == 1 and value['operation'] == OPERATION and value['nonce'] == nonce and
         value['generic_emulated_16K_only'] is True and value['hardware'] == 'NOT_RUN' and
         value['numeric_unshare_errno'] is None, 'exact guest-only report; numeric syscall errno unknown')
    validate_stderr(value)
    if value['inner_observation'] is not None:
        payload = validate_inner_packet(value['inner_observation'])
        need(payload['nonce'] == nonce and payload['release'] == release, 'raw inner observation belongs to this nonce/release')
    context_valid(value['before'], release)
    context_valid(value['after'], release)
    need(value['before'] == value['after'], 'outer guest identity/namespaces unchanged after probe')
    row = value['command']
    need(type(row['exit_code']) is int and type(row['group_absence_verified']) is bool, 'typed actual exit/retirement facts')
    need(row['argv'] == WRAPPER + [nonce, release] and value['bwrap_argv'] == BWRAP + [nonce, release] and
         row['time_limit'] == BOUNDS['command_seconds'] and
         row['output_limit'] == BOUNDS['command_output_bytes'] and type(row['pass_fds']) is list and
         row['pass_fds'] == [3] and type(row['pass_fds'][0]) is int and
         row['close_fds'] is True, 'one fixed finite bwrap operation')
    need(value['cleanup']['group_absence_verified'] is row['group_absence_verified'] and
         type(value['cleanup']['work_removed']) is bool and
         (not value['cleanup']['work_removed'] or row['group_absence_verified'] is True), 'actual guest cleanup provenance')
    if value['exec_context'] is not None:
        context_valid(value['exec_context'], release)
        need(value['exec_context']['pid'] == value['exec_context']['pgid'] == value['exec_context']['sid'] and
             value['exec_context']['pid'] > 1, 'actual new owned session before same-process bwrap exec')
        need(value['exec_context']['bwrap'] == dict(value['bwrap'], mode=0o755, uid=0, gid=0),
             'actual selected root-owned non-setuid bwrap identity')
    if value['status'] == 'OBSERVED_UNPRIVILEGED_BWRAP_SUCCESS':
        need(row['exit_code'] == 0 and row['group_absence_verified'] is True and value['command_error'] is None,
             'natural zero bwrap and verified owned group retirement')
        need(value['exec_context'] is not None and value['cleanup']['work_removed'] is True,
             'exact bwrap exec provenance and scoped guest cleanup')
        context_valid(value['inside'], release, outer=False, evidence=value['inner_observation'],
                      observer=value['before'], nonce=nonce)
        need(all(value['inside']['namespaces'][k] != value['before']['namespaces'][k] for k in ('user', 'mnt', 'net')),
             'actual created user/mount/network namespaces')
    else:
        need(value['status'] in ('OBSERVED_BWRAP_NONZERO', 'PROBE_EXECUTION_OR_RETIREMENT_FAILED') and
             value['inside'] is None and value['numeric_unshare_errno'] is None, 'honest failed or denied probe; errno unknown')
        if value['status'] == 'OBSERVED_BWRAP_NONZERO':
            need(row['exit_code'] == 1 and row['group_absence_verified'] is True and value['exec_context'] is not None and
                 value['command_error'] is None, 'actual nonzero bwrap observation, not an exec or retirement failure')
    return value
