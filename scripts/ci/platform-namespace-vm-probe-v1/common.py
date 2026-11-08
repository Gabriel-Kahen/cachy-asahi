# SPDX-License-Identifier: MIT
"""Shared finite DATA contract; no actor or network entry points."""
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


def need(value, reason):
    if not value:
        raise ValueError(reason)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


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


def context_valid(value, release, outer=True):
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
            matches = [outside + value[identity] - start for start, outside, count in value[mapping]
                       if start <= value[identity] < start + count]
            need(matches == [23001], 'inner identity maps exactly to unprivileged outer UID/GID23001')


def validate_report(value, nonce, release):
    need(type(value['schema']) is int and value['schema'] == 1 and value['operation'] == OPERATION and value['nonce'] == nonce and
         value['generic_emulated_16K_only'] is True and value['hardware'] == 'NOT_RUN' and
         value['numeric_unshare_errno'] is None, 'exact guest-only report; numeric syscall errno unknown')
    context_valid(value['before'], release)
    context_valid(value['after'], release)
    need(value['before'] == value['after'], 'outer guest identity/namespaces unchanged after probe')
    row = value['command']
    need(type(row['exit_code']) is int and type(row['group_absence_verified']) is bool, 'typed actual exit/retirement facts')
    need(row['argv'] == WRAPPER + [nonce, release] and value['bwrap_argv'] == BWRAP + [nonce, release] and
         row['time_limit'] == BOUNDS['command_seconds'] and
         row['output_limit'] == BOUNDS['command_output_bytes'], 'one fixed finite bwrap operation')
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
        context_valid(value['inside'], release, outer=False)
        need(all(value['inside']['namespaces'][k] != value['before']['namespaces'][k] for k in ('user', 'mnt', 'net')),
             'actual created user/mount/network namespaces')
    else:
        need(value['status'] in ('OBSERVED_BWRAP_NONZERO', 'PROBE_EXECUTION_OR_RETIREMENT_FAILED') and
             value['inside'] is None and value['numeric_unshare_errno'] is None, 'honest failed or denied probe; errno unknown')
        if value['status'] == 'OBSERVED_BWRAP_NONZERO':
            need(row['exit_code'] == 1 and row['group_absence_verified'] is True and value['exec_context'] is not None and
                 value['command_error'] is None, 'actual nonzero bwrap observation, not an exec or retirement failure')
    return value
