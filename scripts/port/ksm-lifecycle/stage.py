#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Separate finite DEVELOPMENT KSM signing/install/remove stage; never builds an image.

Consumes the two accepted native build receipts in the current 341-package job.
Only structured public evidence is retained; signing artifacts stay private.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
BASE_SHA = '13c2108aa03d76305a16bf1c9d08aa610e51f54f7726e4732c13d0824e5733f5'
GUARD_SHA = '4bfec1387f87768e5b37475d6172bde302ef52c01c68f81297435048be7f2100'
PURPOSE = 'ksm-diagnostic-development-lifecycle'
SCOPE = 'DEVELOPMENT TEST ONLY'
DOCKER_CLI = Path('/usr/bin/docker')
MAX_CLI = 128 * 1024**2
CHECKS = {
    'sign': {'guard', 'bindings', 'package-contract', 'baseline', 'signature', 'sign'},
    'lifecycle': {'guard', 'bindings', 'package-contract', 'baseline', 'signature', 'install',
                  'installed-payload', 'probes', 'remove', 'reinstall', 'final-remove', 'user-fixture'},
}

# Closed Source-defined diagnostics; this channel grants no worker or lifecycle acceptance.
DIAGNOSTIC_SELECTORS = frozenset(('UNKNOWN', 'CONTROLLER', 'SIGN', 'LIFECYCLE'))
DIAGNOSTIC_SITES = frozenset(('UNKNOWN', 'COORDINATOR', 'PLATFORM', 'JOB_BINDING', 'IMAGE_BINDING', 'DOCKER_BOUNDARY', 'DAEMON_ARCH', 'IMAGE_INSPECT', 'RUNNER_PROVENANCE', 'LOCK_BOOTSTRAP', 'CURRENT_INPUTS', 'CONTRACT_MODULE', 'BUILD_PROVENANCE', 'BUILD_PAIR', 'SOURCES', 'APPROVED_INPUTS', 'PUBLIC_OUTPUT', 'PRIVATE_TEMP', 'SOURCE_COPY', 'CONTRACT_WRITE', 'PHASE_BINDING', 'FRESH_NAME', 'CREATE', 'CREATED_ID', 'INSPECT_BEFORE', 'ATTACH', 'RECEIPT_READ', 'RECEIPT_DECODE', 'RECEIPT_VALIDATE', 'WORKER_RESULT', 'INSPECT_AFTER', 'STOPPED_STATE', 'CLEANUP_INSPECT', 'CLEANUP_OWNERSHIP', 'CLEANUP_REMOVE', 'CLEANUP_ABSENCE', 'PHASE_FINALIZE', 'SIGN_OUTPUTS', 'SIGNATURE_CAPTURE', 'PUBLIC_KEY_CAPTURE', 'LIFECYCLE_OUTPUTS', 'PRIVATE_CLEANUP', 'DOCKER_CLOSE', 'PUBLIC_RECEIPT', 'CLI_OUTPUT'))
DIAGNOSTIC_CHECKS = frozenset(('UNKNOWN', 'ambient-container-environment', 'build-provenance-read-drift', 'closed-docker-boundary', 'controller-receipt-byte-bound', 'controller-receipt-file-contract', 'coordinator-identity-drift', 'docker-boundary-pin-schema', 'docker-cli-byte-drift', 'docker-cli-identity-drift', 'docker-cli-path-drift', 'docker-cli-read-drift', 'docker-operation-failed', 'docker-snapshot-write-failed', 'duplicate-worker-check', 'fresh-container-name-required', 'fresh-public-output-required', 'frozen-helper-drift', 'genuine-same-job-source-required', 'immutable-image-required', 'incomplete-worker-pass', 'invalid-created-container-id', 'invalid-owned-container-id', 'lifecycle-signing-binding', 'local-daemon-identity-drift', 'local-socket-identity-drift', 'local-socket-pin-mismatch', 'matching-positive-coordinator-uid-gid-required', 'native-daemon-required', 'native-image-required', 'native-nonroot-coordinator-required', 'owned-container-absence-unconfirmed', 'phase-docker-binding', 'phase-or-cleanup-failed', 'private-controller-removal-unconfirmed', 'private-tmpfs-drift', 'runner-provenance-binding', 'sandbox-isolation-drift',
    'sandbox-isolation-user-drift', 'sandbox-isolation-readonly-rootfs-drift', 'sandbox-isolation-network-mode-drift', 'sandbox-isolation-ipc-mode-drift', 'sandbox-isolation-pid-mode-drift', 'sandbox-isolation-uts-mode-drift', 'sandbox-isolation-privileged-drift', 'sandbox-isolation-cap-drop-drift', 'sandbox-isolation-cap-add-drift', 'sandbox-isolation-security-opt-drift', 'sandbox-isolation-memory-and-swap-drift', 'sandbox-isolation-nano-cpus-drift', 'sandbox-isolation-pids-limit-drift', 'sandbox-isolation-devices-drift', 'sandbox-isolation-device-requests-drift', 'sandbox-isolation-volumes-from-drift', 'sandbox-isolation-port-bindings-drift', 'sandbox-isolation-device-cgroup-rules-drift', 'sandbox-isolation-ulimits-drift', 'stage-cancelled', 'unbound-docker-command', 'unexpected-container-mount', 'unexpected-lifecycle-output', 'unexpected-sign-output', 'unknown-worker-check', 'unowned-container-refused', 'unsafe-docker-cli', 'unsafe-frozen-helper', 'worker-check-bound', 'worker-cleanup-schema', 'worker-command-drift', 'worker-phase-failed', 'worker-receipt-binding', 'worker-receipt-fields', 'worker-receipt-scope', 'worker-signing-schema'))
DIAGNOSTIC_PREFIX = 'KSM_LIFECYCLE_DIAGNOSTIC_V1 '
DIAGNOSTIC_MAX_BYTES = 16384
_CHECK_PROVENANCE = object()
_DIAGNOSTIC = None


def need(ok, reason):
    if not ok:
        error = ValueError(reason)
        if type(reason) is str and reason in DIAGNOSTIC_CHECKS:
            error._ksm_check = (_CHECK_PROVENANCE, reason)
        raise error


def diagnostic_start(args):
    """CLI activation only; no diagnostic state enters the accepted receipt."""
    global _DIAGNOSTIC
    _DIAGNOSTIC = None
    if type(args.source_commit) is str and re.fullmatch(r'[0-9a-f]{40}', args.source_commit) \
            and type(args.run_id) is str and re.fullmatch(r'[0-9]{1,20}', args.run_id):
        _DIAGNOSTIC = {'schema_version': 1, 'source_commit': args.source_commit, 'run_id': args.run_id,
                       'first_failure': None, 'cleanup_failure': None, 'cancelled': False,
                       'attach_return': {'SIGN': None, 'LIFECYCLE': None},
                       '_selector': 'CONTROLLER', '_site': 'UNKNOWN', '_emitted': False}


def diagnostic_site(site, selector=None):
    if _DIAGNOSTIC is not None:
        _DIAGNOSTIC['_site'] = site if site in DIAGNOSTIC_SITES else 'UNKNOWN'
        if selector is not None:
            _DIAGNOSTIC['_selector'] = selector if selector in DIAGNOSTIC_SELECTORS else 'UNKNOWN'


def diagnostic_failure(error, *, cleanup=False):
    """Optional closed collection must never replace the operative exception."""
    original = None
    fields = ('args', '__cause__', '__context__', '__traceback__', '__suppress_context__')
    try:
        if type(_DIAGNOSTIC) is not dict or not all(type(key) is str for key in dict.keys(_DIAGNOSTIC)):
            return
        original = tuple(BaseException.__dict__[name].__get__(error) for name in fields)
        kind = type(error)
        lineage = type.__dict__['__mro__'].__get__(kind)
        if type(lineage) is not tuple:
            return
        category = 'UNKNOWN'
        if any(parent is base.Cancelled for parent in lineage):
            category = 'CANCELLED'
        elif any(parent is KeyboardInterrupt for parent in lineage):
            category = 'KEYBOARD_INTERRUPT'
        elif kind is ValueError:
            category = 'VALUE_ERROR'
        elif any(parent is OSError for parent in lineage):
            category = 'OS_ERROR'
        elif kind is KeyError:
            category = 'KEY_ERROR'
        elif kind is TypeError:
            category = 'TYPE_ERROR'
        elif any(parent is subprocess.SubprocessError for parent in lineage):
            category = 'SUBPROCESS_ERROR'
        if category in {'CANCELLED', 'KEYBOARD_INTERRUPT'} or base.CANCELLED is True:
            _DIAGNOSTIC['cancelled'] = True
        check = 'UNKNOWN'
        if kind is ValueError:
            metadata = BaseException.__dict__['__dict__'].__get__(error)
            if type(metadata) is dict:
                provenance = next((value for key, value in dict.items(metadata)
                                   if type(key) is str and key == '_ksm_check'), None)
                if type(provenance) is tuple and len(provenance) == 2 and provenance[0] is _CHECK_PROVENANCE \
                        and type(provenance[1]) is str and provenance[1] in DIAGNOSTIC_CHECKS:
                    check = provenance[1]
        selector, site = _DIAGNOSTIC['_selector'], _DIAGNOSTIC['_site']
        selector = selector if type(selector) is str and selector in DIAGNOSTIC_SELECTORS else 'UNKNOWN'
        site = site if type(site) is str and site in DIAGNOSTIC_SITES else 'UNKNOWN'
        row = {'selector': selector, 'site': site, 'check': check, 'category': category}
        if _DIAGNOSTIC['first_failure'] is None:
            _DIAGNOSTIC['first_failure'] = row
        if (cleanup is True or site in {'CLEANUP_INSPECT', 'CLEANUP_OWNERSHIP', 'CLEANUP_REMOVE',
                                       'CLEANUP_ABSENCE', 'PRIVATE_CLEANUP', 'DOCKER_CLOSE'}) \
                and _DIAGNOSTIC['cleanup_failure'] is None:
            _DIAGNOSTIC['cleanup_failure'] = row.copy()
    except BaseException as secondary:
        if original is not None:
            try:
                for name, value in zip(fields, original):
                    BaseException.__dict__[name].__set__(error, value)
            except BaseException:
                pass
        # Secondary collection failure is unavailable, not a new operative error.
        # Remember genuine cancellation separately without mutating the signal flag.
        for observed in (error, secondary):
            try:
                lineage = type.__dict__['__mro__'].__get__(type(observed))
                if type(lineage) is tuple and any(parent is KeyboardInterrupt or parent is base.Cancelled
                                                  for parent in lineage) and type(_DIAGNOSTIC) is dict \
                        and all(type(key) is str for key in dict.keys(_DIAGNOSTIC)):
                    dict.__setitem__(_DIAGNOSTIC, 'cancelled', True)
            except BaseException:
                pass
        try:
            if base.CANCELLED is True and type(_DIAGNOSTIC) is dict \
                    and all(type(key) is str for key in dict.keys(_DIAGNOSTIC)):
                dict.__setitem__(_DIAGNOSTIC, 'cancelled', True)
        except BaseException:
            pass


def diagnostic_phase(contract):
    if _DIAGNOSTIC is not None and type(contract) is dict:
        phase = contract.get('phase')
        if type(phase) is str:
            return {'sign': 'SIGN', 'lifecycle': 'LIFECYCLE'}.get(phase, 'UNKNOWN')
    return 'UNKNOWN'


def diagnostic_attach_return(code):
    if _DIAGNOSTIC is not None and _DIAGNOSTIC['_selector'] in {'SIGN', 'LIFECYCLE'} \
            and type(code) is int and -128 <= code <= 255:
        _DIAGNOSTIC['attach_return'][_DIAGNOSTIC['_selector']] = code


def diagnostic_emit():
    if _DIAGNOSTIC is None or _DIAGNOSTIC['_emitted']:
        return
    # Mark before serialization/write: partial or failed output never retries.
    _DIAGNOSTIC['_emitted'] = True
    try:
        _DIAGNOSTIC['cancelled'] = _DIAGNOSTIC['cancelled'] or bool(base.CANCELLED)
        record = {key: value for key, value in _DIAGNOSTIC.items() if not key.startswith('_')}
        data = DIAGNOSTIC_PREFIX + json.dumps(record, sort_keys=True, separators=(',', ':'))
        if len(data.encode('utf-8')) + 1 <= DIAGNOSTIC_MAX_BYTES:
            print(data, flush=True)
    except Exception:
        # Optional observations cannot replace the operative result. Cancellation propagates.
        return


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load_base():
    path = ROOT / 'scripts/client/stage.py'
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'unsafe-frozen-helper')
    data = path.read_bytes()
    need(sha(data) == BASE_SHA, 'frozen-helper-drift')
    spec = importlib.util.spec_from_file_location('ksm_bounded_base', path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


base = load_base()


def load_contract(expected):
    path = Path(__file__).with_name('contract.py')
    data = base.checked(path, expected)
    spec = importlib.util.spec_from_file_location('ksm_contract', path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


def coordinator_identity():
    uid, gid = os.getuid(), os.getgid()
    need(uid == os.geteuid() and gid == os.getegid() and 0 < uid <= 65535 and 0 < gid <= 65535,
         'matching-positive-coordinator-uid-gid-required')
    return uid, gid


class Docker:
    """One checked boundary for every daemon operation, including cleanup."""
    def __init__(self, endpoint, expected_daemon, cli_sha256, socket_device, socket_inode):
        self.coordinator = coordinator_identity()
        base.docker_command(endpoint)  # Only the two accepted local Unix paths.
        need(re.fullmatch(r'[A-Za-z0-9:-]{8,128}', expected_daemon)
             and re.fullmatch(r'[0-9a-f]{64}', cli_sha256), 'docker-boundary-pin-schema')
        self.endpoint, self.expected, self.cli_sha256 = endpoint, expected_daemon, cli_sha256
        self.socket = Path(endpoint.removeprefix('unix://'))
        self.fds, self.closed = [], False
        try:
            self.file_identity(DOCKER_CLI.lstat())
            self.cli_fd = self.open(DOCKER_CLI, os.O_RDONLY | os.O_NONBLOCK)
            self.cli_identity = self.file_identity(os.fstat(self.cli_fd))
            self.socket_fd = self.open(self.socket, os.O_PATH)
            observed = os.fstat(self.socket_fd)
            need(stat.S_ISSOCK(observed.st_mode) and observed.st_uid in {0, os.getuid()}
                 and not observed.st_mode & stat.S_IWOTH
                 and observed.st_dev == int(socket_device) and observed.st_ino == int(socket_inode), 'local-socket-pin-mismatch')
            self.socket_identity = self.node_identity(observed)
            data = self.cli_bytes()
            # Execute the accepted bytes, never a PATH lookup or a mutable reopened file.
            self.exec_fd = os.memfd_create('ksm-pinned-docker', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            self.fds.append(self.exec_fd)
            data = memoryview(data)
            while data:
                count = os.write(self.exec_fd, data)
                need(count > 0, 'docker-snapshot-write-failed')
                data = data[count:]
            os.fchmod(self.exec_fd, 0o500)
            fcntl.fcntl(self.exec_fd, fcntl.F_ADD_SEALS,
                        fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
            self.executable = f'/proc/{os.getpid()}/fd/{self.exec_fd}'
            self.check_files()
        except BaseException as error:
            diagnostic_failure(error)
            with base.defer_signals():
                try:
                    self.close()
                except BaseException as cleanup_error:
                    diagnostic_site('DOCKER_CLOSE', 'CONTROLLER')
                    diagnostic_failure(cleanup_error, cleanup=True)
                    raise
            raise

    def open(self, path, flags):
        fd = os.open(path, flags | os.O_CLOEXEC | os.O_NOFOLLOW)
        self.fds.append(fd)
        return fd

    @staticmethod
    def node_identity(info):
        return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_ctime_ns)

    def file_identity(self, info):
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid in {0, os.getuid()}
             and not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH) and info.st_mode & 0o111
             and 0 < info.st_size <= MAX_CLI, 'unsafe-docker-cli')
        return self.node_identity(info) + (info.st_size, info.st_mtime_ns)

    def cli_bytes(self):
        need(self.file_identity(os.fstat(self.cli_fd)) == self.cli_identity, 'docker-cli-identity-drift')
        data, offset = bytearray(), 0
        while offset <= MAX_CLI:
            chunk = os.pread(self.cli_fd, min(65536, MAX_CLI + 1 - offset), offset)
            if not chunk:
                break
            data.extend(chunk)
            offset += len(chunk)
        need(len(data) <= MAX_CLI and bytes(data[:4]) == b'\x7fELF' and sha(data) == self.cli_sha256,
             'docker-cli-byte-drift')
        need(self.file_identity(os.fstat(self.cli_fd)) == self.cli_identity, 'docker-cli-read-drift')
        return bytes(data)

    def check_files(self):
        need(coordinator_identity() == self.coordinator, 'coordinator-identity-drift')
        need(not self.closed, 'closed-docker-boundary')
        need(self.file_identity(DOCKER_CLI.lstat()) == self.cli_identity, 'docker-cli-path-drift')
        self.cli_bytes()
        need(self.node_identity(self.socket.lstat()) == self.socket_identity
             and self.node_identity(os.fstat(self.socket_fd)) == self.socket_identity, 'local-socket-identity-drift')

    def raw(self, argv, **kwargs):
        need(argv[:2] == base.docker_command(self.endpoint), 'unbound-docker-command')
        self.check_files()
        try:
            return base.bounded([self.executable, *argv[1:]], env=host_env(), **kwargs)
        except BaseException as error:
            diagnostic_failure(error)
            raise
        finally:
            with base.defer_signals():
                self.check_files()

    def identity(self):
        code, data = self.raw(base.docker_command(self.endpoint, 'info', '--format', '{{.ID}}'))
        need(code == 0 and data.decode('ascii').strip() == self.expected, 'local-daemon-identity-drift')

    def bounded(self, argv, **kwargs):
        self.identity()
        try:
            return self.raw(argv, **kwargs)
        except BaseException as error:
            diagnostic_failure(error)
            raise
        finally:
            with base.defer_signals():
                self.identity()

    def successful(self, argv, **kwargs):
        code, data = self.bounded(argv, **kwargs)
        need(code == 0, 'docker-operation-failed')
        return data

    def remove(self, name, cid):
        self.bounded(base.docker_command(self.endpoint, 'rm', '--force', '--volumes', cid))
        self.absent('name=^/' + name + '$')
        self.absent('id=' + cid)

    def absent(self, selected):
        data = self.successful(base.docker_command(self.endpoint, 'container', 'ls', '--all', '--quiet',
                                                   '--no-trunc', '--filter', selected))
        need(not data.strip(), 'owned-container-absence-unconfirmed')

    def close(self):
        failed = None
        while self.fds:
            try:
                os.close(self.fds.pop())
            except OSError as error:
                failed = error
        self.closed = True
        if failed:
            raise failed


def host_env():
    return {'PATH': '/usr/bin:/bin', 'HOME': os.environ['HOME'], 'LC_ALL': 'C'}


def sources(args):
    pins = {'scripts/client/stage.py': BASE_SHA, 'scripts/ci/source_suites.py': GUARD_SHA,
            'scripts/port/ksm-lifecycle/stage.py': args.stage_sha256,
            'scripts/port/ksm-lifecycle/worker.py': args.worker_sha256,
            'scripts/port/ksm-lifecycle/contract.py': args.contract_source_sha256}
    root = Path(args.source)
    return {name: base.checked(root / name, digest) for name, digest in pins.items()}, pins


def container_command(endpoint, image, name, source, output, uid, phase, nonce, contract_sha):
    root = phase == 'lifecycle'
    owner = 0 if root else uid
    memory, pids = ('2g', 96) if root else ('1g', 64)
    argv = base.docker_command(endpoint, 'create', '--pull=never', '--name', name, '--network=none',
                               '--ipc=private', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                               '--user', f'{owner}:{owner}', '--cpus=2', '--memory=' + memory,
                               '--memory-swap=' + memory, '--pids-limit=' + str(pids), '--ulimit=nofile=256:256')
    if root:
        argv += ['--cap-add=' + cap for cap in ('CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SETUID', 'SETGID')]
    else:
        argv += ['--read-only']
    argv += ['--tmpfs', f'/tmp:rw,nosuid,nodev,exec,size=256m,mode={"1777" if root else "0700"},uid={owner},gid={owner}',
             '--mount', f'type=bind,src={source},dst=/source,readonly',
             '--mount', f'type=bind,src={output},dst=/out',
             '--label', 'cachy-asahi.ksm.nonce=' + nonce, '--label', 'cachy-asahi.ksm.contract=' + contract_sha,
             '--env', 'HOME=/tmp/ksm-stage', '--env', 'PATH=/usr/bin:/bin', '--env', 'PYTHONDONTWRITEBYTECODE=1',
             '--env', 'CACHY_ASAHI_IMAGE_ID=' + image, '--env', 'CACHY_ASAHI_CLIENT_UID=' + str(uid),
             '--entrypoint=/usr/bin/python', image, '-I', '-B', '/source/scripts/port/ksm-lifecycle/worker.py',
             '--phase', phase, '--contract-sha256', contract_sha]
    return argv


def inspect_owned(record, contract_sha, nonce, image):
    labels = record['Config'].get('Labels') or {}
    need(record['Image'] == image and labels.get('cachy-asahi.ksm.nonce') == nonce
         and labels.get('cachy-asahi.ksm.contract') == contract_sha, 'unowned-container-refused')


def inspect_isolation(record, contract, source, output):
    c, h = record['Config'], record['HostConfig']
    root = contract['phase'] == 'lifecycle'
    owner, memory, pids = (0, 2 * 1024**3, 96) if root else (contract['uid'], 1024**3, 64)
    inspect_owned(record, sha(json.dumps(contract, sort_keys=True).encode()), contract['nonce'], contract['image_id'])
    need(c['Entrypoint'] == ['/usr/bin/python']
         and c['Cmd'] == ['-I', '-B', '/source/scripts/port/ksm-lifecycle/worker.py', '--phase', contract['phase'],
                          '--contract-sha256', sha(json.dumps(contract, sort_keys=True).encode())], 'worker-command-drift')
    need(c['User'] == f'{owner}:{owner}', 'sandbox-isolation-user-drift')
    need(h['ReadonlyRootfs'] is (not root), 'sandbox-isolation-readonly-rootfs-drift')
    need(h['NetworkMode'] == 'none', 'sandbox-isolation-network-mode-drift')
    need(h['IpcMode'] == 'private', 'sandbox-isolation-ipc-mode-drift')
    need(not h['PidMode'], 'sandbox-isolation-pid-mode-drift')
    need(not h['UTSMode'], 'sandbox-isolation-uts-mode-drift')
    need(not h['Privileged'], 'sandbox-isolation-privileged-drift')
    need(h['CapDrop'] == ['ALL'], 'sandbox-isolation-cap-drop-drift')
    need(set(h.get('CapAdd') or []) == ({'CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SETUID', 'SETGID'} if root else set()), 'sandbox-isolation-cap-add-drift')
    need(h['SecurityOpt'] in (['no-new-privileges'], ['no-new-privileges:true']), 'sandbox-isolation-security-opt-drift')
    need(h['Memory'] == h['MemorySwap'] == memory, 'sandbox-isolation-memory-and-swap-drift')
    need(h['NanoCpus'] == 2 * 10 ** 9, 'sandbox-isolation-nano-cpus-drift')
    need(h['PidsLimit'] == pids, 'sandbox-isolation-pids-limit-drift')
    need(not h.get('Devices'), 'sandbox-isolation-devices-drift')
    need(not h.get('DeviceRequests'), 'sandbox-isolation-device-requests-drift')
    need(not h.get('VolumesFrom'), 'sandbox-isolation-volumes-from-drift')
    need(not h.get('PortBindings'), 'sandbox-isolation-port-bindings-drift')
    need(not h.get('DeviceCgroupRules'), 'sandbox-isolation-device-cgroup-rules-drift')
    need(h['Ulimits'] == [{'Name': 'nofile', 'Soft': 256, 'Hard': 256}], 'sandbox-isolation-ulimits-drift')
    expected_env = {'HOME': '/tmp/ksm-stage', 'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1',
                    'CACHY_ASAHI_IMAGE_ID': contract['image_id'], 'CACHY_ASAHI_CLIENT_UID': str(contract['uid'])}
    need(c['Env'] == [key + '=' + value for key, value in expected_env.items()] or
         (len(c['Env']) == len(expected_env) and dict(x.split('=', 1) for x in c['Env']) == expected_env), 'ambient-container-environment')
    mounts = record['Mounts']
    binds = [m for m in mounts if m['Type'] == 'bind']
    need(len(binds) == 2 and {(m['Destination'], m['Source'], m['RW']) for m in binds}
         == {('/source', str(source), False), ('/out', str(output), True)}
         and all(m['Type'] == 'bind' or (m['Type'] == 'tmpfs' and m['Destination'] == '/tmp' and m['RW'] is True)
                 for m in mounts), 'unexpected-container-mount')
    need(h['Tmpfs'] == {'/tmp': f'rw,nosuid,nodev,exec,size=256m,mode={"1777" if root else "0700"},uid={owner},gid={owner}'}, 'private-tmpfs-drift')


def validate_receipt(record, contract):
    fields = {'schema_version', 'purpose', 'scope', 'phase', 'status', 'nonce', 'image_id', 'source_commit',
              'package_sha256', 'packages_sha256', 'source_sha256', 'checks', 'signing', 'cleanup', 'hardware', 'management'}
    need(set(record) == fields or (set(record) == fields | {'cancelled'} and record['cancelled'] is True
                                  and record['status'] == 'FAIL'), 'worker-receipt-fields')
    for field in ('schema_version', 'purpose', 'scope', 'phase', 'nonce', 'image_id', 'source_commit', 'packages_sha256', 'source_sha256'):
        need(record[field] == contract[field], 'worker-receipt-binding')
    need(record['package_sha256'] == contract['package']['sha256'] and record['status'] in {'PASS', 'FAIL'}
         and record['hardware'] == record['management'] == 'NOT RUN', 'worker-receipt-scope')
    need(type(record['checks']) is list and len(record['checks']) <= len(CHECKS[contract['phase']]), 'worker-check-bound')
    names = []
    for row in record['checks']:
        need(set(row) == {'name', 'status'} and row['name'] in CHECKS[contract['phase']]
             and row['status'] in {'PASS', 'FAIL'}, 'unknown-worker-check')
        names.append(row['name'])
    need(len(names) == len(set(names)), 'duplicate-worker-check')
    need(set(record['cleanup']) == {'processes', 'tmpfs'} and set(record['cleanup'].values()) <= {'PASS', 'FAIL'}, 'worker-cleanup-schema')
    signing = record['signing']
    if signing is not None:
        need(set(signing) == {'fingerprint', 'signature_sha256', 'public_key_sha256'}
             and re.fullmatch(r'[0-9A-F]{40}', signing['fingerprint'])
             and all(re.fullmatch(r'[0-9a-f]{64}', signing[key]) for key in ('signature_sha256', 'public_key_sha256')), 'worker-signing-schema')
    if contract['phase'] == 'lifecycle':
        need(signing == contract['signing'], 'lifecycle-signing-binding')
    if record['status'] == 'PASS':
        need(set(names) == CHECKS[contract['phase']] and all(x['status'] == 'PASS' for x in record['checks'])
             and set(record['cleanup'].values()) == {'PASS'} and signing is not None, 'incomplete-worker-pass')


def phase_run(endpoint, expected_daemon, image, source, output, contract, report, *, docker):
    diagnostic_site('PHASE_BINDING', diagnostic_phase(contract))
    need(docker.endpoint == endpoint and docker.expected == expected_daemon, 'phase-docker-binding')
    nonce = contract['nonce']
    name = 'cachy-asahi-ksm-' + nonce + '-' + contract['phase']
    contract_data = json.dumps(contract, sort_keys=True).encode()
    diagnostic_site('CONTRACT_WRITE')
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(source / 'inputs.json', flags, 0o600), 'wb') as stream:
        stream.write(contract_data)
        os.fchmod(stream.fileno(), 0o644)  # Exact held output-grant mode, on the written descriptor.
    digest = sha(contract_data)
    cid, attempted = None, False
    row = {'phase': contract['phase'], 'status': 'FAIL', 'container_cleanup': 'NOT RUN'}
    report['phases'].append(row)
    try:
        diagnostic_site('FRESH_NAME')
        before = docker.successful(base.docker_command(endpoint, 'container', 'ls', '--all', '--quiet', '--no-trunc',
                                                       '--filter', 'name=^/' + name + '$'))
        need(not before.strip(), 'fresh-container-name-required')
        attempted = True
        diagnostic_site('CREATE')
        cid = docker.successful(container_command(endpoint, image, name, source, output, contract['uid'],
                                                   contract['phase'], nonce, digest)).decode().strip()
        diagnostic_site('CREATED_ID')
        need(re.fullmatch(r'[0-9a-f]{64}', cid), 'invalid-created-container-id')
        diagnostic_site('INSPECT_BEFORE')
        obj = base.decode(docker.successful(base.docker_command(endpoint, 'inspect', cid)))[0]
        inspect_isolation(obj, contract, source, output)
        diagnostic_site('ATTACH')
        code, raw = docker.bounded(base.docker_command(endpoint, 'start', '--attach', cid),
                                   timeout=180 if contract['phase'] == 'sign' else 600)
        diagnostic_attach_return(code)
        row.update(attach_bytes=len(raw), attach_sha256=sha(raw))
        diagnostic_site('RECEIPT_READ')
        worker_data = base.read(output / 'worker-receipt.json')
        diagnostic_site('RECEIPT_DECODE')
        worker = base.decode(worker_data)
        diagnostic_site('RECEIPT_VALIDATE')
        validate_receipt(worker, contract)  # Never retain an unbound/unknown worker object.
        row['worker'] = worker
        diagnostic_site('WORKER_RESULT')
        need(code == 0 and worker['status'] == 'PASS', 'worker-phase-failed')
        diagnostic_site('INSPECT_AFTER')
        obj = base.decode(docker.successful(base.docker_command(endpoint, 'inspect', cid)))[0]
        inspect_isolation(obj, contract, source, output)
        diagnostic_site('STOPPED_STATE')
        row['container_state'] = base.stopped_state(obj)
        row['status'] = 'PASS'
    except BaseException as error:
        diagnostic_failure(error)
        raise
    finally:
        with base.defer_signals():
            if attempted:
                row['container_cleanup'] = 'FAIL'
                try:
                    diagnostic_site('CLEANUP_INSPECT')
                    code, raw = docker.bounded(base.docker_command(endpoint, 'inspect', name))
                    if code == 0:
                        obj = base.decode(raw)[0]
                        diagnostic_site('CLEANUP_OWNERSHIP')
                        inspect_owned(obj, digest, nonce, image)
                        owned_id = obj['Id']
                        need(re.fullmatch(r'[0-9a-f]{64}', owned_id), 'invalid-owned-container-id')
                        diagnostic_site('CLEANUP_REMOVE')
                        docker.remove(name, owned_id)
                    else:
                        # A transport failure is not absence; require successful daemon list.
                        diagnostic_site('CLEANUP_ABSENCE')
                        docker.absent('name=^/' + name + '$')
                        if cid:
                            docker.absent('id=' + cid)
                    row['container_cleanup'] = 'PASS'
                except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
                    diagnostic_failure(error, cleanup=True)
                    row['status'] = 'FAIL'
                except BaseException as error:
                    diagnostic_failure(error, cleanup=True)
                    raise
            if base.CANCELLED or row['container_cleanup'] != 'PASS':
                row['status'] = 'FAIL'
            diagnostic_site('PHASE_FINALIZE')
            try:
                need(row['status'] == 'PASS', 'phase-or-cleanup-failed')
            except BaseException as error:
                diagnostic_failure(error)
                raise
    return row['worker']


def run(args):
    report = None
    try:
        with base.cancellation_handlers():
            report = controller(args)
    except (base.Cancelled, KeyboardInterrupt) as error:
        diagnostic_failure(error)
        base.CANCELLED = True
        if report is None:
            raise
        public_receipt(Path(args.output).absolute() / 'receipt.json', report, existing=True)
    return report


def public_receipt(path, report, *, existing=False):
    diagnostic_site('PUBLIC_RECEIPT', 'CONTROLLER')
    if not existing:
        base.finalize_receipt(path, report)
    # Observe cancellation during stream close or the writer's final deferral exit.
    if existing or base.CANCELLED and (report['status'] != 'FAIL' or report.get('cancelled') is not True):
        report.update(status='FAIL', cancelled=True)
        with base.defer_signals():
            fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'wb') as stream:
                info = os.fstat(stream.fileno())
                need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
                     and info.st_size <= base.LIMIT, 'controller-receipt-file-contract')
                data = json.dumps(report, sort_keys=True, indent=2).encode() + b'\n'
                need(len(data) <= base.LIMIT, 'controller-receipt-byte-bound')
                stream.seek(0); stream.truncate()
                stream.write(data); stream.flush(); os.fsync(stream.fileno())


def controller(args):
    diagnostic_site('COORDINATOR', 'CONTROLLER')
    uid, gid = coordinator_identity()
    diagnostic_site('PLATFORM')
    need(platform.system() == 'Linux' and platform.machine() in {'aarch64', 'arm64'},
         'native-nonroot-coordinator-required')
    diagnostic_site('JOB_BINDING')
    need(re.fullmatch(r'[0-9a-f]{40}', args.source_commit) and re.fullmatch(r'[0-9]{1,20}', args.run_id)
         and os.environ.get('GITHUB_SHA') == args.source_commit and os.environ.get('GITHUB_RUN_ID') == args.run_id,
         'genuine-same-job-source-required')
    diagnostic_site('IMAGE_BINDING')
    need(re.fullmatch(r'sha256:[0-9a-f]{64}', args.image), 'immutable-image-required')
    diagnostic_site('DOCKER_BOUNDARY')
    docker = Docker(args.docker_endpoint, args.daemon_id, args.docker_sha256,
                    args.docker_socket_device, args.docker_socket_inode)
    try:
        return controller_inputs(args, docker, uid, gid)
    except BaseException as error:
        diagnostic_failure(error)
        raise
    finally:
        if not docker.closed:
            with base.defer_signals():
                diagnostic_site('DOCKER_CLOSE', 'CONTROLLER')
                try:
                    docker.close()
                except BaseException as error:
                    diagnostic_failure(error, cleanup=True)
                    raise


def controller_inputs(args, docker, uid, gid):
    endpoint = docker.endpoint
    prefix = base.docker_command(endpoint)
    diagnostic_site('DAEMON_ARCH', 'CONTROLLER')
    need(docker.successful(prefix + ['info', '--format', '{{.Architecture}}']).decode().strip() in {'aarch64', 'arm64'}, 'native-daemon-required')
    diagnostic_site('IMAGE_INSPECT')
    image = base.decode(docker.successful(prefix + ['image', 'inspect', args.image]))[0]
    need(image['Id'] == args.image and image['Architecture'] == 'arm64' and image['Os'] == 'linux', 'native-image-required')
    diagnostic_site('RUNNER_PROVENANCE')
    runner = base.decode(base.checked(args.runner, args.runner_sha256))
    need(runner['commit'] == args.source_commit and runner['run_id'] == args.run_id and runner['uid'] == uid
         and runner['kernel']['machine'] in {'aarch64', 'arm64'} and runner['docker_server_arch'] in {'aarch64', 'arm64'}
         and runner['docker_endpoint'] == endpoint, 'runner-provenance-binding')
    diagnostic_site('LOCK_BOOTSTRAP')
    lock = base.checked(args.packages, base.PACKAGES_SHA)
    boot = base.checked(args.bootstrap, args.bootstrap_sha256)
    base.bootstrap(boot, lock, args.image)
    diagnostic_site('CURRENT_INPUTS')
    current = base.checked(args.current_inputs, base.INPUTS_SHA)
    diagnostic_site('CONTRACT_MODULE')
    module = load_contract(args.contract_source_sha256)
    diagnostic_site('BUILD_PROVENANCE')
    hashes = [args.build_1_provenance_sha256, args.build_2_provenance_sha256]
    for path, pin in zip((args.build_1, args.build_2), hashes):
        base.checked(Path(path) / 'provenance.json', pin)
    diagnostic_site('BUILD_PAIR')
    package, archive = module.validate_build_pair(Path(args.build_1), Path(args.build_2), Path(args.approved_inputs), args.image, lock)
    need(package['provenance_sha256'] == hashes, 'build-provenance-read-drift')
    diagnostic_site('SOURCES')
    files, pins = sources(args)
    diagnostic_site('APPROVED_INPUTS')
    approved = base.checked(args.approved_inputs, module.APPROVED_MAP_SHA256)
    diagnostic_site('PUBLIC_OUTPUT')
    output = Path(args.output).absolute()
    need(not output.exists() and not output.is_symlink() and not any(x.is_symlink() for x in output.parents), 'fresh-public-output-required')
    output.mkdir(mode=0o700)
    report = {'schema_version': 1, 'purpose': PURPOSE, 'scope': SCOPE, 'status': 'FAIL',
              'source_commit': args.source_commit, 'run_id': args.run_id, 'daemon_id': args.daemon_id,
              'docker_endpoint': endpoint, 'image_id': args.image, 'runner_sha256': args.runner_sha256,
              'docker_cli_sha256': docker.cli_sha256, 'docker_socket_device': int(args.docker_socket_device),
              'docker_socket_inode': int(args.docker_socket_inode), 'coordinator_uid': uid, 'coordinator_gid': gid,
              'bootstrap_sha256': args.bootstrap_sha256, 'packages_sha256': base.PACKAGES_SHA,
              'current_inputs_sha256': base.INPUTS_SHA, 'source_sha256': pins, 'package': package,
              'phases': [], 'hardware': 'NOT RUN', 'management': 'NOT RUN', 'published': False,
              'private_artifacts_retained': False, 'controller_tmp_removed': 'NOT RUN', 'docker_boundary_closed': 'NOT RUN'}
    temp = None
    try:
        diagnostic_site('PRIVATE_TEMP')
        with base.defer_signals():
            temp = tempfile.TemporaryDirectory(prefix='ksm-private-stage-')
            report['private_artifacts_retained'] = True
        need(not base.CANCELLED, 'stage-cancelled')
        diagnostic_site('SOURCE_COPY')
        source = Path(temp.name) / 'source'
        source.mkdir(mode=0o700)
        for name, data in files.items():
            dest = source / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
        for name, data in {'bootstrap.json': boot, 'packages.lock': lock, 'current-inputs.json': current,
                           'approved-inputs.json': approved, package['filename']: archive}.items():
            (source / name).write_bytes(data)
        contract = {'schema_version': 1, 'purpose': PURPOSE, 'scope': SCOPE, 'nonce': os.urandom(16).hex(),
                    'source_commit': args.source_commit, 'run_id': args.run_id, 'daemon_id': args.daemon_id,
                    'image_id': args.image, 'uid': uid, 'package': package,
                    'approved_inputs_sha256': module.APPROVED_MAP_SHA256,
                    'bootstrap_sha256': args.bootstrap_sha256, 'packages_sha256': base.PACKAGES_SHA,
                    'current_inputs_sha256': base.INPUTS_SHA, 'source_sha256': pins, 'signing': None, 'phase': 'sign'}
        signed = Path(temp.name) / 'signed'
        signed.mkdir(mode=0o700)
        result = phase_run(endpoint, args.daemon_id, args.image, source, signed, contract, report, docker=docker)
        diagnostic_site('SIGN_OUTPUTS', 'SIGN')
        need(set(x.name for x in signed.iterdir()) == {'package.sig', 'public.gpg', 'worker-receipt.json'}, 'unexpected-sign-output')
        signing = result['signing']
        diagnostic_site('SIGNATURE_CAPTURE')
        signature = base.checked(signed / 'package.sig', signing['signature_sha256'])
        diagnostic_site('PUBLIC_KEY_CAPTURE')
        public = base.checked(signed / 'public.gpg', signing['public_key_sha256'])
        diagnostic_site('SOURCE_COPY', 'CONTROLLER')
        (source / 'package.sig').write_bytes(signature)
        (source / 'public.gpg').write_bytes(public)
        installed = Path(temp.name) / 'installed'
        installed.mkdir(mode=0o700)
        contract.update(signing=signing, phase='lifecycle')
        phase_run(endpoint, args.daemon_id, args.image, source, installed, contract, report, docker=docker)
        diagnostic_site('LIFECYCLE_OUTPUTS', 'LIFECYCLE')
        need(set(x.name for x in installed.iterdir()) == {'worker-receipt.json'}, 'unexpected-lifecycle-output')
        report['status'] = 'PASS'
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        diagnostic_failure(error)
        report['failure_category'] = type(error).__name__
    finally:
        try:
            with base.defer_signals():
                diagnostic_site('PRIVATE_CLEANUP', 'CONTROLLER')
                if temp is not None:
                    report['controller_tmp_removed'] = 'FAIL'
                    try:
                        temp.cleanup()
                        need(not Path(temp.name).exists(), 'private-controller-removal-unconfirmed')
                        report['controller_tmp_removed'] = 'PASS'
                        report['private_artifacts_retained'] = False
                    except (ValueError, OSError) as error:
                        diagnostic_failure(error, cleanup=True)
                        report['status'] = 'FAIL'
                diagnostic_site('DOCKER_CLOSE', 'CONTROLLER')
                try:
                    docker.close()
                    report['docker_boundary_closed'] = 'PASS'
                except OSError as error:
                    diagnostic_failure(error, cleanup=True)
                    report['docker_boundary_closed'] = 'FAIL'
                if base.CANCELLED or report['controller_tmp_removed'] != 'PASS' or report['docker_boundary_closed'] != 'PASS':
                    report['status'] = 'FAIL'
                public_receipt(output / 'receipt.json', report)
        except (base.Cancelled, KeyboardInterrupt) as error:
            diagnostic_failure(error, cleanup=True)
            base.CANCELLED = True
        # Handler restoration can raise, or remember cancellation after the
        # writer returned. Reconcile outside that final disposal deferral.
        if base.CANCELLED:
            public_receipt(output / 'receipt.json', report, existing=(output / 'receipt.json').exists())
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('image', 'daemon-id', 'docker-endpoint', 'docker-sha256', 'docker-socket-device', 'docker-socket-inode',
                 'source-commit', 'run-id', 'runner', 'runner-sha256', 'bootstrap',
                 'bootstrap-sha256', 'packages', 'current-inputs', 'source', 'stage-sha256', 'worker-sha256',
                 'contract-source-sha256', 'approved-inputs', 'build-1', 'build-1-provenance-sha256',
                 'build-2', 'build-2-provenance-sha256', 'output'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    diagnostic_start(args)
    try:
        report = run(args)
        diagnostic_site('CLI_OUTPUT', 'CONTROLLER')
        print(json.dumps({'status': report['status'], 'phases': [{k: row[k] for k in ('phase', 'status', 'container_cleanup')}
                                                               for row in report['phases']]}))
        diagnostic_emit()
        return 0 if report['status'] == 'PASS' else 1
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        diagnostic_failure(error)
        diagnostic_emit()
        print('FAIL: KSM stage boundary/input refusal', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
