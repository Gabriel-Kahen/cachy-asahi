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
BASE_SHA = 'dc0c75969ed79548c3eb0ab1692f57ebffe7464d9192e591cdcf61aeaeb77154'
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


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


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
        except BaseException:
            with base.defer_signals():
                self.close()
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
    need(c['User'] == f'{owner}:{owner}' and h['ReadonlyRootfs'] is (not root)
         and h['NetworkMode'] == 'none' and h['IpcMode'] == 'private' and not h['PidMode'] and not h['UTSMode']
         and not h['Privileged'] and h['CapDrop'] == ['ALL']
         and set(h.get('CapAdd') or []) == ({'CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SETUID', 'SETGID'} if root else set())
         and h['SecurityOpt'] in (['no-new-privileges'], ['no-new-privileges:true'])
         and h['Memory'] == h['MemorySwap'] == memory and h['NanoCpus'] == 2 * 10**9 and h['PidsLimit'] == pids
         and not h.get('Devices') and not h.get('DeviceRequests') and not h.get('VolumesFrom')
         and not h.get('PortBindings') and not h.get('DeviceCgroupRules')
         and h['Ulimits'] == [{'Name': 'nofile', 'Soft': 256, 'Hard': 256}], 'sandbox-isolation-drift')
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
    need(docker.endpoint == endpoint and docker.expected == expected_daemon, 'phase-docker-binding')
    nonce = contract['nonce']
    name = 'cachy-asahi-ksm-' + nonce + '-' + contract['phase']
    contract_data = json.dumps(contract, sort_keys=True).encode()
    (source / 'inputs.json').write_bytes(contract_data)
    digest = sha(contract_data)
    cid, attempted = None, False
    row = {'phase': contract['phase'], 'status': 'FAIL', 'container_cleanup': 'NOT RUN'}
    report['phases'].append(row)
    try:
        before = docker.successful(base.docker_command(endpoint, 'container', 'ls', '--all', '--quiet', '--no-trunc',
                                                       '--filter', 'name=^/' + name + '$'))
        need(not before.strip(), 'fresh-container-name-required')
        attempted = True
        cid = docker.successful(container_command(endpoint, image, name, source, output, contract['uid'],
                                                   contract['phase'], nonce, digest)).decode().strip()
        need(re.fullmatch(r'[0-9a-f]{64}', cid), 'invalid-created-container-id')
        obj = base.decode(docker.successful(base.docker_command(endpoint, 'inspect', cid)))[0]
        inspect_isolation(obj, contract, source, output)
        code, raw = docker.bounded(base.docker_command(endpoint, 'start', '--attach', cid),
                                   timeout=180 if contract['phase'] == 'sign' else 600)
        row.update(attach_bytes=len(raw), attach_sha256=sha(raw))
        worker = base.decode(base.read(output / 'worker-receipt.json'))
        validate_receipt(worker, contract)  # Never retain an unbound/unknown worker object.
        row['worker'] = worker
        need(code == 0 and worker['status'] == 'PASS', 'worker-phase-failed')
        obj = base.decode(docker.successful(base.docker_command(endpoint, 'inspect', cid)))[0]
        inspect_isolation(obj, contract, source, output)
        row['container_state'] = base.stopped_state(obj)
        row['status'] = 'PASS'
    finally:
        with base.defer_signals():
            if attempted:
                row['container_cleanup'] = 'FAIL'
                try:
                    code, raw = docker.bounded(base.docker_command(endpoint, 'inspect', name))
                    if code == 0:
                        obj = base.decode(raw)[0]
                        inspect_owned(obj, digest, nonce, image)
                        owned_id = obj['Id']
                        need(re.fullmatch(r'[0-9a-f]{64}', owned_id), 'invalid-owned-container-id')
                        docker.remove(name, owned_id)
                    else:
                        # A transport failure is not absence; require successful daemon list.
                        docker.absent('name=^/' + name + '$')
                        if cid:
                            docker.absent('id=' + cid)
                    row['container_cleanup'] = 'PASS'
                except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
                    row['status'] = 'FAIL'
            if base.CANCELLED or row['container_cleanup'] != 'PASS':
                row['status'] = 'FAIL'
            need(row['status'] == 'PASS', 'phase-or-cleanup-failed')
    return row['worker']


def run(args):
    report = None
    try:
        with base.cancellation_handlers():
            report = controller(args)
    except (base.Cancelled, KeyboardInterrupt):
        base.CANCELLED = True
        if report is None:
            raise
        public_receipt(Path(args.output).absolute() / 'receipt.json', report, existing=True)
    return report


def public_receipt(path, report, *, existing=False):
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
    uid, gid = coordinator_identity()
    need(platform.system() == 'Linux' and platform.machine() in {'aarch64', 'arm64'},
         'native-nonroot-coordinator-required')
    need(re.fullmatch(r'[0-9a-f]{40}', args.source_commit) and re.fullmatch(r'[0-9]{1,20}', args.run_id)
         and os.environ.get('GITHUB_SHA') == args.source_commit and os.environ.get('GITHUB_RUN_ID') == args.run_id,
         'genuine-same-job-source-required')
    need(re.fullmatch(r'sha256:[0-9a-f]{64}', args.image), 'immutable-image-required')
    docker = Docker(args.docker_endpoint, args.daemon_id, args.docker_sha256,
                    args.docker_socket_device, args.docker_socket_inode)
    try:
        return controller_inputs(args, docker, uid, gid)
    finally:
        if not docker.closed:
            with base.defer_signals():
                docker.close()


def controller_inputs(args, docker, uid, gid):
    endpoint = docker.endpoint
    prefix = base.docker_command(endpoint)
    need(docker.successful(prefix + ['info', '--format', '{{.Architecture}}']).decode().strip() in {'aarch64', 'arm64'}, 'native-daemon-required')
    image = base.decode(docker.successful(prefix + ['image', 'inspect', args.image]))[0]
    need(image['Id'] == args.image and image['Architecture'] == 'arm64' and image['Os'] == 'linux', 'native-image-required')
    runner = base.decode(base.checked(args.runner, args.runner_sha256))
    need(runner['commit'] == args.source_commit and runner['run_id'] == args.run_id and runner['uid'] == uid
         and runner['kernel']['machine'] in {'aarch64', 'arm64'} and runner['docker_server_arch'] in {'aarch64', 'arm64'}
         and runner['docker_endpoint'] == endpoint, 'runner-provenance-binding')
    lock = base.checked(args.packages, base.PACKAGES_SHA)
    boot = base.checked(args.bootstrap, args.bootstrap_sha256)
    base.bootstrap(boot, lock, args.image)
    current = base.checked(args.current_inputs, base.INPUTS_SHA)
    module = load_contract(args.contract_source_sha256)
    hashes = [args.build_1_provenance_sha256, args.build_2_provenance_sha256]
    for path, pin in zip((args.build_1, args.build_2), hashes):
        base.checked(Path(path) / 'provenance.json', pin)
    package, archive = module.validate_build_pair(Path(args.build_1), Path(args.build_2), Path(args.approved_inputs), args.image, lock)
    need(package['provenance_sha256'] == hashes, 'build-provenance-read-drift')
    files, pins = sources(args)
    approved = base.checked(args.approved_inputs, module.APPROVED_MAP_SHA256)
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
        with base.defer_signals():
            temp = tempfile.TemporaryDirectory(prefix='ksm-private-stage-')
            report['private_artifacts_retained'] = True
        need(not base.CANCELLED, 'stage-cancelled')
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
        need(set(x.name for x in signed.iterdir()) == {'package.sig', 'public.gpg', 'worker-receipt.json'}, 'unexpected-sign-output')
        signing = result['signing']
        signature = base.checked(signed / 'package.sig', signing['signature_sha256'])
        public = base.checked(signed / 'public.gpg', signing['public_key_sha256'])
        (source / 'package.sig').write_bytes(signature)
        (source / 'public.gpg').write_bytes(public)
        installed = Path(temp.name) / 'installed'
        installed.mkdir(mode=0o700)
        contract.update(signing=signing, phase='lifecycle')
        phase_run(endpoint, args.daemon_id, args.image, source, installed, contract, report, docker=docker)
        need(set(x.name for x in installed.iterdir()) == {'worker-receipt.json'}, 'unexpected-lifecycle-output')
        report['status'] = 'PASS'
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        report['failure_category'] = type(error).__name__
    finally:
        try:
            with base.defer_signals():
                if temp is not None:
                    report['controller_tmp_removed'] = 'FAIL'
                    try:
                        temp.cleanup()
                        need(not Path(temp.name).exists(), 'private-controller-removal-unconfirmed')
                        report['controller_tmp_removed'] = 'PASS'
                        report['private_artifacts_retained'] = False
                    except (ValueError, OSError):
                        report['status'] = 'FAIL'
                try:
                    docker.close()
                    report['docker_boundary_closed'] = 'PASS'
                except OSError:
                    report['docker_boundary_closed'] = 'FAIL'
                if base.CANCELLED or report['controller_tmp_removed'] != 'PASS' or report['docker_boundary_closed'] != 'PASS':
                    report['status'] = 'FAIL'
                public_receipt(output / 'receipt.json', report)
        except (base.Cancelled, KeyboardInterrupt):
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
    try:
        report = run(args)
        print(json.dumps({'status': report['status'], 'phases': [{k: row[k] for k in ('phase', 'status', 'container_cleanup')}
                                                               for row in report['phases']]}))
        return 0 if report['status'] == 'PASS' else 1
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError, KeyboardInterrupt):
        print('FAIL: KSM stage boundary/input refusal', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
