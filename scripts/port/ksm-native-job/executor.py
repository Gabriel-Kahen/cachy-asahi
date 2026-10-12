#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite disposable hosted VM execution; unchanged producer/build subprocesses."""
import argparse
import fcntl
import hashlib
import importlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import stat
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import acceptance
import boundary
import broker
import consumer
import executor_contract as contracts
import job
import public
import required_paths
import runtime


SOURCE_GATES = frozenset({
    'native-coordinator', 'job-identity', 'host-capabilities', 'initial-disk-reserve',
    *('host-tool-' + name for name in ('docker', 'python3', 'gpg', 'lscpu', 'zstd', 'git')),
    'output-namespace', 'source-capture', 'source-policy', 'source-copy', 'private-launchers',
    'source-clock', 'private-runtime', 'captured-stage-load', 'docker-cli-capture', 'docker-identity',
    'daemon-readiness', 'daemon-image-baseline', 'daemon-container-baseline', 'broker-reservation',
    'rpc-service', 'runtime-socket-binding', 'endpoint-alias-observations', 'pipeline-source-verification'})

def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def save(path, value, *, directory_fd=None, guard=lambda: None):
    data = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    need(len(data) <= 65536, 'job-status-byte-bound')
    parent = contracts.directory(path.parent) if directory_fd is None else os.dup(directory_fd)
    name = '.ksm-status-' + secrets.token_hex(16)
    fd = None
    try:
        guard()
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            fd = None
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        guard()
        os.replace(name, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
        guard()
    finally:
        if fd is not None: os.close(fd)
        try: os.unlink(name, dir_fd=parent)
        except FileNotFoundError: pass
        os.close(parent)


def initial(args):
    return {'schema_version': 1, 'scope': 'DEVELOPMENT TEST ONLY', 'status': 'FAIL',
            'source_commit': args.source_commit, 'packet_sha256': args.packet_sha256,
            'phase': 'source', 'source_gate': 'native-coordinator', 'source_failure_reason': None,
            'source_observations': {}, 'producer': 'NOT RUN', 'builds': ['NOT RUN', 'NOT RUN'],
            'comparison': 'NOT RUN', 'lifecycle': 'NOT RUN', 'cleanup': 'NOT RUN',
            'public_export': 'NOT RUN', 'cancelled': False, 'ownership_uncertain': False,
            'hardware': 'NOT RUN', 'management': 'NOT RUN', 'performance': 'NOT RUN',
            'published': False, 'legacy_build_cache_absence': 'NOT ESTABLISHED'}


def directory_identity(path):
    fd = contracts.directory(path)
    try:
        info = os.fstat(fd)
        return info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)
    finally: os.close(fd)


def owned_output(args):
    identities = getattr(args, '_owned_directories', None)
    return identities is not None and all(directory_identity(path) == expected for path, expected in identities.items())


def save_status(args, report):
    def guard(): need(owned_output(args), 'owned-job-status-directory-required')
    guard()
    save(args.output / 'private/result.json', report, directory_fd=args._private_fd, guard=guard)


def invalidate_public(output, report, ownership=None):
    """A late job failure cannot retain its own authoritative PASS evidence."""
    path = output / 'public/evidence.json'
    if 'public_evidence_sha256' not in report:
        return
    need(ownership is not None, 'owned-public-descriptors-required')
    directory_fd, evidence_fd, expected_directory, expected_file = ownership
    parent = contracts.directory(path.parent)
    try:
        need(directory_identity(path.parent) == expected_directory and
             directory_identity(path.parent) == directory_identity_fd(directory_fd), 'foreign-public-directory-refused')
        named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        need((named.st_dev, named.st_ino) == expected_file, 'foreign-public-file-refused')
    finally: os.close(parent)
    fd = os.dup(evidence_fd)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid() and
             info.st_size <= 65536 and (info.st_dev,info.st_ino) == expected_file, 'owned-public-evidence-required')
        os.lseek(fd,0,os.SEEK_SET)
        data = os.read(fd, 65537)
        failure = b'{"schema_version":1,"scope":"DEVELOPMENT TEST ONLY","status":"FAIL-native-job"}\n'
        if data == failure:
            report['public_export'] = 'NOT ACCEPTED'
            return
        need(len(data) == info.st_size and job.sha(data) == report['public_evidence_sha256'],
             'foreign-public-evidence-refused')
        os.ftruncate(fd, 0); os.lseek(fd, 0, os.SEEK_SET)
        view = memoryview(failure)
        while view:
            count = os.write(fd, view)
            need(count > 0, 'failure-evidence-write')
            view = view[count:]
        os.fsync(fd)
        report['public_export'] = 'NOT ACCEPTED'
    finally:
        os.close(fd)


def directory_identity_fd(fd):
    info = os.fstat(fd)
    return info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)


def ordinary(args, *, report=None):
    if report is not None: report['source_gate'] = 'native-coordinator'
    need(args.execute_native and platform.system() == 'Linux' and platform.machine() in {'arm64', 'aarch64'} and
         os.getuid() == os.geteuid() != 0 and os.getgid() == os.getegid() != 0, 'native-positive-coordinator-required')
    if report is not None: report['source_gate'] = 'job-identity'
    need(os.environ.get('GITHUB_REPOSITORY') == 'Gabriel-Kahen/cachy-asahi' and
         os.environ.get('RUNNER_ARCH') == 'ARM64' and os.environ.get('RUNNER_OS') == 'Linux' and
         os.environ.get('GITHUB_SHA') == os.environ.get('GITHUB_WORKFLOW_SHA') == args.source_commit,
         'genuine-disposable-hosted-job-required')
    if report is not None: report['source_gate'] = 'host-capabilities'
    caps = re.findall(r'^Cap(?:Eff|Prm):\s+([0-9a-f]+)$', Path('/proc/self/status').read_text(), re.M)
    need(len(caps) == 2 and all(int(value, 16) == 0 for value in caps), 'host-capabilities-refused')
    for name in ('docker', 'python3', 'gpg', 'lscpu', 'zstd', 'git'):
        if report is not None: report['source_gate'] = 'host-tool-' + name
        path = Path('/usr/bin') / name
        need(path.is_file() and os.access(path, os.X_OK), 'host-tool-unavailable')
    if report is not None: report['source_gate'] = 'initial-disk-reserve'
    need(shutil.disk_usage(args.output.parent).free >= 24 * 1024**3, 'initial-disk-reserve')


def source_tree(snapshot, destination):
    """Fresh authenticated tree has no pyc, extension or import-path fallback."""
    destination.mkdir(mode=0o700)
    for name, data in snapshot.files.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        mode = int(snapshot.provenance['files'][name]['mode'], 8)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        try:
            os.fchmod(fd, mode)
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                stream.write(data); stream.flush(); os.fsync(fd)
        finally: os.close(fd)
    check_source_tree(snapshot, destination)
    return acceptance.Snapshot(destination, snapshot.files, dict(snapshot.provenance))


def check_source_tree(snapshot, destination):
    found = set()
    for path in destination.rglob('*'):
        need(not path.is_symlink(), 'snapshot-symlink-refused')
        if path.is_dir():
            continue
        name = str(path.relative_to(destination)); found.add(name)
        data, mode = acceptance.captured_file(path)
        need(name in snapshot.files and data == snapshot.files[name] and
             mode == snapshot.provenance['files'][name]['mode'], 'fresh-source-snapshot-drift')
    need(found == set(snapshot.files), 'snapshot-extraneous-source-refused')


def stage_module(snapshot):
    # Nested exec in held stage propagates this importer to BASE/CONTRACT.
    # Bind their pinned stdlib closure too; retain refusal for every other import.
    names = ['argparse', 'contextlib', 'fcntl', 'gzip', 'hashlib', 'importlib', 'importlib.util',
             'io', 'json', 'lzma', 'os', 'pathlib', 'platform', 're', 'resource', 'selectors',
             'shutil', 'signal', 'stat', 'subprocess', 'sys', 'tarfile', 'tempfile', 'time',
             'unicodedata', 'unittest']
    imports = {name: importlib.import_module(name) for name in names}
    return snapshot.module('scripts/port/ksm-lifecycle/stage.py', 'ksm_accepted_stage', imports=imports)


def context_digest(snapshot, private, context, *, deadline=None):
    def alive():
        need(deadline is None or time.monotonic() < deadline, 'bootstrap-context-deadline')
    alive()
    need(Path(context) == private / 'producer/context', 'exact-bootstrap-context-required')
    inputs = contracts.decode(snapshot.files['scripts/ci/inputs.lock.json'])
    expected = {'rootfs.tar.gz': (inputs['rootfs']['sha256'], inputs['rootfs']['size'])}
    for item in inputs['packages']:
        expected['deps/' + item['filename']] = (item['sha256'], item['size'])
        expected['deps/' + item['filename'] + '.sig'] = (item['signature_sha256'], item['signature_size'])
    for item in inputs['keyring_files']:
        expected['keys/' + item['filename']] = (item['sha256'], item['size'])
    boot = contracts.decode(contracts.capture(private / 'producer/bootstrap.json'))
    expected['Dockerfile'] = (boot['dockerfile_sha256'], None)
    expected['pacman.conf'] = (None, None)
    expected['disabled-hooks.txt'] = (None, None)
    found, rows = set(), {}
    for path in sorted(Path(context).rglob('*')):
        alive()
        need(not path.is_symlink(), 'bootstrap-context-link-refused')
        if path.is_dir(): continue
        name = str(path.relative_to(context)); found.add(name)
        need(name in expected, 'bootstrap-context-extra-file')
        parent = contracts.directory(path.parent)
        fd = None
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= 2 * 1024**3,
                 'bootstrap-context-file-bound')
            digest, size = hashlib.sha256(), 0
            while data := os.read(fd, 65536):
                alive(); digest.update(data); size += len(data)
            after = os.fstat(fd)
            need((before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                 (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) and size == before.st_size,
                 'bootstrap-context-read-drift')
            pin, approved_size = expected[name]
            need((pin is None or digest.hexdigest() == pin) and (approved_size is None or size == approved_size),
                 'bootstrap-context-input-pin-drift')
            rows[name] = {'sha256': digest.hexdigest(), 'size': size}
        finally:
            if fd is not None: os.close(fd)
            os.close(parent)
    need(found == set(expected), 'complete-bootstrap-context-required')
    alive()
    return job.sha((json.dumps(rows, sort_keys=True, separators=(',', ':')) + '\n').encode())


def launcher_environment(source, private, token, socket_path):
    task_home, bindir = private / 'tool-state', private / 'bin'
    task_home.mkdir(mode=0o700); bindir.mkdir(mode=0o700)
    (task_home / 'docker').mkdir(mode=0o700)
    (private / 'tmp').mkdir(mode=0o700)
    scripts = {'docker': f'exec /usr/bin/python3 -I -B -S {shlex_quote(source / "scripts/port/ksm-native-job/shim.py")} "$@"\n',
               'gpg': 'exec /usr/bin/gpg --no-autostart --lock-never "$@"\n'}
    for name, body in scripts.items():
        path = bindir / name
        path.write_text('#!/bin/sh\n' + body); path.chmod(0o700)
    env = {'PATH': str(bindir) + ':/usr/bin:/bin', 'DOCKER_CONFIG': str(task_home / 'docker'),
           'GNUPGHOME': str(task_home / 'gnupg'), 'PYTHONNOUSERSITE': '1',
           'DOCKER_HOST': 'unix:///run/docker.sock', 'DOCKER_BUILDKIT': '0', 'LC_ALL': 'C',
           'PYTHONDONTWRITEBYTECODE': '1', 'TMPDIR': str(private / 'tmp'),
           'KSM_DOCKER_BROKER_SOCKET': str(socket_path), 'KSM_DOCKER_BROKER_TOKEN': token}
    for name in ('HOME', 'GITHUB_SHA', 'GITHUB_WORKFLOW_SHA', 'GITHUB_REPOSITORY', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT',
                 'RUNNER_ARCH', 'RUNNER_OS', 'ImageVersion', 'ImageOS'):
        if name in os.environ: env[name] = os.environ[name]
    return env


def shlex_quote(path):
    # Generated paths are local data, quoted for the tiny explicit exec launcher.
    return "'" + str(path).replace("'", "'\"'\"'") + "'"


def allowance(end, maximum, reserve):
    remaining = end - time.monotonic() - reserve
    need(remaining > 0, 'aggregate-phase-reserve')
    return min(maximum, remaining)


def journal_rows(owner):
    data = contracts.capture(owner.journal_path, broker.JOURNAL_LIMIT)
    rows = [contracts.decode(line) for line in data.splitlines()]
    need(rows == owner.events, 'durable-broker-journal-drift')
    return rows


def scoped_run(owner, runner, command, maximum, reserve, **options):
    end = time.monotonic() + allowance(runner.deadline, maximum, reserve)
    owner.operation_deadline = end
    try:
        with owner.backend.runner.phase_scope(end):
            return runner.run(command, timeout=max(.001, end-time.monotonic()), **options)
    finally: owner.operation_deadline = None


def owned_cleanup(owner, end):
    cleanup_end = min(end - 30, time.monotonic() + 180)
    need(cleanup_end > time.monotonic(), 'cleanup-reserve-expired')
    owner.operation_deadline = cleanup_end
    owner.backend.cleanup_mode = True
    try:
        with owner.backend.runner.phase_scope(cleanup_end): return owner.cleanup()
    finally:
        owner.operation_deadline = None; owner.backend.cleanup_mode = False


def lifecycle_grant_inputs(producer, pair, binding):
    """The held stage's exact contract inputs, before its private nonce/signing."""
    paths = {'scripts/client/stage.py', 'scripts/ci/source_suites.py',
             'scripts/port/ksm-lifecycle/stage.py', 'scripts/port/ksm-lifecycle/worker.py',
             'scripts/port/ksm-lifecycle/contract.py'}
    pins = {name: job.PINS[name] for name in paths}
    package = contracts.plain(pair['package'])
    expected = {'schema_version': 1, 'purpose': 'ksm-diagnostic-development-lifecycle',
        'scope': 'DEVELOPMENT TEST ONLY', 'phase': 'lifecycle',
        'source_commit': binding['source_commit'], 'run_id': binding['run_id'],
        'daemon_id': binding['daemon_id'], 'image_id': producer['image_id'], 'uid': binding['uid'],
        'package': package, 'approved_inputs_sha256': job.MAP_SHA,
        'bootstrap_sha256': producer['sha256']['bootstrap.json'], 'packages_sha256': job.PACKAGES_SHA,
        'current_inputs_sha256': job.INPUTS_SHA, 'source_sha256': pins}
    inputs = {'bootstrap.json': expected['bootstrap_sha256'], 'packages.lock': job.PACKAGES_SHA,
              'current-inputs.json': job.INPUTS_SHA, 'approved-inputs.json': job.MAP_SHA,
              package['filename']: package['sha256']}
    return expected, pins, inputs


def pipeline(snapshot, source, private, owner, service, runner, endpoint_observations, binding, report, state):
    """Only observed zero-exit operations can advance to the next consumer."""
    need(not owner.failed, 'failed-broker-refuses-producer')
    report['phase'] = 'producer'
    command = consumer.producer_command(source, private, inputs_sha=job.INPUTS_SHA, recipes_sha=job.RECIPES_SHA)
    command.insert(1, '-I'); command.insert(3, '-S')
    produced = scoped_run(owner, runner, command, 6600, 1650, log='producer.log', service=service.poll)
    check_source_tree(snapshot, source)
    producer = contracts.validate_producer(snapshot, private / 'producer', produced.returncode, binding,
                                          journal_rows(owner), consumer=consumer, endpoint_observations=endpoint_observations)
    report['producer'] = 'PASS'
    approved = {name: job.sha(snapshot.files['packages/tools/cachy-asahi-ksmctl/' + name]) for name in job.KSM_INPUTS}
    approved_path = private / 'approved-inputs.json'
    save(approved_path, approved)
    need(job.sha(contracts.capture(approved_path)) == job.MAP_SHA, 'approved15-byte-pin')
    exits = []
    for index, command in enumerate(consumer.build_commands(source, private, producer['image_id'])):
        state.check(); owner.phase = 'ksm-' + str(index + 1)
        report['phase'] = owner.phase
        later = (1 - index) * 360 + 930
        command.insert(1, '-I'); command.insert(3, '-S')
        built = scoped_run(owner, runner, command, 360, later,
                           log='ksm-build-' + str(index + 1) + '.log', service=service.poll)
        contracts.clean_exit(built.returncode); exits.append(built.returncode)
        report['builds'][index] = 'EXIT ZERO'
        check_source_tree(snapshot, source)
    contract = snapshot.module('scripts/port/ksm-lifecycle/contract.py', 'ksm_accepted_contract', imports={
        name: importlib.import_module(name) for name in ('gzip', 'hashlib', 'io', 'json', 'lzma', 'os', 'pathlib', 're', 'stat', 'tarfile')})
    pair = contracts.validate_ksm_pair(snapshot, producer, [private / 'build-1', private / 'build-2'], exits,
                                       approved_path, journal_rows(owner), contract=contract, consumer=consumer)
    report['builds'] = ['PASS', 'PASS']
    report['phase'] = 'comparison'
    command = consumer.compare_command(source, private); command.insert(1, '-I'); command.insert(3, '-S')
    compared = runner.run(command, timeout=allowance(runner.deadline, 120, 810), log='comparison.log')
    contracts.clean_exit(compared.returncode)
    comparison = contracts.decode(compared.stdout)
    consumer.validate_comparison(comparison, pair['package']['filename']); report['comparison'] = 'PASS'
    report['phase'] = 'lifecycle'
    lifecycle_binding = {'image': producer['image_id'], 'daemon-id': binding['daemon_id'],
        'docker-endpoint': producer['runner_endpoint'], 'docker-sha256': owner.backend.cli_sha256,
        'docker-socket-device': str(owner.backend.socket_identity[0]),
        'docker-socket-inode': str(owner.backend.socket_identity[1]), 'source-commit': binding['source_commit'],
        'run-id': binding['run_id'], 'runner-sha256': producer['sha256']['runner.json'],
        'bootstrap-sha256': producer['sha256']['bootstrap.json'],
        'stage-sha256': job.PINS['scripts/port/ksm-lifecycle/stage.py'],
        'worker-sha256': job.PINS['scripts/port/ksm-lifecycle/worker.py'],
        'contract-source-sha256': job.PINS['scripts/port/ksm-lifecycle/contract.py'],
        'build-1-provenance-sha256': pair['provenance_sha256'][0],
        'build-2-provenance-sha256': pair['provenance_sha256'][1]}
    command = consumer.lifecycle_command(source, private, lifecycle_binding, job.PINS)
    command.insert(1, '-I'); command.insert(3, '-S')
    lifecycle_end = time.monotonic() + allowance(runner.deadline, 600, 210)
    with runner.phase_scope(lifecycle_end), runner.lifecycle_outputs(*lifecycle_grant_inputs(producer, pair, binding)):
        lifecycle_child = runner.run(command, timeout=max(.001, lifecycle_end-time.monotonic()), log='lifecycle.log')
    contracts.clean_exit(lifecycle_child.returncode)
    lifecycle = contracts.decode(contracts.capture(private / 'lifecycle/receipt.json'))
    report['lifecycle'] = 'NOT ACCEPTED'
    report['phase'] = 'cleanup'
    cleaned = owned_cleanup(owner, runner.deadline)
    need(cleaned['status'] == 'PASS', 'owned-cleanup-refused'); report['cleanup'] = 'PASS'
    encoded, expected = contracts.public_acceptance(snapshot, producer, pair, comparison, compared.returncode,
            lifecycle, lifecycle_child.returncode, journal_rows(owner), consumer=consumer, public=public)
    report['lifecycle'] = 'PASS'
    state.check(); report['phase'] = 'public'
    public_end = time.monotonic() + allowance(runner.deadline, 30, 0)
    accepted = private / 'consumer-acceptance.json'
    save(accepted, contracts.decode(encoded))
    data = contracts.capture(accepted)
    def remember_public(directory_fd,evidence_fd,encoded):
        state.owned_public = (os.dup(directory_fd),os.dup(evidence_fd),directory_identity_fd(directory_fd),
                              (os.fstat(evidence_fd).st_dev,os.fstat(evidence_fd).st_ino))
        report['public_evidence_sha256'] = job.sha(encoded)
    exported = public.export({'path': str(accepted), 'size': len(data), 'sha256': job.sha(data)},
                  contracts.plain(pair['archives']), private.parent / 'public', expected,
                  cancelled=lambda: state.signum is not None or time.monotonic() >= public_end,
                  on_owned=remember_public)
    report['public_evidence_sha256'] = job.sha((json.dumps(exported, sort_keys=True, indent=2) + '\n').encode())
    state.check(); need(time.monotonic() < public_end, 'public-phase-timeout')
    report.update(status='PASS', public_export='PASS', phase='complete')


def execute(args, state):
    report = initial(args)
    args._report = report
    args._owned_directories = None
    args._private_fd = None
    state.owned_public = None
    private, owner, service, native, docker_runner, transport = None, None, None, None, None, None
    try:
        ordinary(args, report=report)
        report['source_gate'] = 'output-namespace'
        need(args.output.parent == Path(os.environ['RUNNER_TEMP']) and
             args.output.name == 'ksm-native-' + os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT'],
             'fresh-scoped-job-output-required')
        args.output.mkdir(mode=0o700); private = args.output / 'private'; private.mkdir(mode=0o700)
        args._owned_directories = {path: directory_identity(path) for path in (args.output, private)}
        args._private_fd = contracts.directory(private)
        save_status(args, report)
        report['source_gate'] = 'source-capture'
        snapshot = acceptance.capture(args.source_root, args.source_root / 'scripts/port/ksm-native-job/packet.lock.json',
            args.packet_sha256, required_paths.EXPECTED_PATHS, required_paths.WORKFLOW, args.source_commit)
        report['source_gate'] = 'source-policy'
        job.source_policy(snapshot.files)
        report['source_gate'] = 'source-copy'
        source = private / 'source'; execution_snapshot = source_tree(snapshot, source)
        token, nonce = secrets.token_hex(32), secrets.token_hex(16)
        socket_path = private / 'rpc.sock'
        report['source_gate'] = 'private-launchers'
        env = launcher_environment(source, private, token, socket_path)
        report['source_gate'] = 'source-clock'
        end = args.started_at + job.BUDGETS['aggregate_seconds']
        need(math.isfinite(args.started_at) and 0 <= time.monotonic() - args.started_at <= 180, 'shared-source-deadline')
        logs = private / 'logs'; logs.mkdir(mode=0o700)
        docker_logs = private / 'docker-logs'; docker_logs.mkdir(mode=0o700)
        cleanenv = {key: env[key] for key in ('HOME', 'LC_ALL', 'DOCKER_CONFIG', 'DOCKER_HOST', 'DOCKER_BUILDKIT') if key in env}
        cleanenv['PATH'] = '/usr/bin:/bin'
        report['source_gate'] = 'private-runtime'
        docker_runner = runtime.Runner(cleanenv, private, docker_logs, deadline_at=end)
        report['source_gate'] = 'captured-stage-load'
        stage = stage_module(execution_snapshot)
        report['source_gate'] = 'docker-cli-capture'
        cli = boundary.cli_capture(); cli_sha = job.sha(cli)
        report['source_gate'] = 'docker-identity'
        transport = boundary.create(stage, runtime, docker_runner, cli_sha)
        report['source_gate'] = 'daemon-readiness'
        info = contracts.decode(transport.call(['docker', '--host=' + transport.endpoint, 'info', '--format', '{{json .}}']).stdout)
        need(info.get('Architecture') in {'aarch64', 'arm64'} and info.get('OSType') == 'linux' and
             info.get('CgroupVersion') == '2' and type(info.get('SecurityOptions')) is list and
             all(type(v) is str and not re.search(r'\b(rootless|userns)\b', v) for v in info['SecurityOptions']),
             'rootful-native-daemon-required')
        for kind in ('image', 'container'):
            report['source_gate'] = 'daemon-' + kind + '-baseline'
            result = transport.call(['docker', '--host=' + transport.endpoint, kind, 'ls', '--all', '--quiet', '--no-trunc'])
            report['source_observations'][kind + '_returned_exit'] = (result.returncode if type(result.returncode) is int
                    and -128 <= result.returncode <= 255 else None)
            report['source_observations'][kind + '_returned_lines'] = len(result.stdout.splitlines())
            need(result.returncode == 0 and not result.stdout.strip(), 'fresh-disposable-daemon-required')
        binding = {'source_commit': args.source_commit, 'run_id': os.environ['GITHUB_RUN_ID'],
                   'packet_sha256': args.packet_sha256, 'uid': os.getuid(), 'gid': os.getgid(),
                   'runner_arch': 'ARM64', 'docker_endpoint': transport.endpoint,
                   'daemon_id': transport.expected, 'nonce': nonce}
        report['source_gate'] = 'broker-reservation'
        owner = broker.Broker(transport, private / 'docker-journal.jsonl', nonce, private, source,
            context_digest=lambda path: context_digest(snapshot, private, path,
                deadline=owner.operation_deadline or owner.deadline),
            binding={key: binding[key] for key in ('source_commit', 'run_id', 'packet_sha256', 'uid', 'gid')},
            deadline=end, cancelled=lambda: state.signum is not None)
        report['source_gate'] = 'rpc-service'
        service = broker.Service(socket_path, owner, token)
        # The supervisor explicitly permits only this captured owned socket.
        info = socket_path.lstat()
        socket_identity = (info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
        report['source_gate'] = 'runtime-socket-binding'
        docker_runner.register_socket(socket_path, socket_identity)
        native = runtime.Runner(env, private, logs, deadline_at=end, allowed_sockets={socket_path: socket_identity})
        report['source_gate'] = 'endpoint-alias-observations'
        observations = {}
        for endpoint in ('unix:///run/docker.sock', 'unix:///var/run/docker.sock'):
            info = Path(endpoint.removeprefix('unix://')).stat()
            observations[endpoint] = {'device': info.st_dev, 'inode': info.st_ino}
        report['source_gate'] = 'pipeline-source-verification'
        pipeline(snapshot, source, private, owner, service, native, observations, binding, report, state)
    except (Exception, runtime.Cancelled, KeyboardInterrupt) as error:
        report.update(status='FAIL', failure_category=type(error).__name__,
                      cancelled=isinstance(error, (runtime.Cancelled, KeyboardInterrupt)) or state.signum is not None)
        if report['phase'] == 'source':
            gate = report.get('source_gate')
            report['source_failure_reason'] = (gate if gate in SOURCE_GATES else 'unknown-source-step') + '-refused'
        report['ownership_uncertain'] = report['phase'] in {'producer', 'ksm-1', 'ksm-2', 'lifecycle', 'cleanup'}
        if owner is not None: owner.failed = True
    finally:
        with runtime.defer_signals() as events:
            if owner is not None and report['cleanup'] != 'PASS':
                try:
                    cleanup = owned_cleanup(owner, docker_runner.deadline)
                    report['cleanup'] = cleanup['status']
                    if cleanup['status'] != 'PASS': report['status'] = 'FAIL'
                except BaseException:
                    report.update(status='FAIL', cleanup='FAIL', ownership_uncertain=True)
            for resource in (service, owner, transport, native, docker_runner):
                if resource is not None:
                    try: resource.close()
                    except BaseException: report.update(status='FAIL', cleanup='FAIL')
            if state.signum is not None or events: report.update(status='FAIL', cancelled=True)
            if report['status'] != 'PASS' and private is not None and owned_output(args):
                try: invalidate_public(args.output, report, state.owned_public)
                except (OSError, ValueError): report['public_export'] = 'FAIL-evidence-invalidation'
            if private is not None: save_status(args, report)
        if state.signum is not None or events:
            report.update(status='FAIL', cancelled=True)
            if private is not None and owned_output(args):
                with runtime.defer_signals():
                    try: invalidate_public(args.output, report, state.owned_public)
                    except (OSError, ValueError): report['public_export'] = 'FAIL-evidence-invalidation'
                    save_status(args, report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source-root', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    for name in ('source-commit', 'packet-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--started-at', required=True, type=float)
    parser.add_argument('--execute-native', action='store_true')
    args = parser.parse_args()
    report = initial(args)
    try:
        with runtime.cancellation_handlers() as state:
            report = execute(args, state)
            print(json.dumps(report, sort_keys=True), flush=True)
    except (runtime.Cancelled, KeyboardInterrupt):
        report = getattr(args, '_report', report)
        report.update(status='FAIL', cancelled=True)
        if owned_output(args):
            with runtime.defer_signals():
                try: invalidate_public(args.output, report, state.owned_public)
                except (OSError, ValueError): report['public_export'] = 'FAIL-evidence-invalidation'
                save_status(args, report)
        print(json.dumps(report, sort_keys=True), flush=True)
    # Retain the three invalidation descriptors through the terminal signal scope.
    # This CLI exits immediately; the kernel closes them without a new signal gap.
    return 0 if report['status'] == 'PASS' and not report['cancelled'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
