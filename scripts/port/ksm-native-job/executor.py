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
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import acceptance
import boundary
import broker
import consumer
import current_cache
import executor_contract as contracts
import job
import public
import required_paths
import runtime


REFUSAL_PREFIX = b'KSM_PRODUCER_REFUSAL_V1 '
REFUSAL_GATES = frozenset({'PREFLIGHT','OUTPUT_BIND','GRAPH_LOAD','WRAP','NATIVE_ENTRY','NATIVE_RETURN','CONTEXT_EXIT','UNKNOWN'})
REFUSAL_PREDICATES = frozenset({
    'producer-annotation-custody','producer-binding-missing','producer-code-custody',
    'producer-custody-bound','producer-custody-keys','producer-deadline','producer-file',
    'producer-file-bound','producer-file-drift','producer-guard-invalidated',
    'producer-image-binding','producer-image-drift','producer-inventory-cap',
    'producer-module-custody','producer-module-grant','producer-native-argv',
    'producer-output','producer-output-binding','producer-output-directory',
    'producer-output-exists','producer-output-parent-drift','producer-path',
    'producer-path-custody','producer-private-parent','producer-project-import',
    'producer-relative-project-import','producer-source-drift','producer-source-pin',
    'producer-unbound-import','producer-wrapper-custody','producer-wrapper-grant',
    'producer-wrapper-output','producer-wrapper-replay','producer-wrapper-slot','UNKNOWN'})


def producer_refusal(result, observation):
    """Optional fixed leaf after an observed natural125; never grants acceptance."""
    try:
        if type(result) is not subprocess.CompletedProcess or type(observation) is not dict:
            return None
        if any(type(key) is not str for key in observation) or set(observation) != {'started','natural_poll_code','runner_return_code','reaped_code','reaping','before_cleanup'}:
            return None
        state = object.__getattribute__(result, '__dict__')
        if type(state) is not dict or any(type(key) is not str for key in state) or set(state) != {'args','returncode','stdout','stderr'}:
            return None
        if type(state.get('returncode')) is not int or state['returncode'] != 125:
            return None
        if observation.get('started') is not True or type(observation.get('reaping')) is not str or observation['reaping'] != 'COMPLETED':
            return None
        for key in ('natural_poll_code','runner_return_code','reaped_code'):
            if type(observation.get(key)) is not int or observation[key] != 125:
                return None
        before = observation.get('before_cleanup')
        if type(before) is not dict or any(type(key) is not str for key in before) or set(before) != {'state','returncode'}:
            return None
        if type(before.get('state')) is not str or before['state'] != 'exited' or type(before.get('returncode')) is not int or before['returncode'] != 125:
            return None
        raw = state.get('stdout')
        if type(raw) is not bytes or not 0 < len(raw) <= 8 * 1024**2 or not raw.endswith(b'\n') or raw.count(REFUSAL_PREFIX) != 1:
            return None
        start = raw.find(REFUSAL_PREFIX)
        if start and raw[start - 1:start] != b'\n':
            return None
        line = raw[start:raw.find(b'\n', start)]
        if not line.startswith(REFUSAL_PREFIX) or len(line) + 1 > 512:
            return None
        def pairs(items):
            value = {}
            for key, item in items:
                if key in value: raise ValueError('duplicate-refusal-key')
                value[key] = item
            return value
        def constant(_): raise ValueError('nonfinite-refusal')
        value = json.loads(line[len(REFUSAL_PREFIX):].decode('ascii'), object_pairs_hook=pairs, parse_constant=constant)
        if type(value) is not dict or set(value) not in ({'schema_version','last_source_gate','predicate'}, {'schema_version','last_source_gate','predicate','rejected_import_root'}):
            return None
        if type(value['schema_version']) is not int or value['schema_version'] != 1 or type(value['last_source_gate']) is not str or value['last_source_gate'] not in REFUSAL_GATES or type(value['predicate']) is not str or value['predicate'] not in REFUSAL_PREDICATES:
            return None
        if 'rejected_import_root' in value:
            root = value['rejected_import_root']
            if value['predicate'] != 'producer-unbound-import' or type(root) is not str or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}', root):
                return None
        return value
    except Exception:
        return None


SOURCE_GATES = frozenset({
    'native-coordinator', 'job-identity', 'host-capabilities', 'initial-disk-reserve',
    *('host-tool-' + name for name in ('docker', 'python3', 'gpg', 'lscpu', 'zstd', 'git')),
    'output-namespace', 'source-capture', 'source-policy', 'source-copy', 'private-launchers',
    'source-clock', 'private-runtime', 'captured-stage-load', 'docker-cli-capture', 'docker-identity',
    'daemon-readiness', 'daemon-image-baseline', 'daemon-container-baseline', 'daemon-baseline-capture', 'broker-reservation',
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
            'producer_mutation': 'NOT_STARTED', 'daemon_baseline': None,
            'producer_diagnostics': broker.Diagnostics().snapshot(runtime.RunObservation().summary()),
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


def ordinary(args, *, report=None, deadline=None):
    acceptance.alive(deadline)
    if report is not None: report['source_gate'] = 'native-coordinator'
    need(args.execute_native and platform.system() == 'Linux' and platform.machine() in {'arm64', 'aarch64'} and
         os.getuid() == os.geteuid() != 0 and os.getgid() == os.getegid() != 0, 'native-positive-coordinator-required')
    if report is not None: report['source_gate'] = 'job-identity'
    need(os.environ.get('GITHUB_REPOSITORY') == 'Gabriel-Kahen/cachy-asahi' and
         os.environ.get('RUNNER_ARCH') == 'ARM64' and os.environ.get('RUNNER_OS') == 'Linux' and
         os.environ.get('GITHUB_SHA') == os.environ.get('GITHUB_WORKFLOW_SHA') == args.source_commit,
         'genuine-disposable-hosted-job-required')
    if report is not None: report['source_gate'] = 'host-capabilities'
    acceptance.alive(deadline)
    caps = re.findall(r'^Cap(?:Eff|Prm):\s+([0-9a-f]+)$', Path('/proc/self/status').read_text(), re.M)
    acceptance.alive(deadline)
    need(len(caps) == 2 and all(int(value, 16) == 0 for value in caps), 'host-capabilities-refused')
    for name in ('docker', 'python3', 'gpg', 'lscpu', 'zstd', 'git'):
        if report is not None: report['source_gate'] = 'host-tool-' + name
        path = Path('/usr/bin') / name
        acceptance.alive(deadline)
        need(path.is_file(), 'host-tool-unavailable')
        acceptance.alive(deadline)
        need(os.access(path, os.X_OK), 'host-tool-unavailable')
        acceptance.alive(deadline)
    if report is not None: report['source_gate'] = 'initial-disk-reserve'
    acceptance.alive(deadline)
    need(shutil.disk_usage(args.output.parent).free >= 24 * 1024**3, 'initial-disk-reserve')
    acceptance.alive(deadline)


def source_tree(snapshot, destination, *, deadline=None):
    """Fresh authenticated tree has no pyc, extension or import-path fallback."""
    acceptance.alive(deadline)
    destination.mkdir(mode=0o700)
    acceptance.alive(deadline)
    for name, data in snapshot.files.items():
        acceptance.alive(deadline)
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        acceptance.alive(deadline)
        mode = int(snapshot.provenance['files'][name]['mode'], 8)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        try:
            acceptance.alive(deadline)
            os.fchmod(fd, mode)
            acceptance.alive(deadline)
            view, offset = memoryview(data), 0
            while offset < len(view):
                acceptance.alive(deadline)
                chunk = view[offset:offset + 65536]
                written = os.write(fd, chunk)
                acceptance.alive(deadline)
                need(type(written) is int and 0 < written <= len(chunk), 'source-copy-write-progress')
                offset += written
            acceptance.alive(deadline)
            os.fsync(fd)
            acceptance.alive(deadline)
        finally: os.close(fd)
    check_source_tree(snapshot, destination, deadline=deadline)
    acceptance.alive(deadline)
    return acceptance.Snapshot(destination, snapshot.files, dict(snapshot.provenance))


def check_source_tree(snapshot, destination, *, deadline=None):
    acceptance.alive(deadline)
    found = set()
    for path in destination.rglob('*'):
        acceptance.alive(deadline)
        need(not path.is_symlink(), 'snapshot-symlink-refused')
        acceptance.alive(deadline)
        directory = path.is_dir()
        acceptance.alive(deadline)
        if directory:
            continue
        name = str(path.relative_to(destination)); found.add(name)
        data, mode = acceptance.captured_file(path, deadline=deadline)
        acceptance.alive(deadline)
        need(name in snapshot.files and data == snapshot.files[name] and
             mode == snapshot.provenance['files'][name]['mode'], 'fresh-source-snapshot-drift')
    acceptance.alive(deadline)
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


def launcher_environment(source, private, token, socket_path, *, deadline=None):
    acceptance.alive(deadline)
    task_home, bindir = private / 'tool-state', private / 'bin'
    task_home.mkdir(mode=0o700)
    acceptance.alive(deadline)
    bindir.mkdir(mode=0o700)
    acceptance.alive(deadline)
    (task_home / 'docker').mkdir(mode=0o700)
    acceptance.alive(deadline)
    (private / 'tmp').mkdir(mode=0o700)
    acceptance.alive(deadline)
    scripts = {'docker': f'exec /usr/bin/python3 -I -B -S {shlex_quote(source / "scripts/port/ksm-native-job/shim.py")} "$@"\n',
               'gpg': 'exec /usr/bin/gpg --no-autostart --lock-never "$@"\n'}
    for name, body in scripts.items():
        acceptance.alive(deadline)
        path = bindir / name
        path.write_text('#!/bin/sh\n' + body)
        acceptance.alive(deadline)
        path.chmod(0o700)
        acceptance.alive(deadline)
    env = {'PATH': str(bindir) + ':/usr/bin:/bin', 'DOCKER_CONFIG': str(task_home / 'docker'),
           'GNUPGHOME': str(task_home / 'gnupg'), 'PYTHONNOUSERSITE': '1',
           'DOCKER_HOST': 'unix:///run/docker.sock', 'DOCKER_BUILDKIT': '0', 'LC_ALL': 'C',
           'PYTHONDONTWRITEBYTECODE': '1', 'TMPDIR': str(private / 'tmp'),
           'KSM_DOCKER_BROKER_SOCKET': str(socket_path), 'KSM_DOCKER_BROKER_TOKEN': token}
    for name in ('HOME', 'GITHUB_SHA', 'GITHUB_WORKFLOW_SHA', 'GITHUB_REPOSITORY', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT',
                 'RUNNER_ARCH', 'RUNNER_OS', 'ImageVersion', 'ImageOS'):
        if name in os.environ: env[name] = os.environ[name]
    acceptance.alive(deadline)
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


def scoped_run(owner, runner, command, maximum, reserve, *, phase_end=None, **options):
    end = time.monotonic() + allowance(runner.deadline, maximum, reserve)
    if phase_end is not None: end = min(end, phase_end)
    owner.operation_deadline = end
    try:
        with owner.backend.runner.phase_scope(end):
            return runner.run(command, timeout=max(.001, end-time.monotonic()), **options)
    finally: owner.operation_deadline = None


def baseline_observe(owner, stage, end, *, cleanup=False):
    """Baseline observations share the caller's absolute phase cutoff."""
    baseline = owner.baseline
    previous = baseline.operation_deadline
    baseline.operation_deadline = end
    try:
        with owner.backend.runner.phase_scope(end): baseline.observe(stage, cleanup=cleanup)
    finally: baseline.operation_deadline = previous


def owned_cleanup(owner, end):
    cleanup_end = getattr(owner, 'cleanup_end', None)
    if cleanup_end is None:
        cleanup_end = min(end - 30, time.monotonic() + 180)
        owner.cleanup_end = cleanup_end
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
    producer_end = time.monotonic() + allowance(runner.deadline, 6600, 1650)
    check_source_tree(snapshot, source, deadline=producer_end)
    with runner.phase_scope(producer_end):
        current_cache.prefill(snapshot, source, private, runner, state, producer_end)
    check_source_tree(snapshot, source, deadline=producer_end)
    baseline_observe(owner, 'before_producer', producer_end)
    command = consumer.producer_command(source, private, inputs_sha=job.INPUTS_SHA,
        recipes_sha=job.RECIPES_SHA, producer_end=producer_end)
    command.insert(1, '-I'); command.insert(3, '-S')
    report['producer_mutation'] = 'UNCERTAIN'
    observation = runtime.RunObservation()
    previous_observation = getattr(runner, 'observation', None)
    diagnostics = getattr(owner, 'diagnostics', None)
    if type(diagnostics) is not broker.Diagnostics: diagnostics = None
    runner.observation = observation
    try:
        produced = scoped_run(owner, runner, command, 6600, 1650, phase_end=producer_end,
                              log='producer.log', service=service.poll)
        observation.runner_return_code = observation.code(produced.returncode)
    except BaseException as error:
        if diagnostics is not None: diagnostics.failure('PRODUCER', error)
        raise
    finally:
        runner.observation = previous_observation
        if diagnostics is not None:
            diagnostics.producer = observation.summary()
            report['producer_diagnostics'] = diagnostics.snapshot(diagnostics.producer)
    if produced.returncode == 0: report['producer_mutation'] = 'COMPLETE_REJECTED'
    check_source_tree(snapshot, source, deadline=producer_end)
    # Observation is subordinate to the existing source check and business refusal.
    try:
        refusal = producer_refusal(produced, observation.summary())
        if refusal is not None: report['producer_refusal'] = refusal
    except BaseException:
        pass
    producer = contracts.validate_producer(snapshot, private / 'producer', produced.returncode, binding,
                                          journal_rows(owner), consumer=consumer, endpoint_observations=endpoint_observations)
    need(producer['image_id'] not in owner.baseline.protected(), 'baseline-ID-collision')
    baseline_observe(owner, 'after_producer', producer_end)
    report['producer_mutation'] = 'COMPLETE_ACCEPTED'
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
        build_end = time.monotonic() + allowance(runner.deadline, 360, later)
        command.insert(1, '-I'); command.insert(3, '-S')
        built = scoped_run(owner, runner, command, 360, later, phase_end=build_end,
                           log='ksm-build-' + str(index + 1) + '.log', service=service.poll)
        contracts.clean_exit(built.returncode); exits.append(built.returncode)
        report['builds'][index] = 'EXIT ZERO'
        check_source_tree(snapshot, source, deadline=build_end)
        baseline_observe(owner, 'after_build_' + str(index + 1), build_end)
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
    baseline_observe(owner, 'before_lifecycle', lifecycle_end)
    with runner.phase_scope(lifecycle_end), runner.lifecycle_outputs(*lifecycle_grant_inputs(producer, pair, binding)):
        lifecycle_child = runner.run(command, timeout=max(.001, lifecycle_end-time.monotonic()), log='lifecycle.log')
    contracts.clean_exit(lifecycle_child.returncode)
    lifecycle = contracts.decode(contracts.capture(private / 'lifecycle/receipt.json'))
    baseline_observe(owner, 'after_lifecycle', lifecycle_end)
    report['lifecycle'] = 'NOT ACCEPTED'
    report['phase'] = 'cleanup'
    cleaned = owned_cleanup(owner, runner.deadline)
    need(cleaned['status'] == 'PASS', 'owned-cleanup-refused')
    baseline_observe(owner, 'after_cleanup', owner.cleanup_end)
    report['daemon_baseline'] = owner.baseline.summary()
    need(report['daemon_baseline']['preservation'] == 'PASS', 'baseline-final-preservation-required')
    report['cleanup'] = 'PASS'
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
    private, owner, service, native, docker_runner, transport, baseline = None, None, None, None, None, None, None
    diagnostics = broker.Diagnostics()
    try:
        report['source_gate'] = 'source-clock'
        now = time.monotonic()
        need(type(args.started_at) in (int, float) and math.isfinite(args.started_at) and
             0 <= now - args.started_at < 180, 'shared-source-deadline')
        source_end = args.started_at + 180
        def source_check():
            state.check()
            acceptance.alive(source_end)
        source_check()
        ordinary(args, report=report, deadline=source_end)
        source_check()
        report['source_gate'] = 'output-namespace'
        need(args.output.parent == Path(os.environ['RUNNER_TEMP']) and
             args.output.name == 'ksm-native-' + os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT'],
             'fresh-scoped-job-output-required')
        args.output.mkdir(mode=0o700)
        source_check()
        private = args.output / 'private'; private.mkdir(mode=0o700)
        # Register the just-created owned directories before deadline refusal so
        # finalization can retain FAIL using the original descriptor guards.
        args._owned_directories = {path: directory_identity(path) for path in (args.output, private)}
        args._private_fd = contracts.directory(private)
        source_check()
        save_status(args, report)
        source_check()
        report['source_gate'] = 'source-capture'
        snapshot = acceptance.capture(args.source_root, args.source_root / 'scripts/port/ksm-native-job/packet.lock.json',
            args.packet_sha256, required_paths.EXPECTED_PATHS, required_paths.WORKFLOW, args.source_commit, deadline=source_end)
        source_check()
        report['source_gate'] = 'source-policy'
        job.source_policy(snapshot.files)
        source_check()
        report['source_gate'] = 'source-copy'
        source = private / 'source'; execution_snapshot = source_tree(snapshot, source, deadline=source_end)
        source_check()
        token, nonce = secrets.token_hex(32), secrets.token_hex(16)
        socket_path = private / 'rpc.sock'
        report['source_gate'] = 'private-launchers'
        env = launcher_environment(source, private, token, socket_path, deadline=source_end)
        source_check()
        report['source_gate'] = 'source-clock'
        end = args.started_at + job.BUDGETS['aggregate_seconds']
        source_check()
        logs = private / 'logs'; logs.mkdir(mode=0o700)
        source_check()
        docker_logs = private / 'docker-logs'; docker_logs.mkdir(mode=0o700)
        source_check()
        cleanenv = {key: env[key] for key in ('HOME', 'LC_ALL', 'DOCKER_CONFIG', 'DOCKER_HOST', 'DOCKER_BUILDKIT') if key in env}
        cleanenv['PATH'] = '/usr/bin:/bin'
        report['source_gate'] = 'private-runtime'
        source_check()
        docker_runner = runtime.Runner(cleanenv, private, docker_logs, deadline_at=end)
        source_check()
        report['source_gate'] = 'captured-stage-load'
        stage = stage_module(execution_snapshot)
        source_check()
        report['source_gate'] = 'docker-cli-capture'
        cli = boundary.cli_capture(); cli_sha = job.sha(cli)
        source_check()
        report['source_gate'] = 'docker-identity'
        source_check()
        with docker_runner.phase_scope(source_end):
            transport = boundary.create(stage, runtime, docker_runner, cli_sha)
        source_check()
        report['source_gate'] = 'daemon-readiness'
        with docker_runner.phase_scope(source_end):
            info = contracts.decode(transport.call(['docker', '--host=' + transport.endpoint, 'info', '--format', '{{json .}}']).stdout)
        need(info.get('Architecture') in {'aarch64', 'arm64'} and info.get('OSType') == 'linux' and
             info.get('CgroupVersion') == '2' and type(info.get('SecurityOptions')) is list and
             all(type(v) is str and not re.search(r'\b(rootless|userns)\b', v) for v in info['SecurityOptions']),
             'rootful-native-daemon-required')
        source_check()
        def inventory_observed(kind, result):
            report['source_gate'] = 'daemon-' + kind + '-baseline'
            report['source_observations'][kind + '_returned_exit'] = (result.returncode if type(result.returncode) is int
                    and -128 <= result.returncode <= 255 else None)
            report['source_observations'][kind + '_returned_lines'] = len(result.stdout.splitlines())
        baseline_binding = {'source_commit': args.source_commit, 'run_id': os.environ['GITHUB_RUN_ID'],
            'run_attempt': os.environ['GITHUB_RUN_ATTEMPT'], 'packet_sha256': args.packet_sha256,
            'uid': os.getuid(), 'gid': os.getgid()}
        report['source_gate'] = 'daemon-baseline-capture'
        baseline = broker.Baseline(transport, private, baseline_binding, nonce, deadline=end,
            cancelled=lambda: state.signum is not None, on_inventory=inventory_observed)
        baseline.operation_deadline = source_end
        with docker_runner.phase_scope(baseline.operation_deadline): baseline.start()
        baseline.operation_deadline = None
        binding = {'source_commit': args.source_commit, 'run_id': os.environ['GITHUB_RUN_ID'],
                   'packet_sha256': args.packet_sha256, 'uid': os.getuid(), 'gid': os.getgid(),
                   'runner_arch': 'ARM64', 'docker_endpoint': transport.endpoint,
                   'daemon_id': transport.expected, 'nonce': nonce}
        source_check()
        report['source_gate'] = 'broker-reservation'
        owner = broker.Broker(transport, private / 'docker-journal.jsonl', nonce, private, source,
            context_digest=lambda path: context_digest(snapshot, private, path,
                deadline=owner.operation_deadline or owner.deadline),
            binding={key: binding[key] for key in ('source_commit', 'run_id', 'packet_sha256', 'uid', 'gid')},
            deadline=end, cancelled=lambda: state.signum is not None, baseline=baseline, diagnostics=diagnostics)
        source_check()
        report['source_gate'] = 'rpc-service'
        service = broker.Service(socket_path, owner, token)
        # The supervisor explicitly permits only this captured owned socket.
        info = socket_path.lstat()
        socket_identity = (info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
        source_check()
        report['source_gate'] = 'runtime-socket-binding'
        docker_runner.register_socket(socket_path, socket_identity)
        native = runtime.Runner(env, private, logs, deadline_at=end, allowed_sockets={socket_path: socket_identity})
        source_check()
        report['source_gate'] = 'endpoint-alias-observations'
        observations = {}
        for endpoint in ('unix:///run/docker.sock', 'unix:///var/run/docker.sock'):
            source_check()
            info = Path(endpoint.removeprefix('unix://')).stat()
            source_check()
            observations[endpoint] = {'device': info.st_dev, 'inode': info.st_ino}
        report['source_gate'] = 'pipeline-source-verification'
        state.check(); need(time.monotonic() < source_end, 'source-phase-deadline')
        pipeline(snapshot, source, private, owner, service, native, observations, binding, report, state)
    except (Exception, runtime.Cancelled, KeyboardInterrupt) as error:
        if report['phase'] == 'producer': diagnostics.failure('PRODUCER', error)
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
                except BaseException as error:
                    diagnostics.failure('CLEANUP', error)
                    report.update(status='FAIL', cleanup='FAIL', ownership_uncertain=True)
                if baseline is not None and baseline.ready:
                    try: baseline_observe(owner, 'after_cleanup', owner.cleanup_end)
                    except BaseException as error:
                        diagnostics.failure('CLEANUP', error)
                        report.update(status='FAIL', cleanup='FAIL', ownership_uncertain=True)
            if baseline is not None: report['daemon_baseline'] = baseline.summary()
            for resource in (service, owner, baseline, transport, native, docker_runner):
                if resource is not None:
                    try: resource.close()
                    except BaseException as error:
                        diagnostics.failure('CLEANUP', error)
                        report.update(status='FAIL', cleanup='FAIL')
            if state.signum is not None or events: report.update(status='FAIL', cancelled=True)
            if report['status'] != 'PASS' and private is not None and owned_output(args):
                try: invalidate_public(args.output, report, state.owned_public)
                except (OSError, ValueError): report['public_export'] = 'FAIL-evidence-invalidation'
            report['producer_diagnostics'] = diagnostics.snapshot(getattr(diagnostics, 'producer', runtime.RunObservation().summary()))
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
