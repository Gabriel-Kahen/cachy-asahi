#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite disposable hosted job using the original producer and held kernel stage."""
import argparse
import json
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
from time import monotonic as snapshot_clock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import packet
import public
import runtime

SETUP, PARALLEL, KERNEL_ENVELOPE, CLEANUP, GUARD = 300, 2050, 18240, 150, 20
DEADLINE = SETUP + PARALLEL + KERNEL_ENVELOPE + CLEANUP + GUARD
BASE_SHA = '89bdb06fea1862b5a6e02b77a4b98f6e04755b02327d875a716bd792929f3a4f'
KERNEL_API_VERSION = '1.48'
HOST_ENV = ('GITHUB_SHA', 'GITHUB_REPOSITORY', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT',
            'RUNNER_ARCH', 'RUNNER_OS', 'ImageVersion', 'ImageOS')


def save(path, value):
    data = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    packet.need(len(data) <= 8 * 1024**2, 'receipt-bound')
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        temporary.replace(path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally: temporary.unlink(missing_ok=True)


def initial(args):
    return {'schema_version': 3, 'stage': 'kernel-native-development-job', 'status': 'FAIL',
        'phase': 'preflight', 'cancelled': False, 'source_commit': args.source_commit,
        'packet_sha256': args.packet_sha256, 'producer': 'NOT RUN', 'kernel_probe': 'NOT RUN',
        'baseline': 'NOT RUN', 'candidate': 'NOT RUN', 'cleanup': 'FAIL', 'native_compilation': 'NOT RUN',
        'kernel_runtime': 'NOT RUN', 'hardware': 'NOT RUN', 'installation': 'NOT RUN',
        'performance': 'NOT MEASURED', 'binary_publication': 'NOT RUN', 'selected_for_release': False,
        'first_failed_phase': 'NONE', 'failure_reason': 'NONE',
        'producer_exit': {'kind': 'NOT_RUN', 'code': None},
        'acquisition_exit': {'kind': 'NOT_RUN', 'code': None},
        'resources': {key: None for key in ('mem_total_bytes', 'mem_available_bytes',
            'initial_free_disk_bytes', 'pre_kernel_free_disk_bytes')},
        'daemon_baseline': {'initial_container_count': None, 'initial_image_id_count': None,
            'pre_identity_sha256': None, 'post_identity_sha256': None, 'preservation': 'NOT_RUN',
            'owned_absence': 'NOT_RUN', 'producer_mutation': 'NOT_STARTED',
            'legacy_build_cache': 'NOT_ESTABLISHED'}}


def failure_reason(error, phase, fallback):
    # Match only exact known errors; never publish arbitrary exception text.
    message = error.args[0] if type(error) is ValueError and len(error.args) == 1 and type(error.args[0]) is str else None
    known = {('preflight', 'host-capabilities'): 'HOST_CAPABILITIES',
        ('preflight', 'host-memory-reserve'): 'HOST_MEMORY_RESERVE',
        ('preflight', 'host-disk-reserve'): 'HOST_DISK_RESERVE',
        ('preflight', 'host-tool-unavailable'): 'HOST_TOOL_UNAVAILABLE',
        ('source', 'baseline-containers-present'): 'DAEMON_CONTAINERS_PRESENT',
        ('producer', 'baseline-ID-collision'): 'PRODUCER_BASELINE_ID_COLLISION',
        ('producer', 'baseline-changed'): 'DAEMON_BASELINE_CHANGED',
        ('cleanup', 'baseline-changed'): 'DAEMON_BASELINE_CHANGED',
        ('parallel', 'command-timeout'): 'PARALLEL_TIMEOUT',
        ('parallel', 'deadline-exhausted'): 'PARALLEL_TIMEOUT',
        ('parallel', 'output-bound'): 'PARALLEL_OUTPUT_BOUND',
        ('kernel', 'command-timeout'): 'KERNEL_TIMEOUT',
        ('kernel', 'deadline-exhausted'): 'KERNEL_TIMEOUT',
        ('kernel', 'output-bound'): 'KERNEL_OUTPUT_BOUND'}
    return known.get((phase, message), fallback)


def publish(out, status, private):
    paths = (out / 'private/result.json', out / 'public/status.json')
    try:
        private.update(status=dict(status), failure_phase=status['first_failed_phase'],
            failure_reason=status['failure_reason'])
        save(paths[0], private)
        data = (json.dumps(status, sort_keys=True) + '\n').encode()
        public.project(data, status['source_commit'], status['packet_sha256'], 'success')
        save(paths[1], status)
    except BaseException:
        for path in paths: path.unlink(missing_ok=True)
        raise


def finish(out, status, private):
    paths = (out / 'private/result.json', out / 'public/status.json')
    try:
        with runtime.defer_signals() as events: publish(out, status, private)
        if events:
            status.update(status='FAIL', cancelled=True)
            public.record_failure(status, 'finalization', 'CANCELLED')
            if status['native_compilation'] == 'PASS': status['native_compilation'] = 'NOT ACCEPTED'
            private['status'] = dict(status)
            for path in paths: path.unlink(missing_ok=True)
            with runtime.defer_signals(): publish(out, status, private)
    except BaseException:
        for path in paths: path.unlink(missing_ok=True)
        raise
    if events: raise runtime.Cancelled(events[0])


def revoke_terminal(args, cancelled):
    """Revoke a completed PASS if failure arrives while the main guard exits."""
    root, out = args.source_root, args.output
    packet.need(root == root.resolve() and str(root) == os.environ.get('GITHUB_WORKSPACE') and
        out == out.resolve() and out.parent == root / 'artifacts/kernel-native-job' and
        not any(path.is_symlink() for path in (out, *out.parents)), 'terminal-revoke-owner')
    paths = (out / 'private/result.json', out / 'public/status.json')
    if not all(path.exists() for path in paths):
        return
    try:
        raw = public.read(paths[1]); previous = public.decode(raw)
        status = public.project(raw, args.source_commit, args.packet_sha256, 'success')
        public.record_failure(status, 'finalization', 'CANCELLED' if cancelled else 'PUBLICATION_FAILED')
        status['cancelled'] = status['cancelled'] or cancelled
        status = public.project(json.dumps(status).encode(), args.source_commit, args.packet_sha256,
            'cancelled' if cancelled else 'failure')
        private = packet.load(paths[0])
        packet.need(private.get('status') == previous, 'terminal-revoke-binding')
        for _ in range(2):
            with runtime.defer_signals() as events:
                private.update(status=dict(status), failure_phase=status['first_failed_phase'],
                    failure_reason=status['failure_reason'])
                save(paths[0], private); save(paths[1], status)
            if not events: break
            status['cancelled'] = True
    except BaseException:
        for path in paths: path.unlink(missing_ok=True)
        raise


def ordinary(args, resources=None):
    packet.need(args.execute_native and args.deadline == DEADLINE and platform.system() == 'Linux' and
        platform.machine() in ('aarch64', 'arm64') and os.getuid() == os.geteuid() != 0 and
        os.getgid() == os.getegid() != 0, 'ordinary-native-host')
    packet.need(os.environ.get('GITHUB_REPOSITORY') == 'Gabriel-Kahen/cachy-asahi' and
        os.environ.get('RUNNER_ARCH') == 'ARM64' and os.environ.get('RUNNER_OS') == 'Linux', 'hosted-disposable-ARM')
    fields = Path('/proc/self/status').read_text()
    caps = re.findall(r'^Cap(?:Eff|Prm):\s+([0-9a-f]+)$', fields, re.M)
    packet.need(len(caps) == 2 and all(int(value, 16) == 0 for value in caps), 'host-capabilities')
    memory = dict(re.findall(r'^(MemTotal|MemAvailable):\s+(\d+) kB$', Path('/proc/meminfo').read_text(), re.M))
    if resources is not None:
        for source, target in (('MemTotal', 'mem_total_bytes'), ('MemAvailable', 'mem_available_bytes')):
            if source in memory:
                value = int(memory[source]) * 1024
                if 0 <= value <= 2**60: resources[target] = value
    packet.need(int(memory.get('MemTotal', 0)) * 1024 >= 15 * 1024**3 and
        int(memory.get('MemAvailable', 0)) * 1024 >= 14 * 1024**3, 'host-memory-reserve')
    free = shutil.disk_usage(args.source_root).free
    if resources is not None and type(free) is int and 0 <= free <= 2**60:
        resources['initial_free_disk_bytes'] = free
    packet.need(free >= 30 * 1024**3, 'host-disk-reserve')
    for name in ('git', 'gpg', 'lscpu', 'zstd', 'docker', 'python3'):
        path = Path('/usr/bin') / name
        packet.need(path.is_file() and os.access(path, os.X_OK), 'host-tool-unavailable')


class Docker:
    def __init__(self, args):
        self.args, self.pins, self.daemon, self.serial = args, None, None, 0

    def local(self):
        binary = self.args.docker_binary
        packet.need(binary == Path('/usr/bin/docker') and binary == binary.resolve() and
            self.args.docker_endpoint == 'unix:///run/docker.sock', 'local-Docker-only')
        data, mode = packet.capture(binary, 128 * 1024**2)
        packet.need(mode == 0o755 and packet.sha(data) == self.args.docker_sha256, 'Docker-CLI-pin')
        socket = Path('/run/docker.sock'); info = socket.lstat()
        packet.need(socket == socket.resolve() and stat.S_ISSOCK(info.st_mode) and info.st_uid == 0,
            'rootful-Docker-socket')
        binary_info = binary.lstat()
        identity = [(s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode) for s in (binary_info, info)]
        packet.need(self.pins is None or self.pins == identity, 'Docker-local-drift')
        self.pins = identity

    def call(self, runner, argv, timeout=30):
        self.local(); self.serial += 1
        result = runner.run([str(self.args.docker_binary), '--host', self.args.docker_endpoint, *argv],
            timeout=timeout, limit=128 * 1024, log='docker-' + str(self.serial) + '.log')
        self.local()
        return result

    def info(self, runner):
        result = self.call(runner, ['info', '--format', '{{json .}}'])
        packet.need(result.returncode == 0, 'Docker-info')
        data = packet.decode(result.stdout)
        identity = {'id': data.get('ID'), 'architecture': data.get('Architecture')}
        security = data.get('SecurityOptions')
        packet.need(type(identity['id']) is str and re.fullmatch('[A-Za-z0-9:_-]{8,128}', identity['id']) and
            identity['architecture'] in ('aarch64', 'arm64') and data.get('OSType') == 'linux' and
            data.get('CgroupVersion') == '2' and type(security) is list and
            all(type(v) is str and not re.search(r'\b(rootless|userns)\b', v) for v in security), 'Docker-native-profile')
        packet.need(self.daemon is None or self.daemon == identity, 'Docker-daemon-drift')
        version = self.call(runner, ['version', '--format', '{{.Server.APIVersion}} {{.Server.MinAPIVersion}}'])
        packet.need(version.returncode == 0, 'Docker-API-version')
        versions = version.stdout.decode().strip().split()
        packet.need(len(versions) == 2 and all(re.fullmatch('[0-9]{1,2}\\.[0-9]{1,3}', v) for v in versions), 'Docker-API-range')
        maximum, minimum = (tuple(map(int, value.split('.'))) for value in versions)
        required = tuple(map(int, KERNEL_API_VERSION.split('.')))
        packet.need(minimum <= required <= maximum, 'held-kernel-API-unavailable')
        self.daemon = identity
        return identity

    def inventory(self, runner, kind):
        result = self.call(runner, [kind, 'ls', '--all', '--no-trunc', '--format', '{{.ID}}'])
        packet.need(result.returncode == 0, 'Docker-inventory-query')
        packet.need(type(result.stdout) is bytes and len(result.stdout) <= 128 * 1024, 'Docker-inventory-bound')
        values = result.stdout.decode().splitlines()
        regex = 'sha256:[0-9a-f]{64}' if kind == 'image' else '[0-9a-f]{64}'
        packet.need(len(values) <= 256 and all(re.fullmatch(regex, value) for value in values), 'Docker-inventory-bound')
        return set(values)



    def image(self, runner, image):
        result = self.call(runner, ['image', 'inspect', image])
        packet.need(result.returncode == 0 and type(result.stdout) is bytes and
            len(result.stdout) <= 128 * 1024, 'baseline-image-query')
        rows = packet.decode(b'{"rows":' + result.stdout + b'}')['rows']
        required = {'Id', 'Architecture', 'Os', 'Config', 'RootFS', 'Size', 'RepoTags', 'RepoDigests'}
        packet.need(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict and
            required <= set(rows[0]) and rows[0]['Id'] == image, 'baseline-image-identity')
        row = rows[0]
        references = []
        for key in ('RepoTags', 'RepoDigests'):
            values = row[key] if row[key] is not None else []
            packet.need(type(values) is list and len(values) <= 256 and
                all(type(v) is str and 0 < len(v.encode()) <= 512 for v in values) and
                len(set(values)) == len(values), 'baseline-image-references')
            references.append(sorted(values))
        packet.need(sum(map(len, references)) <= 256, 'baseline-image-references')
        rootfs = row['RootFS']
        packet.need(type(rootfs) is dict and 'Type' in rootfs and set(rootfs) <= {'Type', 'Layers'},
            'baseline-image-rootfs')
        rootfs = dict(rootfs, Layers=rootfs.get('Layers', []))
        packet.need(
            type(rootfs['Type']) is str and 0 < len(rootfs['Type'].encode()) <= 64 and
            type(rootfs['Layers']) is list and len(rootfs['Layers']) <= 256 and
            all(type(v) is str and re.fullmatch('sha256:[0-9a-f]{64}', v) for v in rootfs['Layers']),
            'baseline-image-rootfs')
        parent = row.get('Parent')
        if type(parent) is str and parent == '': parent = None
        packet.need(parent is None or type(parent) is str and re.fullmatch('sha256:[0-9a-f]{64}', parent),
            'baseline-image-parent')
        packet.need(all(type(row[k]) is str and 0 < len(row[k].encode()) <= 64 for k in ('Architecture', 'Os')) and
            type(row['Size']) is int and 0 <= row['Size'] <= 2**60 and (row['Config'] is None or type(row['Config']) is dict),
            'baseline-image-metadata')
        bounded_json(row['Config'])
        return {'id': image, 'architecture': row['Architecture'], 'os': row['Os'], 'config': row['Config'],
            'rootfs': {'type': rootfs['Type'], 'layers': rootfs['Layers']}, 'size': row['Size'],
            'parent': parent, 'repo_tags': references[0], 'repo_digests': references[1]}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def bounded_json(value):
    nodes = 0
    def visit(item, depth):
        nonlocal nodes
        nodes += 1
        packet.need(nodes <= 8192 and depth <= 16, 'baseline-JSON-bound')
        if type(item) is dict:
            for key, child in item.items():
                packet.need(type(key) is str, 'baseline-JSON-key')
                visit(key, depth + 1); visit(child, depth + 1)
        elif type(item) is list:
            for child in item: visit(child, depth + 1)
        elif type(item) is str:
            packet.need(len(item.encode()) <= 65536, 'baseline-JSON-string')
        else:
            packet.need(item is None or type(item) in (bool, int, float), 'baseline-JSON-value')
    visit(value, 0)
    canonical(value)  # Reject non-finite JSON numbers.


class Baseline:
    """Positive observations on a cooperative VM, never ownership from inventory deltas."""
    def __init__(self, args, docker, private, summary):
        self.args, self.docker, self.path, self.summary = args, docker, private / 'daemon-baseline.json', summary
        self.record, self.ready = None, False

    def inventories(self, runner, initial=False):
        values, errors = {}, []
        for kind, key in (('container', 'initial_container_count'), ('image', 'initial_image_id_count')):
            try:
                values[kind] = self.docker.inventory(runner, kind)
                if initial: self.summary[key] = len(values[kind])
            except (runtime.Cancelled, KeyboardInterrupt): raise
            except Exception as error: errors.append(error)
        if errors: raise errors[0]
        return values['container'], values['image']

    def projection(self, runner, protected=None):
        self.docker.info(runner)
        containers, ids = self.inventories(runner)
        packet.need(not containers, 'baseline-containers-present')
        rows, bindings, total = [], {}, 2
        for image in sorted(ids if protected is None else ids & protected):
            row = self.docker.image(runner, image)
            for ref in row['repo_tags'] + row['repo_digests']:
                packet.need(ref not in bindings or bindings[ref] == image, 'baseline-reference-binding')
                bindings[ref] = image
            total += len(canonical(row)) + bool(rows)
            packet.need(total <= 4 * 1024**2, 'baseline-aggregate-bound')
            rows.append(row)
        return rows, ids

    def within(self, runner):
        packet.need(type(runner.deadline) in (int, float) and snapshot_clock() < runner.deadline, 'deadline-exhausted')

    def capture(self, runner, protected=None):
        self.within(runner)
        before, ids = self.projection(runner, protected)
        after, final = self.projection(runner, protected)
        packet.need(before == after and ids == final, 'baseline-capture-drift')
        self.within(runner)
        return after, final

    def verify(self):
        info = self.path.lstat()
        packet.need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and
            info.st_uid == os.getuid() and info.st_nlink == 1 and self.record is not None and
            packet.load(self.path) == self.record, 'baseline-journal-binding')
        self.docker.local()
        packet.need(self.record['cli_socket_identity'] == [list(row) for row in self.docker.pins] and
            self.record['daemon_id'] == self.docker.daemon['id'] and
            self.record['daemon_architecture'] == self.docker.daemon['architecture'], 'baseline-daemon-binding')

    def observation(self, stage, rows, ids):
        return {'stage': stage, 'monotonic_ns': time.monotonic_ns(), 'container_count': 0,
            'image_id_count': len(ids), 'identity_sha256': packet.sha(canonical(rows))}

    def start(self, runner):
        self.summary['preservation'] = 'UNVERIFIED'
        containers, ids = self.inventories(runner, True)
        packet.need(not containers, 'baseline-containers-present')
        rows, observed = self.capture(runner)
        packet.need(ids == observed, 'baseline-capture-drift')
        nonce = secrets.token_hex(16)
        run, attempt = os.environ.get('GITHUB_RUN_ID', ''), os.environ.get('GITHUB_RUN_ATTEMPT', '')
        packet.need(all(re.fullmatch('[0-9]{1,20}', value) for value in (run, attempt)), 'baseline-run-binding')
        self.record = {'schema_version': 1, 'source_commit': self.args.source_commit,
            'packet_sha256': self.args.packet_sha256, 'run_id': run, 'run_attempt': attempt, 'nonce': nonce,
            'daemon_id': self.docker.daemon['id'], 'daemon_architecture': self.docker.daemon['architecture'],
            'docker_cli_sha256': self.args.docker_sha256,
            'cli_socket_identity': [list(row) for row in self.docker.pins], 'containers': [], 'images': rows,
            'identity_sha256': packet.sha(canonical(rows)),
            'observations': [self.observation('before_producer', rows, observed)]}
        save(self.path, self.record); self.verify(); self.within(runner)
        self.summary['pre_identity_sha256'] = self.record['identity_sha256']
        self.ready = True

    def protected(self):
        packet.need(self.ready, 'baseline-not-established')
        self.verify()
        return {row['id'] for row in self.record['images']}

    def observe(self, runner, stage):
        self.verify()
        rows, ids = self.capture(runner, self.protected())
        row = self.observation(stage, rows, ids)
        self.record['observations'].append(row); save(self.path, self.record); self.within(runner)
        if stage == 'after_cleanup':
            self.summary['post_identity_sha256'] = row['identity_sha256']
            self.summary['preservation'] = 'PASS' if row['identity_sha256'] == self.record['identity_sha256'] else 'FAIL'
        packet.need(row['identity_sha256'] == self.record['identity_sha256'], 'baseline-changed')


def producer_command(snapshot, private):
    return ['/usr/bin/python3', '-I', '-B', str(snapshot / 'scripts/ci/native_arm.py'), 'build',
        '--inputs', str(snapshot / 'scripts/ci/inputs.lock.json'), '--inputs-sha256', packet.INPUTS_SHA,
        '--recipes', str(snapshot / 'scripts/ci/recipes.lock.json'), '--recipes-sha256', packet.RECIPES_SHA,
        '--cache', str(private / 'alarm-cache'), '--output', str(private / 'producer')]


def accepted_producer(private, commit):
    producer = private / 'producer'
    result = packet.load(producer / 'result.json')
    bootstrap = packet.load(producer / 'bootstrap.json')
    runner = packet.load(producer / 'runner.json')
    image = packet.read(producer / 'image-id', 128).decode().strip()
    inputs = packet.read(producer / 'inputs.lock.json')
    packages = packet.read(producer / 'packages.lock', 128 * 1024)
    packet.need(re.fullmatch('sha256:[0-9a-f]{64}', image) and result.get('mode') == 'build' and
        result.get('status') == 'native-builds-and-byte-comparison-pass' and result.get('native_build') == 'PASS' and
        result.get('hardware_validation') == 'NOT RUN' and result.get('verified_signed_packages') == 248 and
        result.get('reviewed_inputs_sha256') == packet.INPUTS_SHA and
        result.get('reviewed_recipes_sha256') == packet.RECIPES_SHA and
        result.get('bootstrap_script_sha256') == packet.HELPERS['scripts/ci/native_arm.py'][0], 'original-producer-receipt')
    packet.need(packet.sha(inputs) == packet.INPUTS_SHA and packet.sha(packages) == BASE_SHA and
        bootstrap.get('status') == 'image-provisioned' and bootstrap.get('image_id') == image and
        bootstrap.get('inputs_sha256') == packet.INPUTS_SHA and bootstrap.get('packages_lock_sha256') == BASE_SHA and
        runner.get('commit') == commit and runner.get('runner_arch') == 'ARM64' and runner.get('uid') == os.getuid() and
        runner.get('bootstrap_script_sha256') == packet.HELPERS['scripts/ci/native_arm.py'][0], 'same-job-base-bindings')
    # Capture exactly the accepted bytes; later stage hashes refer to these copies.
    target = private / 'accepted'; target.mkdir(mode=0o700)
    for name in ('result.json', 'bootstrap.json', 'packages.lock', 'inputs.lock.json'):
        data = packet.read(producer / name)
        packet.need(name not in ('result.json', 'bootstrap.json') or
            packet.decode(data) == (result if name == 'result.json' else bootstrap), 'producer-receipt-read-race')
        (target / name).write_bytes(data); (target / name).chmod(0o600)
    return image, target


def acquired_paths(out):
    receipt = packet.load(out / 'acquisition.json')
    packet.need(receipt.get('status') == 'PASS-acquired-source-data', 'kernel-input-acquisition')
    paths = {'archive': out / 'asahi.tar.gz', 'config': out / 'embedded-config',
        'patch': out / 'candidate.patch',
        'bio-baseline': out / 'artifacts/kernel-candidates/baseline/source-slice/block/bio.c',
        'bio-candidate': out / 'artifacts/kernel-candidates/candidate/source-slice/block/bio.c',
        'package-cache': out / 'packages', 'key-dir': out / 'keys'}
    # Acquisition owns the exact seven paths; no stdout/path override is trusted.
    declared = receipt.get('arguments', {})
    packet.need({key.replace('-', '_'): str(value) for key, value in paths.items()} == declared, 'acquisition-path-bindings')
    return paths


def kernel_command(args, private, image, accepted, paths, kernel_output):
    command = ['/usr/bin/python3', '-I', '-B', str(private / 'source' / (packet.KERNEL + 'stage.py')), 'run',
        '--root', str(args.source_root), '--output', str(kernel_output), '--source-commit', args.source_commit,
        '--lock', str(args.source_root / (packet.KERNEL + 'stage.lock.json')), '--lock-sha256', packet.KERNEL_SHA,
        '--docker', str(args.docker_binary), '--docker-sha256', args.docker_sha256,
        '--endpoint', args.docker_endpoint, '--image', image,
        '--bootstrap', str(accepted / 'bootstrap.json'), '--bootstrap-sha256', packet.sha(packet.read(accepted / 'bootstrap.json')),
        '--accepted-result', str(accepted / 'result.json'), '--accepted-result-sha256', packet.sha(packet.read(accepted / 'result.json')),
        '--base-packages', str(accepted / 'packages.lock'), '--inputs', str(accepted / 'inputs.lock.json')]
    for name, path in paths.items(): command += ['--' + name, str(path)]
    return command


def kernel_status(kernel_output, commit):
    record = packet.load(kernel_output / 'private/result.json')
    packet.need(record.get('source_commit') == commit and record.get('status') == 'PASS' and
        record.get('phase') == 'complete' and record.get('cancelled') is False and
        record.get('native_kernel_compilation') == 'PASS' and record.get('kernel_execution') ==
        record.get('hardware_validation') == 'NOT RUN' and record.get('performance') == 'NOT MEASURED' and
        record.get('cleanup', {}).get('status') == 'PASS', 'kernel-terminal-receipt')
    for name in ('probe', 'baseline', 'candidate'):
        row = record.get(name, {})
        packet.need(row.get('status') == 'PASS' and row.get('action') == name and not row.get('cancelled'), 'kernel-variant-receipt')
    return record


def kernel_progress(kernel_output, commit):
    """Retain only source-bound completed/failed acceptance from a partial stage."""
    record = packet.load(kernel_output / 'private/result.json')
    phase = record.get('phase')
    packet.need(record.get('source_commit') == commit and record.get('status') in ('PASS', 'FAIL') and
        type(record.get('cancelled')) is bool and phase in
        ('snapshot', 'provision', 'derive', 'probe', 'baseline', 'candidate', 'complete') and
        record.get('kernel_execution') == record.get('hardware_validation') == 'NOT RUN' and
        record.get('performance') == 'NOT MEASURED', 'kernel-partial-header')
    progress, nonce = {}, None
    for name, target in (('probe', 'kernel_probe'), ('baseline', 'baseline'), ('candidate', 'candidate')):
        if name in record:
            row = record[name]
            packet.need(type(row) is dict and row.get('status') == 'PASS' and row.get('action') == name and
                row.get('cancelled') is False and re.fullmatch('[0-9a-f]{32}', row.get('nonce', '')) and
                (nonce is None or nonce == row['nonce']), 'kernel-partial-action')
            nonce = row['nonce']; progress[target] = 'PASS'
        elif phase == name:
            progress[target] = 'FAIL'  # Attempted phase never yielded accepted completion.
    if any(progress.get(name) in ('PASS', 'FAIL') for name in ('baseline', 'candidate')):
        progress['native_compilation'] = 'NOT ACCEPTED'
    return progress



def kernel_owned_absence(kernel_output, commit, image, daemon):
    record = packet.load(kernel_output / 'private/result.json')
    clean = record.get('cleanup', {})
    packet.need(record.get('source_commit') == commit and record.get('status') in ('PASS', 'FAIL') and
        record.get('kernel_execution') == record.get('hardware_validation') == 'NOT RUN' and
        record.get('performance') == 'NOT MEASURED' and record.get('daemon') == daemon and
        record.get('accepted_base', {}).get('image_id') == image and
        type(clean) is dict and set(clean) == {'status', 'records'} and clean['status'] == 'PASS' and
        type(clean['records']) is list and 2 <= len(clean['records']) <= 3 and
        all(type(row) is dict and row.get('status') == 'PASS' and row.get('absence_verified') is True and
            not row.get('cancelled', False) and not row.get('uncertain_commit', False) for row in clean['records']),
        'kernel-owned-absence-unverified')
    images = [row for row in clean['records'] if 'commit_attempted' in row]
    containers = [row for row in clean['records'] if 'commit_attempted' not in row]
    packet.need(len(images) == 1 and 1 <= len(containers) <= 2 and
        set(images[0]) == {'status', 'absence_verified', 'commit_attempted'} and
        type(images[0]['commit_attempted']) is bool and
        all(set(row) == {'status', 'absence_verified', 'cancelled', 'errors'} and
            row['cancelled'] is False and row['errors'] == [] for row in containers),
        'kernel-owned-absence-unverified')
    return True

def cleanup_base(docker, runner, private, image, producer_finished, baseline):
    docker.info(runner)
    if image is not None:
        # Only the exact immutable image from a completed accepted producer.
        protected = baseline.protected()
        packet.need(image not in protected, 'baseline-ID-collision')
        journal = packet.load(private / 'base-ownership.json')
        packet.need(journal['image_id'] == image and journal['daemon'] == docker.daemon and
            journal['producer_finished'] is True and
            journal['source_commit'] == baseline.record['source_commit'] and
            journal['producer_sha256'] == packet.HELPERS['scripts/ci/native_arm.py'][0] and
            journal['baseline_identity_sha256'] == baseline.record['identity_sha256'] and
            journal['nonce'] == baseline.record['nonce'], 'base-image-ownership')
        queried = docker.call(runner, ['image', 'inspect', image])
        if queried.returncode == 0:
            rows = json.loads(queried.stdout)
            packet.need(len(rows) == 1 and rows[0]['Id'] == image and rows[0]['Architecture'] == 'arm64' and
                rows[0]['Os'] == 'linux', 'base-image-inspection')
            packet.need(image not in baseline.protected(), 'baseline-ID-collision')
            removed = docker.call(runner, ['image', 'rm', '--no-prune', image])
            packet.need(removed.returncode == 0, 'base-image-removal')
            queried = docker.call(runner, ['image', 'inspect', image])
        packet.need(queried.returncode != 0 and b'No such image' in queried.stdout, 'base-image-absence')
    containers = docker.inventory(runner, 'container')
    # Failed original builds can still finish asynchronously. An empty current
    # inventory is not proof of absence after an interrupted producer.
    return {'status': 'PASS' if producer_finished and image is not None and not containers else 'FAIL',
        'base_image_absence': image is not None, 'containers_currently_absent': not containers,
        'producer_mutation_uncertain': not producer_finished,
        'Docker_build_cache': 'NOT_ESTABLISHED'}


def execute(args):
    start = time.monotonic()
    terminal = []
    with runtime.cancellation_handlers():
        result = work(args, terminal, start)
    # All handler restoration/unmasking precedes PASS. This plain publisher
    # installs no signal context that could terminate after restoring handlers.
    if terminal:
        status, evidence = terminal[0]
        publish(args.output, status, evidence)
    return result


def work(args, terminal, start):
    root = args.source_root
    packet.need(root.is_absolute() and root == root.resolve() and str(root) == os.environ.get('GITHUB_WORKSPACE') and
        re.fullmatch('[0-9a-f]{40}', args.source_commit or '') and re.fullmatch('[0-9a-f]{64}', args.packet_sha256 or ''), 'job-source-contract')
    packet.need(args.output.is_absolute() and args.output == args.output.resolve() and not args.output.exists() and
        args.output.parent == root / 'artifacts/kernel-native-job' and
        not any(path.is_symlink() for path in (args.output, *args.output.parents)), 'new-owned-job-output')
    args.output.parent.mkdir(mode=0o700, exist_ok=True)
    args.output.mkdir(mode=0o700)
    private = args.output / 'private'; private.mkdir(mode=0o700); (args.output / 'public').mkdir(mode=0o700)
    for name in ('home', 'docker-config'): (private / name).mkdir(mode=0o700)
    status = initial(args); evidence = {'status': dict(status), 'source': None, 'commands': []}
    finish(args.output, status, evidence)
    docker = None; image = None; producer_finished = False; kernel_output = None; baseline = None
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(private / 'home'), 'DOCKER_CONFIG': str(private / 'docker-config'),
        'DOCKER_HOST': args.docker_endpoint, 'DOCKER_BUILDKIT': '0', 'LC_ALL': 'C', 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1',
        **{key: os.environ[key] for key in HOST_ENV if key in os.environ}}
    context = ('preflight', 'PREFLIGHT_REJECTED')
    try:
        ordinary(args, status['resources'])
        setup = runtime.Runner(SETUP, env, private / 'setup-logs')
        status['phase'] = 'source'
        context = ('source', 'SOURCE_REJECTED')
        snapshot = private / 'source'
        evidence['source'] = packet.verify(root, args.packet, args.packet_sha256, args.source_commit, setup, snapshot)
        context = ('source', 'DOCKER_REJECTED')
        docker = Docker(args); evidence['daemon'] = docker.info(setup)
        context = ('source', 'DAEMON_BASELINE_UNVERIFIED')
        baseline = Baseline(args, docker, private, status['daemon_baseline'])
        baseline.start(setup)
        context = ('source', 'PRODUCER_TIME_RESERVE')
        packet.need(DEADLINE - (time.monotonic() - start) >= PARALLEL + KERNEL_ENVELOPE + CLEANUP + GUARD, 'producer-time-reserve')
        status['phase'] = 'producer'
        context = ('parallel', 'PARALLEL_RUN_FAILED')
        commands = [producer_command(snapshot, private), ['/usr/bin/python3', '-I', '-B',
            str(snapshot / (packet.KERNEL + 'acquisition.py')), '--root', str(snapshot), '--output', str(private / 'kernel-inputs')]]
        # Acquisition requires owned artifact placement relative to its snapshot.
        commands[1][-1] = str(snapshot / 'artifacts/kernel-native-stage/acquisition')
        phase = runtime.Runner(PARALLEL, env, private / 'phase-logs')
        evidence['commands'] = commands
        save(private / 'producer-started.json', {'commands': commands, 'daemon': docker.daemon, 'producer_finished': False})
        status['daemon_baseline']['producer_mutation'] = 'UNCERTAIN'
        status.update(producer_exit={'kind': 'UNOBSERVED', 'code': None},
            acquisition_exit={'kind': 'UNOBSERVED', 'code': None})
        results = phase.run_many(commands, timeout=PARALLEL, lognames=('original-producer.log', 'kernel-acquisition.log'))
        packet.need(type(results) in (list, tuple) and len(results) == 2, 'parallel-results')
        exits = [public.exit_record(result.returncode) for result in results]
        status.update(producer_exit=exits[0], acquisition_exit=exits[1])
        failed = [result['code'] != 0 for result in exits]
        if any(failed):
            if failed[0]: status['producer'] = 'FAIL'
            reason = 'BOTH_CHILDREN_EXIT' if all(failed) else 'PRODUCER_EXIT' if failed[0] else 'ACQUISITION_EXIT'
            public.record_failure(status, 'parallel', reason)
        packet.need(not any(failed), 'producer-or-acquisition-failed')
        context = ('producer', 'PRODUCER_RECEIPT_REJECTED')
        status['daemon_baseline']['producer_mutation'] = 'COMPLETE_REJECTED'
        candidate, accepted = accepted_producer(private, args.source_commit)
        packet.need(candidate not in baseline.protected(), 'baseline-ID-collision')
        observed = docker.image(phase, candidate)
        packet.need(observed['architecture'] == 'arm64' and observed['os'] == 'linux', 'producer-image-profile')
        save(private / 'base-ownership.json', {'image_id': candidate, 'daemon': docker.daemon, 'producer_finished': True,
            'source_commit': args.source_commit, 'producer_sha256': packet.HELPERS['scripts/ci/native_arm.py'][0],
            'nonce': baseline.record['nonce'], 'baseline_identity_sha256': baseline.record['identity_sha256']})
        image, producer_finished = candidate, True
        context = ('producer', 'DAEMON_BASELINE_UNVERIFIED')
        baseline.observe(phase, 'before_kernel')
        status['producer'] = 'PASS'
        status['daemon_baseline']['producer_mutation'] = 'COMPLETE_ACCEPTED'
        context = ('kernel', 'KERNEL_TIME_RESERVE')
        packet.need(DEADLINE - (time.monotonic() - start) >= KERNEL_ENVELOPE + CLEANUP + GUARD, 'kernel-time-reserve')
        context = ('kernel', 'KERNEL_DISK_RESERVE')
        free = shutil.disk_usage(root).free
        if type(free) is int and 0 <= free <= 2**60:
            status['resources']['pre_kernel_free_disk_bytes'] = free
        packet.need(free >= 8 * 1024**3, 'kernel-disk-reserve')
        context = ('acquisition', 'ACQUISITION_RECEIPT_REJECTED')
        acquisition = snapshot / 'artifacts/kernel-native-stage/acquisition'
        paths = acquired_paths(acquisition)
        context = ('kernel', 'KERNEL_OUTPUT_REJECTED')
        kernel_parent = root / 'artifacts/kernel-native-stage'; kernel_parent.mkdir(mode=0o700, exist_ok=True)
        packet.need(not kernel_parent.is_symlink() and kernel_parent == kernel_parent.resolve(), 'kernel-output-parent')
        kernel_output = kernel_parent / ('hosted-job-' + secrets.token_hex(16))
        command = kernel_command(args, private, image, accepted, paths, kernel_output)
        evidence['commands'].append(command); evidence['kernel_output'] = str(kernel_output)
        status['phase'] = 'kernel'
        context = ('kernel', 'KERNEL_RUN_FAILED')
        phase = runtime.Runner(KERNEL_ENVELOPE, env, private / 'kernel-logs')
        result = phase.run(command, timeout=KERNEL_ENVELOPE, log='kernel-controller.log')
        context = ('kernel', 'KERNEL_EXIT')
        packet.need(result.returncode == 0, 'kernel-controller-failed')
        context = ('kernel', 'KERNEL_RECEIPT_REJECTED')
        evidence['kernel'] = kernel_status(kernel_output, args.source_commit)
        status.update(kernel_probe='PASS', baseline='PASS', candidate='PASS', native_compilation='PASS', status='PASS')
    except (runtime.Cancelled, KeyboardInterrupt):
        status.update(status='FAIL', cancelled=True)
        mutation = status['daemon_baseline']['producer_mutation']
        if mutation == 'COMPLETE_REJECTED':
            status['producer'] = 'FAIL'
            if not producer_finished: status['daemon_baseline']['producer_mutation'] = 'UNCERTAIN'
        elif mutation == 'COMPLETE_ACCEPTED':
            status['producer'] = 'PASS'
        public.record_failure(status, context[0], 'CANCELLED')
    except Exception as error:
        status['status'] = 'FAIL'; evidence['error_type'] = type(error).__name__
        if context[0] == 'producer' and status['producer'] != 'PASS': status['producer'] = 'FAIL'
        public.record_failure(status, context[0], failure_reason(error, *context))
    finally:
        with runtime.defer_signals() as events:
            if kernel_output is not None:
                try:
                    progress = kernel_progress(kernel_output, args.source_commit)
                    # A validated complete stage stays PASS until outer cleanup.
                    if status['native_compilation'] == 'PASS': progress.pop('native_compilation', None)
                    status.update(progress); evidence['kernel_progress'] = progress
                except Exception:
                    evidence['kernel_progress'] = {'status': 'UNAVAILABLE OR UNVERIFIED'}
            status['phase'] = 'cleanup'
            try:
                packet.need(docker is not None, 'Docker-not-initialized')
                cleanup = runtime.Runner(CLEANUP, env, private / 'cleanup-logs')
                evidence['cleanup'] = cleanup_base(docker, cleanup, private, image, producer_finished, baseline)
                packet.need(evidence['cleanup']['status'] == 'PASS', 'owned-absence-unverified')
                if kernel_output is not None:
                    kernel_owned_absence(kernel_output, args.source_commit, image, docker.daemon)
                status['daemon_baseline']['owned_absence'] = 'PASS'
                status['cleanup'] = 'PASS'
            except BaseException as error:
                status['cleanup'] = 'FAIL'; evidence['cleanup'] = {'status': 'FAIL', 'absence_verified': False}
                status['daemon_baseline']['owned_absence'] = 'UNVERIFIED'
                if not isinstance(error, (runtime.Cancelled, KeyboardInterrupt)):
                    public.record_failure(status, 'cleanup', 'OWNED_ABSENCE_UNVERIFIED')
                if isinstance(error, (runtime.Cancelled, KeyboardInterrupt)):
                    status['cancelled'] = True
                    public.record_failure(status, 'cleanup', 'CANCELLED')
            try:
                packet.need(baseline is not None and baseline.ready, 'baseline-not-established')
                baseline.observe(cleanup, 'after_cleanup')
            except BaseException as error:
                status['cleanup'] = 'FAIL'
                if status['daemon_baseline']['preservation'] != 'FAIL':
                    status['daemon_baseline'].update(preservation='UNVERIFIED', post_identity_sha256=None)
                if isinstance(error, (runtime.Cancelled, KeyboardInterrupt)):
                    status['cancelled'] = True
                    public.record_failure(status, 'cleanup', 'CANCELLED')
                else:
                    public.record_failure(status, 'cleanup', failure_reason(error, 'cleanup', 'DAEMON_BASELINE_UNVERIFIED'))
            if status['daemon_baseline']['producer_mutation'] != 'COMPLETE_ACCEPTED': status['cleanup'] = 'FAIL'
            if status['cleanup'] != 'PASS': public.record_failure(status, 'cleanup', 'CLEANUP_FAILED')
            if events:
                status.update(status='FAIL', cancelled=True)
                public.record_failure(status, 'cleanup', 'CANCELLED')
            if status['status'] == 'PASS': status['phase'] = 'complete'
            elif status['native_compilation'] == 'PASS': status['native_compilation'] = 'NOT ACCEPTED'
            evidence['status'] = dict(status)
            if status['status'] == 'PASS':
                terminal.append((dict(status), dict(evidence)))
                pending = dict(status, status='FAIL', native_compilation='NOT ACCEPTED')
                finish(args.output, pending, dict(evidence, status=pending))
            else:
                finish(args.output, status, evidence)
        if events:
            terminal.clear()
            status.update(status='FAIL', cancelled=True)
            public.record_failure(status, 'cleanup', 'CANCELLED')
            if status['native_compilation'] == 'PASS': status['native_compilation'] = 'NOT ACCEPTED'
            evidence['status'] = dict(status); finish(args.output, status, evidence)
    return int(status['status'] != 'PASS')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-native', action='store_true')
    for name in ('source-root', 'packet', 'output', 'docker-binary'): parser.add_argument('--' + name, type=Path, required=True)
    for name in ('source-commit', 'packet-sha256', 'docker-sha256', 'docker-endpoint'): parser.add_argument('--' + name, required=True)
    parser.add_argument('--deadline', type=int, default=DEADLINE)
    args = parser.parse_args(argv)
    try:
        return execute(args)
    except (Exception, runtime.Cancelled, KeyboardInterrupt) as error:
        try: revoke_terminal(args, isinstance(error, (runtime.Cancelled, KeyboardInterrupt)))
        except BaseException: pass  # Owned receipts are absent or invalidated; never retain PASS.
        print('KERNEL_NATIVE_JOB_FAILED', file=sys.stderr); return 1


if __name__ == '__main__': raise SystemExit(main())
