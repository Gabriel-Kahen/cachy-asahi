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
    return {'schema_version': 1, 'stage': 'kernel-native-development-job', 'status': 'FAIL',
        'phase': 'preflight', 'cancelled': False, 'source_commit': args.source_commit,
        'packet_sha256': args.packet_sha256, 'producer': 'NOT RUN', 'kernel_probe': 'NOT RUN',
        'baseline': 'NOT RUN', 'candidate': 'NOT RUN', 'cleanup': 'FAIL', 'native_compilation': 'NOT RUN',
        'kernel_runtime': 'NOT RUN', 'hardware': 'NOT RUN', 'installation': 'NOT RUN',
        'performance': 'NOT MEASURED', 'binary_publication': 'NOT RUN', 'selected_for_release': False}


def publish(out, status, private):
    paths = (out / 'private/result.json', out / 'public/status.json')
    try:
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
        status = public.project(raw, args.source_commit, args.packet_sha256, 'cancelled' if cancelled else 'failure')
        private = packet.load(paths[0])
        packet.need(private.get('status') == previous, 'terminal-revoke-binding')
        for _ in range(2):
            with runtime.defer_signals() as events:
                private['status'] = dict(status)
                save(paths[0], private); save(paths[1], status)
            if not events: break
            status['cancelled'] = True
    except BaseException:
        for path in paths: path.unlink(missing_ok=True)
        raise


def ordinary(args):
    packet.need(args.execute_native and args.deadline == DEADLINE and platform.system() == 'Linux' and
        platform.machine() in ('aarch64', 'arm64') and os.getuid() == os.geteuid() != 0 and
        os.getgid() == os.getegid() != 0, 'ordinary-native-host')
    packet.need(os.environ.get('GITHUB_REPOSITORY') == 'Gabriel-Kahen/cachy-asahi' and
        os.environ.get('RUNNER_ARCH') == 'ARM64' and os.environ.get('RUNNER_OS') == 'Linux', 'hosted-disposable-ARM')
    fields = Path('/proc/self/status').read_text()
    caps = re.findall(r'^Cap(?:Eff|Prm):\s+([0-9a-f]+)$', fields, re.M)
    packet.need(len(caps) == 2 and all(int(value, 16) == 0 for value in caps), 'host-capabilities')
    memory = dict(re.findall(r'^(MemTotal|MemAvailable):\s+(\d+) kB$', Path('/proc/meminfo').read_text(), re.M))
    packet.need(int(memory.get('MemTotal', 0)) * 1024 >= 15 * 1024**3 and
        int(memory.get('MemAvailable', 0)) * 1024 >= 14 * 1024**3, 'host-memory-reserve')
    packet.need(shutil.disk_usage(args.source_root).free >= 30 * 1024**3, 'host-disk-reserve')
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
        values = result.stdout.decode().splitlines()
        regex = 'sha256:[0-9a-f]{64}' if kind == 'image' else '[0-9a-f]{64}'
        packet.need(len(values) <= 256 and all(re.fullmatch(regex, value) for value in values), 'Docker-inventory-bound')
        return set(values)


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


def cleanup_base(docker, runner, private, image, producer_finished):
    docker.info(runner)
    if image is not None:
        # Only the exact immutable image from a completed accepted producer.
        journal = packet.load(private / 'base-ownership.json')
        packet.need(journal['image_id'] == image and journal['daemon'] == docker.daemon and
            journal['producer_finished'] is True, 'base-image-ownership')
        queried = docker.call(runner, ['image', 'inspect', image])
        if queried.returncode == 0:
            rows = json.loads(queried.stdout)
            packet.need(len(rows) == 1 and rows[0]['Id'] == image and rows[0]['Architecture'] == 'arm64' and
                rows[0]['Os'] == 'linux', 'base-image-inspection')
            removed = docker.call(runner, ['image', 'rm', image])
            packet.need(removed.returncode == 0, 'base-image-removal')
            queried = docker.call(runner, ['image', 'inspect', image])
        packet.need(queried.returncode != 0 and b'No such image' in queried.stdout, 'base-image-absence')
    containers = docker.inventory(runner, 'container')
    # Failed original builds can still finish asynchronously. An empty current
    # inventory is not proof of absence after an interrupted producer.
    return {'status': 'PASS' if producer_finished and image is not None and not containers else 'FAIL',
        'base_image_absence': image is not None, 'containers_currently_absent': not containers,
        'producer_mutation_uncertain': not producer_finished,
        'Docker_build_cache': 'private disposable VM; not pruned or independently accepted'}


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
    docker = None; image = None; producer_finished = False; kernel_output = None
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(private / 'home'), 'DOCKER_CONFIG': str(private / 'docker-config'),
        'DOCKER_HOST': args.docker_endpoint, 'DOCKER_BUILDKIT': '0', 'LC_ALL': 'C', 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1',
        **{key: os.environ[key] for key in HOST_ENV if key in os.environ}}
    try:
        ordinary(args)
        setup = runtime.Runner(SETUP, env, private / 'setup-logs')
        status['phase'] = 'source'
        snapshot = private / 'source'
        evidence['source'] = packet.verify(root, args.packet, args.packet_sha256, args.source_commit, setup, snapshot)
        docker = Docker(args); evidence['daemon'] = docker.info(setup)
        packet.need(not docker.inventory(setup, 'container') and not docker.inventory(setup, 'image'), 'fresh-disposable-Docker-required')
        packet.need(DEADLINE - (time.monotonic() - start) >= PARALLEL + KERNEL_ENVELOPE + CLEANUP + GUARD, 'producer-time-reserve')
        status['phase'] = 'producer'
        commands = [producer_command(snapshot, private), ['/usr/bin/python3', '-I', '-B',
            str(snapshot / (packet.KERNEL + 'acquisition.py')), '--root', str(snapshot), '--output', str(private / 'kernel-inputs')]]
        # Acquisition requires owned artifact placement relative to its snapshot.
        commands[1][-1] = str(snapshot / 'artifacts/kernel-native-stage/acquisition')
        phase = runtime.Runner(PARALLEL, env, private / 'phase-logs')
        evidence['commands'] = commands
        save(private / 'producer-started.json', {'commands': commands, 'daemon': docker.daemon, 'producer_finished': False})
        results = phase.run_many(commands, timeout=PARALLEL, lognames=('original-producer.log', 'kernel-acquisition.log'))
        packet.need(all(result.returncode == 0 for result in results), 'producer-or-acquisition-failed')
        image, accepted = accepted_producer(private, args.source_commit); producer_finished = True
        save(private / 'base-ownership.json', {'image_id': image, 'daemon': docker.daemon, 'producer_finished': True,
            'source_commit': args.source_commit, 'producer_sha256': packet.HELPERS['scripts/ci/native_arm.py'][0]})
        status['producer'] = 'PASS'
        packet.need(DEADLINE - (time.monotonic() - start) >= KERNEL_ENVELOPE + CLEANUP + GUARD, 'kernel-time-reserve')
        packet.need(shutil.disk_usage(root).free >= 8 * 1024**3, 'kernel-disk-reserve')
        acquisition = snapshot / 'artifacts/kernel-native-stage/acquisition'
        paths = acquired_paths(acquisition)
        kernel_parent = root / 'artifacts/kernel-native-stage'; kernel_parent.mkdir(mode=0o700, exist_ok=True)
        packet.need(not kernel_parent.is_symlink() and kernel_parent == kernel_parent.resolve(), 'kernel-output-parent')
        kernel_output = kernel_parent / ('hosted-job-' + secrets.token_hex(16))
        command = kernel_command(args, private, image, accepted, paths, kernel_output)
        evidence['commands'].append(command); evidence['kernel_output'] = str(kernel_output)
        status['phase'] = 'kernel'
        phase = runtime.Runner(KERNEL_ENVELOPE, env, private / 'kernel-logs')
        result = phase.run(command, timeout=KERNEL_ENVELOPE, log='kernel-controller.log')
        packet.need(result.returncode == 0, 'kernel-controller-failed')
        evidence['kernel'] = kernel_status(kernel_output, args.source_commit)
        status.update(kernel_probe='PASS', baseline='PASS', candidate='PASS', native_compilation='PASS', status='PASS')
    except (runtime.Cancelled, KeyboardInterrupt):
        status.update(status='FAIL', cancelled=True)
    except Exception as error:
        status['status'] = 'FAIL'; evidence['error_type'] = type(error).__name__
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
                evidence['cleanup'] = cleanup_base(docker, cleanup, private, image, producer_finished)
                status['cleanup'] = evidence['cleanup']['status']
            except BaseException:
                status['cleanup'] = 'FAIL'; evidence['cleanup'] = {'status': 'FAIL', 'absence_verified': False}
            if events: status.update(status='FAIL', cancelled=True)
            if status['cleanup'] != 'PASS': status['status'] = 'FAIL'
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
