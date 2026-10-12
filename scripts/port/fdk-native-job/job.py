#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Separate finite same-job original producer and reviewed FDK native stage."""
import argparse
import builtins
from contextlib import contextmanager
import os
import json
from pathlib import Path
import platform
import re
import secrets
import shutil
import stat
import sys
import time
import types

sys.path.insert(0, str(Path(__file__).resolve().parent))
import job_runtime as jr
import packet
import evidence
from base_broker import broker_class

HERE = Path(__file__).resolve().parent
ENV_FIELDS = ('GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_REPOSITORY', 'RUNNER_ARCH', 'RUNNER_OS', 'ImageVersion', 'ImageOS')
FDK_KEYS = {'schema_version', 'stage', 'status', 'phase', 'error_code', 'cancelled',
            'owned_container_absence', 'native_build', 'hardware', 'installation',
            'selected_for_release', 'binary_publication', 'worker_diagnostics'}
FDK_ACTIONS = ('build-1', 'build-2', 'compare')


def validator_from_bytes(captured):
    """Execute authenticated pure bytes with a private, explicit import binding."""
    if type(captured) is not dict or set(captured) != {'evidence.py', 'worker_evidence.py'} or \
            any(type(value) is not bytes or len(value) > 8 * 1024**2 for value in captured.values()):
        raise ValueError('FDK-validator-bytes')
    modules = {name: types.ModuleType('captured_fdk_' + name) for name in ('evidence', 'worker_evidence')}
    def private_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name in modules:
            return modules[name]
        return builtins.__import__(name, globals, locals, fromlist, level)
    for name, module in modules.items():
        module.__dict__.update(__file__='captured-fdk-stage/' + name + '.py',
            __builtins__=dict(vars(builtins), __import__=private_import))
        exec(compile(captured[name + '.py'], module.__file__, 'exec'), module.__dict__)
    return modules['worker_evidence']


def authenticated_worker_validator(snapshot, manifest_path, manifest_sha):
    manifest = packet.load(manifest_path, manifest_sha)
    packet.need(type(manifest.get('files')) is dict, 'FDK-validator-manifest')
    captured = {}
    for name in ('stage.lock.json', 'evidence.py', 'worker_evidence.py'):
        relative = packet.ADAPTER + name
        row = manifest['files'][relative]; path = snapshot / relative
        packet.need(type(row) is dict and set(row) == {'sha256', 'mode', 'bytes'} and
                    type(row['mode']) is int and row['mode'] == 0o644 and type(row['bytes']) is int and
                    0 <= row['bytes'] <= 8 * 1024**2, 'FDK-validator-row')
        before = path.lstat(); data = packet.read(path); after = path.lstat()
        identity = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink,
                              s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        packet.need(before.st_uid == os.getuid() and identity(before) == identity(after) and
                    stat.S_IMODE(before.st_mode) == row['mode'] and len(data) == row['bytes'] and
                    packet.sha(data) == row['sha256'], 'FDK-validator-binding')
        captured[name] = data
    stage_bytes = captured.pop('stage.lock.json')
    packet.need(packet.sha(stage_bytes) == packet.ADAPTER_SHA, 'FDK-validator-stage-pin')
    # The complete packet/source/Git gate ran before this capture. Additionally
    # bind this exact dependency pair to the independently pinned stage lock.
    adapter = packet.decode(stage_bytes)
    for name, data in captured.items():
        packet.need(adapter['files'][packet.ADAPTER + name] == {'sha256': packet.sha(data), 'mode': 0o644},
                    'FDK-validator-stage-row')
    return validator_from_bytes(captured)


def ordinary():
    packet.need(os.getuid() == os.geteuid() != 0 and os.getgid() == os.getegid() != 0 and
                platform.system() == 'Linux' and platform.machine() in ('aarch64', 'arm64'), 'native-ordinary-user')
    packet.need(os.environ.get('RUNNER_ARCH') == 'ARM64' and os.environ.get('RUNNER_OS') == 'Linux', 'hosted-ARM-runner')
    with open('/proc/self/status', encoding='ascii') as stream:
        fields = stream.read(65536)
    for name in ('CapEff', 'CapPrm'):
        value = re.search(r'^' + name + r':\s+([0-9a-fA-F]+)$', fields, re.M)
        packet.need(value is not None and int(value[1], 16) == 0, 'ordinary-capabilities')


def output(path, root):
    path = Path(path).absolute()
    packet.need('..' not in path.parts and not path.exists() and not path.is_symlink() and
                not path.is_relative_to(root) and all(stat.S_ISDIR(p.lstat().st_mode) for p in path.parents), 'new-external-job-output')
    path.mkdir(mode=0o700)
    for name in ('private', 'public'):
        (path / name).mkdir(mode=0o700)
    return path


def validate_fdk_record(record, validator):
    packet.need(validator is not None and type(record) is dict and set(record) == FDK_KEYS and
                record['stage'] == 'fdk-native-development' and type(record['schema_version']) is int and
                record['schema_version'] == 2 and record['hardware'] == record['installation'] ==
                record['binary_publication'] == 'NOT RUN' and record['selected_for_release'] is False,
                'FDK-public-schema')
    packet.need(record['status'] in ('PASS', 'FAIL') and
                record['native_build'] == ('PASS' if record['status'] == 'PASS' else 'NOT ACCEPTED') and
                record['phase'] in ('preflight', 'base-probe', 'source', 'build-1', 'build-2', 'compare', 'complete') and
                record['error_code'] == (None if record['status'] == 'PASS' else 'fdk-stage-failed') and
                type(record['cancelled']) is type(record['owned_container_absence']) is bool, 'FDK-public-fields')
    record = packet.decode(json.dumps(record, allow_nan=False).encode())
    record['worker_diagnostics'] = validator.validate_workers(record['worker_diagnostics'],
                                                            require_complete=record['status'] == 'PASS')
    packet.need(record['status'] != 'PASS' or record['phase'] == 'complete' and
                record['cancelled'] is False and record['owned_container_absence'] is True, 'FDK-public-acceptance')
    return record


def capture_fdk(private, state):
    if not state.get('fdk_capture_attempted'):
        state['fdk_capture_attempted'] = True
        state['fdk_capture'] = None
        try:
            path = private / 'fdk/public/status.json'
            before = path.lstat(); raw = packet.read(path, 65536); after = path.lstat()
            identity = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink,
                                  s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            packet.need(before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == 0o600 and
                        identity(before) == identity(after), 'FDK-public-owner')
            state['fdk_capture'] = validate_fdk_record(packet.decode(raw), state.get('worker_validator'))
            state['fdk_capture_sha256'] = packet.sha(raw)
        except Exception:
            pass
    return state.get('fdk_capture')


def fdk_public(private, report, state):
    try:
        captured = capture_fdk(private, state)
        packet.need(captured is not None, 'FDK-public-unverified')
        record = packet.decode(json.dumps(captured).encode())
    except Exception:
        kind = 'UNAVAILABLE' if state.get('fdk_attempted') else 'NOT_RUN'
        record = {'schema_version': 2, 'stage': 'fdk-native-development', 'status': 'FAIL', 'phase': 'preflight',
                  'error_code': 'fdk-stage-failed', 'cancelled': False, 'owned_container_absence': False,
                  'native_build': 'NOT ACCEPTED', 'hardware': 'NOT RUN', 'installation': 'NOT RUN',
                  'selected_for_release': False, 'binary_publication': 'NOT RUN',
                  'worker_diagnostics': {name: {'availability': kind,
                      'exit': {'kind': 'UNOBSERVED' if kind == 'UNAVAILABLE' else 'NOT_RUN', 'code': None},
                      'observation': None} for name in FDK_ACTIONS}}
    if evidence.public_status(report)['status'] != 'PASS':
        record.update(status='FAIL', native_build='NOT ACCEPTED', error_code='fdk-stage-failed',
                      cancelled=record['cancelled'] or report['cancelled'])
    return record


def retire_exports(public):
    producer = public / 'producer'
    if producer.exists():
        packet.need(producer.is_dir() and not producer.is_symlink(), 'public-producer-directory')
        for path in producer.iterdir():
            packet.need(path.name in evidence.PUBLIC_FILES and path.is_file() and not path.is_symlink() and
                        path.lstat().st_uid == os.getuid() and path.lstat().st_nlink == 1, 'public-owned-export')
            path.unlink()
        producer.rmdir()


def write_exports(out, report, state):
    child = fdk_public(out / 'private', report, state)
    if report['status'] == 'PASS' and child['status'] != 'PASS':
        report.update(status='FAIL', fdk={'status': 'FAIL'})
    retire_exports(out / 'public')
    manifest = evidence.publish(out / 'private/producer', out / 'public/producer',
        state.get('image', ''), state.get('native_sha', ''), state['recipes'], report)
    if manifest['status'] != 'PASS':
        report['status'] = 'FAIL'
    fdk = out / 'public/fdk'
    fdk.mkdir(mode=0o700, exist_ok=True)
    packet.save(fdk / 'status.json', fdk_public(out / 'private', report, state))
    packet.save(out / 'private/job-result.json', report)
    packet.save(out / 'public/status.json', evidence.public_status(report))


def retain_producer_diagnostic(private, report):
    # Recover the last durable fixed state even if the outer worker call raised.
    try:
        worker = packet.decode(packet.read(private / 'producer-worker.json', 65536))
        diagnostic = evidence.producer_diagnostic(worker.get('diagnostic'))
    except Exception:
        diagnostic = None
    if diagnostic is not None:
        report['producer_diagnostic'] = diagnostic


def retain_producer_boundary(private, report):
    """Retain only the bounded worker-owned fields, never parent gate claims."""
    try:
        worker = packet.decode(packet.read(private / 'producer-worker.json', 65536))
        boundary = evidence.producer_boundary(worker.get('boundary'), worker=True)
        if boundary is None:
            raise ValueError('boundary-invalid')
        cleanup = worker.get('cleanup')
        cleanup = cleanup if type(cleanup) is dict else {}
        known = {'worker_status': worker.get('status'), 'worker_cancelled': worker.get('cancelled'),
                 'worker_cleanup_status': cleanup.get('status'),
                 'worker_cleanup_absence': cleanup.get('absence_verified'),
                 'worker_cleanup_cancelled': cleanup.get('cancelled')}
        packet.need(all(type(boundary[key]) is str and boundary[key] == 'UNOBSERVED' or
                        type(boundary[key]) is type(actual) and boundary[key] == actual
                        for key, actual in known.items()), 'boundary-invalid')
    except Exception:
        report['producer_boundary'].update(evidence.new_boundary(worker=True))
        if report['producer_boundary']['outer_outcome'] != 'FAIL':
            report['producer_boundary'].update(outer_gate='worker-receipt', outer_outcome='FAIL',
                                               outer_reason='boundary-invalid')
        return None
    report['producer_boundary'].update(boundary)
    return worker


def boundary_save(private, report, gate, outcome, reason='none'):
    report['producer_boundary'].update(outer_gate=gate, outer_outcome=outcome, outer_reason=reason)
    packet.save(private / 'job-result.json', report)


def boundary_failure(private, report, gate, error):
    report['producer_boundary'].update(outer_gate=gate, outer_outcome='FAIL',
                                       outer_reason=evidence.boundary_reason(error))
    try:
        packet.save(private / 'job-result.json', report)
    except BaseException as retry:
        if isinstance(retry, jr.Cancelled):
            report['cancelled'] = True


@contextmanager
def producer_gate(private, report, gate):
    try:
        boundary_save(private, report, gate, 'STARTED')
        yield
        boundary_save(private, report, gate, 'PASS')
    except BaseException as error:
        boundary_failure(private, report, gate, error)
        raise


def finish(out, report, state):
    with jr.defer_signals() as events:
        write_exports(out, report, state)
    if events:
        report.update(status='FAIL', cancelled=True)
        with jr.defer_signals():
            write_exports(out, report, state)
        raise jr.Cancelled(events[0])


def execute(args, state):
    root = args.source_root.absolute()
    packet.need(root == HERE.parents[2] and root == root.resolve(), 'job-source-location')
    out = output(args.output, root)
    private = out / 'private'
    report = {'status': 'FAIL', 'phase': 'preflight', 'cancelled': False,
              'producer': {'status': 'NOT RUN'}, 'fdk': {'status': 'NOT RUN'},
              'cleanup': {'status': 'FAIL', 'owned_image_absence': False}}
    state.update(out=out, report=report, recipes=root / 'scripts/ci/recipes.lock.json')
    broker = None
    try:
        ordinary()
        packet.need(args.execute_native and 1800 <= args.producer_timeout <= 4200 and
                    1800 <= args.fdk_timeout <= 3600 and 5400 <= args.deadline <= 9000 and
                    args.deadline >= args.producer_timeout + args.fdk_timeout + 300, 'job-time-budget')
        packet.need(args.docker_endpoint in ('unix:///run/docker.sock', 'unix:///var/run/docker.sock'), 'original-local-endpoint')
        packet.need(re.fullmatch('[0-9a-f]{40}', args.source_commit or '') and
                    os.environ.get('GITHUB_SHA') == args.source_commit, 'hosted-source-commit')
        packet.need(shutil.disk_usage(private).free >= 8 * 1024**3, 'job-disk-reserve')
        config = private / 'docker-config'
        config.mkdir(mode=0o700)
        env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C', 'HOME': str(private), 'DOCKER_CONFIG': str(config)}
        worker_env = {**env, **{k: os.environ[k] for k in ENV_FIELDS if k in os.environ}}
        runner = jr.Runner(args.deadline, worker_env, private / 'logs')
        git = runner.run(['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
                          '--no-optional-locks', '-C', str(root), 'rev-parse', 'HEAD'], timeout=15, limit=4096)
        packet.need(git.returncode == 0 and git.stdout.decode('ascii').strip() == args.source_commit, 'job-Git-commit')
        report['phase'] = 'source'
        report['source'] = packet.verify(root, args.packet, args.packet_sha256, args.source_commit,
                                          runner, private / 'source')
        snapshot = private / 'source'
        state['worker_validator'] = authenticated_worker_validator(snapshot, args.packet, args.packet_sha256)
        packet.save(private / 'source-receipt.json', report['source'])
        state['recipes'] = snapshot / 'scripts/ci/recipes.lock.json'
        state['native_sha'] = packet.sha(packet.read(snapshot / 'scripts/ci/native_arm.py'))
        cls = broker_class(snapshot / packet.ADAPTER)
        jr.Cancelled = cls.runtime.Cancelled
        nonce = secrets.token_hex(16)
        seconds = runner.deadline - time.monotonic()
        cli = cls.runtime.Runner(seconds, {**env, 'DOCKER_BUILDKIT': '0'}, private / 'docker-logs')
        cleanup = cls.runtime.Runner(180, env, private / 'cleanup-logs')
        broker = cls(cli, cleanup, args.docker_binary, args.docker_sha256, args.docker_endpoint,
                     os.getuid(), os.getgid(), private / 'base-image.json', nonce, jobroot=private,
                     context=private / 'producer/context', iidfile=private / 'producer/image-id')
        daemon = broker.initialize()
        cfg = {'snapshot': str(snapshot), 'adapter': str(snapshot / packet.ADAPTER), 'jobroot': str(private),
               'docker_binary': args.docker_binary, 'docker_sha256': args.docker_sha256, 'endpoint': args.docker_endpoint,
               'nonce': nonce, 'daemon': daemon, 'producer_timeout': args.producer_timeout}
        packet.save(private / 'producer-config.json', cfg)
        python = str(Path(sys.executable).resolve())
        report['phase'] = 'producer'
        report['producer_boundary'] = evidence.new_boundary()
        with producer_gate(private, report, 'worker-exit'):
            produced = runner.run([python, '-I', '-B', str(snapshot / (packet.PREFIX + 'producer.py')),
                '--config', str(private / 'producer-config.json'), '--config-sha256', packet.sha(packet.read(private / 'producer-config.json'))],
                timeout=args.producer_timeout + 30, log='producer.log')
            report['producer_boundary']['worker_return_zero'] = produced.returncode == 0 if type(produced.returncode) is int else 'UNOBSERVED'
            packet.need(type(produced.returncode) is int, 'worker-return-invalid')
            packet.need(report['producer_boundary']['worker_return_zero'], 'worker-exit-nonzero')
        with producer_gate(private, report, 'worker-receipt'):
            worker = retain_producer_boundary(private, report)
            packet.need(worker is not None, 'boundary-invalid')
        retain_producer_diagnostic(private, report)
        for gate, valid, reason in (
                ('worker-status', lambda: worker.get('status') == 'PASS', 'worker-status-not-pass'),
                ('worker-cancelled', lambda: worker.get('cancelled') is False, 'worker-cancelled'),
                ('worker-cleanup-status', lambda: worker.get('cleanup', {}).get('status') == 'PASS', 'worker-cleanup-not-pass'),
                ('worker-cleanup-absence', lambda: worker.get('cleanup', {}).get('absence_verified') is True, 'worker-cleanup-absence-unverified')):
            with producer_gate(private, report, gate):
                packet.need(valid(), reason)
        with producer_gate(private, report, 'producer-receipts'):
            state['image'] = worker['image_id']
            report['producer'] = evidence.validate_producer(private / 'producer', state['image'], state['native_sha'], state['recipes'])
        # Preserve the unchanged four-package result before entering the FDK stage.
        with producer_gate(private, report, 'original-result-retention'):
            original = packet.read(private / 'producer/result.json')
            (private / 'original-result.json').write_bytes(original)
            report['original_result_sha256'] = packet.sha(original)
            packet.save(private / 'producer-acceptance.json', report['producer'])
            accepted = dict(report['producer_boundary'], outer_gate='accepted', outer_outcome='PASS')
            packet.need(evidence.producer_boundary(accepted) is not None, 'boundary-invalid')
        try:
            boundary_save(private, report, 'accepted', 'PASS')
        except BaseException as error:
            boundary_failure(private, report, 'original-result-retention', error)
            raise
        report['phase'] = 'fdk'
        state['fdk_attempted'] = True
        child = runner.run([python, '-I', '-B', str(root / (packet.ADAPTER + 'stage.py')), '--execute-native',
            '--source-root', str(root), '--source-commit', args.source_commit,
            '--lock', str(root / (packet.ADAPTER + 'stage.lock.json')), '--lock-sha256', packet.ADAPTER_SHA,
            '--accepted-result', str(private / 'original-result.json'), '--accepted-result-sha256', packet.sha(original),
            '--bootstrap', str(private / 'producer/bootstrap.json'), '--bootstrap-sha256', packet.sha(packet.read(private / 'producer/bootstrap.json')),
            '--packages', str(private / 'producer/packages.lock'), '--inputs', str(private / 'producer/inputs.lock.json'),
            '--image', state['image'], '--docker-endpoint', args.docker_endpoint, '--docker-binary', args.docker_binary,
            '--docker-sha256', args.docker_sha256, '--output', str(private / 'fdk'), '--deadline', str(args.fdk_timeout),
            '--build-timeout', str((args.fdk_timeout - 300) // 2)], timeout=args.fdk_timeout + 30, log='fdk.log')
        fdk = capture_fdk(private, state)
        packet.need(type(child.returncode) is int and child.returncode == 0 and fdk is not None and
                    fdk.get('status') == 'PASS' and fdk.get('cancelled') is False,
                    'FDK-stage-failed')
        report['fdk'] = {'status': 'PASS', 'receipt_sha256': state['fdk_capture_sha256']}
        report['status'] = 'PASS'
    except jr.Cancelled:
        report.update(status='FAIL', cancelled=True)
    except Exception:
        report['error_code'] = 'fdk-native-job-failed'
        if report['phase'] in ('producer', 'fdk'):
            report[report['phase']]['status'] = 'FAIL'
    finally:
        with jr.defer_signals() as events:
            report['work_phase'] = report['phase']
            if report['work_phase'] == 'producer':
                retain_producer_diagnostic(private, report)
                if 'producer_boundary' in report:
                    retain_producer_boundary(private, report)
            report['phase'] = 'cleanup'
            if broker is not None:
                journals = [private / 'fdk/private/containers.json'] if (private / 'fdk/private/containers.json').exists() else []
                try:
                    report['cleanup'] = broker.cleanup(remove_image=True, container_journals=journals)
                    report['cancelled'] |= report['cleanup'].get('cancelled') is True
                except BaseException:
                    report['cleanup'] = {'status': 'FAIL', 'owned_image_absence': False}
            if events or report['cancelled'] or report['cleanup'].get('status') != 'PASS' or report['cleanup'].get('owned_image_absence') is not True:
                report.update(status='FAIL', cancelled=report['cancelled'] or bool(events))
            report['phase'] = 'complete'
            finish(out, report, state)
        if events:
            report.update(status='FAIL', cancelled=True)
            with jr.defer_signals():
                finish(out, report, state)
    return int(evidence.public_status(report)['status'] != 'PASS')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-native', action='store_true')
    for name in ('source-root', 'packet', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('source-commit', 'packet-sha256', 'docker-endpoint', 'docker-binary', 'docker-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--deadline', type=int, default=7200)
    parser.add_argument('--producer-timeout', type=int, default=3300)
    parser.add_argument('--fdk-timeout', type=int, default=3000)
    args = parser.parse_args()
    state = {}
    try:
        with jr.cancellation_handlers():
            return execute(args, state)
    except (Exception, jr.Cancelled) as error:
        if state:
            state['report'].update(status='FAIL', cancelled=state['report']['cancelled'] or isinstance(error, jr.Cancelled))
            with jr.defer_signals():
                try:
                    finish(state['out'], state['report'], state)
                except BaseException:
                    for path in (state['out'] / 'public/status.json', state['out'] / 'public/fdk/status.json', state['out'] / 'private/job-result.json'):
                        path.unlink(missing_ok=True)
                    retire_exports(state['out'] / 'public')
        print('fdk-native-job-failed', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
