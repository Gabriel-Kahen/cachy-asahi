#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Separate finite same-job original producer and reviewed FDK native stage."""
import argparse
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import stat
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import job_runtime as jr
import packet
import evidence
from base_broker import broker_class

HERE = Path(__file__).resolve().parent
ENV_FIELDS = ('GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_REPOSITORY', 'RUNNER_ARCH', 'RUNNER_OS', 'ImageVersion', 'ImageOS')
FDK_KEYS = {'schema_version', 'stage', 'status', 'phase', 'error_code', 'cancelled',
            'owned_container_absence', 'native_build', 'hardware', 'installation',
            'selected_for_release', 'binary_publication'}


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


def fdk_public(private, report):
    try:
        record = packet.load(private / 'fdk/public/status.json')
        packet.need(set(record) == FDK_KEYS and record['stage'] == 'fdk-native-development' and
                    record['schema_version'] == 1 and record['hardware'] == record['installation'] ==
                    record['binary_publication'] == 'NOT RUN' and record['selected_for_release'] is False,
                    'FDK-public-schema')
        # Copy only finite enums/booleans; no child-controlled strings reach publication.
        packet.need(record['status'] in ('PASS', 'FAIL') and record['native_build'] in ('PASS', 'NOT ACCEPTED') and
                    record['phase'] in ('preflight', 'base-probe', 'source', 'build-1', 'build-2', 'compare', 'complete') and
                    record['error_code'] in (None, 'fdk-stage-failed') and
                    type(record['cancelled']) is type(record['owned_container_absence']) is bool,
                    'FDK-public-fields')
        packet.need(record['status'] != 'PASS' or record['phase'] == 'complete' and
                    record['cancelled'] is False and record['owned_container_absence'] is True and
                    record['native_build'] == 'PASS' and record['error_code'] is None, 'FDK-public-acceptance')
    except Exception:
        record = {'schema_version': 1, 'stage': 'fdk-native-development', 'status': 'FAIL', 'phase': 'preflight',
                  'error_code': 'fdk-stage-failed', 'cancelled': False, 'owned_container_absence': False,
                  'native_build': 'NOT ACCEPTED', 'hardware': 'NOT RUN', 'installation': 'NOT RUN',
                  'selected_for_release': False, 'binary_publication': 'NOT RUN'}
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
    child = fdk_public(out / 'private', report)
    if report['status'] == 'PASS' and child['status'] != 'PASS':
        report.update(status='FAIL', fdk={'status': 'FAIL'})
    retire_exports(out / 'public')
    manifest = evidence.publish(out / 'private/producer', out / 'public/producer',
        state.get('image', ''), state.get('native_sha', ''), state['recipes'], report)
    if manifest['status'] != 'PASS':
        report['status'] = 'FAIL'
    fdk = out / 'public/fdk'
    fdk.mkdir(mode=0o700, exist_ok=True)
    packet.save(fdk / 'status.json', fdk_public(out / 'private', report))
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
        produced = runner.run([python, '-I', '-B', str(snapshot / (packet.PREFIX + 'producer.py')),
            '--config', str(private / 'producer-config.json'), '--config-sha256', packet.sha(packet.read(private / 'producer-config.json'))],
            timeout=args.producer_timeout + 30, log='producer.log')
        worker = packet.load(private / 'producer-worker.json')
        retain_producer_diagnostic(private, report)
        packet.need(produced.returncode == 0 and worker.get('status') == 'PASS' and worker.get('cancelled') is False and
                    worker.get('cleanup', {}).get('status') == 'PASS' and
                    worker['cleanup'].get('absence_verified') is True, 'producer-worker-failed')
        state['image'] = worker['image_id']
        report['producer'] = evidence.validate_producer(private / 'producer', state['image'], state['native_sha'], state['recipes'])
        # Preserve the unchanged four-package result before entering the FDK stage.
        original = packet.read(private / 'producer/result.json')
        (private / 'original-result.json').write_bytes(original)
        report['original_result_sha256'] = packet.sha(original)
        packet.save(private / 'producer-acceptance.json', report['producer'])
        report['phase'] = 'fdk'
        child = runner.run([python, '-I', '-B', str(root / (packet.ADAPTER + 'stage.py')), '--execute-native',
            '--source-root', str(root), '--source-commit', args.source_commit,
            '--lock', str(root / (packet.ADAPTER + 'stage.lock.json')), '--lock-sha256', packet.ADAPTER_SHA,
            '--accepted-result', str(private / 'original-result.json'), '--accepted-result-sha256', packet.sha(original),
            '--bootstrap', str(private / 'producer/bootstrap.json'), '--bootstrap-sha256', packet.sha(packet.read(private / 'producer/bootstrap.json')),
            '--packages', str(private / 'producer/packages.lock'), '--inputs', str(private / 'producer/inputs.lock.json'),
            '--image', state['image'], '--docker-endpoint', args.docker_endpoint, '--docker-binary', args.docker_binary,
            '--docker-sha256', args.docker_sha256, '--output', str(private / 'fdk'), '--deadline', str(args.fdk_timeout),
            '--build-timeout', str((args.fdk_timeout - 300) // 2)], timeout=args.fdk_timeout + 30, log='fdk.log')
        fdk = packet.load(private / 'fdk/public/status.json')
        packet.need(child.returncode == 0 and fdk.get('status') == 'PASS' and fdk.get('cancelled') is False,
                    'FDK-stage-failed')
        report['fdk'] = {'status': 'PASS', 'receipt_sha256': packet.sha(packet.read(private / 'fdk/public/status.json'))}
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
