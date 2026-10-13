#!/usr/bin/env python3
"""Standalone maintained-baseline native checkpoint with owned recovery."""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import platform
import re
import secrets
import sys
import stat
import time

BASE = Path(__file__).resolve().parent
# Bind the bootstrap contract from source bytes before any project import.
import types
_contract_path = BASE / 'contract.py'
_contract_info = _contract_path.lstat()
if not stat.S_ISREG(_contract_info.st_mode) or _contract_info.st_nlink != 1 or _contract_info.st_size > 65536:
    raise ValueError('successor-bootstrap-contract-type')
_contract_fd = os.open(_contract_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
try:
    _contract_raw = os.read(_contract_fd, 65537)
finally:
    os.close(_contract_fd)
if hashlib.sha256(_contract_raw).hexdigest() != 'c84168539130394f9fe51bf440d036f44813ff2b923c1e9d77748f97f755c922':
    raise ValueError('successor-bootstrap-contract-pin')
c = types.ModuleType('contract')
c.__file__ = str(_contract_path)
exec(compile(_contract_raw, str(_contract_path), 'exec'), c.__dict__)


def module(name, path, pin):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    # Execute the exact captured source bytes, not a loader's cached bytecode.
    exec(compile(c.pinned(path, pin), str(path), 'exec'), value.__dict__)
    return value


def providers(base, source):
    def load(name, relative): return module(name, base / relative, source['files'][relative]['sha256'])
    runtime = load('maintained_owned_runtime', 'providers/owned_runtime.py')
    worker = load('maintained_successor_worker', 'worker.py')
    packet = load('maintained_packet_writer', 'providers/packet.py')
    return runtime, worker, packet


def ordinary(args):
    c.need(os.getuid() == os.geteuid() > 0 and os.getgid() == os.getegid() > 0
           and platform.system() == 'Linux' and platform.machine() in ('aarch64', 'arm64'), 'successor-native-user')
    c.need(os.environ.get('RUNNER_ARCH') == 'ARM64' and os.environ.get('RUNNER_OS') == 'Linux', 'successor-hosted-arm')
    c.need(type(args.source_commit) is str and re.fullmatch('[0-9a-f]{40}', args.source_commit)
           and os.environ.get('GITHUB_SHA') == args.source_commit, 'successor-source-commit')
    c.need(args.endpoint in ('unix:///run/docker.sock', 'unix:///var/run/docker.sock'), 'successor-local-daemon')
    c.need(Path(args.docker_binary).is_absolute() and re.fullmatch('[0-9a-f]{64}', args.docker_sha256 or ''), 'successor-docker-pin')
    c.need(type(args.deadline) is int and 600 <= args.deadline <= c.MAX_SECONDS, 'successor-job-budget')
    c.live(args.deadline_at)
    c.need(args.deadline_at <= time.monotonic() + c.MAX_SECONDS, 'successor-absolute-budget')
    status = Path('/proc/self/status').read_text()
    for key in ('CapEff', 'CapPrm'):
        found = re.search(r'^' + key + r':\s+([0-9a-fA-F]+)$', status, re.M)
        c.need(found is not None and int(found[1], 16) == 0, 'successor-ordinary-capabilities')


def output(path, base):
    path = Path(path).absolute()
    c.need('..' not in path.parts and not path.exists() and not path.is_symlink()
           and not path.is_relative_to(base) and all(p.is_dir() and not p.is_symlink() for p in path.parents), 'successor-new-output')
    path.mkdir(mode=0o700)
    (path / 'private').mkdir(mode=0o700)
    (path / 'public').mkdir(mode=0o700)
    return path


def accept_worker(worker, code, private, config):
    # A zero process code alone never admits native results.
    receipt = c.decode(c.read(private / 'native-worker.json'))
    worker.validate_receipt(receipt, config)
    c.need(type(code) is int and code == 0 and receipt['status'] == 'PASS', 'successor-worker-failed')
    return receipt


def execute(args, base=BASE):
    inputs, source = c.verify(base, args.packet_sha256)
    if args.verify_only:
        return {'status': 'SOURCE_ONLY_PASS', 'baseline_id': c.ID, 'source_files': len(source['files']), 'native_build': 'NOT RUN'}
    c.need(args.execute_native, 'successor-execution-selection')
    ordinary(args)
    out = output(args.output, base); private = out / 'private'
    runtime, worker, packet = providers(base, source)
    end = args.deadline_at  # Inherited first-step cutoff; never renew after prefetch.
    work_end, cleanup_end = end - c.RESERVE, end - 60
    report = {'schema_version': 1, 'baseline_id': c.ID, 'lineage': 'SUCCESSOR_NOT_HISTORICAL_ORIGINAL',
              'packet_sha256': args.packet_sha256, 'source_commit': args.source_commit,
              'inputs_sha256': c.INPUTS, 'inventory_sha256': c.INVENTORY,
              'native_sha256': c.NATIVE, 'recipes_sha256': c.RECIPES,
              'status': 'FAIL', 'native_build': 'NOT ACCEPTED', 'phase': 'preflight',
              'first_cause': None, 'secondary_errors': [], 'cancelled': False,
              'cleanup': {'status': 'NOT RUN', 'owned_image_absence': False},
              'hardware': 'NOT RUN', 'installation': 'NOT RUN', 'public_admission': False,
              'source_redistribution': 'UNRESOLVED', 'legacy_docker_cache_absence': 'NOT CLAIMED'}
    config = {'source': str(base), 'snapshot': str(base / 'native'), 'adapter': str(base / 'providers/adapter'),
              'jobroot': str(private), 'docker_binary': args.docker_binary, 'docker_sha256': args.docker_sha256,
              'endpoint': args.endpoint, 'nonce': secrets.token_hex(16), 'work_deadline': work_end,
              'cleanup_deadline': cleanup_end, 'job_deadline': end, 'baseline_id': c.ID,
              'source_commit': args.source_commit, 'packet_sha256': args.packet_sha256,
              'contract_sha256': source['files']['contract.py']['sha256']}
    runner, launched, passed, result = None, False, False, None

    def fail(reason, error=None):
        if report['first_cause'] is None: report['first_cause'] = reason
        elif reason != report['first_cause']: report['secondary_errors'].append(reason)
        report['status'], report['native_build'] = 'FAIL', 'NOT ACCEPTED'
        if error is not None and isinstance(error, runtime.Cancelled): report['cancelled'] = True

    try:
        with runtime.cancellation_handlers():
            try:
                for name in ('docker-config', 'tmp'): (private / name).mkdir(mode=0o700)
                env = {'PATH': '/usr/bin:/bin', 'HOME': os.environ['HOME'], 'LANG': 'C.UTF-8', 'LC_ALL': 'C',
                       'DOCKER_CONFIG': str(private / 'docker-config'), 'TMPDIR': str(private / 'tmp'),
                       'PYTHONDONTWRITEBYTECODE': '1', **{k: os.environ[k] for k in
                       ('GITHUB_SHA', 'RUNNER_ARCH', 'RUNNER_OS', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT') if k in os.environ}}
                runner = runtime.Runner(env, private, private / 'logs', deadline_seconds=args.deadline, deadline_at=end)
                with runner.phase_scope(work_end):
                    report['phase'] = 'cache'
                    due = [0.0]
                    def check_resources():
                        if time.monotonic() >= due[0]:
                            runner.check_resources(); due[0] = time.monotonic() + .25
                    report['cache'] = c.seed_cache(inputs, args.offline_cache, private / 'cache', work_end, check_resources)
                    c.verify(base, args.packet_sha256, work_end)
                    config['producer_timeout'] = work_end - time.monotonic()
                    c.live(work_end)
                    packet.save(private / 'worker-config.json', config)
                    config_pin = c.sha(c.read(private / 'worker-config.json'))
                    argv = [str(Path(sys.executable).resolve()), '-I', '-B', str(base / 'worker.py'),
                            '--config', str(private / 'worker-config.json'), '--config-sha256', config_pin]
                    report['phase'] = 'native'
                    launched = True
                    observation = runtime.RunObservation()
                    runner.observation = observation
                    result = runner.run(argv, timeout=work_end-time.monotonic(), log='native-worker.log')
                    report['process'] = observation.summary()
                    c.need(report['process']['reaping'] == 'COMPLETED'
                           and type(report['process']['natural_poll_code']) is int and report['process']['natural_poll_code'] == 0
                           and type(report['process']['runner_return_code']) is int and report['process']['runner_return_code'] == 0,
                           'successor-owned-process-result')
                    report['worker'] = accept_worker(worker, result.returncode, private, config)
                    c.verify(base, args.packet_sha256, work_end)
                    passed = True
            except BaseException as error:
                fail('successor-' + report['phase'] + '-failed', error)
                # Capture an existing finite diagnostic even on a nonzero worker.
                if launched:
                    if runner is not None and hasattr(runner, 'observation'):
                        report['process'] = runner.observation.summary()
                    try:
                        report['worker_observation'] = worker.failure_observation(c.decode(c.read(private / 'native-worker.json')))
                        report['cancelled'] |= report['worker_observation'].get('cancelled') is True
                    except BaseException:
                        report['worker_observation'] = {'availability': 'UNOBSERVED'}
            finally:
                with runtime.defer_signals() as events:
                    report['phase'] = 'cleanup'
                    if launched:
                        try:
                            c.live(cleanup_end)
                            report['cleanup'] = worker.cleanup(config, cleanup_end)
                            report['cancelled'] |= report['cleanup'].get('cancelled') is True
                            c.need(report['cleanup'].get('status') == 'PASS'
                                   and report['cleanup'].get('owned_image_absence') is True
                                   and report['cleanup'].get('absence_verified') is True
                                   and report['cleanup'].get('cancelled') is False, 'successor-owned-cleanup')
                        except BaseException as error:
                            fail('successor-cleanup-failed', error)
                    else:
                        report['cleanup'] = {'status': 'NOT STARTED', 'owned_image_absence': True,
                                             'absence_verified': True, 'cancelled': False}
                    if events:
                        report['cancelled'] = True; fail('successor-cancelled')
                    if runner is not None:
                        report['resource_observation'] = dict(runner.resource_observation)
                        try: runner.close()
                        except BaseException as error: fail('successor-runner-close-failed', error)
                runtime.check_cancelled()
    except BaseException as error:
        fail('successor-cancelled' if isinstance(error, runtime.Cancelled) else 'successor-finalization-failed', error)
    # PASS exists only after worker admission, cleanup and cancellation scope exit.
    if passed and report['first_cause'] is None and not report['cancelled']:
        report.update(status='PASS', native_build='PASS', phase='complete')
    public = out / 'public/status.json'
    custody = {}
    try:
        with runtime.cancellation_handlers():
            c.live(end)
            packet.save(private / 'result.json', report)
            c.publish(public, {k: report[k] for k in ('schema_version', 'baseline_id', 'lineage', 'packet_sha256',
                        'source_commit', 'inputs_sha256', 'inventory_sha256', 'native_sha256', 'recipes_sha256',
                        'status', 'native_build', 'phase', 'first_cause', 'cancelled', 'hardware', 'installation',
                        'public_admission', 'source_redistribution', 'legacy_docker_cache_absence')} |
                        {'owned_image_absence': report['cleanup'].get('owned_image_absence') is True}, custody, end)
            c.live(end); runtime.check_cancelled()
    except BaseException as error:
        fail('successor-publication-failed', error)
        try: report['public_retirement'] = c.retire(custody)
        except BaseException: report['public_retirement'] = 'UNKNOWN; RETURN CODE REMAINS FAILURE'
        # No stale public PASS may survive a failed publication boundary.
        try: packet.save(private / 'result.json', report)
        except BaseException: pass
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packet-sha256', required=True)
    parser.add_argument('--verify-only', action='store_true')
    parser.add_argument('--execute-native', action='store_true')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--offline-cache', type=Path)
    parser.add_argument('--docker-binary', default='/usr/bin/docker')
    parser.add_argument('--docker-sha256')
    parser.add_argument('--endpoint', default='unix:///var/run/docker.sock')
    parser.add_argument('--source-commit')
    parser.add_argument('--deadline', type=int, default=c.MAX_SECONDS)
    parser.add_argument('--deadline-at', type=float)
    args = parser.parse_args()
    try:
        result = execute(args)
        return 0 if result['status'] in ('PASS', 'SOURCE_ONLY_PASS') else 1
    except BaseException:
        print('successor-preflight-failed', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
