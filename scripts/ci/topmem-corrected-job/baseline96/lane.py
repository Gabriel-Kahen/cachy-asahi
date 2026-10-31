#!/usr/bin/env python3
"""One retained first-step deadline for proof, official prefetch and native work."""
import argparse
import hashlib
import importlib.util
import base64
import gzip
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
from types import ModuleType, SimpleNamespace

BASE = Path(__file__).resolve().parent
LANE = 'maintained-native-official-prefetch-v1'
CONTRACT_PIN = 'c84168539130394f9fe51bf440d036f44813ff2b923c1e9d77748f97f755c922'
path = BASE / 'contract.py'
info = path.lstat()
if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 65536:
    raise ValueError('prefetch-contract-type')
fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
try: raw = os.read(fd, 65537)
finally: os.close(fd)
if hashlib.sha256(raw).hexdigest() != CONTRACT_PIN: raise ValueError('prefetch-contract-pin')
c = ModuleType('contract'); c.__file__ = str(path)
exec(compile(raw, str(path), 'exec'), c.__dict__)


def clock(path, pin):
    path = Path(path).absolute()
    data = c.decode(c.pinned(path, pin))
    required = {'schema_version', 'lane_id', 'started_at', 'deadline_at', 'prefetch_end', 'guard_end',
                'source_commit', 'workflow_commit', 'run_id', 'run_attempt', 'uid'}
    c.need(set(data) == required and type(data['schema_version']) is int and data['schema_version'] == 1
           and data['lane_id'] == LANE, 'prefetch-clock-schema')
    info = path.lstat(); parent = path.parent.lstat()
    c.need(info.st_uid == parent.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600
           and stat.S_IMODE(parent.st_mode) == 0o700 and type(data['uid']) is int and data['uid'] == os.getuid(), 'prefetch-clock-owner')
    for key in ('started_at', 'deadline_at', 'prefetch_end', 'guard_end'):
        c.need(type(data[key]) in (int, float) and math.isfinite(data[key]), 'prefetch-clock-time')
    c.need(data['deadline_at'] == data['started_at'] + 7200
           and data['guard_end'] == data['deadline_at'] - 120
           and data['prefetch_end'] == min(data['started_at'] + 1800, data['guard_end'] - 600)
           and data['started_at'] <= time.monotonic(), 'prefetch-clock-reserves')
    c.live(data['deadline_at'])
    c.need(type(data['source_commit']) is str and re.fullmatch('[0-9a-f]{40}', data['source_commit'])
           and data['workflow_commit'] == data['source_commit'] == os.environ.get('GITHUB_SHA')
           and data['workflow_commit'] == os.environ.get('GITHUB_WORKFLOW_SHA')
           and data['run_id'] == os.environ.get('GITHUB_RUN_ID')
           and data['run_attempt'] == os.environ.get('GITHUB_RUN_ATTEMPT')
           and re.fullmatch('[1-9][0-9]{0,19}', data['run_id'])
           and re.fullmatch('[1-9][0-9]{0,9}', data['run_attempt']), 'prefetch-clock-context')
    return data


def load(base, packet, name, relative):
    path = base / relative
    raw = c.pinned(path, packet['files'][relative]['sha256'])
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    return value


def environment(root):
    return {'PATH': '/usr/bin:/bin', 'HOME': os.environ['HOME'], 'LANG': 'C.UTF-8', 'LC_ALL': 'C',
            'TMPDIR': str(root / 'tmp'), 'PYTHONDONTWRITEBYTECODE': '1',
            **{k: os.environ[k] for k in ('GITHUB_SHA', 'GITHUB_WORKFLOW_SHA', 'GITHUB_RUN_ID',
                'GITHUB_RUN_ATTEMPT', 'RUNNER_ARCH', 'RUNNER_OS', 'GITHUB_WORKSPACE') if k in os.environ}}


def fresh(root):
    c.need(not root.exists() and not root.is_symlink() and all(p.is_dir() and not p.is_symlink() for p in root.parents), 'prefetch-new-stage')
    root.mkdir(mode=0o700); (root / 'tmp').mkdir(mode=0o700)
    return root


def process(runtime, runner, argv, deadline, log):
    c.live(deadline)
    observation = runtime.RunObservation(); runner.observation = observation
    result = runner.run(argv, timeout=deadline-time.monotonic(), log=log)
    state = observation.summary()
    c.need(type(result.returncode) is int and result.returncode == 0
           and state['reaping'] == 'COMPLETED'
           and type(state['natural_poll_code']) is int and state['natural_poll_code'] == 0
           and type(state['runner_return_code']) is int and state['runner_return_code'] == 0, 'prefetch-owned-process')
    c.live(deadline)
    return result, state


def proof(base, packet, runtime, writer, clock_data, root):
    deadline = min(clock_data['started_at'] + 300, clock_data['prefetch_end'])
    c.live(deadline)
    root = fresh(root)
    workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve()
    proof_env = environment(root)
    proof_env.update(GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_SYSTEM='/dev/null', GIT_NO_REPLACE_OBJECTS='1')
    with runtime.Runner(proof_env, root, root / 'logs', deadline_seconds=7200, deadline_at=deadline) as runner:
        git = ['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', '--no-optional-locks', '-C', str(workspace)]
        with runner.phase_scope(deadline):
            result = runner.run([*git, 'rev-parse', 'HEAD'], timeout=min(10, deadline-time.monotonic()), limit=4096)
            c.need(type(result.returncode) is int and result.returncode == 0
                   and result.stdout.decode('ascii').strip() == clock_data['source_commit'], 'prefetch-committed-head')
            for name in [*packet['files'], 'packet.json']:
                c.live(deadline)
                path = base / name; relative = str(path.relative_to(workspace))
                blob = runner.run([*git, 'show', 'HEAD:' + relative], timeout=min(10, deadline-time.monotonic()))
                mode = runner.run([*git, 'ls-tree', 'HEAD', '--', relative], timeout=min(10, deadline-time.monotonic()), limit=4096)
                c.need(type(blob.returncode) is type(mode.returncode) is int and blob.returncode == mode.returncode == 0
                       and blob.stdout == c.read(path, deadline=deadline), 'prefetch-committed-bytes')
                expected = packet['files'][name]['mode'] if name != 'packet.json' else 0o644
                row = mode.stdout.decode('ascii').split()
                c.need(expected in (0o644, 0o755) and len(row) >= 4 and row[0] == ('100755' if expected == 0o755 else '100644')
                       and row[1] == 'blob', 'prefetch-committed-mode')
            c.live(deadline)
            writer.save(root / 'receipt.json', {'status': 'PASS', 'source_commit': clock_data['source_commit'],
                'workflow_commit': clock_data['workflow_commit'], 'source_files': len(packet['files']), 'deadline_at': deadline,
                'packet_sha256': c.sha(c.read(base / 'packet.json', deadline=deadline)),
                'clock_sha256': c.sha(c.read(root.parent / 'clock.json', deadline=deadline))})
    c.live(deadline)


def accept_prefetch(root, config):
    receipt = c.decode(c.read(root / 'prefetch-receipt.json'))
    c.need(receipt.get('status') == 'PASS' and receipt.get('cancelled') is False and receipt.get('first_failure') is None
           and receipt.get('packet_sha256') == config['packet_sha256'] and receipt.get('clock_sha256') == config['clock_sha256']
           and receipt.get('inputs_sha256') == c.INPUTS and receipt.get('native_sha256') == c.NATIVE
           and receipt.get('source_commit') == config['source_commit'] and receipt.get('run_id') == config['run_id']
           and receipt.get('run_attempt') == config['run_attempt'] and receipt.get('deadline_at') == config['deadline_at'], 'prefetch-receipt-binding')
    counts = receipt.get('counts')
    expected = {'total': 501, 'pass': 501, 'fail': 0, 'pending': 0}
    c.need(type(counts) is dict and set(counts) == set(expected)
           and all(type(counts[k]) is int and counts[k] == v for k, v in expected.items()), 'prefetch-receipt-count')
    c.need(type(receipt.get('pinned_bytes')) is int and receipt['pinned_bytes'] == 1531622678
           and receipt.get('cache_verified') is True, 'prefetch-receipt-cache')
    c.need(receipt.get('signature_authentication') == receipt.get('native_build') == 'NOT RUN', 'prefetch-not-signing')
    return receipt


def run(args, base=BASE):
    stamp = clock(args.clock, args.clock_sha256)
    end = stamp['deadline_at']
    inputs, packet = c.verify(base, args.packet_sha256, end)
    c.need(packet.get('lane_id') == LANE and packet.get('predecessor_packet_sha256') ==
           '7652ad6bde047af5cc676930fa8beece73c8a7896974231dc5afbb567c2a6ef3', 'prefetch-lane-binding')
    root = Path(args.clock).absolute().parent
    runtime = load(base, packet, 'prefetch_owned_runtime', 'providers/owned_runtime.py')
    writer = load(base, packet, 'prefetch_private_writer', 'providers/packet.py')
    if args.phase == 'proof':
        proof(base, packet, runtime, writer, stamp, root / 'proof')
        return 0
    if args.phase == 'retain':
        return retain(args, base, packet, stamp, root, runtime)
    source_receipt = c.decode(c.read(root / 'proof/receipt.json', 65536))
    c.need(source_receipt.get('status') == 'PASS' and source_receipt.get('source_commit') == stamp['source_commit']
           and source_receipt.get('source_files') == len(packet['files'])
           and source_receipt.get('workflow_commit') == stamp['workflow_commit']
           and source_receipt.get('packet_sha256') == args.packet_sha256
           and source_receipt.get('clock_sha256') == args.clock_sha256
           and source_receipt.get('deadline_at') == min(stamp['started_at'] + 300, stamp['prefetch_end']), 'prefetch-source-proof-required')
    if args.phase == 'prefetch':
        c.need(args.execute_prefetch, 'prefetch-execution-selection')
        c.need(os.getuid() == os.geteuid() > 0 and os.getgid() == os.getegid() > 0
               and os.environ.get('RUNNER_ARCH') == 'ARM64' and os.environ.get('RUNNER_OS') == 'Linux', 'prefetch-hosted-user')
        deadline = stamp['prefetch_end']; c.live(deadline)
        target = fresh(root / 'prefetch')
        child = target / 'worker'; child.mkdir(mode=0o700)
        config = {'source': str(base), 'packet_sha256': args.packet_sha256, 'contract_sha256': CONTRACT_PIN,
            'native_sha256': c.NATIVE, 'inputs_sha256': c.INPUTS, 'deadline_at': deadline,
            'jobroot': str(child), 'cache': str(child / 'cache'), 'source_commit': stamp['source_commit'],
            'clock_sha256': args.clock_sha256, 'run_id': stamp['run_id'], 'run_attempt': stamp['run_attempt']}
        writer.save(target / 'config.json', config)
        with runtime.Runner(environment(target), target, target / 'logs', deadline_seconds=7200,
                            deadline_at=min(end, deadline + 3)) as runner:
            with runner.phase_scope(deadline):
                argv = [str(Path(sys.executable).resolve()), '-I', '-B', str(base / 'prefetch.py'),
                        '--config', str(target / 'config.json'), '--config-sha256', c.sha(c.read(target / 'config.json'))]
                result, observed = process(runtime, runner, argv, deadline, 'prefetch.log')
                receipt = accept_prefetch(child, config)
                c.verify(base, args.packet_sha256, deadline)
                writer.save(target / 'parent-receipt.json', {'status': 'PASS', 'clock_sha256': args.clock_sha256,
                    'deadline_at': deadline, 'process': observed, 'prefetch': receipt})
        c.live(deadline)
        return 0
    prefetch_result = c.decode(c.read(root / 'prefetch/parent-receipt.json'))
    c.need(prefetch_result.get('status') == 'PASS' and prefetch_result.get('clock_sha256') == args.clock_sha256,
           'prefetch-parent-result-required')
    if args.phase == 'native':
        c.live(stamp['guard_end'])
        c.need(stamp['guard_end'] - time.monotonic() >= 600, 'prefetch-native-reserve')
        controller = load(base, packet, 'prefetch_native_controller', 'controller.py')
        native_args = SimpleNamespace(packet_sha256=args.packet_sha256, verify_only=False, execute_native=args.execute_native,
            source_commit=stamp['source_commit'], endpoint='unix:///var/run/docker.sock', docker_binary=args.docker_binary,
            docker_sha256=args.docker_sha256, deadline=7200, deadline_at=stamp['guard_end'],
            output=root / 'native', offline_cache=root / 'prefetch/worker/cache')
        result = controller.execute(native_args, base)
        c.live(stamp['guard_end'])
        return 0 if result['status'] == 'PASS' else 1
    c.need(False, 'prefetch-phase')


def retain(args, base, packet, stamp, root, runtime):
    """Failure evidence does not require a successful prefetch or native phase."""
    end = stamp['deadline_at']; c.live(end)
    observations = {'schema_version': 1, 'lane_id': LANE, 'clock_sha256': args.clock_sha256,
                    'packet_sha256': args.packet_sha256, 'deadline_at': end, 'phases': {}}
    for name in ['proof/receipt.json', 'prefetch/worker/prefetch-receipt.json', 'prefetch/parent-receipt.json']:
        path = root / name
        if not path.exists():
            observations['phases'][name] = {'availability': 'UNOBSERVED'}; continue
        raw = c.read(path, deadline=end); value = c.decode(raw)
        status = value.get('status')
        c.need(type(status) is str and status in ('PASS', 'FAIL', 'IN_PROGRESS'), 'prefetch-retained-status')
        row = {'availability': 'OBSERVED', 'status': status, 'raw_sha256': c.sha(raw)}
        if 'counts' in value:
            counts = value['counts']
            c.need(type(counts) is dict and set(counts) == {'total', 'pass', 'fail', 'pending'}
                   and all(type(v) is int and 0 <= v <= 501 for v in counts.values())
                   and counts['total'] == 501 and sum(counts[k] for k in ('pass', 'fail', 'pending')) == 501, 'prefetch-retained-count')
            row['counts'] = counts
        observations['phases'][name] = row
    acquisition = root / 'prefetch/worker/acquisition.json'
    if acquisition.exists():
        raw = c.read(acquisition, deadline=end); value = c.decode(raw); counts = value.get('counts')
        c.need(type(counts) is dict and set(counts) == {'total', 'pass', 'fail', 'pending'}
               and all(type(v) is int and 0 <= v <= 501 for v in counts.values())
               and counts['total'] == 501 and sum(counts[k] for k in ('pass', 'fail', 'pending')) == 501
               and value.get('signature_authentication') == 'NOT RUN', 'prefetch-retained-acquisition')
        observations['acquisition'] = {'raw_sha256': c.sha(raw), 'counts': counts, 'signature_authentication': 'NOT RUN'}
    encoded = base64.b64encode(gzip.compress(json.dumps(observations, sort_keys=True, allow_nan=False).encode(), mtime=0)).decode()
    print('OFFICIAL_PREFETCH_METADATA=' + encoded, flush=True)
    c.live(end)
    if not (root / 'native').exists(): return 0
    target = fresh(root / 'metadata')
    with runtime.Runner(environment(target), target, target / 'logs', deadline_seconds=7200, deadline_at=end) as runner:
        result, observed = process(runtime, runner, [str(Path(sys.executable).resolve()), '-I', '-B', str(base / 'retain_metadata.py'),
            '--packet-sha256', args.packet_sha256, '--output', str(root / 'native')], end, 'metadata.log')
    c.live(end)
    # Output is bounded, metadata-only data from the pinned retention helper.
    sys.stdout.buffer.write(result.stdout); sys.stdout.flush()
    c.live(end)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', choices=('proof', 'prefetch', 'native', 'retain'), required=True)
    parser.add_argument('--clock', type=Path, required=True)
    parser.add_argument('--clock-sha256', required=True)
    parser.add_argument('--packet-sha256', required=True)
    parser.add_argument('--execute-prefetch', action='store_true')
    parser.add_argument('--execute-native', action='store_true')
    parser.add_argument('--docker-binary')
    parser.add_argument('--docker-sha256')
    try:
        return run(parser.parse_args())
    except BaseException:
        print('official-prefetch-lane-failed', file=sys.stderr)
        return 1


if __name__ == '__main__': raise SystemExit(main())
