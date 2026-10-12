#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Same-job signed kernel builder extension and finite native compilation pair."""
import argparse
import hashlib
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BASE_SHA, INPUTS_SHA, PREFIX, SOURCE, code_contract, digest, inventory, load, module, need, regular, save
from runtime import Cancelled, Runner, cancellation_handlers, defer_signals
from broker import Broker
import image

HELPERS = ('scripts/ci/native_arm.py', 'scripts/ci/commit_image.py', 'scripts/port/fdk-native-stage/evidence.py')
HELD = ('harness.py', 'verify_build.py', 'candidate.json')
MAX_STAGE_SECONDS = 5 * 3600


def source_files(root):
    own = {PREFIX + p.name for p in (root / PREFIX).iterdir() if p.is_file() and p.suffix in ('.py', '.json') and p.name != 'stage.lock.json'}
    return own | {PREFIX + 'embedded-config.txt'} | set(HELPERS) | {SOURCE + name for name in HELD}


def freeze(root, output):
    need(root.is_absolute() and root == root.resolve() and output.is_absolute() and output == output.resolve() and
         not output.exists() and (output == root / (PREFIX + 'stage.lock.json') or
         output.is_relative_to(root / 'artifacts/kernel-native-stage')), 'canonical owned source/new freeze required')
    rows = {}
    for name in sorted(source_files(root)):
        path = root / name; regular(path)
        mode = stat.S_IMODE(path.stat().st_mode); need(mode in (0o644, 0o755), 'source mode differs')
        rows[name] = {'sha256': digest(path), 'mode': mode}
    save(output, {'schema_version': 1, 'purpose': 'KERNEL-NATIVE-C01', 'development_only': True,
                 'base_inventory_sha256': BASE_SHA, 'base_inputs_sha256': INPUTS_SHA, 'files': rows})
    return digest(output)


def ordinary():
    need(platform.system() == 'Linux' and platform.machine() in ('aarch64', 'arm64') and
         os.getuid() == os.geteuid() != 0 and os.getgid() == os.getegid() != 0, 'ordinary native host required')
    status = Path('/proc/self/status').read_text()
    caps = re.findall(r'^Cap(?:Eff|Prm):\s+([0-9a-f]+)$', status, re.M)
    need(len(caps) == 2 and all(int(value, 16) == 0 for value in caps), 'host capabilities present')


def snapshot(args, lock, output, runner):
    need(set(lock['files']) == source_files(args.root), 'exact stage source closure differs')
    target = output / 'code'; target.mkdir(mode=0o700)
    code_contract(args.root, lock['files'])
    for name, row in lock['files'].items():
        result = runner.run(['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
            '--no-optional-locks', '-C', str(args.root), 'show', args.source_commit + ':' + name], timeout=15)
        regular(args.root / name)
        data = (args.root / name).read_bytes()
        need(result.returncode == 0 and result.stdout == data and hashlib.sha256(data).hexdigest() == row['sha256'], 'committed source bytes differ: ' + name)
        mode = runner.run(['/usr/bin/git', '--no-optional-locks', '-C', str(args.root), 'ls-tree',
            '--format=%(objectmode)', args.source_commit, '--', name], timeout=10)
        need(mode.returncode == 0 and mode.stdout == ('100' + oct(row['mode'])[2:] + '\n').encode(), 'committed mode differs')
        path = target / name; path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data); path.chmod(row['mode'])
    code_contract(target, lock['files']); code_contract(args.root, lock['files'])
    return target


def copy_pin(source, target, pin, limit):
    regular(source, limit); need(digest(source) == pin, 'input pin differs: ' + source.name)
    total = 0; hashed = hashlib.sha256()
    with source.open('rb') as src, target.open('xb') as dst:
        for block in iter(lambda: src.read(1024**2), b''):
            total += len(block); need(total <= limit, 'snapshot input budget exceeded')
            hashed.update(block); dst.write(block)
    need(hashed.hexdigest() == pin and digest(source) == pin, 'input changed during snapshot')
    return {'sha256': pin, 'bytes': total}


def packet(args, code, private, lock):
    dependencies = load(code / (PREFIX + 'dependencies.json'), lock['files'][PREFIX + 'dependencies.json']['sha256'])
    candidate = load(code / (SOURCE + 'candidate.json'))
    need(dependencies['base_inventory_sha256'] == BASE_SHA and dependencies['base_inputs_lock_sha256'] == INPUTS_SHA and
         dependencies['initial_count'] == 341 and dependencies['final_count'] == 356 and dependencies['verified_count'] == 15,
         'exact separately reviewed builder extension required')
    need(len(dependencies['packages']) == 15 and not dependencies['baseline_changes'] and not dependencies['conflicts'] and
         not dependencies['removals'] and dependencies['deptest_exit'] == 0, 'extension changes baseline')
    expected = dependencies['expected_inventory'].encode(); expected_map = inventory(expected)
    base = args.base_packages.read_bytes(); base_map = inventory(base)
    need(hashlib.sha256(base).hexdigest() == BASE_SHA and len(base_map) == 341 and len(expected_map) == 356 and
         all(expected_map.get(name) == value for name, value in base_map.items()), 'base inventory preservation differs')
    need(hashlib.sha256(expected).hexdigest() == dependencies['expected_inventory_sha256'], 'extended inventory pin differs')
    additions = {row['name']: row['version'] for row in dependencies['packages']}
    need(expected_map == {**base_map, **additions} and not set(base_map) & set(additions), 'exact15-addition map required')
    inputs = private / 'inputs'; inputs.mkdir(mode=0o700)
    rows = {}
    for source, name, pin, limit in (
        (args.archive, 'asahi.tar.gz', candidate['archive']['sha256'], 300 * 1024**2),
        (args.config, 'embedded-config', candidate['config']['sha256'], 1024**2),
        (args.patch, 'candidate.patch', candidate['patch']['sha256'], 1024**2),
        (args.bio_baseline, 'bio-baseline.c', candidate['files']['block/bio.c']['before_sha256'], 1024**2),
        (args.bio_candidate, 'bio-candidate.c', candidate['files']['block/bio.c']['after_sha256'], 1024**2)):
        rows[name] = copy_pin(source, inputs / name, pin, limit)
    total = 0
    for row in dependencies['packages']:
        for name, pin, size in ((row['filename'], row['sha256'], row['size']),
                                (row['filename'] + '.sig', row['signature_sha256'], row['signature_size'])):
            need(Path(name).name == name and re.fullmatch(r'[A-Za-z0-9@+:_.-]+', name), 'flat archive name required')
            source = args.package_cache / name
            need(source.stat().st_size == size, 'extension archive size differs')
            rows[name] = copy_pin(source, inputs / name, pin, 800 * 1024**2)
            total += size
    need(total <= 800 * 1024**2, 'signed extension packet budget exceeded')
    for key in dependencies['keyring_files']:
        name = key['filename']; need(Path(name).name == name, 'flat key name required')
        rows[name] = copy_pin(args.key_dir / name, inputs / name, key['sha256'], 1024**2)
    contract = {'schema_version': 1, 'nonce': secrets.token_hex(32)[:32], 'uid': os.getuid(), 'gid': os.getgid(),
                'files': lock['files'], 'inputs': rows, 'base_inventory': base.decode(), 'source_commit': args.source_commit,
                'dependencies_sha256': lock['files'][PREFIX + 'dependencies.json']['sha256'],
                'candidate_sha256': lock['files'][SOURCE + 'candidate.json']['sha256']}
    return inputs, contract, dependencies


def finish(output, report):
    # Public output is an explicit finite status projection, never binaries or
    # arbitrary private tree content. Consumers use it only after stage exit.
    def write():
        save(output / 'private/result.json', report)
        public = {key: report[key] for key in ('status', 'phase', 'cancelled', 'source_commit',
            'native_kernel_compilation', 'kernel_execution', 'hardware_validation', 'performance', 'cleanup')}
        save(output / 'public/status.json', public)
    def invalidate():
        # Remove only these owned terminal receipts before failure rewrites.
        # An I/O error must not leave a previously published PASS authoritative.
        for path in (output / 'public/status.json', output / 'private/result.json'):
            path.unlink(missing_ok=True)
    try:
        with defer_signals() as events: write()
        if events:
            report.update(status='FAIL', cancelled=True)
            invalidate()
            with defer_signals(): write()
    except BaseException:
        invalidate()
        raise
    if events:
        raise Cancelled(events[0])


def execute(args):
    ordinary()
    need(args.root.is_absolute() and args.root == args.root.resolve() and
         re.fullmatch('[0-9a-f]{40}', args.source_commit) and os.environ.get('GITHUB_SHA', args.source_commit) == args.source_commit,
         'native checkout/commit binding required')
    need(args.output.is_absolute() and args.output == args.output.resolve() and not args.output.exists() and
         args.output.is_relative_to(args.root / 'artifacts/kernel-native-stage'), 'new owned ignored output required')
    need(shutil.disk_usage(args.root).free >= 8 * 1024**3, '8GiB host storage headroom required')
    lock = load(args.lock, args.lock_sha256)
    need(lock['purpose'] == 'KERNEL-NATIVE-C01' and lock['base_inventory_sha256'] == BASE_SHA, 'kernel stage lock differs')
    args.output.mkdir(parents=True, mode=0o700)
    private = args.output / 'private'; private.mkdir(mode=0o700)
    (args.output / 'public').mkdir(mode=0o700)
    for name in ('home', 'docker-config', 'logs', 'cleanup-logs'):
        (private / name).mkdir(mode=0o700)
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(private / 'home'), 'DOCKER_CONFIG': str(private / 'docker-config'), 'LC_ALL': 'C'}
    runner = Runner(MAX_STAGE_SECONDS, env, private / 'logs')
    cleanup = Runner(120, env, private / 'cleanup-logs')
    report = {'status': 'FAIL', 'phase': 'snapshot', 'cancelled': False, 'source_commit': args.source_commit,
              'native_kernel_compilation': 'NOT RUN', 'kernel_execution': 'NOT RUN',
              'hardware_validation': 'NOT RUN', 'performance': 'NOT MEASURED', 'cleanup': {'status': 'NOT RUN'}}
    finish(args.output, report)  # Interrupted/abandoned stages start authoritatively FAIL.
    brokers, provisioner = [], None
    image_journal = private / 'derived-image.json'
    try:
        code = snapshot(args, lock, private, runner)
        base_helper = module('kernel_accepted_base', code / HELPERS[2])
        bootstrap = load(args.bootstrap, args.bootstrap_sha256)
        result = load(args.accepted_result, args.accepted_result_sha256)
        regular(args.inputs)
        report['accepted_base'] = base_helper.accepted_base(bootstrap, args.base_packages.read_bytes(), args.inputs.read_bytes(),
            result, args.image, args.source_commit, lock['files']['scripts/ci/native_arm.py']['sha256'])
        inputs, contract, dependencies = packet(args, code, private, lock)
        nonce = contract['nonce']
        save(inputs / 'contract.json', contract)
        report['dependency_packet_sha256'] = contract['dependencies_sha256']
        report['expected_inventory_sha256'] = dependencies['expected_inventory_sha256']
        report['kernel_input_pins'] = {name: row['sha256'] for name, row in contract['inputs'].items()}
        def launch(broker, action):
            report['phase'] = action
            out = private / ('output-' + action); out.mkdir(mode=0o700)
            mounts = {'/inputs': str(inputs), '/code': str(code), '/out': str(out)}
            broker.expected_mounts = mounts
            save(inputs / 'contract.json', contract)
            worker_env = {'PATH': '/usr/bin:/bin', 'HOME': '/tmp/home', 'LC_ALL': 'C', 'KERNEL_STAGE_NONCE': nonce,
                          'KERNEL_STAGE_ACTION': action, 'KERNEL_STAGE_CONTRACT_SHA256': digest(inputs / 'contract.json')}
            command_result = broker.launch(action, mounts, worker_env, 7800 if action in ('baseline', 'candidate') else 900,
                                           persist=action == 'provision')
            need(command_result.returncode == 0, 'kernel worker exit failed')
            receipt = load(out / 'result.json')
            need(receipt['status'] == 'PASS' and receipt['action'] == action and receipt['nonce'] == nonce and
                 not receipt.get('cancelled'), 'kernel worker receipt differs')
            report[action] = receipt
            return receipt
        provisioner = Broker(runner, cleanup, args.docker, args.docker_sha256, args.endpoint, args.image,
            os.getuid(), os.getgid(), private / 'provision-containers.json', nonce, role='provision')
        brokers.append(provisioner); report['daemon'] = provisioner.initialize()
        launch(provisioner, 'provision')
        report['phase'] = 'derive'
        derived = image.commit(provisioner, code, image_journal); report['derived_image'] = derived
        builds = Broker(runner, cleanup, args.docker, args.docker_sha256, args.endpoint, derived['image_id'],
            os.getuid(), os.getgid(), private / 'build-containers.json', nonce)
        brokers.append(builds); builds.initialize(expected_daemon=report['daemon'])
        launch(builds, 'probe')
        baseline = launch(builds, 'baseline')
        config_file = private / 'output-baseline/generated-config.txt'; regular(config_file, 1024**2)
        contract['inputs']['baseline-config'] = copy_pin(config_file, inputs / 'baseline-config', digest(config_file), 1024**2)
        candidate = launch(builds, 'candidate')
        need(baseline['tools'] == candidate['tools'] == report['probe']['tools'], 'paired toolchain changed')
        need(baseline['generated_config_delta'] == candidate['generated_config_delta'], 'paired config deltas changed')
        need(digest(config_file) == digest(private / 'output-candidate/generated-config.txt'), 'paired generated config differs')
        need(all(row['native_kernel_compilation'] == 'PASS' for row in (baseline, candidate)), 'kernel pair incomplete')
        report.update(status='PASS', phase='complete', native_kernel_compilation='PASS')
    except (Cancelled, KeyboardInterrupt):
        report.update(status='FAIL', cancelled=True)
    except Exception as error:
        report.update(status='FAIL', error_type=type(error).__name__)
    finally:
        with defer_signals() as events:
            clean = []
            for broker in reversed(brokers):
                try: clean.append(broker.cleanup())
                except BaseException: clean.append({'status': 'FAIL', 'absence_verified': False})
            if provisioner is not None:
                try: clean.append(image.cleanup(provisioner, image_journal))
                except BaseException: clean.append({'status': 'FAIL', 'absence_verified': False})
            report['cleanup'] = {'status': 'PASS' if clean and all(r.get('status') == 'PASS' and r.get('absence_verified') is True for r in clean) else 'FAIL', 'records': clean}
            if events or any(row.get('cancelled') for row in clean): report.update(status='FAIL', cancelled=True)
            if report['cleanup']['status'] != 'PASS': report['status'] = 'FAIL'
            finish(args.output, report)
        if events:
            report.update(status='FAIL', cancelled=True)
            finish(args.output, report)
    return int(report['status'] != 'PASS')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('freeze', 'run')); parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    for name in ('lock', 'docker', 'bootstrap', 'accepted-result', 'base-packages', 'inputs', 'archive', 'config',
                 'patch', 'bio-baseline', 'bio-candidate', 'package-cache', 'key-dir'):
        parser.add_argument('--' + name, type=Path)
    for name in ('lock-sha256', 'docker-sha256', 'bootstrap-sha256', 'accepted-result-sha256', 'source-commit', 'image', 'endpoint'):
        parser.add_argument('--' + name)
    args = parser.parse_args()
    try:
        if args.action == 'freeze': print(freeze(args.root, args.output)); return 0
        need(all(value is not None for key, value in vars(args).items()), 'complete native contract arguments required')
        with cancellation_handlers(): return execute(args)
    except (Exception, Cancelled, KeyboardInterrupt):
        print('kernel native stage refused or failed; inspect owned retained status', file=sys.stderr); return 1


if __name__ == '__main__':
    raise SystemExit(main())
