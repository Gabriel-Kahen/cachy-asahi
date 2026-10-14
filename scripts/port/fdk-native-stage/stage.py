#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Explicit, finite FDK development trial against the accepted native builder."""
import argparse
import os
from pathlib import Path
import platform
import re
import secrets
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evidence import (EPOCH, INVENTORY_SHA, INPUTS_SHA, RECIPE_SHA, TEMPLATE_SHA,
                      accepted_base, digest, finalstatus_public, inventory, load,
                      need, read, safe_relative, save, sha, validate_accepted_output, validate_accepted_outputs)
from runtime import Cancelled, Runner, cancellation_handlers, defer_signals
from broker import Broker
import worker_evidence as worker_diagnostic

HERE = Path(__file__).resolve().parent
PREFIX = 'scripts/port/fdk-native-stage/'
TEMPLATE = 'packages/libraries/cachy-asahi-fdk-aac/'
HELPERS = {'scripts/build/build.py', 'scripts/build/compare.py',
           'scripts/build/container-entry.sh', 'scripts/checks/package_checks.py',
           'scripts/ci/native_arm.py'}


def ordinary():
    need(os.getuid() == os.geteuid() != 0 and os.getgid() == os.getegid() != 0, 'ordinary-identity')
    need(platform.machine() in ('aarch64', 'arm64'), 'native-host-required')
    with open('/proc/self/status', encoding='ascii') as stream:
        status = stream.read(65536)
    for field in ('CapEff', 'CapPrm'):
        match = re.search(r'^' + field + r':\s+([0-9a-fA-F]+)$', status, re.M)
        need(match is not None and int(match[1], 16) == 0, 'ordinary-capabilities')


def new_output(path, root):
    path, root = Path(path).absolute(), Path(root).absolute()
    need('..' not in path.parts and not path.is_relative_to(root) and not path.exists(), 'new-external-output')
    need(all(stat.S_ISDIR(p.lstat().st_mode) for p in path.parents), 'output-parent')
    path.mkdir(mode=0o700)
    (path / 'private').mkdir(mode=0o700)
    (path / 'public').mkdir(mode=0o700)
    return path


def snapshot(root, output, lock, runner, commit):
    need(lock.get('schema_version') == 1 and type(lock.get('files')) is dict, 'stage-lock-format')
    files = lock['files']
    template = load(HERE / 'template-inputs.json', TEMPLATE_SHA)
    own = {PREFIX + p.name for p in HERE.iterdir() if p.is_file() and p.name != 'stage.lock.json'}
    need(set(files) == own | HELPERS | {TEMPLATE + n for n in template}, 'stage-lock-file-set')
    target = output / 'source'
    target.mkdir(mode=0o700)
    for name, row in files.items():
        relative = safe_relative(name)
        need(type(row) is dict and set(row) == {'sha256', 'mode'} and row['mode'] in (0o644, 0o755), 'stage-lock-row')
        source = root / relative
        need(stat.S_IMODE(source.lstat().st_mode) == row['mode'], 'source-mode-drift')
        data = read(source)
        need(sha(data) == row['sha256'], 'source-byte-drift')
        tracked = runner.run(['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
                              '--no-optional-locks', '-C', str(root), 'show', commit + ':' + name], timeout=10)
        need(tracked.returncode == 0 and tracked.stdout == data, 'committed-source-byte-binding')
        mode = runner.run(['/usr/bin/git', '--no-optional-locks', '-C', str(root), 'ls-tree',
                           '--format=%(objectmode)', commit, '--', name], timeout=10, limit=4096)
        need(mode.returncode == 0 and mode.stdout == ('100' + oct(row['mode'])[2:] + '\n').encode(),
             'committed-source-mode-binding')
        dest = target / relative
        dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with dest.open('xb') as stream:
            stream.write(data)
        dest.chmod(row['mode'])
    for name, row in files.items():
        need(digest(root / name) == digest(target / name) == row['sha256'] and
             stat.S_IMODE((root / name).lstat().st_mode) == row['mode'], 'snapshot-race')
    need({n: files[TEMPLATE + n]['sha256'] for n in template} == template, 'frozen-template-drift')
    need(digest(target / (PREFIX + 'template-inputs.json')) == TEMPLATE_SHA and
         digest(target / (PREFIX + 'reviewed-inputs.json')) == RECIPE_SHA, 'review-map-pin')
    return target


def worker(runner, config, action, report=None):
    config = {**config, 'action': action}
    path = Path(config['private']) / (action + '-config.json')
    save(path, config)
    raw, _ = worker_diagnostic.capture(path, 65536)
    need(worker_diagnostic.decode(raw) == config, 'worker-config-race')
    config_sha = sha(raw)
    row = worker_diagnostic.worker_row('UNAVAILABLE')
    if report is not None: report['worker_diagnostics'][action] = row
    try:
        result = runner.run([str(Path(sys.executable).resolve()), '-I', '-B',
                         str(Path(config['snapshot']) / (PREFIX + 'worker.py')),
                         '--config', str(path), '--config-sha256', config_sha],
                        timeout=config['timeout'] + 40 if action != 'compare' else 180,
                        log=action + '.log')
        row['exit'] = worker_diagnostic.exit_record(result.returncode)
    except BaseException:
        worker_diagnostic.receive(config, config_sha, row)
        raise
    receipt = worker_diagnostic.receive(config, config_sha, row)
    need(result.returncode == 0, 'worker-failed')
    need(receipt is not None, 'worker-receipt-unverified')
    need(receipt.get('status') == 'PASS' and receipt.get('cancelled') is not True, 'worker-receipt-failed')
    if action != 'compare':
        need(receipt.get('cleanup', {}).get('absence_verified') is True, 'worker-cleanup-failed')
    if action == 'compare':
        attempts = receipt['attempts']
        need(type(attempts) is list and len(attempts) == 2, 'accepted-outputs-attempts')
        validate_accepted_outputs({'schema_version': 1,
            'builds': {'build-1': attempts[0]['accepted_output'], 'build-2': attempts[1]['accepted_output']},
            'comparison': receipt['comparison']})
    else:
        output = validate_accepted_output(receipt['artifact']['accepted_output'])
        need(receipt['artifact']['filename'] == output['archive']['name'] and
             receipt['artifact']['sha256'] == output['archive']['sha256'], 'accepted-output-receiver-binding')
    return receipt


def finish(output, report):
    # Cancellation during final writes cannot leave a candidate PASS receipt.
    with defer_signals() as events:
        save(output / 'private/result.json', report)
        save(output / 'public/status.json', finalstatus_public(report))
    if events:
        report.update(status='FAIL', cancelled=True)
        with defer_signals():
            save(output / 'private/result.json', report)
            save(output / 'public/status.json', finalstatus_public(report))
        raise Cancelled(events[0])


def execute(args, state=None):
    root = args.source_root.absolute()
    output = new_output(args.output, root)
    private = output / 'private'
    report = {'status': 'FAIL', 'phase': 'preflight', 'cancelled': False,
              'cleanup': {'status': 'FAIL', 'absence_verified': False},
              'worker_diagnostics': {name: worker_diagnostic.worker_row() for name in worker_diagnostic.ACTIONS}}
    if state is not None:
        state.update(output=output, report=report)
    broker = None
    try:
        ordinary()
        need(args.execute_native and 300 <= args.deadline <= 7200 and 60 <= args.build_timeout <= 1800,
             'explicit-bounded-native-request')
        need(args.deadline >= 2 * args.build_timeout + 300, 'deadline-build-budget')
        need(re.fullmatch(r'[0-9a-f]{40}', args.source_commit or ''), 'source-commit')
        need(not os.environ.get('GITHUB_SHA') or os.environ['GITHUB_SHA'] == args.source_commit, 'job-commit')
        configdir = private / 'docker-config'
        configdir.mkdir(mode=0o700)
        env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C',
               'HOME': str(private), 'DOCKER_CONFIG': str(configdir)}
        runner = Runner(args.deadline, env, private / 'logs')
        cleanup = Runner(60, env, private / 'cleanup-logs')
        commit = runner.run(['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
                             '--no-optional-locks', '-C', str(root), 'rev-parse', 'HEAD'], timeout=15, limit=4096)
        need(commit.returncode == 0 and commit.stdout.decode('ascii').strip() == args.source_commit, 'checkout-commit')
        lock = load(args.lock, args.lock_sha256)
        need(args.lock.absolute() == HERE / 'stage.lock.json' and root / PREFIX == HERE, 'stage-source-location')
        source = snapshot(root, private, lock, runner, args.source_commit)
        result = load(args.accepted_result, args.accepted_result_sha256)
        bootstrap = load(args.bootstrap, args.bootstrap_sha256)
        packages = read(args.packages)
        inputs = read(args.inputs)
        base = accepted_base(bootstrap, packages, inputs, result, args.image, args.source_commit,
                             lock['files']['scripts/ci/native_arm.py']['sha256'])
        save(private / 'accepted-base.json', base)
        report['accepted_base'] = base
        (private / 'packages.lock').write_bytes(packages)
        (private / 'inputs.lock.json').write_bytes(inputs)
        report['source_commit'] = args.source_commit
        report['stage_lock_sha256'] = args.lock_sha256
        report['accepted_result_sha256'] = args.accepted_result_sha256
        report['bootstrap_sha256'] = args.bootstrap_sha256
        nonce = secrets.token_hex(16)
        broker = Broker(runner, cleanup, args.docker_binary, args.docker_sha256, args.docker_endpoint,
                        args.image, os.getuid(), os.getgid(), private / 'containers.json', nonce)
        daemon = broker.initialize()
        report['phase'] = 'base-probe'
        probe = broker.probe()
        # Probe output contract is uid LF gid LF exact sorted pacman -Q bytes.
        identity, gid, live = probe.split(b'\n', 2)
        need(identity == str(os.getuid()).encode() and gid == str(os.getgid()).encode(), 'container-identity')
        inventory(live)
        report['live_base'] = {'status': 'PASS', 'packages_sha256': sha(live), 'package_count': 341}
        save(private / 'live-base.json', report['live_base'])
        report['phase'] = 'source'
        packet = private / 'fdk-aac-3.0.0-selected-source.tar'
        selector = source / (TEMPLATE + 'select-source.py')
        materializer = source / (TEMPLATE + 'materialize.py')
        python = str(Path(sys.executable).resolve())
        selected = runner.run([python, '-B', str(selector), '--fetch-upstream', '--output', str(packet)],
                              timeout=120, log='selected-source.log')
        need(selected.returncode == 0, 'selected-source-failed')
        materialized = runner.run([python, '-B', str(materializer), '--archive', str(packet),
                                  '--output', str(private / 'recipe'), '--reviewed-template',
                                  str(source / (PREFIX + 'template-inputs.json')),
                                  '--reviewed-template-sha256', TEMPLATE_SHA], timeout=120, log='materialize.log')
        need(materialized.returncode == 0, 'materialize-failed')
        reviewed = load(source / (PREFIX + 'reviewed-inputs.json'), RECIPE_SHA)
        actual = {p.name: digest(p) for p in (private / 'recipe').iterdir()}
        need(len(actual) == 25 and actual == reviewed, 'materialized-25-map')
        report['source'] = {'status': 'PASS', 'template_sha256': TEMPLATE_SHA,
              'reviewed_inputs_sha256': RECIPE_SHA, 'input_count': 25, 'archive_sha256': digest(packet)}
        save(private / 'source-receipt.json', report['source'])
        config = {'snapshot': str(source), 'private': str(private), 'image': args.image,
                  'endpoint': args.docker_endpoint, 'docker_binary': args.docker_binary,
                  'docker_sha256': args.docker_sha256, 'nonce': nonce, 'daemon': daemon,
                  'timeout': args.build_timeout, 'source_commit': args.source_commit,
                  'stage_lock_sha256': args.lock_sha256, 'run_id': os.environ.get('GITHUB_RUN_ID'),
                  'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT')}
        for number in (1, 2):
            report['phase'] = 'build-' + str(number)
            report[report['phase']] = worker(runner, config, report['phase'], report)
        report['phase'] = 'compare'
        compared = worker(runner, config, 'compare', report)
        report['comparison'] = compared['comparison']
        report['comparison_attempts'] = compared['attempts']
        report['phase'] = 'complete'
        report['status'] = 'PASS'
    except Cancelled:
        report['cancelled'] = True
    except Exception:
        report['error_code'] = 'fdk-stage-failed'
    finally:
        with defer_signals() as events:
            if broker is not None:
                try:
                    report['cleanup'] = broker.cleanup()
                    report['cancelled'] |= report['cleanup'].get('cancelled') is True
                except Exception:
                    report['cleanup'] = {'status': 'FAIL', 'absence_verified': False}
            if events:
                report.update(status='FAIL', cancelled=True)
            if report['cleanup'].get('absence_verified') is not True or report['cleanup'].get('status') != 'PASS':
                report['status'] = 'FAIL'
            finish(output, report)
        if events:
            report.update(status='FAIL', cancelled=True)
            with defer_signals():
                finish(output, report)
    return int(finalstatus_public(report)['status'] != 'PASS')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-native', action='store_true')
    for name in ('source-root', 'lock', 'accepted-result', 'bootstrap', 'packages', 'inputs', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('source-commit', 'lock-sha256', 'accepted-result-sha256', 'bootstrap-sha256',
                 'image', 'docker-endpoint', 'docker-binary', 'docker-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--deadline', type=int, default=3000)
    parser.add_argument('--build-timeout', type=int, default=1200)
    args = parser.parse_args()
    state = {}
    try:
        with cancellation_handlers():
            return execute(args, state)
    except (Exception, Cancelled) as error:
        if state:
            state['report']['status'] = 'FAIL'
            state['report']['cancelled'] |= isinstance(error, Cancelled)
            with defer_signals():
                try:
                    finish(state['output'], state['report'])
                except BaseException:
                    # A failed rewrite must not leave a published PASS receipt.
                    (state['output'] / 'public/status.json').unlink(missing_ok=True)
                    (state['output'] / 'private/result.json').unlink(missing_ok=True)
        print('fdk-stage-failed', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
