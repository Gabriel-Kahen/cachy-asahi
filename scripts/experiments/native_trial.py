#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One native compiler correctness trial on the existing signed 341-package scratch builder."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import traceback
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/ci'))
import native_arm as native
import arm_c01 as arm
import stage

INPUTS_SHA = 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'
PACKAGES_SHA = 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
SOURCE = {'filename': 'zlib-1.3.2.tar.gz', 'url': 'https://zlib.net/zlib-1.3.2.tar.gz',
          'size': 1502830, 'sha256': arm.SOURCE_SHA}


def preflight(args):
    arm.need(platform.system() == 'Linux' and platform.machine() in ('aarch64', 'arm64')
             and os.getuid() == os.geteuid() > 0 and os.getgid() == os.getegid(), 'ordinary native ARM host required')
    arm.need(not any(os.environ.get(k) for k in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY',
                                               'DOCKER_CERT_PATH', 'DOCKER_API_VERSION')), 'Docker overrides refused')
    arm.need(re.fullmatch('[0-9a-f]{40}', args.source_commit or ''), 'exact product commit required')
    arm.need(native.run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], timeout=10) == args.source_commit,
             'checkout differs from selected product')
    subprocess.run(['git', '-C', str(ROOT), 'diff', '--exit-code', 'HEAD', '--',
                    'scripts/experiments', 'scripts/ci/native_arm.py', 'scripts/ci/inputs.lock.json'],
                   check=True, timeout=10, stdout=subprocess.DEVNULL)
    arm.need(args.output.is_absolute() and not args.output.exists() and not args.output.is_symlink()
             and '..' not in args.output.parts and not any(c in str(args.output) for c in ',\n\r')
             and not any(p.is_symlink() for p in args.output.parents), 'new absolute output required')
    arm.need(args.cache.is_absolute() and args.cache.is_dir() and not args.cache.is_symlink(), 'seeded cache required')
    paths = (ROOT, args.cache.resolve(), args.output)
    arm.need(all(not a.is_relative_to(b) and not b.is_relative_to(a)
                 for i, a in enumerate(paths) for b in paths[i + 1:]), 'source/cache/output must be separate')
    return native.load_pinned(ROOT / 'scripts/ci/inputs.lock.json', INPUTS_SHA)


def cleanup(output, docker, bootstrap_started=False):
    """Remove only this trial's nonce container and this job's bootstrap image."""
    result = {'status': 'PASS', 'container': 'NOT CREATED', 'image': 'NOT CREATED'}
    contract = output / 'trial/inputs/contract.json'
    for kind in ('container', 'image'):
        try:
            if kind == 'container' and contract.exists():
                nonce = json.loads(contract.read_text())['nonce']
                arm.need(re.fullmatch('[0-9a-f]{32}', nonce), 'owned trial nonce required')
                name = arm.container_prefix() + nonce
                query = docker + ['container', 'ls', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.Names}}']
                before = native.run(query, timeout=10)
                arm.need(before in ('', name), 'unexpected owned-container query')
                if before:
                    native.run(docker + ['rm', '-f', name], timeout=20)
                arm.need(native.run(query, timeout=10) == '', 'owned container still exists')
                result[kind] = {'name': name, 'absence_verified': True}
            if kind == 'image' and (output / 'native/image-id').exists():
                image = (output / 'native/image-id').read_text().strip()
                arm.need(re.fullmatch('sha256:[0-9a-f]{64}', image), 'owned bootstrap image required')
                native.run(docker + ['image', 'rm', '--no-prune', image], timeout=30)
                arm.need(image not in native.run(docker + ['image', 'ls', '-a', '--no-trunc', '-q'], timeout=10).splitlines(),
                         'owned bootstrap image still exists')
                result[kind] = {'id': image, 'absence_verified': True}
            if kind == 'image' and bootstrap_started and not (output / 'native/image-id').exists():
                result.update(status='FAIL', image={'status': 'UNKNOWN', 'absence_verified': False,
                              'reason': 'bootstrap started without an immutable image ID; cleanup uncertain'})
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            result.update(status='FAIL', **{kind: {'status': 'FAIL', 'traceback': traceback.format_exc(limit=8)}})
    return result


def run(args):
    arm.select_experiment(getattr(args, 'experiment', 'ARM-C01'))
    inputs = preflight(args)
    output = args.output
    output.mkdir(mode=0o700)
    summary = output / 'summary'; summary.mkdir()
    bootstrap = output / 'native'; bootstrap.mkdir()
    report = {'status': 'FAIL', 'experiment': arm.EXPERIMENT, 'candidate': arm.CANDIDATE, 'source_commit': args.source_commit, 'inputs_sha256': INPUTS_SHA,
              'source': SOURCE, 'hardware_validation': 'NOT RUN', 'performance_acceptance': 'NOT RUN',
              'selected_for_release': False, 'cancelled': False, 'workflow_sha': os.environ.get('WORKFLOW_SHA')}
    docker = ['docker', '--host=unix:///var/run/docker.sock']
    bootstrap_started = False
    def cancel(*_):
        raise KeyboardInterrupt()
    previous = {sig: signal.signal(sig, cancel) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        native.save(bootstrap / 'inputs.lock.json', inputs)
        probe = native.probe(bootstrap)
        docker = ['docker', '--host=' + probe['docker_endpoint']]
        native.audit(inputs, args.cache, bootstrap)
        # Empty recipe selection reuses the proven bootstrap without rebuilding unrelated packages.
        bootstrap_started = True
        image = native.build(inputs, args.cache, bootstrap, {})
        arm.need(native.sha(bootstrap / 'packages.lock') == PACKAGES_SHA, '341-package inventory differs')
        source_cache = output / 'source'; source_cache.mkdir()
        source = native.fetch(SOURCE, source_cache)
        report.update(image=image, packages_sha256=PACKAGES_SHA,
                      sources={str(p.relative_to(ROOT)): native.sha(p) for p in
                               (Path(__file__), Path(arm.__file__), Path(stage.__file__),
                                ROOT / 'scripts/experiments/corpus.py', ROOT / 'scripts/ci/native_arm.py')})
        if arm.profile_adapter():
            report['sources']['scripts/experiments/pgo.py'] = native.sha(Path(arm.profile_adapter().__file__).resolve())
        trial = output / 'trial'
        code = arm.host(SimpleNamespace(image=image, source=source, source_commit=args.source_commit,
                         expected_packages=bootstrap / 'packages.lock', expected_packages_sha256=PACKAGES_SHA,
                         output=trial))
        arm.need(code == 0, arm.EXPERIMENT + ' failed; inspect complete retained command and native records')
        contract = json.loads((trial / 'inputs/contract.json').read_text())
        verified = arm.verify_result(trial / 'raw', contract)
        stage.export_artifacts(trial / 'raw', output / 'experiment-artifacts', verified)
        report.update(status='PASS', receiver_verification=verified['receiver_verification'],
                      reproducibility=verified['reproducibility'])
        if arm.profile_adapter():
            report['profile_verification'] = verified['profile_verification']
    except (KeyboardInterrupt, arm.Cancelled, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report.update(error_kind=type(error).__name__, error_traceback=traceback.format_exc(limit=12))
        report['cancelled'] = isinstance(error, (KeyboardInterrupt, arm.Cancelled))
    finally:
        interrupted = []
        for sig in previous:
            signal.signal(sig, lambda signum, _: interrupted.append(signum))
        try:
            try:
                report['cleanup'] = cleanup(output, docker, bootstrap_started)
                if report['cleanup']['status'] != 'PASS':
                    report['status'] = 'FAIL'
            except (OSError, ValueError, KeyError, subprocess.SubprocessError):
                report.update(status='FAIL', cleanup={'status': 'FAIL', 'traceback': traceback.format_exc(limit=8)})
            try:
                if (output / 'trial').is_dir():
                    stage.project_evidence(output / 'trial', output / 'experiment-text')
            except (OSError, ValueError, KeyError):
                report.update(status='FAIL', evidence_error=traceback.format_exc(limit=8))
            if interrupted:
                report.update(status='FAIL', cancelled=True)
            native.save(summary / 'result.json', report)
            arm.late_cancellation(report, interrupted, summary / 'result.json')
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
    return 0 if report['status'] == 'PASS' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--experiment', choices=tuple(arm.EXPERIMENTS), default='ARM-C01')
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    return run(parser.parse_args())


if __name__ == '__main__':
    sys.exit(main())
