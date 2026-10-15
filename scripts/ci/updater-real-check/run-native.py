#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One same-job native build, dependency transaction and real installed Check session."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys

DEPENDENCIES = '9a8064cde23ad90c2352395bdd1f6f5a8e843b3db3468cd2cc5a90829dc32704'
PACKAGE = 'packages/tools/cachy-asahi-update'
HERE = Path(__file__).resolve().parent
CAPS = ('CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SETGID', 'SETUID', 'SYS_CHROOT', 'SETFCAP')


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def command(argv, log, timeout):
    with log.open('wb') as stream:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        except BaseException:
            for sig, seconds in ((signal.SIGTERM, 10), (signal.SIGKILL, 5)):
                try:
                    os.killpg(process.pid, sig)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=seconds)
                    break
                except subprocess.TimeoutExpired:
                    continue
            raise
    need(code == 0, 'command failed: ' + log.stem)


def query(argv):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    need(result.returncode == 0 and len(result.stdout) <= 1024**2, 'bounded Docker query failed')
    return result.stdout


def cleanup(root):
    """Remove only this fresh trial's recorded container/image and private paths."""
    failures = []
    raw = root / 'private'
    state = json.loads((root / 'owned.json').read_text()) if (root / 'owned.json').exists() else {}
    names = [state['container']] if state.get('container') else []
    for attempt in (1, 2):
        provenance = raw / f'native/build-{attempt}/provenance.json'
        if provenance.exists():
            row = json.loads(provenance.read_text())
            argv = row.get('command', [])
            if '--name' in argv:
                names.append(argv[argv.index('--name') + 1])
    for name in names:
        need(re.fullmatch(r'cachy-asahi-updater-(?:runtime-)?[0-9a-f]{32}', name), 'invalid owned container')
        try:
            present = query(['docker', 'container', 'ls', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.Names}}'])
            if present.strip():
                query(['docker', 'rm', '-f', name])
            need(not query(['docker', 'container', 'ls', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.Names}}']).strip(),
                 'owned runtime container remains')
        except Exception:
            failures.append('owned-container')
    image_file = raw / 'native/image-id'
    if image_file.exists():
        image = image_file.read_text().strip()
        need(re.fullmatch(r'sha256:[0-9a-f]{64}', image), 'invalid owned builder image')
        try:
            if image.encode() in query(['docker', 'image', 'ls', '--no-trunc', '--quiet']).splitlines():
                query(['docker', 'image', 'rm', '--no-prune', image])
            need(image.encode() not in query(['docker', 'image', 'ls', '--no-trunc', '--quiet']).splitlines(),
                 'owned builder image remains')
        except Exception:
            failures.append('builder-image')
    keyhome = raw / 'native/gpg'
    if keyhome.exists():
        try:
            subprocess.run(['gpgconf', '--homedir', str(keyhome), '--kill', 'all'],
                           check=True, capture_output=True, timeout=15)
        except Exception:
            failures.append('build-gpg')
    if not failures:
        for path in (raw, root / 'cache'):
            if path.exists():
                shutil.rmtree(path)
    return {'status': 'FAIL' if failures else 'PASS', 'failures': failures,
            'private_data_removed': not raw.exists() and not (root / 'cache').exists(),
            'scope': 'owned runtime container, builder image, build GPG home and private trial data',
            'daemon_disposal': 'NOT ATTESTED'}


def publish(source, root, result):
    guard = module('updater_runtime_export', source / 'scripts/ci/integration_export.py')
    selected = root / 'runtime-selected'
    selected.mkdir(exist_ok=True)
    save(selected / 'result.json', result)
    target = root / 'public/runtime'
    if target.exists():
        shutil.rmtree(target)
    need(guard.export_evidence(selected, target)['evidence_export'] == 'PASS', 'runtime public export refused')


def publish_build(source, root):
    native, materialized = root / 'private/native', root / 'private/materialized'
    if not native.is_dir() or (root / 'public/build').exists():
        return
    projected = root / 'build-selected'
    if projected.exists():
        shutil.rmtree(projected)
    projector = module('updater_runtime_build_projection', source / PACKAGE / 'public-evidence.py')
    need(projector.project_evidence(native, projected, materialized if materialized.exists() else None)['projection'] == 'PASS',
         'build projection failed')
    guard = module('updater_runtime_build_export', source / 'scripts/ci/integration_export.py')
    need(guard.export_evidence(projected, root / 'public/build')['evidence_export'] == 'PASS', 'build public export failed')


def trial(source, root, result):
    raw = root / 'private'
    raw.mkdir(mode=0o700)
    package = source / PACKAGE
    materialized, candidate, native = (raw / name for name in ('materialized', 'candidate', 'native'))
    py = sys.executable
    result['phase'] = 'materialize'
    command([py, '-I', '-B', str(package / 'materialize-inputs.py'), '--output', str(materialized),
             '--pins-sha256', sha(package / 'runner-inputs.lock.json')], raw / 'materialize.log', 930)
    result['phase'] = 'freeze'
    command([py, '-B', str(package / 'updater-native.py'), 'freeze',
             '--source', str(materialized / 'private-sanitized/cachy-update-e2b1b7144be71cf392809f48d1440f8da1d9c81a-sanitized.tar.gz'),
             '--vendor', str(materialized / 'private-cache/cachy-update-vendor.tar.gz'),
             '--output', str(candidate)], raw / 'freeze.log', 120)
    result['phase'] = 'native-pair'
    command([py, '-B', str(package / 'updater-native.py'), 'build', '--candidate', str(candidate / 'candidate.json'),
             '--candidate-sha256', sha(candidate / 'candidate.json'), '--cache', str(root / 'cache'),
             '--output', str(native)], raw / 'native.log', 5400)
    native_result = json.loads((native / 'result.json').read_text())
    need(native_result['native_pair'] == 'PASS', 'native pair did not pass')
    result['native_pair'] = 'PASS'
    image = (native / 'image-id').read_text().strip()
    need(image == native_result['image_id'], 'builder image differs from native pair')
    inspected = json.loads(query(['docker', 'image', 'inspect', image]))[0]
    need(inspected['Id'] == image and inspected['Architecture'] == 'arm64' and inspected['Os'] == 'linux',
         'original local native builder required')
    result['builder_image'] = image
    publish_build(source, root)
    result['phase'] = 'runtime-dependency-authentication'
    lock_path = HERE / 'dependencies/inputs.lock.json'
    need(sha(lock_path) == DEPENDENCIES, 'runtime dependency lock changed')
    lock = json.loads(lock_path.read_text())
    command([py, '-B', str(HERE / 'dependencies/acquire.py'), '--source-root', str(source),
             '--cache', str(root / 'cache'), '--keydir', str(root / 'cache'),
             '--output', str(raw / 'dependency-audit')], raw / 'dependency-audit.log', 180)
    inputs = raw / 'runtime-inputs'
    inputs.mkdir(mode=0o700)
    (inputs / 'dependencies').mkdir()
    for row in lock['packages']:
        for name, pin in ((row['filename'], row['sha256']),
                          (row['filename'] + '.sig', row['signature_sha256'])):
            original = root / 'cache' / name
            need(sha(original) == pin, 'runtime cache changed after authentication')
            shutil.copyfile(original, inputs / 'dependencies' / name)
    artifacts = list((native / 'build-1/artifacts').glob('*.pkg.tar.*'))
    need(len(artifacts) == 1, 'exactly one compiled updater package required')
    package_sha = sha(artifacts[0])
    other = list((native / 'build-2/artifacts').glob('*.pkg.tar.*'))
    need(len(other) == 1 and sha(other[0]) == package_sha, 'native package pair changed')
    shutil.copyfile(artifacts[0], inputs / 'updater.pkg.tar.xz')
    shutil.copyfile(root / 'cache/archlinuxarm.gpg', inputs / 'archlinuxarm.gpg')
    shutil.copyfile(native / 'packages.lock', inputs / 'compiler-packages.lock')
    shutil.copyfile(HERE / 'dependencies/expected-installed-packages.lock', inputs / 'expected-installed-packages.lock')
    shutil.copytree(HERE / 'real-check', inputs / 'real-check',
                    ignore=shutil.ignore_patterns('README.md', 'test-*.py', '__pycache__'))
    shutil.copyfile(HERE / 'inside.py', inputs / 'inside.py')
    # The pinned source recipe declares these 18 relationships; verify from the artifact below in-container too.
    checks = module('updater_runtime_checks', source / 'scripts/checks/package_checks.py')
    report = checks.package(artifacts[0])
    metadata = report['metadata']['.PKGINFO']
    need(metadata['pkgname'] == ['cachy-asahi-update'] and metadata['pkgver'] == ['4.4.2-2'],
         'new Check fix requires exact package release 4.4.2-2')
    requires = metadata['depend']
    need(len(requires) == 18, 'complete updater dependency declarations required')
    save(inputs / 'runtime.json', {'package_sha256': package_sha, 'packages': lock['packages'],
                                 'runtime_dependencies': requires, 'signer_fingerprint': lock['signer_fingerprint']})
    output = raw / 'runtime-output'
    output.mkdir(mode=0o700)
    nonce = os.urandom(16).hex()
    name = 'cachy-asahi-updater-runtime-' + nonce
    save(root / 'owned.json', {'container': name})
    result['phase'] = 'runtime-install-and-real-check'
    argv = ['docker', 'run', '--name', name, '--pull=never', '--platform=linux/arm64', '--user=0:0',
            '--network=none', '--ipc=private', '--cap-drop=ALL', '--security-opt=no-new-privileges',
            '--pids-limit=256', '--memory=2g', '--cpus=2', '--tmpfs=/tmp:rw,nosuid,nodev,exec,size=512m',
            '--mount', f'type=bind,src={inputs},dst=/inputs,readonly',
            '--mount', f'type=bind,src={output},dst=/out', '--env=CACHY_ASAHI_UPDATER_RUNTIME=' + nonce,
            '--entrypoint=/usr/bin/python3']
    for cap in CAPS:
        argv.append('--cap-add=' + cap)
    argv += [image, '-I', '-B', '/inputs/inside.py']
    try:
        command(argv, raw / 'runtime.log', 360)
    finally:
        if (output / 'result.json').is_file():
            result['runtime'] = json.loads((output / 'result.json').read_text())
    need(result.get('runtime', {}).get('status') == 'PASS', 'runtime software checks failed')
    result.update(status='PASS', phase='completed', package_sha256=package_sha)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--cleanup-only', action='store_true')
    args = parser.parse_args()
    source, root = args.source.resolve(strict=True), args.output.resolve(strict=True)
    need(platform.system() == 'Linux' and platform.machine() in ('aarch64', 'arm64') and os.getuid() != 0,
         'nonroot native ARM Linux coordinator required')
    need(not any(name.startswith('DOCKER_') for name in os.environ), 'Docker environment overrides refused')
    need(re.fullmatch('[0-9a-f]{40}', args.source_commit) and
         subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip() == args.source_commit,
         'exact reviewed product checkout required')
    need(root.is_relative_to('/tmp') and root.stat().st_uid == os.getuid()
         and root.stat().st_mode & 0o777 == 0o700 and not any(c in str(root) for c in ',\n'),
         'owned private /tmp trial directory required')
    (root / 'public').mkdir(exist_ok=True)
    result_path = root / 'result.json'
    result = json.loads(result_path.read_text()) if args.cleanup_only and result_path.exists() else {
        'status': 'FAIL', 'phase': 'startup', 'source_commit': args.source_commit, 'native_pair': 'NOT RUN',
        'runtime': {'status': 'NOT RUN'}, 'publication': 'NOT ACCEPTED', 'hardware': 'NOT RUN'}
    previous = signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        if not args.cleanup_only:
            trial(source, root, result)
    except BaseException as error:
        result.update(status='FAIL', error_type=type(error).__name__)
    finally:
        prior_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
        try:
            try:
                publish_build(source, root)
            except Exception as error:
                result.update(status='FAIL', build_export_error_type=type(error).__name__)
            try:
                result['cleanup'] = cleanup(root)
            except Exception as error:
                result['cleanup'] = {'status': 'FAIL', 'error_type': type(error).__name__,
                                     'private_data_removed': False}
            if result['cleanup']['status'] != 'PASS':
                result['status'] = 'FAIL'
            save(result_path, result)
            publish(source, root, result)
        finally:
            signal.signal(signal.SIGTERM, previous)
            signal.pthread_sigmask(signal.SIG_SETMASK, prior_mask)
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
