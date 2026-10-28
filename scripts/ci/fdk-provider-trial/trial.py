#!/usr/bin/env python3
"""Run one offline provider trial on a disposable copy of this job's ARM base."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid

HERE = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def package_input(native, fdk, pins):
    bootstrap = json.loads((native / 'bootstrap.json').read_text())
    image = (native / 'image-id').read_text().strip()
    assert re.fullmatch(r'sha256:[0-9a-f]{64}', image)
    assert json.loads((native / 'result.json').read_text())['native_build'] == 'PASS'
    assert bootstrap['status'] == 'image-provisioned' and bootstrap['image_id'] == image
    assert sha(native / 'packages.lock') == bootstrap['packages_lock_sha256'] == pins['base_packages_sha256']
    assert (fdk / 'result.txt').read_text() == 'FDK_PAIR=PASS\nEXIT=0\n'
    compare = json.loads((fdk / 'compare.json').read_text())
    name = 'cachy-asahi-fdk-aac-3.0.0-1-aarch64.pkg.tar.xz'
    assert not compare['errors'] and compare['packages'][name]['bytes_equal'] is True
    for attempt in (1, 2):
        record = json.loads((fdk / f'build-{attempt}/provenance.json').read_text())
        assert record['status'] == 'built-package-static-pass' and record['mode'] == 'native'
        assert record['image_id'] == image and record['exit_code'] == 0
        assert record['expected_packages_sha256'] == pins['base_packages_sha256']
        assert record['recipe_inputs']['PKGBUILD'] == '774803633213d77e9879005608ff23528b6780465c7bd00f3234430c9a7346df'
        package = fdk / f'build-{attempt}/artifacts' / name
        assert sha(package) == record['artifacts'][name]
        if attempt == 1:
            first = package
            verified_digest = record['artifacts'][name]
        else:
            assert record['artifacts'][name] == verified_digest
    return image, first, verified_digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('core-source', 'native', 'fdk', 'cache', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    pins = json.loads((HERE / 'inputs.json').read_text())
    image, candidate, candidate_digest = package_input(args.native, args.fdk, pins)
    args.output.mkdir(mode=0o700)
    public = args.output / 'public'; public.mkdir()
    inputs = args.output / 'inputs'; inputs.mkdir()
    sys.path.insert(0, str(args.core_source / 'scripts/ci'))
    import native_arm as native
    args.cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    items = [pins['keyring']]
    for row in pins['packages']:
        items.extend((row, native.signature_item(row)))
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda row: native.fetch(row, args.cache), items))
    keyhome = args.output / 'gpg'; keyhome.mkdir(mode=0o700)
    gpg = ['gpg', '--batch', '--no-options', '--homedir', str(keyhome), '--no-auto-key-retrieve']
    subprocess.run(gpg + ['--import', str(args.cache / pins['keyring']['filename'])],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    hooks = set()
    for row in pins['packages']:
        result = subprocess.run(gpg + ['--status-fd', '1', '--verify',
            str(args.cache / (row['filename'] + '.sig')), str(args.cache / row['filename'])],
            capture_output=True, text=True, check=True, timeout=30)
        native.valid_signature(result.stdout, pins['signer_fingerprint'])
        audit = native.inspect_package(args.cache / row['filename'], row)
        hooks.update(Path(name).name for name in audit['hooks'] if name.endswith('.hook'))
        shutil.copyfile(args.cache / row['filename'], inputs / row['filename'])
    shutil.copyfile(candidate, inputs / candidate.name)
    assert sha(inputs / candidate.name) == candidate_digest
    shutil.copyfile(args.native / 'packages.lock', inputs / 'base.lock')
    (inputs / 'plan.json').write_text(json.dumps({'packages': pins['packages'],
        'candidate': candidate.name, 'candidate_sha256': candidate_digest, 'hooks': sorted(hooks)}))
    (public / 'inputs.json').write_text(json.dumps({'signed_upstream_packages': len(pins['packages']),
        'candidate_sha256': candidate_digest, 'base_image': image,
        'packages': {row['name']: row['sha256'] for row in pins['packages']}}, indent=2) + '\n')
    name = 'cachy-asahi-fdk-provider-' + uuid.uuid4().hex
    command = ['docker', 'run', '--rm', '--name', name, '--pull=never', '--platform=linux/arm64',
        '--user=0:0', '--network=none', '--cap-drop=ALL', '--security-opt=no-new-privileges',
        '--pids-limit=256', '--memory=2g', '--cpus=2', '--tmpfs=/tmp:rw,nosuid,nodev,exec,size=256m',
        '--env=PATH=/usr/bin:/bin', '--env=HOME=/tmp', '--env=LC_ALL=C', '--env=PYTHONDONTWRITEBYTECODE=1']
    for cap in ('CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SETUID', 'SETGID', 'SYS_CHROOT'):
        command.append('--cap-add=' + cap)
    for source, target, readonly in ((inputs, '/inputs', True), (HERE, '/runner', True), (public, '/out', False)):
        assert ',' not in str(source.resolve())
        command.extend(('--mount', f'type=bind,src={source.resolve()},dst={target}' + (',readonly' if readonly else '')))
    command.extend(('--entrypoint=/usr/bin/python3', image, '-B', '/runner/container.py'))
    try:
        with (public / 'trial.log').open('wb') as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=300)
    finally:
        cleanup_error = None
        try:
            subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
        except (OSError, subprocess.SubprocessError) as error:
            cleanup_error = error
        # Probe even when removal raised; an exception keeps the original trial
        # exception as its context, and cleanup uncertainty still fails the job.
        remaining = subprocess.check_output(['docker', 'container', 'ls', '-a', '--filter',
            'name=^/' + name + '$', '--format', '{{.ID}}'], timeout=20)
        assert remaining == b'', 'trial container cleanup failed'
        if cleanup_error is not None:
            raise RuntimeError('trial container removal raised; absence probe completed') from cleanup_error
    result = json.loads((public / 'result.json').read_text())
    assert result['status'] == 'PASS'
    print('FDK_PROVIDER_PIPEWIRE=PASS; generic ARM container codec trial only')


if __name__ == '__main__':
    main()
