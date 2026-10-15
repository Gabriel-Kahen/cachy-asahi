#!/usr/bin/env python3
"""Build three local tools on the existing same-job native ARM base image."""
import argparse
import hashlib
import importlib.util
import json
import platform
from pathlib import Path
import re
import shutil
import subprocess
import sys

PACKAGES = ('packages/shells/cachy-asahi-zsh-autosuggestions',
            'packages/shells/cachy-asahi-fish-bang-bang',
            'packages/tools/cachy-asahi-topmem')


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(argv, log, timeout=90):
    with log.open('w') as stream:
        subprocess.run(list(map(str, argv)), check=True, timeout=timeout,
                       stdout=stream, stderr=subprocess.STDOUT)


def prepare(source, output, checks):
    """Snapshot only the fixed recipes and make a changed-version test fixture."""
    reviewed = json.loads((Path(__file__).parent / 'inputs.json').read_text())
    rows = []
    for relative in PACKAGES:
        base = source / relative
        report = checks.recipe(base / 'PKGBUILD')
        need(not report['errors'], str(report['errors']))
        need(report['input_sha256'] == reviewed[relative], 'recipe changed: ' + relative)
        name = base.name
        first = output / name / 'current'
        first.parent.mkdir()
        shutil.copytree(base, first)
        second = first.with_name('upgrade')
        shutil.copytree(first, second)
        metadata = report['metadata']
        old = metadata['pkgrel'][0]
        need(re.fullmatch('[0-9]+', old), 'integer pkgrel required')
        new = str(int(old) + 1)
        recipe = second / 'PKGBUILD'
        raw, count = re.subn(r'(?m)^pkgrel=' + re.escape(old) + '$', 'pkgrel=' + new, recipe.read_text())
        need(count == 1, 'pkgrel fixture edit failed')
        recipe.write_text(raw)
        srcinfo = second / '.SRCINFO'
        if srcinfo.exists():
            raw, count = re.subn(r'(?m)^(\s*pkgrel = )' + re.escape(old) + '$', r'\g<1>' + new, srcinfo.read_text())
            need(count == 1, 'SRCINFO fixture edit failed')
            srcinfo.write_text(raw)
        rows.append((name, first, second))
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--native-output', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source, native, output = (path.resolve() for path in (args.source_root, args.native_output, args.output))
    need(platform.system() == 'Linux' and platform.machine() in ('aarch64', 'arm64'), 'native ARM host required')
    need(not output.is_relative_to(source), 'output must be outside checkout')
    need(json.loads((native / 'result.json').read_text())['native_build'] == 'PASS', 'original builds must pass first')
    bootstrap = json.loads((native / 'bootstrap.json').read_text())
    image = (native / 'image-id').read_text().strip()
    need(re.fullmatch('sha256:[0-9a-f]{64}', image), 'immutable image required')
    need(bootstrap['status'] == 'image-provisioned' and bootstrap['image_id'] == image and
         bootstrap['packages_lock_sha256'] == sha(native / 'packages.lock'), 'base builder handoff differs')
    output.mkdir(mode=0o700)
    spec = importlib.util.spec_from_file_location('checks', source / 'scripts/checks/package_checks.py')
    checks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checks)
    rows = prepare(source, output, checks)
    bundle = output / 'lifecycle-inputs'
    bundle.mkdir()
    shutil.copyfile(native / 'packages.lock', bundle / 'packages.lock')
    lifecycle_rows = []
    epoch = json.loads((native / 'inputs.lock.json').read_text())['source_date_epoch']
    for name, current, upgrade in rows:
        builds = []
        for label, recipe in (('current-1', current), ('current-2', current), ('upgrade', upgrade)):
            reviewed = output / name / (label + '-inputs.json')
            reviewed.write_text(json.dumps(checks.recipe(recipe / 'PKGBUILD')['input_sha256'], sort_keys=True) + '\n')
            target = output / name / label.replace('upgrade', 'upgrade-build')
            run([sys.executable, '-B', source / 'scripts/build/build.py', recipe,
                 '--image', image, '--mode', 'native', '--network', 'none', '--timeout', '60',
                 '--source-date-epoch', epoch, '--expected-packages', native / 'packages.lock',
                 '--reviewed-inputs', reviewed, '--output', target], output / name / (label + '.log'))
            builds.append(target)
        run([sys.executable, '-B', source / 'scripts/build/compare.py', *builds[:2], '--require-bytes'],
            output / name / 'compare.json', 60)
        entries = []
        for label, target in (('current', builds[0]), ('upgrade', builds[2])):
            artifacts = list((target / 'artifacts').glob('*.pkg.tar.*'))
            need(len(artifacts) == 1, 'expected one package')
            archive = artifacts[0]
            report = checks.package(archive)
            need(not report['errors'], 'artifact rejected')
            payload = {path: row for path, row in report['members'].items() if not path.startswith('.') and row['type'] != '5'}
            need(all(row['type'] == '0' and path.startswith(('usr/bin/', 'usr/share/')) for path, row in payload.items()),
                 'unexpected payload')
            shutil.copyfile(archive, bundle / archive.name)
            entries.append({'archive': archive.name, 'version': report['metadata']['.PKGINFO']['pkgver'][0], 'payload': payload})
        need(entries[0]['payload'] == entries[1]['payload'], 'test upgrade must retain exact payload')
        lifecycle_rows.append({'name': name, 'versions': entries})
    (bundle / 'packages.json').write_text(json.dumps(lifecycle_rows, sort_keys=True) + '\n')
    container = 'cachy-asahi-tools-' + __import__('os').urandom(8).hex()
    try:
        run(['docker', 'run', '--rm', '--name', container, '--pull=never', '--platform=linux/arm64',
             '--user=0:0', '--network=none', '--cap-drop=ALL', '--cap-add=CHOWN', '--cap-add=SETUID',
             '--cap-add=SETGID', '--cap-add=DAC_OVERRIDE', '--security-opt=no-new-privileges',
             '--pids-limit=128', '--memory=1g', '--cpus=2', '--tmpfs=/tmp:rw,nosuid,nodev,size=128m',
             '--mount', f'type=bind,src={bundle},dst=/inputs,readonly',
             '--mount', f'type=bind,src={Path(__file__).parent / "lifecycle.py"},dst=/lifecycle.py,readonly',
             '--entrypoint=/usr/bin/python3', image, '-I', '-B', '/lifecycle.py'], output / 'lifecycle.log', 180)
    finally:
        subprocess.run(['docker', 'rm', '-f', container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=30, check=False)
    print('TOOLS_BATCH_PASS: 3 native current pairs, 3 changed-version fixtures, package lifecycle')
    return 0


if __name__ == '__main__':
    sys.exit(main())
