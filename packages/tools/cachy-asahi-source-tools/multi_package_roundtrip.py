#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare exact fixture DATA, then exercise only an installed source-tools CLI.

Preparation may read the reviewed source checkout. The separate run operation
has no project imports and can run with that checkout hidden by a mount namespace.
Package archives are synthetic; retained recipes are never executed.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

NAMES = ('cachy-asahi-maintenance', 'cachy-asahi-session-diagnostics')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def source_map(root):
    return {path.relative_to(root).as_posix(): digest(path.read_bytes())
            for path in sorted(root.rglob('*')) if path.is_file()}


def prepare(checkout, output):
    output.mkdir(parents=True, mode=0o700)
    path = checkout / 'scripts/release/test_release_source_mirror.py'
    spec = importlib.util.spec_from_file_location('trusted_fixture_constructor', path)
    f = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(f)
    fixtures = []
    for label in ('legacy', 'current'):
        fixture = f.ReleaseFixture(output / label)
        fixture.manifest['release_id'] = fixture.spec['release_id'] = 'source-tools-two-package-' + label
        if label == 'legacy':
            for name, version in zip(NAMES, ('0.1.0-1', '0.1.0-2')):
                path = checkout / 'scripts/release/fixtures/recipe-source-legacy' / (name + '-' + version + '.tar.gz')
                raw = gzip.decompress(path.read_bytes())
                _, bodies = f.recipe.unpacked(raw, digest(raw))
                fixture.bodies[name] = bodies
                package = fixture.package(name)
                package.update(version=version, filename=name + '-' + version + '-any.pkg.tar.gz')
                provenance = fixture.provenance[name]
                provenance['package']['version'] = version
                provenance['recipe_sha256'] = digest(bodies['PKGBUILD'])
                provenance['sources'][0]['sha256'] = digest(bodies['PKGBUILD'])
                fixture.archive_rows[name] = {key: (bodies[src], mode)
                    for key, (src, mode) in f.recipe.payload(name, version).items()}
                fixture.archive_rows[name].update({
                    '.PKGINFO': (f.metadata(dict(pkgname=[name], pkgbase=[name], pkgver=[version], arch=['any'], license=['MIT'])), 0o644),
                    '.BUILDINFO': (f.metadata(dict(format=['2'], pkgname=[name], pkgver=[version], pkgarch=['any'],
                        pkgbuild_sha256sum=[digest(bodies['PKGBUILD'])], installed=['python-3.14-1-aarch64'])), 0o644),
                    '.MTREE': (b'Inert synthetic package archive; no native execution.\n', 0o644)})
                fixture.refresh_archive(name)
                fixture.refresh_source(name)
        fixture.refresh()
        fixtures.append(dict(label=label, release_sha256=fixture.pin, packages=[
            dict(name=name, version=fixture.package(name)['version'], arch=fixture.package(name)['arch'],
                package_sha256=fixture.package(name)['sha256'], recipe_sha256=digest(fixture.bodies[name]['PKGBUILD']),
                srcinfo_sha256=digest(fixture.bodies[name]['.SRCINFO']),
                sources={key: digest(raw) for key, raw in fixture.bodies[name].items()}) for name in NAMES]))
    info = dict(schema_version=1, purpose='source-tools-synthetic-two-package-roundtrip',
                source_execution='FORBIDDEN', native_build='NOT_RUN', fixtures=fixtures)
    (output / 'fixtures.json').write_bytes(encoded(info))
    print(json.dumps(dict(status='PREPARED', fixtures=fixtures, data_map=source_map(output)), sort_keys=True))


def run(cli, fixtures, work, prefix, unavailable_checkout=None):
    if unavailable_checkout is not None:
        assert not unavailable_checkout.exists() or not any(unavailable_checkout.iterdir()), unavailable_checkout
    work.mkdir(parents=True, mode=0o700)
    os.chmod(work, 0o700)
    info = json.loads((fixtures / 'fixtures.json').read_bytes())
    records = []

    def call(arguments, success=True):
        command = prefix + [str(cli)] + [str(arg) for arg in arguments]
        result = subprocess.run(command, cwd=work, env={'PATH': '/usr/bin:/bin', 'HOME': str(work),
            'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONPATH': '/nonexistent'}, capture_output=True, timeout=60)
        try:
            report = json.loads(result.stdout)
        except (ValueError, UnicodeError) as error:
            raise AssertionError((command, result.returncode, result.stdout, result.stderr)) from error
        assert result.returncode == (0 if success else 1), (command, result.returncode, report, result.stderr)
        if not success:
            assert report['status'] == 'REFUSED', report
        records.append(dict(argv=command, returncode=result.returncode, report=report,
                            stderr=result.stderr.decode(errors='replace')))
        return report

    old, current = info['fixtures']
    first = call(['mirror-export', '--release-dir', fixtures / old['label'], '--release-sha256', old['release_sha256'],
                  '--output', work / 'first'])
    assert first['packages'] == 2
    repeat = call(['mirror-export', '--release-dir', fixtures / old['label'], '--release-sha256', old['release_sha256'],
                   '--output', work / 'repeat'])
    assert first['mirror_sha256'] == repeat['mirror_sha256']
    assert (work / 'first/mirror.tar').read_bytes() == (work / 'repeat/mirror.tar').read_bytes()
    successor = call(['mirror-successor', '--previous-bundle', work / 'first/mirror.tar',
        '--previous-sha256', first['mirror_sha256'], '--previous-release-sha256', old['release_sha256'],
        '--release-dir', fixtures / current['label'], '--release-sha256', current['release_sha256'], '--output', work / 'history'])
    assert successor['packages'] == 2
    assert successor['stats']['pruned_objects'] == 0
    assert set(successor['retained_releases']) == {old['release_sha256'], current['release_sha256']}
    mirror = work / 'history/mirror.tar'
    for fixture in (old, current):
        verified = call(['mirror-verify', '--bundle', mirror, '--sha256', successor['mirror_sha256'],
                         '--release-sha256', fixture['release_sha256']])
        assert verified['release_sha256'] == fixture['release_sha256']
        assert set(verified['retained_releases']) == {old['release_sha256'], current['release_sha256']}
        for package in fixture['packages']:
            dest = work / (fixture['label'] + '-' + package['name'])
            receipt = call(['build-context', '--bundle', mirror, '--mirror-sha256', successor['mirror_sha256'],
                '--release-sha256', fixture['release_sha256'], '--package', package['name'], '--version', package['version'],
                '--arch', package['arch'], '--package-sha256', package['package_sha256'],
                '--recipe-sha256', package['recipe_sha256'], '--srcinfo-sha256', package['srcinfo_sha256'], '--output', dest])
            assert source_map(dest / 'recipe') == package['sources'], (fixture['label'], package['name'])
            request = json.loads((dest / 'builder-request.json').read_bytes())
            assert request['actual_selectors'] and all(value is None for value in request['actual_selectors'].values())
            moved = dest.with_name(dest.name + '-moved')
            dest.rename(moved)
            call(['verify-context', '--context', moved, '--selection-sha256', receipt['selection_sha256']])
    tampered = work / 'tampered.tar'
    tampered.write_bytes(mirror.read_bytes() + b'tampered')
    call(['mirror-verify', '--bundle', tampered, '--sha256', successor['mirror_sha256'],
          '--release-sha256', current['release_sha256']], False)
    incomplete = work / 'incomplete.tar'
    with tarfile.open(mirror, 'r:') as source, tarfile.open(incomplete, 'w', format=tarfile.USTAR_FORMAT) as target:
        omitted = False
        for node in source:
            if node.name.startswith('objects/') and not omitted:
                omitted = True
                continue
            target.addfile(node, source.extractfile(node))
    assert omitted
    call(['mirror-verify', '--bundle', incomplete, '--sha256', digest(incomplete.read_bytes()),
          '--release-sha256', current['release_sha256']], False)
    bad_dest = work / 'must-not-exist'
    call(['mirror-successor', '--previous-bundle', incomplete, '--previous-sha256', digest(incomplete.read_bytes()),
          '--previous-release-sha256', current['release_sha256'], '--release-dir', fixtures / current['label'],
          '--release-sha256', current['release_sha256'], '--output', bad_dest], False)
    assert not bad_dest.exists()
    release = work / 'incomplete-release'
    shutil.copytree(fixtures / current['label'], release)
    next((release / 'evidence').glob('*-source.tar')).unlink()
    call(['mirror-export', '--release-dir', release, '--release-sha256', current['release_sha256'],
          '--output', bad_dest], False)
    assert not bad_dest.exists()
    report = dict(status='PASS', controls=len(records), packages_per_release=2, retained_releases=2,
        exact_contexts=4, fixture_data_sha256=digest((fixtures / 'fixtures.json').read_bytes()),
        mirror_sha256=successor['mirror_sha256'], mirror_bytes=mirror.stat().st_size,
        source_execution='NOT_RUN', native_build='NOT_RUN', alpm_installation='NOT_RUN', hardware='NOT_RUN',
        unavailable_checkout=str(unavailable_checkout) if unavailable_checkout is not None else None, commands=records)
    (work / 'results.json').write_bytes(encoded(report))
    print(json.dumps(report, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='mode', required=True)
    create = commands.add_parser('prepare')
    create.add_argument('--checkout', type=Path, required=True)
    create.add_argument('--output', type=Path, required=True)
    check = commands.add_parser('run')
    check.add_argument('--cli', type=Path, required=True)
    check.add_argument('--fixtures', type=Path, required=True)
    check.add_argument('--work', type=Path, required=True)
    check.add_argument('--command-prefix', default='[]', help='JSON argv prefix, e.g. a namespace launcher')
    check.add_argument('--unavailable-checkout', type=Path, help='Assert the original checkout is absent or empty')
    args = parser.parse_args()
    if args.mode == 'prepare':
        prepare(args.checkout.absolute(), args.output.absolute())
    else:
        run(args.cli.absolute(), args.fixtures.absolute(), args.work.absolute(), json.loads(args.command_prefix), args.unavailable_checkout)


if __name__ == '__main__':
    main()
