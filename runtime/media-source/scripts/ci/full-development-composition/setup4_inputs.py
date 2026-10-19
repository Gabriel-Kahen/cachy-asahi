#!/usr/bin/env python3
"""Reuse the retained Source98 setup4 native pair in the existing composition."""
import json
from pathlib import Path
import shutil

HERE = Path(__file__).resolve().parent
SOURCE = '98fecf28a3cde63a9dd7531501c2187825349310'
RECIPE = 'ec816728a154f77723d34e56bcbf04bb39ef436be1d883fb90c1af8d43dae31e'
IMAGE = 'sha256:173e4b8f57026f63ad53d6670be7a31fb35d8c6e9082d03f737c5d4502e50178'
PACKAGE = 'c817c01aad875fcf5a34073d4c9d0e830c577301189148b3c0e0969f001bea1a'
SOURCE_MAP = 'b4d2e8294cf9cbe0587aecc3a82cd2fd8524c5ade69c686c5c7aebc35ac5c9d1'
EXPECTED = {False: '7285387a74ea3988059a22de8196c6d50c965a2697c7d6621f363c7e543d13de',
            True: 'dbfe042f77bf61ce8e15a63c53391bcc4f04b94f18e99eeffdfdf85e68aa26ac'}
NAME = 'cachy-asahi-setup'


def expected_lock(checkpoint, target):
    rows = [[line.split() for line in data.decode('ascii').splitlines()] for data in (checkpoint, target)]
    assert all(all(len(r) == 2 for r in group) for group in rows)
    before, after = [dict(group) for group in rows]
    assert all(len(group) == 587 for group in rows) and len(before) == len(after) == 587
    assert before[NAME] == '0.1.0-3' and after == before | {NAME: '0.1.0-4'}, 'setup4 changes more than setup release'
    return after


def retained_pair(pair, checks, build, api):
    pins = HERE / 'setup4-source-inputs.json'
    assert api.sha(pins) == SOURCE_MAP
    pins = json.loads(pins.read_text())
    assert len(pins) == 29 and pins['PKGBUILD'] == RECIPE
    packages = []
    for attempt in (1, 2):
        directory = pair / f'build-{attempt}'
        record = json.loads((directory / 'provenance.json').read_text())
        assert record['recipe_inputs'] == pins
        for name, digest in pins.items():
            path = directory / 'inputs' / name
            assert path.is_file() and not path.is_symlink() and api.sha(path) == digest, 'retained source differs: ' + name
        assert api.sha(directory / 'expected-packages.lock') == api.BASE
        archive, digest = api.standard(directory, RECIPE, IMAGE)
        assert digest == PACKAGE and archive.stat().st_size == 22632
        report = checks.package(archive)
        assert not report['errors'] and report['sha256'] == digest
        metadata = checks.metadata((directory / 'inputs/.SRCINFO').read_text())
        assert not build.bind_artifact(metadata, report, RECIPE)
        pkg = report['metadata']['.PKGINFO']
        assert pkg['pkgname'] == [NAME] and pkg['pkgver'] == ['0.1.0-4'] and pkg['license'] == ['MIT']
        assert sorted(pkg.get('depend', [])) == ['gnupg', 'pacman', 'python>=3.11']
        assert not pkg.get('provides') and not pkg.get('conflict')
        payload = api.payload(report)
        wanted = {'/usr/bin/' + name: (pins[name], 0o755) for name in ('cachy-asahi-setup', 'cachy-asahi-repository')}
        wanted.update({'/usr/share/doc/' + NAME + '/' + name: (pins[name], 0o644)
                       for name in ('README.md', 'repository-enrollment.md')})
        wanted.update({'/usr/share/licenses/' + NAME + '/' + name: (pins[name], 0o644)
                       for name in ('NOTICE', 'LICENSE')})
        assert len(payload) == 6 and {p['path'] for p in payload} == set(wanted), 'exact six setup4 files required'
        for item in payload:
            assert item['type'] == 'file' and (item['sha256'], item['mode']) == wanted[item['path']]
        packages.append((archive, report, payload))
    return packages[0]


def prepare(args, raw, inputs, checks, build, api):
    archive, report, payload = retained_pair(args.setup4_pair, checks, build, api)
    target = inputs / archive.name
    assert not target.exists() and not target.is_symlink()
    shutil.copyfile(archive, target)
    assert api.sha(target) == PACKAGE
    v2 = bool(args.updater_v2_source)
    checkpoint = HERE / ('expected-updater-v2.lock' if v2 else 'expected-installed.lock')
    expected = HERE / ('expected-setup4-v2.lock' if v2 else 'expected-setup4-v1.lock')
    assert api.sha(expected) == EXPECTED[v2]
    expected_lock(checkpoint.read_bytes(), expected.read_bytes())
    shutil.copyfile(expected, inputs / 'expected-setup4.lock')
    helper_api = api.module('setup4_existing_helpers', HERE / 'lifecycle_inputs.py')
    helpers = {}
    for name, path, digest in (
        ('core-lifecycle.py', args.product / 'scripts/integration/lifecycle.py', helper_api.CORE),
        ('provider-helpers.py', HERE.parent / 'fdk-provider-trial/container.py', helper_api.PROVIDER),
    ):
        assert api.sha(path) == digest
        shutil.copyfile(path, inputs / name)
        helpers[name] = {'sha256': digest, 'size': (inputs / name).stat().st_size}
    pkg = report['metadata']['.PKGINFO']
    row = {'name': NAME, 'version': '0.1.0-4', 'filename': target.name, 'sha256': PACKAGE,
           'size': target.stat().st_size, 'payload': payload, 'depends': pkg.get('depend', []),
           'provides': pkg.get('provides', []), 'conflicts': pkg.get('conflict', [])}
    api.save(raw / 'setup4-summary.json', {'source': SOURCE, 'package_sha256': PACKAGE,
        'recipe_sha256': RECIPE, 'source_inputs_sha256': SOURCE_MAP, 'retained_native_pair': 'MATCHED',
        'new_native_build': 'NOT RUN', 'composition': 'NOT RUN', 'hardware': 'NOT RUN'})
    return {'package': row, 'expected_inventory_sha256': EXPECTED[v2], 'helpers': helpers}, target
