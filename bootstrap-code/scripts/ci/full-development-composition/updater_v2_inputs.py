#!/usr/bin/env python3
"""Prepare the separately pinned updater successor using the existing pair API."""
import json
from pathlib import Path
import shutil

SOURCE = '480053c0866a922138d85af2b9880fb0e10d7b2c'
MATERIALIZER = '601283adb9deeca949a857ee136896e8d1559ab4ecf6fed3928531059965c6f9'
RECIPE = '251009c63e3a9c2e62cd899b077c70f0f6a418ba38beac00a0323e3bf60dafa0'
PACKAGE = '88e6ebad51700499bc2f0c608409e06983b0146ebf555101b526c7a32d5ba4f6'
EXPECTED = '2198942a546f4714587c810fe174d4457121960f3a7b1dbaa276e9f970f322c7'
HERE = Path(__file__).resolve().parent


def expected_lock(v1, v2):
    before, after = [dict(line.split() for line in data.decode().splitlines()) for data in (v1, v2)]
    assert len(v1.splitlines()) == len(before) == len(v2.splitlines()) == len(after) == 587
    assert before['cachy-asahi-update'] == '4.4.2-1'
    assert after == before | {'cachy-asahi-update': '4.4.2-2'}, 'v2 changes more than updater release'
    return after


def prepare(args, raw, inputs, checks, build, api):
    source = args.updater_v2_source
    package = source / 'packages/tools/cachy-asahi-update'
    assert api.sha(package / 'PKGBUILD') == RECIPE
    assert api.sha(package / 'runner-inputs.lock.json') == MATERIALIZER
    assert api.sha(HERE / 'expected-updater-v2.lock') == EXPECTED
    expected_lock((HERE / 'expected-installed.lock').read_bytes(), (HERE / 'expected-updater-v2.lock').read_bytes())
    branch = raw / 'updater-v2'; branch.mkdir()
    archive, digest = api.updater(source, branch, args.cache, materializer_pin=MATERIALIZER)
    assert digest == PACKAGE, 'fresh v2 pair differs from its exact prior native bytes'
    report = checks.package(archive)
    assert not report['errors'] and report['sha256'] == digest
    metadata = checks.metadata((package / '.SRCINFO').read_text())
    assert not build.bind_artifact(metadata, report, RECIPE)
    pkg = report['metadata']['.PKGINFO']
    assert pkg['pkgname'] == ['cachy-asahi-update'] and pkg['pkgver'] == ['4.4.2-2']
    assert '.INSTALL' not in report['members']
    target = inputs / archive.name
    assert not target.exists() and not target.is_symlink()
    shutil.copyfile(archive, target)
    assert api.sha(target) == digest
    fixture = HERE / 'updater-v2-real-check.py'
    shutil.copyfile(fixture, inputs / fixture.name)
    shutil.copyfile(HERE / 'expected-updater-v2.lock', inputs / 'expected-updater-v2.lock')
    row = {'name': 'cachy-asahi-update', 'version': '4.4.2-2', 'filename': target.name,
           'sha256': digest, 'size': target.stat().st_size, 'payload': api.payload(report),
           'depends': pkg.get('depend', []), 'provides': pkg.get('provides', []),
           'conflicts': pkg.get('conflict', [])}
    api.save(raw / 'updater-v2-summary.json', {'source': SOURCE, 'version': row['version'],
        'package_sha256': digest, 'recipe_sha256': RECIPE, 'expected_inventory_sha256': EXPECTED,
        'native_pair': 'PASS', 'composition_upgrade': 'NOT RUN', 'hardware': 'NOT RUN'})
    return {'package': row, 'expected_inventory_sha256': EXPECTED,
            'check_fixture': {'sha256': api.sha(fixture), 'size': fixture.stat().st_size}}, target
