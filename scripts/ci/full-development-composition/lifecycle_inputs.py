#!/usr/bin/env python3
"""Prepare four explicit DEVELOPMENT upgrades and the original signed FDK."""
import json
from pathlib import Path
import re
import shutil
import sys

RECIPES = 'a5fb287b4dda2a90bf61d4fa8cbbc5d666dad8bb450a70544d00545b091f36e3'
GENERATOR = 'c1a634b0d0c8d900d8809241c55ab12c09a03c3eb07ba20a6fc545cb2472252a'
CORE = 'c3223a1bd4002683071f4442e1f5b9caf439c68c4e231da10039cc9cebcdb52b'
PROVIDER = 'b10bc7037d2994538fa5bd853a2b98cd549a55b6d30c8b84354a369f67980672'
DESKTOP = 'b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9'
ORIGINALS = {'cachy-asahi-' + name for name in
             ('hyprland-settings', 'fish-config', 'zsh-config', 'setup')}


def copy_pinned(row, directory, target, api):
    """Preserve the archive's existing official signature, checking both bytes."""
    assert re.fullmatch(r'[A-Za-z0-9+_.:@-]+\.pkg\.tar\.(?:xz|zst|gz)', row['filename'])
    for suffix, prefix in (('', ''), ('.sig', 'signature_')):
        old = directory / (row['filename'] + suffix)
        assert old.is_file() and not old.is_symlink()
        assert old.stat().st_size == row[prefix + 'size'] and api.sha(old) == row[prefix + 'sha256']
        new = target / old.name
        assert not new.exists() and not new.is_symlink()
        shutil.copyfile(old, new)
        assert api.sha(new) == row[prefix + 'sha256']


def generate(args, raw, api):
    lock = args.product / 'scripts/ci/recipes.lock.json'
    generator = args.product / 'scripts/integration/fixtures.py'
    assert api.sha(lock) == RECIPES and api.sha(generator) == GENERATOR
    fixtures = api.module('composition_upgrade_fixtures', generator)
    output = raw / 'lifecycle-fixtures'
    record = fixtures.generate(args.product, lock, output, RECIPES,
                               api.SOURCES['product'], version='0.1.1', epoch=1791748800)
    assert record['development_only'] is True and record['selected_for_release'] is False
    assert set(record['packages']) == ORIGINALS
    return output, record


def prepare(args, raw, inputs, image, checks, build, api):
    """Use existing generator/build/check APIs; no alternative package builder."""
    runtime_inputs = args.desktop / 'scripts/ci/maintained-desktop574-inputs.json'
    assert api.sha(runtime_inputs) == DESKTOP
    rows = json.loads(runtime_inputs.read_text())['packages']
    upstream, = [row for row in rows if row['name'] == 'libfdk-aac']
    assert upstream['version'] == '3.0.0-1'
    copy_pinned(upstream, raw / 'desktop574/context/deps', inputs, api)
    helpers = {}
    for name, path, pin in (
        ('core-lifecycle.py', args.product / 'scripts/integration/lifecycle.py', CORE),
        ('provider-helpers.py', Path(__file__).resolve().parent.parent / 'fdk-provider-trial/container.py', PROVIDER),
    ):
        assert api.sha(path) == pin
        shutil.copyfile(path, inputs / name)
        helpers[name] = {'sha256': pin, 'size': (inputs / name).stat().st_size}
    tree, fixture = generate(args, raw, api)
    upgrades, archives = [], []
    for name, record in sorted(fixture['packages'].items()):
        recipe = tree / record['upgrade_recipe']
        inspected = checks.recipe(recipe / 'PKGBUILD')
        assert not inspected['errors'] and inspected['input_sha256'] == record['fixture_inputs_sha256']
        output = raw / (name + '-lifecycle-upgrade')
        api.command([sys.executable, '-B', args.product / 'scripts/build/build.py', recipe,
            '--image', image, '--output', output, '--mode', 'native', '--network', 'none',
            '--timeout', '120', '--source-date-epoch', '1791748800',
            '--expected-packages', args.native / 'packages.lock',
            '--reviewed-inputs', tree / record['reviewed_inputs']['upgrade']],
            raw / (name + '-lifecycle-upgrade.log'), 180)
        archive, digest = api.standard(output, record['fixture_recipe_sha256'], image)
        report = checks.package(archive)
        assert not report['errors'] and report['sha256'] == digest
        assert not build.bind_artifact(inspected['metadata'], report, record['fixture_recipe_sha256'])
        assert report['metadata']['.PKGINFO']['pkgver'] == [record['upgrade_version']]
        assert '.INSTALL' not in report['members']
        target = inputs / archive.name
        assert not target.exists() and not target.is_symlink()
        shutil.copyfile(archive, target)
        assert api.sha(target) == digest
        metadata = report['metadata']['.PKGINFO']
        upgrades.append({'name': name, 'version': record['upgrade_version'],
            'filename': target.name, 'sha256': digest, 'size': target.stat().st_size,
            'payload': api.payload(report), 'depends': metadata.get('depend', []),
            'provides': metadata.get('provides', []), 'conflicts': metadata.get('conflict', [])})
        archives.append(target)
    api.save(raw / 'lifecycle-fixture-summary.json', {
        'development_only': True, 'selected_for_release': False, 'version': '0.1.1-1',
        'generator_sha256': GENERATOR, 'recipes_sha256': RECIPES,
        'packages': {row['name']: {'version': row['version'], 'sha256': row['sha256']} for row in upgrades},
        'source_migration': 'NOT RUN; comment/identity-only controlled development fixtures'})
    return {'upstream': upstream, 'upgrades': upgrades, 'helpers': helpers}, archives
