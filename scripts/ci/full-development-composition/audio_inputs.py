#!/usr/bin/env python3
"""Reuse six exact retained audio archives; no fetch, compilation or installation."""
import json
import os
from pathlib import Path
import shutil

HERE = Path(__file__).resolve().parent
POLICY = '01f8f2cdefddbb5bb86748817935777186a64ec18371922d2c7a14ec2a116f5a'
EXPECTED = 'ff70e71ad067cb3cf261645b15173be315f02a3e91cd35e6bea5732125cce564'
NAMES = {'asahi-audio', 'alsa-ucm-conf-asahi', 'speakersafetyd', 'bankstown', 'triforce-lv2', 'lsp-plugins-lv2'}


def inspect(row, report, api):
    """An exact archive pin and closed generic-error set; no generic guard changes."""
    assert report['sha256'] == row['sha256'], 'retained archive bytes differ'
    assert report['metadata']['.PKGINFO'] == row['metadata'], 'actual audio metadata differs'
    assert sorted(report['errors']) == row['generic_errors'], 'unexpected generic audio error'
    assert sorted(api.payload(report), key=lambda r: r['path']) == row['payload'], 'audio payload differs'
    assert sorted(report['elf']) == row['elf_paths'] and not any(r['errors'] for r in report['elf'].values()), 'audio ELF checks differ'
    assert sorted(p for p, r in report['members'].items() if r['type'] == '5') == row['directories'], 'audio directories differ'
    allowed = {p['path'].removeprefix('/') for p in row['payload']} | set(row['directories']) | {'.PKGINFO', '.BUILDINFO', '.MTREE'}
    assert set(report['members']) == allowed, 'unexpected archive member'
    for name, member in report['members'].items():
        assert member['type'] in ('0', '5') and member['uid'] == member['gid'] == 0, 'ordinary root-owned audio payload required'
        assert name != '.INSTALL' and not name.endswith('.hook'), 'audio hooks/scriptlets refused'
        if member['type'] == '5': assert member['mode'] == 0o755, 'audio directory mode differs'
    pkg = report['metadata']['.PKGINFO']
    assert not any(pkg.get(k) for k in ('conflict', 'replaces', 'backup')), 'audio replacement/config mutation refused'
    return dict(row, depends=pkg.get('depend', []), provides=pkg.get('provides', []), conflicts=[])


def prepare(args, raw, inputs, checks, api):
    source = args.audio_inputs
    assert source.is_absolute() and '..' not in source.parts and all(not p.is_symlink() for p in (source, *source.parents)), 'ordinary absolute audio input directory required'
    assert source.is_dir() and source.stat().st_uid == os.getuid() and not source.stat().st_mode & 0o022, 'owned audio input directory required'
    assert api.sha(HERE / 'audio-inputs.json') == POLICY, 'audio policy differs'
    policy = json.loads((HERE / 'audio-inputs.json').read_text())
    assert len(policy) == 6 and {r['name'] for r in policy} == NAMES, 'exact six audio additions required'
    names = {r['filename'] for r in policy} | {r['filename'] + '.sig' for r in policy if r['origin'] == 'ALARM'}
    assert {p.name for p in source.iterdir()} == names, 'exact six archives and official LSP signature required'
    rows, sign = [], []
    for row in policy:
        path = source / row['filename']
        assert path.is_file() and not path.is_symlink() and path.stat().st_size == row['size'] and api.sha(path) == row['sha256'], 'retained audio archive pin differs'
        inspected = inspect(row, checks.package(path), api)
        target = inputs / path.name
        assert not target.exists() and not target.is_symlink(), 'audio output collision'
        shutil.copyfile(path, target)
        assert api.sha(target) == row['sha256'], 'copied audio archive differs'
        if row['origin'] == 'ALARM':
            assert row['name'] == 'lsp-plugins-lv2'
            sig = source / (path.name + '.sig')
            assert sig.is_file() and not sig.is_symlink() and sig.stat().st_size == row['signature_size'] and api.sha(sig) == row['signature_sha256'], 'official LSP signature pin differs'
            shutil.copyfile(sig, inputs / sig.name)
        else:
            assert row['origin'] == 'TEST-signed-native-output'
            sign.append(target)
        rows.append(inspected)
    assert len(sign) == 5
    assert api.sha(HERE / 'expected-installed.lock') == api.FINAL and api.sha(HERE / 'expected-audio.lock') == EXPECTED
    before = dict(line.split() for line in (HERE / 'expected-installed.lock').read_text().splitlines())
    after = dict(line.split() for line in (HERE / 'expected-audio.lock').read_text().splitlines())
    assert len(before) == 587 and not set(before) & NAMES and len(after) == 593 and after == before | {r['name']: r['version'] for r in rows}, 'only six additions permitted'
    shutil.copyfile(HERE / 'expected-audio.lock', inputs / 'expected-audio.lock')
    api.save(raw / 'audio-summary.json', {'policy_sha256': POLICY, 'expected593_sha256': EXPECTED,
        'archives': {r['name']: r['sha256'] for r in rows}, 'new_builds': 'NOT RUN', 'transaction': 'NOT RUN',
        'services': 'NOT RUN', 'audio': 'NOT RUN', 'hardware': 'NOT RUN', 'release': 'NOT ACCEPTED'})
    return {'packages': rows, 'expected_inventory_sha256': EXPECTED}, sign
