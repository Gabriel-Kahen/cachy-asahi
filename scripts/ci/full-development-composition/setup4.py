#!/usr/bin/env python3
"""Installed setup3→4→3 trial inside the existing disposable composition."""
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

NAME = 'cachy-asahi-setup'
CLI = '/usr/bin/cachy-asahi-repository'
PACKAGE_SHA = 'c817c01aad875fcf5a34073d4c9d0e830c577301189148b3c0e0969f001bea1a'
PATHS = {'/usr/bin/cachy-asahi-setup', CLI,
         '/usr/share/doc/' + NAME + '/README.md',
         '/usr/share/doc/' + NAME + '/repository-enrollment.md',
         '/usr/share/licenses/' + NAME + '/NOTICE', '/usr/share/licenses/' + NAME + '/LICENSE'}
NEW_PATHS = {CLI, '/usr/share/doc/' + NAME + '/repository-enrollment.md'}
BLOCK = (b'\n# BEGIN cachy-asahi repository enrollment v1\nInclude = /etc/pacman.d/cachy-asahi.conf\n'
         b'# END cachy-asahi repository enrollment v1\n')


def inventory_sha(rows):
    return hashlib.sha256(''.join(k + ' ' + v + '\n' for k, v in sorted(rows.items())).encode()).hexdigest()


def inputs(plan, checkpoint, source, composition):
    row = plan['setup4']['package']
    lock = (source / 'expected-setup4.lock').read_bytes()
    expected = composition.lock(lock.decode('ascii'))
    composition.need(len(checkpoint) == len(expected) == 587 and checkpoint.get(NAME) == '0.1.0-3'
                     and expected == checkpoint | {NAME: '0.1.0-4'} and
                     hashlib.sha256(lock).hexdigest() == plan['setup4']['expected_inventory_sha256'],
                     'setup4 expected inventory differs from checkpoint')
    composition.need(row['name'] == NAME and row['version'] == '0.1.0-4'
                     and row['sha256'] == PACKAGE_SHA and row['size'] == 22632
                     and re.fullmatch(r'[A-Za-z0-9+_.:@-]+\.pkg\.tar\.(?:xz|zst|gz)', row['filename']),
                     'exact retained setup4 package required')
    composition.pin(source / row['filename'], row['sha256'], row['size'])
    composition.pin(source / (row['filename'] + '.sig'), row['signature_sha256'], row['signature_size'])
    composition.need(len(row['payload']) == 6 and {p['path'] for p in row['payload']} == PATHS
                     and all(p['type'] == 'file' for p in row['payload']), 'exact six-file setup4 payload required')
    hashes = {p['path']: p['sha256'] for p in row['payload']}
    composition.need(hashes['/usr/bin/cachy-asahi-setup'] ==
                     '3e652bff75f6202cd3c13c327e50a298f7b25149b3c5cb55cdf4912d35af5919'
                     and hashes[CLI] == '38db2d45955b569a4c74c3f31d6b6c79611126238e1bbe1e5cf819f81d0fb54f',
                     'installed command identity differs')
    fields = composition.archive_metadata(row, source)
    composition.need(sorted(row['depends']) == ['gnupg', 'pacman', 'python>=3.11']
                     and not row['provides'] and not row['conflicts'], 'setup4 dependency/provider policy differs')
    for supplied, actual in (('depends', 'depend'), ('provides', 'provides'), ('conflicts', 'conflict')):
        composition.need(sorted(row[supplied]) == sorted(fields.get(actual, [])), 'setup4 actual metadata differs')
    listing = composition.run(['bsdtar', '-tf', str(source / row['filename'])]).splitlines()
    composition.need(not any(p.removeprefix('./') == '.INSTALL' or p.endswith('.hook') for p in listing),
                     'unexpected install script or hook')
    paths = composition.run(['pacman', '-Qqlp', str(source / row['filename'])]).splitlines()
    composition.need({p for p in paths if not p.endswith('/')} == PATHS, 'actual setup4 file list differs')
    return row, expected


def repository_trial(plan, source, work, composition, main, include):
    """Use the installed CLI against its real root; path arguments permit inert tests."""
    original = main.read_bytes()
    composition.need(not include.exists() and not include.is_symlink()
                     and b'cachy-asahi repository enrollment' not in original, 'repository must initially be disabled')
    # The installed CLI requires every certificate ancestor to be root-owned and non-writable.
    with tempfile.TemporaryDirectory(dir='/root', prefix='setup4-TEST-') as temporary:
        public = Path(temporary) / 'TEST-public.asc'
        public.write_bytes((source / 'TEST-public.asc').read_bytes()); public.chmod(0o644)
        os.chown(public, 0, 0)
        fingerprint = plan['test_signer_fingerprint']
        composition.need(re.fullmatch('[0-9A-F]{40}', fingerprint), 'exact TEST fingerprint required')
        gpg = ['gpg', '--no-options', '--batch', '--no-autostart', '--homedir', '/etc/pacman.d/gnupg',
               '--no-auto-key-retrieve', '--no-auto-check-trustdb', '--lock-never', '--with-colons', '--fingerprint', '--list-keys']
        def retained():
            rows = composition.run(gpg + [plan['signer_fingerprint']]).splitlines()
            composition.need(any(line.startswith('fpr:') and line.split(':')[9] == plan['signer_fingerprint'] for line in rows),
                             'original ALARM fingerprint missing')
        retained()
        url = 'https://repository.test.invalid/generations/' + 'a' * 64 + '/release/repo'
        args = ['enroll', '--snapshot-url', url, '--public-key', str(public), '--fingerprint', fingerprint]
        preview = json.loads(composition.run([CLI, *args]))
        composition.need(preview['status'] == 'preview' and main.read_bytes() == original and not include.exists(),
                         'installed enrollment preview changed configuration')
        enrolled = json.loads(composition.run([CLI, '--apply', *args]))
        composition.need(enrolled['status'] == 'enabled' and main.read_bytes() == original + BLOCK
                         and include.is_file() and include.read_text() == enrolled['managed_include'],
                         'explicit installed enrollment differs')
        enabled_main, enabled_include = main.read_bytes(), include.read_bytes()
        effective = composition.run(['pacman-conf', '--repo', 'cachy-asahi', 'SigLevel', 'Server'])
        composition.need(all(s in effective for s in ('PackageRequired', 'DatabaseRequired', 'PackageTrustedOnly',
                                                      'DatabaseTrustedOnly', url)) and 'Optional' not in effective,
                         'effective repository signature policy differs')
        repeated = json.loads(composition.run([CLI, '--apply', *args]))
        composition.need(repeated['status'] == 'enabled' and not repeated['config_changed']
                         and main.read_bytes() == enabled_main and include.read_bytes() == enabled_include,
                         'repeated enrollment changed configuration')
        for attempt in range(2):
            disabled = json.loads(composition.run([CLI, '--apply', 'disable']))
            composition.need(disabled['status'] == 'disabled' and main.read_bytes() == original and not include.exists()
                             and (attempt == 0 or not disabled['config_changed']), 'disable was not idempotent')
            retained()
            listed = composition.run(gpg + [fingerprint]).splitlines()
            composition.need(any(line.startswith(('pub:f:', 'pub:u:')) for line in listed)
                             and any(line.startswith('fpr:') and line.split(':')[9] == fingerprint for line in listed),
                             'disable unexpectedly removed TEST public trust')
        return {'status': 'PASS-disposable-TEST-only', 'preview': 'PASS', 'repeat': 'PASS', 'disable_twice': 'PASS',
                'original_pacman_conf': 'PASS-bytes-preserved', 'alarm_fingerprint': 'PRESERVED',
                'public_trust_after_disable': 'INTENTIONALLY RETAINED', 'network': 'NOT USED'}


def run(pacman, plan, checkpoint, source, work, composition, core, payload_helper):
    phase = 'checkpoint'
    composition.guard()
    try:
        composition.need(composition.inventory() == checkpoint, 'setup4 requires exact checkpoint587')
        row, expected = inputs(plan, checkpoint, source, composition)
        main, include = Path('/etc/pacman.conf'), Path('/etc/pacman.d/cachy-asahi.conf')
        original_main = main.read_bytes()
        composition.need(not include.exists() and not include.is_symlink(), 'initial repository include exists')
        originals = plan['projects']
        projects = [row if p['name'] == NAME else p for p in originals]
        work.chmod(0o755)
        phase = 'signed-setup4-upgrade'
        composition.run(pacman + ['--noconfirm', '--noscriptlet', '-U', str(source / row['filename'])])
        def installed(wanted, payload):
            composition.need(composition.inventory() == wanted, 'setup4 stage exact inventory differs')
            composition.run(pacman + ['-Dk'])
            dependencies = sorted({d for p in payload for d in p['depends']})
            composition.run(pacman + ['-T', *dependencies])
            payload_helper.payloads(pacman, payload, composition)
        installed(expected, projects)
        composition.run(['/usr/bin/cachy-asahi-setup', '--help'])
        composition.run([CLI, '--help'])
        composition.need(main.read_bytes() == original_main and not include.exists(), 'upgrade automatically changed enrollment')
        phase = 'installed-per-user-setup'
        fixture_work = work / 'setup4-fixtures'; fixture_work.mkdir(mode=0o755)
        adapter, (fresh, existing) = payload_helper.fixtures(fixture_work, composition, core)
        components = ('fish', 'zsh', 'hyprland')
        before = adapter.snapshot(fresh)
        adapter.helper(fresh, 'activate', components, apply=False)
        adapter.check('setup4-preview-readonly', adapter.snapshot(fresh) == before)
        adapter.helper(fresh, 'activate', components)
        before = adapter.snapshot(fresh)
        adapter.helper(fresh, 'activate', components)
        adapter.check('setup4-repeat-idempotent', adapter.snapshot(fresh) == before)
        adapter.fixture(existing, '.zshrc', b'# existing user zsh\n')
        adapter.helper(existing, 'activate', components)
        desktop = adapter.paths(existing)['hyprland']
        desktop.write_bytes(desktop.read_bytes() + b'\n-- retained user edit\n')
        edited = desktop.read_bytes()
        adapter.helper(existing, 'activate', components, allowed=(2,))
        adapter.check('setup4-edited-copy-preserved', desktop.read_bytes() == edited)
        adapter.check('setup4-existing-prefix-preserved', adapter.paths(existing)['zsh'].read_bytes().startswith(b'# existing user zsh\n'))
        phase = 'installed-repository-enrollment'
        enrollment = repository_trial(plan, source, work, composition, main, include)
        homes = [adapter.snapshot(u) for u in (fresh, existing)]
        phase = 'normal-setup4-removal'
        composition.run(pacman + ['--noconfirm', '--noscriptlet', '-R', NAME])
        removed = {k: v for k, v in expected.items() if k != NAME}
        installed(removed, [p for p in projects if p['name'] != NAME])
        composition.need(len(removed) == 586 and all(not Path(p).exists() and not Path(p).is_symlink() for p in PATHS),
                         'removed setup4 payload remains')
        adapter.check('setup4-removal-preserves-user-files', homes == [adapter.snapshot(u) for u in (fresh, existing)])
        phase = 'setup4-reinstallation'
        composition.run(pacman + ['--noconfirm', '--noscriptlet', '-U', str(source / row['filename'])])
        installed(expected, projects)
        adapter.check('setup4-reinstall-preserves-user-files', homes == [adapter.snapshot(u) for u in (fresh, existing)])
        phase = 'setup3-checkpoint-restoration'
        old = next(p for p in plan['packages'] if p['name'] == NAME)
        composition.pin(source / old['filename'], old['sha256'], old['size'])
        composition.pin(source / (old['filename'] + '.sig'), old['signature_sha256'], old['signature_size'])
        composition.archive_metadata(old, source)
        composition.run(pacman + ['--noconfirm', '--noscriptlet', '-U', str(source / old['filename'])])
        installed(checkpoint, originals)
        composition.need(all(not Path(p).exists() and not Path(p).is_symlink() for p in NEW_PATHS),
                         'setup4-only command or documentation remains')
        composition.need(main.read_bytes() == original_main and not include.exists(), 'final disabled configuration changed')
        adapter.check('setup3-restoration-preserves-user-files', homes == [adapter.snapshot(u) for u in (fresh, existing)])
        return {'status': 'PASS', 'checks': adapter.checks, 'repository_enrollment': enrollment,
                'installed_versions': ['0.1.0-3', '0.1.0-4'], 'removed_package_count': 586,
                'final_package_count': len(checkpoint), 'final_inventory_sha256': inventory_sha(checkpoint),
                'scriptlets': 'DISABLED', 'hooks': 'MASKED', 'automatic_enrollment': False, 'production': 'NOT RUN',
                'hardware': 'NOT RUN', 'target_installation': 'NOT RUN', 'full_transaction': 'NOT RUN'}
    except Exception as error:
        raise RuntimeError('setup4 composition failed at ' + phase + ': ' + str(error)) from error
