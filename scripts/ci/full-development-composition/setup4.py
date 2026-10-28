#!/usr/bin/env python3
"""Installed setup3→4→3 trial inside the existing disposable composition."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time

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
KEYRING_HOME = Path('/etc/pacman.d/gnupg')
KEYRING_SOCKETS = ('S.gpg-agent', 'S.gpg-agent.browser', 'S.gpg-agent.extra', 'S.gpg-agent.ssh')
KEYRING_FILES = ('pubring.kbx', 'pubring.gpg', 'trustdb.gpg', 'tofu.db', 'gpg.conf',
                 'gpg-agent.conf', 'common.conf', 'public-keys.d/pubring.db')


def inventory_sha(rows):
    return hashlib.sha256(''.join(k + ' ' + v + '\n' for k, v in sorted(rows.items())).encode()).hexdigest()


def _measurement_roots(measurement, composition):
    root = Path('/measurement-source')
    for name, digest in measurement.SOURCES.items():
        path = root / name
        composition.need(path.is_file() and not path.is_symlink() and path.stat().st_size <= 512 * 1024,
                         'ordinary bounded measurement source required')
        composition.pin(path, digest, path.stat().st_size)
    spec = importlib.util.spec_from_file_location('setup4_keyring_roots', root / 'scripts/update/full_root.py')
    roots = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = roots
    spec.loader.exec_module(roots)
    return roots


def _keyring_guard(roots, limits):
    for path in (Path('/'), Path('/etc'), Path('/etc/pacman.d'), KEYRING_HOME):
        limits.tick()
        info = path.lstat()
        roots.need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                   'unsafe system keyring directory')
    descriptors = []
    failure = None
    try:
        root = roots._open_root(Path('/')); descriptors.append(root)
        home = roots._open_root(KEYRING_HOME); descriptors.append(home)
        mount = roots._mount_id(home, limits)
        roots.need(os.fstat(root).st_dev == os.fstat(home).st_dev
                   and roots._mount_id(root, limits) == mount,
                   'system keyring must belong to disposable root mount')
        for name in KEYRING_SOCKETS:
            limits.tick()
            try:
                endpoint = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=home)
            except FileNotFoundError:
                continue
            descriptors.append(endpoint)
            info = os.fstat(endpoint)
            roots.need(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0
                       and info.st_dev == os.fstat(home).st_dev
                       and roots._mount_id(endpoint, limits) == mount,
                       'system keyring endpoint must belong to disposable root mount')
    except BaseException as error:
        failure = error
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError as error:
                if failure is None: failure = error
                else: failure.add_note('system keyring descriptor cleanup failed')
    if failure is not None: raise failure


def _agent_sockets():
    present = []
    for name in KEYRING_SOCKETS:
        try:
            info = (KEYRING_HOME / name).lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
            raise ValueError('unsafe system keyring agent endpoint')
        present.append(name)
    return tuple(present)


def _persistent_state(roots, measurement, limits):
    files = {}
    paths = [str(KEYRING_HOME / name) for name in KEYRING_FILES]
    paths.extend(('/etc/pacman.conf', '/etc/pacman.d/cachy-asahi.conf'))
    for path in paths:
        try:
            row = roots.node(Path('/'), path.lstrip('/'), limits=limits)
        except FileNotFoundError:
            row = None
        roots.need((row is not None or path != '/etc/pacman.conf')
                   and (row is None or row['type'] == 'file'), 'ordinary persistent keyring/config file required')
        files[path] = row
    return {'files': files, 'database': measurement.database(roots)}


def _bounded_keyring(core, argv):
    row = core.bounded_process(argv, timeout=15, stdout_limit=65536, stderr_limit=65536,
        env={'PATH': '/usr/bin:/bin', 'HOME': '/root', 'LC_ALL': 'C', 'LANG': 'C'})
    if row['reason'] != 'exit' or row['returncode'] != 0 or row.get('cleanup', {}).get('errors'):
        raise ValueError('bounded system keyring command failed')
    return row['stdout']


def _keyring_fingerprints(core, fingerprint):
    raw = _bounded_keyring(core, ['/usr/bin/gpg', '--no-options', '--batch', '--no-autostart',
        '--homedir', str(KEYRING_HOME), '--no-auto-key-retrieve', '--no-auto-check-trustdb',
        '--lock-never', '--with-colons', '--fingerprint', '--list-keys', fingerprint])
    fingerprints = tuple(sorted(line.split(b':')[9].decode('ascii') for line in raw.splitlines()
        if line.startswith(b'fpr:') and len(line.split(b':')) > 9))
    if fingerprint not in fingerprints:
        raise ValueError('original ALARM fingerprint missing')
    return fingerprints


def _quiesce_system_keyring(plan, expected, composition, core, measurement):
    """Stop only this disposable system home's agent before measurement baselines."""
    composition.guard()
    composition.need(plan['footprint'] == {'limits': measurement.LIMITS, 'sources': measurement.SOURCES}
        and plan['setup4']['expected_inventory_sha256'] == measurement.EXPECTED
        and len(expected) == 587 and expected.get(NAME) == '0.1.0-4'
        and expected.get('cachy-asahi-update') == '4.4.2-2'
        and inventory_sha(expected) == measurement.EXPECTED, 'fixed keyring quiescence selection differs')
    fingerprint = plan['signer_fingerprint']
    composition.need(re.fullmatch('[0-9A-F]{40}', fingerprint), 'exact ALARM fingerprint required')
    roots = _measurement_roots(measurement, composition)
    limits = roots.Limits(deadline=time.monotonic() + 120, max_nodes=20000,
                          max_bytes=256 * 1024**2, max_file_bytes=32 * 1024**2)
    _keyring_guard(roots, limits)
    composition.need(composition.inventory() == expected, 'keyring initial inventory differs')
    before = _persistent_state(roots, measurement, limits)
    fingerprints = _keyring_fingerprints(core, fingerprint)
    present = _agent_sockets()
    if present:
        _bounded_keyring(core, ['/usr/bin/gpgconf', '--homedir', str(KEYRING_HOME), '--kill', 'gpg-agent'])
    composition.need(not _agent_sockets(), 'system keyring agent endpoints remain')
    composition.need(_keyring_fingerprints(core, fingerprint) == fingerprints, 'ALARM fingerprints changed')
    composition.need(composition.inventory() == expected, 'keyring final inventory differs')
    composition.need(_persistent_state(roots, measurement, limits) == before, 'persistent keyring/config/database changed')
    composition.need(not _agent_sockets(), 'system keyring agent endpoints reappeared')
    _keyring_guard(roots, limits)
    return {'status': 'PASS-absence-verified', 'action': 'TARGETED_STOP' if present else 'NOT_NEEDED',
            'initial_endpoints': len(present), 'absent_endpoints': 4,
            'persistent_keyring_config_preserved': True, 'package_database_inventory_preserved': True}


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
        footprint = None
        if 'footprint' in plan:
            measurement = composition.load('composition_footprint', Path('/footprint.py'))
            phase = 'owned-system-keyring-agent-quiescence'
            quiescence = _quiesce_system_keyring(plan, expected, composition, core, measurement)
            phase = 'installed-setup4-scoped-copy-measurement'
            footprint = measurement.collect(plan, expected, source, composition)
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
                **({'footprint': footprint, 'keyring_quiescence': quiescence} if footprint is not None else {}),
                'installed_versions': ['0.1.0-3', '0.1.0-4'], 'removed_package_count': 586,
                'final_package_count': len(checkpoint), 'final_inventory_sha256': inventory_sha(checkpoint),
                'scriptlets': 'DISABLED', 'hooks': 'MASKED', 'automatic_enrollment': False, 'production': 'NOT RUN',
                'hardware': 'NOT RUN', 'target_installation': 'NOT RUN', 'full_transaction': 'NOT RUN'}
    except Exception as error:
        raise RuntimeError('setup4 composition failed at ' + phase + ': ' + str(error)) from error
