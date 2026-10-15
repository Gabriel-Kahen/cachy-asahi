#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real installed Check against an inert, signed repository in disposable ARM Docker."""
import hashlib
import io
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import subprocess
import tarfile
import time

NAME = 'cachy-asahi-check-fixture'
PAYLOAD = Path('/usr/share/cachy-asahi-check-fixture/value')
OPTIONS = 'NoAUR\nNoFlatpak\nNoNotification\nNoALHPCheck\nNoColor\n'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def package_data(version):
    need(version in ('0.1.0-1', '0.1.1-1'), 'unsupported fixture version')
    payload = ('inert Check fixture ' + version + '\n').encode()
    info = (f'pkgname = {NAME}\npkgbase = {NAME}\npkgver = {version}\n'
            'pkgdesc = Disposable update-check test data\nurl = https://test.invalid/\n'
            'builddate = 1\npackager = TEST ONLY\narch = any\nlicense = MIT\n'
            f'size = {len(payload)}\n').encode()
    return {'.PKGINFO': info, str(PAYLOAD).lstrip('/'): payload}


def write_package(path, version):
    with tarfile.open(path, 'w:gz', format=tarfile.USTAR_FORMAT) as archive:
        for name, data in package_data(version).items():
            member = tarfile.TarInfo(name)
            member.mode, member.mtime = 0o644, 1
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))


def configuration(repo, trust):
    for path in (repo, trust):
        need(path.is_absolute() and not re.search(r'[\s\[\]#]', str(path)), 'invalid fixture path')
    return ('[options]\nArchitecture = aarch64\nSigLevel = Required\n'
            'LocalFileSigLevel = Required\nHookDir = /builder-disabled-hooks\n'
            f'GPGDir = {trust}\n\n[check-fixture]\nSigLevel = Required\nServer = file://{repo}\n')


def user_command(home, args):
    return ['/usr/bin/runuser', '-u', 'alarm', '--', '/usr/bin/env', '-i',
            'PATH=/usr/bin:/bin', 'LANG=C', 'LC_ALL=C', 'TZ=UTC', 'TERM=dumb',
            'USER=alarm', 'LOGNAME=alarm', f'HOME={home}',
            f'XDG_CONFIG_HOME={home}/config', f'XDG_STATE_HOME={home}/state',
            f'XDG_DATA_HOME={home}/data', f'XDG_RUNTIME_DIR={home}/runtime', *args]


def snapshot(root, *, metadata=False):
    rows = {}
    for path in sorted(root.rglob('*')):
        stat = path.lstat()
        if path.is_symlink():
            value = 'link:' + os.readlink(path)
        elif path.is_file():
            value = hashlib.sha256(path.read_bytes()).hexdigest()
        elif path.is_dir():
            value = 'directory'
        else:
            raise ValueError('unexpected special file')
        rows[str(path.relative_to(root))] = ([value, stat.st_mode, stat.st_mtime_ns]
                                            if metadata else value)
    return rows


def capture(argv, *, data=None, env=None, timeout=45):
    process = subprocess.run(argv, input=data, capture_output=True,
                             timeout=timeout, env=env)
    # The 1,113 installed notice paths alone exceed 64 KiB.
    limit = 1024**2 if argv == ['/usr/bin/pacman', '-Qlq', 'cachy-asahi-update'] else 65536
    need(len(process.stdout) + len(process.stderr) <= limit, 'diagnostic exceeds bound')
    return process


def validate_inventory(data, expected_inventory=None):
    """Require the standalone runtime or an exact composed runtime before fixtures."""
    rows = [line.split(' ') for line in data.decode('ascii').splitlines()]
    need(all(len(row) == 2 and all(row) and all(32 < ord(c) < 127 for c in ''.join(row))
             for row in rows) and len({row[0] for row in rows}) == len(rows),
         'invalid or duplicate installed inventory')
    actual = dict(rows)
    need(NAME not in actual, 'inert fixture already installed')
    if expected_inventory is None:
        need(len(actual) == 360, 'exact fresh standalone runtime required')
    else:
        need(isinstance(expected_inventory, dict) and len(expected_inventory) == 587
             and expected_inventory.get('cachy-asahi-update') == '4.4.2-2'
             and NAME not in expected_inventory and actual == expected_inventory,
             'exact expected composed runtime required')
    return actual


def exercise(work, signing, fingerprint, *, expected_inventory=None):
    """Return bounded status; only the caller's disposable container is mutated."""
    result = {'status': 'FAIL', 'scope': 'disposable-native-software-check',
              'cases': {}, 'real_update_transaction': 'NOT RUN',
              'hardware': 'NOT RUN', 'target_safety': 'NOT ESTABLISHED'}
    original_conf = None
    trust = root = home = None

    def run(argv, *, data=None, env=None, expected=0, timeout=45):
        process = capture(argv, data=data, env=env, timeout=timeout)
        if expected is not None and process.returncode != expected:
            result['failed_command_exit'] = process.returncode
        need(expected is None or process.returncode == expected,
             'unexpected command exit ' + str(process.returncode))
        return process

    try:
        result['phase'] = 'container-guard'
        need(platform.system() == 'Linux' and platform.machine() == 'aarch64'
             and os.getuid() == 0 and Path('/.dockerenv').is_file()
             and re.fullmatch('[0-9a-f]{32}', os.environ.get('CACHY_ASAHI_UPDATER_RUNTIME', '')),
             'explicit disposable native ARM runtime required')
        work, signing = Path(work).resolve(), Path(signing).resolve()
        need(work.is_dir() and work.is_relative_to('/tmp') and signing.is_relative_to(work)
             and signing.stat().st_mode & 0o777 == 0o700
             and re.fullmatch('[0-9A-F]{40}', fingerprint), 'invalid private caller state')
        work.chmod(0o755)  # Only traverse the workspace; signing remains 0700.
        need(run(['/usr/bin/pacman', '-Q', 'cachy-asahi-update']).stdout
             == b'cachy-asahi-update 4.4.2-2\n', 'new updater identity required')
        before = run(['/usr/bin/pacman', '-Q']).stdout
        validate_inventory(before, expected_inventory)
        need(not PAYLOAD.exists(), 'inert fixture payload already exists')
        root = work / 'real-check'
        root.mkdir(mode=0o755)
        repo, home = root / 'repo', root / 'user'
        repo.mkdir(mode=0o755)
        home.mkdir(mode=0o700)
        account = pwd.getpwnam('alarm')
        os.chown(home, account.pw_uid, account.pw_gid)
        for name in ('config/arch-update', 'state', 'data', 'runtime', 'public-keyring'):
            run(['/usr/bin/runuser', '-u', 'alarm', '--', '/usr/bin/mkdir', '-p', str(home / name)])
        trust = home / 'public-keyring'
        trust.chmod(0o700)
        gpg = ['/usr/bin/gpg', '--batch', '--no-options', '--homedir', str(signing),
               '--no-auto-key-retrieve', '--pinentry-mode', 'loopback', '--passphrase', '',
               '--local-user', fingerprint]
        public = run(gpg + ['--export', fingerprint]).stdout
        verifier = user_command(home, ['/usr/bin/gpg', '--batch', '--no-options', '--homedir',
                                       str(trust), '--no-auto-key-retrieve'])
        run(verifier + ['--import'], data=public)
        run(verifier + ['--import-ownertrust'], data=(fingerprint + ':6:\n').encode())
        need(not (trust / 'private-keys-v1.d').exists()
             or not any((trust / 'private-keys-v1.d').iterdir()), 'public verifier contains private key')
        need(run(user_command(home, ['/usr/bin/test', '-r', str(signing / 'private-keys-v1.d')]),
                 expected=None).returncode != 0, 'private signing key accessible to alarm')
        config_file = home / 'config/arch-update/arch-update.conf'
        config_file.write_text(OPTIONS)
        os.chown(config_file, account.pw_uid, account.pw_gid)
        packages = {}
        result['phase'] = 'signed-fixture-preparation'
        for version in ('0.1.0-1', '0.1.1-1'):
            package = root / f'{NAME}-{version}-any.pkg.tar.gz'
            write_package(package, version)
            run(gpg + ['--output', str(package) + '.sig', '--detach-sign', str(package)])
            packages[version] = package
        pacman_conf = Path('/etc/pacman.conf')
        need(pacman_conf.is_file() and not pacman_conf.is_symlink(), 'regular container config required')
        original_conf = pacman_conf.read_bytes()
        pacman_conf.write_text(configuration(repo, trust))
        result['phase'] = 'signed-baseline-installation'
        run(['/usr/bin/pacman', '-U', '--noconfirm', str(packages['0.1.0-1'])])
        installed = run(['/usr/bin/pacman', '-Q']).stdout
        need(set(installed.splitlines()) == set(before.splitlines()) | {f'{NAME} 0.1.0-1'.encode()},
             'fixture changed other installed packages')
        need(PAYLOAD.read_bytes() == package_data('0.1.0-1')[str(PAYLOAD).lstrip('/')],
             'baseline payload missing')
        db_before = snapshot(Path('/var/lib/pacman'))
        payload_before = PAYLOAD.read_bytes()
        result['phase'] = 'installed-updater-payload-snapshot'
        owned_paths = run(['/usr/bin/pacman', '-Qlq', 'cachy-asahi-update']).stdout.decode().splitlines()
        updater_before = {name: hashlib.sha256(Path(name).read_bytes()).hexdigest()
                          for name in owned_paths if Path(name).is_file() and not Path(name).is_symlink()}
        need('/usr/lib/cachy-asahi-update/asahi-policy' in updater_before,
             'installed Apple protection helper missing')

        def repository(version):
            result['phase'] = 'signed-local-repository-preparation'
            for path in repo.iterdir():
                path.unlink()
            package = packages[version]
            shutil.copyfile(package, repo / package.name)
            shutil.copyfile(str(package) + '.sig', repo / (package.name + '.sig'))
            env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'GNUPGHOME': str(signing)}
            run(['/usr/bin/repo-add', '--sign', '--key', fingerprint,
                 str(repo / 'check-fixture.db.tar.gz'), str(repo / package.name)], env=env)
            for path in repo.iterdir():
                if path.is_file() and not path.is_symlink():
                    path.chmod(0o644)
            need((repo / 'check-fixture.db.sig').is_file(), 'signed database alias missing')

        state = home / 'state/arch-update'

        def check(case, expected_line, *, failure=False):
            result['phase'] = case
            old = snapshot(state, metadata=True) if state.exists() else {}
            start = int(time.time())
            process = run(user_command(home, ['/usr/bin/arch-update', '--check']), expected=None)
            row = {'exit': process.returncode}
            result['cases'][case] = row
            if failure:
                need(process.returncode == 20, 'failed sync did not report updater check failure')
                need(snapshot(state, metadata=True) == old, 'failed sync changed prior state')
                row['state_preserved'] = 'PASS-bytes-mode-mtime'
            else:
                need(process.returncode == 0, 'real check failed')
                expected = (expected_line + '\n').encode()
                need((state / 'last_updates_check_packages').read_bytes()
                     == (expected if expected_line else b''), 'package update line differs')
                need((state / 'last_updates_check').read_bytes() == expected, 'composite state differs')
                need((state / 'last_updates_check_aur').read_bytes() == b''
                     and (state / 'last_updates_check_flatpak').read_bytes() == b'', 'optional backend state differs')
                icon = 'cachy-update_updates-available-blue\n' if expected_line else 'cachy-update-blue\n'
                need((state / 'tray_icon').read_text() == icon, 'tray icon state differs')
                timestamp = (state / 'last_updates_check_time').read_text().splitlines()
                need(len(timestamp) == 2 and timestamp[0].isdigit()
                     and start <= int(timestamp[0]) <= int(time.time())
                     and re.fullmatch(r'\d{4}-\d\d-\d\d \d\d:\d\d:\d\d', timestamp[1]),
                     'successful timestamp missing')
                need(not (state / 'current_updates_check').exists(), 'temporary composite remains')
                row.update(state='PASS-real-installed-check', expected_update=expected_line,
                           icon='PASS', timestamp='PASS')

        repository('0.1.1-1')
        check('pending-versioned', f'{NAME} 0.1.0-1 -> 0.1.1-1')
        signature = repo / 'check-fixture.db.tar.gz.sig'
        valid_signature = signature.read_bytes()
        signature.write_bytes(b'invalid TEST database signature\n')
        check('invalid-signature-preserves-pending', None, failure=True)
        signature.unlink()
        check('missing-signature-preserves-pending', None, failure=True)
        signature.write_bytes(valid_signature)
        repository('0.1.0-1')
        check('no-updates-clears-pending', '')
        repository('0.1.1-1')
        config_file.write_text(OPTIONS + 'NoVersion\n')
        check('pending-no-version', NAME)
        (repo / 'check-fixture.db.tar.gz.sig').unlink()
        check('missing-signature-preserves-no-version', None, failure=True)

        result['phase'] = 'unconfigured-full-update-refusal'
        need(Path('/usr/bin/run0').is_file(), 'installed real run0 prerequisite missing')
        config_file.write_text(OPTIONS + 'PrivilegeElevationCommand = run0\n')
        state_before_refusal = snapshot(state, metadata=True)
        refusal = run(user_command(home, ['/usr/bin/arch-update']), expected=None)
        result['cases']['unconfigured-full-update'] = {'exit': refusal.returncode}
        need(refusal.returncode == 21 and b'policy' in (refusal.stdout + refusal.stderr).lower(),
             'installed full update did not refuse unconfigured Apple policy')
        need(snapshot(state, metadata=True) == state_before_refusal,
             'policy refusal changed Check state')
        need(run(['/usr/bin/pacman', '-Q']).stdout == installed
             and snapshot(Path('/var/lib/pacman')) == db_before
             and PAYLOAD.read_bytes() == payload_before
             and all(hashlib.sha256(Path(name).read_bytes()).hexdigest() == digest
                     for name, digest in updater_before.items()), 'check or refusal changed installed state')
        result.update(status='PASS', phase='completed', installed_packages=len(installed.splitlines()),
                      inventory_preserved='PASS-exact-inventory-plus-inert-baseline',
                      pacman_database_preserved='PASS', fixture_payload_preserved='PASS',
                      updater_and_apple_policy_payload_preserved='PASS',
                      protected_platform_changes='NONE-fixture-only-no-policy-supplied',
                      installed_inventory_sha256=hashlib.sha256(installed).hexdigest(),
                      public_only_verifier='PASS', full_update_privileged_command='NOT INVOKED-before-policy-refusal')
    except Exception as error:
        result['error_type'] = type(error).__name__
    finally:
        if original_conf is not None:
            try:
                Path('/etc/pacman.conf').write_bytes(original_conf)
                result['container_config_restored'] = 'PASS'
            except OSError:
                result.update(status='FAIL', container_config_restored='FAIL')
        if trust is not None:
            try:
                run(user_command(home, ['/usr/bin/gpgconf', '--homedir', str(trust),
                                        '--kill', 'all']), timeout=10)
                result['verifier_agent_cleanup'] = 'PASS'
            except Exception:
                result.update(status='FAIL', verifier_agent_cleanup='FAIL')
        if root is not None and root.is_dir():
            try:
                shutil.rmtree(root)
                result['private_fixture_files_removed'] = 'PASS'
            except OSError:
                result.update(status='FAIL', private_fixture_files_removed='FAIL')
    return result
