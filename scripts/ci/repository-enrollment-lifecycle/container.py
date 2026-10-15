#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Installed setup3→4 lifecycle, only in the caller's offline ARM container."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import traceback


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def snapshot(paths):
    result = {}
    for path in paths:
        row = path.lstat()
        if not stat.S_ISREG(row.st_mode): raise ValueError('regular fixture file required')
        result[str(path)] = (hashlib.sha256(path.read_bytes()).hexdigest(), stat.S_IMODE(row.st_mode),
                             row.st_uid, row.st_gid, row.st_mtime_ns)
    return result


def ownertrust(text):
    return sorted(line for line in text.splitlines() if line and not line.startswith('#'))


def suite(api, signer, source, work, result):
    api.guard()
    plan = json.loads((source / 'packages.json').read_text())
    base = api.lock((source / 'packages.lock').read_text())
    api.need(len(base) == 341 and 'cachy-asahi-setup' not in base and api.inventory() == base,
             'exact original 341-package builder required')
    api.need([row['version'] for row in plan] == ['0.1.0-3', '0.1.0-4'], 'exact real predecessor and successor required')
    incoming = work / 'incoming'; incoming.mkdir()
    for row in plan:
        api.pin(source / row['filename'], row['sha256'], row['size'])
        api.archive_metadata(row, source)
        shutil.copyfile(source / row['filename'], incoming / row['filename'])
    fingerprint = signer.sign(incoming, work, [incoming / row['filename'] for row in plan])
    trust = work / 'transaction-trust'; trust.mkdir(mode=0o700)
    gpg = ['gpg', '--no-options', '--batch', '--homedir', str(trust), '--no-auto-key-retrieve']
    api.run(gpg + ['--import', str(incoming / 'TEST-public.asc')])
    api.run(gpg + ['--import-ownertrust'], data=fingerprint + ':6:\n')
    hooks = work / 'hooks'; hooks.mkdir()
    for directory in ('/usr/share/libalpm/hooks', '/etc/pacman.d/hooks'):
        for path in Path(directory).glob('*.hook'):
            api.need(re.fullmatch(r'[A-Za-z0-9_.@+-]+\.hook', path.name), 'unsafe existing hook name')
            (hooks / path.name).symlink_to('/dev/null') if not (hooks / path.name).is_symlink() else None
    conf = work / 'pacman.conf'
    conf.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\n'
                    'GPGDir = ' + str(trust) + '\nHookDir = ' + str(hooks) + '\n')
    pacman = ['pacman', '--config', str(conf), '--noconfirm', '--noscriptlet']
    main = Path('/etc/pacman.conf'); original_main = main.read_bytes()
    include = Path('/etc/pacman.d/cachy-asahi.conf')
    api.need(not include.exists() and b'cachy-asahi repository enrollment' not in original_main,
             'enrollment must initially be absent')
    work.chmod(0o755)
    user = work / 'existing-user'; user.mkdir(mode=0o700)
    paths = [user / name for name in ('.zshrc', 'config.fish', 'history', 'editor.conf')]
    for path in paths:
        path.write_text('# existing user file\n'); path.chmod(0o600); os.chown(path, 1001, 1001)
    os.chown(user, 1001, 1001)
    sentinel = Path('/etc/pacman.d/unrelated-lifecycle-sentinel')
    api.need(not sentinel.exists(), 'foreign fixture sentinel exists')
    sentinel.write_text('# unrelated operator configuration\n'); sentinel.chmod(0o640)
    preserved = snapshot([*paths, sentinel])
    default = ['gpg', '--no-options', '--batch', '--homedir', '/etc/pacman.d/gnupg', '--no-auto-key-retrieve']
    listed = api.run(default + ['--with-colons', '--fingerprint', '--list-keys'])
    primary = False; originals = []
    for line in listed.splitlines():
        fields = line.split(':')
        if fields[0] == 'pub': primary = True
        elif fields[0] == 'fpr' and primary: originals.append(fields[9]); primary = False
    api.need(originals, 'existing default public trust required')

    def certificates(fingerprints):
        return subprocess.check_output(default + ['--export-options', 'export-local-sigs', '--export', *sorted(fingerprints)], timeout=45)

    original_certificates = certificates(originals)
    original_ownertrust = [line for line in ownertrust(api.run(default + ['--export-ownertrust'])) if line.split(':')[0] in originals]
    checks = result['checks']

    def check(label, ok):
        api.need(ok, label); checks.append(label); print(label + ': PASS', flush=True)

    def kept():
        check('user-and-unrelated-config-preserved', snapshot([*paths, sentinel]) == preserved)
        check('base-public-certificates-preserved', certificates(originals) == original_certificates)
        check('base-ownertrust-preserved', [line for line in ownertrust(api.run(default + ['--export-ownertrust'])) if line.split(':')[0] in originals] == original_ownertrust)

    def installed(row):
        check('installed-version-' + row['version'], api.inventory() == {**base, row['name']: row['version']})
        api.run(pacman + ['-Qkk', row['name']]); api.run(pacman + ['-Dk'])
        for name, desired in row['payload'].items():
            path = Path('/') / name; actual = path.lstat()
            api.need(stat.S_ISREG(actual.st_mode) and stat.S_IMODE(actual.st_mode) == desired['mode'] and
                     actual.st_uid == actual.st_gid == 0 and hashlib.sha256(path.read_bytes()).hexdigest() == desired['sha256'],
                     'installed payload differs: ' + name)
            api.need(api.run(pacman + ['-Qqo', str(path)]).strip() == row['name'], 'package owner differs')

    for row in plan:
        api.run(pacman + ['-U', str(incoming / row['filename'])]); installed(row); kept()
        check('no-automatic-enrollment-' + row['version'], main.read_bytes() == original_main and not include.exists())
        if row['version'] == '0.1.0-3':
            check('predecessor-has-no-repository-command', not Path('/usr/bin/cachy-asahi-repository').exists())
    cli = ['/usr/bin/cachy-asahi-repository']
    public = Path('/etc/pacman.d/lifecycle-TEST-public.asc')
    api.need(not public.exists(), 'foreign public fixture exists')
    public.write_bytes((incoming / 'TEST-public.asc').read_bytes()); public.chmod(0o600)
    url = 'https://repository-lifecycle.example.invalid/generations/' + 'a' * 64 + '/release/repo'
    args = ['enroll', '--snapshot-url', url, '--public-key', str(public), '--fingerprint', fingerprint]
    preview = json.loads(api.run(cli + args))
    check('installed-default-preview-readonly', preview['status'] == 'preview' and
          main.read_bytes() == original_main and not include.exists())
    kept()
    enrolled = json.loads(api.run(cli + ['--apply', *args]))
    check('explicit-installed-enrollment', enrolled['status'] == 'enabled' and include.is_file())
    effective = api.run(['pacman-conf', '--repo', 'cachy-asahi', 'SigLevel', 'Server'])
    check('mandatory-package-and-database-signatures', all(value in effective for value in
          ('PackageRequired', 'DatabaseRequired', 'PackageTrustedOnly', 'DatabaseTrustedOnly', url)) and 'Optional' not in effective)
    selected = snapshot([main, include, public])
    enrolled_cert = certificates([fingerprint])
    valid = api.run(default + ['--with-colons', '--list-keys', fingerprint])
    check('enrolled-test-primary-fully-valid', any(line.startswith(('pub:f:', 'pub:u:')) for line in valid.splitlines()))
    kept()

    def enrollment_kept():
        check('manual-selection-preserved', snapshot([main, include, public]) == selected)
        check('manual-public-trust-preserved', certificates([fingerprint]) == enrolled_cert)
        kept()

    api.run(pacman + ['-R', 'cachy-asahi-setup'])
    check('removed-exact-base-inventory', api.inventory() == base)
    check('removed-all-package-files', all(not (Path('/') / name).exists() for name in plan[1]['payload']))
    enrollment_kept()
    api.run(pacman + ['-U', str(incoming / plan[1]['filename'])]); installed(plan[1]); enrollment_kept()
    disabled = json.loads(api.run(cli + ['--apply', 'disable']))
    check('explicit-installed-disable', disabled['status'] == 'disabled' and not include.exists() and main.read_bytes() == original_main)
    check('disable-retains-public-trust', certificates([fingerprint]) == enrolled_cert); kept()
    api.run(pacman + ['-R', 'cachy-asahi-setup'])
    check('final-exact-base-inventory', api.inventory() == base)
    check('final-package-files-absent', all(not (Path('/') / name).exists() for name in plan[1]['payload']))
    check('final-removal-retains-public-trust', certificates([fingerprint]) == enrolled_cert); kept()
    check('final-removal-keeps-disabled-config', main.read_bytes() == original_main and not include.exists())
    public.unlink(); sentinel.unlink()
    result.update(status='PASS', package_versions=['0.1.0-3', '0.1.0-4'], local_signatures='REQUIRED-TEST-ONLY',
                  scriptlets='DISABLED', hooks='MASKED', automatic_enrollment=False,
                  test_fingerprint=fingerprint, base_public_primary_count=len(originals),
                  final_package_count=len(base), default_public_trust_retained=True)


def main():
    result = {'status': 'FAIL', 'checks': [], 'hardware': 'NOT RUN', 'target_installation': 'NOT RUN',
              'production_trust': 'NOT ACCEPTED', 'network': 'none'}
    work = None; guarded = False
    try:
        api = load('composition_api', '/helpers/composition-container.py'); api.guard(); guarded = True
        signer = load('composition_signer', '/helpers/composition-run.py')
        work = Path(tempfile.mkdtemp(prefix='repository-installed-', dir='/tmp'))
        suite(api, signer, Path('/inputs'), work, result)
    except BaseException as error:
        result.update(status='FAIL', error=str(error), traceback=traceback.format_exc(limit=10))
    finally:
        if work:
            try:
                for home in (work / 'test-signing', work / 'transaction-trust', Path('/etc/pacman.d/gnupg')):
                    subprocess.run(['gpgconf', '--homedir', str(home), '--kill', 'all'], check=True, capture_output=True, timeout=15)
                shutil.rmtree(work)
                result['private_fixture_cleanup'] = not work.exists()
            except (OSError, subprocess.SubprocessError) as error:
                result.update(status='FAIL', cleanup_error=str(error))
        if guarded: Path('/results/result.json').write_text(json.dumps(result, indent=2) + '\n')
        else: print(json.dumps(result), flush=True)
    return int(result['status'] != 'PASS')


if __name__ == '__main__': raise SystemExit(main())
