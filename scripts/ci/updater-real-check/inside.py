#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Install and exercise one local updater only in its disposable ARM container."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile


def need(ok, message):
    if not ok:
        raise ValueError(message)


def run(argv, *, data=None, timeout=60, env=None):
    result = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, env=env)
    need(result.returncode == 0 and len(result.stdout) + len(result.stderr) <= 1024**2,
         'runtime command failed: ' + Path(argv[0]).name)
    return result.stdout


def inventory(data):
    rows = [line.split(' ') for line in data.decode('ascii').splitlines()]
    need(all(len(row) == 2 for row in rows) and len({row[0] for row in rows}) == len(rows),
         'invalid runtime inventory')
    return dict(rows)


def main():
    need(platform.system() == 'Linux' and platform.machine() == 'aarch64' and os.getuid() == 0
         and Path('/.dockerenv').is_file()
         and re.fullmatch('[0-9a-f]{32}', os.environ.get('CACHY_ASAHI_UPDATER_RUNTIME', '')),
         'explicit disposable native ARM Docker container required')
    inputs, output = Path('/inputs'), Path('/out/result.json')
    contract = json.loads((inputs / 'runtime.json').read_text())
    result = {'status': 'FAIL', 'scope': 'disposable-updater-real-check-software',
              'installation': 'NOT RUN', 'dependencies': 'NOT RUN', 'pyalpm': 'NOT RUN',
              'real_check': 'NOT RUN', 'test_signing_state_removed': False,
              'hardware': 'NOT RUN', 'target_update': 'NOT RUN', 'publication': 'NOT ACCEPTED'}
    work = Path(tempfile.mkdtemp(prefix='updater-runtime-', dir='/tmp'))
    homes = []
    try:
        result['phase'] = 'compiler-base-verification'
        before = run(['/usr/bin/pacman', '-Q'])
        need(inventory(before) == inventory((inputs / 'compiler-packages.lock').read_bytes())
             and len(inventory(before)) == 354, 'exact compiler base inventory required')
        package = inputs / 'updater.pkg.tar.xz'
        need(hashlib.sha256(package.read_bytes()).hexdigest() == contract['package_sha256'],
             'compiled package differs from native pair')
        signing, trust = work / 'test-signing', work / 'transaction-trust'
        result['phase'] = 'disposable-test-signing'
        for home in (signing, trust):
            home.mkdir(mode=0o700)
            homes.append(home)
        gpg = ['/usr/bin/gpg', '--batch', '--no-options', '--homedir', str(signing),
               '--no-auto-key-retrieve', '--pinentry-mode', 'loopback', '--passphrase', '']
        run(gpg + ['--quick-generate-key', 'TEST ONLY updater runtime <runtime@test.invalid>',
                   'ed25519', 'sign', '1d'])
        listing = run(gpg + ['--with-colons', '--list-keys']).decode()
        fingerprints = [line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:')]
        need(len(fingerprints) == 1 and re.fullmatch('[0-9A-F]{40}', fingerprints[0]),
             'one disposable TEST signer required')
        public = work / 'TEST-public.asc'
        public.write_bytes(run(gpg + ['--armor', '--export', fingerprints[0]]))
        signature = work / 'updater.pkg.tar.xz.sig'
        run(gpg + ['--output', str(signature), '--detach-sign', str(package)])
        local_package = work / package.name
        shutil.copyfile(package, local_package)
        verifier = ['/usr/bin/gpg', '--batch', '--no-options', '--homedir', str(trust),
                    '--no-auto-key-retrieve']
        run(verifier + ['--import', str(inputs / 'archlinuxarm.gpg'), str(public)])
        run(verifier + ['--import-ownertrust'], data=(contract['signer_fingerprint'] + ':6:\n'
                                                     + fingerprints[0] + ':6:\n').encode())
        conf = work / 'pacman.conf'
        conf.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required DatabaseOptional\n'
                        'LocalFileSigLevel = Required\nHookDir = /builder-disabled-hooks\n'
                        'GPGDir = ' + str(trust) + '\n')
        archives = [str(inputs / 'dependencies' / row['filename']) for row in contract['packages']]
        for row in contract['packages']:
            for name, digest in ((row['filename'], row['sha256']),
                                 (row['filename'] + '.sig', row['signature_sha256'])):
                need(Path(name).name == name and hashlib.sha256(
                    (inputs / 'dependencies' / name).read_bytes()).hexdigest() == digest,
                    'authenticated runtime archive changed')
        # Ordinary dependency checking and required signatures apply to all six archives.
        result['phase'] = 'signed-runtime-installation'
        run(['/usr/bin/pacman', '--config', str(conf), '-U', '--noconfirm', *archives,
             str(local_package)], timeout=180)
        run(['/usr/bin/ldconfig'])
        after = run(['/usr/bin/pacman', '-Q'])
        need(inventory(after) == inventory((inputs / 'expected-installed-packages.lock').read_bytes())
             and len(inventory(after)) == 360, 'complete installed runtime inventory differs')
        need(all(inventory(after).get(name) == version for name, version in inventory(before).items()),
             'runtime transaction changed the compiler base')
        result['installation'] = 'PASS-disposable-container'
        result['phase'] = 'installed-dependency-verification'
        run(['/usr/bin/pacman', '--config', str(conf), '-Dk'])
        run(['/usr/bin/pacman', '--config', str(conf), '-T', *contract['runtime_dependencies']])
        result['dependencies'] = 'PASS-no-waivers'
        result['phase'] = 'native-pyalpm-import'
        run(['/usr/bin/python', '-I', '-B', '-c', 'import pyalpm; assert pyalpm.Handle("/", "/var/lib/pacman")'])
        result['pyalpm'] = 'PASS-native-import'
        result['phase'] = 'installed-real-check'
        spec = importlib.util.spec_from_file_location('installed_real_check', inputs / 'real-check/real-check.py')
        checks = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checks)
        result['check_cases'] = checks.exercise(work, signing, fingerprints[0])
        need(result['check_cases']['status'] == 'PASS', 'installed real Check cases failed')
        result['real_check'] = 'PASS-installed-Check-signed-local-repository'
        result.update(status='PASS', phase='completed', installed_inventory_sha256=hashlib.sha256(after).hexdigest(),
                      package_sha256=contract['package_sha256'], test_signer_fingerprint=fingerprints[0],
                      target_update='NOT RUN', publication='NOT ACCEPTED')
    except Exception as error:
        result['error_type'] = type(error).__name__
    finally:
        cleanup = True
        for home in homes:
            try:
                run(['/usr/bin/gpgconf', '--homedir', str(home), '--kill', 'all'], timeout=10)
            except Exception:
                cleanup = False
        try:
            shutil.rmtree(work)
        except OSError:
            cleanup = False
        result['test_signing_state_removed'] = cleanup
        if not cleanup:
            result['status'] = 'FAIL'
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
