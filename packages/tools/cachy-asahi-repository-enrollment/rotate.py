#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Preview a planned repository signing-key rotation; --apply changes local trust/config."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location('repository_enrollment', Path(__file__).resolve().with_name('enroll.py'))
E = importlib.util.module_from_spec(spec)
spec.loader.exec_module(E)


def signing_trust(ring, fingerprint, home, name):
    """Require a currently usable signing certificate as well as full local validity."""
    E.need(E.trusted(ring, fingerprint, home), 'current/new certificate is not valid and fully trusted: ' + fingerprint)
    text = E.run(['/usr/bin/gpg', '--no-options', '--homedir', str(ring), '--batch', '--no-autostart',
                  '--auto-key-locate', 'clear', '--no-auto-key-retrieve', '--no-auto-check-trustdb',
                  '--lock-never', '--armor', '--export', fingerprint], home)
    E.need(0 < len(text) <= 4 * 1024**2, 'selected keyring public certificate bound')
    copied = home / name
    copied.unlink(missing_ok=True)
    copied.write_text(text, encoding='ascii')
    copied.chmod(0o400)
    E.inspect_key(copied, fingerprint, home)


def execute(root, expected_current, public_key, fingerprint, apply=False):
    selection = E.state(root, 'enroll')
    report = {'status': 'preview', 'operation': 'planned-key-rotation', 'config_changed': False,
              'config_may_have_changed': False, 'keyring_may_have_changed': False,
              'keys_removed': False, 'old_trust_retained': True, 'packages_installed': False,
              'network_used': False, 'production_accepted': False}
    try:
        E.need(selection['enabled'] and selection['managed'], 'planned rotation requires an enabled managed repository')
        for value in (expected_current, fingerprint):
            E.need(isinstance(value, str) and E.FPR.fullmatch(value), 'full uppercase primary fingerprint required')
        previous = selection['managed']
        E.need(previous['fingerprint'] == expected_current, 'expected current fingerprint differs from managed selection')
        key = E.canonical(str(public_key))
        E.parents(key, selection['root'], selection['owner'])
        ring = selection['root'] / 'etc/pacman.d/gnupg'
        E.need(not key.is_relative_to(ring), 'provide a separate public certificate export, not a live keyring file')
        public = E.read(key, selection['owner'])
        selection['observed'][key] = public
        E.parents(ring / 'trustdb.gpg', selection['root'], selection['owner'])
        E.keyring_safe(ring, selection['owner'])
        E.need((ring / 'trustdb.gpg').is_file() and (ring / 'trustdb.gpg').stat().st_size > 0 and
               any((ring / name).is_file() and (ring / name).stat().st_size > 0 for name in ('pubring.gpg', 'pubring.kbx')),
               'existing initialized pacman keyring required')
        desired = E.config(previous['url'], fingerprint, E.sha(public[0]))
        same = expected_current == fingerprint
        E.need(not same or previous['key_sha256'] == E.sha(public[0]),
               'same-primary certificate updates require a separate certificate-update policy')
        report.update(expected_current_fingerprint=expected_current, fingerprint=fingerprint,
                      key_sha256=E.sha(public[0]), snapshot_url=previous['url'],
                      managed_include=desired.decode(), currently_enabled=True, no_op=same)
        with tempfile.TemporaryDirectory(prefix='cachy-asahi-rotation-') as temporary:
            home = Path(temporary)
            copied = home / 'operator-public.gpg'
            copied.write_bytes(public[0]); copied.chmod(0o400)
            E.inspect_key(copied, fingerprint, home)
            signing_trust(ring, expected_current, home, 'current-public.asc')
            E.stable(selection)
            if not apply:
                return report
            E.need(os.geteuid() == 0, '--apply requires root; tests may use a disposable user-namespace root')
            with E.lock(selection):
                E.stable(selection)
                E.keyring_safe(ring, selection['owner'])
                signing_trust(ring, expected_current, home, 'current-public.asc')
                if not same:
                    report['keyring_may_have_changed'] = True
                    command = ['/usr/bin/pacman-key', '--config', str(selection['main']), '--gpgdir', str(ring)]
                    E.run(command + ['--add', str(copied)], home)
                    E.run(command + ['--lsign-key', fingerprint], home)
                    E.keyring_safe(ring, selection['owner'])
                    signing_trust(ring, fingerprint, home, 'new-public.asc')
                    signing_trust(ring, expected_current, home, 'current-public.asc')
                    E.stable(selection)
                    report['config_may_have_changed'] = True
                    E.replace(selection['include'], desired, selection['observed'][selection['include']], selection['owner'])
                    report['config_changed'] = True
                    E.stable(selection, (selection['include'],))
                    E.need(E.read(selection['include'], selection['owner'])[0] == desired,
                           'managed selection changed after replacement')
                report['status'] = 'unchanged' if same else 'rotated'
                return report
    except BaseException as error:
        report.update(status='failed', error=str(error) or type(error).__name__,
                      recovery='Public import/local signing is retained. Inspect the actual include and keyring before retrying; '
                               'the expected-current fingerprint must match the observed include. No trust rollback or key removal is automatic.')
        error.rotation_result = report
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('/'), help='existing root; alternate roots are disposable-test only')
    parser.add_argument('--apply', action='store_true', help='import/local-sign new public key, then atomically change the managed include')
    parser.add_argument('--expected-current-fingerprint', required=True)
    parser.add_argument('--public-key', type=Path, required=True)
    parser.add_argument('--fingerprint', required=True, help='independently authenticated NEW full primary fingerprint')
    args = parser.parse_args(argv)
    try:
        result = execute(args.root, args.expected_current_fingerprint, args.public_key, args.fingerprint, args.apply)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (E.Error, OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        print(json.dumps(getattr(error, 'rotation_result', {'status': 'failed', 'error': str(error)}), sort_keys=True))
        return 1


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(InterruptedError('interrupted by SIGTERM')))
    raise SystemExit(main())
