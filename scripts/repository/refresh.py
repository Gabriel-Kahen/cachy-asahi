#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Preview a same-primary certificate refresh; --apply imports public updates only."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location('refresh_rotation', Path(__file__).with_name('rotate.py'))
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)
E = R.E


def public_view(home, certificates):
    """Use GPG's effective minimal public export, without local trust signatures."""
    home.mkdir(mode=0o700)
    prefix = ['/usr/bin/gpg', '--no-options', '--homedir', str(home), '--batch', '--no-autostart',
              '--auto-key-locate', 'clear', '--no-auto-key-retrieve', '--no-auto-check-trustdb']
    for certificate in certificates:
        E.run(prefix + ['--import', str(certificate)], home)
    exported = E.run(prefix + ['--armor', '--export-options', 'export-minimal', '--export'], home)
    E.need(0 < len(exported) <= 4 * 1024**2, 'bounded effective public certificate required')
    return exported.encode('ascii')


def proposed(home, current, candidate):
    home.mkdir(mode=0o700)
    before = public_view(home / 'before', [current])
    after = public_view(home / 'after', [candidate])
    merged = public_view(home / 'merged', [current, candidate])
    E.need(merged == after, 'successor omits effective current public material or supplies an older certificate')
    return before, after


def execute(root, fingerprint, expected_certificate_sha256, current_public_key, public_key, apply=False):
    selection = E.state(root, 'enroll')
    report = dict(status='preview', operation='same-primary-certificate-refresh', config_changed=False,
                  config_may_have_changed=False, keyring_may_have_changed=False, keys_removed=False,
                  local_signing_requested=False, snapshot_url_retained=True, packages_installed=False,
                  network_used=False, production_accepted=False)
    try:
        E.need(selection['enabled'] and selection['managed'], 'refresh requires an enabled managed repository')
        E.need(isinstance(fingerprint, str) and E.FPR.fullmatch(fingerprint), 'full uppercase primary fingerprint required')
        E.need(isinstance(expected_certificate_sha256, str) and E.HEX.fullmatch(expected_certificate_sha256),
               'expected current certificate SHA-256 required')
        previous = selection['managed']
        E.need(previous['fingerprint'] == fingerprint and previous['key_sha256'] == expected_certificate_sha256,
               'expected current fingerprint/certificate differs from managed selection')
        key = E.canonical(str(public_key))
        E.parents(key, selection['root'], selection['owner'])
        ring = selection['root'] / 'etc/pacman.d/gnupg'
        E.need(not key.is_relative_to(ring), 'provide a separate public certificate, not a live keyring file')
        old_key = E.canonical(str(current_public_key))
        E.parents(old_key, selection['root'], selection['owner'])
        E.need(not old_key.is_relative_to(ring), 'provide a separate retained current public certificate')
        old_public = E.read(old_key, selection['owner'])
        E.need(E.sha(old_public[0]) == expected_certificate_sha256, 'retained current public certificate hash differs')
        selection['observed'][old_key] = old_public
        public = E.read(key, selection['owner'])
        selection['observed'][key] = public
        E.parents(ring / 'trustdb.gpg', selection['root'], selection['owner'])
        E.keyring_safe(ring, selection['owner'])
        E.need((ring / 'trustdb.gpg').is_file() and (ring / 'trustdb.gpg').stat().st_size > 0 and
               any((ring / name).is_file() and (ring / name).stat().st_size > 0 for name in ('pubring.gpg', 'pubring.kbx')),
               'initialized existing pacman keyring required')
        digest = E.sha(public[0])
        desired = E.config(previous['url'], fingerprint, digest)
        same = digest == expected_certificate_sha256
        report.update(fingerprint=fingerprint, expected_current_certificate_sha256=expected_certificate_sha256,
                      certificate_sha256=digest, snapshot_url=previous['url'], managed_include=desired.decode(), no_op=same)
        with tempfile.TemporaryDirectory(prefix='cachy-asahi-refresh-') as temporary:
            home = Path(temporary)
            candidate = home / 'operator-public.gpg'
            candidate.write_bytes(public[0]); candidate.chmod(0o400)
            original = home / 'selected-current.gpg'
            original.write_bytes(old_public[0]); original.chmod(0o400)
            E.inspect_key(original, fingerprint, home)
            E.inspect_key(candidate, fingerprint, home)
            R.signing_trust(ring, fingerprint, home, 'current-public.asc')
            original_before, original_after = proposed(home / 'selected', original, candidate)
            E.need(same or original_before != original_after, 'no effective certificate update; changed encoding alone is not a refresh')
            before, after = proposed(home / 'preview', home / 'current-public.asc', candidate)
            E.need(original_after == after, 'selected successor effective view differs from current merge')
            E.stable(selection)
            if not apply:
                return report
            E.need(os.geteuid() == selection['owner'] == 0, '--apply requires root-owned selected root and root privileges')
            with E.lock(selection):
                E.stable(selection)
                E.keyring_safe(ring, selection['owner'])
                E.inspect_key(candidate, fingerprint, home)  # Real current clock, again immediately before import.
                R.signing_trust(ring, fingerprint, home, 'locked-public.asc')
                locked_before, locked_after = proposed(home / 'locked', home / 'locked-public.asc', candidate)
                E.need((locked_before, locked_after) == (before, after), 'effective current certificate changed before import')
                if not same:
                    report['keyring_may_have_changed'] = True
                    E.run(['/usr/bin/pacman-key', '--config', str(selection['main']), '--gpgdir', str(ring),
                           '--add', str(candidate)], home)
                    E.keyring_safe(ring, selection['owner'])
                    R.signing_trust(ring, fingerprint, home, 'imported-public.asc')
                    actual = public_view(home / 'imported', [home / 'imported-public.asc'])
                    E.need(actual == after, 'imported effective public certificate differs from reviewed successor')
                    E.stable(selection)
                    report['config_may_have_changed'] = True
                    E.replace(selection['include'], desired, selection['observed'][selection['include']], selection['owner'])
                    report['config_changed'] = True
                    E.stable(selection, (selection['include'],))
                    E.need(E.read(selection['include'], selection['owner'])[0] == desired, 'managed include changed after replacement')
                report['status'] = 'unchanged' if same else 'refreshed'
                return report
    except BaseException as error:
        report.update(status='failed', error=str(error) or type(error).__name__,
                      recovery='Public imports are retained and never rolled back. Inspect the actual include and keyring '
                               'before retrying with the observed current certificate hash. No key deletion or local signing is automatic.')
        error.refresh_result = report
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('/'), help='existing root; alternate roots are disposable tests only')
    parser.add_argument('--fingerprint', required=True, help='independently authenticated unchanged primary fingerprint')
    parser.add_argument('--expected-current-certificate-sha256', required=True)
    parser.add_argument('--current-public-key', type=Path, required=True, help='retained public certificate matching the managed hash')
    parser.add_argument('--public-key', type=Path, required=True, help='independently authenticated complete renewed public certificate')
    parser.add_argument('--apply', action='store_true', help='import public updates and atomically change only the managed certificate hash')
    args = parser.parse_args(argv)
    try:
        print(json.dumps(execute(args.root, args.fingerprint, args.expected_current_certificate_sha256, args.current_public_key, args.public_key, args.apply), sort_keys=True))
        return 0
    except (E.Error, OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        print(json.dumps(getattr(error, 'refresh_result', dict(status='failed', error=str(error))), sort_keys=True))
        return 1


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(InterruptedError('interrupted by SIGTERM')))
    raise SystemExit(main())
