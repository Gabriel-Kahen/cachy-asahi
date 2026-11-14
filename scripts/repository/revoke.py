#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Preview authenticated primary revocation and quarantine one managed repository.

Complete public certificates only. No fetching, key deletion, successor enrollment,
package transaction, incident-freshness claim or production acceptance.
"""
import argparse
import base64
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


def gpg(home, *args):
    return E.run(['/usr/bin/gpg', '--no-options', '--homedir', str(home), '--batch', '--no-autostart',
                  '--auto-key-locate', 'clear', '--no-auto-key-retrieve', '--no-auto-check-trustdb', *map(str, args)], home)


def packets(raw):
    """Finite public-export packet framing; never interpret revocations as proof."""
    result, position = [], 0
    while position < len(raw):
        start = position
        header = raw[position]; position += 1
        E.need(header & 0x80, 'invalid OpenPGP packet header')
        if header & 0x40:
            tag = header & 0x3f
            E.need(position < len(raw), 'truncated packet length')
            size = raw[position]; position += 1
            if 192 <= size < 224:
                E.need(position < len(raw), 'truncated packet length')
                size = ((size - 192) << 8) + raw[position] + 192; position += 1
            elif size == 255:
                E.need(position + 4 <= len(raw), 'truncated packet length')
                size = int.from_bytes(raw[position:position + 4], 'big'); position += 4
            else:
                E.need(size < 224, 'partial packet lengths refused')
        else:
            tag, kind = (header >> 2) & 15, header & 3
            E.need(kind != 3, 'indeterminate packet length refused')
            width = (1, 2, 4)[kind]
            E.need(position + width <= len(raw), 'truncated packet length')
            size = int.from_bytes(raw[position:position + width], 'big'); position += width
        E.need(tag in (2, 6, 13, 14, 17), 'secret/non-public packet refused')
        E.need(0 < size and position + size <= len(raw), 'truncated/empty public packet')
        body = raw[position:position + size]; position += size
        result.append((tag, body, raw[start:position]))
        E.need(len(result) <= 2048, 'public packet count bound')
    E.need(sum(tag == 6 for tag, _, _ in result) == 1, 'exactly one public primary certificate required')
    return result


def primary(text, fingerprint):
    rows = [line.split(':') for line in text.splitlines()]
    indices = [index for index, row in enumerate(rows) if row[0] == 'pub']
    E.need(len(indices) == 1, 'exactly one selected public primary required')
    index = indices[0]
    E.need(index + 1 < len(rows) and rows[index + 1][0] == 'fpr' and rows[index + 1][9] == fingerprint,
           'public primary differs from selected fingerprint')
    return rows[index], rows


def certificate(home, raw, name, fingerprint):
    binary = raw
    if raw.lstrip().startswith(b'-----'):
        lines = raw.strip().splitlines()
        E.need(lines[0] == b'-----BEGIN PGP PUBLIC KEY BLOCK-----'
               and lines[-1] == b'-----END PGP PUBLIC KEY BLOCK-----'
               and sum(b'-----BEGIN' in line or b'-----END' in line for line in lines) == 2,
               'one complete public armor block required; secret/mixed/trailing material refused')
        body = lines[1:-1]
        while body and b':' in body[0]:
            body.pop(0)
        E.need(body and body.pop(0) == b'', 'public armor header separator required')
        if body and body[-1].startswith(b'='):
            E.need(len(body[-1]) == 5, 'invalid armor checksum field')
            body.pop()
        binary = base64.b64decode(b''.join(body), validate=True)
        E.need(0 < len(binary) <= 4 * 1024**2, 'public certificate size bound')
    framed = packets(binary)
    copied = home / name
    copied.write_bytes(raw); copied.chmod(0o400)
    shown = gpg(home, '--with-colons', '--fingerprint', '--import-options', 'show-only', '--dry-run', '--import', copied)
    primary(shown, fingerprint)
    return copied, framed


def validated_revocation(home, original, updated, fingerprint):
    """Each selected primary-revocation signature must work on a fresh public copy."""
    original_file, _ = certificate(home, original, 'original-public.gpg', fingerprint)
    _, framed = certificate(home, updated, 'updated-public.gpg', fingerprint)
    revocations = []
    for tag, body, encoded in framed:
        if tag == 2:
            E.need(len(body) >= 2 and body[0] in (4, 5, 6), 'modern public signature packets required')
            if body[1] == 0x20:
                revocations.append(encoded)
    E.need(0 < len(revocations) <= 8, 'one to eight primary-key revocations required; subkey-only/non-revoking input refused')
    merged = home / 'merged'; merged.mkdir(mode=0o700)
    gpg(merged, '--import', original_file)
    row, _ = primary(gpg(merged, '--with-colons', '--fingerprint', '--list-keys', fingerprint), fingerprint)
    E.need(row[1] != 'r', 'original managed certificate is already revoked; non-revoked original required')
    for index, raw in enumerate(revocations):
        check = home / ('proof-' + str(index)); check.mkdir(mode=0o700)
        gpg(check, '--import', original_file)
        revocation = home / ('primary-revocation-' + str(index) + '.gpg')
        revocation.write_bytes(raw); revocation.chmod(0o400)
        gpg(check, '--import', revocation)
        row, rows = primary(gpg(check, '--with-colons', '--fingerprint', '--check-sigs', fingerprint), fingerprint)
        E.need(row[1] == 'r' and any(len(sig) > 12 and sig[0] == 'rev' and sig[1] == '!'
                                   and sig[10].startswith('20') and sig[12] == fingerprint for sig in rows),
               'revocation is invalid, foreign or not a verified self-revocation of the selected primary')
        gpg(merged, '--import', revocation)
    sanitized = home / 'validated-selected-public.asc'
    sanitized.write_text(gpg(merged, '--armor', '--export', fingerprint), encoding='ascii'); sanitized.chmod(0o400)
    # Reinspection rejects secret/other primaries in the exact material imported live.
    certificate(home, sanitized.read_bytes(), 'sanitized-public.asc', fingerprint)
    return sanitized, len(revocations)


def live_revoked(ring, fingerprint, home):
    text = E.run(['/usr/bin/gpg', '--no-options', '--homedir', str(ring), '--batch', '--no-autostart',
                  '--auto-key-locate', 'clear', '--no-auto-key-retrieve', '--no-auto-check-trustdb', '--lock-never',
                  '--with-colons', '--fingerprint', '--list-keys', fingerprint], home)
    row, _ = primary(text, fingerprint)
    return row[1] == 'r'


def initialized_keyring(ring, owner):
    E.keyring_safe(ring, owner)
    E.need((ring / 'trustdb.gpg').is_file() and (ring / 'trustdb.gpg').stat().st_size > 0
           and any((ring / name).is_file() and (ring / name).stat().st_size > 0
                   for name in ('pubring.gpg', 'pubring.kbx')), 'existing initialized pacman keyring required; never initialize during preview')


def execute(root, expected_current, expected_certificate_sha256, current_public_key, revoked_public_key, apply=False):
    report = {'status': 'preview', 'operation': 'primary-revocation-quarantine',
              'config_changed': False, 'config_may_have_changed': False, 'keyring_may_have_changed': False,
              'revocation_confirmed': False, 'repository_enabled': None, 'quarantine_record_preserved': False,
              'keys_removed': False, 'successor_enrolled': False, 'packages_installed': False,
              'network_used': False, 'production_accepted': False, 'freshness': 'UNKNOWN; caller authenticates external input'}
    try:
        selection = E.state(root, 'enroll')
        E.need(selection['owner'] == 0, 'selected root and public inputs must be root-owned')
        E.need(isinstance(expected_current, str) and E.FPR.fullmatch(expected_current), 'full uppercase current primary fingerprint required')
        E.need(isinstance(expected_certificate_sha256, str) and E.HEX.fullmatch(expected_certificate_sha256), 'exact expected managed certificate SHA-256 required')
        previous = selection['managed']
        E.need(previous and (previous['fingerprint'], previous['key_sha256']) ==
               (expected_current, expected_certificate_sha256), 'expected managed primary/certificate differs; no quarantine or import')
        report.update(expected_current_fingerprint=expected_current, expected_certificate_sha256=expected_certificate_sha256,
                      repository_enabled=selection['enabled'], quarantine_record_preserved=True, snapshot_url=previous['url'])
        ring = selection['root'] / 'etc/pacman.d/gnupg'
        E.parents(ring / 'trustdb.gpg', selection['root'], selection['owner'])
        initialized_keyring(ring, selection['owner'])
        public = []
        for value in (current_public_key, revoked_public_key):
            path = E.canonical(str(value))
            E.parents(path, selection['root'], selection['owner'])
            E.need(not path.is_relative_to(ring), 'public inputs must be separate exports outside the live keyring')
            observed = E.read(path, selection['owner'])
            selection['observed'][path] = observed
            public.append(observed[0])
        E.need(E.sha(public[0]) == expected_certificate_sha256, 'retained original certificate differs from managed certificate pin')
        report['revoked_input_sha256'] = E.sha(public[1])
        with tempfile.TemporaryDirectory(prefix='caa-revoke-') as temporary:
            home = Path(temporary)
            sanitized, count = validated_revocation(home, *public, expected_current)
            report.update(verified_primary_revocations=count, validated_import_sha256=E.sha(sanitized.read_bytes()),
                          current_primary_already_revoked=live_revoked(ring, expected_current, home))
            E.stable(selection)
            if not apply:
                return report
            E.need(os.geteuid() == 0, '--apply requires root; alternate roots are disposable-test only')
            with E.lock(selection):
                E.stable(selection)
                initialized_keyring(ring, selection['owner'])
                already_revoked = live_revoked(ring, expected_current, home)
                if selection['enabled']:
                    disabled = selection['main_bytes'].replace(E.BLOCK, b'')
                    report['config_may_have_changed'] = True
                    E.replace(selection['main'], disabled, selection['observed'][selection['main']], selection['owner'])
                    report.update(config_changed=True, repository_enabled=False)
                    selection['observed'][selection['main']] = E.read(selection['main'], selection['owner'])
                    E.need(selection['observed'][selection['main']][0] == disabled, 'configuration changed after quarantine')
                E.stable(selection)
                E.need(not E.state(root, 'enroll')['enabled'], 'managed repository must be disabled before revocation import')
                if not already_revoked:
                    report['keyring_may_have_changed'] = True
                    E.run(['/usr/bin/pacman-key', '--config', str(selection['main']), '--gpgdir', str(ring), '--add', str(sanitized)], home)
                initialized_keyring(ring, selection['owner'])
                E.need(live_revoked(ring, expected_current, home), 'selected primary revocation not confirmed in live keyring')
                report['revocation_confirmed'] = True
                E.stable(selection)
                observed = E.state(root, 'enroll')
                E.need(not observed['enabled'] and observed['managed'] == previous, 'quarantine selection or owned record changed')
                report['status'] = 'unchanged' if already_revoked and not report['config_changed'] else 'quarantined-revoked'
            return report
    except BaseException as error:
        report.update(status='failed', error=str(error) or type(error).__name__,
                      recovery='Keep the owned unselected include and both public inputs. Inspect actual configuration/keyring and retry the same exact pins. '
                               'A failed quarantine rename may already have disabled selection; failed import may already have revoked the key. '
                               'Do not re-enable or enroll a successor during partial recovery. No trust rollback or key removal is automatic.')
        try:
            observed = E.state(root, 'enroll')
            report['repository_enabled'] = observed['enabled']
            selected = observed['managed']
            report['quarantine_record_preserved'] = bool(selected and
                (selected['fingerprint'], selected['key_sha256']) == (expected_current, expected_certificate_sha256))
        except (E.Error, OSError, ValueError):
            report['repository_enabled'] = None
            report['quarantine_record_preserved'] = None
        error.revocation_result = report
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('/'), help='existing root; alternate roots are disposable-test only')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--expected-current-fingerprint', required=True)
    parser.add_argument('--expected-current-certificate-sha256', required=True)
    parser.add_argument('--current-public-key', type=Path, required=True, help='retained exact original enrollment certificate')
    parser.add_argument('--revoked-public-key', type=Path, required=True, help='externally authenticated complete revoked public certificate')
    args = parser.parse_args(argv)
    try:
        report = execute(args.root, args.expected_current_fingerprint, args.expected_current_certificate_sha256,
                         args.current_public_key, args.revoked_public_key, args.apply)
        print(json.dumps(report, sort_keys=True))
        return 0
    except (E.Error, OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        print(json.dumps(getattr(error, 'revocation_result', {'status': 'failed', 'error': str(error)}), sort_keys=True))
        return 1


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(InterruptedError('interrupted by SIGTERM')))
    raise SystemExit(main())
