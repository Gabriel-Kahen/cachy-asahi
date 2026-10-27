#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inspect explicitly supplied public signing certificates offline."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile


class Error(ValueError):
    pass


def need(value, reason):
    if not value:
        raise Error(reason)


def timestamp(value):
    need(isinstance(value, str) and value.endswith('Z'), 'explicit UTC timestamp ending Z required')
    try:
        result = datetime.fromisoformat(value[:-1] + '+00:00')
    except ValueError as error:
        raise Error('invalid UTC timestamp') from error
    need(result.tzinfo == timezone.utc and result.microsecond == 0 and result.timestamp() >= 0,
         'nonnegative whole-second UTC timestamp required')
    return int(result.timestamp())


def public_bytes(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= 4 * 1024**2,
             'bounded ordinary single-link public certificate required')
        chunks, size = [], 0
        while size <= before.st_size:
            chunk = os.read(fd, min(65536, before.st_size + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        identity = lambda row: (row.st_dev, row.st_ino, row.st_mode, row.st_nlink, row.st_uid,
                                row.st_gid, row.st_size, row.st_mtime_ns, row.st_ctime_ns)
        need(size == before.st_size and identity(os.fstat(fd)) == identity(before),
             'certificate changed while reading')
        raw = b''.join(chunks)
        return raw
    finally:
        os.close(fd)


def inspect(raw, as_of):
    # No configured keyring, network lookup, agent, or user configuration is used.
    with tempfile.TemporaryDirectory(prefix='signing-expiry-') as temporary:
        home = Path(temporary)
        certificate = home / 'public-key'
        certificate.write_bytes(raw)
        argv = ['/usr/bin/gpg', '--no-options', '--homedir', temporary, '--batch', '--no-autostart',
                '--auto-key-locate', 'clear', '--no-auto-key-retrieve', '--with-colons',
                '--with-fingerprint', '--with-subkey-fingerprint', '--faked-system-time', str(as_of) + '!',
                '--import-options', 'show-only', '--dry-run', '--import', str(certificate)]
        try:
            result = subprocess.run(argv, capture_output=True, timeout=30,
                                    env={'PATH': '/usr/bin:/bin', 'HOME': temporary, 'LANG': 'C', 'LC_ALL': 'C'})
        except (OSError, subprocess.SubprocessError) as error:
            raise Error('offline GPG certificate inspection unavailable or failed') from error
        need(result.returncode == 0 and len(result.stdout) + len(result.stderr) <= 2 * 1024**2,
             'offline GPG refused certificate or exceeded output bound')
        try:
            return result.stdout.decode('utf-8')
        except UnicodeError as error:
            raise Error('invalid GPG colon output') from error


def report(colons, expected, as_of, warning_days):
    need(re.fullmatch(r'(?:[A-F0-9]{40}|[A-F0-9]{64})', expected) is not None,
         'independently authenticated uppercase primary fingerprint required')
    need(type(as_of) is int and as_of >= 0 and type(warning_days) is int and 1 <= warning_days <= 3650,
         'explicit evaluation time and warning window required')
    rows = [line.split(':') for line in colons.splitlines()]
    need(len(rows) <= 4096 and not any(row[0] in ('sec', 'ssb') for row in rows),
         'public certificate only; secret material refused')
    need(sum(row[0] == 'pub' for row in rows) == 1, 'exactly one public primary certificate required')
    keys = []
    seen = set()
    for index, row in enumerate(rows):
        if row[0] not in ('pub', 'sub'):
            continue
        need(len(row) >= 12 and index + 1 < len(rows) and rows[index + 1][0] == 'fpr'
             and len(rows[index + 1]) > 9, 'complete key and fingerprint rows required')
        fingerprint = rows[index + 1][9]
        need(re.fullmatch(r'(?:[A-F0-9]{40}|[A-F0-9]{64})', fingerprint) is not None
             and fingerprint not in seen, 'unique complete key fingerprints required')
        seen.add(fingerprint)
        need(row[5].isdigit() and (not row[6] or row[6].isdigit()), 'explicit key creation/expiry epochs required')
        created, expires = int(row[5]), int(row[6]) if row[6] else None
        need(expires is None or expires >= created, 'key expiry precedes creation')
        primary = row[0] == 'pub'
        if primary:
            need(not keys and fingerprint == expected, 'primary fingerprint differs from independent selection')
        else:
            need(keys, 'subkey precedes primary')
        # Uppercase capabilities on a primary summarize its subkeys, not its own authority.
        signing = 's' in row[11]
        if not primary and not signing:
            continue
        if row[1] == 'r':
            state, action = 'REVOKED_IN_EXPORT', 'Stop using this key; perform the reviewed signing-key rotation.'
        elif row[1] == 'd' or 'D' in row[11]:
            state, action = 'DISABLED_IN_EXPORT', 'Review key custody and rotate or repair the selected signing certificate.'
        elif row[1] == 'i':
            state, action = 'INVALID_IN_EXPORT', 'Investigate the invalid public certificate before signing or publishing.'
        elif created > as_of:
            state, action = 'NOT_YET_CREATED', 'Check the evaluation time and independently authenticated certificate.'
        elif expires is not None and expires <= as_of:
            state, action = 'EXPIRED', 'Renew and redistribute the public certificate, or complete signing-key rotation before another release.'
        elif row[1] == 'e':
            state, action = 'GPG_EXPIRED_OR_UNUSABLE', 'Inspect certificate and parent/subkey validity before signing another release.'
        elif expires is not None and expires - as_of <= warning_days * 86400:
            state, action = 'EXPIRES_SOON', 'Schedule renewal or rotation and redistribute the public certificate before the expiry shown.'
        elif expires is None:
            state, action = 'NO_EXPIRY_IN_EXPORT', 'Continue scheduled custody/revocation reviews; no expiry does not establish trust.'
        else:
            state, action = 'WITHIN_EXPORTED_TIME_WINDOW', 'Continue scheduled checks and plan certificate renewal before expiry.'
        keys.append(dict(role='primary' if primary else 'signing-subkey', fingerprint=fingerprint,
                         own_signing_capability=signing, created_epoch=created, expires_epoch=expires,
                         seconds_until_expiry=None if expires is None else expires - as_of,
                         status=state, action=action))
    need(keys and keys[0]['role'] == 'primary', 'primary certificate required')
    good = {'EXPIRES_SOON', 'NO_EXPIRY_IN_EXPORT', 'WITHIN_EXPORTED_TIME_WINDOW'}
    available = keys[0]['status'] in good and any(k['own_signing_capability'] and k['status'] in good for k in keys)
    return dict(schema_version=1, status='OFFLINE_SIGNING_EXPIRY_REPORT_NOT_TRUST_ACCEPTANCE',
                as_of_epoch=as_of, warning_days=warning_days, expected_primary_fingerprint=expected,
                signing_time_window='AVAILABLE_IN_EXPORT' if available else 'NO_USABLE_SIGNING_TIME_WINDOW_IN_EXPORT',
                current_revocation='UNKNOWN_OFFLINE_EXPORT', trust='UNKNOWN_NOT_CHECKED', keys=keys,
                limitations=['A cached export cannot establish current revocation, custody, trust, or client acceptance.',
                             'This evaluation is a snapshot at the supplied time, not a historical certificate-state attestation.',
                             'No release, repository, native ARM, or hardware acceptance is granted.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--certificate', type=Path, required=True)
    parser.add_argument('--fingerprint', required=True)
    parser.add_argument('--as-of', required=True)
    parser.add_argument('--warning-days', type=int, default=30)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    now = timestamp(args.as_of)
    raw = public_bytes(args.certificate)
    value = report(inspect(raw, now), args.fingerprint, now, args.warning_days)
    value['certificate'] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    args.output.mkdir(mode=0o700)
    (args.output / 'certificate-public.original').write_bytes(raw)
    (args.output / 'report.json').write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
    print(json.dumps(value, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
