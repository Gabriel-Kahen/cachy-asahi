# SPDX-License-Identifier: MIT
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

P = Path(__file__).with_name('signing_expiry.py')
spec = importlib.util.spec_from_file_location('signing_expiry', P)
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)
NOW = 1792440000
FPR = 'A' * 40
SUB = 'B' * 40


def key(kind, fingerprint, created=NOW - 100, expires=NOW + 86400, caps='s', validity='-'):
    row = [kind, validity, '255', '22', fingerprint[-16:], str(created), str(expires) if expires else '', '', '', '', '', caps]
    return ':'.join(row) + ':\nfpr:::::::::' + fingerprint + ':\n'


class Expiry(unittest.TestCase):
    def check(self, text, **kwargs):
        return S.report(text, FPR, kwargs.get('now', NOW), kwargs.get('days', 30))

    def test_exact_deadline_and_warning_boundaries(self):
        for expiry, state in [(NOW, 'EXPIRED'), (NOW + 30 * 86400, 'EXPIRES_SOON'),
                              (NOW + 30 * 86400 + 1, 'WITHIN_EXPORTED_TIME_WINDOW')]:
            with self.subTest(state=state):
                self.assertEqual(self.check(key('pub', FPR, expires=expiry))['keys'][0]['status'], state)

    def test_primary_aggregate_signing_is_not_own_signing(self):
        value = self.check(key('pub', FPR, caps='cS') + key('sub', SUB))
        self.assertFalse(value['keys'][0]['own_signing_capability'])
        self.assertEqual(value['signing_time_window'], 'AVAILABLE_IN_EXPORT')
        value = self.check(key('pub', FPR, caps='cS'))
        self.assertEqual(value['signing_time_window'], 'NO_USABLE_SIGNING_TIME_WINDOW_IN_EXPORT')

    def test_expired_primary_blocks_unexpired_signing_subkey(self):
        value = self.check(key('pub', FPR, expires=NOW, caps='cS') + key('sub', SUB))
        self.assertEqual(value['signing_time_window'], 'NO_USABLE_SIGNING_TIME_WINDOW_IN_EXPORT')

    def test_revoked_disabled_invalid_and_future_creation(self):
        for flag, state in [('r', 'REVOKED_IN_EXPORT'), ('d', 'DISABLED_IN_EXPORT'), ('i', 'INVALID_IN_EXPORT')]:
            self.assertEqual(self.check(key('pub', FPR, validity=flag))['keys'][0]['status'], state)
        self.assertEqual(self.check(key('pub', FPR, created=NOW + 1))['keys'][0]['status'], 'NOT_YET_CREATED')
        self.assertEqual(self.check(key('pub', FPR, caps='sD'))['keys'][0]['status'], 'DISABLED_IN_EXPORT')

    def test_no_expiry_and_non_signing_subkey(self):
        value = self.check(key('pub', FPR, expires=None) + key('sub', SUB, caps='e'))
        self.assertEqual(len(value['keys']), 1)
        self.assertEqual(value['keys'][0]['status'], 'NO_EXPIRY_IN_EXPORT')
        self.assertEqual(value['current_revocation'], 'UNKNOWN_OFFLINE_EXPORT')

    def test_secret_multiple_fingerprint_and_malformed_refusals(self):
        for text in [key('sec', FPR), key('pub', FPR) + key('pub', SUB), key('pub', SUB),
                     key('pub', FPR) + key('sub', FPR), 'pub:-:255:22:X:bad:\n',
                     key('pub', FPR, created=NOW, expires=NOW - 1)]:
            with self.subTest(text=text), self.assertRaises(S.Error):
                self.check(text)

    def test_explicit_time_and_window(self):
        self.assertEqual(S.timestamp('2026-10-19T20:00:00Z'), NOW)
        for value in ['2026-10-19T20:00:00', '2026-10-19T20:00:00.1Z', 'badZ', '1960-01-01T00:00:00Z']:
            with self.assertRaises(S.Error):
                S.timestamp(value)
        for days in [0, 3651, True]:
            with self.assertRaises(S.Error):
                self.check(key('pub', FPR), days=days)

    def test_input_symlink_hardlink_and_special_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            p = root / 'key'
            p.write_bytes(b'certificate')
            self.assertEqual(S.public_bytes(p), b'certificate')
            link = root / 'link'
            link.symlink_to(p)
            with self.assertRaises(OSError):
                S.public_bytes(link)
            link.unlink()
            os.link(p, link)
            with self.assertRaises(S.Error):
                S.public_bytes(p)
            fifo = root / 'fifo'
            os.mkfifo(fifo)
            with self.assertRaises(S.Error):
                S.public_bytes(fifo)


class RealCertificate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='expiry-real-test-')
        cls.home = Path(cls.directory.name)
        cls.env = {'PATH': '/usr/bin:/bin', 'HOME': str(cls.home), 'LANG': 'C', 'LC_ALL': 'C'}
        cls.gpg = ['/usr/bin/gpg', '--no-options', '--homedir', str(cls.home), '--batch',
                   '--pinentry-mode', 'loopback', '--passphrase', '', '--faked-system-time', str(NOW) + '!']
        cls.run_gpg('--quick-gen-key', 'Disposable signing expiry control <expiry@example.invalid>', 'ed25519', 'cert', '2d')
        rows = cls.run_gpg('--with-colons', '--list-keys').decode().splitlines()
        cls.fingerprint = next(row.split(':')[9] for row in rows if row.startswith('fpr:'))
        cls.run_gpg('--quick-add-key', cls.fingerprint, 'ed25519', 'sign', '1d')
        cls.public = cls.run_gpg('--armor', '--export', cls.fingerprint)
        cls.secret = cls.run_gpg('--armor', '--export-secret-keys', cls.fingerprint)

    @classmethod
    def run_gpg(cls, *args):
        return subprocess.run([*cls.gpg, *args], capture_output=True, check=True, timeout=30, env=cls.env).stdout

    @classmethod
    def tearDownClass(cls):
        subprocess.run(['/usr/bin/gpgconf', '--homedir', str(cls.home), '--kill', 'gpg-agent'],
                       capture_output=True, check=True, timeout=10, env=cls.env)
        cls.directory.cleanup()

    def test_real_primary_and_signing_subkey_with_different_deadlines(self):
        value = S.report(S.inspect(self.public, NOW + 1), self.fingerprint, NOW + 1, 30)
        self.assertEqual([k['role'] for k in value['keys']], ['primary', 'signing-subkey'])
        self.assertEqual([k['expires_epoch'] for k in value['keys']], [NOW + 2 * 86400, NOW + 86400])
        self.assertFalse(value['keys'][0]['own_signing_capability'])
        self.assertEqual(value['signing_time_window'], 'AVAILABLE_IN_EXPORT')
        expired = S.report(S.inspect(self.public, NOW + 86400), self.fingerprint, NOW + 86400, 30)
        self.assertEqual(expired['keys'][1]['status'], 'EXPIRED')
        self.assertEqual(expired['signing_time_window'], 'NO_USABLE_SIGNING_TIME_WINDOW_IN_EXPORT')

    def test_real_secret_refused(self):
        with self.assertRaises(S.Error):
            S.report(S.inspect(self.secret, NOW + 1), self.fingerprint, NOW + 1, 30)

    def test_cli_retains_original_and_refuses_existing_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, output = root / 'public.asc', root / 'report'
            source.write_bytes(self.public)
            argv = [sys.executable, '-B', str(P), '--certificate', str(source), '--fingerprint', self.fingerprint,
                    '--as-of', '2026-10-19T20:00:01Z', '--output', str(output)]
            first = subprocess.run(argv, capture_output=True, timeout=40)
            self.assertEqual(first.returncode, 0, first.stderr.decode())
            self.assertEqual((output / 'certificate-public.original').read_bytes(), self.public)
            value = json.loads((output / 'report.json').read_bytes())
            self.assertEqual(value['trust'], 'UNKNOWN_NOT_CHECKED')
            self.assertNotIn('expiry@example.invalid', (output / 'report.json').read_text())
            before = (output / 'report.json').read_bytes()
            self.assertNotEqual(subprocess.run(argv, capture_output=True, timeout=40).returncode, 0)
            self.assertEqual((output / 'report.json').read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
