#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real TEST revocations and mapped-root quarantine; never host configuration/trust."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('enrollment_fixtures', HERE / 'test_enroll.py')
T = importlib.util.module_from_spec(spec); spec.loader.exec_module(T)
spec = importlib.util.spec_from_file_location('revocation', HERE / 'revoke.py')
R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)


class RevocationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        T.EnrollmentTests.setUpClass.__func__(cls)
        cls.revoked_home = cls.root / 'revoked-public'; cls.revoked_home.mkdir(mode=0o700)
        cls.revocation = cls.root / 'primary-revocation.asc'
        text = (cls.project / 'openpgp-revocs.d' / (cls.fpr + '.rev')).read_text()
        cls.revocation.write_text(text[text.index(':-----BEGIN PGP PUBLIC KEY BLOCK-----'):].replace(':-----BEGIN', '-----BEGIN', 1))
        original = cls.root / 'original-public.gpg'; original.write_bytes(cls.public)
        T.gpg(cls.revoked_home, '--import', original)
        T.gpg(cls.revoked_home, '--import', cls.revocation)
        cls.revoked_public = T.gpg(cls.revoked_home, '--export', cls.fpr)
        cls.revoked_armor = T.gpg(cls.revoked_home, '--armor', '--export', cls.fpr)
        foreign = cls.root / 'foreign-revocation.asc'
        text = (cls.seed / 'openpgp-revocs.d' / (cls.base_fpr + '.rev')).read_text()
        foreign.write_text(text[text.index(':-----BEGIN PGP PUBLIC KEY BLOCK-----'):].replace(':-----BEGIN', '-----BEGIN', 1))
        cls.foreign_revocation_packet = T.gpg(cls.seed, '--output', '-', '--dearmor', foreign)
        cls.secret = T.gpg(cls.project, '--export-secret-keys', cls.fpr)
        cls.message = cls.root / 'message'; cls.message.write_text('DISPOSABLE revocation signature TEST\n')
        cls.signature = cls.root / 'message.sig'
        T.gpg(cls.project, '--local-user', cls.fpr, '--output', cls.signature, '--detach-sign', cls.message)

    @classmethod
    def tearDownClass(cls):
        T.command(['gpgconf', '--homedir', cls.revoked_home, '--kill', 'all'])
        T.EnrollmentTests.tearDownClass.__func__(cls)

    cli = T.EnrollmentTests.cli
    enable = T.EnrollmentTests.enable

    def setUp(self):
        T.EnrollmentTests.setUp(self)
        self.enable()
        self.include = self.target / T.enrollment.INCLUDE.lstrip('/')
        self.original_include = self.include.read_bytes()
        self.main.write_bytes(self.main.read_bytes() + b'\n# unrelated operator configuration\n')
        self.original_main = self.main.read_bytes()
        self.original_current = T.gpg(self.ring, '--export', self.fpr)
        self.updated = self.target / 'etc/pacman.d/selected-revoked-public.gpg'
        self.updated.write_bytes(self.revoked_public); self.updated.chmod(0o600)
        self.pin = T.enrollment.sha(self.public)

    def revoke(self, apply=False, expected=None, pin=None):
        args = ['unshare', '--user', '--map-root-user', '--', sys.executable, '-I', '-B', HERE / 'revoke.py', '--root', self.target,
                '--expected-current-fingerprint', expected or self.fpr,
                '--expected-current-certificate-sha256', pin or self.pin,
                '--current-public-key', self.key, '--revoked-public-key', self.updated]
        if apply: args.append('--apply')
        result = T.command(args)
        self.assertTrue(result.stdout, result.stderr.decode())
        return result, json.loads(result.stdout)

    def inject(self, code):
        script = '''import importlib.util,json,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('revoke',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
root,current,updated,fpr,pin=Path(sys.argv[2]),Path(sys.argv[3]),Path(sys.argv[4]),sys.argv[5],sys.argv[6]
''' + code + '''
try: print(json.dumps(m.execute(root,fpr,pin,current,updated,True)))
except BaseException as error:
 print(json.dumps(getattr(error,'revocation_result',{'error':str(error)})));sys.exit(1)
'''
        result = T.command(['unshare', '--user', '--map-root-user', '--', sys.executable, '-I', '-B', '-c', script,
                            HERE / 'revoke.py', self.target, self.key, self.updated, self.fpr, self.pin])
        self.assertTrue(result.stdout, result.stderr.decode())
        return result, json.loads(result.stdout)

    def preserved(self, enabled=True):
        self.assertEqual(self.main.read_bytes(), self.original_main if enabled else self.original_main.replace(T.enrollment.BLOCK, b''))
        self.assertEqual(self.include.read_bytes(), self.original_include)
        self.assertEqual(T.gpg(self.ring, '--export', self.base_fpr), self.base_export)
        self.assertFalse((self.target / 'var/lib/pacman/db.lck').exists())

    def is_revoked(self):
        return any(row.startswith('pub:r:') for row in T.gpg(self.ring, '--with-colons', '--list-keys', self.fpr).decode().splitlines())

    def test_preview_proves_actual_revocation_without_live_changes(self):
        before = {str(p.relative_to(self.ring)): p.read_bytes() for p in self.ring.rglob('*') if p.is_file()}
        result, report = self.revoke()
        self.assertEqual(result.returncode, 0, report)
        self.assertEqual(report['status'], 'preview')
        self.assertEqual(report['verified_primary_revocations'], 1)
        self.assertFalse(report['keyring_may_have_changed'])
        self.assertFalse(report['config_may_have_changed'])
        self.assertEqual(before, {str(p.relative_to(self.ring)): p.read_bytes() for p in self.ring.rglob('*') if p.is_file()})
        self.preserved()

    def test_uninitialized_keyring_is_not_created_or_repaired_by_preview(self):
        (self.ring / 'trustdb.gpg').unlink()
        before = {str(p.relative_to(self.ring)): p.read_bytes() for p in self.ring.rglob('*') if p.is_file()}
        result, report = self.revoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(report['keyring_may_have_changed']); self.assertFalse(report['config_may_have_changed'])
        self.assertFalse((self.ring / 'trustdb.gpg').exists())
        self.assertEqual(before, {str(p.relative_to(self.ring)): p.read_bytes() for p in self.ring.rglob('*') if p.is_file()})
        self.assertEqual(self.main.read_bytes(), self.original_main)

    def test_apply_quarantines_revokes_preserves_base_and_repeats_without_mutation(self):
        result, report = self.revoke(True)
        self.assertEqual(result.returncode, 0, report)
        self.assertEqual(report['status'], 'quarantined-revoked')
        self.assertTrue(report['revocation_confirmed']); self.assertFalse(report['repository_enabled'])
        self.assertTrue(self.is_revoked()); self.preserved(False)
        self.assertNotEqual(T.effective_configuration(self.target).returncode, 0)
        verified = T.command(['gpg', '--no-options', '--homedir', self.ring, '--batch', '--status-fd=1', '--verify', self.signature, self.message])
        self.assertIn('[GNUPG:] REVKEYSIG ', verified.stdout.decode())
        result, report = self.revoke(True)
        self.assertEqual(result.returncode, 0, report); self.assertEqual(report['status'], 'unchanged')
        self.assertFalse(report['keyring_may_have_changed']); self.assertFalse(report['config_may_have_changed'])
        self.preserved(False)
        result, report = self.cli(apply=True)
        self.assertNotEqual(result.returncode, 0, report)
        self.assertNotIn(T.enrollment.BLOCK, self.main.read_bytes())

    def test_exact_primary_certificate_and_original_bytes_are_required(self):
        for expected, pin in ((self.base_fpr, self.pin), (self.fpr, 'a' * 64)):
            result, report = self.revoke(True, expected, pin)
            self.assertNotEqual(result.returncode, 0); self.assertFalse(report['config_may_have_changed'])
        self.key.write_bytes(self.public + b'\n')
        result, report = self.revoke(True)
        self.assertNotEqual(result.returncode, 0); self.assertFalse(report['keyring_may_have_changed'])
        self.preserved()

    def test_nonrevoking_foreign_multiple_secret_and_tampered_input_refused(self):
        tampered = bytearray(self.revoked_public)
        for tag, body, encoded in R.packets(self.revoked_public):
            if tag == 2 and body[1] == 0x20:
                offset = self.revoked_public.index(encoded)
                tampered[offset + len(encoded) - 1] ^= 1
                break
        for raw in (self.public, self.base_export, self.revoked_public + self.base_export,
                    self.secret, self.revoked_public + self.secret, bytes(tampered), self.revocation.read_bytes(),
                    self.public + self.foreign_revocation_packet, self.revoked_public + self.foreign_revocation_packet):
            with self.subTest(size=len(raw)):
                self.updated.write_bytes(raw)
                result, report = self.revoke(True)
                self.assertNotEqual(result.returncode, 0, report)
                self.assertFalse(report['keyring_may_have_changed']); self.assertFalse(report['config_may_have_changed'])
                self.assertEqual(T.gpg(self.ring, '--export', self.fpr), self.original_current)
        self.preserved()

    def test_complete_armored_revoked_export_is_supported(self):
        self.updated.write_bytes(self.revoked_armor)
        result, report = self.revoke(True)
        self.assertEqual(result.returncode, 0, report); self.assertTrue(self.is_revoked()); self.preserved(False)

    def test_already_revoked_current_is_quarantined_without_trust_import(self):
        T.gpg(self.ring, '--import', self.updated)
        result, report = self.revoke(True)
        self.assertEqual(result.returncode, 0, report); self.assertTrue(report['current_primary_already_revoked'])
        self.assertTrue(report['revocation_confirmed']); self.assertFalse(report['keyring_may_have_changed'])
        self.preserved(False)

    def test_foreign_lock_and_unsafe_input_are_preserved(self):
        lock = self.target / 'var/lib/pacman/db.lck'; lock.write_bytes(b'foreign\n')
        result, report = self.revoke(True)
        self.assertNotEqual(result.returncode, 0); self.assertEqual(lock.read_bytes(), b'foreign\n')
        self.assertFalse(report['keyring_may_have_changed']); lock.unlink()
        for mode in (0o666,):
            self.updated.chmod(mode)
            result, report = self.revoke(True)
            self.assertNotEqual(result.returncode, 0); self.assertFalse(report['config_may_have_changed'])
        self.updated.chmod(0o600)
        linked = self.updated.with_name('linked'); os.link(self.updated, linked)
        result, report = self.revoke(True)
        self.assertNotEqual(result.returncode, 0); linked.unlink()
        self.updated.unlink(); self.updated.symlink_to(self.key)
        result, report = self.revoke(True)
        self.assertNotEqual(result.returncode, 0); self.preserved()

    def test_post_rename_flush_failure_leaves_disabled_record_and_retry_completes(self):
        result, report = self.inject("def fail(path): raise OSError('injected directory flush failure')\nm.E.sync=fail\n")
        self.assertNotEqual(result.returncode, 0); self.assertTrue(report['config_may_have_changed'])
        self.assertFalse(report['config_changed']); self.assertFalse(report['repository_enabled'])
        self.assertFalse(report['keyring_may_have_changed']); self.assertFalse(self.is_revoked()); self.preserved(False)
        result, report = self.revoke(True)
        self.assertEqual(result.returncode, 0, report); self.assertTrue(self.is_revoked()); self.preserved(False)

    def test_failed_import_keeps_repository_disabled_and_retries(self):
        result, report = self.inject('''original=m.E.run
def fail(argv,home):
 if argv[0]=='/usr/bin/pacman-key' and '--add' in argv: raise m.E.Error('injected import refusal')
 return original(argv,home)
m.E.run=fail
''')
        self.assertNotEqual(result.returncode, 0); self.assertTrue(report['config_changed'])
        self.assertFalse(report['repository_enabled']); self.assertTrue(report['keyring_may_have_changed'])
        self.assertFalse(report['revocation_confirmed']); self.assertFalse(self.is_revoked()); self.preserved(False)
        result, report = self.revoke(True)
        self.assertEqual(result.returncode, 0, report); self.assertTrue(self.is_revoked()); self.preserved(False)

    def test_actual_import_then_failure_reports_uncertainty_and_can_resume(self):
        result, report = self.inject('''original=m.E.run
def fail(argv,home):
 result=original(argv,home)
 if argv[0]=='/usr/bin/pacman-key' and '--add' in argv: raise m.E.Error('injected failure after actual public import')
 return result
m.E.run=fail
''')
        self.assertNotEqual(result.returncode, 0); self.assertTrue(report['keyring_may_have_changed'])
        self.assertFalse(report['revocation_confirmed']); self.assertTrue(self.is_revoked()); self.preserved(False)
        result, report = self.revoke(True)
        self.assertEqual(result.returncode, 0, report); self.assertEqual(report['status'], 'unchanged')
        self.assertTrue(report['revocation_confirmed']); self.assertFalse(report['keyring_may_have_changed'])

    def test_concurrent_configuration_edit_stops_before_any_revocation_import(self):
        result, report = self.inject('''original=m.E.replace
def changed(path,*args):
 path.write_bytes(path.read_bytes()+b'# concurrent operator edit\\n')
 return original(path,*args)
m.E.replace=changed
''')
        self.assertNotEqual(result.returncode, 0); self.assertFalse(report['keyring_may_have_changed'])
        self.assertTrue(report['repository_enabled']); self.assertFalse(self.is_revoked())
        self.assertEqual(self.main.read_bytes(), self.original_main + b'# concurrent operator edit\n')
        self.assertEqual(self.include.read_bytes(), self.original_include)


if __name__ == '__main__':
    unittest.main(verbosity=2)
