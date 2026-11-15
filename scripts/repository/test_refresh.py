#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real same-primary GPG renewal in disposable mapped roots; never host trust."""
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import time
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('refresh_enrollment_controls', HERE / 'test_enroll.py')
T = importlib.util.module_from_spec(spec); spec.loader.exec_module(T)


class RefreshTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        T.EnrollmentTests.setUpClass.__func__(cls)
        cls.addClassCleanup(T.EnrollmentTests.tearDownClass.__func__, cls)
        T.gpg(cls.project, '--quick-set-expire', cls.fpr, '2d')
        T.gpg(cls.project, '--quick-add-key', cls.fpr, 'ed25519', 'sign', '2d')
        cls.renewed = T.gpg(cls.project, '--export', cls.fpr)
        rows = T.gpg(cls.project, '--with-colons', '--fingerprint', '--list-keys').decode().splitlines()
        cls.sub_fpr = [line.split(':')[9] for line in rows if line.startswith('fpr:')][-1]
        cls.message = cls.root / 'message'; cls.message.write_bytes(b'Disposable certificate renewal test, not a release.\n')
        cls.signature = cls.root / 'message.sig'
        T.gpg(cls.project, '--local-user', cls.sub_fpr + '!', '--output', cls.signature, '--detach-sign', cls.message)
        cls.expired = cls.root / 'expired'
        shutil.copytree(cls.project, cls.expired, ignore=shutil.ignore_patterns('S.*'))
        cls.addClassCleanup(T.command, ['gpgconf', '--homedir', cls.expired, '--kill', 'all'])
        T.gpg(cls.expired, '--quick-set-expire', cls.fpr, 'seconds=1')
        cls.expired_public = T.gpg(cls.expired, '--export', cls.fpr)
        text = (cls.project / 'openpgp-revocs.d' / (cls.fpr + '.rev')).read_text()
        cls.revocation = text[text.index(':-----BEGIN PGP PUBLIC KEY BLOCK-----'):].replace(':-----BEGIN', '-----BEGIN', 1)
        cls.revoked = cls.root / 'revoked'; cls.revoked.mkdir(mode=0o700)
        cls.addClassCleanup(T.command, ['gpgconf', '--homedir', cls.revoked, '--kill', 'all'])
        path = cls.root / 'revocation.asc'; path.write_text(cls.revocation)
        public = cls.root / 'renewed.gpg'; public.write_bytes(cls.renewed)
        T.gpg(cls.revoked, '--import', public); T.gpg(cls.revoked, '--import', path)
        cls.revoked_public = T.gpg(cls.revoked, '--export', cls.fpr)
        expiry = int(next(line.split(':')[6] for line in T.gpg(cls.expired, '--with-colons', '--list-keys').decode().splitlines() if line.startswith('pub:')))
        deadline = time.monotonic() + 5
        while time.time() <= expiry:
            if time.monotonic() >= deadline:raise RuntimeError('disposable expiry fixture exceeded real-clock deadline')
            time.sleep(0.05)

    cli = T.EnrollmentTests.cli
    enable = T.EnrollmentTests.enable

    def setUp(self):
        T.EnrollmentTests.setUp(self)
        self.enable()
        self.include = self.target / T.enrollment.INCLUDE.lstrip('/')
        self.before_include = self.include.read_bytes(); self.before_main = self.main.read_bytes()
        self.expected = T.enrollment.sha(self.public)
        self.candidate = self.target / 'etc/pacman.d/renewed.gpg'
        self.candidate.write_bytes(self.renewed); self.candidate.chmod(0o600)
        self.before_base = T.gpg(self.ring, '--export', self.base_fpr)

    def refresh(self, apply=False, expected=None, fingerprint=None):
        argv = ['unshare', '--user', '--map-root-user', '--', sys.executable, '-I', '-B', HERE / 'refresh.py',
                '--root', self.target, '--fingerprint', fingerprint or self.fpr,
                '--expected-current-certificate-sha256', expected or self.expected, '--current-public-key', self.key, '--public-key', self.candidate]
        if apply:argv.append('--apply')
        result = T.command(argv)
        self.assertTrue(result.stdout, result.stderr.decode())
        return result, json.loads(result.stdout)

    def inject(self, code):
        program = '''import importlib.util,json,sys
from pathlib import Path
s=importlib.util.spec_from_file_location('refresh',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
root,key,oldkey,fpr,pin=Path(sys.argv[2]),Path(sys.argv[3]),Path(sys.argv[4]),sys.argv[5],sys.argv[6]
''' + code + '''
try:print(json.dumps(m.execute(root,fpr,pin,oldkey,key,True)))
except BaseException as e:
 print(json.dumps(getattr(e,'refresh_result',{'error':str(e)})));sys.exit(1)
'''
        result = T.command(['unshare', '--user', '--map-root-user', '--', sys.executable, '-I', '-B', '-c', program,
                            HERE / 'refresh.py', self.target, self.candidate, self.key, self.fpr, self.expected])
        self.assertTrue(result.stdout, result.stderr.decode())
        return result, json.loads(result.stdout)

    def preserved(self, include=True):
        self.assertEqual(self.main.read_bytes(), self.before_main)
        self.assertEqual(T.gpg(self.ring, '--export', self.base_fpr), self.before_base)
        if include:self.assertEqual(self.include.read_bytes(), self.before_include)
        self.assertFalse((self.target / 'var/lib/pacman/db.lck').exists())

    def test_preview_preserves_all_keyring_and_configuration_bytes(self):
        before = {str(p):p.read_bytes() for p in self.ring.rglob('*') if p.is_file()}
        result, report = self.refresh()
        self.assertEqual(result.returncode, 0, report); self.assertEqual(report['status'], 'preview')
        self.assertFalse(report['keyring_may_have_changed']); self.assertFalse(report['config_may_have_changed'])
        self.assertEqual(before, {str(p):p.read_bytes() for p in self.ring.rglob('*') if p.is_file()}); self.preserved()

    def test_real_refresh_new_subkey_signature_trust_stale_cas_and_noop(self):
        verify = ['gpg', '--no-options', '--homedir', self.ring, '--batch', '--no-auto-key-retrieve', '--status-fd=1', '--verify', self.signature, self.message]
        self.assertNotEqual(T.command(verify).returncode, 0)
        result, report = self.refresh(True)
        self.assertEqual(result.returncode, 0, report); self.assertEqual(report['status'], 'refreshed')
        self.assertTrue(report['config_changed']); self.assertFalse(report['local_signing_requested'])
        new_pin = T.enrollment.sha(self.renewed)
        self.assertEqual(self.include.read_bytes(), T.enrollment.config(T.URL, self.fpr, new_pin))
        checked = T.command(verify); self.assertEqual(checked.returncode, 0, checked.stderr.decode())
        self.assertIn('[GNUPG:] VALIDSIG ' + self.sub_fpr + ' ', checked.stdout.decode())
        self.assertIn('[GNUPG:] TRUST_FULLY', checked.stdout.decode())
        policy = T.effective_configuration(self.target); self.assertEqual(policy.returncode, 0, policy.stderr.decode())
        for token in ('PackageRequired', 'DatabaseRequired', 'PackageTrustedOnly', 'DatabaseTrustedOnly', T.URL):self.assertIn(token, policy.stdout.decode())
        result, report = self.refresh(True)
        self.assertNotEqual(result.returncode, 0); self.assertFalse(report['keyring_may_have_changed'])
        self.key.write_bytes(self.renewed)
        result, report = self.refresh(True, expected=new_pin)
        self.assertEqual(result.returncode, 0, report); self.assertEqual(report['status'], 'unchanged')
        self.assertFalse(report['keyring_may_have_changed']); self.assertFalse(report['config_changed']); self.preserved(False)

    def test_wrong_current_fingerprint_or_certificate_cas(self):
        for expected, fingerprint in (('0'*64, self.fpr), (self.expected, self.base_fpr)):
            result, report = self.refresh(True, expected, fingerprint)
            self.assertNotEqual(result.returncode, 0); self.assertFalse(report['keyring_may_have_changed']); self.preserved()

    def test_other_primary_secret_multiple_expired_revoked_inputs_refused(self):
        secret = T.gpg(self.project, '--export-secret-keys', self.fpr)
        for data in (self.base_export, secret, self.renewed + self.base_export, self.expired_public, self.revoked_public):
            with self.subTest(bytes=len(data)):
                self.candidate.write_bytes(data); result, report = self.refresh(True)
                self.assertNotEqual(result.returncode, 0, report); self.assertFalse(report['keyring_may_have_changed']); self.preserved()

    def test_encoding_only_change_is_not_certificate_renewal(self):
        armor = T.command(['gpg', '--no-options', '--homedir', self.project, '--batch', '--enarmor'], input=self.public)
        self.assertEqual(armor.returncode, 0, armor.stderr.decode())
        self.candidate.write_bytes(armor.stdout.replace(b'PGP ARMORED FILE', b'PGP PUBLIC KEY BLOCK'))
        result, report = self.refresh(True)
        self.assertNotEqual(result.returncode, 0); self.assertIn('no effective certificate update', report['error']); self.preserved()

    def test_older_export_cannot_remove_known_new_signing_subkey(self):
        T.gpg(self.ring, '--import', self.candidate)
        self.candidate.write_bytes(self.public)
        result, report = self.refresh(True)
        self.assertNotEqual(result.returncode, 0); self.assertIn('omits effective current public material', report['error'])
        self.assertFalse(report['keyring_may_have_changed']); self.preserved()

    def test_retained_current_certificate_must_match_exact_hash(self):
        self.key.write_bytes(self.renewed)
        result, report = self.refresh(True)
        self.assertNotEqual(result.returncode, 0); self.assertIn('retained current public certificate hash differs', report['error'])
        self.assertFalse(report['keyring_may_have_changed']); self.preserved()

    def test_known_primary_revocation_cannot_be_hidden(self):
        path = self.case / 'revoke.asc'; path.write_text(self.revocation); T.gpg(self.ring, '--import', path)
        result, report = self.refresh(True)
        self.assertNotEqual(result.returncode, 0); self.assertFalse(report['keyring_may_have_changed']); self.preserved()

    def test_untrusted_or_disabled_current_repository_refused(self):
        T.gpg(self.ring, '--yes', '--delete-key', self.fpr)
        result, report = self.refresh(True)
        self.assertNotEqual(result.returncode, 0); self.assertFalse(report['keyring_may_have_changed'])
        self.main.write_bytes(self.before_main.replace(T.enrollment.BLOCK, b''))
        result, report = self.refresh(True)
        self.assertNotEqual(result.returncode, 0); self.assertFalse(report['keyring_may_have_changed'])

    def test_foreign_lock_and_unsafe_certificate_refused(self):
        lock = self.target / 'var/lib/pacman/db.lck'; lock.write_bytes(b'foreign\n')
        result, report = self.refresh(True)
        self.assertNotEqual(result.returncode, 0); self.assertFalse(report['keyring_may_have_changed']); self.assertEqual(lock.read_bytes(), b'foreign\n')
        lock.unlink()
        self.candidate.chmod(0o666); result, report = self.refresh(True)
        self.assertNotEqual(result.returncode, 0); self.assertFalse(report['keyring_may_have_changed']); self.preserved()

    def test_changed_input_inside_lock_refused_before_import(self):
        result, report = self.inject('''from contextlib import contextmanager
original=m.E.lock
@contextmanager
def change(selection):
 with original(selection):
  key.write_bytes(key.read_bytes()+b'\\n')
  yield
m.E.lock=change
''')
        self.assertNotEqual(result.returncode, 0); self.assertFalse(report['keyring_may_have_changed']); self.preserved()

    def test_effective_keyring_change_inside_lock_refused_before_import(self):
        result, report = self.inject('''from contextlib import contextmanager
original=m.E.lock
@contextmanager
def change(selection):
 with original(selection):
  m.E.run(['/usr/bin/gpg','--homedir',str(root/'etc/pacman.d/gnupg'),'--batch','--import',str(key)],key.parent)
  yield
m.E.lock=change
''')
        self.assertNotEqual(result.returncode, 0); self.assertIn('effective current certificate changed', report['error'])
        self.assertFalse(report['keyring_may_have_changed']); self.preserved()

    def test_import_failure_and_post_import_config_failure_are_honest(self):
        result, report = self.inject('''original=m.E.run
def fail(argv,home):
 if '--add'in argv:raise m.E.Error('injected import failure')
 return original(argv,home)
m.E.run=fail
''')
        self.assertNotEqual(result.returncode, 0); self.assertTrue(report['keyring_may_have_changed']); self.preserved()
        result, report = self.inject("def fail(*args):raise OSError('injected include replacement failure')\nm.E.replace=fail\n")
        self.assertNotEqual(result.returncode, 0); self.assertTrue(report['keyring_may_have_changed']); self.assertTrue(report['config_may_have_changed']); self.preserved()
        self.assertEqual(T.command(['gpg','--homedir',self.ring,'--batch','--verify',self.signature,self.message]).returncode,0)
        result, report = self.refresh(True)
        self.assertEqual(result.returncode, 0, report); self.preserved(False)

    def test_include_cas_preserves_concurrent_edit_after_import(self):
        result, report = self.inject("""original=m.E.replace
def change(path,*args):
 path.write_bytes(path.read_bytes()+b'# concurrent include edit\\n')
 return original(path,*args)
m.E.replace=change
""")
        self.assertNotEqual(result.returncode, 0); self.assertTrue(report['keyring_may_have_changed'])
        self.assertTrue(report['config_may_have_changed']); self.assertFalse(report['config_changed'])
        self.assertIn('configuration changed before atomic edit', report['error'])
        self.assertEqual(self.include.read_bytes(), self.before_include+b'# concurrent include edit\n')
        self.preserved(False)

    def test_post_rename_failure_reports_uncertainty_and_requires_new_cas(self):
        result, report = self.inject("def fail(*args):raise OSError('injected post-rename fsync failure')\nm.E.sync=fail\n")
        self.assertNotEqual(result.returncode, 0); self.assertTrue(report['config_may_have_changed']); self.assertFalse(report['config_changed'])
        self.assertEqual(self.include.read_bytes(), T.enrollment.config(T.URL, self.fpr, T.enrollment.sha(self.renewed)))
        result, report = self.refresh(True)
        self.assertNotEqual(result.returncode, 0); self.assertFalse(report['keyring_may_have_changed']); self.preserved(False)


if __name__ == '__main__':unittest.main()
