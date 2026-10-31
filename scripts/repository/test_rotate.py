#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real planned-key rotation in disposable mapped-root fixtures; never host trust."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('enrollment_controls', HERE / 'test_enroll.py')
T = importlib.util.module_from_spec(spec); spec.loader.exec_module(T)


class RotationTests(T.EnrollmentTests):
    @classmethod
    def setUpClass(cls):
        # Inherit and rerun the original enrollment controls with unchanged source.
        super().setUpClass()
        cls.successor = cls.root / 'successor'; cls.successor.mkdir(mode=0o700)
        cls.expired = cls.root / 'expired'; cls.expired.mkdir(mode=0o700)
        cls.revoked = cls.root / 'revoked'; cls.revoked.mkdir(mode=0o700)
        for home, label, expiry in ((cls.successor, 'SUCCESSOR', '7d'), (cls.expired, 'EXPIRED', 'seconds=1'), (cls.revoked, 'REVOKED', '7d')):
            T.gpg(home, '--quick-generate-key', 'DISPOSABLE ' + label + ' TEST <rotation@example.invalid>', 'ed25519', 'sign', expiry)
        cls.new_fpr = T.fingerprint(cls.successor)
        cls.new_public = T.gpg(cls.successor, '--export', cls.new_fpr)
        cls.expired_fpr = T.fingerprint(cls.expired)
        cls.expired_public = T.gpg(cls.expired, '--export', cls.expired_fpr)
        cls.revoked_fpr = T.fingerprint(cls.revoked)
        revocation = (cls.revoked / 'openpgp-revocs.d' / (cls.revoked_fpr + '.rev')).read_text()
        revocation = revocation[revocation.index(':-----BEGIN PGP PUBLIC KEY BLOCK-----'):].replace(':-----BEGIN', '-----BEGIN', 1)
        path = cls.revoked / 'revoke.asc'; path.write_text(revocation)
        T.gpg(cls.revoked, '--import', str(path))
        cls.revoked_public = T.gpg(cls.revoked, '--export', cls.revoked_fpr)
        cls.message = cls.root / 'message'; cls.message.write_bytes(b'Disposable rotation control, not a repository release.\n')
        cls.signature = cls.root / 'message.sig'
        T.gpg(cls.successor, '--local-user', cls.new_fpr, '--output', str(cls.signature), '--detach-sign', str(cls.message))
        # Expire naturally; verification uses the real current clock.
        while int(time.time()) <= int(next(line.split(':')[6] for line in T.gpg(cls.expired, '--with-colons', '--list-keys').decode().splitlines() if line.startswith('pub:'))):
            time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        for home in (cls.successor, cls.expired, cls.revoked):
            T.command(['gpgconf', '--homedir', home, '--kill', 'all'])
        super().tearDownClass()

    def prepare_rotation(self):
        self.enable()
        self.include = self.target / T.enrollment.INCLUDE.lstrip('/')
        self.old_include = self.include.read_bytes()
        self.old_main = self.main.read_bytes() + b'\n# independently owned configuration\n'
        self.main.write_bytes(self.old_main)
        self.old_export = T.gpg(self.ring, '--export', self.fpr)
        self.new_key = self.target / 'etc/pacman.d/successor-public.gpg'
        self.new_key.write_bytes(self.new_public); self.new_key.chmod(0o600)

    def rotate(self, apply=False, expected=None, fingerprint=None, key=None):
        argv = ['unshare', '--user', '--map-root-user', '--', sys.executable, '-I', '-B', HERE / 'rotate.py', '--root', self.target]
        if apply: argv += ['--apply']
        argv += ['--expected-current-fingerprint', expected or self.fpr, '--public-key', key or self.new_key,
                 '--fingerprint', fingerprint or self.new_fpr]
        result = T.command(argv)
        self.assertTrue(result.stdout, result.stderr.decode())
        return result, json.loads(result.stdout)

    def inject_rotation(self, code):
        program = '''import importlib.util,json,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('rotate',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
root,key,old,new=Path(sys.argv[2]),Path(sys.argv[3]),sys.argv[4],sys.argv[5]
''' + code + '''
try: print(json.dumps(m.execute(root,old,key,new,True)))
except BaseException as error:
 print(json.dumps(getattr(error,'rotation_result',{'error':str(error)})));sys.exit(1)
'''
        result = T.command(['unshare', '--user', '--map-root-user', '--', sys.executable, '-I', '-B', '-c', program,
                            HERE / 'rotate.py', self.target, self.new_key, self.fpr, self.new_fpr])
        self.assertTrue(result.stdout, result.stderr.decode())
        return result, json.loads(result.stdout)

    def preserved(self):
        self.assertEqual(self.main.read_bytes(), self.old_main)
        self.assertEqual(T.gpg(self.ring, '--export', self.base_fpr), self.base_export)
        self.assertEqual(T.gpg(self.ring, '--export', self.fpr), self.old_export)
        self.assertFalse((self.target / 'var/lib/pacman/db.lck').exists())

    def test_rotation_preview_is_read_only_including_keyring_bytes(self):
        self.prepare_rotation()
        before = {str(p.relative_to(self.ring)): p.read_bytes() for p in self.ring.rglob('*') if p.is_file()}
        result, body = self.rotate()
        self.assertEqual(result.returncode, 0, body); self.assertEqual(body['status'], 'preview')
        self.assertFalse(body['config_may_have_changed']); self.assertFalse(body['keyring_may_have_changed'])
        after = {str(p.relative_to(self.ring)): p.read_bytes() for p in self.ring.rglob('*') if p.is_file()}
        self.assertEqual(before, after); self.assertEqual(self.include.read_bytes(), self.old_include)
        self.preserved()

    def test_real_rotation_signature_policy_current_cas_and_explicit_noop(self):
        self.prepare_rotation()
        result, body = self.rotate(True)
        self.assertEqual(result.returncode, 0, body); self.assertEqual(body['status'], 'rotated')
        self.assertTrue(body['config_changed']); self.assertTrue(body['keyring_may_have_changed'])
        self.assertEqual(self.include.read_bytes(), T.enrollment.config(T.URL, self.new_fpr, T.enrollment.sha(self.new_public)))
        verify = T.command(['gpg', '--no-options', '--homedir', self.ring, '--batch', '--no-auto-key-retrieve',
                            '--status-fd=1', '--verify', self.signature, self.message])
        self.assertEqual(verify.returncode, 0, verify.stderr.decode())
        status = verify.stdout.decode().splitlines()
        self.assertEqual(len([line for line in status if line.startswith('[GNUPG:] VALIDSIG ' + self.new_fpr + ' ')]), 1)
        self.assertTrue(any(line.startswith('[GNUPG:] TRUST_FULLY') for line in status), status)
        bad = {'EXPKEYSIG', 'KEYEXPIRED', 'REVKEYSIG', 'KEYREVOKED', 'EXPSIG', 'SIGEXPIRED', 'BADSIG', 'ERRSIG', 'NO_PUBKEY'}
        self.assertFalse(any(len(line.split()) > 1 and line.split()[1] in bad for line in status), status)
        query = T.effective_configuration(self.target)
        self.assertEqual(query.returncode, 0, query.stderr.decode())
        for token in ('PackageRequired', 'DatabaseRequired', 'PackageTrustedOnly', 'DatabaseTrustedOnly', T.URL):
            self.assertIn(token, query.stdout.decode())
        self.assertNotIn('Optional', query.stdout.decode()); self.preserved()
        committed = self.include.read_bytes()
        result, body = self.rotate(True)  # stale expected-current must not become an implicit no-op
        self.assertNotEqual(result.returncode, 0); self.assertFalse(body['keyring_may_have_changed'])
        self.assertEqual(self.include.read_bytes(), committed)
        result, body = self.rotate(True, expected=self.new_fpr)
        self.assertEqual(result.returncode, 0, body); self.assertEqual(body['status'], 'unchanged')
        self.assertFalse(body['config_changed']); self.assertFalse(body['keyring_may_have_changed']); self.preserved()

    def test_rotation_requires_exact_enabled_current_and_trusted_key(self):
        self.prepare_rotation()
        result, body = self.rotate(True, expected=self.base_fpr)
        self.assertNotEqual(result.returncode, 0); self.assertFalse(body['keyring_may_have_changed'])
        T.gpg(self.ring, '--yes', '--delete-key', self.fpr)
        result, body = self.rotate(True)
        self.assertNotEqual(result.returncode, 0); self.assertFalse(body['keyring_may_have_changed'])
        self.assertEqual(self.include.read_bytes(), self.old_include)
        self.main.write_bytes(self.old_main.replace(T.enrollment.BLOCK, b''))
        result, body = self.rotate(True)
        self.assertNotEqual(result.returncode, 0); self.assertFalse(body['keyring_may_have_changed'])

    def test_rotation_wrong_new_secret_expired_revoked_and_changed_same_primary_refused(self):
        self.prepare_rotation()
        cases = ((self.new_public, self.base_fpr), (T.gpg(self.successor, '--export-secret-keys', self.new_fpr), self.new_fpr),
                 (self.expired_public, self.expired_fpr), (self.revoked_public, self.revoked_fpr),
                 (self.public + b'\n', self.fpr))
        for data, fingerprint in cases:
            with self.subTest(fingerprint=fingerprint, size=len(data)):
                self.new_key.write_bytes(data)
                result, body = self.rotate(True, fingerprint=fingerprint)
                self.assertNotEqual(result.returncode, 0, body)
                self.assertFalse(body['keyring_may_have_changed']); self.assertEqual(self.include.read_bytes(), self.old_include)
        self.preserved()

    def test_rotation_existing_revocations_cannot_be_hidden_by_old_public_exports(self):
        self.prepare_rotation()
        for home, fingerprint in ((self.successor, self.new_fpr), (self.project, self.fpr)):
            with self.subTest(fingerprint=fingerprint):
                if fingerprint == self.new_fpr:
                    T.gpg(self.ring, '--import', str(self.new_key))
                text = (home/'openpgp-revocs.d'/(fingerprint+'.rev')).read_text()
                text = text[text.index(':-----BEGIN PGP PUBLIC KEY BLOCK-----'):].replace(':-----BEGIN', '-----BEGIN', 1)
                revocation = self.case/'revocation.asc'; revocation.write_text(text)
                T.gpg(self.ring, '--import', str(revocation))
                result, body = self.rotate(True)
                self.assertNotEqual(result.returncode, 0, body)
                self.assertEqual(self.include.read_bytes(), self.old_include)
                self.assertFalse(body['config_may_have_changed'])
                # An already-known successor revocation is found after add/sign; a revoked current key stops before either.
                self.assertEqual(body['keyring_may_have_changed'], fingerprint == self.new_fpr)
        self.assertEqual(self.main.read_bytes(), self.old_main)
        self.assertEqual(T.gpg(self.ring, '--export', self.base_fpr), self.base_export)

    def test_rotation_real_import_then_lsign_failure_retains_selection_and_retry(self):
        self.prepare_rotation()
        result, body = self.inject_rotation('''original=m.E.run
def fail(argv,home):
 if '--lsign-key' in argv:raise m.E.Error('injected local-sign failure after actual import')
 return original(argv,home)
m.E.run=fail
''')
        self.assertNotEqual(result.returncode, 0); self.assertTrue(body['keyring_may_have_changed'])
        self.assertFalse(body['config_may_have_changed']); self.assertEqual(self.include.read_bytes(), self.old_include)
        self.assertTrue(T.gpg(self.ring, '--export', self.new_fpr)); self.preserved()
        result, body = self.rotate(True)
        self.assertEqual(result.returncode, 0, body); self.preserved()

    def test_rotation_import_failure_preserves_active_selection(self):
        self.prepare_rotation()
        result, body = self.inject_rotation('''original=m.E.run
def fail(argv,home):
 if '--add' in argv:raise m.E.Error('injected import failure')
 return original(argv,home)
m.E.run=fail
''')
        self.assertNotEqual(result.returncode, 0); self.assertTrue(body['keyring_may_have_changed'])
        self.assertFalse(body['config_may_have_changed']); self.assertEqual(self.include.read_bytes(), self.old_include); self.preserved()

    def test_rotation_checks_successor_trust_before_selection(self):
        self.prepare_rotation()
        result, body = self.inject_rotation('''original=m.E.trusted
m.E.trusted=lambda ring,fpr,home: False if fpr==new else original(ring,fpr,home)
''')
        self.assertNotEqual(result.returncode, 0); self.assertTrue(body['keyring_may_have_changed'])
        self.assertFalse(body['config_may_have_changed']); self.assertEqual(self.include.read_bytes(), self.old_include); self.preserved()

    def test_rotation_changed_public_input_stops_before_import(self):
        self.prepare_rotation()
        result, body = self.inject_rotation('''original=m.E.inspect_key
def changed(path,*args):
 original(path,*args)
 if path.name=='operator-public.gpg':key.write_bytes(key.read_bytes()+b'\\n')
m.E.inspect_key=changed
''')
        self.assertNotEqual(result.returncode, 0); self.assertFalse(body['keyring_may_have_changed'])
        self.assertEqual(self.include.read_bytes(), self.old_include); self.preserved()

    def test_rotation_changed_main_after_trust_preserves_edit_and_old_selection(self):
        self.prepare_rotation()
        result, body = self.inject_rotation('''original=m.E.run
def changed(argv,home):
 answer=original(argv,home)
 if '--lsign-key' in argv:
  path=root/'etc/pacman.conf';path.write_bytes(path.read_bytes()+b'# concurrent edit\\n')
 return answer
m.E.run=changed
''')
        self.assertNotEqual(result.returncode, 0); self.assertTrue(body['keyring_may_have_changed'])
        self.assertFalse(body['config_may_have_changed']); self.assertEqual(self.include.read_bytes(), self.old_include)
        self.assertTrue(self.main.read_bytes().endswith(b'# concurrent edit\n'))

    def test_rotation_include_cas_does_not_overwrite_concurrent_bytes(self):
        self.prepare_rotation()
        result, body = self.inject_rotation('''original=m.E.replace
def changed(path,*args):
 path.write_bytes(path.read_bytes()+b'# concurrent include edit\\n')
 return original(path,*args)
m.E.replace=changed
''')
        self.assertNotEqual(result.returncode, 0); self.assertTrue(body['config_may_have_changed']); self.assertFalse(body['config_changed'])
        self.assertEqual(self.include.read_bytes(), self.old_include+b'# concurrent include edit\n')
        self.preserved()

    def test_rotation_post_rename_fsync_failure_reports_uncertainty(self):
        self.prepare_rotation()
        result, body = self.inject_rotation('''def fail(directory):raise OSError('injected post-rename directory fsync failure')
m.E.sync=fail
''')
        self.assertNotEqual(result.returncode, 0); self.assertTrue(body['config_may_have_changed']); self.assertFalse(body['config_changed'])
        self.assertEqual(self.include.read_bytes(), T.enrollment.config(T.URL, self.new_fpr, T.enrollment.sha(self.new_public)))
        result, body = self.rotate(True)
        self.assertNotEqual(result.returncode, 0); self.assertFalse(body['keyring_may_have_changed']); self.preserved()

    def test_rotation_foreign_lock_unsafe_input_and_edited_policy_refused(self):
        self.prepare_rotation()
        lock = self.target/'var/lib/pacman/db.lck'; lock.write_bytes(b'foreign\n')
        result, body = self.rotate(True)
        self.assertNotEqual(result.returncode, 0); self.assertFalse(body['keyring_may_have_changed'])
        self.assertEqual(lock.read_bytes(), b'foreign\n'); lock.unlink()
        self.new_key.chmod(0o666)
        result, body = self.rotate(True)
        self.assertNotEqual(result.returncode, 0); self.assertFalse(body['keyring_may_have_changed']); self.new_key.chmod(0o600)
        self.include.write_bytes(self.old_include.replace(b'DatabaseRequired', b'DatabaseOptional'))
        result, body = self.rotate(True)
        self.assertNotEqual(result.returncode, 0); self.assertIn(b'DatabaseOptional', self.include.read_bytes()); self.preserved()


if __name__ == '__main__':
    unittest.main(verbosity=2)
