#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Signed release handoffs and real local trust rotation in disposable mapped roots."""
import argparse
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import py_compile
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


m = module('repository_transition', HERE / 'transition.py')
F = module('enrollment_fixture', HERE / 'test_enroll.py')
R = module('release_fixture', HERE.parent / 'release/test_compare_releases.py')
R.c = m.T.c
R.fixture.r = m.T.r


class SourceLoadingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='repository-source-loader-')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.repository = root / 'repository'
        self.release = root / 'release'
        self.repository.mkdir()
        self.release.mkdir()
        prefix = patch.object(sys, 'pycache_prefix', None)
        prefix.start()
        self.addCleanup(prefix.stop)

    def write_source_update(self, path, source=b''):
        path.write_bytes(source + b'\nREVISION = "one"\n')
        original = path.stat()
        py_compile.compile(str(path), doraise=True, invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
        path.write_bytes(source + b'\nREVISION = "two"\n')
        os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))

    def test_rotation_loads_current_enrollment_source(self):
        entry = self.repository / 'rotate.py'
        shutil.copyfile(HERE / entry.name, entry)
        self.write_source_update(self.repository / 'enroll.py')
        rotation = module('test_rotation_source_update', entry)
        self.assertEqual(rotation.E.REVISION, 'two')

    def test_transition_loads_current_signing_and_rotation_sources(self):
        entry = self.repository / 'transition.py'
        shutil.copyfile(HERE / entry.name, entry)
        self.write_source_update(self.release / 'signing_transition.py')
        self.write_source_update(self.repository / 'rotate.py')
        transition = module('test_transition_source_update', entry)
        self.assertEqual((transition.T.REVISION, transition.load_rotation().REVISION), ('two', 'two'))

    def test_refresh_loads_current_rotation_and_enrollment_sources(self):
        entry = self.repository / 'refresh.py'
        shutil.copyfile(HERE / entry.name, entry)
        self.write_source_update(self.repository / 'rotate.py', (HERE / 'rotate.py').read_bytes())
        self.write_source_update(self.repository / 'enroll.py')
        refresh = module('test_refresh_source_update', entry)
        self.assertEqual((refresh.R.REVISION, refresh.E.REVISION), ('two', 'two'))

    def test_revoke_loads_current_enrollment_source(self):
        entry = self.repository / 'revoke.py'
        shutil.copyfile(HERE / entry.name, entry)
        self.write_source_update(self.repository / 'enroll.py')
        revoke = module('test_revoke_source_update', entry)
        self.assertEqual(revoke.E.REVISION, 'two')


class TransitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        F.EnrollmentTests.setUpClass.__func__(cls)
        for command in ('repo-add', 'bsdtar', 'vercmp'):
            if not shutil.which(command):raise unittest.SkipTest('release fixture dependency absent: ' + command)
        cls.home = cls.project
        cls.successor = cls.root / 'successor';cls.successor.mkdir(mode=0o700)
        F.gpg(cls.successor, '--quick-generate-key', 'SUCCESSOR TRANSITION TEST <next@example.invalid>',
              'ed25519', 'sign', '1d')
        cls.new_fpr = F.fingerprint(cls.successor)
        cls.new_public = F.gpg(cls.successor, '--export', cls.new_fpr)

    @classmethod
    def tearDownClass(cls):
        F.command(['gpgconf', '--homedir', cls.successor, '--kill', 'all'])
        F.EnrollmentTests.tearDownClass.__func__(cls)

    cli = F.EnrollmentTests.cli
    enable = F.EnrollmentTests.enable
    put = R.ComparisonTests.put
    ref = R.ComparisonTests.ref
    save_spec = R.ComparisonTests.save_spec
    bundle = R.ComparisonTests.bundle

    def setUp(self):
        F.EnrollmentTests.setUp(self)
        self.enable()
        self.include = self.target / F.enrollment.INCLUDE.lstrip('/')
        self.old_include, self.old_main = self.include.read_bytes(), self.main.read_bytes()
        self.old_export = F.gpg(self.ring, '--export', self.fpr)
        R.ComparisonTests.setUp(self)
        self.release_spec['repo_name'] = 'cachy-asahi'
        self.key, self.env = self.fpr, m.T.r.gpg_env(self.project, self.root)
        self.before = self.bundle('before', [('fixture', '1-1', b'before')])
        self.key, self.env = self.new_fpr, m.T.r.gpg_env(self.successor, self.root)
        self.after = self.bundle('after', [('fixture', '2-1', b'after')])
        self.old_cert, self.new_cert = self.base / 'old.asc', self.base / 'new.asc'
        self.old_cert.write_bytes(self.public);self.new_cert.write_bytes(self.new_public)
        self.handoff = self.base / 'transition'
        now = datetime.now(timezone.utc).replace(microsecond=0)
        stamp = lambda when: when.isoformat().replace('+00:00', 'Z')
        self.as_of = stamp(now)
        self.args = argparse.Namespace(before=self.before, after=self.after, old_key=self.fpr, new_key=self.new_fpr,
            old_certificate=self.old_cert, new_certificate=self.new_cert, old_gpg_home=self.project,
            new_gpg_home=self.successor, output=self.handoff,
            not_before=stamp(now - timedelta(minutes=1)), not_after=stamp(now + timedelta(hours=1)), as_of=self.as_of)
        m.T.create(self.args)

    def bridge(self, apply=False, extra=()):
        args = ['unshare', '--user', '--map-root-user', '--', sys.executable, '-I', '-B', HERE / 'transition.py',
                '--root', self.target, '--bundle', self.handoff, '--before', self.before, '--after', self.after,
                '--expected-current-fingerprint', self.fpr, '--fingerprint', self.new_fpr]
        if apply:args += ['--apply']
        value = F.command([*args, *extra])
        self.assertTrue(value.stdout, value.stderr.decode())
        return value, json.loads(value.stdout)

    def injected(self, code):
        program = '''import importlib.util,json,sys
from pathlib import Path
from contextlib import contextmanager
spec=importlib.util.spec_from_file_location('transition',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
root,bundle,before,after=map(Path,sys.argv[2:6]);old,new=sys.argv[6:8]
''' + code + '''
try: print(json.dumps(m.execute(root,bundle,before,after,old,new,apply=True)))
except BaseException as error:
 print(json.dumps(getattr(error,'transition_result',{'status':'failed','error':str(error)})));sys.exit(1)
'''
        value = F.command(['unshare', '--user', '--map-root-user', '--', sys.executable, '-I', '-B', '-c', program,
                           HERE / 'transition.py', self.target, self.handoff, self.before, self.after, self.fpr, self.new_fpr])
        self.assertTrue(value.stdout, value.stderr.decode())
        return value, json.loads(value.stdout)

    def preserved(self, include=True):
        self.assertEqual(self.main.read_bytes(), self.old_main)
        if include:self.assertEqual(self.include.read_bytes(), self.old_include)
        self.assertEqual(F.gpg(self.ring, '--export', self.fpr), self.old_export)
        self.assertEqual(F.gpg(self.ring, '--export', self.base_fpr), self.base_export)
        self.assertFalse((self.target / 'var/lib/pacman/db.lck').exists())
        self.assertFalse(list((self.target / 'var/lib/pacman').glob('.cachy-asahi-transition-*')))

    def test_preview_verifies_signed_handoff_without_config_or_keyring_changes(self):
        before = {str(p.relative_to(self.ring)):p.read_bytes() for p in self.ring.rglob('*') if p.is_file()}
        result, body = self.bridge()
        self.assertEqual(result.returncode, 0, body)
        self.assertEqual(body['status'], 'preview')
        self.assertEqual(body['transition_sha256'], m.T.digest((self.handoff / 'transition.json').read_bytes()))
        self.assertFalse(body['keyring_may_have_changed']);self.assertFalse(body['config_changed'])
        self.assertEqual({str(p.relative_to(self.ring)):p.read_bytes() for p in self.ring.rglob('*') if p.is_file()}, before)
        self.preserved()

    def test_real_apply_trusts_successor_preserves_old_trust_url_and_stale_current_refuses(self):
        result, body = self.bridge(True)
        self.assertEqual(result.returncode, 0, body)
        self.assertEqual(body['status'], 'rotated')
        self.assertTrue(body['config_changed']);self.assertTrue(body['keyring_may_have_changed'])
        self.assertTrue(body['old_trust_retained']);self.assertTrue(body['snapshot_url_retained'])
        self.assertFalse(body['snapshot_upgrade_accepted']);self.assertFalse(body['stable_eligibility_checked'])
        self.assertEqual(self.include.read_bytes(), F.enrollment.config(F.URL, self.new_fpr, F.enrollment.sha(self.new_public)))
        verify = F.command(['gpg', '--no-options', '--homedir', self.ring, '--batch', '--no-auto-key-retrieve',
                            '--status-fd=1', '--verify', self.after / 'release.json.sig', self.after / 'release.json'])
        self.assertEqual(verify.returncode, 0, verify.stderr.decode())
        self.assertIn('[GNUPG:] TRUST_FULLY', verify.stdout.decode())
        self.assertIn('[GNUPG:] VALIDSIG ' + self.new_fpr + ' ', verify.stdout.decode())
        query = F.effective_configuration(self.target)
        self.assertEqual(query.returncode, 0, query.stderr.decode())
        for token in (F.URL, 'PackageRequired', 'DatabaseRequired', 'PackageTrustedOnly', 'DatabaseTrustedOnly'):
            self.assertIn(token, query.stdout.decode())
        self.preserved(include=False)
        selected = self.include.read_bytes()
        result, body = self.bridge(True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(body['keyring_may_have_changed']);self.assertEqual(self.include.read_bytes(), selected)

    def test_exact_old_certificate_hash_and_expected_primary_required(self):
        self.include.write_bytes(self.old_include.replace(F.enrollment.sha(self.public).encode(), b'0' * 64))
        result, body = self.bridge(True)
        self.assertNotEqual(result.returncode, 0);self.assertIn('signed predecessor', body['error'])
        self.assertFalse(body['keyring_may_have_changed'])
        self.include.write_bytes(self.old_include)
        result, body = self.bridge(True, ['--expected-current-fingerprint', self.base_fpr])
        self.assertNotEqual(result.returncode, 0);self.assertFalse(body['keyring_may_have_changed'])
        self.preserved()

    def test_tampered_transition_release_or_wrong_successor_refused_before_import(self):
        for path in (self.handoff / 'new-public.asc', self.handoff / 'old.sig', self.after / 'base.json'):
            raw = path.read_bytes();path.write_bytes(raw + b'changed')
            result, body = self.bridge(True)
            self.assertNotEqual(result.returncode, 0);self.assertFalse(body['keyring_may_have_changed'])
            path.write_bytes(raw)
        result, body = self.bridge(True, ['--fingerprint', self.base_fpr])
        self.assertNotEqual(result.returncode, 0);self.assertFalse(body['keyring_may_have_changed'])
        self.preserved()

    def test_unsafe_retained_files_directories_aliases_and_external_ancestors_refused(self):
        for path in (self.handoff / 'new-public.asc', self.before / 'release.json', self.handoff):
            original = path.stat().st_mode & 0o777
            path.chmod(original | 0o022)
            result, body = self.bridge(True)
            self.assertNotEqual(result.returncode, 0);self.assertFalse(body['keyring_may_have_changed'])
            path.chmod(original)
        alias = self.base / 'alias';alias.symlink_to(self.handoff, target_is_directory=True)
        result, body = self.bridge(True, ['--bundle', alias])
        self.assertNotEqual(result.returncode, 0);self.assertFalse(body['keyring_may_have_changed'])
        self.base.chmod(0o777)
        result, body = self.bridge(True)
        self.assertNotEqual(result.returncode, 0);self.assertIn('ancestor', body['error'])
        self.base.chmod(0o700)
        os.link(self.handoff / 'new.sig', self.base / 'hardlinked.sig')
        result, body = self.bridge(True)
        self.assertNotEqual(result.returncode, 0);self.assertFalse(body['keyring_may_have_changed'])
        (self.base / 'hardlinked.sig').unlink();self.preserved()

    def test_current_transition_and_handoff_rechecked_after_original_lock_acquisition(self):
        result, body = self.injected('''original=m.load_rotation
def injected():
 r=original();lock=r.E.lock
 @contextmanager
 def changed(selection):
  with lock(selection):
   path=bundle/'transition.json';path.write_bytes(path.read_bytes()+b' ')
   yield
 r.E.lock=changed
 return r
m.load_rotation=injected
''')
        self.assertNotEqual(result.returncode, 0);self.assertFalse(body['keyring_may_have_changed'])
        self.assertIn('retained transition inputs changed', body['error']);self.preserved()

    def test_complete_verifier_runs_again_with_original_transaction_lock_held(self):
        result, body = self.injected('''original=m.T.verify;count=0
def checked(*args,**kwargs):
 global count
 count+=1
 if count==2:
  assert (root/'var/lib/pacman/db.lck').is_file()
  raise m.T.r.Error('injected complete locked verification refusal')
 return original(*args,**kwargs)
m.T.verify=checked
''')
        self.assertNotEqual(result.returncode, 0);self.assertFalse(body['keyring_may_have_changed'])
        self.assertIn('complete locked verification refusal', body['error']);self.preserved()

    def test_same_primary_current_description_change_under_lock_is_not_overwritten(self):
        result, body = self.injected('''original=m.load_rotation
def injected():
 r=original();lock=r.E.lock
 @contextmanager
 def changed(selection):
  with lock(selection):
   path=selection['include'];data=path.read_bytes();start=data.index(b'# key-sha256: ')+14
   path.write_bytes(data[:start]+b'0'*64+data[start+64:]);yield
 r.E.lock=changed
 return r
m.load_rotation=injected
''')
        self.assertNotEqual(result.returncode, 0);self.assertFalse(body['keyring_may_have_changed'])
        self.assertIn(b'# key-sha256: ' + b'0' * 64, self.include.read_bytes());self.preserved(include=False)

    def test_private_handoff_changed_between_verification_and_rotation_is_refused(self):
        result, body = self.injected('''with m.T.verifier((bundle/'new-public.asc').read_bytes(),new) as env:
 replacement=m.T.gpg(env['GNUPGHOME'],['--armor','--export',new])
original=m.load_rotation
def injected():
 r=original();read=r.E.read;count=0
 def changed(path,*args,**kwargs):
  nonlocal count
  answer=read(path,*args,**kwargs)
  if path.name=='successor-public.gpg':
   count+=1
   if count==2:path.write_bytes(replacement)
  return answer
 r.E.read=changed
 return r
m.load_rotation=injected
''')
        self.assertNotEqual(result.returncode, 0);self.assertFalse(body['keyring_may_have_changed'])
        self.assertIn('private successor handoff changed', body['error']);self.preserved()

    def test_historical_as_of_is_preview_only_and_real_time_apply_refuses_expired_overlap(self):
        shutil.rmtree(self.handoff)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        stamp = lambda when: when.isoformat().replace('+00:00', 'Z')
        self.args.not_before = stamp(now - timedelta(days=30))
        self.args.not_after = stamp(now - timedelta(days=1))
        self.args.as_of = stamp(now - timedelta(days=10))
        m.T.create(self.args)
        result, body = self.bridge(False, ['--as-of', self.args.as_of])
        self.assertEqual(result.returncode, 0, body)
        result, body = self.bridge(True, ['--as-of', self.args.as_of])
        self.assertNotEqual(result.returncode, 0);self.assertIn('diagnostic preview only', body['error'])
        result, body = self.bridge(True)
        self.assertNotEqual(result.returncode, 0);self.assertIn('overlap window', body['error'])
        self.assertFalse(body['keyring_may_have_changed']);self.preserved()

    def test_overlap_expiring_after_locked_verification_stops_actual_import(self):
        result, body = self.injected('''original=m.load_rotation
def injected():
 r=original();run=r.E.run;exports=0
 def changed(argv,home):
  nonlocal exports
  answer=run(argv,home)
  if argv[0]=='/usr/bin/gpg' and '--export' in argv:
   exports+=1
   if exports==2:m.utc_now=lambda:'2099-01-01T00:00:00Z'
  return answer
 r.E.run=changed
 return r
m.load_rotation=injected
''')
        self.assertNotEqual(result.returncode, 0);self.assertIn('overlap window', body['error'])
        self.assertEqual(F.gpg(self.ring, '--export', self.new_fpr), b'');self.preserved()

    def test_foreign_lock_is_preserved_without_trust_changes(self):
        lock = self.target / 'var/lib/pacman/db.lck';lock.write_bytes(b'foreign\n')
        result, body = self.bridge(True)
        self.assertNotEqual(result.returncode, 0);self.assertFalse(body['keyring_may_have_changed'])
        self.assertEqual(lock.read_bytes(), b'foreign\n');lock.unlink();self.preserved()

    def test_actual_import_then_local_sign_failure_reports_partial_trust_and_cleans_only_scratch(self):
        result, body = self.injected('''original=m.load_rotation
def injected():
 r=original();run=r.E.run
 def changed(argv,home):
  if '--lsign-key' in argv:raise r.E.Error('injected local-sign failure after real import')
  return run(argv,home)
 r.E.run=changed
 return r
m.load_rotation=injected
''')
        self.assertNotEqual(result.returncode, 0);self.assertTrue(body['keyring_may_have_changed'])
        self.assertFalse(body['config_changed']);self.assertFalse(body['config_may_have_changed'])
        self.assertTrue(F.gpg(self.ring, '--export', self.new_fpr));self.preserved()
        result, body = self.bridge(True)
        self.assertEqual(result.returncode, 0, body);self.preserved(include=False)


if __name__ == '__main__':
    unittest.main()
