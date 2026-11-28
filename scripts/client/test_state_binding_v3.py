"""NEW temporary-filesystem client state binding controls; crypto is mocked."""
import argparse,contextlib,hashlib,json,os,stat,subprocess,sys,tempfile,types,unittest
from datetime import datetime,timedelta,timezone
from pathlib import Path
from unittest.mock import patch
T=Path(__file__).resolve().parent;parser=argparse.ArgumentParser(add_help=False);parser.add_argument('--client',type=Path);parser.add_argument('--before',type=Path);options,rest=parser.parse_known_args();ATTEMPTS=[];ACTIVE=False
def fence(event,args):
 if ACTIVE and (event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.spawn','os.fork','os.posix_spawn'))or event in('os.system','pty.spawn','os.kill','os.killpg')):
  ATTEMPTS.append(event);raise RuntimeError('client DATA actor fence '+event)
def end_fence():
 global ACTIVE
 ACTIVE=False
sys.addaudithook(fence)
def load(name,path):
 module=types.ModuleType(name);module.__file__=str(path);sys.modules[name]=module
 exec(compile(path.read_bytes(),str(path),'exec'),vars(module));return module
old=load('_unchanged_client_before',options.before or T/'fixtures/state-binding-before-v2.py.txt');c=load('_candidate_client_state_binding',options.client or T/'client_v3.py')
class Controls(unittest.TestCase):
 def setUp(self):
  global ACTIVE
  ACTIVE=True;self.addCleanup(end_fence)
  self.temp=tempfile.TemporaryDirectory(prefix='client-state-binding-');self.addCleanup(self.temp.cleanup);self.base=Path(self.temp.name);self.state=self.base/'state';self.state.mkdir(mode=0o700);self.detached=self.base/'detached-state';self.bundle=self.base/'bundle';self.bundle.mkdir(mode=0o700);self.now=datetime(2026,11,8,12,0,tzinfo=timezone.utc);self.key='A'*40
  self.prior=dict(schema_version=1,scope='development',namespace='dev.fixture',signer=self.key,sequence=1,metadata_sha256='a'*64,release_sha256='b'*64,issued_utc=c.utc(self.now-timedelta(minutes=2)),verified_utc=c.utc(self.now-timedelta(minutes=1)))
  self.prior_raw=c.encoded(self.prior);(self.state/'checkpoint.json').write_bytes(self.prior_raw);(self.state/'checkpoint.json').chmod(0o600)
  targets=dict(release_record=dict(path='release.json',sha256='c'*64),spec=dict(path='spec.json',sha256='d'*64),databases=[],packages=[])
  self.actual=dict(synthetic=True,release_id='fixture',repo_name='fixture',targets=targets);self.metadata=dict(schema_version=1,type=c.TYPE,scope='development',namespace='dev.fixture',sequence=2,issued_utc=c.utc(self.now-timedelta(seconds=30)),expires_utc=c.utc(self.now+timedelta(hours=1)),signer=self.key,**self.actual)
  self.metadata_path=self.base/'metadata.json';self.metadata_path.write_bytes(c.encoded(self.metadata));(self.base/'signature').write_bytes(b'TEST-MOCKED-SIGNATURE');(self.base/'public.gpg').write_bytes(b'TEST-MOCKED-KEYRING');(self.bundle/'release.json.sig').write_bytes(b'TEST-MOCKED-RELEASE-SIGNATURE')
  self.args=argparse.Namespace(bundle=str(self.bundle),metadata=str(self.metadata_path),signature=str(self.base/'signature'),public_keyring=str(self.base/'public.gpg'),state_dir=str(self.state),namespace='dev.fixture',signer=self.key,minimum_sequence=1,apply=True)
 def verify(self,module,callback=lambda:None,*,live_clock=False):
  case=self;calls=[]
  class MockVerifier:
   def __init__(self,*unused):pass
   def verify(self,*unused):
    calls.append('signature')
    if len(calls)==1:callback()
    return dict(primary_fingerprint=case.key)
   def bundle(self,*unused):raise AssertionError('no package actor in this state-only fixture')
  with patch.object(module,'Verifier',MockVerifier),patch.object(module,'describe',return_value=(self.actual,dict(signer=self.key,files={}),b'TEST-MOCKED-RELEASE')):
   result=module.verify(self.args,now=None if live_clock else self.now)
  self.assertEqual(calls,['signature','signature']);return result
 def replace_state(self):self.state.rename(self.detached);self.state.mkdir(mode=0o700)
 def assert_detached_preserved(self):
  self.assertEqual((self.detached/'checkpoint.json').read_bytes(),self.prior_raw);self.assertFalse((self.state/'checkpoint.json').exists());self.assertEqual(sorted(p.name for p in self.detached.iterdir()),['checkpoint.json'])
 def test_before_reproduces_applied_checkpoint_in_detached_directory(self):
  result=self.verify(old,self.replace_state);self.assertEqual(result['status'],'applied-development');self.assertTrue(result['state_changed']);self.assertFalse((self.state/'checkpoint.json').exists());self.assertEqual(json.loads((self.detached/'checkpoint.json').read_bytes())['sequence'],2)
 def test_replacement_during_verification_refuses_before_any_checkpoint_write(self):
  with self.assertRaisesRegex(c.Error,'state directory path changed during verification'):self.verify(c,self.replace_state)
  self.assert_detached_preserved()
 def test_removal_during_verification_refuses_without_writing_detached_inode(self):
  with self.assertRaisesRegex(c.Error,'state directory path changed during verification'):self.verify(c,lambda:self.state.rename(self.detached))
  self.assertFalse(self.state.exists());self.assertEqual((self.detached/'checkpoint.json').read_bytes(),self.prior_raw)
 def test_symlink_replacement_refuses_and_preserves_target(self):
  target=self.base/'other';target.mkdir(mode=0o700);(target/'sentinel').write_bytes(b'unchanged')
  def alias():self.state.rename(self.detached);self.state.symlink_to(target,target_is_directory=True)
  with self.assertRaisesRegex(c.Error,'state directory path changed during verification'):self.verify(c,alias)
  self.assertEqual((target/'sentinel').read_bytes(),b'unchanged');self.assertFalse((target/'checkpoint.json').exists());self.assertEqual((self.detached/'checkpoint.json').read_bytes(),self.prior_raw)
 def test_private_mode_changed_during_verification_refuses(self):
  with self.assertRaisesRegex(c.Error,'owner/mode changed during verification'):self.verify(c,lambda:self.state.chmod(0o755))
  self.assertEqual((self.state/'checkpoint.json').read_bytes(),self.prior_raw)
 def test_replacement_during_precommit_cleanup_is_also_checked(self):
  original=tempfile.TemporaryDirectory;case=self
  class CleanupSwap:
   def __init__(self,*a,**kw):self.inner=original(*a,**kw)
   def __enter__(self):return self.inner.__enter__()
   def __exit__(self,*a):
    result=self.inner.__exit__(*a);case.replace_state();return result
  with patch.object(c.tempfile,'TemporaryDirectory',CleanupSwap):
   with self.assertRaisesRegex(c.Error,'state directory path changed during verification'):self.verify(c)
  self.assert_detached_preserved()
 def test_unchanged_path_applies_private_checkpoint_normally(self):
  result=self.verify(c);self.assertEqual(result['status'],'applied-development');self.assertTrue(result['checkpoint_directory_synced']);p=self.state/'checkpoint.json';self.assertEqual(json.loads(p.read_bytes())['sequence'],2);self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600);self.assertFalse(self.detached.exists())
 def test_unrelated_state_directory_contents_do_not_cause_false_refusal(self):
  result=self.verify(c,lambda:(self.state/'notes').write_bytes(b'keep'));self.assertEqual(result['status'],'applied-development');self.assertEqual((self.state/'notes').read_bytes(),b'keep')
 def test_readonly_verification_never_commits(self):
  self.args.apply=False;result=self.verify(c);self.assertEqual(result['status'],'verified-development');self.assertFalse(result['state_changed']);self.assertEqual((self.state/'checkpoint.json').read_bytes(),self.prior_raw)
 def test_envelope_expiring_during_verification_refuses_before_completion(self):
  expires = self.now + timedelta(seconds=1)
  self.metadata['expires_utc'] = c.utc(expires)
  self.metadata_path.write_bytes(c.encoded(self.metadata))

  class Clock(datetime):
   current = self.now

   @classmethod
   def now(cls, tz):
    return cls.current.astimezone(tz)

  def expire():
   Clock.current = expires

  for apply in (False, True):
   with self.subTest(apply=apply), patch.object(c, 'datetime', Clock):
    Clock.current = self.now
    self.args.apply = apply
    with self.assertRaisesRegex(c.Error, 'metadata is expired'):
     self.verify(c, expire, live_clock=True)
    self.assertEqual((self.state/'checkpoint.json').read_bytes(), self.prior_raw)

  self.metadata['expires_utc'] = c.utc(expires + timedelta(seconds=1))
  self.metadata_path.write_bytes(c.encoded(self.metadata))
  with patch.object(c, 'datetime', Clock):
   Clock.current = self.now
   result = self.verify(c, expire, live_clock=True)
  self.assertEqual(result['status'], 'applied-development')
  self.assertEqual(result['checked_utc'], c.utc(expires))
  self.assertEqual(json.loads((self.state/'checkpoint.json').read_bytes())['verified_utc'], c.utc(expires))
 def test_primary_signature_refusal_is_not_replaced_by_path_check(self):
  primary=c.Error('TEST primary signature refusal')
  def refusal():self.replace_state();raise primary
  with self.assertRaises(c.Error)as caught:self.verify(c,refusal)
  self.assertIs(caught.exception,primary);self.assert_detached_preserved()

 def build_output_fixture(self):
  parent = self.base / 'output'
  parent.mkdir(mode=0o700)
  output = parent / 'envelope.json'
  now = datetime.now(timezone.utc)
  args = argparse.Namespace(bundle=str(self.bundle), output=str(output), namespace='dev.fixture',
                            sequence=2, signer=self.key, issued_utc=c.utc(now - timedelta(seconds=1)),
                            expires_utc=c.utc(now + timedelta(hours=1)))
  return parent, output, args

 def test_build_refuses_replaced_output_parent_after_sync(self):
  parent, output, args = self.build_output_fixture()
  detached = self.base / 'detached-output'
  parent_inode = parent.stat().st_ino
  sync = os.fsync

  def replace_after_sync(fd):
   sync(fd)
   if os.fstat(fd).st_ino == parent_inode and not detached.exists():
    parent.rename(detached)
    parent.mkdir(mode=0o700)
    (parent / 'sentinel').write_bytes(b'external replacement')

  with patch.object(c, 'describe', return_value=(self.actual, {'signer': self.key}, b'')), \
       patch.object(c.os, 'fsync', replace_after_sync):
   with self.assertRaisesRegex(c.Error, 'output parent path changed during envelope build'):
    c.build(args)
  self.assertFalse(output.exists())
  self.assertFalse((detached / output.name).exists())
  self.assertEqual((parent / 'sentinel').read_bytes(), b'external replacement')

 def test_build_keeps_exclusive_private_output_and_matching_digest(self):
  _, output, args = self.build_output_fixture()
  with patch.object(c, 'describe', return_value=(self.actual, {'signer': self.key}, b'')):
   result = c.build(args)
   self.assertEqual(result['path'], str(output))
   self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
   self.assertEqual(result['sha256'], hashlib.sha256(output.read_bytes()).hexdigest())
   with self.assertRaises(FileExistsError):
    c.build(args)
  self.assertEqual(result['sha256'], hashlib.sha256(output.read_bytes()).hexdigest())

 def test_build_refuses_leaf_replacement_and_keeps_foreign_file(self):
  parent, output, args = self.build_output_fixture()
  replacement = self.base / 'foreign'
  replacement.write_bytes(b'external replacement')
  parent_inode = parent.stat().st_ino
  sync = os.fsync
  def replace_after_sync(fd):
   sync(fd)
   if os.fstat(fd).st_ino == parent_inode and replacement.exists():
    replacement.replace(output)
  with patch.object(c, 'describe', return_value=(self.actual, {'signer': self.key}, b'')), \
       patch.object(c.os, 'fsync', replace_after_sync):
   with self.assertRaisesRegex(c.Error, 'output file changed during envelope build'):
    c.build(args)
  self.assertEqual(output.read_bytes(), b'external replacement')

 def test_each_bundle_signature_and_target_is_retired_before_the_next(self):
  scratch = self.base / 'verification'
  scratch.mkdir(mode=0o700)
  verifier = c.Verifier(scratch, b'TEST-MOCKED-KEYRING', self.key, self.now)
  retained = {'gpg-home', 'external-public.gpg'}
  root = c.directory(self.bundle)
  self.addCleanup(os.close, root)
  detached_sig = b'TEST-MOCKED-SIGNATURE'
  for number in range(3):
   name = f'payload-{number}'
   data = str(number).encode()
   (self.bundle / name).write_bytes(data)
   (self.bundle / (name + '.sig')).write_bytes(detached_sig)
   ref = {'path': name, 'sha256': c.digest(data)}
   with patch.object(c.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'', b'')) as gpg, \
        patch.object(c, 'signature_status', return_value={'primary_fingerprint': self.key}):
    verifier.bundle(root, ref, c.digest(detached_sig))
   self.assertEqual({path.name for path in scratch.iterdir()}, retained)
   self.assertTrue(all(not Path(path).exists() for path in gpg.call_args.args[0][-2:]))
  with self.assertRaisesRegex(c.Error, 'signed target changed'):
   verifier.bundle(root, {'path': 'payload-0', 'sha256': 'f'*64}, c.digest(detached_sig))
  self.assertEqual({path.name for path in scratch.iterdir()}, retained)
  with patch.object(c.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, b'', b'')):
   with self.assertRaisesRegex(c.Error, 'GPG rejected'):
    verifier.bundle(root, {'path': 'payload-0', 'sha256': c.digest(b'0')}, c.digest(detached_sig))
  self.assertEqual({path.name for path in scratch.iterdir()}, retained)

 def test_verify_uses_configured_scratch_directory(self):
  # Redirect the frozen reproduction away from /tmp while recording its request.
  scratch = self.base / 'scratch'
  scratch.mkdir(mode=0o700)
  make_temp = tempfile.TemporaryDirectory
  requested = []
  def record(*args, **kwargs):
   requested.append(Path(kwargs.get('dir') or tempfile.gettempdir()))
   return make_temp(*args, **{**kwargs, 'dir': scratch})
  with patch.dict(os.environ, {'TMPDIR': str(scratch)}), patch.object(tempfile, 'tempdir', None), \
       patch.object(c.tempfile, 'TemporaryDirectory', side_effect=record):
   self.verify(c)
  self.assertEqual(requested, [scratch])
  self.assertEqual(list(scratch.iterdir()), [])

 def test_verify_refuses_untrusted_scratch_ancestors(self):
  unsafe = self.base / 'shared'
  child = unsafe / 'private'
  child.mkdir(parents=True)
  unsafe.chmod(0o777)
  with patch.object(tempfile, 'gettempdir', return_value=str(child)):
   with self.assertRaisesRegex(c.Error, 'scratch path must have trusted directory ownership'):
    self.verify(c)
  self.assertEqual(list(child.iterdir()), [])
  alias = self.base / 'alias'
  alias.symlink_to(child, target_is_directory=True)
  with patch.object(tempfile, 'gettempdir', return_value=str(alias)):
   with self.assertRaisesRegex(c.Error, 'scratch path must have trusted directory ownership'):
    self.verify(c)

 def tearDown(self):self.assertEqual(ATTEMPTS,[])
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest])
