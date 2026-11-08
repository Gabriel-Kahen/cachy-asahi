"""New fixed-adapter tests. Fake owned backend only, never GPG or pacman."""
import copy,hashlib,importlib,json,os,shutil,sys,tempfile,time,types,unittest
from unittest.mock import patch
from pathlib import Path
P=Path(__file__).resolve().parents[1];sys.path.insert(0,str(P/'overlay/native'))
A=importlib.import_module('security_recovery_adapter');R=importlib.import_module('security_recovery');F=importlib.import_module('security_recovery_fs');S=importlib.import_module('security_recovery_state')
SIGNER='AB'*20
NOW=int(time.time())
def pin(b):return R.Pin(len(b),hashlib.sha256(b).hexdigest())
def listing(signer=SIGNER,created=NOW-5,expires=NOW-5+86400):
 p=['pub','u','255','22','0123456789ABCDEF',str(created),str(expires),'','u','','','scSC'];f=['fpr']+['']*9;f[9]=signer;u=['uid']+['']*9;u[9]='TEST ONLY security-maintenance <security@test.invalid>';return ('\n'.join(':'.join(x)+':'for x in(p,f,u))+'\n').encode()
def status():return ('[GNUPG:] GOODSIG 0123456789ABCDEF TEST ONLY\n[GNUPG:] VALIDSIG '+SIGNER+' 2026-11-08 1794100000 0 4 0 22 8 00 '+SIGNER+'\n').encode()
def desc(t,version='0.1.0-2'):return ('%NAME%\n'+S.NAME+'\n\n%VERSION%\n'+version+'\n\n%INSTALLDATE%\n'+str(t)+'\n\n').encode()
def retired(exit=0):return dict(exit=exit,error=None,timeout=False,forced_retirement=False,passed=True,reaped=True,group_absent=True,pid_reserved_until_retirement=True,wall_started=NOW,wall_finished=NOW)
class Fake:
 test_only=True
 def __init__(self,fixture):self.f=fixture;self.calls=[];self.behavior='ok'
 def run(self,argv,**kwargs):
  self.calls.append((argv,kwargs));out=b'';ret=retired()
  if argv==list(A.CMD_KEY):out=listing(created=NOW-86406,expires=NOW-6)if self.behavior=='expired-key'else listing()
  elif argv[0]=='/usr/bin/gpgv':
   out=status()
   if self.behavior=='bad-signature':out+=b'[GNUPG:] EXPKEYSIG bad\n'
   if self.behavior=='prior-drift':self.f.write(A.PRIOR,b'changed',0o600)
  elif argv[0]=='/usr/bin/pacman'and'-U'in argv:
   version='0.1.0-1'if argv[-1].endswith('0.1.0-1-any.pkg.tar.zst')else'0.1.0-2';name=S.OLD if version.endswith('-1')else S.NEW
   self.f.write('var/lib/pacman/local/'+name+'/desc',desc(NOW,version),0o644);(self.f.local/name).chmod(0o755);self.f.write('var/lib/pacman/local/'+name+'/files',b'%FILES%\nbin/security\n\n',0o644);self.f.write('usr/bin/security',b'candidate',0o755)
  elif argv==list(A.CMD_REMOVE):shutil.rmtree(self.f.local/S.NEW);(self.f.root/'usr/bin/security').unlink()
  elif argv==list(A.CMD_QUERY):out=b'query fixture\n'
  else:raise AssertionError('unknown command reached fakebackend')
  if self.behavior=='forced':ret['forced_retirement']=True
  if self.behavior=='overflow':out=b'x'*(kwargs['output_cap']+1)
  return dict(stdout=out,stderr=b'',retirement=ret)
class Fixture:
 def __init__(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY);self.local=self.root/'var/lib/pacman/local';self.local.mkdir(parents=True);(self.root/'usr/bin').mkdir(parents=True)
  for i in range(349):d=self.local/('base%03d-1-1'%i);d.mkdir();d.chmod(0o755);(d/'desc').write_bytes(b'baseline');(d/'desc').chmod(0o644)
  source_map=b'{"unbound":"source-map"}\n';self.write(A.SOURCE_MAP,source_map,0o644)
  self.binding=dict(source='c'*40,ref='refs/heads/codex/unbound-adapter',run='9000000000021',attempt=1,map_sha256=hashlib.sha256(source_map).hexdigest(),token='d'*24)
  sentinel=(json.dumps(dict(protocol='security-recovery-native-scope-v1',binding=self.binding,caller_verified_source=True,disposable_native_image=True),sort_keys=True)+'\n').encode();self.write(A.SENTINEL,sentinel,0o600);self.sentinel=pin(sentinel)
  bodies={R.ARCHIVE:b'fake archive',R.ARCHIVE+'.sig':b'fake signature',R.KEYRING:b'fake ring',R.CONFIG:('[options]\n'+''.join(k+' = '+v+'\n'for k,v in R.OPTIONS.items())).encode()}
  for n,b in bodies.items():self.write(n,b,0o600)
  self.write(A.PRIOR,b'prior archive',0o600);self.write(A.PRIOR+'.sig',b'prior signature',0o600)
  self.inputs=R.Inputs(*(pin(bodies[n])for n in(R.ARCHIVE,R.ARCHIVE+'.sig',R.CONFIG,R.KEYRING)),SIGNER);self.fake=Fake(self);self.adapter=A.NativeCommandAdapter.for_test(self.fd,self.binding,self.sentinel,self.inputs,self.fake);self.baseline=F.snapshot(self.fd,('bin/security',),owner_uid=os.geteuid(),owner_gid=os.getegid())
 def write(self,n,b,mode):f=self.root/n;f.parent.mkdir(parents=True,exist_ok=True);f.write_bytes(b);f.chmod(mode)
 def close(self):os.close(self.fd);self.tmp.cleanup()
class Adapter(unittest.TestCase):
 def setUp(self):self.f=Fixture()
 def tearDown(self):self.f.close()
 def signature(self):return self.f.adapter.run(R.Command('verify-signature',A.CMD_VERIFY,30,65536))
 def test_fixed_signature_and_owned_natural_result(self):
  result=self.signature();self.assertIn(b'VALIDSIG',result.stdout);self.assertEqual([x[0]for x in self.f.fake.calls],[list(A.CMD_KEY),list(A.CMD_VERIFY)]);self.assertNotIn('HOME',self.f.fake.calls[0][1]['env'])
 def test_unknown_or_broadened_command_refused(self):
  for c in(R.Command('anything',('/bin/sh',),30,65536),R.Command('verify-signature',A.CMD_VERIFY+('--faked-system-time','1'),30,65536),R.Command('verify-signature',A.CMD_VERIFY,31,65536)):
   with self.subTest(c=c),self.assertRaises(ValueError):self.f.adapter.run(c)
  self.assertEqual(self.f.fake.calls,[])
 def test_expired_key_prevents_signature_command(self):
  self.f.fake.behavior='expired-key'
  with self.assertRaises(ValueError):self.signature()
  self.assertEqual(len(self.f.fake.calls),1)
 def test_expired_signature_does_not_authorize_install(self):
  self.f.fake.behavior='bad-signature'
  with self.assertRaises(ValueError):self.signature()
  with self.assertRaises(ValueError):self.f.adapter.run(R.Command('signed-candidate-install',A.CMD_INSTALL,180,1048576))
 def test_install_without_signature_refused(self):
  with self.assertRaises(ValueError):self.f.adapter.run(R.Command('signed-candidate-install',A.CMD_INSTALL,180,1048576))
  self.assertEqual(self.f.fake.calls,[])
 def test_scope_binding_or_map_drift_refused_before_commands(self):
  self.f.write(A.SOURCE_MAP,b'changed',0o644)
  with self.assertRaises(ValueError):self.signature()
  self.assertEqual(self.f.fake.calls,[])
 def test_output_overflow_or_forced_retirement_refused(self):
  for behavior in('overflow','forced'):
   self.f.fake.behavior=behavior
   with self.subTest(behavior=behavior),self.assertRaises(ValueError):self.signature()
 def test_warm_reference_is_captured_before_removal_and_restores_baseline(self):
  result=self.f.adapter.capture_reference(('bin/security',),self.f.baseline);self.assertEqual(result['reference'].install_window,dict(started_epoch=NOW,finished_epoch=NOW));self.assertIn(S.NEW+'/desc',result['reference'].raw_files);self.assertEqual(F.snapshot(self.f.fd,('bin/security',),owner_uid=os.geteuid(),owner_gid=os.getegid()),self.f.baseline)
  with self.assertRaises(ValueError):self.f.adapter.capture_reference(('bin/security',),self.f.baseline)
 def test_real_durable_journal_wraps_fake_warm_reference_commands(self):
  J=importlib.import_module('security_recovery_journal');journal=J.Journal.create(self.f.root/'journal.jsonl',self.f.binding)
  try:
   journal.append('BASELINE_RECORDED',dict(snapshot_sha256=F.snapshot_sha256(self.f.baseline)))
   self.f.adapter.journal=journal;result=self.f.adapter.capture_reference(('bin/security',),self.f.baseline)
   self.assertEqual(journal.phase,'BASELINE_RESTORED');self.assertIsNone(journal.pending)
  finally:journal.close()
  parsed=J.load(self.f.root/'journal.jsonl',self.f.binding)
  self.assertTrue(parsed)
 def test_prior_archive_rechecked_after_signature_before_install(self):
  self.f.fake.behavior='prior-drift'
  with self.assertRaises(ValueError):self.f.adapter.install_prior(pin(b'prior archive'),pin(b'prior signature'))
  self.assertFalse(any('-U'in x[0]for x in self.f.fake.calls))
 def test_explicit_fake_constructor_required(self):
  class NotFake:pass
  with self.assertRaises(ValueError):A.NativeCommandAdapter.for_test(self.f.fd,self.f.binding,self.f.sentinel,self.f.inputs,NotFake())
 def test_production_constructor_rejects_temporary_process_root_before_actor(self):
  O=importlib.import_module('security_interruption_owner')
  home=self.f.root/'owned';home.mkdir(mode=0o700)
  runner=O.OwnedProcessRunner(home)
  journal=types.SimpleNamespace(binding=self.f.binding)
  with self.assertRaises(ValueError):
   A.NativeCommandAdapter(self.f.fd,self.f.binding,self.f.sentinel,self.f.inputs,journal=journal,runner=runner)
  self.assertEqual(self.f.fake.calls,[])
 def test_key_identity_multiple_or_non_one_day_refused(self):
  for raw in(listing(signer='CD'*20),listing(expires=NOW+100),listing()+listing(),listing().replace(b'pub:u:',b'pub:-:'),listing().replace(b':u:::scSC',b':-:::scSC')):
   with self.subTest(raw=raw[:20]),self.assertRaises(ValueError):A.validate_test_key(raw,SIGNER,NOW)
if __name__=='__main__':unittest.main(verbosity=2)
