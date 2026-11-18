# SPDX-License-Identifier: MIT
"""Narrow CLI routing/refusal controls; full Git/data-copy controls are reused."""
import importlib.util,json,os,shutil,subprocess,sys,tempfile,time,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));sys.dont_write_bytecode=True

def metadata_carrier(root):
 carrier=root/'carrier';carrier.mkdir()
 for name in('native-inputs.lock.json','desktop574-inputs.lock.json'):
  shutil.copyfile(HERE/name,carrier/name)
 # Compiler metadata belongs to the external carrier; stub it only for routing.
 for name in('original-extension.lock.json','archive6-policy.json'):(carrier/name).write_bytes(b'{}')
 return carrier

spec=importlib.util.spec_from_file_location('maintained_prepare',HERE/'prepare.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
class Controls(unittest.TestCase):
 def test_explicit_modes_route_after_selected_original_lock_and_source_proof(self):
  calls=[];proof=lambda *a,**k:(calls.append(('prove',a[2]['source']))or dict(status='MOCKED_SOURCE_PROOF_CLI_ROUTING_ONLY'))
  real=P.module;real_profile=P.profile
  def route_profile(mode,deadline):
   value=real_profile(mode,deadline)
   if mode=='compiler6':
    value=json.loads(json.dumps(value))
    for name in('original-extension.lock.json','archive6-policy.json'):value['files'][name]=P.L.pin(b'{}')
   return value
  def selected(path,want,deadline):
   if path.name=='seed.py':
    def seed(lock,cache,mode,deadline):calls.append(('seed',mode));return dict(actual_authority=False,cache=dict(fresh_cache=False,all_previous_inode_metadata_bytes_unchanged=True,before_identity={},after_previous_identity={}))
    return types.SimpleNamespace(seed=seed)
   if path.name=='compiler_policy.py':
    def policy(path,lock):calls.append(('policy',6));return dict(files={str(n):{}for n in range(6)})
    return types.SimpleNamespace(policy=policy)
   return real(path,want,deadline)
  def prefill(carrier,cache,v,deadline,**kwargs):calls.append(('prefill',len(v['files'])));return dict(actual_authority=False,carrier_source_proof=dict(status='MOCKED_SOURCE_PROOF_CLI_ROUTING_ONLY'))
  with tempfile.TemporaryDirectory(prefix='retained-cli-')as td,patch.object(P.L,'prove',side_effect=proof),patch.object(P,'module',side_effect=selected),patch.object(P.L,'prefill',side_effect=prefill),patch.object(P,'profile',side_effect=route_profile):
   root=Path(td);carrier=metadata_carrier(root);cache=root/'cache';cache.mkdir(mode=0o700)
   for mode,lock in [('native248','native-inputs.lock.json'),('desktop574','desktop574-inputs.lock.json'),('compiler6','original-extension.lock.json')]:
    out=P.prepare(carrier,cache if mode!='compiler6'else root/'compiler-cache',mode,carrier/lock,time.monotonic()+30,root/'never-opened-git');self.assertIsNone(out['actual']);self.assertEqual(out['mode'],mode)
   self.assertEqual(calls,[('prove','ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad'),('seed','native248'),('prove','ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad'),('seed','desktop574'),('policy',6),('prefill',6)]);self.assertEqual(list(cache.iterdir()),[]);self.assertFalse((root/'compiler-cache').exists())
 def test_real_cli_bad_modes_deadlines_wrong_lock_refuse_without_copy_or_Git(self):
  with tempfile.TemporaryDirectory(prefix='retained-cli-')as td:
   root=Path(td);carrier=metadata_carrier(root);cache=root/'cache';cache.mkdir(mode=0o700);(cache/'sentinel').write_bytes(b'KEEP');before=(cache/'sentinel').stat()
   base=[sys.executable,'-B',str(HERE/'prepare.py'),'--carrier',str(carrier),'--cache',str(cache),'--git-dir',str(root/'absent-git')]
   for mode,lock,deadline,error in [('foreign',carrier/'native-inputs.lock.json',str(time.monotonic()+30),b'invalid choice'),('native248',carrier/'native-inputs.lock.json','0',b'explicit fixed mode and original caller deadline'),('native248',carrier/'native-inputs.lock.json','inf',b'explicit fixed mode and original caller deadline'),('native248',carrier/'desktop574-inputs.lock.json',str(time.monotonic()+30),b'whole selected original input lock')]:
    result=subprocess.run([*base,'--mode',mode,'--lock',str(lock),'--deadline',deadline],capture_output=True,timeout=10);self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'');self.assertIn(error,result.stderr);self.assertEqual((cache/'sentinel').read_bytes(),b'KEEP');after=(cache/'sentinel').stat();self.assertEqual(P.L.identity(before),P.L.identity(after));self.assertFalse((root/'absent-git').exists())
 def test_profile_tamper_and_nonprivate_cache_refuse_before_source_or_copy(self):
  with tempfile.TemporaryDirectory(prefix='retained-cli-')as td:
   root=Path(td);carrier=metadata_carrier(root);cache=root/'cache';cache.mkdir(mode=0o755)
   with patch.object(P.L,'prove',side_effect=AssertionError('NO_GIT_OR_COPY')),self.assertRaisesRegex(ValueError,'owned0700'):P.prepare(carrier,cache,'native248',carrier/'native-inputs.lock.json',time.monotonic()+30,root/'git')
   (root/'legacy-prefill-profile.json').write_bytes((HERE/'legacy-prefill-profile.json').read_bytes()+b' ')
   with patch.object(P,'HERE',root),self.assertRaisesRegex(ValueError,'fixed capability profile'):P.profile('native248',time.monotonic()+30)
if __name__=='__main__':unittest.main(verbosity=2)
