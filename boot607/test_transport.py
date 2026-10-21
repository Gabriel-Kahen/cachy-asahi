"""Exact policy/context/nonce refusal controls, without an accepting native fixture."""
import copy,importlib.util,json,os,sys,unittest
from pathlib import Path
from unittest.mock import patch
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));import transport_scope as S
spec=importlib.util.spec_from_file_location('trusted_boot_only_transport',HERE/'transport.py');T=importlib.util.module_from_spec(spec);spec.loader.exec_module(T)
class Transport(unittest.TestCase):
 def test_whole387_inverse(self):
  import guard
  self.assertEqual(guard.verify()['files'],397)
 def test_full_fixed_policy_and_original_functions(self):
  self.assertEqual(T.policy(dict(S.POLICY)),S.POLICY)
  old=HERE.parent/'scripts/ci/native-evidence-transport/transport.py';scope={};exec(compile(old.read_bytes(),str(old),'exec'),dict(scope,__name__='inert_prior',__file__=str(old)))
  self.assertEqual(S.inverse(S.transport_before_failure((HERE/'transport.py').read_text()),S.BOOT_INSERT).encode(),old.read_bytes())
 def test_every_original_function_body_held(self):
  import ast
  before=ast.parse((HERE.parent/'scripts/ci/native-evidence-transport/transport.py').read_text());after=ast.parse(S.transport_before_failure((HERE/'transport.py').read_text()))
  original=[n for n in before.body if isinstance(n,ast.FunctionDef)];derived=[n for n in after.body if isinstance(n,ast.FunctionDef)]
  for fn in original:
   matches=[n for n in derived if n.name==fn.name and ast.dump(n,include_attributes=False)==ast.dump(fn,include_attributes=False)]
   self.assertEqual(len(matches),1)
  self.assertEqual(len(derived),len(original)+1)
 def test_old_shared_policy_still_refuses_boot_path(self):
  with self.assertRaisesRegex(ValueError,'original owner nonce'):T._prior_policy(dict(S.POLICY))
 def test_no_generic_nonce_or_scope_admission(self):
  for key,value in(('nonce_path','plan/bridge-selection.json'),('nonce_path','foreign.json'),('nonce_field','foreign'),('workflow_name','foreign'),('job','foreign'),('step_id','foreign'),('step_name','foreign'),('workflow_path','.github/workflows/foreign.yml'),('purpose','foreign'),('repository','foreign')):
   p=dict(S.POLICY);p[key]=value
   with self.assertRaisesRegex(ValueError,'complete Boot607'):T.policy(p)
  for p in(dict(S.POLICY,foreign=True),{k:v for k,v in S.POLICY.items()if k!='nonce_field'}):
   with self.assertRaisesRegex(ValueError,'complete Boot607'):T.policy(p)
 def test_no_foreign_context_or_missing_actual(self):
  with self.assertRaisesRegex(ValueError,'workflow context'):T.context(dict(S.POLICY),{})
 def test_duplicate_nonce_document_and_nonfinite_refused(self):
  for raw in(b'{"nonce":"a","nonce":"b"}',b'{"nonce":NaN}'):
   with self.assertRaises(ValueError):T.obj(raw)
 def test_missing_indexed_nonce_refuses(self):
  # Empty original packet index reconstructs no native result or nonce, never acceptance.
  packets={'part-0000':{'retention.json':T.encoded(dict(files={},bytes=0,cap=T.TOTAL,packet_raw_cap=T.PACKET,packet_count=0,reconstruction=T.RECONSTRUCTION,scope=T.SCOPE))}}
  _,values=T.reconstruct(packets);self.assertNotIn(S.POLICY['nonce_path'],values)
 def test_source_guard_before_any_process(self):
  import guard
  with patch('subprocess.Popen',side_effect=AssertionError('ACTOR_FORBIDDEN')):self.assertEqual(guard.verify()['files'],397)
if __name__=='__main__':unittest.main(verbosity=2)
