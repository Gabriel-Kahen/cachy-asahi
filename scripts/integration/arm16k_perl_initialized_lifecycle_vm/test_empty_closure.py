"""Actual public r74 closure and bounded decoder refusal controls; no actor."""
import copy,importlib.util,json,os,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).parent
PROOF=Path('/home/gabe/Documents/ChatGPT/cachy-asahi-perl-initialized-fullscan-preparation-20261117/operation/proof')
LEGACY=Path('/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114/Root-warm-baseline-inputs-r1/constructed-source/arm16k_perl5423_vm')
INITIALIZED=Path('/home/gabe/Documents/ChatGPT/cachy-asahi-perl-initialized-qualification-20261117/scripts/integration/arm16k_perl_initialized_vm')
def module(n,root):
 s=importlib.util.spec_from_file_location('empty_closure_test_'+n,root/(n+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
J=module('integration',HERE);K=module('contracts',LEGACY);Q=module('qualification',INITIALIZED)
class Controls(unittest.TestCase):
 def actual(self):
  p=PROOF/'empty-closure.DATA.json';self.assertEqual(K.pin(p),dict(bytes=7556,sha256='135759471cc66dbcafcc0b14600a0c5fc1badcc2e1fc6e458199eb0269f731dc'));return J.empty_closure(K,p)
 def decoded(self,value=None,raw=None,cap=4*1024**2):
  with tempfile.TemporaryDirectory()as tmp:
   p=Path(tmp)/'closure.json';p.write_bytes(K.canonical(value)if raw is None else raw);return J.empty_closure(K,p,cap)
 def test_actual_public_closure_passes_unchanged_qualification_privacy_and_retirement_gates(self):
  value=self.actual();proof=K.load(PROOF/'empty-proof.DATA.json');Q.empty_inputs(proof,value)
  self.assertEqual(K.json_pin(value),K.pin(PROOF/'empty-closure.DATA.json'));self.assertEqual(value['external']['seconds'],5.421363410016056)
  bad=copy.deepcopy(value);bad['owned_absence_independently_verified'][0]['retirement']['reaped']=False
  with self.assertRaises(ValueError):Q.empty_inputs(proof,self.decoded(bad))
  bad=copy.deepcopy(value);bad['policy_result']['file_payload_chunks_read']=True
  with self.assertRaises(ValueError):Q.empty_inputs(bad['policy_result'],self.decoded(bad))
 def test_all_four_timing_paths_require_nonnegative_numeric_values(self):
  for index in range(4):
   for timing in(-0.01,-1,True,False,None,'1'):
    with self.subTest(index=index,timing=timing):
     v=self.actual();row=v['external']if index==0 else v['owned_absence_independently_verified'][index-1]['retirement'];row['seconds']=timing
     with self.assertRaises(ValueError):self.decoded(v)
  v=self.actual();v['external']['seconds']=0;self.assertEqual(self.decoded(v),v)
 def test_misplaced_floats_refuse_at_root_authority_proof_and_fourth_absence(self):
  for path in('root','external','proof','fourth'):
   with self.subTest(path=path):
    v=self.actual()
    if path=='root':v['seconds']=0.5
    elif path=='external':v['external']['exit']=0.0
    elif path=='proof':v['policy_result']['root_ssh_emptiness']['directory_bytes_read']=4096.0
    else:v['owned_absence_independently_verified'].append(copy.deepcopy(v['owned_absence_independently_verified'][0]))
    with self.assertRaises(ValueError):self.decoded(v)
 def test_nonfinite_and_overflow_tokens_refuse(self):
  raw=K.canonical(self.actual())
  for token in(b'NaN',b'Infinity',b'-Infinity',b'1e999'):
   with self.subTest(token=token):
    with self.assertRaises(ValueError):self.decoded(raw=raw.replace(b'5.421363410016056',token))
 def test_duplicate_and_noncanonical_json_refuse(self):
  raw=K.canonical(self.actual())
  for body in(raw.replace(b'"seconds": 5.421363410016056',b'"seconds": 1.0, "seconds": 5.421363410016056'),raw+b' ',raw.replace(b'5.421363410016056',b'5.4213634100160560')):
   with self.assertRaises(ValueError):self.decoded(raw=body)
 def test_caps_single_link_symlink_and_changed_read_refuse(self):
  raw=K.canonical(self.actual())
  with self.assertRaises(ValueError):self.decoded(raw=raw,cap=len(raw)-1)
  with tempfile.TemporaryDirectory()as tmp:
   p=Path(tmp)/'body';p.write_bytes(raw);alias=Path(tmp)/'alias';alias.symlink_to(p)
   with self.assertRaises(ValueError):J.empty_closure(K,alias)
   alias.unlink();os.link(p,alias)
   with self.assertRaises(ValueError):J.empty_closure(K,p)
  class Changed:
   ordinary=staticmethod(K.ordinary);need=staticmethod(K.need);canonical=staticmethod(K.canonical)
   @staticmethod
   def pin(p,cap):
    result=K.pin(p,cap);p.write_bytes(raw+b' ');return result
  with tempfile.TemporaryDirectory()as tmp:
   p=Path(tmp)/'body';p.write_bytes(raw)
   with self.assertRaises(ValueError):J.empty_closure(Changed,p)
 def test_every_other_qualification_role_retains_strict_integer_loader(self):
  for role in J.ROLES:
   if role=='empty_closure':continue
   with self.subTest(role=role):
    with self.assertRaises(ValueError):J.input_value(K,role,PROOF/'empty-closure.DATA.json')
if __name__=='__main__':unittest.main(verbosity=2)
