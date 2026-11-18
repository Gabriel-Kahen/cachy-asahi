# SPDX-License-Identifier: MIT
"""Current authority/source controls; synthetic protocols supply no acceptance."""
import ast,hashlib,importlib.util,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file());SOURCE=Path(os.environ.get('CURRENT604_INSTALLER_SOURCE',ROOT))
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
P=load('current604_installer_emitter',HERE/'prepare.py')
def functions(raw):return {n.name:ast.get_source_segment(raw.decode(),n) for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
class Controls(unittest.TestCase):
 def setUp(self):
  t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.work=Path(t.name);p=patch.object(subprocess,'Popen',side_effect=AssertionError('no actors/Git/network'));p.start();self.addCleanup(p.stop)
 def emit(self):
  out=self.work/'source';r=P.emit(SOURCE,out);C=load('current_installer_test_contract',out/P.NEW/'contract.py');return out,C,r
 def test_installer_actual_native_authority_unbound_before_observation(self):
  out,C,r=self.emit();self.assertEqual(C.policy(bound=False)['native604'],{k:None for k in C.policy(bound=False)['native604']})
  with patch.object(C,'revision',side_effect=AssertionError('no Git before authority')),self.assertRaisesRegex(ValueError,'UNBOUND'):C.verify_source(out)
  self.assertEqual(C.policy(bound=False)['fresh600'],C.load('original604_contract',SOURCE/P.OLD/'contract.py').policy(bound=False)['fresh600'])
 def test_new_lock_joins_current_native_and_only_two_differences(self):
  out,C,r=self.emit();before,after=C.locks();old=C.COMPOSITION.lock((SOURCE/P.OLD/'expected604.lock').read_bytes(),604);self.assertEqual({n for n in after if after[n]!=old[n]},{'cachy-asahi-welcome','cachy-asahi-orphans'});self.assertEqual(after['cachy-asahi-welcome'],'0.1.0-4');self.assertEqual(after['cachy-asahi-orphans'],'0.1.0-2');self.assertEqual(C.TARGET_SHA,P.TARGET);self.assertEqual(C.COMPOSITION.policy()['welcome']['carrier_source'],'77bd2c6ecf2e5c28a04116c3da85c45f70d1cc90')
 def test_current_native_decision_has_no_historical_authority_alternative(self):
  out,C,_=self.emit();text=(out/P.NEW/'contract.py').read_text();self.assertIn("native.get('status')=='ROOT_ACCEPTED_NATIVE_CURRENT604_COMPOSITION'",text);self.assertNotIn("native.get('status')=='ROOT_ACCEPTED_NATIVE_EXPANDED604_COMPOSITION'",text);self.assertIn("directory=HERE.parent/'expanded604-current-management'",text)
  self.assertIn("'source_manifest_sha256','input_policy_sha256'",text);self.assertIsNone(C.policy(bound=False)['native604']['carrier_source'])
 def test_original_coordinator_custody_and_deadline_bodies_preserved(self):
  out,C,_=self.emit();a=functions((SOURCE/P.OLD/'ci.py').read_bytes());b=functions((out/P.NEW/'ci.py').read_bytes());self.assertEqual({n for n in a if a[n]!=b[n]},{'main'})
  for n in ('cleanup_ready','vm_retired','parser'):self.assertEqual(a[n],b[n])
  raw=(out/P.NEW/'ci.py').read_text();self.assertIn("verifier=producer_output/'private/expanded604-verifier'",raw);self.assertIn("RETAINED_VM_OR_VERIFIER_OR_CACHE_CLEANUP_UNKNOWN",raw)
 def test_wrapper_reuses_full_old_transform_and_fixed_helper_pins(self):
  out,C,_=self.emit();A=C.scoped_load('current_installer_wrapper',out/P.NEW/'adapter.py',{'contract':C});original=C.scoped_load('original_installer_transform',SOURCE/P.OLD/'adapter.py',{'contract':C});self.assertEqual(A.HELPERS,original.HELPERS)
  self.assertEqual(ast.dump(ast.parse(__import__('inspect').getsource(A.transform)),include_attributes=False),ast.dump(ast.parse(__import__('inspect').getsource(original.transform)),include_attributes=False));self.assertEqual(A.TARGET,C.TARGET_SHA)
  for name in A.NAMES:
   mapped=A.rules(name);old=original.rules(name);self.assertEqual([(r[0],r[1],r[3:]) for r in mapped],[(r[0],r[1],r[3:]) for r in old])
 def test_stale_dependency_refuses_before_new_output(self):
  rows=P.source(SOURCE);repo=self.work/'repo';repo.mkdir()
  for n in rows:p=repo/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((SOURCE/n).read_bytes())
  (repo/P.NATIVE/'expected604.lock').write_bytes((SOURCE/P.OLD/'expected604.lock').read_bytes())
  with self.assertRaisesRegex(ValueError,'exact current604 installer support'):P.emit(repo,self.work/'never')
  self.assertFalse((self.work/'never').exists())
 def test_root_freeze_retains_every_emitted_support_operand(self):
  out,C,_=self.emit();lane=out/P.NEW;workflow=out/P.WORKFLOW;text=workflow.read_text()
  for marker,path in (('@OWNER_SHA256@',lane/'ci.py'),('@MANIFEST_SHA256@',lane/'source-manifest.json')):
   digest=hashlib.sha256(path.read_bytes()).hexdigest();self.assertEqual(text.count(digest),1);text=text.replace(digest,marker)
  workflow.write_text(text)
  with patch.object(C,'policy',return_value={}),patch.object(C.COMPOSITION,'verify_source',return_value={}):result=C.freeze(out)
  retained=json.loads((lane/'source-manifest.json').read_bytes())['files'];support=json.loads((lane/'source-pins.json').read_bytes())['files']
  self.assertTrue(set(support)<=set(retained));self.assertEqual(result['files'],144)
  for name,row in retained.items():self.assertEqual(row,P.pin((out/name).read_bytes()))
if __name__=='__main__':unittest.main(verbosity=2)
