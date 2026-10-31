# SPDX-License-Identifier: MIT
"""Finite source/refusal controls; no native actors or simulated604 success."""
import ast,copy,hashlib,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
ROOT=Path(os.environ.get('APPS6_PUBLIC_HELD_SOURCE',str(next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file()))))
def load(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);sys.modules[n]=m;s.loader.exec_module(m);return m
P=load('public_pairs_prepare',HERE/'prepare.py');H=load('public_pairs_inputs',HERE/'apps_inputs.py')
def funcs(raw):return {n.name:ast.dump(n,include_attributes=False) for n in ast.parse(raw).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
class Controls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='public659-source-');self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);p=patch.object(subprocess,'Popen',side_effect=AssertionError('no actors/Git/network'));p.start();self.addCleanup(p.stop)
 def emit(self):
  output=self.root/'source';r=P.emit(ROOT,output);C=load('public_pairs_contract',output/P.NEW/'contract.py');return output,C,r
 def binding(self):
  v=json.loads((HERE/'policy.json').read_bytes())['apps6'];v['status']=H.STATUS;return v
 def test_same_target_other603_and_587_locks_unchanged(self):
  out,C,r=self.emit();self.assertEqual(C.TARGET_SHA,'7bc6caa51301bf076aeda4d137277a128c53a16e5bfd25f02e7309c4b3a408c3');old,new=C.locks();self.assertEqual(len(new),604);self.assertEqual(r['other_packages_unchanged'],603)
  for n in ('expected587.lock','expected604.lock'):self.assertEqual((out/P.NEW/n).read_bytes(),(ROOT/P.OLD/n).read_bytes())
 def test_unbound_and_old223_authority_refuse_before_packet_or_actor(self):
  out,C,_=self.emit()
  bound=json.loads((out/P.NEW/'input-policy.json').read_bytes())
  bound['status']='ROOT_BOUND_PUBLIC_PAIRS_APPS6_CURRENT604_NATIVE_INPUTS';bound['apps6']['status']=H.STATUS
  with patch.object(C,'read',return_value=bound):self.assertEqual(C.policy(),bound)
  unbound=copy.deepcopy(bound);unbound['status']='UNBOUND_PUBLIC_PAIRS_APPS6_CURRENT604_NATIVE_INPUTS';unbound['apps6']['status']='UNBOUND'
  with patch.object(C,'read',return_value=unbound),self.assertRaisesRegex(ValueError,'UNBOUND'):C.policy()
  for bad in ({},dict(self.binding(),status='ROOT_ACCEPTED_APPS6_NATIVE_PAIRS_INSTALLED_LIFECYCLE_AND_SIGNED_SYNTHETIC_REPAIR'),dict(self.binding(),authority_source=None),dict(self.binding(),carrier_source='a'*40),dict(self.binding(),index=dict(path='index.json',bytes=1,sha256='a'*64))):
   with patch.object(C,'checked',side_effect=AssertionError('IO before authority')),self.assertRaises(ValueError):H.validate(C,ROOT,self.root,bad,None,None,self.root)
 def test_only_finite_input_identity_functions_change_all_transactions_held(self):
  out,C,_=self.emit();allowed={'contract.py':{'policy','inputs','bound_inputs','validate_result'},'inputs.py':{'_validate_inputs','retention'},'lifecycle.py':{'main'},'run.py':{'parser','main'},'gate.py':{'main'}}
  for name in P.MODULES:
   if not name.endswith('.py'):continue
   a,b=funcs((ROOT/P.OLD/name).read_bytes()),funcs((out/P.NEW/name).read_bytes());self.assertEqual(set(a),set(b));self.assertEqual({n for n in a if a[n]!=b[n]},allowed.get(name,set()),name)
  self.assertEqual((out/P.NEW/'materializer.py').read_bytes(),(ROOT/P.OLD/'materializer.py').read_bytes());self.assertEqual(len(C.PHASES),6);self.assertEqual(len(C.LD_PHASES),8)
 def test_complete_closed_source_and_original223_files_untouched(self):
  out,_,r=self.emit();manifest=json.loads((out/P.NEW/'source-manifest.json').read_bytes());self.assertEqual(len(manifest['files']),r['files'])
  for n,pin in manifest['files'].items():self.assertEqual(P.pin((out/n).read_bytes()),pin)
  for n in P.source(ROOT):self.assertEqual((out/n).read_bytes(),(ROOT/n).read_bytes())
  for p in (out/P.NEW).glob('*.py'):compile(p.read_bytes(),str(p),'exec')
  hooks=json.loads((out/P.NEW/'hooks.json').read_bytes());self.assertTrue(hooks['fresh']['status'].startswith('UNBOUND'));self.assertTrue(hooks['update']['status'].startswith('UNBOUND'))
 def test_native_owner_original_budgets_resources_and_public_authority_retention(self):
  out,_,_=self.emit();run=(out/P.NEW/'run.py').read_text();inputs=(out/P.NEW/'inputs.py').read_text()
  for s in ('signal.setitimer(signal.ITIMER_REAL,6600)','active.process.wait(timeout=1800)','PUBLIC_CAP=64*1024**2','--pids-limit=512','--memory=8g','--cpus=4','--network=none','--security-opt=no-new-privileges',"('CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETUID','SETGID')",'require_verifier_absence(producerout)'):self.assertIn(s,run)
  self.assertIn("('apps6_authority_source',Path(apps6_native),policy['apps6']['byte_case_decision'],False)",inputs);self.assertIn("if name in ('cachy-asahi-orphans','cachy-asahi-apps'):continue",inputs)
 def test_workflow_public_routes_before_secrets_same_caps_and_global_bounds(self):
  out,_,_=self.emit();text=(out/P.WF).read_text();old=(ROOT/'.github/workflows/native-arm-expanded604-apps6.yml').read_text()
  for term in ('timeout-minutes: 220','timeout-minutes: 115','6660s','packet_raw_cap=4*1024**2','total<=65*1024**2','--require-bytes','--network none'):self.assertIn(term,text)
  self.assertEqual(text.count('secrets.'),old.count('secrets.'));self.assertLess(text.index('Checkout accepted public native byte-case authority'),text.index('secrets.'));self.assertEqual(text.count('--apps6-authority-source'),2);self.assertNotIn('--apps6-native-source',text);self.assertIn('expanded604-apps6-inputs/payload',text);self.assertIn('steps.policy604.outputs.apps6_authority_source',text)
 def test_source_drift_and_missing_anchors_refuse_before_output(self):
  repo=self.root/'repo';repo.mkdir()
  for n in P.source(ROOT):p=repo/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((ROOT/n).read_bytes())
  (repo/P.OLD/'materializer.py').write_bytes(b'changed')
  with self.assertRaises(ValueError):P.emit(repo,self.root/'absent')
  self.assertFalse((self.root/'absent').exists())
  with self.assertRaises(ValueError):P.adapt(b'wrong source','contract.py')
 def test_bad_byte_case_refuses_before_loading_packet_code(self):
  out,C,_=self.emit();p=self.root/'authority.json'
  for value in (dict(status='ROOT_ACCEPTED_NATIVE_FULL574_SIGNED_REPAIR_CASE',case='repair-missing'),dict(status='ROOT_ACCEPTED_APPS6_NATIVE_PAIRS_INSTALLED_LIFECYCLE_AND_SIGNED_SYNTHETIC_REPAIR'),dict(status='ROOT_ACCEPTED_NATIVE_APPS6_CURRENT604_COMPOSITION')):
   p.write_bytes(P.encoded(value))
   with patch.object(C,'checked',return_value=p),patch.object(C,'load',side_effect=AssertionError('no packet import before byte-case authority')),self.assertRaises(ValueError):H.validate(C,ROOT,self.root,self.binding(),None,None,self.root)
 def test_old_native_packet_factory_bytes_and_build_inventory_qualification_explicit(self):
  self.assertEqual(hashlib.sha256((HERE/'pair_packet.py').read_bytes()).hexdigest(),'c06e8aabcca5793b65010a504457954eae49bd209115017e72f1a69f32584863')
  text=(HERE/'apps_inputs.py').read_text();self.assertIn('PROVENANCE_AND_ORIGINAL_ROOT_PAIR_AUTHORITY_NOT_RECONSTRUCTED_Q_LOCK_BYTES',text);self.assertIn('575 if name==NAME else 574',text);self.assertIn('len(clean)==len(set(clean))==8',text)
if __name__=='__main__':unittest.main(verbosity=2)
