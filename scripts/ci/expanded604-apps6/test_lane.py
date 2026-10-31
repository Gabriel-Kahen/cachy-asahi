# SPDX-License-Identifier: MIT
"""Finite actor-blocked source composition/refusal controls; no native credit."""
import ast,hashlib,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
ROOT=Path(os.environ.get('APPS6_HELD_SOURCE',str(next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file()))))
spec=importlib.util.spec_from_file_location('apps6_604_prepare',HERE/'prepare.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
def funcs(raw):return {n.name:ast.dump(n) for n in ast.parse(raw).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
class Controls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);p=patch.object(subprocess,'Popen',side_effect=AssertionError('no actor/Git/network'));p.start();self.addCleanup(p.stop)
 def emit(self):
  target=self.root/'source';result=P.emit(ROOT,target);C=P.load('apps6_test_contract',target/P.NEW/'contract.py');return target,C,result
 def test_only_apps_version_changes_other603_and_platform_exact(self):
  out,C,r=self.emit();before=C.lock((ROOT/P.OLD/'expected604.lock').read_bytes(),604);baseline,after=C.locks();self.assertEqual(len(after),604);self.assertEqual({n for n in before if before[n]!=after[n]},{'cachy-asahi-apps'});self.assertEqual(after['cachy-asahi-apps'],'0.1.0-6');self.assertEqual(r['other_versions_unchanged'],603);self.assertEqual(C.BASE_SHA,hashlib.sha256((ROOT/P.OLD/'expected587.lock').read_bytes()).hexdigest());self.assertEqual(len(C.ADDITIONS),17);self.assertEqual(len(C.UPGRADES),2)
 def test_unbound_before_source_git_or_actor_and_no_prior_acceptance(self):
  out,C,r=self.emit()
  with self.assertRaisesRegex(ValueError,'UNBOUND'):C.policy()
  self.assertEqual(C.policy(bound=False)['management']['versions']['cachy-asahi-apps'],'0.1.0-5')
  with self.assertRaises(ValueError):C.validate_result(dict(status='PASS_CURRENT604_METADATA_LIFECYCLE',target_sha256=P.OLD_SHA))
  hooks=json.loads((out/P.NEW/'hooks.json').read_bytes());self.assertTrue(hooks['fresh']['status'].startswith('UNBOUND'));self.assertTrue(hooks['update']['status'].startswith('UNBOUND'))
 def test_original_functions_unchanged_except_finite_wiring_identity(self):
  out,C,r=self.emit();allowed={'contract.py':{'policy','read_policy_management','inputs','bound_inputs','validate_result'},'inputs.py':{'management_pairs','_validate_inputs','validate_inputs','retention'},'materializer.py':{'accepted','prepare'},'lifecycle.py':{'main'},'run.py':{'main','parser'},'gate.py':{'main'},'installed_shells.py':set()}
  for n in P.MODULES:
   a=funcs((ROOT/P.OLD/n).read_bytes());b=funcs((out/P.NEW/n).read_bytes());self.assertEqual(set(a),set(b));self.assertEqual({k for k in a if a[k]!=b[k]},allowed[n],n)
  self.assertEqual(len(C.PHASES),6);self.assertEqual(len(C.LD_PHASES),8)
 def test_complete_source_emission_compiles_and_normal_owner_remains_bounded(self):
  out,C,r=self.emit()
  for p in (out/P.NEW).glob('*.py'):compile(p.read_bytes(),str(p),'exec')
  run=(out/P.NEW/'run.py').read_text()
  for value in ('signal.setitimer(signal.ITIMER_REAL,6600)','active.process.wait(timeout=1800)','PUBLIC_CAP=64*1024**2','--pids-limit=512','--memory=8g','--cpus=4','--network=none','--security-opt=no-new-privileges','require_verifier_absence(producerout)'):self.assertIn(value,run)
  old=(ROOT/P.OLD/'run.py').read_text();self.assertEqual(run.count('--cap-add='),old.count('--cap-add='));self.assertIn("('CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETUID','SETGID')",run)
 def test_workflow_has_both_new_sources_before_secrets_and_same_bounds(self):
  out,_,_=self.emit();new=(out/'.github/workflows/native-arm-expanded604-apps6.yml').read_text();old=(ROOT/'.github/workflows/native-arm-expanded604-current-management.yml').read_text()
  for term in ('timeout-minutes: 220','timeout-minutes: 115','6660s','packet_raw_cap=4*1024**2','total<=65*1024**2','--require-bytes','--network none'):self.assertIn(term,new)
  self.assertEqual(new.count('secrets.'),old.count('secrets.'));self.assertLess(new.index('Checkout Root bound Apps6'),new.index('secrets.'));self.assertEqual(new.count('--apps6-source "$GITHUB_WORKSPACE/expanded604-apps6-inputs/payload"'),2);self.assertEqual(new.count('--apps6-native-source "$GITHUB_WORKSPACE/expanded604-apps6-native"'),2)
 def test_drift_refuses_before_output_and_counted_anchor_refuses(self):
  repo=self.root/'repo';repo.mkdir()
  for n in P.source(ROOT):p=repo/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((ROOT/n).read_bytes())
  (repo/P.OLD/'materializer.py').write_bytes(b'changed')
  with self.assertRaisesRegex(ValueError,'pinned current604'):P.emit(repo,self.root/'absent')
  self.assertFalse((self.root/'absent').exists())
  with self.assertRaisesRegex(ValueError,'anchor'):P.adapt(b'wrong source','contract.py')
 def test_old_packet_fully_validated_only_apps_and_orphans_selection_skipped(self):
  out,C,_=self.emit();text=(out/P.NEW/'inputs.py').read_text();self.assertLess(text.index('api.package_payload(root,packet,checks)'),text.index("if name in ('cachy-asahi-orphans','cachy-asahi-apps'):continue"));self.assertIn("result['management']['cachy-asahi-apps']=",text);self.assertIn("result['management']['cachy-asahi-orphans']=",text);self.assertIn("('apps6_source',Path(apps6),policy['apps6']['index'],False)",text)
 def test_old_authority_and_unbound_carrier_refuse_before_packet_io(self):
  out,C,_=self.emit();H=P.load('apps6_test_inputs',HERE/'apps_inputs.py');good=dict(status=H.STATUS,native_source=H.SOURCE,native_run=H.RUN,root_decision_sha256=H.DECISION,carrier_source='a'*40,index=dict(path='index.json',bytes=1,sha256='a'*64))
  for key,value in (('status','ROOT_ACCEPTED_APPS_RUNTIME_CACHE_NATIVE_PAIRS'),('native_source','0'*40),('native_run',38970264456),('root_decision_sha256','b'*64),('carrier_source',None)):
   bad=dict(good);bad[key]=value
   with self.subTest(key=key),patch.object(C,'checked',side_effect=AssertionError('IO before authority')),self.assertRaises(ValueError):H.validate(C,out,self.root,bad,None,None,self.root)
if __name__=='__main__':unittest.main(verbosity=2)
