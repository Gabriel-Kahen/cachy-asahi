# SPDX-License-Identifier: MIT
"""Finite source controls and optional explicit retained packet replay; no actors."""
import ast,copy,hashlib,importlib.util,json,os,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())
spec=importlib.util.spec_from_file_location('current604_prepare',HERE/'prepare.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
def functions(raw):return {n.name:ast.get_source_segment(raw.decode(),n) for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
class Controls(unittest.TestCase):
 def setUp(self):
  t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.temp=Path(t.name);p=patch.object(subprocess,'Popen',side_effect=AssertionError('no actors/Git/network'));p.start();self.addCleanup(p.stop)
 def emit(self):
  out=self.temp/'source';receipt=P.emit(ROOT,out);C=P.load('current604_test_contract',out/P.NEW/'contract.py');return out,C,receipt
 def test_exact_source_and_two_version_lock_change_only(self):
  out,C,r=self.emit();old=C.lock((ROOT/P.OLD/'expected604.lock').read_bytes(),604);base,new=C.locks();self.assertEqual(len(new),604);self.assertEqual({n for n in new if old[n]!=new[n]},{'cachy-asahi-welcome','cachy-asahi-orphans'});self.assertEqual(r['other_versions_unchanged'],602);self.assertEqual(C.BASE_SHA,hashlib.sha256((ROOT/P.OLD/'expected587.lock').read_bytes()).hexdigest());self.assertEqual(C.policy(bound=False)['management'],P.load('historical604_test_contract',ROOT/P.OLD/'contract.py').policy(bound=False)['management'])
 def test_unbound_source_refuses_before_output_or_git(self):
  out,C,_=self.emit();p=out/P.NEW/'input-policy.json';v=json.loads(p.read_bytes());v['status']='UNBOUND_CURRENT604_NATIVE_INPUTS';v['welcome']['carrier_source']=None;p.write_bytes(P.encoded(v))
  with self.assertRaisesRegex(ValueError,'UNBOUND'):C.policy()
  H=P.load('current604_test_pairs',HERE/'current_inputs.py')
  with self.assertRaises(ValueError):H.require(C,v['welcome'])
 def test_all_materializer_shell_and_transaction_checks_reused(self):
  out,C,r=self.emit()
  for n in ('materializer.py','installed_shells.py'):self.assertEqual((out/P.NEW/n).read_bytes(),(ROOT/P.OLD/n).read_bytes())
  for n in ('contract.py','lifecycle.py','run.py'):
   old=functions((ROOT/P.OLD/n).read_bytes());new=functions((out/P.NEW/n).read_bytes())
   allowed={'policy','read_policy_management','validate_result'} if n=='contract.py' else {'main'}
   self.assertEqual({k for k in old if old[k]!=new[k]},allowed)
  self.assertEqual(len(C.LD_PHASES),8);self.assertEqual(len(C.PHASES),6);self.assertEqual(len(C.UPGRADES),2);self.assertEqual(len(C.ADDITIONS),17)
  text=(out/P.NEW/'run.py').read_text();self.assertIn('signal.setitimer(signal.ITIMER_REAL,6600)',text);self.assertIn('PUBLIC_CAP=64*1024**2',text);self.assertIn('require_verifier_absence(producerout)',text)
 def test_historical_receipt_cannot_pass_current_contract(self):
  _,C,_=self.emit()
  with self.assertRaises(ValueError):C.validate_result(dict(status='PASS_EXPANDED604_METADATA_LIFECYCLE',target_sha256=P.OLD_SHA))
  H=P.load('current604_test_inputs',HERE/'current_inputs.py')
  for field,value in [('status','ROOT_ACCEPTED_NATIVE_WELCOME2_PAIR_AND_CLI_LIFECYCLE'),('source','1'*40),('candidate_source','2'*40),('carrier_source',None),('carrier_source','main')]:
   binding=dict(status=H.STATUS,source=H.SOURCE,candidate_source=H.PRODUCT,carrier_source='3'*40,index=dict(path='index.json',bytes=1,sha256='a'*64));binding[field]=value
   with self.subTest(field=field),self.assertRaises(ValueError):H.require(C,binding)
 def test_source_drift_refuses_before_emission(self):
  repo=self.temp/'repo';repo.mkdir()
  for n in P.source(ROOT):p=repo/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((ROOT/n).read_bytes())
  (repo/P.OLD/'materializer.py').write_text('changed')
  with self.assertRaisesRegex(ValueError,'exact current604 input source'):P.emit(repo,self.temp/'never')
  self.assertFalse((self.temp/'never').exists())
 def test_actual_current_packet_scope_and_original_native_snapshot(self):
  # Explicit packet path in hosted workflow; local actual projection otherwise.
  packet=Path(os.environ.get('CURRENT604_PACKET_ROOT',str(ROOT/'artifacts/development/expanded604-current-management-20261017/payload')))
  if not packet.is_dir():self.skipTest('no explicit retained current packet supplied; no runtime credit')
  _,C,_=self.emit();H=P.load('current604_current_pair_replay',HERE/'current_inputs.py');reader=C.scoped_load('current604_reader',ROOT/P.OLD/'inputs.py',{'contract':C});checks,bind=reader.tools(ROOT);raw=(packet/'index.json').read_bytes();binding=dict(status=H.STATUS,source=H.SOURCE,candidate_source=H.PRODUCT,carrier_source=None,index=dict(path='index.json',**P.pin(raw)))
  native=Path(os.environ.get('CURRENT604_NATIVE_SOURCE',str(ROOT/'artifacts/development/welcome4-native-root-20261017/source')))
  # Canonical CI can supply the same pinned pure guards from its full source;
  # this local actual replay deliberately uses the original Root113 snapshot.
  rows=H.validate(C,ROOT,packet,binding,checks,bind,published=False,native_source=native);self.assertEqual({n:r['version'] for n,r in rows.items()},H.VERSIONS);self.assertEqual(rows['cachy-asahi-welcome']['files']['a']['sha256'],H.ARCHIVES['cachy-asahi-welcome']['sha256']);self.assertEqual(C.read(packet/'root-decision.json')['GUI'],'FAIL_NOT_ACCEPTED')
 def test_original_four_packet_is_validated_but_only_old_orphans_selection_skipped(self):
  packet=Path(os.environ.get('CURRENT604_MANAGEMENT_ROOT',str(ROOT/'artifacts/development/management-tools-native-inputs-20261016/payload')))
  if not packet.is_dir():self.skipTest('no explicit original management packet supplied')
  out,C,_=self.emit();I=C.scoped_load('current604_derived_inputs',out/P.NEW/'inputs.py',{'contract':C});checks,_=I.tools(ROOT);api=C.scoped_load('old604_management',ROOT/'scripts/ci/management-tools-generic16k/contract.py',{});rows=I.management_pairs(ROOT,packet,api.policy(),checks);self.assertEqual(set(rows),set(api.VERSIONS)-{'cachy-asahi-orphans'})
 def test_workflow_keeps_original_build_signing_resource_and_carrier_layout(self):
  out,_,_=self.emit();text=(out/'.github/workflows/native-arm-expanded604-current-management.yml').read_text();old=(ROOT/'.github/workflows/native-arm-expanded604.yml').read_text()
  for term in ('timeout-minutes: 220','timeout-minutes: 115','6660s','--management-source "$GITHUB_WORKSPACE/expanded604-management/payload"','--setup-source "$GITHUB_WORKSPACE/expanded604-setup"','--welcome-source "$GITHUB_WORKSPACE/expanded604-welcome/payload"','packet_raw_cap=4*1024**2','total<=65*1024**2','--require-bytes','--network none'):
   self.assertIn(term,text)
  self.assertEqual(text.count('secrets.'),old.count('secrets.'));self.assertIn('ROOT_BOUND_CURRENT604_NATIVE_INPUTS',(out/P.NEW/'contract.py').read_text());self.assertIn('test_current.py',text)
if __name__=='__main__':unittest.main(verbosity=2)
