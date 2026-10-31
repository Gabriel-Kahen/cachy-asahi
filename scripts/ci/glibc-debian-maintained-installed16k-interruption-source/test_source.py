# SPDX-License-Identifier: MIT
"""Real source-only generation and refusal controls; no accepted actual fixtures."""
import ast,copy,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import prepare as P
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
NORMAL=Path(os.environ['MAINTAINED_INTERRUPTION_NORMAL_SOURCE']);NATIVE=Path(os.environ['MAINTAINED_INTERRUPTION_NATIVE_SOURCE'])
def funcs(raw):return{n.name:ast.get_source_segment(raw.decode(),n)for n in ast.parse(raw).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.temp=tempfile.TemporaryDirectory();cls.addClassCleanup(cls.temp.cleanup);cls.work=Path(cls.temp.name);cls.out=cls.work/'emitted'
  with patch.object(subprocess,'Popen',side_effect=AssertionError('source only, no actors/network/Git')):cls.receipt=P.derive(ROOT,NORMAL,NATIVE,cls.out)
  cls.folder=cls.out/P.LANE;cls.C=P.load('test_maintained_interruption_contract',cls.folder/'contract.py')
 def setUp(self):
  p=patch.object(subprocess,'Popen',side_effect=AssertionError('no actors/network/Git'));p.start();self.addCleanup(p.stop)
 def test_whole157_165_and_exact_alias_exclusion(self):
  v=P.snapshots(NORMAL,NATIVE);self.assertEqual(len(v['normal']['files']),157);self.assertEqual(len(v['native']['files']),165)
  self.assertEqual(v['normal']['source'],'34548c30fa5b0d65172eba2302ddcb4a07840488');self.assertEqual(v['native']['source'],'73da7728469c7c11b5877ba47645bf812ac6dbdc');self.assertFalse((self.out/'.github/workflows/native-arm-build.yml').exists())
 def test_closed236_bundle219_dependencies16_derived_and_null_runtime_gate(self):
  self.assertEqual(self.receipt['source_files'],219);self.assertEqual(self.receipt['derived_files'],16);self.assertEqual(self.receipt['bundle_files'],236);self.assertEqual(sum(p.is_file()for p in self.out.rglob('*')),236);self.C.check_source(self.out)
  policy=P.decode(P.read(self.folder/'input-policy.json'));self.assertEqual(policy['binding'],dict.fromkeys(P.KINDS))
  with self.assertRaisesRegex(ValueError,'UNBOUND'):self.C.gate(Path('/absent'))
  with patch.dict(sys.modules,{'contract':self.C}):run=P.load('test_held_run',self.folder/'run.py')
  with self.assertRaisesRegex(ValueError,'UNBOUND'):run.execute(type('Args',(),dict(acceptances=Path('/absent')))())
 def test_four_native_edits20_bodies_actual_interruption_maintained_identity(self):
  with patch.dict(sys.modules,{'contract':self.C}):adapter=P.load('test_exact_native_adapter',self.folder/'adapter.py')
  text,r=adapter.derive(self.out);self.assertEqual(r['counted_edits'],4);self.assertEqual(r['changed_bodies'],['guard','validate_runtime']);self.assertEqual(len(r['unchanged_bodies']),20)
  before,after=funcs(P.read(self.out/P.NATIVE/'container.py')),funcs(text.encode())
  for n in('transaction','run_case','copy_probes','runtime_mounts','snapshot','main','Commands'):self.assertEqual(before[n],after[n],n)
  self.assertIn('interruption.exercise',text);self.assertIn('caa_debian_maintained_interrupted16k=1',text)
 def test_recovery_exact_three_native_owner_bodies_only_two_required_edits(self):
  original=funcs(P.read(self.out/(P.NATIVE+'-owner')/'job.py'));expected='import json,signal,stat\nfrom pathlib import Path\nimport contract as C\nneed=C.need\n\n'+'\n\n'.join(original[n]for n in('ordinary','read','consumer_records'))+'\n'
  for a,b in(("public=output/'inner/public'","public=output"),("runtime['result']['page_size']==4096","runtime['result']['page_size']==16384")):self.assertEqual(expected.count(a),1);expected=expected.replace(a,b)
  self.assertEqual(P.read(self.folder/'recovery.py'),expected.encode())
 def test_345_private_path_and_fresh_copy_functions_byteheld_first_observer_only(self):
  a,b=funcs(P.read(NORMAL/P.NORMAL/'guest.py')),funcs(P.read(self.folder/'guest.py'))
  for n in('_copy_clone','_copy_relative','_copy_path_roots','_copy_scoped_aux','_copy_capability_bridge','observer_file_limit'):self.assertEqual(a[n],b[n],n)
  for n in('supervised_progress','inner_failure_report','child_failure'):self.assertEqual(a[n],b[n].replace('DEBIAN_MAINTAINED_INTERRUPTED16K','GNU_INSTALLED16K').replace('/debian-maintained-installed16k-interruption','/installed16k'),n)
  self.assertIn("api['capabilities']=_copy_capability_bridge",b['install_progress']);self.assertIn('def first_observation(',P.read(self.folder/'guest.py').decode());self.assertNotIn('FirstObserverComplete',P.read(self.folder/'guest.py').decode())
 def test_native_runtime_caps_and_all_security_budgets_held(self):
  for name in('sandbox.py','snapshot_progress.py','observer_progress.py'):self.assertEqual(P.read(self.folder/name),P.read(NORMAL/P.NORMAL/name))
  guest=P.read(self.folder/'guest.py').decode();run=P.read(self.folder/'run.py').decode();prepare=P.read(self.folder/'prepare.py').decode()
  for term in('10500,512*1024','normal_runtime_observations=10',"'recovered_runtime'",'recovery.consumer_records'):self.assertIn(term,guest)
  for term in('seconds=10800','cap=16*1024**2','--network=none','--cap-drop=ALL','free>=48*C.GIB','544*1024**2','arm64.nomops'):self.assertIn(term,run)
  for term in('umount /volume','umount /dev','remount,bind,ro /held','16*C.GIB','24*C.GIB','allocated<=10*C.GIB','copy_guest_sources'):self.assertIn(term,prepare)
  self.assertIn('CAPS=(0,1,3,4,5,6,7,18,21,31)',P.read(self.folder/'sandbox.py').decode())
 def test_source_only_default_refuses_preflight_assemble_before_paths_outputs(self):
  args=dict(root=Path('/absent'),inputs=dict.fromkeys(P.KINDS),env={})
  with self.assertRaisesRegex(ValueError,'UNBOUND'):P.preflight(**args)
  out=self.work/'forbidden'
  with self.assertRaisesRegex(ValueError,'UNBOUND'):P.assemble(Path('/absent'),Path('/absent'),Path('/absent'),out,{},dict.fromkeys(P.KINDS),{},self.work/'public-forbidden')
  self.assertFalse(out.exists());self.assertFalse((self.work/'public-forbidden').exists())
 def test_old_e07_b07_staged_receipt_cannot_be_native_or_normal_decision(self):
  phase=P.load('test_no_transfer_schema',HERE/'phase_gate.py');old=P.decode(P.read(NATIVE/P.NATIVE_ROUTE/'known-native-normal.json'))
  for kind in P.KINDS:
   for v in({},old,dict(status='ROOT_ACCEPTED_CONVENTIONAL_PROVIDER_INTERRUPTION_RECOVERY',source_sha='365c952fcfbdc7d4760313df4d5fa1da7c8a2120'),dict(status='ROOT_ACCEPTED_DEBIAN_MAINTAINED_SYSTEM_PATHS_GENERIC16K',ALPM_installation='NOT_RUN')):
    with self.subTest(kind=kind),self.assertRaises(ValueError):phase.fields(v,kind,phase.EXPECTED,phase.PROVIDER)
 def test_exact_expected_source_and_both_manifest_descriptors_are_data_not_decisions(self):
  phase=P.load('test_finite_expected_schema',HERE/'phase_gate.py');v=P.decode(P.read(HERE/'source-inputs.json'));self.assertEqual(phase.EXPECTED,v['expected_decisions']);self.assertEqual(phase.PROVIDER,v['provider'])
  for kind,root in(('native_interruption',NATIVE),('normal_installed16k',NORMAL)):
   row=phase.EXPECTED[kind];self.assertEqual(row['integration_manifest'],dict(path=row['integration_manifest']['path'],**P.pin(P.read(root/row['integration_manifest']['path']))));self.assertEqual(row['zero_commit_refusals'],2)
  self.assertEqual(phase.EXPECTED['native_interruption']['complete574_maps'],20);self.assertEqual(phase.EXPECTED['normal_installed16k']['complete574_maps'],16)
  policy=P.decode(P.read(HERE/'policy.json'));self.assertEqual(policy['binding'],dict.fromkeys(P.KINDS));self.assertIsNone(policy['Root_interruption16k_decision'])
 def test_closed_snapshot_missing_changed_extra_alias_refuse(self):
  for kind in('missing','changed','extra','alias'):
   with tempfile.TemporaryDirectory()as td:
    root=Path(td)/'native';shutil.copytree(NATIVE,root);n=next(iter(P.decode(P.read(HERE/'source-inputs.json'))['native']['files']));p=root/n
    if kind=='missing':p.unlink()
    elif kind=='changed':p.write_bytes(p.read_bytes()+b'\n')
    elif kind=='extra':(root/'unrecognized').write_bytes(b'x')
    else:p.unlink();p.symlink_to(NATIVE/n)
    with self.subTest(kind=kind),self.assertRaises(ValueError):P.snapshots(NORMAL,root)
 def test_duplicate_nonfinite_unsafe_descriptors_and_null_refuse(self):
  for raw in(b'{"x":1,"x":2}',b'{"x":NaN}'):
   with self.assertRaises(ValueError):P.decode(raw)
  for row in(None,{},dict(ref='0'*40,path='../escape',bytes=1,sha256='0'*64),dict(ref=None,path='decision.json',bytes=1,sha256='0'*64),dict(ref='0'*40,path='bad\nname',bytes=1,sha256='0'*64)):
   with self.assertRaises(ValueError):P.descriptor(row)
 def test_workflow_fixed_argv_roles_order_and_literal_environment_names(self):
  t=P.read(ROOT/P.WF).decode();self.assertIn('MAINTAINED_INTERRUPTION_NORMAL_SOURCE="$GITHUB_WORKSPACE/normal-component"',t);self.assertIn('MAINTAINED_INTERRUPTION_NATIVE_SOURCE="$GITHUB_WORKSPACE/native-component"',t);self.assertNotIn('MAINTAINED_INTERRUPTION_scripts/',t)
  order=[t.index(n)for n in('id: decisions','path: native-component','id: wiring','id: proof','secrets.','Reuse unchanged owned574 native producer','Provision accepted kernel','id: installed16k','Retire every clone')];self.assertEqual(order,sorted(order))
  self.assertIn('timeout-minutes: 360',t);self.assertIn('2300s',t);self.assertIn('3700s',t);self.assertNotIn('--privileged',t)
  self.assertIn('--workspace "$BUNDLE" --proof',t);self.assertIn('--output "$BUNDLE"',t)
if __name__=='__main__':unittest.main(verbosity=2)
