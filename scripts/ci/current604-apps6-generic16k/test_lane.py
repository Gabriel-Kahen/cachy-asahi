# SPDX-License-Identifier: MIT
"""Finite source/generator/schema controls only, never ARM/GUI/runtime credit."""
import ast,copy,json,subprocess,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import contract as C
import adapter as A
import ci,gate,retain
ROOT=C.ROOT
class Controls(unittest.TestCase):
 def setUp(self):
  p=patch.object(subprocess,'Popen',side_effect=AssertionError('all actors/Git/network forbidden'));p.start();self.addCleanup(p.stop)
 def test_unbound_before_inputs_actor_or_output_and_required_profile(self):
  with patch.object(C,'revision',side_effect=AssertionError('revision before binding')):
   with self.assertRaisesRegex(ValueError,'UNBOUND'):ci.preflight(SimpleNamespace())
  self.assertEqual(C.TARGET,'7bc6caa51301bf076aeda4d137277a128c53a16e5bfd25f02e7309c4b3a408c3');self.assertIn('APPS6',C.PASS);self.assertIn('SINGLE_PROFILE',C.FINAL)
  self.assertEqual(C.policy(False)['fresh604']['run_id'],None);self.assertEqual(C.policy(False)['welcome4_gui']['carrier_source'],None)
  self.assertEqual(set(ci.CARRIERS)-{'legacy_source','eight_source','seven_source','management_source','setup_source','welcome_source'},{'apps6_source','apps6_native_source'});self.assertIn('fresh604_decisions',ci.DECISIONS)
  for value in ('both','',None):
   with self.assertRaises(ValueError):C.profile(value)
 def generated(self,base,selected):
  native=C.load(ROOT,'scripts/ci/welcome-management-native/prepare.py');N=native.C;candidate=native.candidates;UI=N.policy(False)['ui']
  def stage(source,assets,output):
   output.mkdir();lock=dict(status='INERT_SOURCE_TEMPLATE_ONLY',eligibility='PRIVATE_GUI_TRIAL_ONLY',products={},policy=dict(ui=UI));(output/'candidate-lock.json').write_bytes(C.encoded(lock));return lock
  ready=base/'ready';ready.mkdir();(ready/'manifest.json').write_text('{"packages":[]}')
  with patch.object(C,'check_source'),patch.object(N,'verify_source'),patch.object(candidate,'verify_source'),patch.object(N,'policy',return_value=dict(ui=UI)),patch.object(candidate,'stage',side_effect=stage):A.prepare(ROOT,base/'runner',base/'assets',ready,selected)
  return base/'runner'
 def test_both_generated_profiles_keep_full_original_guards_and_budgets(self):
  for selected in C.PROFILES:
   with self.subTest(profile=selected),tempfile.TemporaryDirectory() as tmp:
    runner=self.generated(Path(tmp),selected)
    for p in runner.glob('*.py'):ast.parse(p.read_bytes())
    runtime=(runner/'desktop574_runtime.py').read_text();guest=(runner/'base_guest.py').read_text();fixture=(runner/'desktop574_fixture.sh').read_text();managed=(runner/'management_contract.py').read_text()
    self.assertIn('for stage in '+repr((selected,))+':',managed);self.assertIn('present_count',managed);self.assertIn('time.monotonic() + 1300',runtime);self.assertIn('signal.ITIMER_REAL, 1750',runtime);self.assertIn('TimeoutStartSec=1200',fixture);self.assertIn("DL.service_lease()['deadline_ns']",guest);self.assertIn("os.sysconf('SC_PAGE_SIZE')==16384",guest);self.assertIn('installed604_preserved',guest);self.assertIn('elf_audit.py --root',fixture);self.assertIn("DL.validate(finals[0]",(runner/'contract.py').read_text());self.assertNotIn('hosted.fetch',runtime)
    self.assertIn('independent-installed-apps6-current604-management-generic16k-profile',runtime)
    for filename,source in (('doctor_lifetime.py','scripts/ci/welcome-management-native/doctor_lifetime.py'),('a11y_driver.c','scripts/ci/welcome-management-native/a11y_driver.c'),('file_capabilities.py','scripts/apps/file_capabilities.py')):self.assertEqual((runner/filename).read_bytes(),(ROOT/source).read_bytes())
 def test_context_install_helpers_change_only_composition_namespace(self):
  for name,count in (('context604.py',4),('install604.py',3)):
   original=(ROOT/C.OLD/name).read_text();changed=(C.HERE/name).read_text();self.assertEqual(original.count('scripts/ci/expanded604-current-management'),count);self.assertEqual(changed,original.replace('scripts/ci/expanded604-current-management','scripts/ci/expanded604-apps6'))
  self.assertEqual(Path(ci.context604.__file__),C.HERE/'context604.py')
  observer=(ROOT/C.OLD/'installed604.py').read_text()
  for check in ('complete actual payload hardlink set required','capability hardlink aliases','deadline=600','max_packages=604','6*1024**3','200000','database/root drift'):self.assertIn(check,observer)
 def test_cleanup_predicate_and_caller_guards_remain_original(self):
  raw=(ROOT/C.OLD/'ci.py').read_text();derived=ci.derive(raw)
  funcs=lambda s:{n.name:ast.dump(n,include_attributes=False) for n in ast.parse(s).body if isinstance(n,ast.FunctionDef)}
  self.assertEqual(funcs(raw)['retired'],funcs(derived)['retired']);self.assertIn("len(report.get('cleanup',[]))==14",derived);self.assertIn('C.decisions(args.native604_decisions,args.fresh604_decisions,args.gui_decisions,value)',derived);self.assertIn('args.implementation,args.apps6_source,args.apps6_native_source)',derived)
  retained=retain.derive((ROOT/C.OLD/'retain.py').read_text())
  for field in ("len(raw['frames'])==12","owner['diagnostic_kernel']['page_size']==16384","capture['status']=='PASS_COMPLETE_ACTUAL604_CAPTURE'","final['status']=='PASS_COMPLETE_ACTUAL604_VERIFY'","C.sha(C.read(runtime/'elf16k.json'))==raw['elf16k']['sha256']"):self.assertIn(field,retained)
 def decision_data(self):
  native=dict(status='ROOT_ACCEPTED_NATIVE_APPS6_CURRENT604_COMPOSITION',source_sha='1'*40,run_id='1',cleanup='PASS',hardware='NOT_RUN',release='NOT_ADMITTED',package_count=604,expected604_sha256=C.TARGET,installed_lifecycle='PASS',installed_six_modules='PASS',source_manifest_sha256='a'*64,input_policy_sha256='b'*64)
  gui=dict(status='ROOT_ACCEPTED_NATIVE_WELCOME4_MANAGEMENT_GUI_INDEPENDENT_PROFILES',source_sha='2'*40,profile_runs=dict(minimal='2',overlay='3'),cleanup='PASS',hardware='NOT_RUN',release='NOT_ADMITTED',frames=24,management_operations_per_profile=17,profiles=list(C.PROFILES),welcome_version='0.1.0-4',doctor_version='0.1.0-1',orphans_version='0.1.0-2',candidate_source='0b74d8ecea4f152bda4adfbd9bee488890db4363',doctor_lifetime='PASS_ACTUAL_CHILD_WAIT_RELEASE_AND_FIXED_PARENT',gui_contract='PASS',source_manifest_sha256='c'*64,archives={n:dict(bytes=r[0],sha256=r[1]) for n,r in C.ARCHIVES.items()})
  fresh=dict(status='ROOT_ACCEPTED_SIGNED_APPS6_CURRENT604_FRESH_INSTALLER',source_sha='3'*40,run_id='4',source_manifest_sha256='d'*64,package_count=604,expected604_sha256=C.TARGET,ordinary_parent_retired='PASS',independent_root_readback='PASS',cleanup='PASS',hardware='NOT_RUN',release='NOT_ADMITTED',native604_decision_sha256='e'*64)
  value={k:dict(source_sha=d['source_sha'],carrier_source='4'*40,decision=dict(path='x',bytes=1,sha256='e'*64),source_manifest_sha256=d['source_manifest_sha256']) for k,d in (('native604',native),('welcome4_gui',gui),('fresh604',fresh))};value['native604'].update(run_id='1',input_policy_sha256='b'*64);value['welcome4_gui']['profile_runs']=gui['profile_runs'];value['fresh604'].update(run_id='4',native604_decision_sha256='e'*64);return value,native,gui,fresh
 def test_new_fresh_authority_is_mandatory_exact_same_native_hash(self):
  v,n,g,f=self.decision_data()
  with patch.object(C,'revision',return_value='4'*40),patch.object(C,'checked',side_effect=lambda root,row,cap:root):
   with patch.object(C,'json_read',side_effect=[n,g,f]):self.assertEqual(C.decisions(Path('/n'),Path('/f'),Path('/g'),v)['fresh604'],f)
   for key,wrong in (('status','ROOT_ACCEPTED_SIGNED_CURRENT604_FRESH_INSTALLER'),('expected604_sha256','0'*64),('independent_root_readback','UNKNOWN'),('native604_decision_sha256','f'*64)):
    bad=dict(f);bad[key]=wrong
    with self.subTest(key=key),patch.object(C,'json_read',side_effect=[n,g,bad]),self.assertRaises(ValueError):C.decisions(Path('/n'),Path('/f'),Path('/g'),v)
 def test_single_or_failed_gui_cannot_supply_full_upstream_gui(self):
  v,n,g,f=self.decision_data()
  for key,wrong in (('frames',12),('management_operations_per_profile',16),('doctor_lifetime','UNKNOWN'),('profile_runs',dict(minimal='2',overlay='2'))):
   bad=dict(g);bad[key]=wrong
   with self.subTest(key=key),patch.object(C,'revision',return_value='4'*40),patch.object(C,'checked',side_effect=lambda root,row,cap:root),patch.object(C,'json_read',side_effect=[n,bad]),self.assertRaises(ValueError):C.decisions(Path('/n'),Path('/f'),Path('/g'),v)
 def test_source_closure_and_workflow_profile_payload_roles_and_budgets(self):
  C.check_source(ROOT);self.assertLessEqual(len(C.pins())+1,512)
  text=(ROOT/'.github/workflows/native-arm-current604-apps6-generic16k.yml').read_text();self.assertEqual(text.count('--profile "$GUI_PROFILE"'),4);self.assertEqual(text.count('--fresh604-decisions "$GITHUB_WORKSPACE/expanded604-apps6-fresh604-decisions"'),3);self.assertEqual(text.count('--apps6-source "$GITHUB_WORKSPACE/expanded604-apps6-inputs/payload"'),2)
  for value in ('options: [minimal, overlay]','3700s','15600s','timeout-minutes: 350','--preflight','-p test_lane.py -v'):self.assertIn(value,text)
  self.assertLess(text.index('--preflight'),text.index('secrets.CACHY'));self.assertNotIn('ignore.git',text)

 def test_two_profile_schema_requires_apps6_and_same_fresh_authority(self):
  docs={}
  for i,profile in enumerate(C.PROFILES,1):
   docs[profile]=dict(status='ROOT_ACCEPTED_APPS6_CURRENT604_SINGLE_PROFILE_GENERIC16K',profile=profile,run_id=str(i),source_sha='a'*40,package_count=604,expected604_sha256=C.TARGET,candidate_source='0b74d8ecea4f152bda4adfbd9bee488890db4363',archives={n:dict(bytes=r[0],sha256=r[1]) for n,r in C.ARCHIVES.items()},apps6=C.APPS6,frames=12,management_operations=17,page_size=16384,cleanup='PASS',visual_review='PASS',doctor_lifetime='PASS',installed604_preserved='PASS',hardware='NOT_RUN',release='NOT_ADMITTED',**{k:'b'*64 for k in ('source_manifest_sha256','input_bindings_sha256','kernel_image_sha256','kernel_config_sha256','kernel_source_sha256','native604_decision_sha256','fresh604_decision_sha256','welcome4_gui_decision_sha256')})
  def join(values):
   d=dict(status='ROOT_ACCEPTED_APPS6_CURRENT604_TWO_PROFILE_GENERIC16K',profiles=list(C.PROFILES),source_sha='a'*40,expected604_sha256=C.TARGET,cleanup='PASS',hardware='NOT_RUN',release='NOT_ADMITTED',components={p:dict(run_id=v['run_id'],bytes=len(C.encoded(v)),sha256=C.sha(C.encoded(v))) for p,v in values.items()});return C.join_profiles(d,values)
  self.assertEqual(join(docs)['status'],'TWO_PROFILE_ROOT_DECISION_SCHEMA_VALID_DATA_ONLY')
  for key,value in (('fresh604_decision_sha256','c'*64),('run_id','1'),('apps6',{}),('status','ROOT_ACCEPTED_CURRENT604_SINGLE_PROFILE_GENERIC16K')):
   changed=copy.deepcopy(docs);changed['overlay'][key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):join(changed)

if __name__=='__main__':unittest.main(verbosity=2)
