# SPDX-License-Identifier: MIT
"""Finite source emission/import/deadline/gate controls; no native/VM actors."""
import ast,copy,json,os,subprocess,sys,tempfile,textwrap,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import contract as C
import adapter as A
import ci,gate,retain
ROOT=C.ROOT
class Controls(unittest.TestCase):
 def setUp(self):
  self.block=patch.object(subprocess,'Popen',side_effect=AssertionError('all actors forbidden'));self.block.start();self.addCleanup(self.block.stop)
 def test_unbound_before_source_outputs_or_actors_and_profile_required(self):
  unbound=dict(C.policy(False),status='UNBOUND_CURRENT_NATIVE604_AND_FULL_WELCOME4_GUI')
  with patch.object(C,'json_read',return_value=unbound),patch.object(C,'revision',side_effect=AssertionError('source observation forbidden')):
   with self.assertRaisesRegex(ValueError,'UNBOUND'):ci.preflight(SimpleNamespace())
  for value in ('both','',None,'minimal,overlay'):
   with self.assertRaises(ValueError):C.profile(value)
  parser=ci.parser()
  for action in parser._actions:
   if action.dest!='profile':action.required=False
  with self.assertRaises(SystemExit):parser.parse_args([])
  self.assertEqual(parser.parse_args(['--profile','minimal']).profile,'minimal')
  self.assertEqual(C.PREFIX,C.NEW+'/');self.assertIn('SINGLE_PROFILE',C.PASS);self.assertIn('SINGLE_PROFILE',C.FINAL)
 def generated(self,base,selected):
  native=C.load(ROOT,'scripts/ci/welcome-management-native/prepare.py');N=native.C;candidate=native.candidates;UI=N.policy(False)['ui']
  def stage(source,assets,output):
   output.mkdir();lock=dict(status='SYNTHETIC_TEMPLATE_CONTROL_ONLY',eligibility='PRIVATE_GUI_TRIAL_ONLY',products={},policy=dict(ui=UI));(output/'candidate-lock.json').write_bytes(C.encoded(lock));return lock
  ready=base/'ready';ready.mkdir();(ready/'manifest.json').write_text('{"packages":[]}')
  with patch.object(C,'check_source'),patch.object(N,'verify_source'),patch.object(candidate,'verify_source'),patch.object(N,'policy',return_value=dict(ui=UI)),patch.object(candidate,'stage',side_effect=stage):A.prepare(ROOT,base/'runner',base/'assets',ready,selected)
  return base/'runner'
 def test_both_complete_generated_profiles_import_and_preserve_deadlines_604_guards(self):
  for selected in C.PROFILES:
   with self.subTest(profile=selected),tempfile.TemporaryDirectory() as name:
    runner=self.generated(Path(name),selected)
    for p in runner.glob('*.py'):ast.parse(p.read_bytes())
    root=(runner/'management_root.py').read_text();managed=(runner/'management_contract.py').read_text();runtime=(runner/'desktop574_runtime.py').read_text();guest=(runner/'base_guest.py').read_text();contract=(runner/'contract.py').read_text();fixture=(runner/'desktop574_fixture.sh').read_text()
    self.assertIn('INDEPENDENT_PROFILE = '+repr(selected),root);self.assertIn('len(baseline)==604',root);self.assertIn('len(inventory())==602',root)
    self.assertIn('for stage in '+repr((selected,))+':',managed);self.assertIn("'profile': "+repr(selected),runtime)
    self.assertIn('time.monotonic() + 1300',runtime);self.assertIn('signal.ITIMER_REAL, 1750',runtime);self.assertIn('TimeoutStartSec=1200',fixture)
    self.assertIn("DL.service_lease()['deadline_ns']",guest);self.assertIn("os.sysconf('SC_PAGE_SIZE')==16384",guest);self.assertIn('installed604_preserved',guest);self.assertIn('DL.validate(finals[0]',contract)
    self.assertIn('elf_audit.py --root',fixture);self.assertNotIn('hosted.fetch',runtime);self.assertNotIn("'package-build'",runtime)
    for filename,source in (('doctor_lifetime.py','scripts/ci/welcome-management-native/doctor_lifetime.py'),('a11y_driver.c','scripts/ci/welcome-management-native/a11y_driver.c'),('file_capabilities.py','scripts/apps/file_capabilities.py')):self.assertEqual((runner/filename).read_bytes(),(ROOT/source).read_bytes())
    self.assertEqual(len([v for v in __import__('ast').walk(ast.parse(managed)) if isinstance(v,ast.Constant) and v.value==604]),2)
    # Import the real generated wrapper with isolated module names but no actors.
    names=('contract','candidates','gui_contract','management_contract','management_root','doctor_lifetime','managed_contract')
    old={n:sys.modules.pop(n,None) for n in names};sys.path.insert(0,str(runner))
    try:
     m=__import__('contract');self.assertEqual(Path(m.M.__file__),runner/'management_contract.py');self.assertIn(604,m.M.verify_result.__code__.co_consts);self.assertNotIn(594,m.M.verify_result.__code__.co_consts)
    finally:
     sys.path.pop(0)
     for n in names:
      sys.modules.pop(n,None)
      if old[n] is not None:sys.modules[n]=old[n]
 def components(self):
  docs={}
  for i,p in enumerate(C.PROFILES,1):
   docs[p]=dict(status='ROOT_ACCEPTED_CURRENT604_SINGLE_PROFILE_GENERIC16K',profile=p,run_id=str(i),source_sha='a'*40,package_count=604,expected604_sha256=C.TARGET,candidate_source='0b74d8ecea4f152bda4adfbd9bee488890db4363',archives={n:dict(bytes=r[0],sha256=r[1]) for n,r in C.ARCHIVES.items()},frames=12,management_operations=17,page_size=16384,cleanup='PASS',visual_review='PASS',doctor_lifetime='PASS',installed604_preserved='PASS',hardware='NOT_RUN',release='NOT_ADMITTED',**{k:'b'*64 for k in ('source_manifest_sha256','input_bindings_sha256','kernel_image_sha256','kernel_config_sha256','kernel_source_sha256','native604_decision_sha256','welcome4_gui_decision_sha256')})
  decision=dict(status='ROOT_ACCEPTED_CURRENT604_TWO_PROFILE_GENERIC16K',profiles=list(C.PROFILES),source_sha='a'*40,expected604_sha256=C.TARGET,cleanup='PASS',hardware='NOT_RUN',release='NOT_ADMITTED')
  return decision,docs
 def joined(self,d,docs):
  d['components']={p:dict(run_id=v['run_id'],bytes=len(C.encoded(v)),sha256=C.sha(C.encoded(v))) for p,v in docs.items()};return C.join_profiles(d,docs)
 def test_two_profile_root_schema_requires_both_distinct_identical_frozen_candidates(self):
  d,docs=self.components();self.assertEqual(self.joined(d,docs)['status'],'TWO_PROFILE_ROOT_DECISION_SCHEMA_VALID_DATA_ONLY')
  for field,value in (('source_sha','c'*40),('run_id','1'),('frames',24),('visual_review','NOT_RUN'),('status',C.FINAL),('candidate_source','c'*40),('kernel_source_sha256','c'*64),('welcome4_gui_decision_sha256','c'*64)):
   d,docs=self.components();docs['overlay'][field]=value
   with self.subTest(field=field),self.assertRaises(ValueError):self.joined(d,docs)
  d,docs=self.components();docs.pop('overlay')
  with self.assertRaises(ValueError):self.joined(d,docs)
 def test_held_authority_cleanup_and_resource_bodies_unchanged(self):
  raw=C.read(ROOT/C.OLD/'contract.py').decode();self.assertIn("'ROOT_ACCEPTED_NATIVE_WELCOME4_MANAGEMENT_GUI'",raw);self.assertIn("doc.get('frames')==24",raw)
  before=ast.parse(C.read(ROOT/C.OLD/'ci.py'));after=ast.parse(ci.derive(C.read(ROOT/C.OLD/'ci.py').decode()))
  functions=lambda t:{n.name:ast.dump(n,include_attributes=False) for n in t.body if isinstance(n,ast.FunctionDef)}
  self.assertEqual(functions(before)['retired'],functions(after)['retired']);self.assertEqual(functions(before)['preflight'],functions(after)['preflight'])
  self.assertIn("len(report.get('cleanup',[]))==14",C.read(ROOT/C.OLD/'ci.py').decode())
 def test_full_upstream_gui_requires_explicit_two_actual_profile_runs_without_fake_id(self):
  native=dict(status='ROOT_ACCEPTED_NATIVE_CURRENT604_COMPOSITION',source_sha='1'*40,run_id='1',cleanup='PASS',hardware='NOT_RUN',release='NOT_ADMITTED',package_count=604,expected604_sha256=C.TARGET,installed_lifecycle='PASS',installed_six_modules='PASS',source_manifest_sha256='a'*64,input_policy_sha256='b'*64)
  gui=dict(status='ROOT_ACCEPTED_NATIVE_WELCOME4_MANAGEMENT_GUI_INDEPENDENT_PROFILES',source_sha='e0b03524745de71aa3ab2ebe16a2cfa979553442',profile_runs=dict(minimal='39014808038',overlay='39014822190'),cleanup='PASS',hardware='NOT_RUN',release='NOT_ADMITTED',frames=24,management_operations_per_profile=17,profiles=list(C.PROFILES),welcome_version='0.1.0-4',doctor_version='0.1.0-1',orphans_version='0.1.0-2',candidate_source='0b74d8ecea4f152bda4adfbd9bee488890db4363',doctor_lifetime='PASS_ACTUAL_CHILD_WAIT_RELEASE_AND_FIXED_PARENT',gui_contract='PASS',source_manifest_sha256='c'*64,archives={n:dict(bytes=r[0],sha256=r[1]) for n,r in C.ARCHIVES.items()})
  value={k:dict(source_sha=d['source_sha'],carrier_source='3'*40,decision=dict(path='x',bytes=1,sha256='d'*64),source_manifest_sha256=d['source_manifest_sha256']) for k,d in (('native604',native),('welcome4_gui',gui))};value['native604'].update(run_id='1',input_policy_sha256='b'*64);value['welcome4_gui']['profile_runs']=gui['profile_runs']
  with patch.object(C,'revision',return_value='3'*40),patch.object(C,'checked',side_effect=lambda root,row,cap:root):
   with patch.object(C,'json_read',side_effect=[native,gui]):self.assertEqual(C.decisions(Path('/native'),Path('/gui'),value)['welcome4_gui'],gui)
   for field,bad in (('status','ROOT_ACCEPTED_NATIVE_WELCOME4_MANAGEMENT_GUI'),('run_id','999'),('frames',12),('management_operations_per_profile',16),('doctor_lifetime','UNKNOWN'),('archives',{}),('profile_runs',dict(minimal='39014808038',overlay='39014808038'))):
    changed=dict(gui);changed[field]=bad
    with self.subTest(field=field),patch.object(C,'json_read',side_effect=[native,changed]),self.assertRaises(ValueError):C.decisions(Path('/native'),Path('/gui'),value)
 def test_profile_retention_selects12_without_replacing_full604_kernel_or_payload_guards(self):
  raw=C.read(ROOT/C.OLD/'retain.py').decode();derived=retain.derive(raw)
  self.assertIn("len(raw['frames'])==12",derived);self.assertIn("raw.get('profile')==selected",derived)
  for guard in ("capture['status']=='PASS_COMPLETE_ACTUAL604_CAPTURE'","final['status']=='PASS_COMPLETE_ACTUAL604_VERIFY'","owner['diagnostic_kernel']['page_size']==16384",'isolated original GUI methods replay refused','raw original GUI methods replay differs','full-tree16K'):
   if guard in raw:self.assertIn(guard,derived)
  self.assertEqual(raw.count('controller'),derived.count('controller'));self.assertIn("C.sha(C.read(runtime/'elf16k.json'))==raw['elf16k']['sha256']",derived)
 def test_current_namespace_source_manifest_and_workflow_profile_wiring(self):
  C.check_source(ROOT);text=(ROOT/'.github/workflows/native-arm-expanded604-current-management-profile16k.yml').read_text()
  self.assertEqual(text.count('--profile "$GUI_PROFILE"'),4);self.assertIn('options: [minimal, overlay]',text);self.assertIn('3700s',text);self.assertIn('15600s',text);self.assertIn('timeout-minutes: 350',text)
  self.assertLess(text.index('--preflight'),text.index('secrets.CACHY'));self.assertIn('inputs.profile',text);self.assertIn('-p test_profile.py -v',text);self.assertNotIn('-p test_lane.py',text)
if __name__=='__main__':unittest.main(verbosity=2)
