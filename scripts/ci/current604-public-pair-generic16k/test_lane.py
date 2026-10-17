# SPDX-License-Identifier: MIT
"""Actor-blocked finite controls; no native or signing success fixtures."""
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
     self.assertIn('independent-installed-public-pairs-apps6-current604-management-generic16k-profile',runtime)
     self.assertIn('context604.selection(base,expected)',runtime);self.assertNotIn("all(expected.get(n)==v for n,v in base.items())",runtime)
     for filename,source in (('doctor_lifetime.py','scripts/ci/welcome-management-native/doctor_lifetime.py'),('a11y_driver.c','scripts/ci/welcome-management-native/a11y_driver.c'),('file_capabilities.py','scripts/apps/file_capabilities.py')):self.assertEqual((runner/filename).read_bytes(),(ROOT/source).read_bytes())
 def test_exact_provider_replacement_keeps_original573(self):
   base={r['name']:r['version'] for r in C.json_read(ROOT/'scripts/ci/maintained-desktop574-inputs.json')['packages']}
   expected=dict(row.split() for row in (ROOT/'scripts/ci/expanded604-apps6-public-pairs/expected604.lock').read_text().splitlines())
   incoming=ci.context604.selection(base,expected)
   self.assertEqual(len(incoming),31);self.assertIn('cachy-asahi-fdk-aac',incoming)
   self.assertEqual(base.keys()-expected.keys(),{'libfdk-aac'})
   self.assertEqual({n:v for n,v in base.items() if n!='libfdk-aac'},{n:v for n,v in expected.items() if n in base})
   for changed in ({**expected,'libfdk-aac':'3.0.0-1'},{**expected,'glibc':'wrong'},dict(expected,**{'cachy-asahi-fdk-aac':'wrong'})):
    with self.subTest(change=changed.get('glibc')),self.assertRaisesRegex(ValueError,'exact Apps6'):ci.context604.selection(base,changed)
   for changed in ({**base,'libfdk-aac':'wrong'},{k:v for k,v in base.items() if k!='glibc'}):
    with self.assertRaisesRegex(ValueError,'exact original574'):ci.context604.selection(changed,expected)
   self.assertEqual(Path(ci.context604.__file__),C.HERE/'context604.py')
   observer=(ROOT/C.OLD/'installed604.py').read_text()
   for check in ('complete actual payload hardlink set required','capability hardlink aliases','deadline=600','max_packages=604','6*1024**3','200000','database/root drift'):self.assertIn(check,observer)
 def test_unbound_and_exact_new_carriers(self):
  null=copy.deepcopy(C.policy(False));null['status']='UNBOUND_PUBLIC_PAIRS_APPS6_NATIVE_FRESH_AND_GUI_COMPONENT'
  for key in ('native604','fresh604'):null[key]={k:None for k in null[key]}
  null['welcome4_gui']['carrier_source']=None
  original=C.json_read
  with patch.object(C,'json_read',side_effect=lambda path,*args:copy.deepcopy(null) if path==C.HERE/'input-policy.json' else original(path,*args)):
   with patch.object(C,'revision',side_effect=AssertionError('Git before binding')):
    with self.assertRaisesRegex(ValueError,'UNBOUND'):ci.preflight(SimpleNamespace())
   value=C.policy(False)
  self.assertTrue(all(v is None for v in value['native604'].values()));self.assertTrue(all(v is None for v in value['fresh604'].values()))
  self.assertIsNone(value['welcome4_gui']['carrier_source']);self.assertNotIn('assets_index',value['welcome4_gui'])
  self.assertEqual(set(ci.CARRIERS)-{'legacy_source','eight_source','seven_source','management_source','setup_source','welcome_source'},{'apps6_source','apps6_authority_source'})
  self.assertIn('PUBLIC_PAIRS',C.FINAL)
  for selected in ('both',None,''):
   with self.assertRaises(ValueError):C.profile(selected)
 def test_no_asset_preparation_in_preflight_and_actual_returned_binding(self):
  raw=(ROOT/C.OLD/'ci.py').read_text();text=ci.derive(raw);m=ast.parse(text);f={n.name:n for n in m.body if isinstance(n,ast.FunctionDef)}
  pre=ast.get_source_segment(text,f['preflight']);main=ast.get_source_segment(text,f['main'])
  self.assertIn('C.authorize_assets(args,value);assets=None',pre);self.assertNotIn('prepare_assets',pre)
  self.assertLess(main.index('ordinary explicit native ARM CI only'),main.index('C.prepare_assets'))
  self.assertLess(main.index('C.prepare_assets'),main.index('producer.prepare'))
  self.assertEqual(ast.dump(f['retired'],include_attributes=False),ast.dump(next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name=='retired'),include_attributes=False))
  text=(C.HERE/'contract.py').read_text();self.assertIn("receipt['binding']",text);self.assertIn("not work.exists()",text)
  self.assertNotIn("assets_index=dict(path=",text)
 def test_actual_builder_returned_binding_is_forwarded_and_retained(self):
  with tempfile.TemporaryDirectory() as td:
   out=Path(td);args=SimpleNamespace(welcome_source=out/'packet',gui_decisions=out/'authority');value={'welcome4_gui':{'decision':{'sha256':'a'*64}}}
   binding=dict(asset_root='assets',assets_index=dict(path='index.json',bytes=123,sha256='b'*64));receipt=dict(binding=binding,authority_sha256='a'*64);report={}
   with patch.object(C,'authorize_assets'),patch.object(C.AS,'prepare',return_value=receipt) as prepare,patch.object(C.AS,'asset_directory',return_value=out/'actual-assets') as directory:
    self.assertEqual(C.prepare_assets(args,value,out,report),out/'actual-assets')
    directory.assert_called_once_with(out/'fresh-public-gui-assets',binding,ROOT)
   self.assertIs(report['public_gui_assets'],receipt);self.assertEqual(prepare.call_args.args[-2:],(out/'fresh-public-gui-assets',out/'private-test-gui-work'))
 def test_failed_signer_cannot_invoke_assets_or_become_positive(self):
  args=SimpleNamespace(welcome_source=Path('/p'),gui_decisions=Path('/a'));value={'welcome4_gui':{'decision':{'sha256':'a'*64}}};report={}
  with patch.object(C,'authorize_assets'),patch.object(C.AS,'prepare',side_effect=ValueError('original signer refused')),patch.object(C.AS,'asset_directory',side_effect=AssertionError('after failed signing')):
   with self.assertRaisesRegex(ValueError,'signer refused'):C.prepare_assets(args,value,Path('/owned'),report)
  self.assertEqual(report,{})
 def test_sanitized_gui_old_or_partial_authority_refused(self):
  for doc in ({},dict(status='ROOT_ACCEPTED_NATIVE_WELCOME4_MANAGEMENT_GUI_INDEPENDENT_PROFILES'),dict(status='ROOT_ACCEPTED_NATIVE_WELCOME4_MANAGEMENT_GUI_INDEPENDENT_PROFILES',authority_kind='DERIVED_ROOT_ACCEPTED_NATIVE_GUI_COMPONENT_FACTS',asset_binding='HISTORICAL')):
   with self.assertRaises(ValueError):C.AS.gui_component(doc,{n:dict(bytes=r[0],sha256=r[1]) for n,r in C.ARCHIVES.items()})
  text=(C.HERE/'contract.py').read_text()
  for status in ('ROOT_ACCEPTED_NATIVE_PUBLIC_PAIRS_APPS6_CURRENT604_COMPOSITION','ROOT_ACCEPTED_SIGNED_PUBLIC_PAIRS_APPS6_CURRENT604_FRESH_INSTALLER','ROOT_ACCEPTED_PUBLIC_PAIRS_APPS6_CURRENT604_TWO_PROFILE_GENERIC16K'):self.assertIn(status,text)
 def test_source_workflow_original_budgets_and_full_asset_retention_cap(self):
  C.check_source(ROOT);self.assertLessEqual(len(C.pins())+1,512)
  text=(ROOT/'.github/workflows/native-arm-current604-public-pair-generic16k.yml').read_text()
  for term in ('options: [minimal, overlay]','3700s','15600s','timeout-minutes: 350','--preflight','--decisions-only','--apps6-authority-source'):self.assertIn(term,text)
  self.assertNotIn('--apps6-native-source',text);self.assertIn('expanded604-apps6-inputs/payload',text)
  self.assertLess(text.index('--decisions-only'),text.index('secrets.CACHY'))
  r=(C.HERE/'retain.py').read_text();self.assertIn('128*1024**2',r);self.assertIn("receipt==owner['public_gui_assets']",r);self.assertIn("C.AS.asset_directory",r)
 def test_exact_recipe_complete_installer_emits_and_incomplete_old_shape_refuses(self):
  P=C.load(ROOT,C.NEW+'/prepare.py');pins=C.json_read(C.HERE/'source-pins.json');recipes=pins['installer_recipe_inputs']
  controls=pins['installer_control_inputs'];self.assertEqual(len(controls),9)
  for name,row in controls.items():self.assertEqual(P.pin((ROOT/name).read_bytes()),row)
  self.assertEqual(len(recipes),47);self.assertEqual(len(pins['groups']['installer']),273)
  self.assertEqual(C.sha((ROOT/P.INSTALLER/'source-manifest.json').read_bytes()),pins['installer_source_manifest_sha256'])
  with tempfile.TemporaryDirectory() as td:
   base=Path(td);output=base/'emitted';receipt=P.emit(ROOT,ROOT,ROOT,output)
   self.assertEqual(receipt['source_rows'],424)
   for n,pin in recipes.items():self.assertEqual(P.pin((output/n).read_bytes()),pin)
   incomplete=base/'old-incomplete';incomplete.mkdir()
   for n in pins['groups']['installer']:
    if n not in recipes and n not in controls:
     target=incomplete/n;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((ROOT/n).read_bytes())
   with self.assertRaises((ValueError,OSError)):P.source(ROOT,incomplete,ROOT)
   for name in controls:
    target=incomplete/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((ROOT/name).read_bytes())
   name=next(iter(recipes));target=incomplete/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(b'recipe drift')
   with self.assertRaisesRegex(ValueError,'pinned source differs'):P.source(ROOT,incomplete,ROOT)
 def test_two_profile_schema_requires_apps6_and_same_fresh_authority(self):
   docs={}
   for i,profile in enumerate(C.PROFILES,1):
    docs[profile]=dict(status='ROOT_ACCEPTED_PUBLIC_PAIRS_APPS6_CURRENT604_SINGLE_PROFILE_GENERIC16K',profile=profile,run_id=str(i),source_sha='a'*40,package_count=604,expected604_sha256=C.TARGET,candidate_source='0b74d8ecea4f152bda4adfbd9bee488890db4363',archives={n:dict(bytes=r[0],sha256=r[1]) for n,r in C.ARCHIVES.items()},apps6=C.APPS6,frames=12,management_operations=17,page_size=16384,cleanup='PASS',visual_review='PASS',doctor_lifetime='PASS',installed604_preserved='PASS',hardware='NOT_RUN',release='NOT_ADMITTED',**{k:'b'*64 for k in ('source_manifest_sha256','input_bindings_sha256','kernel_image_sha256','kernel_config_sha256','kernel_source_sha256','native604_decision_sha256','fresh604_decision_sha256','welcome4_gui_decision_sha256','fresh_assets_index_sha256')})
   def join(values):
    d=dict(status='ROOT_ACCEPTED_PUBLIC_PAIRS_APPS6_CURRENT604_TWO_PROFILE_GENERIC16K',profiles=list(C.PROFILES),source_sha='a'*40,expected604_sha256=C.TARGET,cleanup='PASS',hardware='NOT_RUN',release='NOT_ADMITTED',components={p:dict(run_id=v['run_id'],bytes=len(C.encoded(v)),sha256=C.sha(C.encoded(v))) for p,v in values.items()});return C.join_profiles(d,values)
   self.assertEqual(join(docs)['status'],'TWO_PROFILE_ROOT_DECISION_SCHEMA_VALID_DATA_ONLY')
   different=copy.deepcopy(docs);different['overlay']['fresh_assets_index_sha256']='c'*64;self.assertEqual(join(different)['status'],'TWO_PROFILE_ROOT_DECISION_SCHEMA_VALID_DATA_ONLY')
   for key,value in (('fresh604_decision_sha256','c'*64),('run_id','1'),('apps6',{}),('status','ROOT_ACCEPTED_CURRENT604_SINGLE_PROFILE_GENERIC16K'),('fresh_assets_index_sha256',None)):
    changed=copy.deepcopy(docs);changed['overlay'][key]=value
    with self.subTest(key=key),self.assertRaises(ValueError):join(changed)
if __name__=='__main__':unittest.main(verbosity=2)

