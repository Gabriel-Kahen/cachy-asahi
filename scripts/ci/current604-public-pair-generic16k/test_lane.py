# SPDX-License-Identifier: MIT
"""Actor-blocked finite controls; no native or signing success fixtures."""
import stat
import textwrap
import ast,copy,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch,Mock
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
    output.mkdir();lock=dict(status='INERT_SOURCE_TEMPLATE_ONLY',eligibility='PRIVATE_GUI_TRIAL_ONLY',products={},policy=dict(ui=UI),producer_lifecycle='PASS_SAME_JOB_SIGNED_THREE_PRODUCT_LIFECYCLE');(output/'candidate-lock.json').write_bytes(C.encoded(lock));return lock
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
     for filename,source in (('doctor_lifetime.py','scripts/ci/welcome-management-native/doctor_lifetime.py'),('a11y_driver.c','scripts/ci/welcome-management-native/a11y_driver.c'),('file_capabilities.py','scripts/apps/file_capabilities.py')):
      original=(ROOT/source).read_bytes();self.assertEqual((runner/filename).read_bytes(),A.peer_focus_driver(original) if filename=='a11y_driver.c' else A.doctor_publication(original) if filename=='doctor_lifetime.py' else original)
 def test_generated_host_and_guest_locks_are_exactly_equal_both_profiles(self):
  for selected in C.PROFILES:
   with self.subTest(profile=selected),tempfile.TemporaryDirectory()as td:
    runner=self.generated(Path(td),selected)
    self.assertEqual((runner/'candidate-lock.json').read_bytes(),(runner/'candidates/candidate-lock.json').read_bytes())
    self.assertEqual(C.json_read(runner/'candidate-lock.json')['producer_lifecycle'],'ROOT_ACCEPTED_NATIVE604_AND_SEPARATE_CURRENT_WELCOME4_GUI')
 def test_candidate_lock_alignment_refuses_foreign_inputs_and_qualification(self):
  for changed in ('products','producer_lifecycle','extra'):
   with self.subTest(changed=changed),tempfile.TemporaryDirectory()as td:
    root=Path(td);(root/'candidates').mkdir()
    guest=dict(products={'unit':'inert'},producer_lifecycle='ROOT_ACCEPTED_NATIVE604_AND_SEPARATE_CURRENT_WELCOME4_GUI')
    host=dict(guest,producer_lifecycle='PASS_SAME_JOB_SIGNED_THREE_PRODUCT_LIFECYCLE')
    host[changed]={'foreign':'inert'} if changed=='products' else 'foreign'
    C.save(root/'candidate-lock.json',guest);C.save(root/'candidates/candidate-lock.json',host)
    before=C.read(root/'candidates/candidate-lock.json')
    with self.assertRaises(ValueError):A.align_candidate_locks(root)
    self.assertEqual(C.read(root/'candidates/candidate-lock.json'),before)
 def test_failed_controller_exports_only_fixed_bounded_original_build_log_without_authority(self):
  for log_name in ('runtime-image.log','qemu-tooling-image.log'):
   # Execute the actual derived owner.main failure/finally path. Every producer,
   # signer and controller actor is inert; only real ordinary test-file IO occurs.
   for selected in C.PROFILES:
    for mode in ('present','missing','symlink','hardlink','over-cap'):
     with self.subTest(profile=selected,mode=mode),tempfile.TemporaryDirectory(dir='/tmp') as td:
      base=Path(td);output=base.with_name(base.name+'-output');producer_output=output.with_name(output.name+'-producer');kernel=base/'kernel';kernel.mkdir();image=kernel/'Image';image.write_bytes(b'UNIT_NOT_A_KERNEL');config=kernel/'config';config.write_bytes(b'UNIT_NOT_A_CONFIG');marker=b'UNIT_ORIGINAL_DOCKER_BUILD_STDERR_NOT_RUNTIME_SUCCESS\n'
      args=SimpleNamespace(**{n:base/'inert-input' for n in (*ci.PRODUCER_PATHS,*ci.CARRIERS,*ci.DECISIONS,'audio_inputs')},implementation=ROOT,implementation_revision='a'*40,profile=selected,output=output,kernel_work=kernel,kernel_receipt=base/'inert-kernel-receipt')
      cleanup=Mock(side_effect=AssertionError('unknown retirement must preserve producer'))
      def produce(original):
       producer_output.mkdir();(producer_output/'producer-owner.json').write_text('{"unit":"inert"}');return base/'inert-ready'
      producer=SimpleNamespace(prepare=produce,cleanup=cleanup);materializer=SimpleNamespace(prepare=lambda *a:None);installer=SimpleNamespace(LEGACY='b'*40,COMPOSITION=object(),load=lambda *a:producer,scoped_load=lambda *a:materializer)
      def prepare(*a):a[1].mkdir()
      controller=dict(exit=1,natural_exit=True,group_absent=True)
      def supervise(argv,log):
       runtime=base/'current604-public-pair-generic16k-runtime';runtime.mkdir();raw=dict(status='FAIL',profile=selected,error='command failed: runtime-image',cleanup=[],events=[],frames={});(runtime/'runtime.json').write_bytes(C.encoded(raw));log.write_bytes(b'UNIT_FAILED_CONTROLLER')
       path=runtime/log_name
       if mode=='present':path.write_bytes(marker)
       elif mode=='symlink':
        other=base/'private-not-exported';other.write_bytes(b'PRIVATE_UNIT_SECRET');path.symlink_to(other)
       elif mode=='hardlink':path.write_bytes(marker);os.link(path,base/'alias')
       elif mode=='over-cap':
        with path.open('wb') as stream:stream.truncate(16*1024**2+1)
       return controller
      runtime=SimpleNamespace(kernel=lambda *a:(dict(Image=dict(sha256=C.sha(image.read_bytes()))),{},image,config),supervise=supervise)
      actual=ci._BASE
      try:
       with patch.object(actual,'parser',return_value=SimpleNamespace(parse_args=lambda _:args)),patch.object(actual,'preflight',return_value=({}, {}, object(), {}, base/'inert-assets',installer)),patch.object(actual.platform,'machine',return_value='aarch64'),patch.dict(os.environ,GITHUB_ACTIONS='true',RUNNER_ARCH='ARM64',RUNNER_TEMP=str(base)),patch.object(C,'prepare_assets',return_value=base/'inert-assets'),patch.object(C,'load',side_effect=lambda root,path:runtime if path.endswith('/run.py') else object()),patch.object(A,'prepare',side_effect=prepare),patch.object(ci.context604,'prepare'),patch.object(ci.context604,'preserve_producer_image') as preservation,patch.object(ci.KP,'kernel',side_effect=lambda original,args:original.kernel(args)):
        if mode in ('hardlink','over-cap'):
         with self.assertRaisesRegex(ValueError,'bounded ordinary'):ci.main([])
         self.assertFalse((output/'public/retention.json').exists())
        else:
         self.assertEqual(ci.main([]),1);report=C.json_read(output/'result.json');ledger=C.json_read(output/'public/retention.json');self.assertEqual(report['status'],'FAIL');self.assertEqual(report['cleanup'],'RETAINED_CONSUMER_OR_PRODUCER_ABSENCE_UNKNOWN');self.assertEqual(ledger['status'],'NOT_ACCEPTED');self.assertEqual(ledger['ordered_private_cleanup'],report['cleanup']);name='runtime/'+log_name
         if mode=='present':self.assertEqual((output/'public'/name).read_bytes(),marker);self.assertEqual(ledger['files'][name],dict(bytes=len(marker),sha256=C.sha(marker)))
         else:self.assertNotIn(name,ledger['files'])
         self.assertLessEqual(ledger['bytes'],128*1024**2);self.assertNotIn('private-not-exported',str(ledger))
       preservation.assert_called_once_with(producer_output,unittest.mock.ANY)
       cleanup.assert_not_called();self.assertTrue(kernel.exists());self.assertTrue((producer_output/'producer-owner.json').exists())
      finally:
       for path in (output,producer_output):
        if path.exists():shutil.rmtree(path)
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
  self.assertEqual(ast.dump(f['retired'],include_attributes=False),ast.dump(next(n for n in ast.parse(raw.replace("len(report.get('cleanup',[]))==14","len(report.get('cleanup',[]))==15 and context604.launcher_retired(report,C.ROOT)")).body if isinstance(n,ast.FunctionDef) and n.name=='retired'),include_attributes=False))
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
   self.assertEqual(receipt['source_rows'],len(P.source(ROOT,ROOT,ROOT))+len(P.OWN)+1)
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
class BuildContextGuard(unittest.TestCase):
 def module(self):
  import importlib.util
  p=C.HERE/'install604.py';s=importlib.util.spec_from_file_location('_current604_build_guard_control',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
 def test_actual_host_refuses_before_any_installer_or_package_method(self):
  import io
  from contextlib import redirect_stdout
  m=self.module();capture=io.StringIO()
  with patch.object(m.sys,'argv',[str(m.__file__)]),patch.object(m,'load',side_effect=AssertionError('host must refuse before source imports')),redirect_stdout(capture),self.assertRaises(ValueError):m.install()
  facts=json.loads(capture.getvalue().split(' ',1)[1]);self.assertIn('euid',facts);self.assertIn('machine',facts);self.assertFalse(facts['buildkit_context'])
 def test_all_original_predicates_and_explicit_context_refusals_are_retained(self):
  import io
  from contextlib import redirect_stdout
  from types import SimpleNamespace
  m=self.module()
  def invoke(uid=0,machine='aarch64',marker=False,systemd=False,context=True,explicit=True):
   factory=lambda p:SimpleNamespace(is_file=lambda:marker,exists=lambda:systemd)
   args=[str(m.__file__)]+(['--owned-buildkit-context','a'*64]if explicit else [])
   with patch.object(m.sys,'argv',args),patch.object(m.os,'geteuid',return_value=uid),patch.object(m.os,'uname',return_value=SimpleNamespace(machine=machine)),patch.object(m,'Path',side_effect=factory),patch.object(m,'build_admission',side_effect=None if context else ValueError('invalid readonly binding'),return_value=True),redirect_stdout(io.StringIO()):return m.build_guard()
  # Inert predicate-only fragments do not execute installation or claim native success.
  invoke();invoke(marker=True,explicit=False)
  for args in ({'uid':1000},{'machine':'x86_64'},{'systemd':True},{'context':False,'marker':True},{'explicit':False,'marker':False}):
   with self.subTest(args=args),self.assertRaises(ValueError):invoke(**args)
  node=next(n for n in ast.parse((C.HERE/'install604.py').read_bytes()).body if isinstance(n,ast.FunctionDef)and n.name=='install');self.assertEqual(ast.dump(node.body[0]),ast.dump(ast.parse('build_guard()').body[0]))
 def test_both_generated_dockerfiles_use_exact_readonly_context_digest_and_explicit_root(self):
  import hashlib
  for selected in C.PROFILES:
   with self.subTest(profile=selected),tempfile.TemporaryDirectory()as td:
    base=Path(td);runner=Controls.generated(self,base,selected);runtime=(runner/'desktop574_runtime.py').read_text();self.assertEqual(runtime.count("(context/'Dockerfile').write_text(context604.dockerfile(base_reference,context))"),1)
    context=base/'context';context.mkdir();raw=b'UNIT_CONTEXT_BYTES_ONLY';(context/'build-authorization.json').write_bytes(raw);text=ci.context604.dockerfile('cachy-asahi-desktop574-base:'+'a'*32,context)
    self.assertIn('\nUSER 0:0\n',text);self.assertIn('RUN --network=none --mount=type=bind,source=build-authorization.json,target=/run/cachy-asahi-managed604-build.json,ro ',text);self.assertIn('--owned-buildkit-context '+hashlib.sha256(raw).hexdigest(),text);self.assertNotIn('touch /.dockerenv',text);self.assertIn("'runtime-image',300",runtime)
    self.assertIn('build-authorization.json',(C.HERE/'context604.py').read_text())

class SeparateQemuToolingControls(unittest.TestCase):
 def setUp(self):
  p=patch.object(subprocess,'Popen',side_effect=AssertionError('no actors/Git/network'));p.start();self.addCleanup(p.stop)
 def make(self,root,fail=False):
  import hashlib
  base={r['name']:r['version']for r in C.json_read(ROOT/'scripts/ci/maintained-desktop574-inputs.json')['packages']};calls=[];build=[];images=['sha256:'+'b'*64]
  # Explicit inert byte-transport fixture; no package/signature/native PASS.
  source=root/'unit-source';(source/'scripts/virtual').mkdir(parents=True);packet=root/'unit-packet';packet.mkdir();lock=copy.deepcopy(C.json_read(ROOT/'scripts/virtual/tooling.lock.json'));files={}
  for row in lock['keyring_files']:
   raw=('INERT_KEY:'+row['filename']).encode();row.update(size=len(raw),sha256=hashlib.sha256(raw).hexdigest());(packet/row['filename']).write_bytes(raw);files[row['filename']]=dict(bytes=len(raw),sha256=row['sha256'])
  for row in lock['packages']:
   for sig in(False,True):
    n=row['filename']+('.sig'if sig else'');raw=('INERT_INPUT:'+n).encode();(packet/n).write_bytes(raw);row['signature_size'if sig else'size']=len(raw);row['signature_sha256'if sig else'sha256']=hashlib.sha256(raw).hexdigest();files[n]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
  raw=C.encoded(lock);(source/'scripts/virtual/tooling.lock.json').write_bytes(raw);(packet/'index.json').write_bytes(C.encoded(dict(schema_version=1,purpose='installer-full26-generic-vm-tooling-inputs',tooling_lock_sha256=hashlib.sha256(raw).hexdigest(),files=files)))
  def execute(argv,label,seconds):
   build.append((argv,label,seconds))
   if fail:raise ValueError('UNIT genuine build refusal')
   Path(argv[argv.index('--iidfile')+1]).write_text('sha256:'+'c'*64+'\n')
  q=ci.context604.tooling_image(source,base,'sha256:'+'a'*64,'cachy-asahi-desktop574-base:'+'d'*32,root,images,packet,execute)
  return q,lock,build,images
 def test_original32_pinned_tooling_transfers_only_build_separate590_image(self):
  import hashlib
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);q,tooling,build,images=self.make(root);self.assertEqual(images,['sha256:'+'b'*64,'sha256:'+'c'*64]);self.assertEqual(q['package_count'],590)
   selected=list((root/'qemu-tooling-context/tooling').iterdir());self.assertEqual(len(selected),32);self.assertEqual(q['retained_inputs']['files'],45);self.assertEqual(q['retained_inputs']['network'],'NOT_USED')
   for target in selected:
    original=next(r for r in tooling['packages']if target.name.removesuffix('.sig')==r['filename']);sig=target.name.endswith('.sig');raw=target.read_bytes();self.assertEqual((hashlib.sha256(raw).hexdigest(),len(raw)),(original['signature_sha256'if sig else'sha256'],original['signature_size'if sig else'size']))
   text=(root/'qemu-tooling-context/Dockerfile').read_text();self.assertIn('USER 0:0',text);self.assertIn('pacman -U --noconfirm --noscriptlet /tmp/tooling/*.pkg.tar.xz',text);self.assertIn('cmp /expected-qemu-tooling.lock /qemu-tooling-packages.lock',text);self.assertIn('qemu-system-aarch64 --version',text);self.assertNotIn('--nodeps',text);self.assertNotIn('SigLevel',text)
   argv,label,seconds=build[0];self.assertEqual(argv[:4],['docker','build','--network=none','--pull=false']);self.assertEqual((label,seconds),('qemu-tooling-image',300));self.assertEqual(len((root/'qemu-tooling-context/expected.lock').read_text().splitlines()),590)
 def test_extra_image_absence_duplicate_failure_or_wrong_identity_blocks_producer_retirement(self):
  with tempfile.TemporaryDirectory()as td:q,_,_,_=self.make(Path(td))
  # Inert retirement receipt uses exact source-static expected metadata; it is
  # neither a collected image nor a positive native construction claim.
  import hashlib
  lock=C.json_read(ROOT/'scripts/virtual/tooling.lock.json');base={r['name']for r in C.json_read(ROOT/'scripts/ci/maintained-desktop574-inputs.json')['packages']};extra=[r for r in lock['packages']if r['name']not in base];q['tooling_packages']={r['name']:dict(version=r['version'],sha256=r['sha256'],signature_sha256=r['signature_sha256'])for r in extra};q['tooling_lock_sha256']=hashlib.sha256((ROOT/'scripts/virtual/tooling.lock.json').read_bytes()).hexdigest()
  blobs=lock['keyring_files']+[v for r in lock['packages']for v in(r,dict(filename=r['filename']+'.sig',size=r['signature_size'],sha256=r['signature_sha256']))];index=dict(schema_version=1,purpose='installer-full26-generic-vm-tooling-inputs',tooling_lock_sha256=q['tooling_lock_sha256'],files={r['filename']:dict(bytes=r['size'],sha256=r['sha256'])for r in blobs});q['retained_inputs']['index_sha256']=hashlib.sha256(C.encoded(index)).hexdigest()
  cleanup=[dict(action='original-role-'+str(n),exit=0)for n in range(12)]+[dict(action='remove-image:'+'sha256:'+'b'*64,exit=0),dict(guest_disk_removed=True),dict(action='remove-image:'+q['image'],exit=0)]
  raw=dict(qemu_launcher=q,base_image='sha256:'+'a'*64,runtime_image='sha256:'+'b'*64,base_reference=q['base_reference'],cleanup=cleanup,base_reference_cleanup=dict(ok=True));controller=dict(natural_exit=True,group_absent=True)
  self.assertTrue(ci.retired(raw,controller))
  for kind in ('absent','failed','duplicate','identity','group','old-role','package','build'):
   bad=copy.deepcopy(raw);ctl=dict(controller)
   if kind=='absent':bad['cleanup'].pop()
   elif kind=='failed':bad['cleanup'][-1]['exit']=1
   elif kind=='duplicate':bad['cleanup'].append(dict(bad['cleanup'][-1]))
   elif kind=='identity':bad['qemu_launcher']['image']=bad['runtime_image']
   elif kind=='group':ctl['group_absent']=False
   elif kind=='package':bad['qemu_launcher']['tooling_packages']['qemu-system-aarch64']['sha256']='0'*64
   elif kind=='build':bad['qemu_launcher']['build']['argv'][2]='--network=host'
   else:bad['cleanup'][0]['exit']=1
   self.assertFalse(ci.retired(bad,ctl),kind)
 def test_changed_missing_or_aliased_tooling_packet_refuses_before_build(self):
  for kind in ('changed','missing','alias'):
   with tempfile.TemporaryDirectory()as td:
    root=Path(td);self.make(root);packet=root/'unit-packet';lock=C.json_read(root/'unit-source/scripts/virtual/tooling.lock.json');raw=(root/'unit-source/scripts/virtual/tooling.lock.json').read_bytes();leaf=packet/lock['packages'][0]['filename']
    if kind=='changed':leaf.write_bytes(b'CHANGED')
    elif kind=='missing':leaf.unlink()
    else:leaf.unlink();leaf.symlink_to(packet/'index.json')
    with self.assertRaises(ValueError):ci.context604.tooling_packet(packet,lock,raw)
 def test_failed_tooling_build_cannot_create_positive_image_receipt(self):
  with tempfile.TemporaryDirectory()as td:
   with self.assertRaisesRegex(ValueError,'build refusal'):self.make(Path(td),True)
 def test_both_profile_generators_use_tool_image_only_for_qemu_and_hold_guest604(self):
  for selected in C.PROFILES:
   with tempfile.TemporaryDirectory()as td:
    runner=Controls.generated(self,Path(td),selected);text=(runner/'desktop574_runtime.py').read_text()
    self.assertEqual(text.count("context604.tooling_image(source,base,image,base_reference,out,images,Path(os.environ['CACHY_ASAHI_QEMU_TOOLING_INPUTS']),execute)"),1);self.assertIn("qemu_command(report['qemu_launcher']['image'], name, fixture, source, runner)",text)
    self.assertIn('docker_args(derived, name, fixture, source, runner, root=True)',text);self.assertIn('docker_args(derived, name, result, source, verifier)',text);self.assertIn('virt-11.1',text)
    self.assertIn('signal.ITIMER_REAL, 1750',text);self.assertIn('time.monotonic() + 1300',text);self.assertIn("for owned_image in images:",text);self.assertIn("'remove-image:' + owned_image",text)

class ToolingEnvironmentControls(unittest.TestCase):
 def setUp(self):
  p=patch.object(subprocess,'Popen',side_effect=AssertionError('no actors/Git/network'));p.start();self.addCleanup(p.stop)
 def prelude(self,text,out,value):
  tree=ast.parse(text);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='main')
  clear=next(i for i,n in enumerate(node.body)if isinstance(n,ast.Expr)and isinstance(n.value,ast.Call)and ast.unparse(n.value.func)=='os.environ.clear')
  # Execute the exact generated cleanenv boundary, including every newly
  # required path validation. Earlier source/native guards are held elsewhere.
  start=next((i for i,n in enumerate(node.body[:clear])if isinstance(n,ast.Assign)and any(isinstance(a,ast.Name)and a.id=='tooling_inputs'for a in n.targets)),clear)
  body=copy.deepcopy(node.body[start:clear+2]);space=dict(Path=Path,os=os,ENV={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'},require=C.need,out=out)
  env=dict(PRIVATE_UNRELATED_SECRET='NEVER_FORWARD',GITHUB_TOKEN='NEVER_FORWARD')
  if value is not None:env['CACHY_ASAHI_QEMU_TOOLING_INPUTS']=value
  with patch.dict(os.environ,env,clear=True):
   exec(compile(ast.fix_missing_locations(ast.Module(body=body,type_ignores=[])),'<exact-generated-delegated-cleanenv>','exec'),space)
   return dict(os.environ)
 def test_exact_delegated_clean_environment_keeps_only_tooling_path_both_profiles(self):
  for selected in C.PROFILES:
   with self.subTest(profile=selected),tempfile.TemporaryDirectory()as td:
    base=Path(td);runner=Controls.generated(self,base,selected);text=(runner/'desktop574_runtime.py').read_text();packet=base/'packet';packet.mkdir()
    original=self.prelude((ROOT/'scripts/ci/desktop574_runtime.py').read_text(),base/'original',str(packet));self.assertNotIn('CACHY_ASAHI_QEMU_TOOLING_INPUTS',original)
    env=self.prelude(text,base/'corrected',str(packet));self.assertEqual(env,dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',LC_ALL='C.UTF-8',HOME=str(base/'corrected/home'),CACHY_ASAHI_QEMU_TOOLING_INPUTS=str(packet)))
    self.assertIn('explicit bounded tooling input path required',text);self.assertIn('ordinary owned tooling input directory required',text)
 def test_missing_malformed_or_aliased_path_refuses_before_any_actor(self):
  for selected in C.PROFILES:
   with self.subTest(profile=selected),tempfile.TemporaryDirectory()as td:
    base=Path(td);runner=Controls.generated(self,base,selected);text=(runner/'desktop574_runtime.py').read_text();packet=base/'packet';packet.mkdir();alias=base/'alias';alias.symlink_to(packet);file=base/'not-directory';file.write_bytes(b'inert')
    for i,value in enumerate((None,'','relative',str(base/'missing'),str(file),str(alias),str(packet)+'/',str(packet)+'/../packet','/'+'x'*4096)):
     with self.subTest(value=value),self.assertRaises(ValueError):self.prelude(text,base/('refused-'+str(i)),value)

class LauncherClockControls(unittest.TestCase):
 def setUp(self):
  p=patch.object(subprocess,'Popen',side_effect=AssertionError('source clock controls forbid actors'));p.start();self.addCleanup(p.stop)
 def function(self,text,name,scope):
  node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name==name)
  exec(compile(ast.Module(body=[node],type_ignores=[]),'<exact-generated-clock-source>','exec'),scope);return scope[name]
 def test_generated_both_profiles_handoff_immediate_launcher_epoch_without_other_qemu_changes(self):
  for profile in C.PROFILES:
   with self.subTest(profile=profile),tempfile.TemporaryDirectory()as td:
    runner=Controls().generated(Path(td),profile);text=(runner/'desktop574_runtime.py').read_text();g=(runner/'base_guest.py').read_text();scope=dict(time=SimpleNamespace(time=lambda:1792288000.75),require=C.need,docker_args=lambda *a:['OWNED_COMMAND_FIXTURE'])
    command=self.function(text,'qemu_command',scope)('image','name','out','source','runner');shell=command[-1]
    self.assertEqual(shell.count('cachy_asahi_public_pair_epoch=1792288000'),1);self.assertIn('-smp 2 -m 4096',shell);self.assertIn('-nic none',shell);self.assertNotIn('faked-system-time',g+text)
    boot=next(n for n in ast.parse(g).body if isinstance(n,ast.FunctionDef)and n.name=='boot');calls=[n.func.id for n in ast.walk(boot)if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)];self.assertEqual(calls.count('initialize_launcher_clock'),1)
    self.assertLess(g.index('        initialize_launcher_clock()'),g.index('        code = management_root.serve'))
    self.assertIn('time.clock_settime(time.CLOCK_REALTIME,epoch)',g)
    for epoch in (0,1699999999,2**32):
     scope['time']=SimpleNamespace(time=lambda:epoch)
     with self.assertRaisesRegex(ValueError,'bounded launcher UTC'):self.function(text,'qemu_command',scope)('image','name','out','source','runner')
 def clock(self,words,*,guard=True,after=1792288000*10**9):
  calls=[];ticks=iter((1790293564*10**9,after));scope=dict(Path=lambda _:SimpleNamespace(read_text=lambda:words),time=SimpleNamespace(CLOCK_REALTIME=0,time_ns=lambda:next(ticks),clock_settime=lambda *a:calls.append(('set',a))),guard=lambda root:C.need(guard and root,'owned guest refused'),need=C.need,emit=lambda *a,**k:calls.append(('receipt',a,k)))
  return self.function(A.CLOCK_GUEST,'initialize_launcher_clock',scope),calls
 def test_exact_generated_guest_sets_realtime_and_records_original_clock_operands(self):
  f,calls=self.clock('console=ttyAMA0 cachy_asahi_public_pair_epoch=1792288000');f();self.assertEqual(calls[0],('set',(0,1792288000)));v=calls[1][2];self.assertEqual(v['before_ns'],1790293564*10**9);self.assertEqual(v['after_ns'],1792288000*10**9);self.assertEqual(v['requested_epoch_s'],1792288000);self.assertEqual(v['hardware'],'NOT_RUN');self.assertEqual(v['source'],'OWNED_QEMU_LAUNCHER_NOT_EXTERNAL_TIME_AUTHORITY')
 def test_guest_absent_foreign_duplicate_malformed_or_unset_clock_refuses_before_trust(self):
  for words in ('','other_epoch=1792288000','cachy_asahi_public_pair_epoch=1792288000 cachy_asahi_public_pair_epoch=1792288000','cachy_asahi_public_pair_epoch=01792288000','cachy_asahi_public_pair_epoch=+1792288000','cachy_asahi_public_pair_epoch=١٧٩٢٢٨٨٠٠٠','cachy_asahi_public_pair_epoch=0','cachy_asahi_public_pair_epoch=4294967296','x'*65537):
   with self.subTest(words=words[:70]):
    f,calls=self.clock(words)
    with self.assertRaises(ValueError):f()
    self.assertEqual(calls,[])
  f,calls=self.clock('cachy_asahi_public_pair_epoch=1792288000',guard=False)
  with self.assertRaisesRegex(ValueError,'owned guest'):f()
  self.assertEqual(calls,[])
  for after in (1790293564*10**9,1792288002*10**9):
   f,calls=self.clock('cachy_asahi_public_pair_epoch=1792288000',after=after)
   with self.assertRaisesRegex(ValueError,'handoff failed'):f()
   self.assertEqual(len(calls),1)


class PeerFocusControls(unittest.TestCase):
 def setUp(self):
  p=patch.object(subprocess,'Popen',side_effect=AssertionError('peer-focus source controls forbid actors'));p.start();self.addCleanup(p.stop)
 def test_exact_lane_derivation_and_both_composed_profiles_hold_every_other_driver_byte(self):
  raw=(ROOT/'scripts/ci/welcome-management-native/a11y_driver.c').read_bytes();derived=A.peer_focus_driver(raw);self.assertEqual(len(derived),23323);self.assertEqual(C.sha(derived),'20a7c6f0aed6740fcdce989174f682fc3433d40dbeab9cd677a80df07069a19e');text=derived.decode()
  for old,new in reversed((*A.FOCUS_EDITS,*A.JOINT_OPERAND_EDITS)):self.assertEqual(text.count(new),1);text=text.replace(new,old)
  self.assertEqual(text.encode(),raw);self.assertEqual(derived.count(b'atspi_component_grab_focus(peer_component, &error)'),1);self.assertEqual(derived.count(b'g_get_monotonic_time() + 2 * G_USEC_PER_SEC'),1);self.assertIn(b'alarm(20); atspi_set_timeout(1000, 1000)',derived)
  for selected in C.PROFILES:
   with self.subTest(profile=selected),tempfile.TemporaryDirectory()as td:
    runner=Controls().generated(Path(td),selected);self.assertEqual((runner/'a11y_driver.c').read_bytes(),derived);self.assertIn('initialize_launcher_clock()',(runner/'base_guest.py').read_text())
 def test_whole_historical_driver_and_deadline_peer_guard_tamper_refuse(self):
  raw=(ROOT/'scripts/ci/welcome-management-native/a11y_driver.c').read_bytes()
  for changed in(raw+b' ',raw.replace(b'2 * G_USEC_PER_SEC',b'3 * G_USEC_PER_SEC'),raw.replace(b'peer_matches == 1',b'peer_matches >= 1')):
   with self.assertRaises(ValueError):A.peer_focus_driver(changed)
 def held_semantic(self,name):
  # Compile only the exact held pure assertion and its ordinary data helper.
  # This avoids loading unrelated GUI/producer test actors or replacing predicates.
  import base64
  M=C.module('_peer_focus_held_management_contract','scripts/ci/welcome-management-native/management_contract.py')
  path='scripts/ci/welcome-management-native/test_gui.py';raw=(ROOT/path).read_bytes();self.assertEqual(dict(bytes=len(raw),sha256=C.sha(raw)),C.pins()[path]);tree=ast.parse(raw);klass=next(n for n in tree.body if isinstance(n,ast.ClassDef)and n.name=='Semantics');klass.body=[n for n in klass.body if isinstance(n,ast.FunctionDef)and n.name==name];self.assertEqual(len(klass.body),1)
  ui=next(n for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(x,ast.Name)and x.id=='UI'for x in n.targets));helper=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='scroll_proof');scope=dict(C=M,copy=copy,base64=base64,unittest=unittest);exec(compile(ast.Module(body=[ui,helper,klass],type_ignores=[]),'<exact-held-peer-focus-semantic-controls>','exec'),scope);scope['Semantics'](name).__getattribute__(name)()
 def test_held_disabled_target_enabled_same_panel_peer_and_focus_refusals(self):self.held_semantic('test_disabled_button_visibility_requires_owned_enabled_same_panel_peer')
 def test_held_genuine_component_geometry_and_target_focus_refusals(self):self.held_semantic('test_visibility_requires_genuine_component_or_unclipped_or_focused_geometry')
 def test_held_clipped_sentinel_hidden_foreign_and_window_refusals(self):self.held_semantic('test_false_scroll_cannot_hide_clipping_sentinel_missing_owner_or_window')


 def test_bounded_readback_progress_derives_only_exact_original(self):
  raw=(ROOT/C.OLD/'installed604.py').read_bytes();derived=A.readback_progress(raw);self.assertNotEqual(raw,derived)
  for before,after,count in reversed(A.READBACK_EDITS):
   self.assertEqual(derived.decode().count(after),count);derived=derived.decode().replace(after,before).encode()
  self.assertEqual(derived,raw)
  text=A.readback_progress(raw).decode()
  for marker in ('INTERVAL=45','MAX_ROWS=32','MAX_BYTES=4096',"MAX_BYTES-512",'deadline=600','max_packages=604','6*1024**3','200000','database/root drift','snapshot_validation'):self.assertIn(marker,text)
 def test_bounded_readback_whole_source_and_validation_tamper_refused(self):
  raw=(ROOT/C.OLD/'installed604.py').read_bytes()
  for changed in (raw+b'\n',raw.replace(b'deadline=600',b'deadline=601'),raw.replace(b'200000',b'200001')):
   with self.assertRaisesRegex(ValueError,'whole original installed604'):A.readback_progress(changed)
 def test_bounded_readback_both_generated_profiles_preserve_timeout_and_helpers(self):
  for selected in C.PROFILES:
   with tempfile.TemporaryDirectory()as tmp:
    runner=Controls().generated(Path(tmp),selected);self.assertEqual((runner/'installed604.py').read_bytes(),A.readback_more_keys(A.readback_openat2(A.readback_snapshot_mismatch(A.readback_path_hotpath(A.readback_fresh_mount(A.readback_progress((ROOT/C.OLD/'installed604.py').read_bytes()),ROOT),ROOT)))))
    self.assertIn("'installed604-preserved',timeout=600",(runner/'base_guest.py').read_text())
    for name,path in (('alpm_reader.py','scripts/ci/full-root-upgrade/root_upgrade.py'),('file_capabilities.py','scripts/apps/file_capabilities.py')):self.assertEqual((runner/name).read_bytes(),(ROOT/path).read_bytes())


class JointOperandControls(unittest.TestCase):
 def intermediate(self):
  raw=(ROOT/'scripts/ci/welcome-management-native/a11y_driver.c').read_bytes();text=raw.decode()
  for before,after in A.FOCUS_EDITS:text=C.one(text,before,after)
  self.assertEqual((len(text.encode()),C.sha(text.encode())),(20790,'e59b3767a6f4ca6009c2eab194946b84add16a06bcd7f3129993a29a53d84ebe'))
  return raw,text
 def test_one_failure_row_preserves_ATSPI_queries_and_positive_body(self):
  import collections,re
  raw,old=self.intermediate();new=A.peer_focus_driver(raw).decode()
  calls=lambda text:collections.Counter(re.findall(r'\batspi_[a-z0-9_]+\s*\(',text))
  self.assertEqual(calls(old),calls(new));marker='static void ensure_visible(guint pid)'
  self.assertEqual(old.split(marker)[1],new.split(marker)[1]);self.assertEqual(new.count('welcome_settle_failure'),1)
  self.assertEqual(len(A.JOINT_OPERAND_EDITS),9)
  for before,after in reversed(A.JOINT_OPERAND_EDITS):self.assertEqual(new.count(after),1);new=new.replace(after,before)
  self.assertEqual(new,old)
 def test_final_failure_only_formatter_fits_original_stderr_tail(self):
  import re
  raw,_=self.intermediate();text=A.peer_focus_driver(raw).decode();start=text.index('    /* At most one row, only if the final joint check refuses')
  body=text[start:text.index('static AtspiAccessible *tool_panel',start)]
  self.assertIn('if (focus) {',body);self.assertEqual(body.count('fprintf(stderr,'),1)
  part=body.split('fprintf(stderr,',1)[1].split('focus ? "after_focus"',1)[0]
  fmt=''.join(ast.literal_eval(v)for v in re.findall(r'"(?:\\.|[^"\\])*"',part))
  fields=re.findall(r'%[sud]',fmt);values=tuple('after_focus'if v=='%s'else 4294967295 if v=='%u'else -2147483648 for v in fields)
  raw=(fmt%values).encode();self.assertLessEqual(len(raw),1024);self.assertEqual(json.loads(raw)['event'],'welcome_settle_failure');self.assertLess(len(raw)+94,4096)
 def test_both_profiles_emit_exact_new_C_and_hold_readback_deadline(self):
  raw,_=self.intermediate();derived=A.peer_focus_driver(raw)
  for selected in C.PROFILES:
   with tempfile.TemporaryDirectory()as td:
    runner=Controls().generated(Path(td),selected);self.assertEqual((runner/'a11y_driver.c').read_bytes(),derived)
    self.assertIn("'installed604-preserved',timeout=600",(runner/'base_guest.py').read_text())

class ReadbackFreshMountControls(unittest.TestCase):
 def test_fresh_mount_uses_whole_existing_query_and_holds_complete_observer(self):
  raw=A.readback_progress((ROOT/C.OLD/'installed604.py').read_bytes());new=A.readback_fresh_mount(raw,ROOT)
  def funcs(text):return{n.name:ast.get_source_segment(text,n)for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
  a,b=funcs(raw.decode()),funcs(new.decode())
  for name in set(a)-{'capabilities'}:self.assertEqual(a[name],b[name],name)
  query=(ROOT/'scripts/ci/expanded600-installer-vm/observer600.py').read_bytes()
  self.assertEqual(dict(bytes=len(query),sha256=C.sha(query)),dict(bytes=2784,sha256='c3d804e7f2927c7889835ad187a39a3d7c618a4651700f57b0c5413c46612607'))
  self.assertEqual(b['_mount600'],funcs(query.decode())['_mount600'])
  with self.assertRaisesRegex(ValueError,'whole progress readback'):A.readback_fresh_mount(raw+b'\n',ROOT)
  ns={'__file__':str(ROOT/C.OLD/'installed604.py')};exec(compile(new,'<exact source-only generated readback>','exec'),ns)
  original=ns['capabilities']();limit=type('Limits',(),{'tick':lambda self:None})()
  with tempfile.TemporaryDirectory()as td:
   fd=os.open(td,os.O_RDONLY|os.O_DIRECTORY)
   try:self.assertIsInstance(original._mount(fd,limit),int)
   finally:os.close(fd)


class ReadbackPathHotpathControls(unittest.TestCase):
 def helper(self):
  raw=A.readback_fresh_mount(A.readback_progress((ROOT/C.OLD/'installed604.py').read_bytes()),ROOT);new=A.readback_path_hotpath(raw,ROOT);space={'__file__':str(ROOT/C.OLD/'installed604.py')};exec(compile(new,'<source-owned-path-helper>','exec'),space);return raw,new,space
 def test_complete_walk_progress_caps_and_mount_query_byte_held(self):
  raw,new,space=self.helper();funcs=lambda data:{n.name:ast.get_source_segment(data.decode(),n)for n in ast.parse(data).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))};a,b=funcs(raw),funcs(new)
  self.assertEqual(set(b)-set(a),{'_relative604','_directory604'})
  for n in set(a)-{'load_db'}:self.assertEqual(a[n],b[n],n)
  original=C.module('_hotpath_original_database','scripts/ci/full-root-upgrade/root_upgrade.py');selected=space['load_db'](ROOT/'scripts/ci/full-root-upgrade/root_upgrade.py')
  self.assertEqual(original.identity.__code__.co_code,selected.identity.__code__.co_code)
  self.assertEqual(original.read_record.__code__.co_code,selected.read_record.__code__.co_code)
  self.assertEqual(original.database.__code__.co_code,selected.database.__code__.co_code)
 def test_relative_grammar_matches_original_including_literal_backslash(self):
  import itertools
  raw,new,space=self.helper();original=C.module('_hotpath_relative_oracle','scripts/ci/full-root-upgrade/root_upgrade.py');selected=space['load_db'](ROOT/'scripts/ci/full-root-upgrade/root_upgrade.py')
  def result(fn,name):
   try:return ('return',fn(name))
   except ValueError as e:return ('refuse',str(e))
  values=['','/','.','..','a','a/','/a','a//b','a/./b','a/../b','a\\b','é','a\0b',None,1]
  for parts in itertools.product(('a','','.','..','é','\\'),repeat=3):values.append('/'.join(parts))
  for name in values:self.assertEqual(result(original.relative,name),result(selected.relative,name),repr(name))
 def test_real_fresh_directory_alias_and_mount_refusals(self):
  raw,new,space=self.helper();original=C.module('_hotpath_directory_oracle','scripts/ci/full-root-upgrade/root_upgrade.py');selected=space['load_db'](ROOT/'scripts/ci/full-root-upgrade/root_upgrade.py')
  with tempfile.TemporaryDirectory()as td:
   base=Path(td);root=base/'root';(root/'real').mkdir(parents=True);(root/'alias').symlink_to('real',target_is_directory=True);(base/'root-alias').symlink_to(root,target_is_directory=True)
   for module in (original,selected):
    with module.directory(root,'real')as fd:self.assertTrue(stat.S_ISDIR(os.fstat(fd).st_mode))
    for path,name in ((root,'alias'),(base/'root-alias','real'),(root,'../other')):
     with self.subTest(module=module.__name__,path=path,name=name),self.assertRaises((ValueError,OSError)):
      with module.directory(path,name):pass
    with self.assertRaisesRegex(ValueError,'mount crossing'):
     with module.directory(Path('/'),'proc'):pass
 def test_whole_helper_guards_fail_before_unpinned_import(self):
  raw,new,space=self.helper()
  with self.assertRaisesRegex(ValueError,'whole fresh-mount'):A.readback_path_hotpath(raw+b'\n',ROOT)
  with tempfile.TemporaryDirectory()as td:
   p=Path(td)/'untrusted.py';p.write_text("raise AssertionError('untrusted code must never execute')")
   with self.assertRaisesRegex(ValueError,'whole original readback database'):space['load_db'](p)

class SnapshotMismatchControls(unittest.TestCase):
 def helper(self):
  raw=A.readback_path_hotpath(A.readback_fresh_mount(A.readback_progress((ROOT/C.OLD/'installed604.py').read_bytes()),ROOT),ROOT);new=A.readback_snapshot_mismatch(raw);space={'__file__':str(ROOT/C.OLD/'installed604.py')};exec(compile(new,'<whole-source-failed-snapshot-diagnostic>','exec'),space);return raw,new,space
 def diagnose(self,space,actual,baseline):
  writes=[]
  with patch.object(os,'write',side_effect=lambda fd,raw:(writes.append((fd,raw)),len(raw))[1]):
   with self.assertRaisesRegex(ValueError,'complete installed inventory/payload/hardlink/nonselected DB preservation differs'):space['verify'](actual,baseline)
  self.assertEqual(len(writes),1);self.assertEqual(writes[0][0],2);self.assertLessEqual(len(writes[0][1]),2048);self.assertEqual(len(writes[0][1].splitlines()),1)
  return json.loads(writes[0][1]),writes[0][1]
 def template(self):return dict(schema_version=1,packages={},ownership={},nodes={},hardlinks=[],nonselected_database={},capabilities={},payload_bytes=0,qualification='INERT_COMPARISON_CONTROL_NOT_NATIVE')
 def test_all_observer_functions_and_original_equality_held_success_silent(self):
  raw,new,space=self.helper();funcs=lambda text:{n.name:ast.get_source_segment(text.decode(),n)for n in ast.parse(text).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))};old,now=funcs(raw),funcs(new)
  self.assertEqual(set(now)-set(old),{'snapshot_mismatch'})
  for name in set(old)-{'verify'}:self.assertEqual(now[name],old[name],name)
  self.assertEqual(now['verify'].replace('    if actual!=baseline:snapshot_mismatch(actual,baseline)\n',''),old['verify'])
  with patch.object(os,'write',side_effect=AssertionError('successful comparison is silent')):self.assertTrue(space['verify'](self.template(),self.template()))
  with self.assertRaisesRegex(ValueError,'whole hotpath readback'):A.readback_snapshot_mismatch(raw+b'\n')
 def test_real_complete604_observation_payload_mismatch_retains_exact_whole_pins(self):
  raw,new,space=self.helper()
  with tempfile.TemporaryDirectory()as directory:
   root=Path(directory);db=root/'var/lib/pacman/local';db.mkdir(parents=True);(db/'ALPM_DB_VERSION').write_bytes(b'9\n');expected={}
   for i in range(604):
    name=('cachy-asahi-doctor','cachy-asahi-orphans')[i]if i<2 else'finite'+str(i);expected[name]='1-1';payload=root/'usr/share/finite'/name;payload.mkdir(parents=True);(payload/'file').write_bytes(b'BASELINE');owned=[str((payload/'file').relative_to(root))]
    if i==0:
     os.link(payload/'file',payload/'alias');(payload/'symlink').symlink_to('file');owned.extend(str((payload/n).relative_to(root))for n in('alias','symlink'))
    row=db/(name+'-1-1');row.mkdir();(row/'desc').write_text('%NAME%\n'+name+'\n\n%VERSION%\n1-1\n\n%ARCH%\nany\n\n');(row/'files').write_text('%FILES%\n'+'\n'.join(owned)+'\n\n')
   helper=space['load_db'](ROOT/'scripts/ci/full-root-upgrade/root_upgrade.py');baseline=space['observe'](root,helper,expected);self.assertEqual(len(baseline['nodes']),606);self.assertEqual(len(baseline['packages']),604);(root/'usr/share/finite/finite2/file').write_bytes(b'MUTATION');actual=space['observe'](root,helper,expected)
   row,data=self.diagnose(space,actual,baseline);self.assertEqual(row['fields'],['nodes']);self.assertEqual(row['counts']['nodes'],[0,0,1]);self.assertEqual(row['node_fields']['sha256'],1);self.assertEqual(row['examples'][0]['key'],'usr/share/finite/finite2/file');self.assertEqual(row['actual'],dict(bytes=len(space['encoded'](actual)),sha256=space['digest'](space['encoded'](actual))));self.assertEqual(row['baseline'],dict(bytes=len(space['encoded'](baseline)),sha256=space['digest'](space['encoded'](baseline))))
   self.assertNotIn(b'MUTATION',data);self.assertNotIn(b'BASELINE',data)
 def test_each_node_db_cap_ownership_package_and_hardlink_category_counted(self):
  raw,new,space=self.helper();baseline=self.template();actual=copy.deepcopy(baseline)
  for category in ('nodes','nonselected_database','capabilities','ownership','packages'):
   baseline[category]={'removed':'PRIVATE_CONFIG_CONTENT','changed':'OLD_PRIVATE_VALUE'};actual[category]={'added':'NEW_PRIVATE_VALUE','changed':'NEW_PRIVATE_VALUE'}
  baseline['nodes']['changed']={'mode':420,'uid':1,'target':'PRIVATE_TARGET'};actual['nodes']['changed']={'mode':384,'uid':2,'target':'CHANGED_PRIVATE_TARGET'};baseline['hardlinks']=[['a','b']];actual['hardlinks']=[['c','d']]
  row,data=self.diagnose(space,actual,baseline)
  for category in ('nodes','nonselected_database','capabilities','ownership','packages','hardlinks'):self.assertEqual(row['counts'][category],[1,1,1])
  self.assertEqual(row['node_fields']['mode'],1);self.assertEqual(row['node_fields']['uid'],1);self.assertEqual(row['node_fields']['target'],1);self.assertEqual(row['examples_omitted'],17-len(row['examples']));self.assertNotIn(b'PRIVATE_',data)
 def test_bounded_many_unicode_paths_and_original4096_tail_failure_retention(self):
  import traceback
  raw,new,space=self.helper();baseline=self.template();actual=copy.deepcopy(baseline)
  for i in range(1000):actual['nodes']['\\u00e9'.encode().decode('unicode_escape')*200+str(i)]={'mode':420,'type':'file','sha256':'a'*64}
  writes=[]
  with patch.object(os,'write',side_effect=lambda fd,data:(writes.append(data),len(data))[1]):
   try:space['verify'](actual,baseline)
   except ValueError:trace=traceback.format_exc().encode()
  self.assertEqual(len(writes),1);data=writes[0];self.assertLessEqual(len(data),2048);row=json.loads(data);self.assertEqual(row['counts']['nodes'],[1000,0,0]);self.assertEqual(row['examples_omitted'],1000-len(row['examples']));self.assertTrue(all(r['key_truncated']for r in row['examples']))
  terminal=b'{"event":"installed604_progress","phase":"snapshot_validation","status":"FAILED"}\n';tail=(b'OLD_PROGRESS\n'*400+data+terminal+trace)[-4096:];self.assertIn(data,tail);self.assertIn(b'complete installed inventory/payload/hardlink/nonselected DB preservation differs',tail)
 def test_diagnostic_failure_never_replaces_original_refusal_or_opens_files(self):
  raw,new,space=self.helper();actual=self.template();baseline=copy.deepcopy(actual);actual['payload_bytes']=1
  with patch.object(os,'open',side_effect=AssertionError('diagnostics never scan filesystem')),patch.object(os,'write',side_effect=OSError('closed stderr')):
   with self.assertRaisesRegex(ValueError,'complete installed inventory/payload/hardlink/nonselected DB preservation differs'):space['verify'](actual,baseline)
  malformed=copy.deepcopy(baseline);malformed['nodes']=None;row,data=self.diagnose(space,actual,malformed);self.assertEqual(row['status'],'DIAGNOSTIC_UNAVAILABLE_NOT_ACCEPTANCE');self.assertEqual(row['error_type'],'ValueError')
 def test_hardlink_multiplicity_or_order_is_not_collapsed_to_a_set(self):
  raw,new,space=self.helper();baseline=self.template();actual=copy.deepcopy(baseline);baseline['hardlinks']=[['a','b']];actual['hardlinks']=[['a','b'],['a','b']]
  row,data=self.diagnose(space,actual,baseline);self.assertEqual(row['counts']['hardlinks'],[0,0,1]);self.assertIn('hardlinks',row['fields'])

class Openat2ReadbackControls(unittest.TestCase):
 def helper(self):
  old=A.readback_snapshot_mismatch(A.readback_path_hotpath(A.readback_fresh_mount(A.readback_progress((ROOT/C.OLD/'installed604.py').read_bytes()),ROOT),ROOT));new=A.readback_openat2(old)
  def module(raw):
   scope={'__file__':str(ROOT/C.OLD/'installed604.py')};exec(compile(raw,'<source-owned-openat2-readback>','exec'),scope);return scope
  return old,new,module(old),module(new)
 def test_exact_factory_and_all_observer_verifier_diagnostic_bodies_held(self):
  old,new,before,after=self.helper();funcs=lambda raw:{n.name:ast.get_source_segment(raw.decode(),n)for n in ast.parse(raw).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))};a,b=funcs(old),funcs(new);self.assertEqual(set(b)-set(a),{'_openat2_directory604'})
  for name in set(a)-{'load_db'}:self.assertEqual(a[name],b[name],name)
  factory=b['_openat2_directory604'].replace('def _openat2_directory604(relative, need):\n    import ctypes, platform','def factory(relative, need):',1);self.assertEqual((len(factory.encode()),C.sha(factory.encode())),(2060,'e0b7f5c5fd90070b5f85b0d7c2cc123448f9971ea698b86720515d20c21f1a58'))
  self.assertEqual(b['load_db'].replace('m.directory=_openat2_directory604(m.relative,need)','m.directory=_directory604'),a['load_db'])
  with self.assertRaisesRegex(ValueError,'whole mismatch diagnostic'):A.readback_openat2(old+b'\n')
 def test_real_kernel_fresh_lookup_and_fd_retirement_on_success_body_and_stat_error(self):
  old,new,before,after=self.helper();fast=after['load_db'](ROOT/'scripts/ci/full-root-upgrade/root_upgrade.py').directory
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);(root/'a/b').mkdir(parents=True);(root/'a/b/file').write_bytes(b'ORDINARY_PRIVATE_CONTROL');count=lambda:len(os.listdir('/proc/self/fd'));start=count()
   for _ in range(8):
    with fast(root,'a/b')as fd:
     self.assertEqual(os.fstat(fd).st_ino,(root/'a/b').stat().st_ino);leaf=os.open('file',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
     try:self.assertEqual(os.read(leaf,128),b'ORDINARY_PRIVATE_CONTROL')
     finally:os.close(leaf)
   self.assertEqual(count(),start)
   with self.assertRaisesRegex(RuntimeError,'body failure'):
    with fast(root,'a/b'):raise RuntimeError('body failure')
   self.assertEqual(count(),start);real=os.fstat;calls=[]
   def fail_second(fd):
    calls.append(fd)
    if len(calls)==2:raise OSError('injected final descriptor failure')
    return real(fd)
   with patch.object(os,'fstat',side_effect=fail_second):
    with self.assertRaisesRegex(OSError,'injected final descriptor'):
     with fast(root,'a/b'):pass
   self.assertEqual(len(calls),2);self.assertEqual(count(),start)
 def test_real_invalid_roots_paths_symlinks_and_mount_crossing_fail_closed(self):
  import errno
  old,new,before,after=self.helper();fast=after['load_db'](ROOT/'scripts/ci/full-root-upgrade/root_upgrade.py').directory
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);(root/'a/b').mkdir(parents=True);(root/'a/b/file').write_bytes(b'INERT');(root/'alias').symlink_to('a',target_is_directory=True);(root/'root-alias').symlink_to(root,target_is_directory=True);start=len(os.listdir('/proc/self/fd'))
   for name in('../a','/a','a//b','a/./b','a/../b','alias/b','missing','a/b/file','a\0b',None):
    with self.subTest(path=name),self.assertRaises((ValueError,OSError)):
     with fast(root,name):pass
   for base in(Path('relative-root'),root/'root-alias',Path(str(root)+'/a/..')):
    with self.subTest(root=base),self.assertRaises((ValueError,OSError)):
     with fast(base,'a/b'):pass
   with self.assertRaises(OSError)as caught:
    with fast(Path('/'),'proc'):pass
   self.assertEqual(caught.exception.errno,errno.EXDEV);self.assertEqual(len(os.listdir('/proc/self/fd')),start)
 def test_unsupported_abi_syscall_and_race_errors_have_no_fallback_or_fd_leak(self):
  import ctypes,errno,platform
  old,new,before,after=self.helper();factory=after['_openat2_directory604']
  with patch.object(platform,'machine',return_value='unreviewed'),patch.object(ctypes,'CDLL',side_effect=AssertionError('ABI refusal before libc')):
   with self.assertRaisesRegex(ValueError,'reviewed syscall ABI'):factory(after['_relative604'],after['need'])
  real_sizeof=ctypes.sizeof
  def wrong_how(value):return 16 if isinstance(value,type)and value.__name__=='How'else real_sizeof(value)
  with patch.object(ctypes,'sizeof',side_effect=wrong_how):
   with self.assertRaisesRegex(ValueError,'exact Linux open_how ABI'):factory(after['_relative604'],after['need'])
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);(root/'a').mkdir();start=len(os.listdir('/proc/self/fd'))
   for code in(errno.ENOSYS,errno.EAGAIN,errno.EXDEV):
    syscall=Mock(return_value=-1)
    with patch.object(ctypes,'CDLL',return_value=SimpleNamespace(syscall=syscall)),patch.object(ctypes,'get_errno',return_value=code):
     fast=factory(after['_relative604'],after['need'])
     with self.assertRaises(OSError)as caught:
      with fast(root,'a'):pass
     self.assertEqual(caught.exception.errno,code)
    self.assertEqual(syscall.call_count,1);args=syscall.call_args.args;self.assertEqual(args[0].value,437);self.assertEqual(args[4].value,24);how=args[3]._obj;self.assertEqual(how.mode,0);self.assertEqual(how.resolve,15);self.assertEqual(how.flags,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);self.assertEqual(len(os.listdir('/proc/self/fd')),start)
 def test_complete_actual604_observations_progress_and_unknown_xattr_refusals_match(self):
  old,new,before,after=self.helper();path=ROOT/'scripts/ci/full-root-upgrade/root_upgrade.py'
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);db=root/'var/lib/pacman/local';db.mkdir(parents=True);(db/'ALPM_DB_VERSION').write_bytes(b'9\n');expected={}
   for i in range(604):
    name=('cachy-asahi-doctor','cachy-asahi-orphans')[i]if i<2 else'finite'+str(i);expected[name]='1-1';parent=root/'usr/share/finite'/name;parent.mkdir(parents=True);(parent/'file').write_bytes(b'COMPLETE_PRIVATE_PAYLOAD');owned=[str((parent/'file').relative_to(root))]
    if i==0:
     os.link(parent/'file',parent/'alias');(parent/'link').symlink_to('file');owned.extend(str((parent/n).relative_to(root))for n in('alias','link'))
    record=db/(name+'-1-1');record.mkdir();(record/'desc').write_text('%NAME%\n'+name+'\n\n%VERSION%\n1-1\n\n%ARCH%\nany\n\n');(record/'files').write_text('%FILES%\n'+'\n'.join(owned)+'\n\n')
   results=[];counts=[]
   for scope in(before,after):
    progress=scope['Progress']();value=scope['observe'](root,scope['load_db'](path),expected,progress=progress);results.append(value);counts.append(progress.counts);self.assertEqual(len(value['packages']),604);self.assertEqual(len(value['nodes']),606)
   self.assertEqual(results[0],results[1]);self.assertEqual(before['encoded'](results[0]),after['encoded'](results[1]));self.assertEqual(counts[0],counts[1]);self.assertEqual(counts[0]['nodes'],606)
   os.setxattr(root/'usr/share/finite/finite2/file','user.unreviewed',b'REFUSE')
   for scope in(before,after):
    with self.assertRaisesRegex(ValueError,'unknown xattr'):scope['observe'](root,scope['load_db'](path),expected)

class PrivateKeyboardBuildReceipt(unittest.TestCase):
 # A source-owned kernel-guard fragment with real private files. This is not a
 # built Image, VM fixture, native build receipt, boot or acceptance document.
 def receipt_files(self,base):
  K=A.KP;work=base/'managed-gui16k-kernel';helper=work/'helper';helper.mkdir(parents=True)
  for name in('build_kernel.py','kernel.fragment'):(helper/name).write_bytes(K.held(ROOT,name))
  K.prepare_kernel(ROOT,helper);H=K.helper(ROOT);H.HERE=helper
  build=helper/'built/build';image=build/'arch/arm64/boot/Image';image.parent.mkdir(parents=True);header=bytearray(64);header[24]=4;header[56:60]=b'ARM\x64';image.write_bytes(header)
  config=build/'.config';config.write_bytes((helper/'kernel.fragment').read_bytes()+H.DIAGNOSTIC_FRAGMENT.encode()+b'CONFIG_VIRTIO=y\n')
  contract=K.contract(ROOT)
  receipt=dict(status='BUILT_ONLY',kernel_build='PASS',profile=K.PROFILE,
   derivation=dict(base_helper_sha256='e94adb4474183feea30ce1e2949b55c03e4969eeb1addb4c36892e8664ba9aaa',base_fragment_sha256='6d91180b80138d2d8039efafaaa9ca31349baea22b90430cbb15e07bce02e8f6',workspace_scan='ACTIVE_CHILD_COMPILER_OUTPUT_ENOENT_ONLY_STRICT_FINAL',accepted_profiles_modified=False),
   source_commit=contract.REVISION,archive=dict(bytes=262965559,sha256=contract.ARCHIVE),boot_diagnostics=True,kernel_release=contract.RELEASE,module_policy=dict(CONFIG_MODULES='n'),
   helper=H.identity(helper/'build_kernel.py'),fragment=H.identity(helper/'kernel.fragment'),image=H.identity(image),config=H.identity(config),diagnostic_fragment=dict(sha256=K.sha((helper/'kernel.fragment').read_bytes()+H.DIAGNOSTIC_FRAGMENT.encode())))
  path=helper/'built/build-receipt.json';path.write_bytes(C.encoded(receipt))
  # Compile ONLY the source-pinned original ordinary-directory guard. The kernel
  # function itself is the real K.kernel derivation and original from_receipt.
  raw=K.held(ROOT,'run.py');node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='ordinary')
  s=SimpleNamespace(HERE=ROOT/K.BASE,need=C.need,read=lambda p,cap=65536:K.read(p),sha=K.sha)
  namespace=dict(Path=Path,os=os,stat=stat,json=json,s=s);exec(compile(ast.Module(body=[node],type_ignores=[]),'<pinned-ordinary-kernel-guard>','exec'),namespace)
  return K,H,contract,receipt,path,SimpleNamespace(**namespace),SimpleNamespace(source=ROOT,kernel_work=work,kernel_receipt=path),image,config
 def test_actual_copied_helper_hash_reaches_original_receipt_and_file_guards(self):
  with tempfile.TemporaryDirectory()as td,patch.dict(os.environ,RUNNER_TEMP=td):
   K,H,contract,r,p,original,args,image,config=self.receipt_files(Path(td));old=K.sha(K.held(ROOT,'build_kernel.py'))
   self.assertNotEqual(old,r['helper']['sha256']);self.assertEqual(r['helper']['sha256'],contract.HELPER_SHA)
   with self.assertRaisesRegex(ValueError,'completed exact diagnostic build required'):contract.from_receipt(r,H,K.fragment(K.held(ROOT,'kernel.fragment')),old,r['fragment']['sha256'])
   result=K.kernel(original,args);self.assertEqual(result[0]['helper_sha256'],r['helper']['sha256']);self.assertEqual(result[1],r);self.assertEqual(result[2:],(image,config))
 def test_original_status_profile_archive_and_hash_refusals_remain(self):
  with tempfile.TemporaryDirectory()as td,patch.dict(os.environ,RUNNER_TEMP=td):
   K,H,contract,r,p,original,args,image,config=self.receipt_files(Path(td))
   for change in(dict(status='CONFIGURED_ONLY'),dict(profile=K.OLD),dict(kernel_build='FAIL'),dict(boot_diagnostics=False),dict(archive=dict(bytes=262965559,sha256='0'*64)),dict(helper=dict(r['helper'],sha256='0'*64))):
    bad=copy.deepcopy(r);bad.update(change);p.write_bytes(C.encoded(bad))
    with self.subTest(change=change),self.assertRaises(ValueError):K.kernel(original,args)
 def test_original_real_image_config_and_copied_helper_drift_refusals_remain(self):
  with tempfile.TemporaryDirectory()as td,patch.dict(os.environ,RUNNER_TEMP=td):
   K,H,contract,r,p,original,args,image,config=self.receipt_files(Path(td))
   for target in(image,config,Path(r['helper']['path']),Path(r['fragment']['path'])):
    raw=target.read_bytes();target.write_bytes(raw+b'\n')
    with self.subTest(target=target.name),self.assertRaises(ValueError):K.kernel(original,args)
    target.write_bytes(raw)
   alias=image.with_name('original');image.rename(alias);image.symlink_to(alias.name)
   with self.assertRaisesRegex(ValueError,'symlink'):K.kernel(original,args)
 def test_only_one_kernel_hash_operand_rewrite_and_original_contract_functions_held(self):
  K=A.KP;original=K.held(ROOT,'run.py');self.assertEqual(original.count(b"s.sha(s.read(s.HERE/'build_kernel.py'))"),1)
  contract=K.held(ROOT,'kernel_contract.py');new=K.contract_bytes(ROOT)
  fs=lambda raw:{n.name:ast.get_source_segment(raw.decode(),n)for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
  self.assertEqual(fs(contract),fs(new));self.assertIn(b"receipt['status']=='BUILT_ONLY'",new)

if __name__=='__main__':unittest.main(verbosity=2)


class DoctorPublication(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(dir='/tmp',prefix='doctor-publish-');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
  self.original=(ROOT/'scripts/ci/welcome-management-native/doctor_lifetime.py').read_bytes()
  import types
  self.old=types.ModuleType('held_doctor_lifetime');exec(compile(self.original,'held_doctor_lifetime','exec'),self.old.__dict__)
  self.new=types.ModuleType('private_atomic_doctor_lifetime');exec(compile(A.doctor_publication(self.original),'private_atomic_doctor_lifetime','exec'),self.new.__dict__)
 def concurrent(self,module,name,expect_visible,partial=False):
  import threading
  ready=threading.Event();release=threading.Event();errors=[];real=os.fdopen;path=self.root/name;value={'nonce':'a'*32}
  class Paused:
   def __init__(self,stream):self.stream=stream
   def __enter__(self):return self
   def __exit__(self,*args):return self.stream.__exit__(*args)
   def __getattr__(self,name):return getattr(self.stream,name)
   def write(self,raw):
    split=len(raw)//2 if partial else 0
    if split:self.stream.write(raw[:split]);self.stream.flush()
    ready.set()
    if not release.wait(5):raise AssertionError('bounded writer rendezvous')
    return split+self.stream.write(raw[split:])
  def writer():
   try:module.publish(path,value,0o600)
   except BaseException as error:errors.append(error)
  with patch.object(module.os,'fdopen',side_effect=lambda *a,**k:Paused(real(*a,**k))):
   thread=threading.Thread(target=writer);thread.start()
   try:
    self.assertTrue(ready.wait(5));self.assertEqual(path.exists(),expect_visible)
    if expect_visible:
     if partial:
      self.assertGreater(path.stat().st_size,0)
      with self.assertRaises(json.JSONDecodeError):module.read(path,os.getuid(),0o600)
     else:
      self.assertEqual(path.stat().st_size,0)
      with self.assertRaisesRegex(ValueError,'private lifetime metadata differs'):module.read(path,os.getuid(),0o600)
    else:
     with self.assertRaises(FileNotFoundError):module.read(path,os.getuid(),0o600)
   finally:release.set();thread.join(5)
  self.assertFalse(thread.is_alive());self.assertEqual(errors,[]);self.assertEqual(module.read(path,os.getuid(),0o600),value);self.assertEqual(path.stat().st_nlink,1)
 def test_real_original_zero_length_visibility_and_atomic_candidate(self):
  self.concurrent(self.old,'original.json',True);self.concurrent(self.new,'candidate.json',False)
 def test_real_partial_visibility_is_excluded_before_atomic_publication(self):
  self.concurrent(self.old,'original-partial.json',True,True);self.concurrent(self.new,'candidate-partial.json',False,True)
 def test_real_no_clobber_existing_file_and_symlink(self):
  for kind in ('file','symlink'):
   with self.subTest(kind=kind):
    path=self.root/(kind+'.json');target=self.root/(kind+'-target');target.write_bytes(b'untouched')
    if kind=='file':path.write_bytes(b'original')
    else:path.symlink_to(target)
    with self.assertRaises(FileExistsError):self.new.publish(path,{'nonce':'b'*32},0o600)
    self.assertEqual(target.read_bytes(),b'untouched');self.assertEqual(path.read_bytes(),b'original' if kind=='file' else b'untouched');self.assertEqual(path.is_symlink(),kind=='symlink');self.assertFalse(list(self.root.glob('.*.partial')))
 def test_real_complete_single_link_permissions_all_original_modes(self):
  for mode in (0o444,0o600):
   path=self.root/str(mode);self.new.publish(path,{'nonce':'c'*32},mode)
   self.assertEqual(self.new.read(path,os.getuid(),mode),{'nonce':'c'*32});self.assertEqual(stat.S_IMODE(path.stat().st_mode),mode);self.assertEqual(path.stat().st_nlink,1)
 def test_failed_rename_has_no_fallback_and_retires_only_staging_file(self):
  import ctypes,errno
  class Refuse:
   calls=[]
   def __call__(self,*args):self.calls.append(args);ctypes.set_errno(errno.ENOSYS);return -1
  rename=Refuse();path=self.root/'failed.json';library=SimpleNamespace(renameat2=rename)
  with patch.object(ctypes,'CDLL',return_value=library),patch.object(os,'rename',side_effect=AssertionError('no fallback')),patch.object(os,'replace',side_effect=AssertionError('no fallback')):
   with self.assertRaises(OSError)as error:self.new.publish(path,{'nonce':'d'*32},0o600)
  self.assertEqual(error.exception.errno,errno.ENOSYS);self.assertEqual(len(rename.calls),1);self.assertEqual(rename.calls[0][-1],1);self.assertEqual(rename.calls[0][0],rename.calls[0][2]);self.assertFalse(path.exists());self.assertFalse(list(self.root.iterdir()))
 def test_failed_flush_retires_staging_without_final_visibility(self):
  with patch.object(os,'fsync',side_effect=OSError('inert fsync refusal')):
   with self.assertRaisesRegex(OSError,'inert fsync refusal'):self.new.publish(self.root/'failed.json',{'nonce':'e'*32},0o600)
  self.assertEqual(list(self.root.iterdir()),[])
 def test_original_metadata_predicate_and_bounded_typed_refusals(self):
  old=ast.parse(self.original);new=ast.parse(A.doctor_publication(self.original))
  def predicate(tree):
   function=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='read')
   return ast.dump(next(n for n in ast.walk(function)if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='need').args[0],include_attributes=False)
  self.assertEqual(predicate(old),predicate(new))
  path=self.root/'empty';path.touch(mode=0o600)
  with self.assertRaises(ValueError)as error:self.new.read(path,os.getuid(),0o600)
  message=str(error.exception);self.assertLess(len(message),512);row=json.loads(message.split(': ',1)[1]);self.assertEqual(row['bytes'],0);self.assertTrue(row['regular']);self.assertEqual(row['uid'],os.getuid())
  path.unlink();self.new.publish(path,{'nonce':'f'*32},0o600)
  for uid,mode in ((os.getuid()+1,0o600),(os.getuid(),0o444)):
   with self.assertRaisesRegex(ValueError,'private lifetime metadata differs'):self.new.read(path,uid,mode)
  os.link(path,self.root/'alias')
  with self.assertRaisesRegex(ValueError,'private lifetime metadata differs'):self.new.read(path,os.getuid(),0o600)
 def test_original_lifetime_and_retirement_algorithms_whole_held(self):
  old=ast.parse(self.original);new=ast.parse(A.doctor_publication(self.original))
  functions=lambda t:{n.name:ast.dump(n,include_attributes=False)for n in t.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
  before=functions(old);after=functions(new);self.assertEqual(before.keys(),after.keys())
  for name in before.keys()-{'publish','read'}:self.assertEqual(before[name],after[name],name)
  self.assertEqual(self.new.SECONDS,1080);self.assertEqual(self.new.SERVICE_SECONDS,1200);self.assertEqual(self.new.CAP,8192)
 def test_real_repeat_retirement_has_no_fd_leak(self):
  count=lambda:len(os.listdir('/proc/self/fd'))
  before=count()
  for i in range(24):
   path=self.root/str(i);self.new.publish(path,{'nonce':'a'*32},0o600);self.assertEqual(self.new.read(path,os.getuid(),0o600),{'nonce':'a'*32});path.unlink()
  self.assertEqual(count(),before)

class ImageAccountsBeforeSnapshot(unittest.TestCase):
 def test_whole_fixture_guard_and_exact_order_in_both_composed_profiles(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('no actors/Git/API')):
   for profile in C.PROFILES:
    with tempfile.TemporaryDirectory() as td:
     runner=Controls().generated(Path(td),profile)
     candidate=(runner/'desktop574_fixture.sh').read_bytes()
     inserted=b'# Settle the same image-owned account configuration before its offline baseline.\n/usr/bin/systemd-sysusers --root="$root"\n'
     self.assertEqual(candidate.count(inserted),1)
     candidate=candidate.replace(b'# Settle only the image-owned mtab rule before its offline baseline.\n[[ -L "$root/etc/mtab" ]]\n/usr/bin/systemd-tmpfiles --root="$root" --create --prefix=/etc/mtab\n[[ -L "$root/etc/mtab" ]]\n',b'');original=candidate.replace(inserted,b'')
     self.assertEqual(A.initialize_image_accounts(original),candidate)
     text=candidate.decode()
     self.assertLess(text.index("'desktop574:!:20000:0:99999:7:::'"),text.index('/usr/bin/systemd-sysusers --root="$root"'))
     self.assertLess(text.index('/usr/bin/systemd-sysusers --root="$root"'),text.index('/runner/installed604.py capture'))
     self.assertLess(text.index('/runner/installed604.py capture'),text.index('mkfs.ext4'))
     for tampered in (original+b'\n',original.replace(b'installed604.py capture',b'installed604.py verify')):
      with self.assertRaisesRegex(ValueError,'whole generated fixture'):A.initialize_image_accounts(tampered)
     helper=(runner/'installed604.py').read_text()
     self.assertIn("need(actual==baseline,'complete installed inventory/payload/hardlink/nonselected DB preservation differs')",helper)
     self.assertIn('timeout=600',(runner/'base_guest.py').read_text())
 def test_no_universal_boot_or_snapshot_exception(self):
  raw=(ROOT/C.NEW/'adapter.py').read_text()
  tree=ast.parse(raw);fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='initialize_image_accounts')
  text=ast.get_source_segment(raw,fn)
  self.assertNotIn('tmpfiles',text);self.assertNotIn('baseline.pop',text);self.assertNotIn('ignore',text)
class FiveMismatchKeys(unittest.TestCase):
 def test_actual_composed_helper_retains_five_keys_within_original2048bytes(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('no actors/Git/API')),tempfile.TemporaryDirectory() as td:
   runner=Controls().generated(Path(td),'overlay');space={};exec(compile((runner/'installed604.py').read_bytes(),'trusted_generated_helper','exec'),space)
   baseline=dict(schema_version=1,packages={},ownership={},nodes={},hardlinks=[],nonselected_database={},capabilities={},payload_bytes=0,qualification='PRIVATE_INERT_DIAGNOSTIC_CONTROL')
   actual=copy.deepcopy(baseline)
   names=['etc/group','etc/gshadow','fixture/unknown-three','fixture/unknown-four','fixture/unknown-five']
   for name in names:baseline['nodes'][name]={'bytes':1,'sha256':'a'*64};actual['nodes'][name]={'bytes':2,'sha256':'b'*64}
   with patch.object(space['os'],'write')as write:
    with self.assertRaisesRegex(ValueError,'preservation differs'):space['verify'](actual,baseline)
   raw=write.call_args.args[1];row=json.loads(raw);self.assertLessEqual(len(raw),2048);self.assertEqual(row['schema_version'],2);self.assertEqual([k['key']for k in row['keys']],sorted(names));self.assertEqual(row['keys_omitted'],0);self.assertEqual(row['counts']['nodes'],[0,0,5]);self.assertEqual(row['status'],'DIAGNOSTIC_ONLY_NOT_ACCEPTANCE')
   actual['nodes']={('🧪'*100)+str(n):{'bytes':3,'sha256':'c'*64}for n in range(100)}
   with patch.object(space['os'],'write')as write:space['snapshot_mismatch'](actual,baseline)
   raw=write.call_args.args[1];row=json.loads(raw);self.assertLessEqual(len(raw),2048);self.assertLessEqual(len(row['keys']),5);self.assertEqual(row['keys_omitted']+len(row['keys']),105)
 def test_only_failure_formatter_changes_all_comparison_and_readback_functions_held(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('no actors/Git/API')),tempfile.TemporaryDirectory() as td:
   runner=Controls().generated(Path(td),'minimal');candidate=(runner/'installed604.py').read_bytes()
   # Remove only the new formatter by selecting the original composed derivation.
   raw=A.readback_openat2(A.readback_snapshot_mismatch(A.readback_path_hotpath(A.readback_fresh_mount(A.readback_progress((ROOT/C.OLD/'installed604.py').read_bytes()),ROOT),ROOT)))
   functions=lambda v:{n.name:ast.dump(n,include_attributes=False)for n in ast.parse(v).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
   before,after=functions(raw),functions(candidate);self.assertEqual(before.keys(),after.keys())
   for name in before.keys()-{'snapshot_mismatch'}:self.assertEqual(before[name],after[name],name)

class ImageMtabBeforeSnapshot(unittest.TestCase):
 def test_exact_whole_fixture_and_order_both_profiles(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('no native actors/Git/API')):
   for profile in C.PROFILES:
    with tempfile.TemporaryDirectory()as td:
     runner=Controls().generated(Path(td),profile);raw=(runner/'desktop574_fixture.sh').read_bytes()
     inserted=b'# Settle only the image-owned mtab rule before its offline baseline.\n[[ -L "$root/etc/mtab" ]]\n/usr/bin/systemd-tmpfiles --root="$root" --create --prefix=/etc/mtab\n[[ -L "$root/etc/mtab" ]]\n'
     self.assertEqual(raw.count(inserted),1);old=raw.replace(inserted,b'');self.assertEqual(A.initialize_image_mtab(old),raw)
     text=raw.decode();self.assertLess(text.index('systemd-sysusers --root='),text.index('systemd-tmpfiles --root='));self.assertLess(text.index('systemd-tmpfiles --root='),text.index('/runner/installed604.py capture'));self.assertLess(text.index('/runner/installed604.py capture'),text.index('mkfs.ext4'))
     for changed in (old+b'\n',old.replace(b'installed604.py capture',b'installed604.py verify')):
      with self.assertRaisesRegex(ValueError,'whole account-settled fixture'):A.initialize_image_mtab(changed)
     self.assertIn("need(actual==baseline,'complete installed inventory/payload/hardlink/nonselected DB preservation differs')",(runner/'installed604.py').read_text());self.assertIn('timeout=600',(runner/'base_guest.py').read_text())
 def tmpfiles(self,root,*args):
  return subprocess.run(['/usr/bin/systemd-tmpfiles','--root='+str(root),*args],env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},capture_output=True,timeout=20,check=True)
 def root(self,root,config):
  (root/'etc').mkdir();(root/'etc/tmpfiles.d').mkdir();(root/'etc/tmpfiles.d/owned-mtab.conf').write_bytes(config)
 def test_real_tmpfiles_image_rule_before_boot_is_idempotent(self):
  # Explicit owned test DATA; never reads the host or claims a native image rule.
  config=b'L+ /etc/mtab - - - - ../proc/self/mounts\n';rules=[line for line in config.splitlines()if line.startswith(b'L+ /etc/mtab ')]
  self.assertEqual(len(rules),1)
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);self.root(root,rules[0]+b'\n');(root/'etc/mtab').symlink_to('/proc/mounts')
   self.tmpfiles(root,'--create','--prefix=/etc/mtab');target=os.readlink(root/'etc/mtab');self.assertEqual(target,rules[0].decode().split()[-1]);before=(root/'etc/mtab').lstat()
   self.tmpfiles(root,'--create','--remove','--boot','--exclude-prefix=/dev');self.assertEqual(os.readlink(root/'etc/mtab'),target);self.assertEqual((root/'etc/mtab').lstat().st_ino,before.st_ino)
 def test_real_tmpfiles_uses_owned_root_rule_and_leaves_other_paths_whole(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);self.root(root,b'L+ /etc/mtab - - - - ../proc/CONTROL_ONLY/mounts\nL+ /etc/mtab-shadow - - - - /MUST_NOT_REPLACE\nf /etc/other - - - - MUST_NOT_WRITE\n');(root/'etc/mtab').symlink_to('/OLD_CONTROL_ONLY');(root/'etc/mtab-shadow').symlink_to('/OWNED_OTHER');(root/'etc/other').write_bytes(b'KEEP')
   old={n:(p.lstat().st_ino,p.read_bytes()if p.is_file()else os.readlink(p))for n in('etc/mtab-shadow','etc/other')for p in(root/n,)}
   self.tmpfiles(root,'--create','--prefix=/etc/mtab');self.assertEqual(os.readlink(root/'etc/mtab'),'../proc/CONTROL_ONLY/mounts')
   self.assertEqual({n:(p.lstat().st_ino,p.read_bytes()if p.is_file()else os.readlink(p))for n in old for p in(root/n,)},old)
 def test_real_tmpfiles_refusal_stops_before_capture(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);self.root(root,b'L+ /etc/mtab - - - - ../proc/self/mounts\n');(root/'etc/mtab').mkdir();(root/'etc/mtab/unknown').write_bytes(b'KEEP')
   marker=root/'capture-was-not-run';script='set -e\nroot="$1"\n[[ -L "$root/etc/mtab" ]]\n/usr/bin/systemd-tmpfiles --root="$root" --create --prefix=/etc/mtab\nprintf unexpected > "$root/capture-was-not-run"\n'
   result=subprocess.run(['/bin/bash','-c',script,'private-fixture',str(root)],env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},capture_output=True,timeout=20)
   self.assertNotEqual(result.returncode,0);self.assertFalse(marker.exists());self.assertEqual((root/'etc/mtab/unknown').read_bytes(),b'KEEP')

class PrivateKeyboardProfile(unittest.TestCase):
 def test_whole_historical_inputs_and_only_one_fragment_symbol(self):
  K=A.KP;raw=K.held(ROOT,'kernel.fragment');new=K.fragment(raw)
  self.assertEqual(new,raw+b'CONFIG_VIRTIO_INPUT=y\n');self.assertNotIn(b'CONFIG_INPUT_KEYBOARD=y',new);self.assertNotIn(b'CONFIG_INPUT_MISC=y',new)
  for bad in(raw+b'\n',raw.replace(b'CONFIG_INPUT=y',b'CONFIG_INPUT=n')):
   with self.assertRaises(ValueError):K.fragment(bad)
 def test_distinct_kernel_profile_and_old_profile_refusal(self):
  K=A.KP;derived=K.contract(ROOT);old=C.module('_held_no_keyboard_contract','scripts/ci/managed-gui-generic16k/kernel_contract.py')
  self.assertNotEqual(derived.PROFILE,old.PROFILE);self.assertNotEqual(derived.FRAGMENT_SHA,old.FRAGMENT_SHA);self.assertNotEqual(derived.HELPER_SHA,old.HELPER_SHA)
  self.assertEqual(derived.REVISION,old.REVISION);self.assertEqual(derived.RELEASE,old.RELEASE)
  for value in(dict(profile=old.PROFILE),dict(profile=derived.PROFILE)):
   with self.assertRaises(ValueError):derived.validate(value)
 def test_actual_copied_kernel_derivative_and_drift_refusal(self):
  K=A.KP
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)
   for n in('build_kernel.py','kernel.fragment'):(root/n).write_bytes(K.held(ROOT,n))
   K.prepare_kernel(ROOT,root);self.assertEqual((root/'kernel.fragment').read_bytes(),K.fragment(K.held(ROOT,'kernel.fragment')))
   self.assertEqual((root/'build_kernel.py').read_bytes(),K.build_helper(K.held(ROOT,'build_kernel.py')))
   with self.assertRaises(ValueError):K.prepare_kernel(ROOT,root)
 def test_configuration_requires_builtin_keyboard_and_all_prior_dependencies(self):
  K=A.KP
  with tempfile.TemporaryDirectory()as td:
   p=Path(td)/'config';raw=b'CONFIG_INPUT=y\nCONFIG_INPUT_EVDEV=y\nCONFIG_VIRTIO=y\nCONFIG_VIRTIO_PCI=y\nCONFIG_VIRTIO_INPUT=y\n# CONFIG_MODULES is not set\n';p.write_bytes(raw);K.check_config(p)
   for name in('CONFIG_INPUT','CONFIG_INPUT_EVDEV','CONFIG_VIRTIO','CONFIG_VIRTIO_PCI','CONFIG_VIRTIO_INPUT'):
    p.write_bytes(raw.replace((name+'=y').encode(),(name+'=m').encode()))
    with self.assertRaises(ValueError):K.check_config(p)
   p.write_bytes(raw+b'CONFIG_VIRTIO_INPUT=y\n')
   with self.assertRaises(ValueError):K.check_config(p)
 def test_generated_device_profile_seat_guard_and_unchanged_focus_driver(self):
  for profile in C.PROFILES:
   with tempfile.TemporaryDirectory()as td:
    runner=Controls().generated(Path(td),profile);runtime=(runner/'desktop574_runtime.py').read_text();session=(runner/'session.py').read_text()
    self.assertEqual(runtime.count('-device virtio-keyboard-pci'),1);self.assertIn('-nodefaults',runtime);self.assertNotIn('input-send-event',runtime)
    self.assertIn("'one actual private QEMU US keyboard seat required'",session);self.assertIn("'virtual_keyboard_ready'",session)
    self.assertLess(session.index("'one actual private QEMU US keyboard seat required'"),session.index("checkpoint='doctor-startup'"))
    self.assertEqual((runner/'kernel_contract.py').read_bytes(),A.KP.contract_bytes(ROOT));self.assertEqual((runner/'a11y_driver.c').read_bytes(),A.peer_focus_driver((ROOT/'scripts/ci/welcome-management-native/a11y_driver.c').read_bytes()))
    for value in('time.monotonic() + 1300','signal.ITIMER_REAL, 1750'):self.assertIn(value,runtime)
    self.assertIn('TimeoutStartSec=1200',(runner/'desktop574_fixture.sh').read_text())

class PrivateKeyboardSeatRefusals(unittest.TestCase):
 def test_actual_emitted_mandatory_seat_query_refuses_missing_duplicate_foreign_or_bad_state(self):
  for keyboards in ([],[dict(name='gpio-keys',layout='us',capsLock=False)],[dict(name='qemu-virtio-keyboard',layout='us',capsLock=False)]*2,[dict(name='qemu-virtio-keyboard',layout='de',capsLock=False)],[dict(name='qemu-virtio-keyboard',layout='us',capsLock=True)]):
   emitted=[];scope=dict(json=json,C=C,stage='minimal',base=SimpleNamespace(emit=lambda *a,**kw:emitted.append((a,kw))),command=lambda *a:json.dumps(dict(keyboards=keyboards)))
   with self.assertRaisesRegex(ValueError,'one actual private QEMU US keyboard seat required'):exec(compile(textwrap.dedent(A.KEYBOARD_GUEST),'<exact-emitted-guest-seat-guard>','exec'),scope)
   self.assertEqual(emitted,[])


class ProducerImagePreservation(unittest.TestCase):
 class Docker:
  """Inert finite command model, never a native or Docker-positive fixture."""
  image='sha256:'+'1'*64;core='sha256:'+'2'*64;foreign='sha256:'+'3'*64
  def __init__(self):self.images={self.image};self.refs={};self.calls=[];self.error=False
  def run(self,argv,**kwargs):
   self.calls.append(list(argv));exit=0;stdout=b'';stderr=b''
   if self.error:return SimpleNamespace(returncode=125,stdout=b'',stderr=b'permission denied')
   if argv[:3]==['docker','image','inspect']:
    ref=argv[-1];image=self.refs.get(ref,ref)
    if image in self.images:stdout=(image+'\n').encode()
    else:exit=1;stdout=b'\n';stderr=('Error: No such image: '+ref).encode()
   elif argv[:3]==['docker','image','tag']:
    image,ref=argv[-2:]
    if image not in self.images:exit=1;stderr=b'No such image'
    else:self.refs[ref]=image
   elif argv[:3]==['docker','image','ls']:
    refs=[v.split('=',1)[1]for v in argv if v.startswith('reference=')];values={self.refs[refs[0]]}if refs and refs[0]in self.refs else set()if refs else self.images;stdout=''.join(x+'\n'for x in sorted(values)).encode()
   elif argv[:3]==['docker','image','rm']:
    ref=argv[-1];image=self.refs.get(ref,ref)
    if image not in self.images:exit=1;stderr=b'No such image'
    elif ref in self.refs:
     del self.refs[ref]
     if image not in self.refs.values():self.images.remove(image)
    else:
     self.images.remove(image);self.refs={k:v for k,v in self.refs.items()if v!=image}
   else:raise AssertionError('unlisted command '+repr(argv))
   if kwargs.get('check')and exit:raise subprocess.CalledProcessError(exit,argv,stdout,stderr)
   return SimpleNamespace(returncode=exit,stdout=stdout,stderr=stderr)
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='producer-image-private-',dir='/tmp');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.docker=self.Docker();self.context=ci.context604
  (self.root/'private/desktop574').mkdir(parents=True);(self.root/'public').mkdir();(self.root/'private/desktop574/image-id').write_text(self.docker.image+'\n');self.owner=dict(schema_version=1,token='a'*32,core_image=self.docker.core,images_preexisting=[],preparation_source='/inert/private/source');self.owner_path=self.root/'producer-owner.json';self.owner_path.write_bytes(C.encoded(self.owner))
  self.actor=patch.object(subprocess,'run',side_effect=self.docker.run);self.actor.start();self.addCleanup(self.actor.stop)
 def old_release(self):
  original=(ROOT/'scripts/ci/desktop574_runtime.py').read_text();tree=ast.parse(original);scope=dict(re=__import__('re'),require=C.need)
  for name in('bind_local_base','release_local_base'):
   n=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name==name);exec(compile(ast.get_source_segment(original,n),'<exact-original-image-operation>','exec'),scope)
  def execute(argv,*_):
   r=self.docker.run(argv);C.need(r.returncode==0,'inert source operation');return r.stdout
  def inspect(argv):return execute(argv).decode().strip()
  def cleanup(argv,*_):
   r=self.docker.run(argv);return r.stdout if r.returncode==0 else None
  ref='cachy-asahi-desktop574-base:'+'b'*32;scope['bind_local_base'](self.docker.image,ref,execute,inspect);return ref,scope['release_local_base'](self.docker.image,ref,cleanup)
 def producer(self):return C.module('_test_whole_original_producer_image_cleanup','scripts/ci/full-composition-installer-vm/producer.py')
 def test_real_private_receipts_original_cleanup_fails_without_hold_model(self):
  _,released=self.old_release();self.assertEqual(released,dict(ok=True,base_image_present=False))
  with self.assertRaisesRegex(ValueError,'owned-image:desktop574/image-id'):self.producer().cleanup(self.root)
  self.assertTrue((self.root/'private').exists());self.assertEqual(json.loads((self.root/'public/producer-cleanup.json').read_bytes())['status'],'FAIL')
 def test_exact_original_cleanup_body_removes_image_and_preservation_tag(self):
  report={};lease=self.context.preserve_producer_image(self.root,report);self.assertIs(report['producer_image_preservation'],lease);ref,released=self.old_release();self.assertEqual(released,dict(ok=True,base_image_present=True));runtime=dict(base_image=self.docker.image,base_reference=ref,base_reference_cleanup=released);self.assertTrue(self.context.require_producer_image_preserved(runtime,lease))
  old=self.producer().cleanup(self.root);self.assertEqual(old['status'],'PASS');retired=self.context.producer_image_retired(lease,old);self.assertEqual(retired['status'],'PASS_ORIGINAL_PRODUCER_IMAGE_AND_PRESERVATION_REFERENCE_ABSENT');self.assertFalse((self.root/'private').exists());self.assertEqual(self.docker.images,set());self.assertEqual(self.docker.refs,{});self.assertEqual([a for a in self.docker.calls if a[:3]==['docker','image','rm']and a[-1]==self.docker.image],[['docker','image','rm','--no-prune',self.docker.image]])
 def test_borrowed_changed_reference_alias_or_uncertain_observation_refuse(self):
  for mode in('preexisting','core','foreign-reference','API-error','receipt-alias'):
   with self.subTest(mode=mode):
    self.owner.update(core_image=self.docker.core,images_preexisting=[]);self.owner_path.write_bytes(C.encoded(self.owner));self.docker.refs={};self.docker.error=False;report={}
    if mode=='preexisting':self.owner['images_preexisting']=[self.docker.image];self.owner_path.write_bytes(C.encoded(self.owner))
    elif mode=='core':self.owner['core_image']=self.docker.image;self.owner_path.write_bytes(C.encoded(self.owner))
    elif mode=='foreign-reference':self.docker.images.add(self.docker.foreign);self.docker.refs['cachy-asahi-desktop574-producer:'+'a'*32]=self.docker.foreign
    elif mode=='API-error':self.docker.error=True
    else:self.owner_path.rename(self.root/'held-owner');self.owner_path.symlink_to('held-owner')
    before=len(self.docker.calls)
    with self.assertRaises(ValueError):self.context.preserve_producer_image(self.root,report)
    self.assertFalse(any(a[:3]in(['docker','image','tag'],['docker','image','rm'])for a in self.docker.calls[before:]))
    if self.owner_path.is_symlink():self.owner_path.unlink();(self.root/'held-owner').rename(self.owner_path)
 def test_missing_image_is_not_cleanup_pass_and_runtime_or_foreign_ref_refuses(self):
  lease=self.context.preserve_producer_image(self.root,{});runtime=dict(base_image=self.docker.image,base_reference='cachy-asahi-desktop574-base:'+'b'*32,base_reference_cleanup=dict(ok=True,base_image_present=True))
  for bad in(dict(runtime,base_image=self.docker.foreign),dict(runtime,base_reference_cleanup=dict(ok=True,base_image_present=False))):
   with self.assertRaises(ValueError):self.context.require_producer_image_preserved(bad,lease)
  with self.assertRaises(ValueError):self.context.producer_image_retired(lease,dict(status='FAIL',failures=['owned-image:desktop574/image-id']))
  with self.assertRaises(ValueError):self.context.producer_image_retired(lease,dict(status='PASS',failures=[]))
  self.docker.images.clear();self.docker.refs.clear()
  with self.assertRaisesRegex(ValueError,'owned-image:desktop574/image-id'):self.producer().cleanup(self.root)
 def test_actual_ci_order_and_all_original_consumer_guards_held(self):
  old=C.read(ROOT/C.OLD/'ci.py').decode();text=ci.derive(old)
  self.assertEqual(text.count('producer.cleanup(producer_output)'),1);self.assertEqual(text.count('context604.preserve_producer_image(producer_output,report)'),1);self.assertEqual(text.count("context604.require_producer_image_preserved(raw,report['producer_image_preservation'])"),1);self.assertEqual(text.count("context604.producer_image_retired(report.get('producer_image_preservation'),report['producer_cleanup'])"),1)
  self.assertLess(text.index('context604.preserve_producer_image(producer_output,report)'),text.index('materializer.prepare('));self.assertLess(text.index('context604.require_producer_image_preserved'),text.index("C.need(retired(raw,controller)"));self.assertLess(text.index('producer.cleanup(producer_output)'),text.index('context604.producer_image_retired'))
  self.assertIn("len(report.get('cleanup',[]))==15 and context604.launcher_retired(report,C.ROOT)",text);self.assertIn("C.need(report['producer_cleanup']['status']=='PASS','original producer retirement required')",text)

class CaptureCustody(unittest.TestCase):
 def helper(self):return C.module('_actual604_capture_custody',C.NEW+'/context604.py')
 def paths(self,base):
  output=Path(base)/'runtime';output.mkdir(mode=0o700);fixture=output/'fixture';fixture.mkdir();return output,fixture
 def test_real_bounded_receipt_survives_original_private_fixture_deletion(self):
  h=self.helper()
  with tempfile.TemporaryDirectory()as td:
   output,fixture=self.paths(td);raw=b'{"status":"INERT_NOT_NATIVE_CAPTURE","bytes":"unchanged"}\n';source=fixture/'installed604-capture.json';source.write_bytes(raw)
   row=h.preserve_capture(fixture,output);self.assertEqual(row,dict(bytes=len(raw),sha256=C.sha(raw)));shutil.rmtree(fixture)
   self.assertFalse(fixture.exists());self.assertEqual((output/'installed604-capture.json').read_bytes(),raw);self.assertEqual(stat.S_IMODE((output/'installed604-capture.json').stat().st_mode),0o600)
   # It is the preserved original bytes, never a result reconstructed from events.
   self.assertNotIn('PASS_COMPLETE',raw.decode())
 def test_receipt_source_alias_hardlink_oversize_and_target_alias_refuse(self):
  h=self.helper()
  for mode in('source-symlink','source-hardlink','oversize','target-alias','fixture-alias'):
   with self.subTest(mode=mode),tempfile.TemporaryDirectory()as td:
    output,fixture=self.paths(td);source=fixture/'installed604-capture.json';other=Path(td)/'held';other.write_bytes(b'PRIVATE_INERT_HELD')
    if mode=='source-symlink':source.symlink_to(other)
    elif mode=='source-hardlink':os.link(other,source)
    elif mode=='oversize':source.write_bytes(b'X'*65537)
    elif mode=='target-alias':source.write_bytes(b'INERT');(output/'installed604-capture.json').symlink_to(other)
    else:fixture.rmdir();fixture.symlink_to(Path(td),target_is_directory=True)
    with self.assertRaises((OSError,ValueError)):h.preserve_capture(fixture,output)
    self.assertEqual(other.read_bytes(),b'PRIVATE_INERT_HELD')
    if mode!='target-alias':self.assertFalse((output/'installed604-capture.json').exists())
 def test_both_generated_profiles_copy_before_qemu_and_hold_original_cleanup(self):
  for profile in C.PROFILES:
   with tempfile.TemporaryDirectory()as td:
    runtime=(Controls().generated(Path(td),profile)/'desktop574_runtime.py').read_text()
    original="        execute(cmd + ['/runner/desktop574_fixture.sh'], 'fixture', 600)"
    copy='        context604.preserve_capture(fixture,out)';self.assertEqual(runtime.count(copy),1)
    self.assertLess(runtime.index(original),runtime.index(copy));self.assertLess(runtime.index(copy),runtime.index("name = 'desktop574-vm-"))
    self.assertIn("fixture.rmdir()",runtime);self.assertIn("'guest_disk_removed': True",runtime)
    self.assertIn('signal.ITIMER_REAL, 1750',runtime)
 def test_retention_keeps_original_public_path_and_all_capture_join_guards(self):
  before=(ROOT/C.OLD/'retain.py').read_text();after=retain.derive(before)
  self.assertIn("('fixture/installed604-capture.json',65536)",after)
  self.assertIn("runtime/('installed604-capture.json' if name=='fixture/installed604-capture.json' else name)",after)
  self.assertIn("capture=C.json_read(runtime/'installed604-capture.json',65536)",after)
  for text in("capture['status']=='PASS_COMPLETE_ACTUAL604_CAPTURE'","all(capture[k]==final[k]","len(raw.get('cleanup',[]))==15","context604.launcher_retired(raw,C.ROOT)"):
   self.assertIn(text,after)
 def test_workflow_only_existing_bounded_public_root_includes_hidden_config(self):
  raw=(ROOT/'.github/workflows/native-arm-current604-public-pair-generic16k.yml').read_text()
  marker='          path: /tmp/cachy-asahi-current604-public-pair-generic16k-${{ github.run_id }}-${{ github.run_attempt }}/public/\n'
  self.assertEqual(raw.count(marker+'          include-hidden-files: true\n'),1);self.assertEqual(raw.count('include-hidden-files:'),1)
  # Real tiny ordinary-file ZIP transport reproduces the default hidden-file loss.
  import zipfile
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);public=root/'public';(public/'kernel').mkdir(parents=True);(public/'kernel/.config').write_bytes(b'INERT_NOT_A_KERNEL_CONFIG');(public/'retention.json').write_bytes(b'INERT_NOT_A_NATIVE_RECEIPT');(root/'private').write_bytes(b'NOT_PUBLIC')
   expected={p.relative_to(public).as_posix()for p in public.rglob('*')if p.is_file()}
   old={n for n in expected if not any(part.startswith('.')for part in Path(n).parts)};self.assertEqual(expected-old,{'kernel/.config'})
   path=root/'bounded-public.zip'
   with zipfile.ZipFile(path,'w')as z:
    for name in sorted(expected):z.writestr(name,(public/name).read_bytes())
   with zipfile.ZipFile(path)as z:self.assertEqual(set(z.namelist()),expected);self.assertNotIn('private',z.namelist())

