# SPDX-License-Identifier: MIT
"""Actor-blocked finite controls; no native or signing success fixtures."""
import stat
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
     for filename,source in (('doctor_lifetime.py','scripts/ci/welcome-management-native/doctor_lifetime.py'),('a11y_driver.c','scripts/ci/welcome-management-native/a11y_driver.c'),('file_capabilities.py','scripts/apps/file_capabilities.py')):
      original=(ROOT/source).read_bytes();self.assertEqual((runner/filename).read_bytes(),A.peer_focus_driver(original) if filename=='a11y_driver.c' else original)
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
       with patch.object(actual,'parser',return_value=SimpleNamespace(parse_args=lambda _:args)),patch.object(actual,'preflight',return_value=({}, {}, object(), {}, base/'inert-assets',installer)),patch.object(actual.platform,'machine',return_value='aarch64'),patch.dict(os.environ,GITHUB_ACTIONS='true',RUNNER_ARCH='ARM64',RUNNER_TEMP=str(base)),patch.object(C,'prepare_assets',return_value=base/'inert-assets'),patch.object(C,'load',side_effect=lambda root,path:runtime if path.endswith('/run.py') else object()),patch.object(A,'prepare',side_effect=prepare),patch.object(ci.context604,'prepare'):
        if mode in ('hardlink','over-cap'):
         with self.assertRaisesRegex(ValueError,'bounded ordinary'):ci.main([])
         self.assertFalse((output/'public/retention.json').exists())
        else:
         self.assertEqual(ci.main([]),1);report=C.json_read(output/'result.json');ledger=C.json_read(output/'public/retention.json');self.assertEqual(report['status'],'FAIL');self.assertEqual(report['cleanup'],'RETAINED_CONSUMER_OR_PRODUCER_ABSENCE_UNKNOWN');self.assertEqual(ledger['status'],'NOT_ACCEPTED');self.assertEqual(ledger['ordered_private_cleanup'],report['cleanup']);name='runtime/'+log_name
         if mode=='present':self.assertEqual((output/'public'/name).read_bytes(),marker);self.assertEqual(ledger['files'][name],dict(bytes=len(marker),sha256=C.sha(marker)))
         else:self.assertNotIn(name,ledger['files'])
         self.assertLessEqual(ledger['bytes'],128*1024**2);self.assertNotIn('private-not-exported',str(ledger))
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
    runner=Controls().generated(Path(tmp),selected);self.assertEqual((runner/'installed604.py').read_bytes(),A.readback_path_hotpath(A.readback_fresh_mount(A.readback_progress((ROOT/C.OLD/'installed604.py').read_bytes()),ROOT),ROOT))
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

if __name__=='__main__':unittest.main(verbosity=2)

