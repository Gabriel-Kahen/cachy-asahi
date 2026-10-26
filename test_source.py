#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit finite non-actor controls; no unittest discovery/fallback."""
import copy,json,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent/'implementation'))
import common as C,adapter,authority,source_guard
class Controls(unittest.TestCase):
 def test_closed_source_and_all_runtime_inverses(self):
  r=source_guard.verify();self.assertEqual(r['cases'],3);self.assertGreater(r['python_bodies'],200)
 def test_only_apps_delta(self):
  a,b=C.locks();self.assertEqual({n for n in a if a[n]!=b[n]},{'cachy-asahi-apps'});self.assertEqual(a['cachy-asahi-repository-runtime'],'0.1.0-1');self.assertNotIn('systemd-tests',a);driver=C.load('_source_selected_committed',C.ROOT/'cases/normal/scripts/ci/full-root-upgrade/root_upgrade.py');row=dict(status='PASS',before=a,after=b,prepared_add={'cachy-asahi-apps':'0.1.0-16'},prepared_remove={},**{k:True for k in('commit_started','packages_committed','checkpoint_changed','checkpoint_directory_synced')});driver.committed(row,a,b);row['prepared_add']['cachy-asahi-apps']='0.1.0-6'
  with self.assertRaises(ValueError):driver.committed(row,a,b)
  for case in C.CASES:
   hook=C.load('_source_quiesce_'+case,C.ROOT/'cases'/case/'scripts/ci/full-root-upgrade-caller/upgrade_hook.py')
   class ReachedOriginalGuard(Exception):pass
   def stopped(*_):raise ReachedOriginalGuard()
   hook.load=stopped
   with self.assertRaises(ReachedOriginalGuard):hook.quiesce({},a,None,None,None)
   bad=dict(a,**{'cachy-asahi-apps':'0.1.0-5'})
   with self.assertRaises(ValueError):hook.quiesce({},bad,None,None,None)
 def test_no_authority_transfer(self):
  if any(v is not None for v in C.profile()['authorities'].values()):
   p=copy.deepcopy(C.profile());self.assertEqual(authority.require_bound(),p);self.assertFalse(authority.source_context()['actor_authority']);p['authorities']['baseline607']=None
   with self.assertRaisesRegex(ValueError,'UNBOUND'):authority.require_bound(p)
   return
  with self.assertRaisesRegex(ValueError,'UNBOUND'):authority.require_bound()
  p=copy.deepcopy(C.profile());p['authorities']['fresh607']={'status':'ROOT_ACCEPTED_FINITE_NATIVE_APPS16_SIX_TOOL_SOFTWARE_COMPOSITION'}
  with self.assertRaisesRegex(ValueError,'UNBOUND'):authority.require_bound(p)
 def test_typed_counter_drift(self):
  row=C.profile()['old_source_lineage']['normal']['scripts/update/full_root.py'];raw=C.read(C.ROOT/'cases/normal/scripts/update/full_root.py');old=source_guard.inverse(raw,row);self.assertEqual(old.count(b'max_packages: int = 604'),1)
  with self.assertRaisesRegex(ValueError,'counts'):adapter.transform(old.replace(b'max_packages: int = 604',b'max_packages: int = 608'),'scripts/update/full_root.py')
 def test_malformed_whole_body_inverse(self):
  row=C.profile()['old_source_lineage']['normal']['scripts/update/full_root.py'];raw=C.read(C.ROOT/'cases/normal/scripts/update/full_root.py')
  with self.assertRaises(ValueError):source_guard.inverse(raw+b'\n',row)
 def test_ordinary_clocks_and_errno(self):
  p=C.profile()
  for case in C.CASES:
   root=C.ROOT/'cases'/case;cfg=json.loads(C.read(root/'upgrade-config.json'));self.assertEqual((cfg['stage_seconds'],cfg['copy_seconds'],cfg['driver_seconds'],cfg['verify_seconds']),(1200,1200,1860 if case=='normal'else 2400,600));name='scripts/ci/full-root-upgrade-caller/container.py';raw=C.read(root/name);old=source_guard.inverse(raw,p['old_source_lineage'][case][name]);self.assertEqual(raw.count(b'3900'),old.count(b'3900'));self.assertEqual(raw.count(b'errno'),old.count(b'errno'))
 def test_honest_native_build_inventory(self):
  d=json.loads(C.read(C.HERE/'selected-input.json'));raw=d['build_evidence']['raw_pacman_Q_lock'].encode();self.assertEqual(C.pin(raw),d['build_evidence']['raw_pacman_Q_pin']);self.assertEqual(len(raw.splitlines()),575);self.assertEqual(d['build_evidence']['new607_installed_state'],'NOT_RUN_NOT_FABRICATED');self.assertEqual(len(d['payload']),8)
 def test_projection_preserves_exact_original_and_limits(self):
  p=C.profile();record=p['authority_projection_policy']['records']['fresh607'];row=authority.projection('fresh607',record,p)
  self.assertEqual(row['original'],record['original']);self.assertEqual(row['original']['cleanup'],'PASS_SOURCE_BOUND_RETAINED_RECEIPTS')
  self.assertEqual(row['original']['limits'],record['original']['limits']);self.assertIn('NOT_FRESH_FD_OBSERVATION',row['readback'])
  self.assertNotIn('ordinary_parent_retired',row);self.assertNotIn('independent_root_readback',row)
  unbound=all(v is None for v in p['authorities'].values())
  if unbound:
   self.assertEqual(authority.source_context()['status'],'SOURCE_ONLY_BINDING_MACHINERY_UNBOUND')
   self.assertIsNone(p['authority_projection_policy']['records']['baseline607'])
   with self.assertRaisesRegex(ValueError,'UNBOUND'):authority.require_bound()
  else:
   self.assertEqual(authority.source_context()['status'],'BOUND_SOURCE_REQUIRES_RUNTIME_FULL_CARRIER_GATES')
   self.assertEqual(authority.require_bound(),p)
  with self.assertRaisesRegex(ValueError,'UNBOUND'):authority.projection('baseline607',None,p)
 def test_original_projection_flags_clock_identity_refusals(self):
  p=C.profile();original=p['authority_projection_policy']['records']['fresh607']['original']
  for change in({'status':'ROOT_ACCEPTED_FINITE_NATIVE_APPS16_SIX_TOOL_SOFTWARE_COMPOSITION'},
    {'package_count':True},{'cleanup':'PASS'},{'qemu_natural_exit':False},
    {'expected607_sha256':p['before']['sha256']},{'source_sha':'0'*40}):
   row=copy.deepcopy(original);row.update(change)
   with self.assertRaises(ValueError):authority.original_decision('fresh607',row,p)
  for flag in authority.FLAGS:
   row=copy.deepcopy(original);row['ordinary_and_root_flags'][flag]=False
   with self.assertRaises(ValueError):authority.original_decision('fresh607',row,p)
  for change in({'complete':False},{'deadline_seconds':601},{'elapsed_ms':600000},{'missing_database_nodes':1},{'observed_nodes':200001}):
   row=copy.deepcopy(original);row['root_observation'].update(change)
   with self.assertRaises(ValueError):authority.original_decision('fresh607',row,p)
 def test_partial_or_source_machine_never_unlocks_actors(self):
  p=copy.deepcopy(C.profile());p['authorities']['baseline607']=None;p['authorities']['fresh607']={'path':'fresh607/projection.json','bytes':1,'sha256':'0'*64,'source':p['fresh_source'],'run':40223603945}
  with self.assertRaisesRegex(ValueError,'UNBOUND'):authority.require_bound(p)
  old=C.profile
  try:
   C.profile=lambda:p
   with self.assertRaises(ValueError):authority.source_context()
  finally:C.profile=old
  self.assertEqual(authority.source_context()['actor_authority'],False)
 def test_private_before_inverse_and_no_circular_self_identity(self):
  p=C.profile();b=json.loads(C.read(C.HERE/'parent355.json'))['binding_context']
  self.assertEqual(len(b['files']),357);self.assertEqual(b['source'],'3b8ca255d90f0b4b0be18639a4b754da8c7aa969')
  self.assertEqual({k:p[k]for k in('actual_source','actual_ref','actual_run')},{'actual_source':None,'actual_ref':None,'actual_run':None})
  if all(v is None for v in p['authorities'].values()):
   self.assertIsNone(p['input_sources']['latest_decisions']);self.assertIsNone(p['authority_files'])
   self.assertEqual(authority.source_context()['baseline607'],'UNBOUND')
  else:
   self.assertIsInstance(p['authority_files'],dict)
   self.assertEqual(authority.source_context()['baseline607'],'RUNTIME_GATE_REQUIRED')

 def _held(self):
  import os
  path=C.safe(os.environ['LATEST607_HELD_SOURCE']);self.assertEqual(C.rows(path),C.profile()['held_files']);return path
 def _plan(self):
  import ast,types
  raw=C.read(self._held()/'scripts/ci/expanded600-root-upgrade/run.py');fn=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='prepare_with_plan');scope=dict(C=types.SimpleNamespace(need=C.need,encoded=C.enc),json=json);exec(compile(ast.Module(body=[fn],type_ignores=[]),'<whole-original-plan-source-control>','exec'),scope);return scope['prepare_with_plan']
 def _facade(self,failure):
  import os,tempfile,types,base64
  import cache
  held=self._held();producer=C.load('_fixture_real_producer_'+str(failure),held/'scripts/ci/full-composition-installer-vm/producer.py');diagnostic=C.load('_fixture_source_diagnostic_'+str(failure),C.HERE/'producer_diagnostic.py');oldprepare,oldexport,oldload=producer.prepare,producer.export_ready,producer.load
  with tempfile.TemporaryDirectory(prefix='updater-source-flow-')as td:
   root=Path(td);output=root/'producer';output.mkdir(mode=0o700);(output/'private').mkdir();(output/'public').mkdir();prep=root/'preparation';script=prep/'scripts/ci/full-development-composition/dependencies/acquire.py';script.parent.mkdir(parents=True);script.write_text("print('SOURCE_FIXTURE_NOT_AUTHENTICATION')\nraise SystemExit(9)\n");args=types.SimpleNamespace(output=output,preparation_source=prep,code=held,updater=root/'updater',cache=root/'cache');(output/'producer-owner.json').write_bytes(C.enc(dict(schema_version=1,token='b'*32,preparation_source=str(prep))))
   # Control fixture drives the REAL producer module globals, real original plan
   # function, exact diagnostic callback, original command and real Python child.
   # It never calls or claims the native preparation/Git/ALPM/package gates.
   source="""def fixture_prepare(args):
 raw=args.output/'private';(raw/'inputs').mkdir();ready=raw/'ready'
 if _fixture_failure:
  try:
   api=load(args.code/_fixture_diagnostic.CALLER)
   argv=[_fixture_executable,'-B',str(args.preparation_source/'scripts/ci/full-development-composition/dependencies/acquire.py'),'--source-root',str(args.updater),'--cache',str(args.cache),'--keydir',str(args.cache),'--output',str(raw/'dependency-audit')]
   api.command(argv,raw/'dependency.log',180)
  except BaseException as e:
   (args.output/'public/producer.json').write_bytes(_fixture_encode(dict(status='FAIL',phase='authenticate-five-deduplicate-four',installer='NOT RUN',upgrade='NOT RUN',error_type=type(e).__name__,error=str(e))))
   raise
 return export_ready(raw,ready,dict(inputs=raw/'inputs',plan=dict(source_fixture=True)))
"""
   producer.__dict__.update(_fixture_failure=failure,_fixture_diagnostic=diagnostic,_fixture_executable=sys.executable,_fixture_encode=C.enc);exec(compile(source,'<explicit-source-flow-fixture-not-native>','exec'),producer.__dict__);producer.prepare=producer.fixture_prepare
   def exporting(raw,ready,held,*a,**kw):ready.mkdir();return ready
   producer.export_ready=exporting;facade=cache.ProducerFacade(producer,diagnostic);plan=self._plan()
   try:
    if failure:
     from unittest.mock import patch
     with patch.dict(os.environ,dict(PATH=os.defpath,HOME=str(root),LANG='C.UTF-8'),clear=True),self.assertRaisesRegex(AssertionError,'command failed: dependency.log'):plan(facade,args)
     report=json.loads((output/'public/producer.json').read_bytes());data=report['failure_data'];self.assertEqual(data['purpose'],diagnostic.DEPENDENCY_PURPOSE);self.assertFalse(data['acceptance_authority']);self.assertFalse(data['cleanup_authority']);self.assertEqual(data['command']['timeout_seconds'],180);self.assertEqual(data['command']['returncode'],9);self.assertEqual(data['command']['role'],'AUTHENTICATE_FIVE_DEDUPLICATE_FOUR');self.assertEqual(base64.b64decode(data['logs']['dependency.log']['base64']),b'SOURCE_FIXTURE_NOT_AUTHENTICATION\n');self.assertTrue(data['logs']['dependency.log']['complete']);self.assertLess(len(C.enc(report)),448*1024)
    else:
     ready,value=plan(facade,args);self.assertEqual(ready,output/'private/ready');self.assertEqual(value,dict(source_fixture=True));self.assertFalse((output/'public/producer.json').exists())
    self.assertIs(producer.export_ready,exporting);self.assertIs(producer.load,oldload)
   finally:producer.prepare=oldprepare;producer.export_ready=oldexport;producer.load=oldload
 def test_retained_dependency_policy_and_exact_source_helpers(self):
  import cache
  p=cache.dependency_policy();helper=C.load('_source_dependency_static_controls',C.HERE/'compiler6.py');profile,dependency=helper.dependency_configuration();self.assertEqual(len(dependency['selected']),8);self.assertEqual(dependency['source'],p['incoming_source']);self.assertEqual(p['prior_files'],1159);self.assertEqual(p['total_dependency_files'],10);self.assertEqual(p['new_phase_seconds'],240);self.assertEqual(p['original_acquisition_seconds'],180);self.assertEqual(p['outer_fit'],'NOT_ESTABLISHED')
 def test_new_owner_forward_whole_inverse_and_shared_arguments(self):
  import runtime
  raw=C.read(self._held()/runtime.OLD/'run.py');derived=runtime.derive_owner(raw);self.assertIn('return Y.prepare_with_plan(C.old600()[1],producer,args)',derived);self.assertEqual(len(runtime.OWNER_EDITS),7)
 def test_facade_real_globals_original_plan_capture_positive(self):self._facade(False)
 def test_facade_real_command_failure_capture_before_cleanup(self):self._facade(True)
 def test_cache_policy_foreign_and_missing_runtime_input_refuse(self):
  import cache,types
  from unittest.mock import patch
  for key,value in(('new_phase_seconds',241),('incoming_source','f'*40),('prior_files',1158),('total_dependency_files',8),('authority',True)):
   p=copy.deepcopy(C.profile());p['dependency_cache'][key]=value
   with self.subTest(key=key),patch.object(C,'profile',return_value=p),self.assertRaises(ValueError):cache.dependency_policy()
  with self.assertRaisesRegex(ValueError,'explicit immutable'):cache.prepare_with_plan(types.SimpleNamespace(dependency_incoming=None),None,None,None)


 def _decisions_argv(self):
  import shlex,os
  workflow=json.loads(C.read(C.ROOT/'.github/workflows/native-arm-build.yml'));step=next(r for r in workflow['jobs']['native']['steps']if r['name']=='Require five actual decisions and frozen installer before input retrieval');self.assertNotIn('--dependency-incoming',step['run']);text=step['run'].split('python3 -I -B native4k-source/entry.py ',1)[1].replace('\\\n',' ');args=shlex.split(text)
  values={'GITHUB_WORKSPACE':'/tmp/source-only-updater-workspace','RUNNER_TEMP':'/tmp/source-only-updater-runner','IMPLEMENTATION_SOURCE':'764da54af95f91ad7e72059b3c0eea0af0631774','WORKFLOW_SOURCE':'764da54af95f91ad7e72059b3c0eea0af0631774','UPGRADE_CASE':'normal'}
  for i,text in enumerate(args):
   for key,value in values.items():text=text.replace('$'+key,value)
   args[i]=text
  self.assertEqual(args[0],'decisions');return args[1:]
 def test_actual_decisions_caller_reaches_original_authority_gate(self):
  import os
  from unittest.mock import patch
  import entry,runtime
  class SourceGateReached(Exception):pass
  held=self._held();module=entry.wrapper(held);calls=[]
  def stop(path):calls.append(path);raise SourceGateReached('SOURCE_FIXTURE_NOT_GATE_AUTHORITY')
  with patch.object(entry.authority,'gates',side_effect=stop),patch.object(runtime.Integration,'inputs',side_effect=AssertionError('NO_ACTORS_OR_INPUT_GATE_SUBSTITUTION')):
   with self.assertRaises(SourceGateReached):module.prerequisites(held,'decisions',self._decisions_argv())
  self.assertEqual(calls,[Path('/tmp/source-only-updater-workspace/latest607-latest-decisions')])
 def test_all_seven_original_prerequisite_extras_stay_required(self):
  import contextlib,io,runtime
  args=self._decisions_argv();names=('latest-installer','six-public','six-record','apps16','apps16qualification','apps16current606qualification','latest-decisions');selected,rest=runtime.extras(args);self.assertEqual(set(vars(selected)),{n.replace('-','_')for n in names});self.assertFalse(hasattr(selected,'dependency_incoming'))
  for name in names:
   bad=list(args);i=bad.index('--'+name);del bad[i:i+2];err=io.StringIO()
   with self.subTest(name=name),contextlib.redirect_stderr(err),self.assertRaises(SystemExit)as caught:runtime.extras(bad)
   self.assertEqual(caught.exception.code,2);self.assertIn('--'+name,err.getvalue())
 def test_execute_requires_cache_argument_before_any_gate_or_actor(self):
  import contextlib,io,subprocess,runtime
  from unittest.mock import patch
  args=self._decisions_argv();err=io.StringIO()
  with patch.object(authority,'gates',side_effect=AssertionError('NO_AUTHORITY_BEFORE_PARSE')),patch.object(runtime.Integration,'owner',side_effect=AssertionError('NO_ACTOR_BEFORE_PARSE')),patch.object(subprocess,'Popen',side_effect=AssertionError('NO_SUBPROCESS_BEFORE_PARSE')):
   with contextlib.redirect_stderr(err),self.assertRaises(SystemExit)as caught:runtime.execute(self._held(),args)
  self.assertEqual(caught.exception.code,2);self.assertIn('required: --dependency-incoming',err.getvalue())
  incoming=Path('/tmp/source-only-updater-workspace/latest607-dependency-incoming');full=args+['--dependency-incoming',str(incoming)];selected,_=runtime.extras(full,require_dependency=True);self.assertEqual(selected.dependency_incoming,incoming)
  class SourceGateReached(Exception):pass
  with patch.object(authority,'gates',side_effect=SourceGateReached('SOURCE_FIXTURE_NOT_GATE_AUTHORITY')),patch.object(runtime.Integration,'owner',side_effect=AssertionError('NO_ACTOR')):
   with self.assertRaises(SourceGateReached):runtime.execute(self._held(),full)


 def _materializer_policy_fixture(self):
  import ast,types,runtime
  from unittest.mock import patch
  held=self._held();folder=held/'scripts/ci/expanded604-apps6-public-pairs'
  composition=json.loads(C.read(folder/'input-policy.json'))
  installer=json.loads(C.read(held/'scripts/ci/expanded604-apps6-public-pair-installer/input-policy.json'))
  self.assertNotEqual(composition,installer)
  class SourceBoundaryReached(Exception):pass
  def boundary(*args):raise SourceBoundaryReached('SOURCE_ONLY_ORIGINAL_BOUND_INPUTS_BOUNDARY')
  contract=types.SimpleNamespace(policy=lambda:composition,need=C.need,bound_inputs=boundary)
  source=C.read(folder/'materializer.py').decode();nodes=ast.parse(source).body
  selected=ast.Module(body=[n for n in nodes if isinstance(n,ast.FunctionDef)and n.name in('accepted','prepare')],type_ignores=[])
  namespace=dict(C=contract,Path=Path,shutil=__import__('shutil'),sys=sys)
  exec(compile(selected,'<genuine604-materializer-source-only>','exec'),namespace)
  materializer=types.SimpleNamespace(prepare=namespace['prepare'],accepted=namespace['accepted'])
  return composition,installer,materializer,SourceBoundaryReached
 def test_real_materializer_guard_rejects_installer_policy_before_input_or_actor(self):
  import subprocess
  from unittest.mock import patch
  composition,installer,materializer,reached=self._materializer_policy_fixture()
  with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTOR')):
   with self.assertRaisesRegex(ValueError,'complete current Root604 input binding required'):
    materializer.accepted(*([None]*8),installer,None,None)
   with self.assertRaises(reached):materializer.accepted(*([None]*8),composition,None,None)
 def test_actual_runtime_materializer_passes_composition_policy_to_original(self):
  import runtime,types,subprocess
  from unittest.mock import patch
  composition,installer,materializer,reached=self._materializer_policy_fixture()
  api=runtime.Integration.__new__(runtime.Integration)
  api.args=types.SimpleNamespace(installer_source=self._held(),apps6_source=Path('/tmp/source-only-apps6'),apps6_authority_source=Path('/tmp/source-only-apps6-authority'))
  with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTOR')):
   wrapper=api.materializer(None,materializer,composition)
   with self.assertRaises(reached):wrapper.prepare(Path('/tmp/source-only-ready'),Path('/tmp/source-only-producer'),*([Path('/tmp/source-only-operand')]*10))
   wrong=api.materializer(None,materializer,installer)
   with self.assertRaisesRegex(ValueError,'complete current Root604 input binding required'):
    wrong.prepare(Path('/tmp/source-only-ready'),Path('/tmp/source-only-producer'),*([Path('/tmp/source-only-operand')]*10))
 def test_actual_owner_input_closure_keeps_installer_gate_policy_separate(self):
  import ast,runtime,types,subprocess
  from unittest.mock import patch
  composition,installer,materializer,reached=self._materializer_policy_fixture()
  source=C.read(C.HERE/'runtime.py').decode();owner=next(n for n in ast.walk(ast.parse(source))if isinstance(n,ast.FunctionDef)and n.name=='owner')
  node=next(n for n in owner.body if isinstance(n,ast.FunctionDef)and n.name=='inputs')
  fixture=types.SimpleNamespace(COMPOSITION=types.SimpleNamespace(policy=lambda:composition),policy=lambda:installer)
  oldgate=types.SimpleNamespace(inputs=lambda *args:(None,None,None,'DECISIONS_DATA','SUMMARY_DATA'),installer=lambda *args:(fixture,materializer,installer))
  api=runtime.Integration.__new__(runtime.Integration);api.inputs=lambda:None
  namespace=dict(api=api,oldgate=oldgate,contract=None,types=types,cache=types.SimpleNamespace(api=lambda value:value))
  exec(compile(ast.Module(body=[node],type_ignores=[]),'<genuine-owner-inputs-source-only>','exec'),namespace)
  args=types.SimpleNamespace(installer_source=self._held(),apps6_source=Path('/tmp/source-only-apps6'),apps6_authority_source=Path('/tmp/source-only-authority'))
  with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTOR')):
   result=namespace['inputs'](args,{})
   self.assertIs(result[2],installer);self.assertEqual(result[3:],('DECISIONS_DATA','SUMMARY_DATA'))
   with self.assertRaises(reached):result[1].prepare(Path('/tmp/source-only-ready'),Path('/tmp/source-only-producer'),*([Path('/tmp/source-only-operand')]*10))

 def _descriptor_import(self,case,mode):
  import subprocess,tempfile,shutil
  root=C.ROOT/'cases'/case
  with tempfile.TemporaryDirectory(prefix='updater-descriptor-source-')as td:
   target=Path(td)/'code';shutil.copytree(root,target);copier=target/'scripts/update/aux_copy.py';roots=target/'scripts/update/full_root.py'
   if mode in('stale','old604'):
    before=json.loads(C.read(C.HERE/'parent355.json'))['descriptor_source_binding']['before_bodies']['cases/'+case+'/scripts/update/aux_copy.py'];copier.write_text(before)
   if mode=='old604':
    raw=roots.read_bytes();self.assertEqual(raw.count(b'max_packages: int = 607'),1);roots.write_bytes(raw.replace(b'max_packages: int = 607',b'max_packages: int = 604',1))
   if mode=='foreign':roots.write_bytes(roots.read_bytes()+b'\n')
   if mode=='wrongcount':roots.write_bytes(roots.read_bytes().replace(b'max_packages: int = 607',b'max_packages: int = 608',1))
   code="import importlib.util,sys;from pathlib import Path;p=Path(sys.argv[1]);sys.path.insert(0,str(p.parent));s=importlib.util.spec_from_file_location('root_upgrade_copy',p);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m);assert m.roots.Limits.__dataclass_fields__['max_packages'].default==int(sys.argv[2]);assert m._DESCRIPTOR_PINS['full_root']==(35970,'cece1c597b2e2eb98b0e3087cc7e7c148b54332f8a1c4f18e04e4552a71fb51d');print('PASS_TRUSTED_SOURCE_IMPORT_NO_ACTORS')"
   row=subprocess.run([sys.executable,'-I','-B','-Werror','-c',code,str(copier),'604'if mode=='old604'else'607'],capture_output=True,timeout=30)
   if mode in('current','old604'):self.assertEqual(row.returncode,0,row.stderr.decode());self.assertEqual(row.stdout,b'PASS_TRUSTED_SOURCE_IMPORT_NO_ACTORS\n');self.assertFalse(row.stderr)
   else:self.assertNotEqual(row.returncode,0);self.assertIn(b'aux-checkpoint-whole updater descriptor source: full_root',row.stderr)
 def test_real_worker_aux_copy_import_all_three_current_cases(self):
  for case in C.CASES:
   with self.subTest(case=case):self._descriptor_import(case,'current')
 def test_exact_parent_stale_descriptor_reproduces_qualified_refusal(self):
  self._descriptor_import('normal','stale')
 def test_original604_descriptor_remains_valid_source_control(self):
  self._descriptor_import('normal','old604')
 def test_whole_descriptor_seal_rejects_foreign_body_and_wrong_count(self):
  for mode in('foreign','wrongcount'):
   with self.subTest(mode=mode):self._descriptor_import('normal',mode)

 def _cleanup_fixture(self,run):
  import os,tempfile,shutil,types,contextlib
  import runtime
  self.assertEqual(os.getuid(),os.geteuid());self.assertGreater(os.geteuid(),0)
  output=Path(tempfile.mkdtemp(prefix='updater-owned-cleanup-'));producer_output=output.with_name(output.name+'-producer');producer_output.mkdir(mode=0o700);(producer_output/'private').mkdir(mode=0o700);(producer_output/'public').mkdir();cache_root=producer_output/'private/latest607-base604';cache_root.mkdir(mode=0o700)
  shared=Path(tempfile.mkdtemp(prefix='updater-borrowed-cache-'));sentinel=shared/'opus-1.6.1-1-aarch64.pkg.tar.xz.sig';sentinel.write_bytes(b'BORROWED_SOURCE_FIXTURE');sentinel.chmod(0o444);shared.chmod(0o555)
  owner=dict(schema_version=1,purpose='expanded604-apps6-public-pair-updater',token='a'*32,output=str(output),producer=str(producer_output),case='normal');(output/'owner.json').write_bytes(C.enc(owner));powner=dict(schema_version=1,token='b'*32,images_preexisting=[],core_image='sha256:'+'c'*64,preparation_source='/SOURCE_FIXTURE_NOT_NATIVE');(producer_output/'producer-owner.json').write_bytes(C.enc(powner))
  for name in('packages','keys'):
   p=cache_root/name;p.mkdir(mode=0o700);(p/sentinel.name).write_bytes(b'OWNED_SOURCE_FIXTURE');(p/sentinel.name).chmod(0o444);p.chmod(0o555)
  producer=C.load('_cleanup_source_fixture_'+str(id(output)),self._held()/'scripts/ci/full-composition-installer-vm/producer.py');api=runtime.Integration.__new__(runtime.Integration);before=(C.rows(shared),shared.stat().st_mode,sentinel.stat().st_mode)
  try:run(api,producer,producer_output,output,owner,cache_root,shared,powner);self.assertEqual((C.rows(shared),shared.stat().st_mode,sentinel.stat().st_mode),before)
  finally:
   for root in(producer_output,output,shared):
    if root.exists():
     for path in root.rglob('*'):
      if path.is_dir()and not path.is_symlink():path.chmod(0o700)
     root.chmod(0o700);shutil.rmtree(root)
 def test_actual_nonroot0555_failure_then_original_cleanup_with_narrow_fix(self):
  import subprocess
  from unittest.mock import patch
  def run(api,producer,p,o,owner,cache,shared,powner):
   import os
   fd=os.open(cache/'packages',os.O_RDONLY|os.O_DIRECTORY)
   try:
    with self.assertRaises(PermissionError)as exact:os.unlink('opus-1.6.1-1-aarch64.pkg.tar.xz.sig',dir_fd=fd)
    self.assertEqual(exact.exception.filename,'opus-1.6.1-1-aarch64.pkg.tar.xz.sig')
   finally:os.close(fd)
   with patch.object(subprocess,'run',side_effect=AssertionError('NO_GPG_DOCKER_OR_PACKAGE_ACTORS')):
    with self.assertRaises(PermissionError)as caught:producer.cleanup(p)
    self.assertEqual(caught.exception.errno,__import__('errno').EACCES);self.assertTrue((cache/'packages').exists());r=api.cleanup_producer(producer,p,o,owner)
   self.assertEqual(r['status'],'PASS');self.assertFalse((p/'private').exists());self.assertEqual(r['source_cache'],'BORROWED-NOT-REMOVED');self.assertEqual(r['vm_cleanup'],'NOT OWNED')
  self._cleanup_fixture(run)
 def test_cleanup_private_alias_refuses_before_any_permission_change(self):
  import shutil,os
  from unittest.mock import patch
  def run(api,producer,p,o,owner,cache,shared,powner):
   old=cache/'keys';old.chmod(0o700);shutil.rmtree(old);old.symlink_to(shared,target_is_directory=True)
   with patch.object(os,'fchmod',side_effect=AssertionError('NO_CHMOD_BEFORE_COMPLETE_PREFLIGHT')):
    with self.assertRaisesRegex(ValueError,'canonical ordinary'):api.cleanup_producer(producer,p,o,owner)
   self.assertEqual((cache/'packages').stat().st_mode&0o777,0o555);old.unlink()
  self._cleanup_fixture(run)
 def test_cleanup_original_producer_owner_refuses_before_callback(self):
  import os
  from unittest.mock import patch
  def run(api,producer,p,o,owner,cache,shared,powner):
   powner['token']='foreign';(p/'producer-owner.json').write_bytes(C.enc(powner))
   with patch.object(os,'fchmod',side_effect=AssertionError('NO_CHMOD_BEFORE_ORIGINAL_GUARDS')):
    with self.assertRaisesRegex(ValueError,'producer ownership receipt'):api.cleanup_producer(producer,p,o,owner)
   self.assertTrue((cache/'packages').exists())
  self._cleanup_fixture(run)
 def test_cleanup_outer_binding_drift_and_writable_mode_refuse(self):
  import os
  from unittest.mock import patch
  def run(api,producer,p,o,owner,cache,shared,powner):
   wrong=dict(owner,token='d'*32)
   with patch.object(os,'fchmod',side_effect=AssertionError('NO_UNSEAL_ON_OWNER_DRIFT')):
    with self.assertRaisesRegex(ValueError,'outer-to-producer'):api.cleanup_producer(producer,p,o,wrong)
   (cache/'keys').chmod(0o777)
   with patch.object(os,'fchmod',side_effect=AssertionError('NO_UNSEAL_ON_FOREIGN_MODE')):
    with self.assertRaisesRegex(ValueError,'original sealed or partial'):api.cleanup_producer(producer,p,o,owner)
   self.assertEqual((cache/'packages').stat().st_mode&0o777,0o555)
  self._cleanup_fixture(run)
 def test_cleanup_no_intermediate_and_partial_export_keep_original_contract(self):
  import shutil
  def run(api,producer,p,o,owner,cache,shared,powner):
   for name in('packages','keys'):(cache/name).chmod(0o700)
   shutil.rmtree(cache/'keys');r=api.cleanup_producer(producer,p,o,owner);self.assertEqual(r['status'],'PASS');self.assertFalse((p/'private').exists())
  self._cleanup_fixture(run)
  def absent(api,producer,p,o,owner,cache,shared,powner):
   for name in('packages','keys'):(cache/name).chmod(0o700)
   shutil.rmtree(cache);self.assertEqual(api.cleanup_producer(producer,p,o,owner)['status'],'PASS')
  self._cleanup_fixture(absent)
 def test_actual_owner_cleanup_call_and_original_method_foreign_source_refusal(self):
  import runtime,types,tempfile
  held=self._held();source=runtime.derive_owner(C.read(held/runtime.OLD/'run.py'));self.assertEqual(source.count('receipt=Y.cleanup_producer(producer,producer_output,output,owner);'),1);self.assertNotIn('receipt=producer.cleanup(producer_output);',source)
  with tempfile.TemporaryDirectory(prefix='foreign-producer-source-')as td:
   path=Path(td)/'producer.py';path.write_bytes(C.read(held/'scripts/ci/full-composition-installer-vm/producer.py')+b'\n');foreign=types.SimpleNamespace(__file__=str(path));api=runtime.Integration.__new__(runtime.Integration)
   with self.assertRaisesRegex(ValueError,'whole original producer cleanup source'):api.cleanup_producer(foreign,None,None,None)

if __name__=='__main__':
 suite=unittest.defaultTestLoader.loadTestsFromTestCase(Controls);C.need(suite.countTestCases()==32,'nonzero exact32 source groups');r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not r.wasSuccessful())
