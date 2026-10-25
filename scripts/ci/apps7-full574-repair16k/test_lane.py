# SPDX-License-Identifier: MIT
"""Finite Apps7 source/VM compatibility controls; no accepted actual fixture."""
import ast,importlib.util,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
sys.path.insert(0,str(HERE));import contract as C,adapter as A,prepare as P,vm
class Controls(unittest.TestCase):
 def test_complete184_source_and_native157_manifest(self):
  self.assertEqual(len(C.check_source(ROOT)),186);native=C.load('source_checks',ROOT/C.NATIVE/'contract.py');p=native.source(ROOT)
  self.assertEqual(p['packet_source'],C.PACKET);self.assertEqual(native.VERSIONS['cachy-asahi-apps'],'0.1.0-7');self.assertEqual(native.VERSIONS['cachy-asahi-repository-runtime'],'0.1.0-1')
  self.assertEqual(C.row(ROOT/C.NATIVE/'source-manifest.json')['sha256'],C.NATIVE_MANIFEST)
 def test_null_both_cases_refuse_before_any_source_or_actor(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('no actor/Git/API')):
   for case in C.CASES:
    with self.assertRaisesRegex(ValueError,'UNBOUND16K'):C.gate(ROOT,case)
 def test_genuine_whole_source_emission_defaults_all_authority_null(self):
  with tempfile.TemporaryDirectory()as td,patch.object(subprocess,'Popen',side_effect=AssertionError('no actor')):
   out=Path(td)/'bridge';P.emit(ROOT,out,ROOT)
   for n,r in C.decode(C.read(out/C.LANE/'source-manifest.json'))['files'].items():self.assertEqual(C.row(out/n),r)
   pins=C.decode(C.read(out/C.LANE/'source-pins.json'));self.assertTrue(all(pins[k]is None for k in('native_case_decisions','kernel_authority','actual_source','actual_ref')));self.assertTrue(all(v is None for v in pins['actual_runs'].values()))
 def test_missing_changed_alias_native_axis_refuses_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);empty=root/'empty';empty.mkdir();out=root/'out'
   with self.assertRaises((FileNotFoundError,ValueError)):P.emit(ROOT,out,empty)
   self.assertFalse(out.exists());alias=root/'alias';alias.symlink_to(ROOT,target_is_directory=True)
   with self.assertRaisesRegex(ValueError,'ordinary explicit'):P.emit(ROOT,out,alias)
   self.assertFalse(out.exists())
 def test_execution_renders_apps7_wrapper_only_original_helpers_held(self):
  native=C.decode(C.read(ROOT/C.NATIVE/'source-manifest.json'));before={n:C.row(ROOT/n)for n in native['files']}
  with tempfile.TemporaryDirectory()as td,patch.object(subprocess,'Popen',side_effect=AssertionError('no actor')):
   out=Path(td)/'execution';receipt=A.execution(ROOT,out,native);selected=C.NATIVE+'/transaction.py'
   self.assertEqual(receipt['changed'],[selected]);self.assertIn('0.1.0-7',(out/C.NATIVE/'derive.py').read_text());self.assertEqual(C.read(out/'scripts/apps/transaction.py'),C.read(ROOT/'scripts/apps/transaction.py'))
   text=(out/selected).read_text();self.assertIn(A.ENV_AFTER,text);self.assertNotIn(A.ENV_BEFORE,text);self.assertIn("__file__ = str(next",text);self.assertIn(C.NATIVE+"/closure.py",text)
   spec=importlib.util.spec_from_file_location('_tests_native_apps7_derivative',ROOT/C.NATIVE/'derive.py');d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d);rendered,_=d.derive(ROOT,'transaction');self.assertEqual(receipt['derivation']['native_rendered'],A.pin(rendered));self.assertEqual(A.functions(rendered).keys(),A.functions(A.backend(rendered)).keys());self.assertEqual([n for n in A.functions(rendered)if A.functions(rendered)[n]!=A.functions(A.backend(rendered))[n]],['environment_guard'])
  self.assertEqual(before,{n:C.row(ROOT/n)for n in before})
 def test_fresh_execution_import_resolves_apps7_helpers_and_600610_policy(self):
  native=C.decode(C.read(ROOT/C.NATIVE/'source-manifest.json'))
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'execution';A.execution(ROOT,out,native)
   program="import importlib.util,sys;from pathlib import Path;p=Path(sys.argv[1]);s=importlib.util.spec_from_file_location('actual_apps7_vm_backend',p);T=importlib.util.module_from_spec(s);sys.modules[s.name]=T;s.loader.exec_module(T);C=T.load('actual_apps7_vm_closure',T.ROOT/'scripts/ci/apps7-full574-repair-native/closure.py');assert C.VERSIONS['cachy-asahi-apps']=='0.1.0-7';assert C.VERSIONS['cachy-asahi-repository-runtime']=='0.1.0-1';assert C.EXECUTION_BUDGET==dict(backend_seconds=600,caller_seconds=610);assert T.SECONDS==300;assert len(C.current_payloads())==4;assert T.__file__.endswith('/scripts/apps/transaction.py');print('PASS_GENUINE_RENDERED_APPS7_IMPORT_AND_HELPER_LAYOUT')"
   result=subprocess.run([sys.executable,'-B','-c',program,str(out/C.NATIVE/'transaction.py')],capture_output=True,timeout=30);self.assertEqual(result.returncode,0,result.stderr.decode());self.assertIn(b'PASS_GENUINE',result.stdout)
 def test_whole_native_job_actor_routes_exact4320_without_changing_caps(self):
  import job
  native=C.load('original_native_job_contract',ROOT/C.NATIVE/'contract.py');J=job.native_job(ROOT,native);parts=J.derived(C.read(ROOT/'scripts/ci/apps-full574-native/job.py').decode());actor=job.actor_body(parts['actor']);ast.parse(actor)
  self.assertIn('4320 if role==',actor);self.assertIn('_repair16k_dispatch',actor);self.assertIn("'--cap-drop=ALL'",actor);self.assertIn("'CHOWN','DAC_OVERRIDE','FOWNER','FSETID'",actor);self.assertIn("argv+=['--cap-add=SETFCAP']",actor)
 def test_execution_rejects_wrong_original_hash_and_duplicate_environment(self):
  manifest=C.decode(C.read(ROOT/C.NATIVE/'source-manifest.json'));manifest['files'][C.NATIVE+'/transaction.py']['sha256']='0'*64
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'execution'
   with self.assertRaisesRegex(ValueError,'original source pin differs'):A.execution(ROOT,out,manifest)
   self.assertFalse(out.exists())
  with self.assertRaisesRegex(ValueError,'one source-bound'):A.backend((A.ENV_BEFORE+'\n'+A.ENV_BEFORE).encode())
 def test_apps7_lifecycle_four_commits_refusals_runtime1_paths(self):
  raw=C.read(ROOT/C.NATIVE/'lifecycle.py');derived=A.lifecycle(raw);ast.parse(derived);text=derived.decode()
  self.assertIn('/execution/'+C.NATIVE+'/inspection.py',text);self.assertIn('/execution/'+C.NATIVE+'/transaction.py',text);self.assertIn("{'cachy-asahi-apps':'0.1.0-7'}",text);self.assertIn("rows.get('cachy-asahi-repository-runtime')=='0.1.0-1'",text)
  old=A.functions(raw);new=A.functions(derived);self.assertEqual([n for n in old if old[n]!=new[n]],['inspected','main']);self.assertTrue({'damage','restore','repaired','planned','observed'}<=old.keys())
  for n in ('damage','restore','repaired','planned','observed'):self.assertEqual(old[n],new[n])
 def test_nomops_qemu_full_argv_and_16k_guard_held(self):
  argv=vm.qemu(Path('/Image'),Path('/boot'),Path('/data'),123);append=argv[argv.index('-append')+1].split();self.assertIn('arm64.nomops',append);self.assertIn('caa_apps574_repair16k=1',append);self.assertIn('caa_clock_ns=123',append)
  for n in ('-nodefaults','-no-reboot','-nic','-monitor'):self.assertIn(n,argv)
  text=C.read(HERE/'guest.py').decode();self.assertIn("os.sysconf('SC_PAGE_SIZE')==16384",text);self.assertIn('source_capabilities_sha256',text);self.assertIn("'EXACT_SOURCE_MAP_PRESERVED'",C.read(ROOT/C.NATIVE/'lifecycle.py').decode())
 def test_native4320_slot_is_not_vm3000_or_product600610(self):
  text=C.read(HERE/'vm.py').decode();self.assertIn('seconds==4320',text);self.assertIn("clock['owner_deadline_monotonic_ns']/10**9",text);self.assertIn("shared_lifecycle_seconds=clock['selected_seconds']",text)
  disk=C.read(HERE/'disk.py').decode();self.assertIn('dict(backend_seconds=600,caller_seconds=610)',disk);self.assertIn("name=C.NATIVE+'/closure.py'",disk)
  self.assertIn("'--full574-policy'",disk);self.assertIn('group_absence_verified',disk)
 def test_no_case_acceptance_substitution_constants(self):
  self.assertEqual(C.NATIVE_SOURCE,'c89868439988f99d4179d208d1198f6f9c94d5d5');self.assertEqual(C.PACKET,'54352850a57a7e34e75c3a021fa20525eee59bf6');text=C.read(HERE/'contract.py').decode();self.assertIn('qualified.validate(records)',text);Q=C.load('qualification_constants',HERE/'native_qualification.py');self.assertEqual(Q.SOURCE,C.NATIVE_SOURCE);self.assertEqual(Q.VERSIONS['cachy-asahi-apps'],'0.1.0-7');self.assertEqual(Q.default_decisions(),{case:None for case in C.CASES})
class BackendFailureData(unittest.TestCase):
 """Inert returned-capture controls, never an accepted backend/native fixture."""
 def setUp(self):
  block=patch.object(subprocess,'Popen',side_effect=AssertionError('no actor/network/Git'));block.start();self.addCleanup(block.stop)
  self.disk=C.load('failure_data_disk',HERE/'disk.py')
 def capture(self,error_reason='root observation deadline'):
  out=b'';rows=[]
  for seq,stage,event in((1,'complete-capability-map','BEGIN'),(2,'capability-scan','BEGIN'),(3,'capability-scan','FAIL'),(4,'complete-capability-map','FAIL')):
   row=dict(schema_version=1,seq=seq,stage=stage,event=event,monotonic_ns=1000+seq)
   if event=='FAIL':row.update(error_type='ValueError',error_reason=error_reason)
   rows.append(b'APPS574_PHASE '+json.dumps(row,separators=(',',':')).encode()+b'\n')
  err=b'non-record inert capture\n'*450+b''.join(rows)
  record=dict(argv=['/usr/bin/python3','-I','-B','/source/scripts/ci/apps7-full574-repair16k/native_prepare.py','prepare-copy'],exit_code=-15,seconds=610.01,time_limit=610,output_limit=1024**2,group_absence_verified=True,stdout_bytes=len(out),stdout_sha256=C.sha(out),stderr_bytes=len(err),stderr_sha256=C.sha(err))
  return record,out,err,ValueError('command-time-limit')
 def test_original_failures_and_suffix_survive_prefix_truncation(self):
  row,out,err,error=self.capture();v=self.disk.backend_failure_data(row,out,err,error)
  self.assertGreater(len(err),1024);self.assertNotIn(b'root observation deadline',err[:1024]);self.assertEqual(v['phase_failures']['count'],2);self.assertEqual([r['error_reason']for r in v['phase_failures']['first']],['root observation deadline']*2)
  self.assertEqual(v['stderr'],dict(bytes=len(err),sha256=C.sha(err)));tail=v['stderr_suffix'];import base64
  self.assertEqual(base64.b64decode(tail['base64'],validate=True),err[-2048:]);self.assertEqual(tail['sha256'],C.sha(err[-2048:]));self.assertTrue(tail['truncated']);self.assertLessEqual(len(C.encoded(v)),8192);self.assertFalse(v['acceptance_authority']);self.assertFalse(v['cleanup_authority'])
 def test_tampered_stream_limits_or_untrusted_phase_fields_refuse_or_mark_invalid(self):
  row,out,err,error=self.capture()
  for change in(dict(stderr_bytes=len(err)+1),dict(stderr_sha256='0'*64),dict(time_limit=2411),dict(output_limit=2*1024**2)):
   with self.subTest(change=change),self.assertRaises(ValueError):self.disk.backend_failure_data(dict(row,**change),out,err,error)
  for reason in('/private/untrusted/path','aux-checkpoint-'+('x'*97)):
   row,out,err,error=self.capture(reason);v=self.disk.backend_failure_data(row,out,err,error);self.assertEqual(v['phase_failures']['status'],'INVALID_PHASE_FAILURE_FIELDS');self.assertEqual(v['phase_failures']['first'],[])
  broken=err.replace(b'"seq":4',b'"seq":6');row=dict(row,stderr_bytes=len(broken),stderr_sha256=C.sha(broken));v=self.disk.backend_failure_data(row,out,broken,error);self.assertEqual(v['phase_failures']['status'],'INVALID_PHASE_RECORDS')
 def test_only_failed_original_prepare_route_is_projected(self):
  row,out,err,error=self.capture();self.assertIsNone(self.disk.backend_failure_data(dict(row,exit_code=0),out,err,None));self.assertIsNone(self.disk.backend_failure_data(dict(row,argv=['/usr/bin/mkfs.ext4']),out,err,error))
  row,out,err,error=self.capture('OTHER_REDACTED');v=self.disk.backend_failure_data(row,out,err,None);self.assertIsNone(v['supervisor_error']);self.assertEqual(v['phase_failures']['first'][0]['error_reason'],'OTHER_REDACTED')
 def test_actual_command_retains_returned_failure_before_unchanged_guard(self):
  row,out,err,error=self.capture();D=self.disk;original_path=Path;calls=[]
  with tempfile.TemporaryDirectory()as td:
   receipt=original_path(td)/'repair16k-media-commands.json'
   def path(value):return receipt if str(value)=='/out/repair16k-media-commands.json'else original_path(value)
   def run(*args):calls.append(args);return row,out,err,error
   runtime=type('InertReturnedCapture',(),{'run_command':staticmethod(run)})
   s=dict(deadline_monotonic=__import__('time').monotonic()+3000,env={'OWNER_TOKEN':'inert-only'},uid=os.getuid(),gid=os.getgid())
   with patch.object(C,'load',return_value=runtime),patch.object(D,'Path',side_effect=path),patch.object(D.os,'chown'):
    with self.assertRaisesRegex(ValueError,'bounded owned media command/group retirement'):D.command(s,row['argv'],610)
   retained=C.decode(receipt.read_bytes());self.assertEqual(len(calls),1);self.assertEqual(calls[0][-2:],(610,1024**2));self.assertEqual(retained[0]['record'],row);self.assertEqual(retained[0]['phase_summary'],D.phase_summary(err));self.assertEqual(retained[0]['backend_failure_data'],D.complete_failure_data(D.backend_failure_data(row,out,err,error),err));self.assertLessEqual(receipt.stat().st_size,2*1024**2)
 def test_diagnostic_loss_does_not_replace_original_failure(self):
  row,out,err,error=self.capture();D=self.disk;original_path=Path
  with tempfile.TemporaryDirectory()as td:
   receipt=original_path(td)/'repair16k-media-commands.json';runtime=type('InertReturnedCapture',(),{'run_command':staticmethod(lambda *args:(row,out,err,error))})
   s=dict(deadline_monotonic=__import__('time').monotonic()+3000,env={'OWNER_TOKEN':'inert-only'},uid=os.getuid(),gid=os.getgid())
   with patch.object(C,'load',return_value=runtime),patch.object(D,'Path',side_effect=lambda value:receipt if str(value)=='/out/repair16k-media-commands.json'else original_path(value)),patch.object(D.os,'chown'),patch.object(D,'backend_failure_data',side_effect=ValueError('inert diagnostic loss')):
    with self.assertRaisesRegex(ValueError,'bounded owned media command/group retirement'):D.command(s,row['argv'],610)
   self.assertEqual(set(C.decode(receipt.read_bytes())[0]),{'record','error','previews','phase_summary'})
 def test_success_command_preserves_tuple_and_old_receipt_shape(self):
  row,out,err,error=self.capture();row=dict(row,exit_code=0,seconds=0.1);D=self.disk;original_path=Path
  with tempfile.TemporaryDirectory()as td:
   receipt=original_path(td)/'repair16k-media-commands.json';runtime=type('InertReturnedCapture',(),{'run_command':staticmethod(lambda *args:(row,out,err,None))})
   s=dict(deadline_monotonic=__import__('time').monotonic()+3000,env={'OWNER_TOKEN':'inert-only'},uid=os.getuid(),gid=os.getgid())
   with patch.object(C,'load',return_value=runtime),patch.object(D,'Path',side_effect=lambda value:receipt if str(value)=='/out/repair16k-media-commands.json'else original_path(value)),patch.object(D.os,'chown'):
    self.assertEqual(D.command(s,row['argv'],610),(row,out,err))
   self.assertEqual(set(C.decode(receipt.read_bytes())[0]),{'record','error','previews','phase_summary'})


class InventoryObserverSource(unittest.TestCase):
 def test_actual_rendered_app_source_gate_then_explicit_inventory_derivative(self):
  import types
  rendered,proof=A.rendered_backend(ROOT)
  m=types.ModuleType('_tests_vm_inventory_backend');m.__file__=str(ROOT/C.NATIVE/'transaction.py');sys.modules[m.__name__]=m
  with patch.object(subprocess,'Popen',side_effect=AssertionError('no actor')),patch.object(subprocess,'run',side_effect=AssertionError('no actor')):
   exec(compile(rendered,m.__file__,'exec'),m.__dict__)
   source=ROOT/'packages/tools/cachy-asahi-apps7';args=types.SimpleNamespace(apps_source=source,apps_provenance_sha256=C.sha(C.read(source/'source-provenance.json')),repository_source=ROOT)
   app,client,release=m.app_source(args);reader=app.inventory_reader()
   self.assertTrue(reader.scan.__code__.co_filename.endswith(':source-owned-pure-checks'))
   self.assertEqual(proof['inventory_source_before'],'68f9b0bc6bd5c494ebfc10bdc1e243c014d7fa8e56b1386491b75cdb9ee2e3df')
   self.assertEqual(proof['inventory_source_after'],'60b4e5be36b727bdcd514667d5808903759e8f673f5e09d05e442d8ddf0610cf')
   args.apps_provenance_sha256='0'*64
   with self.assertRaises(ValueError):m.app_source(args)
 def test_inventory_whole_source_and_all_canonical_parent_checks_held(self):
  import types
  scope=types.ModuleType('_source_inventory_test');exec(A.INVENTORY_OBSERVER,scope.__dict__)
  raw=C.read(ROOT/'packages/tools/cachy-asahi-apps7/inventory.py')
  self.assertEqual(scope.restore(scope.derive(raw)),raw)
  with self.assertRaises(ValueError):scope.derive(raw+b'\n')
  from pathlib import PurePosixPath
  for path in ('a','a/b','a/b/c','usr/share/fixture/path','unicode-ä/child'):
   old=[p.as_posix()for p in PurePosixPath(path).parents if p.as_posix()!='.'];new=[];parent=path.rpartition('/')[0]
   while parent:new.append(parent);parent=parent.rpartition('/')[0]
   self.assertEqual(old,new)


class PureDatabaseChecks(unittest.TestCase):
 def modules(self):
  import types
  scope=types.ModuleType('_source_pure_checks');exec(A.INVENTORY_OBSERVER,scope.__dict__);raw=C.read(ROOT/'packages/tools/cachy-asahi-apps7/inventory.py');before=types.ModuleType('_before_inventory');after=types.ModuleType('_after_inventory');exec(raw,before.__dict__);exec(scope.derive(raw),after.__dict__);return scope,raw,before,after
 def test_canonical_component_and_every_control_character_equivalence(self):
  scope,raw,before,after=self.modules()
  def outcome(fn):
   try:return ('PASS',fn())
   except Exception as e:return(type(e).__name__,str(e))
  for value in ('a','a/','a/b','a//b','/a','a/./b','a/../b','a\\b','ü/文件','a'*512,'a'*513)+tuple('pre'+chr(i)+'post'for i in range(256)):
   self.assertEqual(outcome(lambda:before.relative(value)),outcome(lambda:after.relative(value)))
 def test_raw_sections_error_order_duplicate_relations_and_CR_refusal(self):
  scope,raw,before,after=self.modules()
  def outcome(fn):
   try:return ('PASS',fn())
   except Exception as e:return(type(e).__name__,str(e))
  for value in (b'%FILES%\na\na\n',b'%DEPENDS%\na\nb\na\n',b'%FILES%\na\r\n',b'%FILES%\na',b'%UNKNOWN%\na\n',b'\xff\n'):
   self.assertEqual(outcome(lambda:before.sections(value,{'FILES','DEPENDS'})),outcome(lambda:after.sections(value,{'FILES','DEPENDS'})))
 def test_all_current_filesystem_scan_and_30s_collect_bodies_byte_held(self):
  scope,raw,before,after=self.modules();current=raw.decode().replace(scope.BEFORE,scope.AFTER);a=A.functions(current.encode());b=A.functions(scope.derive(raw));self.assertEqual([n for n in a if a[n]!=b[n]],['sections','relative']);self.assertEqual(scope.restore(scope.derive(raw)),raw);self.assertIn('deadline=time.monotonic()+30',scope.derive(raw).decode());self.assertIn('first=scan(dbpath,c,normalize,deadline);second=scan(dbpath,c,normalize,deadline)',scope.derive(raw).decode())

class IndependentPackagePaths(unittest.TestCase):
 def setup_package(self):
  import types
  s=types.ModuleType('_package_paths');exec(A.INVENTORY_OBSERVER,s.__dict__)
  p=ROOT/'packages/tools/cachy-asahi-apps7/apps.py';raw=C.read(p);app=types.ModuleType('_whole_apps_package');app.__file__=str(p);exec(compile(raw,str(p),'exec'),app.__dict__)
  before=app.package;client,release,_=app.helpers(ROOT);s.bind_package(app);return s,raw,before,app.package,release
 def test_exhaustive_component_and_error_equivalence(self):
  import itertools
  s,raw,before,after,r=self.setup_package()
  def outcome(fn,path):
   row=dict(name='probe',version='1-1',arch='aarch64',files=[path],depend=[],provides=[],conflict=[],replaces=[])
   try:return ('PASS',fn(row,r))
   except Exception as e:return(type(e).__name__,str(e))
  parts=('','a','.','..','b','ü','a\\b','x\x00y','x\ny')
  paths=['/'.join(v)for length in range(1,5)for v in itertools.product(parts,repeat=length)]
  paths+=['pre'+chr(i)+'post'for i in range(256)]+['a'*512,'a'*513,'//host/a','a/',1,None]
  for path in paths:self.assertEqual(outcome(before,path),outcome(after,path),repr(path))
 def test_whole_source_inverse_and_all_other_package_predicates(self):
  s,raw,before,after,r=self.setup_package();derived=raw.decode().replace(s.PACKAGE_BEFORE,s.PACKAGE_AFTER)
  self.assertEqual(derived.replace(s.PACKAGE_AFTER,s.PACKAGE_BEFORE).encode(),raw)
  with self.assertRaisesRegex(ValueError,'whole selected Apps7'):s.package_source(raw+b'\n')
  base=dict(name='probe',version='1-1',arch='aarch64',files=['usr/share/a'],depend=[],provides=[],conflict=[],replaces=[])
  def outcome(fn,row):
   try:return ('PASS',fn(row,r))
   except Exception as e:return(type(e).__name__,str(e))
  variants=[{},dict(base),dict(base,files=['a','a']),dict(base,files=['a/../b']),dict(base,depend=['x86_64-only']),dict(base,provides=['foreign-x86=1']),dict(base,repository='lib32-bad'),dict(base,sha256='bad'),dict(base,arch='x86_64'),dict(base,version='bad/1')]
  for row in variants:self.assertEqual(outcome(before,row),outcome(after,row))
 def test_current_inventory_scans_and_deadline_whole_held(self):
  import types
  s,raw,before,after,r=self.setup_package();original=C.read(ROOT/'packages/tools/cachy-asahi-apps7/inventory.py');derived=s.derive(original)
  self.assertEqual(C.sha(derived),'60b4e5be36b727bdcd514667d5808903759e8f673f5e09d05e442d8ddf0610cf')
  self.assertIn(b'first=scan(dbpath,c,normalize,deadline);second=scan(dbpath,c,normalize,deadline)',derived)
  self.assertIn(b'deadline=time.monotonic()+30',derived)


from collections import Counter
import types,time,hashlib
def _fusion_helper():
 value=types.ModuleType('actual_fused_observer_test');exec(A.FUSED_OBSERVER,value.__dict__);return value
def _fusion_closure(name):
 derive=C.load(name+'_derive',ROOT/C.NATIVE/'derive.py')
 with patch.dict(sys.modules,{'derive':derive}):
  for key in('full_root','measure_copy','root_link_selection','root_path','aux_checkpoint','aux_copy','disposable_copy','capacity'):sys.modules.pop(key,None)
  return C.load(name,ROOT/C.NATIVE/'closure.py')
def _fusion_stable(v):
 v=json.loads(json.dumps(v));v['footprint'].pop('filesystem_free_bytes');v['footprint'].pop('filesystem_free_inodes');return v
def _fusion_corpus(r,n=16):
 for i in range(n):
  p=r/('usr/share/pkg%03d/deep/leaf'%i);p.mkdir(parents=True)
  for j in range(32):(p/('file%03d'%j)).write_bytes(hashlib.sha256(('%s/%s'%(i,j)).encode()).digest()*8)
  (p/'alias').symlink_to('file000');os.link(p/'file001',p/'hard')
 (r/'absolute').symlink_to('/usr/share');(r/'usr/bin').mkdir();(r/'usr/bin/ldconfig').write_bytes(b'INERT_NOT_EXECUTED')
class FusedObservationControls(unittest.TestCase):
 def test_real_complete_maps_and_lower_repeated_traversal(self):
  old=_fusion_closure('old_fused_compare');new=_fusion_closure('new_fused_compare');_fusion_helper().bind(new)
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);_fusion_corpus(root);results=[];counts=[]
   for m,candidate in((old,False),(new,True)):
    calls=Counter();original={n:getattr(os,n)for n in('stat','fstat','open','close','read','listxattr','getxattr','scandir','readlink')}
    def traced(n):
     def call(*a,**kw):calls[n]+=1;return original[n](*a,**kw)
     return call
    with __import__('contextlib').ExitStack()as stack:
     for n in original:stack.enter_context(patch.object(os,n,traced(n)))
     limits=m.roots.Limits(time.monotonic()+60)
     if candidate:v=m._fused_observe(root,limits=limits,hardlinks='generic-development-internal');c=m._fused_capabilities(root,v['nodes'],limits)
     else:v=m.roots.observe(root,limits=limits,hardlinks='generic-development-internal');c=m.caps.observe(root,v['nodes'],limits)
     self.assertTrue(v['complete']);results.append((_fusion_stable(v),c))
    counts.append(calls)
   self.assertEqual(results[0],results[1]);self.assertEqual(counts[0]['read'],counts[1]['read']);self.assertEqual(counts[0]['listxattr'],counts[1]['listxattr']);self.assertLess(counts[1]['scandir'],counts[0]['scandir']);self.assertLess(counts[1]['open'],counts[0]['open'])
   with patch.object(new.caps,'observe',wraps=new.caps.observe)as original:
    self.assertEqual(new._fused_capabilities(root,v['nodes'],limits),{});original.assert_called_once_with(root,v['nodes'],limits)
 def test_post_tree_mutation_and_unknown_attrs_refuse(self):
  for operation in('mode','content','inode','unknown','hardlink','directory'):
   m=_fusion_closure('fused_mutation_'+operation);_fusion_helper().bind(m)
   with tempfile.TemporaryDirectory()as td:
    root=Path(td);_fusion_corpus(root,1);limits=m.roots.Limits(time.monotonic()+60);v=m._fused_observe(root,limits=limits,hardlinks='generic-development-internal');self.assertTrue(v['complete']);p=root/'usr/share/pkg000/deep/leaf/file000'
    if operation=='mode':p.chmod(0o600)
    if operation=='content':p.write_bytes(b'x'*p.stat().st_size)
    if operation=='inode':data=p.read_bytes();q=p.with_name('replacement');q.write_bytes(data);q.replace(p)
    if operation=='unknown':os.setxattr(p,'user.no',b'x')
    if operation=='hardlink':os.link(p,p.with_name('foreign'))
    if operation=='directory':(p.parent/'new').write_bytes(b'x')
    with self.assertRaises(ValueError):m._fused_capabilities(root,v['nodes'],limits)
 def test_during_read_mutation_and_deadline_close_descriptors(self):
  m=_fusion_closure('fused_live_mutation');_fusion_helper().bind(m)
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);_fusion_corpus(root,1);p=root/'usr/share/pkg000/deep/leaf/file000';original=os.read;changed=False
   def change(fd,n):
    nonlocal changed
    data=original(fd,n)
    if not changed and os.fstat(fd).st_ino==p.stat().st_ino:
     changed=True;p.write_bytes(b'z'*p.stat().st_size)
    return data
   baseline=len(os.listdir('/proc/self/fd'))
   with patch.object(os,'read',change):v=m._fused_observe(root,limits=m.roots.Limits(time.monotonic()+60),hardlinks='generic-development-internal')
   self.assertTrue(changed);self.assertFalse(v['complete']);self.assertEqual(len(os.listdir('/proc/self/fd')),baseline)
   with self.assertRaisesRegex(ValueError,'root observation deadline'):m._fused_observe(root,limits=m.roots.Limits(time.monotonic()-1),hardlinks='generic-development-internal')
   self.assertEqual(len(os.listdir('/proc/self/fd')),baseline)
 def test_source_inverse_and_original_bodies_held(self):
  S=ROOT
  raw=(S/'scripts/update/full_root.py').read_bytes();out=_fusion_helper().observer_source(raw)
  for before,after in reversed(_fusion_helper().EDITS):out=out.replace(after,before)
  self.assertEqual(out,_fusion_helper().function(raw,'observe',_fusion_helper().ROOT_SHA))
  with self.assertRaises(ValueError):_fusion_helper().observer_source(raw+b'\n')
  m=_fusion_closure('fused_body_conservation');before=m.measure.__code__;restore=m.caps.restore;_fusion_helper().bind(m);self.assertIs(before,m.measure.__code__);self.assertIs(restore,m.caps.restore)
 def test_actual_rendered_backend_loads_fused_closure_only(self):
  native=C.decode(C.read(ROOT/C.NATIVE/'source-manifest.json'))
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'execution';A.execution(ROOT,out,native);module=C.load('actual_rendered_fusion_backend',out/C.NATIVE/'transaction.py')
   closure=module.load('actual_rendered_fusion_closure',out/C.NATIVE/'closure.py');self.assertTrue(hasattr(closure,'_fused_observe'));self.assertTrue(hasattr(closure,'_fused_capabilities'))
   raw,_=C.load('fusion_native_derive',ROOT/C.NATIVE/'derive.py').derive(ROOT,'transaction');base=A.inventory_backend(A.backend(raw));derived=A.fused_backend(base);self.assertEqual([n for n in A.functions(base)if A.functions(base)[n]!=A.functions(derived)[n]],['load'])
   self.assertEqual(C.read(out/'scripts/update/full_root.py'),C.read(ROOT/'scripts/update/full_root.py'));self.assertEqual(C.read(out/'scripts/apps/file_capabilities.py'),C.read(ROOT/'scripts/apps/file_capabilities.py'))


import contextlib
class ScopedAuxCaptureControls(unittest.TestCase):
 def setUp(self):
  self.path=list(sys.path);self.job=sys.modules.get('job');self.addCleanup(self.clean_imports)
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.base=Path(self.tmp.name);self.root=self.base/'tree';(self.root/'usr/lib/deep').mkdir(parents=True)
  for n in('first','second'):(self.root/'usr/lib/deep'/n).write_bytes((n.encode()*300))
  os.link(self.root/'usr/lib/deep/first',self.root/'usr/lib/deep/hard');(self.root/'usr/lib/alias').symlink_to('deep')
  self.m=_fusion_closure('source_scoped_capture')
  self.h=_fusion_helper();self.h.bind(self.m);self.limits=self.m.roots.Limits(time.monotonic()+60);self.report=self.m._fused_observe(self.root,limits=self.limits,hardlinks='generic-development-internal');self.assertTrue(self.report['complete']);self.reader=self.m.aux.Reader(self.root,self.report,self.limits)
 def clean_imports(self):
  sys.path[:]=self.path
  if self.job is None:sys.modules.pop('job',None)
  else:sys.modules['job']=self.job
 def test_repeated_capture_fresh_descriptors_complete_output_and_original_bodies(self):
  old=_fusion_closure('source_scoped_original');other=old.aux.Reader(self.root,self.report,self.limits);counts=[];values=[]
  for reader in(other,self.reader):
   calls=Counter();original={n:getattr(os,n)for n in('open','close','dup','read','stat','fstat','listxattr','getxattr')}
   def wrapper(name):
    def call(*a,**kw):calls[name]+=1;return original[name](*a,**kw)
    return call
   with contextlib.ExitStack()as stack:
    for name in original:stack.enter_context(patch.object(os,name,wrapper(name)))
    values.append(reader.capture('usr/lib/alias/hard'));counts.append(calls)
  self.assertEqual(values[0],values[1]);self.assertEqual(counts[0]['read'],counts[1]['read']);self.assertLess(counts[1]['open'],counts[0]['open'])
  first=self.reader.capture('usr/lib/alias/hard');self.assertEqual(first,self.reader.capture('usr/lib/alias/hard'));self.assertNotIn('literal',self.reader.__dict__)
  self.assertIs(self.m._measure.__wrapped__.__globals__['aux'].Reader,self.m.aux.Reader);self.assertIs(self.m._measure.__wrapped__.__globals__['aux'].checkpoint.__wrapped__,self.m.aux.checkpoint)
  self.assertEqual(self.m.aux.checkpoint.__code__.co_code,old.aux.checkpoint.__code__.co_code)
 def test_same_capture_content_parent_root_ancestor_and_descriptor_reuse_refuse(self):
  # Each subcase gets its own true source observation; mutations never become
  # a baseline or accepted fixture.
  for operation in('content','directory','root','ancestor','reuse'):
   with self.subTest(operation=operation):self.mutate(operation)
 def mutate(self,operation):
  r=self.root;leaf=r/'usr/lib/deep/first';read=os.read;changed=False;seen=[];Lease=self.h.CaptureLease
  class Spy(Lease):
   def __init__(s,*a,**kw):super().__init__(*a,**kw);seen.append(s)
  moved=None
  def change(fd,n):
   nonlocal changed,moved
   data=read(fd,n)
   if not changed and os.fstat(fd).st_ino==leaf.stat().st_ino:
    changed=True
    if operation=='content':leaf.write_bytes(b'z'*leaf.stat().st_size)
    elif operation=='directory':
     moved=r/'usr/lib/moved';(r/'usr/lib/deep').rename(moved);(r/'usr/lib/deep').mkdir()
    elif operation=='root':
     moved=self.base/'movedroot';r.rename(moved);r.mkdir()
    elif operation=='ancestor':
     # Replace a named directory in the absolute source ancestry while retaining
     # the original root inode under the same final name.
     ancestor=r.parent;backup=ancestor.with_name(ancestor.name+'-moved');ancestor.rename(backup);ancestor.mkdir();(backup/'tree').rename(r);moved=backup
    else:
     target=seen[-1].directories['usr'][0];proc=os.open('/proc',os.O_RDONLY|os.O_DIRECTORY)
     try:os.dup2(proc,target)
     finally:os.close(proc)
   return data
  baseline=len(os.listdir('/proc/self/fd'))
  try:
   with patch.object(self.h,'CaptureLease',Spy),patch.object(os,'read',change),self.assertRaises((ValueError,FileNotFoundError,NotADirectoryError)):self.reader.capture('usr/lib/deep/first')
   self.assertTrue(changed);self.assertNotIn('literal',self.reader.__dict__);self.assertEqual(len(os.listdir('/proc/self/fd')),baseline)
  finally:
   # This test method recreates source state for the next mutation without
   # reusing a receipt: restore only our own files then take a new observation.
   if operation=='directory'and moved is not None:
    (r/'usr/lib/deep').rmdir();moved.rename(r/'usr/lib/deep')
   if operation=='root'and moved is not None:r.rmdir();moved.rename(r)
   if operation=='ancestor'and moved is not None:
    r.rename(moved/'tree');r.parent.rmdir();moved.rename(r.parent)
   leaf.write_bytes(b'first'*300)
   with contextlib.suppress(ValueError):self.m._fused_capabilities(r,self.report['nodes'],self.limits)
   self.limits=self.m.roots.Limits(time.monotonic()+60);self.report=self.m._fused_observe(r,limits=self.limits,hardlinks='generic-development-internal');self.assertTrue(self.report['complete']);self.reader=self.m.aux.Reader(r,self.report,self.limits)
 def test_expired_deadline_external_hardlink_and_pending_scope_refuse(self):
  with patch.object(self.limits.__class__,'tick',side_effect=ValueError('root observation deadline')),self.assertRaisesRegex(ValueError,'deadline'):self.reader.capture('usr/lib/deep/first')
  os.link(self.root/'usr/lib/deep/first',self.base/'outside')
  with self.assertRaises(ValueError):self.reader.capture('usr/lib/deep/first')
 def test_descriptor_cap_falls_back_to_fresh_original_acquisition(self):
  before=len(os.listdir('/proc/self/fd'))
  with patch.object(self.h,'MAX_CAPTURE_DIRECTORIES',1):value=self.reader.capture('usr/lib/alias/hard')
  self.assertEqual(value['node']['sha256'],hashlib.sha256(b'first'*300).hexdigest());self.assertEqual(before,len(os.listdir('/proc/self/fd')))
 def test_whole_parent_source_inverse_and_dependency_drift_refuse(self):
  raw=(ROOT/'scripts/update/measure_copy.py').read_bytes();out=self.h.parent_source(raw);self.assertEqual(out.replace(self.h.PARENT_INFO_AFTER,self.h.PARENT_INFO,1).replace(self.h.PARENT_AFTER,self.h.PARENT_BEFORE,1),self.h.function(raw,'_parent',self.h.COPY_PIN))
  with self.assertRaisesRegex(ValueError,'dependency differs'):self.h.parent_source(raw+b'\n')

class CompiledParentControls(unittest.TestCase):
 def setUp(self):
  import builtins
  self.compiles=[];original=builtins.compile
  def compile_once(source,filename,*a,**kw):
   if filename=='<private-capture-parent>':self.compiles.append(source)
   return original(source,filename,*a,**kw)
  p=patch.object(builtins,'compile',compile_once);p.start();self.addCleanup(p.stop)
  ScopedAuxCaptureControls.setUp(self)
  self.assertEqual(len(self.compiles),1)
 def clean_imports(self):ScopedAuxCaptureControls.clean_imports(self)
 def test_one_immutable_code_distinct_sequential_and_concurrent_lease_globals(self):
  import concurrent.futures,threading,types
  original=self.h.CaptureLease;seen=[];barrier=[None]
  class Spy(original):
   def __init__(s,*a,**kw):super().__init__(*a,**kw);seen.append(s)
   def read(s,*a,**kw):
    if barrier[0]is not None:barrier[0].wait(timeout=10)
    return super().read(*a,**kw)
  count=len(os.listdir('/proc/self/fd'))
  with patch.object(self.h,'CaptureLease',Spy):
   for name in('first','second'):self.reader.capture('usr/lib/deep/'+name)
   # Deliberately poison the retired namespace; the next fresh lease must not
   # inherit its callbacks or dictionaries merely because its code is shared.
   seen[0].parent.__wrapped__.__globals__['_lease_child']=lambda *a:(_ for _ in()).throw(AssertionError('retired namespace reused'))
   self.reader.capture('usr/lib/deep/first')
   barrier[0]=threading.Barrier(2);readers=[self.m.aux.Reader(self.root,self.report,self.limits)for _ in range(2)]
   with concurrent.futures.ThreadPoolExecutor(max_workers=2)as pool:
    values=[pool.submit(reader.capture,'usr/lib/deep/'+name)for reader,name in zip(readers,('first','second'))]
    for value in values:self.assertEqual(value.result(timeout=20)['node']['type'],'file')
  self.assertEqual(len(self.compiles),1);code=seen[0].parent.__wrapped__.__code__;self.assertIsInstance(code,types.CodeType);self.assertEqual(code.co_freevars,())
  self.assertEqual(len({id(v.parent.__wrapped__.__globals__)for v in seen}),len(seen))
  for lease in seen:
   self.assertIs(lease.parent.__wrapped__.__code__,code);self.assertTrue(lease.closed)
   with self.assertRaises(ValueError):lease.root(self.root)
  self.assertEqual(len(os.listdir('/proc/self/fd')),count);self.assertNotIn('literal',self.reader.__dict__)
 def test_callback_failure_and_descriptor_reuse_still_refuse_without_leak(self):
  original=self.h.CaptureLease
  for mode in('callback','reuse'):
   seen=[]
   class Fail(original):
    def __init__(s,*a,**kw):super().__init__(*a,**kw);seen.append(s)
    def check_child(s,info,name):
     if mode=='callback'and name=='usr/lib':raise ValueError('injected lease callback failure')
     return super().check_child(info,name)
    def read(s,*a,**kw):
     if mode=='reuse':
      fd=os.open('/proc',os.O_RDONLY|os.O_DIRECTORY)
      try:os.dup2(fd,s.fd)
      finally:os.close(fd)
     return super().read(*a,**kw)
   count=len(os.listdir('/proc/self/fd'))
   with patch.object(self.h,'CaptureLease',Fail),self.assertRaises((ValueError,FileNotFoundError,NotADirectoryError)):self.reader.capture('usr/lib/deep/first')
   self.assertEqual(len(os.listdir('/proc/self/fd')),count);self.assertTrue(seen[0].closed);self.assertNotIn('literal',self.reader.__dict__)
  self.assertEqual(len(self.compiles),1)
 def test_verified_parent_body_and_early_compiler_failure_close_all_fds(self):
  import builtins
  raw=(ROOT/'scripts/update/measure_copy.py').read_bytes()
  with self.assertRaisesRegex(ValueError,'dependency differs'):self.h.parent_source(raw+b'\n')
  original=builtins.compile
  def fail(source,filename,*a,**kw):
   if filename=='<private-capture-parent>':raise ValueError('injected immutable compiler failure')
   return original(source,filename,*a,**kw)
  m=_fusion_closure('compile_failure_fresh_closure');count=len(os.listdir('/proc/self/fd'))
  with patch.object(builtins,'compile',fail),self.assertRaisesRegex(ValueError,'immutable compiler failure'):_fusion_helper().bind(m)
  self.assertEqual(len(os.listdir('/proc/self/fd')),count)



class InnerFailureDiagnosticControls(unittest.TestCase):
 def fixture(self,failed=None,error=None):
  import functools
  actions=[];observation={'unit':'DIAGNOSTIC_ONLY_NOT_NATIVE'};state={'unit':'OWNED_NO_FS'}
  def observed(*a,**kw):
   actions.append('TREE_OBSERVE')
   if failed=='TREE_OBSERVE':raise error
   return observation
  def links(*a,**kw):
   actions.append('SELECTED_LINKS')
   if failed=='SELECTED_LINKS':raise error
  def aux(*a,**kw):
   actions.append('AUX_CHECKPOINT')
   if failed=='AUX_CHECKPOINT':raise error
   return state
  text=C.read(ROOT/'scripts/apps/full574_closure.py').decode();node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name=='_measure');node.decorator_list=[]
  scope=dict(roots=types.SimpleNamespace(observe=observed),links=types.SimpleNamespace(check=links),aux=types.SimpleNamespace(checkpoint=aux));exec(compile(ast.Module(body=[node],type_ignores=[]),'<trusted-original-measure-unit>','exec'),scope);original=scope['_measure']
  def traced(tag):
   def wrap(f):
    @functools.wraps(f)
    def call(*a,**kw):return f(*a,**kw)
    return call
   return wrap
  module=types.SimpleNamespace(_measure=traced('tree-and-aux-observation')(original),fast=types.SimpleNamespace(traced=traced));_fusion_helper().install_measure_diagnostics(module);self.assertIs(module._measure.__wrapped__.__code__,original.__code__);return module,actions,observation,state
 def test_original_measure_code_call_order_return_and_no_success_output(self):
  m,actions,v,s=self.fixture();writes=[]
  with patch.object(os,'write',side_effect=lambda fd,b:writes.append(b)or len(b)):self.assertEqual(m._measure(Path('/UNIT_NO_IO'),object()),(v,s))
  self.assertEqual(actions,['TREE_OBSERVE','SELECTED_LINKS','AUX_CHECKPOINT']);costs=[v for v in writes if v.startswith(b'APPS574_COST ')];self.assertEqual(len(costs),6);self.assertTrue(all(len(C.decode(v[len(b'APPS574_COST '):]))==17 for v in costs));self.assertEqual([v for v in writes if not v.startswith(b'APPS574_COST ')],[])
 def test_failure_and_cancellation_same_objects_and_one_literal_label(self):
  for phase in('TREE_OBSERVE','SELECTED_LINKS','AUX_CHECKPOINT'):
   for error in(ValueError('original source error'),KeyboardInterrupt('original cancellation'),SystemExit(8)):
    m,actions,*_=self.fixture(phase,error);writes=[]
    with patch.object(os,'write',side_effect=lambda fd,b:writes.append((fd,b))or len(b)),self.assertRaises(type(error))as caught:m._measure(Path('/UNIT_NO_IO'),object())
    self.assertIs(caught.exception,error);costs=[b for fd,b in writes if b.startswith(b'APPS574_COST ')];self.assertEqual(len(costs),2*(('TREE_OBSERVE','SELECTED_LINKS','AUX_CHECKPOINT').index(phase)+1));self.assertTrue(all(fd==2 for fd,b in writes));self.assertTrue(all(len(C.decode(v[len(b'APPS574_COST '):]))==17 for v in costs));original=[v for v in writes if not v[1].startswith(b'APPS574_COST ')];self.assertEqual(original,[(2,b'APPS574_MEASURE_FAILURE_DATA '+phase.encode()+b'\n')]);self.assertLessEqual(len(original[0][1]),64)
 def test_failed_diagnostic_write_never_replaces_original_exception(self):
  error=ValueError('ORIGINAL');m,*_=self.fixture('AUX_CHECKPOINT',error)
  with patch.object(os,'write',side_effect=KeyboardInterrupt('diagnostic failure'))as write,self.assertRaises(ValueError)as caught:m._measure(Path('/UNIT_NO_IO'),object())
  self.assertIs(caught.exception,error);self.assertEqual(write.call_count,7)
 def test_complete_original_capture_bound_hash_and_success_omission(self):
  import base64
  disk=C.load('source_owned_complete_capture_test',HERE/'disk.py')
  for err in(b'owned diagnostic bytes\nAPPS574_MEASURE_FAILURE_DATA AUX_CHECKPOINT\n',b'x'*(1024**2)):
   out=b'';record=dict(argv=['/usr/bin/python3','-I','-B','/source/scripts/ci/apps7-full574-repair16k/native_prepare.py','prepare-copy'],time_limit=610,output_limit=1024**2,exit_code=-15,stdout_bytes=0,stdout_sha256=C.sha(out),stderr_bytes=len(err),stderr_sha256=C.sha(err));v=disk.complete_failure_data(disk.backend_failure_data(record,out,err,ValueError('unit only')),err);self.assertEqual(v['schema_version'],2);self.assertEqual(base64.b64decode(v['stderr_complete']['base64'],validate=True),err);self.assertEqual(v['stderr_complete']['sha256'],record['stderr_sha256']);self.assertLessEqual(len(C.encoded(v)),2*1024**2);record['exit_code']=0;self.assertIsNone(disk.backend_failure_data(record,out,err,None));record['stderr_sha256']='0'*64;record['exit_code']=-15
   with self.assertRaises(ValueError):disk.backend_failure_data(record,out,err,ValueError('unit only'))
 def test_actual_private_aux_checkpoint_keeps_fresh_scoped_reader_and_code(self):
  module=_fusion_closure('diagnostic_scoped_reader_held');original=module._measure.__wrapped__.__code__;_fusion_helper().bind(module);self.assertIs(module._measure.__wrapped__.__code__,original);private=module._measure.__wrapped__.__globals__;self.assertIs(private['aux'].Reader,module.aux.Reader);self.assertIsNot(private['aux'],module.aux)



class NativePreparationCapacity(unittest.TestCase):
 def test_original_budget_runs_first_and_product_actions_keep_their_limits(self):
  import types,native_prepare as N
  calls=[]
  def original(args):calls.append(args);return 600 if args is not None else 300
  selected=N.validation_seconds(original)
  for action in ('apply','inspect','dispose-copy'):
   args=types.SimpleNamespace(action=action);self.assertEqual(selected(args),600);self.assertIs(calls[-1],args)
  self.assertEqual(selected(),300);args=types.SimpleNamespace(action='prepare-copy');self.assertEqual(selected(args),2400);self.assertIs(calls[-1],args)
 def test_invalid_original_policy_and_lease_refuse_before_capacity_is_selected(self):
  import types,native_prepare as N
  args=types.SimpleNamespace(action='prepare-copy')
  for invalid in (True,600.0,300,601,None):
   with self.subTest(invalid=invalid),self.assertRaisesRegex(ValueError,'authenticated native600'):
    N.validation_seconds(lambda a:invalid)(args)
  def refused(args):raise ValueError('original policy or lease refused')
  with self.assertRaisesRegex(ValueError,'original policy or lease refused'):N.validation_seconds(refused)(args)
 def test_native_profile_never_routes_apply_inspection_or_disposal(self):
  import native_prepare as N
  for action in ('apply','inspect','dispose-copy','--worker'):
   with patch.object(sys,'argv',['native_prepare.py',action]),patch.object(C,'check_source',side_effect=AssertionError('no source or actor before refusal')):
    with self.assertRaisesRegex(ValueError,'preparation only'):N.main()
 def test_original_same_owner_and_other_command_caps_stay_held(self):
  disk=C.read(HERE/'disk.py').decode()
  self.assertIn("min(cap,s['deadline_monotonic']-time.monotonic())",disk)
  self.assertIn("seconds=caller_seconds(s) if mode=='prepare-copy' else 75",disk)
  self.assertIn("dict(backend_seconds=600,caller_seconds=610)",disk)
  self.assertIn("same_owner_deadline_monotonic=s['deadline_monotonic']",disk)
  self.assertIn("origin,target],600)",disk);self.assertIn("tree,image],600)",disk)


class GuestCopyColdCapacity(unittest.TestCase):
 def budget(self,original):
  import adapter as A
  scope={};exec(compile(A.CAPACITY_BIND,'<guest-copy-budget-control>','exec'),scope);return scope['_vm_capacity_wrap'](original)
 def test_only_guest_prepare_copy_selects9000_after_original_policy(self):
  import types
  seen=[]
  def original(a):seen.append(a);return 300 if a is None else 600
  selected=self.budget(original);self.assertEqual(selected(),300)
  for action,want in [('prepare-copy',9000),('apply',600),('inspect',600),('dispose-copy',600)]:
   args=types.SimpleNamespace(action=action);self.assertEqual(selected(args),want);self.assertIs(seen[-1],args)
  self.assertEqual(selected(types.SimpleNamespace(validation_profile='REPAIR_GENERIC16K_COLD_VALIDATION_2400_V1')),2400)
 def test_invalid_or_failed_original_policy_is_never_capacity_authority(self):
  import types
  args=types.SimpleNamespace(action='prepare-copy')
  for v in [True,600.0,599,601,None]:
   with self.assertRaisesRegex(ValueError,'authenticated full574'):self.budget(lambda a:v)(args)
  def fail(a):raise OSError('EXPLICIT_CONTROL_ORIGINAL_REFUSAL')
  with self.assertRaisesRegex(OSError,'ORIGINAL_REFUSAL'):self.budget(fail)(args)
 def test_failure_capture_5296_bytes_is_lossless_bounded_and_never_positive(self):
  import adapter as A,types,base64
  class Calls:
   def call(*a,**kw):raise AssertionError('no actor')
  scope=dict(C=C,H=types.SimpleNamespace(Calls=Calls),types=types);exec(compile(A.BACKEND_NOTE,'<failure-capture-memory-control>','exec'),scope)
  raw=(b'EXPLICIT_SOURCE_CONTROL_ONLY\n'*204)[:5296];self.assertEqual(len(raw),5296);out=b'';record=dict(argv=['/usr/bin/python3','-I','-B','/execution/scripts/ci/apps7-full574-repair-native/transaction.py','prepare-copy'],exit_code=-15,seconds=9010.1,time_limit=9010,output_limit=1024**2,group_absence_verified=True,stdout_bytes=0,stdout_sha256=C.sha(out),stderr_bytes=len(raw),stderr_sha256=C.sha(raw))
  line=scope['_vm_backend_complete'](record,out,raw,ValueError('CONTROL_ONLY'));self.assertIsNotNone(line);self.assertLessEqual(len(line.encode()),10240);v=C.decode(line.removeprefix('APPS574_BACKEND_COMPLETE ').encode());self.assertEqual(__import__('zlib').decompress(base64.b64decode(v['streams']['stderr']['base64'],validate=True)),raw);self.assertFalse(v['acceptance_authority']);self.assertFalse(v['cleanup_authority']);self.assertEqual(v['schema_version'],3);self.assertEqual(v['streams']['stderr']['encoding'],'ZLIB_BASE64');self.assertEqual(v['supervisor_sha256'],C.sha(C.encoded(record)));self.assertNotIn('supervisor',v)
  self.assertIsNone(scope['_vm_backend_complete'](record,out,b'x'*65537,None));bad=dict(record,stderr_sha256='0'*64)
  with self.assertRaisesRegex(ValueError,'capture join'):scope['_vm_backend_complete'](bad,out,raw,None)
 def test_profile_output_and_all_original_outer_frame_and_owner_bounds_held(self):
  raw=C.read(HERE/'guest.py').decode();self.assertIn("guest_copy_profile='REPAIR_GENERIC16K_GUEST_COPY_CORRECTNESS_9000_V1'",raw);self.assertIn('guest_prepare_copy_seconds=[9000,9010]',raw);self.assertIn('len(C.encoded(candidate))<=12288',raw);self.assertIn('len(raw)<=65536',raw);self.assertIn('prefix=raw[:16384]',raw);self.assertIn('capacity_remaining(),2*1024**2',raw)
  clock=C.read(HERE/'job_clock.py').decode();self.assertIn('JOB=21000;POST=1260;ADMISSION=120;KILL=30;OWNER_MARGIN=90',clock);self.assertIn('seconds=min(18000,',clock)
 def test_native_preparation_and_product_limits_do_not_follow_guest_profile(self):
  import native_prepare as N,types,adapter as A
  self.assertEqual(N.validation_seconds(lambda a:600)(types.SimpleNamespace(action='prepare-copy')),2400);scope={};exec(compile(A.BACKEND_NOTE,'<guest-only-caller-source-control>','exec'),dict(scope,C=C,H=types.SimpleNamespace(Calls=type('Calls',(),{'call':lambda *a,**k:None})),types=types))
  self.assertIn("seconds==610:seconds=9010",A.BACKEND_NOTE);self.assertIn("transaction.py','prepare-copy'] and seconds==610",A.BACKEND_NOTE);disk=C.read(HERE/'disk.py').decode();self.assertIn('return 2410 # Explicit native preparation profile',disk);self.assertIn("seconds=caller_seconds(s) if mode=='prepare-copy' else 75",disk)

class PlannedCliFailureControls(unittest.TestCase):
 def cli_scope(self):
  import types
  raw=C.read(ROOT/C.NATIVE/'base_lifecycle.py').decode();tree=ast.parse(raw);node=next(n for n in tree.body if isinstance(n,ast.ClassDef)and n.name=='Calls');space=dict(C=types.SimpleNamespace(**dict(vars(C),ENV={})),SOURCE=ROOT,WORK=Path('/work'),OUT=Path('/out'),INPUTS=Path('/inputs'),os=os);exec(compile(ast.Module(body=[node],type_ignores=[]),'<whole-original-caller-class>','exec'),space);h=types.SimpleNamespace(Calls=space['Calls']);scope=dict(C=C,H=h,types=types);exec(compile(A.BACKEND_NOTE,'<whole-execution-failure-note>','exec'),scope);return scope,space
 def inventory_argv(self):return ['/inputs/candidate/usr/bin/cachy-asahi-apps','inventory','--dbpath','/work/main/root/var/lib/pacman','--output','/work/install-inventory.json']
 def command(self,argv,out,err,seconds=45,code=1):return dict(argv=argv,exit_code=code,seconds=.1,time_limit=seconds,output_limit=1024**2,group_absence_verified=True,stdout_bytes=len(out),stdout_sha256=C.sha(out),stderr_bytes=len(err),stderr_sha256=C.sha(err))
 def test_fixed_inventory_and_plan_roles_refuse_unrelated_commands_or_limits(self):
  scope,_=self.cli_scope();role=scope['_vm_cli_role'];argv=self.inventory_argv();self.assertEqual(role(argv,45,0),'PLANNED_INVENTORY');self.assertIsNone(role(argv,46,0));self.assertIsNone(role(argv,45,1));self.assertIsNone(role([*argv[:-1],'/private/foreign'],45,0))
  plan=[argv[0],'--release','/inputs/release/bundle','--release-sha256','a'*64,'--catalog','/inputs/release/catalog.json','--catalog-sha256','b'*64,'--catalog-signature','/inputs/release/catalog.json.sig','--keyring','/inputs/release/public.gpg','--signer','C'*40,'--installed',argv[-1],'--installed-sha256','d'*64,'plan','install','apps','cache','orphans'];self.assertEqual(role(plan,120,0),'PLANNED_PLAN');self.assertIsNone(role(plan+['foreign'],120,0));plan[8]='not-a-hash';self.assertIsNone(role(plan,120,0))
 def test_actual_whole_original_call_keeps_rc_clock_streams_and_exception(self):
  import types,base64,zlib
  scope,space=self.cli_scope();out=C.encoded(dict(status='REFUSED',error='INERT_SOURCE_SHAPED_CLI_REASON'));err=b'INERT COMPLETE CLI STDERR\n';argv=self.inventory_argv();row=self.command(argv,out,err);seen=[]
  def run(*args):seen.append(args);return row,out,err,None
  original=types.SimpleNamespace(run_command=run)
  with tempfile.TemporaryDirectory()as td:
   space['OUT']=Path(td);call=object.__new__(scope['H'].Calls);call.api=original;call.rows=[]
   with patch.dict(os.environ,OWNER_TOKEN='0'*32):
    with self.assertRaisesRegex(ValueError,'bounded actual command failed')as caught:call.call(argv,seconds=45)
   self.assertIs(call.api,original);self.assertEqual(seen[0][-2:],(45,1024**2));self.assertEqual(len(call.rows),1);notes=caught.exception.__notes__;self.assertEqual(len(notes),2);self.assertTrue(notes[1].startswith('APPS574_CLI_FAILURE '));self.assertTrue(notes[0].startswith('APPS574_CLI_COMPLETE '));v=C.decode(notes[0].split(' ',1)[1].encode());self.assertEqual(v['supervisor'],row);self.assertEqual(v['role'],'PLANNED_INVENTORY');self.assertFalse(v['acceptance_authority']);self.assertFalse(v['cleanup_authority'])
   for name,data in(('stdout',out),('stderr',err)):
    stream=v['streams'][name];self.assertEqual(zlib.decompress(base64.b64decode(stream['base64'],validate=True)),data);self.assertEqual((stream['bytes'],stream['sha256']),(len(data),C.sha(data)))
   successful=C.encoded(dict(status='OBSERVED_LOCAL_DB_METADATA'));success_row=self.command(argv,successful,b'',code=0);call.api=types.SimpleNamespace(run_command=lambda *a:(success_row,successful,b'',None));api=call.api
   with patch.dict(os.environ,OWNER_TOKEN='0'*32):self.assertEqual(call.call(argv,seconds=45),C.decode(successful))
   self.assertIs(call.api,api)
 def test_capture_bounds_and_original_stream_hash_drift_refuse(self):
  scope,_=self.cli_scope();argv=self.inventory_argv();out=b'{}';err=b'INERT';row=self.command(argv,out,err);capture=scope['_vm_cli_complete'];self.assertIsNotNone(capture('PLANNED_INVENTORY',row,out,err,None));bad=dict(row,stderr_sha256='0'*64)
  with self.assertRaisesRegex(ValueError,'streams'):capture('PLANNED_INVENTORY',bad,out,err,None)
  self.assertIsNone(capture('PLANNED_INVENTORY',row,b'x'*1025,err,None));self.assertIsNone(capture('PLANNED_INVENTORY',row,out,b'x'*65537,None));self.assertIsNone(capture('FOREIGN',row,out,err,None));self.assertIn('seconds==610:seconds=9010',A.BACKEND_NOTE)
  large=b'x'*1025;summary=scope['_vm_cli_note']('PLANNED_INVENTORY',self.command(argv,large,err),large,err,None);value=C.decode(summary.split(' ',1)[1].encode());self.assertEqual(value['stream_capture'],'HASH_AND_LENGTH_ONLY');self.assertEqual(value['supervisor']['stdout_bytes'],1025);self.assertLessEqual(len(summary.encode()),1900)
 def test_actual_nested_lifecycle_frame_promotes_cli_separately_without_cap_change(self):
  import base64,io,contextlib
  scope,_=self.cli_scope();argv=self.inventory_argv();out=b'{}';err=b'INERT CLI ERROR\n';row=self.command(argv,out,err);line=scope['_vm_cli_complete']('PLANNED_INVENTORY',row,out,err,None);note=scope['_vm_cli_note']('PLANNED_INVENTORY',row,out,err,None);nested=('INERT TRACE\n'+line+'\n'+note+'\n').encode();text=C.read(HERE/'guest.py').decode();node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name=='lifecycle_failure');space=dict(C=C,base64=base64,json=json);exec(compile(ast.Module(body=[node],type_ignores=[]),'<whole-actual-lifecycle-failure>','exec'),space);record=dict(self.command(['/usr/bin/python3','-I','-B','/workspace/execution-lifecycle.py'],b'',nested,seconds=100),output_limit=2*1024**2);stream=io.StringIO()
  with contextlib.redirect_stdout(stream):space['lifecycle_failure'](dict(nonce='1'*32,case='repair-bytes'),record,b'',nested,None)
  raw=stream.getvalue().encode();self.assertLessEqual(len(raw),12288+80);v=C.decode(raw.split(b' ',2)[2]);self.assertEqual(v['schema_version'],3);self.assertEqual(v['cli_complete'],C.decode(line.split(' ',1)[1].encode()));self.assertEqual(v['cli_failure'],C.decode(note.split(' ',1)[1].encode()));self.assertNotIn('backend_complete',v);self.assertFalse(v['acceptance_authority']);self.assertFalse(v['cleanup_authority']);self.assertLessEqual(len(C.encoded(v)),12288)

if __name__=='__main__':unittest.main()
