# SPDX-License-Identifier: MIT
"""Finite Apps7 source/VM compatibility controls; no accepted actual fixture."""
import ast,importlib.util,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
sys.path.insert(0,str(HERE));import contract as C,adapter as A,prepare as P,vm
class Controls(unittest.TestCase):
 def test_complete184_source_and_native157_manifest(self):
  self.assertEqual(len(C.check_source(ROOT)),184);native=C.load('source_checks',ROOT/C.NATIVE/'contract.py');p=native.source(ROOT)
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
  text=C.read(HERE/'vm.py').decode();self.assertIn('seconds==4320',text);self.assertIn('deadline=time.monotonic()+3000',text);self.assertIn('shared_lifecycle_seconds=3000',text)
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
  record=dict(argv=['/usr/bin/python3','-I','-B','/source/'+C.NATIVE+'/transaction.py','prepare-copy'],exit_code=-15,seconds=610.01,time_limit=610,output_limit=1024**2,group_absence_verified=True,stdout_bytes=len(out),stdout_sha256=C.sha(out),stderr_bytes=len(err),stderr_sha256=C.sha(err))
  return record,out,err,ValueError('command-time-limit')
 def test_original_failures_and_suffix_survive_prefix_truncation(self):
  row,out,err,error=self.capture();v=self.disk.backend_failure_data(row,out,err,error)
  self.assertGreater(len(err),1024);self.assertNotIn(b'root observation deadline',err[:1024]);self.assertEqual(v['phase_failures']['count'],2);self.assertEqual([r['error_reason']for r in v['phase_failures']['first']],['root observation deadline']*2)
  self.assertEqual(v['stderr'],dict(bytes=len(err),sha256=C.sha(err)));tail=v['stderr_suffix'];import base64
  self.assertEqual(base64.b64decode(tail['base64'],validate=True),err[-2048:]);self.assertEqual(tail['sha256'],C.sha(err[-2048:]));self.assertTrue(tail['truncated']);self.assertLessEqual(len(C.encoded(v)),8192);self.assertFalse(v['acceptance_authority']);self.assertFalse(v['cleanup_authority'])
 def test_tampered_stream_limits_or_untrusted_phase_fields_refuse_or_mark_invalid(self):
  row,out,err,error=self.capture()
  for change in(dict(stderr_bytes=len(err)+1),dict(stderr_sha256='0'*64),dict(time_limit=611),dict(output_limit=2*1024**2)):
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
   retained=C.decode(receipt.read_bytes());self.assertEqual(len(calls),1);self.assertEqual(calls[0][-2:],(610,1024**2));self.assertEqual(retained[0]['record'],row);self.assertEqual(retained[0]['phase_summary'],D.phase_summary(err));self.assertEqual(retained[0]['backend_failure_data'],D.backend_failure_data(row,out,err,error));self.assertLessEqual(receipt.stat().st_size,2*1024**2)
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
   self.assertTrue(reader.scan.__code__.co_filename.endswith(':source-owned-ancestor-walk'))
   self.assertEqual(proof['inventory_source_before'],'68f9b0bc6bd5c494ebfc10bdc1e243c014d7fa8e56b1386491b75cdb9ee2e3df')
   self.assertEqual(proof['inventory_source_after'],'faca184446aa9214c53bc78b797813cbad9768f7d8276a733fb15e4ecc7c2630')
   args.apps_provenance_sha256='0'*64
   with self.assertRaises(ValueError):m.app_source(args)
 def test_inventory_whole_source_and_all_canonical_parent_checks_held(self):
  import types
  scope=types.ModuleType('_source_inventory_test');exec(A.INVENTORY_OBSERVER,scope.__dict__)
  raw=C.read(ROOT/'packages/tools/cachy-asahi-apps7/inventory.py')
  self.assertEqual(scope.derive(raw).replace(scope.AFTER.encode(),scope.BEFORE.encode()),raw)
  with self.assertRaises(ValueError):scope.derive(raw+b'\n')
  from pathlib import PurePosixPath
  for path in ('a','a/b','a/b/c','usr/share/fixture/path','unicode-ä/child'):
   old=[p.as_posix()for p in PurePosixPath(path).parents if p.as_posix()!='.'];new=[];parent=path.rpartition('/')[0]
   while parent:new.append(parent);parent=parent.rpartition('/')[0]
   self.assertEqual(old,new)

if __name__=='__main__':unittest.main()
