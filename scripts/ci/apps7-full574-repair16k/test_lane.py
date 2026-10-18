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
if __name__=='__main__':unittest.main()
