# SPDX-License-Identifier: MIT
"""Local source and real private-model controls; no native ALPM or kernel credit."""
import ast,copy,hashlib,json,shutil,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import adapter as A
import selection as S
import contract as C
import fixture_checks as F
import rules
ROOT=A.ROOT
class Controls(unittest.TestCase):
 def test_default_null_entry_refuses_before_observers_output_or_actors(self):
  run=A.module(ROOT,'run.py');original=S.read;fixture=copy.deepcopy(S.policy(False));fixture.update(status='UNBOUND_SOURCE_TEMPLATE',recipe_sources=dict.fromkeys(S.NAMES))
  with tempfile.TemporaryDirectory()as td,patch.object(S,'read',side_effect=lambda p:fixture if p==S.HERE/'input-policy.json'else original(p)),patch.object(subprocess,'Popen',side_effect=AssertionError('no native actors')),patch.object(run.platform,'machine',side_effect=AssertionError('policy before observers')):
   out=Path(td)/'absent'
   with self.assertRaisesRegex(ValueError,'NULL/UNBOUND'):run.execute(ROOT,Path('/absent'),out,'a'*32)
   self.assertFalse(out.exists())
 def test_source_closure_and_exact_six_consumer_derivatives(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('no source actors')):
   S.verify_source(ROOT,False)
   for name in('contract.py','run.py','job.py'):compile(A.text(ROOT,name),name,'exec')
  raw=A.text(ROOT,'run.py');self.assertIn('len(self)<6',raw);self.assertIn('signal.setitimer(signal.ITIMER_REAL,2350)',raw);self.assertIn("out/'lifecycle.log',600",raw);self.assertIn("for side in ('a','b')",raw)
  self.assertIn("C.PACKAGE not in base",raw);job=A.text(ROOT,'job.py');self.assertIn("len(owner['containers'])==6",job);self.assertIn("==list(reversed(owner['containers']))",job)
 def test_original_builder_is_whole_byte_held_and_240_bound(self):
  raw=A.B.read(ROOT,'scripts/ci/welcome-native/run.py');self.assertIn("execute(argv,directory/'build.log',240)",raw);self.assertNotIn('def builder(',Path(A.__file__).read_text())
 def test_same_actual_package_two_exact_versions_and_five_paths(self):
  p=S.policy(False)
  with patch.object(S,'policy',return_value=p):
   versions=[]
   for role in S.NAMES:
    r=S.recipe(ROOT,role);self.assertEqual(r['metadata']['pkgname'],['cachy-asahi-sysctl']);versions.append(C.version(ROOT,role));self.assertEqual(len(C.files(role)),5)
   self.assertEqual(versions,['0.1.0-1','0.1.0-2']);self.assertEqual(set(C.files(S.NAMES[0])),set(C.files(S.NAMES[1])))
 def test_original_cleanup_pair_and_process_owners_held(self):
  def functions(raw):return{n.name:ast.get_source_segment(raw,n)for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
  for name,held in [('run.py',('save','pair_gate')),('job.py',('regular','read','save','manifest_files','prove','invoke','retire_consumers','cleanup'))]:
   before,after=functions(A.B.text(ROOT,name)),functions(A.text(ROOT,name))
   for n in held:self.assertEqual(before[n],after[n],name+':'+n)
  run=A.module(ROOT,'run.py')
  for v in ({},dict(status='contents-reproduced',errors=['changed'],packages={})):
   with self.assertRaises((ValueError,KeyError)):run.pair_gate(v)
 def test_composed_generated_runner_contract_has_same_package_roles_and_null_barrier(self):
  import importlib.util,sys
  with tempfile.TemporaryDirectory()as td:
   context=Path(td);runner=A.runner(ROOT,context)
   def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
   selected=load('_runner_selection',runner/'selection.py');rule=load('_runner_rules',runner/'rules.py')
   with patch.dict(sys.modules,{'selection':selected,'rules':rule}):
    contract=load('_real_composed_contract',runner/'contract.py');self.assertEqual(contract.NAMES,S.NAMES);self.assertEqual(contract.PACKAGE,'cachy-asahi-sysctl')
    if selected.policy(False)['status']=='UNBOUND_SOURCE_TEMPLATE':
     with self.assertRaisesRegex(ValueError,'NULL/UNBOUND'):contract.final_spec()
    with self.assertRaises(ValueError):contract.validate_lifecycle({})
   self.assertEqual((runner/'installed.py').read_bytes(),(ROOT/'scripts/ci/apps-cache-native/installed.py').read_bytes());self.assertEqual((runner/'accepted/lifecycle.py').read_bytes(),(ROOT/'scripts/ci/welcome-native/lifecycle.py').read_bytes())
 def test_real_v1_records_discovered_by_v2_without_any_record_or_model_write(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);program=root/'cachy-asahi-sysctl';shutil.copyfile(S.recipe_path(ROOT,S.NAMES[1])/'cachy-asahi-sysctl',program);program.chmod(0o755)
   seed=F.seed(S.recipe_path(ROOT,S.NAMES[0])/'cachy-asahi-sysctl',root);before=F.snapshot(root/'legacy');r=F.discover(program,root)
   self.assertEqual(r['phases'],{'applied':'APPLIED','planned':'PLANNED'});self.assertEqual(F.snapshot(root/'legacy'),before);self.assertEqual((root/'legacy/tree/vm/swappiness').read_bytes(),b'30\n');self.assertEqual(seed['scope'],'PRIVATE_MODEL_NOT_KERNEL')
 def test_changed_original_record_and_alias_refused(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);F.seed(S.recipe_path(ROOT,S.NAMES[0])/'cachy-asahi-sysctl',root);p=root/'legacy/state/applied/journal.json';p.write_bytes(p.read_bytes()+b' ')
   with self.assertRaisesRegex(ValueError,'altered'):F.preserved(root)
   (root/'legacy/foreign').symlink_to('/proc/sys/vm/swappiness')
   with self.assertRaisesRegex(ValueError,'ordinary'):F.snapshot(root/'legacy')
 def test_v1_cannot_claim_new_discovery(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);program=root/'cachy-asahi-sysctl';shutil.copyfile(S.recipe_path(ROOT,S.NAMES[0])/'cachy-asahi-sysctl',program);program.chmod(0o755);F.seed(program,root);before=F.snapshot(root/'legacy')
   with self.assertRaisesRegex(ValueError,'fixture failed'):F.discover(program,root)
   self.assertEqual(F.snapshot(root/'legacy'),before)
 def test_source_drift_refused_and_actual_authorities_null(self):
  v=S.policy(False);self.assertTrue(all(v[k]is None for k in('actual_source','actual_ref','actual_run')));self.assertEqual(set(v['recipe_sources']),set(S.NAMES))
  with tempfile.TemporaryDirectory()as td:
   p=Path(td)/'file';p.write_bytes(b'wrong')
   with self.assertRaisesRegex(ValueError,'byte join'):S.checked(p,dict(bytes=5,sha256='a'*64))
 def test_lifecycle_requires_signatures_versions_28_controls_and_preservation(self):
  with self.assertRaises(ValueError):rules.validate({})
  text=(Path(__file__).parent/'lifecycle.py').read_text();self.assertNotIn('SigLevel = Optional',text);self.assertIn('I.pacman(',text);self.assertIn("I.payloads(L,{BASE:row})",text);self.assertIn("base|{BASE:row['version']}",text);self.assertIn('system pacman/trust changed',text);self.assertEqual(text.count("L.command(pacman+['-U'"),3);self.assertEqual(text.count("L.command(pacman+['-R',BASE]"),2)
if __name__=='__main__':unittest.main(verbosity=2)
