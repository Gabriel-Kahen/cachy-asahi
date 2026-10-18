# SPDX-License-Identifier: MIT
"""Finite source/real private-files controls; no native ALPM or live KSM credit."""
import ast,copy,hashlib,json,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import adapter as A,selection as S,contract as C,fixture_checks as F,rules
ROOT=A.ROOT
class Controls(unittest.TestCase):
 def test_null_policy_refuses_before_output_observation_or_actor(self):
  run=A.module(ROOT,'run.py');p=copy.deepcopy(S.policy(False));p.update(status='UNBOUND_SOURCE_TEMPLATE',recipe_sources=dict.fromkeys(S.NAMES));original=S.read
  with tempfile.TemporaryDirectory()as td,patch.object(S,'read',side_effect=lambda path:p if path==S.HERE/'input-policy.json'else original(path)),patch.object(subprocess,'Popen',side_effect=AssertionError('actor')),patch.object(run.platform,'machine',side_effect=AssertionError('observer')):
   out=Path(td)/'absent'
   with self.assertRaisesRegex(ValueError,'NULL/UNBOUND'):run.execute(ROOT,Path('/absent'),out,'a'*32)
   self.assertFalse(out.exists())
 def test_complete_source_and_genuine_rendered_programs(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('actor')):
   S.verify_source(ROOT,False)
   for n in('contract.py','run.py','job.py'):compile(A.text(ROOT,n),n,'exec')
  p=S.policy(False);self.assertTrue(all(p[k]is None for k in('actual_source','actual_ref','actual_run')))
 def test_exact_actual_same_package_versions_gpl_sources_and_payloads(self):
  p=S.policy(False)
  with patch.object(S,'policy',return_value=p):
   for role,version,files in zip(S.NAMES,('0.1.0-1','0.1.0-2'),(5,7)):
    r=S.recipe(ROOT,role);self.assertEqual(r['metadata']['pkgname'],['cachy-asahi-ksmctl']);self.assertEqual(r['metadata']['license'],['GPL-2.0-or-later']);self.assertEqual(C.version(ROOT,role),version);self.assertEqual(len(C.files(role)),files)
  self.assertEqual(p['products'][S.NAMES[0]]['source_files'][S.PACKAGE],p['products'][S.NAMES[1]]['source_files'][S.PACKAGE])
 def test_held_build_pair_caps_deadlines_and_reverse_cleanup_functions(self):
  def functions(raw):return{n.name:ast.get_source_segment(raw,n)for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
  for name,held in(('run.py',('save','pair_gate')),('job.py',('regular','read','save','manifest_files','prove','invoke','retire_consumers','cleanup'))):
   before,after=functions(A.B.text(ROOT,name)),functions(A.text(ROOT,name))
   for n in held:self.assertEqual(before[n],after[n],name+':'+n)
  run=A.text(ROOT,'run.py');self.assertIn('len(self)<6',run);self.assertIn('signal.setitimer(signal.ITIMER_REAL,2350)',run);self.assertIn("out/'lifecycle.log',600",run);self.assertIn("for side in ('a','b')",run)
  self.assertIn("execute(argv,directory/'build.log',240)",A.B.read(ROOT,'scripts/ci/welcome-native/run.py'))
  job=A.text(ROOT,'job.py');self.assertIn("len(owner['containers'])==6",job);self.assertIn('==list(reversed(owner[\'containers\']))',job)
 def test_real_reporter_and_experiment_software_suites_no_live_interfaces(self):
  # Exact reviewed source bytes here; native main separately requires root-owned
  # installed byte pins before these same suites. This is no installation proof.
  old=S.recipe_path(ROOT,S.NAMES[0]);new=S.recipe_path(ROOT,S.NAMES[1])
  self.assertEqual(F.suite(old,old/S.PACKAGE)['experiment'],0)
  result=F.suite(new,new/S.PACKAGE,new/F.EXPERIMENT);self.assertEqual(result,dict(reporting=18,experiment=26,domain='PRIVATE_REGULAR_FILES_ONLY',live_kernel_write='NOT_RUN'))
 def test_generated_runner_whole_helpers_and_null_gate(self):
  import importlib.util
  with tempfile.TemporaryDirectory()as td:
   runner=A.runner(ROOT,Path(td));self.assertEqual((runner/'installed.py').read_bytes(),(ROOT/'scripts/ci/apps-cache-native/installed.py').read_bytes());self.assertEqual((runner/'accepted/lifecycle.py').read_bytes(),(ROOT/'scripts/ci/welcome-native/lifecycle.py').read_bytes())
   code=(runner/'contract.py').read_text();self.assertIn("NAMES=('cachy-asahi-ksmctl','cachy-asahi-ksmctl2')",code)
   for p in runner.rglob('*.py'):compile(p.read_bytes(),str(p),'exec')
 def test_source_drift_and_foreign_recipe_refuse(self):
  with tempfile.TemporaryDirectory()as td:
   p=Path(td)/'file';p.write_bytes(b'wrong')
   with self.assertRaisesRegex(ValueError,'byte join'):S.checked(p,dict(bytes=5,sha256='a'*64))
  with self.assertRaises(ValueError):S.recipe_path(ROOT,'cachy-asahi-sysctl')
 def test_live_store_and_all574_rawdb_user_trust_guards_present(self):
  code=(Path(__file__).parent/'lifecycle.py').read_text()
  self.assertIn('all original574 payload/raw database rows preserved',code);self.assertIn('original system pacman/trust changed',code);self.assertIn('L.preservation_check(home,before,output,outside)',code);self.assertIn('earlier private receipt changed',code)
  self.assertIn("not os.path.lexists('/var/lib/cachy-asahi-ksm-experiments')",code);self.assertIn("I.payloads(L,{BASE:row})",code);self.assertIn('I.pacman(',code);self.assertNotIn('SigLevel = Optional',code)
  self.assertEqual(code.count("L.command(pacman+['-U'"),3);self.assertEqual(code.count("L.command(pacman+['-R',BASE]"),2)
 def test_incomplete_or_non_native_receipts_never_qualify(self):
  for value in({},dict(status='PASS_KSM2_SIGNED_UPGRADE_PRIVATE_LIFECYCLE'),dict(status='PASS_KSM2_SIGNED_UPGRADE_PRIVATE_LIFECYCLE',base_count=574,installed_count=575,live_kernel_write='PASS')):
   with self.assertRaises(ValueError):rules.validate(value)
if __name__=='__main__':unittest.main(verbosity=2)
