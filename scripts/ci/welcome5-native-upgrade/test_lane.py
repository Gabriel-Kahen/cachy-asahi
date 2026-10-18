# SPDX-License-Identifier: MIT
"""Source/private local controls only: no ALPM, Docker, host mutations or actual IDs."""
import ast,copy,hashlib,importlib.util,json,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import adapter as A,selection as S,contract as C,fixture_checks as F,rules
ROOT=A.ROOT
legacy=C.load('welcome5_original_cleanup_controls',ROOT/'scripts/ci/tools-native/test_native.py');legacy.ROOT=ROOT
# Patch the real derivative module globals, rather than its forwarding wrapper.
legacy.J=A.module(ROOT,'job.py');legacy.R=A.module(ROOT,'run.py')
Cleanup=legacy.Cleanup;SourceProof=legacy.SourceProof
class Controls(unittest.TestCase):
 def test_NULL_refuses_before_any_observer_actor_or_output(self):
  p=copy.deepcopy(S.policy(False));p.update(status='UNBOUND_SOURCE_TEMPLATE',recipe_sources=dict.fromkeys(S.NAMES));read=S.read;r=A.module(ROOT,'run.py')
  with tempfile.TemporaryDirectory()as d,patch.object(S,'read',side_effect=lambda path:p if path==S.HERE/'input-policy.json'else read(path)),patch.object(subprocess,'Popen',side_effect=AssertionError('actor')),patch.object(r.platform,'machine',side_effect=AssertionError('observer')):
   out=Path(d)/'absent'
   with self.assertRaisesRegex(ValueError,'NULL/UNBOUND'):r.execute(ROOT,Path('/absent'),out,'a'*32)
   self.assertFalse(out.exists())
 def test_complete_source_closure_and_derivative_compilation(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('source actor')):
   S.verify_source(ROOT,False)
   for n in('contract.py','run.py','job.py'):compile(A.text(ROOT,n),n,'exec')
   compile(A.builder_text(ROOT),'counted builder','exec')
  for p in Path(__file__).parent.glob('*.py'):compile(p.read_bytes(),str(p),'exec')
 def test_actual_roles_versions_and_exact_nine_file_ELF_payload(self):
  p=S.policy(False)
  with patch.object(S,'policy',return_value=p):
   self.assertEqual([C.version(ROOT,r)for r in S.NAMES],['0.1.0-4','0.1.0-5'])
   for role in S.NAMES:
    row=S.recipe(ROOT,role);self.assertEqual(row['metadata']['pkgname'],['cachy-asahi-welcome']);self.assertEqual(row['metadata']['arch'],['aarch64']);self.assertEqual(len(C.files(role)),9);self.assertIn('usr/bin/cachy-asahi-welcome',C.files(role))
   with self.assertRaises(ValueError):S.payload(dict(errors=[],elf=[],members={}),ROOT,S.NAMES[1])
 def test_exact_two_builder_routing_edits_retain240_and_original_ELF(self):
  old=A.B.read(ROOT,'scripts/ci/welcome-native/run.py');new=A.builder_text(ROOT)
  self.assertEqual(new,old.replace('if name==C.NAME:','if name in C.NAMES:').replace("=='usr/bin/'+name:","=='usr/bin/'+C.PACKAGE:"))
  self.assertIn("execute(argv,directory/'build.log',240)",new);self.assertIn('elf=C.elf(data,checks)',new)
  original,_=S.welcome(ROOT);self.assertIn('actual_16k_execution',ast.get_source_segment(A.B.read(ROOT,'scripts/ci/welcome-native/contract.py'),next(n for n in ast.parse(A.B.read(ROOT,'scripts/ci/welcome-native/contract.py')).body if isinstance(n,ast.FunctionDef)and n.name=='elf')))
 def test_six_actors_original_budgets_and_reverse_retirement(self):
  run=A.text(ROOT,'run.py');job=A.text(ROOT,'job.py')
  for s in('len(self)<6','signal.setitimer(signal.ITIMER_REAL,2350)',"out/'lifecycle.log',600","for side in ('a','b')","C.PACKAGE not in base"):self.assertIn(s,run)
  self.assertIn('MAX_TOTAL=192*1024**2',job);self.assertIn("len(owner['containers'])==6",job);self.assertIn('==list(reversed(',job);self.assertIn('-aarch64.pkg.tar.',job);self.assertNotIn('-any.pkg.tar.',job)
 def test_original_pair_cleanup_and_docker_guard_bodies_held(self):
  def funcs(text):return{n.name:ast.get_source_segment(text,n)for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
  for name,names in [('run.py',['save','pair_gate']),('job.py',['regular','read','save','manifest_files','prove','invoke','retire_consumers','cleanup'])]:
   old,new=funcs(A.B.text(ROOT,name)),funcs(A.text(ROOT,name))
   for n in names:self.assertEqual(old[n],new[n])
  self.assertEqual(funcs(A.B.read(ROOT,'scripts/ci/welcome-native/run.py'))['docker'],funcs(A.builder_text(ROOT))['docker'])
 def test_generated_runner_keeps_original_private_trust_and_installed_helpers(self):
  with tempfile.TemporaryDirectory()as d:
   runner=A.runner(ROOT,Path(d));self.assertEqual((runner/'installed.py').read_bytes(),(ROOT/'scripts/ci/apps-cache-native/installed.py').read_bytes());self.assertEqual((runner/'accepted/lifecycle.py').read_bytes(),(ROOT/'scripts/ci/welcome-native/lifecycle.py').read_bytes())
   for p in runner.rglob('*.py'):compile(p.read_bytes(),str(p),'exec')
   deriv=json.loads((Path(d)/'runner-derivations.json').read_bytes());self.assertEqual(deriv['builder']['exact_replacements'],2)
 def test_original_root_skip_is_only_declared_build_deferment(self):
  p=S.policy(False)
  with tempfile.TemporaryDirectory()as d,patch.object(S,'policy',return_value=p):
   path=Path(d)/'log'
   for role in S.NAMES:
    count=13 if role==S.NAMES[0]else 15;text='\n'.join(p['products'][role]['check_markers'])+'\nok '+str(count)+' /management/root-guard # SKIP Root guard requires an actual root test process\n';path.write_text(text);self.assertIn('DEFERRED',S.check_log(path,role)['status']);path.write_text(text+'ok 99 /other # SKIP anything\n')
    with self.assertRaises(ValueError):S.check_log(path,role)
 def test_actual_native_report_fixture_compiler_on_private_local_source(self):
  # Real host compilation/execution of the exact future native fixture API.
  # This is local x86 source evidence only, never an installed/native receipt.
  for role,count in zip(S.NAMES,(8,12)):
   with tempfile.TemporaryDirectory()as d:
    program=F.compile_fixture(S.recipe_path(ROOT,role),Path(d),'report');r=F.command([str(program)]);self.assertIn(('1..'+str(count)+'\n').encode(),r.stdout);self.assertNotIn(b'# SKIP',r.stdout)
 def test_positive_scope_and_missing_critical_receipts_refuse(self):
  with self.assertRaises(ValueError):rules.validate({})
  with self.assertRaises((ValueError,KeyError)):rules.validate_products({})
  life=(Path(__file__).parent/'lifecycle.py').read_text();self.assertIn("I.pacman(L,control['signer'])",life);self.assertIn('I.payloads(L,{actual:row})',life);self.assertIn('I.preserve_base(L,state)==base_digest',life);self.assertIn('--root-guard',life);self.assertIn('GUI=\'NOT_RUN\'',life)
 def test_source_drift_and_actual_binding_refusal(self):
  p=S.policy(False);self.assertTrue(all(p[k]is None for k in('actual_source','actual_ref','actual_run')))
  for key in('actual_source','actual_ref','actual_run'):
   bad=copy.deepcopy(p);bad[key]='not authority';read=S.read
   with patch.object(S,'read',side_effect=lambda path:bad if path==S.HERE/'input-policy.json'else read(path)),self.assertRaisesRegex(ValueError,'actual authority'):S.policy(False)
  with tempfile.TemporaryDirectory()as d:
   path=Path(d)/'f';path.write_bytes(b'wrong')
   with self.assertRaises(ValueError):S.checked(path,dict(bytes=5,sha256='a'*64))
 def test_generated_lifecycle_contract_API_exists_for_every_reference(self):
  # Resolve the real generated contract used by the lifecycle, before actors.
  contract=A.module(ROOT,'contract.py');tree=ast.parse((A.HERE/'lifecycle.py').read_text())
  names={n.attr for n in ast.walk(tree)if isinstance(n,ast.Attribute)and isinstance(n.value,ast.Name)and n.value.id=='C'}
  for name in names:self.assertTrue(hasattr(contract,name),'missing generated lifecycle API: '+name)
  self.assertEqual(contract.PACKAGE,'cachy-asahi-welcome');self.assertEqual(set(contract.NAMES),set(S.NAMES))
if __name__=='__main__':unittest.main(verbosity=2)
