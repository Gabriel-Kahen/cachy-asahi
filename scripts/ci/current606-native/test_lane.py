"""Private source/plan/fixture controls; no native success fixture or actors."""
import ast,copy,hashlib,json,subprocess,sys,tempfile,unittest,types
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
import contract as P,adapter as A,bridge606 as B,run as R,gate as G
class Controls(unittest.TestCase):
 def test_NULL_refuses_before_args_outputs_or_actors(self):
  with tempfile.TemporaryDirectory()as d,patch.object(P,'HERE',Path(d)),patch.object(subprocess,'Popen',side_effect=AssertionError('actor')):
   (Path(d)/'input-policy.json').write_bytes((HERE/'default-input-policy.json').read_bytes());(Path(d)/'expected606.lock').write_bytes((HERE/'expected606.lock').read_bytes())
   for f in(R.main,G.main):
    with self.assertRaisesRegex(ValueError,'NULL606'):f([])
 def test_exact_two_additions_lock(self):
  p=P.policy(False);after=dict(r.split()for r in(HERE/'expected606.lock').read_text().splitlines());self.assertEqual(len(after),606)
  if(P.ROOT/'held604').exists():
   before=dict(r.split()for r in(P.ROOT/'held604'/P.OLD/'expected604.lock').read_text().splitlines());self.assertEqual(after.keys()-before.keys(),{'cachy-asahi-dns','cachy-asahi-sysctl'});self.assertEqual({k:after[k]for k in before},before)
 def test_roles_versions_programs_and_suites(self):
  p=P.policy(False);self.assertEqual([p['products'][r]['controls']for r in P.ROLES],[27,28]);self.assertEqual([p['products'][r]['source_files'][r[:-1]]['sha256']for r in P.ROLES],['d708cbe54a8e96a62ff7d85e4eadfb7a980401adb3a9fe8465052f754b4c8c88','70e3e35d1bf517b21c84f5ecbe608da551e6f8577c68bbfbbd2412b8dd3ed4f0'])
 def test_actual_builder_recipe_route_uses_alias_folder_and_real_package_name(self):
  if not(P.ROOT/'held-tools').exists():return
  import build_pairs
  with patch.object(subprocess,'Popen',side_effect=AssertionError('actor')):
   for role in P.ROLES:
    row=build_pairs.inspect_recipe(P.ROOT/'held-tools',role,P.policy(False));self.assertFalse(row['errors']);self.assertEqual(row['metadata']['pkgname'],[role[:-1]]);self.assertEqual(row['metadata']['pkgver'],['0.1.0']);self.assertEqual(row['metadata']['pkgrel'],['2'])
 def test_authorities_missing_and_foreign_refuse(self):
  for a in(None,{},dict(base604={},dns2={},sysctl2={})):
   with self.assertRaises(ValueError):P.authorities(a)
 def test_counted_derivation_rejects_ambiguous_or_missing(self):
  for value in('none','xx'):
   with self.assertRaises(ValueError):A.one(value,'x','y')
 def test_actual_composed_lifecycle_insertion_and_conservation(self):
  if not(P.ROOT/'held604').exists():return
  raw=A.lifecycle(P.ROOT);self.assertIn("install();checkpoint('install604',after,rows)\n        import tools606\n        previous_ld,previous_aux=tools606.exercise(globals(),locals())",raw);self.assertEqual(A.proof(P.ROOT)['original_methods'],'BYTE_IDENTICAL_AFTER_REMOVING_INSERTION')
  original=ast.parse(A.held(P.ROOT,'lifecycle.py'));derived=ast.parse(raw)
  a={n.name:ast.dump(n,include_attributes=False)for n in original.body if isinstance(n,ast.FunctionDef)and n.name!='main'};b={n.name:ast.dump(n,include_attributes=False)for n in derived.body if isinstance(n,ast.FunctionDef)and n.name!='main'};self.assertEqual(a,b)
 def test_no_new_caps_or_deadlines_in_composed_owner(self):
  if not(P.ROOT/'held604').exists():return
  raw=A.owner(P.ROOT);self.assertIn('signal.setitimer(signal.ITIMER_REAL,6600)',raw);self.assertIn('active.process.wait(timeout=1800)',raw);self.assertIn('len(owned.rows)==5',raw);self.assertNotIn('CAP_NET_ADMIN',raw);self.assertNotIn('SYS_ADMIN',raw)
 def test_actual_generated_runner_denies_non_native_before_actors(self):
  if not(P.ROOT/'held604').exists():return
  with tempfile.TemporaryDirectory()as d,patch.object(subprocess,'Popen',side_effect=AssertionError('actor')):
   runner,ledger=B.emit_runner(P.ROOT,Path(d)/'runner');self.assertEqual(ledger['lifecycle'],'ONE_INSERTION_ALL_OTHER_BYTES_HELD');old=P.load('606_composed_control_contract',runner/'contract.py')
   with patch.dict(sys.modules,{'contract':old}):module=P.load('606_composed_control_lifecycle',runner/'lifecycle.py')
   out=Path(d)/'out';out.mkdir();module.OUT=out;self.assertEqual(module.main(),1);v=json.loads((out/'lifecycle.json').read_bytes());self.assertEqual(v['status'],'FAIL');self.assertIn('owned offline604 native container',v['error'])
 def test_full604_observer_has_only_count_derivative(self):
  if not(P.ROOT/'held-tools').exists():return
  raw=(P.ROOT/'held-tools/scripts/ci/apps-cache-native/installed.py').read_text();derived=A.one(raw,'max_packages=574','max_packages=604');self.assertEqual(A.one(derived,'max_packages=604','max_packages=574'),raw);self.assertIn('device=info.st_dev,inode=info.st_ino,links=info.st_nlink',derived);self.assertIn('spent<=6*1024**3',derived)
 def test_receipt_missing_or_wrong_count_refused(self):
  for v in(None,{},dict(status='PASS_SIGNED604_TO606_PRIVATE_LIFECYCLE',base_count=574,installed_count=576,restored_count=574)):
   with self.assertRaises((ValueError,KeyError)):B.validate(v)
 def test_source_closure_Popen_blocked(self):
  if not(P.ROOT/'held604').exists():return
  with patch.object(subprocess,'Popen',side_effect=AssertionError('actor')):P.verify(bound=False)
 def test_metadata_role_is_exact_disjoint_public_b015(self):
  rows=P.metadata();self.assertEqual(len(rows),47);self.assertFalse(rows.keys()&P.read(HERE/'base-pins.json').keys())
  self.assertEqual(sum(n.startswith('packages/tools/cachy-asahi-apps/')for n in rows),15)
  self.assertEqual(sum(n.startswith('packages/tools/cachy-asahi-cache/')for n in rows),7)
  self.assertEqual(sum(n.startswith('packages/tools/cachy-asahi-repository-runtime/')for n in rows),11)
  self.assertEqual(sum(n.startswith('packages/settings/cachy-asahi-setup/')for n in rows),12)
  self.assertIn('LICENSE',rows);self.assertIn('scripts/setup/setup.py',rows)
 def test_metadata_selection_missing_extra_tampered_and_alias_refuse_before_output(self):
  if not(P.ROOT/'held604').exists():return
  import prepare
  with tempfile.TemporaryDirectory()as d,patch.object(subprocess,'Popen',side_effect=AssertionError('actor')):
   t=Path(d);out=t/'new';meta=t/'metadata';meta.mkdir()
   def emit():return prepare.emit(P.ROOT/'held604',P.ROOT/'held-tools',out,metadata_source=meta)
   with self.assertRaisesRegex(ValueError,'exact47'):emit()
   for n in P.metadata():
    p=meta/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((P.ROOT/'held604'/n).read_bytes())
   extra=meta/'extra';extra.write_bytes(b'x')
   with self.assertRaisesRegex(ValueError,'exact47'):emit()
   extra.unlink();target=meta/'packages/tools/cachy-asahi-cache/.SRCINFO';raw=target.read_bytes();target.write_bytes(raw+b'\n')
   with self.assertRaisesRegex(ValueError,'whole source drift'):emit()
   target.unlink();target.symlink_to(P.ROOT/'held604/packages/tools/cachy-asahi-cache/.SRCINFO')
   with self.assertRaisesRegex(ValueError,'source alias'):emit()
   self.assertFalse(out.exists())
 def test_original151_contract_and_manifest_stay_valid(self):
  if not(P.ROOT/'held604').exists():return
  with patch.object(subprocess,'Popen',side_effect=AssertionError('actor')):
   old=P.load('606_held151_metadata_control',P.ROOT/'held604'/P.OLD/'contract.py');manifest=old.verify_source(P.ROOT/'held604');self.assertEqual(len(manifest['files']),148)
 def test_real_preservation_map_rejects_bytes_mode_inode_changes(self):
  if not(P.ROOT/'held-tools').exists():return
  L=P.load('606_test_original_user',P.ROOT/'held-tools/scripts/ci/welcome-native/lifecycle.py');I=P.load('606_test_original_preserve',P.ROOT/'held-tools/scripts/ci/apps-cache-native/installed.py')
  with tempfile.TemporaryDirectory()as d:
   p=Path(d)/'payload';p.write_bytes(b'held');held=dict(packages=[],nodes={str(p):I.entry(L,p)});I.preserve_base(L,held)
   p.write_bytes(b'changed')
   with self.assertRaises(ValueError):I.preserve_base(L,held)
   p.write_bytes(b'held');held['nodes'][str(p)]=I.entry(L,p);p.chmod(0o400)
   with self.assertRaises(ValueError):I.preserve_base(L,held)
   p.chmod(0o600);held['nodes'][str(p)]=I.entry(L,p);fresh=Path(d)/'replacement';fresh.write_bytes(b'held');fresh.replace(p)
   with self.assertRaises(ValueError):I.preserve_base(L,held)
 def test_generated_driver_declares_real_installed_commands_only(self):
  f=(HERE/'fixture606.py').read_text();self.assertIn("program=Path('/usr/bin')/product['package_name']",f);self.assertIn("'--command-source',program",f);self.assertIn("'skipped='not in text",f);self.assertNotIn('sysctl -w',f);self.assertNotIn('nmcli connection up',f)
 def test_explicit_continuation_return_contract(self):
  tree=ast.parse((HERE/'tools606.py').read_bytes());fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='exercise');last=fn.body[-1]
  self.assertIsInstance(last,ast.Return);self.assertEqual(ast.dump(last.value),ast.dump(ast.Tuple(elts=[ast.Name(id='previous_ld',ctx=ast.Load()),ast.Name(id='previous_aux',ctx=ast.Load())],ctx=ast.Load())))
  self.assertNotIn("s['previous_ld']=",(HERE/'tools606.py').read_text());self.assertNotIn("s['previous_aux']=",(HERE/'tools606.py').read_text())
 def test_real_generated_assignment_updates_caller_checkpoint_closure(self):
  if not(P.ROOT/'held604').exists():return
  tree=ast.parse(A.lifecycle(P.ROOT));call=next(n for n in ast.walk(tree)if isinstance(n,ast.Assign)and isinstance(n.value,ast.Call)and isinstance(n.value.func,ast.Attribute)and n.value.func.attr=='exercise')
  self.assertEqual([n.id for n in call.targets[0].elts],['previous_ld','previous_aux'])
  seed=(object(),b'INERT_INITIAL');final=(object(),b'INERT_CONTINUATION');module=types.ModuleType('tools606');module.exercise=lambda g,s:final
  text='def caller():\n previous_ld,previous_aux=seed\n def checkpoint():return previous_ld,previous_aux\n '+ast.unparse(call)+'\n return checkpoint()\n';scope=dict(seed=seed,tools606=module)
  exec(compile(text,'<actual-counted-continuation-statement>','exec'),scope);self.assertEqual(scope['caller'](),final);self.assertNotEqual(seed,final)

if __name__=='__main__':unittest.main()
