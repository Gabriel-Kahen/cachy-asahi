# SPDX-License-Identifier: MIT
"""Actor-blocked source composition and fail-closed authority controls."""
import ast,copy,importlib.util,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
ROOT=Path(os.environ.get('PUBLIC_PAIR_INSTALLER_ROOT',str(HERE.parents[2])))
COMP=Path(os.environ.get('PUBLIC_PAIR_COMPOSITION_ROOT',ROOT))
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value);return value
P=load('public_pair_fresh_prepare',HERE/'prepare.py')
def functions(raw):return {n.name:ast.dump(n,include_attributes=False) for n in ast.parse(raw).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
class Controls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
  blocked=patch.object(subprocess,'Popen',side_effect=AssertionError('no actors/Git/network'));blocked.start();self.addCleanup(blocked.stop)
 def emit(self):
  out=self.root/'source';r=P.emit(ROOT,COMP,out);C=load('public_pair_fresh_contract',out/P.NEW/'contract.py');return out,C,r
 def test_unbound_refuses_before_git_outputs_and_actors(self):
  out,C,_=self.emit()
  self.assertEqual(C.locks()[1]['cachy-asahi-apps'],'0.1.0-6')
  self.assertTrue(C.COMPOSITION.HERE.as_posix().endswith(P.COMP))
  self.assertTrue(all(v is None for v in C.policy(bound=False)['native604'].values()))
  with self.assertRaisesRegex(ValueError,'UNBOUND'):C.policy()
  G=C.scoped_load('public_pair_fresh_gate',out/P.NEW/'gate.py',{'contract':C})
  with self.assertRaisesRegex(ValueError,'UNBOUND'):G.main(['--implementation',str(out),'--source','a'*40,'--workflow-sha','a'*40,'--preflight'])
  self.assertNotIn('apps6_native_source',C.CARRIERS);self.assertIn('apps6_authority_source',C.CARRIERS)
 def test_all_604_identities_and_other603_preserved(self):
  out,C,_=self.emit();self.assertEqual((out/P.NEW/'expected604.lock').read_bytes(),(COMP/P.COMP/'expected604.lock').read_bytes())
  before=dict(line.split() for line in (ROOT/'scripts/ci/expanded604-current-management/expected604.lock').read_text().splitlines());after=C.locks()[1]
  self.assertEqual(len(after),604);self.assertEqual(after,before|{'cachy-asahi-apps':'0.1.0-6'})
 def test_runtime_functions_change_only_input_and_output_identities(self):
  out,_,_=self.emit();allowed={'contract.py':{'_shared','policy','decisions','freeze'},'ci.py':{'main'},'gate.py':{'main'},'adapter.py':set(),'freeze.py':set()}
  for name in P.MODULES:
   old=(ROOT/P.OLD/name).read_bytes();new=(out/P.NEW/name).read_bytes();a,b=functions(old),functions(new)
   self.assertEqual(set(a),set(b));self.assertEqual({n for n in a if a[n]!=b[n]},allowed[name],name)
   numbers=lambda raw:[n.value for n in ast.walk(ast.parse(raw)) if isinstance(n,ast.Constant) and type(n.value) in (int,float)]
   self.assertEqual(numbers(old),numbers(new),name)
  self.assertEqual((out/P.NEW/'freeze.py').read_bytes(),(ROOT/P.OLD/'freeze.py').read_bytes())
 def test_full_closed_sources_and_target_composition_byteexact(self):
  out,_,r=self.emit();manifest=json.loads((out/P.NEW/'source-manifest.json').read_bytes());self.assertEqual(r['source_rows'],len(manifest['files']))
  for n,row in manifest['files'].items():self.assertEqual(P.pin((out/n).read_bytes()),row)
  for n,raw in P.source(ROOT,COMP).items():self.assertEqual((out/n).read_bytes(),raw)
  for p in (out/P.NEW).glob('*.py'):compile(p.read_bytes(),str(p),'exec')
 def test_public_authority_checkout_and_exact_workflow_digests(self):
  out,_,_=self.emit();text=(out/P.WF).read_text();old=(ROOT/'.github/workflows/native-arm-expanded604-apps6-installer.yml').read_text()
  self.assertNotIn('apps6_native_source',text);self.assertNotIn('--apps6-native-source',text)
  self.assertEqual(text.count('--apps6-authority-source'),2);self.assertIn('steps.installer_policy.outputs.apps6_authority_source',text)
  self.assertIn('apps6-inputs/payload',text);self.assertIn(P.pin((out/P.NEW/'ci.py').read_bytes())['sha256'],text);self.assertIn(P.pin((out/P.NEW/'source-manifest.json').read_bytes())['sha256'],text)
  self.assertEqual(text.count('secrets.'),old.count('secrets.'));self.assertLess(text.index('Checkout exact apps6_authority_source'),text.index('secrets.'))
  self.assertEqual([line for line in text.splitlines() if 'timeout' in line],[line for line in old.splitlines() if 'timeout' in line])
 def test_old_or_partial_native_authority_rejected(self):
  _,C,_=self.emit();template=C.policy(bound=False)
  for status in ('ROOT_BOUND_APPS6_CURRENT604_NATIVE_ACCEPTANCE','ROOT_BOUND_CURRENT604_NATIVE_ACCEPTANCE','ROOT_BOUND_PUBLIC_PAIRS_APPS6_CURRENT604_NATIVE_ACCEPTANCE'):
   value=copy.deepcopy(template);value['status']=status
   with patch.object(C,'read',return_value=value),self.assertRaisesRegex(ValueError,'UNBOUND'):C.policy()
  text=P.adapt((ROOT/P.OLD/'contract.py').read_bytes(),'contract.py')[0].decode()
  self.assertIn('ROOT_ACCEPTED_NATIVE_PUBLIC_PAIRS_APPS6_CURRENT604_COMPOSITION',text)
  self.assertNotIn("=='ROOT_ACCEPTED_NATIVE_APPS6_CURRENT604_COMPOSITION'",text)
 def test_copied_composition_is_exact_bound_b015_not_native_acceptance(self):
  out,C,r=self.emit();pins=json.loads((P.HERE/'source-pins.json').read_bytes())
  self.assertEqual(pins['composition_source'],'b0154bd3b60434e45d4411b558f3ffda9e415640')
  self.assertEqual(r['source_rows'],271)
  self.assertEqual(C.COMPOSITION.policy()['status'],'ROOT_BOUND_PUBLIC_PAIRS_APPS6_CURRENT604_NATIVE_INPUTS')
  self.assertEqual(P.pin((out/P.COMP/'source-manifest.json').read_bytes())['sha256'],'e2b1f8ac11fa119493e22f44722d265293887de7edda80f4b61c00f8a80bf51c')
  self.assertEqual(P.pin((out/P.COMP/'input-policy.json').read_bytes())['sha256'],'a97b82d79e5aa967cde1b65c2f0a8b47cfd24d8cd3854b070dc919753a479e30')
  self.assertTrue(all(x is None for x in C.policy(bound=False)['native604'].values()))
  with self.assertRaisesRegex(ValueError,'UNBOUND'):C.policy()
 def test_emitted_actual_recipe_guards_and_setup_provenance(self):
  out,C,_=self.emit();I=C.COMPOSITION.scoped_load('closed_recipe_inputs',out/P.COMP/'inputs.py',{'contract':C.COMPOSITION})
  checks,_=I.tools(out)
  for name in ('cachy-asahi-apps','cachy-asahi-cache','cachy-asahi-repository-runtime'):
   recipe=checks.recipe(out/'packages/tools'/name/'PKGBUILD');self.assertEqual(recipe['errors'],[],name)
  setup=C.COMPOSITION.load('closed_setup_recipe',out/'scripts/ci/setup5-native/contract.py');self.assertEqual(len(setup.recipe(out)['input_sha256']),12)
  current=C.COMPOSITION.load('closed_current_recipes',out/'scripts/ci/welcome-management-native/native_contract.py')
  for name in ('cachy-asahi-welcome','cachy-asahi-orphans'):self.assertEqual(current.recipe(out,name)['errors'],[])
  missing=out/'packages/tools/cachy-asahi-cache/.SRCINFO';missing.unlink()
  with self.assertRaisesRegex(ValueError,'reviewed .SRCINFO'):checks.recipe(missing.with_name('PKGBUILD'))
 def test_missing_recipe_role_refuses_before_emission(self):
  import shutil
  copyroot=self.root/'composition';shutil.copytree(COMP,copyroot)
  (copyroot/'packages/tools/cachy-asahi-cache/.SRCINFO').unlink()
  with self.assertRaises(FileNotFoundError):P.emit(ROOT,copyroot,self.root/'absent')
  self.assertFalse((self.root/'absent').exists())
  pins=json.loads((P.HERE/'source-pins.json').read_bytes());del pins['groups']['composition']['packages/tools/cachy-asahi-apps/apps.py']
  with patch.object(P.json,'loads',return_value=pins),self.assertRaisesRegex(ValueError,'recipe/provenance closure'):P.source(ROOT,COMP)
 def test_original_workflow_controls_are_closed_and_byte_pinned(self):
  out,_,_=self.emit();pins=json.loads((P.HERE/'source-pins.json').read_bytes());rows=pins['workflow_control_inputs'];self.assertEqual(len(rows),9)
  for n,row in rows.items():self.assertEqual(P.pin((out/n).read_bytes()),row)
  self.assertEqual({p.name for p in (out/'scripts/ci/expanded600-installer-vm').glob('test_*.py')},{'test_source.py','test_observer600.py'})
  text=(out/P.WF).read_text()
  for name in ('PUBLIC_PAIR_INSTALLER_ROOT','PUBLIC_PAIR_COMPOSITION_ROOT'):self.assertIn(name+': ${{ github.workspace }}/expanded604-installer',text)
  self.assertIn("python3 -B -m unittest discover -s expanded604-installer/scripts/ci/expanded600-installer-vm -p 'test_*.py' -v",text)
  self.assertIn("python3 -B -m unittest discover -s expanded604-installer/scripts/ci/expanded604-apps6-public-pair-installer -p 'test_*.py' -v",text)
 def test_drift_alias_and_missing_anchors_refuse(self):
  with patch.object(P,'pin',return_value={}):
   with self.assertRaisesRegex(ValueError,'pinned source'):P.emit(ROOT,COMP,self.root/'absent')
  self.assertFalse((self.root/'absent').exists())
  alias=self.root/'alias';alias.symlink_to(ROOT,target_is_directory=True)
  with self.assertRaisesRegex(ValueError,'aliases'):P.emit(alias,COMP,self.root/'absent')
  with self.assertRaises(ValueError):P.adapt(b'wrong source','contract.py')
if __name__=='__main__':unittest.main(verbosity=2)
