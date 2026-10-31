# SPDX-License-Identifier: MIT
"""Eleven controls on actual emitted557 source, never on native retained code."""
import argparse,base64,copy,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;p=argparse.ArgumentParser()
for n in('parent','expected','carrier','recipe','native'):p.add_argument('--'+n,type=Path,required=True)
a,rest=p.parse_known_args();PARENT,EXPECTED,CARRIER,RECIPE,NATIVE=(getattr(a,n).absolute()for n in('parent','expected','carrier','recipe','native'));sys.dont_write_bytecode=True
def load(name,path):s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
F=load('_actual_Apps9_GUI_factory',HERE/'prepare.py');M=load('_actual_Apps9_assembler',HERE/'apps9.py');PROFILE,MAPS,_=M.inputs(F.__dict__)
class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.temp=tempfile.TemporaryDirectory();cls.root=Path(cls.temp.name);cls.bound=cls.root/'bound';cls.null=cls.root/'null';F.prepare_apps9(PARENT,cls.bound);F.prepare_apps9(PARENT,cls.null,True);cls.C=load('_actual_apps9_common',cls.bound/'apps9_common.py');cls.A=load('_actual_apps9_admission',cls.bound/'admission.py');cls.N=load('_NULL_apps9_admission',cls.null/'admission.py')
 @classmethod
 def tearDownClass(cls):cls.temp.cleanup()
 def test_01_whole557_NULL_context_and_before_actor_gate(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTOR_API_GIT')),patch.object(subprocess,'run',side_effect=AssertionError('NO_CHILD')):
   self.assertEqual(self.N.source_context(self.null)['Apps9_inputs'],'UNBOUND')
   with self.assertRaisesRegex(ValueError,'BEFORE ACTORS'):self.N.prove(self.null)
 def test_02_actual_NULL_native_proof_and_run_before_owner(self):
  with patch.dict(sys.modules,{'admission':self.N}):N=load('_actual_NULL_native',self.null/'native.py')
  state=self.root/'no-owner'
  with patch.object(N,'original',side_effect=AssertionError('NO_ORIGINAL_ACTOR')),patch.object(N,'factory',side_effect=AssertionError('NO_FACTORY_ACTOR')):
   with self.assertRaisesRegex(ValueError,'BEFORE ACTORS'):N.proof('minimal-generic4k',state,{})
   with self.assertRaisesRegex(ValueError,'BEFORE ACTORS'):N.run('minimal-generic4k',state,*([Path('/not-used')]*8),[])
  self.assertFalse(state.exists())
 def test_03_actual_installed_helper_identity_mutation_link_refusals(self):
  C=self.C;helper=load('_actual_installed9',self.bound/'factory/apps9_runtime.py');profile=C.obj(self.bound/'factory/apps9-installed-profile.json')
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)
   for n,w in profile['payload'].items():
    q=root/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(C.read(RECIPE/'packages/tools/cachy-asahi-apps9'/Path(n).name));q.chmod(profile['modes'][n]);self.assertEqual(C.pin(q.read_bytes()),w)
   for n,w in profile['runtime'].items():
    q=root/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(C.read(RECIPE/n.split('/repository-runtime/',1)[1]));self.assertEqual(C.pin(q.read_bytes()),w)
   before=helper.observe(root);self.assertEqual(helper.validate(before,helper.observe(root))['version'],'0.1.0-9');leaf=root/'usr/lib/cachy-asahi-apps/inventory.py';raw=leaf.read_bytes();leaf.write_bytes(raw+b'drift')
   with self.assertRaises(ValueError):helper.observe(root)
   leaf.write_bytes(raw[:-1]+bytes([raw[-1]^1]))
   with self.assertRaises(ValueError):helper.observe(root)
   leaf.unlink();holder=root/'holder';holder.write_bytes(raw);leaf.symlink_to(holder)
   with self.assertRaises(ValueError):helper.observe(root)
   leaf.unlink();os.link(holder,leaf)
   with self.assertRaises(ValueError):helper.observe(root)
 def test_04_all_other_inputs_Welcome_clocks_and_methods_held(self):
  old=self.C.obj(PARENT/'input-policy33.json')['packages'];new=self.C.obj(self.bound/'input-policy33.json')['packages'];self.assertEqual({n:v for n,v in old.items()if n!='cachy-asahi-apps'},{n:v for n,v in new.items()if n!='cachy-asahi-apps'})
  for n in('native.py','input606.py','factory/factory.py','factory/current_products.py'):self.assertEqual((self.bound/n).read_text().replace('Apps9','Apps8').replace('APPS9','APPS8').replace('apps9','apps8'),(PARENT/n).read_text())
  for n in('factory/run.py','factory/context606.py','bootstrap2.py','welcome8-parent.json','factory/original606.lock'):self.assertEqual((self.bound/n).read_bytes(),(PARENT/n).read_bytes())
 def test_05_full_before_bodies_538held_exact_inverse(self):
  p=self.C.obj(self.bound/'apps9-parent.json');self.assertEqual(p['files'],MAPS['before']);self.assertEqual(p['source'],'51e7797ef639de8fbed96e51b5b12bf5a92c7cb7')
  for n,b in p['before_bodies'].items():self.assertEqual(base64.b64decode(b,validate=True),(PARENT/n).read_bytes())
  before=F.files(PARENT);after=F.files(self.bound);self.assertEqual(sum(n in after and before[n]==after[n]for n in before),538)
 def test_06_original_four_command_failure_transport_controls(self):
  r=subprocess.run([sys.executable,'-I','-B','-Werror',str(self.bound/'apps9_common.py')],capture_output=True,timeout=60);self.assertEqual(r.returncode,0,r.stderr);self.assertIn(b'Ran 4 tests',r.stderr)
 def test_07_postemission_full_source_drift_refused(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)/'source';shutil.copytree(self.bound,root);leaf=root/'factory/run.py';leaf.write_bytes(leaf.read_bytes()+b'drift');A=load('_bad_apps9_source',root/'admission.py')
   with self.assertRaises(ValueError):A.prove(root)
 def test_08_whole_genuine93_index_acceptance_and_old_role_refusals(self):
  C=self.C;s=PROFILE['selection']['selection'];C.closed(CARRIER,s['files']);index=C.obj(CARRIER/'index.json');acceptance=C.obj(CARRIER/index['acceptance']);self.assertEqual(C.index_check(index,s['files'],C.obj(self.bound/'apps9-recipe-map.json'),acceptance),s['package'])
  for key,v in(('status','EXACT_ACCEPTED_APPS8_PAIR_INPUT_DATA_ONLY'),('source','0'*40),('run',39727987029),('recipe_prefix','wrong')):
   bad=copy.deepcopy(index);bad[key]=v
   with self.assertRaises(ValueError):C.index_check(bad,s['files'],C.obj(self.bound/'apps9-recipe-map.json'),acceptance)
 def test_09_actual_bound_full_source_admission_and_isolated_CLI(self):
  fact=self.A.prove(self.bound);self.assertEqual((fact['files'],fact['Apps9_inputs'],fact['native_GUI']),(557,'ROOT_BOUND_INPUT_ONLY','NOT_RUN'));r=subprocess.run([sys.executable,'-I','-B','-Werror',str(self.bound/'native.py'),'preflight'],capture_output=True,timeout=30);self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(json.loads(r.stdout)['native_GUI'],'NOT_RUN')
 def test_10_whole557_exact_expected_and_NULL_maps(self):
  self.assertEqual({n:F.pin(b)for n,b in F.files(self.bound).items()},MAPS['selected']);self.assertEqual({n:F.pin(b)for n,b in F.files(EXPECTED).items()},MAPS['selected']);self.assertEqual({n:F.pin(b)for n,b in F.files(self.null).items()},MAPS['unbound']);self.assertIsNone(self.C.obj(self.null/'input-policy33.json')['packages']['cachy-asahi-apps']['sha256'])
 def test_11_registered_alias_whole_argv_checksum_and_limits(self):
  old=(PARENT/M.WF).read_text();expected=old.replace('Apps8','Apps9').replace('APPS8','APPS9').replace('apps8','apps9').replace('979b2d6ec7417e607a911d8c25bef2f1f7f72dcb','128b9806c8e972a729d5c1ef4f2dc9e39e48fc42');self.assertEqual((self.bound/M.WF).read_text(),expected);self.assertEqual((self.bound/M.ALIAS).read_text(),expected);self.assertIn('sha256sum --check',expected);p=self.C.obj(self.bound/'factory/apps9-installed-profile.json');self.assertEqual((p['GUI_command_limit_seconds'],p['inventory_limit_seconds'],p['required_fresh_scans']),(35,30,2));self.assertIn("'--dbpath','/var/lib/pacman'",(self.bound/'factory/current_products.py').read_text())
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
