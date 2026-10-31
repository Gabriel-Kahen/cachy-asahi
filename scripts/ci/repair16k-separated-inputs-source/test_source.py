# SPDX-License-Identifier: MIT
"""Public fixtures only; exact emissions and source/constructor refusals."""
import ast,copy,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));import prepare as P
BASE=Path(os.environ['REPAIR_SEPARATED_INPUT_SOURCE']);EXPECTED=Path(os.environ['REPAIR_SEPARATED_EXPECTED_SOURCE'])
def load(path):
 s=importlib.util.spec_from_file_location('_portable_factory_control',path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.old=P.source(BASE);cls.expected=P.source(EXPECTED);cls.p=P.settings();assert{n:P.pin(v)for n,v in cls.old.items()}==P.decode(P.read(HERE/'input-source.json'));assert{n:P.pin(v)for n,v in cls.expected.items()}==P.decode(P.read(HERE/'output-source.json'))
 def setUp(self):self.tmp=tempfile.TemporaryDirectory(prefix='separated-factory-');self.work=Path(self.tmp.name)
 def tearDown(self):self.tmp.cleanup()
 def test_actual_cli_known_null_exact_and_complete239_guard(self):
  for context in('known','null'):
   output=self.work/context;authorization=self.work/(context+'.json');r=subprocess.run([sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--source',str(BASE),'--output',str(output),'--authorization',str(authorization),'--context',context],capture_output=True,timeout=30);self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(P.source(output),self.expected)
   v=P.decode(authorization.read_bytes());self.assertTrue(all(v[n]is None for n in('source','ref','run','actual')));self.assertFalse(v['native_acceptance']);self.assertEqual(v['public_output_source'],self.p['output_source']if context=='known'else None)
  r=subprocess.run([sys.executable,'-I','-B','-Werror',str(self.work/'known/apps16-repair/entry.py'),'--require-selection'],capture_output=True,timeout=30);self.assertEqual(r.returncode,0,r.stderr);v=P.decode(r.stdout);self.assertEqual(v['source_files'],239);self.assertIsNone(v['actual'])
 def test_whole237_inverse_runtime229_and_all_workflow_operands(self):
  result=P.render(self.old,self.p);self.assertEqual(result,self.expected);G=P.helper();changed={n for n in self.old if self.old[n]!=result[n]};self.assertEqual(changed,{G.PREPARE,G.SELECTION,G.SUCCESSOR,*G.MANIFESTS,*G.WORKFLOWS});self.assertEqual(len(self.old)-len(changed),229)
  out=self.work/'source';P.prepare(BASE,out,self.work/'auth.json','known');guard=load(out/G.GUARD);profile=guard.profile(out);self.assertEqual(guard.bodies(out,profile),self.old)
  functions=lambda raw:{n.name:ast.get_source_segment(raw.decode(),n)for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
  a,b=functions(self.old[G.PREPARE]),functions(result[G.PREPARE]);self.assertEqual([n for n in a if a[n]!=b[n]],['_retained_workflow'])
  wf=result[G.WORKFLOWS[0]].decode();self.assertEqual(result[G.WORKFLOWS[0]],result[G.WORKFLOWS[1]])
  for n,count in zip(G.NAMES,(3,3,4,1)):
   self.assertEqual(wf.count('          path: '+n+'\n'),1);self.assertNotIn('repair-source/'+n,wf);self.assertEqual(wf.count('$GITHUB_WORKSPACE/'+n),count+(2 if n=='retained-public-inputs'else 0))
  for n in('seed.py','index.json'):self.assertIn('"$GITHUB_WORKSPACE/retained-public-inputs/'+n+'"',wf)
  for n in('apps16-repair/inspect_source.py','apps16-repair/inspect-profile.json','scripts/ci/apps7-full574-repair16k/adapter.py'):self.assertEqual(result[n],self.old[n])
 def test_wrong_source_mutation_foreign_alias_and_hardlink_prewrite(self):
  output=self.work/'absent';authorization=self.work/'absent.json'
  with self.assertRaises(ValueError):P.prepare(EXPECTED,output,authorization,'known')
  source=self.work/'input';shutil.copytree(BASE,source,ignore=shutil.ignore_patterns('.git'));foreign=source/'foreign';foreign.write_bytes(b'foreign')
  with self.assertRaises(ValueError):P.prepare(source,output,authorization,'known')
  foreign.unlink();(source/'nested').mkdir();(source/'nested/.git').mkdir()
  with self.assertRaises(ValueError):P.source(source)
  shutil.rmtree(source/'nested');name=next(iter(self.old));target=source/name;target.write_bytes(target.read_bytes()+b'\n')
  with self.assertRaises(ValueError):P.prepare(source,output,authorization,'known')
  target.write_bytes(self.old[name]);outside=self.work/'hardlink';os.link(target,outside)
  with self.assertRaises(ValueError):P.source(source)
  outside.unlink();alias=self.work/'alias';alias.symlink_to(source,target_is_directory=True)
  with self.assertRaises(ValueError):P.prepare(alias,output,authorization,'known')
  self.assertFalse(output.exists());self.assertFalse(authorization.exists())
 def test_canonical_disjoint_output_authorization_and_context(self):
  output=self.work/'output';authorization=self.work/'auth.json'
  for out,auth in((BASE/'fresh',authorization),(HERE/'fresh',authorization),(output,output/'auth'),(output,BASE/'new.json'),(output,output),(self.work/'x/../out',authorization),(Path('relative'),authorization),(self.work,authorization),(self.work/'future-native-actual-20990101/out',authorization)):
   with self.assertRaises(ValueError):P.paths(BASE,out,auth)
  alias=self.work/'alias';alias.symlink_to(BASE,target_is_directory=True)
  with self.assertRaises(ValueError):P.paths(BASE,alias/'out',authorization)
  for context in('',True,'selected'):
   with self.assertRaises(ValueError):P.prepare(BASE,output,authorization,context)
  self.assertFalse(output.exists());self.assertFalse(authorization.exists())
 def test_maintained_profile_payload_clock_and_late_input_drift(self):
  root=self.work/'factory';shutil.copytree(HERE,root,ignore=shutil.ignore_patterns('__pycache__'));m=load(root/'prepare.py');(root/'separated_source.py.in').write_bytes((root/'separated_source.py.in').read_bytes()+b'\n')
  with self.assertRaises(ValueError):m.settings()
  shutil.copyfile(HERE/'separated_source.py.in',root/'separated_source.py.in');p=P.decode((root/'profile.json').read_bytes());p['clocks']['backend']=601;raw=P.enc(p);(root/'profile.json').write_bytes(raw);m.PROFILE_SHA=P.pin(raw)['sha256']
  with self.assertRaises(ValueError):m.settings()
  output=self.work/'absent';authorization=self.work/'absent.json';calls=[]
  def changing(root):calls.append(1);return self.old if len(calls)==1 else dict(self.old,foreign=b'x')
  with patch.object(P,'source',side_effect=changing),self.assertRaisesRegex(ValueError,'late source'):P.prepare(BASE,output,authorization,'known')
  self.assertFalse(output.exists());self.assertFalse(authorization.exists())
 def test_null_context_has_no_authority_and_factory_is_portable(self):
  self.assertTrue(all(self.p[n]is None for n in('source','ref','run','actual')));self.assertEqual(self.p['clocks'],P.CLOCKS);self.assertFalse(self.p['native_acceptance'])
  for name in('prepare.py','profile.json','input-source.json','output-source.json','separated_source.py.in'):
   raw=(HERE/name).read_bytes();self.assertNotIn(b'artifacts/development/',raw);self.assertNotIn(b'/home/gabe/',raw);self.assertNotIn(b'release-freeze.json',raw)
  p=P.prepare(BASE,self.work/'null',self.work/'null.json','null');self.assertIsNone(p['public_output_source']);self.assertEqual(p['files'],P.decode(P.read(HERE/'output-source.json')))
if __name__=='__main__':unittest.main(verbosity=2)
