# SPDX-License-Identifier: MIT
"""Public ordinary source fixtures; complete emissions and prewrite refusals."""
import importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));import prepare as P
BASE=Path(os.environ['FRESH607_DIAGNOSTIC_INPUT']);EXPECTED=Path(os.environ['FRESH607_DIAGNOSTIC_EXPECTED'])
def load(path):
 s=importlib.util.spec_from_file_location('_private_factory',path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.old=P.source(BASE);cls.expected=P.source(EXPECTED);cls.p=P.settings();assert{n:P.pin(b)for n,b in cls.expected.items()}==P.decode(P.read(HERE/'output-source.json'))
 def setUp(self):self.temp=tempfile.TemporaryDirectory(prefix='producer-factory-');self.work=Path(self.temp.name)
 def tearDown(self):self.temp.cleanup()
 def test_real_cli_known_null_exact_and_whole1182_source_entry(self):
  for context in('known','null'):
   out=self.work/context;auth=self.work/(context+'.json');r=subprocess.run([sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--source',str(BASE),'--output',str(out),'--authorization',str(auth),'--context',context],capture_output=True,timeout=30);self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(P.source(out),self.expected);v=P.decode(auth.read_bytes());self.assertTrue(all(v[n]is None for n in('source','ref','run','actual')));self.assertFalse(v['native_acceptance']);self.assertEqual(v['public_output_source'],self.p['output_source']if context=='known'else None)
  r=subprocess.run([sys.executable,'-I','-B','-Werror',str(self.work/'known/implementation/run.py'),'--source-preflight'],capture_output=True,timeout=300,env={k:v for k,v in os.environ.items()if k not in('GH_TOKEN','GITHUB_TOKEN','PYTHONPATH','PYTHONHOME')});self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stderr,b'');v=P.decode(r.stdout);self.assertEqual(v['files'],1185);self.assertEqual(v['parent_files'],1182);self.assertIsNone(v['actual_run']);self.assertEqual(P.source(self.work/'known'),self.expected)
 def test_whole_run_inverse_all1177_held_and_failure_only_role(self):
  G=P.helper();out=P.render(self.old,self.p);self.assertEqual(out,self.expected);changed={n for n in self.old if out[n]!=self.old[n]};self.assertEqual(changed,{G.RUN,G.GUARD,G.MANIFEST,*G.ALIASES});self.assertEqual(len(self.old)-len(changed),1177)
  text=out[G.RUN].decode()
  for before,after in reversed(G.EDITS):self.assertEqual(text.count(after),1);text=text.replace(after,before,1)
  self.assertEqual(text.encode(),self.old[G.RUN]);self.assertEqual(out[G.GUARD][:-len(G.FOOTER)],self.old[G.GUARD]);self.assertEqual(out['implementation/workflow-template.yml'],self.old['implementation/workflow-template.yml']);self.assertEqual(out[G.HELPER],P.read(HERE/'producer_diagnostic.py'))
  parent=P.decode(out[G.PARENT]);self.assertEqual(parent['before'],parent['parent_git']['files']);self.assertEqual(parent['before'],parent['parent_authorization']);self.assertTrue(all(parent[k]is None for k in('actual_source','actual_ref','actual_run')))
 def test_wrong_source_foreign_nested_git_mutation_hardlink_alias_before_write(self):
  out=self.work/'absent';auth=self.work/'absent.json'
  with self.assertRaises(ValueError):P.prepare(EXPECTED,out,auth,'known')
  source=self.work/'input';shutil.copytree(BASE,source,ignore=shutil.ignore_patterns('.git'));foreign=source/'foreign';foreign.write_bytes(b'x')
  with self.assertRaises(ValueError):P.prepare(source,out,auth,'known')
  foreign.unlink();(source/'nested/.git').mkdir(parents=True)
  with self.assertRaises(ValueError):P.source(source)
  shutil.rmtree(source/'nested');name=next(iter(self.old));target=source/name;target.write_bytes(target.read_bytes()+b'\n')
  with self.assertRaises(ValueError):P.prepare(source,out,auth,'known')
  target.write_bytes(self.old[name]);os.link(target,self.work/'hardlink')
  with self.assertRaises(ValueError):P.source(source)
  (self.work/'hardlink').unlink();alias=self.work/'alias';alias.symlink_to(source,target_is_directory=True)
  with self.assertRaises(ValueError):P.prepare(alias,out,auth,'known')
  self.assertFalse(out.exists());self.assertFalse(auth.exists())
 def test_paths_normalization_disjoint_alias_existing_and_context(self):
  out=self.work/'out';auth=self.work/'auth.json'
  for a,b in((BASE/'new',auth),(HERE/'new',auth),(out,out/'auth'),(out,BASE/'new.json'),(out,out),(self.work/'x/../out',auth),(Path('relative'),auth),(self.work,auth),(self.work/'future-native-actual-20990101/out',auth)):
   with self.assertRaises(ValueError):P.paths(BASE,a,b)
  alias=self.work/'alias';alias.symlink_to(BASE,target_is_directory=True)
  with self.assertRaises(ValueError):P.paths(BASE,alias/'out',auth)
  for context in('',True,'accepted'):
   with self.assertRaises(ValueError):P.prepare(BASE,out,auth,context)
  self.assertFalse(out.exists());self.assertFalse(auth.exists())
 def test_profile_payload_clocks_and_late_input_drift(self):
  factory=self.work/'factory';shutil.copytree(HERE,factory);m=load(factory/'prepare.py');(factory/'producer_diagnostic.py').write_bytes(b'# drift')
  with self.assertRaises(ValueError):m.settings()
  shutil.copyfile(HERE/'producer_diagnostic.py',factory/'producer_diagnostic.py');p=P.decode((factory/'profile.json').read_bytes());p['clocks']['build']=5401;raw=P.enc(p);(factory/'profile.json').write_bytes(raw);m.PROFILE_SHA=P.pin(raw)['sha256']
  with self.assertRaises(ValueError):m.settings()
  # A resealed local metadata change must still fail the exact decode/input join.
  codecs=P.decode((HERE/'parent-codecs.json').read_bytes());name=next(iter(codecs));codecs[name]=__import__('base64').b64encode(__import__('zlib').compress(b'foreign')).decode()
  original=P.read
  def foreign(path,*args):return P.enc(codecs)if path==HERE/'parent-codecs.json'else original(path,*args)
  with patch.object(P,'read',side_effect=foreign),self.assertRaisesRegex(ValueError,'parent codec DATA'):P.render(self.old,self.p)
  calls=[]
  def changing(root):calls.append(1);return self.old if len(calls)==1 else dict(self.old,foreign=b'x')
  out=self.work/'absent';auth=self.work/'absent.json'
  with patch.object(P,'source',side_effect=changing),self.assertRaisesRegex(ValueError,'late source'):P.prepare(BASE,out,auth,'known')
  self.assertFalse(out.exists());self.assertFalse(auth.exists())
 def test_guard_refuses_product_drift_and_is_portable(self):
  out=self.work/'out';P.prepare(BASE,out,self.work/'auth.json','null');(out/'implementation/run.py').write_bytes((out/'implementation/run.py').read_bytes()+b'\n# drift\n');r=subprocess.run([sys.executable,'-I','-B','-Werror',str(out/'implementation/run.py'),'--source-preflight'],capture_output=True,timeout=30);self.assertNotEqual(r.returncode,0)
  for path in HERE.iterdir():
   if path.is_file():self.assertNotIn(b'/home/'+b'gabe/',path.read_bytes());self.assertNotIn(b'artifacts/'+b'development/',path.read_bytes())
  self.assertEqual(self.p['clocks'],P.CLOCKS);self.assertFalse(self.p['native_acceptance'])
if __name__=='__main__':unittest.main(verbosity=2)
