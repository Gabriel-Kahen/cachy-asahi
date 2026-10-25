# SPDX-License-Identifier: MIT
"""Portable exact-source/namespace controls; no installed or native authority."""
import contextlib,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('updater_tooling_factory',HERE/'prepare.py')
K=importlib.util.module_from_spec(spec);spec.loader.exec_module(K)
P,F,E,S=(Path(os.environ['UPDATER_TOOLING_'+n]).resolve()for n in('PARENT','FRESH','EXPECTED','SOURCE'))
@contextlib.contextmanager
def modules():
 old,path=dict(sys.modules),list(sys.path)
 try:
  sys.path.insert(0,str(S/'implementation'))
  for n in('common','namespace_context','adapter','baseline','runtime','source_guard','authority'):
   sys.modules.pop(n,None)
  import common,namespace_context,source_guard,authority
  yield common,namespace_context,source_guard,authority
 finally:
  sys.modules.clear();sys.modules.update(old);sys.path[:]=path

class Controls(unittest.TestCase):
 def test_01_complete_public_reproduction_and_entire_inverse(self):
  before=dict(sys.modules);path=list(sys.path)
  out,_,_=K.render(P,F)
  self.assertEqual(out,K.tree(E));self.assertEqual(K.tree(S),out)
  self.assertEqual(before,dict(sys.modules));self.assertEqual(path,sys.path)
  changed={n for n in out if K.read(P/n)!=out[n]}
  self.assertEqual(changed,set(json.loads(K.read(HERE/'profile.json'))['changed']))
  self.assertEqual(len(out)-len(changed),351)
 def test_02_real_cli_known_null_same_bytes_authority_null(self):
  with tempfile.TemporaryDirectory(prefix='portable-updater357-')as td:
   for context in('known','null'):
    out=Path(td)/context
    v=subprocess.run([sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),
        '--parent',str(P),'--fresh',str(F),'--output',str(out),'--context',context],capture_output=True,timeout=60)
    self.assertEqual(v.returncode,0,v.stderr.decode());self.assertEqual(v.stderr,b'')
    r=json.loads(v.stdout);self.assertEqual(K.tree(out),K.tree(E));self.assertEqual(r['receipt_context'],context)
    self.assertEqual(r['publication_assertion']is None,context=='null')
    self.assertTrue(all(r[k]is None for k in('actual_source','actual_ref','actual_run','fresh607','baseline607','Root_acceptance')))
 def test_03_current357_355_208_guard_and_apps6_target(self):
  with modules()as(C,N,G,A):
   self.assertEqual(N.verify357(),dict(files=357,held=351,changed=6,added=0))
   self.assertEqual(N.verify()['held'],350);self.assertEqual(G.verify()['python_bodies'],208)
   a,b=C.locks();self.assertEqual(a['cachy-asahi-apps'],'0.1.0-6');self.assertEqual(b['cachy-asahi-apps'],'0.1.0-16')
   self.assertEqual(a['cachy-asahi-repository-runtime'],'0.1.0-1');self.assertEqual({n for n in a if a[n]!=b[n]},{'cachy-asahi-apps'})
   p=C.profile();self.assertEqual(p['authorities'],{'fresh607':None,'baseline607':None});self.assertIsNone(p['authority_files'])
   with self.assertRaisesRegex(ValueError,'UNBOUND'):A.require_bound()
 def test_04_real_pinned1197_source_cli_namespace_preserved(self):
  with modules()as(C,N,G,A):
   before,path=dict(sys.modules),list(sys.path)
   fact=N.fresh(F)
   self.assertEqual(fact['files'],1197);self.assertEqual(fact['parent_files'],1192)
   self.assertEqual(fact['fresh607'],'NOT_RUN');self.assertEqual(fact['status'],'PASS_SOURCE_ONLY_EXACT_ORIGINAL35_TOOLING_INPUT_PREPARATION')
   self.assertEqual(before,dict(sys.modules));self.assertEqual(path,sys.path)
 def test_05_wrong_source_drift_alias_refuse_before_child_or_output(self):
  with modules()as(C,N,G,A),patch.object(N.subprocess,'Popen',side_effect=AssertionError('no foreign child')):
   with self.assertRaises(ValueError):N.fresh(P)
   with tempfile.TemporaryDirectory(prefix='foreign-updater-source-')as td:
    root=Path(td);alias=root/'alias';alias.symlink_to(F,target_is_directory=True)
    with self.assertRaises(ValueError):N.fresh(alias)
    private=root/'fresh';shutil.copytree(F,private)
    (private/'implementation/tooling_source.py').write_bytes(K.read(private/'implementation/tooling_source.py')+b'\n# foreign\n')
    with self.assertRaises(ValueError):N.fresh(private)
    with self.assertRaises(ValueError):K.build(P,private,root/'output')
    self.assertFalse((root/'output').exists())
 def test_06_canonical_disjoint_fresh_destinations_before_writes(self):
  with tempfile.TemporaryDirectory(prefix='updater-paths-')as td:
   root=Path(td);existing=root/'existing';existing.mkdir()
   for out in(existing,P/'child',F/'child',HERE/'child',P.parent,
               root/'native-actual'/'child'):
    with self.assertRaises(ValueError):K.paths(P,F,out)
   for raw in(str(root/'a')+'/../out',str(root/'a')+'/./out','relative'):
    with self.assertRaises(ValueError):K.paths(P,F,raw)
   alias=root/'alias';alias.symlink_to(F,target_is_directory=True)
   with self.assertRaises(ValueError):K.paths(P,alias,root/'out')
   with self.assertRaises(ValueError):K.build(P,F,root/'out','foreign')
   self.assertFalse((root/'out').exists())
 def test_07_late_input_identity_refusal_before_any_output(self):
  with tempfile.TemporaryDirectory(prefix='updater-late-')as td:
   out=Path(td)/'out';real=K.scan;count=[0]
   def drift(root):
    rows,state=real(root)
    if root==F:
     count[0]+=1
     if count[0]>1:state=dict(state,foreign=True)
    return rows,state
   with patch.object(K,'scan',side_effect=drift):
    with self.assertRaisesRegex(ValueError,'late'):K.build(P,F,out)
   self.assertFalse(out.exists())
 def test_08_stable_fd_refusals_and_unchanged_runtime_bodies(self):
  with tempfile.TemporaryDirectory(prefix='updater-fd-')as td:
   root=Path(td);f=root/'data';f.write_bytes(b'whole');link=root/'link';os.link(f,link)
   with self.assertRaises(ValueError):K.read(f)
   link.unlink();self.assertEqual(K.read(f),b'whole')
   alias=root/'alias';alias.symlink_to(f)
   with self.assertRaises(ValueError):K.read(alias)
   fifo=root/'fifo';os.mkfifo(fifo)
   with self.assertRaises(ValueError):K.read(fifo)
  for n in('baseline.py','runtime.py','adapter.py','selected_package.py','common.py','cache.py','authority.py'):
   self.assertEqual(K.read(S/'implementation'/n),K.read(P/'implementation'/n))
  self.assertEqual(K.read(S/'entry.py'),K.read(P/'entry.py'))

if __name__=='__main__':
 suite=unittest.defaultTestLoader.loadTestsFromTestCase(Controls);assert suite.countTestCases()==8
 raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
