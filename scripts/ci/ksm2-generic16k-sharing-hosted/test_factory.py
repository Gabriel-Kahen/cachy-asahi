# SPDX-License-Identifier: MIT
"""Whole-source emitter/refusal controls. Requires an exact scalar605 runtime."""
import ast, copy, importlib.util, io, json, os, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('_sharing_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
RUNTIME=Path(os.environ['KSM_SHARING_SCALAR_RUNTIME']).absolute()

def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def emitter(path,runtime,output,binding=None):
 saved=sys.path[:];old=sys.modules.pop('hosted',None)
 try:
  module=load('_held_original_emitter',path)
  return module.assemble(runtime,output,binding)
 finally:
  sys.path[:]=saved;sys.modules.pop('hosted',None)
  if old is not None:sys.modules['hosted']=old

class Factory(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.profile=F.profile();cls.default,_,_=F.render(RUNTIME)
 def test_real_relatime_read_and_metadata_drift(self):
  # A first read may change atime on the native runner. It cannot change identity/content.
  with tempfile.TemporaryDirectory(prefix='ksm-source-atime-',dir='/dev/shm')as directory:
   path=Path(directory)/'source';path.write_bytes(b'complete unchanged source\n');mtime=path.stat().st_mtime_ns;os.utime(path,ns=(1,mtime));before=path.stat()
   self.assertEqual(F.read(path),b'complete unchanged source\n');after=path.stat()
   self.assertGreater(after.st_atime_ns,before.st_atime_ns);self.assertEqual(F.stable_identity(after),F.stable_identity(before));self.assertNotEqual(after,before)
   original=Path.read_bytes
   def changed_mode(target):
    raw=original(target);target.chmod(0o640);return raw
   with patch.object(Path,'read_bytes',changed_mode):
    with self.assertRaisesRegex(ValueError,'source drift'):F.read(path)
 def test_default_emitter_exact628_and_all_actual_selectors_null(self):
  with tempfile.TemporaryDirectory()as directory:
   out=Path(directory)/'source'
   with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')):result=F.assemble(RUNTIME,out)
   self.assertEqual({n:F.pin(raw)for n,raw in F.files(out).items()},self.profile['expected_sources']['default'])
   policy=F.decode((out/F.LANE/'input-policy.json').read_bytes())
   for key in('native_carrier','kernel_carrier','native_decision','native_inputs','kernel_authority','kernel_transport','kernel_build','kernel_run','actual_source','actual_ref','actual_run'):self.assertIsNone(policy[key])
   self.assertEqual((result['files'],result['whole_runtime_files']),(628,608));self.assertEqual(result['acceptance'],'NOT_GRANTED')
 def test_explicit_root_selected_emitter_exact628(self):
  with tempfile.TemporaryDirectory()as directory:
   path=Path(directory);binding=path/'selection.json';binding.write_bytes(F.encoded(self.profile['policies']['selected']));out=path/'source'
   with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')):result=F.assemble(RUNTIME,out,binding)
   self.assertEqual({n:F.pin(raw)for n,raw in F.files(out).items()},self.profile['expected_sources']['selected']);self.assertEqual(result['view'],'selected')
 def test_emitted_exact_original608_factory_self_reproduces(self):
  for view in('default','selected'):
   with self.subTest(view=view),tempfile.TemporaryDirectory()as directory:
    path=Path(directory);binding=None
    if view=='selected':binding=path/'selection';binding.write_bytes(F.encoded(self.profile['policies']['selected']))
    first=path/'first';F.assemble(RUNTIME,first,binding);second=path/'second'
    with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')):emitter(first/F.LANE/'prepare.py',first/'runtime',second,binding)
    self.assertEqual(F.files(first),F.files(second))
 def test_ordinary605_factory_stays_scalar_and_self_reproduces(self):
  with tempfile.TemporaryDirectory()as directory:
   path=Path(directory);out=path/'scalar'
   with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')):result=emitter(F.SCALAR/'prepare.py',RUNTIME,out)
   self.assertEqual(result['whole_runtime_files'],605);self.assertFalse((out/'runtime/sharing.py').exists())
   again=path/'again';emitter(out/F.LANE/'prepare.py',out/'runtime',again);self.assertEqual(F.files(out),F.files(again))
 def test_wrong_runtime_refuses_before_output(self):
  with tempfile.TemporaryDirectory()as directory:
   path=Path(directory);runtime=path/'runtime';runtime.mkdir();(runtime/'sharing.py').write_bytes(b'foreign');out=path/'source'
   with self.assertRaisesRegex(ValueError,'whole scalar605'):F.assemble(runtime,out)
   self.assertFalse(out.exists())
 def test_changed_full_runtime_refuses_before_output(self):
  with tempfile.TemporaryDirectory()as directory:
   path=Path(directory);runtime=path/'runtime';shutil.copytree(RUNTIME,runtime);(runtime/'host.py').write_bytes(b'foreign');out=path/'source'
   with self.assertRaisesRegex(ValueError,'whole scalar605'):F.assemble(runtime,out)
   self.assertFalse(out.exists())
 def test_profile_or_runtime_delta_tamper_refuses_before_output(self):
  for leaf in('profile.json','runtime/sharing.py','templates/hosted.py'):
   with self.subTest(leaf=leaf),tempfile.TemporaryDirectory()as directory:
    path=Path(directory);factory=path/'factory';shutil.copytree(HERE,factory);changed=factory/leaf;changed.write_bytes(changed.read_bytes()+b' ');out=path/'source'
    with patch.object(F,'HERE',factory),self.assertRaises(ValueError):F.assemble(RUNTIME,out)
    self.assertFalse(out.exists())
 def test_selected_actual_identity_and_missing_selectors_refuse_before_output(self):
  for key,value in(('actual_source','0'*40),('actual_ref','codex/unreviewed'),('actual_run',1),('kernel_carrier',None),('native_carrier',None),('kernel_run',True)):
   with self.subTest(key=key),tempfile.TemporaryDirectory()as directory:
    path=Path(directory);policy=copy.deepcopy(self.profile['policies']['selected']);policy[key]=value;binding=path/'selection';binding.write_bytes(F.encoded(policy));out=path/'source'
    with self.assertRaises(ValueError):F.assemble(RUNTIME,out,binding)
    self.assertFalse(out.exists())
 def test_unreviewed_valid_selection_still_refuses_before_output(self):
  with tempfile.TemporaryDirectory()as directory:
   path=Path(directory);policy=copy.deepcopy(self.profile['policies']['selected']);policy['kernel_carrier']='0'*40;binding=path/'selection';binding.write_bytes(F.encoded(policy));out=path/'source'
   with self.assertRaisesRegex(ValueError,'reviewed Root selection'):F.assemble(RUNTIME,out,binding)
   self.assertFalse(out.exists())
 def test_ordinary_read_refuses_symlink_hardlink_and_duplicate_json(self):
  with tempfile.TemporaryDirectory()as directory:
   p=Path(directory)/'a';p.write_bytes(b'x');q=p.with_name('b');q.symlink_to(p)
   with self.assertRaises(ValueError):F.read(q)
   q.unlink();os.link(p,q)
   with self.assertRaises(ValueError):F.read(p)
  for raw in(b'{"x":1,"x":2}',b'{"x":NaN}'):
   with self.assertRaises(ValueError):F.decode(raw)
 def test_all_original14_sharing_refusals_and_owned_fd_controls(self):
  with tempfile.TemporaryDirectory()as directory:
   path=Path(directory);source=path/'source';F.assemble(RUNTIME,source);sharing=load('_maintained_sharing_runtime',source/'runtime/sharing.py');old=sys.modules.get('sharing');sys.modules['sharing']=sharing
   try:
    test=load('_maintained_original_controls',source/'runtime/test_sharing.py');out=io.StringIO()
    with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')),patch.object(subprocess,'run',side_effect=AssertionError('NO_ACTORS')):result=unittest.TextTestRunner(stream=out).run(unittest.defaultTestLoader.loadTestsFromModule(test))
    self.assertTrue(result.wasSuccessful(),out.getvalue());self.assertEqual(result.testsRun,14);self.assertFalse(result.skipped)
   finally:
    if old is None:sys.modules.pop('sharing',None)
    else:sys.modules['sharing']=old
 def test_exact_pinned_run2_epoch_and_fresh_progression(self):
  raw=self.default['runtime/sharing.py'].decode();sharing=load('_maintained_epoch_runtime',HERE/'runtime/sharing.py');fn=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='validate');start=next(i for i,n in enumerate(fn.body)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='counters'for t in n.targets));end=next(i for i,n in enumerate(fn.body)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='config'for t in n.targets));code=compile(ast.Module(body=fn.body[start:end],type_ignores=[]),'<PARTIAL_COUNTER_RELATION_NOT_VM_RECEIPT>','exec')
  rows={phase:{name:(7 if name=='full_scans'and phase=='sharing'else sharing.PAGES if name in('pages_shared','pages_sharing')and phase=='sharing'else 0)for name in sharing.COUNTERS}for phase in('before','sharing','unmerged','retired')}
  def check(value):exec(code,dict(value=dict(counters=value),COUNTERS=sharing.COUNTERS,need=sharing.need,PAGES=sharing.PAGES))
  check(rows)
  for phase,value in(('sharing',0),('unmerged',1),('retired',1),('before',True)):
   invalid=copy.deepcopy(rows);invalid[phase]['full_scans']=value
   with self.assertRaises(ValueError):check(invalid)

if __name__=='__main__':unittest.main(verbosity=2)
