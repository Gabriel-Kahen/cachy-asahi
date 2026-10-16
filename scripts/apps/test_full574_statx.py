# SPDX-License-Identifier: MIT
"""Bounded temporary-tree/scoped-query controls; no native actors or timing claim."""
import builtins,ctypes,hashlib,importlib.util,json,os,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('statx_scoped_apps_closure',HERE/'full574_closure.py');C=importlib.util.module_from_spec(spec);sys.modules[spec.name]=C;spec.loader.exec_module(C)
F=C.fast
import full_root as roots,aux_copy
spec=importlib.util.spec_from_file_location('statx_unchanged_caps',HERE/'file_capabilities.py');caps=importlib.util.module_from_spec(spec);spec.loader.exec_module(caps)
spec=importlib.util.spec_from_file_location('statx_unchanged_copy',HERE/'full574_copy.py');proof=importlib.util.module_from_spec(spec);spec.loader.exec_module(proof)

def limits(**kwargs):return roots.Limits(deadline=time.monotonic()+20,max_nodes=100,max_bytes=1024**2,max_file_bytes=1024**2,**kwargs)
def binding():return F.bind(C.ROOT,roots,caps,proof,aux_copy,C.source_bytes)

class Scoped(unittest.TestCase):
 def setUp(self):
  block=patch.object(subprocess,'Popen',side_effect=AssertionError('actors forbidden'));block.start();self.addCleanup(block.stop)
 def tree(self,path):
  (path/'nested').mkdir();(path/'nested/a').write_bytes(b'inert read-only data');os.link(path/'nested/a',path/'alias');(path/'relative').symlink_to('nested/a')
 def test_exact_sources_private_namespaces_and_shared_apis_unchanged(self):
  before=(roots.observe,roots._mount_id,caps.observe,caps.restore,caps._scan,caps._mount,proof.copy_data,aux_copy._copy_binding);bound=binding()
  self.assertEqual(before,(roots.observe,roots._mount_id,caps.observe,caps.restore,caps._scan,caps._mount,proof.copy_data,aux_copy._copy_binding))
  self.assertIsNot(bound.roots,roots);self.assertIs(bound.roots.require_eligible,roots.require_eligible)
  self.assertIs(bound.caps._scan.__wrapped__.__code__,caps._scan.__code__);self.assertIs(bound.caps.restore.__code__,caps.restore.__code__)
  self.assertIs(bound.copy_scope.copy_data.__wrapped__.__code__,proof.copy_data.__code__)
  namespace=bound.copy_scope.copy_data.__wrapped__.__globals__;self.assertIs(namespace['roots'],bound.roots)
  factory=namespace['aux_copy']._copy_binding;self.assertIs(factory.__globals__['roots'],bound.roots)
  copied=factory(limits());self.assertIs(copied.roots._mount_id,bound.roots._mount_id)
  for name,(size,pin) in F.PINS.items():
   raw=(C.ROOT/name).read_bytes();self.assertEqual((len(raw),hashlib.sha256(raw).hexdigest()),(size,pin))
 def test_wrong_source_pin_refuses_before_libc_or_observation(self):
  def changed(path):return C.source_bytes(path)+b' changed'
  with patch.object(ctypes,'CDLL',side_effect=AssertionError('query initialized before pins')),self.assertRaisesRegex(ValueError,'exact source pin'):F.bind(C.ROOT,roots,caps,proof,aux_copy,changed)
 def test_real_temp_complete_nodes_hashes_hardlinks_and_caps_equal(self):
  bound=binding()
  with tempfile.TemporaryDirectory() as temporary:
   path=Path(temporary);self.tree(path);old=roots.observe(path,limits=limits(),hardlinks='generic-development-internal');new=bound.roots.observe(path,limits=limits(),hardlinks='generic-development-internal')
   self.assertTrue(new['complete']);self.assertEqual(new['nodes'],old['nodes']);self.assertEqual(new['hardlink_groups'],old['hardlink_groups']);self.assertEqual(new['unsupported_counts'],old['unsupported_counts'])
   self.assertEqual(bound.caps.observe(path,new['nodes'],limits()),caps.observe(path,old['nodes'],limits()))
   self.assertEqual(bound.caps.restore(path,new['nodes'],{},limits()),{})
 def test_original_fdinfo_fallback_preserves_tree_and_attribute_refusals(self):
  with patch.object(ctypes,'CDLL',return_value=SimpleNamespace()):
   bound=binding()
   with tempfile.TemporaryDirectory() as temporary:
    path=Path(temporary);self.tree(path);old=roots.observe(path,limits=limits(),hardlinks='generic-development-internal');new=bound.roots.observe(path,limits=limits(),hardlinks='generic-development-internal');self.assertEqual(new['nodes'],old['nodes'])
    os.setxattr(path/'alias','user.UNIT-unknown',b'not permitted')
    with self.assertRaisesRegex(ValueError,'unknown xattr'):bound.caps.observe(path,new['nodes'],limits())
 def test_source_hashing_and_finite_caps_still_refuse(self):
  bound=binding()
  with tempfile.TemporaryDirectory() as temporary:
   path=Path(temporary);self.tree(path);value=bound.roots.observe(path,limits=limits(),hardlinks='generic-development-internal')
   os.setxattr(path/'alias','user.UNIT-unknown',b'not permitted')
   with self.assertRaisesRegex(ValueError,'unknown xattr'):bound.caps.observe(path,value['nodes'],limits())
   for budget,reason in ((roots.Limits(deadline=time.monotonic()+20,max_nodes=1),'root node limit'),(roots.Limits(deadline=time.monotonic()+20,max_bytes=1),'root byte limit')):
    result=bound.roots.observe(path,limits=budget,hardlinks='generic-development-internal');self.assertFalse(result['complete']);self.assertIn(reason,result['unsupported_counts'])
 def test_query_opens_fdinfo_for_crosscheck_without_caching_mount_ids(self):
  bound=binding();opening=Path.open;counts=[]
  def tracked(path,*args,**kwargs):
   if str(path).startswith('/proc/self/fdinfo/'):counts.append(str(path))
   return opening(path,*args,**kwargs)
  with tempfile.TemporaryDirectory() as temporary,patch.object(Path,'open',tracked):
   path=Path(temporary);self.tree(path);roots.observe(path,limits=limits(),hardlinks='generic-development-internal');original=len(counts);counts.clear()
   bound.roots.observe(path,limits=limits(),hardlinks='generic-development-internal')
   # Exact source helper crosschecks the first descriptor, then queries statx
   # afresh. This is an inert I/O-count control, never a native timing result.
   if hasattr(ctypes.CDLL(None),'statx') and sys.byteorder=='little':self.assertEqual(len(counts),1);self.assertGreater(original,len(counts))
 def test_bounded_phase_stderr_leaves_stdout_and_operations_unchanged(self):
  writes=[];completed=[]
  with patch.object(F,'_phases',0),patch.object(F.os,'write',side_effect=lambda fd,data:writes.append((fd,data)) or len(data)):
   @F.traced('inert-control')
   def function(value):completed.append(value);return value
   for i in range(100):self.assertEqual(function(i),i)
  self.assertEqual(completed,list(range(100)));self.assertEqual(len(writes),96);self.assertTrue(all(fd==2 and len(raw)<=512 for fd,raw in writes));self.assertLessEqual(sum(len(raw) for _,raw in writes),96*512)
  records=[json.loads(raw.split(b' ',1)[1]) for _,raw in writes];self.assertEqual(records[-1]['event'],'FURTHER_PHASE_RECORDS_OMITTED');self.assertNotIn('path',records[0])
 def test_phase_failure_preserves_original_exception_and_no_success_line(self):
  writes=[];error=ValueError('original refusal')
  with patch.object(F,'_phases',0),patch.object(F.os,'write',side_effect=lambda fd,raw:writes.append(raw) or len(raw)):
   @F.traced('inert-control')
   def fail():raise error
   with self.assertRaises(ValueError) as observed:fail()
  self.assertIs(observed.exception,error);self.assertEqual([json.loads(r.split(b' ',1)[1])['event'] for r in writes],['BEGIN','FAIL'])

if __name__=='__main__':unittest.main(verbosity=2)
