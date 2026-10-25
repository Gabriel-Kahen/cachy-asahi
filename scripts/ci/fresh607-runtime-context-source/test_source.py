# SPDX-License-Identifier: MIT
"""Actual closed-source factory reproduction and prewrite refusals."""
import importlib.util,json,os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('_maintained_runtime_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
PARENT=Path(os.environ['FRESH_RUNTIME_PARENT']).resolve()
class Source(unittest.TestCase):
 def test_complete_output_and_null_actuals(self):
  with tempfile.TemporaryDirectory(prefix='maintained1192-')as td:
   out=Path(td)/'source';prior=sys.modules.get('common');v=F.build(PARENT,out);self.assertEqual(len(v['files']),1192);self.assertEqual({n:F.pin(b)for n,b in F.tree(out).items()},json.loads(F.read(HERE/'output-source.json'))['files']);self.assertIs(sys.modules.get('common'),prior)
   self.assertTrue(all(v[k]is None for k in('actual_source','actual_ref','actual_run')))
   with self.assertRaises(ValueError):F.build(PARENT,out)
 def test_canonical_alias_and_overlap_before_writes(self):
  with tempfile.TemporaryDirectory(prefix='maintained1192-refusal-')as td:
   root=Path(td);alias=root/'alias';alias.symlink_to(PARENT,target_is_directory=True)
   for out in(PARENT/'must-not-write',HERE/'must-not-write',alias/'must-not-write'):
    with self.assertRaises(ValueError):F.build(PARENT,out)
    self.assertFalse(out.exists())
   wrong=root/'wrong';wrong.mkdir();(wrong/'extra').write_bytes(b'foreign');out=root/'absent'
   with self.assertRaises(ValueError):F.build(wrong,out)
   self.assertFalse(out.exists())
 def test_late_parent_change_refuses_before_output(self):
  with tempfile.TemporaryDirectory(prefix='maintained1192-late-')as td:
   out=Path(td)/'absent';original=F.tree;calls=[]
   def changed(root):
    v=original(root);calls.append(1)
    if len(calls)==2:v['LICENSE']+=b'private simulated read drift'
    return v
   with patch.object(F,'tree',changed),self.assertRaisesRegex(ValueError,'late parent'):F.build(PARENT,out)
   self.assertFalse(out.exists())
 def test_changed_library_refuses_before_output(self):
  with tempfile.TemporaryDirectory(prefix='maintained1192-library-')as td:
   out=Path(td)/'absent';original=F.read
   def changed(p):
    b=original(p)
    return b+b'\n# private drift\n'if p==HERE/'runtime_context.py'else b
   with patch.object(F,'read',changed),self.assertRaisesRegex(ValueError,'pinned complete'):F.build(PARENT,out)
   self.assertFalse(out.exists())
 def test_stable_source_descriptor_refuses_links(self):
  with tempfile.TemporaryDirectory(prefix='maintained1192-links-')as td:
   root=Path(td);p=root/'data';p.write_bytes(b'fixture');alias=root/'alias';alias.symlink_to(p)
   with self.assertRaises(ValueError):F.read(alias)
   os.link(p,root/'hard')
   with self.assertRaises(ValueError):F.read(p)
if __name__=='__main__':unittest.main(verbosity=2)
