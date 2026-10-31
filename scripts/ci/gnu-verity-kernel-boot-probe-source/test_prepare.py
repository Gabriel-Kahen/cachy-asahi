#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure file-emitter controls. No accepting guest fixture or actors."""
import importlib.util,json,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('_boot_source_prepare',HERE/'prepare.py');E=importlib.util.module_from_spec(spec);spec.loader.exec_module(E)
OWN=HERE.parents[2]

def files(root):return {p.relative_to(root).as_posix():E.pin(E.read(p))for p in root.rglob('*')if p.is_file()}

class FactoryTests(unittest.TestCase):
 def test_default_exact72_null(self):
  with tempfile.TemporaryDirectory()as t:
   out=Path(t)/'default';r=E.emit(OWN,out);self.assertEqual(files(out),json.loads(E.read(HERE/'default-role.json'))['files']);self.assertIsNone(r['published_source']);self.assertEqual(r['kernel_input'],'NULL_REFUSE_BEFORE_ACTORS');self.assertTrue(all(json.loads(E.read(out/E.LANE/n))is None for n in('kernel-descriptor.json','Root-build-decision.json','kernel-build-result.json')))
 def test_selected_equals_whole_genuine_published72(self):
  with tempfile.TemporaryDirectory()as t:
   out=Path(t)/'selected';r=E.emit(OWN,out,True);self.assertEqual(files(out),json.loads(E.read(HERE/'selected-role.json'))['files']);self.assertEqual(r['published_source'],'bd31022395cc9231dfd966a4c0efc589ac1d49c2');self.assertIsNone(r['actual_run'])
 def test_no_actors_even_for_explicit_selected_source(self):
  with tempfile.TemporaryDirectory()as t,patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')),patch.object(subprocess,'run',side_effect=AssertionError('NO_ACTORS')):self.assertEqual(E.emit(OWN,Path(t)/'source',True)['files'],72)
 def test_six_leaf_inverse_conserves_every_executable(self):
  a=json.loads(E.read(HERE/'default-role.json'))['files'];b=json.loads(E.read(HERE/'selected-role.json'))['files'];diff={n for n in a if a[n]!=b[n]};self.assertEqual(len(diff),6);self.assertFalse(any(n.endswith(('.py','.c','.h'))for n in diff));self.assertEqual(json.loads(E.read(HERE/'selection.json'))['changed_leaves'],sorted(diff))
 def test_protected_generic_canonical_workflow_is_ignored(self):
  with tempfile.TemporaryDirectory()as t:
   root=Path(t)/'own';root.mkdir();a=json.loads(E.read(HERE/'default-role.json'))['files']
   for n in a:
    if n==E.GENERIC:continue
    dst=root/n;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(E.read(OWN/n))
   (root/E.GENERIC).write_bytes(b'held unrelated native workflow\n');out=Path(t)/'out';E.emit(root,out);self.assertEqual(files(out),a);self.assertEqual(E.read(root/E.GENERIC),b'held unrelated native workflow\n')
 def test_source_drift_refuses_before_output(self):
  with tempfile.TemporaryDirectory()as t:
   root=Path(t)/'own';root.mkdir();a=json.loads(E.read(HERE/'default-role.json'))['files']
   for n in a:
    if n==E.GENERIC:continue
    dst=root/n;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(E.read(OWN/n))
   (root/E.LANE/'init.c').write_bytes(b'drift');out=Path(t)/'refused'
   with self.assertRaisesRegex(ValueError,'whole NULL-default'):E.emit(root,out)
   self.assertFalse(out.exists())
 def test_symlink_source_refuses(self):
  with tempfile.TemporaryDirectory()as t:
   root=Path(t)/'own';root.mkdir();(root/'.github').symlink_to(OWN/'.github',target_is_directory=True)
   with self.assertRaisesRegex(ValueError,'ordinary'):E.emit(root,Path(t)/'refused')
 def test_output_exists_refuses(self):
  with tempfile.TemporaryDirectory()as t:
   out=Path(t)/'exists';out.mkdir()
   with self.assertRaisesRegex(ValueError,'fresh'):E.emit(OWN,out)
 def test_selection_type_refuses(self):
  with tempfile.TemporaryDirectory()as t:
   with self.assertRaisesRegex(ValueError,'finite explicit'):E.emit(OWN,Path(t)/'refused','true')
 def test_named_workflow_default_authority_gate_before_apt(self):
  wf=E.read(OWN/E.WF).decode();self.assertLess(wf.index('check-authority'),wf.index('apt-get'));self.assertIn('SOURCE_SHA',wf);self.assertIn('timeout --kill-after=8s 255s',wf)

if __name__=='__main__':unittest.main(verbosity=2)
