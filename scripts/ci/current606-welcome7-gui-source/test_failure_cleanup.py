# SPDX-License-Identifier: MIT
"""Exact opt-in source factory, old-route parity and before-write refusals."""
import ast,hashlib,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
PARENT=Path(os.environ['GUI_CLEANUP_PARENT']);EXPECTED=Path(os.environ['GUI_CLEANUP_EXPECTED']);APPS13=Path(os.environ['GUI_CLEANUP_APPS13'])
def load(name,path):s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
F=load('_cleanup_source_factory',HERE/'prepare.py');M=load('_cleanup_source_option',HERE/'failure_cleanup_source.py');P,PAYLOAD=M.inputs(F.__dict__)
class Factory(unittest.TestCase):
 def test_exact_whole_emission_NULL_authority_inverse_and_isolated_CLI(self):
  self.assertEqual({n:F.pin(b)for n,b in F.files(EXPECTED).items()},P['after'])
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'source';r=subprocess.run([sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--failure-cleanup','--predecessor-root',str(PARENT),'--output',str(out)],capture_output=True,cwd='/tmp',timeout=20);self.assertEqual(r.returncode,0,r.stderr);receipt=json.loads(r.stdout);self.assertEqual(receipt['source'],P['after_source']);self.assertIsNone(receipt['actual_source']);self.assertEqual(F.files(out),F.files(EXPECTED));a=load('_new_complete_source_guard',out/'admission.py');self.assertEqual(a.prove(out)['files'],561);p=json.loads((out/'failure-cleanup-parent.json').read_bytes());self.assertEqual(p['files'],P['before'])
   for n,b in p['before_bodies'].items():self.assertEqual(__import__('base64').b64decode(b,validate=True),F.ordinary(PARENT/n))
   for wf in('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-current606-welcome8-gui.yml'):self.assertEqual((out/wf).read_bytes(),(PARENT/wf).read_bytes())
 def test_all_old_functions_default_and_actual_Apps14_outputs_held(self):
  text=(HERE/'prepare.py').read_text();functions={n.name:F.pin(ast.get_source_segment(text,n).encode())for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
  for n,w in P['held_functions'].items():self.assertEqual(functions[n],w,n)
  self.assertEqual(F.profile()['output']['source'],'bb72a0fc5e84af5621f0b783056137efdd780282')
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'old';F.prepare_apps14_stage(APPS13,out);self.assertEqual(F.files(out),F.files(PARENT))
 def test_profile_payload_parent_directory_alias_and_metadata_drift_refuse_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);factory=root/'factory';shutil.copytree(HERE,factory)
   for name in('failure-cleanup-profile.json','failure-cleanup-payload/native.py','failure-cleanup-payload/factory/failure_cleanup.py'):
    leaf=factory/name;raw=leaf.read_bytes();leaf.write_bytes(raw+b'drift')
    with patch.object(M,'HERE',factory),self.assertRaises(ValueError):M.emit(F.__dict__,PARENT,root/'no')
    self.assertFalse((root/'no').exists());leaf.write_bytes(raw)
   extra=factory/'failure-cleanup-payload/foreign';extra.write_bytes(b'foreign')
   with patch.object(M,'HERE',factory),self.assertRaises(ValueError):M.emit(F.__dict__,PARENT,root/'no')
   self.assertFalse((root/'no').exists())
   parent=root/'parent';shutil.copytree(PARENT,parent);leaf=parent/'native.py';leaf.write_bytes(leaf.read_bytes()+b'drift')
   with self.assertRaises(ValueError):F.prepare_failure_cleanup(parent,root/'no')
   self.assertFalse((root/'no').exists())
 def test_noncanonical_overlap_symlink_hardlink_existing_output_and_immutable_inputs(self):
  before=F.files(PARENT)
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);alias=root/'alias';alias.symlink_to(PARENT,target_is_directory=True)
   for parent,out in((alias,root/'bad'),(PARENT/'absent/..',root/'bad'),(PARENT,root/'absent/../bad'),(PARENT,PARENT/'bad'),(PARENT,HERE/'bad'),(PARENT,PARENT)):
    with self.assertRaises((ValueError,OSError)):F.prepare_failure_cleanup(parent,out)
   self.assertFalse((root/'bad').exists());self.assertFalse((HERE/'bad').exists());self.assertFalse((PARENT/'bad').exists())
   own=root/'parent';shutil.copytree(PARENT,own);os.link(own/'native.py',root/'hardlink')
   with self.assertRaises(ValueError):F.prepare_failure_cleanup(own,root/'no')
   self.assertFalse((root/'no').exists())
  self.assertEqual(F.files(PARENT),before)
 def test_fixed_failure_projection_custody_and_whole_runtime_controls(self):
  fixture={n:F.pin(b)for n,b in F.files(HERE/'failure-cleanup-controls').items()};self.assertEqual(fixture,P['control_fixture']);c=json.loads((HERE/'failure-cleanup-controls/custody.json').read_bytes());self.assertFalse(c['GUI_acceptance']);self.assertFalse(c['cleanup_acceptance']);self.assertEqual(c['projection'],fixture['gui/runtime.json']);self.assertEqual(c['runtime'],dict(bytes=74033,sha256='60f35dc403c4d299e537f8d618a1abd7a36f4b7f60d14c9ae37d84cee40bb00e'));r=subprocess.run([sys.executable,'-I','-B','-Werror',str(HERE/'test_failure_cleanup_runtime.py')],capture_output=True,timeout=60);self.assertEqual(r.returncode,0,r.stderr);self.assertIn(b'Ran 8 tests',r.stderr);self.assertTrue(r.stderr.endswith(b'\nOK\n'));sys.stderr.write(r.stderr.decode())
  r=subprocess.run([sys.executable,'-I','-B','-Werror',str(EXPECTED/'native.py'),'preflight'],capture_output=True,timeout=30);self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(json.loads(r.stdout)['files'],561)
if __name__=='__main__':unittest.main(verbosity=2)
