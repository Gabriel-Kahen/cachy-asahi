#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""NEW client-v3 source/layout controls; only owned DATA staging, no package actor."""
import argparse,contextlib,importlib.util,io,json,os,runpy,shutil,stat,sys,tempfile,unittest
from pathlib import Path
p=argparse.ArgumentParser(add_help=False);p.add_argument('--recipe-root',type=Path);p.add_argument('--runtime-recipe-root',type=Path);p.add_argument('--canonical-root',type=Path);args,rest=p.parse_known_args();ROOT=args.recipe_root or Path(__file__).resolve().parent;ATTEMPTS=[]
def deny(event,values):
 if event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.spawn','os.fork','os.posix_spawn'))or event in('os.system','pty.spawn','os.kill','os.killpg'):ATTEMPTS.append(event);raise RuntimeError('package DATA actor denied '+event)
sys.addaudithook(deny)
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
C=load('_v3_package_source_checker',ROOT/'check_source.py')
class Controls(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='client-v3-package-data-');self.addCleanup(self.temp.cleanup);self.base=Path(self.temp.name);self.recipe=self.base/'recipe';shutil.copytree(ROOT,self.recipe);self.stage=self.base/'stage';self.stage.mkdir(mode=0o700)
 def stage_data(self):
  for n,(source,mode)in C.payload().items():q=self.stage/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes((self.recipe/source).read_bytes());q.chmod(mode)
 def test_exact_sources_and_canonical_dependency(self):
  value=C.check(self.recipe,canonical_root=args.canonical_root,runtime_recipe=args.runtime_recipe_root);self.assertEqual(value['source_files'],11);self.assertFalse(value['automatic_legacy_switch'])
 def test_declared_private_stage_has_exact_modes_and_no_runtime_overlap(self):
  self.stage_data();value=C.check(self.recipe,self.stage);self.assertEqual(value['owned_payload_files'],7);self.assertTrue(all('scripts/client/client.py'not in n and 'scripts/release/'not in n for n in C.payload()))
 def test_changed_helper_is_refused_before_any_stage(self):
  path=self.recipe/'client_v3.py';path.write_bytes(path.read_bytes()+b'\n')
  with self.assertRaisesRegex(ValueError,'package source differs'):C.check(self.recipe)
  self.assertEqual(list(self.stage.iterdir()),[])
 def test_missing_or_wrong_mode_staged_launcher_is_refused(self):
  self.stage_data();launcher=self.stage/'usr/bin/cachy-asahi-repository-client';launcher.chmod(0o644)
  with self.assertRaisesRegex(ValueError,'bytes/mode'):C.check(self.recipe,self.stage)
  launcher.unlink()
  with self.assertRaisesRegex(ValueError,'namespace'):C.check(self.recipe,self.stage)
 def test_actual_installed_prefix_launcher_selects_v3_help(self):
  self.stage_data();stream=io.StringIO()
  with contextlib.redirect_stdout(stream):
   with __import__('unittest.mock',fromlist=['patch']).patch.object(sys,'argv',['cachy-asahi-repository-client','verify','--help']):
    with self.assertRaises(SystemExit)as caught:runpy.run_path(str(self.stage/'usr/bin/cachy-asahi-repository-client'),run_name='__main__')
  self.assertEqual(caught.exception.code,0);self.assertIn('--state-dir',stream.getvalue());self.assertIn('--apply',stream.getvalue())
 def test_new10_against_staged_v3_helper(self):
  self.stage_data();client=self.stage/'usr/share/cachy-asahi/repository-runtime/scripts/client/client_v3.py'
  with __import__('unittest.mock',fromlist=['patch']).patch.object(sys,'argv',['state-tests','--client',str(client),'--before',str(ROOT/'state-binding-before-v2.py.txt')]):m=load('_staged_v3_state_controls',ROOT/'test_state_binding_v3.py')
  result=unittest.TestResult();unittest.defaultTestLoader.loadTestsFromTestCase(m.Controls).run(result);self.assertEqual(result.testsRun,10);self.assertEqual(result.errors,[]);self.assertEqual(result.failures,[]);self.assertEqual(result.skipped,[])
 def tearDown(self):self.assertEqual(ATTEMPTS,[])
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest])
