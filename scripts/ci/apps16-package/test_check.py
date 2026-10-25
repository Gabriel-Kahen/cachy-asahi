#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Portable source/ordered94/routing controls; no duplicate package TEST suite."""
import argparse,contextlib,importlib.util,io,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser(add_help=False);p.add_argument('--repository-source',type=Path,required=True);p.add_argument('--expected-source',type=Path,required=True);options,rest=p.parse_known_args()
SOURCE=options.repository_source.absolute();EXPECTED=options.expected_source.absolute()
spec=importlib.util.spec_from_file_location('apps16_package_check',HERE/'check.py');C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)
PROFILE=json.loads((HERE/'profile.json').read_bytes())
MARKERS=''.join('Ran '+str(n)+' tests in 0.001s\n\nOK\n'for n in(54,32,8))
def argv(output,*extra):return [str(HERE/'check.py'),'--repository-source',str(SOURCE),'--expected-source',str(EXPECTED),'--output',str(output),*extra]
def main(args):
 with patch.object(sys,'argv',args),contextlib.redirect_stdout(io.StringIO()):C.main()

class Helper(unittest.TestCase):
 def test_exact_ordered94_gate_refuses_old_missing_extra_failed_skipped(self):
  self.assertEqual(C.completed_suites(MARKERS),[54,32,8])
  for text in(MARKERS.replace('54','45'),MARKERS+'FAILED (failures=1)\n',MARKERS+'ERROR: control\n',MARKERS+'FAIL: control\n',MARKERS+'Ran 1 test in 1.000s\n',MARKERS.replace('32','24'),MARKERS.replace('54','53'),MARKERS.replace('OK\n','FAILED (failures=1)\n',1),MARKERS.replace('OK\n','OK (skipped=1)\n',1),MARKERS+MARKERS[:MARKERS.index('Ran 32')],''.join('Ran '+str(n)+' tests in 0.001s\n\nOK\n'for n in(54,8,32)),'',MARKERS[:MARKERS.index('Ran 8')],MARKERS+'OK\n'):
   with self.subTest(text=text),self.assertRaises(ValueError):C.completed_suites(text)
 def test_actual_source_only_entry_has_no_test_actor(self):
  with tempfile.TemporaryDirectory()as td:
   output=Path(td)/'source-check'
   with patch.object(subprocess,'run',side_effect=AssertionError('NO_TEST_ACTORS')):main(argv(output,'--source-only'))
   value=json.loads((output/'result.json').read_bytes());self.assertEqual(value,dict(status='PASS_SOURCE_CLOSURE_ONLY',source_files=42,recipe_files=17,test_execution='NOT_RUN',native_acceptance='NOT_INFERRED'))
 def test_real_isolated_source_cli_and_help(self):
  with tempfile.TemporaryDirectory()as td:
   v=subprocess.run([sys.executable,'-I','-B','-Werror',*argv(Path(td)/'source-check','--source-only')],capture_output=True,timeout=15);self.assertEqual(v.returncode,0,v.stderr);self.assertEqual(json.loads(v.stdout)['test_execution'],'NOT_RUN')
   v=subprocess.run([sys.executable,'-I','-B',str(HERE/'check.py'),'--help'],capture_output=True,timeout=10);self.assertEqual(v.returncode,0,v.stderr);self.assertIn(b'--source-only',v.stdout)
 def test_recipe_fixture_and_output_alias_refuse_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);recipe=root/'recipe';shutil.copytree(SOURCE/'packages/tools/cachy-asahi-apps16',recipe);(recipe/'inventory.py').write_bytes((recipe/'inventory.py').read_bytes()+b'X');output=root/'never'
   with self.assertRaises(ValueError):main(argv(output,'--recipe-root',str(recipe),'--source-only'))
   self.assertFalse(output.exists());fixture=root/'fixture';fixture.mkdir()
   for name in PROFILE['source_files']:
    path=fixture/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes((EXPECTED/name).read_bytes())
   leaf=fixture/'packages/tools/cachy-asahi-apps16/NOTICE';leaf.write_bytes(leaf.read_bytes()+b'X');args=argv(output,'--source-only');args[args.index('--expected-source')+1]=str(fixture)
   with self.assertRaises(ValueError):main(args)
   self.assertFalse(output.exists());alias=root/'alias';alias.symlink_to(root,target_is_directory=True)
   with self.assertRaises(ValueError):main(argv(alias/'never','--source-only'))
   self.assertFalse(output.exists())
 def test_full_entry_routing_with_explicit_inert_test_actor_boundary(self):
  # This source-shaped control supplies ONLY the three finite TEST markers.
  # It does not rerun or claim a real94-suite result. Original package() and
  # staged source checker execute; the actual94 proof is separate custody.
  calls=[];original=subprocess.run
  with tempfile.TemporaryDirectory()as td:
   output=Path(td)/'route'
   def route(args,**kw):
    calls.append(args)
    if args[0]=='/bin/bash'and args[-2]=='apps16-check':
     self.assertEqual(args[4],'set -euo pipefail; source "$1"; check');self.assertEqual(kw['timeout'],180)
     env=kw['env'];self.assertEqual(env['startdir'],str(SOURCE/'packages/tools/cachy-asahi-apps16'));self.assertEqual(env['CACHY_ASAHI_REPOSITORY_SOURCE'],str(SOURCE));self.assertEqual(env['CACHY_ASAHI_RUNTIME_RECIPE'],str(SOURCE/'packages/tools/cachy-asahi-repository-runtime'))
     names=list(Path(env['srcdir']).iterdir());self.assertEqual(len(names),15);self.assertTrue(all(n.is_symlink()and n.resolve().parent==Path(env['startdir'])for n in names));kw['stderr'].write(MARKERS.encode());return subprocess.CompletedProcess(args,0)
    return original(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,**kw)
   with patch.object(subprocess,'run',side_effect=route):main(argv(output))
   value=json.loads((output/'result.json').read_bytes());self.assertEqual(value['tests'],[54,32,8]);self.assertEqual(value['package_files'],8);self.assertEqual(len(calls),3);self.assertEqual(calls[1][-2],'apps16-package');self.assertEqual(calls[2][3],str(SOURCE/'packages/tools/cachy-asahi-apps16/check_source.py'));self.assertEqual(len([p for p in(output/'package').rglob('*')if p.is_file()]),8)
 def test_noncanonical_paths_refuse_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);output=root/'never'
   for flag in('--repository-source','--expected-source','--recipe-root','--output'):
    args=argv(output,'--source-only');bad=str(root/'absent'/'..'/'never')
    if flag in args:args[args.index(flag)+1]=bad
    else:args.extend((flag,bad))
    with self.subTest(flag=flag),self.assertRaises(ValueError):main(args)
    self.assertFalse(output.exists());self.assertFalse((root/'absent').exists())
   with self.assertRaises(ValueError):main(argv(EXPECTED/'never','--source-only'))
   self.assertFalse((EXPECTED/'never').exists())
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
