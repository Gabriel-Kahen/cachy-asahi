# SPDX-License-Identifier: MIT
"""Opt-in emitter controls and complete public-source custody, without actors."""
import argparse,ast,importlib.util,json,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;p=argparse.ArgumentParser()
for name in('parent','expected','carrier','recipe','native'):p.add_argument('--'+name,type=Path,required=True)
args,rest=p.parse_known_args();args={k:v.absolute()for k,v in vars(args).items()};sys.dont_write_bytecode=True
s=importlib.util.spec_from_file_location('_Apps9_maintained_prepare',HERE/'prepare.py');F=importlib.util.module_from_spec(s);s.loader.exec_module(F);s=importlib.util.spec_from_file_location('_Apps9_readable_assembler',HERE/'apps9.py');M=importlib.util.module_from_spec(s);s.loader.exec_module(M)
def argv(out,*flags):return [sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--predecessor-root',str(args['parent']),'--output',str(out),*flags]
class Controls(unittest.TestCase):
 def test_exact_isolated557_CLI_and_existing_output_refusal(self):
  _,maps,_=M.inputs(F.__dict__);self.assertEqual({n:F.pin(b)for n,b in F.files(args['expected']).items()},maps['selected'])
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'source';r=subprocess.run(argv(out,'--apps9'),capture_output=True,cwd='/tmp',timeout=30);self.assertEqual(r.returncode,0,r.stderr);v=json.loads(r.stdout);self.assertEqual(v['source'],'5c22c8dbac8b6a79ebbbd19141ace4840d41e43e');self.assertIsNone(v['actual']);self.assertEqual({n:F.pin(b)for n,b in F.files(out).items()},maps['selected']);before=F.files(out);r=subprocess.run(argv(out,'--apps9'),capture_output=True,timeout=30);self.assertNotEqual(r.returncode,0);self.assertEqual(F.files(out),before)
 def test_explicit_NULL_fallback_refuses_native_admission(self):
  _,maps,_=M.inputs(F.__dict__)
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'null';r=subprocess.run(argv(out,'--apps9-unbound'),capture_output=True,timeout=30);self.assertEqual(r.returncode,0,r.stderr);self.assertEqual({n:F.pin(b)for n,b in F.files(out).items()},maps['unbound']);r=subprocess.run([sys.executable,'-I','-B',str(out/'native.py'),'preflight'],capture_output=True,timeout=15);self.assertNotEqual(r.returncode,0);self.assertIn(b'BEFORE ACTORS',r.stderr)
 def test_every_old_function_and_profile_output_held(self):
  p,_,_=M.inputs(F.__dict__);text=(HERE/'prepare.py').read_text();functions={n.name:ast.get_source_segment(text,n)for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
  for n,w in p['held_functions'].items():self.assertEqual(F.pin(functions[n].encode()),w,n)
  self.assertEqual(F.profile()['output']['source'],'bb72a0fc5e84af5621f0b783056137efdd780282');self.assertEqual(F.cli_failure_inputs()[0]['after_source'],'51e7797ef639de8fbed96e51b5b12bf5a92c7cb7')
 def test_profile_payload_parent_and_alias_drift_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);factory=root/'factory';shutil.copytree(HERE,factory)
   for name in('apps9-profile.json','apps9-payload/apps9_common.py'):
    leaf=factory/name;raw=leaf.read_bytes();leaf.write_bytes(raw+b'drift')
    with patch.object(M,'HERE',factory),self.assertRaises(ValueError):M.emit(F.__dict__,args['parent'],root/'no-output')
    self.assertFalse((root/'no-output').exists());leaf.write_bytes(raw)
   parent=root/'parent';shutil.copytree(args['parent'],parent,ignore=shutil.ignore_patterns('.git'));leaf=parent/'native.py';leaf.write_bytes(leaf.read_bytes()+b'drift')
   with self.assertRaises(ValueError):F.prepare_apps9(parent,root/'no-parent')
   alias=root/'alias';alias.symlink_to(args['parent'],target_is_directory=True)
   with self.assertRaises(ValueError):F.prepare_apps9(alias,root/'no-alias')
   self.assertFalse((root/'no-parent').exists());self.assertFalse((root/'no-alias').exists())
 def test_full_historical_Root_custody_matches_five_public_fixtures(self):
  p,maps,_=M.inputs(F.__dict__)
  for role,path in args.items():
   key='output'if role=='expected'else role;self.assertEqual({n:F.pin(b)for n,b in F.files(path).items()},p['custody'][key]['git']['files'])
  self.assertEqual(len(p['custody']['native']['git']['files']),114);self.assertEqual(len(p['custody']['carrier']['git']['files']),93);self.assertEqual(len(p['custody']['recipe']['git']['files']),41)
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
