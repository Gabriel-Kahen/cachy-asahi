# SPDX-License-Identifier: MIT
"""Exact new option/source controls, whole old functions and before-output refusals."""
import argparse,ast,hashlib,importlib.util,json,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
CFG={'gui': False, 'flag': 'rawdb-key-correction', 'stem': 'rawdb-key', 'source': 'ed4fb355ff939bf269905592ba5d71517ffab373', 'count': 698, 'held_functions': {'correction_inputs': {'bytes': 1094, 'sha256': 'cd53abe672c419c8f2ebddabcb64c6c31156715c4171c2d0131a79954c7c51fc'}, 'emit': {'bytes': 1019, 'sha256': 'ab39758b497097be7967f9e8fcc666b418302303e8e6652ca28ea9c0d6d4d73c'}, 'emit_export_closure': {'bytes': 1315, 'sha256': 'dcb8507d0599b0608f6583c2ee4c8321cef08c52461ee1fe5fcb87d950dc4464'}, 'emit_loader': {'bytes': 1222, 'sha256': 'b1e092405d743b61b11ae008a6e3d29659c5fc5ab3596a2dc2df8bb98a800219'}, 'inputs': {'bytes': 1333, 'sha256': 'fcb701fd319be34dc46fb570a15b9576119a78378af3203ef04d6590b5d7ef4b'}, 'loader_inputs': {'bytes': 1189, 'sha256': '84db304233423071b7ed6cc7e692997aa86ee11f88243dbf81d4ec41700333fd'}, 'need': {'bytes': 50, 'sha256': 'a8ebc8f5f3a23b40b0c85a9adaa7e6f5bb29fcb122a2f824dc2f25deed384a8a'}, 'ordinary': {'bytes': 183, 'sha256': '20bdd50e404a145a765dc5c5d87f4feff220c0e8b07b763998d7e4cd05b55efe'}, 'pin': {'bytes': 79, 'sha256': 'f71b81de3a25bf17c4f69ffdebe13551b8d55744df3da3469a5b12a9b5ae1076'}, 'read': {'bytes': 664, 'sha256': '9eee27849f82e76a02dd1f889de8f4bf72196db9d509a939b401cff42d289797'}, 'source': {'bytes': 850, 'sha256': 'eb718ac2be3b4470b0e62d4e82b1841bedb13c3b54c4a07c4fa8c22b8ce525fe'}}}
p=argparse.ArgumentParser();p.add_argument('--parent',type=Path,required=True);p.add_argument('--expected',type=Path,required=True);args,rest=p.parse_known_args();PARENT,EXPECTED=args.parent.absolute(),args.expected.absolute();s=importlib.util.spec_from_file_location('_maintained_followup_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(s);s.loader.exec_module(F)
def table(root):
 return {p.relative_to(root).as_posix():dict(bytes=len(b:=p.read_bytes()),sha256=hashlib.sha256(b).hexdigest())for p in root.rglob('*')if p.is_file()and'.git'not in p.relative_to(root).parts}
def emit(parent,out):return (F.prepare_cli_failure_data if CFG['gui']else F.emit_rawdb_key_correction)(parent,out)
def inputs():return (F.cli_failure_inputs if CFG['gui']else F.rawdb_inputs)()
def argv(parent,out):return [sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--'+CFG['flag'],'--predecessor-root'if CFG['gui']else'--parent',str(parent),'--output',str(out)]
class Controls(unittest.TestCase):
 def test_exact_isolated_CLI_whole_output_source_guard_and_actual_controls(self):
  _,_,wanted,_=inputs();self.assertEqual(table(EXPECTED),wanted)
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'source';r=subprocess.run(argv(PARENT,out),capture_output=True,cwd='/tmp',timeout=30);self.assertEqual(r.returncode,0,r.stderr);v=json.loads(r.stdout);self.assertEqual(v['source'],CFG['source']);self.assertIsNone(v['actual']);self.assertEqual(table(out),wanted);self.assertEqual(len(wanted),CFG['count'])
   r=subprocess.run([sys.executable,'-I','-B',str(HERE/'prepare.py'),'--help'],capture_output=True,timeout=10);self.assertEqual(r.returncode,0,r.stderr);self.assertIn(('--'+CFG['flag']).encode(),r.stdout)
   if CFG['gui']:
    s=importlib.util.spec_from_file_location('_whole_emitted_GUI_admission',out/'admission.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);self.assertEqual(m.prove(out)['files'],556);entry=out/'apps8_common.py';count=b'Ran 4 tests'
   else:entry=out/'developer/test_source.py';count=b'Ran 13 tests'
   r=subprocess.run([sys.executable,'-I','-B','-Werror',str(entry)],capture_output=True,timeout=60);self.assertEqual(r.returncode,0,r.stderr);self.assertIn(count,r.stderr)
   before=table(out);r=subprocess.run(argv(PARENT,out),capture_output=True,timeout=30);self.assertNotEqual(r.returncode,0);self.assertEqual(table(out),before)
 def test_all_prior_function_bodies_remain_byteexact(self):
  text=(HERE/'prepare.py').read_text();functions={n.name:ast.get_source_segment(text,n)for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
  for n,w in CFG['held_functions'].items():
   with self.subTest(function=n):self.assertEqual(F.pin(functions[n].encode()),w)
 def test_new_payload_and_whole_parent_drift_refuse_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   t=Path(td);factory=t/'factory';shutil.copytree(HERE,factory);leaf=next(p for p in(factory/(CFG['stem']+'-payload')).rglob('*')if p.is_file());leaf.write_bytes(leaf.read_bytes()+b'\n')
   with patch.object(F,'HERE',factory),self.assertRaises(ValueError):emit(PARENT,t/'never-support')
   self.assertFalse((t/'never-support').exists());bad=t/'parent';shutil.copytree(PARENT,bad,ignore=shutil.ignore_patterns('.git'));leaf=next(p for p in bad.rglob('*')if p.is_file());leaf.write_bytes(leaf.read_bytes()+b'\n')
   with self.assertRaises(ValueError):emit(bad,t/'never-parent')
   self.assertFalse((t/'never-parent').exists());alias=t/'alias';alias.symlink_to(PARENT,target_is_directory=True)
   with self.assertRaises(ValueError):emit(alias,t/'never-alias')
   self.assertFalse((t/'never-alias').exists())
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
