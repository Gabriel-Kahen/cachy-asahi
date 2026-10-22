# SPDX-License-Identifier: MIT
"""Finite correction CLI, whole source, historical function and drift controls."""
import argparse,ast,hashlib,importlib.util,json,os,shutil,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--parent',type=Path,required=True);p.add_argument('--expected',type=Path,required=True);p.add_argument('--carrier',type=Path);args,rest=p.parse_known_args();P,E=args.parent.absolute(),args.expected.absolute();I=args.carrier.absolute()if args.carrier else None

def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
F=load('_finite_runtime_correction_factory',HERE/'prepare.py')
HELD={'need': 'a8ebc8f5f3a23b40b0c85a9adaa7e6f5bb29fcb122a2f824dc2f25deed384a8a', 'pin': 'f71b81de3a25bf17c4f69ffdebe13551b8d55744df3da3469a5b12a9b5ae1076', 'ordinary': '20bdd50e404a145a765dc5c5d87f4feff220c0e8b07b763998d7e4cd05b55efe', 'read': '9eee27849f82e76a02dd1f889de8f4bf72196db9d509a939b401cff42d289797', 'source': 'eb718ac2be3b4470b0e62d4e82b1841bedb13c3b54c4a07c4fa8c22b8ce525fe', 'inputs': 'fcb701fd319be34dc46fb570a15b9576119a78378af3203ef04d6590b5d7ef4b', 'emit': 'ab39758b497097be7967f9e8fcc666b418302303e8e6652ca28ea9c0d6d4d73c', 'loader_inputs': '84db304233423071b7ed6cc7e692997aa86ee11f88243dbf81d4ec41700333fd', 'emit_loader': 'b1e092405d743b61b11ae008a6e3d29659c5fc5ab3596a2dc2df8bb98a800219'}
FLAG='export-closure'
def table(root,wanted):return {n:F.pin(raw)for n,raw in F.source(root,wanted).items()}
def argv(out):return [sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--'+FLAG,*['--parent',str(P)],'--output',str(out)]
class Controls(unittest.TestCase):
 def test_actual_isolated_CLI_exact_full_source_and_complete_emitted_controls(self):
  variant,before,after,payload=F.correction_inputs();self.assertEqual(table(E,after),after)
  with tempfile.TemporaryDirectory()as t:
   out=Path(t)/'source';r=subprocess.run(argv(out),capture_output=True,cwd='/tmp',timeout=30);self.assertEqual(r.returncode,0,r.stderr);v=json.loads(r.stdout);self.assertEqual(v['source'],variant['after_source']);self.assertIsNone(v['actual']);self.assertEqual(table(out,after),table(E,after))
   for tail in (('developer/run.py','--source-preflight'),('developer/test_source.py',)):
    r=subprocess.run([sys.executable,'-I','-B','-Werror',str(out/tail[0]),*tail[1:]],capture_output=True,timeout=45);self.assertEqual(r.returncode,0,r.stderr)
    if len(tail)==1:self.assertIn(b'Ran 9 tests',r.stderr)
 def test_all_old_function_bodies_and_support_authorities_held(self):
  text=(HERE/'prepare.py').read_text();functions={n.name:ast.get_source_segment(text,n)for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
  for name,w in HELD.items():self.assertEqual(hashlib.sha256(functions[name].encode()).hexdigest(),w,name)
 def test_profile_map_and_every_readable_replacement_drift_refuse_before_output(self):
  p,_,_,_=F.correction_inputs()
  for name in ['correction-profile.json','correction-maps.json',*['correction-payload/'+n for n in p['payload']]]:
   with self.subTest(name=name),tempfile.TemporaryDirectory()as t:
    t=Path(t);factory=t/'factory';shutil.copytree(HERE,factory);q=factory/name;q.write_bytes(q.read_bytes()+b' ');out=t/'never';command=argv(out);command[command.index(str(HERE/'prepare.py'))]=str(factory/'prepare.py');r=subprocess.run(command,capture_output=True,timeout=30);self.assertNotEqual(r.returncode,0);self.assertFalse(out.exists())
 def test_parent_alias_and_drift_refuse_before_output(self):
  with tempfile.TemporaryDirectory()as t:
   t=Path(t);root=t/'parent';shutil.copytree(P,root,ignore=shutil.ignore_patterns('.git'));alias=t/'alias';alias.symlink_to(root,target_is_directory=True)
   command=argv(t/'never');command[command.index(str(P))]=str(alias);r=subprocess.run(command,capture_output=True,timeout=30);self.assertNotEqual(r.returncode,0);self.assertFalse((t/'never').exists())
   leaf=next(q for q in sorted(root.rglob('*'))if q.is_file());leaf.write_bytes(leaf.read_bytes()+b' ');command=argv(t/'never');command[command.index(str(P))]=str(root);r=subprocess.run(command,capture_output=True,timeout=30);self.assertNotEqual(r.returncode,0);self.assertFalse((t/'never').exists())
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
