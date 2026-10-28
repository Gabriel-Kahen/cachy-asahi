#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact opt-in loader698 emission and unchanged default; no native actors."""
import argparse,ast,hashlib,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--parent',type=Path,required=True);p.add_argument('--expected',type=Path,required=True);args,rest=p.parse_known_args();P,E=args.parent.absolute(),args.expected.absolute();s=importlib.util.spec_from_file_location('_onboarding_loader_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(s);s.loader.exec_module(F)
HELD={'need': 'a8ebc8f5f3a23b40b0c85a9adaa7e6f5bb29fcb122a2f824dc2f25deed384a8a', 'pin': 'f71b81de3a25bf17c4f69ffdebe13551b8d55744df3da3469a5b12a9b5ae1076', 'ordinary': '20bdd50e404a145a765dc5c5d87f4feff220c0e8b07b763998d7e4cd05b55efe', 'read': '9eee27849f82e76a02dd1f889de8f4bf72196db9d509a939b401cff42d289797', 'source': 'eb718ac2be3b4470b0e62d4e82b1841bedb13c3b54c4a07c4fa8c22b8ce525fe', 'inputs': 'fcb701fd319be34dc46fb570a15b9576119a78378af3203ef04d6590b5d7ef4b', 'emit': 'ab39758b497097be7967f9e8fcc666b418302303e8e6652ca28ea9c0d6d4d73c', 'main': '692f2b07ecdaca6a118ce865d897424ad666192ea7e1e3181e44ba603238d85f'}
class Controls(unittest.TestCase):
 def test_actual_isolated_cli_exact_new698_and_eight_emitted_source_controls(self):
  _,_,old,_=F.inputs();_,after,_=F.loader_inputs(old);self.assertEqual({n:F.pin(b)for n,b in F.source(E,after).items()},after)
  with tempfile.TemporaryDirectory()as t:
   out=Path(t)/'corrected';r=subprocess.run([sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--loader-correction','--parent',str(P),'--output',str(out)],capture_output=True,timeout=20);self.assertEqual(r.returncode,0,r.stderr);v=json.loads(r.stdout);self.assertEqual((v['source'],v['files'],v['held'],v['changed'],v['added']),('d0ed51fa626b9343321952277607718b900e90bc',698,693,5,0));self.assertIsNone(v['actual']);self.assertEqual(v['native'],'NOT_RUN');self.assertEqual(F.source(out,after),F.source(E,after))
   for argv in([sys.executable,'-I','-B','-Werror',str(out/'developer/run.py'),'--source-preflight'],[sys.executable,'-I','-B','-Werror',str(out/'developer/test_source.py')]):
    r=subprocess.run(argv,capture_output=True,timeout=40);self.assertEqual(r.returncode,0,r.stderr)
    if argv[-1].endswith('test_source.py'):self.assertIn(b'Ran 8 tests',r.stderr)
 def test_entire_old_functions_and_main_inverse_and_default_exact(self):
  text=(HERE/'prepare.py').read_text();functions={n.name:ast.get_source_segment(text,n)for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
  for name,w in HELD.items():
   body=functions[name]
   if name=='main':body=body.replace("group.add_argument('--rawdb-key-correction',action='store_true',help='exacted4fb rawDB package binding after complete export closure; all old outputs held');",'').replace('(emit_rawdb_key_correction if a.rawdb_key_correction else emit_export_closure','(emit_export_closure')
   if name=='main':body=body.replace("group=parser.add_mutually_exclusive_group();group.add_argument('--loader-correction',action='store_true',help='emit exact d0ed loader-corrected698; default3b60 unchanged');group.add_argument('--export-closure',action='store_true',help='exact3b900 export closure after d0ed; all prior outputs held');","parser.add_argument('--loader-correction',action='store_true',help='emit exact d0ed loader-corrected698; default3b60 unchanged');").replace('(emit_export_closure if a.export_closure else emit_loader if a.loader_correction else emit)(a.parent,a.output)','(emit_loader if a.loader_correction else emit)(a.parent,a.output)').replace("parser.add_argument('--loader-correction',action='store_true',help='emit exact d0ed loader-corrected698; default3b60 unchanged');",'').replace('(emit_loader if a.loader_correction else emit)(a.parent,a.output)','emit(a.parent,a.output)')
   self.assertEqual(hashlib.sha256(body.encode()).hexdigest(),w,name)
  with tempfile.TemporaryDirectory()as t:
   out=Path(t)/'old';v=F.emit(P,out);_,_,after,_=F.inputs();self.assertEqual(v['source'],'3b60dfffcc3ceb8cddce86b29d245cab01c2a772');self.assertEqual({n:F.pin(b)for n,b in F.source(out,after).items()},after)
 def test_loader_profile_map_and_each_payload_drift_before_output(self):
  for name in ['loader-profile.json','loader-expected698.json',*['loader-payload/'+n for n in F.loader_inputs(F.inputs()[2])[0]['payload']]]:
   with self.subTest(name=name),tempfile.TemporaryDirectory()as t:
    t=Path(t);factory=t/'factory';shutil.copytree(HERE,factory);q=factory/name;q.write_bytes(q.read_bytes()+b' ');out=t/'never';r=subprocess.run([sys.executable,'-I','-B',str(factory/'prepare.py'),'--loader-correction','--parent',str(P),'--output',str(out)],capture_output=True,timeout=20);self.assertNotEqual(r.returncode,0);self.assertFalse(out.exists())
 def test_parent_and_output_alias_and_foreign_directory_refusals_before_output(self):
  with tempfile.TemporaryDirectory()as t:
   t=Path(t);root=t/'parent';shutil.copytree(P,root,ignore=shutil.ignore_patterns('.git'));alias=t/'input-alias';alias.symlink_to(root,target_is_directory=True)
   with self.assertRaises(ValueError):F.emit_loader(alias,t/'never')
   self.assertFalse((t/'never').exists());(root/'foreign-empty').mkdir()
   with self.assertRaises(ValueError):F.emit_loader(root,t/'never')
   self.assertFalse((t/'never').exists());(root/'foreign-empty').rmdir();q=root/'coexist/apps_entry.py';q.write_bytes(q.read_bytes()+b' ')
   with self.assertRaises(ValueError):F.emit_loader(root,t/'never')
   self.assertFalse((t/'never').exists());existing=t/'existing';existing.mkdir();(existing/'sentinel').write_bytes(b'held');out=t/'output-alias';out.symlink_to(existing,target_is_directory=True)
   with self.assertRaises(ValueError):F.emit_loader(P,out)
   with self.assertRaises(ValueError):F.emit_loader(P,existing)
   with self.assertRaises(ValueError):F.emit_loader(P,P/'never-source-child')
   self.assertEqual((existing/'sentinel').read_bytes(),b'held');self.assertFalse((P/'never-source-child').exists())
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
