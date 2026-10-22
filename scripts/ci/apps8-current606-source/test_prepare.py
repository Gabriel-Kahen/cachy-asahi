#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Portable exact380/inverse/CLI/refusal controls; no native or GPG actors."""
import argparse,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--parent',type=Path,required=True);p.add_argument('--carrier',type=Path,required=True);p.add_argument('--expected',type=Path,required=True);args,rest=p.parse_known_args();P,I,E=map(lambda x:x.absolute(),(args.parent,args.carrier,args.expected));s=importlib.util.spec_from_file_location('_Apps8_current606_source_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(s);s.loader.exec_module(F)
class Controls(unittest.TestCase):
 def test_exact_isolated_cli_source_entry_and_nine_whole_emitted_controls(self):
  _,before,carrier,after,_=F.inputs();F.source(P,before);F.source(I,carrier);F.source(E,after)
  with tempfile.TemporaryDirectory()as t:
   out=Path(t)/'source';argv=[sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--parent',str(P),'--carrier',str(I),'--output',str(out)];r=subprocess.run(argv,capture_output=True,timeout=20,cwd='/tmp');self.assertEqual(r.returncode,0,r.stderr);value=json.loads(r.stdout);self.assertEqual((value['files'],value['held'],value['changed'],value['added']),(380,332,16,32));self.assertIsNone(value['actual']);self.assertEqual(value['native'],'NOT_RUN');self.assertEqual(F.source(out,after),F.source(E,after))
   for command in([sys.executable,'-I','-B','-Werror',str(out/'apps8/entry.py'),'--source-only'],[sys.executable,'-I','-B','-Werror',str(out/'apps8/test_source.py')]):
    r=subprocess.run(command,capture_output=True,timeout=40);self.assertEqual(r.returncode,0,r.stderr)
    if command[-1].endswith('test_source.py'):self.assertIn(b'Ran 9 tests',r.stderr)
    else:self.assertIsNone(json.loads(r.stdout)['actual'])
 def test_actual_emitted_whole348_inverse_before_publishing_any_ancestor(self):
  _,before,_,after,_=F.inputs()
  with tempfile.TemporaryDirectory()as t:
   t=Path(t);out=t/'source';F.emit(P,I,out);inverse=t/'inverse';r=subprocess.run([sys.executable,'-I','-B','-Werror',str(out/'apps8/entry.py'),'--inverse-parent','--output',str(inverse)],capture_output=True,timeout=20);self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(F.source(inverse,before),F.source(P,before));self.assertEqual(json.loads(r.stdout)['emitted'],348)
 def test_parent_and_carrier_missing_extra_changed_emptydir_and_alias_before_output(self):
  for role,original,leaf in(('parent',P,'scripts/ci/current606-apps7-closed-owner/owner.py'),('carrier',I,'index.json')):
   for change in('missing','extra','changed','emptydir','symlink','hardlink'):
    with self.subTest(role=role,change=change),tempfile.TemporaryDirectory()as t:
     t=Path(t);root=t/role;shutil.copytree(original,root,ignore=shutil.ignore_patterns('.git'));target=root/leaf
     if change=='missing':target.unlink()
     elif change=='extra':(root/'foreign').write_bytes(b'foreign')
     elif change=='changed':target.write_bytes(target.read_bytes()+b' ')
     elif change=='emptydir':(root/'foreign-empty').mkdir()
     elif change=='symlink':target.unlink();target.symlink_to(original/leaf)
     else:os.link(target,t/'hardlink')
     out=t/'never'
     with self.assertRaises((ValueError,FileNotFoundError)):F.emit(root if role=='parent'else P,root if role=='carrier'else I,out)
     self.assertFalse(out.exists())
 def test_profiles_payloads_and_legal_drift_before_output(self):
  names=('profile.json','parent348.json','carrier93.json','expected380.json','LICENSE','NOTICE.md','payload/apps8/packet.py','payload/scripts/ci/current606-apps7-closed-owner/owner.py','payload/apps8/inverse/scripts/ci/current606-apps7-closed-owner/owner.py')
  for name in names:
   with self.subTest(name=name),tempfile.TemporaryDirectory()as t:
    t=Path(t);factory=t/'factory';shutil.copytree(HERE,factory);q=factory/name;q.write_bytes(q.read_bytes()+b' ');out=t/'never';r=subprocess.run([sys.executable,'-I','-B','-Werror',str(factory/'prepare.py'),'--parent',str(P),'--carrier',str(I),'--output',str(out)],capture_output=True,timeout=20);self.assertNotEqual(r.returncode,0);self.assertFalse(out.exists())
 def test_input_and_output_directory_aliases_and_missing_selection_refuse(self):
  with tempfile.TemporaryDirectory()as t:
   t=Path(t);existing=t/'existing';existing.mkdir();(existing/'sentinel').write_bytes(b'held')
   for label,target in(('parent',P),('carrier',I)):
    alias=t/label;alias.symlink_to(target,target_is_directory=True)
    with self.assertRaises(ValueError):F.emit(alias if label=='parent'else P,alias if label=='carrier'else I,t/'never')
    self.assertFalse((t/'never').exists())
   alias=t/'output';alias.symlink_to(existing,target_is_directory=True)
   for out in(existing,alias,P/'never-source-child',I/'never-source-child'):
    with self.assertRaises(ValueError):F.emit(P,I,out)
   self.assertEqual((existing/'sentinel').read_bytes(),b'held');self.assertFalse((P/'never-source-child').exists());self.assertFalse((I/'never-source-child').exists())
   r=subprocess.run([sys.executable,'-I','-B',str(HERE/'prepare.py'),'--parent',str(P),'--output',str(t/'never')],capture_output=True);self.assertEqual(r.returncode,2);self.assertFalse((t/'never').exists())
   r=subprocess.run([sys.executable,'-I','-O','-B',str(HERE/'prepare.py'),'--parent',str(P),'--carrier',str(I),'--output',str(t/'never')],capture_output=True);self.assertNotEqual(r.returncode,0);self.assertFalse((t/'never').exists())
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
