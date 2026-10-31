#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Portable source/CLI/refusal tests only, no actors or acceptance replay."""
import argparse,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent;parser=argparse.ArgumentParser();parser.add_argument('--parent',type=Path,required=True);parser.add_argument('--expected',type=Path,required=True);args,rest=parser.parse_known_args();spec=importlib.util.spec_from_file_location('onboarding_source_factory',HERE/'prepare.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
class Controls(unittest.TestCase):
 def test_exact_emission_isolated_help_source_entry_and_existing_seven_controls(self):
  _,before,after,_=P.inputs();self.assertEqual({n:P.pin(b)for n,b in P.source(args.parent,before).items()},before);self.assertEqual({n:P.pin(b)for n,b in P.source(args.expected,after).items()},after)
  with tempfile.TemporaryDirectory()as temp:
   out=Path(temp)/'source';row=subprocess.run([sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--help'],capture_output=True,timeout=10);self.assertEqual(row.returncode,0,row.stderr);self.assertIn(b'--parent',row.stdout)
   row=subprocess.run([sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--parent',str(args.parent),'--output',str(out)],capture_output=True,timeout=20);self.assertEqual(row.returncode,0,row.stderr);value=json.loads(row.stdout);self.assertEqual((value['files'],value['held'],value['changed'],value['added']),(698,672,4,22));self.assertIsNone(value['actual']);self.assertEqual(value['native'],'NOT_RUN');self.assertEqual({n:P.pin(b)for n,b in P.source(out,after).items()},after)
   row=subprocess.run([sys.executable,'-I','-B','-Werror',str(out/'developer/run.py'),'--source-preflight'],capture_output=True,timeout=40);self.assertEqual(row.returncode,0,row.stderr);self.assertIsNone(json.loads(row.stdout)['actual'])
   row=subprocess.run([sys.executable,'-I','-B','-Werror',str(out/'developer/test_source.py')],capture_output=True,timeout=40);self.assertEqual(row.returncode,0,row.stderr);self.assertIn(b'Ran 7 tests',row.stderr)
 def test_parent_missing_extra_drift_empty_directory_and_aliases_before_output(self):
  for change in('missing','extra','drift','empty-directory','symlink','hardlink'):
   with self.subTest(change=change),tempfile.TemporaryDirectory()as temp:
    base=Path(temp);root=base/'parent';shutil.copytree(args.parent,root,ignore=shutil.ignore_patterns('.git'));target=root/'coexist/apps_entry.py'
    if change=='missing':target.unlink()
    elif change=='extra':(root/'foreign').write_bytes(b'foreign')
    elif change=='drift':target.write_bytes(target.read_bytes()+b'\n# source drift\n')
    elif change=='empty-directory':(root/'foreign-empty-directory').mkdir()
    elif change=='symlink':target.unlink();target.symlink_to(args.parent/'coexist/apps_entry.py')
    elif change=='hardlink':os.link(target,base/'alias')
    out=base/'never'
    with self.assertRaises((ValueError,FileNotFoundError)):P.emit(root,out)
    self.assertFalse(out.exists())
  with tempfile.TemporaryDirectory()as temp:
   base=Path(temp);alias=base/'parent-link';alias.symlink_to(args.parent,target_is_directory=True);out=base/'never'
   with self.assertRaises(ValueError):P.emit(alias,out)
   self.assertFalse(out.exists())
 def test_support_map_and_payload_drift_refused_before_output(self):
  for name in('profile.json','parent676.json','expected698.json','payload/developer/ordinary_entry.py'):
   with self.subTest(name=name),tempfile.TemporaryDirectory()as temp:
    base=Path(temp);factory=base/'factory';shutil.copytree(HERE,factory);p=factory/name;p.write_bytes(p.read_bytes()+b'\n');out=base/'never';row=subprocess.run([sys.executable,'-I','-B',str(factory/'prepare.py'),'--parent',str(args.parent),'--output',str(out)],capture_output=True,timeout=20);self.assertNotEqual(row.returncode,0);self.assertFalse(out.exists())
 def test_existing_nested_and_aliased_outputs_refused_and_stale_atime_read_is_stable(self):
  with tempfile.TemporaryDirectory()as temp:
   base=Path(temp);existing=base/'existing';existing.mkdir();(existing/'sentinel').write_bytes(b'held')
   with self.assertRaises(ValueError):P.emit(args.parent,existing)
   self.assertEqual((existing/'sentinel').read_bytes(),b'held');alias=base/'output-link';alias.symlink_to(existing,target_is_directory=True)
   with self.assertRaises(ValueError):P.emit(args.parent,alias)
   with self.assertRaises(ValueError):P.emit(args.parent,args.parent/'never-source-child')
   self.assertFalse((args.parent/'never-source-child').exists());p=base/'stale-atime';p.write_bytes(b'whole stable ordinary input');before=p.stat();os.utime(p,ns=(1,before.st_mtime_ns));self.assertEqual(P.read(p),b'whole stable ordinary input');self.assertEqual(P.read(p),b'whole stable ordinary input')
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
