#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact explicit rollback36; no default drift, actors or native authority."""
import argparse,ast,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--expected',type=Path,required=True)
for name in('core-source','vm-source','kernel-carrier'):p.add_argument('--'+name,type=Path,required=True)
a,rest=p.parse_known_args();spec=importlib.util.spec_from_file_location('_rollback_factory',HERE/'prepare.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
class Controls(unittest.TestCase):
 def test_exact36_public_source_actual_isolated_entry_and_all40_source_controls(self):
  profile,bodies=P.rollback_inputs();self.assertEqual({n:P.pin(v)for n,v in P.source(a.expected,profile['result']['files']).items()},profile['result']['files'])
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'source'
   for command in([sys.executable,'-I','-B',str(HERE/'prepare.py'),'--help'],[sys.executable,'-I','-B',str(HERE/'prepare.py'),'--automatic-rollback','--source-only'],[sys.executable,'-I','-B',str(HERE/'prepare.py'),'--automatic-rollback','--output',str(out)]):
    r=subprocess.run(command,cwd='/',capture_output=True,timeout=20);self.assertEqual((r.returncode,r.stderr),(0,b''))
    if command[-1]!='--help':self.assertIsNone(json.loads(r.stdout)['actual'])
   self.assertEqual({n:P.pin(v)for n,v in P.source(out,profile['result']['files']).items()},profile['result']['files'])
   extra={'test_route.py':['--vm-source',str(a.vm_source)],'test_sources.py':['--core-source',str(a.core_source),'--vm-source',str(a.vm_source),'--kernel-carrier',str(a.kernel_carrier)],'test_rollback.py':['--core-source',str(a.core_source)]}
   for name,count in(('test_case.py',12),('test_protocol.py',3),('test_emission.py',4),('test_host.py',3),('test_route.py',3),('test_sources.py',6),('test_rollback.py',9)):
    r=subprocess.run([sys.executable,'-I','-B',str(out/name),*extra.get(name,[])],cwd='/',capture_output=True,timeout=60);self.assertEqual(r.returncode,0,(name,r.stderr));self.assertIn(('Ran %d tests'%count).encode(),r.stderr);sys.stdout.buffer.write((name+'\n').encode()+r.stderr)
 def test_all_old_factory_support_and_nonCLI_functions_held(self):
  profile,_=P.rollback_inputs();old,_=P.virtio20_inputs();self.assertEqual(profile['parent']['files'],old['result']['files']);self.assertEqual(len(profile['held']),18);self.assertEqual(len(profile['held_factory']),44)
  for name,row in profile['held_factory'].items():self.assertEqual(P.pin(P.read(HERE/name)),row,name)
  raw=P.read(HERE/'prepare.py').decode();lines=raw.splitlines(keepends=True);definitions={n.name:P.pin(''.join(lines[n.lineno-1:n.end_lineno]).encode())for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
  self.assertTrue(all(definitions[n]==v for n,v in profile['held_functions'].items()))
 def test_support_drift_alias_ambiguous_profile_refuses_before_output(self):
  for name,mode in(('automatic-rollback-profile.json','drift'),('automatic-rollback/rollback.py','drift'),('automatic-rollback/guest.py','missing'),('automatic-rollback/foreign','extra'),('automatic-rollback/empty','directory'),('automatic-rollback/host.py','symlink'),('automatic-rollback/validate.py','hardlink')):
   with self.subTest(name=name),tempfile.TemporaryDirectory()as td:
    root=Path(td);factory=root/'factory';shutil.copytree(HERE,factory);path=factory/name
    if mode=='drift':path.write_bytes(path.read_bytes()+b'\n')
    elif mode=='missing':path.unlink()
    elif mode=='extra':path.write_bytes(b'foreign')
    elif mode=='directory':path.mkdir()
    elif mode=='symlink':path.unlink();path.symlink_to(HERE/name)
    else:os.link(path,root/'alias')
    out=root/'never';r=subprocess.run([sys.executable,'-I','-B',str(factory/'prepare.py'),'--automatic-rollback','--output',str(out)],cwd='/',capture_output=True,timeout=20);self.assertNotEqual(r.returncode,0);self.assertFalse(out.exists())
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'never';r=subprocess.run([sys.executable,'-I','-B',str(HERE/'prepare.py'),'--virtio20','--automatic-rollback','--output',str(out)],cwd='/',capture_output=True,timeout=20);self.assertNotEqual(r.returncode,0);self.assertFalse(out.exists());out.mkdir();(out/'sentinel').write_bytes(b'held');alias=out.parent/'alias';alias.symlink_to(out,target_is_directory=True)
   for path in(out,alias,HERE/'nested'):
    with self.assertRaises(ValueError):P.emit_rollback(path)
   self.assertEqual((out/'sentinel').read_bytes(),b'held')
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
