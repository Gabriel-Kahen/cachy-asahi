#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Optional exact34 correction and all31 emitted controls; source-only, no native acceptance."""
import argparse,ast,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
parser=argparse.ArgumentParser();parser.add_argument('--expected',type=Path,required=True)
for n in('core-source','vm-source','kernel-carrier'):parser.add_argument('--'+n,type=Path,required=True)
a,rest=parser.parse_known_args();spec=importlib.util.spec_from_file_location('_core7_virtio20_factory',HERE/'prepare.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
class Controls(unittest.TestCase):
 def test_exact_optional_emission_isolated_entry_and_all31_source_controls(self):
  profile,bodies=P.virtio20_inputs();self.assertEqual({n:P.pin(v)for n,v in P.source(a.expected,profile['result']['files']).items()},profile['result']['files'])
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'source'
   for argv in([sys.executable,'-I','-B',str(HERE/'prepare.py'),'--help'],[sys.executable,'-I','-B',str(HERE/'prepare.py'),'--virtio20','--source-only'],[sys.executable,'-I','-B',str(HERE/'prepare.py'),'--virtio20','--output',str(out)]):
    p=subprocess.run(argv,cwd='/',capture_output=True,timeout=20);self.assertEqual((p.returncode,p.stderr),(0,b''))
   self.assertEqual({n:P.pin(v)for n,v in P.source(out,profile['result']['files']).items()},profile['result']['files'])
   extras={'test_route.py':['--vm-source',str(a.vm_source)],'test_sources.py':['--core-source',str(a.core_source),'--vm-source',str(a.vm_source),'--kernel-carrier',str(a.kernel_carrier)]}
   for name,count in(('test_case.py',12),('test_protocol.py',3),('test_route.py',3),('test_sources.py',6),('test_emission.py',4),('test_host.py',3)):
    p=subprocess.run([sys.executable,'-I','-B',str(out/name),*extras.get(name,[])],cwd='/',capture_output=True,timeout=60);self.assertEqual(p.returncode,0,(name,p.stderr));self.assertIn(('Ran %d tests'%count).encode(),p.stderr);sys.stdout.write('EMITTED_SOURCE_CONTROL '+name+'\n');sys.stdout.flush();sys.stdout.buffer.write(p.stderr)
 def test_old_default_profile_templates_tests_and_nonCLI_functions_held(self):
  p,bodies=P.virtio20_inputs();old,original=P.inputs();self.assertEqual(old['result']['files'],p['parent']['files']);self.assertEqual(len(p['held']),22)
  for n,row in p['held_factory'].items():self.assertEqual(P.pin(P.read(HERE/n)),row,n)
  raw=P.read(HERE/'prepare.py').decode();lines=raw.splitlines(keepends=True);functions={n.name:P.pin(''.join(lines[n.lineno-1:n.end_lineno]).encode())for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
  self.assertTrue(all(functions[name]==row for name,row in p['held_functions'].items()))
 def test_profile_payload_membership_and_alias_drift_before_output(self):
  for name,kind in(('virtio20-profile.json','drift'),('virtio20/case.py','drift'),('virtio20/host.py','missing'),('virtio20/foreign','extra'),('virtio20/empty','directory'),('virtio20/boot.py','symlink'),('virtio20/validate.py','hardlink')):
   with self.subTest(name=name,kind=kind),tempfile.TemporaryDirectory()as td:
    root=Path(td);factory=root/'factory';shutil.copytree(HERE,factory);p=factory/name
    if kind=='drift':p.write_bytes(p.read_bytes()+b'\n')
    elif kind=='missing':p.unlink()
    elif kind=='extra':p.write_bytes(b'foreign')
    elif kind=='directory':p.mkdir()
    elif kind=='symlink':p.unlink();p.symlink_to(HERE/name)
    else:os.link(p,root/'alias')
    output=root/'never';r=subprocess.run([sys.executable,'-I','-B',str(factory/'prepare.py'),'--virtio20','--output',str(output)],cwd='/',capture_output=True,timeout=20);self.assertNotEqual(r.returncode,0);self.assertFalse(output.exists())
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);out=root/'exists';out.mkdir();(out/'sentinel').write_bytes(b'held');link=root/'alias';link.symlink_to(out,target_is_directory=True)
   for target in(out,link,HERE/'nested'):
    with self.assertRaises(ValueError):P.emit_virtio20(target)
   self.assertEqual((out/'sentinel').read_bytes(),b'held')
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
