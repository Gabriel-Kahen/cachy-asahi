# SPDX-License-Identifier: MIT
"""Exercise emitted Core37, exact old function bodies and ownership refusals."""
import argparse,ast,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--expected',type=Path,required=True)
for n in('core-source','vm-source','kernel-carrier'):p.add_argument('--'+n,type=Path,required=True)
a,rest=p.parse_known_args();spec=importlib.util.spec_from_file_location('_core_module_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
class Controls(unittest.TestCase):
 def test_actual_isolated_cli_exact37_and_original_source_controls(self):
  profile,bodies=F.module_index_inputs();expected=profile['result']['files'];self.assertEqual({n:F.pin(v)for n,v in F.source(a.expected,expected).items()},expected)
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'source'
   for flags in(['--source-only'],['--output',str(out)]):
    r=subprocess.run([sys.executable,'-I','-B',str(HERE/'prepare.py'),'--module-indexes',*flags],capture_output=True,timeout=30);self.assertEqual((r.returncode,r.stderr),(0,b''));self.assertIsNone(json.loads(r.stdout)['actual'])
   self.assertEqual({n:F.pin(v)for n,v in F.source(out,expected).items()},expected)
   commands=[['-m','unittest','-v','test_case','test_protocol','test_host','test_emission','test_initramfs'],['test_route.py','--vm-source',str(a.vm_source)],['test_sources.py','--core-source',str(a.core_source),'--vm-source',str(a.vm_source),'--kernel-carrier',str(a.kernel_carrier)]]
   for args,count in zip(commands,(35,3,6)):
    r=subprocess.run([sys.executable,'-B','-Werror',*args],cwd=out,capture_output=True,timeout=120);self.assertEqual(r.returncode,0,r.stderr[-4096:]);self.assertIn(('Ran %d tests'%count).encode(),r.stderr);sys.stdout.buffer.write(r.stderr)
 def test_complete_old_routes_and_held_functions_still_pass(self):
  for load in(F.inputs,F.virtio20_inputs,F.rollback_inputs,lambda:F.host_clock_inputs(False),lambda:F.host_clock_inputs(True)):load()
  profile=json.loads(F.read(HERE/'host-clock-profile.json'));text=F.read(HERE/'prepare.py').decode();lines=text.splitlines(keepends=True);functions={n.name:F.pin(''.join(lines[n.lineno-1:n.end_lineno]).encode())for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
  self.assertTrue(all(functions[n]==w for n,w in profile['held_functions'].items()))
  for n,w in profile['held_factory'].items():self.assertEqual(F.pin(F.read(HERE/n)),w)
  p,b=F.module_index_inputs();self.assertEqual(len(p['held']),26);self.assertTrue(all(F.pin(b[n])==w for n,w in p['held'].items()))
 def test_profile_payload_drift_aliases_refuse_before_output(self):
  for name,mode in [('module-index-profile.json','drift'),('module-indexes/initramfs.py','drift'),('module-indexes/foreign','extra'),('module-indexes/empty','directory'),('module-indexes/media.py','symlink'),('module-indexes/boot.py','hardlink')]:
   with self.subTest(name=name),tempfile.TemporaryDirectory()as td:
    root=Path(td);factory=root/'factory';shutil.copytree(HERE,factory);p=factory/name;out=root/'never'
    if mode=='drift':p.write_bytes(p.read_bytes()+b'\n')
    elif mode=='extra':p.write_bytes(b'foreign')
    elif mode=='directory':p.mkdir()
    elif mode=='symlink':p.unlink();p.symlink_to(HERE/name)
    else:os.link(p,root/'alias')
    r=subprocess.run([sys.executable,'-I','-B',str(factory/'prepare.py'),'--module-indexes','--output',str(out)],capture_output=True,timeout=30);self.assertNotEqual(r.returncode,0);self.assertFalse(out.exists())
 def test_profile_ambiguity_and_existing_output_refuse(self):
  for flag in('--host-clock','--automatic-rollback','--virtio20'):
   with tempfile.TemporaryDirectory()as td:
    out=Path(td)/'never';r=subprocess.run([sys.executable,'-I','-B',str(HERE/'prepare.py'),'--module-indexes',flag,'--output',str(out)],capture_output=True,timeout=30);self.assertNotEqual(r.returncode,0);self.assertFalse(out.exists())
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'exists';out.mkdir();(out/'sentinel').write_bytes(b'held');alias=Path(td)/'alias';alias.symlink_to(out,target_is_directory=True)
   for target in(out,alias,HERE/'never-nested'):
    with self.assertRaises(ValueError):F.emit_module_indexes(target)
   self.assertEqual((out/'sentinel').read_bytes(),b'held')
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
