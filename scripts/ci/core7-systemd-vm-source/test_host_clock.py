#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact optional clock35/37, whole old routes held; source-only no actors."""
import argparse,ast,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--expected-two',type=Path,required=True);p.add_argument('--expected-four',type=Path,required=True)
for name in('core-source','vm-source','kernel-carrier'):p.add_argument('--'+name,type=Path,required=True)
a,rest=p.parse_known_args();spec=importlib.util.spec_from_file_location('_core7_host_clock_factory',HERE/'prepare.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
class Controls(unittest.TestCase):
 def test_exact_both_public_emissions_actual_isolated_entries_and_all90_source_controls(self):
  for four,expected in((False,a.expected_two),(True,a.expected_four)):
   profile,bodies=P.host_clock_inputs(four);wanted=profile['result']['files'];self.assertEqual({n:P.pin(v)for n,v in P.source(expected,wanted).items()},wanted)
   with tempfile.TemporaryDirectory()as td:
    out=Path(td)/'source';flags=['--host-clock',*(['--automatic-rollback']if four else[])]
    for command in([sys.executable,'-I','-B',str(HERE/'prepare.py'),'--help'],[sys.executable,'-I','-B',str(HERE/'prepare.py'),*flags,'--source-only'],[sys.executable,'-I','-B',str(HERE/'prepare.py'),*flags,'--output',str(out)]):
     r=subprocess.run(command,cwd='/',capture_output=True,timeout=20);self.assertEqual((r.returncode,r.stderr),(0,b''))
     if command[-1]!='--help':self.assertIsNone(json.loads(r.stdout)['actual'])
    self.assertEqual({n:P.pin(v)for n,v in P.source(out,wanted).items()},wanted)
    for command in([sys.executable,'-I','-B',str(out/'entry.py'),'source','--source',str(out)],[sys.executable,'-I','-B',str(out/'guest.py'),'--help']):
     r=subprocess.run(command,cwd='/',capture_output=True,timeout=20);self.assertEqual((r.returncode,r.stderr),(0,b''))
    extra={'test_route.py':['--vm-source',str(a.vm_source)],'test_sources.py':['--core-source',str(a.core_source),'--vm-source',str(a.vm_source),'--kernel-carrier',str(a.kernel_carrier)],'test_rollback.py':['--core-source',str(a.core_source)]};tests=[('test_case.py',22 if four else 21),('test_protocol.py',3),('test_emission.py',4),('test_host.py',3),('test_route.py',3),('test_sources.py',6)]+([('test_rollback.py',9)]if four else[])
    for name,count in tests:
     r=subprocess.run([sys.executable,'-W','error','-I','-B',str(out/name),*extra.get(name,[])],cwd='/',capture_output=True,timeout=60);self.assertEqual(r.returncode,0,(name,r.stderr));self.assertIn(('Ran %d tests'%count).encode(),r.stderr);sys.stdout.buffer.write(('CLOCK_EMITTED '+str(four)+' '+name+'\n').encode()+r.stderr)
 def test_all_old_factory_inputs_functions_and_output_maps_held(self):
  raw=P.read(HERE/'host-clock-profile.json');P.need(P.pin(raw)==P.HOST_CLOCK_PROFILE,'pinned profile');profile=json.loads(raw)
  for n,row in profile['held_factory'].items():self.assertEqual(P.pin(P.read(HERE/n)),row,n)
  raw=P.read(HERE/'prepare.py').decode();lines=raw.splitlines(keepends=True);definitions={node.name:P.pin(''.join(lines[node.lineno-1:node.end_lineno]).encode())for node in ast.parse(raw).body if isinstance(node,ast.FunctionDef)};self.assertTrue(all(definitions[n]==row for n,row in profile['held_functions'].items()))
  for four,load in((False,P.virtio20_inputs),(True,P.rollback_inputs)):
   old,_=load();new,_=P.host_clock_inputs(four);self.assertEqual(new['parent']['files'],old['result']['files']);self.assertEqual(len(new['held']),24)
 def test_profile_payload_whole_closure_alias_drift_refuses_before_output(self):
  for name,mode in(('host-clock-profile.json','drift'),('host-clock/two-boot/clock.py','drift'),('host-clock/four-boot/rollback.py','missing'),('host-clock/foreign','extra'),('host-clock/empty','directory'),('host-clock/four-boot/host.py','symlink'),('host-clock/two-boot/validate.py','hardlink')):
   with self.subTest(name=name),tempfile.TemporaryDirectory()as td:
    root=Path(td);factory=root/'factory';shutil.copytree(HERE,factory);path=factory/name
    if mode=='drift':path.write_bytes(path.read_bytes()+b'\n')
    elif mode=='missing':path.unlink()
    elif mode=='extra':path.write_bytes(b'foreign')
    elif mode=='directory':path.mkdir()
    elif mode=='symlink':path.unlink();path.symlink_to(HERE/name)
    else:os.link(path,root/'alias')
    for four in(False,True):
     out=root/('never'+str(four));r=subprocess.run([sys.executable,'-I','-B',str(factory/'prepare.py'),'--host-clock',*(['--automatic-rollback']if four else[]),'--output',str(out)],cwd='/',capture_output=True,timeout=20);self.assertNotEqual(r.returncode,0);self.assertFalse(out.exists())
 def test_finite_profile_ambiguity_fresh_output_and_alias_refusal(self):
  for flags in(('--host-clock','--virtio20'),('--host-clock','--virtio20','--automatic-rollback')):
   with tempfile.TemporaryDirectory()as td:
    out=Path(td)/'never';r=subprocess.run([sys.executable,'-I','-B',str(HERE/'prepare.py'),*flags,'--output',str(out)],cwd='/',capture_output=True,timeout=20);self.assertNotEqual(r.returncode,0);self.assertFalse(out.exists())
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);out=root/'exists';out.mkdir();(out/'sentinel').write_bytes(b'held');alias=root/'alias';alias.symlink_to(out,target_is_directory=True)
   for four in(False,True):
    for target in(out,alias,HERE/'never-nested'):
     with self.assertRaises(ValueError):P.emit_host_clock(target,four)
   self.assertEqual((out/'sentinel').read_bytes(),b'held');self.assertFalse((HERE/'never-nested').exists())
  with self.assertRaises(ValueError):P.host_clock_inputs('four-boot')
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
