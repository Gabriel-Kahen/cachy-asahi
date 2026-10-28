#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Portable exact emission/refusal and original27 source controls; no actors."""
import argparse,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--expected',type=Path,required=True)
for n in('core-source','vm-source','core7','core64','kernel-carrier'):p.add_argument('--'+n,type=Path,required=True)
args,rest=p.parse_known_args();spec=importlib.util.spec_from_file_location('core7_two_boot_factory',HERE/'prepare.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
class Controls(unittest.TestCase):
 def test_exact_emission_all_external_inputs_and_original27_source_controls(self):
  profile,bodies=P.inputs();self.assertEqual({n:P.pin(raw)for n,raw in P.source(args.expected,profile['result']['files']).items()},profile['result']['files']);runtime=json.loads(bodies['profile.json'])
  for role,path in(('core800',args.core_source),('ksm637',args.vm_source),('core7_carrier',args.core7),('kernel_carrier',args.kernel_carrier)):
   expected=runtime['source_profiles'][role];self.assertEqual({n:P.pin(raw)for n,raw in P.source(path,expected['files'],128*1024**2).items()},expected['files'])
  native=json.loads(P.read(args.core_source/'scripts/ci/core-native-lifecycle/input-profile.json'));retained=native['retained64'];self.assertEqual(retained['source'],'7dfce898755583bbf8081aae04d8b8579f66be58');self.assertEqual(len(retained['files']),133);self.assertEqual({n:P.pin(raw)for n,raw in P.source(args.core64,retained['files'],128*1024**2).items()},retained['files']);self.assertEqual(native['retained574']['source'],'ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad');self.assertEqual(len(native['retained574']['files']),1154)
  with tempfile.TemporaryDirectory()as t:
   out=Path(t)/'source'
   for argv in([sys.executable,'-I','-B',str(HERE/'prepare.py'),'--help'],[sys.executable,'-I','-B',str(HERE/'prepare.py'),'--source-only'],[sys.executable,'-I','-B',str(HERE/'prepare.py'),'--output',str(out)]):
    r=subprocess.run(argv,cwd='/',capture_output=True,timeout=20);self.assertEqual(r.returncode,0,r.stderr)
   self.assertEqual({n:P.pin(raw)for n,raw in P.source(out,profile['result']['files']).items()},profile['result']['files'])
   extra={'test_route.py':['--vm-source',str(args.vm_source)],'test_sources.py':['--core-source',str(args.core_source),'--vm-source',str(args.vm_source),'--kernel-carrier',str(args.kernel_carrier)]}
   for name,count in(('test_case.py',8),('test_protocol.py',3),('test_route.py',3),('test_sources.py',6),('test_emission.py',4),('test_host.py',3)):
    r=subprocess.run([sys.executable,'-I','-B',str(out/name),*extra.get(name,[])],cwd='/',capture_output=True,timeout=60);self.assertEqual(r.returncode,0,(name,r.stderr));self.assertIn(('Ran %d tests'%count).encode(),r.stderr)
 def test_factory_profile_template_and_membership_drift_before_output(self):
  for name,action in(('profile.json','drift'),('templates/guest.py','drift'),('templates/hook.py','missing'),('templates/foreign','extra'),('templates/empty','directory'),('templates/effects.py','symlink'),('templates/boot.py','hardlink')):
   with self.subTest(name=name,action=action),tempfile.TemporaryDirectory()as t:
    root=Path(t);factory=root/'factory';shutil.copytree(HERE,factory);target=factory/name
    if action=='drift':target.write_bytes(target.read_bytes()+b'\n')
    elif action=='missing':target.unlink()
    elif action=='extra':target.write_bytes(b'foreign')
    elif action=='directory':target.mkdir()
    elif action=='symlink':target.unlink();target.symlink_to(HERE/name)
    else:os.link(target,root/'alias')
    output=root/'never';r=subprocess.run([sys.executable,'-I','-B',str(factory/'prepare.py'),'--output',str(output)],cwd='/',capture_output=True,timeout=20);self.assertNotEqual(r.returncode,0);self.assertFalse(output.exists())
 def test_existing_nested_symlink_output_and_stale_atime_identity(self):
  with tempfile.TemporaryDirectory()as t:
   root=Path(t);existing=root/'existing';existing.mkdir();(existing/'sentinel').write_bytes(b'held');link=root/'alias';link.symlink_to(existing,target_is_directory=True)
   for output in(existing,link,HERE/'never-nested'):
    with self.subTest(output=str(output)),self.assertRaises(ValueError):P.emit(output)
   self.assertEqual((existing/'sentinel').read_bytes(),b'held');self.assertFalse((HERE/'never-nested').exists());file=root/'stale-atime';file.write_bytes(b'whole ordinary source');st=file.stat();os.utime(file,ns=(1,st.st_mtime_ns));self.assertEqual(P.read(file),b'whole ordinary source');self.assertEqual(P.read(file),b'whole ordinary source')
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
