# SPDX-License-Identifier: MIT
"""Portable behavior controls; no development artifacts, carrier payload or native actor."""
import ast,importlib.util,json,os,subprocess,sys,tempfile,time,types,unittest
from pathlib import Path
from unittest.mock import patch
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));import prepare as F

def module(path,name):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
PROFILE=F.profile();C=module(HERE/'test_support/common.py','maintained_core_test_common');F.need(F.pin(F.read(HERE/'test_support/common.py'))==PROFILE['test_common']['pin']==PROFILE['base_files']['lane/common.py'],'whole original common for controls');S=module(HERE/'runtime/lane/systemd_seccomp.py','maintained_core_seccomp')
def cache_module(name):
 with patch.dict(sys.modules,{'common':C}):return module(HERE/'runtime/lane'/name,'maintained_'+name.replace('.','_'))
N=cache_module('native248_cache.py');R=cache_module('recovery_cache.py')
class BoundaryReached(Exception):pass
class Controls(unittest.TestCase):
 def test_systemd_fresh_exact_engine_and_pacman_default(self):
  with tempfile.TemporaryDirectory()as td:
   out=Path(td);art=out/'artifacts';art.mkdir();response=subprocess.CompletedProcess(S.COMMAND,0,F.enc(dict(Version='28.0.4',Os='linux',Arch='arm64')),b'')
   with patch.object(S.subprocess,'run',return_value=response)as query:
    self.assertIsNone(S.prepare('pacman',out,art));query.assert_not_called();v=S.prepare('systemd',out,art);query.assert_called_once_with(S.COMMAND,stdin=subprocess.DEVNULL,capture_output=True,timeout=10)
   self.assertEqual(v['profile'],S.PROFILE);self.assertEqual(S.arguments('pacman',out/'systemd-seccomp.json'),[]);self.assertEqual(S.arguments('systemd',out/'systemd-seccomp.json'),['--security-opt','seccomp='+str(out/'systemd-seccomp.json')]);S.verify('systemd',out)
   (out/'systemd-seccomp.json').write_bytes(b'foreign')
   with self.assertRaises(ValueError):S.verify('systemd',out)
 def test_fresh_engine_version_arch_and_stderr_refusal(self):
  for server,stderr in((dict(Version='29',Os='linux',Arch='arm64'),b''),(dict(Version='28.0.4',Os='linux',Arch='amd64'),b''),(dict(Version='28.0.4',Os='linux',Arch='arm64'),b'warning')):
   with tempfile.TemporaryDirectory()as td:
    out=Path(td);art=out/'artifacts';art.mkdir()
    with patch.object(S.subprocess,'run',return_value=subprocess.CompletedProcess(S.COMMAND,0,F.enc(server),stderr)),self.assertRaises(ValueError):S.prepare('systemd',out,art)
    self.assertFalse((out/'systemd-seccomp.json').exists())
 def test_source_derived_late_cache_path_survives_real_environment_clear(self):
  with tempfile.TemporaryDirectory()as td:
   workspace=Path(td);source=workspace/'core-source';(source/'lane').mkdir(parents=True);(source/'lane/native248-cache-profile.json').write_bytes(F.read(HERE/'runtime/lane/native248-cache-profile.json'));out=workspace/'output';out.mkdir(mode=0o700);(out/'context').mkdir();(out/'context/deps').mkdir(mode=0o700);calls=[]
   def boundary(carrier,deadline,p):calls.append((carrier,p['source']));raise BoundaryReached
   with patch.object(C,'ROOT',source),patch.dict(os.environ,{},clear=True),patch.object(N,'prove',side_effect=boundary),self.assertRaises(BoundaryReached):N.seed(out,time.monotonic()+10)
   self.assertEqual(calls,[(workspace/'core-native248-recovered-inputs','ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad')]);self.assertEqual(list((out/'context/deps').iterdir()),[])
 def test_retained64_fixed_path_and_original_prefetch_order(self):
  with tempfile.TemporaryDirectory()as td:
   workspace=Path(td);source=workspace/'core-source'
   with patch.object(C,'ROOT',source),patch.dict(os.environ,{'GITHUB_WORKSPACE':str(workspace)}):self.assertEqual(R.fixed_carrier(),workspace/'core64-recovered-inputs')
  raw=F.read(HERE/'runtime/lane/prefetch.py').decode();self.assertLess(raw.index('prepare_core(core)'),raw.index('recovery_cache.seed(core,deadline)'));self.assertLess(raw.index('recovery_cache.seed(core,deadline)'),raw.index("str(C.ROOT/'lane/acquire64.py')"));self.assertLess(raw.index("str(C.ROOT/'lane/acquire64.py')"),raw.index('baseline_inputs=m.prepare(out,deadline)'));self.assertLess(raw.index('baseline_inputs=m.prepare(out,deadline)'),raw.index('native248_cache.seed(out,deadline)'))
 def test_exact_two_rules_original_assertions_and_NULL_selection(self):
  v=F.decode(F.read(HERE/'runtime/lane/systemd-seccomp.json'));self.assertEqual(v['syscalls'][-2:],[dict(names=['unshare'],action='SCMP_ACT_ALLOW',args=[dict(index=0,value=268435456,op='SCMP_CMP_EQ')]),dict(names=['chroot'],action='SCMP_ACT_ALLOW')]);self.assertEqual(v['defaultAction'],'SCMP_ACT_ERRNO');self.assertEqual(v['defaultErrnoRet'],1);self.assertIsNone(PROFILE['actual_source']);self.assertIsNone(PROFILE['actual_ref']);self.assertIsNone(PROFILE['actual_run']);self.assertEqual(PROFILE['bounds']['makepkg'],14400);self.assertEqual(PROFILE['bounds']['owner'],19680)
  for n in('effective-profile/systemd/cachy-asahi-owned-userns.patch','lane/test_environment.py','lane/mechanism/probe.c'):self.assertEqual(PROFILE['base_files'][n],PROFILE['expected_sources']['selected'][n])
 def test_real_stale_atime_and_profile_tamper_refusal(self):
  with tempfile.TemporaryDirectory(dir='/dev/shm')as td:
   p=Path(td)/'held';p.write_bytes(b'held');os.utime(p,ns=(1,p.stat().st_mtime_ns));before=p.stat();self.assertEqual(F.read(p),b'held');self.assertNotEqual(before.st_atime_ns,p.stat().st_atime_ns)
  with patch.object(F,'PROFILE_SHA','0'*64),self.assertRaises(ValueError):F.profile()
if __name__=='__main__':unittest.main(verbosity=2)
