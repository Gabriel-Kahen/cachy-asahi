# SPDX-License-Identifier: MIT
"""Inert diagnostic controls; no actual mount, Docker or namespace actor."""
from pathlib import Path
from types import SimpleNamespace as NS
import ctypes,errno,importlib.util,json,os,tempfile,unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('proc_probe_control',HERE/'proc_mount.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)

class Controls(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.work=Path(self.temp.name);self.target=self.work/'probe'
 def facts(self):return dict(status={k:hex(P.MASK) for k in ('CapEff','CapPrm','CapBnd')}|dict(CapInh='0',CapAmb='0',NoNewPrivs='1',Seccomp='2'))
 def model(self,utility,legacy,absent=True):
  state={'mounted':False};commands=NS(report={'commands':[]})
  def call(argv,**kwargs):
   if argv[0].endswith('/mount'):
    self.assertEqual(argv[1:],['-t','proc','-o','ro,nosuid,nodev,noexec','proc',str(self.target)]);self.assertEqual(kwargs['seconds'],10)
    commands.report['commands'].append(dict(exit_code=utility,group_absence_verified=absent));state['mounted']=utility==0
    if utility:raise ValueError('original utility refusal')
   else:self.assertEqual(argv,['/usr/bin/umount',str(self.target)]);state['mounted']=False;commands.report['commands'].append(dict(exit_code=0,group_absence_verified=True))
  def syscall(target,unmount=False):
   self.assertEqual(target,self.target)
   if unmount:state['mounted']=False;return dict(returncode=0,errno=0)
   state['mounted']=legacy==0;return dict(returncode=0 if legacy==0 else -1,errno=legacy)
  commands.call=call
  with patch.object(P,'TARGET',self.target),patch.object(P,'guard'),patch.object(P,'facts',side_effect=self.facts),patch.object(P,'mounted',side_effect=lambda:['owned'] if state['mounted'] else []),patch.object(P,'verify_mount',return_value={'status':'PASS_EXACT_READONLY_PROC_FLAGS'}),patch.object(P,'syscall',side_effect=syscall):
   value=P.check(commands,self.work)
  return value,commands
 def test_denied_routes_capture_errno_fail_before_copy_and_clean_owned_target(self):
  value,_=self.model(32,errno.EPERM);self.assertEqual(value['status'],'FAIL_PROC_MOUNT_PREFLIGHT');self.assertEqual(value['legacy']['errno'],errno.EPERM)
  self.assertEqual(value['classification'],'BOTH_ROUTES_DENIED_SECURITY_LAYER_NOT_DISAMBIGUATED');self.assertEqual(value['cleanup'],'PASS_OWNED_EMPTY_PROBE_REMOVED');self.assertFalse(self.target.exists())
 def test_utility_refusal_with_legacy_success_is_diagnostic_still_fail(self):
  value,_=self.model(32,0);self.assertEqual(value['classification'],'UTILITY_AND_LEGACY_DIFFER');self.assertEqual(value['status'],'FAIL_PROC_MOUNT_PREFLIGHT');self.assertFalse(self.target.exists())
 def test_both_routes_success_requires_verified_teardown(self):
  value,commands=self.model(0,0);self.assertEqual(value['status'],'PASS_READONLY_PROC_PREFLIGHT');self.assertEqual(value['cleanup'],'PASS_OWNED_EMPTY_PROBE_REMOVED');self.assertEqual(len(commands.report['commands']),2);self.assertFalse(self.target.exists())
 def test_unknown_process_group_preserves_probe_for_outer_owner(self):
  value,_=self.model(32,errno.EPERM,absent=False);self.assertEqual(value['status'],'FAIL_PROC_MOUNT_PREFLIGHT');self.assertEqual(value['cleanup'],'FAIL_RETAIN_OUTER_OWNED_CONTAINER');self.assertTrue(self.target.is_dir());self.assertNotIn('legacy',value)
 def test_existing_foreign_probe_never_removed(self):
  self.target.mkdir();(self.target/'foreign').write_bytes(b'preserve');value,_=self.model(32,errno.EPERM);self.assertEqual(value['status'],'FAIL_PROC_MOUNT_PREFLIGHT');self.assertEqual((self.target/'foreign').read_bytes(),b'preserve')
 def test_exact_legacy_syscall_flags_and_errno_without_invoking_kernel(self):
  class Function:
   def __init__(self,code,number):self.code,self.number=code,number;self.calls=[]
   def __call__(self,*args):self.calls.append(args);ctypes.set_errno(self.number);return self.code
  mount=Function(-1,errno.EACCES);unmount=Function(0,0);libc=NS(mount=mount,umount2=unmount)
  value=P.syscall(Path('/work/.gnu-readonly-proc-probe'),libc=libc);self.assertEqual(value['errno_name'],'EACCES');self.assertEqual(mount.calls,[(b'proc',b'/work/.gnu-readonly-proc-probe',b'proc',15,None)])
  P.syscall(Path('/work/.gnu-readonly-proc-probe'),unmount=True,libc=libc);self.assertEqual(unmount.calls,[(b'/work/.gnu-readonly-proc-probe',0)])
 def test_host_call_refuses_before_path_or_mount_work(self):
  with self.assertRaisesRegex(ValueError,'same-role'):P.check(None,Path('/not-work'))
  self.assertEqual(list(self.work.iterdir()),[])
 def test_security_profile_text_is_bounded_hashed_and_explicitly_clipped(self):
  raw=b'x'*600
  with patch.object(P,'bounded',return_value=raw):v=P.text_fact('/inert')
  self.assertTrue(v['clipped']);self.assertEqual(len(v['value']),512);self.assertEqual(v['bytes'],600)
  with patch.object(P,'bounded',return_value=b'bad\x00profile'),self.assertRaises(ValueError):P.text_fact('/inert')

 def test_both_real_main_bodies_stop_before_copy_on_failed_preflight(self):
  import sys
  for lane in ('lifecycle','interruption'):
   folder=HERE.parent/('glibc-gnu-provider-'+lane)
   def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
   common=load('proc_main_common_'+lane,folder/'common.py')
   with patch.dict(sys.modules,{'common':common}):module=load('proc_main_'+lane,folder/'container.py')
   work=self.work/lane;work.mkdir();out=self.work/(lane+'-out');out.mkdir()
   failure=dict(status='FAIL_PROC_MOUNT_PREFLIGHT',cleanup='PASS_OWNED_EMPTY_PROBE_REMOVED')
   api=dict(capabilities=NS(disjoint=lambda *a:None),proc_probe=NS(check=lambda *a:failure))
   with self.subTest(lane=lane),patch.object(module,'guard'),patch.object(module,'WORK',work),patch.object(module,'OUT',out),patch.object(module.C,'configuration',return_value=({}, {}, {}, {})),patch.object(module.C,'helpers',return_value=api),patch.object(module.os,'chown'),patch.dict(os.environ,INPUT_INDEX_SHA256='0'*64,OUTPUT_UID=str(os.getuid()),OUTPUT_GID=str(os.getgid())),patch.object(module,'run_case',side_effect=AssertionError('must never copy')) as case:
    self.assertEqual(module.main(),1);case.assert_not_called()
   result=json.loads((out/'result.json').read_bytes());self.assertEqual(result['status'],'FAIL');self.assertEqual(result['proc_preflight'],failure);self.assertEqual(result['cases'],{})

if __name__=='__main__':unittest.main()
