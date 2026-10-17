# SPDX-License-Identifier: MIT
"""Exact direct-mount data controls. No actual mount/container/namespace actor."""
from pathlib import Path
from types import SimpleNamespace as NS
import ctypes,errno,importlib.util,json,os,stat,sys,tempfile,unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('legacy_proc_controls',HERE/'proc_mount.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
class Function:
 def __init__(self,code=0,number=0):self.code,self.number=code,number;self.calls=[]
 def __call__(self,*args):self.calls.append(args);ctypes.set_errno(self.number);return self.code
class Controls(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.work=Path(self.temp.name);self.target=self.work/'probe';self.root=self.work/'pristine/root';(self.root/'proc').mkdir(parents=True);(self.root/'dev').mkdir();self.events=[];self.mounts={};self.denied=None;self.failed_umount=False
 def facts(self):return dict(status={k:hex(P.MASK) for k in ('CapEff','CapPrm','CapBnd')}|dict(CapInh='0',CapAmb='0',NoNewPrivs='1',Seccomp='2'))
 def invoke(self,target,unmount=False,bind=False):
  self.events.append((target,unmount,bind));failure=unmount and self.failed_umount or not unmount and self.denied==('bind' if bind else 'proc');value=dict(api='umount2' if unmount else 'mount',returncode=-1 if failure else 0,errno=errno.EACCES if failure else 0,flags=0 if unmount else 4096 if bind else 15)
  if not failure:
   if unmount:del self.mounts[target]
   else:self.mounts[target]=str(len(self.events))+' 2 0:1 / '+str(target)+' ro,nosuid,nodev,noexec - proc proc ro'
  return value
 def model(self):
  # Model container-owned null; the host sandbox remaps device owners. No kernel mount.
  fstat=os.fstat;lstat=Path.lstat
  def root_null(info):
   if stat.S_ISCHR(info.st_mode) and info.st_rdev==os.makedev(1,3):
    return NS(**{k:getattr(info,k) for k in ('st_dev','st_ino','st_mode','st_rdev','st_nlink','st_size')},st_uid=0,st_gid=0)
   return info
  stack=__import__('contextlib').ExitStack();stack.enter_context(patch.object(P.os,'fstat',side_effect=lambda fd:root_null(fstat(fd))));stack.enter_context(patch.object(Path,'lstat',lambda path,*a,**kw:root_null(lstat(path,*a,**kw))));stack.enter_context(patch.object(P,'guard'));stack.enter_context(patch.object(P,'facts',side_effect=self.facts));stack.enter_context(patch.object(P,'invoke',side_effect=self.invoke));stack.enter_context(patch.object(P,'mounted',side_effect=lambda target=None:[self.mounts[target or self.target]] if (target or self.target) in self.mounts else []));stack.enter_context(patch.object(P,'verify_mount',return_value=dict(status='PASS_EXACT_READONLY_PROC_FLAGS')));stack.enter_context(patch.object(P,'verify_bind',return_value=dict(status='PASS_EXACT_DEV_NULL_BIND_IDENTITY')));stack.enter_context(patch.object(P,'source_mount',return_value='2 1 0:1 / /dev rw,nosuid - tmpfs tmpfs rw'));stack.enter_context(patch.object(P,'ROOTS',(self.root,)));stack.enter_context(patch.object(P,'TARGET',self.target));return stack
 def status_facts(self,changes=None,omit=()):
  fields={key:'0' for key in P.STATUS};fields.update(Uid='0 0 0 0',Gid='0 0 0 0',Groups='',CapEff=hex(P.MASK)[2:],CapPrm=hex(P.MASK)[2:],CapBnd=hex(P.MASK)[2:],NoNewPrivs='1',Seccomp='2',Seccomp_filters='2');fields.update(changes or {})
  raw=''.join(key+':\t'+value+'\n' for key,value in fields.items() if key not in omit).encode()
  def bounded(path,cap):return raw if path=='/proc/self/status' else b'0 0 4294967295\n'
  with patch.object(P,'bounded',side_effect=bounded),patch.object(P.os,'readlink',side_effect=OSError(errno.ENOENT,'inert namespace absent')),patch.object(P,'text_fact',return_value={}),patch.object(P,'mounts',return_value=[]):return P.facts()
 def test_empty_linux_supplementary_groups_retained_with_exact_cap_checks(self):
  value=self.status_facts();self.assertEqual(value['status']['Groups'],'');P.caps(value)
  for groups in ('0','0 1 65534','  \t'):
   with self.subTest(groups=groups):self.assertEqual(self.status_facts({'Groups':groups})['status']['Groups'],groups.strip())
 def test_empty_non_groups_fields_still_refuse(self):
  for key in set(P.STATUS)-{'Groups'}:
   for value in ('',' \t'):
    with self.subTest(key=key,value=value),self.assertRaisesRegex(ValueError,'finite self status field'):self.status_facts({key:value})
 def test_malformed_or_oversize_groups_and_other_status_still_refuse(self):
  for key in P.STATUS:
   for value in ('not-numeric!','0'*1025):
    with self.subTest(key=key,value=value[:20]),self.assertRaisesRegex(ValueError,'finite self status field'):self.status_facts({key:value})
 def test_empty_groups_does_not_relax_cap_nnp_seccomp_or_missing_fields(self):
  for key,value in [('CapEff','0'),('CapPrm','0'),('CapBnd','0'),('CapInh','1'),('CapAmb','1'),('NoNewPrivs','0'),('Seccomp','0')]:
   with self.subTest(key=key),self.assertRaises(ValueError):P.caps(self.status_facts({key:value}))
  self.assertIsNone(self.status_facts(omit=('Groups',))['status']['Groups'])
 def test_exact_ten_caps_include_owned_group_signal_authority(self):
  self.assertEqual(P.MASK,2149843195);self.assertEqual(P.MASK,0x802400fb);self.assertEqual({n for n in range(64) if P.MASK&(1<<n)},{0,1,3,4,5,6,7,18,21,31});P.caps(self.facts())
  for key in ('CapEff','CapPrm','CapBnd'):
   old=self.facts();old['status'][key]=hex(2149843163)
   with self.assertRaises(ValueError):P.caps(old)
 def test_exact_three_libc_apis_and_errno(self):
  mount=Function(-1,errno.EACCES);umount=Function();libc=NS(mount=mount,umount2=umount)
  result=P.syscall(Path('/work/.gnu-readonly-proc-probe'),libc=libc);self.assertEqual(result['errno_name'],'EACCES');self.assertEqual(mount.calls[-1],(b'proc',b'/work/.gnu-readonly-proc-probe',b'proc',15,None))
  P.syscall(Path('/work/pristine/root/dev/null'),bind=True,libc=libc);self.assertEqual(mount.calls[-1],(b'/dev/null',b'/work/pristine/root/dev/null',None,4096,None));P.syscall(Path('/work/pristine/root/dev/null'),unmount=True,libc=libc);self.assertEqual(umount.calls,[(b'/work/pristine/root/dev/null',0)])
  with self.assertRaises(ValueError):P.syscall(self.target,bind=True,unmount=True,libc=libc)
 def test_preflight_direct_success_no_utility_and_verified_teardown(self):
  commands=NS(report={'commands':[]},call=lambda *a:(_ for _ in ()).throw(AssertionError('utility forbidden')))
  with self.model():value=P.check(commands,self.work)
  self.assertEqual(value['status'],'PASS_READONLY_PROC_PREFLIGHT');self.assertEqual(value['classification'],'LEGACY_READONLY_PROC_SUCCEEDED_UTILITY_ROUTE_NOT_REQUIRED');self.assertEqual(value['cleanup'],'PASS_OWNED_EMPTY_PROBE_REMOVED');self.assertEqual(commands.report['commands'],[]);self.assertEqual(self.events,[(self.target,False,False),(self.target,True,False)]);self.assertFalse(self.target.exists())
 def test_preflight_direct_failure_is_fatal_even_without_mount(self):
  self.denied='proc'
  with self.model():value=P.check(NS(),self.work)
  self.assertEqual(value['status'],'FAIL_PROC_MOUNT_PREFLIGHT');self.assertEqual(value['legacy']['errno'],errno.EACCES);self.assertEqual(value['cleanup'],'PASS_OWNED_EMPTY_PROBE_REMOVED');self.assertFalse(self.target.exists())
 def test_preflight_direct_unmount_failure_retains_owned_probe(self):
  self.failed_umount=True
  with self.model():value=P.check(NS(),self.work)
  self.assertEqual(value['status'],'FAIL_PROC_MOUNT_PREFLIGHT');self.assertEqual(value['cleanup'],'FAIL_RETAIN_OUTER_OWNED_CONTAINER');self.assertTrue(self.target.exists());self.assertEqual(value['calls'][-1]['errno'],errno.EACCES)
 def test_existing_foreign_probe_never_removed(self):
  self.target.mkdir();(self.target/'foreign').write_bytes(b'keep')
  with self.model():value=P.check(NS(),self.work)
  self.assertEqual(value['cleanup'],'NOT_CREATED_NO_REMOVAL');self.assertEqual((self.target/'foreign').read_bytes(),b'keep');self.assertEqual(self.events,[])
 def test_runtime_exact_lifetime_reverse_unmount_and_no_fd_leak(self):
  report={};before=len(list(Path('/proc/self/fd').iterdir()))
  with self.model():
   with P.runtime_mounts(self.root,report):self.assertEqual(len(self.mounts),2);self.assertTrue((self.root/'dev/null').exists())
  self.assertFalse(self.mounts);self.assertFalse((self.root/'dev/null').exists());self.assertEqual(self.events,[(self.root/'proc',False,False),(self.root/'dev/null',False,True),(self.root/'dev/null',True,False),(self.root/'proc',True,False)]);self.assertEqual(report['runtime_mounts'][0]['cleanup'],'PASS_EXACT_MOUNTS_ABSENT_PLACEHOLDER_REMOVED');self.assertEqual(before,len(list(Path('/proc/self/fd').iterdir())))
 def test_underlying_proc_identity_only_checked_before_mount_or_after_retirement(self):
  original=P.stable
  def stable(path,*args):
   self.assertFalse(path==self.root/'proc' and path in self.mounts,'underlying proc FD must not be compared with its mounted proc inode');return original(path,*args)
  with self.model(),patch.object(P,'stable',side_effect=stable):
   with P.runtime_mounts(self.root,{}):pass
 def test_original_ten_interruption_lifetimes_fit_but_eleventh_refused(self):
  report={}
  with self.model():
   for _ in range(10):
    with P.runtime_mounts(self.root,report):pass
   with self.assertRaisesRegex(ValueError,'ten original'):
    with P.runtime_mounts(self.root,report):pass
  self.assertEqual(len(report['runtime_mounts']),10);self.assertFalse(self.mounts)
 def test_runtime_bind_failure_fatal_and_proc_retired(self):
  self.denied='bind';report={}
  with self.model(),self.assertRaisesRegex(ValueError,'mount failed'):
   with P.runtime_mounts(self.root,report):self.fail('must not yield')
  self.assertFalse(self.mounts);self.assertFalse((self.root/'dev/null').exists());self.assertEqual(report['runtime_mounts'][0]['calls'][1]['errno'],errno.EACCES)
 def test_runtime_proc_failure_never_binds_or_yields(self):
  self.denied='proc';report={}
  with self.model(),self.assertRaises(ValueError):
   with P.runtime_mounts(self.root,report):self.fail('must not yield')
  self.assertEqual(self.events,[(self.root/'proc',False,False)]);self.assertFalse((self.root/'dev/null').exists())
 def test_runtime_unmount_failure_is_fatal_and_keeps_placeholder(self):
  self.failed_umount=True;report={}
  with self.model(),self.assertRaisesRegex(ValueError,'retirement incomplete'):
   with P.runtime_mounts(self.root,report):pass
  self.assertTrue((self.root/'dev/null').exists());self.assertEqual(report['runtime_mounts'][0]['cleanup'],'FAIL_RETAIN_OUTER_OWNED_CONTAINER');self.assertTrue(any(r['errno']==errno.EACCES for r in report['runtime_mounts'][0]['calls']))
 def test_runtime_primary_failure_not_masked_by_cleanup_failure(self):
  self.failed_umount=True;report={}
  with self.model(),self.assertRaisesRegex(RuntimeError,'primary caller') as ctx:
   with P.runtime_mounts(self.root,report):raise RuntimeError('primary caller')
  self.assertIn('cleanup also failed',ctx.exception.__notes__[0]);self.assertEqual(report['runtime_mounts'][0]['primary_error']['type'],'RuntimeError')
 def test_changed_mount_identity_not_unmounted(self):
  report={}
  with self.model(),self.assertRaises(ValueError):
   with P.runtime_mounts(self.root,report):self.mounts[self.root/'dev/null']='foreign replacement row'
  self.assertNotIn((self.root/'dev/null',True,False),self.events);self.assertTrue((self.root/'dev/null').exists())
 def test_foreign_placeholder_and_symlink_proc_refused(self):
  (self.root/'dev/null').write_bytes(b'foreign')
  with self.model(),self.assertRaises(ValueError):
   with P.runtime_mounts(self.root,{}):pass
  self.assertEqual((self.root/'dev/null').read_bytes(),b'foreign');self.assertFalse(self.events)
  (self.root/'dev/null').unlink();(self.root/'proc').rmdir();(self.root/'proc').symlink_to(self.work,target_is_directory=True)
  with self.model(),self.assertRaises(ValueError):
   with P.runtime_mounts(self.root,{}):pass
  self.assertFalse(self.events)
 def test_scope_and_cap_drift_refuse_before_syscall(self):
  with self.model(),self.assertRaises(ValueError):
   with P.runtime_mounts(self.work,{}):pass
  bad=self.facts();bad['status']['CapEff']='0'
  with self.model(),patch.object(P,'facts',return_value=bad),self.assertRaises(ValueError):
   with P.runtime_mounts(self.root,{}):pass
  self.assertFalse(self.events)
 def test_proc_mountinfo_flags_type_and_readonly_superblock_verified(self):
  info=self.root.stat();device=str(os.major(info.st_dev))+':'+str(os.minor(info.st_dev));row='3 2 '+device+' / '+str(self.root)+' ro,nosuid,nodev,noexec,relatime - proc proc ro'
  with patch.object(P,'mounted',return_value=[row]),patch.object(P.os,'fstatvfs',return_value=NS(f_flag=os.ST_RDONLY)):self.assertEqual(P.verify_mount(self.root)['mount_row'],row)
  for wrong in (row.replace('ro,nosuid','rw,nosuid'),row.replace('- proc proc','- tmpfs proc')):
   with patch.object(P,'mounted',return_value=[wrong]),self.assertRaises(ValueError):P.verify_mount(self.root)
 def test_dev_null_char_inode_rdev_and_mount_root_verified(self):
  info=Path('/dev/null').stat();device=str(os.major(info.st_dev))+':'+str(os.minor(info.st_dev));source='2 1 '+device+' / /dev rw,nosuid - tmpfs tmpfs rw';target=self.root/'dev/null';row='3 1 '+device+' /null '+str(target)+' rw,nosuid - tmpfs tmpfs rw'
  with patch.object(P,'mounted',return_value=[row]),patch.object(Path,'lstat',return_value=info):self.assertEqual(P.verify_bind(target,info,source)['rdev'],info.st_rdev)
  with patch.object(P,'mounted',return_value=[row.replace('/null ','/zero ')]),patch.object(Path,'lstat',return_value=info),self.assertRaises(ValueError):P.verify_bind(target,info,source)
  with patch.object(P,'mounted',return_value=[row]),patch.object(Path,'lstat',return_value=self.root.stat()),self.assertRaises(ValueError):P.verify_bind(target,info,source)
 def test_exact_single_role_marker_only_with_unchanged_native_fences(self):
  with patch.object(P.os,'getuid',return_value=0),patch.object(P.os,'geteuid',return_value=0),patch.object(P.os,'uname',return_value=NS(machine='aarch64')),patch.object(Path,'is_mount',return_value=True),patch.object(Path,'iterdir',return_value=iter([Path('/sys/class/net/lo')])):
   for key in ('CACHY_GNU_PROVIDER_LIFECYCLE','CACHY_GNU_PROVIDER_INTERRUPTION'):
    with patch.dict(P.os.environ,{key:'1'},clear=True),patch.object(Path,'iterdir',return_value=iter([Path('/sys/class/net/lo')])):P.guard(Path('/work'))
   for markers in ({},{'CACHY_GNU_PROVIDER_LIFECYCLE':'1','CACHY_GNU_PROVIDER_INTERRUPTION':'1'},{'CACHY_GNU_PROVIDER_LIFECYCLE':'0'},{'CACHY_GNU_PROVIDER_INTERRUPTION':''},{'CACHY_GNU_PROVIDER_UNKNOWN':'1'},{'CACHY_GNU_PROVIDER_LIFECYCLE':'1','CACHY_GNU_PROVIDER_SNAPSHOT':'1'}):
    with patch.dict(P.os.environ,markers,clear=True),self.assertRaisesRegex(ValueError,'one exact known'):P.guard(Path('/work'))
   with patch.dict(P.os.environ,{'CACHY_GNU_PROVIDER_INTERRUPTION':'1'},clear=True),patch.object(Path,'iterdir',return_value=iter([Path('/sys/class/net/lo'),Path('/sys/class/net/eth0')])),self.assertRaises(ValueError):P.guard(Path('/work'))
 def test_host_guard_refuses_before_mount(self):
  with self.assertRaisesRegex(ValueError,'same-role'):P.check(None,Path('/not-work'))
  self.assertFalse(self.events)
 def test_security_profile_text_bounded_and_clipped(self):
  with patch.object(P,'bounded',return_value=b'x'*600):v=P.text_fact('/inert')
  self.assertTrue(v['clipped']);self.assertEqual(len(v['value']),512)
  with patch.object(P,'bounded',return_value=b'bad\0profile'),self.assertRaises(ValueError):P.text_fact('/inert')
 def test_both_real_controllers_use_same_exact_runtime_helper(self):
  import ast
  report={};commands=NS(api=dict(proc_probe=P),report=report,call=lambda *a:(_ for _ in ()).throw(AssertionError('utility forbidden')))
  for lane in ('lifecycle','interruption'):
   path=HERE.parent/('glibc-gnu-provider-'+lane)/'container.py';text=path.read_text();node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name=='runtime_mounts');namespace=dict(contextmanager=__import__('contextlib').contextmanager)
   exec(compile('@contextmanager\n'+ast.get_source_segment(text,node),str(path),'exec'),namespace)
   with self.model():
    with namespace['runtime_mounts'](commands,self.root):self.assertEqual(len(self.mounts),2)
  self.assertEqual(len(report['runtime_mounts']),2);self.assertFalse(self.mounts)

 def test_both_real_main_bodies_stop_before_copy_on_failed_preflight(self):
  import sys
  for lane in ('lifecycle','interruption'):
   folder=HERE.parent/('glibc-gnu-provider-'+lane)
   repository=next(p for p in HERE.parents if (p/'AGENTS.md').is_file())
   shared=repository/'scripts/ci'/('glibc-gnu-provider-'+lane)
   def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
   common=load('proc_main_common_'+lane,shared/'common.py')
   with patch.dict(sys.modules,{'common':common}):module=load('proc_main_'+lane,folder/'container.py')
   work=self.work/lane;work.mkdir();out=self.work/(lane+'-out');out.mkdir()
   failure=dict(status='FAIL_PROC_MOUNT_PREFLIGHT',cleanup='PASS_OWNED_EMPTY_PROBE_REMOVED')
   api=dict(capabilities=NS(disjoint=lambda *a:None),proc_probe=NS(check=lambda *a:failure))
   with self.subTest(lane=lane),patch.object(module,'guard'),patch.object(module,'WORK',work),patch.object(module,'OUT',out),patch.object(module.C,'configuration',return_value=({}, {}, {}, {})),patch.object(module.C,'helpers',return_value=api),patch.object(module.os,'chown'),patch.dict(os.environ,INPUT_INDEX_SHA256='0'*64,OUTPUT_UID=str(os.getuid()),OUTPUT_GID=str(os.getgid())),patch.object(module,'run_case',side_effect=AssertionError('must never copy')) as case:
    self.assertEqual(module.main(),1);case.assert_not_called()
   result=json.loads((out/'result.json').read_bytes());self.assertEqual(result['status'],'FAIL');self.assertEqual(result['proc_preflight'],failure);self.assertEqual(result['cases'],{})

if __name__=='__main__':unittest.main()
