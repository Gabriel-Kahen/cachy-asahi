#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emitted initializer controls; no real chroot, ldconfig or native execution.

FD tests use real files/hash/descriptor readers and mock only namespace/exec
primitives, with an explicit inert helper pin. Parent-flow tests model graph,
checkpoint and command boundaries; real marker/lease operations and actual
preservation/live-key validators execute. These are not native receipts.
"""
import base64,contextlib,copy,dataclasses,hashlib,importlib.util,io,json,os,struct,sys,tempfile,time,types,unittest
from pathlib import Path
from unittest.mock import patch
sys.dont_write_bytecode=True
D=Path(__file__).resolve().parent;SOURCE=Path(os.environ['CORE622_EMITTED_SOURCE']).resolve();CORE=Path(os.environ['CORE622_CORE_SOURCE']).resolve();sys.path[:0]=[str(SOURCE),str(CORE/'runtime/runtime-vm/scripts/update'),str(CORE/'scripts/ci/core-native-lifecycle')]
import full_root as R,measure_copy as M,aux_checkpoint as Q,audio_aux as A
spec=importlib.util.spec_from_file_location('_emitted_owned_cache_init',SOURCE/'provision622.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
def cache(key):return A.MAGIC+struct.pack('<II',1,1)+A.ENTRY.pack(*key,771,0,0)+b'\0'*4+b'\0'
class Controls(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='initialization-',dir=D);self.base=Path(self.temp.name);self.root=self.base/'root';(self.root/'usr/bin').mkdir(parents=True);self.helper=self.root/Q.HELPER_NODE;self.helper.write_bytes(b'INERT_PINNED_HELPER_NEVER_EXECUTED');self.helper.chmod(0o755);self.limits=R.Limits(deadline=time.monotonic()+30,max_nodes=500000,max_bytes=8*1024**3,max_file_bytes=1024**3);self.api=dict(roots=R,copy=types.SimpleNamespace(measure_copy=M));self.core=types.SimpleNamespace(api=self.api,F=types.SimpleNamespace(A=A));self.graph=R.observe(self.root,limits=self.limits,hardlinks='generic-development-internal',absolute_paths=True);s=self.root.stat();self.lease=dict(root=[s.st_dev,s.st_ino],parent=[self.root.parent.stat().st_dev,self.root.parent.stat().st_ino],nonce='a'*32,status='OWNED_CURRENT607_ROOT_LIVE');(self.root.parent/'current607-lease.json').write_text(json.dumps(self.lease))
 def tearDown(self):self.temp.cleanup()
 def states(self):
  oldnode=dict(type='file',uid=0,gid=0,mode=0o644,bytes=1,sha256='a'*64);nodes={'root/private':dict(oldnode),'usr/lib/libfixture.so':dict(oldnode)}
  for name,mode in((Q.MAIN_CACHE,0o644),(Q.AUX_CACHE,0o600)):nodes[name]=dict(oldnode,mode=mode)
  before=dict(complete=True,unsupported_counts={},nodes=nodes,hardlink_groups={});after=copy.deepcopy(before)
  for name in(Q.MAIN_CACHE,Q.AUX_CACHE):after['nodes'][name]['sha256']='b'*64
  old={name:{}for name in('helper','configs','aliases','scan','targets')};old.update(closure=('fixed',),scan_directories=('usr/lib',),caches={name:dict(node=copy.deepcopy(node))for name,node in nodes.items()if name in(Q.MAIN_CACHE,Q.AUX_CACHE)})
  old['caches']['var/cache/ldconfig']=dict(node=dict(type='directory',uid=0,gid=0,mode=0o700),inode=[2049,999]);old['caches'][Q.AUX_CACHE+'~']=dict(node=dict(type='absent'));old['caches'][Q.MAIN_CACHE+'~']=dict(node=dict(type='absent'));identity=[2049,123,0o100644,0,0,1,1,10**9,10**9];old['scan']['usr/lib/libfixture.so']=dict(node=oldnode,identity=identity);old['aux_bytes']=cache((4,1,1,48));new=copy.deepcopy(old);new['aux_bytes']=cache((123,1,1,2049))
  for name in(Q.MAIN_CACHE,Q.AUX_CACHE):new['caches'][name]['node']['sha256']='b'*64
  return before,after,old,new
 def test_only_two_cache_nodes_change_and_full_closure_stays_exact(self):
  before,after,old,new=self.states();self.assertTrue(all(P.initialization_change(before,after,old,new).values()));self.assertEqual(Q.live_keys(new,A)['records'],1)
 def test_every_unrelated_node_hardlink_and_checkpoint_change_refuses(self):
  for kind in('node','hardlink','complete','unsupported','helper','configs','aliases','scan','targets','closure','scan_directories','parent','temporary','owner','mode'):
   before,after,old,new=self.states()
   if kind=='node':after['nodes']['root/private']['sha256']='f'*64
   elif kind=='hardlink':after['hardlink_groups']={'foreign':{'members':['root/private']}}
   elif kind=='complete':after['complete']=False
   elif kind=='unsupported':after['unsupported_counts']={'fifo':1}
   elif kind=='parent':new['caches']['var/cache/ldconfig']['inode']=[2049,111]
   elif kind=='temporary':new['caches'][Q.AUX_CACHE+'~']={'node':{'type':'file'}}
   elif kind=='owner':new['caches'][Q.AUX_CACHE]['node']['uid']=1000
   elif kind=='mode':new['caches'][Q.MAIN_CACHE]['node']['mode']=0o666
   elif kind in('closure','scan_directories'):new[kind]=('foreign',)
   else:new[kind]={'foreign':True}
   with self.subTest(kind=kind),self.assertRaises(ValueError):P.initialization_change(before,after,old,new)
 def test_wrong_device_records_remain_refused_without_filtering(self):
  _,_,_,state=self.states();state['aux_bytes']=cache((4,1,1,48));self.assertEqual(len(A.parse(state['aux_bytes'])),1)
  with self.assertRaisesRegex(ValueError,'stale-or-unobserved-aux-key'):Q.live_keys(state,A)
 def exec_boundary(self,graph=None,lease=None,support=True):
  events=[];fds=[];inert=(self.helper.stat().st_size,hashlib.sha256(self.helper.read_bytes()).hexdigest());helper_pin=(inert[1],inert[0])
  class ReachedExec(Exception):pass
  def execute(fd,argv,env):fds.append(fd);events.append(('exec',argv,env,os.fstat(fd).st_ino));raise ReachedExec()
  with contextlib.ExitStack()as stack:
   stack.enter_context(patch.object(Q,'HELPER',helper_pin));stack.enter_context(patch.object(P.os,'execve',execute));stack.enter_context(patch.object(P.os,'supports_fd',{execute}if support else set()))
   for name in('fchdir','chroot','chdir'):stack.enter_context(patch.object(P.os,name,side_effect=lambda value,n=name:events.append((n,value))))
   try:P.exec_owned_auxiliary(self.core,self.root,graph or self.graph,self.limits,lease or self.lease)
   except ReachedExec:pass
  return events,fds
 def test_real_fd_hash_root_pin_and_namespace_order_before_fd_exec(self):
  events,fds=self.exec_boundary();self.assertEqual([e[0]for e in events],['fchdir','chroot','chdir','exec']);self.assertEqual(events[1],('chroot','.'));self.assertEqual(events[2],('chdir','/'));self.assertEqual(events[3][1],['/usr/bin/ldconfig']);self.assertEqual(events[3][2],dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',HOME='/',TMPDIR='/tmp'))
  for fd in(fds[0],events[0][1]):
   with self.assertRaises(OSError):os.fstat(fd)
 def test_helper_hash_drift_and_alias_refuse_before_chroot(self):
  self.helper.write_bytes(b'X'*self.helper.stat().st_size)
  with self.assertRaises(ValueError),patch.object(P.os,'chroot',side_effect=AssertionError('no chroot after changed helper')):
   with patch.object(Q,'HELPER',(self.graph['nodes'][Q.HELPER_NODE]['sha256'],self.graph['nodes'][Q.HELPER_NODE]['bytes'])):P.exec_owned_auxiliary(self.core,self.root,self.graph,self.limits,self.lease)
  self.helper.unlink();self.helper.symlink_to(self.root/'outside')
  with self.assertRaises(OSError),patch.object(P.os,'chroot',side_effect=AssertionError('no chroot through alias')):P.exec_owned_auxiliary(self.core,self.root,self.graph,self.limits,self.lease)
 def test_wrong_root_lease_and_missing_fd_exec_support_refuse(self):
  with self.assertRaises(ValueError):self.exec_boundary(lease=dict(self.lease,root=[0,0]))
  with self.assertRaisesRegex(ValueError,'FD exec support'):self.exec_boundary(support=False)
 def test_lease_requires_fixed_ordinary_root_and_exact_parent_nonce(self):
  selected=dict(nonce='a'*32)
  with patch.object(P,'ROOT',self.root):self.assertEqual(P.initialization_lease(selected,self.root),self.lease)
  with patch.object(P,'ROOT',self.root),self.assertRaises(ValueError):P.initialization_lease(dict(nonce='b'*32),self.root)
  alias=self.base/'alias';alias.symlink_to(self.root,target_is_directory=True)
  with patch.object(P,'ROOT',alias),self.assertRaises(ValueError):P.initialization_lease(selected,alias)
 def flow(self,error=None,expired=False):
  before,after,old,new=self.states();calls=[];marker=self.base/'marker';realpath=Path
  def path(value):return marker if str(value)=='/tmp/current607-aux-initialization-started'else realpath(value)
  def run(argv,work,env,seconds,cap):calls.append((argv,work,env,seconds,cap));return dict(argv=argv,exit_code=1 if error else 0,group_absence_verified=True),b'',b'',error
  limits=dataclasses.replace(self.limits,deadline=time.monotonic()-1)if expired else self.limits;core=types.SimpleNamespace(api=dict(self.api,runtime=types.SimpleNamespace(run_command=run)),F=self.core.F);out=io.StringIO()
  with patch.object(P,'ROOT',self.root),patch.object(P,'Path',path),patch.object(Q,'checkpoint',side_effect=lambda r,g,l:old if g is before else new),patch.object(R,'observe',return_value=after),contextlib.redirect_stderr(out):
   if error or expired:
    with self.assertRaises(ValueError)as caught:P.initialize_auxiliary(core,self.root,before,limits,dict(nonce='a'*32))
    if error:self.assertIs(caught.exception,error)
   else:
    graph,checkpoint,proof=P.initialize_auxiliary(core,self.root,before,limits,dict(nonce='a'*32));self.assertIs(graph,after);self.assertIs(checkpoint,new);self.assertEqual(proof['status'],'PASS_ONE_OWNED_ROOT_AUX_INITIALIZATION');self.assertTrue(all(proof['preservation'].values()));self.assertEqual(proof['live_cache_keys']['records'],1)
   with self.assertRaises(FileExistsError):P.initialize_auxiliary(core,self.root,before,limits,dict(nonce='a'*32))
  self.assertTrue(marker.is_file());self.assertEqual(json.loads(marker.read_bytes())['root'],self.lease['root']);self.assertEqual(len(calls),0 if expired else 1)
  if calls:
   argv,work,env,seconds,cap=calls[0];self.assertEqual(argv,[sys.executable,'-I','-B','/workspace/provision622.py','initialize607']);self.assertEqual(work,Path('/tmp'));self.assertEqual(float(env['CAA_CORE622_PHASE_END']),limits.deadline);self.assertLessEqual(seconds,min(180,limits.deadline-time.monotonic()+1));self.assertEqual(cap,65536);self.assertEqual(json.loads(out.getvalue())['kind'],'CORE622_OWNED_AUX_INITIALIZATION_WORKER')
 def test_parent_flow_one_shot_shared_deadline_and_preservation(self):self.flow()
 def test_parent_worker_failure_is_retained_and_never_retried(self):self.flow(error=ValueError('inert worker failure'))
 def test_parent_expiry_does_not_reset_clock_or_start_worker(self):self.flow(expired=True)
if __name__=='__main__':unittest.main(verbosity=2)
