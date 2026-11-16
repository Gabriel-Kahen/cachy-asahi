#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Joint actor/maintained-reader/constructor MODELS; no image or process entry.

The real observe/Budget/parser path crosses the real actor API. Only input FDs,
processes, supervision and scratch output are in-memory substitutes. The public
constructor snapshots the actual maintained Python source in owned temp DATA.
"""
from contextlib import contextmanager,ExitStack
import builtins
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent

def module(name):
 spec=importlib.util.spec_from_file_location('no_package_joint_MODEL_'+name,HERE/(name+'.py'))
 value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

A,P,M=map(module,('actor','prepare','metadata'))
RF=module('test_metadata_raw_reader')
RDR=RF.R
PF=module('test_prepare')
K=P.K
READER_PIN=dict(bytes=12810,sha256='94a755ab24b940a809f53a78faf90a851ded9f14d28c0fdb9cf75f5e01c59f23')
READER_TEST_PIN=dict(bytes=13288,sha256='57ed369bba57e90839a8e8c5b4bd2935b48726aaf495ef4b44e326fc1cda6753')
TOOL_BYTES=b'PUBLIC_INERT_MODEL_DEBUGFS_BYTES_NOT_EXECUTABLE'
TOOL_PIN=K.bytes_pin(TOOL_BYTES)
BASE=Path('/base/guest.raw')
WORK=Path('/MODEL/work')
NOW_NS=1794829001000000000


def fence(event,args):
 if event=='open'and args and type(args[0])in(str,bytes):
  path=os.fsdecode(args[0])
  if path.endswith('.raw')or any(path==root or path.startswith(root+'/')for root in('/base','/reader','/kernel','/work','/root/.ssh')):
   raise AssertionError('joint MODEL forbids opening raw/actor/private operands')
 if event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.spawn','os.fork','os.posix_spawn'))or event in('os.system','os.kill','os.killpg','fcntl.flock'):
  raise AssertionError('joint integration MODEL forbids process/actor entry: '+event)
sys.addaudithook(fence)


class Clock:
 def __init__(self):self.now=100.0
 def monotonic(self):return self.now
 def time_ns(self):return NOW_NS+round((self.now-100.0)*10**9)
 def advance(self,seconds):self.now+=seconds


class JointModel:
 def __init__(self,*,overall=1000.0,stat_seconds=4.,qemu_seconds=200.):
  self.clock=Clock();self.overall=overall;self.stat_seconds=stat_seconds;self.qemu_seconds=qemu_seconds
  self.trace=[];self.outputs={};self.removed=[];self.budgets=[];self.tool_reads=0
  self.bad_frame=False;self.forced=False;self.epoch_age=0
  self.packet,source,*_=PF.modeled(uid=1000)
  self.packet['resources']['boot_seconds']=1800
  self.packet['reader']=dict(READER_PIN);self.packet['actor_tools']['/usr/bin/debugfs']=dict(TOOL_PIN)
  self.contract=SimpleNamespace(OP=K.OP,need=K.need,canonical=K.canonical,load=self.load,pin=self.pin)
  self.runtime=SimpleNamespace(command=self.command,receipt=self.receipt,natural=RF.L.natural)
  self.raw_info=SimpleNamespace(st_dev=1,st_ino=100,st_mode=stat.S_IFREG|0o600,st_nlink=1,st_uid=0,st_gid=0,
                               st_size=self.packet['baseline']['raw']['bytes'],st_mtime_ns=1,st_ctime_ns=2)
  self.tool_info=SimpleNamespace(st_dev=2,st_ino=200,st_mode=stat.S_IFREG|0o755,st_nlink=1,st_uid=0,st_gid=0,
                                st_size=len(TOOL_BYTES),st_mtime_ns=3,st_ctime_ns=4)
 def guard(self):
  self.trace.append(('guard',self.clock.now))
  if self.clock.now>=self.overall:raise TimeoutError('MODEL overall guard deadline')
 def load(self,path):
  self.trace.append(('load',str(path),self.clock.now))
  if path!=WORK/'host-epoch.json':raise AssertionError('only public admission epoch loaded')
  return dict(nonce=self.packet['nonce'],utc_ns=NOW_NS-self.epoch_age)
 def pin(self,path,*args):
  if path==WORK/'qemu.json':return K.json_pin(self.receipt(path))
  if path not in self.outputs:raise AssertionError('public output pin only; never raw image body')
  return K.json_pin(self.outputs[path])
 def write(self,contract,path,value):
  self.trace.append(('write',path.name,self.clock.now))
  if path in self.outputs:raise AssertionError('exclusive scratch output')
  self.outputs[path]=copy.deepcopy(value)
 def remove(self,path):
  self.trace.append(('remove',str(path),self.clock.now));self.removed.append(path)
  if path!=WORK/'verification.raw':raise AssertionError('owned verification copy only')
 def identity(self,contract,path,expected):
  self.trace.append(('stat-original',str(path),self.clock.now))
  if path!=BASE or expected!=self.raw_info.st_size:raise AssertionError('fixed original geometry stat')
  return ('MODEL_ORIGINAL_UNCHANGED',)
 def command(self,argv,work,label,seconds,deadline,**kwargs):
  self.trace.append(('actor-command',label,tuple(argv),deadline,self.clock.now))
  if label=='qemu':self.clock.advance(self.qemu_seconds)
  else:self.clock.advance(1.)
  return SimpleNamespace(returncode=0)if label=='journal-copy-only'else b'MODEL'
 def receipt(self,path):
  if path!=WORK/'qemu.json':raise AssertionError('exact original QEMU receipt')
  return dict(RF.outcome(),argv=self.outputs[WORK/'qemu-argv.json']['argv'])
 @contextmanager
 def held(self,path,budget,maximum):
  self.trace.append(('held',str(path),budget.end,maximum))
  if path==Path('/usr/bin/debugfs'):
   self.tool_reads=0;yield 200,self.tool_info
  elif path in(BASE,WORK/'verification.raw'):
   yield 100 if path==BASE else 101,self.raw_info
  else:raise AssertionError('no other filesystem operand may be held')
 def read(self,fd,size):
  if fd!=200:raise AssertionError('raw image body read forbidden')
  if size!=65536:raise AssertionError('bounded public tool-byte hashing only')
  self.tool_reads+=1;return TOOL_BYTES if self.tool_reads==1 else b''
 def fstat(self,fd):
  if fd==200:return self.tool_info
  if fd in(100,101):return self.raw_info
  raise AssertionError('no unrelated descriptor')
 def dependencies(self,legacy_root,budget,stack):
  self.trace.append(('legacy',legacy_root,budget.end))
  if legacy_root!=Path('/legacy')or budget.guard!=self.guard:raise AssertionError('explicit legacy/guard handoff')
  return RF.L,SimpleNamespace(prepare=lambda:self.trace.append(('supervisor-prepare',)),supervise=self.supervise)
 def spawn(self,argv,**kwargs):
  if argv[:2]!=['/usr/bin/debugfs','-R']:raise AssertionError('fixed read-only tool request')
  path=argv[2][len('stat /'):]
  if argv[2]!='stat /'+path or path not in RDR.PATHS:raise AssertionError('fixed fifteen metadata path only')
  if kwargs['executable']!='/proc/self/fd/200'or kwargs['pass_fds']not in((100,200),(101,200)):
   raise AssertionError('held original/verification descriptor and pinned tool handoff')
  self.trace.append(('debugfs',path,kwargs['pass_fds'][0],self.clock.now))
  return SimpleNamespace(path=path,after=kwargs['pass_fds'][0]==101)
 def supervise(self,child,**kwargs):
  if kwargs['max_output']!=RDR.STAT_CAP:raise AssertionError('bounded metadata output')
  self.clock.advance(self.stat_seconds)
  output=RF.missing(child.path)if child.path=='var/cache/ldconfig'else RF.frame(20+RDR.PATHS.index(child.path),ns=123456790 if child.after else 123456789)
  if self.bad_frame:output+=b'Extended attributes:\n  user.private = "MODEL_PRIVATE_NEVER_EXPORTED"\n'
  result=dict(RF.outcome(),output=output)
  if self.forced:result['signals']=['SIGTERM']
  return result
 def execute(self):
  original_budget=RDR.Budget
  def budget(deadline,guard):
   self.budgets.append((self.clock.now,deadline,guard))
   return original_budget(deadline,guard)
  with ExitStack()as stack:
   for target,name,value in ((A,'load_reader',lambda contract,packet:RDR),(A,'raw_identity',self.identity),
       (A,'write_json',self.write),(A,'remove_verification',self.remove),(RDR,'dependencies',self.dependencies),
       (RDR,'held_regular',self.held),(RDR,'fixed_tool_path',lambda:Path('/usr/bin/debugfs')),
       (RDR,'Budget',budget),(RDR.os,'read',self.read),(RDR.os,'fstat',self.fstat),
       (RDR.subprocess,'Popen',self.spawn),(A.time,'monotonic',self.clock.monotonic),(A.time,'time_ns',self.clock.time_ns)):
    stack.enter_context(patch.object(target,name,value))
   return A.run(self.contract,self.runtime,WORK,self.packet,self.guard,self.overall)


class Controls(unittest.TestCase):
 def test_actual_A_whole_bytes_pass_real_constructor_AST_and_readonly_snapshot(self):
  public_reader=HERE/'metadata_raw_reader.py';body=public_reader.read_bytes()
  self.assertEqual(K.bytes_pin(body),READER_PIN)
  self.assertEqual(K.bytes_pin((HERE/'test_metadata_raw_reader.py').read_bytes()),READER_TEST_PIN)
  self.assertIs(P.reader_shape(body),body)
  packet,source,*_=PF.modeled(uid=os.getuid());packet['resources']['boot_seconds']=1800;packet['reader']=dict(READER_PIN)
  public_plan=K.local('plan')
  with tempfile.TemporaryDirectory(prefix='public-reader-joint-MODEL-')as tmp:
   root=Path(tmp);inputs=root/'PUBLIC-MODEL-inputs.json';out=root/'PUBLIC-MODEL-snapshot'
   inputs.write_bytes(K.canonical(packet))
   try:
    # All required policy modules are already loaded. Actual reader bytes are
    # parsed/copied by the real constructor, with any exec explicitly forbidden.
    with patch.object(P.K,'local',return_value=public_plan),patch.object(builtins,'exec',side_effect=AssertionError('constructor executed reader Source')):
     report=P.prepare(inputs,source['sha256'],public_reader,out,now=1000000,source_loader=lambda _:source)
    self.assertEqual((out/'raw_metadata.py').read_bytes(),body)
    self.assertEqual((out/'control-packet.json').read_bytes(),K.canonical(packet))
    self.assertEqual(report['reader'],READER_PIN);self.assertIsNone(report['actual_VM'])
    self.assertEqual(stat.S_IMODE(out.stat().st_mode),0o500)
    self.assertTrue(all(stat.S_IMODE(path.stat().st_mode)==0o400 for path in out.iterdir()))
   finally:
    if out.exists():out.chmod(0o700)
 def test_real_reader_rejects_old_overall_deadline_before_input_or_process(self):
  with patch.object(RDR.time,'monotonic',return_value=100.),patch.object(RDR,'dependencies',side_effect=AssertionError('deadline must refuse before inputs')):
   with self.assertRaisesRegex(ValueError,'finite externally bounded read-only deadline'):
    RDR.observe(BASE,TOOL_PIN,1000.,legacy_root=Path('/legacy'),guard=lambda:None)
 def test_real_actor_reader_parser_and_fresh_launch_epoch_join_all_metadata(self):
  model=JointModel();result=model.execute()
  self.assertEqual(len(model.budgets),2)
  for started,end,guard in model.budgets:
   self.assertEqual(end,min(model.overall,started+RDR.MAX_SECONDS));self.assertEqual(guard,model.guard)
  calls=[event for event in model.trace if event[0]=='debugfs']
  self.assertEqual([event[1]for event in calls[:15]],list(RDR.PATHS))
  self.assertEqual([event[1]for event in calls[15:]],list(RDR.PATHS))
  self.assertTrue(all(event[2]==100 for event in calls[:15]));self.assertTrue(all(event[2]==101 for event in calls[15:]))
  for stage,ns in(('offline_before',123456789),('offline_after',123456790)):
   rows=result['metadata'][stage];self.assertEqual(tuple(rows),M.PATHS);self.assertIsNone(rows['var/cache/ldconfig'])
   self.assertEqual(tuple(rows['root']),M.FIELDS);self.assertEqual(rows['etc']['mtime_ns'],ns)
   self.assertEqual(rows['etc']['atime_ns'],ns)
  first_budget=next(i for i,event in enumerate(model.trace)if event[0]=='held')
  admission=next(i for i,event in enumerate(model.trace)if event[0]=='load')
  self.assertLess(admission,first_budget)
  launch=model.outputs[WORK/'qemu-epoch.json'];self.assertGreater(launch['utc_ns']-NOW_NS,30*10**9)
  argv=model.outputs[WORK/'qemu-argv.json']['argv'];append=argv[argv.index('-append')+1]
  self.assertIn('arm16k_rtc_host_epoch='+str(launch['utc_ns']//10**9),append)
  self.assertEqual(result['qemu_epoch'],K.json_pin(launch))
  self.assertEqual(result['reader'],READER_PIN);self.assertEqual(model.removed,[WORK/'verification.raw'])
  for field in('VM_acceptance','Root_acceptance','preservation','ALPM'):self.assertIsNone(result[field])
 def test_each_reader_slot_is_clipped_to_shorter_overall_deadline(self):
  model=JointModel(overall=150.,stat_seconds=.2,qemu_seconds=20.);model.execute()
  self.assertEqual([end for _,end,_ in model.budgets],[150.,150.])
  self.assertLess(model.clock.now,150.)
 def test_expired_scan_slot_cannot_consume_whole_actor_budget(self):
  model=JointModel(stat_seconds=8.)
  with self.assertRaisesRegex(ValueError,'read-only metadata deadline'):model.execute()
  self.assertLess(model.clock.now,model.overall)
  self.assertFalse(any(event[0]=='actor-command'for event in model.trace))
  self.assertEqual(model.outputs,{});self.assertEqual(model.removed,[])
 def test_actor_debugfs_pin_reaches_actual_reader_tool_byte_check(self):
  model=JointModel();model.packet['actor_tools']['/usr/bin/debugfs']=dict(TOOL_PIN,sha256='f'*64)
  with self.assertRaisesRegex(ValueError,'actual selected debugfs tool bytes'):model.execute()
  self.assertFalse(any(event[0]=='debugfs'for event in model.trace));self.assertEqual(model.outputs,{})
 def test_real_reader_forced_child_or_private_extra_frame_prevents_actor_success(self):
  for field in('forced','bad_frame'):
   with self.subTest(field=field):
    model=JointModel();setattr(model,field,True)
    with self.assertRaises(ValueError)as caught:model.execute()
    self.assertNotIn('MODEL_PRIVATE',str(caught.exception));self.assertEqual(model.outputs,{})
    self.assertEqual(model.removed,[])
 def test_stale_initial_admission_epoch_refuses_before_real_reader(self):
  model=JointModel();model.epoch_age=30*10**9+1
  with self.assertRaisesRegex(ValueError,'fresh same-nonce host RTC epoch'):model.execute()
  self.assertEqual(model.budgets,[]);self.assertFalse(any(event[0]=='held'for event in model.trace))


if __name__=='__main__':unittest.main(verbosity=2)
