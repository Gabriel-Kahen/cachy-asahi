#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Fenced in-memory actor MODEL controls: no image, tool or actor is entered."""
import copy
import dataclasses
import hashlib
import importlib.util
from importlib.machinery import ModuleSpec
import json
import stat
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent

def module(name):
 spec=importlib.util.spec_from_file_location('no_package_actor_MODEL_'+name,HERE/(name+'.py'))
 value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
A,M=module('actor'),module('metadata')
NONCE='a'*32
NOW=1794829001123456789
DEADLINE=1000.0
WORK=Path('/MODEL/work')


def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.fork','os.posix_spawn'))or event in('os.system','fcntl.flock'):
  raise AssertionError('actor MODEL forbids operational resource entry: '+event)
sys.addaudithook(fence)


def pin(label):
 raw=('MODEL '+label).encode();return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def packet():
 return dict(nonce=NONCE,baseline_nonce='b'*32,source_lock=pin('new source'),reader=pin('metadata reader'),
             actor_tools={name:pin('actor tool '+name)for name in A.TOOLS},
             baseline=dict(raw=dict(bytes=1610612736,sha256='1'*64),prepared=pin('prepared'),certificate=pin('certificate')),
             kernel=dict(Image=pin('qualified Image'),config=pin('qualified config')),tool_image='sha256:'+'2'*64,
             resources=dict(cpus=2,guest_memory_bytes=2*1024**3,boot_seconds=1200,cleanup_seconds=90,
                            overlay_cap_bytes=512*1024**2,readback_allocated_cap_bytes=2*1024**3,
                            logs_cap_bytes=16*1024**2,reserve_bytes=1024**3))


def scan():
 return dict(observed_paths=list(M.PATHS),nodes={path:dict(type='directory',mode=0o700 if i==0 else 0o755,
             uid=0,gid=0,inode=16+i,links=2+i,size=4096,atime=1794708503,atime_ns=0,mtime=1794708503,mtime_ns=123456789)
             for i,path in enumerate(M.PATHS)})


class Poison:
 def __getattr__(self,name):raise AssertionError('forbidden private/inventory API: '+name)
 def __repr__(self):raise AssertionError('private MODEL value must not be exposed')


class Reader:
 def __init__(self,trace,advance=lambda seconds:None):
  self.trace=trace;self.before=scan();self.after=scan();self.after['nodes']['etc']['mtime_ns']+=1
  self.advance=advance;self.before_seconds=0;self.after_seconds=0
  self.before['nodes']['PRIVATE_UNSELECTED_NODE']=Poison()
  self.before['nodes']['etc']['xattrs']=Poison();self.before['nodes']['etc']['sha256']=Poison()
 def observe(self,path,debugfs_pin,deadline,*,legacy_root,guard):
  if debugfs_pin!=pin('actor tool /usr/bin/debugfs')or legacy_root!=Path('/legacy'):
   raise AssertionError('exact Root debugfs pin and readonly legacy root required')
  self.trace.append(('observe',str(path),copy.deepcopy(debugfs_pin),deadline,str(legacy_root)));guard()
  if path==Path('/base/guest.raw'):self.advance(self.before_seconds);return self.before
  if path==WORK/'verification.raw':self.advance(self.after_seconds);return self.after
  raise AssertionError('fixed metadata scan operand only')
 def __getattr__(self,name):raise AssertionError('reader inventory/body API forbidden: '+name)


class Model:
 def __init__(self):
  self.trace=[];self.packet=packet();self.reader=Reader(self.trace,self.advance);self.outputs={};self.removed=[]
  self.clock=100.0;self.now_ns=NOW;self.overlay_seconds=0;self.deadline=DEADLINE
  self.epoch=dict(nonce=NONCE,utc_ns=NOW);self.replay=0;self.natural=True;self.argv_mismatch=False
  self.command_error=None;self.write_error=None;self.raw_identity_changed=False;self.identity_calls=0
  self.K=SimpleNamespace(OP='MODEL_NO_PACKAGE_OPERATION',need=A.need,canonical=lambda v:(json.dumps(v,sort_keys=True,indent=2)+'\n').encode(),
                         load=self.load,pin=self.pin)
  self.R=SimpleNamespace(command=self.command,receipt=self.receipt,natural=lambda row:row['MODEL_natural'])
 def load(self,path):
  if path!=WORK/'host-epoch.json':raise AssertionError('only public host epoch DATA is loaded')
  self.trace.append(('load',path.name))
  return copy.deepcopy(self.epoch)
 def pin(self,path,*args):
  if path not in(WORK/'qemu.json',WORK/'qemu-argv.json',WORK/'qemu-epoch.json'):raise AssertionError('no raw image/body pin allowed')
  return pin(path.name)
 def command(self,argv,work,label,seconds,deadline,**kwargs):
  self.trace.append(('command',label,list(argv),seconds,deadline,kwargs))
  if label==self.command_error:raise ValueError('MODEL command failure')
  if label=='overlay-create':self.advance(self.overlay_seconds)
  if label=='journal-copy-only':return SimpleNamespace(returncode=self.replay)
  return b'MODEL_PUBLIC_TOOL_STDOUT_NOT_EXPORTED'
 def receipt(self,path):
  if path!=WORK/'qemu.json':raise AssertionError('only original QEMU retirement receipt')
  argv=A.qemu_argv(self.packet,self.outputs[WORK/'qemu-epoch.json']['utc_ns']//10**9)
  if self.argv_mismatch:argv=argv+['MODEL_DIFFERENT_COMMAND']
  return dict(argv=argv,MODEL_natural=self.natural)
 def identity(self,K,path,expected):
  self.trace.append(('identity',str(path),expected));self.identity_calls+=1
  if path!=Path('/base/guest.raw')or expected!=1610612736:raise AssertionError('only original stat identity')
  return ('MODEL_CHANGED'if self.raw_identity_changed and self.identity_calls==2 else'MODEL_ORIGINAL',)
 def write(self,K,path,value):
  self.trace.append(('write',path.name))
  if path.name==self.write_error:raise OSError('MODEL output write failure')
  if path in self.outputs:raise AssertionError('exclusive output')
  self.outputs[path]=copy.deepcopy(value)
 def remove(self,path):
  self.trace.append(('remove',str(path)));self.removed.append(path)
  if path!=WORK/'verification.raw':raise AssertionError('only owned verification copy may be removed')
 def guard(self):self.trace.append(('guard',))
 def advance(self,seconds):self.clock+=seconds;self.now_ns+=int(seconds*10**9)
 def run(self):
  with patch.object(A,'load_reader',return_value=self.reader),patch.object(A,'raw_identity',side_effect=self.identity),\
       patch.object(A,'write_json',side_effect=self.write),patch.object(A,'remove_verification',side_effect=self.remove),\
       patch.object(A.time,'time_ns',side_effect=lambda:self.now_ns),patch.object(A.time,'monotonic',side_effect=lambda:self.clock):
   return A.run(self.K,self.R,WORK,self.packet,self.guard,self.deadline)
 def commands(self):return [event for event in self.trace if event[0]=='command']


class Controls(unittest.TestCase):
 def test_exact_original_overlay_geometry_and_no_package_tokens(self):
  p=packet();argv=A.qemu_argv(p,NOW//10**9)
  self.assertEqual(argv[argv.index('-nic')+1],'none');self.assertEqual(argv[argv.index('-accel')+1],'tcg,thread=multi')
  self.assertEqual(argv[argv.index('-m')+1],'2048');self.assertEqual(argv[argv.index('-smp')+1],'2')
  self.assertEqual(argv[argv.index('-kernel')+1],'/kernel/Image')
  append=argv[argv.index('-append')+1]
  tokens=[token for token in append.split()if token.startswith('arm16k_')]
  self.assertEqual(tokens,['arm16k_systemd_nonce='+'b'*32,'arm16k_rtc_host_epoch='+str(NOW//10**9)])
  self.assertNotIn(NONCE,append)
  for forbidden in('perl','prepared','root-ssh','package'):
   self.assertNotIn(forbidden,append)
  self.assertNotIn('-enable-kvm',argv)
 def test_qemu_geometry_rejects_unbounded_or_injected_values(self):
  for field,value in(('baseline_nonce','b'*31),('baseline_nonce','b'*32+' injected'),('cpus',True),('cpus',0),
                      ('cpus',65),('guest_memory_bytes',1024),('guest_memory_bytes',2*1024**3+1)):
   p=packet();(p if field=='baseline_nonce'else p['resources'])[field]=value
   with self.subTest(field=field),self.assertRaises(ValueError):A.qemu_argv(p,NOW//10**9)
  for epoch in(-1,2**34,True,'PRIVATE_RAW_VALUE'):
   with self.assertRaises(ValueError):A.qemu_argv(packet(),epoch)
 def test_original_raw_identity_uses_stat_only_and_fixed_geometry(self):
  info=SimpleNamespace(st_dev=1,st_ino=7,st_mode=stat.S_IFREG|0o600,st_uid=1000,st_gid=1000,
                       st_nlink=1,st_size=1610612736,st_mtime_ns=1,st_ctime_ns=2,st_blocks=1024)
  calls=[]
  def lstat():calls.append('lstat');return info
  K=SimpleNamespace(ordinary=lambda path:SimpleNamespace(lstat=lstat),need=A.need)
  identity=A.raw_identity(K,Path('/MODEL/original.raw'),1610612736)
  self.assertEqual(calls,['lstat']);self.assertEqual(identity[6],1610612736)
  for field,value in(('st_mode',stat.S_IFDIR|0o700),('st_nlink',0),('st_ino',0),('st_size',1)):
   old=getattr(info,field);setattr(info,field,value)
   with self.assertRaisesRegex(ValueError,'ordinary original raw'):A.raw_identity(K,Path('/MODEL/original.raw'),1610612736)
   setattr(info,field,old)
 def test_reader_pin_precedes_import_and_stable_observe_api_is_required(self):
  p=packet();reader=SimpleNamespace(observe=lambda *args,**kwargs:None);events=[]
  K=SimpleNamespace(ordinary=lambda path:path,pin=lambda *args:p['reader'],need=A.need)
  loader=SimpleNamespace(exec_module=lambda value:events.append('MODEL_SOURCE_IMPORT'))
  fake_spec=SimpleNamespace(name='Root_selected_fixed_raw_metadata_MODEL',loader=loader)
  self.addCleanup(sys.modules.pop,fake_spec.name,None)
  with patch.object(A.importlib.util,'spec_from_file_location',return_value=fake_spec),\
       patch.object(A.importlib.util,'module_from_spec',return_value=reader):
   self.assertIs(A.load_reader(K,p),reader)
   self.assertEqual(events,['MODEL_SOURCE_IMPORT'])
   events.clear();K.pin=lambda *args:pin('wrong selected reader')
   with self.assertRaisesRegex(ValueError,'exact separately selected'):A.load_reader(K,p)
   self.assertEqual(events,[])
   pins=iter((p['reader'],pin('changed after import')));K.pin=lambda *args:next(pins)
   with self.assertRaisesRegex(ValueError,'stable selected metadata reader'):A.load_reader(K,p)
   self.assertEqual(events,['MODEL_SOURCE_IMPORT'])
 def test_reader_with_old_scan_api_is_not_an_observe_or_inventory_fallback(self):
  p=packet();K=SimpleNamespace(ordinary=lambda path:path,pin=lambda *args:p['reader'],need=A.need)
  value=SimpleNamespace(scan=lambda *args:None,inventory=Poison(),body=Poison());loader=SimpleNamespace(exec_module=lambda value:None)
  with patch.object(A.importlib.util,'spec_from_file_location',return_value=SimpleNamespace(name='Root_selected_fixed_raw_metadata_old_MODEL',loader=loader)),\
       patch.object(A.importlib.util,'module_from_spec',return_value=value):
   with self.assertRaisesRegex(ValueError,'stable selected metadata reader'):A.load_reader(K,p)
 def test_reader_module_registration_supports_dataclasses_and_cleans_failed_import(self):
  p=packet();K=SimpleNamespace(ordinary=lambda path:path,pin=lambda *args:p['reader'],need=A.need)
  name='Root_selected_fixed_raw_metadata_dataclass_MODEL';self.addCleanup(sys.modules.pop,name,None)
  def execute(value):
   self.assertIs(sys.modules.get(name),value)
   exec('from __future__ import annotations\nfrom dataclasses import dataclass\n@dataclass\nclass PublicRow:\n inode: int\ndef observe(*args, **kwargs):\n return PublicRow(7)\n',value.__dict__)
  loader=SimpleNamespace(create_module=lambda spec:None,exec_module=execute)
  with patch.object(A.importlib.util,'spec_from_file_location',return_value=ModuleSpec(name,loader)):
   loaded=A.load_reader(K,p)
   self.assertIs(sys.modules.get(name),loaded)
   self.assertTrue(dataclasses.is_dataclass(loaded.PublicRow));self.assertEqual(loaded.observe().inode,7)
  def failed(value):
   self.assertIs(sys.modules.get(name),value)
   raise RuntimeError('MODEL import failure')
  with patch.object(A.importlib.util,'spec_from_file_location',return_value=ModuleSpec(name,SimpleNamespace(create_module=lambda spec:None,exec_module=failed))):
   with self.assertRaisesRegex(RuntimeError,'MODEL import failure'):A.load_reader(K,p)
   self.assertNotIn(name,sys.modules)
 def test_complete_model_sequence_fixed_metadata_and_unlink_after_observations(self):
  model=Model();result=model.run()
  commands=model.commands()
  self.assertEqual([event[1]for event in commands],['overlay-create','qemu','readback-convert','journal-copy-only','readback-readonly-fsck'])
  self.assertEqual(commands[0][2],['/usr/bin/qemu-img','create','-f','qcow2','-F','raw','-b','/base/guest.raw','/work/overlay.qcow2'])
  self.assertEqual(commands[3][2][:4],['/usr/bin/e2fsck','-p','-E','journal_only'])
  self.assertEqual(commands[4][2][:2],['/usr/bin/e2fsck','-fn'])
  observed=[event for event in model.trace if event[0]=='observe']
  self.assertEqual([event[1]for event in observed],['/base/guest.raw','/MODEL/work/verification.raw'])
  for event in observed:
   self.assertEqual(event[2],model.packet['actor_tools']['/usr/bin/debugfs']);self.assertEqual(event[3],220.0);self.assertEqual(event[4],'/legacy')
  writes=[event[1]for event in model.trace if event[0]=='write']
  self.assertEqual(writes,['offline-before.json','qemu-epoch.json','qemu-argv.json','observations.json'])
  self.assertEqual(result['qemu_epoch'],pin('qemu-epoch.json'))
  self.assertLess(model.trace.index(('write','observations.json')),model.trace.index(('remove','/MODEL/work/verification.raw')))
  self.assertEqual(model.removed,[WORK/'verification.raw'])
  self.assertEqual(tuple(result['metadata']['offline_before']),M.PATHS)
  self.assertNotIn('PRIVATE',json.dumps(result))
  self.assertNotEqual(result['metadata']['offline_before']['etc']['mtime_ns'],result['metadata']['offline_after']['etc']['mtime_ns'])
  self.assertEqual(result['status'],'PASS_NO_PACKAGE_ACTOR_OFFLINE_METADATA_ONLY')
  for field in('VM_acceptance','Root_acceptance','preservation','ALPM'):self.assertIsNone(result[field])
 def test_all_commands_share_guard_deadline_and_allocated_file_caps(self):
  model=Model();model.run();r=model.packet['resources']
  expected=(WORK,r['overlay_cap_bytes']+r['readback_allocated_cap_bytes']+r['logs_cap_bytes'],r['reserve_bytes'])
  for event in model.commands():
   self.assertEqual(event[4],DEADLINE);self.assertEqual(event[5]['watched_tree'],expected)
  qemu=next(event for event in model.commands()if event[1]=='qemu')
  self.assertEqual(qemu[3],900.0);self.assertEqual(qemu[5]['child_file_size_cap'],r['overlay_cap_bytes'])
  self.assertGreater(sum(event[0]=='guard'for event in model.trace),10)
 def test_unnatural_or_different_qemu_receipt_stops_before_readback(self):
  for field in('natural','argv_mismatch'):
   model=Model();setattr(model,field,False if field=='natural'else True)
   with self.assertRaisesRegex(ValueError,'same naturally retired'):model.run()
   self.assertEqual([event[1]for event in model.commands()],['overlay-create','qemu'])
   self.assertEqual(model.removed,[]);self.assertNotIn(WORK/'observations.json',model.outputs)
 def test_journal_replay_zero_or_one_only_and_readonly_fsck_required(self):
  for code in(0,1):
   model=Model();model.replay=code;self.assertTrue(model.run()['qemu_naturally_retired'])
  for code in(2,4,-1,True):
   model=Model();model.replay=code
   with self.assertRaisesRegex(ValueError,'journal replay only'):model.run()
   self.assertEqual(model.commands()[-1][1],'journal-copy-only');self.assertEqual(model.removed,[])
 def test_failed_convert_or_fsck_never_publishes_final_observation_or_removes_raw(self):
  for label in('readback-convert','journal-copy-only','readback-readonly-fsck'):
   model=Model();model.command_error=label
   with self.assertRaisesRegex(ValueError,'MODEL command failure'):model.run()
   self.assertEqual(model.commands()[-1][1],label);self.assertEqual(model.removed,[])
   self.assertNotIn(WORK/'observations.json',model.outputs)
 def test_unobserved_or_nonordinary_final_metadata_refuses_without_inventory(self):
  for malformed in('coverage','type','size'):
   model=Model()
   if malformed=='coverage':del model.reader.after['observed_paths']
   elif malformed=='type':model.reader.after['nodes']['root']['type']='file'
   else:model.reader.after['nodes']['root']['size']=Poison()
   with self.assertRaises(ValueError):model.run()
   self.assertNotIn(WORK/'observations.json',model.outputs);self.assertEqual(model.removed,[])
 def test_original_identity_change_is_not_reclassified_as_preservation(self):
  model=Model();model.raw_identity_changed=True
  with self.assertRaisesRegex(ValueError,'original raw host identity unchanged'):model.run()
  self.assertEqual(model.removed,[]);self.assertNotIn(WORK/'observations.json',model.outputs)
 def test_failed_final_write_retains_verification_copy(self):
  model=Model();model.write_error='observations.json'
  with self.assertRaises(OSError):model.run()
  self.assertEqual(model.removed,[])
 def test_stale_future_wrong_nonce_or_malformed_epoch_refuses_before_qemu(self):
  for epoch in(dict(nonce='c'*32,utc_ns=NOW),dict(nonce=NONCE,utc_ns=NOW-30*10**9-1),
               dict(nonce=NONCE,utc_ns=NOW+1),dict(nonce=NONCE,utc_ns=True),dict(nonce=NONCE,utc_ns=NOW,extra='PRIVATE')):
   model=Model();model.epoch=epoch
   with self.assertRaisesRegex(ValueError,'fresh same-nonce'):model.run()
   self.assertEqual(model.commands(),[]);self.assertEqual(model.removed,[])
   self.assertFalse(any(event[0]=='observe'for event in model.trace));self.assertEqual(model.outputs,{})
 def test_each_reader_deadline_is_limited_by_fixed_slot_and_overall_envelope(self):
  self.assertEqual(A.METADATA_SECONDS,120)
  for end,expected in((1000.0,220.0),(180.0,180.0)):
   model=Model();model.deadline=end;model.run()
   self.assertEqual([event[3]for event in model.trace if event[0]=='observe'],[expected,expected])
   self.assertTrue(all(event[4]==end for event in model.commands()))
 def test_long_first_metadata_uses_fresh_launch_epoch_after_overlay_creation(self):
  model=Model();model.reader.before_seconds=45;model.overlay_seconds=2;result=model.run()
  expected=NOW+47*10**9
  self.assertEqual(model.outputs[WORK/'qemu-epoch.json'],dict(nonce=NONCE,utc_ns=expected))
  argv=model.outputs[WORK/'qemu-argv.json']['argv']
  self.assertIn('arm16k_rtc_host_epoch='+str(expected//10**9),argv[argv.index('-append')+1].split())
  events=model.trace
  first_read=next(i for i,event in enumerate(events)if event[0]=='observe')
  overlay=next(i for i,event in enumerate(events)if event[:2]==('command','overlay-create'))
  self.assertLess(events.index(('load','host-epoch.json')),first_read)
  self.assertLess(overlay,events.index(('write','qemu-epoch.json')))
  self.assertLess(events.index(('write','qemu-epoch.json')),events.index(('write','qemu-argv.json')))
  self.assertEqual([event[3]for event in events if event[0]=='observe'],[220.0,267.0])
  self.assertEqual(result['qemu_epoch'],pin('qemu-epoch.json'))
 def test_scan_and_command_guards_propagate_without_later_success(self):
  model=Model()
  def failed_guard():raise TimeoutError('MODEL deadline')
  model.guard=failed_guard
  with self.assertRaises(TimeoutError):model.run()
  self.assertEqual(model.commands(),[]);self.assertEqual(model.outputs,{})
 def test_public_offline_before_survives_qemu_failure_without_final_acceptance(self):
  model=Model();model.command_error='qemu'
  with self.assertRaises(ValueError):model.run()
  before=model.outputs[WORK/'offline-before.json']
  self.assertEqual(before['nonce'],NONCE);self.assertIsNone(before['Root_acceptance'])
  self.assertIsNone(before['VM_acceptance']);self.assertNotIn(WORK/'observations.json',model.outputs)

if __name__=='__main__':unittest.main(verbosity=2)
