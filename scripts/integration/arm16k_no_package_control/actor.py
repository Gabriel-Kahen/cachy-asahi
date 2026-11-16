#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Explicit rootless no-package VM actor; no actions on import.

The Root controller authenticates original raw/prepared pins. This actor checks
raw size/identity only and delegates both scans to the separately pinned fixed-
metadata reader. It never imports the legacy image/inventory/payload reader.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import resource
import socket
import stat
import sys
import time

HERE=Path(__file__).resolve().parent
METADATA_SECONDS=120
TOOLS=('/usr/bin/python3','/usr/bin/cp','/usr/bin/debugfs','/usr/bin/e2fsck',
       '/usr/bin/qemu-img','/usr/bin/qemu-system-aarch64')


def module(name):
 spec=importlib.util.spec_from_file_location('no_package_actor_'+name,HERE/(name+'.py'))
 value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


def need(ok,message):
 if not ok:raise ValueError(message)


def qemu_argv(packet,epoch_seconds):
 """Same Source65 TCG/RTC geometry, original baseline only, no Perl token."""
 import re
 nonce=packet['baseline_nonce'];r=packet['resources']
 need(type(nonce)is str and re.fullmatch('[0-9a-f]{32}',nonce)is not None,'literal original baseline nonce')
 need(type(epoch_seconds)is int and 0<=epoch_seconds<2**34,'bounded UTC boot epoch')
 need(type(r['cpus'])is int and 1<=r['cpus']<=64,'bounded integer guest CPUs')
 memory=r['guest_memory_bytes']
 need(type(memory)is int and 128*1024**2<=memory<=64*1024**3 and memory%1024**2==0,'bounded MiB guest memory')
 return ['/usr/bin/qemu-system-aarch64','-machine','virt','-accel','tcg,thread=multi',
  '-rtc','base=utc,clock=host','-cpu','max','-smp',str(r['cpus']),'-m',str(memory//1024**2),
  '-nodefaults','-no-user-config','-display','none','-monitor','none','-nic','none','-no-reboot',
  '-kernel','/kernel/Image','-append',
  'root=/dev/vda rootfstype=ext4 rw console=ttyAMA0,115200n8 rootwait init=/usr/lib/systemd/systemd systemd.unit=multi-user.target arm16k_systemd_nonce='+nonce+' arm16k_rtc_host_epoch='+str(epoch_seconds),
  '-drive','if=none,id=refdisk,file=/work/overlay.qcow2,format=qcow2','-device','virtio-blk-device,drive=refdisk',
  '-serial','unix:/work/serial.sock,server=on,wait=off','-qmp','unix:/work/qmp.sock,server=on,wait=off',
  '-sandbox','on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny']


def raw_identity(K,path,expected_bytes):
 """Host-file metadata only. Never body-hash an original or readback raw."""
 info=K.ordinary(path).lstat()
 K.need(type(expected_bytes)is int and expected_bytes>0 and stat.S_ISREG(info.st_mode)and info.st_size==expected_bytes and info.st_ino>0 and info.st_nlink>0,'ordinary original raw with fixed geometry')
 return tuple(getattr(info,name)for name in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns','st_blocks'))


def load_reader(K,packet):
 path=K.ordinary(Path('/reader/raw_metadata.py'))
 K.need(K.pin(path,packet['reader']['bytes'])==packet['reader'],'exact separately selected metadata reader')
 spec=importlib.util.spec_from_file_location('Root_selected_fixed_raw_metadata',path)
 K.need(spec is not None and spec.loader is not None,'metadata reader Python loader')
 value=importlib.util.module_from_spec(spec)
 # Dataclasses and ordinary Python module introspection require registration
 # during execution; the pinned reader remains a single explicit source file.
 sys.modules[spec.name]=value
 try:
  spec.loader.exec_module(value)
  K.need(K.pin(path,packet['reader']['bytes'])==packet['reader']and callable(getattr(value,'observe',None)),
         'stable selected metadata reader with observe API')
 except BaseException:
  sys.modules.pop(spec.name,None)
  raise
 return value


def write_json(K,path,value):
 raw=K.canonical(value)
 K.need(0<len(raw)<=65536,'bounded public metadata actor JSON')
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 with os.fdopen(fd,'wb')as stream:os.fchmod(stream.fileno(),0o600);stream.write(raw)


def remove_verification(path):path.unlink()


def run(K,R,W,packet,guard,deadline):
 """Run only after Root input/cap/owner validation; injectable DATA dependencies."""
 epoch=K.load(W/'host-epoch.json')
 K.need(type(epoch)is dict and set(epoch)=={'nonce','utc_ns'}and epoch['nonce']==packet['nonce']and type(epoch['utc_ns'])is int
        and 0<=time.time_ns()-epoch['utc_ns']<=30*10**9,'fresh same-nonce host RTC epoch')
 r=packet['resources'];metadata=module('metadata');reader=load_reader(K,packet)
 base=Path('/base/guest.raw');original=raw_identity(K,base,packet['baseline']['raw']['bytes'])
 guard();before=metadata.project_scan(reader.observe(base,packet['actor_tools']['/usr/bin/debugfs'],min(deadline,time.monotonic()+METADATA_SECONDS),legacy_root=Path('/legacy'),guard=guard));guard()
 binding=dict(operation=K.OP,nonce=packet['nonce'],baseline_nonce=packet['baseline_nonce'],source_lock=packet['source_lock'],
              baseline={name:packet['baseline'][name]for name in('raw','prepared','certificate')},
              kernel={name:packet['kernel'][name]for name in('Image','config')},reader=packet['reader'])
 write_json(K,W/'offline-before.json',dict(kind='NO_PACKAGE_CONTROL_OFFLINE_BEFORE_METADATA_V1',**binding,metadata=before,
            VM_acceptance=None,Root_acceptance=None))
 watched=(W,r['overlay_cap_bytes']+r['readback_allocated_cap_bytes']+r['logs_cap_bytes'],r['reserve_bytes'])
 def command(label,argv,seconds,**kwargs):
  guard()
  result=R.command(argv,W,label,seconds,deadline,watched_tree=watched,**kwargs)
  guard();return result
 command('overlay-create',['/usr/bin/qemu-img','create','-f','qcow2','-F','raw','-b','/base/guest.raw','/work/overlay.qcow2'],15)
 launch=dict(nonce=packet['nonce'],utc_ns=time.time_ns())
 write_json(K,W/'qemu-epoch.json',launch)
 argv=qemu_argv(packet,launch['utc_ns']//10**9)
 write_json(K,W/'qemu-argv.json',dict(argv=argv))
 command('qemu',argv,deadline-time.monotonic(),child_file_size_cap=r['overlay_cap_bytes'])
 receipt=R.receipt(W/'qemu.json')
 K.need(R.natural(receipt)and receipt.get('argv')==argv,'same naturally retired no-package QEMU command')
 raw=W/'verification.raw'
 command('readback-convert',['/usr/bin/qemu-img','convert','-f','qcow2','-O','raw','-S','4k','/work/overlay.qcow2',str(raw)],r['cleanup_seconds'])
 replay=command('journal-copy-only',['/usr/bin/e2fsck','-p','-E','journal_only',str(raw)],r['cleanup_seconds'],check=False,completed=True)
 K.need(type(replay.returncode)is int and replay.returncode in(0,1),'verification-copy journal replay only')
 command('readback-readonly-fsck',['/usr/bin/e2fsck','-fn',str(raw)],r['cleanup_seconds'])
 guard();after=metadata.project_scan(reader.observe(raw,packet['actor_tools']['/usr/bin/debugfs'],min(deadline,time.monotonic()+METADATA_SECONDS),legacy_root=Path('/legacy'),guard=guard));guard()
 K.need(raw_identity(K,base,packet['baseline']['raw']['bytes'])==original,'original raw host identity unchanged')
 result=dict(schema=1,status='PASS_NO_PACKAGE_ACTOR_OFFLINE_METADATA_ONLY',**binding,
             metadata=dict(offline_before=before,offline_after=after),qemu_receipt=K.pin(W/'qemu.json'),
             qemu_argv=K.pin(W/'qemu-argv.json'),qemu_epoch=K.pin(W/'qemu-epoch.json'),
             qemu_naturally_retired=True,original_raw_identity_unchanged=True,
             VM_acceptance=None,Root_acceptance=None,preservation=None,ALPM=None)
 write_json(K,W/'observations.json',result)
 # No successful write means no deletion; retained scratch remains Root-owned.
 guard();remove_verification(raw)
 return result


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--execute-root-bound-actor',action='store_true');args=p.parse_args()
 need(args.execute_root_bound_actor and __debug__ and sys.flags.isolated and sys.dont_write_bytecode
      and os.environ.get('CACHY_NO_PACKAGE_ACTOR')=='1'and Path('/.dockerenv').is_file(),
      'explicit disposable no-package actor entry')
 status=dict(line.split(':',1)for line in Path('/proc/self/status').read_text().splitlines()if ':'in line)
 need(all(int(status[name],16)==0 for name in('CapEff','CapPrm','CapInh','CapAmb','CapBnd'))and status['NoNewPrivs'].strip()=='1'
      and {name for _,name in socket.if_nameindex()}=={'lo'}and not Path('/dev/kvm').exists(),
      'cap0 NNP network-none software-only no-package actor')
 S=module('support');K=S.local('contracts');R=S.legacy('runtime')
 packet=K.load(Path('/packet/control-packet.json'));source=S.source(packet['source_lock']);K.inputs(packet,source)
 W=Path('/work');r=packet['resources'];envelope=K.load(W/'actor-envelope.json')
 K.need(type(envelope)is dict and set(envelope)=={'deadline_monotonic_ns'}and type(envelope['deadline_monotonic_ns'])is int,
        'fixed Root actor deadline envelope')
 deadline=envelope['deadline_monotonic_ns']/10**9
 K.need(0<deadline-time.monotonic()<=r['boot_seconds'],'finite Root actor envelope')
 K.END=deadline;S.legacy('contracts').END=deadline
 def guard():
  K.need(time.monotonic()<deadline and not(W/'STOP').exists()and not(W/'STOP').is_symlink(),'actor cancellation/deadline')
  R.component_limits(W,[(W/'overlay.qcow2',r['overlay_cap_bytes']),(W/'verification.raw',r['readback_allocated_cap_bytes'])])
  K.need(R.allocated(W,deadline)<=r['overlay_cap_bytes']+r['readback_allocated_cap_bytes']+r['logs_cap_bytes'],'bounded no-package actor allocation')
 R.GUARD=guard;resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 guard()
 for name in TOOLS:K.need(R.image_tool_pin(name)==packet['actor_tools'][name],'same Root-selected actual actor tool')
 for name in('Image','config'):K.need(K.pin(Path('/kernel')/name,packet['kernel'][name]['bytes'])==packet['kernel'][name],'same selected case14 kernel file')
 guard()
 run(K,R,W,packet,guard,deadline)
 return 0

if __name__=='__main__':raise SystemExit(main())
