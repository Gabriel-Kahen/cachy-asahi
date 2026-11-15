#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Owned real-seat reference-QEMU child. Invoked ONLY by Root's explicit boot controller."""
import hashlib,importlib.util,json,os,resource,signal,socket,subprocess,time
from pathlib import Path
# No import-time VM launch. The constructor only copies this file.

def main():
 if not(__debug__ and os.environ.get('CACHY_ASAHI_ALLOW_REFERENCE_BOOT')=='1'and Path('/.dockerenv').is_file()):raise RuntimeError('explicit owned reference boot required')
 status=dict(l.split(':',1)for l in Path('/proc/self/status').read_text().splitlines()if ':'in l)
 assert all(int(status[k].strip(),16)==0 for k in ['CapEff','CapPrm','CapBnd','CapInh','CapAmb'])and status['NoNewPrivs'].strip()=='1'
 assert {x[1]for x in socket.if_nameindex()}=={'lo'}and not Path('/dev/kvm').exists()
 spec=importlib.util.spec_from_file_location('tcg_owned_process','/opt/owned_process.py');O=importlib.util.module_from_spec(spec);spec.loader.exec_module(O)
 cancelled=[]
 for number in [signal.SIGINT,signal.SIGTERM]:signal.signal(number,lambda number,frame:cancelled.append(number))
 I=Path('/inputs');W=Path('/work');manifest=json.loads((I/'prepared.json').read_text())
 for n,ref in manifest['files'].items():
  p=I/n;assert p.is_file()and not p.is_symlink()and p.stat().st_size==ref['bytes']
  with p.open('rb')as f:assert hashlib.file_digest(f,'sha256').hexdigest()==ref['sha256']
 assert not (W/'attempt.json').exists();(W/'attempt.json').write_text(json.dumps({'nonce':manifest['nonce'],'scope':'x86 software reference; no ARM/M2'}))
 subprocess.run(['qemu-img','create','-f','qcow2','-F','raw','-b','/inputs/guest.raw','/work/overlay.qcow2'],check=True,timeout=10)
 resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_FSIZE,(256*1024**2,256*1024**2))
 argv=['/usr/bin/qemu-system-x86_64','-machine','q35,i8042=on','-accel','tcg,thread=multi','-cpu','max','-smp','2','-m','1536','-nodefaults','-no-user-config','-display','none','-monitor','none','-nic','none','-device','VGA','-no-reboot','-kernel','/inputs/vmlinuz','-initrd','/inputs/initramfs.img','-append','root=/dev/vda rootfstype=ext4 rw console=tty0 console=ttyS0,115200n8 reboot=t init=/usr/lib/systemd/systemd systemd.unit=multi-user.target tcg_reference_nonce='+manifest['nonce'],'-drive','if=none,id=refdisk,file=/work/overlay.qcow2,format=qcow2','-device','virtio-blk-pci,drive=refdisk','-serial','unix:/work/serial.sock,server=on,wait=off','-qmp','unix:/work/qmp.sock,server=on,wait=off','-sandbox','on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny']
 if cancelled or(W/'STOP').exists():
  (W/'qemu-retirement.json').write_text(json.dumps({'passed':False,'no_VM_launched':True,'actor_cancelled':cancelled}));return 1
 (W/'qemu-argv.json').write_text(json.dumps(argv,indent=2)+'\n');O.prepare();child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
 until=time.monotonic()+480
 while time.monotonic()<until and not(W/'STOP').exists()and not cancelled:
  if os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOWAIT|os.WNOHANG)is not None:break
  time.sleep(.05)
 row=os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOWAIT|os.WNOHANG)
 if row is None:os.kill(child.pid,signal.SIGTERM)
 result=O.supervise(child,cap=10,retirement=3,grace=.5,max_output=1024**2);data=result.pop('output');result['actor_cancelled']=cancelled;(W/'qemu.log').write_bytes(data);(W/'qemu-retirement.json').write_text(json.dumps(result,indent=2)+'\n')
 return 0 if result['passed']and not cancelled else 1

if __name__=='__main__':raise SystemExit(main())
