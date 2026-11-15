#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit ARM virtio-seat actor; unchanged owned retirement, new checked argv."""
import hashlib,importlib.util,json,os,re,resource,signal,socket,subprocess,sys,time
from pathlib import Path
# No import-time VM launch. The constructor only copies this file.

def qemu_argv(nonce,host_epoch):
 assert re.fullmatch('[0-9a-f]{32}',nonce)and type(host_epoch)is int and 0<host_epoch<10**12
 return ['/usr/bin/qemu-system-aarch64','-machine','virt','-accel','tcg,thread=multi','-rtc','base=utc,clock=host','-cpu','max','-smp','2','-m','2048','-nodefaults','-no-user-config','-display','none','-monitor','none','-nic','none','-no-reboot','-kernel','/inputs/Image','-append','root=/dev/vda rootfstype=ext4 rw console=tty0 console=ttyAMA0,115200n8 rootwait init=/usr/lib/systemd/systemd systemd.unit=multi-user.target arm16k_virtio_seat_nonce='+nonce+' arm16k_rtc_host_epoch='+str(host_epoch),'-drive','if=none,id=refdisk,file=/work/overlay.qcow2,format=qcow2','-device','virtio-blk-device,drive=refdisk','-device','virtio-keyboard-device','-device','virtio-gpu-device','-serial','unix:/work/serial.sock,server=on,wait=off','-qmp','unix:/work/qmp.sock,server=on,wait=off','-sandbox','on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny']

def main():
 if not(__debug__ and os.environ.get('CACHY_ASAHI_ALLOW_ARM16K_UI_BOOT')=='1'and sys.flags.isolated and Path('/.dockerenv').is_file()):raise RuntimeError('explicit owned reference boot required')
 status=dict(l.split(':',1)for l in Path('/proc/self/status').read_text().splitlines()if ':'in l)
 assert all(int(status[k].strip(),16)==0 for k in ['CapEff','CapPrm','CapBnd','CapInh','CapAmb'])and status['NoNewPrivs'].strip()=='1'
 assert {x[1]for x in socket.if_nameindex()}=={'lo'}and not Path('/dev/kvm').exists()
 assert hashlib.sha256(Path('/opt/owned_process.py').read_bytes()).hexdigest()=='83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f'
 spec=importlib.util.spec_from_file_location('tcg_owned_process','/opt/owned_process.py');O=importlib.util.module_from_spec(spec);spec.loader.exec_module(O)
 cancelled=[]
 for number in [signal.SIGINT,signal.SIGTERM]:signal.signal(number,lambda number,frame:cancelled.append(number))
 I=Path('/inputs');W=Path('/work');manifest=json.loads((I/'prepared.json').read_text());assert manifest['operation']=='arm16k-first-login-ui-vm-v1'
 for n,ref in manifest['files'].items():
  p=I/n;assert p.is_file()and not p.is_symlink()and p.stat().st_size==ref['bytes']
  with p.open('rb')as f:assert hashlib.file_digest(f,'sha256').hexdigest()==ref['sha256']
 admission=json.loads((W/'host-admission.json').read_text());assert admission['nonce']==manifest['nonce']
 now=time.time_ns();mono=time.monotonic_ns();elapsed=(mono-admission['monotonic_ns'])/1e9
 assert 0<=elapsed<=30 and abs((now-admission['utc_ns'])/1e9-elapsed)<=5,'live host UTC/monotonic admission differs'
 (W/'host-qemu-start.json').write_text(json.dumps({'utc_ns':now,'monotonic_ns':mono,'nonce':manifest['nonce']}))
 host_epoch=now//1000000000
 assert not (W/'attempt.json').exists();(W/'attempt.json').write_text(json.dumps({'nonce':manifest['nonce'],'scope':'emulated ARM16K only; no native16K/M2'}))
 subprocess.run(['qemu-img','create','-f','qcow2','-F','raw','-b','/inputs/guest.raw','/work/overlay.qcow2'],check=True,timeout=10)
 resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_FSIZE,(1024*1024**2,1024*1024**2))
 argv=qemu_argv(manifest['nonce'],host_epoch)
 if cancelled or(W/'STOP').exists():
  (W/'qemu-retirement.json').write_text(json.dumps({'passed':False,'no_VM_launched':True,'actor_cancelled':cancelled}));return 1
 (W/'qemu-argv.json').write_text(json.dumps(argv,indent=2)+'\n');O.prepare();child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
 until=time.monotonic()+600
 while time.monotonic()<until and not(W/'STOP').exists()and not cancelled:
  if os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOWAIT|os.WNOHANG)is not None:break
  time.sleep(.05)
 row=os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOWAIT|os.WNOHANG)
 if row is None:os.kill(child.pid,signal.SIGTERM)
 result=O.supervise(child,cap=10,retirement=3,grace=.5,max_output=1024**2);data=result.pop('output');result['actor_cancelled']=cancelled;(W/'qemu.log').write_bytes(data);(W/'qemu-retirement.json').write_text(json.dumps(result,indent=2)+'\n')
 return 0 if result['passed']and not cancelled else 1

if __name__=='__main__':raise SystemExit(main())
