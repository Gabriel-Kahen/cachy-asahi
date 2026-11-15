#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit ARM virtio-seat actor; unchanged owned retirement, new checked argv."""
import contextlib,hashlib,importlib.util,json,os,re,resource,signal,socket,subprocess,sys,time
from pathlib import Path
# No import-time VM launch. The constructor only copies this file.

def qemu_argv(nonce,host_epoch):
 assert re.fullmatch('[0-9a-f]{32}',nonce)and type(host_epoch)is int and 0<host_epoch<10**12
 return ['/usr/bin/qemu-system-aarch64','-machine','virt','-global','virtio-mmio.force-legacy=false','-accel','tcg,thread=multi','-rtc','base=utc,clock=host','-cpu','max','-smp','2','-m','2048','-nodefaults','-no-user-config','-display','none','-monitor','none','-nic','none','-no-reboot','-kernel','/inputs/Image','-append','root=/dev/vda rootfstype=ext4 rw console=tty0 console=ttyAMA0,115200n8 rootwait init=/usr/lib/systemd/systemd systemd.unit=multi-user.target arm16k_virtio_seat_nonce='+nonce+' arm16k_rtc_host_epoch='+str(host_epoch),'-drive','if=none,id=refdisk,file=/work/overlay.qcow2,format=qcow2','-device','virtio-blk-device,drive=refdisk','-device','virtio-keyboard-device','-device','virtio-gpu-device','-serial','unix:/work/serial.sock,server=on,wait=off','-qmp','unix:/work/qmp.sock,server=on,wait=off','-sandbox','on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny']

MEMORY_EVENTS={'low','high','max','oom','oom_kill','oom_group_kill','sock_throttled'}
def memory_snapshot(work,nonce,stage,cgroup=Path('/sys/fs/cgroup')):
 assert stage in ['before-vm','at-qemu-exit','final']and re.fullmatch('[0-9a-f]{32}',nonce)
 def read(name):
  fd=os.open(cgroup/name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
  try:raw=os.read(fd,4097);assert len(raw)<=4096;return raw.decode('ascii').strip()
  finally:os.close(fd)
 def number(text):
  assert re.fullmatch('[0-9]{1,20}',text);value=int(text);assert value<=2**64-1;return value
 value={'schema_version':1,'nonce':nonce,'stage':stage,'utc_ns':time.time_ns(),'source':'fixed cgroup-v2 numeric DATA','status':'OBSERVED'}
 failure=None
 try:
  events={}
  for line in read('memory.events').splitlines():
   key,value_text=line.split();assert key in MEMORY_EVENTS and key not in events;events[key]=number(value_text)
  assert {'low','high','max','oom','oom_kill'}<=events.keys();value['memory.events']=events
  for name in ['memory.peak','memory.current','memory.max','memory.swap.current','memory.swap.max']:value[name]=number(read(name))
  assert value['memory.max']==4*1024**3 and value['memory.swap.max']==0,'exact4GiB no-swap actual cgroup required'
 except (OSError,ValueError,AssertionError)as error:
  failure=error;value.update(status='REFUSED',error_category=type(error).__name__)
 raw=(json.dumps(value,indent=2,sort_keys=True)+'\n').encode();assert len(raw)<=16384 and work.is_dir()and not work.is_symlink()
 path=work/('memory-'+stage+'.json');fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  os.fchmod(fd,0o600)
  with os.fdopen(fd,'wb',closefd=False)as stream:stream.write(raw);stream.flush();os.fsync(fd)
 finally:os.close(fd)
 directory=os.open(work,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(directory)
 finally:os.close(directory)
 if failure is not None:raise failure
 return value

@contextlib.contextmanager
def memory_receipts(work,nonce):
 try:
  memory_snapshot(work,nonce,'before-vm')
  yield
 finally:memory_snapshot(work,nonce,'final')

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
 with memory_receipts(W,manifest['nonce']):
  (W/'qemu-argv.json').write_text(json.dumps(argv,indent=2)+'\n');O.prepare();child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
  until=time.monotonic()+600
  while time.monotonic()<until and not(W/'STOP').exists()and not cancelled:
   if os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOWAIT|os.WNOHANG)is not None:break
   time.sleep(.05)
  row=os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOWAIT|os.WNOHANG)
  if row is None:os.kill(child.pid,signal.SIGTERM)
  result=O.supervise(child,cap=10,retirement=3,grace=.5,max_output=1024**2);data=result.pop('output');result['actor_cancelled']=cancelled;(W/'qemu.log').write_bytes(data);(W/'qemu-retirement.json').write_text(json.dumps(result,indent=2)+'\n');memory_snapshot(W,manifest['nonce'],'at-qemu-exit')
  return 0 if result['passed']and not cancelled else 1

if __name__=='__main__':raise SystemExit(main())
