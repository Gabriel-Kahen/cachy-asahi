# SPDX-License-Identifier: MIT
"""Bounded native ARM KVM capability DATA; no kernel, disks, guest, or network."""
import argparse, hashlib, json, os, platform, shutil, signal, socket, stat
import subprocess, tempfile, time
from pathlib import Path

CAP=1024*1024

def command(binary,qmp):
 return [binary,'-nodefaults','-machine','virt','-accel','kvm','-cpu','host',
         '-smp','1','-m','128','-nic','none','-display','none','-serial','none',
         '-monitor','none','-S','-qmp','unix:'+str(qmp)+',server=on,wait=off']

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def device(path):
 try:
  info=path.lstat()
  return dict(exists=True,character_device=stat.S_ISCHR(info.st_mode),symlink=stat.S_ISLNK(info.st_mode),
              mode=oct(stat.S_IMODE(info.st_mode)),uid=info.st_uid,gid=info.st_gid,
              readable=os.access(path,os.R_OK),writable=os.access(path,os.W_OK),
              major=os.major(info.st_rdev),minor=os.minor(info.st_rdev))
 except FileNotFoundError:return dict(exists=False)

class QMP:
 def __init__(self,sock,end):self.sock,self.end,self.pending=sock,end,b'';self.bytes=0
 def row(self):
  while b'\n'not in self.pending:
   self.sock.settimeout(max(.01,self.end-time.monotonic()))
   raw=self.sock.recv(4096);self.bytes+=len(raw)
   if not raw or self.bytes>65536:raise ValueError('bounded QMP response required')
   self.pending+=raw
  raw,self.pending=self.pending.split(b'\n',1)
  if len(raw)>8192:raise ValueError('bounded QMP row required')
  return json.loads(raw)
 def query(self,name):
  self.sock.sendall((json.dumps(dict(execute=name,id=name))+'\n').encode())
  for _ in range(16):
   row=self.row()
   if row.get('id')==name:return row
  raise ValueError('finite QMP event bound')

def probe():
 result=dict(schema_version=1,purpose='KVM_CAPABILITY_ONLY_NO_GUEST_EXECUTION',
   host=dict(architecture=platform.machine(),page_size=os.sysconf('SC_PAGE_SIZE'),kernel=platform.release()),
   device=device(Path('/dev/kvm')),binary=shutil.which('qemu-system-aarch64'),
   source_identity={k:os.environ.get(k)for k in('GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT')},
   guest_kernel='NONE',guest_media='NONE',guest_network='NONE',generic16K='NOT_RUN',
   hardware='NOT_RUN',Root_acceptance='NOT_GRANTED',release='NOT_ADMITTED')
 if result['binary']is None:
  result.update(status='UNKNOWN_QEMU_BINARY_UNAVAILABLE',process_started=False);return result
 binary=result['binary']
 help_result=subprocess.run([binary,'-accel','help'],stdin=subprocess.DEVNULL,capture_output=True,timeout=10)
 if len(help_result.stdout)+len(help_result.stderr)>CAP:raise ValueError('accelerator help output bound')
 result['accel_help']=dict(exit=help_result.returncode,stdout=help_result.stdout.decode(errors='replace'),stderr=help_result.stderr.decode(errors='replace'))
 with tempfile.TemporaryDirectory(prefix='caa-kvm-')as directory:
  root=Path(directory);qmp=root/'qmp';process=None;sock=None;error=None;rows={};started=time.monotonic()
  with (root/'stdout').open('w+b')as out,(root/'stderr').open('w+b')as err:
   try:
    argv=command(binary,qmp);result['argv']=argv
    process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True,close_fds=True)
    end=time.monotonic()+30
    while time.monotonic()<end and process.poll()is None:
     if out.tell()+err.tell()>CAP:raise ValueError('QEMU output cap')
     sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
     try:sock.connect(str(qmp));break
     except (FileNotFoundError,ConnectionRefusedError):sock.close();sock=None;time.sleep(.05)
    if sock is None:raise ValueError('QEMU exited or bounded initialization expired')
    api=QMP(sock,end);rows['greeting']=api.row()
    if 'QMP'not in rows['greeting']:raise ValueError('QMP greeting missing')
    for name in ('qmp_capabilities','query-kvm','query-status'):rows[name]=api.query(name)
    if any('error'in row for row in rows.values()):raise ValueError('QMP command failure')
    actual=rows['query-kvm']['return']
    if actual!={'enabled':True,'present':True}:raise ValueError('KVM must be enabled and present')
    if rows['query-status']['return'].get('running')is not False:raise ValueError('guest execution must remain stopped')
    rows['quit']=api.query('quit')
   except Exception as caught:error=dict(type=type(caught).__name__,message=str(caught)[:512])
   finally:
    if sock is not None:sock.close()
    if process is not None:
     try:process.wait(timeout=3)
     except subprocess.TimeoutExpired:
      try:os.killpg(process.pid,signal.SIGTERM)
      except ProcessLookupError:pass
      try:process.wait(timeout=3)
      except subprocess.TimeoutExpired:
       try:os.killpg(process.pid,signal.SIGKILL)
       except ProcessLookupError:pass
       process.wait(timeout=3)
     try:os.killpg(process.pid,0);absent=False
     except ProcessLookupError:absent=True
     result['process']=dict(pid=process.pid,exit=process.returncode,direct_child_reaped=True,group_absence_verified=absent)
    out.seek(0);err.seek(0);stdout=out.read(CAP+1);stderr=err.read(CAP+1)
    if len(stdout)+len(stderr)>CAP:error=dict(type='OutputLimit',message='QEMU output cap exceeded')
    result['streams']={name:dict(**pin(raw),text=raw[:8192].decode(errors='replace'),truncated=len(raw)>8192)for name,raw in(('stdout',stdout),('stderr',stderr))}
  result.update(qmp=rows,error=error,elapsed_seconds=round(time.monotonic()-started,6),process_started=process is not None)
  retired=result.get('process',{}).get('group_absence_verified')is True
  result['status']='KVM_INITIALIZED_NO_GUEST_EXECUTION'if error is None and retired else'KVM_UNAVAILABLE_OR_PROBE_FAILED_DATA_ONLY'
 return result

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
 try:value=probe()
 except Exception as error:value=dict(status='UNKNOWN_PROBE_ERROR',error=dict(type=type(error).__name__,message=str(error)[:512]),Root_acceptance='NOT_GRANTED',generic16K='NOT_RUN',hardware='NOT_RUN')
 raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
 fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb')as stream:stream.write(raw)
 print(value['status'])
