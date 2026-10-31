# SPDX-License-Identifier: MIT
"""Pinned original supervisor plus explicit owned-group identity/absence receipt."""
import hashlib,os,signal,time,types
from pathlib import Path
import contract as C
ANCHOR=b'result.update(stdout=bytes(output[0]), stderr=bytes(output[1]))'
SOURCE_SHA='f18bcbd2a6279cff8fe6c7e9c9f80fc01c9818844b01df8c4e97b83d61704b10'

def _credentials():
 fd=os.open('/proc/self/status',os.O_RDONLY|os.O_CLOEXEC)
 try:raw=os.read(fd,65537)
 finally:os.close(fd)
 C.need(len(raw)<=65536,'bounded signal credential status')
 fields={k:v.strip()for k,v in(line.split(':',1)for line in raw.decode().splitlines()if ':'in line)}
 state={k:int(fields[k],16)for k in('CapEff','CapPrm','CapBnd','CapInh','CapAmb')}
 state.update(NoNewPrivs=int(fields['NoNewPrivs']),uid=os.geteuid(),gid=os.getegid())
 return (os.getresuid(),os.getresgid(),tuple(os.getgroups()),state)

class _SignalOS:
 """Only signals/probes use the declared child's UID; every credential restores."""
 def __init__(self,uid):
  C.need(type(uid)is int and 0<=uid<2**31,'explicit bounded rooted fixture UID')
  self.uid=uid;self.before=_credentials();self.group=None
  C.need(self.before[0]==(0,0,0),'owned root supervisor credential triples')
  C.capability_profile(self.before[3])
 def __getattr__(self,name):return getattr(os,name)
 def killpg(self,group,sig):
  C.need(type(group)is int and group>1 and sig in(signal.SIGTERM,signal.SIGKILL,0),'owned group signal/probe only')
  if self.group is None:self.group=group
  C.need(group==self.group and _credentials()==self.before,'one owned group and unchanged supervisor credentials')
  try:
   if self.uid!=0:os.seteuid(self.uid)
   return os.killpg(group,sig)
  finally:
   if os.geteuid()!=self.before[0][1]:os.seteuid(self.before[0][1])
   C.need(_credentials()==self.before,'exact UID/GID/groups/capability/NNP restoration after signal')


def run(*args,signal_uid=None,**kwargs):
 signal_os=os if signal_uid is None else _SignalOS(signal_uid)
 path=Path(__file__).resolve().parents[3]/'held-copy/scripts/update/supervision.py';raw=C.ordinary(path,128*1024)
 C.need(C.pin(raw)['sha256']==SOURCE_SHA and raw.count(ANCHOR)==1,'whole original process supervisor and one receipt seam')
 changed=raw.replace(ANCHOR,b'result.update(stdout=bytes(output[0]), stderr=bytes(output[1]), owned_group_id=process.pid)')
 module=types.ModuleType('_copy606_owned_supervisor');exec(compile(changed,str(path),'exec'),module.__dict__);module.os=signal_os;result=module.run(*args,**kwargs)
 group=result['owned_group_id'];end=time.monotonic()+1;reaped=0;absent=False
 while time.monotonic()<end:
  try:
   child,_=os.waitpid(-group,os.WNOHANG)
   if child:reaped+=1;C.need(reaped<=512,'owned descendant reap bound')
  except ChildProcessError:pass
  try:signal_os.killpg(group,0)
  except ProcessLookupError:absent=True;break
  time.sleep(.01)
 # Never send another signal after the leader is reaped and its ID can be reused.
 # A remaining/reused group is an explicit failure, not a target for further kill.
 result.update(group_retired=absent,descendants_reaped=reaped)
 return result
