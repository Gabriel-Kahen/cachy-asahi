# SPDX-License-Identifier: MIT
"""Pinned original supervisor plus explicit owned-group identity/absence receipt."""
import hashlib,os,signal,time,types
from pathlib import Path
import contract as C
ANCHOR=b'result.update(stdout=bytes(output[0]), stderr=bytes(output[1]))'
SOURCE_SHA='f18bcbd2a6279cff8fe6c7e9c9f80fc01c9818844b01df8c4e97b83d61704b10'

def run(*args,**kwargs):
 path=Path(__file__).resolve().parents[3]/'held-copy/scripts/update/supervision.py';raw=C.ordinary(path,128*1024)
 C.need(C.pin(raw)['sha256']==SOURCE_SHA and raw.count(ANCHOR)==1,'whole original process supervisor and one receipt seam')
 changed=raw.replace(ANCHOR,b'result.update(stdout=bytes(output[0]), stderr=bytes(output[1]), owned_group_id=process.pid)')
 module=types.ModuleType('_copy606_owned_supervisor');exec(compile(changed,str(path),'exec'),module.__dict__);result=module.run(*args,**kwargs)
 group=result['owned_group_id'];end=time.monotonic()+1;reaped=0;absent=False
 while time.monotonic()<end:
  try:
   child,_=os.waitpid(-group,os.WNOHANG)
   if child:reaped+=1;C.need(reaped<=512,'owned descendant reap bound')
  except ChildProcessError:pass
  try:os.killpg(group,0)
  except ProcessLookupError:absent=True;break
  time.sleep(.01)
 # Never send another signal after the leader is reaped and its ID can be reused.
 # A remaining/reused group is an explicit failure, not a target for further kill.
 result.update(group_retired=absent,descendants_reaped=reaped)
 return result
