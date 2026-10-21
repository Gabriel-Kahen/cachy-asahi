# SPDX-License-Identifier: MIT
"""Bounded missing per-graph timing DATA, preserving original owner/consumer clocks."""
import json,math,os,stat,time
from pathlib import Path
PROFILE='LATEST607_FRESH_GRAPH_TIMING_DATA_V1'
def need(ok,why):
 if not ok:raise ValueError(why)
class GraphTiming:
 def __init__(self,path,nonce,deadline,phase):
  self.path=Path(path);self.nonce=nonce;self.deadline=deadline;self.phase=phase;self.rows=[]
  need(self.path.is_absolute()and self.path.name=='latest607-graph-timing.json'and not any(p.is_symlink()for p in(self.path,*self.path.parents))and type(nonce)is str and len(nonce)==32 and all(c in'0123456789abcdef'for c in nonce),'fixed bounded graph timing DATA path/nonce')
  need(type(deadline)in(int,float)and math.isfinite(deadline)and time.monotonic()<deadline,'same original graph deadline')
  fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|os.O_NOFOLLOW,0o600)
  try:
   os.fchmod(fd,0o644)  # Fixed public scalar diagnostic only, readable by the owning host retainer.
   s=os.fstat(fd);self.identity=(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_nlink)
  finally:os.close(fd)
  self.save()
 def save(self):
  value=dict(profile=PROFILE,status='GRAPH_TIMING_DATA_ONLY_NOT_ACCEPTANCE',nonce=self.nonce,original_deadline=self.deadline,consumer_seconds=1800,owner_seconds=6600,observations=self.rows,actual_authority=False)
  raw=(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode();need(len(raw)<=128*1024 and len(self.rows)<=51,'finite51 original complete graph observations')
  fd=os.open(self.path,os.O_WRONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
  try:
   s=os.fstat(fd);need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_nlink)==self.identity,'same ordinary graph diagnostic DATA inode');os.ftruncate(fd,0);view=memoryview(raw)
   while view:view=view[os.write(fd,view):]
  finally:os.close(fd)
 def wrap(self,capture):
  def measured(root,packages,**kwargs):
   need(kwargs.get('deadline')==self.deadline and len(self.rows)<51,'same original deadline and51 complete captures');started=time.monotonic();row=dict(sequence=len(self.rows),phase=self.phase(),state='BEGIN',started=started);self.rows.append(row);self.save()
   try:
    value=capture(root,packages,**kwargs);row.update(state='COMPLETE',nodes=len(value['nodes']),bytes_read=value['bytes_read']);return value
   except BaseException:row['state']='FAILED';raise
   finally:row['seconds']=round(time.monotonic()-started,6);self.save()
  return measured
