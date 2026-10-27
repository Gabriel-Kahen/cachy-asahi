# SPDX-License-Identifier: MIT
"""Bounded source/DATA reads; no actors."""
import hashlib,json,os,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
def need(ok,why):
 if not ok:raise ValueError(why)
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def safe(p):
 p=Path(p).absolute();need(p==p.resolve()and not any(q.is_symlink()for q in(p,*p.parents)),'canonical ordinary path required');return p
def read(p,maximum=16*1024**2):
 p=safe(p);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=maximum,'bounded singlelink DATA/source');out=bytearray()
  while b:=os.read(fd,1024**2):out.extend(b);need(len(out)<=a.st_size,'DATA read growth refused')
  key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  need(len(out)==a.st_size and key(a)==key(os.fstat(fd))==key(p.lstat()),'stable descriptor/path required');return bytes(out)
 finally:os.close(fd)
def checked(p,row):
 b=read(p,max(16*1024**2,row['bytes']));need(pin(b)==row,'exact byte input '+str(p));return b
def profile():return json.loads(read(HERE/'input-profile.json'))
def fresh(*paths,protected=()):
 ps=[safe(p)for p in paths];need(len(set(ps))==len(ps),'distinct output paths required');roots=[safe(p)for p in protected]
 for p in ps:
  need(not os.path.lexists(p)and p.parent.is_dir(),'fresh output required')
  for q in ps+roots:
   if p!=q:need(not p.is_relative_to(q)and not q.is_relative_to(p),'disjoint outputs/inputs required')
 return ps
