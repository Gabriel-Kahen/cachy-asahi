# SPDX-License-Identifier: MIT
"""Closed source/DATA reads and fixed latest-tools607 selection, no actors."""
import hashlib,importlib.util,json,os,stat,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent
CASES=('normal','precommit-exit86','postcommit-exit87')
def need(ok,why):
 if not ok:raise ValueError(why)
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def safe(p):
 p=Path(p).absolute();need(p==p.resolve()and not any(q.is_symlink()for q in(p,*p.parents)),'canonical ordinary path');return p
def read(p,cap=16*1024**2):
 p=safe(p);fd=os.open(p,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded ordinary singlelink file');out=bytearray()
  while b:=os.read(fd,1024**2):out.extend(b);need(len(out)<=a.st_size,'bounded stable read')
  ident=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns);need(len(out)==a.st_size and ident(a)==ident(os.fstat(fd))==ident(p.lstat()),'whole descriptor/path identity');return bytes(out)
 finally:os.close(fd)
def checked(p,row):
 b=read(p,max(16*1024**2,row['bytes']));need(pin(b)==row,'exact source/DATA pin '+str(p));return b
def rows(root):
 root=safe(root);out={}
 for p in root.rglob('*'):
  n=p.relative_to(root).as_posix()
  if n.split('/')[0]=='.git':continue
  need(not p.is_symlink()and(p.is_file()or p.is_dir()),'ordinary closed namespace')
  if p.is_file():out[n]=pin(read(p,512*1024**2))
 return out
def profile():return json.loads(read(HERE/'profile.json'))
def locks():
 p=profile();raws=[checked(HERE/n,p[k])for n,k in(('before607.lock','before'),('after607.lock','after'))];values=[]
 for raw in raws:
  pairs=[line.split()for line in raw.decode('ascii').splitlines()];need(len(pairs)==607 and all(len(r)==2 for r in pairs)and len(dict(pairs))==607,'complete distinct607 records');values.append(dict(pairs))
 a,b=values;need(a['cachy-asahi-apps']=='0.1.0-6'and b==dict(a,**{'cachy-asahi-apps':'0.1.0-16'})and a['cachy-asahi-setup']=='0.1.0-6'and a['cachy-asahi-repository-runtime']=='0.1.0-1','ONLY Apps6 to accepted16; all other606 held');return a,b

def load(name,path,aliases=None):
 missing=object();old={k:sys.modules.get(k,missing)for k in(aliases or{})}
 try:
  sys.modules.update(aliases or{});s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
 finally:
  for k,v in old.items():
   if v is missing:sys.modules.pop(k,None)
   else:sys.modules[k]=v
