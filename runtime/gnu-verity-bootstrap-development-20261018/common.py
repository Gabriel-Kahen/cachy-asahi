"""Finite private GNU source-verity prototype; no existing route is activated."""
import hashlib,json,os,stat
from pathlib import Path
D=Path(__file__).resolve().parent
SOURCE='7d7ccbcb7b5a170999716ed640285806b7cab9bb'
PROFILE='GNU_GENERIC16K_IMMUTABLE_SOURCE_BOOTSTRAP_V1'
GIB=1024**3

def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def obj(raw):
 def pairs(rows):
  out={}
  for k,v in rows:need(k not in out,'duplicate JSON key');out[k]=v
  return out
 v=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'));need(type(v)is dict,'object required');return v
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def stable(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def ordinary(path,cap):
 p=Path(path);need(p.is_absolute()and not any(x.is_symlink()for x in(p,*p.parents)),'ordinary absolute input');fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=cap,'bounded single-link ordinary input');raw=os.read(fd,before.st_size+1);need(len(raw)==before.st_size and stable(before)==stable(os.fstat(fd))==stable(p.lstat()),'input drift');return raw
 finally:os.close(fd)
def source_inputs():
 rows=obj(ordinary(D/'input-pins.json',2*1024**2));root=D.parent
 for role in rows['roles'].values():
  base=root/role['root']
  if role['closed']:need({p.relative_to(base).as_posix()for p in base.rglob('*')if p.is_file()}==set(role['files']),'whole exact borrowed source closure')
  for n,p in role['files'].items():need(pin(ordinary(base/n,16*1024**2))==p,'trusted source drift: '+n)
 return rows
