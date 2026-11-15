# SPDX-License-Identifier: MIT
"""Finite ordinary DATA reads; no producer, actor, package or archive code imports."""
import hashlib,json,os,re,stat,time
from pathlib import Path
MIB=1024**2

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def decode(b):
 def pairs(rows):
  d={}
  for k,v in rows:need(k not in d,'duplicate JSON key');d[k]=v
  return d
 return json.loads(b,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def relative(n):
 need(type(n)is str and re.fullmatch('[A-Za-z0-9._+/-]{1,260}',n)and all(p not in('','.','..')for p in n.split('/')),'ordinary relative DATA name');return n

def read(p,cap=16*MIB):
 p=Path(p);need(p.is_absolute()and p==p.resolve()and not any(q.is_symlink()for q in(p,*p.parents)),'ordinary absolute DATA path');fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded single-link DATA')
  with os.fdopen(os.dup(fd),'rb')as f:b=f.read(cap+1)
  key=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
  need(len(b)==a.st_size and key(a)==key(os.fstat(fd))==key(p.lstat()),'whole stable DATA file');return b
 finally:os.close(fd)
def descriptors(leaves):return {n:dict(**pin(b),mode=m)for n,(b,m)in leaves.items()}
def snapshot(root,maximum=320):
 root=Path(root);need(root.is_absolute()and root==root.resolve(),'absolute input root');files={};dirs=set();total=0;deadline=time.monotonic()+120
 for base,children,names in os.walk(root,followlinks=False):
  need(time.monotonic()<deadline,'finite DATA deadline')
  for n in children:
   p=Path(base)/n;need(not p.is_symlink(),'directory aliases refused');dirs.add(str(p.relative_to(root)));need(len(dirs)+len(files)<=1500,'finite Source node count')
  for n in names:
   p=Path(base)/n;name=relative(str(p.relative_to(root)));b=read(p,64*MIB);total+=len(b);files[name]=(b,stat.S_IMODE(p.stat().st_mode));need(len(files)<=maximum and total<=96*MIB,'finite full Source')
 need(dirs=={str(p)for n in files for p in Path(n).parents if str(p)!='.'},'empty/unaccounted directory refused');return files

def tree(leaves):
 nodes={}
 for n,row in leaves.items():
  node=nodes;parts=relative(n).split('/')
  for part in parts[:-1]:node=node.setdefault(part,{})
  need(parts[-1]not in node,'tree collision');node[parts[-1]]=row
 def oid(kind,b):return hashlib.sha1(kind+b' '+str(len(b)).encode()+b'\0'+b).digest()
 def visit(node):
  out=bytearray()
  for n,v in sorted(node.items(),key=lambda row:row[0].encode()+(b'/'if type(row[1])is dict else b'')):
   if type(v)is dict:mode,h=b'40000',visit(v)
   else:b,m=v;need(m in(0o644,0o755),'ordinary Source mode');mode,h=(b'100755'if m==0o755 else b'100644'),oid(b'blob',b)
   out.extend(mode+b' '+n.encode()+b'\0'+h)
  return oid(b'tree',out)
 return visit(nodes).hex()
