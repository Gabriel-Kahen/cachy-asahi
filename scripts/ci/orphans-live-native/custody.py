# SPDX-License-Identifier: MIT
"""Pure closed-source Git object hashing; never invokes Git or grants authority."""
import hashlib,json,stat
from pathlib import Path

def need(value,reason):
 if not value:raise ValueError(reason)
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def oid(kind,raw):return hashlib.sha1(kind+b' '+str(len(raw)).encode()+b'\0'+raw).digest()
def state(root,names):
 root=Path(root);files={};tree={}
 for name in sorted(names):
  relative=Path(name);need(not relative.is_absolute() and '..' not in relative.parts and str(relative)==name,'ordinary closed source name required')
  path=root/relative;s=path.lstat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and not any(p.is_symlink() for p in (path,*path.parents)) and stat.S_IMODE(s.st_mode) in (0o644,0o755),'ordinary source mode required')
  raw=path.read_bytes();need(len(raw)==s.st_size,'stable source length required');after=path.lstat();need(all(getattr(s,k)==getattr(after,k) for k in ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')),'source changed while hashing')
  mode='100755' if s.st_mode&0o111 else '100644';files[name]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),mode=mode)
  parent=tree
  for part in relative.parts[:-1]:parent=parent.setdefault(part,{})
  need(relative.name not in parent,'duplicate source path');parent[relative.name]=(mode,oid(b'blob',raw))
 def finish(directory):
  raw=b''
  for name,value in sorted(directory.items(),key=lambda row:(row[0]+('/' if isinstance(row[1],dict) else '')).encode()):
   mode,data=('40000',finish(value)) if isinstance(value,dict) else value
   raw+=mode.encode()+b' '+name.encode()+b'\0'+data
  return oid(b'tree',raw)
 modes={n:r['mode'] for n,r in files.items()};summary=dict(tree=finish(tree).hex(),files=len(files),source_map_sha256=hashlib.sha256(encoded(files)).hexdigest())
 return files,modes,summary
