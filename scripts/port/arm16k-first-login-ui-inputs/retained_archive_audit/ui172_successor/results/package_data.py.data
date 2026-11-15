# SPDX-License-Identifier: MIT
"""Finite172 archive DATA reader; no extraction, imports or package execution."""
import hashlib,tarfile
from pathlib import Path,PurePosixPath
def package(path,elf):
 assert path.stat().st_size<=64*1024**2;metadata={};payload={};controls={};total=0
 with tarfile.open(path,'r|*')as archive:
  for count,m in enumerate(archive):
   name=m.name.removeprefix('./').rstrip('/')
   if name in ['','.']:continue
   p=PurePosixPath(name);assert not p.is_absolute()and '..'not in p.parts and not any(ord(c)<32 for c in name)and count<100000
   total+=m.size;assert total<=512*1024**2 and m.size<=256*1024**2 and m.sparse is None
   assert m.isfile()or m.isdir()or m.issym()or m.islnk()
   if name.startswith('.'):
    assert name not in controls and m.isfile()and m.size<=2*1024**2;raw=archive.extractfile(m).read();controls[name]={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
    if name=='.PKGINFO':
     for line in raw.decode().splitlines():
      if line and not line.startswith('#'):key,value=line.split(' = ',1);metadata.setdefault(key,[]).append(value)
    continue
   assert name not in payload;shape=None
   if m.isfile():
    raw=archive.extractfile(m).read();digest=hashlib.sha256(raw).hexdigest();shape=elf.parse_elf(raw)
    if shape is not None and shape['type']in [2,3]:
     assert shape['machine']==183 and shape['class']==64 and not shape['insufficient_declared_16K_alignment']and shape['static_16K_observation']=='load-congruence-observed','known non-ARM16K-loadable ELF shape'
   else:digest=None
   payload[name]={'type':m.type.decode(),'mode':m.mode,'uid':m.uid,'gid':m.gid,'bytes':m.size,'sha256':digest,'link':m.linkname}
 return {'metadata':metadata,'payload':payload,'controls':controls,'logical_bytes':total}
