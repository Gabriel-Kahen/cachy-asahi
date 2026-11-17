# SPDX-License-Identifier: MIT
"""Read only the three stat-selected public inodes; never inventory or payload."""
import base64,hashlib,importlib.util,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
PIN=dict(bytes=13913,sha256='8fb8c2c32dc5a40998bf31cc5727768f88ce51e423b7090cfb702116bdc9b5d3')
PATHS=('etc/ld.so.cache','var/cache/ldconfig','var/cache/ldconfig/aux-cache')
FIELDS=('type','mode','uid','gid','inode','links','size','mtime','mtime_ns','atime','atime_ns')
def need(ok,why):
 if not ok:raise ValueError(why)
def digest(b):return hashlib.sha256(b).hexdigest()
def attrs(values):
 need(type(values)is dict and len(values)<=64,'bounded selected public xattr map')
 rows=[]
 for name,value in values.items():
  need(type(name)is str and len(name.encode())<=255 and type(value)is str,'bounded decoded xattr')
  body=base64.b64decode(value,validate=True);need(len(body)<=4096,'bounded inode/block xattr value')
  rows.append(dict(name_sha256=digest(name.encode()),value_bytes=len(body),value_sha256=digest(body)))
 return dict(count=len(rows),entries=sorted(rows,key=lambda row:row['name_sha256']))
def observe(path,rows,deadline):
 need(type(rows)is dict and set(rows)==set(PATHS),'only three exact public inode selections')
 selected=[v['inode']for v in rows.values()if v is not None];need(len(selected)==len(set(selected)),'no aliases among selected public inodes')
 raw=(HERE/'ext4_readback.py').read_bytes();need(dict(bytes=len(raw),sha256=digest(raw))==PIN,'whole frozen Source65 independent inode reader')
 s=importlib.util.spec_from_file_location('frozen_public_inode_reader',HERE/'ext4_readback.py');F=importlib.util.module_from_spec(s);s.loader.exec_module(F)
 class Reader(F.Ext4Reader):
  remaining=65536
  def read(self,offset,length):
   need(time.monotonic()<deadline and type(length)is int and 0<=length<=self.remaining,'finite selected-inode metadata read budget')
   self.remaining-=length;return super().read(offset,length)
  def inode(self,number):need(number in selected,'no unselected inode access');return super().inode(number)
  def inventory(self):raise ValueError('directory inventory forbidden')
  def chunks(self,*args):raise ValueError('file or directory payload forbidden in inode observer')
 result={}
 with Reader(path,max_nodes=3,max_file_bytes=1048576)as reader:
  for name,row in rows.items():
   if row is None:result[name]=None;continue
   actual,_=reader.inode(row['inode']);need(all(actual[k]==row[k]for k in FIELDS),'independent selected inode typed fields match literal debugfs stat')
   result[name]=dict(row,**{k:actual[k]for k in('ctime','ctime_ns','crtime','crtime_ns')},xattrs=attrs(actual['xattrs']))
 return result
