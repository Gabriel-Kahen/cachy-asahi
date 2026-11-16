#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Fixed public-directory debugfs stat observations; no inventory or body reader.

The standalone caller binds its tool pin and immutable Source65 helper directory.
Only complete fixed-scope metadata is returned. No VM/Root acceptance is issued.
"""
from contextlib import contextmanager,ExitStack
from datetime import datetime,timezone
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import time
import types

PATHS=('root','etc','etc/audit','etc/udev','usr','usr/bin','usr/lib','usr/share',
       'var','var/cache','var/cache/ldconfig','var/lib','var/lib/pacman',
       'var/lib/pacman/local','var/log')
FIELDS=('type','mode','uid','gid','inode','links','size','mtime','mtime_ns','atime','atime_ns')
BOUNDS=dict(mode=(0,0o7777),uid=(0,2**32-1),gid=(0,2**32-1),inode=(1,2**64-1),
            links=(1,2**32-1),size=(0,2**40-1),mtime=(-2**31,2**34-1),
            mtime_ns=(0,999999999),atime=(-2**31,2**34-1),atime_ns=(0,999999999))
LEGACY_PINS={
 'contracts.py':(36158,'9152a9fad6b22b249c681c9e18fbdeed90664d98026110734492925ca1c02b28'),
 'runtime.py':(18202,'443f085b7d821478d0390ae8053e6d30629eeea655c88ed6b473b4cc1f12d395'),
 'frozen/owned_process.py':(25140,'83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f')}
STAT_CAP=16384
TOTAL_CAP=15*STAT_CAP
MAX_SECONDS=120
IDENTITY=('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')
BANNER=rb'debugfs [0-9]+\.[0-9]+\.[0-9]+ \([A-Za-z0-9 .-]{1,64}\)'


def need(ok,why):
 if not ok:raise ValueError(why)


def identity(info):return tuple(getattr(info,k)for k in IDENTITY)
def encoded(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin_shape(value):
 need(type(value)is dict and set(value)=={'bytes','sha256'}and type(value['bytes'])is int and 0<value['bytes']<=64*1024**2
      and type(value['sha256'])is str and re.fullmatch('[0-9a-f]{64}',value['sha256']),'exact public tool byte/hash selection');return value


def decoded(raw):
 def unique(rows):
  value={}
  for key,item in rows:need(key not in value,'duplicate public pin field');value[key]=item
  return value
 return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:need(False,'finite public JSON'))


class Budget:
 def __init__(self,deadline,guard):
  now=time.monotonic();need(type(deadline)in(int,float)and math.isfinite(deadline)and now+2<deadline<=now+MAX_SECONDS,'finite externally bounded read-only deadline')
  need(callable(guard),'explicit caller observation guard');self.end=deadline;self.guard=guard;self.bytes=0;self.calls=0
 def check(self):
  need(time.monotonic()<self.end,'read-only metadata deadline');self.guard()
 def charge(self,raw):
  need(type(raw)is bytes and 0<len(raw)<=STAT_CAP,'bounded stat frame');self.bytes+=len(raw)
  need(self.bytes<=TOTAL_CAP,'combined fixed metadata output bound');self.check()


@contextmanager
def held_regular(path,budget,maximum):
 """Source65 observer's nofollow/read-only binding; no raw image body hashing."""
 path=Path(path);need(path.is_absolute()and str(path)==os.path.normpath(str(path))and len(str(path))<=4096
      and len(path.parts)<=65 and not any(ord(c)<32 or ord(c)==127 for c in str(path)),'literal absolute input path')
 with ExitStack()as stack:
  parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);stack.callback(os.close,parent);ancestors=[]
  for name in path.parts[1:-1]:
   budget.check();fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);stack.callback(os.close,fd)
   ancestors.append((parent,name,os.fstat(fd)));parent=fd
  binding=os.open(path.name,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);stack.callback(os.close,binding);before=os.fstat(binding)
  need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=maximum,'bounded ordinary single-link input before read')
  fd=os.open('/proc/self/fd/'+str(binding),os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC);stack.callback(os.close,fd)
  need(identity(os.fstat(fd))==identity(before),'read-only descriptor identity')
  yield fd,before
  budget.check();need(identity(before)==identity(os.fstat(fd))==identity(os.fstat(binding))==identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False)),'input changed during metadata observation')
  for p,name,old in ancestors:
   now=os.stat(name,dir_fd=p,follow_symlinks=False)
   need((old.st_dev,old.st_ino,old.st_mode)==(now.st_dev,now.st_ino,now.st_mode),'input ancestor changed')


def hashed_code(fd,info,budget,expected):
 budget.check();need(info.st_size==expected[0]and stat.S_IMODE(info.st_mode)==0o644,'exact public helper size/mode')
 data=b''
 while block:=os.read(fd,65536):
  data+=block;need(len(data)<=expected[0],'bounded public helper');budget.check()
 need(len(data)==expected[0]and hashlib.sha256(data).hexdigest()==expected[1],'exact immutable Source65 helper')
 return data


def dependencies(legacy_root,budget,stack):
 root=Path(legacy_root);need(root.is_absolute(),'explicit immutable Source65 helper root');result={}
 for name,expected in LEGACY_PINS.items():
  path=root/name;fd,info=stack.enter_context(held_regular(path,budget,65536));raw=hashed_code(fd,info,budget,expected)
  module=types.ModuleType('fixed_metadata_'+name.replace('/','_'));module.__file__=str(path)
  exec(compile(raw,str(path),'exec'),module.__dict__);result[name]=module
 return result['runtime.py'],result['frozen/owned_process.py']


def request(path):
 need(type(path)is str and path in PATHS,'fixed public directory lookup only')
 return 'stat /'+path


def number(value,field):
 low,high=BOUNDS[field];need(type(value)is int and low<=value<=high,'bounded public directory metadata integer');return value


def ext4_time(low,extra,comment):
 # Same signed low-word plus epoch/nanosecond decoding as Source65's frozen
 # independent_readback.Ext4Reader.inode. No timestamp normalization/waiver.
 seconds=struct.unpack('<i',struct.pack('<I',int(low,16)))[0]+((int(extra or '0',16)&3)<<32)
 ns=int(extra or '0',16)>>2;number(seconds,'mtime');number(ns,'mtime_ns')
 date=datetime.fromtimestamp(seconds,timezone.utc)
 days=('Mon','Tue','Wed','Thu','Fri','Sat','Sun');months=('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec')
 expected=f'{days[date.weekday()]} {months[date.month-1]} {date.day:2d} {date.hour:02d}:{date.minute:02d}:{date.second:02d} {date.year:04d}'
 need(comment==expected,'debugfs numeric/calendar time mismatch');return seconds,ns


def parse_stat(raw,path):
 """One bounded diagnostic/stat frame, bound to one literal fixed request.

 Only recognized inode-metadata lines are admitted. Xattr values, symlink text,
 arbitrary diagnostics, duplicate fields and unknown frames refuse, without
 echoing their contents. No raw frame is included in returned observations.
 """
 request(path);need(type(raw)is bytes and 0<len(raw)<=STAT_CAP and raw.endswith(b'\n'),'bounded complete debugfs frame')
 need(not re.search(rb'[\x00-\x08\x0b-\x1f\x7f-\xff]',raw),'canonical ASCII metadata frame')
 lines=raw.decode('ascii').splitlines();need(lines and re.fullmatch(BANNER.decode(),lines[0]),'one exact debugfs diagnostic banner')
 missing='/'+path+': File not found by ext2_lookup'
 if len(lines)==2 and lines[1]in (missing,missing+' '):return None
 row={};seen=set();extent=False
 for line in lines[1:]:
  if not line:continue
  match=re.fullmatch(r'Inode: ([0-9]+)   Type: ([A-Za-z ]+)    Mode:  (0[0-7]{3,4})   Flags: 0x[0-9a-fA-F]+',line)
  if match:
   need('header'not in seen and match[2]=='directory','ordinary public directory stat required');seen.add('header')
   row.update(type='directory',inode=number(int(match[1]),'inode'),mode=number(int(match[3],8),'mode'));continue
  match=re.fullmatch(r'User:\s+([0-9]+)   Group:\s+([0-9]+)(?:\s+Project:\s+[0-9]+)?\s+Size: ([0-9]+)',line)
  if match:
   need('owner'not in seen,'duplicate directory owner/size');seen.add('owner')
   row.update(uid=number(int(match[1]),'uid'),gid=number(int(match[2]),'gid'),size=number(int(match[3]),'size'));continue
  match=re.fullmatch(r'Links: ([0-9]+)   Blockcount: [0-9]+',line)
  if match:
   need('links'not in seen,'duplicate directory links');seen.add('links');row['links']=number(int(match[1]),'links');continue
  match=re.fullmatch(r'\s?(ctime|atime|mtime|crtime): 0x([0-9a-fA-F]{8})(?::([0-9a-fA-F]{8}))? -- (.{1,64})',line)
  if match:
   field=match[1];need(field not in seen,'duplicate inode timestamp');seen.add(field)
   seconds,ns=ext4_time(match[2],match[3],match[4])
   if field in ('atime','mtime'):row[field]=seconds;row[field+'_ns']=ns
   continue
  if line=='EXTENTS:':need(not extent,'duplicate extent frame');extent=True;continue
  if extent and re.fullmatch(r'\((?:ETB[0-3]|[0-9]+(?:-[0-9]+)?)\):[0-9]+(?:-[0-9]+)?(?:, \((?:ETB[0-3]|[0-9]+(?:-[0-9]+)?)\):[0-9]+(?:-[0-9]+)?)*',line):continue
  patterns=(r'Generation: [0-9]+    Version: 0x[0-9a-fA-F]+(?::[0-9a-fA-F]+)?',r'File ACL: [0-9]+',
            r'Fragment:  Address: [0-9]+    Number: [0-9]+    Size: [0-9]+',r'Size of extra inode fields: [0-9]+',r'Inode checksum: 0x[0-9a-fA-F]+')
  known=next((i for i,p in enumerate(patterns)if re.fullmatch(p,line)),None)
  need(known is not None and ('extra'+str(known))not in seen,'unexpected or repeated debugfs metadata frame')
  seen.add('extra'+str(known))
 need({'header','owner','links','atime','mtime'}<=seen and set(row)==set(FIELDS),'complete exact eleven-field directory observation')
 return {field:row[field]for field in FIELDS}


def observe_with(call,budget):
 """Fixed lookup orchestration; call returns naturally retired debugfs bytes."""
 nodes={};inodes=set()
 for path in PATHS:
  budget.check();parent=path.rpartition('/')[0]
  need(not parent or parent in nodes,'literal ordinary parent must be observed before child/absence')
  raw=call(path);budget.charge(raw);row=parse_stat(raw,path)
  if row is not None:
   need(row['inode']not in inodes,'selected public directories cannot alias or cycle');inodes.add(row['inode']);nodes[path]=row
 return dict(observed_paths=list(PATHS),nodes=nodes)


def fixed_tool_path():return Path('/usr/bin/debugfs').resolve(strict=True)


def observe(raw_path,debugfs_pin,deadline,*,legacy_root,guard):
 """Read-only fifteen stat calls. Caller owns image/phase/tool authorization."""
 pin_shape(debugfs_pin);budget=Budget(deadline,guard)
 with ExitStack()as stack:
  R,O=dependencies(legacy_root,budget,stack)
  raw_fd,raw_info=stack.enter_context(held_regular(raw_path,budget,4*1024**3));need(raw_info.st_size>=4096,'bounded raw filesystem input')
  tool_path=fixed_tool_path()
  tool_fd,tool_info=stack.enter_context(held_regular(tool_path,budget,64*1024**2));R.image_tool_metadata('/usr/bin/debugfs',tool_info)
  digest=hashlib.sha256();size=0
  while block:=os.read(tool_fd,65536):digest.update(block);size+=len(block);budget.check()
  need(dict(bytes=size,sha256=digest.hexdigest())==debugfs_pin,'actual selected debugfs tool bytes')
  def call(path):
   budget.check();need(budget.calls<len(PATHS),'fixed fifteen-call bound');budget.calls+=1
   need(identity(os.fstat(tool_fd))==identity(tool_info)and identity(os.fstat(raw_fd))==identity(raw_info)and fixed_tool_path()==tool_path,'held input/tool identity before stat')
   argv=['/usr/bin/debugfs','-R',request(path),'/proc/self/fd/'+str(raw_fd)]
   O.prepare();started=time.monotonic()
   child=subprocess.Popen(argv,executable='/proc/self/fd/'+str(tool_fd),pass_fds=(raw_fd,tool_fd),stdin=subprocess.DEVNULL,
      stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True,cwd='/',env={'PATH':'/usr/bin:/bin','LC_ALL':'C','TZ':'UTC'})
   left=min(5,budget.end-started)-(time.monotonic()-started)
   result=O.supervise(child,cap=max(.6,left),retirement=.5,grace=.1,max_output=STAT_CAP)
   raw=result.pop('output');need(left>1 and R.natural(result),'natural complete held metadata command required');budget.check()
   return raw
  value=observe_with(call,budget);need(budget.calls==15 and fixed_tool_path()==tool_path,'complete actual fixed lookup coverage and tool alias binding');return value


def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--raw',type=Path,required=True)
 parser.add_argument('--legacy-root',type=Path,required=True);parser.add_argument('--debugfs-pin-json',required=True)
 parser.add_argument('--deadline-monotonic',type=float,required=True);args=parser.parse_args()
 try:value=observe(args.raw,decoded(args.debugfs_pin_json),args.deadline_monotonic,legacy_root=args.legacy_root,guard=lambda:None)
 except BaseException:raise SystemExit(2)from None
 sys.stdout.buffer.write(encoded(value))


if __name__=='__main__':main()
