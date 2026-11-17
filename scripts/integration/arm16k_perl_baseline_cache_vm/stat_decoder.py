# SPDX-License-Identifier: MIT
# Narrow derivative of maintained metadata_raw_reader.py; parser only, no executor.
from datetime import datetime,timezone
import re,struct
STAT_CAP=16384
def need(ok,why):
 if not ok:raise ValueError(why)
def request(path):
 need(path in ('etc','etc/ld.so.cache'),'only fixed public cache and parent')
 return 'stat /'+path

FIELDS=('type','mode','uid','gid','inode','links','size','mtime','mtime_ns','atime','atime_ns')

BOUNDS=dict(mode=(0,0o7777),uid=(0,2**32-1),gid=(0,2**32-1),inode=(1,2**64-1),
            links=(1,2**32-1),size=(0,2**40-1),mtime=(-2**31,2**34-1),
            mtime_ns=(0,999999999),atime=(-2**31,2**34-1),atime_ns=(0,999999999))

BANNER=rb'debugfs [0-9]+\.[0-9]+\.[0-9]+ \([A-Za-z0-9 .-]{1,64}\)'

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
   need('header'not in seen and match[2]==('directory'if path=='etc'else'regular'),'ordinary public directory stat required');seen.add('header')
   row.update(type=('directory'if path=='etc'else'file'),inode=number(int(match[1]),'inode'),mode=number(int(match[3],8),'mode'));continue
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
