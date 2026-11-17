# SPDX-License-Identifier: MIT
"""Finite public failure facts only; never serialize exception text or xattrs."""
import hashlib,json,os,re,stat,struct
from datetime import datetime,timezone
STAGES=('START','REQUEST','TOOLS','OUTPUT','PLAN','SPAWN','RETIRE','FRAME','NORMALIZE','PARSE_STAT','XATTR_DISPLAY_COUNT','STAT_LINKS','STAT_REPEAT','INODE_READ','INODE_TYPED_COMPARE','INODE_XATTR_HASH','INODE_XATTR_COUNT','INODE_REPEAT','WRITE_COMMAND_FACT','BODY_PIN','BASELINE_COMPARE','TEMP_REMOVE','CONSOLIDATE','SUMMARY','COMPLETE')
FIELDS=('type','mode','uid','gid','inode','links','size','mtime','mtime_ns','atime','atime_ns')
BOUNDS=dict(mode=(0,0o7777),uid=(0,2**32-1),gid=(0,2**32-1),inode=(1,2**64-1),links=(1,2**32-1),size=(0,2**40-1),mtime=(-2**31,2**34-1),mtime_ns=(0,999999999),atime=(-2**31,2**34-1),atime_ns=(0,999999999))
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def exception(error):
 name=type(error).__name__
 category=name if name in('ValueError','ReadbackError','TimeoutError','AssertionError','TypeError','KeyError','UnicodeDecodeError','JSONDecodeError','FileNotFoundError','PermissionError','OSError')else'OTHER_EXCEPTION'
 raw=str(error).encode('utf-8','backslashreplace');return dict(type=category,message_prefix=pin(raw[:4096]),message_truncated=len(raw)>4096)
def fields(row):
 result={};valid={}
 for key in FIELDS:
  value=row.get(key);ok=value in('file','directory','symlink')if key=='type'else type(value)is int and BOUNDS[key][0]<=value<=BOUNDS[key][1]
  valid[key]=ok;result[key]=value if ok else None
 return dict(values=result,valid=valid)
def projection(raw):
 """Numeric/enum candidates only. An xattr section is entirely masked."""
 need(type(raw)is bytes and len(raw)<=16384,'bounded public frame projection')
 result=dict(frame=pin(raw),complete_newline=raw.endswith(b'\n'),ascii_only=not bool(re.search(rb'[\x00-\x08\x0b-\x1f\x7f-\xff]',raw)),banner_count=0,unknown_lines=0,xattr_lines_masked=0,candidates={},time_facts={})
 attrs=False
 for line in raw.splitlines():
  if line==b'Extended attributes:':attrs=True;continue
  if attrs:
   if line==b'EXTENTS:':attrs=False
   else:result['xattr_lines_masked']+=1;continue
  if re.fullmatch(rb'debugfs [0-9]+\.[0-9]+\.[0-9]+ \([A-Za-z0-9 .-]{1,64}\)',line):result['banner_count']+=1;continue
  m=re.fullmatch(rb'Inode: ([0-9]{1,20})   Type: ([A-Za-z ]{1,32})    Mode:  (0[0-7]{3,4})   Flags: 0x[0-9a-fA-F]{1,16}',line)
  if m:
   kind={b'regular':'file',b'directory':'directory',b'symlink':'symlink'}.get(m[2],'OTHER_TYPE');result['candidates'].update(inode=int(m[1]),type=kind,mode=int(m[3],8));continue
  m=re.fullmatch(rb'User:\s+([0-9]{1,10})   Group:\s+([0-9]{1,10})(?:\s+Project:\s+[0-9]{1,10})?\s+Size: ([0-9]{1,20})',line)
  if m:result['candidates'].update(uid=int(m[1]),gid=int(m[2]),size=int(m[3]));continue
  m=re.fullmatch(rb'Links: ([0-9]{1,10})   Blockcount: [0-9]{1,20}',line)
  if m:result['candidates']['links']=int(m[1]);continue
  m=re.fullmatch(rb'\s?(ctime|atime|mtime|crtime): 0x([0-9a-fA-F]{8})(?::([0-9a-fA-F]{8}))? -- (.{1,64})',line)
  if m:
   name=m[1].decode();extra=int(m[3]or b'0',16);seconds=struct.unpack('<i',struct.pack('<I',int(m[2],16)))[0]+((extra&3)<<32);ns=extra>>2
   date=datetime.fromtimestamp(seconds,timezone.utc);days=('Mon','Tue','Wed','Thu','Fri','Sat','Sun');months=('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec');expected=f'{days[date.weekday()]} {months[date.month-1]} {date.day:2d} {date.hour:02d}:{date.minute:02d}:{date.second:02d} {date.year:04d}'.encode()
   result['time_facts'][name]=dict(seconds=seconds,nanoseconds=ns if ns<=999999999 else None,nanoseconds_valid=ns<=999999999,calendar_equal=m[4]==expected)
   if name in('atime','mtime'):result['candidates'][name]=seconds;result['candidates'][name+'_ns']=ns
   continue
  result['unknown_lines']+=1
 # Out-of-bound/unknown type candidates never escape as arbitrary values.
 result['candidates']=fields(result['candidates']);return result
class State:
 def __init__(self,out,labels):
  self.out=out;self.labels=tuple(labels);self.fd=None;self.value=dict(kind='FINITE_PUBLIC_CACHE_OBSERVER_DIAGNOSTIC_V2',stage=0,command=None,inode=None,outcome='IN_PROGRESS',frame=None,projection=None,typed_comparisons={},xattr_count_comparisons=None,fault=None,Root_acceptance=None,lifecycle_acceptance=None,VM=None,M2=None,release=None)
 def persist(self):
  if self.fd is None:
   root=self.out/'scan'
   if not root.exists():root.mkdir(mode=0o700)
   st=root.lstat();need(not root.is_symlink()and root.is_dir()and st.st_uid==os.geteuid()and stat.S_IMODE(st.st_mode)==0o700,'ordinary owned diagnostic directory')
   self.path=root/'diagnostic.DATA.json';self.fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
  raw=(json.dumps(self.value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode();need(len(raw)<=16384,'bounded fixed diagnostic')
  before=os.fstat(self.fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_uid==os.geteuid()and stat.S_IMODE(before.st_mode)==0o600 and(before.st_dev,before.st_ino)==(self.path.lstat().st_dev,self.path.lstat().st_ino),'same private owned diagnostic FD')
  os.lseek(self.fd,0,os.SEEK_SET);os.ftruncate(self.fd,0)
  while raw:
   n=os.write(self.fd,raw);need(n>0,'complete finite diagnostic write');raw=raw[n:]
  os.fsync(self.fd)
 def stage(self,name,label=None,inode=None,write=True):
  need(name in STAGES and(label is None or label in self.labels)and(inode is None or type(inode)is int and 0<=inode<3),'fixed stage/command/inode ordinals only')
  self.value.update(stage=STAGES.index(name),command=self.labels.index(label)if label is not None else self.value['command'],inode=inode)
  if write:self.persist()
 def frame(self,raw):self.value.update(frame=pin(raw),projection=projection(raw));self.persist()
 def typed(self,index,actual,expected):
  need(type(index)is int and 0<=index<3,'fixed public inode ordinal');self.value['typed_comparisons'][str(index)]=dict(command=self.value['command'],present=True,actual=fields(actual),expected=fields(expected),equal_bits={k:actual.get(k)==expected.get(k)for k in FIELDS});self.persist()
 def absent(self,index):
  need(type(index)is int and 0<=index<3,'fixed public inode ordinal');self.value['typed_comparisons'][str(index)]=dict(command=self.value['command'],present=False,actual=None,expected=None,equal_bits=None);self.persist()
 def counts(self,values):
  need(type(values)is list and len(values)==3,'three fixed xattr count facts')
  for row in values:
   need(type(row)is dict and set(row)=={'present','expected','actual','equal'}and type(row['present'])is bool and type(row['expected'])is int and 0<=row['expected']<=64,'closed public count facts')
   need(type(row['actual'])is int and 0<=row['actual']<=64 and type(row['equal'])is bool if row['present']else row['actual']is row['equal']is None,'bounded public count/equality facts')
  self.value['xattr_count_comparisons']=values;self.persist()
 def fail(self,error):self.value.update(outcome='REFUSED_UNCHANGED_PREDICATE',fault=exception(error));self.persist()
 def summary_pending(self):self.value.update(stage=STAGES.index('SUMMARY'),outcome='PREDICATES_CHECK_PENDING');self.persist()
 def complete(self):self.value.update(stage=STAGES.index('COMPLETE'),outcome='COMPLETED_PREDICATES',fault=None);self.persist()
 def close(self):
  if self.fd is not None:os.close(self.fd);self.fd=None
