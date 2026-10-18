"""Opt-in experimental immutable-source parent reader; current mutable route untouched.

Only a real privileged kernel DM-table query may prepare a context. Activation
requires permanent absence of SYS_ADMIN from the worker's capability bounding
set. A trusted bootstrap/operator remains in the TCB and must not rebind the DM
device; no untrusted privileged peer is allowed. JSON/readonly flags alone are
never accepted as evidence. This is not integrated into the GNU copier.
"""
import ctypes,fcntl,os,platform,re,stat
from contextlib import contextmanager
from pathlib import Path

FORBIDDEN=sum(1<<v for v in(8,16,17,19,21,22,27));ALLOWED=0x800400db

def need(ok,why):
 if not ok:raise ValueError(why)
def identity(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def relative(name):
 need(type(name)is str and 0<len(name.encode())<=4096 and not name.startswith('/')and all(p not in('','.','..')for p in name.split('/'))and '\0'not in name and len(name.split('/'))<=129,'canonical bounded relative path');return name

def status():
 raw=Path('/proc/self/status').read_text();need(len(raw)<=65536,'bounded process status');return dict(v.split(':',1)for v in raw.splitlines()if ':'in v)
def restricted(value):
 masks={k:int(value[k].strip(),16)for k in('CapEff','CapPrm','CapBnd','CapInh','CapAmb')}
 need(value['NoNewPrivs'].strip()=='1'and not any(v&FORBIDDEN or v&~ALLOWED for v in masks.values())and masks['CapInh']==masks['CapAmb']==0,'permanent no-admin bounded worker authority required');return masks

def mount_id(fd):
 raw=Path('/proc/self/fdinfo/%d'%fd).read_bytes();need(len(raw)<=65536,'bounded fdinfo');rows=[v.split(b':',1)[1].strip()for v in raw.splitlines()if v.startswith(b'mnt_id:')];need(len(rows)==1 and rows[0].isdigit(),'one exact fresh mount identity');return int(rows[0])

def mount_table():
 with open('/proc/self/mountinfo','rb')as stream:raw=stream.read(4*1024**2+1)
 need(len(raw)<=4*1024**2 and len(raw.splitlines())<=32768,'bounded actual mount inventory');return raw

def source_mount(raw,fd,root):
 selected=[];wanted_mount=mount_id(fd)
 for line in raw.splitlines():
  fields=line.split()
  if fields and fields[0]==str(wanted_mount).encode():selected.append(fields)
 need(len(selected)==1,'one root mount');row=selected[0];need(row.count(b'-')==1,'canonical root mount fields');at=row.index(b'-')
 need(len(row)==at+4 and row[4]==os.fsencode(root)and row[at+1]==b'ext4'and b'ro'in row[5].split(b',')and b'ro'in row[at+3].split(b','),'whole read-only ext4 superblock required; RO bind is insufficient')
 need(os.fstatvfs(fd).f_flag&os.ST_RDONLY,'fresh readonly filesystem flag');return mount_id(fd)

class How(ctypes.Structure):_fields_=[('flags',ctypes.c_uint64),('mode',ctypes.c_uint64),('resolve',ctypes.c_uint64)]
def open_beneath(root,name):
 need(platform.machine()in('aarch64','x86_64')and ctypes.sizeof(How)==24,'reviewed Linux openat2 ABI');need(name=='.'or relative(name),'contained directory')
 call=ctypes.CDLL(None,use_errno=True).syscall;call.restype=ctypes.c_long;how=How(os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,0,0x0f)
 fd=call(ctypes.c_long(437),ctypes.c_int(root),ctypes.c_char_p(os.fsencode(name)),ctypes.byref(how),ctypes.c_size_t(24))
 if fd<0:raise OSError(ctypes.get_errno(),'kernel constrained parent lookup refused')
 return fd

class Header(ctypes.Structure):
 _fields_=[('version',ctypes.c_uint32*3),('data_size',ctypes.c_uint32),('data_start',ctypes.c_uint32),('target_count',ctypes.c_uint32),('open_count',ctypes.c_int32),('flags',ctypes.c_uint32),('event_nr',ctypes.c_uint32),('padding',ctypes.c_uint32),('dev',ctypes.c_uint64),('name',ctypes.c_char*128),('uuid',ctypes.c_char*129),('data',ctypes.c_char*7)]
class Target(ctypes.Structure):_fields_=[('start',ctypes.c_uint64),('length',ctypes.c_uint64),('status',ctypes.c_int32),('next',ctypes.c_uint32),('type',ctypes.c_char*16)]

def kernel_table(device):
 need(ctypes.sizeof(Header)==312 and ctypes.sizeof(Target)==40,'exact DM ioctl ABI');raw=bytearray(65536);header=Header.from_buffer(raw);header.version[:]=(4,0,0);header.data_size=len(raw);header.data_start=312;header.flags=1<<4;header.dev=device
 fd=os.open('/dev/mapper/control',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  info=os.fstat(fd);need(stat.S_ISCHR(info.st_mode)and(os.major(info.st_rdev),os.minor(info.st_rdev))==(10,236),'actual kernel DM control')
  fcntl.ioctl(fd,(3<<30)|(312<<16)|(0xfd<<8)|12,raw,True)
 finally:os.close(fd)
 need(header.dev==device and header.version[0]==4 and header.target_count==1 and header.flags&1 and header.flags&(1<<5)and not header.flags&((1<<8)|(1<<1)),'one active readonly unsuspended complete DM table')
 need(312<=header.data_start<=header.data_size-40<=len(raw)-40,'bounded DM data offsets');target=Target.from_buffer(raw,header.data_start);need(bytes(target.type)==b'verity'and target.start==0 and target.status==0,'only verity target')
 params=bytes(raw[header.data_start+40:header.data_size]).split(b'\0',1)[0];need(len(params)<=4096,'bounded table parameters');return target.length,params.decode('ascii')

def validate_table(length,params,wanted):
 need(type(wanted)is dict and type(wanted.get('data_blocks'))is int and 2<=wanted['data_blocks']<=4*1024**2,'bounded whole image blocks')
 fields=params.split();need(len(fields)in(10,11)and(len(fields)==10 or fields[-1]=='0'),'no optional corruption/cache bypass flags')
 need(fields[0]=='1'and fields[3:5]==['4096','4096']and fields[7]=='sha256'and fields[6]=='0','fixed full verity1/SHA256 layout')
 need(all(re.fullmatch('[0-9]+:[0-9]+',v)for v in fields[1:3])and fields[5].isdigit(),'kernel data/hash devices and count')
 need(int(fields[5])==wanted['data_blocks']and length==wanted['data_blocks']*8 and fields[8]==wanted['root_hash']and fields[9]==wanted['salt'],'exact source-owned verity digest/salt/whole size')
 need(re.fullmatch('[0-9a-f]{64}',fields[8])and re.fullmatch('[0-9a-f]{64}',fields[9]),'bounded SHA256 operands')
 return dict(data_device=fields[1],hash_device=fields[2],data_blocks=int(fields[5]),root_hash=fields[8],salt=fields[9])

@contextmanager
def lookup_parent(root,path,mount,limits,expected):
 # Kernel lookup primitive only: NOT an immutable context/activation API.
 relative(path);limits.tick();parts=path.split('/');parent='/'.join(parts[:-1])or'.';fd=open_beneath(root,parent)
 try:
  before=identity(os.fstat(fd));need(mount_id(fd)==mount,'fresh source mount crossing')
  if parent!='.':need(expected.get(parent,{}).get('type')=='directory'and(before[2]&0o7777,before[3],before[4])==(expected[parent]['mode'],expected[parent]['uid'],expected[parent]['gid']),'source parent metadata differs')
  yield fd,parts[-1]
  limits.tick();again=open_beneath(root,parent)
  try:need(identity(os.fstat(fd))==before==identity(os.fstat(again))and mount_id(again)==mount,'source parent rebound')
  finally:os.close(again)
 finally:os.close(fd)

class Prepared:
 """Must be constructed BEFORE cap drop, from live kernel state, not DATA flags."""
 def __init__(self,root,wanted):
  spelling=os.fspath(root);root=Path(root);need(root.as_posix()==spelling and root.is_absolute()and str(root)!='/'and all(not p.is_symlink()for p in(root,*root.parents))and '..'not in root.parts,'ordinary dedicated source root')
  self.root=root;self.fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);self.active=False;self.closed=False
  try:
   self.root_identity=identity(os.fstat(self.fd));self.mounts=mount_table();self.mount=source_mount(self.mounts,self.fd,root)
   length,params=kernel_table(os.fstat(self.fd).st_dev);self.verity=validate_table(length,params,wanted)
  except BaseException:os.close(self.fd);self.closed=True;raise
 def activate(self):
  need(not self.closed and not self.active,'one fresh prepared context');restricted(status());need(mount_table()==self.mounts and identity(os.fstat(self.fd))==self.root_identity,'source root/table setup drift');self.active=True;return self
 def check(self):
  need(self.active and not self.closed,'genuine activated immutable source required');restricted(status());need(mount_table()==self.mounts and identity(os.fstat(self.fd))==self.root_identity,'whole source root/mount drift')
 @contextmanager
 def parent(self,path,limits,expected):
  need(self.active and not self.closed,'immutable prerequisite required; no mutable fallback')
  with lookup_parent(self.fd,path,self.mount,limits,expected)as value:yield value
 def close(self):
  if not self.closed:os.close(self.fd);self.closed=True;self.active=False
