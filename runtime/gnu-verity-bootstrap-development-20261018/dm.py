"""Exact Linux DM ioctls; mutation callable ONLY from reviewed guest PID1."""
import ctypes,fcntl,os,platform,stat
from pathlib import Path
from common import need
from borrowed.reader import Header,Target,validate_table,kernel_table
READONLY=1;BUFFER_FULL=1<<8
BLKROGET=0x125e;BLKGETSIZE64=(2<<30)|(8<<16)|(0x12<<8)|114
NAME='gnu-source-verity'

def pid1():
 need(os.getpid()==1 and os.getuid()==os.geteuid()==0 and platform.machine()=='aarch64'and os.sysconf('SC_PAGE_SIZE')==16384,'dedicated real16K guest PID1 only')
 with Path('/proc/cmdline').open('r')as stream:raw=stream.read(65537)
 need(len(raw)<=65536 and raw.split().count('caa_gnu_verity_bootstrap=1')==1,'one bounded original boot marker')
def number(command):
 need(ctypes.sizeof(Header)==312 and ctypes.sizeof(Target)==40 and command in(3,4,6,7,9,12),'reviewed Linux DM ioctl ABI');return(3<<30)|(312<<16)|(0xfd<<8)|command

def block(path,size,readonly):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);need(stat.S_ISBLK(s.st_mode),'actual block device required');raw=bytearray(8);fcntl.ioctl(fd,BLKGETSIZE64,raw,True);ro=bytearray(4);fcntl.ioctl(fd,BLKROGET,ro,True)
  need(int.from_bytes(raw,'little')==size and int.from_bytes(ro,'little')==int(readonly),'exact actual block size/access required');return s.st_rdev
 finally:os.close(fd)

class Device:
 def __init__(self,nonce):
  pid1();need(len(nonce)==32 and all(c in'0123456789abcdef'for c in nonce),'owned device nonce');self.name=NAME;self.uuid='CAA-GNU-VERITY-'+nonce;self.dev=None;self.created=False
 def request(self,cmd,*,payload=b'',count=0,flags=READONLY):
  pid1();raw=bytearray(312+len(payload));h=Header.from_buffer(raw);h.version[:]=(4,0,0);h.data_size=len(raw);h.data_start=312;h.target_count=count;h.flags=flags;h.name=self.name.encode();h.uuid=self.uuid.encode()
  if self.dev is not None:h.dev=self.dev
  raw[312:]=payload;fd=os.open('/dev/mapper/control',os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   info=os.fstat(fd);need(stat.S_ISCHR(info.st_mode)and info.st_rdev==os.makedev(10,236),'actual DM control node');fcntl.ioctl(fd,number(cmd),raw,True)
  finally:os.close(fd)
  need(h.version[0]==4 and not h.flags&BUFFER_FULL,'complete DM response');return h.dev
 def create(self,wanted,data,hashdev):
  need(not self.created,'one owned DM target');self.dev=self.request(3);self.created=True
  fields=f'1 {os.major(data)}:{os.minor(data)} {os.major(hashdev)}:{os.minor(hashdev)} 4096 4096 {wanted["data_blocks"]} 0 sha256 {wanted["root_hash"]} {wanted["salt"]}'
  validate_table(wanted['data_blocks']*8,fields,wanted);params=fields.encode()+b'\0';length=(40+len(params)+7)//8*8;buf=bytearray(length);t=Target.from_buffer(buf);t.start=0;t.length=wanted['data_blocks']*8;t.next=0;t.type=b'verity';buf[40:40+len(params)]=params
  self.request(9,payload=bytes(buf),count=1);self.request(6)
  sectors,actual=kernel_table(self.dev);v=validate_table(sectors,actual,wanted)
  need(v['data_device']==f'{os.major(data)}:{os.minor(data)}'and v['hash_device']==f'{os.major(hashdev)}:{os.minor(hashdev)}','exact selected backing devices, not foreign target');return self.dev
 def remove(self):
  need(self.created,'only owned created mapping removed');self.request(4);self.created=False
