"""PID1-only full cold index and fresh retained-control verity checks."""
import ctypes,fcntl,importlib.util,os,platform,re,stat,sys
from pathlib import Path
import protocol as P
D=Path(__file__).resolve().parent

def pid1():
 P.need(os.getpid()==1 and os.getuid()==os.geteuid()==0 and platform.machine()=='aarch64'and os.sysconf('SC_PAGE_SIZE')==16384,'dedicated real16K aarch64 root PID1 only')
 libc=ctypes.CDLL(None,use_errno=True);P.need(libc.prctl(4,0,0,0,0)==0 and libc.prctl(3,0,0,0,0)==0,'PID1 dumpable must be zero')
def trusted(relative):
 pins=P.decode((D/'input-pins.json').read_bytes());row=pins[relative];path=D.parent/relative
 raw=path.read_bytes();P.need(P.pin(raw)==row,'whole trusted source drift: '+relative);return path,raw

def source_api():
 # Explicit pinned import seam; source_snapshot's original functions are held.
 trusted('gnu-verity-bootstrap-development-20261018/input-pins.json')
 path,raw=trusted('gnu-verity-bootstrap-development-20261018/common.py');name='_gnu_broker_original_common';spec=importlib.util.spec_from_file_location(name,path);C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)
 path,raw=trusted('gnu-verity-bootstrap-development-20261018/source_snapshot.py');anchor=b'import common as C\n';P.need(raw.count(anchor)==1,'one explicit common import seam');space={'__name__':'_gnu_broker_original_snapshot','C':C};exec(compile(raw.replace(anchor,b''),str(path),'exec'),space)
 return space,space['api']()

def reader():
 path,raw=trusted('gnu-immutable-source-reader-development-20261018/reader.py');spec=importlib.util.spec_from_file_location('_gnu_broker_original_reader',path);R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R);return R

def selection(value):
 P.need(type(value)is dict and set(value)=={'purpose','nonce','source_authority','kernel_authority','producer_retirement','native_readback','verity'},'finite source-owned selection')
 P.need(value['purpose']==P.PURPOSE and re.fullmatch('[a-f0-9]{32}',value.get('nonce')or''),'purpose/nonce required')
 for n in('source_authority','kernel_authority','producer_retirement','native_readback'):
  v=value[n];P.need(type(v)is dict and set(v)=={'bytes','sha256'}and type(v['bytes'])is int and 0<v['bytes']<=256*1024**2 and type(v['sha256'])is str and re.fullmatch('[a-f0-9]{64}',v['sha256']),'NULL upstream authority: '+n)
 bound=P.decode((D/'input-pins.json').read_bytes()).get('accepted_authorities')
 P.need(type(bound)is dict and bound=={n:value[n]for n in('source_authority','kernel_authority','producer_retirement','native_readback')},'upstream source-owned authority selection UNSUPPLIED; no device access')
 w=value['verity'];P.need(type(w)is dict and set(w)=={'data_blocks','root_hash','salt','data_device','hash_device'}and type(w['data_blocks'])is int and 2<=w['data_blocks']<=4*1024**2,'full verity descriptor')
 for n in('root_hash','salt'):P.need(type(w[n])is str and re.fullmatch('[a-f0-9]{64}',w[n]),'SHA256 verity operand')
 for n in('data_device','hash_device'):P.need(type(w[n])is str and re.fullmatch('[0-9]+:[0-9]+',w[n]),'kernel backing device')
 P.need(w['data_device']!=w['hash_device'],'distinct backing devices');return value

def authority_inputs(value):
 # Private source-owned binding is necessary but not an exported authority.
 # Root must supply the exact accepted documents, never worker-written JSON.
 for name in('source_authority','kernel_authority','producer_retirement','native_readback'):
  path=Path('/broker-authorities')/(name+'.json')
  P.need(not any(p.is_symlink()for p in(path,*path.parents)),'ordinary private authority path')
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   before=os.fstat(fd);P.need(stat.S_ISREG(before.st_mode)and before.st_uid==0 and not stat.S_IMODE(before.st_mode)&0o022 and before.st_nlink==1 and 0<before.st_size<=4*1024**2,'root-owned bounded private authority')
   raw=os.read(fd,before.st_size+1);P.need(len(raw)==before.st_size and P.stable(before)==P.stable(os.fstat(fd))==P.stable(path.lstat())and P.pin(raw)==value[name],'exact private accepted authority bytes')
   P.need(type(P.decode(raw))is dict,'accepted document object')
  finally:os.close(fd)

class Context:
 def __init__(self, value, root, work, limits):
     selection(value)
     pid1()
     authority_inputs(value)
     self.value = value
     self.root = Path(root)
     self.work = Path(work)
     self.control = -1
     self.fd = -1
     self.index = -1
     R = reader()
     self.R = R
     P.need(self.root == Path('/held') and self.work == Path('/work'), 'fixed separate source/work purpose')
     try:
         self.control = os.open('/dev/mapper/control', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
         s = os.fstat(self.control)
         P.need(stat.S_ISCHR(s.st_mode) and s.st_rdev == os.makedev(10, 236), 'private actual DM control')
         self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
         self.identity = P.stable(os.fstat(self.fd))
         self.mounts = R.mount_table()
         self.mount = R.source_mount(self.mounts, self.fd, self.root)
         s = self.work.lstat()
         P.need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and (stat.S_IMODE(s.st_mode) == 448) and (s.st_dev != self.identity[0]) and (not os.statvfs(self.work).f_flag & os.ST_RDONLY), 'separate owned RW work filesystem')
         self.check()
         api, modules = source_api()
         baseline = api['observe'](modules, self.root, limits)
         api['_phase'](b'AUXILIARY_2_BEGIN')
         try:
             baseline['auxiliary'] = modules['aux_checkpoint'].checkpoint(self.root, baseline['observation'], limits)
         except BaseException:
             try:
                 api['_phase'](b'AUXILIARY_2_FAIL')
             except BaseException:
                 pass
             raise
         api['_phase'](b'AUXILIARY_2_END')
         self.check()
         raw = P.encode(P.pack(baseline))
         self.index_pin = P.pin(raw)
         self.index = P.sealed(raw)
     except BaseException:
         self.close()
         raise
 def check(self):
  pid1();R=self.R;P.need(P.stable(os.fstat(self.fd))==self.identity and R.mount_table()==self.mounts,'fresh complete mount/root identity')
  R.source_mount(self.mounts,self.fd,self.root)
  P.need(ctypes.sizeof(R.Header)==312 and ctypes.sizeof(R.Target)==40,'reviewed DM query ABI')
  raw=bytearray(65536);h=R.Header.from_buffer(raw);h.version[:]=(4,0,0);h.data_size=len(raw);h.data_start=312;h.flags=1<<4;h.dev=self.identity[0]
  fcntl.ioctl(self.control,(3<<30)|(312<<16)|(0xfd<<8)|12,raw,True)
  P.need(h.dev==self.identity[0]and h.version[0]==4 and h.target_count==1 and h.flags&1 and h.flags&(1<<5)and not h.flags&((1<<8)|(1<<1)),'live complete readonly unsuspended DM table')
  P.need(312<=h.data_start<=h.data_size-40<=len(raw)-40,'bounded DM response');t=R.Target.from_buffer(raw,h.data_start);P.need(bytes(t.type)==b'verity'and t.start==0 and t.status==0,'one complete verity target')
  params=bytes(raw[h.data_start+40:h.data_size]).split(b'\0',1)[0];P.need(len(params)<=4096,'bounded table parameters')
  got=R.validate_table(t.length,params.decode('ascii'),self.value['verity']);P.need(got==self.value['verity'],'exact selected readonly hash/backing identities')
  return dict(root_identity=self.identity,source_mount=self.mount,verity=got,index=getattr(self,'index_pin',None))
 def capacity(self):
  s=os.fstatvfs(self.fd);return dict(filesystem_free_bytes=s.f_bavail*s.f_frsize,filesystem_free_inodes=s.f_favail if s.f_files else None)
 def close(self):
  for n in('index','fd','control'):
   fd=getattr(self,n,-1)
   if fd>=0:os.close(fd);setattr(self,n,-1)
