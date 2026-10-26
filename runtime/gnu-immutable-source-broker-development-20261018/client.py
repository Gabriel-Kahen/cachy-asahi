"""No worker JSON can substitute for actual PID1-issued descriptors."""
import copy,ctypes,fcntl,os,re,stat
from pathlib import Path
import context as C
import protocol as P

def restricted():
 P.need(os.getpid()!=1 and os.getppid()==1 and os.getuid()==os.geteuid()==0,'actual direct PID1 root worker only')
 raw=Path('/proc/self/status').read_text();P.need(len(raw)<=65536,'bounded actual worker status');v=dict(row.split(':',1)for row in raw.splitlines()if ':'in row)
 P.need(v['NoNewPrivs'].strip()=='1'and v['Seccomp'].strip()=='2','NNP and original syscall filters required')
 for n in('CapEff','CapPrm','CapBnd'):P.need(int(v[n],16)==P.WORKER_MASK,'exact declared9-cap worker purpose')
 for n in('CapInh','CapAmb'):P.need(int(v[n],16)==0,'no inherited/ambient capabilities')
 libc=ctypes.CDLL(None,use_errno=True);P.need(libc.prctl(4,0,0,0,0)==0 and libc.prctl(3,0,0,0,0)==0,'worker dumpable zero')
 P.need({p.name for p in Path('/dev').iterdir()}=={'null','zero','random','urandom'},'no raw/control device paths')
 for path in Path('/proc/self/fd').iterdir():
  try:s=path.stat()
  except FileNotFoundError:continue
  P.need(not stat.S_ISBLK(s.st_mode)and not(stat.S_ISCHR(s.st_mode)and s.st_rdev==os.makedev(10,236)),'no worker raw/control descriptors')

class Client:
 def __init__(self,sock,nonce):
  P.need(re.fullmatch('[a-f0-9]{32}',nonce or''),'exact nonce');restricted();P.channel(sock);P.need(P.peer(sock)==(1,0,0),'kernel SO_PEERCRED real PID1 issuer required')
  self.sock=sock;self.nonce=nonce;self.seq=0;self.baseline=None;self.pinned=None;self.R=C.reader()
 def source(self,limits):
  restricted();limits.tick();P.need(self.seq<P.MAX_REQUESTS,'bounded source requests');self.seq+=1
  P.request(self.sock,dict(purpose=P.PURPOSE,nonce=self.nonce,op='source',seq=self.seq))
  value,fds=P.receive(self.sock,(1,0,0),2)
  try:
   root,index=fds;P.need(set(value)=={'root_identity','source_mount','verity','index','purpose','nonce','seq','capacity'}and value['purpose']==P.PURPOSE and value['nonce']==self.nonce and value['seq']==self.seq,'exact source response')
   P.need(fcntl.fcntl(root,fcntl.F_GETFL)&os.O_ACCMODE==os.O_RDONLY and stat.S_ISDIR(os.fstat(root).st_mode)and P.stable(os.fstat(root))==value['root_identity'],'real read-only root descriptor identity')
   self.R.source_mount(self.R.mount_table(),root,Path('/held'));P.need(self.R.mount_id(root)==value['source_mount'],'fresh source mount identity')
   stable={k:value[k]for k in('root_identity','source_mount','verity','index')}
   if self.pinned is None:
    self.baseline=P.unpack(P.decode(P.index_bytes(index,value['index'])));self.pinned=stable;self.index_identity=P.stable(os.fstat(index))
    P.need(type(self.baseline)is dict and set(self.baseline)=={'observation','nodes','capabilities','physical','auxiliary'}and self.baseline['observation']['complete']is True and self.baseline['nodes']==self.baseline['observation']['nodes'],'whole original maps/auxiliary index')
   else:P.need(stable==self.pinned and P.stable(os.fstat(index))==self.index_identity and fcntl.fcntl(index,1034)==P.SEALS,'same kernel-sealed immutable full index')
   # Only dynamic free-capacity counters are freshly refreshed, explicitly.
   v=os.fstatvfs(root);capacity=dict(filesystem_free_bytes=v.f_bavail*v.f_frsize,filesystem_free_inodes=v.f_favail if v.f_files else None)
   P.need(value['capacity']==capacity,'independent fresh source capacity')
   out=copy.deepcopy(self.baseline)
   for k,v in capacity.items():P.need(k in out['observation']['footprint'],'original capacity field');out['observation']['footprint'][k]=v
   limits.tick();return out
  finally:
   for fd in fds:os.close(fd)
 def close(self):self.sock.close()
