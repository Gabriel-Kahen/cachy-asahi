"""One inherited seqpacket protocol. Transport tests grant no source authority."""
import array,ctypes,fcntl,hashlib,json,os,socket,stat,struct
PURPOSE='GNU_PID1_VERITY_SOURCE_BROKER_V1';WORKER_MASK=0x800400fb
MAX_FRAME=4096;MAX_INDEX=256*1024**2;MAX_REQUESTS=64
SEALS=0x0f;CREDENTIALS=struct.Struct('3i')
def need(ok,why):
 if not ok:raise ValueError(why)
def encode(v):return(json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def decode(raw):
 def pairs(rows):
  out={}
  for k,v in rows:need(k not in out,'duplicate field');out[k]=v
  return out
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite number'))
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def stable(s):return[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def peer(sock):return CREDENTIALS.unpack(sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,CREDENTIALS.size))
def channel(sock):
 need(sock.family==socket.AF_UNIX and sock.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE)==socket.SOCK_SEQPACKET,'inherited Unix seqpacket only')
 sock.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1);sock.settimeout(5)
def send(sock,value,fds=()):
 raw=encode(value);need(len(raw)<=MAX_FRAME and len(fds)<=2,'bounded protocol send');anc=[]
 if fds:anc=[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',fds))]
 need(sock.sendmsg([raw],anc)==len(raw),'whole seqpacket send')
def request(sock,value):
 # No rights on worker requests. Original service fence denies socket sendmsg,
 # sendto and connect; write on the sole inherited channel needs no exemption.
 raw=encode(value);need(len(raw)<=MAX_FRAME,'bounded request');need(os.write(sock.fileno(),raw)==len(raw),'whole inherited seqpacket write')
def receive(sock,expected,rights):
 data,anc,flags,_=sock.recvmsg(MAX_FRAME+1,socket.CMSG_SPACE(CREDENTIALS.size)+socket.CMSG_SPACE(16*4),socket.MSG_CMSG_CLOEXEC);fds=[];creds=[]
 try:
  # Collect rights before validating any ancillary row so every received FD
  # closes on every refusal, including unknown metadata/truncated frames.
  for level,kind,raw in anc:
   if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
    a=array.array('i');a.frombytes(raw[:len(raw)//a.itemsize*a.itemsize]);fds.extend(a)
  for level,kind,raw in anc:
   need(level==socket.SOL_SOCKET,'unknown ancillary level')
   if kind==socket.SCM_RIGHTS:continue
   if kind==socket.SCM_CREDENTIALS:
    need(len(raw)==CREDENTIALS.size,'exact kernel credentials');creds.append(CREDENTIALS.unpack(raw))
   else:need(False,'unknown ancillary type')
  need(not flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC)and 0<len(data)<=MAX_FRAME,'complete bounded frame')
  need(creds==[expected]and len(fds)==rights,'actual sender credentials/exact descriptors')
  return decode(data),fds
 except BaseException:
  for fd in fds:os.close(fd)
  raise

def sealed(raw):
 need(0<len(raw)<=MAX_INDEX,'bounded complete source index')
 libc=ctypes.CDLL(None,use_errno=True);fd=libc.memfd_create(b'gnu-source-index',3)
 if fd<0:raise OSError(ctypes.get_errno(),'memfd_create')
 try:
  pos=0
  while pos<len(raw):
   n=os.write(fd,raw[pos:pos+1024**2]);need(n>0,'complete index write');pos+=n
  fcntl.fcntl(fd,1033,SEALS);need(fcntl.fcntl(fd,1034)==SEALS,'complete immutable index seals');return fd
 except BaseException:os.close(fd);raise

def index_bytes(fd,wanted):
 s=os.fstat(fd);need(stat.S_ISREG(s.st_mode)and 0<s.st_size<=MAX_INDEX and fcntl.fcntl(fd,1034)==SEALS,'fully sealed bounded source index')
 raw=bytearray();pos=0
 while pos<s.st_size:
  block=os.pread(fd,min(1024**2,s.st_size-pos),pos);need(bool(block),'complete index read');raw.extend(block);pos+=len(block)
 raw=bytes(raw);need(stable(s)==stable(os.fstat(fd))and pin(raw)==wanted,'complete index identity/hash');return raw

def pack(value):
 # Preserve tuples/bytes exactly; never normalize an arbitrary observation.
 if type(value)is tuple:return {'$gnu_tuple':[pack(x)for x in value]}
 if type(value)is bytes:return {'$gnu_bytes':value.hex()}
 if type(value)is list:return[pack(x)for x in value]
 if type(value)is dict:
  need(all(type(k)is str and not k.startswith('$gnu_')for k in value),'source map string keys/no codec aliases');return{k:pack(v)for k,v in value.items()}
 need(value is None or type(value)in(str,int,float,bool),'unsupported source index type');return value

def unpack(value,depth=0):
 need(depth<=192,'bounded source map nesting')
 if type(value)is dict:
  if '$gnu_tuple'in value:
   need(set(value)=={'$gnu_tuple'}and type(value['$gnu_tuple'])is list,'exact tuple codec');return tuple(unpack(x,depth+1)for x in value['$gnu_tuple'])
  if '$gnu_bytes'in value:
   need(set(value)=={'$gnu_bytes'}and type(value['$gnu_bytes'])is str,'exact bytes codec');return bytes.fromhex(value['$gnu_bytes'])
  need(not any(k.startswith('$gnu_')for k in value),'unknown codec tag');return{k:unpack(v,depth+1)for k,v in value.items()}
 if type(value)is list:return[unpack(x,depth+1)for x in value]
 return value
