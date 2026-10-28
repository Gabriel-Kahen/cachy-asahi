# SPDX-License-Identifier: MIT
"""Explicit emulated16K CI limits; production defaults stay held."""
import hashlib,json,os,re,signal,stat,time
from contextlib import contextmanager
from datetime import datetime,timezone
from pathlib import Path
BUDGETS={'CIleaseTTL': 15840, 'ELF': 300, 'actor_retirement_reserve': 900, 'caller_fault': 7740, 'caller_normal': 12480, 'capmap': 900, 'cleanup': 300, 'composition_step': 18600, 'copy': 4260, 'export': 1200, 'fault_driver': 5700, 'guest_worker_fault': 10140, 'guest_worker_normal': 14880, 'host_owner': 17400, 'job': 21600, 'job_build_reserve': 2400, 'job_owner': 18000, 'normal_driver': 10440, 'pid1_fault': 10260, 'pid1_normal': 15000, 'post_composition_reserve': 600, 'prepare': 2400, 'qemu_fault': 10380, 'qemu_normal': 15120, 'scrub': 1200, 'stage': 1200, 'verify': 600, 'vm_transport': 15840}
CASE='postcommit-exit87'
PURPOSE='normal-emulated16k-lifecycle-v1'
def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def ceiling(name,case=CASE):
 key=name+'_'+('normal'if case=='normal'else'fault');v=BUDGETS[key]if key in BUDGETS else BUDGETS[name]
 need(type(v)is int and 0<v<=21600,'finite exact CI phase budget');return v
def guest_deadline():
 raw=os.environ.get('LIFECYCLE_GUEST_DEADLINE_NS','');need(raw.isascii()and raw.isdecimal()and str(int(raw))==raw,'same guest monotonic deadline required')
 v=int(raw);now=time.monotonic_ns();need(now<v<=now+BUDGETS['CIleaseTTL']*10**9,'unexpired finite guest CI deadline');return v/10**9
def remaining(requested,reserve=0):
 need(type(requested)in(int,float)and 0<requested<=21600 and type(reserve)is int and reserve>=0,'finite CI phase/reserve')
 v=min(requested,guest_deadline()-time.monotonic()-reserve);need(v>0,'CI parent deadline exhausted');return v
def deadline(requested,reserve=0):return time.monotonic()+remaining(requested,reserve)
def release_window(config):
 raw=os.environ.get('LIFECYCLE_LAUNCHER_EPOCH','');need(raw.isascii()and raw.isdecimal()and str(int(raw))==raw,'owned launcher epoch required')
 epoch=int(raw);need(1700000000<=epoch<2**32 and epoch-60<=int(time.time())<=epoch+BUDGETS['CIleaseTTL'],'owned launcher TEST window')
 v=json.loads(json.dumps(config));v['release']['issued_utc']=datetime.fromtimestamp(epoch-60,timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ');v['release']['expires_utc']=datetime.fromtimestamp(epoch+BUDGETS['CIleaseTTL'],timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ');return v
@contextmanager
def phase(seconds):
 need(type(seconds)in(int,float)and 0<seconds<=21600,'finite CI phase')
 before=time.monotonic();old=signal.getsignal(signal.SIGALRM);left,interval=signal.getitimer(signal.ITIMER_REAL);need(not interval,'no repeating timer')
 def expired(*args):
  if left and left<=seconds and callable(old):return old(*args)
  raise TimeoutError('explicit emulated16K CI phase deadline')
 signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,min(seconds,left)if left else seconds)
 try:yield
 finally:
  signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,old)
  if left:signal.setitimer(signal.ITIMER_REAL,max(.000001,left-(time.monotonic()-before)))
def timed(seconds,function,*args,**kwargs):
 with phase(seconds):return function(*args,**kwargs)
class Lease:
 def __init__(self,args,config):
  data=Path(args.data);need(data==data.resolve()and data.is_dir()and not any(p.is_symlink()for p in(data,*data.parents)),'canonical CI lease data')
  nonce=os.environ.get('CACHY_ASAHI_BOUND_UPDATE','');source=os.environ.get('LIFECYCLE_SOURCE_SHA','');need(re.fullmatch('[a-f0-9]{32}',nonce)and re.fullmatch('[a-f0-9]{40}',source),'same source and bound nonce')
  self.path=data/'emulated16k-lifecycle-lease.json';self.fd=os.open(self.path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|os.O_NOFOLLOW,0o600);self.start=time.monotonic_ns();self.end=min(self.start+BUDGETS['CIleaseTTL']*10**9,int(guest_deadline()*10**9));self.closed=False
  self.identity=dict(source=source,nonce=nonce,case=CASE,signer=args.signer,source_path=str(Path(args.source)),workspace=str(Path(args.workspace)),config_sha256=hashlib.sha256(encoded(config)).hexdigest(),requested_ttl_seconds=BUDGETS['CIleaseTTL'],acquired_monotonic_ns=self.start,effective_deadline_monotonic_ns=self.end,clock_scope='SAME_OWNED_GUEST_KERNEL_MONOTONIC_ONLY',kind='NEW_PRIVATE_CI_LEASE_NOT_PRODUCTION_TTL',held_from='BEFORE_FIRST_COPY')
  self.identity['fd_identity']=dict(dev=os.fstat(self.fd).st_dev,ino=os.fstat(self.fd).st_ino,uid=os.fstat(self.fd).st_uid,mode=0o600);body=encoded(self.identity);os.write(self.fd,body);os.fsync(self.fd);self.file_pin=pin(body);self.inode=os.fstat(self.fd)
 def check(self):
  need(not self.closed and time.monotonic_ns()<self.end,'CI lease unexpired and held');a=os.fstat(self.fd);b=self.path.lstat();key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size)
  need(key(a)==key(b)==key(self.inode)and stat.S_ISREG(a.st_mode)and a.st_nlink==1 and stat.S_IMODE(a.st_mode)==0o600,'exact CI lease FD/path')
  os.lseek(self.fd,0,os.SEEK_SET);need(pin(os.read(self.fd,a.st_size+1))==self.file_pin,'whole CI lease bytes');return self.identity
 def close(self):
  try:self.check()
  finally:self.closed=True;os.close(self.fd)
  return dict(self.identity,fd_closed=True,release='CLOSE_ONLY_OWNED_RECEIPT_PRESERVED',held_through='ORDERED_COPY_SNAPSHOT_RETIREMENT',ended_monotonic_ns=time.monotonic_ns())
def effective_witness(nominal,parent_elapsed_ns,reserve=900):
 need(type(nominal)is int and 0<nominal<=21600 and type(parent_elapsed_ns)is int and 0<=parent_elapsed_ns<15840*10**9 and type(reserve)is int and reserve in(0,900),'typed fixed CI remaining-time witness')
 effective=min(nominal,(15840*10**9-parent_elapsed_ns-reserve*10**9)//10**9);need(effective>5,'CI actor/retirement budget exhausted')
 return dict(nominal_seconds=nominal,parent_total_seconds=15840,parent_elapsed_ns=parent_elapsed_ns,reserve_seconds=reserve,effective_seconds=effective)
def guest_witness(nominal):
 # The deadline is a duration handed from owned QEMU; this is not host clock identity.
 left=guest_deadline()-time.monotonic();elapsed=max(0,15840*10**9-int(left*10**9));return effective_witness(nominal,elapsed)
def kernel_milliseconds():
 rows=[x.split('=',1)[1]for x in Path('/proc/cmdline').read_text().split()if x.startswith('cachy_asahi_lifecycle_qemu_ms=')]
 need(len(rows)==1 and rows[0].isascii()and rows[0].isdecimal()and str(int(rows[0]))==rows[0],'one owned QEMU duration handoff')
 value=int(rows[0]);need(6000<value<=15840*1000,'finite owned QEMU milliseconds');return value
def verify_deadline_record(record,nominal):
 """Pure exact finite-clock witness; the original record predicate keeps equality."""
 def require(ok,why):
  if not ok:raise ValueError(why)
 w=record['emulated16k_deadline'];require(type(w)is dict and set(w)=={'nominal_seconds','parent_total_seconds','parent_elapsed_ns','reserve_seconds','effective_seconds'},'closed emulated16K deadline witness')
 require(all(type(w[k])is int for k in w)and type(nominal)is int and w['nominal_seconds']==nominal and w['parent_total_seconds']==15840 and 0<=w['parent_elapsed_ns']<15840*10**9 and w['reserve_seconds']in(0,900),'typed exact nominal/parent/reserve clock')
 expected=min(nominal,(15840*10**9-w['parent_elapsed_ns']-w['reserve_seconds']*10**9)//10**9)
 require(expected>5 and w['effective_seconds']==expected and type(record['time_limit'])is int and record['time_limit']==expected,'exact effective deadline equality')
 return expected
