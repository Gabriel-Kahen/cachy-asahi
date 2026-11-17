# SPDX-License-Identifier: MIT
"""Proposed bounded QMP framing and public retirement observations; no actor entry."""
import hashlib,json,os,select,socket,stat,time

def quit_hold_qmp(K,peer,qfile,guard,end,progress=None):
 # Source9dd creates SocketIO with buffering=0: no reader-ahead bytes exist.
 K.need(type(qfile)is socket.SocketIO and qfile.fileno()==peer.fd and not qfile.closed and not qfile._timeout_occurred,'original unbuffered healthy QMP stream')
 if progress is None:progress={}
 progress.update(stage='VALIDATING',request_bytes=0,reply_attempts=0,reply_bytes=0,idle_polls=0)
 stream=peer.stream;K.need(stream.fileno()==peer.fd,'same original QMP socket')
 original_timeout=stream.gettimeout();pending=bytearray();request=b'{"execute":"quit","id":"guest-HOLD-retire"}\n'
 def ready(reading):
  while True:
   guard();remaining=end-time.monotonic()
   if remaining<=0:
    progress.update(stage='DEADLINE_EXPIRED',io_error='TimeoutError',errno=None);raise TimeoutError('bounded HOLD quit deadline')
   try:r,w,_=select.select([stream]if reading else[],[]if reading else[stream],[],min(.25,remaining))
   except InterruptedError:continue
   if r or w:return
   progress['idle_polls']+=1
 def unique(rows):
  result={}
  for key,value in rows:K.need(key not in result,'duplicate QMP field');result[key]=value
  return result
 def invalid(value):raise ValueError('nonfinite QMP field')
 try:
  guard();K.need(time.monotonic()<end,'bounded HOLD quit deadline');stream.setblocking(False)
  progress['stage']='WRITE_ENTERED'
  while progress['request_bytes']<len(request):
   ready(False)
   try:written=stream.send(request[progress['request_bytes']:])
   except (BlockingIOError,InterruptedError):continue
   K.need(written>0,'HOLD QMP request EOF');progress['request_bytes']+=written
  progress['stage']='WRITE_RETURNED'
  while progress['reply_attempts']<16:
   progress['stage']='READ_ENTERED';ready(True)
   try:chunk=stream.recv(min(4096,65537-progress['reply_bytes']))
   except (BlockingIOError,InterruptedError):continue
   K.need(chunk,'HOLD QMP reply EOF');pending.extend(chunk);progress['reply_bytes']+=len(chunk)
   K.need(progress['reply_bytes']<=65536,'bounded HOLD QMP aggregate reply')
   while b'\n'in pending:
    line,_,tail=pending.partition(b'\n');pending=bytearray(tail);progress['reply_attempts']+=1
    K.need(progress['reply_attempts']<=16 and len(line)>0,'bounded HOLD QMP reply count')
    row=json.loads(line,object_pairs_hook=unique,parse_constant=invalid);K.need(type(row)is dict,'QMP reply object')
    if row.get('id')=='guest-HOLD-retire':
     K.need('return'in row and 'error'not in row,'QMP HOLD quit acknowledged');progress['stage']='ACKNOWLEDGED';return
  raise ValueError('QMP HOLD quit acknowledgement absent')
 except OSError as error:
  if progress['stage']!='DEADLINE_EXPIRED':progress.update(stage='IO_FAILED',io_error=type(error).__name__,errno=error.errno)
  raise
 finally:stream.settimeout(original_timeout)


def retirement_observation(K,out,retired_name):
 """Record only fixed public receipt pins and typed counters; never accept a run."""
 K.need(retired_name=='guest-HOLD-retired.json','fixed public HOLD receipt name')
 def observe(name):
  try:
   path=K.ordinary(out/name)
   fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
   with os.fdopen(fd,'rb')as stream:
    before=os.fstat(stream.fileno());K.need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_uid==os.getuid()and before.st_gid==os.getgid()and stat.S_IMODE(before.st_mode)in((0o600,0o644)if name=='qemu.json'else(0o600,)) and 0<before.st_size<=65536,'bounded owned public retirement receipt')
    raw=stream.read(65537);after=os.fstat(stream.fileno())
   identity=lambda s:tuple(getattr(s,n)for n in('st_dev','st_ino','st_size','st_mode','st_uid','st_gid','st_nlink','st_mtime_ns','st_ctime_ns'))
   K.need(identity(before)==identity(after)==identity(path.lstat())and len(raw)==before.st_size,'stable whole retirement observation')
   result=dict(status='PRESENT_PIN_ONLY_NOT_VALIDATED_RETIREMENT',file=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))
   if name=='qemu.json':
    # No argv, exception text, paths or file content can enter the report.
    def unique(rows):
     value={}
     for k,v in rows:K.need(k not in value,'duplicate retirement observation field');value[k]=v
     return value
    def invalid(v):raise ValueError('nonfinite retirement observation')
    row=json.loads(raw,object_pairs_hook=unique,parse_constant=invalid);K.need(type(row)is dict and raw==K.canonical(row),'canonical retirement observation')
    fields={}
    for key in('passed','reaped','output_complete','timeout','command_timed_out','original_budget_overrun','emergency_retirement'):
     if key in row:K.need(type(row[key])is bool,'typed retirement observation');fields[key]=row[key]
    if 'exit'in row:K.need(row['exit']is None or type(row['exit'])is int and 0<=row['exit']<=255,'bounded retirement exit');fields['exit']=row['exit']
    for key,values in(('ownership',('REAPED','OWNERSHIP_LOST')),('group_census',('EMPTY_TWICE','NOT_EMPTY','UNKNOWN'))):
     if key in row:K.need(row[key]in values,'allowlisted retirement observation');fields[key]=row[key]
    if 'signals'in row:
     K.need(type(row['signals'])is list and len(row['signals'])<=16 and all(v in('SIGTERM','SIGKILL','SIGINT')for v in row['signals']),'allowlisted retirement signals');fields['signals']=row['signals']
    result['observed']=fields
   return result
  except FileNotFoundError:return dict(status='ABSENT')
  except BaseException:return dict(status='REFUSED_UNSAFE_OR_INVALID')
 return dict(status='PUBLIC_RETIREMENT_OBSERVATIONS_ONLY',qemu=observe('qemu.json'),guest_HOLD_retired=observe(retired_name),VM_acceptance=None,Root_acceptance=None)
