#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""One source-owned SIGTERM after real sharing; private disposable VM only."""
import json,os,select,signal,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import sharing as S
PROFILE='OWNED_KSM16K_AFTER_SHARED_SIGTERM_CLEANUP_V1'

class Terminated(Exception):pass

def record(fd,deadline):
 raw=bytearray()
 while not raw.endswith(b'\n'):
  remaining=deadline-time.monotonic();S.need(remaining>0 and select.select([fd],[],[],remaining)[0],'bounded interruption record deadline')
  part=os.read(fd,32769-len(raw));S.need(part and len(raw)+len(part)<=32768,'bounded complete interruption record');raw.extend(part)
 S.need(raw.count(b'\n')==1,'one interruption record')
 def pairs(rows):
  value={}
  for k,v in rows:S.need(k not in value,'duplicate interruption key');value[k]=v
  return value
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:S.need(False,'finite interruption record'))

def checkpoint(fd,nonce,children,scalars,deadline):
 # The one installed handler exists only around the explicit test barrier.
 # The original sharing/unmerge/retire/restoration body executes afterwards.
 observed=[]
 def term(signum,frame):
  observed.append(signum);raise Terminated()
 prior=signal.signal(signal.SIGTERM,term)
 try:
  value=dict(event='SHARED_READY_FOR_OWNED_SIGTERM',nonce=nonce,controller=dict(pid=os.getpid(),parent=os.getppid(),group=os.getpgid(0),birth=S.birth(os.getpid())),children=[row['initial']for row in children],original=dict(scalars.original))
  raw=S.encoded(value);S.need(len(raw)<=4096 and os.write(fd,raw)==len(raw),'one complete owned barrier')
  stop=min(deadline-5,time.monotonic()+5)
  while time.monotonic()<stop:time.sleep(min(.01,max(0,stop-time.monotonic())))
  raise ValueError('owned SIGTERM not received in original deadline')
 except Terminated:
  S.need(observed==[signal.SIGTERM],'exact one owned interruption')
  return dict(signal='SIGTERM',number=int(signal.SIGTERM),received=1,point='AFTER_REAL_SHARED_BEFORE_RUN2',handler='EXPLICIT_TEST_BARRIER_ONLY')
 finally:signal.signal(signal.SIGTERM,prior)

def fresh(audit,children):
 return dict(settings={n:audit.read(n)for n in audit.original},counters=audit.counters(),children=[dict(pid=r['pid'],birth=S.birth(r['pid']),ksm_merging_pages=S.merged(r['pid']))for r in children])

def experiment(selection,parent):
 nonce=S.guard(selection,parent);deadline=time.monotonic()+82;audit=S.Scalars();original=dict(audit.original);before=fresh(audit,[]);opened=[];pid=None;reaped=False
 previous_term=signal.getsignal(signal.SIGTERM)
 def stop(signum,frame):raise S.SharingInterrupted('owned interruption observer SIGTERM')
 signal.signal(signal.SIGTERM,stop)
 try:
  receive,send=os.pipe2(os.O_CLOEXEC);opened.extend((receive,send));result_in,result_out=os.pipe2(os.O_CLOEXEC);opened.extend((result_in,result_out));pid=os.fork()
  if pid==0:
   try:
    os.close(receive);os.close(result_in);audit.close();os.setsid();interruption=[]
    def barrier(nonce,children,scalars,deadline):interruption.append(checkpoint(send,nonce,children,scalars,deadline))
    shared=S.experiment(selection,os.getppid(),barrier);S.need(len(interruption)==1,'one explicit barrier')
    raw=S.encoded(dict(sharing=shared,interruption=interruption[0]));S.need(len(raw)<=32768 and os.write(result_out,raw)==len(raw),'one complete cleanup result');os._exit(0)
   except BaseException:os._exit(1)
  os.close(send);opened.remove(send);os.close(result_out);opened.remove(result_out)
  ready=record(receive,deadline);controller=ready.get('controller',{})
  S.need(set(ready)=={'event','nonce','controller','children','original'}and ready['event']=='SHARED_READY_FOR_OWNED_SIGTERM'and ready['nonce']==nonce and ready['original']==original,'exact source-owned sharing barrier')
  S.need(controller==dict(pid=pid,parent=os.getpid(),group=pid,birth=S.birth(pid))and os.getpgid(pid)==pid,'fresh direct owned controller PID/birth/session')
  children=ready['children'];S.need(type(children)is list and len(children)==2 and len({r['pid']for r in children})==2,'two owned children at interruption')
  for r in children:
   S.need(r==dict(pid=r['pid'],parent=pid,group=pid,birth=S.birth(r['pid']),nonce=nonce,bytes=S.PAGE*S.PAGES,sha256=S.expected_hash(nonce),mergeable=True)and r['pid']not in(pid,os.getpid())and os.getpgid(r['pid'])==pid,'fresh owned child birth/group/nonce')
  active=fresh(audit,children);S.need(active['settings']==dict(run=1,**S.CONFIG)and all(r['ksm_merging_pages']>=S.PAGES for r in active['children'])and active['counters']['pages_shared']>=S.PAGES and active['counters']['pages_sharing']>=S.PAGES,'fresh parent readback of actual sharing before signal')
  # Direct unreaped child cannot have its PID reused; no discovery or group signal.
  os.kill(pid,signal.SIGTERM);result=record(result_in,deadline)
  while True:
   got,status=os.waitpid(pid,os.WNOHANG)
   if got:reaped=True;break
   S.need(time.monotonic()<deadline,'interrupted controller retirement deadline');time.sleep(.01)
  S.need(os.waitstatus_to_exitcode(status)==0 and not Path('/proc',str(pid)).exists(),'natural cleaned controller retirement')
  S.need(type(result)is dict and set(result)=={'sharing','interruption'},'closed cleanup result');S.validate(result['sharing'],nonce)
  S.need(result['sharing']['controller']=={k:controller[k]for k in('pid','group','birth')}and result['sharing']['parent']==os.getpid()and result['sharing']['children']==children,'exact interrupted controller/children join')
  absent=[dict(pid=r['pid'],birth=r['birth'],proc_absent=not Path('/proc',str(r['pid'])).exists())for r in children];S.need(all(r['proc_absent']for r in absent),'fresh parent observes both owned child PIDs absent')
  after=fresh(audit,[]);S.need(after['settings']==original and after['counters']['pages_shared']==after['counters']['pages_sharing']==after['counters']['full_scans']==0,'fresh held-FD original settings and unmerge epoch readback')
  value=dict(profile=PROFILE,status='PASS_OWNED_SIGTERM_SHARING_UNMERGE_CLEANUP',nonce=nonce,parent=os.getpid(),owner_parent=parent,observer=dict(pid=os.getpid(),group=os.getpgid(0),birth=S.birth(os.getpid())),controller=controller,sharing=result['sharing'],interruption=result['interruption'],before=before,active=active,after=after,parent_child_absence=absent,controller_retirement=dict(pid=pid,birth=controller['birth'],exit=0,reaped=True,proc_absent=True),command_limit=S.COMMAND_SECONDS,scope='DISPOSABLE_GENERIC16K_OWNED_SHARING_ONLY',hardware='NOT_RUN',performance='NOT_MEASURED',release='NOT_ADMITTED')
  return validate(value,nonce)
 finally:
  try:
   if pid not in(None,0)and not reaped:
    # Exceptional failure gets no receipt. Retire only our still-unreaped child
    # session. Never restore an audit snapshot over a foreign edit.
    try:
     if os.getpgid(pid)==pid:os.killpg(pid,signal.SIGKILL)
     else:os.kill(pid,signal.SIGKILL)
    except ProcessLookupError:pass
    try:os.waitpid(pid,0)
    except ChildProcessError:pass
   for fd in opened:os.close(fd)
   audit.close()
  finally:signal.signal(signal.SIGTERM,previous_term)

def validate(v,nonce):
 fields={'profile','status','nonce','parent','owner_parent','observer','controller','sharing','interruption','before','active','after','parent_child_absence','controller_retirement','command_limit','scope','hardware','performance','release'}
 S.need(type(v)is dict and set(v)==fields and v['profile']==PROFILE and v['status']=='PASS_OWNED_SIGTERM_SHARING_UNMERGE_CLEANUP'and v['nonce']==nonce,'closed explicit interruption receipt')
 S.need(type(v['owner_parent'])is int and v['owner_parent']>1 and v['owner_parent']!=v['parent'] and v['observer']==dict(pid=v['parent'],group=v['parent'],birth=v['observer']['birth'])and type(v['observer']['birth'])is int and 0<v['observer']['birth']<=v['controller']['birth'],'fresh observer direct session identity')
 s=S.validate(v['sharing'],nonce);c=v['controller'];S.need(c==dict(pid=s['controller']['pid'],parent=v['parent'],group=s['controller']['group'],birth=s['controller']['birth'])and s['parent']==v['parent'],'same interrupted direct controller')
 S.need(v['interruption']==dict(signal='SIGTERM',number=int(signal.SIGTERM),received=1,point='AFTER_REAL_SHARED_BEFORE_RUN2',handler='EXPLICIT_TEST_BARRIER_ONLY'),'one exact after-sharing interruption')
 original=s['configuration']['original']
 for phase in('before','active','after'):
  row=v[phase];S.need(type(row)is dict and set(row)=={'settings','counters','children'}and set(row['counters'])==set(S.COUNTERS)and all(type(x)is int and 0<=x<2**63 for x in row['counters'].values()),'complete fresh parent settings/counters')
  S.need(row['settings']==(dict(run=1,**S.CONFIG)if phase=='active'else original),'fresh parent settings agree with same controller')
  if phase!='active':S.need(row['children']==[]and row['counters']['pages_shared']==row['counters']['pages_sharing']==0,'fresh outside sharing is empty')
  else:S.need(row['children']==[dict(pid=r['pid'],birth=r['birth'],ksm_merging_pages=n['ksm_merging_pages'])for r,n in zip(s['children'],row['children'])]and len(row['children'])==2 and all(type(r['ksm_merging_pages'])is int and r['ksm_merging_pages']>=S.PAGES for r in row['children'])and row['counters']['pages_shared']>=S.PAGES and row['counters']['pages_sharing']>=S.PAGES,'fresh parent owned-mm/global sharing')
 S.need(v['active']['counters']['full_scans']>=s['counters']['sharing']['full_scans']>s['counters']['before']['full_scans'],'fresh parent observes same actual sharing scan epoch')
 S.need(v['after']['counters']['full_scans']==0 and v['parent_child_absence']==[dict(pid=r['pid'],birth=r['birth'],proc_absent=True)for r in s['children']]and v['controller_retirement']==dict(pid=c['pid'],birth=c['birth'],exit=0,reaped=True,proc_absent=True),'fresh parent controller and child absence after original run2 epoch reset')
 S.need(v['command_limit']==S.COMMAND_SECONDS and v['scope']=='DISPOSABLE_GENERIC16K_OWNED_SHARING_ONLY'and v['hardware']=='NOT_RUN'and v['performance']=='NOT_MEASURED'and v['release']=='NOT_ADMITTED','same finite budget and scope')
 return v

def command_join(v,commands):
 argv=['/usr/bin/python3','-I','-B','/source/interrupted.py','--owned-parent',str(v['owner_parent'])]
 rows=[r for r in commands if r['argv']==argv]
 S.need(len(rows)==1,'one exact original interrupted command');row=rows[0];raw=S.encoded(v)
 S.need(row['exit_code']==0 and row['group_absence_verified']is True and type(row['time_limit'])in(int,float)and 0<row['time_limit']<=S.COMMAND_SECONDS and type(row['seconds'])in(int,float)and 0<=row['seconds']<=row['time_limit']+6 and row['output_limit']==128*1024,'natural bounded interrupted command retirement')
 S.need(row['stdout_bytes']==len(raw)and row['stdout_sha256']==S.sha(raw)and row['stderr_bytes']==0 and row['stderr_sha256']==S.sha(b''),'complete original interruption stdout/stderr join');return row

if __name__=='__main__':
 S.need(len(sys.argv)==3 and sys.argv[1]=='--owned-parent'and sys.argv[2].isdigit(),'explicit owned guest parent required')
 with Path('/workspace/selection.json').open('rb')as stream:raw=stream.read(2*1024**2+1)
 S.need(len(raw)<=2*1024**2,'bounded original selection')
 def pairs(rows):
  value={}
  for k,v in rows:S.need(k not in value,'duplicate selection key');value[k]=v
  return value
 selection=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:S.need(False,'finite selection'))
 sys.stdout.buffer.write(S.encoded(experiment(selection,int(sys.argv[2]))))
