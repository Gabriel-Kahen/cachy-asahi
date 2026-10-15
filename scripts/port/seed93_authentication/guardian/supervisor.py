#!/usr/bin/env python3
"""Private admitted cleanup extraction; no standalone execution entry point.
Caller must require the external GNU guardian and pass work_seconds=None.
"""
import hashlib,json,os,signal,stat,subprocess,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
WORK_SECONDS=1800;CLEANUP_SECONDS=10

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def save(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')

def directory(path):
 s=path.lstat()
 if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.getuid() or s.st_mode&0o077 or any(p.is_symlink() for p in (path,*path.parents)):raise ValueError('owned directory required')

def group_exists(pgid):
 try:os.killpg(pgid,0);return True
 except ProcessLookupError:return False

def supervise(argv,destination,work_seconds=WORK_SECONDS,cleanup_seconds=CLEANUP_SECONDS):
 """One owned session; exceptional cleanup cannot renew work or erase first cause."""
 directory(destination)
 entered=time.monotonic();work_end=None if work_seconds is None else entered+work_seconds
 end=None if work_end is None else work_end+cleanup_seconds
 record=dict(status='FAIL',entered_monotonic=entered,work_end=work_end,end=end,
  work_seconds=work_seconds,cleanup_seconds=cleanup_seconds,first_failure=None,
  cancelled=False,signals_sent=[],cleanup_notes=[],cleanup_uncertainty=False,
  natural_exit=False,cleanup_verified=False,returncode=None)
 process=None;pgid=None;original=None;observed_returncode=None;custody=False;previous={};out=None;err=None
 def fail(kind):
  if record['first_failure'] is None:record['first_failure']=kind
 def fault(error,where):
  nonlocal original
  record['cleanup_uncertainty']=True;record['cleanup_notes'].append(where)
  record['cancelled']=record['cancelled'] or issubclass(type(error),(KeyboardInterrupt,SystemExit))
  fail('cleanup-unverified')
  if original is None:original=error
 def owned_exit():
  nonlocal custody
  try:info=os.waitid(os.P_PID,process.pid,os.WEXITED|os.WNOWAIT|os.WNOHANG)
  except BaseException:
   custody=False;record['cleanup_uncertainty']=True;fail('child-custody-lost');raise
  if info is not None and (info.si_pid!=process.pid or info.si_code not in (os.CLD_EXITED,os.CLD_KILLED,os.CLD_DUMPED)):
   custody=False;record['cleanup_uncertainty']=True;fail('child-custody-lost');raise ValueError('owned child exit identity refused')
  return info
 def interrupted(number,frame):raise KeyboardInterrupt('owned envelope signal')
 try:
  for sig in (signal.SIGINT,signal.SIGTERM):previous[sig]=signal.signal(sig,interrupted)
  out=(destination/'stdout').open('xb');err=(destination/'stderr').open('xb')
  spawning_mask=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
  spawn_error=None
  try:
   process=subprocess.Popen(['/usr/bin/python3','-I','-B',str(HERE/'child_entry.py'),str(os.getpid()),*argv],stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True,close_fds=True,env={'PATH':'/usr/bin:/bin','LC_ALL':'C.UTF-8','LANG':'C.UTF-8'})
   pgid=process.pid;custody=True;record['owned_pgid']=pgid
  except BaseException as error:
   spawn_error=error
   raise
  finally:
   try:signal.pthread_sigmask(signal.SIG_SETMASK,spawning_mask)
   except BaseException as error:
    record['cleanup_uncertainty']=True;record['cleanup_notes'].append('spawn-mask-restoration')
    record['cancelled']=record['cancelled'] or issubclass(type(error),(KeyboardInterrupt,SystemExit))
    if spawn_error is None:raise
  while True:
   info=owned_exit()
   if info is not None:
    observed_returncode=info.si_status if info.si_code==os.CLD_EXITED else -info.si_status
    record['natural_exit']=True
    if observed_returncode:fail('child-return')
    break
   if work_end is not None and time.monotonic()>=work_end:fail('work-deadline');break
   time.sleep(.02 if work_end is None else min(.02,max(0,work_end-time.monotonic())))
 except BaseException as error:
  original=error;record['cancelled']=record['cancelled'] or issubclass(type(error),(KeyboardInterrupt,SystemExit))
  fail('cancelled' if issubclass(type(error),(KeyboardInterrupt,SystemExit)) else 'spawn-or-wait-refused')
 finally:
  blocked=None
  try:blocked=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
  except BaseException as error:fault(error,'cleanup-mask')
  cleanup_end=None
  try:
   now=time.monotonic();cleanup_end=now+cleanup_seconds if end is None else min(end,now+cleanup_seconds)
  except BaseException as error:fault(error,'cleanup-clock')
  def remaining():
   if cleanup_end is None:return 0
   try:return max(0,cleanup_end-time.monotonic())
   except BaseException as error:fault(error,'cleanup-clock');return 0
  def group():
   try:return group_exists(pgid)
   except BaseException as error:fault(error,'group-probe');return None
  def send(number,label):
   # Single waiter retains the leader through the last signal. Once any
   # custody observation fails, no later observation reauthorizes a signal.
   if not custody:return
   try:
    owned_exit()
    os.killpg(pgid,number);record['signals_sent'].append(label)
   except ProcessLookupError:pass
   except BaseException as error:fault(error,'signal-'+label)
  if process is not None:
   unreaped=False
   try:unreaped=process.returncode is None
   except BaseException as error:fault(error,'returncode-before-cleanup');custody=False
   if unreaped and custody:
    try:owned_exit()
    except BaseException as error:fault(error,'cleanup-custody')
    send(signal.SIGTERM,'TERM')
    # Grace consumes the fixed cleanup endpoint; no restarted work timer.
    grace=remaining()/2
    try:grace_end=time.monotonic()+grace
    except BaseException as error:fault(error,'grace-clock');grace_end=None
    while grace_end is not None:
     try:
      left=min(remaining(),max(0,grace_end-time.monotonic()))
      if left<=0 or group() is not True:break
      time.sleep(min(.02,left))
     except BaseException as error:fault(error,'grace-wait');break
    if group() is not False:send(signal.SIGKILL,'KILL')
   elif not unreaped:
    custody=False  # Never signal a numeric group whose leader was reaped.
   # Attempt reaping even when an earlier mask, signal or probe failed.
   try:process.wait(timeout=remaining())
   except BaseException as error:fault(error,'child-wait')
   custody=False  # Final signal phase is permanently closed before probes.
   try:record['returncode']=process.returncode
   except BaseException as error:fault(error,'returncode-after-cleanup')
   absent=False
   while True:
    try:
     absent=group_exists(pgid) is False
     if absent:break
     left=remaining()
     if left<=0:break
     time.sleep(min(.02,left))
    except BaseException as error:fault(error,'final-group-probe-or-wait');break
   record['cleanup_verified']=record['returncode'] is not None and absent and not record['cleanup_uncertainty']
   if record['natural_exit'] and record['returncode']!=observed_returncode:
    record['cleanup_verified']=False;record['cleanup_uncertainty']=True;fail('child-custody-lost')
   if not record['cleanup_verified']:fail('cleanup-unverified')
  else:fail('spawn-refused')
  for label,stream in [('stderr-close',err),('stdout-close',out)]:
   if stream is not None:
    try:stream.close()
    except BaseException as error:fault(error,label)
  if blocked is not None:
   try:signal.pthread_sigmask(signal.SIG_SETMASK,blocked)
   except BaseException as error:fault(error,'cleanup-mask-restoration')
  for sig,handler in previous.items():
   try:signal.signal(sig,handler)
   except BaseException as error:fault(error,'handler-restoration-'+str(sig))
  try:
   record['ended_monotonic']=time.monotonic()
   record['within_envelope']=None if end is None else record['ended_monotonic']<=end
  except BaseException as error:
   fault(error,'terminal-clock');record['ended_monotonic']=None;record['within_envelope']=False
  record['scope']='CHILD_CLEANUP_ONLY; guardian exit required for whole invocation'
  record['whole_invocation_acceptance']='EXTERNAL_GUARDIAN_EXIT_REQUIRED'
  if record['within_envelope'] is False:fail('aggregate-envelope')
  if record['cleanup_uncertainty']:record['cleanup_verified']=False
  record['status']='PASS_PROCESS_ENVELOPE' if record['first_failure'] is None and record['cleanup_verified'] and record['returncode']==0 else 'FAIL'
  try:save(destination/'process.json',dict(record,status='CHILD_CLEANUP_CHECKPOINT_ONLY',within_envelope=None))
  except BaseException as error:fault(error,'checkpoint-retention');record['cleanup_verified']=False;record['status']='FAIL'
 # Late retention can fail or consume the endpoint; it cannot upgrade a result.
 try:
  record['ended_monotonic']=time.monotonic()
  record['within_envelope']=None if end is None else record['ended_monotonic']<=end
  if record['within_envelope'] is False:fail('aggregate-envelope');record['status']='FAIL'
 except BaseException as error:fault(error,'post-retention-clock');record['status']='FAIL'
 if original is not None:raise original
 return record
