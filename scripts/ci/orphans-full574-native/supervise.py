#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Selected Orphans outer process retirement; inner cleanup remains authoritative."""
import argparse,hashlib,json,os,signal,stat,subprocess,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
CAP=16384

def need(ok,why):
 if not ok:raise ValueError(why)
def process(pid):
 raw=Path('/proc/'+str(pid)+'/stat').read_text();tail=raw.rsplit(')',1)[1].split()
 return dict(pid=pid,pgid=int(tail[2]),sid=int(tail[3]),start=int(tail[19]))
def same(child,identity):
 need(process(child.pid)==identity,'unreaped owned job identity changed')
def handoff(argv,receipt,identity):
 need(receipt.is_absolute() and not any(p.is_symlink() for p in (receipt,*receipt.parents)) and receipt.parent.stat().st_uid==os.getuid(),'owned ordinary handoff path')
 fd=os.open(receipt,os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_CLOEXEC|os.O_NOFOLLOW,0o600);held=os.fstat(fd);child=None;pending=[];old={};events=[];started=time.monotonic();report=dict(schema_version=1,status='RUNNING_NOT_CLEANUP_AUTHORITY',identity=identity,job=None,group_absent=False,direct_reaped=False,inner_actors='NOT_OBSERVED_OR_RETIRED_BY_OUTER_SUPERVISOR')
 def save():
  current=receipt.lstat();need(stat.S_IMODE(current.st_mode)==0o600,'exact private0600 handoff mode');need((current.st_dev,current.st_ino,current.st_uid,current.st_nlink)==(held.st_dev,held.st_ino,os.getuid(),1),'handoff named identity changed')
  raw=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode();need(len(raw)<=CAP,'bounded outer handoff receipt');os.ftruncate(fd,0);need(os.pwrite(fd,raw,0)==len(raw),'complete handoff write');os.fsync(fd)
 def incoming(number,_):
  if not pending:pending.append(number)
 def send(number):
  same(child,report['job'])
  try:os.killpg(child.pid,number);events.append(int(number))
  except ProcessLookupError:pass
 def observed():return os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is not None
 try:
  save()
  for number in (signal.SIGINT,signal.SIGTERM):old[number]=signal.signal(number,incoming)
  child=subprocess.Popen(list(map(str,argv)),stdin=subprocess.DEVNULL,start_new_session=True,close_fds=True);report['job']=process(child.pid);need(report['job']['pgid']==report['job']['sid']==child.pid,'fresh exact owned job session');save()
  while not observed() and not pending:time.sleep(.02)
  cancellation=time.monotonic() if pending else None
  if pending:
   send(pending[0]);end=time.monotonic()+1.5
   while not observed() and time.monotonic()<end:time.sleep(.02)
  # Even an already exited, unreaped leader pins its PGID through final signals.
  send(signal.SIGTERM);end=time.monotonic()+1.5
  while not observed() and time.monotonic()<end:time.sleep(.02)
  send(signal.SIGKILL);code=child.wait(timeout=1);report.update(exit_code=code,direct_reaped=True)
  end=time.monotonic()+1
  while True:
   try:os.killpg(child.pid,0)
   except ProcessLookupError:report['group_absent']=True;break
   if time.monotonic()>=end:break
   time.sleep(.02)
  report.update(signals=events,cancellation_signal=pending[0] if pending else None,cancellation_seconds=None if cancellation is None else round(time.monotonic()-cancellation,6),seconds=round(time.monotonic()-started,6))
  need(report['group_absent'],'outer job group absence unproved')
  report['status']='DIRECT_JOB_REAPED_GROUP_ABSENT_INNER_CLEANUP_STILL_REQUIRED';save()
  return report
 except BaseException as error:
  if child is not None and child.returncode is None and report['job'] is not None:
   try:
    send(signal.SIGTERM);send(signal.SIGKILL);child.wait(timeout=1);report['direct_reaped']=True
   except BaseException as retirement:report['retirement_error']=type(retirement).__name__
  report.update(status='FAIL_OUTER_RETIREMENT_UNKNOWN',error_type=type(error).__name__,error=str(error)[:256]);save();print('ORPHANS_JOB_HANDOFF '+json.dumps(report,sort_keys=True,separators=(',',':')),flush=True);raise
 finally:
  for number,handler in old.items():signal.signal(number,handler)
  os.close(fd)

def binding(args,C):
 C.source(args.source);raw=C.read(args.proof,65536);proof=C.decode(raw)
 need(proof['trial']==args.trial and proof['source_sha']==os.environ['SOURCE_SHA'] and proof['source_sha']==os.environ['GITHUB_WORKFLOW_SHA'] and proof['source_sha']==os.environ['GITHUB_SHA'],'exact selected current job source/trial')
 return dict(source_sha=proof['source_sha'],trial=args.trial,proof_sha256=hashlib.sha256(raw).hexdigest(),consumer_token=proof['consumer_token'],producer_token=proof['job_token'])
def check(receipt,identity,never_started=False):
 if never_started:
  need(not receipt.exists() and not receipt.is_symlink(),'a started or uncertain job cannot use never-started handoff');return
 info=receipt.lstat();need(not any(p.is_symlink() for p in (receipt,*receipt.parents)) and stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1 and info.st_uid==os.getuid() and info.st_size<=CAP,'original owned bounded job handoff')
 value=json.loads(receipt.read_bytes());need(value['identity']==identity and value['status']=='DIRECT_JOB_REAPED_GROUP_ABSENT_INNER_CLEANUP_STILL_REQUIRED' and value['direct_reaped'] is True and value['group_absent'] is True and type(value['job']['pid']) is int and value['job']['pid']>1 and value['job']['pid']==value['job']['pgid']==value['job']['sid'] and value['job']['start']>0,'exact direct job retirement before nonblocking lease cleanup')
 try:os.killpg(value['job']['pid'],0)
 except ProcessLookupError:return
 raise ValueError('retired outer group is present; cleanup refused')

def workflow(text):
 """Exactly three outer wiring edits, after the unchanged mode transformer."""
 edits=(('      - name: Actual native574 Apps copied-root transactions\n','      - name: Actual native574 Apps copied-root transactions\n        id: orphan_trial\n'),('python3 -I -B "$SLICE/job.py" run --trial "$TRIAL" --source "$GITHUB_WORKSPACE"','python3 -I -B "$SLICE/supervise.py" run --handoff "$RUNNER_TEMP/orphans-job-handoff.json" --trial "$TRIAL" --source "$GITHUB_WORKSPACE"'),('python3 -I -B "$SLICE/job.py" cleanup --trial "$TRIAL" --source "$GITHUB_WORKSPACE"',"python3 -I -B \"$SLICE/supervise.py\" cleanup --handoff \"$RUNNER_TEMP/orphans-job-handoff.json\" --job-outcome '${{ steps.orphan_trial.outcome }}' --trial \"$TRIAL\" --source \"$GITHUB_WORKSPACE\""))
 for before,after in edits:need(text.count(before)==1,'one fixed selected-job workflow seam');text=text.replace(before,after)
 return text

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=('run','check','cleanup'));p.add_argument('--trial',choices=('normal','interruption'),required=True);p.add_argument('--never-started',action='store_true');p.add_argument('--job-outcome',choices=('success','failure','cancelled','skipped'));p.add_argument('--receipt',type=Path)
 for name in ('source','packet','proof','base','output','handoff'):p.add_argument('--'+name,type=Path,required=name!='packet')
 a=p.parse_args();sys.path.insert(0,str(HERE));import contract as C
 identity=binding(a,C)
 if a.mode=='check':check(a.handoff,identity,a.never_started);return 0
 if a.mode=='cleanup':
  need(a.job_outcome is not None and a.receipt is not None and not a.never_started,'exact workflow job outcome and original cleanup receipt required');check(a.handoff,identity,a.job_outcome=='skipped')
  os.execv('/usr/bin/python3',['/usr/bin/python3','-I','-B',str(HERE/'job.py'),'cleanup','--trial',a.trial,'--source',str(a.source),'--proof',str(a.proof),'--base',str(a.base),'--output',str(a.output),'--receipt',str(a.receipt)])
 need(not a.never_started and a.packet is not None,'fixed selected job inputs only');argv=['/usr/bin/python3','-I','-B',str(HERE/'job.py'),'run','--trial',a.trial,'--source',str(a.source),'--packet',str(a.packet),'--proof',str(a.proof),'--base',str(a.base),'--output',str(a.output)];value=handoff(argv,a.handoff,identity)
 print('ORPHANS_JOB_HANDOFF '+json.dumps(value,sort_keys=True,separators=(',',':')),flush=True)
 return 128+value['cancellation_signal'] if value['cancellation_signal'] is not None else value['exit_code'] if value['exit_code']>=0 else 128-value['exit_code']
if __name__=='__main__':raise SystemExit(main())
