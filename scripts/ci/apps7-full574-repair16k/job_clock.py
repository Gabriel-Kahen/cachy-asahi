#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Fixed source-owned current-job capacity clock; no API, realtime or actors."""
import argparse,hashlib,json,math,os,re,stat,time
from pathlib import Path
PROFILE='REPAIR_GENERIC16K_COLD_VALIDATION_2400_V1'
JOB=21000;POST=1260;ADMISSION=120;KILL=30;OWNER_MARGIN=90
NAME='apps574-repair16k-capacity-clock.json'
def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def identity():
 values={k:os.environ[k]for k in('GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','SOURCE_SHA')}
 need(all(re.fullmatch('[1-9][0-9]{0,19}',values[k])for k in('GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT'))and re.fullmatch('[a-f0-9]{40}',values['SOURCE_SHA']),'exact current workflow identifiers')
 return dict(run=int(values['GITHUB_RUN_ID']),attempt=int(values['GITHUB_RUN_ATTEMPT']),source=values['SOURCE_SHA'])
def path():
 p=Path(os.environ['RUNNER_TEMP'])/NAME
 need(p.is_absolute()and not any(q.is_symlink()for q in(p,*p.parents)),'ordinary fixed current-job clock path');return p

def validate(value,expected,now):
 need(type(value)is dict and set(value)=={'schema_version','purpose','profile','identity','start_monotonic_ns','job_seconds','post_seconds','admission_seconds'},'closed capacity stamp')
 need(value['schema_version']==1 and type(value['schema_version'])is int and value['purpose']=='SOURCE_OWNED_FIRST_WORKFLOW_STEP_NOT_API_TIME'and value['profile']==PROFILE and value['identity']==expected and type(value['start_monotonic_ns'])is int and 0<value['start_monotonic_ns']<=now,'genuine current job/source and monotonic clock order')
 need((value['job_seconds'],value['post_seconds'],value['admission_seconds'])==(JOB,POST,ADMISSION),'fixed job and untouched post-trial reservations')
 elapsed=now-value['start_monotonic_ns'];need(elapsed<=JOB*10**9,'current bounded job clock')
 return value['start_monotonic_ns']+(JOB-POST-ADMISSION)*10**9

def read():
 p=path();a=p.lstat();need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_uid==os.getuid()and stat.S_IMODE(a.st_mode)==0o600 and 0<a.st_size<=4096,'private ordinary job stamp');raw=p.read_bytes();b=p.lstat();need((a.st_dev,a.st_ino,a.st_size,a.st_ctime_ns,a.st_mtime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_ctime_ns,b.st_mtime_ns),'job stamp drift');v=json.loads(raw);now=time.monotonic_ns();deadline=validate(v,identity(),now);return raw,v,now,deadline

def trial(first,now,reserved):
 p=path().with_name(NAME+'.trial');a=p.lstat();need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_uid==os.getuid()and stat.S_IMODE(a.st_mode)==0o600 and 0<a.st_size<=4096,'private ordinary trial-entry receipt');raw=p.read_bytes();b=p.lstat();need((a.st_dev,a.st_ino,a.st_size,a.st_ctime_ns,a.st_mtime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_ctime_ns,b.st_mtime_ns),'trial entry drift');v=json.loads(raw);validate_trial(v,first,now,reserved);return raw,v

def validate_trial(v,first,now,reserved):
 need(type(v)is dict and set(v)=={'schema_version','profile','first_stamp_pin','entry_monotonic_ns','term_seconds','term_deadline_monotonic_ns','kill_seconds','step_seconds'},'closed source-owned trial entry')
 need(v['schema_version']==1 and v['profile']==PROFILE and v['first_stamp_pin']==dict(bytes=len(first),sha256=hashlib.sha256(first).hexdigest()) and type(v['entry_monotonic_ns'])is int and json.loads(first)['start_monotonic_ns']<=v['entry_monotonic_ns']<=now,'same initial stamp and monotonic trial-entry order')
 seconds=min(18550,math.floor((reserved-v['entry_monotonic_ns'])/10**9)-KILL)
 need(type(v['term_seconds'])is int and v['term_seconds']==seconds and seconds>0 and v['term_deadline_monotonic_ns']==v['entry_monotonic_ns']+seconds*10**9 and v['kill_seconds']==30 and v['step_seconds']==18600 and seconds+30<=18600,'fixed trial TERM/KILL/step margins and original post-reserve')
 return v['term_deadline_monotonic_ns']

def selected_owner():
 raw,v,now,deadline=read();trial_raw,entry=trial(raw,now,deadline);protective=min(deadline,entry['term_deadline_monotonic_ns']);seconds=min(18000,(protective-now)/10**9-OWNER_MARGIN)
 need(seconds>=3000,'insufficient reserved capacity before media or VM actors')
 return dict(profile=PROFILE,trial_entry=entry,trial_entry_pin=dict(bytes=len(trial_raw),sha256=hashlib.sha256(trial_raw).hexdigest()),protective_deadline_monotonic_ns=protective,stamp=v,stamp_pin=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()),read_monotonic_ns=now,reserved_deadline_monotonic_ns=deadline,selected_seconds=seconds,owner_deadline_monotonic_ns=now+int(seconds*10**9),owner_margin_seconds=OWNER_MARGIN,backend_seconds=2400,caller_seconds=2410,old600_fit='NOT_ESTABLISHED',performance='NOT_CLAIMED',hardware='NOT_RUN')

def main():
 p=argparse.ArgumentParser();p.add_argument('mode',choices=('remaining','owner'));a=p.parse_args()
 if a.mode=='owner':print(encoded(selected_owner()).decode(),end='')
 else:
  raw,v,now,deadline=read();seconds=min(18550,math.floor((deadline-now)/10**9)-KILL);need(seconds>0,'reserved job deadline before command')
  entry=dict(schema_version=1,profile=PROFILE,first_stamp_pin=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()),entry_monotonic_ns=now,term_seconds=seconds,term_deadline_monotonic_ns=now+seconds*10**9,kill_seconds=30,step_seconds=18600)
  fd=os.open(path().with_name(NAME+'.trial'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb')as f:f.write(encoded(entry))
  print(seconds)
if __name__=='__main__':main()
