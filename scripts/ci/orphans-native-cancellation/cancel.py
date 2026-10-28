#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""One owned native-job SIGINT component, never a transaction-matrix result."""
import argparse,errno,fcntl,hashlib,importlib.util,json,os,resource,signal,stat,subprocess,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
LANE='scripts/ci/orphans-full574-native'
CAP=1024**2
STATUS='PASS_NATIVE_OUTER_SIGINT_HANDOFF_AND_ORDERED_CLEANUP_COMPONENT_ONLY'

def need(ok,why):
 if not ok:raise ValueError(why)
def decode(raw):
 def pairs(rows):
  value={}
  for k,v in rows:need(k not in value,'duplicate component JSON key');value[k]=v
  return value
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite component JSON'))
def relative(n):
 need(type(n) is str and n and '\0' not in n and not n.startswith('/') and '\\' not in n and all(x not in ('','.','..') for x in n.split('/')),'ordinary closed relative path');return n
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
def read(path,cap=CAP):
 need(not any(p.is_symlink() for p in (path,*path.parents)),'ordinary component path');a=path.stat();need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<=cap,'bounded single-link component file');raw=path.read_bytes();b=path.stat();need((a.st_dev,a.st_ino,a.st_mode,a.st_uid,a.st_gid,a.st_nlink,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_mode,b.st_uid,b.st_gid,b.st_nlink,b.st_size,b.st_mtime_ns,b.st_ctime_ns) and len(raw)==a.st_size,'component read drift');return raw
def source(root):
 manifest=decode(read(HERE/'source-manifest.json'));need(manifest['status']=='FROZEN_ORPHANS_NATIVE_CANCELLATION_COMPONENT_SOURCE' and len(manifest['files'])==126,'exact original121 plus finite component closure required')
 for n,row in manifest['files'].items():
  need(n and '\0' not in n and not n.startswith('/') and '\\' not in n and all(x not in ('','.','..') for x in n.split('/')),'source reference path');need(pin(read(root/n,16*CAP))==row,'component source differs: '+n)
 C=load('cancellation_original_contract',root/LANE/'contract.py');C.source(root);return C,load('cancellation_original_supervisor',root/LANE/'supervise.py')
def file_id(s):return dict(device=s.st_dev,inode=s.st_ino,mode=stat.S_IMODE(s.st_mode),uid=s.st_uid,gid=s.st_gid,links=s.st_nlink,kind='directory' if stat.S_ISDIR(s.st_mode) else 'file')
def held_lease(path,pid,directory=False):
 """Read only our child's FD lock rows, and independently observe contention."""
 need(not any(p.is_symlink() for p in (path,*path.parents)),'no lease aliases');fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|(os.O_DIRECTORY if directory else 0))
 try:
  info=os.fstat(fd);need(file_id(info)==file_id(path.stat()) and info.st_uid==os.getuid() and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600),'exact owned named lease identity')
  matched=[];entries=list(Path('/proc/'+str(pid)+'/fd').iterdir());need(len(entries)<=256,'bounded owned job descriptors')
  for entry in entries:
   try:
    value=entry.stat()
    if (value.st_dev,value.st_ino)!=(info.st_dev,info.st_ino):continue
    raw=(Path('/proc/'+str(pid)+'/fdinfo')/entry.name).read_bytes();need(len(raw)<=4096,'bounded owned descriptor lock record')
   except FileNotFoundError:continue
   for line in raw.decode().splitlines():
    fields=line.split()
    if len(fields)==9 and fields[0]=='lock:' and fields[2:5]==['FLOCK','ADVISORY','WRITE'] and fields[5]==str(pid):
     dev=fields[6].split(':');need(len(dev)==3,'kernel lock device identity')
     if (int(dev[0],16),int(dev[1],16),int(dev[2]))==(os.major(info.st_dev),os.minor(info.st_dev),info.st_ino):matched.append(line)
  need(len(matched)==1,'exact job PID-owned exclusive lease not observed')
  try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:pass
  else:fcntl.flock(fd,fcntl.LOCK_UN);raise ValueError('owned job lease unexpectedly available')
  need(file_id(os.fstat(fd))==file_id(path.stat()),'lease identity drift')
  return dict(path=str(path),identity=file_id(info),owner_pid=pid,lock=matched[0],contended=True)
 finally:os.close(fd)
def released(path,before,directory=False):
 fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|(os.O_DIRECTORY if directory else 0))
 try:
  need(file_id(os.fstat(fd))==before['identity']==file_id(path.stat()),'retired lease named identity changed');fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
 finally:os.close(fd)
def inspect_actor(name,temporary):
 # A separate readonly Docker inspect child only; its file cap never reaches the trial.
 with temporary.open('xb') as stream:
  row=subprocess.run(['/usr/bin/docker','container','inspect',name],stdout=stream,stderr=stream,timeout=10,preexec_fn=lambda:resource.setrlimit(resource.RLIMIT_FSIZE,(CAP,CAP)))
 raw=read(temporary);temporary.unlink()
 if row.returncode:
  text=raw.decode(errors='replace').lower();need(row.returncode==1 and name.lower() in text and ('no such container' in text or 'no such object' in text),'unknown native actor inspect');return None
 value=decode(raw);need(type(value) is list and len(value)==1,'one exact native actor');return value[0]
def phase(actors):
 need([r['role'] for r in actors]==['export','extract','signer','lifecycle'] and [r['status'] for r in actors]==['PASS_ABSENCE_VERIFIED','EXITED','PASS_ABSENCE_VERIFIED','RESERVED'] and actors[1].get('exit')==0 and actors[2].get('exit')==0 and actors[-1]['id'] is None,'exact original live phase export-absent extract-exited0 signer-absent lifecycle-reserved required')
 return actors[1]
def extract_record(value):
 state=value['state'];need(state['Status']=='exited' and state['Running'] is False and state['Pid']==0 and state['ExitCode']==0 and state['Error']=='' and all(state[k] is False for k in ('Paused','Restarting','OOMKilled','Dead')) and not state['StartedAt'].startswith('0001-') and not state['FinishedAt'].startswith('0001-') and value['restart_count']==0,'original extract must have naturally exited0 and remain nonrunning')
 expected=dict(Privileged=False,ReadonlyRootfs=True,NetworkMode='none',CapDrop=['ALL'],CapAdd=['CAP_CHOWN','CAP_DAC_OVERRIDE','CAP_FOWNER','CAP_FSETID','CAP_SETFCAP'],SecurityOpt=['no-new-privileges'],Memory=4*1024**3,NanoCpus=2000000000,PidsLimit=128,Ulimits=[dict(Name='nofile',Hard=8192,Soft=8192)])
 need(value['apparmor']=='docker-default' and value['security']==expected and value['command']==dict(User='0:0',Entrypoint=['/usr/bin/python3'],Cmd=['-I','-B','/source/'+LANE+'/snapshot.py']),'unchanged exact extract security/resource/command identity required');return value

def native_ready(args,C,S,child,supervisor,identity):
 S.same(child,supervisor)
 if not args.handoff.exists() or not (args.output/'owner.json').exists():return None
 try:handoff=decode(read(args.handoff,16384));owner=decode(read(args.output/'owner.json',4*CAP))
 except json.JSONDecodeError:return None # Original command recorder may be between finite writes.
 except ValueError as error:
  if str(error)=='component read drift':return None
  raise
 need(handoff['identity']==identity and handoff['status']=='RUNNING_NOT_CLEANUP_AUTHORITY' and handoff['job'] is not None,'original running supervisor/job identity required')
 job=handoff['job'];need(S.process(job['pid'])==job and job['pid']==job['pgid']==job['sid'],'live original job session required')
 need(owner['source_sha']==identity['source_sha'] and owner['trial']=='normal' and owner['token']==identity['consumer_token'] and owner['producer_token']==identity['producer_token'],'actual owner binding')
 actors=owner['actors']
 if not actors or actors[-1]['role']!='lifecycle':return None
 extract=phase(actors)
 name='caa-apps574-'+identity['consumer_token']+'-lifecycle';need(actors[-1]['name']==name,'exact declared live actor')
 value=inspect_actor(name,args.component/'inspect.pending')
 if value is None:return None
 api=C.load('cancellation_unchanged_owner_api',args.source/'scripts/ci/glibc-gnu-provider-lifecycle-owner/job.py');cid=api.verify_actor(value,name,owner['image'],C.LABEL,owner['token'],actors[-1]['id'])
 extract_name='caa-apps574-'+identity['consumer_token']+'-extract';need(extract['name']==extract_name,'exact prior extract name')
 extracted=inspect_actor(extract_name,args.component/'extract-inspect.pending');need(extracted is not None,'original exited extract must remain present until original cleanup');extract_id=api.verify_actor(extracted,extract_name,owner['image'],C.LABEL,owner['token'],extract['id'])
 extract_proof=extract_record(dict(id=extract_id,name=extract_name,image=owner['image'],label=C.LABEL,token=owner['token'],state=extracted['State'],restart_count=extracted['RestartCount'],apparmor=extracted['AppArmorProfile'],security={k:extracted['HostConfig'][k] for k in ('Privileged','ReadonlyRootfs','NetworkMode','CapDrop','CapAdd','SecurityOpt','Memory','NanoCpus','PidsLimit','Ulimits')},command={k:extracted['Config'][k] for k in ('User','Entrypoint','Cmd')}))
 need(value['State']['Running'] is True and value['State']['Pid']>0 and value['State']['Paused'] is False,'actual lifecycle actor must be running')
 leases=dict(producer=held_lease(args.base,job['pid'],True),owner=held_lease(args.output/'owner.lock',job['pid']))
 S.same(child,supervisor);need(S.process(job['pid'])==job,'job drift before owned cancellation')
 return dict(status='ACTUAL_LIFECYCLE_RUNNING_WITH_BOTH_JOB_OWNED_LEASES',identity=identity,supervisor=supervisor,job=job,actor=dict(id=cid,name=name,image=owner['image'],label=C.LABEL,token=owner['token'],state=value['State'],apparmor=value['AppArmorProfile']),leases=leases,extract=extract_proof,source_snapshot=pin(read(args.output/'snapshot-public/snapshot.json',4*CAP)),held_payloads=pin(read(args.output/'inputs/held-payloads.json',256*1024)))
def run(args,C,S):
 C.safe(args.component);need(args.component.is_absolute() and not args.component.exists() and args.component.parent.stat().st_uid==os.getuid(),'fresh private cancellation component directory');args.component.mkdir(mode=0o700);identity=S.binding(args,C)
 argv=['/usr/bin/python3','-I','-B',str(args.source/LANE/'supervise.py'),'run','--trial','normal']
 for n in ('source','packet','proof','base','output','handoff'):argv+=['--'+n,str(getattr(args,n))]
 report=dict(status='FAIL_NATIVE_CANCELLATION_COMPONENT',identity=identity,normal_matrix='NOT_CLAIMED',rollback='NOT_CLAIMED',commit_outcome='UNKNOWN',source_sha=identity['source_sha']);child=None;supervisor=None;started=time.monotonic()
 try:
  child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,start_new_session=True,close_fds=True);supervisor=S.process(child.pid);need(supervisor['pid']==supervisor['pgid']==supervisor['sid'],'owned supervisor session')
  end=started+3540 # Reserve original supervisor retirement inside unchanged3550 outer.
  while time.monotonic()<end:
   need(child.poll() is None,'trial ended before positively observed cancellation point');before=native_ready(args,C,S,child,supervisor,identity)
   if before is not None:break
   time.sleep(.2)
  else:raise ValueError('native cancellation point not reached within original outer envelope')
  (args.component/'before.json').write_bytes(encoded(before));S.same(child,supervisor);os.kill(child.pid,signal.SIGINT)
  code=child.wait(timeout=8);need(code==130,'exact original supervisor SIGINT status required');S.check(args.handoff,identity);handoff=decode(read(args.handoff,16384))
  need(handoff['cancellation_signal']==signal.SIGINT and handoff['signals'][0]==signal.SIGINT and handoff['job']==before['job'] and 0<=handoff['cancellation_seconds']<=6,'typed original SIGINT handoff required')
  released(args.base,before['leases']['producer'],True);released(args.output/'owner.lock',before['leases']['owner'])
  (args.component/'handoff.json').write_bytes(read(args.handoff,16384));report.update(status='OBSERVED_NATIVE_SIGINT_HANDOFF_ORDERED_CLEANUP_STILL_REQUIRED',before=pin(read(args.component/'before.json')),handoff=pin(read(args.component/'handoff.json')),supervisor_exit=code,leases_released=True,seconds=round(time.monotonic()-started,6))
 except BaseException as error:
  report.update(error_type=type(error).__name__,error=str(error)[:512]);raise
 finally:
  if child is not None and child.poll() is None:
   S.same(child,supervisor);os.kill(child.pid,signal.SIGTERM)
   try:child.wait(timeout=8)
   except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=1)
  (args.component/'run.json').write_bytes(encoded(report))
 return report

def validate(value,identity):
 need(value['status']==STATUS and value['identity']==identity and value['signal']==signal.SIGINT and value['normal_matrix']=='NOT_CLAIMED' and value['transaction_outcome']=='UNKNOWN' and value['rollback']=='NOT_CLAIMED' and value['hardware']=='NOT_RUN' and value['release']=='NOT_ADMITTED','strict cancellation component scope required')
 before=value['actual_live_before'];h=value['original_handoff'];need(before['status']=='ACTUAL_LIFECYCLE_RUNNING_WITH_BOTH_JOB_OWNED_LEASES' and before['identity']==h['identity']==identity and before['job']==h['job'],'before/live and original handoff join')
 need(h['status']=='DIRECT_JOB_REAPED_GROUP_ABSENT_INNER_CLEANUP_STILL_REQUIRED' and h['direct_reaped'] is True and h['group_absent'] is True and h['cancellation_signal']==signal.SIGINT and h['signals'][0]==signal.SIGINT and 0<=h['cancellation_seconds']<=6,'typed original SIGINT retirement required')
 job=h['job'];need(job['pid']==job['pgid']==job['sid'] and job['pid']>1 and job['start']>0,'exact original job identity')
 actor=before['actor'];need(actor['name']=='caa-apps574-'+identity['consumer_token']+'-lifecycle' and actor['token']==identity['consumer_token'] and actor['label']=='org.cachy-asahi.orphans-full574-native' and actor['apparmor']=='docker-default' and actor['state']['Running'] is True and actor['state']['Pid']>0 and actor['state']['Paused'] is False,'genuine owned native lifecycle readiness record')
 extract=extract_record(before['extract']);need(extract['name']=='caa-apps574-'+identity['consumer_token']+'-extract' and extract['image']==actor['image'] and extract['label']==actor['label'] and extract['token']==identity['consumer_token'],'original extract CID/image/token/security proof required')
 need(set(before['leases'])=={'producer','owner'} and all(v['contended'] is True and v['owner_pid']==job['pid'] and v['identity']['uid']>=0 for v in before['leases'].values()),'both actual job-owned lease observations required')
 cleanup=value['ordered_cleanup'];need(cleanup['status']=='PASS_ORDERED_CONSUMERS_COPIES_KEYS_SOURCE_THEN_PRODUCER' and cleanup['trial']=='normal' and cleanup['consumer']=='PASS_ALL_ACTORS_COPIES_KEYS_AND_SOURCE_RETIRED' and cleanup['authority']=='PASS_REMOVED_AFTER_CONSUMER_ABSENCE' and cleanup['producer']['status']=='PASS' and cleanup['producer']['image']['absence_verified'] is True and cleanup['producer']['probe']['absence_verified'] is True,'original ordered cleanup remains mandatory')
 need(value['original_retention_status']=='FAIL_OR_INCOMPLETE' and value['original_retention_errors'],'cancelled original result must not become normal success');return value

def complete(args,C,S):
 report=decode(read(args.component/'run.json'));identity=S.binding(args,C);need(report['status']=='OBSERVED_NATIVE_SIGINT_HANDOFF_ORDERED_CLEANUP_STILL_REQUIRED' and report['identity']==identity,'actual typed cancellation, not natural/unknown trial')
 before=decode(read(args.component/'before.json'));handoff=decode(read(args.component/'handoff.json'));need(pin(read(args.component/'before.json'))==report['before'] and pin(read(args.component/'handoff.json'))==report['handoff'],'original component joins');S.check(args.handoff,identity);need(read(args.handoff,16384)==read(args.component/'handoff.json'),'original supervisor receipt unchanged')
 ordered=decode(read(args.receipt));owner=decode(read(args.output/'owner.json',4*CAP));producer=decode(read(args.base/'report.json',4*CAP));need(ordered['status']=='PASS_ORDERED_CONSUMERS_COPIES_KEYS_SOURCE_THEN_PRODUCER' and ordered['trial']=='normal' and ordered['consumer']==owner['consumer_cleanup']=='PASS_ALL_ACTORS_COPIES_KEYS_AND_SOURCE_RETIRED' and ordered['authority']=='PASS_REMOVED_AFTER_CONSUMER_ABSENCE' and ordered['producer']==producer['owned_cleanup'] and producer['owned_cleanup']['status']=='PASS','original complete ordered cleanup required')
 roles=['export','extract','signer','lifecycle','scrub','source-cleanup'];need([r['role'] for r in owner['actors']]==roles and all(r['status']=='PASS_ABSENCE_VERIFIED' for r in owner['actors']) and owner['actors'][3]['id']==before['actor']['id'] and owner['actors'][1]['id']==before['extract']['id'],'all original cancelled actors must be retired before source/producer')
 need(producer['owned_cleanup']['image']['absence_verified'] is True and producer['owned_cleanup']['probe']['absence_verified'] is True,'producer and probe absent')
 retained=decode(read(args.retained/'retention.json',4*CAP));need(retained['status']=='FAIL_OR_INCOMPLETE' and retained['trial']=='normal' and retained['errors'],'intentional cancelled original result must retain failure classification')
 for n,row in retained['files'].items():need(pin(read(args.retained/relative(n),64*CAP))==row,'original retained bytes differ')
 result=dict(status=STATUS,identity=identity,signal=signal.SIGINT,original_handoff=handoff,actual_live_before=before,ordered_cleanup=ordered,original_retention_status=retained['status'],original_retention_errors=retained['errors'],normal_matrix='NOT_CLAIMED',transaction_outcome='UNKNOWN',rollback='NOT_CLAIMED',hardware='NOT_RUN',release='NOT_ADMITTED')
 validate(result,identity);need(len(encoded(result))<=65536,'bounded component result');(args.component/'result.json').write_bytes(encoded(result))
 sources=args.component/'source';need(not sources.exists(),'fresh component source retention');sources.mkdir(mode=0o700)
 for n in ('cancel.py','test_cancel.py','README.md','source-manifest.json'):(sources/n).write_bytes(read(HERE/n))
 files={p.relative_to(args.component).as_posix():pin(read(p)) for p in args.component.rglob('*') if p.is_file()};need(len(files)==8 and sum(r['bytes'] for r in files.values())<=2*CAP,'finite closed component export');(args.component/'closed.json').write_bytes(encoded(dict(status='CLOSED_NATIVE_CANCELLATION_COMPONENT_EXPORT',files=files,bytes=sum(r['bytes'] for r in files.values()))))
 print('ORPHANS_NATIVE_CANCELLATION '+json.dumps(result,sort_keys=True,separators=(',',':')),flush=True);return result

def replay(args,C):
 closure=decode(read(args.component/'closed.json'));need(closure['status']=='CLOSED_NATIVE_CANCELLATION_COMPONENT_EXPORT' and len(closure['files'])==8 and closure['bytes']<=2*CAP,'bounded complete component metadata export')
 paths={p.relative_to(args.component).as_posix() for p in args.component.rglob('*') if p.is_file()};need(paths==set(closure['files'])|{'closed.json'},'closed component path set')
 for n,row in closure['files'].items():
  need(n and '\0' not in n and not n.startswith('/') and '\\' not in n and all(x not in ('','.','..') for x in n.split('/')),'ordinary component ref');need(pin(read(args.component/n))==row,'component metadata hash differs')
 need(sum(r['bytes'] for r in closure['files'].values())==closure['bytes'],'component aggregate differs')
 for n in ('cancel.py','test_cancel.py','README.md','source-manifest.json'):need(read(args.component/'source'/n)==read(HERE/n),'component source differs from frozen trusted source')
 proof=read(args.retained/'source-proof.json',65536);p=json.loads(proof);need(p['source_sha']==args.source_sha and p['trial']=='normal' and args.run_id>0,'explicit original source/trial/run binding');key=str(args.run_id)+':1:'+args.source_sha
 identity=dict(source_sha=args.source_sha,trial='normal',proof_sha256=pin(proof)['sha256'],consumer_token=C.sha(('apps574-consumer:'+key).encode())[:32],producer_token=C.sha(('apps574-producer:'+key).encode())[:16]);need(p['consumer_token']==identity['consumer_token'] and p['job_token']==identity['producer_token'],'original actual run-derived ownership tokens')
 result=validate(decode(read(args.component/'result.json',65536)),identity)
 need(decode(read(args.component/'handoff.json',16384))==result['original_handoff'] and decode(read(args.component/'before.json'))==result['actual_live_before'],'original before/handoff full records agree')
 before=result['actual_live_before'];need(before['source_snapshot']==pin(read(args.retained/'snapshot-public/snapshot.json',4*CAP)) and before['held_payloads']==pin(read(args.retained/'inputs/held-payloads.json',256*1024)),'actual live-before snapshot/held-proof pins must equal original retained bytes')
 ordered=read(args.retained/'ordered-cleanup.json');need(decode(ordered)==result['ordered_cleanup'],'original ordered cleanup bytes agree')
 retention=decode(read(args.retained/'retention.json',4*CAP));need(retention['status']==result['original_retention_status'] and retention['errors']==result['original_retention_errors'],'original failure classification unchanged')
 for n,row in retention['files'].items():need(pin(read(args.retained/relative(n),64*CAP))==row,'original retained bytes differ')
 return dict(status='PASS_PASSIVE_NATIVE_CANCELLATION_COMPONENT_JOINS_NOT_ROOT_ACCEPTANCE',identity=identity,component=pin(read(args.component/'closed.json')),normal_matrix='NOT_CLAIMED',API_and_original_logs='ROOT_MUST_INDEPENDENTLY_JOIN_ORPHANS_JOB_HANDOFF_AND_COMPONENT_TYPED_FRAMES',hardware='NOT_RUN',release='NOT_ADMITTED')

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=('proof','run','complete','verify'));p.add_argument('--source',type=Path,required=True)
 for n in ('packet','proof','base','output','handoff','component','receipt','retained'):p.add_argument('--'+n,type=Path)
 p.add_argument('--run-id',type=int);p.add_argument('--source-sha');args=p.parse_args();args.source=args.source.absolute();C,S=source(args.source);args.trial='normal'
 if args.mode=='proof':
  need(pin(read(HERE/'source-manifest.json'))['sha256']==os.environ['COMPONENT_MANIFEST_SHA256'],'exact requested component manifest');return 0
 if args.mode=='verify':
  need(args.component is not None and args.retained is not None and args.run_id is not None and args.source_sha is not None,'explicit future actual replay inputs');print(json.dumps(replay(args,C),sort_keys=True));return 0
 need(all(getattr(args,n) is not None for n in ('proof','base','output','handoff','component')),'finite original native paths required')
 if args.mode=='run':need(args.packet is not None,'original held packet required');run(args,C,S)
 else:need(args.receipt is not None and args.retained is not None,'original cleanup and retained result required');complete(args,C,S)
 return 0
if __name__=='__main__':raise SystemExit(main())
