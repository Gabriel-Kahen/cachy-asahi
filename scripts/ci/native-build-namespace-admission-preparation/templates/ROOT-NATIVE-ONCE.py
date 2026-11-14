"""Root-only exact Developer Tools canonical exclusive heavy admission; no inherited finite exception."""
import argparse,fcntl,hashlib,importlib.util,json,os,resource,signal,stat,sys,time
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
T=Path(__file__).resolve().parent
ROOT=Path('/home/gabe/Documents/ChatGPT/cachy-asahi');DEV=ROOT/'artifacts/development';OUT=T/'receipts';ACTUAL=T/'actual-native'
COMMON=DEV/'orchestrator-resume-20261025';PUB=T/'publication';SOURCE_ROOT=Path(json.loads((T/'facts.json').read_bytes())['source_root'])
API='https://api.github.com/repos/Gabriel-Kahen/cachy-asahi';M=1024**2
SOURCE='6b5b5a8f20ad2698c2d7f14a8f59c9b0ad5da165'
TREE='a825d475d248f2254070d256d23780c4ef2d0f4b';MAP='7474683e198759876dcee6b31a036473f2129da351fce3bcc8e37770b4a70f79'
PARENT='97a44c4c7cb206704bf76e9fd1f1afb2266278c2'
REF='codex/native-build-namespace-preflight-v2-20261114';GROUP='native-arm-build';OP='native-build-namespace-preflight-v1'
WF='.github/workflows/native-arm-build.yml';WORKFLOW=381664314
STATUSES=('in_progress','pending','queued','waiting','requested')
COUNTER=0;ENV=None;FD=None;OWNER=None;C=U=S=L=None;DEADLINE=None;INPUT_SEAL='@INPUT_SEAL_SHA256@'

def need(ok,why):
 if not ok:raise ValueError(why)

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def load(name,path,digest):
 raw=path.read_bytes();need(pin(raw)['sha256']==digest,'pinned module '+name);spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module

def write(path,raw):U.write(path,raw)

def save(path,value):U.save(path,value)

def obj(path,cap=4*M):return U.obj(U.read(path,cap))

def rowread(path,row):
 need(type(row['bytes'])is int and 0<=row['bytes']<=32*M,'exact Source row<=32MiB');raw=U.read(path,row['bytes']);need(pin(raw)=={k:row[k]for k in ('bytes','sha256')},'whole declared Source leaf');return raw

def run(role,argv,cap=30):
 global COUNTER
 C.held(U,L,FD,OWNER);need(time.monotonic()<DEADLINE,'whole owner deadline');COUNTER+=1;prefix=OUT/('%03d-%s'%(COUNTER,role))
 save(prefix.with_suffix('.intent.json'),dict(argv=argv,cap=cap,retry=False))
 with prefix.with_suffix('.stdout').open('xb')as so,prefix.with_suffix('.stderr').open('xb')as se:
  result=S.supervise(argv,cwd=ROOT,env=ENV,stdout=so,stderr=se,lock_fd=FD,cap=min(cap,DEADLINE-time.monotonic()))
 save(prefix.with_suffix('.status.json'),result);C.natural(result);C.held(U,L,FD,OWNER);return U.read(prefix.with_suffix('.stdout'),64*M)

def git(role,*args):return run(role,['/usr/bin/git','--no-replace-objects','-c','core.hooksPath=/dev/null','-c','maintenance.auto=false','-c','gc.auto=0',*args])

def oid(kind,raw):return hashlib.sha1(kind.encode()+b' '+str(len(raw)).encode()+b'\0'+raw).hexdigest()

def entries(raw):
 rows={}
 for line in raw.split(b'\0'):
  if line:
   header,name=line.split(b'\t');mode,kind,blob=header.decode().split();need(kind=='blob'and name.decode()not in rows,'whole distinct blob map');rows[name.decode()]=dict(mode=mode,blob=blob)
 return rows

def main_guard(expected=None):
 live=git('main-head','rev-parse','HEAD').decode().strip();need(expected is None or live==expected,'main moved; HOLD')
 need(git('main-branch','symbolic-ref','--short','HEAD').decode().strip()=='main'and not git('main-clean','status','--porcelain','--untracked-files=no'),'clean primary main')
 need(git('main-tracking','rev-parse','refs/remotes/origin/main').decode().strip()==live and git('main-remote','ls-remote','--heads','origin','refs/heads/main').decode().split()==[live,'refs/heads/main'],'same actual local/tracking/remote main');return live

def bootstrap():
 need(__debug__,'optimized Python forbidden')
 raw=(T/'input-seal.json').read_bytes();need(pin(raw)['sha256']==INPUT_SEAL,'fixed bounded authority')
 for name,row in json.loads(raw).items():need(pin(Path(name).read_bytes())==row,'held authority '+name)
 path=DEV/'security200-v5-ci-feedback-development-20261031/capture.py'
 C=load('_platform_matrix_custody',path,json.loads(raw)[str(path)]['sha256'])
 U,S,L=C.modules();return C,U,S,L

def verify_packet(digest):
 need(type(SOURCE)is str and len(SOURCE)==40 and type(TREE)is str and len(TREE)==40 and type(MAP)is str and len(MAP)==64 and type(REF)is str and REF.startswith('codex/')and type(INPUT_SEAL)is str,'Root actual Source publication/complete seal tuple remains NULL')
 raw=(T/'seal.json').read_bytes();need(pin(raw)['sha256']==digest,'external native packet seal')
 for name,row in json.loads(raw)['files'].items():
  p=T/name;need(p==p.resolve() and not any(q.is_symlink()for q in(p,*p.parents)),'ordinary packet input')
  need(pin(p.read_bytes())==row,'whole packet '+name)
 facts=json.loads((T/'facts.json').read_bytes());binding=facts.get('factory_binding')
 need(type(binding)is dict and binding.get('status')=='ROOT_BOUND_NAMESPACE_FACTORY_CI_MAIN' and binding.get('approved')is True,'PR433 factory CI/Main binding pending; HOLD before bootstrap or role output')



def admission(path,digest):
 raw=U.read(Path(path).resolve());need(pin(raw)['sha256']==digest,'external Root authority pin');a=U.obj(raw);template=obj(T/'Root-authority.TEMPLATE.json')
 need(a['issuer']=='Root'and a['approved']is True and a['status']=='ROOT_ISSUED_EXACT_NAMESPACE_PREFLIGHT_CANONICAL_HEAVY','Root independently issues first package-operation authority')
 for key in('namespace_x86_body_certificates','schema','source','ref','tree','map_sha256','git_parent','workflow_id','workflow_path','workflow_sha256','group','operation','classification','scope','resources','x86_body_catalog','x86_body_certificates','current_x86_body_certificates','scheduling_lane'):
  need(a[key]==template[key],'held exact Root component classification '+key)
 for key in template['reviews']:need(a['reviews'][key]is True,'Root explicit input/resource/retire/privacy review '+key)
 r=a['reservation'];need(r['source']==SOURCE and r['group']==GROUP and r['operation']==OP and r['scheduling_lane']==GROUP and r['active']==r['pending']==0 and r['held_by']=='Root'and r['heavy_kernel_signer_physical_serialization_preserved']is True,'actual Root existing component reservation')
 issued=datetime.fromisoformat(a['issued_at']);need(0<=(datetime.now(timezone.utc)-issued).total_seconds()<=3600,'fresh Root classification/reservation')
 need(a['active_run_certificates']==[],'canonical heavy admission forbids other live native/heavy/kernel coexistence; no exemption')
 return a

def static_qualification():
 path=T/'namespace_guard.py'
 gate=load('_exact_namespace_source_and_factory_gate',path,json.loads((T/'input-seal.json').read_bytes())[str(path)]['sha256'])
 return gate.qualify(globals())

def metadata_worker(args):
 global C,U,S,L,FD,OWNER,DEADLINE,ENV
 C,U,S,L=bootstrap();C.OWNER_START=args.owner_start;FD=args.fd;OWNER=args.owner;DEADLINE=args.deadline;ENV=dict(os.environ);C.held(U,L,FD,OWNER)
 authority=admission(args.authority,args.authority_sha256);token=os.environ['GH_TOKEN'];calls=0
 x86_path=T/'ci-adapter.py'
 x86=load('_platform_matrix_exact_x86_certifier',x86_path,json.loads((T/'input-seal.json').read_bytes())[str(x86_path)]['sha256'])
 def get(role,path):
  nonlocal calls
  calls+=1;need(calls<=100 and time.monotonic()<DEADLINE,'finite metadata budget');C.held(U,L,FD,OWNER)
  raw,http=C.fetch_observed(U,API+path,8*M,token,False,lambda i,row:save(OUT/(role+'.hop'+str(i)+'.headers.json'),row))
  write(OUT/(role+'.json'),raw);save(OUT/(role+'.http.json'),http)
  need(http['hops'][0]['authenticated'] and http['hops'][0]['request_id'] and all(h['date']for h in http['hops']) and http['hops'][-1]['status']==200 and http['body']==pin(raw),'authenticated complete bounded metadata')
  return U.obj(raw)
 def pages(role,path,key):
  result=[];total=None
  for page in range(1,11):
   value=get(role+'-page'+str(page),path+('&'if'?'in path else'?')+'per_page=100&page='+str(page));need(type(value['total_count'])is int and 0<=value['total_count']<=1000 and(total is None or total==value['total_count']),'stable bounded total');total=value['total_count'];chunk=value[key];need(type(chunk)is list and len(chunk)<=100,'bounded page');result.extend(chunk)
   if len(chunk)<100:break
  need(len(result)==total==len({r['id']for r in result}),'complete distinct paginated catalog');return result
 terminal_joins=[]
 for prior in obj(T/'known-terminal-runs.json')['runs']:
  directory=Path(prior['actual_directory']);actual=obj(directory/'actual-run.json');intent=obj(directory/'dispatch-intent.json')
  need(actual['run_id']==prior['run'] and actual['source']==prior['source'] and actual['ref']==prior['ref'] and actual['attempt']==1 and actual['workflow_id']==WORKFLOW,'genuine prior Root once selection')
  need(obj(directory/'dispatch-status.json')==dict(exit=0,once=True,retry=False) and intent['once']is True and intent['retry']is False and intent['source']==prior['source'] and intent['ref']==prior['ref'],'prior original9d once custody; no replay')
  run=get('known-terminal-'+str(prior['run']),'/actions/runs/'+str(prior['run'])+'/attempts/1')
  need((run['id'],run['head_sha'],run['head_commit']['id'],run['head_commit']['tree_id'],run['head_branch'],run['run_attempt'],run['workflow_id'],run['path'],run['event'],run['status'],run['conclusion'])==(prior['run'],prior['source'],prior['source'],prior['tree'],prior['ref'],1,WORKFLOW,WF,'workflow_dispatch','completed','failure'),'fresh exact known terminal run; never name-only exemption')
  need(run['repository']['id']==run['head_repository']['id']==1414857795 and run['repository']['full_name']==run['head_repository']['full_name']=='Gabriel-Kahen/cachy-asahi','known terminal exact repository')
  jobs=pages('known-terminal-jobs-'+str(prior['run']),'/actions/runs/'+str(prior['run'])+'/attempts/1/jobs?filter=all','jobs')
  need(len(jobs)==1 and jobs[0]['id']==prior['job'],'complete actual known-terminal job set')
  for job in jobs:
   need((job['run_id'],job['head_sha'],job['head_branch'],job['run_attempt'],job['name'],job['status'],job['conclusion'],job['labels'])==(prior['run'],prior['source'],prior['ref'],1,'native','completed','failure',['ubuntu-24.04-arm']),'all known terminal jobs exact metadata join')
   need(type(job['runner_id'])is int and job['runner_id']>0 and job['runner_group_id']==0 and job['runner_group_name']=='GitHub Actions' and job['runner_name']=='GitHub Actions '+str(job['runner_id']),'known terminal actual hosted runner identity')
   need(all(s['status']=='completed'for s in job['steps']) and [s['number']for s in job['steps']if s['conclusion']=='failure']==prior['failed_steps'],'known terminal exact failure boundary')
  terminal_joins.append(dict(role=prior['role'],source=prior['source'],ref=prior['ref'],run=prior['run'],attempt=1,jobs=[j['id']for j in jobs],status='FRESH_ALL_JOB_METADATA_TERMINAL_FAILURE_REJOINED',original_body_GETs=0,reader_runs=0))
 save(OUT/'known-terminal-all-jobs-qualified.json',dict(status='ALL_KNOWN_PRIOR_ROOT_NATIVE_RUNS_FRESH_TERMINAL_ALL_JOB_METADATA_ONLY',runs=terminal_joins,originals_replayed=False,POSTs=0,acceptance=False))
 prior=pages('prior-exact-ref','/actions/workflows/381664314/runs?branch='+REF+'&event=workflow_dispatch','workflow_runs');need(not prior,'source/ref already selected or uncertain; never repeat')
 checked=datetime.now(timezone.utc).isoformat();active=[]
 for status in STATUSES:
  rows=pages('live-'+status,'/actions/runs?status='+status,'workflow_runs');need(all(r['status']==status for r in rows),'status moved during sweep; HOLD');active.extend(rows)
 need(len({r['id']for r in active})==len(active),'cross-status movement; HOLD')
 certs=authority['active_run_certificates'];need(certs==[],'exclusive heavy reservation: no other live native certificates/exceptions')
 certs={c['run']:c for c in certs};need(set(certs)<={r['id']for r in active},'Root native resource certificates stale; HOLD')
 qualified=[];runners=set();first_jobs={}
 for row in active:
  need(row['repository']['id']==row['head_repository']['id']==1414857795 and row['repository']['full_name']==row['head_repository']['full_name']=='Gabriel-Kahen/cachy-asahi','exact public repository')
  actual=dict(run=row['id'],source=row['head_sha'],ref=row['head_branch'],attempt=row['run_attempt'],workflow_id=row['workflow_id'],workflow_path=row['path'],event=row['event'])
  need(row['head_commit']['id']==row['head_sha'],'exact active Source tuple')
  raw=git('active-raw-'+str(row['id']),'cat-file','commit',row['head_sha']);need(oid('commit',raw)==row['head_sha'],'actual active raw Git Source')
  table=entries(git('active-tree-'+str(row['id']),'ls-tree','-r','-z','--full-tree',row['head_sha']))
  tree=C.tree_id({n:(r['mode'],r['blob'])for n,r in table.items()});need([s[5:].decode()for s in raw.split(b'\n\n',1)[0].splitlines()if s.startswith(b'tree ')]==[tree],'actual active full Git tree')
  body=git('active-workflow-'+str(row['id']),'show',row['head_sha']+':'+row['path'])
  jobs=pages('active-jobs-'+str(row['id']),'/actions/runs/'+str(row['id'])+'/attempts/'+str(row['run_attempt'])+'/jobs?filter=all','jobs')
  first_jobs[row['id']]=jobs
  if row['id']not in certs and row['workflow_id']!=WORKFLOW:
   def xgit(*argv):return git('x86-exact-'+str(COUNTER),*argv)
   result=x86.certify_x86_run(None,xgit,row,row['path'],body,jobs,args.main,OUT)
   need(result.get('native_permission',result.get('native_acceptance'))is False,'x86 qualification grants no native permission')
   for job in jobs:
    if job['status']=='in_progress':
     need(job['runner_id']not in runners,'distinct actual active hosted runner');runners.add(job['runner_id'])
   qualified.append(dict(**actual,classification='ROOT_QUALIFIED_EXACT_AUTOMATIC_HOSTED_X86_BODY',group=None,operation=None,jobs=[j['id']for j in jobs]));continue
  need(False,'any live native/heavy/kernel occupies canonical reservation or has unknown resource scope; HOLD')
 # A second complete sweep detects appeared/disappeared work immediately before qualification.
 repeat=[]
 for status in STATUSES:
  rows=pages('verify-live-'+status,'/actions/runs?status='+status,'workflow_runs');need(all(r['status']==status for r in rows),'status moved during second sweep; HOLD');repeat.extend(rows)
 signature=lambda rows:sorted((r['id'],r['head_sha'],r['head_branch'],r['run_attempt'],r['status'])for r in rows)
 need(signature(active)==signature(repeat),'active inventory changed across qualification; HOLD')
 job_signature=lambda rows:sorted((j['id'],j['run_id'],j['head_sha'],j['run_attempt'],j['name'],j['status'],j['conclusion'],j['runner_id'],tuple(j['labels']),j['runner_name'],j['runner_group_id'],j['runner_group_name'])for j in rows)
 for row in repeat:
  jobs=pages('verify-active-jobs-'+str(row['id']),'/actions/runs/'+str(row['id'])+'/attempts/'+str(row['run_attempt'])+'/jobs?filter=all','jobs')
  need(job_signature(jobs)==job_signature(first_jobs[row['id']]),'complete active all-job/runner catalog changed across two sweeps; HOLD')
 save(OUT/'live-gate-qualified.json',dict(status='ROOT_FRESH_COMPLETE_FIVE_STATUS_NAMESPACE_PREFLIGHT_EXCLUSIVE_HEAVY_CLEAR',checked_at_utc=checked,completed_at_utc=datetime.now(timezone.utc).isoformat(),statuses=list(STATUSES),complete_paginated=True,source=SOURCE,ref=REF,group=GROUP,operation=OP,active=qualified,unknown_native=0,same_group=0,same_operation=0,independent_hosted_runner_ids=sorted(runners),metadata_GETs=calls,POSTs=0,authority_sha256=args.authority_sha256))
 return 0

def execute(args):
 global C,U,S,L,FD,OWNER,DEADLINE,ENV
 os.umask(0o077);C,U,S,L=bootstrap()
 need(not OUT.exists() and not ACTUAL.exists(),'fresh once outputs only; reconcile partial outcomes without replay')
 OUT.mkdir(mode=0o700);OWNER=os.getpid();acquired=False;token=None
 report=dict(status='NOT_DISPATCHED',retry=False,acceptance=False)
 try:
  FD=os.open(U.canonical(U.LOCK),os.O_RDWR|os.O_CLOEXEC|os.O_NOFOLLOW);U.lock_identity(FD);until=time.monotonic()+300
  while True:
   try:fcntl.flock(FD,fcntl.LOCK_EX|fcntl.LOCK_NB);acquired=True;break
   except BlockingIOError:need(time.monotonic()<until,'shared lease queue expired; HOLD');time.sleep(.1)
  C.OWNER_START=S._read_stat(OWNER)[4];C.OWNER_PIDFD=os.pidfd_open(OWNER,0);DEADLINE=time.monotonic()+420
  ENV=dict(os.environ,GIT_NO_LAZY_FETCH='1',GIT_NO_REPLACE_OBJECTS='1',GIT_TERMINAL_PROMPT='0',GIT_CONFIG_GLOBAL='/dev/null',GIT_CONFIG_NOSYSTEM='1',PYTHONDONTWRITEBYTECODE='1')
  ENV.pop('GH_DEBUG',None)
  save(OUT/'once-entry.json',dict(source=SOURCE,publication_status='PUBLIC_SOURCE_DATA_ONLY_NOT_NATIVE_ADMISSION',lease=C.held(U,L,FD,OWNER),retry=False,admission=False))
  authority=admission(args.authority,args.authority_sha256);save(OUT/'Root-issued-authority.json',authority)
  save(OUT/'admission-bound.json',dict(path=str(Path(args.authority).resolve()),admission=pin(U.read(Path(args.authority).resolve()))))
  live=static_qualification()
  token=os.environ.get('GH_TOKEN')or os.environ.get('GITHUB_TOKEN')
  if not token:
   with os.fdopen(os.memfd_create('platform-matrix-auth',os.MFD_CLOEXEC),'w+b')as memory,open(os.devnull,'wb')as quiet:
    result=S.supervise(['/usr/bin/gh','auth','token'],cwd=T,env=ENV,stdout=memory,stderr=quiet,lock_fd=FD,cap=20);save(OUT/'auth-process.json',result);C.natural(result);need(0<os.fstat(memory.fileno()).st_size<=4097,'bounded memory-only credential');memory.seek(0);token=memory.read(4097).decode().strip()
  need(type(token)is str and 0<len(token)<=4096 and not any(c.isspace()for c in token),'memory-only credential');ENV.update(GH_TOKEN=token)
  command=['/usr/bin/python3','-I','-B',str(T/'ROOT-NATIVE-ONCE.py'),'--seal',args.seal,'--metadata-worker','--fd',str(FD),'--owner',str(OWNER),'--owner-start',str(C.OWNER_START),'--deadline',repr(min(DEADLINE,time.monotonic()+110)),'--authority',args.authority,'--authority-sha256',args.authority_sha256,'--main',live]
  run('metadata',command,120);gate=obj(OUT/'live-gate-qualified.json');main_guard(live)
  age=(datetime.now(timezone.utc)-datetime.fromisoformat(gate['checked_at_utc'])).total_seconds()
  need(0<=age<=120 and gate['source']==SOURCE and gate['group']==GROUP and gate['operation']==OP and gate['same_group']==gate['same_operation']==gate['unknown_native']==0,'fresh complete singleton scheduling gate')
  admission(args.authority,args.authority_sha256)
  need(git('last-source-remote','ls-remote','--heads','origin','refs/heads/'+REF).decode().split()==[SOURCE,'refs/heads/'+REF] and not ACTUAL.exists(),'exact remote/fresh actual before helper')
  need(time.monotonic()+190<DEADLINE,'insufficient once-discovery reserve; HOLD');C.held(U,L,FD,OWNER)
  # Give unchanged9d a genuine complete local200 view and unmodified receipt.
  view=OUT/'publication-for-original9d';view.mkdir(mode=0o700);write(view/'publication.json',U.read(PUB/'publication.json'))
  full=obj(T/'source-full200.json')
  for name,row in full.items():
   target=view/'source'/name;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True);write(target,rowread(SOURCE_ROOT/name,row));target.chmod(int(row['mode'],8)&511)
  need(C.closed_source_declared(U,view/'source',{n:{k:r[k]for k in('bytes','sha256')}for n,r in full.items()},{n:int(r['mode'],8)&511 for n,r in full.items()})==TREE,'complete original9d view, never a subset or fakeCOMMON')
  inputs=dict(source_sha=SOURCE,source_map_sha256=MAP,operation=OP);save(OUT/'dispatch-inputs-only.json',inputs)
  command=['/usr/bin/python3','-B',str(T/'RUN-PINNED-9D.py'),'--fd',str(FD),'--owner',str(OWNER),'--owner-start',str(C.OWNER_START),'--source',SOURCE,'--authority',args.authority,'--authority-sha256',args.authority_sha256]
  save(OUT/'dispatch-wrapper-intent.json',dict(argv=command,helper_sha256='9d014a2c5405f2ba5a478143545629cd5499eda2218a7306ca20cd4f24d5f94f',once=True,retry=False,lease=C.held(U,L,FD,OWNER)))
  run('dispatch-once',command,190)
  actual=obj(ACTUAL/'actual-run.json');initial=obj(ACTUAL/'initial-run.json');intent=obj(ACTUAL/'dispatch-intent.json');status=obj(ACTUAL/'dispatch-status.json')
  need(actual['source']==initial['head_sha']==SOURCE and actual['ref']==initial['head_branch']==REF and actual['run_id']==initial['id'] and actual['attempt']==initial['run_attempt']==1 and actual['workflow_id']==initial['workflow_id']==WORKFLOW and initial['event']=='workflow_dispatch' and initial['path']==WF,'genuine new original9d actual run')
  need(intent['request']==dict(ref=REF,inputs=inputs) and intent['once']is True and intent['retry']is False and status==dict(exit=0,once=True,retry=False),'one exact original-helper dispatch')
  binding=obj(T/'strict-reader-binding.TEMPLATE.json');binding['expected_binding'].update(run=str(actual['run_id']));binding['actual_run']=actual['run_id'];binding['status']='ACTUAL_RUN_BOUND_JOB_ARTIFACT_BODY_ENGINE_AUTHORITY_STILL_UNBOUND';save(OUT/'strict-reader-binding-actual-run.json',binding)
  report=dict(status='ROOT_ONCE_NAMESPACE_PREFLIGHT_CANONICAL_HEAVY_DISPATCHED_MATCHING200_READER_RUN_BOUND',source=SOURCE,ref=REF,run=actual['run_id'],attempt=1,workflow_id=WORKFLOW,operation=OP,group=GROUP,map_sha256=MAP,parent=PARENT,matching_reader=str(SOURCE_ROOT/'native/build_tools_reader_v2.py'),reader_sha256=obj(T/'facts.json')['reader']['sha256'],reader_executed=False,native_result='PENDING',POSTs=1,retry=False,acceptance=False)
 except BaseException as error:
  report=dict(status='HOLD_OR_PARTIAL_UNCERTAIN_NO_RETRY',type=type(error).__name__,guard=str(error)[:700]if isinstance(error,ValueError)else'',actual_directory_exists=ACTUAL.exists(),actual_POST_boundary_guard_exists=(OUT/'at-actual-POST-guard.json').exists(),retry=False,acceptance=False)
 finally:
  token=None
  if ENV is not None:ENV.pop('GH_TOKEN',None)
  mask=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
  try:
   if acquired:report['final_lease']=C.held(U,L,FD,OWNER)
   report['release']='CLOSE_ONLY';save(OUT/'execution-result.json',report)
  finally:
   if FD is not None:os.close(FD)
   if C.OWNER_PIDFD is not None:os.close(C.OWNER_PIDFD)
   signal.pthread_sigmask(signal.SIG_SETMASK,mask)
 print(json.dumps(report,sort_keys=True));return int(report['status']!='ROOT_ONCE_NAMESPACE_PREFLIGHT_CANONICAL_HEAVY_DISPATCHED_MATCHING200_READER_RUN_BOUND')

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--seal',required=True);p.add_argument('--authority',required=True);p.add_argument('--authority-sha256',required=True);p.add_argument('--metadata-worker',action='store_true');p.add_argument('--fd',type=int);p.add_argument('--owner',type=int);p.add_argument('--owner-start',type=int);p.add_argument('--deadline',type=float);p.add_argument('--main')
 a=p.parse_args();verify_packet(a.seal);raise SystemExit(metadata_worker(a)if a.metadata_worker else execute(a))
