"""Root independent readonly Source/live preflight; NOT authority or native entry."""
import argparse,fcntl,hashlib,importlib.util,json,os,re,signal,stat,sys,time
from pathlib import Path
from types import SimpleNamespace
sys.dont_write_bytecode=True
N=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--seal',required=True);p.add_argument('--index',type=int,default=0);p.add_argument('--worker',action='store_true');p.add_argument('--execute-root-preflight-once',action='store_true');p.add_argument('--fd',type=int);p.add_argument('--owner',type=int);p.add_argument('--owner-start',type=int);p.add_argument('--deadline',type=float);p.add_argument('--main');a=p.parse_args()
def need(v,s):
 if not v:raise ValueError(s)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
ROOT_OPERATOR_SHA256='@ROOT_OPERATOR_SHA256@'
raw=(N/'ROOT-NATIVE-ONCE.py').read_bytes();need(pin(raw)['sha256']==ROOT_OPERATOR_SHA256,'exact reviewed native guard before import')
spec=importlib.util.spec_from_file_location('_Root_independent_readonly_developer_preflight',N/'ROOT-NATIVE-ONCE.py');O=importlib.util.module_from_spec(spec);spec.loader.exec_module(O);O.verify_packet(a.seal)
need(__debug__ and sys.flags.isolated and sys.flags.dont_write_bytecode,'exact -I -B interpreter');need(type(a.index)is int and 0<=a.index<1000,'fresh bounded preflight index');OUT=N/('Root-preflight-%03d'%a.index);O.OUT=OUT
need(not O.ACTUAL.exists()and not(N/'receipts').exists(),'preflight strictly before any actual native entry; no overlap')
# This hook supplies sealed UNISSUED DATA only to the metadata routine. It never
# creates an issued authority and cannot reach O.execute/RUN-PINNED-9D/POST.
def metadata_template_only(path,sha):
 raw=(N/'Root-authority.TEMPLATE.json').read_bytes();need(Path(path)==N/'Root-authority.TEMPLATE.json'and pin(raw)['sha256']==sha,'exact unissued metadata template');v=json.loads(raw)
 need(v['approved']is None and v['issued_at']is None and v['status']=='ROOT_MUST_ISSUE_EXACT_NAMESPACE_PREFLIGHT_CANONICAL_HEAVY'and v['active_run_certificates']==[]and v['source']==O.SOURCE,'preflight grants no Root resource/native authority')
 return v
if a.worker:
 O.admission=metadata_template_only
 args=SimpleNamespace(fd=a.fd,owner=a.owner,owner_start=a.owner_start,deadline=a.deadline,authority=str(N/'Root-authority.TEMPLATE.json'),authority_sha256=pin((N/'Root-authority.TEMPLATE.json').read_bytes())['sha256'],main=a.main)
 raise SystemExit(O.metadata_worker(args))
need(a.execute_root_preflight_once,'explicit Root readonly preflight role');need(not OUT.exists(),'fresh independent preflight output; never reuse partial index');os.umask(0o077);OUT.mkdir(mode=0o700);C,U,S,L=O.bootstrap();owner=os.getpid();fd=None;acquired=False;token=None;env=None;report=dict(status='NOT_ENTERED',native_POSTs=0,Original_GETs=0,Reader_calls=0,authority_issued=False)
try:
 fd=os.open(U.canonical(U.LOCK),os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC);U.lock_identity(fd);until=time.monotonic()+300
 while True:
  try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);acquired=True;break
  except BlockingIOError:need(time.monotonic()<until,'same shared lease queue expired; readonly HOLD');time.sleep(.1)
 C.OWNER_START=S._read_stat(owner)[4];C.OWNER_PIDFD=os.pidfd_open(owner,0);deadline=time.monotonic()+420;O.C,O.U,O.S,O.L=C,U,S,L;O.FD=fd;O.OWNER=owner;O.DEADLINE=deadline;O.ENV=dict(os.environ,GIT_NO_LAZY_FETCH='1',GIT_NO_REPLACE_OBJECTS='1',GIT_TERMINAL_PROMPT='0',GIT_CONFIG_GLOBAL='/dev/null',GIT_CONFIG_NOSYSTEM='1',PYTHONDONTWRITEBYTECODE='1');O.ENV.pop('GH_DEBUG',None)
 U.save(OUT/'once-intent.json',dict(source=O.SOURCE,operation=O.OP,role='INDEPENDENT_READONLY_PREFLIGHT_NOT_AUTHORITY',source_reader_qualification=True,complete_double_status_and_all_job_sweeps=True,GET_cap=100,metadata_seconds=110,native_POSTs=0,Original_GETs=0,Reader_calls=0,authority_issued=False,lease=C.held(U,L,fd,owner)))
 template_path=N/'Root-authority.TEMPLATE.json';template_raw=template_path.read_bytes();metadata_template_only(template_path,pin(template_raw)['sha256']);U.save(OUT/'admission-bound.json',dict(path=str(template_path),admission=pin(template_raw)))
 live=O.static_qualification();token=os.environ.get('GH_TOKEN')or os.environ.get('GITHUB_TOKEN')
 if not token:
  with os.fdopen(os.memfd_create('developer-preflight-auth',os.MFD_CLOEXEC),'w+b')as memory,open(os.devnull,'wb')as quiet:
   r=S.supervise(['/usr/bin/gh','auth','token'],cwd=N,env=O.ENV,stdout=memory,stderr=quiet,lock_fd=fd,cap=20);U.save(OUT/'auth-process.json',r);C.natural(r);need(0<os.fstat(memory.fileno()).st_size<=4097,'bounded memory-only credential');memory.seek(0);token=memory.read(4097).decode().strip()
 need(type(token)is str and 0<len(token)<=4096 and not any(c.isspace()for c in token),'ephemeral credential');env=dict(O.ENV,GH_TOKEN=token);worker_deadline=min(deadline,time.monotonic()+110)
 argv=['/usr/bin/python3','-I','-B',str(Path(__file__).resolve()),'--seal',a.seal,'--index',str(a.index),'--worker','--fd',str(fd),'--owner',str(owner),'--owner-start',str(C.OWNER_START),'--deadline',repr(worker_deadline),'--main',live]
 with(OUT/'worker.stdout').open('xb')as so,(OUT/'worker.stderr').open('xb')as se:r=S.supervise(argv,cwd=N,env=env,stdout=so,stderr=se,lock_fd=fd,cap=min(120,deadline-time.monotonic()))
 U.save(OUT/'worker-status.json',r);C.natural(r);gate=U.obj(U.read(OUT/'live-gate-qualified.json'));O.main_guard(live);need(gate['source']==O.SOURCE and gate['group']==O.GROUP and gate['operation']==O.OP and gate['complete_paginated']is True and gate['same_group']==gate['same_operation']==gate['unknown_native']==0,'independent complete exclusive metadata gate')
 need(not O.ACTUAL.exists()and not(N/'receipts').exists(),'no native outputs or entry by preflight');report=dict(status='ROOT_INDEPENDENT_SOURCE_AND_LIVE_PREFLIGHT_COMPLETE_NOT_AUTHORITY',source=O.SOURCE,main=live,metadata_GETs=gate['metadata_GETs'],metadata_gate=pin(U.read(OUT/'live-gate-qualified.json')),source_qualification=pin(U.read(OUT/'source-qualification.json')),native_POSTs=0,Original_GETs=0,Reader_calls=0,authority_issued=False,approved=None,acceptance=False)
except BaseException as e:report=dict(status='ROOT_READONLY_PREFLIGHT_HOLD_NO_DISPATCH',error_type=type(e).__name__,guard=str(e)[:700]if isinstance(e,ValueError)else'',native_POSTs=0,Original_GETs=0,Reader_calls=0,authority_issued=False,acceptance=False)
finally:
 token=None
 if env is not None:env.pop('GH_TOKEN',None)
 mask=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
 try:
  if acquired:report['final_lease']=C.held(U,L,fd,owner)
  report['release']='CLOSE_ONLY';U.save(OUT/'execution-result.json',report)
 finally:
  if fd is not None:os.close(fd)
  if C.OWNER_PIDFD is not None:os.close(C.OWNER_PIDFD)
  signal.pthread_sigmask(signal.SIG_SETMASK,mask)
print(json.dumps(report,sort_keys=True));raise SystemExit(int(report['status']!='ROOT_INDEPENDENT_SOURCE_AND_LIVE_PREFLIGHT_COMPLETE_NOT_AUTHORITY'))
