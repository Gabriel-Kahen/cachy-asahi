#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Actual GitHub self-cancel at an observed owned frontier, never synthetic SIGINT."""
import argparse,hashlib,http.client,importlib.util,json,os,re,stat,sys,threading,time
from pathlib import Path
HERE=Path(__file__).resolve().parent;LANE='scripts/ci/apps-full574-github-cancel';NATIVE='scripts/ci/apps-full574-repair-native'
NATIVE_SOURCE='5051663cf191e40bdbb3b03e2d62748f69b6afb1';NATIVE_MF='636baf21fa537ca813b7403b1bc6afb920404d974236bd52d8c1cdf479477ba9';PACKET='65950a7e3ca82d97e21a65556844dab1cfd1a7f7';REPO='Gabriel-Kahen/cachy-asahi'
TOKEN=None
sys.path.insert(0,str(HERE));import observe

def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def read(p,cap=4*1024**2):
 p=Path(p);need(not any(q.is_symlink() for q in (p,*p.parents)),'ordinary diagnostic path');a=p.stat();need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<=cap,'bounded single-link diagnostic file');raw=p.read_bytes();b=p.stat();need((a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns),'diagnostic read drift');return raw
def save(p,value):
 raw=encoded(value);need(len(raw)<=65536,'bounded cancellation receipt');need(not any(q.is_symlink() for q in (p,*p.parents)),'no receipt aliases');fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 s=p.stat();need(s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and read(p,65536)==raw,'private cancellation receipt readback')
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

def source(root,case):
 policy=json.loads(read(HERE/'input-policy.json',65536));need(policy.get('status')=='ROOT_BOUND_SELF_CANCEL_DIAGNOSTIC' and type(policy.get('binding')) is dict,'UNBOUND cancellation refuses before actors, tokens or network');b=policy['binding'];need(b==dict(native_source=NATIVE_SOURCE,native_manifest_sha256=NATIVE_MF,packet_source=PACKET,cases=['repair-bytes','repair-missing']),'exact immutable diagnostic source operands');need(case in b['cases'],'one explicit source-owned case')
 mf=json.loads(read(HERE/'source-manifest.json'));need(mf['status']=='FROZEN_SELF_GITHUB_CANCEL_DIAGNOSTIC_SOURCE' and len(mf['files'])==123,'finite cancellation source closure')
 for n,row in mf['files'].items():need(type(n) is str and n and not n.startswith('/') and '\\' not in n and all(x not in ('','.','..') for x in n.split('/')) and pin(read(root/n,16*1024**2))==row,'diagnostic source differs: '+n)
 need(pin(read(root/NATIVE/'source-manifest.json'))['sha256']==NATIVE_MF,'exact unchanged original113 native manifest');C=load('contract',root/NATIVE/'contract.py');C.source(root);C.case(case);return C

def own_run():
 need(os.environ.get('GITHUB_REPOSITORY')==REPO and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and os.environ.get('GITHUB_RUN_ATTEMPT')=='1','first-attempt own manual run only');run=os.environ.get('GITHUB_RUN_ID','');sha=os.environ.get('SOURCE_SHA','');need(re.fullmatch('[1-9][0-9]{0,19}',run) and re.fullmatch('[0-9a-f]{40}',sha) and sha==os.environ.get('GITHUB_SHA')==os.environ.get('GITHUB_WORKFLOW_SHA'),'own source/run identity');return int(run),sha

def request(run):
 token=TOKEN if TOKEN is not None else os.environ.get('GH_TOKEN','');need(type(token) is str and 0<len(token)<=4096 and '\r' not in token and '\n' not in token,'workflow-scoped actions-write token required');conn=http.client.HTTPSConnection('api.github.com',timeout=20)
 try:
  conn.request('POST','/repos/'+REPO+'/actions/runs/'+str(run)+'/cancel',body=b'',headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'cachy-asahi-owned-self-cancel'})
  response=conn.getresponse();raw=response.read(65537);need(len(raw)<=65536,'bounded original cancellation response');return dict(http_status=response.status,response=pin(raw),accepted=response.status==202,cleanup_authority=False)
 finally:conn.close()

def cancel_once(component,frontier_value):
 run,sha=own_run();need(frontier_value['identity']['source_sha']==sha and frontier_value['status']=='OBSERVED_OWNED_RUNNING_LIFECYCLE_AND_DIRECT_JOB_LEASES','genuine exact-source observed frontier required');save(component/'before.json',frontier_value)
 intent=dict(status='ONE_OWN_RUN_CANCEL_INTENT_NO_RETRY',repository=REPO,run=run,attempt=1,source_sha=sha,frontier=pin(read(component/'before.json',65536)),transaction_outcome='UNKNOWN',cleanup_authority=False);save(component/'cancel-intent.json',intent)
 try:result=request(run)
 except BaseException as e:result=dict(status='CANCEL_REQUEST_OUTCOME_UNKNOWN_NO_RETRY',error_type=type(e).__name__,cleanup_authority=False)
 else:result.update(status='CANCEL_ACCEPTED_ORIGINAL_CLEANUP_PENDING' if result['accepted'] else 'CANCEL_NOT_ACCEPTED_NO_RETRY')
 save(component/'cancel-response.json',result);print('APPS574_GITHUB_CANCEL '+json.dumps(dict(intent=intent,response=result),sort_keys=True,separators=(',',':')),flush=True);return result

def run(args,C):
 global TOKEN
 TOKEN=os.environ.pop('GH_TOKEN','');own_run();need(args.component.is_absolute() and not args.component.exists() and args.component.parent.stat().st_uid==os.getuid() and not any(p.is_symlink() for p in (args.component,*args.component.parents)),'fresh owned cancellation directory');args.component.mkdir(mode=0o700)
 raw=C.read(args.proof,65536);proof=C.decode(raw);identity=dict(case=args.case,source_sha=proof['source_sha'],trial='full574-signed-repair',proof_sha256=C.sha(raw),consumer_token=proof['consumer_token'],producer_token=proof['job_token']);need(proof['case']==args.case and proof['outer_handoff']==str(args.handoff),'exact original case/handoff proof');S=C.load('self_cancel_original_process',args.source/'scripts/ci/orphans-full574-native/supervise.py');H=observe.helpers(args.source);stopped=threading.Event();state={};started=time.monotonic()
 def monitor():
  try:
   while not stopped.wait(.2) and time.monotonic()<started+3540:
    value=observe.frontier(args,C,S,identity,H)
    if value is not None:state['response']=cancel_once(args.component,value);return
   state['status']='FRONTIER_NOT_REACHED_NO_CANCEL_REQUEST'
  except BaseException as e:state.update(status='FRONTIER_OBSERVATION_FAILED_NO_CANCEL_AUTHORITY',error_type=type(e).__name__)
  finally:save(args.component/'observer.json',dict(state,transaction_outcome='UNKNOWN',cleanup_authority=False))
 thread=threading.Thread(target=monitor,daemon=True);thread.start();original=C.load('self_cancel_unchanged_repair_supervisor',args.source/NATIVE/'supervise.py');argv=[str(args.source/NATIVE/'supervise.py'),'run','--case',args.case]
 for name in ('source','packet','proof','base','output','handoff'):argv+=['--'+name,str(getattr(args,name))]
 before=sys.argv[:]
 try:
  sys.argv=argv;code=original.main() # Original supervisor owns real incoming SIGINT/SIGTERM and child retirement.
  need(code!=0,'original trial completed without actual workflow cancellation');return code
 finally:
  sys.argv=before;stopped.set();thread.join(timeout=.5)

def retain(args):
 need(args.public.is_dir(),'original public directory required');dest=args.public/'github-cancel';need(not dest.exists(),'fresh cancellation evidence destination');raws={}
 for name in ('before.json','cancel-intent.json','cancel-response.json','observer.json'):
  path=args.component/name
  if not path.exists():continue
  info=path.stat();need(info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o600,'original private cancellation receipt');raws[name]=read(path,65536)
 from prepare import OWN,WF
 for name in (*OWN,'source-manifest.json'):raws['source/'+name]=read(HERE/name,65536)
 raws['source/workflow.yml']=read(args.source/WF,65536);helper=observe.HELPER;raws['source/readonly-helper.py']=read(args.source/helper,65536)
 total=sum(map(len,raws.values()));need(total<=448*1024,'bounded diagnostic evidence');original=json.loads(read(args.public/'retention.json'));need(original['bytes']+total+65536<=192*1024**2,'original public aggregate cap remains192MiB');dest.mkdir(mode=0o700)
 for name,raw in raws.items():
  target=dest/name;target.parent.mkdir(parents=True,exist_ok=True,mode=0o700);fd=os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
  with os.fdopen(fd,'wb') as f:f.write(raw)
  need(read(target,65536)==raw,'original cancellation evidence bytes retained')
 save(dest/'closed.json',dict(status='ORIGINAL_GITHUB_CANCEL_DIAGNOSTICS_NOT_ACCEPTANCE',files={n:pin(raw) for n,raw in raws.items()},bytes=total,transaction_outcome='UNKNOWN',cleanup_authority=False,hardware='NOT_RUN',release='NOT_ADMITTED'))

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=('preflight','run','retain'));p.add_argument('--case',choices=('repair-bytes','repair-missing'),required=True)
 for name in ('source','packet','proof','base','output','handoff','component','public'):p.add_argument('--'+name,type=Path,required=name=='source')
 args=p.parse_args();args.source=args.source.absolute();C=source(args.source,args.case)
 if args.mode=='preflight':own_run();return 0
 if args.mode=='retain':retain(args);return 0
 return run(args,C)
if __name__=='__main__':raise SystemExit(main())
