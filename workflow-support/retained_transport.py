#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One full retained DATA fetch, held1154 Git/blob proof, original cache join."""
import argparse,base64,hashlib,importlib.util,json,os,re,signal,stat,subprocess,sys,time,types
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent;M=1024**2
SOURCE='ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad';TREE='e21f947bac3afdfbd67e4e65c8234b35ae42b00f'
REPO='https://github.com/Gabriel-Kahen/cachy-asahi.git'
HELD={'owned_child.py':dict(bytes=10908,sha256='eaf9a46630e4fe4ca0a8f94a6dc2de4a881a6ad7e8b4dd0810b3347c0d7038d5'),'legacy_prefill.py':dict(bytes=5986,sha256='05a91a91efd69b3b2e06561f5bbf08bdbb105998d42dbf133e75fd1fe25945ac'),'carrier-profile.json':dict(bytes=195440,sha256='4089fd798849cafda23d03c0dd95ac896a83fd63ad21e331ae420c147535586c')}
PROOF_ENV={'PATH':os.defpath,'LANG':'C','LC_ALL':'C','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_NO_REPLACE_OBJECTS':'1','GIT_OPTIONAL_LOCKS':'0','GIT_NO_LAZY_FETCH':'1','GIT_TERMINAL_PROMPT':'0'}
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def decode(raw):
 def pairs(rows):
  out={}
  for k,v in rows:need(k not in out,'duplicate retained DATA key');out[k]=v
  return out
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite retained DATA JSON'))
def path(value):
 text=os.fspath(value);p=Path(text);need(p.is_absolute()and text==os.path.normpath(text)and not text.startswith('//')and not any(q.is_symlink()for q in(p,*p.parents)),'ordinary absolute retained DATA path');return p
def identity(s):return tuple(getattr(s,n)for n in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def read(p,cap=4*M):
 p=path(p);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<=s.st_size<=cap,'bounded singlelink retained DATA');parts=[];size=0
  while raw:=os.read(fd,min(M,cap+1-size)):parts.append(raw);size+=len(raw);need(size<=s.st_size,'retained DATA growth')
  need(size==s.st_size and identity(s)==identity(os.fstat(fd))==identity(p.lstat()),'stable retained DATA FD/path');return b''.join(parts)
 finally:os.close(fd)
def save(p,v):
 raw=encoded(v);cap=128*1024 if p.name in('transport.json','proof.json','retention.json')else 4*M;need(len(raw)<=cap,'bounded retained report');temporary=p.with_name(p.name+'.new');fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 with os.fdopen(fd,'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
 os.replace(temporary,p)
def held(name):
 raw=read(HERE/name);need(pin(raw)==HELD[name],'whole held helper '+name);spec=importlib.util.spec_from_file_location('_apps607_retained_'+name[:-3],HERE/name);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def profile():
 raw=read(HERE/'carrier-profile.json');need(pin(raw)==HELD['carrier-profile.json'],'whole1154 retained profile');p=decode(raw);need(p['source']==SOURCE and p['actual']is None and len(p['files'])==1154 and sum(v['bytes']for v in p['files'].values())==1046432165,'complete retained1154/1046432165B profile');return p
def who():
 e=os.environ;source=e.get('SOURCE_SHA','');run=e.get('GITHUB_RUN_ID','');attempt=e.get('GITHUB_RUN_ATTEMPT','');need(re.fullmatch('[0-9a-f]{40}',source)and source==e.get('GITHUB_SHA')==e.get('GITHUB_WORKFLOW_SHA')and re.fullmatch('[1-9][0-9]*',run)and re.fullmatch('[1-9][0-9]*',attempt),'actual same source/run/attempt transport identity')
 need(e.get('OPERATION')=='recover-apps16-reinstall607'and all(re.fullmatch('[0-9a-f]{64}',e.get(n,''))for n in('CAPSULE_SHA256','OPERATION_PROFILE_SHA256')),'source-bound independent operation pins')
 return dict(source_sha=source,run_id=int(run),attempt=int(attempt),token=hashlib.sha256(('apps607-consumer:'+run+':'+attempt+':'+source).encode()).hexdigest()[:32],operation=e['OPERATION'],capsule_sha256=e['CAPSULE_SHA256'],operation_profile_sha256=e['OPERATION_PROFILE_SHA256'])
def paths():
 temp=path(os.environ['RUNNER_TEMP']);s=temp.stat();need(stat.S_ISDIR(s.st_mode)and s.st_uid==os.getuid()and not stat.S_IMODE(s.st_mode)&0o022,'owned nonforeign-writable runtime temp')
 carrier=temp/'apps607-retained-complete574';public=temp/'apps607-retained-transport-public';need(all(not p.is_relative_to(ROOT)and not ROOT.is_relative_to(p)for p in(carrier,public)),'retained DATA outside complete executable source');return temp,carrier,public

def base_report(phase,owner,carrier):return dict(schema_version=1,phase=phase,status='FAIL_'+phase.upper()+'_DATA',identity=owner,carrier_source=SOURCE,carrier_tree=TREE,carrier_path=str(carrier),source_root=str(ROOT),retry=False,acceptance=False,native='NOT_RUN',cleanup_authority=False,partial_data_retained=True)
def retired(completed,row):
 need(completed.returncode==row.get('exit')==0 and all(row.get(n)is True for n in('natural_exit','group_absent','leader_held_until_group_inspection','exit_observed_via_waitpid'))and row.get('ownership_lost')is False and row.get('forced_cleanup')is False and row.get('retirement')=='REAPED','direct-owned natural exit and group retirement')
def transport_plan(carrier):
 git=['/usr/bin/git','-c','credential.helper=','-c','http.extraHeader=','-c','http.sslVerify=true','-c','core.hooksPath=/dev/null','-c','protocol.allow=never','-c','protocol.https.allow=always']
 return [([*git,'init','--template=',str(carrier)],10),([*git,'-C',str(carrier),'-c','http.lowSpeedLimit=65536','-c','http.lowSpeedTime=60','fetch','--depth=1','--no-tags','--no-recurse-submodules',REPO,SOURCE],400),([*git,'-C',str(carrier),'rev-parse','--verify','FETCH_HEAD'],10),([*git,'-C',str(carrier),'checkout','--detach',SOURCE],45),([*git,'-C',str(carrier),'rev-parse','--verify','HEAD'],10)]
def transport():
 owner=who();temp,carrier,public=paths();profile();need(not os.path.lexists(carrier)and not os.path.lexists(public),'fresh once-only external DATA and public report');public.mkdir(mode=0o700);report=base_report('transport',owner,carrier);report.update(budget_seconds=480,command_caps=[10,400,10,45,10],actors=[]);save(public/'transport.json',report);owned=held('owned_child.py');deadline=time.monotonic()+480
 try:
  carrier.mkdir(mode=0o700)
  env=dict(PROOF_ENV,HOME=str(public),GIT_CONFIG_COUNT='0')
  for i,(argv,seconds)in enumerate(transport_plan(carrier)):
   left=deadline-time.monotonic();need(left>0,'aggregate480s transport bound');row=dict(argv=argv,timeout_seconds=seconds,stdout_stderr='COMBINED',log='transport-%02d.log'%i);report['actors'].append(row);life={}
   try:
    with(public/row['log']).open('xb')as stream:result=owned.run(argv,stdin=subprocess.DEVNULL,stdout=stream,stderr=subprocess.STDOUT,timeout=min(seconds,left),env=env,lifecycle=life,allowed_uids={os.geteuid()},stdout_limit=256*1024,stderr_limit=256*1024)
    retired(result,life);body=read(public/row['log'],256*1024);row['log_pin']=pin(body)
    if i in(2,4):need(body.decode().strip()==SOURCE,'exact fetched and checked-out retained commit')
   finally:row['owned_child']=life;save(public/'transport.json',report)
  report['status']='PASS_EXACT_RETAINED_INPUT_TRANSPORT_DATA_ONLY'
 except BaseException as error:report.update(error_type=type(error).__name__,error=str(error)[:2048]);raise
 finally:report['elapsed_seconds']=480-(deadline-time.monotonic());save(public/'transport.json',report)
 return report

def prior(public,name,owner,status):
 raw=read(public/name);v=decode(raw);need(v['identity']==owner and v['status']==status and v['carrier_source']==SOURCE and v['carrier_tree']==TREE and v['retry']is False and v['acceptance']is False,'matching successful previous DATA stage '+name);return v,pin(raw)
def proof_adapter(owned,carrier,p,deadline,rows,public):
 """Held complete proof gets exact selected per-blob stdout bound, never8MiB truncation."""
 def run(argv,**kwargs):
  values=list(map(str,argv));prefix=['/usr/bin/git','--git-dir='+str(carrier/'.git'),'-c','protocol.allow=never'];need(values[:4]==prefix and set(kwargs)=={'capture_output','timeout','env','check'}and kwargs['capture_output']is True and kwargs['check']is False and kwargs['env']==PROOF_ENV,'exact captured read-only proof call')
  tail=values[4:];limit=2*M
  if tail==['cat-file','commit',SOURCE]:limit=65536
  elif tail==['ls-tree','-rz','--full-tree',SOURCE]:pass
  else:
   need(len(tail)==3 and tail[:2]==['cat-file','blob']and tail[2].startswith(SOURCE+':'),'exact fixed source proof blob');name=tail[2][len(SOURCE)+1:];need(name in p['files'],'selected full carrier blob');limit=p['files'][name]['bytes'];need(type(limit)is int and 0<limit<=128*M,'original128MiB selected whole blob bound')
  left=deadline-time.monotonic();need(left>0 and len(rows)<1156 and type(kwargs['timeout'])in(int,float)and 0<kwargs['timeout']<=240,'original complete proof aggregate240s bound');life={};row=dict(argv=values,stdout_limit=limit)
  rows.append(row)
  try:
   result=owned.run(values,stdin=subprocess.DEVNULL,capture_output=True,timeout=min(kwargs['timeout'],left),env=PROOF_ENV,lifecycle=life,allowed_uids={os.geteuid()},stdout_limit=limit,stderr_limit=65536);need(type(result.stdout)is bytes and type(result.stderr)is bytes and len(result.stdout)<=limit and len(result.stderr)<=65536,'whole bounded binary Git proof');row.update(stdout=pin(result.stdout),stderr=pin(result.stderr))
   if result.stderr:row['stderr_data']=dict(encoding='BASE64',base64=base64.b64encode(result.stderr).decode())
   retired(result,life);need(not result.stderr,'original read-only Git proof stderr refusal');return result
  finally:row['owned_child']=life;save(public/'proof-actors.json',rows)
 return run

def prove():
 owner=who();temp,carrier,public=paths();p=profile();previous,previous_pin=prior(public,'transport.json',owner,'PASS_EXACT_RETAINED_INPUT_TRANSPORT_DATA_ONLY');need(previous['carrier_path']==str(carrier)and not os.path.lexists(public/'proof.json')and not os.path.lexists(public/'proof-actors.json'),'same external carrier and fresh proof stage');report=base_report('proof',owner,carrier);report.update(transport_pin=previous_pin,budget_seconds=240,profile=HELD['carrier-profile.json']);save(public/'proof.json',report);L=held('legacy_prefill.py');owned=held('owned_child.py');deadline=time.monotonic()+240;rows=[]
 try:
  L.subprocess=types.SimpleNamespace(run=proof_adapter(owned,carrier,p,deadline,rows,public))
  result=L.prove(carrier,carrier/'.git',p,deadline)
  need(result==dict(source=SOURCE,ref=p['ref'],files=1154,blob_joins=1154,tree=TREE,status='WHOLE_IMMUTABLE_SOURCE_GIT_JOIN_NO_NATIVE_AUTHORITY')and len(rows)==1156,'complete1154 physical/Git/blob/mode/tree proof')
  report.update(status='PASS_WHOLE_IMMUTABLE_RETAINED_SOURCE_DATA_ONLY',proof=result,actor_count=len(rows),proof_actors_pin=pin(read(public/'proof-actors.json')))
 except BaseException as error:report.update(error_type=type(error).__name__,error=str(error)[:2048]);raise
 finally:report['elapsed_seconds']=240-(deadline-time.monotonic());save(public/'proof.json',report)
 return report
def seed():
 owner=who();temp,carrier,public=paths();p=profile();previous,previous_pin=prior(public,'proof.json',owner,'PASS_WHOLE_IMMUTABLE_RETAINED_SOURCE_DATA_ONLY');need(previous['carrier_path']==str(carrier)and not os.path.lexists(public/'seed.json'),'same external carrier and fresh original seed stage');need(pin(read(public/'proof-actors.json'))==previous['proof_actors_pin'],'whole original proof actor receipt');report=base_report('seed',owner,carrier);report.update(proof_pin=previous_pin,budget_seconds=240,mode='desktop574');save(public/'seed.json',report);deadline=time.monotonic()+240
 try:
  body=read(carrier/'seed.py',65536);need(pin(body)==p['files']['seed.py'],'immediate original immutable seed source pin');module=types.ModuleType('_held_apps607_complete574_seed');module.__file__=str(carrier/'seed.py');exec(compile(body,module.__file__,'exec'),module.__dict__)
  receipt=module.seed(carrier/'desktop574-inputs.lock.json',temp/'alarm-cache','desktop574',deadline)
  need(receipt['status']=='EXACT_PUBLIC_CACHE_INPUTS_JOINED_NOT_AUTHENTICATED'and receipt['actual_authority']is False and receipt['mode']=='desktop574'and receipt['cache']['all_previous_inode_metadata_bytes_unchanged']is True,'original full574 cache DATA join and all prior inodes held')
  report.update(status='PASS_ORIGINAL_COMPLETE574_CACHE_DATA_ONLY',seed_source=p['files']['seed.py'],receipt=receipt)
 except BaseException as error:report.update(error_type=type(error).__name__,error=str(error)[:2048]);raise
 finally:report['elapsed_seconds']=240-(deadline-time.monotonic());save(public/'seed.json',report)
 return report

def retain():
 owner=who();temp,carrier,public=paths();need(not public.is_symlink(),'ordinary public DATA directory')
 if not public.exists():public.mkdir(mode=0o700)
 need(public.is_dir()and public.stat().st_uid==os.getuid()and stat.S_IMODE(public.stat().st_mode)==0o700 and not os.path.lexists(public/'retention.json'),'owned fresh DATA retention index')
 missing=[]
 for phase in('transport','prove','seed'):
  for side in('stdout','stderr','exit'):
   source=temp/('apps607-retained-'+phase+'.'+side);target=public/('outer-'+phase+'.'+side)
   if not os.path.lexists(source):missing.append(source.name);continue
   raw=read(source,16 if side=='exit'else 65536)
   if side=='exit':need(re.fullmatch(rb'[0-9]{1,3}\n',raw)and 0<=int(raw)<=255,'original outer shell exit code')
   with target.open('xb')as stream:stream.write(raw)
 reports={'transport.json','proof.json','proof-actors.json','seed.json'}
 allowed=reports|{n+'.new'for n in reports}|{'transport-%02d.log'%i for i in range(5)}|{'outer-'+p+'.'+s for p in('transport','prove','seed')for s in('stdout','stderr','exit')}
 files={};total=0
 for entry in public.iterdir():
  need(entry.name in allowed and not entry.is_symlink(),'finite public DATA roles only');raw=read(entry,4*M);files[entry.name]=pin(raw);total+=len(raw)
  if entry.name in('transport.json','proof.json','seed.json'):need(decode(raw)['identity']==owner,'same source/run/attempt public phase')
 need(total<=15*M,'complete retained DATA below source16MiB expanded logger cap')
 report=dict(schema_version=1,status='RETAINED_BOUNDED_COMPLETE574_DATA_NOT_ACCEPTANCE',identity=owner,files=files,bytes=total,missing_outer_files=missing,uncommitted_report_files=sorted(n for n in files if n.endswith('.new')),partial_data_retained=True,native='NOT_RUN',cleanup_authority=False,acceptance=False)
 save(public/'retention.json',report);return report

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mode',choices=('transport','prove','seed','retain'));args=parser.parse_args()
 def cancel(*unused):raise KeyboardInterrupt('owned retained DATA phase cancelled')
 for sig in(signal.SIGTERM,signal.SIGINT):signal.signal(sig,cancel)
 try:result=globals()[args.mode]();print(encoded({k:v for k,v in result.items()if k not in('actors','receipt')}).decode(),end='');return 0
 except BaseException as error:print(type(error).__name__+': '+str(error)[:2048],file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
