# SPDX-License-Identifier: MIT
"""Fixed cache comparison after maintained actual PIDFD/GO; no journal replay."""
import hashlib,importlib.util,json,os,re,resource,signal,stat,subprocess,time
from pathlib import Path
HERE=Path(__file__).resolve().parent;OUT=Path('/output')
def load(name):
 s=importlib.util.spec_from_file_location('restored_executor_'+name,HERE/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(path):
 st=path.lstat();need(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and not path.is_symlink(),'ordinary single-link tool/public output')
 with path.open('rb')as f:sha=hashlib.file_digest(f,'sha256').hexdigest()
 return dict(bytes=st.st_size,sha256=sha)
def identity(st):return tuple(getattr(st,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def put(path,value,cap=16384):
 body=(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode();need(len(body)<=cap,'bounded canonical public command facts')
 with path.open('xb')as f:f.write(body)
 path.chmod(0o600)
def normalize(raw,S):
 lines=raw.splitlines(keepends=True);banners=[i for i,line in enumerate(lines)if re.fullmatch(S.BANNER+b'\n',line)]
 need(len(banners)==1,'one exact pinned debugfs banner');i=banners[0];return lines[i]+b''.join(lines[:i]+lines[i+1:])
def _execute(authority_path,authority_sha,diagnostic):
 R=load('recovery');M=load('inode_metadata');O=load('owned_process')
 diagnostic.stage('REQUEST',write=False)
 request_path=Path(authority_path);need(pin(request_path)['sha256']==authority_sha,'same exact Root comparison request');request=json.loads(request_path.read_bytes());R.require_issued(request)
 diagnostic.stage('TOOLS',write=False)
 for name,expected in R.TOOLS.items():
  path=Path(name);st=path.lstat();need(st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o755 and pin(path)==expected,'actual immutable529 tool bytes/mode/owner')
 diagnostic.stage('OUTPUT',write=False)
 need({p.name for p in OUT.iterdir()}=={'decoder.ready.json','decoder.go.json'},'fresh owned output contains only maintained handshake');(OUT/'scan').mkdir(mode=0o700);scan=OUT/'scan';diagnostic.stage('OUTPUT')
 remaining=signal.getitimer(signal.ITIMER_REAL)[0];need(0<remaining<=180,'inherited original180s alarm remains active');deadline=time.monotonic()+remaining
 rows={v:{}for v in('baseline','restored')};printed={v:{}for v in rows};independent={};executed=0;temp_identity=None
 for command in R.plan(request):
  label=command['label'];stage=command.get('stage');view=command.get('view');path=command.get('path')
  diagnostic.stage('PLAN',label)
  if stage=='body'and rows[view][path]is None:
   put(scan/(label+'.log'),dict(kind='FIXED_PUBLIC_PATH_ABSENT_NO_BODY',path=path,view=view))
   put(scan/(label+'.retirement.json'),dict(argv=command['argv'],executed=False,reason='PRIOR_LITERAL_STAT_ABSENT',result=None));continue
  budget=min(command['seconds'],deadline-time.monotonic());need(budget>3,'shared actual comparison deadline');O.prepare()
  def limits():
   cap=R.RAW_BYTES if label=='convert'else 1048576 if stage=='body'else 16384
   resource.setrlimit(resource.RLIMIT_FSIZE,(cap,cap));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
  diagnostic.stage('SPAWN',label)
  child=subprocess.Popen(command['argv'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,env=dict(PATH='/usr/bin:/bin',LC_ALL='C',TZ='UTC'),preexec_fn=limits)
  result=O.supervise(child,cap=budget,retirement=min(1,budget/4),grace=.1,max_output=16384);raw=result.pop('output');result['children_ru_maxrss_kib']=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss;executed+=1
  put(scan/(label+'.retirement.json'),dict(argv=command['argv'],executed=True,result=result))
  diagnostic.stage('RETIRE',label)
  need(result['passed']is True and result['reaped']is True and result['ownership']=='REAPED'and result['group_census']=='EMPTY_TWICE'and result['exit']==0 and result['signals']==[]and not result['timeout']and result['error']is None,'natural exact tool retirement required; no forced success')
  fact=dict(kind='VALIDATED_FIXED_PUBLIC_COMMAND_FRAME',frame=R.pin(raw))
  diagnostic.stage('FRAME',label);diagnostic.frame(raw)
  if label=='chain':fact['chain']=R.G.chain(raw,request['overlay']['pin']['bytes'])
  elif label=='convert':
   need(raw==b'','quiet fixed conversion');p=OUT/'observation.raw';st=p.lstat();need(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and st.st_uid==os.geteuid() and st.st_size==R.RAW_BYTES and st.st_blocks*512<=R.RAW_BYTES,'fresh bounded owned sparse temporary raw');temp_identity=identity(st)
  elif stage=='body':
   diagnostic.stage('BODY_PIN',label)
   need(re.fullmatch(R.S.BANNER+b'\n',raw)is not None,'only fixed debugfs dump banner');p=OUT/(view+'-'+('main'if path==R.FILES[0]else'aux')+'.bin');need(pin(p)['bytes']==rows[view][path]['size']<=1048576,'public body size matches prior literal stat')
  else:
   diagnostic.stage('NORMALIZE',label);normalized=normalize(raw,R.S)
   diagnostic.stage('PARSE_STAT',label);observed=R.S.parse_stat(normalized,path)
   diagnostic.stage('XATTR_DISPLAY_COUNT',label);count=R.S.printed_xattr_count(normalized,path);fact.update(path=path,view=view,stage=stage,stat=observed,printed_xattr_count=count)
   if stage=='before':
    diagnostic.stage('STAT_LINKS',label)
    need(observed is None or observed['type']=='directory' or observed['links']==1,'no unexpected public cache hardlink payload');rows[view][path]=observed;printed[view][path]=count
   else:
    diagnostic.stage('STAT_REPEAT',label);need(observed==rows[view][path]and count==printed[view][path],'exact repeated typed metadata around cache dumps')
   if path==R.PATHS[-1]:
    image=Path('/baseline/guest.raw')if view=='baseline'else OUT/'observation.raw';diagnostic.stage('INODE_READ',label);meta=M.observe(image,rows[view],deadline,diagnostic)
    diagnostic.stage('INODE_XATTR_COUNT',label);diagnostic.counts([dict(present=value is not None,expected=printed[view][name],actual=value['xattrs']['count']if value is not None else None,equal=value['xattrs']['count']==printed[view][name]if value is not None else None)for name,value in meta.items()])
    need(all(value is None or value['xattrs']['count']==printed[view][name]for name,value in meta.items()),'independent inode xattr count matches bounded display; no silent empty inference')
    if stage=='before':independent[view]=meta
    else:
     diagnostic.stage('INODE_REPEAT',label);need(meta==independent[view],'exact repeated independent inode/xattr facts')
  diagnostic.stage('WRITE_COMMAND_FACT',label)
  put(scan/(label+'.log'),fact)
 views=independent
 for view in('baseline','restored'):
  for key,path in(('main',R.FILES[0]),('aux',R.FILES[1])):
   source=OUT/(view+'-'+key+'.bin')
   if views[view][path]is None:need(not source.exists()and not source.is_symlink(),'absent public cache has no invented body artifact');continue
   views[view][path]['sha256']=pin(source)['sha256'];source.chmod(0o600);source.rename(scan/source.name)
 diagnostic.stage('BASELINE_COMPARE');comparison=R.compare(views,json.loads((HERE/'baseline-public.DATA.json').read_bytes()))
 diagnostic.stage('TEMP_REMOVE')
 p=OUT/'observation.raw';need(identity(p.lstat())==temp_identity,'same owned temporary raw remains unchanged');p.unlink();need(not p.exists()and not p.is_symlink(),'temporary raw removed; no raw publication')
 command_files={label+suffix for label in R.labels()for suffix in('.log','.retirement.json')}
 expected=command_files|(R.artifact_names(views)-{'commands.DATA.json'});diagnostic.stage('CONSOLIDATE')
 need({p.name for p in scan.iterdir()}==expected,'only fixed public artifacts, no raw or arbitrary path')
 commands={label:dict(facts=json.loads((scan/(label+'.log')).read_bytes()),retirement=json.loads((scan/(label+'.retirement.json')).read_bytes()))for label in R.labels()}
 put(scan/'commands.DATA.json',dict(kind='EXACT_FIXED_COMMAND_FACTS_AND_NATURAL_RETIREMENTS_V1',commands=commands,planned=18,executed=executed),65536)
 # Consolidate complete fixed receipts so both maintained16KiB parent summaries
 # retain their limits. On an earlier HOLD individual canonical receipts remain.
 for name in command_files:
  p=scan/name;st=p.lstat();need(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and st.st_uid==os.geteuid()and stat.S_IMODE(st.st_mode)==0o600,'only own fixed canonical receipt consolidation');p.unlink()
 need({p.name for p in scan.iterdir()}==R.artifact_names(views),'exact consolidated public artifacts')
 diagnostic.summary_pending()
 files={p.name:pin(p)for p in scan.iterdir()};need(sum(v['bytes']for v in files.values())+16384<=4*1024**2,'four-MiB whole public artifact cap')
 summary=dict(kind='OBSERVED_R94_THREE_PUBLIC_CACHE_DIAGNOSTIC_V2',status='PUBLIC_CACHE_FACTS_ONLY_CAUSE_UNPROVEN',request=pin(request_path),Source_lock=R.SOURCE,files=files,cache_observation=comparison,tools_reverified=True,commands=executed,planned_commands=18,all_tools_naturally_reaped=True,temporary_raw_removed=True,Root_acceptance=None,VM_acceptance=None,lifecycle_acceptance=None,M2=None,release=None)
 R.validate_summary(summary,pin(request_path),R.SOURCE);diagnostic.complete()
 final_diagnostic=pin(scan/'diagnostic.DATA.json');need(final_diagnostic['bytes']<=summary['files']['diagnostic.DATA.json']['bytes'],'final diagnostic fits already validated artifact cap');summary['files']['diagnostic.DATA.json']=final_diagnostic
 put(scan/'observation.DATA.json',summary);return 0

def execute(authority_path,authority_sha):
 # Even a natural diagnostic refusal must not publish a temporary raw image.
 # Only this fixed owned conversion name may be removed; input mounts stay RO.
 R=load('recovery');D=load('diagnostic');diagnostic=D.State(OUT,R.labels())
 temp=OUT/'observation.raw';need(not temp.exists()and not temp.is_symlink(),'fresh fixed temporary conversion output')
 try:return _execute(authority_path,authority_sha,diagnostic)
 except BaseException as error:
  diagnostic.fail(error);raise
 finally:
  if temp.exists()or temp.is_symlink():
   st=temp.lstat();need(stat.S_ISREG(st.st_mode)and st.st_uid==os.geteuid() and st.st_nlink==1 and 0<=st.st_size<=1610612736,'only owned bounded temporary conversion cleanup')
   temp.unlink()
  diagnostic.close()
