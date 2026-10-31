# SPDX-License-Identifier: MIT
"""Retain one genuine already-retired generated image-id between whole owners."""
import hashlib,json,math,os,re,stat,time
from pathlib import Path

def need(v,s):
 if not v:raise ValueError(s)
def identity(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))
def read(p,cap):
 p=Path(p);need(not any(x.is_symlink()for x in(p,*p.parents)),'ordinary owned retirement path');fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_uid==os.getuid()and a.st_size<=cap,'bounded caller-owned retirement metadata');raw=os.read(fd,cap+1);need(len(raw)==a.st_size and identity(a)==identity(os.fstat(fd))==identity(p.lstat()),'whole stable generated metadata');return raw,identity(a)
 finally:os.close(fd)
def handoff(producer,core_output,proof,cleanup,command,deadline):
 need(type(deadline)in(int,float)and math.isfinite(deadline)and time.monotonic()<deadline,"remaining original producer cleanup allowance, no reset")
 producer,core_output=Path(producer),Path(core_output);need(producer.parent==Path('/tmp')and core_output.parent==producer.parent and producer.is_absolute()and core_output.is_absolute()and producer!=core_output,'same fresh original owner siblings');base=producer/'private/desktop574';iid=base/'image-id';raw,iid_identity=read(iid,128);need(re.fullmatch(b'sha256:[a-f0-9]{64}\n',raw)is not None,'entire exact generated image-id bytes');image=raw.decode().strip();report=json.loads(read(base/'report.json',2*1024**2)[0]);owner=json.loads(read(producer/'producer-owner.json',2*1024**2)[0]);need(re.fullmatch('[a-f0-9]{32}',owner['token'])and image!=owner['core_image']and image not in owner['images_preexisting'],'never retire/move borrowed image authority')
 need(report['image']==image and report['ownership']['token']==proof['producer_token']and image not in report['ownership']['before_images'],'actual base image/token equality');retired=report['owned_cleanup'];need(retired['status']=='PASS'and retired['image']==dict(id=image,absence_verified=True)and retired['probe']['absence_verified']is True,'entire original base cleanup required')
 need(cleanup['status']=='PASS_ALL_VM_THEN_ORIGINAL800_CONSUMER_PRODUCER_RETIREMENT'and cleanup['original_cleanup']==0,'VM and entire original Core cleanup precede ownership handoff')
 # This is an independent live absence query in the current owned run, not
 # authority inferred from an earlier receipt, a suppressed rm or cached result.
 result=command(['/usr/bin/docker','image','inspect',image],False,min(20,deadline-time.monotonic()));need(time.monotonic()<deadline,'original shared producer cleanup allowance after query');need(result['code']==1 and image.encode()in result['err']and b'No such image'in result['err']and result['out'].strip()in(b'',b'[]'),'unambiguous independently observed exact image absence')
 need(identity(iid.lstat())==iid_identity and read(iid,128)[0]==raw,'same generated image-id before move');target=core_output/'image-retirement';need(not os.path.lexists(target)and core_output.is_dir()and core_output.stat().st_uid==os.getuid(),'fresh caller-owned public retirement role');target.mkdir(mode=0o700);iid.rename(target/'original-desktop574-image-id');need(not os.path.lexists(iid)and read(target/'original-desktop574-image-id',128)[0]==raw,'only exact generated marker moved, raw DATA retained')
 value=dict(schema=1,status='EXACT_ORIGINAL_BASE_IMAGE_RETIRED_BEFORE_FRESH_PRODUCER_PRIVATE_CLEANUP',image=image,producer_token=proof['producer_token'],parent_producer_token=owner['token'],original_core_cleanup=cleanup['status'],independent_absence=True,marker=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()),borrowed_core_image='PRESERVED',native_result='NOT_GRANTED_BY_THIS_RECEIPT');(target/'retirement.json').write_text(json.dumps(value,sort_keys=True,indent=2)+'\n');return value

def prepare_owned(original,args,prepare,caller_pin,core_source,source_fact,command_factory,capture,end,dependency_capture=None):
 """Use the existing genuine owned574 build branch before image creation."""
 import ast,inspect
 import desktop622 as X
 caller=Path(args.code)/'scripts/ci/full-root-upgrade-caller/run.py';old_load=original.load;restores=[]
 def helper():return owned_helper(args,core_source,source_fact)
 def callback(argv,log,timeout,code,error):
  try:capture(desktop_note(args,helper(),token(Path(args.output)/'private'),argv,log,timeout,code,error,end))
  except BaseException:pass # Optional fixed DATA never replaces original failure.

 def token(raw):
  need(Path(raw)==Path(args.output)/'private','same original producer private root');owner=json.loads(read(Path(args.output)/'producer-owner.json',65536)[0]);need(owner['schema_version']==1 and re.fullmatch('[a-f0-9]{32}',owner['token'])and owner['preparation_source']==str(args.preparation_source),'same actual parent producer source/instance');return hashlib.sha256(('core622-owned574:'+owner['token']).encode()).hexdigest()[:16]
 def load(path):
  api=old_load(path)
  if Path(path)==caller:
   raw=read(caller,128*1024)[0];need(hashlib.sha256(raw).hexdigest()==caller_pin,'entire immutable original fresh caller');tree=ast.parse(raw);nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='desktop'];need(len(nodes)==1,'one original574 producer function');body=ast.get_source_segment(raw.decode(),nodes[0]);need(inspect.getsource(api.desktop).strip()==body,'actual original producer function identity')
   edits=(("helper = source / 'scripts/ci/maintained_desktop574.py'","helper = CURRENT_CORE622_OWNED_HELPER()"),("command([sys.executable, '-I', '-B', helper, 'build'","CURRENT_CORE622_DESKTOP_COMMAND([sys.executable, '-I', '-B', helper, 'build'"),("work = root / 'desktop574'; work.mkdir()","work = root / 'desktop574'; work.mkdir(mode=0o700)"),("'--output', work], work / 'build.log', 2400)","'--output', work, '--job-token', CURRENT_CORE622_BASE_TOKEN(root)], work / 'build.log', 2400)"));changed=body
   for a,b in edits:need(changed.count(a)==1,'one owned base CLI seam');changed=changed.replace(a,b)
   inverse=changed
   for a,b in reversed(edits):need(inverse.count(b)==1,'unique owned base inverse');inverse=inverse.replace(b,a)
   need(inverse==body,'entire original default desktop function inverse');prior=api.desktop;missing=object();names={'CURRENT_CORE622_BASE_TOKEN':token,'CURRENT_CORE622_OWNED_HELPER':helper,'CURRENT_CORE622_DESKTOP_COMMAND':command_factory(api.command,raw,callback)};previous={n:vars(api).get(n,missing)for n in names};vars(api).update(names);exec(compile(changed,'original-fresh-desktop-with-existing-job-token-role','exec'),vars(api));restores.append((api,prior,missing,previous))
  return api
 def prefix(api,path):
  fn,digest=original.preparation_prefix(api,path);need(fn.__globals__ is vars(api),'actual unchanged preparation prefix globals');raw=read(Path(path),128*1024)[0];need(hashlib.sha256(raw).hexdigest()==caller_pin,'whole original actual caller before dependency callback');prior=api.command;old_callback=prior.__globals__.get('_producer_failure_callback')
  def callback(argv,log,timeout,code,error):
   if old_callback is not None:
    try:old_callback(argv,log,timeout,code,error)
    except BaseException:pass
   if dependency_capture is not None:
    try:dependency_capture(dependency_note(args,argv,log,timeout,code,error,end))
    except BaseException:pass
  import types
  namespace=dict(fn.__globals__,command=command_factory(prior,raw,callback));selected=types.FunctionType(fn.__code__,namespace,fn.__name__,fn.__defaults__,fn.__closure__);need(selected.__code__ is fn.__code__ and selected.__globals__['command']is namespace['command'],'actual prefix command facade, original full body/digest held');return selected,digest
 scoped=X.clone(original,load=load,preparation_prefix=prefix)
 try:return prepare(scoped,args)
 finally:
  for api,prior,missing,previous in restores:
   api.desktop=prior
   for name,value in previous.items():
    if value is missing:vars(api).pop(name,None)
    else:vars(api)[name]=value

# Fixed first-builder failure DATA only; no new transport/member/authority.
DESKTOP_LOG_MAX=16*1024**2
DESKTOP_TAIL_MAX=2048
DESKTOP_NOTE_MAX=6144
UNOWNED_DESKTOP_SHA='80fde943f82def61f2f1734388a8e27b8e0a6c8d83b758eb91bd6ccc0bfeae7d'
OWNED_CLOSURE=('runtime/runtime-vm/scripts/ci/maintained_desktop574.py','runtime/runtime-vm/scripts/ci/maintained-desktop574-inputs.json','runtime/runtime-vm/scripts/ci/old_four_seed.py')

def owned_helper(args,core_source,source_fact):
 """Same already proven Core800 Git role; recheck its actual helper closure."""
 profile=json.loads(read(Path(__file__).with_name('profile.json'),4*1024**2)[0])['source_profiles']['core800'];root=Path(core_source)
 need(root.is_absolute()and root==root.resolve()and not any(p.is_symlink()for p in(root,*root.parents))and root.is_dir(),'literal already proven Core source role')
 need(source_fact['status']=='WHOLE_IMMUTABLE_SOURCE_GIT_JOIN_NO_NATIVE_AUTHORITY'and source_fact['source']==profile['source']and source_fact['ref']==profile['ref']and source_fact['files']==source_fact['blob_joins']==len(profile['files'])and re.fullmatch('[0-9a-f]{40}',source_fact['tree']),'same full Core800 source/Git proof before selected build')
 for name in OWNED_CLOSURE:
  raw=read(root/name,4*1024**2)[0];need(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())==profile['files'][name],'whole required owned helper closure before build')
 legacy=Path(args.desktop)/'scripts/ci';old=read(legacy/'maintained_desktop574.py',128*1024)[0];need(hashlib.sha256(old).hexdigest()==UNOWNED_DESKTOP_SHA,'exact original unowned9a2 helper/default preserved')
 inputs=read(legacy/'maintained-desktop574-inputs.json',4*1024**2)[0];need(inputs==read(root/OWNED_CLOSURE[1],4*1024**2)[0]and hashlib.sha256(inputs).hexdigest()=='b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9','identical complete574 input lock, no source substitution')
 return root/OWNED_CLOSURE[0]

def desktop_note(args,helper,token,argv,log,timeout,code,error,end):
 import base64
 values=list(map(str,argv));work=Path(args.output)/'private/desktop574';expected=[str(__import__('sys').executable),'-I','-B',str(helper),'build','--inputs',str(Path(args.desktop)/'scripts/ci/maintained-desktop574-inputs.json'),'--output',str(work),'--job-token',token]
 need(values==expected and Path(log)==work/'build.log'and type(timeout)is int and timeout==2400 and re.fullmatch('[0-9a-f]{16}',token),'only exact first owned desktop574 build failure role')
 need(code is None or type(code)is int and -(2**31)<=code<2**31,'original bounded returncode type');need(error is None or isinstance(error,BaseException),'original wait exception type');need(code!=0 or error is not None,'success never emits failure DATA')
 wait=None if error is None else type(error).__name__;wait=wait if wait in(None,'TimeoutExpired','InterruptedError','KeyboardInterrupt','SystemExit','AssertionError','OSError','ProcessLookupError')else'OTHER_BASE_EXCEPTION'
 note=dict(schema=1,purpose='CORE622_FIRST_DESKTOP574_BUILD_FAILURE_DATA_ONLY',stage='BEFORE_PRIVATE_PRODUCER_CLEANUP',acceptance_authority=False,cleanup_authority=False,command=dict(role='FIRST_DESKTOP574_OWNED_BUILD',argv_sha256=hashlib.sha256(json.dumps(values,separators=(',',':'),ensure_ascii=True).encode()).hexdigest(),timeout_seconds=2400,returncode=code,wait_error_type=wait,retirement='ORIGINAL_COMMAND_FLOW_NOT_INDEPENDENTLY_REOBSERVED'),log=dict(status='UNAVAILABLE_UNSAFE_CHANGED_OR_BOUNDED'))
 try:
  path=work/'build.log';need(type(end)in(int,float)and math.isfinite(end)and time.monotonic()<end,'remaining original outer deadline during optional capture');need(path==path.resolve()and not any(p.is_symlink()for p in(path,*path.parents)),'fixed ordinary build log path');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
  try:
   before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_uid==os.geteuid()and 0<=before.st_size<=DESKTOP_LOG_MAX,'bounded owned first build log');digest=hashlib.sha256();tail=b'';size=0
   while True:
    need(time.monotonic()<end,'same original deadline, no capture clock reset');part=os.read(fd,65536)
    if not part:break
    size+=len(part);need(size<=before.st_size,'bounded stable complete log read');digest.update(part);tail=(tail+part)[-DESKTOP_TAIL_MAX:]
   need(size==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'whole stable descriptor/path log read');note['log']=dict(status='CAPTURED_BOUNDED_FULL_HASH_AND_TAIL',file_bytes=size,file_sha256=digest.hexdigest(),offset=size-len(tail),tail_bytes=len(tail),tail_sha256=hashlib.sha256(tail).hexdigest(),encoding='BASE64',tail_base64=base64.b64encode(tail).decode())
  finally:os.close(fd)
 except FileNotFoundError:note['log']=dict(status='UNAVAILABLE_NOT_PRESENT')
 except (OSError,ValueError):pass
 validate_desktop_note(note);return note

def validate_desktop_note(value):
 import base64
 need(type(value)is dict and set(value)=={'schema','purpose','stage','acceptance_authority','cleanup_authority','command','log'}and type(value['schema'])is int and value['schema']==1 and value['purpose']=='CORE622_FIRST_DESKTOP574_BUILD_FAILURE_DATA_ONLY'and value['stage']=='BEFORE_PRIVATE_PRODUCER_CLEANUP'and value['acceptance_authority']is value['cleanup_authority']is False,'fixed failure-only desktop note schema')
 command=value['command'];need(type(command)is dict and set(command)=={'role','argv_sha256','timeout_seconds','returncode','wait_error_type','retirement'}and command['role']=='FIRST_DESKTOP574_OWNED_BUILD'and re.fullmatch('[0-9a-f]{64}',command['argv_sha256'])and type(command['timeout_seconds'])is int and command['timeout_seconds']==2400 and(command['returncode']is None or type(command['returncode'])is int and -(2**31)<=command['returncode']<2**31)and(command['returncode']!=0 or command['wait_error_type']is not None)and command['wait_error_type']in(None,'TimeoutExpired','InterruptedError','KeyboardInterrupt','SystemExit','AssertionError','OSError','ProcessLookupError','OTHER_BASE_EXCEPTION')and command['retirement']=='ORIGINAL_COMMAND_FLOW_NOT_INDEPENDENTLY_REOBSERVED','fixed original command failure metadata')
 log=value['log'];need(type(log)is dict,'typed fixed log record')
 if log.get('status')in('UNAVAILABLE_NOT_PRESENT','UNAVAILABLE_UNSAFE_CHANGED_OR_BOUNDED'):need(set(log)=={'status'},'unavailable note contains no substituted contents')
 else:
  need(set(log)=={'status','file_bytes','file_sha256','offset','tail_bytes','tail_sha256','encoding','tail_base64'}and log['status']=='CAPTURED_BOUNDED_FULL_HASH_AND_TAIL'and type(log['file_bytes'])is int and 0<=log['file_bytes']<=DESKTOP_LOG_MAX and type(log['offset'])is int and type(log['tail_bytes'])is int and log['tail_bytes']==min(log['file_bytes'],DESKTOP_TAIL_MAX)and log['offset']==log['file_bytes']-log['tail_bytes']and log['encoding']=='BASE64'and all(re.fullmatch('[0-9a-f]{64}',log[k])for k in('file_sha256','tail_sha256'))and type(log['tail_base64'])is str and len(log['tail_base64'])<=4*((DESKTOP_TAIL_MAX+2)//3),'bounded exact full log and tail metadata');raw=base64.b64decode(log['tail_base64'],validate=True);need(len(raw)==log['tail_bytes']and base64.b64encode(raw).decode()==log['tail_base64']and hashlib.sha256(raw).hexdigest()==log['tail_sha256'],'canonical exact tail encoding and hash')
  if log['offset']==0:need(log['file_sha256']==log['tail_sha256'],'complete small log hash equality')
 need(len((json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode())<=DESKTOP_NOTE_MAX,'fixed optional DATA bound inside existing4MiB caller result');return value

def dependency_note(args,argv,log,timeout,code,error,end):
 import base64
 values=list(map(str,argv));work=Path(args.output)/'private';preparation=Path(args.preparation_source)/'scripts/ci/full-development-composition/dependencies';expected=[str(__import__('sys').executable),'-B',str(preparation/'acquire.py'),'--source-root',str(args.updater),'--cache',str(args.cache),'--keydir',str(args.cache),'--output',str(work/'dependency-audit')]
 need(values==expected and Path(log)==work/'dependency.log'and type(timeout)is int and timeout==180,'only exact dependency11argv/180 failure role')
 config=json.loads(read(Path(__file__).with_name('composition-parent.json'),4*1024**2)[0])['dependency_cache_context']['dependency_cache']
 for name,w in config['preparation_files'].items():
  body=read(Path(args.preparation_source)/name,4*1024**2)[0];need(dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest())==w,'same exact original93bc dependency source and lock')
 owner=json.loads(read(Path(args.output)/'producer-owner.json',65536)[0]);need(owner['schema_version']==1 and re.fullmatch('[0-9a-f]{32}',owner['token'])and owner['preparation_source']==str(args.preparation_source),'actual same original dependency producer instance')
 need(code is None or type(code)is int and -(2**31)<=code<2**31,'original bounded returncode type');need(error is None or isinstance(error,BaseException),'original wait exception type');need(code!=0 or error is not None,'success never emits failure DATA')
 wait=None if error is None else type(error).__name__;wait=wait if wait in(None,'TimeoutExpired','InterruptedError','KeyboardInterrupt','SystemExit','AssertionError','OSError','ProcessLookupError')else'OTHER_BASE_EXCEPTION'
 note=dict(schema=1,purpose='CORE622_FIXED_FIVE_DEPENDENCY_FAILURE_DATA_ONLY',stage='BEFORE_PRIVATE_PRODUCER_CLEANUP',acceptance_authority=False,cleanup_authority=False,command=dict(role='AUTHENTICATE_FIVE_DEDUPLICATE_FOUR',argv_sha256=hashlib.sha256(json.dumps(values,separators=(',',':'),ensure_ascii=True).encode()).hexdigest(),timeout_seconds=180,returncode=code,wait_error_type=wait,retirement='ORIGINAL_COMMAND_FLOW_NOT_INDEPENDENTLY_REOBSERVED'),log=dict(status='UNAVAILABLE_UNSAFE_CHANGED_OR_BOUNDED'))
 try:
  path=work/'dependency.log';need(type(end)in(int,float)and math.isfinite(end)and time.monotonic()<end,'remaining original outer deadline during optional capture');need(path==path.resolve()and not any(p.is_symlink()for p in(path,*path.parents)),'fixed ordinary build log path');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
  try:
   before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_uid==os.geteuid()and 0<=before.st_size<=DESKTOP_LOG_MAX,'bounded owned first build log');digest=hashlib.sha256();tail=b'';size=0
   while True:
    need(time.monotonic()<end,'same original deadline, no capture clock reset');part=os.read(fd,65536)
    if not part:break
    size+=len(part);need(size<=before.st_size,'bounded stable complete log read');digest.update(part);tail=(tail+part)[-DESKTOP_TAIL_MAX:]
   need(size==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'whole stable descriptor/path log read');note['log']=dict(status='CAPTURED_BOUNDED_FULL_HASH_AND_TAIL',file_bytes=size,file_sha256=digest.hexdigest(),offset=size-len(tail),tail_bytes=len(tail),tail_sha256=hashlib.sha256(tail).hexdigest(),encoding='BASE64',tail_base64=base64.b64encode(tail).decode())
  finally:os.close(fd)
 except FileNotFoundError:note['log']=dict(status='UNAVAILABLE_NOT_PRESENT')
 except (OSError,ValueError):pass
 validate_dependency_note(note);return note

def validate_dependency_note(value):
 import base64
 need(type(value)is dict and set(value)=={'schema','purpose','stage','acceptance_authority','cleanup_authority','command','log'}and type(value['schema'])is int and value['schema']==1 and value['purpose']=='CORE622_FIXED_FIVE_DEPENDENCY_FAILURE_DATA_ONLY'and value['stage']=='BEFORE_PRIVATE_PRODUCER_CLEANUP'and value['acceptance_authority']is value['cleanup_authority']is False,'fixed failure-only desktop note schema')
 command=value['command'];need(type(command)is dict and set(command)=={'role','argv_sha256','timeout_seconds','returncode','wait_error_type','retirement'}and command['role']=='AUTHENTICATE_FIVE_DEDUPLICATE_FOUR'and re.fullmatch('[0-9a-f]{64}',command['argv_sha256'])and type(command['timeout_seconds'])is int and command['timeout_seconds']==180 and(command['returncode']is None or type(command['returncode'])is int and -(2**31)<=command['returncode']<2**31)and(command['returncode']!=0 or command['wait_error_type']is not None)and command['wait_error_type']in(None,'TimeoutExpired','InterruptedError','KeyboardInterrupt','SystemExit','AssertionError','OSError','ProcessLookupError','OTHER_BASE_EXCEPTION')and command['retirement']=='ORIGINAL_COMMAND_FLOW_NOT_INDEPENDENTLY_REOBSERVED','fixed original command failure metadata')
 log=value['log'];need(type(log)is dict,'typed fixed log record')
 if log.get('status')in('UNAVAILABLE_NOT_PRESENT','UNAVAILABLE_UNSAFE_CHANGED_OR_BOUNDED'):need(set(log)=={'status'},'unavailable note contains no substituted contents')
 else:
  need(set(log)=={'status','file_bytes','file_sha256','offset','tail_bytes','tail_sha256','encoding','tail_base64'}and log['status']=='CAPTURED_BOUNDED_FULL_HASH_AND_TAIL'and type(log['file_bytes'])is int and 0<=log['file_bytes']<=DESKTOP_LOG_MAX and type(log['offset'])is int and type(log['tail_bytes'])is int and log['tail_bytes']==min(log['file_bytes'],DESKTOP_TAIL_MAX)and log['offset']==log['file_bytes']-log['tail_bytes']and log['encoding']=='BASE64'and all(re.fullmatch('[0-9a-f]{64}',log[k])for k in('file_sha256','tail_sha256'))and type(log['tail_base64'])is str and len(log['tail_base64'])<=4*((DESKTOP_TAIL_MAX+2)//3),'bounded exact full log and tail metadata');raw=base64.b64decode(log['tail_base64'],validate=True);need(len(raw)==log['tail_bytes']and base64.b64encode(raw).decode()==log['tail_base64']and hashlib.sha256(raw).hexdigest()==log['tail_sha256'],'canonical exact tail encoding and hash')
  if log['offset']==0:need(log['file_sha256']==log['tail_sha256'],'complete small log hash equality')
 need(len((json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode())<=DESKTOP_NOTE_MAX,'fixed optional DATA bound inside existing4MiB caller result');return value

def dependency_configuration():
 p=configuration();d=p['dependency_cache']
 C.need(d['source']=='405761af52cdfa92b97bbf5b0519f32230d9a254'and d['ref']=='codex/current606-incoming31-v1'and len(d['carrier_files'])==108 and
  d['preparation_source']=='93bc9bfac7343ee3b443ae3332c0942ed1ba5b55'and d['packages']=={'archlinux-contrib':'20261009-1','htmlq':'0.4.0-3','pacman-contrib':'1.13.1-1','pyalpm':'0.12.0-1','xdg-utils':'1.2.1-2'}and
  d['status']=='FIXED_EIGHT_RETAINED_DEPENDENCY_INPUTS_UNAUTHENTICATED_DATA_ONLY'and d['acceptance']is False and all(d[k]is None for k in('actual_source','actual_ref','actual_run')),
  'fixed five dependency identities and public incoming31 context only');return p,d

def dependency_carrier_snapshot(root,expected):
 root=C.safe(root);root_identity=identity(root.lstat());files={};directories={}
 for path in root.rglob('*'):
  rel=path.relative_to(root)
  if rel.parts[0]=='.git':
   C.need((root/'.git').is_dir()and not(root/'.git').is_symlink(),'only ordinary top-level checkout administration');continue
  C.need('.git'not in rel.parts and not path.is_symlink(),'foreign Git or input alias refused');s=path.lstat()
  if stat.S_ISDIR(s.st_mode):directories[rel.as_posix()]=identity(s)
  else:
   name=rel.as_posix();C.need(name in expected and stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size==expected[name]['bytes'],'closed declared incoming31 file extent');files[name]=identity(s)
 required={q.as_posix()for n in expected for q in Path(n).parents if q.as_posix()!='.'}
 C.need(set(files)==set(expected)and set(directories)==required and identity(root.lstat())==root_identity,'whole declared incoming31 namespace; selected eight bodies separately checked');return files,root_identity,directories

def prepare_dependency_cache(incoming,preparation,desktop_lock,cache,deadline):
 C.need(type(deadline)in(int,float)and math.isfinite(deadline)and 0<deadline-time.monotonic()<=240,'same finite original240 preparation deadline');tick(deadline)
 p,d=dependency_configuration();incoming=C.safe(incoming);preparation=C.safe(preparation);desktop_lock=C.safe(desktop_lock);cache=C.safe(cache)
 for root in(incoming,preparation):C.need(not cache.is_relative_to(root)and not root.is_relative_to(cache),'cache disjoint from immutable dependency inputs')
 source_identity={n:identity((preparation/n).lstat())for n in d['preparation_files']};preparation_identity=identity(preparation.lstat());desktop_identity=identity(desktop_lock.lstat());source={n:C.checked(preparation/n,w)for n,w in d['preparation_files'].items()};C.need({n:identity((preparation/n).lstat())for n in source}==source_identity,'stable dependency source descriptors');raw=source['scripts/ci/full-development-composition/dependencies/inputs.lock.json'];lock=json.loads(raw)
 C.need(lock['signer_fingerprint']=='68B3537F39A313B3E574D06777193F152BDBE6A6'and len(lock['packages'])==5 and{r['name']:r['version']for r in lock['packages']}==d['packages'],'whole original fixed five lock/signature identity')
 desktop_raw=C.checked(desktop_lock,p['desktop_lock']);desktop=json.loads(desktop_raw);packages,prior=inputs(desktop)
 C.need(len(packages)==1148,'entire held complete574 input set')
 prior.update({n.removeprefix('packages/'):w for n,w in p['carrier_files'].items()if n.startswith('packages/')})
 C.need(len(prior)==1159,'entire prior1153 plus six original compiler inputs required')
 before,directory=cache_snapshot(cache,prior);original=dependency_carrier_snapshot(incoming,d['carrier_files']);targets={};allten={};bodies={}
 for row in lock['packages']:
  for suffix,size,sha in(('',row['size'],row['sha256']),('.sig',row['signature_size'],row['signature_sha256'])):
   name=row['filename']+suffix;w=dict(bytes=size,sha256=sha);C.need(name not in allten,'unique fixed dependency archive/signature');allten[name]=w
   if row['name']=='xdg-utils':
    C.need(prior.get(name)==w and C.pin(C.read(cache/name,size))==w,'exact already-retained xdg-utils pair; never overwritten')
   else:
    member=('upstream-signatures/'if suffix else'packages/')+name
    C.need(name not in before and d['selected'].get(member)==w==d['carrier_files'].get(member),'exact selected eight declared incoming inputs; no overwrite')
    targets[name]=w;tick(deadline);bodies[name]=C.checked(incoming/member,w)
 C.need(len(allten)==10 and len(targets)==len(d['selected'])==8 and sum(w['bytes']for w in allten.values())<1024**2,'closed ten bytes below original dependency bound')
 created={}
 try:
  for name,w in targets.items():
   tick(deadline);fd=os.open(cache/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600);created[name]=identity(os.fstat(fd))[:2]
   try:
    offset=0;body=bodies[name]
    while offset<len(body):tick(deadline);n=os.write(fd,body[offset:offset+65536]);C.need(n>0,'retained dependency cache copy');offset+=n
   finally:os.close(fd)
   C.need(C.pin(C.read(cache/name,w['bytes']))==w,'whole copied dependency archive/signature')
  after,now=cache_snapshot(cache,dict(prior,**targets))
  C.need({n:after[n]for n in before}==before and now==directory,'complete prior1159 file metadata/identity and owned cache directory preserved')
  for name,w in allten.items():tick(deadline);C.need(C.pin(C.read(cache/name,w['bytes']))==w,'all ten exact cache-hit objects before unchanged180 acquisition')
  C.need(dependency_carrier_snapshot(incoming,d['carrier_files'])==original and all(C.checked(preparation/n,w)==source[n]for n,w in d['preparation_files'].items())and C.checked(desktop_lock,p['desktop_lock'])==desktop_raw and identity(desktop_lock.lstat())==desktop_identity and identity(preparation.lstat())==preparation_identity and{n:identity((preparation/n).lstat())for n in source}==source_identity,'whole declared incoming namespace and source lock held');tick(deadline)
 except BaseException:
  for name,owned in created.items():
   path=cache/name
   if path.exists()and not path.is_symlink()and identity(path.lstat())[:2]==owned and path.stat().st_nlink==1:path.unlink()
  C.need(cache_snapshot(cache,prior)==(before,directory),'failed new8 preparation preserves entire prior1159 metadata');raise
 return dict(status='EXACT_EIGHT_RETAINED_DEPENDENCY_CACHE_DATA_NOT_AUTHENTICATED',source=d['source'],preparation_source=d['preparation_source'],new_files=targets,all_ten=allten,prior_files=len(before),before_identity=before,after_prior_identity={n:after[n]for n in before},directory_identity=directory,
  namespace='WHOLE_DECLARED108_MEMBERS_AND_SIZES_ONLY',content='EXACT_SELECTED8_AND_EXISTING_XDG2_FULL_BYTES',original180_GPG_metadata_URLs='MANDATORY_UNCHANGED',acceptance_authority=False,cleanup_authority=False)

def prepare_with_dependencies(carrier,updater,desktop_lock,cache,deadline,incoming,preparation):
 C.need(incoming is not None and preparation is not None,'both immutable dependency roots required')
 # The old six-copy function and its globals/default route remain unchanged.
 compiler=prepare(carrier,updater,desktop_lock,cache,deadline)
 dependency=prepare_dependency_cache(incoming,preparation,desktop_lock,cache,deadline)
 return dict(compiler6=compiler,dependency_cache=dependency,shared_original_deadline=deadline,acceptance_authority=False)


# Original compiler6 code and four frozen cache functions execute in one private
# namespace. Only the explicit selected configuration adds dependency DATA.
def cache_facade(fresh):
 import importlib.util,sys,types
 from contextlib import contextmanager
 path=Path(__file__).resolve().with_name('desktop622.py');raw=read(path,4*1024**2)[0]
 need(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())=={'bytes': 9856, 'sha256': 'eace06a0842aa08b803de34522178a086943c3e05086b1ed07f7fb986fd07400'},'exact held local desktop622 cache bootstrap')
 spec=importlib.util.spec_from_file_location('_core622_cache_local_desktop',path);X=importlib.util.module_from_spec(spec);exec(compile(raw,str(path),'exec'),vars(X))
 value=json.loads(read(Path(__file__).with_name('composition-parent.json'),4*1024**2)[0]);profile=value['dependency_cache_context'];source=json.loads(read(Path(__file__).with_name('composition.json'),4*1024**2)[0])['public']['latest607-fresh-tooling-inputs-trial-root-20261025'];root=Path(fresh)
 need(root.is_absolute()and root==root.resolve()and not any(p.is_symlink()for p in(root,*root.parents)),'exact ordinary original1197 source operand')
 for name in('implementation/compiler6.py','implementation/compiler6-profile.json','implementation/common.py'):
  raw=read(root/name,4*1024**2)[0];need(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())==source['files'][name],'whole original1197 compiler6 import/profile closure')
 saved=dict(sys.modules);paths=sys.path[:]
 try:
  sys.path.insert(0,str(root/'implementation'));sys.modules.pop('common',None);sys.modules.pop('compiler6',None);spec=importlib.util.spec_from_file_location('_core622_original_compiler6',root/'implementation/compiler6.py');base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base);need(Path(base.C.__file__).resolve()==root/'implementation/common.py','actual original common source import')
 finally:
  sys.path[:]=paths
  for name in set(sys.modules)-set(saved):sys.modules.pop(name,None)
  sys.modules.update(saved)
 old_configuration=base.configuration
 def configuration():
  original=old_configuration();need(original=={n:v for n,v in profile.items()if n!='dependency_cache'},'entire original compiler6 configuration before selected dependency addition');return dict(profile)
 selected=X.clone(base,configuration=configuration)
 for function in(dependency_configuration,dependency_carrier_snapshot,prepare_dependency_cache,prepare_with_dependencies):
  fn=types.FunctionType(function.__code__,vars(selected),function.__name__,function.__defaults__,function.__closure__);setattr(selected,function.__name__,fn)
 need(selected.prepare.__code__ is base.prepare.__code__ and selected.prepare.__globals__['configuration']is configuration and selected.prepare_dependency_cache.__globals__['cache_snapshot']is selected.cache_snapshot and selected.prepare_with_dependencies.__globals__['prepare']is selected.prepare and selected.prepare_with_dependencies.__globals__['prepare_dependency_cache']is selected.prepare_dependency_cache,'actual old6/new8 executing global bindings, not namespace attributes only');return selected

def cache_main():
 import argparse
 p=argparse.ArgumentParser(description='Explicit selected Core622 exact6+8 cache DATA, not authentication')
 p.add_argument('--prepare-dependency-cache',action='store_true',required=True)
 for name in('compiler6-source','carrier','updater','desktop-lock','cache','incoming31','preparation'):p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--deadline',type=float,required=True);a=p.parse_args();need(not a.cache.resolve().is_relative_to(a.compiler6_source.resolve())and not a.compiler6_source.resolve().is_relative_to(a.cache.resolve()),'owned cache disjoint original source');selected=cache_facade(a.compiler6_source);value=selected.prepare_with_dependencies(a.carrier,a.updater,a.desktop_lock,a.cache,a.deadline,a.incoming31,a.preparation);print(json.dumps(value,sort_keys=True));return 0

if __name__=='__main__':raise SystemExit(cache_main())
