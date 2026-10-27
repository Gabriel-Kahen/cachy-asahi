# SPDX-License-Identifier: MIT
"""Retain one genuine already-retired generated image-id between whole owners."""
import hashlib,json,math,os,re,stat,time
from pathlib import Path

# Admit only this canonical closed Source directory before sibling imports.
import sys

def _admit_closed_sibling_source():
 root=Path(__file__).absolute().parent
 def require(value):
  if not value:raise ValueError('closed current Source sibling admission refused')
 def identity(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 require(root==root.resolve()and not any(p.is_symlink()for p in(root,*root.parents)));before=root.stat();require(stat.S_ISDIR(before.st_mode)and before.st_uid==os.getuid()and not before.st_mode&0o022)
 def raw(name):
  path=root/name;require(path.is_relative_to(root)and not any(p.is_symlink()for p in(path,*path.parents)));fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   first=os.fstat(fd);require(stat.S_ISREG(first.st_mode)and first.st_nlink==1 and first.st_uid==os.getuid()and stat.S_IMODE(first.st_mode)==0o644 and 0<=first.st_size<=4*1024**2);data=bytearray()
   while len(data)<=first.st_size:
    part=os.read(fd,min(1024**2,first.st_size+1-len(data)))
    if not part:break
    data.extend(part)
   require(len(data)==first.st_size and identity(first)==identity(os.fstat(fd))==identity(path.lstat()));return bytes(data)
  finally:os.close(fd)
 manifest=json.loads(raw('source-manifest.json'));files=manifest['files'];aliases=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-core7-real-systemd.yml');expected=set(files)|{'source-manifest.json',*aliases};require(type(files)is dict and len(files)==63 and len(expected)==66 and manifest['actual']is None);found=set();directories={''}
 for path in root.rglob('*'):
  name=path.relative_to(root).as_posix()
  if name.split('/')[0]=='.git':continue
  require(not path.is_symlink()and(path.is_dir()or path.is_file()))
  if path.is_dir():directories.add(name)
  else:found.add(name)
 require(found==expected);wanted={''}
 for name in expected:
  require(type(name)is str and name==Path(name).as_posix()and not Path(name).is_absolute()and all(p not in('', '.', '..')for p in name.split('/')))
  wanted.update(''if str(p)=='.'else p.as_posix()for p in Path(name).parents)
 require(directories==wanted)
 for name,want in files.items():
  data=raw(name);require(want==dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest()))
 require(all(raw(name)==raw('workflow.yml.in')for name in aliases));require(identity(before)==identity(root.stat()))
 for name in('case','ownership622'):
  module=sys.modules.get(name)
  if module is not None:require(Path(getattr(module,'__file__','/invalid')).absolute()==root/(name+'.py'))
 sys.path.insert(0,str(root));return root

_ADMITTED_SOURCE=_admit_closed_sibling_source()

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
 producer,core_output=Path(producer),Path(core_output);need(producer.parent==Path('/tmp')and core_output.parent==producer.parent and producer.is_absolute()and core_output.is_absolute()and producer!=core_output,'same fresh original owner siblings');base=producer/'private/desktop574';iid=base/'image-id';raw,iid_identity=read(iid,128);need(re.fullmatch(b'sha256:[a-f0-9]{64}\n?',raw)is not None,'entire exact generated image-id bytes');image=raw.decode().strip();report=json.loads(read(base/'report.json',2*1024**2)[0]);owner=json.loads(read(producer/'producer-owner.json',2*1024**2)[0]);need(re.fullmatch('[a-f0-9]{32}',owner['token'])and image!=owner['core_image']and image not in owner['images_preexisting'],'never retire/move borrowed image authority')
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


# Passive original verifier/query retention; all actual commands stay original.
def verifier_capture(binding,module,context,integration,original,producer):
 import base64,subprocess,types
 import desktop622 as X
 original_prepare=module.materialize.prepare
 def prepare(*args,**kw):
  api=kw['verifier_api'];real=api.subprocess.run
  def run(argv,**options):
   if '--verify'not in argv:return real(argv,**options)
   need(options==dict(check=True,capture_output=True,text=True,timeout=30),'entire original607 PublicVerifier invocation');need(len(context.verification)<607,'finite607 original verifier capture');row=None;primary=None
   try:
    result=real(argv,check=False,capture_output=True,text=False,timeout=30);need(type(result.stdout)is type(result.stderr)is bytes,'exact original raw verifier streams');need(len(result.stdout)<=16384 and len(result.stderr)<=16384,'bounded original verifier output');row=dict(argv=list(map(str,argv)),returncode=result.returncode,stdout_base64=base64.b64encode(result.stdout).decode('ascii'),stderr_base64=base64.b64encode(result.stderr).decode('ascii'),time_limit=30);context.verification.append(row);need(sum(len(base64.b64decode(v[k],validate=True))for v in context.verification for k in('stdout_base64','stderr_base64'))<=2*1024**2,'bounded whole607 verifier aggregate');result.check_returncode();return subprocess.CompletedProcess(result.args,result.returncode,result.stdout.decode('utf-8'),result.stderr.decode('utf-8'))
   except BaseException as error:
    primary=error;context.verification_error=dict(error_type=type(error).__name__,completed=len(context.verification),acceptance=False);raise
  scoped=X.clone(api,subprocess=types.SimpleNamespace(run=run));return original_prepare(*args,**dict(kw,verifier_api=scoped))
 materialize=X.clone(module.materialize,prepare=prepare);namespace=dict(binding.__globals__,materialize=materialize);bound=types.FunctionType(binding.__code__,namespace,binding.__name__,binding.__defaults__,binding.__closure__);need(bound.__globals__['materialize']is materialize,'exact finite private materializer global binding');return bound(integration,original,producer)

def handoff_capture(command,report,core_output,proof,deadline):
 """Write attempted raw query DATA before the original absence predicate."""
 import case as C
 selected=__import__('provision622').export_selection(proof);root=Path(core_output)/'handoff-query';need(not os.path.lexists(root),'fresh literal handoff query evidence');root.mkdir(mode=0o700);marker=read(Path(proof['producer_path'])/'private/desktop574/image-id',128)[0];image=marker.decode().strip();owner=json.loads(read(Path(proof['producer_path'])/'producer-owner.json',2*1024**2)[0]);used=False
 def captured(argv,required=True,seconds=30):
  nonlocal used
  need(not used and argv==['/usr/bin/docker','image','inspect',image]and required is False and type(seconds)in(int,float)and 0<seconds<=20 and seconds<=deadline-time.monotonic()+.05,'one exact independently observed handoff query');used=True;position=len(report['commands']);primary=None;result=None
  try:result=command(argv,required,seconds);return result
  except BaseException as error:primary=error;raise
  finally:
   try:
    need(len(report['commands'])==position+1,'query original command row retained');row=report['commands'][position];need(row['argv']==argv and row['time_limit']==seconds and type(row['exit_code'])is int and row['output_limit']==1024**2,'exact original handoff command row');artifacts={}
    for suffix in('stdout','stderr'):
     raw=C.read(Path(core_output)/('command-%03d.%s'%(position,suffix)),1024**2);need(C.pin(raw)==dict(bytes=row[suffix+'_bytes'],sha256=row[suffix+'_sha256']),'original handoff stream/pin identity');(root/suffix).write_bytes(raw);artifacts[suffix]=C.pin(raw)
    need(sum(v['bytes']for v in artifacts.values())<=1024**2,'original combined query output cap');value=dict(schema=1,status='ORIGINAL_EXTRA_HANDOFF_QUERY_DATA_ONLY',selection=selected,producer_token=proof['producer_token'],parent_producer_token=owner['token'],image=image,command_index=position,command=row,requested_seconds=seconds,artifacts=artifacts);raw=C.encoded(value);need(len(raw)<=512*1024,'bounded complete handoff query index');(root/'command.json').write_bytes(raw)
   except BaseException as error:
    try:(root/'capture-error.json').write_bytes(C.encoded(dict(schema=1,status='INCOMPLETE_ORIGINAL_EXTRA_HANDOFF_QUERY_DATA_ONLY',selection=selected,error_type=type(error).__name__,acceptance=False)))
    except BaseException:pass
    if primary is None:raise
    primary.add_note('handoff raw query retention failed: '+type(error).__name__)
 return captured

def retain_handoff_query(core_output,public,complete):
 import case as C,shutil
 core_output,public=Path(core_output),Path(public);source=core_output/'handoff-query';need(source.is_dir()and not(public/'handoff-query').exists(),'fresh owned handoff query public retention');shutil.copytree(source,public/'handoff-query');export=C.decode(C.read(public/'export.json',4*1024**2));rows={};total=0
 for path in sorted((public/'handoff-query').iterdir()):
  need(path.name in('command.json','stdout','stderr','capture-error.json')and not path.is_symlink()and path.is_file(),'finite actual extra handoff query roles');raw=C.read(path,1024**2 if path.name in('stdout','stderr')else 512*1024);rows['handoff-query/'+path.name]=C.pin(raw);total+=len(raw)
 need(total<=2*1024**2 and export['bytes']+total<=768*1024**2,'unchanged whole public cap plus bounded query index');export['files'].update(rows);export['bytes']+=total
 if complete is not True or 'handoff-query/capture-error.json'in rows:export['errors'].append(dict(file='handoff-query',error='INCOMPLETE_ORIGINAL_EXTRA_HANDOFF_QUERY_DATA_ONLY'));export['status']='FAIL_OR_INCOMPLETE'
 (public/'export.json').write_bytes(C.encoded(export));return rows


# Reviewed complete574 DATA transport; no native/cleanup acceptance authority.
import subprocess,sys,types
RETAINED_SOURCE='ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad'
RETAINED_PROFILE={'bytes':195440,'sha256':'4089fd798849cafda23d03c0dd95ac896a83fd63ad21e331ae420c147535586c'}
JOB_SECONDS=350*60
JOB_RESERVE=dict(cleanup=240,retention=360,upload=300,grace=120)

def retained_save(path,value):
 raw=(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode();need(len(raw)<=4*1024**2,'bounded complete retained DATA receipt');Path(path).write_bytes(raw)

def retained_binding():
 source=os.environ.get('GITHUB_SHA');run=os.environ.get('GITHUB_RUN_ID');ref=os.environ.get('GITHUB_REF_NAME');need(re.fullmatch('[0-9a-f]{40}',source or'')and source==os.environ.get('SOURCE_SHA')==os.environ.get('WORKFLOW_SHA')and re.fullmatch('[1-9][0-9]{0,19}',run or'')and re.fullmatch('codex/[a-z0-9-]+',ref or'')and os.environ.get('GITHUB_RUN_ATTEMPT')=='1'and os.environ.get('GITHUB_REPOSITORY')=='Gabriel-Kahen/cachy-asahi'and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch'and os.environ.get('RUNNER_ARCH')=='ARM64','genuine first current Core622 workflow identity for transport');actual=dict(source=source,ref=ref,run=int(run),attempt=1);nonce=hashlib.sha256(('current607-core622:'+source+':'+run).encode()).hexdigest()[:32];return actual,nonce

def retained_paths():
 root=Path(__file__).resolve().parent;workspace=Path(os.environ['GITHUB_WORKSPACE']);temporary=Path(os.environ['RUNNER_TEMP']);need(root==workspace/'core622-code'and root==root.resolve()and temporary==temporary.resolve()and all(p.is_absolute()and not any(q.is_symlink()for q in(p,*p.parents))for p in(root,temporary))and temporary.is_dir()and temporary.stat().st_uid==os.getuid()and not temporary.stat().st_mode&0o022,'literal owned source/temp roles');carrier=temporary/'core622-retained-complete574';work=temporary/'core622-retained-transport';need(not any(a.is_relative_to(b)or b.is_relative_to(a)for a,b in((root,carrier),(root,work),(carrier,work))),'retained DATA/work/source are disjoint');return root,temporary,carrier,work

def job_clock():
 actual,nonce=retained_binding();root,temporary,_,_=retained_paths();path=temporary/'core622-job-clock.json';raw,info=read(path,16384);clock=__import__('case').decode(raw);need(set(clock)=={'schema','status','identity','nonce','runtime_temp','started','deadline','global_seconds','reserved_seconds'}and type(clock['schema'])is int and clock['schema']==1 and clock['status']=='SOURCE_OWNED_CORE622_JOB_CLOCK_DATA_ONLY'and clock['identity']==actual and clock['nonce']==nonce and clock['runtime_temp']==str(temporary)and clock['global_seconds']==JOB_SECONDS and clock['reserved_seconds']==JOB_RESERVE,'whole source/run/nonce job clock');need(all(type(clock[k])in(int,float)and math.isfinite(clock[k])for k in('started','deadline'))and clock['deadline']==clock['started']+JOB_SECONDS and 0<=time.monotonic()-clock['started']<=JOB_SECONDS+30 and stat.S_IMODE(path.stat().st_mode)==0o600,'same finite source-owned monotonic job clock');return clock

def remaining_deadline(maximum,role='work',clock=None):
 clock=job_clock()if clock is None else clock;need(type(maximum)in(int,float)and math.isfinite(maximum)and 0<maximum<=15600 and role in('work','cleanup','retention','upload'),'finite original phase cap and explicit role');reserve=sum(JOB_RESERVE.values())if role=='work'else sum(JOB_RESERVE[k]for k in({'cleanup':('retention','upload','grace'),'retention':('upload','grace'),'upload':('grace',)}[role]));end=min(time.monotonic()+maximum,clock['deadline']-reserve);need(end>time.monotonic(),'reserved cleanup/retention/upload allowance unavailable before phase');return end

_RETAINED_CONFIG=None

def begin_native_phase():
 import case as C
 clock=job_clock();_,temporary,_,_=retained_paths();started=time.monotonic();total=min(started+15600,clock['deadline']-sum(JOB_RESERVE[k]for k in('retention','upload','grace')));work=total-JOB_RESERVE['cleanup'];need(work>started,'native phase has no reserved work/cleanup allowance before actors');path=temporary/'core622-native-phase.json';value=dict(schema=1,status='SOURCE_OWNED_CORE622_NATIVE_PHASE_DATA_ONLY',identity=clock['identity'],nonce=clock['nonce'],runtime_temp=str(temporary),job_clock=C.pin(read(temporary/'core622-job-clock.json',16384)[0]),started=started,phase_end=total,work_end=work,outer_seconds=15600,cleanup_seconds=240,proof_clock='BEFORE_ORIGINAL_INPUT_SOURCE_PROOF',acceptance=False);raw=C.encoded(value);need(len(raw)<=16384,'bounded source-owned native phase');fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:need(os.write(fd,raw)==len(raw),'whole original native phase write')
 finally:os.close(fd)
 return value

def native_phase(*,require_work=True):
 import case as C
 clock=job_clock();_,temporary,_,_=retained_paths();path=temporary/'core622-native-phase.json';value=C.decode(read(path,16384)[0]);need(set(value)=={'schema','status','identity','nonce','runtime_temp','job_clock','started','phase_end','work_end','outer_seconds','cleanup_seconds','proof_clock','acceptance'}and type(value['schema'])is int and value['schema']==1 and value['status']=='SOURCE_OWNED_CORE622_NATIVE_PHASE_DATA_ONLY'and value['identity']==clock['identity']and value['nonce']==clock['nonce']and value['runtime_temp']==str(temporary)and value['job_clock']==C.pin(read(temporary/'core622-job-clock.json',16384)[0])and value['outer_seconds']==15600 and value['cleanup_seconds']==240 and value['proof_clock']=='BEFORE_ORIGINAL_INPUT_SOURCE_PROOF'and value['acceptance']is False,'whole typed same-owner original native phase DATA');need(all(type(value[k])in(int,float)and math.isfinite(value[k])for k in('started','phase_end','work_end'))and clock['started']<=value['started']<=time.monotonic()and value['phase_end']==min(value['started']+15600,clock['deadline']-780)and value['work_end']==value['phase_end']-240 and stat.S_IMODE(path.stat().st_mode)==0o600,'single absolute native outer/work/cleanup endpoints')
 if require_work:need(time.monotonic()<value['work_end'],'original native work allowance exhausted before actors')
 return value

def retained_configuration():
 global _RETAINED_CONFIG
 if _RETAINED_CONFIG is not None:return _RETAINED_CONFIG
 import case as C
 record=json.loads(read(Path(__file__).with_name('composition-parent.json'),4*1024**2)[0])['retained_complete574_transport'];profile=record['carrier_profile'];need(C.pin(C.encoded(profile))==RETAINED_PROFILE and profile['source']==RETAINED_SOURCE and len(profile['files'])==1154 and sum(v['bytes']for v in profile['files'].values())==1046432165,'whole original1154 carrier profile/count/bytes');_RETAINED_CONFIG=(record,profile);return _RETAINED_CONFIG

_RETAINED_OWNED=None

def retained_owned_child():
 global _RETAINED_OWNED
 if _RETAINED_OWNED is None:
  record,_=retained_configuration();raw=record['owned_child_body'].encode();need(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())==record['owned_child_pin'],'whole reviewed owned-child body');module=types.ModuleType('_core622_embedded_reviewed_owned_child');module.__file__=str(Path(__file__).with_name('@retained-owned-child.py'));exec(compile(raw,module.__file__,'exec'),vars(module));_RETAINED_OWNED=module
 return _RETAINED_OWNED

def retained_fresh(path):
 path=Path(path);need(not os.path.lexists(path)and not any(q.is_symlink()for q in(path,*path.parents)),'fresh literal retained DATA directory');path.mkdir(mode=0o700);return path

class RetainedActors:
 """PGO owned-child contract, restricted environment and one shared phase end."""
 def __init__(self,directory,deadline):self.directory=retained_fresh(directory);self.deadline=deadline;self.rows=[]
 def run(self,argv,timeout):
  need(time.monotonic()<self.deadline,'retained transport shared deadline reached');argv=list(map(str,argv));log=self.directory/('%04d.log'%len(self.rows));need(not os.path.lexists(log),'fresh retained actor log');started=time.monotonic();budget=min(timeout,self.deadline-started);need(budget>0,'positive remaining owned transport budget');row=dict(argv=argv,log=str(log),requested_seconds=timeout,time_limit=budget,status='FAIL',exit=None,natural_exit=False,group_absent=False);lifecycle={};self.rows.append(row)
  env=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',HOME=str(self.directory.parent),TMPDIR=str(self.directory.parent),GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_NO_REPLACE_OBJECTS='1',GIT_OPTIONAL_LOCKS='0',GIT_NO_LAZY_FETCH='1',GIT_TERMINAL_PROMPT='0')
  try:
   with log.open('xb')as stream:completed=retained_owned_child().run(argv,stdin=subprocess.DEVNULL,stdout=stream,stderr=subprocess.STDOUT,timeout=budget,lifecycle=lifecycle,allowed_uids={os.geteuid()},cwd=str(self.directory.parent),env=env)
   need(log.stat().st_size<=16*1024**2,'reviewed bounded retained actor log');need(completed.returncode==lifecycle.get('exit')==0 and lifecycle.get('natural_exit')is True and lifecycle.get('group_absent')is True and lifecycle.get('leader_held_until_group_inspection')is True and lifecycle.get('exit_observed_via_waitpid')is True and lifecycle.get('ownership_lost')is False and lifecycle.get('forced_cleanup')is False and lifecycle.get('retirement')=='REAPED','whole owned natural retained actor retirement');row['status']='PASS'
  finally:
   row.update({k:v for k,v in lifecycle.items()if k!='status'});row['owned_child']=lifecycle;row['seconds']=time.monotonic()-started;retained_save(self.directory/'actors.json',self.rows)
  return read(log,16*1024**2)[0].decode().strip()

def retained_entry_intent(actual,nonce,root,temporary,carrier,work):
 import case as C
 path=work/'owner.json';value=C.decode(read(path,16384)[0]);expected=dict(schema=1,status='SOURCE_OWNED_COMPLETE574_TRANSPORT_ENTRY_INTENT_DATA_ONLY',identity=actual,nonce=nonce,source_root=str(root),runtime_temp=str(temporary),carrier_path=str(carrier),work_path=str(work),argv=['python3','-I','-B',str(root/'ownership622.py'),'--transport-complete574'],outer_seconds=500,kill_grace_seconds=30,step_minutes=9,native='NOT_RUN',native_cleanup='NOT_ESTABLISHED',acceptance=False);need(value==expected and stat.S_IMODE(path.stat().st_mode)==0o600,'one exact source-owned pre-CLI transport entry intent');return value

def transport_complete574():
 actual,nonce=retained_binding();root,temporary,carrier,work=retained_paths();clock=job_clock();record,profile=retained_configuration();entry_intent=retained_entry_intent(actual,nonce,root,temporary,carrier,work);need(not os.path.lexists(carrier)and work.is_dir()and work.stat().st_uid==os.getuid()and stat.S_IMODE(work.stat().st_mode)==0o700 and set(p.name for p in work.iterdir())<= {'phase.stdout','phase.stderr','owner.json'},'fresh fixed carrier/transport work, no retry');end=remaining_deadline(480,clock=clock);actor=RetainedActors(work/'input-transport-actors',end);started=time.monotonic();report=dict(entry_intent=entry_intent,schema=1,status='FAIL_RETAINED_INPUT_TRANSPORT_DATA',identity=actual,nonce=nonce,role='RETAINED_INPUT_TRANSPORT_DATA',source_root=str(root),runtime_temp=str(temporary),carrier_path=str(carrier),work_path=str(work),carrier_source=RETAINED_SOURCE,profile=RETAINED_PROFILE,expected_carrier_files=1154,expected_carrier_bytes=1046432165,budget_seconds=480,retirement_seconds=2,outer_seconds=500,kill_grace_seconds=30,step_minutes=9,effective_deadline=end,job_clock=clock,retry=False,partial_data_retained=True,native='NOT_RUN',native_cleanup='NOT_ESTABLISHED',acceptance=False,authentication='ORIGINAL_COMPLETE1154_GIT_BLOB_MODE_AND_NATIVE_SIGNATURE_GATES_REQUIRED')
 try:
  retained_fresh(carrier);git=['/usr/bin/git','-c','credential.helper=','-c','http.extraHeader=','-c','http.sslVerify=true','-c','core.hooksPath=/dev/null','-c','protocol.allow=never','-c','protocol.https.allow=always'];actor.run([*git,'init','--template=',str(carrier)],10);actor.run([*git,'-C',str(carrier),'-c','http.lowSpeedLimit=65536','-c','http.lowSpeedTime=60','fetch','--depth=1','--no-tags','--no-recurse-submodules','https://github.com/Gabriel-Kahen/cachy-asahi.git',RETAINED_SOURCE],400);fetched=actor.run([*git,'-C',str(carrier),'rev-parse','--verify','FETCH_HEAD'],10);need(fetched==RETAINED_SOURCE,'exact complete574 FETCH_HEAD');actor.run([*git,'-C',str(carrier),'checkout','--detach',RETAINED_SOURCE],45);head=actor.run([*git,'-C',str(carrier),'rev-parse','--verify','HEAD'],10);need(head==RETAINED_SOURCE,'exact complete574 HEAD');report.update(status='PASS_EXACT_RETAINED_INPUT_TRANSPORT_DATA_ONLY',carrier_head=head)
 except BaseException as error:report['error_type']=type(error).__name__;raise
 finally:
  report['seconds']=time.monotonic()-started;report['actor_count']=len(actor.rows);retained_save(work/'owner.json',report)
 return report

def retained_blob_run(argv,**kwargs):
 """Exact profile bytes only for the original read-only seven-argument proof."""
 need('stdout_limit'not in kwargs,'callers cannot select an owned stdout cap');_,_,carrier,_=retained_paths();_,profile=retained_configuration()
 if type(argv)in(list,tuple)and len(argv)==7 and list(argv[:1])==['/usr/bin/git']and argv[1]=='--git-dir='+str(carrier/'.git')and list(argv[2:6])==['-c','protocol.allow=never','cat-file','blob']and type(argv[6])is str and argv[6].startswith(RETAINED_SOURCE+':'):
  name=argv[6][len(RETAINED_SOURCE)+1:];environment={'PATH':os.defpath,'LANG':'C','LC_ALL':'C','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_NO_REPLACE_OBJECTS':'1','GIT_OPTIONAL_LOCKS':'0','GIT_NO_LAZY_FETCH':'1','GIT_TERMINAL_PROMPT':'0'};need(name in profile['files']and set(kwargs)=={'capture_output','timeout','env','check'}and kwargs['capture_output']is True and kwargs['check']is False and kwargs['env']==environment,'exact original binary read-only full-carrier Git proof');size=profile['files'][name]['bytes'];need(type(size)is int and 0<=size<=128*1024**2,'held per-blob128MiB cap');kwargs['stdout_limit']=size
 return retained_owned_child().run(argv,**kwargs)

def prepare_complete574(cache,deadline):
 import case as C
 actual,nonce=retained_binding();root,temporary,carrier,work=retained_paths();clock=job_clock();need(type(deadline)in(int,float)and math.isfinite(deadline)and 0<deadline-time.monotonic()<=240 and deadline<=clock['deadline']-sum(JOB_RESERVE.values()),'original join240 inside same job work allowance');owner=json.loads(read(work/'owner.json',4*1024**2)[0]);need(owner['status']=='PASS_EXACT_RETAINED_INPUT_TRANSPORT_DATA_ONLY'and owner['identity']==actual and owner['nonce']==nonce and owner['carrier_source']==owner['carrier_head']==RETAINED_SOURCE and owner['carrier_path']==str(carrier)and owner['job_clock']==clock and owner['actor_count']==5 and read(work/'phase.exit-code',32)[0]==b'0\n','complete same-owner one-shot transport before whole1154 proof');need(not os.path.lexists(work/'preparation.json'),'fresh one-shot complete1154 preparation receipt');record,profile=retained_configuration();raw=record['legacy_proof_body'].encode();need(C.pin(raw)==record['legacy_proof_pin'],'whole reviewed complete-carrier original proof body');legacy=types.ModuleType('_core622_exact_original_carrier_proof');legacy.__file__=str(root/'@retained-carrier-proof.py');exec(compile(raw,legacy.__file__,'exec'),vars(legacy));legacy.subprocess=types.SimpleNamespace(run=retained_blob_run);report=dict(schema=1,status='FAIL_COMPLETE574_PREPARATION_DATA',identity=actual,nonce=nonce,carrier_path=str(carrier),source=RETAINED_SOURCE,deadline=deadline,native='NOT_RUN',acceptance=False)
 try:
  proof=legacy.prove(carrier,carrier/'.git',profile,deadline);need(proof['files']==proof['blob_joins']==1154,'whole1154 Git/blob/filesystem proof before cache');seed_raw=legacy.read(carrier/'seed.py',deadline,65536);need(C.pin(seed_raw)==profile['files']['seed.py'],'original complete574 seed helper body');seed=types.ModuleType('_core622_exact_complete574_seed');seed.__file__=str(carrier/'seed.py');exec(compile(seed_raw,seed.__file__,'exec'),vars(seed));receipt=seed.seed(carrier/'desktop574-inputs.lock.json',Path(cache),'desktop574',deadline);need(receipt['actual_authority']is False,'cache DATA never native authority');report.update(status='EXACT_RETAINED_INPUT_PREPARATION_DATA_ONLY',mode='desktop574',carrier=proof,receipt=receipt)
 except BaseException as error:report['error_type']=type(error).__name__;raise
 finally:retained_save(work/'preparation.json',report)
 return report

def retain_complete574_transport(public):
 import case as C
 _,temporary,_,work=retained_paths();clock=job_clock();public=Path(public);record=json.loads(read(public/'export.json',4*1024**2)[0]);need(not(public/'retained-input-transport').exists(),'fresh retained transport public prefix');target=public/'retained-input-transport';target.mkdir(mode=0o700);names={'owner.json','preparation.json','phase.stdout','phase.stderr','phase.exit-code','input-transport-actors/actors.json'}|{'input-transport-actors/%04d.log'%n for n in range(5)};seen=set();total=0;errors=[]
 if work.exists():
  for p in work.rglob('*'):
   need(not p.is_symlink()and(p.is_file()or p.is_dir()),'ordinary retained transport DATA')
   if p.is_file():need(p.relative_to(work).as_posix()in names,'closed retained transport DATA roles')
 for name in sorted(names):
  p=work/name
  if not p.exists():continue
  try:
   cap=16*1024**2 if name.endswith('.log')else 4*1024**2 if name.endswith('.json')else 1024**2;raw=read(p,cap)[0];need(total+len(raw)<=16*1024**2 and record['bytes']+len(raw)<=768*1024**2,'bounded transport aggregate inside held public768MiB');q=target/name;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(raw);record['files']['retained-input-transport/'+name]=C.pin(raw);record['bytes']+=len(raw);total+=len(raw);seen.add(name)
  except BaseException as error:errors.append(dict(file='retained-input-transport/'+name,error=type(error).__name__))
 raw=read(temporary/'core622-job-clock.json',16384)[0];need(record['bytes']+len(raw)<=768*1024**2,'held public cap with exact job clock');(target/'job-clock.json').write_bytes(raw);record['files']['retained-input-transport/job-clock.json']=C.pin(raw);record['bytes']+=len(raw)
 if(temporary/'core622-native-phase.json').exists():
  phase=native_phase(require_work=False);phase_raw=read(temporary/'core622-native-phase.json',16384)[0];need(record['bytes']+len(phase_raw)<=768*1024**2,'held public cap with exact native phase');(target/'native-phase.json').write_bytes(phase_raw);record['files']['retained-input-transport/native-phase.json']=C.pin(phase_raw);record['bytes']+=len(phase_raw)
 elif record['status']!='FAIL_OR_INCOMPLETE':errors.append(dict(file='retained-input-transport/native-phase.json',error='MISSING_ORIGINAL_NATIVE_PHASE'))
 try:
  owner=json.loads(read(work/'owner.json',4*1024**2)[0]);prepared=json.loads(read(work/'preparation.json',4*1024**2)[0]);need(owner['status']=='PASS_EXACT_RETAINED_INPUT_TRANSPORT_DATA_ONLY'and prepared['status']=='EXACT_RETAINED_INPUT_PREPARATION_DATA_ONLY'and owner['identity']==prepared['identity']==clock['identity']and owner['nonce']==prepared['nonce']==clock['nonce']and owner['carrier_source']==prepared['source']==RETAINED_SOURCE and prepared['carrier']['files']==prepared['carrier']['blob_joins']==1154 and seen==names and read(work/'phase.exit-code',32)[0]==b'0\n','same-owner complete transport and original full1154 preparation before any positive Core export')
 except BaseException as error:errors.append(dict(file='retained-input-transport',error='INCOMPLETE_DATA_ONLY_'+type(error).__name__))
 if errors:record['status']='FAIL_OR_INCOMPLETE';record['errors'].extend(errors)
 retained_save(public/'export.json',record);return dict(files=len(seen)+1,bytes=total+len(raw),native='NOT_RUN',native_cleanup='NOT_ESTABLISHED',errors=errors)

def retained_main(argv=None):
 import argparse
 parser=argparse.ArgumentParser(description='Fixed full1154 transport and hierarchical job DATA clock; no native credit');group=parser.add_mutually_exclusive_group(required=True);group.add_argument('--transport-complete574',action='store_true');group.add_argument('--begin-core-phase',action='store_true');group.add_argument('--prepare-complete574',action='store_true');group.add_argument('--job-timeout',type=float);group.add_argument('--job-deadline',type=float);group.add_argument('--phase-remaining',type=float);parser.add_argument('--role',choices=('work','cleanup','retention','upload'),default='work');parser.add_argument('--cache',type=Path);parser.add_argument('--deadline',type=float);args=parser.parse_args(argv)
 if args.begin_core_phase:phase=begin_native_phase();print('%.6f'%(phase['phase_end']-time.monotonic()));return 0
 if args.phase_remaining is not None:
  now=time.monotonic();need(args.role=='retention'and math.isfinite(args.phase_remaining)and 0<args.phase_remaining-now<=210 and args.phase_remaining<=remaining_deadline(210,'retention')+.05,'same bounded shared retention phase end');print('%.6f'%(args.phase_remaining-time.monotonic()));return 0
 if args.job_timeout is not None:print('%.6f'%max(.001,remaining_deadline(args.job_timeout,args.role)-time.monotonic()));return 0
 if args.job_deadline is not None:print('%.6f'%remaining_deadline(args.job_deadline,args.role));return 0
 if args.transport_complete574:transport_complete574();return 0
 need(args.cache is not None and args.deadline is not None,'literal complete574 preparation cache/deadline');prepare_complete574(args.cache,args.deadline);return 0

if __name__=='__main__':raise SystemExit(retained_main()if len(sys.argv)>1 and sys.argv[1]in('--transport-complete574','--prepare-complete574','--job-timeout','--job-deadline','--phase-remaining','--begin-core-phase')else cache_main())
