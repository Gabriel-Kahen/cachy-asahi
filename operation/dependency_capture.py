# SPDX-License-Identifier: MIT
"""Optional failure DATA before the unchanged dependency assertion and cleanup."""
import base64,hashlib,json,os,re,stat,sys
from pathlib import Path
PRODUCER='scripts/ci/full-composition-installer-vm/producer.py'
CALLER='scripts/ci/full-root-upgrade-caller/run.py'
PRODUCER_PIN='98d61944888485870b31b5457bcad9edfd8e51cb367414833f8d54611d7b0eaf'
CALLER_PIN='b9840c79ffc6c45070ac12b80d469fb46c26059df63e121801d6ab223035e303'
DIAGNOSTIC_PIN='e8713c5c4b0dcd8f9d0debc9009c04228e3ae0c7d96e0ad391e94b1ff807088a'
LOCK_PIN='9a8064cde23ad90c2352395bdd1f6f5a8e843b3db3468cd2cc5a90829dc32704'
LOG_CAP=256*1024;FILE_CAP=16*1024**2;MAX_DATA=768*1024
def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def identity(s):return {n:getattr(s,n)for n in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}
def ordinary(path):
 path=Path(path);need(path.is_absolute()and path==path.resolve()and not any(p.is_symlink()for p in(path,*path.parents)),'ORDINARY_NONALIAS_PATH');s=path.lstat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_uid==os.geteuid(),'OWNED_SINGLE_LINK_FILE');return path,s
def read(path,cap=FILE_CAP):
 path,s=ordinary(path);need(0<=s.st_size<=cap,'BOUNDED_FILE');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  need(identity(os.fstat(fd))==identity(s),'OPEN_IDENTITY');parts=[];size=0
  while raw:=os.read(fd,min(65536,cap+1-size)):
   parts.append(raw);size+=len(raw);need(size<=s.st_size,'GROWING_FILE')
  need(size==s.st_size and identity(os.fstat(fd))==identity(s)==identity(path.lstat()),'ORIGINAL_CHANGED');return b''.join(parts),identity(s)
 finally:os.close(fd)
def snapshot(path,retain=False,cap=FILE_CAP):
 try:raw,ident=read(path,cap)
 except FileNotFoundError:return dict(status='NOT_PRESENT',path=str(path))
 value=dict(status='CAPTURED',path=str(path),identity=ident,**pin(raw))
 if retain:value.update(encoding='BASE64',base64=base64.b64encode(raw).decode())
 return value
def combined(path):
 raw,ident=read(path)
 parts=[(0,raw)]if len(raw)<=LOG_CAP else[(0,raw[:65536]),(len(raw)-(LOG_CAP-65536),raw[-(LOG_CAP-65536):])]
 return dict(status='CAPTURED',stream='COMBINED_ORIGINAL_STDOUT_AND_STDERR',separate_streams='NOT_AVAILABLE_ORIGINAL_COMMAND_USES_STDERR_STDOUT',file=pin(raw),identity=ident,complete=len(raw)<=LOG_CAP,chunks=[dict(offset=offset,encoding='BASE64',base64=base64.b64encode(body).decode(),**pin(body))for offset,body in parts])
def role(args,argv,log,timeout):
 root=Path(args.preparation_source)/'scripts/ci/full-development-composition';raw=Path(args.output)/'private'
 expected=[sys.executable,'-B',str(root/'dependencies/acquire.py'),'--source-root',str(args.updater),'--cache',str(args.cache),'--keydir',str(args.cache),'--output',str(raw/'dependency-audit')]
 return type(timeout)is int and timeout==180 and list(map(str,argv))==expected and Path(log)==raw/'dependency.log'
def cache_operands(lock,cache):
 need(pin(lock)['sha256']==LOCK_PIN,'EXACT_PUBLIC_DEPENDENCY_LOCK');value=json.loads(lock);need(len(value['packages'])==5 and len(value['keyring_files'])==3,'FINITE_PUBLIC_OPERANDS');rows=[]
 for row in value['packages']:
  rows.extend([(row['filename'],row['size'],row['sha256']),(row['filename']+'.sig',row['signature_size'],row['signature_sha256'])])
 rows.extend((row['filename'],row['size'],row['sha256'])for row in value['keyring_files']);need(len({r[0]for r in rows})==13,'THIRTEEN_UNIQUE_PUBLIC_OPERANDS');result={}
 for name,size,sha in rows:
  need(type(name)is str and re.fullmatch('[A-Za-z0-9+_.-]{1,240}',name)and type(size)is int and 0<=size<=FILE_CAP and re.fullmatch('[0-9a-f]{64}',sha),'PUBLIC_DECLARED_OPERAND')
  try:item=snapshot(Path(cache)/name)
  except (OSError,ValueError)as error:item=dict(status='REFUSED_UNSAFE_OR_CHANGED',error_type=type(error).__name__)
  item['expected']=dict(bytes=size,sha256=sha);item['matches_lock']=item.get('bytes')==size and item.get('sha256')==sha;result[name]=item
 return result
def record(args,argv,log,timeout,code,error):
 need(role(args,argv,log,timeout),'EXACT_DEPENDENCY_AUTH_ROLE');need(code is None or type(code)is int,'COMMAND_EXIT_TYPE');need(error is None or isinstance(error,BaseException),'WAIT_ERROR_TYPE')
 root=Path(args.preparation_source)/'scripts/ci/full-development-composition';owner_raw,_=read(Path(args.output)/'producer-owner.json',65536);owner=json.loads(owner_raw)
 need(owner['schema_version']==1 and re.fullmatch('[0-9a-f]{32}',owner['token'])and owner['preparation_source']==str(args.preparation_source),'ORIGINAL_PRODUCER_OWNER')
 def optional(path,retain=False):
  try:return snapshot(path,retain=retain,cap=256*1024)
  except (OSError,ValueError)as failure:return dict(status='REFUSED_UNSAFE_OR_CHANGED',error_type=type(failure).__name__)
 operands={name:optional(root/'dependencies'/name,retain=name=='inputs.lock.json')for name in('acquire.py','inputs.lock.json')}
 helpers={name:optional(Path(args.updater)/name)for name in('scripts/port/authenticate.py','scripts/port/preview.py','scripts/ci/native_arm.py','scripts/checks/package_checks.py')}
 lock=operands['inputs.lock.json'];lock['expected_sha256']=LOCK_PIN;lock['matches_held_source']=lock.get('sha256')==LOCK_PIN
 if not lock['matches_held_source']:lock.pop('base64',None);lock.pop('encoding',None)
 cached=cache_operands(base64.b64decode(lock['base64']),args.cache)if lock['matches_held_source']else dict(status='LOCK_NOT_HELD_NO_CACHE_ENUMERATION')
 try:stream=combined(log)
 except (OSError,ValueError)as failure:stream=dict(status='REFUSED_UNSAFE_MISSING_OR_CHANGED',error_type=type(failure).__name__)
 value=dict(schema_version=1,purpose='SOURCE_OWNED_DEPENDENCY_AUTH_FAILURE_DATA_ONLY',status='CAPTURED_DEPENDENCY_FAILURE_DATA',producer_owner=pin(owner_raw),producer_token=owner['token'],command=dict(role='AUTHENTICATE_FIVE_DEDUPLICATE_FOUR',argv=list(map(str,argv)),timeout_seconds=timeout,returncode=code,wait_error_type=None if error is None else type(error).__name__,wait_error=None if error is None else str(error)[:2048],retirement='ORIGINAL_COMMAND_FLOW_ONLY_NOT_INDEPENDENTLY_REOBSERVED'),combined_output=stream,operands=operands,transitive_source_helpers=helpers,cache_operands=cached,acceptance_authority=False,cleanup_authority=False)
 need(len(encoded(value))<=MAX_DATA,'BOUNDED_DEPENDENCY_DATA');return value
def publish(args,value):
 root=Path(args.output);parent=root/'public';need(root.is_absolute()and root==root.resolve()and parent.is_dir()and not parent.is_symlink()and parent.stat().st_uid==os.geteuid(),'ORIGINAL_OWNED_PUBLIC_DIRECTORY')
 raw=encoded(value);need(len(raw)<=MAX_DATA,'BOUNDED_DEPENDENCY_REPORT');path=parent/'dependency-failure.json';fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 with os.fdopen(fd,'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
 return path
def prepare(producer,args,delegate,*,diagnostic):
 """Compose the held updater hook; never replace its source or failure outcome."""
 need(pin(read(producer.__file__,128*1024)[0])['sha256']==PRODUCER_PIN,'WHOLE_HELD_PRODUCER')
 need(pin(read(Path(args.code)/CALLER,128*1024)[0])['sha256']==CALLER_PIN,'WHOLE_HELD_CALLER')
 need(pin(read(diagnostic.__file__,128*1024)[0])['sha256']==DIAGNOSTIC_PIN,'WHOLE_HELD_DIAGNOSTIC')
 original=diagnostic.command;captured=[]
 def factory(old,source,updater_callback):
  def callback(argv,log,timeout,code,error):
   try:updater_callback(argv,log,timeout,code,error)
   except BaseException:pass # Same optional updater DATA behavior, independently preserved.
   if not role(args,argv,log,timeout)or captured:return
   try:value=record(args,argv,log,timeout,code,error)
   except BaseException as failure:value=dict(schema_version=1,purpose='SOURCE_OWNED_DEPENDENCY_AUTH_FAILURE_DATA_ONLY',status='REFUSED_UNSAFE_OR_CHANGED_DEPENDENCY_DATA',error_type=type(failure).__name__,acceptance_authority=False,cleanup_authority=False)
   captured.append(value)
   try:publish(args,value)
   except BaseException:pass # Optional DATA cannot replace the pending original failure.
  return original(old,source,callback) # Held factory verifies whole command and exact inverse.
 diagnostic.command=factory
 try:return delegate()
 finally:diagnostic.command=original
