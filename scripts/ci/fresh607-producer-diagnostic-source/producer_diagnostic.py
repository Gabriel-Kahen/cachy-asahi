# SPDX-License-Identifier: MIT
"""Failure-only fixed updater build DATA, captured before original producer cleanup."""
import ast,base64,hashlib,json,os,re,stat
from pathlib import Path
PRODUCER='scripts/ci/full-composition-installer-vm/producer.py'
CALLER='scripts/ci/full-root-upgrade-caller/run.py'
PRODUCER_PIN='98d61944888485870b31b5457bcad9edfd8e51cb367414833f8d54611d7b0eaf'
CALLER_PIN='b9840c79ffc6c45070ac12b80d469fb46c26059df63e121801d6ab223035e303'
COMMAND_PIN='40cee272769962bc2ff75f543548cfb2b40ef4d645699b7ea6d530f0232b6e6a'
LOGS={'updater/build.log':65536,'updater/native/result.json':16384,'updater/native/bootstrap.log':65536,'updater/native/key-import.log':8192,'updater/native/build-1/build.log':32768,'updater/native/build-2/build.log':32768}
MAX_DATA=384*1024

def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def identity(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))
def ordinary(path):
 p=Path(path);need(p==p.resolve()and not any(q.is_symlink()for q in(p,*p.parents)),'ALIASED_PATH');s=p.lstat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_uid==os.geteuid(),'NON_OWNED_OR_LINKED_FILE');return p,s

def tail(raw,name,cap):
 need(name in LOGS and LOGS[name]==cap,'UNDECLARED_LOG');root=Path(raw);path=root/name
 try:p,a=ordinary(path)
 except FileNotFoundError:return dict(status='NOT_PRESENT')
 need(0<=a.st_size<=1024**3,'LOG_FILE_SIZE');fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  need(identity(os.fstat(fd))==identity(a),'OPEN_IDENTITY_CHANGED');offset=max(0,a.st_size-cap);os.lseek(fd,offset,os.SEEK_SET);b=b''
  while len(b)<min(cap,a.st_size):
   part=os.read(fd,min(16384,min(cap,a.st_size)-len(b)))
   if not part:break
   b+=part
  need(len(b)==a.st_size-offset and identity(os.fstat(fd))==identity(a)and identity(p.lstat())==identity(a),'LOG_CHANGED_DURING_CAPTURE')
  return dict(status='CAPTURED',file_bytes=a.st_size,offset=offset,complete=offset==0,**pin(b),encoding='BASE64',base64=base64.b64encode(b).decode())
 finally:os.close(fd)

def role(args,argv,log,timeout):
 values=list(map(str,argv));raw=Path(args.output)/'private';package=Path(args.updater)/'packages/tools/cachy-asahi-update'
 return(type(timeout)is int and timeout==5400 and Path(log)==raw/'updater/build.log'and len(values)==12 and values[:6]==[str(__import__('sys').executable),'-B',str(package/'updater-native.py'),'build','--candidate',str(raw/'updater/candidate/candidate.json')]and values[6]=='--candidate-sha256'and re.fullmatch('[0-9a-f]{64}',values[7])is not None and values[8:]==['--cache',str(args.cache),'--output',str(raw/'updater/native')])

def record(args,argv,log,timeout,returncode,wait_error):
 need(role(args,argv,log,timeout),'NOT_FIXED_UPDATER_BUILD_ROLE');need(returncode is None or type(returncode)is int,'COMMAND_EXIT_TYPE');need(wait_error is None or isinstance(wait_error,BaseException),'WAIT_ERROR_TYPE')
 output=Path(args.output);owner=json.loads(read(output/'producer-owner.json',65536));need(owner['schema_version']==1 and re.fullmatch('[0-9a-f]{32}',owner['token'])and owner['preparation_source']==str(args.preparation_source),'ORIGINAL_PRODUCER_OWNER');logs={}
 for name,cap in LOGS.items():
  try:logs[name]=tail(output/'private',name,cap)
  except (OSError,ValueError):logs[name]=dict(status='REFUSED_UNSAFE_OR_CHANGED')
 values=list(map(str,argv));value=dict(schema_version=1,purpose='SOURCE_OWNED_UPDATER_EXACT354_BUILD_FAILURE_DATA_ONLY',status='CAPTURED_FIXED_LOG_SET'if logs['updater/build.log']['status']=='CAPTURED'else'PRIMARY_LOG_UNAVAILABLE',command=dict(role='UPDATER_EXACT354_PAIR_BUILD',argv_sha256=hashlib.sha256(json.dumps(values,separators=(',',':'),ensure_ascii=True).encode()).hexdigest(),timeout_seconds=timeout,returncode=returncode,wait_error_type=None if wait_error is None else type(wait_error).__name__,retirement='ORIGINAL_COMMAND_FLOW_NOT_INDEPENDENTLY_REOBSERVED'),logs=logs,acceptance_authority=False,cleanup_authority=False)
 need(len(encoded(value))<=MAX_DATA,'BOUNDED_DIAGNOSTIC_JSON');return value

def read(path,cap):
 p,a=ordinary(path);need(0<=a.st_size<=cap,'BOUNDED_SOURCE_OR_REPORT');fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  need(identity(os.fstat(fd))==identity(a),'OPEN_IDENTITY_CHANGED');b=b''
  while len(b)<=cap:
   part=os.read(fd,min(65536,cap+1-len(b)))
   if not part:break
   b+=part
  need(len(b)==a.st_size and identity(os.fstat(fd))==identity(a)and identity(p.lstat())==identity(a),'SOURCE_OR_REPORT_CHANGED');return b
 finally:os.close(fd)

def command(original,source,callback):
 """Exact held command, with failure callbacks at its two original boundaries."""
 tree=ast.parse(source);nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='command'];need(len(nodes)==1,'ONE_ORIGINAL_COMMAND');body=ast.get_source_segment(source.decode(),nodes[0]);need(hashlib.sha256(body.encode()).hexdigest()==COMMAND_PIN,'WHOLE_ORIGINAL_COMMAND')
 wait='        except BaseException:\n';wait_new='        except BaseException as _diagnostic_wait_error:\n';raise_line='            raise\n';assert_line="        assert code == 0, 'command failed: ' + log.name"
 failure="            try:_producer_failure_callback(argv,log,timeout,proc.returncode,_diagnostic_wait_error)\n            except BaseException:pass # Optional DATA cannot replace original failure.\n"
 nonzero="        if code != 0:\n            try:_producer_failure_callback(argv,log,timeout,code,None)\n            except BaseException:pass # Original nonzero assert remains authoritative.\n"
 need(body.count(wait)==body.count(raise_line)==body.count(assert_line)==1,'EXACT_FAILURE_CALLBACK_BOUNDARIES');out=body.replace(wait,wait_new,1).replace(raise_line,failure+raise_line,1).replace(assert_line,nonzero+assert_line,1)
 inverse=out.replace(nonzero,'',1).replace(failure,'',1).replace(wait_new,wait,1);need(inverse==body,'ENTIRE_ORIGINAL_COMMAND_INVERSE');namespace=dict(original.__globals__,_producer_failure_callback=callback);exec(compile(out,'<source-owned-original-producer-command>','exec'),namespace);return namespace['command']

def append(args,data):
 path=Path(args.output)/'public/producer.json';raw=read(path,65536);value=json.loads(raw);need(set(value)=={'status','phase','installer','upgrade','error_type','error'}and value['status']=='FAIL'and value['phase']=='updater-exact354-pair'and value['installer']==value['upgrade']=='NOT RUN','ORIGINAL_FAILED_PRODUCER_SCOPE');value['failure_data']=data;new=encoded(value);need(len(new)<=MAX_DATA+65536,'BOUNDED_NESTED_EXISTING_REPORT');p,a=ordinary(path)
 # A private temporary preserves the original report on failed optional capture.
 temporary=Path(args.output)/'private/producer-diagnostic-report.json.tmp';need(not temporary.exists()and not temporary.is_symlink(),'FRESH_PRIVATE_DIAGNOSTIC_TEMP');fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600);owned=os.fstat(fd)
 try:
  offset=0
  while offset<len(new):
   written=os.write(fd,new[offset:]);need(written>0,'DIAGNOSTIC_TEMP_WRITE');offset+=written
  os.close(fd);fd=None;need(read(temporary,MAX_DATA+65536)==new,'DIAGNOSTIC_TEMP_CHANGED');need(identity(p.lstat())==identity(a)and read(p,65536)==raw,'ORIGINAL_REPORT_CHANGED');os.replace(temporary,p)
 finally:
  if fd is not None:os.close(fd)
  if temporary.exists()and not temporary.is_symlink():
   current=temporary.lstat()
   if(current.st_dev,current.st_ino)==(owned.st_dev,owned.st_ino):temporary.unlink()

def prepare(producer,args):
 # The caller already verifies the complete legacy source before this seam.
 need(pin(read(Path(producer.__file__),128*1024))['sha256']==PRODUCER_PIN,'WHOLE_HELD_PRODUCER');original_load=producer.load;restores=[];captured=[]
 def callback(argv,log,timeout,code,error):
  if not role(args,argv,log,timeout):return
  try:value=record(args,argv,log,timeout,code,error)
  except BaseException:value=dict(schema_version=1,purpose='SOURCE_OWNED_UPDATER_EXACT354_BUILD_FAILURE_DATA_ONLY',status='UNAVAILABLE_UNSAFE_OR_CHANGED_SOURCE',acceptance_authority=False,cleanup_authority=False)
  if not captured:captured.append(value)
 def load(path):
  api=original_load(path)
  if Path(path)==Path(args.code)/CALLER:
   raw=read(Path(path),128*1024);need(pin(raw)['sha256']==CALLER_PIN,'WHOLE_HELD_CALLER');old=api.command;api.command=command(old,raw,callback);restores.append((api,old))
  return api
 producer.load=load
 try:return producer.prepare(args)
 except BaseException:
  # Original prepare has saved producer.json; outer cleanup has not run yet.
  try:
   data=captured[0]if captured else dict(schema_version=1,purpose='SOURCE_OWNED_UPDATER_EXACT354_BUILD_FAILURE_DATA_ONLY',status='FIXED_BUILD_COMMAND_NOT_CAPTURED',acceptance_authority=False,cleanup_authority=False);append(args,data)
  except BaseException:pass # Never change original error, cleanup or caller outcome.
  raise
 finally:
  producer.load=original_load
  for api,old in restores:api.command=old
