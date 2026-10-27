# SPDX-License-Identifier: MIT
"""Actual normal-libALPM callback plus payload mutation; never lock inference."""
import ast,base64,ctypes as C,functools,hashlib,importlib.util,json,os,re,signal,stat,sys,time,types
from pathlib import Path
SOURCE=Path('/source');LANE='scripts/ci/apps7-full574-repair-native'
NORMAL='/source/'+LANE+'/transaction.py';WRAPPER='/operation/boundary.py'
CONTEXT='apps-boundary-context.json';CAPTURE='apps-boundary-capture.json'
APPS='cachy-asahi-apps';VERSION='0.1.0-16';TARGET='usr/share/doc/cachy-asahi-apps/README.md'
ARCHIVE='319cc1db4738945ad3b146490ea0fabd80f8c8d89d8c41a11750dd0ba5d5b8af'
LIBRARY='/usr/lib/libalpm.so.16.0.1';LIBRARY_SHA='94c013b9026772ffe4f227f508a2cdf0c61323dc1f7b7836fe629b49bfbc3902'
ABI=b'16.0.1';PACKAGE_START=11;PACKAGE_DONE=12;REINSTALL=3;PROGRESS_REINSTALL=3;LIMIT=1024**2
CTX_KEYS={'schema_version','operation_profile_sha256','ownership_sha256','plan_sha256','normal_argv','before_target'}
SOURCE_PINS={'scripts/apps/transaction.py:commit':{'bytes':1453,'sha256':'a31c5c2e17555c4d5c62bf4ad0d7eaea77f16ed64932a07cacec1b055455bee0'},'scripts/update/bound_update.py:transaction':{'bytes':711,'sha256':'0f72ab8ac1230495da8cc1fba4ee192228f8dc496ee73238bbe243a16ef369a5'},'scripts/install/local_transaction.py:Alpm':{'bytes':3702,'sha256':'c3bdf433c66c9c8b15edcecf74c336e81bd3f9086a9536f23c0e58297bf85bcb'}}
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def decode(raw):
 def pairs(rows):
  v={}
  for k,x in rows:need(k not in v,'duplicate boundary key');v[k]=x
  return v
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite boundary JSON'))
def key(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def canonical(path):
 text=os.fspath(path);need(os.path.isabs(text)and text==os.path.normpath(text)and not text.startswith('//'),'canonical boundary path');p=Path(text);need(not any(q.is_symlink()for q in(p,*p.parents)),'ordinary boundary ancestry');return p
def read(path,cap=LIMIT,private=False):
 p=canonical(path);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded singlelink boundary input')
  if private:need(a.st_uid==0 and stat.S_IMODE(a.st_mode)==0o600,'source-owned root0600 boundary input')
  out=b''
  while b:=os.read(fd,65536):out+=b;need(len(out)<=a.st_size,'boundary input grew')
  need(len(out)==a.st_size and key(a)==key(os.fstat(fd))==key(p.lstat()),'boundary FD/path drift');return out
 finally:os.close(fd)
def writer(pid=None):
 pid=os.getpid()if pid is None else pid;raw=Path('/proc/'+str(pid)+'/stat').read_bytes();need(len(raw)<=65536,'bounded writer proc stat');w=raw[raw.rfind(b')')+2:].split()
 return dict(pid=pid,pgid=int(w[2]),sid=int(w[3]),start=int(w[19]),uid=Path('/proc/'+str(pid)).stat().st_uid),w[0].decode()
def unwrap_argv(argv):
 need(type(argv)is list and len(argv)>5 and argv[:3]==['/usr/bin/python3','-I','-B']and argv[3]==WRAPPER and argv[-1]=='--worker','only exact source-owned wrapper argv seam');v=list(argv);v[3]=NORMAL;return v
def option(argv,name):
 need(argv.count(name)==1,'one explicit original option: '+name);i=argv.index(name);need(i+1<len(argv)and not argv[i+1].startswith('--'),'explicit original option value');return argv[i+1]
def source_audit(root):
 root=canonical(root);out={}
 for role,want in SOURCE_PINS.items():
  name,func=role.split(':');raw=read(root/name,16*LIMIT).decode();nodes=[n for n in ast.parse(raw).body if getattr(n,'name',None)==func];need(len(nodes)==1,'one normal source object');body=(ast.get_source_segment(raw,nodes[0])+'\n').encode();need(pin(body)==want,'exact normal backend source: '+role);out[role]=want
 return dict(status='SOURCE_ONLY_NORMAL_BACKEND_BOUNDARY_AUDIT',source_pins=out,callback_abi='libalpm16.0.1',callback_order='NOT_ASSUMED_ACTUAL_DB_EQUALITY_REQUIRED',native='NOT_RUN')
def snapshot(path):
 p=canonical(path);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size<=4*LIMIT,'bounded selected data file');h=hashlib.sha256();size=0
  while b:=os.read(fd,65536):h.update(b);size+=len(b);need(size<=s.st_size,'selected data grew')
  need(size==s.st_size and key(s)==key(os.fstat(fd))==key(p.lstat()),'selected data FD/path drift')
  return dict(node=dict(type='file',mode=stat.S_IMODE(s.st_mode),uid=s.st_uid,gid=s.st_gid,bytes=size,sha256=h.hexdigest()),physical=list(key(s)))
 finally:os.close(fd)
def database(root,deadline):
 folder=canonical(Path(root)/'var/lib/pacman/local');nodes={};physical={};total=0;pending=[folder];queued=1
 while pending:
  p=pending.pop();need(time.monotonic()<deadline and len(nodes)<8192,'existing600s bounded DB snapshot');name=p.relative_to(folder).as_posix();s=p.lstat();need(not p.is_symlink(),'ordinary ALPM DB node')
  if stat.S_ISDIR(s.st_mode):
   row=dict(type='directory',mode=stat.S_IMODE(s.st_mode),uid=s.st_uid,gid=s.st_gid)
   with os.scandir(p)as children:
    for child in children:
     queued+=1;need(queued<=8192 and time.monotonic()<deadline,'bounded DB directory traversal');pending.append(Path(child.path))
  else:
   v=snapshot(p);row=v['node'];total+=row['bytes'];need(total<=64*LIMIT,'bounded complete DB metadata bytes')
  nodes[name]=row;physical[name]=list(key(s));need(key(s)==key(p.lstat()),'DB metadata drift')
 return dict(content_sha256=pin(encoded(nodes))['sha256'],physical_sha256=pin(encoded(physical))['sha256'],nodes=len(nodes),bytes=total)
class PackageEvent(C.Structure):_fields_=[('type',C.c_int),('operation',C.c_int),('oldpkg',C.c_void_p),('newpkg',C.c_void_p)]
EVENT_CB=C.CFUNCTYPE(None,C.c_void_p,C.c_void_p)
PROGRESS_CB=C.CFUNCTYPE(None,C.c_void_p,C.c_int,C.c_char_p,C.c_int,C.c_size_t,C.c_size_t)

class Observer:
 def __init__(self,T,alpm,workspace,context,archives,result):
  self.T,self.alpm,self.workspace,self.context,self.result=T,alpm,workspace,context,result
  self.deadline=min(alpm.limits.deadline,time.monotonic()+600);self.identity,_=writer()
  need(self.identity['pid']==self.identity['pgid']==self.identity['sid']and self.identity['uid']==0,'source-owned native worker session')
  need(isinstance(alpm.lib,C.CDLL)and alpm.lib._name==LIBRARY and pin(read(Path(LIBRARY),64*LIMIT))['sha256']==LIBRARY_SHA,'normal pinned native libalpm object only')
  need(alpm.alpm_version()==ABI and alpm.started is True,'normal ALPM16.0.1 active transaction')
  for name in ('alpm_trans_commit','alpm_pkg_get_name','alpm_pkg_get_version'):
   need(isinstance(getattr(alpm,name),C._CFuncPtr)and C.cast(getattr(alpm,name),C.c_void_p).value==C.cast(getattr(alpm.lib,name),C.c_void_p).value,'normal actual libalpm function identity')
  need(set(archives)=={APPS},'one actual authenticated selected archive');archive=Path(archives[APPS]);raw=read(archive,4*LIMIT);need(pin(raw)['sha256']==ARCHIVE,'actual normal backend archive bytes')
  payload=T.I.archive_payload(raw,dict(bytes=0,nodes=0));need(TARGET in payload and payload[TARGET]['type']=='file','selected authenticated ordinary target')
  self.archive_node=payload[TARGET];self.before=snapshot(workspace/'root'/TARGET);need(self.before['node']==context['before_target']and self.before['node']!=self.archive_node,'actual damaged-before target matches inspection')
  self.db=database(workspace/'root',self.deadline);self.started=None;self.count=0;self.total=0;self.errors=[];self.fd=os.open(workspace/CAPTURE,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
  self.file=os.fstat(self.fd);self.value=dict(schema_version=1,status='NOT_OBSERVED',ready=False,commit_started='UNKNOWN',packages_committed='UNKNOWN',rollback='NOT_CLAIMED',writer=self.identity,normal_argv=context['normal_argv'],derived_argv=[*context['normal_argv'][:3],WRAPPER,*context['normal_argv'][4:]],plan_sha256=context['plan_sha256'],ownership_sha256=context['ownership_sha256'],source_pins=SOURCE_PINS,operation_profile_sha256=context['operation_profile_sha256'],library=dict(path=LIBRARY,sha256=LIBRARY_SHA,version=ABI.decode()),actual_archive=dict(path=str(archive),**pin(raw)),before_target=self.before,archive_node=self.archive_node,database_before=self.db,errors=self.errors,capture_fd=self.fd,capture_identity=list(key(self.file)[:6]))
  self.event=EVENT_CB(self.on_event);self.progress=PROGRESS_CB(self.on_progress);self.registered=[]
  try:self.register();self.publish()
  except BaseException:
   try:self.detach()
   finally:os.close(self.fd)
   raise
 def register(self):
  for kind,callback,ctype in [('event',self.event,EVENT_CB),('progress',self.progress,PROGRESS_CB)]:
   get=getattr(self.alpm.lib,'alpm_option_get_'+kind+'cb');get.restype=C.c_void_p;get.argtypes=[C.c_void_p];need(not get(self.alpm.handle),'normal backend has no preexisting callback to replace')
   setcb=getattr(self.alpm.lib,'alpm_option_set_'+kind+'cb');setcb.restype=C.c_int;setcb.argtypes=[C.c_void_p,ctype,C.c_void_p];need(setcb(self.alpm.handle,callback,None)==0,'register source-owned ALPM observer');self.registered.append((kind,ctype))
 def publish(self):
  need(time.monotonic()<self.deadline,'existing600s boundary deadline');self.value['observer_output_bytes']=self.total
  for _ in range(8):
   raw=encoded(self.value);cumulative=self.total+len(raw)
   if self.value['observer_output_bytes']==cumulative:break
   self.value['observer_output_bytes']=cumulative
  else:raise ValueError('stable bounded output accounting')
  need(len(raw)<=LIMIT and cumulative<=LIMIT,'entire1MiB boundary observer output')
  need(key(os.fstat(self.fd))[:6]==key((self.workspace/CAPTURE).lstat())[:6]==key(self.file)[:6],'source-owned capture descriptor identity')
  os.ftruncate(self.fd,0);need(os.pwrite(self.fd,raw,0)==len(raw),'whole callback evidence publication');os.fsync(self.fd);self.total+=len(raw)
 def event_error(self,stage,error):
  if len(self.errors)<8:self.errors.append(dict(stage=stage,type=type(error).__name__,message=str(error)[:512]))
  self.value.update(status='NOT_OBSERVED',ready=False,commit_started='UNKNOWN',packages_committed='UNKNOWN')
  try:self.publish()
  except Exception:pass
 def on_event(self,ctx,event):
  try:
   self.count+=1;need(self.count<=4096 and time.monotonic()<self.deadline,'bounded original ALPM event observation')
   event_type=C.cast(event,C.POINTER(C.c_int)).contents.value
   if event_type!=PACKAGE_START:return
   e=C.cast(event,C.POINTER(PackageEvent)).contents;need(e.operation==REINSTALL and e.oldpkg and e.newpkg,'actual ALPM reinstall package-start struct')
   old=dict(name=self.alpm.alpm_pkg_get_name(e.oldpkg).decode(),version=self.alpm.alpm_pkg_get_version(e.oldpkg).decode());new=dict(name=self.alpm.alpm_pkg_get_name(e.newpkg).decode(),version=self.alpm.alpm_pkg_get_version(e.newpkg).decode());need(old==new==dict(name=APPS,version=VERSION),'actual selected old/new ALPM package identity')
   self.started=dict(type=event_type,operation=e.operation,oldpkg=int(e.oldpkg),newpkg=int(e.newpkg),old=old,new=new,raw_base64=base64.b64encode(C.string_at(event,C.sizeof(PackageEvent))).decode())
  except Exception as error:self.event_error('event',error)
 def on_progress(self,ctx,kind,package,percent,howmany,current):
  try:
   self.count+=1;need(self.count<=4096 and time.monotonic()<self.deadline,'bounded original ALPM progress observation')
   if self.errors or kind!=PROGRESS_REINSTALL or package!=APPS.encode()or self.started is None:return
   need(0<=percent<=100 and howmany==1 and 0<=current<=1,'bounded selected ALPM progress data')
   need(self.result.get('phase')=='commit'and self.result.get('commit_started')is True and self.result.get('packages_committed')=='UNKNOWN','inside unchanged normal commit before terminal return')
   after=snapshot(self.workspace/'root'/TARGET)
   if after['node']!=self.archive_node or after['node']==self.before['node']:return
   db=database(self.workspace/'root',self.deadline)
   if db!=self.db:self.value['database_mutation_observed']=True;return
   observed,_=writer();need(observed==self.identity,'same callback writer kernel identity')
   self.value.update(status='OBSERVED_NORMAL_ALPM_MUTATION_BEFORE_DB_WRITE',ready=True,commit_started=True,packages_committed='UNKNOWN',entered_commit='OBSERVED_WITH_SELECTED_PAYLOAD_MUTATION',package_start=self.started,progress=dict(kind=kind,package=package.decode(),percent=percent,howmany=howmany,current=current),backend_state={k:self.result[k]for k in ('phase','commit_started','packages_committed')},after_target=after,database_at_capture=db,self_stop_signal=int(signal.SIGSTOP))
   self.publish();os.killpg(self.identity['pgid'],signal.SIGSTOP)
   # Only an external resume reaches here; it no longer describes a held point.
   self.value.update(status='NOT_OBSERVED',ready=False,commit_started='UNKNOWN',resumed=True);self.publish()
  except Exception as error:self.event_error('progress',error)
 def detach(self):
  for kind,ctype in reversed(self.registered):
   setcb=getattr(self.alpm.lib,'alpm_option_set_'+kind+'cb');need(setcb(self.alpm.handle,ctype(),None)==0,'restore original empty callback')
  self.registered=[]
 def close(self):
  try:
   self.detach();self.value.update(normal_backend_returned=True,normal_backend_state=dict(self.result));self.publish()
  finally:os.close(self.fd)

def unknown(reason,**extra):return dict(schema_version=1,status='NOT_OBSERVED',ready=False,commit_started='UNKNOWN',packages_committed='UNKNOWN',rollback='NOT_CLAIMED',reason=reason,**extra)
def _capture_check(v):
 need(type(v['observer_output_bytes'])is int and 0<v['observer_output_bytes']<=LIMIT,'cumulative callback output accounting')
 need(v['schema_version']==1 and v['status']=='OBSERVED_NORMAL_ALPM_MUTATION_BEFORE_DB_WRITE'and v['ready']is True and v['commit_started']is True and v['packages_committed']=='UNKNOWN'and v['rollback']=='NOT_CLAIMED'and not v['errors'],'genuine observed mutation boundary, never sidecar flag alone')
 need(type(v['operation_profile_sha256'])is str and re.fullmatch('[0-9a-f]{64}',v['operation_profile_sha256']),'source-verified operation profile binding')
 need(v['source_pins']==SOURCE_PINS and v['library']==dict(path=LIBRARY,sha256=LIBRARY_SHA,version=ABI.decode())and v['actual_archive']['sha256']==ARCHIVE,'normal pinned source/library/authenticated archive')
 need(v['before_target']['node']!=v['after_target']['node']==v['archive_node']and v['before_target']['node']['sha256']!=v['after_target']['node']['sha256'],'actual selected authenticated payload bytes changed')
 need(v['database_before']==v['database_at_capture']and v['database_before']['nodes']>0,'complete raw localDB content and physical state unchanged')
 need(v['backend_state']==dict(phase='commit',commit_started=True,packages_committed='UNKNOWN'),'unchanged normal backend commit state')
 e=v['package_start'];need(e['type']==PACKAGE_START and e['operation']==REINSTALL and e['old']==e['new']==dict(name=APPS,version=VERSION)and type(e['oldpkg'])is int and e['oldpkg']>0 and type(e['newpkg'])is int and e['newpkg']>0,'actual ALPM selected package-start identity')
 raw=base64.b64decode(e['raw_base64'],validate=True);need(len(raw)==C.sizeof(PackageEvent),'whole raw ALPM package event struct');actual=PackageEvent.from_buffer_copy(raw);need(actual.type==e['type']and actual.operation==e['operation']and actual.oldpkg==e['oldpkg']and actual.newpkg==e['newpkg'],'raw ALPM event bytes and decoded identity join')
 p=v['progress'];need(p['kind']==PROGRESS_REINSTALL and p['package']==APPS and type(p['percent'])is int and 0<=p['percent']<=100 and type(p['howmany'])is int and p['howmany']==1 and type(p['current'])is int and 0<=p['current']<=1,'actual bounded selected progress, percent is not mutation proof')
 need(v['self_stop_signal']==signal.SIGSTOP and unwrap_argv(v['derived_argv'])==v['normal_argv'],'one exact wrapper and kernel stop intent')
 return v

def probe_boundary(workspace,identity,normal_argv=None,deadline=None,output_bytes=0):
 """Parent-side read only. NOT_OBSERVED never means commit_started=False."""
 workspace=canonical(workspace)
 if deadline is not None:need(time.monotonic()<deadline,'original600s polling deadline')
 need(type(output_bytes)is int and 0<=output_bytes<=LIMIT,'original output accounting')
 path=workspace/CAPTURE
 if not os.path.lexists(path):return unknown('NO_SOURCE_OWNED_CALLBACK_CAPTURE')
 try:raw=read(path,LIMIT,private=True);v=decode(raw)
 except (OSError,ValueError):return unknown('CAPTURE_NOT_STABLE_OR_COMPLETE')
 need(output_bytes+len(raw)<=LIMIT,'original combined1MiB output including boundary capture')
 observed_bytes=v.get('observer_output_bytes');need(type(observed_bytes)is int and len(raw)<=observed_bytes<=LIMIT and output_bytes+observed_bytes<=LIMIT,'entire callback publication plus stdout/stderr1MiB cap')
 if v.get('status')!='OBSERVED_NORMAL_ALPM_MUTATION_BEFORE_DB_WRITE'or v.get('ready')is not True:return unknown('NO_QUALIFYING_CALLBACK_MUTATION',source_capture=pin(raw),capture=v)
 _capture_check(v);actual,state_now=writer(identity['pid']);need(actual==identity==v['writer'],'same actual owned callback writer')
 if state_now not in ('T','t'):return unknown('WRITER_NOT_KERNEL_STOPPED',source_capture=pin(raw))
 if normal_argv is not None:need(v['normal_argv']==normal_argv,'exact original normal argv')
 cmd=read_proc_cmdline(identity['pid']);need(cmd==v['derived_argv'],'actual stopped source-owned wrapper cmdline')
 fd=v['capture_fd'];need(type(fd)is int and fd>=0,'source-owned capture descriptor number');info=os.stat('/proc/'+str(identity['pid'])+'/fd/'+str(fd));need(list(key(info)[:6])==v['capture_identity']==list(key(path.lstat())[:6]),'actual writer holds this exact capture file')
 fdinfo=Path('/proc/'+str(identity['pid'])+'/fdinfo/'+str(fd)).read_text();flags=[x.split(':',1)[1].strip()for x in fdinfo.splitlines()if x.startswith('flags:')];need(len(flags)==1 and int(flags[0],8)&os.O_ACCMODE==os.O_RDWR,'actual source writer read/write descriptor')
 value=dict(v,source_capture=pin(raw),capture_raw_base64=base64.b64encode(raw).decode(),parent_kernel_state=state_now,parent_writer_fd_identity=list(key(info)[:6]));return value

def read_proc_cmdline(pid):
 with open('/proc/'+str(pid)+'/cmdline','rb')as f:raw=f.read(LIMIT+1)
 need(len(raw)<=LIMIT and raw.endswith(b'\0'),'bounded complete actual writer argv');return[x.decode()for x in raw[:-1].split(b'\0')]

def validate(value,trace,plan,inspection):
 _capture_check(value);need(value['writer']==trace['identity']and value['derived_argv']==trace['argv']and value['ownership_sha256']==trace['ownership_sha256'],'boundary belongs to exact retired owned worker')
 need(trace['direct_child_reaped']is True and trace['group_absent']is True and trace['returncode']==-signal.SIGKILL,'normal held writer stop/kill/reap evidence')
 need(value['plan_sha256']==inspection['plan_sha256']==pin(encoded(plan))['sha256']and value['before_target']['node']==inspection['damage'][TARGET]and inspection['archives']=={APPS:ARCHIVE},'original authenticated plan/damage/archive boundary joins')
 raw=base64.b64decode(value['capture_raw_base64'],validate=True);need(len(raw)<=value['observer_output_bytes']and pin(raw)==value['source_capture']and decode(raw)=={k:v for k,v in value.items()if k not in ('source_capture','capture_raw_base64','parent_kernel_state','parent_writer_fd_identity')},'whole exact source-owned callback raw bytes')
 need(value['parent_kernel_state']in('T','t')and value['parent_writer_fd_identity']==value['capture_identity'],'independent parent kernel stop and descriptor custody')
 return dict(status='VALIDATED_NORMAL_SOURCE_OWNED_MUTATION_BOUNDARY',normal_argv=value['normal_argv'],derived_argv=value['derived_argv'],commit_started=True,packages_committed='UNKNOWN',rollback='NOT_CLAIMED')

def _load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

def wrap_commit(T,workspace,context):
 source_audit(SOURCE);text=read(SOURCE/'scripts/apps/transaction.py',16*LIMIT).decode();node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name=='commit');body=ast.get_source_segment(text,node)+'\n';scope={};exec(compile(body,'<exact-held-normal-commit-source>','exec'),scope)
 original=T.commit;reference=scope['commit'].__code__;actual=original.__code__
 need(all(getattr(actual,n)==getattr(reference,n)for n in ('co_code','co_consts','co_names','co_varnames','co_argcount','co_kwonlyargcount','co_flags')),'whole unchanged normal commit function object')
 @functools.wraps(original)
 def observed(alpm,add,remove,archives,architecture,result):
  need(add=={APPS:VERSION}and remove=={}and architecture=='aarch64','normal authenticated exact selected reinstall arguments')
  observer=Observer(T,alpm,workspace,context,archives,result);alpm._apps_boundary_observer=observer
  try:return original(alpm,add,remove,archives,architecture,result)
  finally:observer.close()
 T.commit=observed;return original

def pre_environment():
 need(os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64'and Path('/.dockerenv').is_file(),'original owned offline native actor only')
 need(os.environ.get('PATH')=='/usr/bin:/bin'and not any(k.startswith(('LD_','GPG_','ALPM_','PACMAN_'))for k in os.environ),'original clean normal backend environment')
 need(re.fullmatch('[0-9a-f]{32}',os.environ.get('CACHY_ASAHI_APPS_TRANSACTION','')),'original exact owner token')
 interfaces={s.split(':',1)[0].strip()for s in Path('/proc/net/dev').read_text().splitlines()if ':'in s};need(interfaces=={'lo'},'original offline namespace')

def main():
 try:
  pre_environment();actual=read_proc_cmdline(os.getpid());normal=unwrap_argv(actual)
  need(normal[4]=='apply'and normal.count('--worker')==1 and option(normal,'--operation')=='reinstall','one original apply --worker reinstall only')
  workspace=canonical(option(normal,'--workspace'));need(str(workspace)=='/work/main'and stat.S_IMODE(workspace.stat().st_mode)==0o700 and workspace.stat().st_uid==0,'exact owned private component workspace')
  context=decode(read(workspace/CONTEXT,LIMIT,private=True));need(type(context)is dict and set(context)==CTX_KEYS and type(context['schema_version'])is int and context['schema_version']==1,'closed source-owned boundary context')
  profile=os.environ.get('APPS16_INTERRUPTION_PROFILE_SHA256');need(type(profile)is str and re.fullmatch('[0-9a-f]{64}',profile)and context['operation_profile_sha256']==profile,'independently passed original operation profile')
  X=_load('_boundary_common',Path(__file__).with_name('common.py'));X.verify(SOURCE,profile);source_audit(SOURCE)
  need(context['normal_argv']==normal and context['ownership_sha256']==option(normal,'--ownership-sha256')and context['plan_sha256']==option(normal,'--plan-sha256'),'normal original caller arguments unchanged')
  need(pin(read(workspace/'apps-copy.json',65536))['sha256']==context['ownership_sha256']and pin(read(Path(option(normal,'--plan')),16*LIMIT))['sha256']==context['plan_sha256'],'physical copy owner and caller plan pins')
  contract=_load('_boundary_normal_contract',SOURCE/LANE/'contract.py');contract.source(SOURCE)
  sys.path.insert(0,str(SOURCE/LANE));T=contract.load('boundary_normal_transaction',SOURCE/LANE/'transaction.py');T.environment_guard();wrap_commit(T,workspace,context)
  return T.main()
 except Exception as error:
  print(encoded(dict(status='FAIL',phase='boundary-wrapper',boundary='NOT_OBSERVED',error_type=type(error).__name__,error=str(error)[:1024],commit_started='UNKNOWN',packages_committed='UNKNOWN',rollback='NOT_CLAIMED')).decode(),end='');return 1

if __name__=='__main__':raise SystemExit(main())
