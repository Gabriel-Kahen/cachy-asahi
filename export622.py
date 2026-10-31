# SPDX-License-Identifier: MIT
"""Preserve current public DATA and invoke the entire original opaque transport."""
import argparse,hashlib,importlib.util,json,os,stat,sys,types
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

_ADMITTED_SOURCE=None

def need(v,s):
 if not v:raise ValueError(s)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def copy(output,public,*,retained_transport=False):
 source=output/'core622-public';need(output.parent==Path('/tmp')and output.is_absolute()and public.is_absolute()and not public.exists()and not any(x.is_symlink()for x in(output,public,*output.parents,*public.parents)),'fresh explicit current output/public paths');rows={};total=0
 if source.exists():
  for f in source.rglob('*'):
   st=f.lstat();need(st.st_uid==os.getuid()and not f.is_symlink()and(stat.S_ISDIR(st.st_mode)or stat.S_ISREG(st.st_mode)and st.st_nlink==1),'only current caller-owned ordinary public evidence')
   if f.is_file():
    n=f.relative_to(source).as_posix();need(st.st_size<=128*1024**2 and len(rows)<4096,'original individual public caps');raw=f.read_bytes();need(len(raw)==st.st_size,'whole current public bytes');rows[n]=pin(raw);total+=len(raw);need(total<=768*1024**2,'original768MiB aggregate');target=public/n;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
  need((public/'export.json').is_file(),'source-owned full Core retainer required');record=json.loads((public/'export.json').read_bytes());need(set(rows)==set(record['files'])|{'export.json'}and all(rows[n]==v for n,v in record['files'].items()),'unchanged complete current Core public closure');
  if retained_transport:_retain_transport_or_early_data(public);optional_outer_caller(output,public)
  return
 public.mkdir(mode=0o700)
 # An original producer failure can precede every Core consumer. Preserve only
 # the fixed outer current result; no invented Core owner or cleanup receipt.
 result=output/'result.json'
 if result.is_file():
  st=result.lstat();need(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and st.st_uid==os.getuid()and st.st_size<=4*1024**2,'ordinary bounded current outer result');raw=result.read_bytes();need(len(raw)==st.st_size,'whole current result');(public/'fresh607-caller-result.json').write_bytes(raw);rows['fresh607-caller-result.json']=pin(raw)
 raw=(json.dumps(dict(status='CORE622_PRE_PROVISION_FAILURE_DATA_ONLY',scope='COPIED_ROOT_PROVISIONING_NOT_NORMAL_HOOK_INSTALLATION_THEN_NORMAL_CORE_VM',Core_runtime='NOT_ESTABLISHED',acceptance=False,hardware='NOT_RUN'),sort_keys=True,indent=2)+'\n').encode();(public/'current622-context.json').write_bytes(raw);rows['current622-context.json']=pin(raw);(public/'export.json').write_text(json.dumps(dict(schema=1,status='FAIL_OR_INCOMPLETE',files=rows,bytes=sum(r['bytes']for r in rows.values()),errors=[dict(file='Core622',error='PRE_PROVISION_FAILURE_DATA_ONLY')],hardware='NOT_RUN'),sort_keys=True,indent=2)+'\n')

 if retained_transport:_retain_transport_or_early_data(public);optional_outer_caller(output,public)


def _retain_early_transport_data(public,reason):
 """Stdlib-only failure DATA; no sibling imports, actor or cleanup authority."""
 public=Path(public);temporary=Path(os.environ['RUNNER_TEMP']);work=temporary/'core622-retained-transport';root=Path(__file__).absolute().parent
 def require(value):
  if not value:raise ValueError('bounded early transport DATA custody refused')
 def raw(path,cap):
  path=Path(path);require(path.is_absolute()and not any(p.is_symlink()for p in(path,*path.parents)));fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   before=os.fstat(fd);identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns);require(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_uid==os.getuid()and 0<=before.st_size<=cap);data=bytearray()
   while len(data)<=before.st_size:
    part=os.read(fd,min(1024**2,before.st_size+1-len(data)))
    if not part:break
    data.extend(part)
   require(len(data)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()));return bytes(data)
  finally:os.close(fd)
 require(temporary.is_absolute()and temporary==temporary.resolve()and temporary.is_dir()and temporary.stat().st_uid==os.getuid()and not temporary.stat().st_mode&0o022 and not public.is_relative_to(root)and not root.is_relative_to(public));record=json.loads(raw(public/'export.json',4*1024**2));record['status']='FAIL_OR_INCOMPLETE';record['errors'].append(dict(file='retained-input-transport',error='EARLY_DEPENDENCY_OR_RETENTION_'+reason));target=public/'retained-input-transport';require(not target.is_symlink());target.mkdir(mode=0o700,exist_ok=True);require(target.stat().st_uid==os.getuid()and stat.S_IMODE(target.stat().st_mode)==0o700);names={'owner.json','preparation.json','phase.stdout','phase.stderr','phase.exit-code','input-transport-actors/actors.json'}|{'input-transport-actors/%04d.log'%n for n in range(5)};total=0;copied=[];errors=[]
 if work.exists():
  require(work==work.resolve()and work.stat().st_uid==os.getuid()and stat.S_IMODE(work.stat().st_mode)==0o700)
  for p in work.rglob('*'):
   n=p.relative_to(work).as_posix();require(not p.is_symlink()and(p.is_dir()or p.is_file()))
   if p.is_file():require(n in names)
 for n in sorted(names):
  p=work/n
  if not p.exists():continue
  try:
   cap=16*1024**2 if n.endswith('.log')else 4*1024**2 if n.endswith('.json')else 1024**2;data=raw(p,cap);require(total+len(data)<=16*1024**2 and record['bytes']+len(data)<=768*1024**2);q=target/n;q.parent.mkdir(parents=True,exist_ok=True)
   if q.exists():require(raw(q,cap)==data)
   else:q.write_bytes(data)
   key='retained-input-transport/'+n
   if key in record['files']:require(record['files'][key]==pin(data))
   else:record['files'][key]=pin(data);record['bytes']+=len(data)
   total+=len(data);copied.append(n)
  except BaseException as error:errors.append(dict(file=n,error_type=type(error).__name__))
 for source,n in((temporary/'core622-job-clock.json','job-clock.json'),(temporary/'core622-native-phase.json','native-phase.json')):
  if source.exists():
   try:
    data=raw(source,16384);require(record['bytes']+len(data)<=768*1024**2);q=target/n
    if q.exists():require(raw(q,16384)==data)
    else:q.write_bytes(data)
    key='retained-input-transport/'+n
    if key in record['files']:require(record['files'][key]==pin(data))
    else:record['files'][key]=pin(data);record['bytes']+=len(data)
    copied.append(n)
   except BaseException as error:errors.append(dict(file=n,error_type=type(error).__name__))
 record['early_retention']=dict(schema=1,status='BOUNDED_EARLY_TRANSPORT_DATA_ONLY',reason_type=reason,dependency_source='ADMISSION_OR_RETENTION_FAILED_NOT_CLASSIFIED',files=copied,errors=errors,first_transport_exception='UNKNOWN_UNLESS_RAW_PHASE_STDERR_IDENTIFIES_IT',native='NOT_RUN',native_scope='THIS_STDLIB_RETENTION_FALLBACK_ONLY',prior_job_native='NOT_INFERRED',native_cleanup='NOT_ESTABLISHED',acceptance=False);(public/'export.json').write_text(json.dumps(record,sort_keys=True,indent=2,allow_nan=False)+'\n');return record

def _retain_transport_or_early_data(public):
 try:
  _admit_closed_sibling_source();__import__('ownership622').retain_complete574_transport(public)
 except BaseException as error:return _retain_early_transport_data(public,type(error).__name__)


# Versioned bounded original outer-caller DATA, never runtime/cleanup authority.
OUTER_ROLES={'result.json':4*1024**2,'intent.json':16384,'child-exception.txt':65536,'child-exception.json':16384,'outer-exception.txt':65536,'outer-exception.json':16384,'selected-main.json':16384,'phase.stdout':1024**2,'phase.stderr':1024**2,'phase.exit-code':32,'phase.stdout.json':16384,'phase.stderr.json':16384,'context-retirement.json':16384}

def outer_read(path,limit,*,prefix=False):
 path=Path(path);need(path.is_absolute()and path==path.resolve()and not any(p.is_symlink()for p in(path,*path.parents)),'literal outer diagnostic DATA');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);key=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'));need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_uid==os.getuid()and stat.S_IMODE(a.st_mode)in(0o600,0o644)and a.st_size>=0,'ordinary owned bounded outer diagnostic role');need(prefix or a.st_size<=limit,'outer diagnostic role exceeds its held cap');keep=bytearray();digest=hashlib.sha256();scanned=0;full=a.st_size<=128*1024**2
  while scanned<(a.st_size if full else min(a.st_size,limit)):
   part=os.read(fd,min(1024**2,(a.st_size if full else limit)-scanned));need(part,'whole stable outer diagnostic read');digest.update(part);scanned+=len(part)
   if len(keep)<limit:keep.extend(part[:limit-len(keep)])
  need(key(a)==key(os.fstat(fd))==key(path.lstat()),'stable original outer diagnostic descriptor/path');data=bytes(keep);return data,dict(original_path=str(path),original_bytes=a.st_size,original_sha256=digest.hexdigest()if full else None,retained=pin(data),complete=len(data)==a.st_size,window='FULL'if len(data)==a.st_size else'PREFIX',whole_digest_known=full)
 finally:os.close(fd)

def outer_encoded(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()

def outer_paths():
 import re
 source=os.environ.get('GITHUB_SHA','');run=os.environ.get('GITHUB_RUN_ID','');ref=os.environ.get('GITHUB_REF_NAME','');need(re.fullmatch('[a-f0-9]{40}',source)and source==os.environ.get('SOURCE_SHA')==os.environ.get('WORKFLOW_SHA')and re.fullmatch('[1-9][0-9]{0,19}',run)and re.fullmatch('codex/[a-z0-9-]+',ref)and os.environ.get('GITHUB_RUN_ATTEMPT')=='1','exact outer diagnostic Source/run binding');root=Path(__file__).absolute().parent;temporary=Path(os.environ['RUNNER_TEMP']);workspace=Path(os.environ['GITHUB_WORKSPACE']);need(root==workspace/'core622-code'and root==root.resolve()and temporary==temporary.resolve()and all(p.is_absolute()and not any(q.is_symlink()for q in(p,*p.parents))for p in(root,temporary))and temporary.is_dir()and temporary.stat().st_uid==os.getuid()and not temporary.stat().st_mode&0o022,'canonical disjoint Source/runtime outer diagnostic roles');work=temporary/'core622-outer-fresh-caller';output=Path('/tmp')/('cachy-asahi-expanded604-installer-'+run+'-1');need(not root.is_relative_to(temporary)and not temporary.is_relative_to(root)and not any(p.is_symlink()for p in(output,*output.parents)),'disjoint exact outer caller path');identity=dict(source=source,ref=ref,run=int(run),attempt=1);nonce=hashlib.sha256(('current607-core622:'+source+':'+run).encode()).hexdigest()[:32];code=pin(outer_read(root/'export622.py',4*1024**2)[0]);intent=dict(schema=1,status='SOURCE_BOUND_OUTER_FRESH_CALLER_INTENT_DATA_ONLY',identity=identity,nonce=nonce,source_root=str(root),runtime_temp=str(temporary),work_path=str(work),output=str(output),source_export=code,acceptance=False);return temporary,work,output,intent

def outer_intent():
 temporary,work,output,expected=outer_paths();need(work.is_dir()and work.stat().st_uid==os.getuid()and stat.S_IMODE(work.stat().st_mode)==0o700,'owned outer diagnostic directory');raw=outer_read(work/'intent.json',16384)[0];need(raw==outer_encoded(expected),'exact immutable original outer diagnostic intent');return temporary,work,output,expected

def outer_write(path,data,limit):
 need(len(data)<=limit,'bounded actual outer diagnostic write');fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:
  with os.fdopen(fd,'wb',closefd=False)as stream:stream.write(data)
  info=os.fstat(fd);return(info.st_dev,info.st_ino)
 except BaseException:
  try:
   a=os.fstat(fd);b=Path(path).lstat()
   if(a.st_dev,a.st_ino)==(b.st_dev,b.st_ino)and a.st_uid==os.getuid()and a.st_nlink==1:Path(path).unlink()
  except BaseException:pass
  raise
 finally:os.close(fd)

def outer_begin():
 _,work,_,intent=outer_paths();need(not os.path.lexists(work),'one fresh outer diagnostic intent');work.mkdir(mode=0o700);outer_write(work/'intent.json',outer_encoded(intent),16384);return intent

def outer_exception(error,kind):
 import traceback
 need(kind in('child','outer'),'fixed actual exception role');_,work,_,intent=outer_intent();body=bytearray();total=0;digest=hashlib.sha256()
 for text in traceback.TracebackException.from_exception(error,capture_locals=False).format():
  raw=text.encode('utf-8','backslashreplace');digest.update(raw);total+=len(raw)
  if len(body)<65536:body.extend(raw[:65536-len(body)])
 raw=bytes(body);outer_write(work/(kind+'-exception.txt'),raw,65536);value=dict(schema=1,status='ORIGINAL_CAUGHT_EXCEPTION_TRACEBACK_DATA_ONLY',identity=intent['identity'],nonce=intent['nonce'],kind=kind,error_type=type(error).__name__,traceback=dict(original_bytes=total,original_sha256=digest.hexdigest(),retained=pin(raw),complete=len(raw)==total,window='FULL'if len(raw)==total else'PREFIX',locals=False),acceptance=False);outer_write(work/(kind+'-exception.json'),outer_encoded(value),16384)

def outer_delegate(call):
 event=dict(schema=1,status='SELECTED_ORIGINAL_FRESH_MAIN_BOUNDARY_DATA_ONLY',phase='SELECTED_ORIGINAL_FRESH_MAIN',event='ENTER',acceptance=False)
 try:
  value=call();event.update(event='RETURN',return_type=type(value).__name__,return_value=value if type(value)in(int,bool,type(None))else None);return value
 except BaseException as error:
  event.update(event='RAISE',error_type=type(error).__name__)
  try:outer_exception(error,'outer')
  except BaseException:pass
  raise
 finally:
  try:
   _,work,_,intent=outer_intent();event.update(identity=intent['identity'],nonce=intent['nonce']);outer_write(work/'selected-main.json',outer_encoded(event),16384)
  except BaseException:pass # Optional DATA never replaces the original return/raise.

def outer_pump(role):
 """Drain FD0; optional prefix-write failure never closes the input early."""
 import select,time
 need(role in('phase.stdout','phase.stderr'),'fixed bounded stream role');deadline=time.monotonic()+60;work=None;intent=None;clock=None;stream=None;created=None;errors=[];observed=0;digest=hashlib.sha256();eof=False;kept=0
 try:
  _,work,_,intent=outer_intent();_admit_closed_sibling_source();O=__import__('ownership622');clock=O.job_clock();deadline=clock['deadline']-120
  try:stream=open(work/role,'xb',buffering=0);info=os.fstat(stream.fileno());created=(info.st_dev,info.st_ino)
  except BaseException as error:errors.append(dict(stage='OPEN_PREFIX',error_type=type(error).__name__))
 except BaseException as error:errors.append(dict(stage='CAPTURE_BINDING',error_type=type(error).__name__))
 try:
  while True:
   if clock is not None:
    try:phase=O.native_phase(require_work=False);deadline=min(deadline,phase['phase_end']+60)
    except FileNotFoundError:pass
    except BaseException as error:
     if not any(v['stage']=='PHASE_BOUND'for v in errors):errors.append(dict(stage='PHASE_BOUND',error_type=type(error).__name__))
   remaining=deadline-time.monotonic()
   if remaining<=0:errors.append(dict(stage='DRAIN_DEADLINE',error_type='TimeoutError'));break
   ready,_,_=select.select([0],[],[],min(.25,remaining))
   if not ready:continue
   raw=os.read(0,65536)
   if not raw:eof=True;break
   observed+=len(raw);digest.update(raw)
   if stream is not None and kept<1024**2:
    try:piece=raw[:1024**2-kept];count=stream.write(piece);need(count==len(piece),'whole bounded prefix write');kept+=count
    except BaseException as error:
     errors.append(dict(stage='WRITE_PREFIX',error_type=type(error).__name__))
     try:stream.close()
     except BaseException:pass
     stream=None
 finally:
  if stream is not None:
   try:stream.close()
   except BaseException as error:errors.append(dict(stage='CLOSE_PREFIX',error_type=type(error).__name__))
 if work is not None and intent is not None:
  retained=None
  try:
   need(created is not None,'no borrowed prefix adoption');info=(work/role).lstat();need((info.st_dev,info.st_ino)==created,'same owned prefix inode');retained=pin(outer_read(work/role,1024**2)[0])
  except BaseException as error:errors.append(dict(stage='PREFIX_PIN',error_type=type(error).__name__))
  value=dict(schema=1,status='BOUNDED_ORIGINAL_PHASE_STREAM_CAPTURE_DATA_ONLY',identity=intent['identity'],nonce=intent['nonce'],role=role,observed_bytes=observed,observed_sha256=digest.hexdigest(),eof=eof,retained=retained,complete=eof and retained is not None and retained['bytes']==observed and not errors,window='FULL'if eof and retained is not None and retained['bytes']==observed and not errors else'PREFIX',errors=errors,acceptance=False)
  try:outer_write(work/(role+'.json'),outer_encoded(value),16384)
  except BaseException:pass
 return 0 if eof else 1

def outer_collect(output):
 _,work,expected,intent=outer_intent();need(Path(output)==expected,'only the original source-bound fresh caller output');allowed=set(OUTER_ROLES)-{'result.json'};need(all(not p.is_symlink()and p.is_file()and p.name in allowed for p in work.iterdir()),'finite owned outer diagnostic namespace');rows={};bodies={};errors=[];total=0
 for name,cap in OUTER_ROLES.items():
  path=expected/'result.json'if name=='result.json'else work/name
  if not path.exists():rows[name]=dict(status='UNAVAILABLE',original_path=str(path));continue
  try:
   raw,meta=outer_read(path,cap);
   if name in('phase.stdout','phase.stderr'):
    pump_raw=outer_read(work/(name+'.json'),16384)[0];pump=json.loads(pump_raw);need(pump['schema']==1 and pump['status']=='BOUNDED_ORIGINAL_PHASE_STREAM_CAPTURE_DATA_ONLY'and pump['identity']==intent['identity']and pump['nonce']==intent['nonce']and pump['role']==name and pump['retained']==pin(raw)and type(pump['observed_bytes'])is int and pump['observed_bytes']>=len(raw)and type(pump['eof'])is bool and type(pump['complete'])is bool and pump['window']in('FULL','PREFIX')and pump['complete']==(pump['eof']and pump['observed_bytes']==len(raw)and not pump['errors']),'actual bounded stream pump receipt');meta.update(original_bytes=pump['observed_bytes'],original_sha256=pump['observed_sha256']if pump['eof']else None,complete=pump['complete'],window=pump['window'],whole_digest_known=pump['eof'],pump_metadata=pin(pump_raw))
   need(total+len(raw)<=8*1024**2,'held8MiB outer diagnostic aggregate');total+=len(raw);bodies[name]=raw;rows[name]=dict(status='ORIGINAL_DATA'if meta['complete']else'PARTIAL_ORIGINAL_PREFIX_DATA',**meta)
  except BaseException as error:rows[name]=dict(status='REFUSED_OR_UNAVAILABLE',original_path=str(path),error_type=type(error).__name__);errors.append(dict(role=name,error_type=type(error).__name__))
 index=dict(schema=1,status='BOUNDED_ORIGINAL_OUTER_FRESH_CALLER_DIAGNOSTICS_DATA_ONLY',identity=intent['identity'],nonce=intent['nonce'],intent=pin(outer_encoded(intent)),source_export=intent['source_export'],output=str(expected),work_path=str(work),roles=rows,retained_bytes=total,errors=errors,exception_cause='NOT_INFERRED_FROM_ABSENCE_OR_STREAM_TEXT',acceptance=False);need(len(outer_encoded(index))<=65536,'bounded diagnostic index');return bodies,index

def outer_export_commit(public,record,before):
 path=public/'export.json';temporary=public/'.outer-export-commit.tmp';data=outer_encoded(record);need(len(data)<=4*1024**2 and outer_read(path,4*1024**2)[0]==before,'stable complete original export before optional commit')
 created=None
 try:
  created=outer_write(temporary,data,4*1024**2);info=temporary.lstat();need((info.st_dev,info.st_ino)==created and outer_read(temporary,4*1024**2)[0]==data,'same prepared optional export inode/body');need(outer_read(path,4*1024**2)[0]==before,'same original export at optional commit');os.replace(temporary,path)
 finally:
  if created is not None and os.path.lexists(temporary):
   info=temporary.lstat()
   if(info.st_dev,info.st_ino)==created and info.st_uid==os.getuid()and info.st_nlink==1:temporary.unlink()

def retain_outer_caller(output,public):
 temporary,_,_,_=outer_intent();public=Path(public);need(public==temporary/'core622-public'and public==public.resolve()and public.is_dir(),'fixed existing complete Core public diagnostic target');bodies,index=outer_collect(output);bodies['index.json']=outer_encoded(index);before=outer_read(public/'export.json',4*1024**2)[0];record=json.loads(before);need(not(public/'outer-fresh-caller').exists(),'fresh versioned outer diagnostic public roles');target=public/'outer-fresh-caller';target.mkdir(mode=0o700);need(sum(map(len,bodies.values()))<=8*1024**2,'unchanged outer component cap');failures=[];written={}
 try:
  for name,raw in bodies.items():
   try:
    need(record['bytes']+len(raw)<=768*1024**2 and len(record['files'])<4096,'held whole Core public capacities');identity=outer_write(target/name,raw,OUTER_ROLES.get(name,65536));written[name]=dict(pin=pin(raw),identity=identity);record['files']['outer-fresh-caller/'+name]=pin(raw);record['bytes']+=len(raw)
   except BaseException as error:failures.append(dict(role=name,error_type=type(error).__name__))
  record['outer_caller_diagnostics']=dict(schema=1,status='OPTIONAL_ORIGINAL_OUTER_DIAGNOSTIC_DATA_ONLY',index=pin(bodies['index.json'])if'outer-fresh-caller/index.json'in record['files']else None,errors=failures,acceptance=False);outer_export_commit(public,record,before);return index
 except BaseException:
  # Roll back only these freshly-created, unchanged owned copies. Originals stay.
  for name,w in written.items():
   path=target/name
   info=path.lstat()
   if(info.st_dev,info.st_ino)==w['identity']and pin(outer_read(path,OUTER_ROLES.get(name,65536))[0])==w['pin']:path.unlink()
  if not any(target.iterdir()):target.rmdir()
  raise

def optional_outer_caller(output,public):
 try:return retain_outer_caller(output,public)
 except BaseException as error:
  try:
   public=Path(public);need(not(public/'outer-fresh-caller').exists(),'no undeclared optional physical roles');before=outer_read(public/'export.json',4*1024**2)[0];record=json.loads(before);record['outer_caller_diagnostics']=dict(schema=1,status='UNAVAILABLE_OR_REFUSED_OPTIONAL_OUTER_DATA',error_type=type(error).__name__,acceptance=False);outer_export_commit(public,record,before)
  except BaseException:pass # Original complete export remains authoritative.


class ContextRetirementObservations:
 """Observe original values only; never walk, stat, read or sample a clock."""
 def __init__(self,parent,deadline,authority=None):
  self.authority=authority;self.inventory_validation="NOT_EVALUATED";self.parent=Path(parent);self.deadline=deadline;self.context_hash=hashlib.sha256(str(parent).encode('utf-8','surrogateescape')).hexdigest();self.scalars={n:dict(status='NOT_EVALUATED')for n in('entry_count','file_bytes_total','owner_type_alias_all','monotonic')};self.evaluations={n:dict(status='NOT_EVALUATED',calls=0,true=0,false=0)for n in('byte_is_file','file_bytes','alias','owner_matches_current','type_is_file','type_is_dir')};self.samples={};self.events=hashlib.sha256();self.error_type=None
 def record(self,name,value,role=None):
  try:
   if name in self.scalars:self.scalars[name]=dict(status='EVALUATED',value=value)
   else:
    row=self.evaluations[name];row['status']='EVALUATED';row['calls']+=1
    if type(value)is bool:row['true'if value else'false']+=1
   if role is not None:
    digest=hashlib.sha256(role.relative_to(self.parent).as_posix().encode('utf-8','surrogateescape')).hexdigest();self.events.update((name+':'+digest+'\n').encode())
    if digest in self.samples or len(self.samples)<8:self.samples.setdefault(digest,{})[name]=value
  except BaseException as error:self.error_type=type(error).__name__
  return value
 def inventory_check(self,call):
  try:value=call()
  except BaseException:self.inventory_validation='REFUSED';raise
  self.inventory_validation='PASS_EXACT_CACHED_ENTRY_NAMESPACE';return value
 def emit(self,predicate=None,operand_error=None):
  try:
   _,work,_,intent=outer_intent();value=dict(schema=1,status='OBSERVED_EXISTING_CURRENT_CONTEXT_RETIREMENT_GUARD_DATA_ONLY',identity=intent['identity'],nonce=intent['nonce'],source_export=intent['source_export'],context_role='CURRENT_SELECTED_CONTEXT',context_path_sha256=self.context_hash,limits=dict(entries=2048,bytes=768*1024**2,shared_cleanup_seconds=240),cleanup_end=self.deadline,scalars=self.scalars,evaluations=self.evaluations,role_event_sha256=self.events.hexdigest(),sampled_roles=[dict(role_sha256=k,values=v)for k,v in self.samples.items()],sample_limit=8,predicate=dict(status='OPERAND_RAISED',error_type=operand_error)if operand_error is not None else dict(status='EVALUATED',value=predicate),observation_error_type=self.error_type,extra_context_walks=0,extra_context_stats=0,extra_clock_samples=0,acceptance=False);
   if self.authority is not None:value.update(schema=2,context_authority=self.authority,inventory_validation=self.inventory_validation);value['limits']['bytes']=self.authority['bytes']
   outer_write(work/'context-retirement.json',outer_encoded(value),16384)
  except BaseException:pass # Observation cannot replace original guard/exception.

class _NoContextRetirementObservation:
 def record(self,name,value,role=None):return value
 def inventory_check(self,call):return call()
 def emit(self,predicate=None,operand_error=None):pass

def context_retirement_observations(parent,deadline,authority=None):
 try:return ContextRetirementObservations(parent,deadline,authority)
 except BaseException:return _NoContextRetirementObservation()

def context_authority_value(value,index):
 """Finite semantic budget declaration; not an independent removal receipt."""
 import re
 keys={'schema','status','identity','nonce','context_path_sha256','root_identity_sha256','files_sha256','context_owner','public_export','public_files_sha256','kernel_files_sha256','files','directories','components','bytes','acceptance'};need(type(value)is dict and set(value)==keys and type(value['schema'])is int and value['schema']==1 and value['status']=='EXACT_SOURCE_DECLARED_POST_CORE_CONTEXT_BYTES_DATA_ONLY'and value['identity']==index['identity']and value['nonce']==index['nonce']and value['acceptance']is False,'exact private context authority declaration')
 def integer(v):return type(v)is int and 0<=v<=2**63-1
 need(all(type(value[k])is str and re.fullmatch('[a-f0-9]{64}',value[k])for k in('context_path_sha256','root_identity_sha256','files_sha256','public_files_sha256','kernel_files_sha256'))and all(integer(value[k])for k in('files','directories','bytes'))and 0<value['files']+value['directories']<=2048,'bounded context inventory and private root marker');export=value['public_export'];need(type(export)is dict and set(export)=={'bytes','sha256'}and integer(export['bytes'])and export['bytes']<=4*1024**2 and type(export['sha256'])is str and re.fullmatch('[a-f0-9]{64}',export['sha256']),'finite original complete public export pin');owner=value['context_owner'];need(type(owner)is dict and set(owner)=={'bytes','sha256'}and integer(owner['bytes'])and owner['bytes']<=16384 and type(owner['sha256'])is str and re.fullmatch('[a-f0-9]{64}',owner['sha256']),'finite original owner pin');parts=value['components'];need(type(parts)is dict and set(parts)=={'public','inputs','kernel','fixed'}and all(type(r)is dict and set(r)=={'files','bytes'}and all(integer(r[k])for k in('files','bytes'))for r in parts.values()),'four exact declared retained components');need(sum(r['files']for r in parts.values())==value['files']and sum(r['bytes']for r in parts.values())==value['bytes']and parts['public']['files']<=4096 and parts['public']['bytes']<=768*1024**2 and parts['inputs']['files']==272 and parts['inputs']['bytes']<=647070676+3*1024**2 and parts['fixed']['files']==9 and parts['fixed']['bytes']<=16384+6*4*1024**2+2*64*1024**2,'exact component-derived private byte budget and unchanged retention capacities');profile=json.loads(outer_read(Path(__file__).absolute().parent/'profile.json',4*1024**2)[0]);kernel=profile['source_profiles']['kernel_carrier']['files'];need(value['kernel_files_sha256']==hashlib.sha256(outer_encoded(kernel)).hexdigest()and parts['kernel']==dict(files=len(kernel),bytes=sum(r['bytes']for r in kernel.values())),'entire pinned original kernel component');return value

def context_observation_value(raw,index):
 import math,re
 need(len(raw)<=16384,'bounded original observation role')
 def unique(pairs):
  value={}
  for key,item in pairs:need(key not in value,'unique observation fields');value[key]=item
  return value
 value=json.loads(raw,object_pairs_hook=unique,parse_constant=lambda x:need(False,'finite observation JSON'));keys={'schema','status','identity','nonce','source_export','context_role','context_path_sha256','limits','cleanup_end','scalars','evaluations','role_event_sha256','sampled_roles','sample_limit','predicate','observation_error_type','extra_context_walks','extra_context_stats','extra_clock_samples','acceptance'};need(type(value)is dict,'original observation object');version=value.get('schema');need(type(version)is int and version in(1,2)and set(value)==keys|({'context_authority','inventory_validation'}if version==2 else set()),'exact versioned observation schema');authority=context_authority_value(value['context_authority'],index)if version==2 else None;need(version==1 or value['inventory_validation']in('NOT_EVALUATED','REFUSED','PASS_EXACT_CACHED_ENTRY_NAMESPACE'),'finite authority validation outcome');need(type(value['schema'])is int and value['schema']==version and value['status']=='OBSERVED_EXISTING_CURRENT_CONTEXT_RETIREMENT_GUARD_DATA_ONLY'and value['identity']==index['identity']and value['nonce']==index['nonce']and value['source_export']==index['source_export']and value['context_role']=='CURRENT_SELECTED_CONTEXT'and value['acceptance']is False,'Source-bound observation identity')
 def hexpin(x):return type(x)is str and re.fullmatch('[0-9a-f]{64}',x)is not None
 def integer(x,maximum=2**127):return type(x)is int and 0<=x<=maximum
 def finite(x):return type(x)in(int,float)and math.isfinite(x)and x>=0
 errors={'OSError','FileNotFoundError','PermissionError','NotADirectoryError','IsADirectoryError','ValueError','TypeError','AttributeError','OverflowError','UnicodeError','UnicodeEncodeError','MemoryError','RuntimeError','InterruptedError','KeyboardInterrupt','SystemExit'}
 need(hexpin(value['context_path_sha256'])and hexpin(value['role_event_sha256'])and finite(value['cleanup_end'])and value['limits']==dict(entries=2048,bytes=authority['bytes']if authority is not None else 768*1024**2,shared_cleanup_seconds=240)and(authority is None or authority['context_path_sha256']==value['context_path_sha256']),'safe hash/numeric observation fields');need(value['observation_error_type']is None or value['observation_error_type']in errors,'finite observer error class');need(all(type(value[k])is int and value[k]==0 for k in('extra_context_walks','extra_context_stats','extra_clock_samples')),'no additional context probes');need(type(value['sample_limit'])is int and value['sample_limit']==8,'fixed safe sample limit')
 scalars=value['scalars'];need(type(scalars)is dict and set(scalars)=={'entry_count','file_bytes_total','owner_type_alias_all','monotonic'},'only existing guard scalar operands')
 for name,row in scalars.items():
  need(type(row)is dict and row.get('status')in('EVALUATED','NOT_EVALUATED'),'typed scalar evaluation')
  if row['status']=='NOT_EVALUATED':need(set(row)=={'status'},'skipped operand has no invented value')
  else:
   need(set(row)=={'status','value'},'one exact existing scalar value');item=row['value'];need(type(item)is bool if name=='owner_type_alias_all'else finite(item)if name=='monotonic'else integer(item),'finite original scalar type')
 names={'byte_is_file','file_bytes','alias','owner_matches_current','type_is_file','type_is_dir'};evaluations=value['evaluations'];need(type(evaluations)is dict and set(evaluations)==names,'only original owner/type/alias operations')
 for name,row in evaluations.items():
  need(type(row)is dict and set(row)=={'status','calls','true','false'}and row['status']in('EVALUATED','NOT_EVALUATED')and all(integer(row[k],2048)for k in('calls','true','false')),'bounded typed original evaluation counters');need(row['status']==('NOT_EVALUATED'if row['calls']==0 else'EVALUATED')and(row['true']==row['false']==0 if name=='file_bytes'else row['true']+row['false']==row['calls']),'faithful primitive counters')
 samples=value['sampled_roles'];need(type(samples)is list and len(samples)<=8,'bounded hashed role samples');seen=set()
 for sample in samples:
  need(type(sample)is dict and set(sample)=={'role_sha256','values'}and hexpin(sample['role_sha256'])and sample['role_sha256']not in seen,'unique hashed context roles');seen.add(sample['role_sha256']);need(type(sample['values'])is dict and set(sample['values'])<=names,'only original role operations')
  for name,item in sample['values'].items():need(integer(item)if name=='file_bytes'else type(item)is bool,'no raw role names/paths/owners')
 predicate=value['predicate'];need(type(predicate)is dict and(predicate.get('status')=='EVALUATED'and set(predicate)=={'status','value'}and type(predicate['value'])is bool or predicate.get('status')=='OPERAND_RAISED'and set(predicate)=={'status','error_type'}and predicate['error_type']in errors),'exact original guard outcome only');return value

def context_retirement_frame(bodies,index,remaining):
 """Tiny source-asserted operand projection, never an inferred failure cause."""
 name='context-retirement.json'
 if name not in bodies:return dict(status='UNAVAILABLE',acceptance=False),0
 raw=bodies[name];retained=pin(raw)
 try:
  value=context_observation_value(raw,index);scalars={k:v['value']if v['status']=='EVALUATED'else'NOT_EVALUATED'for k,v in value['scalars'].items()};evaluations={k:[v['calls'],v['true'],v['false']]if v['status']=='EVALUATED'else'NOT_EVALUATED'for k,v in value['evaluations'].items()};projection=dict(status='SOURCE_ASSERTED_EXISTING_OPERANDS_DATA_ONLY',retained=retained,context_sha256=value['context_path_sha256'],role_event_sha256=value['role_event_sha256'],cleanup_end=value['cleanup_end'],scalars=scalars,evaluations=evaluations,predicate=value['predicate'],observation_error_type=value['observation_error_type'],acceptance=False);
  if value['schema']==2:projection.update(schema=2,inventory_validation=value['inventory_validation'],limit_bytes=value['context_authority']['bytes'],authority_sha256=hashlib.sha256(outer_encoded(value['context_authority'])).hexdigest())
  size=len(json.dumps(projection,sort_keys=True,separators=(',',':')).encode());need(size<=min(1024,remaining),'held aggregate plus tiny operand projection');return projection,size
 except BaseException as error:return dict(status='REFUSED_OR_UNAVAILABLE',retained=retained,error_type=type(error).__name__,acceptance=False),0

def context_stderr_privacy(raw,source_root):
 """Only fixed guard text and exact public Source traceback locations."""
 import re
 try:
  text=raw.decode('utf-8');need(bool(text)and len(raw)<=512,'bounded full stderr privacy inspection');allowed={'Traceback (most recent call last):','ValueError: bounded exact owned current context retirement'};filenames={str(Path(source_root)/n)for n in('run622.py','case.py','export622.py')}
  for line in text.splitlines():
   if line in allowed or re.fullmatch(r'[ \^~]*',line):continue
   match=re.fullmatch(r'  File "([^"\n]+)", line [1-9][0-9]{0,6}, in (main|_cleanup|cleanup|need|outer_delegate)',line)
   need(match is not None and match.group(1)in filenames,'no arbitrary path/code/message in stderr frame')
  need('ValueError: bounded exact owned current context retirement'in text,'exact known original guard diagnostic');return True
 except BaseException:return False

def outer_frame():
 import base64
 _,_,output,_=outer_intent();bodies,index=outer_collect(output);selected={};remaining=24576
 for name,cap in(('result.json',8192),('child-exception.txt',6144),('outer-exception.txt',6144),('selected-main.json',2048),('phase.exit-code',32)):
  if name not in bodies:continue
  raw=bodies[name];window=raw[:min(cap,remaining)];remaining-=len(window);selected[name]=dict(retained=pin(raw),content_base64=base64.b64encode(window).decode(),window_pin=pin(window),content_bytes=len(window),complete_content=len(window)==len(raw),window='FULL'if len(window)==len(raw)else'PREFIX')
 stderr_privacy=dict(status='UNAVAILABLE',window_cap=512,acceptance=False)
 if 'phase.stderr'in bodies:
  raw_stderr=bodies['phase.stderr'];admitted=context_stderr_privacy(raw_stderr,Path(__file__).absolute().parent);stderr_privacy=dict(status='ADMITTED_FIXED_SOURCE_GUARD_WINDOW'if admitted else'REFUSED_PRIVATE_OR_UNRECOGNIZED_STDERR',retained=pin(raw_stderr),stream_complete=index['roles']['phase.stderr']['complete'],source_root=str(Path(__file__).absolute().parent),window_cap=512,acceptance=False)
  if admitted:
   window=raw_stderr[:min(512,remaining)];remaining-=len(window);selected['phase.stderr']=dict(retained=pin(raw_stderr),content_base64=base64.b64encode(window).decode(),window_pin=pin(window),content_bytes=len(window),complete_content=len(window)==len(raw_stderr),window='FULL'if len(window)==len(raw_stderr)else'PREFIX')
 context_projection,context_bytes=context_retirement_frame(bodies,index,remaining);remaining-=context_bytes
 projection=None
 if 'result.json'in bodies:
  try:
   value=json.loads(bodies['result.json']);need(type(value)is dict,'original result object projection only');fields={};budget=4096
   for name in('status','error_type','error','producer_cleanup','cleanup_error','caller_private_cleanup','private_cleanup_error','expanded_cache_cleanup','expanded_cleanup_error'):
    if name not in value or type(value[name])not in(str,int,bool,type(None)):continue
    original=json.dumps(value[name],sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode();window=original[:min(1536,budget)];budget-=len(window);fields[name]=dict(content_base64=base64.b64encode(window).decode(),window_pin=pin(window),original_json_bytes=len(original),complete_value=len(window)==len(original))
   projection=dict(status='SOURCE_ASSERTED_FIXED_ORIGINAL_SCALAR_FIELDS_DATA_ONLY',result=pin(bodies['result.json']),fields=fields,acceptance=False)
  except BaseException:pass
 frame=dict(context_retirement_projection=context_projection,phase_stderr_privacy=stderr_privacy,original_result_projection=projection,schema=1,status='SOURCE_BOUND_ORIGINAL_OUTER_CALLER_JOBLOG_DATA_ONLY',identity=index['identity'],nonce=index['nonce'],source_export=index['source_export'],roles=index['roles'],selected_content=selected,exception_cause='NOT_INFERRED',acceptance=False);raw=b'CORE622_OUTER_CALLER_FRAME_V1 '+json.dumps(frame,sort_keys=True,separators=(',',':'),allow_nan=False).encode()+b'\n';need(len(raw)<=65536,'small fixed diagnostic joblog frame');return raw

def transport(core,public,target):
 path=core/'scripts/ci/core-native-lifecycle/owner.py';sys.path.insert(0,str(path.parent));spec=importlib.util.spec_from_file_location('_core622_whole_original_transport',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module.transport(types.SimpleNamespace(public=public,output=target))

def main():
 if sys.argv[1:]==['--outer-caller-begin']:outer_begin();return 0
 if len(sys.argv)==3 and sys.argv[1]=='--outer-caller-pump':return outer_pump(sys.argv[2])
 if sys.argv[1:]==['--outer-caller-frame']:print(outer_frame().decode(),end='');return 0
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--public',type=Path,required=True);p.add_argument('--transport-only',action='store_true');p.add_argument('--core-source',type=Path);p.add_argument('--transport',type=Path);a=p.parse_args()
 if a.transport_only:need(a.core_source is not None and a.transport is not None,'explicit original transport source/output');return transport(a.core_source,a.public,a.transport)
 return copy(a.output,a.public,retained_transport=True)
if __name__=='__main__':raise SystemExit(main())
