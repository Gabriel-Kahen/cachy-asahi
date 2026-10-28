#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Original engine/result DATA before the unchanged signed607 install guard."""
import hashlib,json,math,os,re,stat,sys,types
from pathlib import Path
sys.dont_write_bytecode=True
PROVIDER={'bytes':33239,'sha256':'c5bb6332b8a874380f75df683e2746cfabf07a20a1d897af93065e0b9241fb04'}
RUNTIME={'bytes':11345,'sha256':'8a7cd5e73cf383b2d81ad577b8513c6fd7d49f9fd2572961c73ae9d289cab821'}
RESULT_CAP=256*1024;STREAM_CAP=64*1024;TOTAL_CAP=2*1024**2;MAX_COMMANDS=640
FORBIDDEN=(b'-----BEGIN PGP PRIVATE KEY',b'-----BEGIN PGP PUBLIC KEY',b'-----BEGIN PRIVATE KEY',b'-----BEGIN RSA PRIVATE KEY',b'-----BEGIN OPENSSH PRIVATE KEY',b'(private-key',b'Authorization: Bearer ',b'ghp_',b'github_pat_')
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def identity(s):return {n:getattr(s,'st_'+n)for n in('dev','ino','mode','uid','gid','nlink','size','mtime_ns','ctime_ns')}
def snapshot(path,cap,owned=True,privacy=True):
 path=Path(path);fd=None
 try:
  need(path.is_absolute() and path==path.resolve() and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary original ancestry')
  fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC);s=os.fstat(fd);observed=identity(s)
  if not stat.S_ISREG(s.st_mode)or s.st_nlink!=1 or(owned and s.st_uid!=os.geteuid()):return dict(status='REFUSED_TYPE_LINK_OR_OWNER',identity=observed),None
  if not 0<=s.st_size<=cap:return dict(status='REFUSED_OVERSIZE',identity=observed,cap=cap),None
  raw=bytearray()
  while block:=os.read(fd,65536):raw.extend(block);need(len(raw)<=s.st_size,'original stream growth')
  need(len(raw)==s.st_size and observed==identity(os.fstat(fd))==identity(path.lstat()),'stable original FD/path');raw=bytes(raw)
  if privacy and any(marker in raw for marker in FORBIDDEN):return dict(status='REFUSED_PRIVACY_MARKER',identity=observed),None
  return dict(status='COMPLETE_ORIGINAL_DATA',identity=observed,**pin(raw)),raw
 except FileNotFoundError:return dict(status='MISSING'),None
 except BaseException as error:return dict(status='REFUSED_READ',error_type=type(error).__name__),None
 finally:
  if fd is not None:os.close(fd)
def typed(value):
 t=type(value);r=dict(type_module=t.__module__,type_name=t.__qualname__)
 if value is None or t in(bool,int):r['value']=value
 elif t is float and math.isfinite(value):r['value']=value
 elif t is str and len(value)<=1024 and not any(m in value.encode('utf-8','replace')for m in FORBIDDEN):r['value']=value
 else:r['value_status']='NOT_SERIALIZED_UNSUPPORTED_OR_PRIVATE'
 return r
def error_data(error):return None if error is None else dict(type_module=type(error).__module__,type_name=type(error).__qualname__,message=typed(str(error)))
def conjuncts(returned,value,result):
 r={k:dict(status='NOT_OBSERVED')for k in('code_equals_zero','result_status','result_committed','result_package_count')}
 if returned and type(value)in(int,bool,float):r['code_equals_zero']=dict(status='OBSERVED',value=value==0)
 if type(result)is dict:
  for field,name,want in(('status','result_status','PROVISIONAL_FULL_COMPOSITION_INSTALLER'),('committed','result_committed',True),('package_count','result_package_count',607)):
   if field not in result:r[name]=dict(status='MISSING_KEY');continue
   v=result[field];r[name]=dict(status='OBSERVED',actual=typed(v),value=(v is True)if field=='committed'else v==want)
 return r
def command_role(argv,area):
 prefix=['/usr/bin/gpg','--batch','--no-options','--no-autostart','--homedir',str(area.parent/'gpg'),'--no-auto-key-retrieve']
 if type(argv)is not list or argv[:len(prefix)]!=prefix:return 'UNSELECTED'
 tail=argv[len(prefix):]
 if tail==['--with-colons','--list-secret-keys']:return 'SECRET_KEY_PRESENCE_CHECK'
 if len(tail)==2 and tail[0]=='--import':return 'PUBLIC_KEYRING_IMPORT'
 if len(tail)==2 and tail[0]=='--import-ownertrust':return 'OWNERTRUST_IMPORT'
 if len(tail)==5 and tail[:3]==['--status-fd','1','--verify']:return 'PACKAGE_SIGNATURE_VERIFY'
 return 'UNSELECTED'
class Capture:
 def __init__(self,P,area,who):self.P,self.area,self.who=P,area,who;self.index=0;self.used=0;self.refused=0
 def save(self,name,value):self.P.save(self.P.OUT/name,value)
 def row(self,argv,row=None,error=None):
  i=self.index;self.index+=1
  if i>=MAX_COMMANDS:self.refused+=1;return
  role=command_role(argv,self.area);r=dict(schema_version=1,index=i,role=role,identity=self.who,stream_semantics='ORIGINAL_STDOUT_COMBINED_STDERR_STDOUT_REDIRECT',runtime=RUNTIME,returned=row is not None,error=error_data(error),acceptance=False)
  if row is not None:
   r['returncode']=typed(row.returncode);r['row_type']=dict(module=type(row).__module__,name=type(row).__qualname__);r['stderr']=typed(row.stderr);raw=row.stdout
   if type(raw)is not bytes:r['stdout']=dict(status='REFUSED_NONBYTES',type=typed(raw))
   elif role in('SECRET_KEY_PRESENCE_CHECK','UNSELECTED'):r['stdout']=dict(status='REFUSED_PRIVACY_ROLE',bytes=len(raw))
   elif len(raw)>STREAM_CAP:r['stdout']=dict(status='REFUSED_OVERSIZE',bytes=len(raw),cap=STREAM_CAP)
   elif any(marker in raw for marker in FORBIDDEN):r['stdout']=dict(status='REFUSED_PRIVACY_MARKER',bytes=len(raw))
   elif self.used+len(raw)>TOTAL_CAP:r['stdout']=dict(status='REFUSED_TOTAL_CAP',bytes=len(raw),cap=TOTAL_CAP)
   else:
    name='engine-command-%03d.stdout.bin'%i;self.P.write(self.P.OUT/name,raw);self.used+=len(raw);r['stdout']=dict(status='COMPLETE_ORIGINAL_DATA',exported=name,**pin(raw))
  else:r['stdout']=dict(status='NOT_RETURNED');r['stderr']=dict(status='NOT_RETURNED')
  self.save('engine-command-%03d.json'%i,r)
 def original_run(self,runner,argv,kwargs):
  try:row=runner.run(argv,**kwargs)
  except BaseException as error:
   try:self.row(argv,error=error)
   except BaseException:self.refused+=1
   raise
  try:self.row(argv,row=row)
  except BaseException:self.refused+=1
  return row
 def finish(self,returned,value,error):
  r=dict(schema_version=1,status='ORIGINAL_NATIVE607_ENGINE_DATA_ONLY',purpose='BEFORE_UNCHANGED_INSTALL_GUARD_AND_CLEANUP',identity=self.who,returned=returned,return_value=typed(value)if returned else None,error=error_data(error),files={},commands=self.index,command_capture_refusals=self.refused,Root_acceptance=None,acceptance=False,cleanup_authority=False);parsed=None
  for role,name,cap in(('result','result.json',RESULT_CAP),('alpm','alpm.log',128*1024)):
   observation,raw=snapshot(self.area/name,cap)
   if raw is not None:
    if self.used+len(raw)>TOTAL_CAP:observation=dict(status='REFUSED_TOTAL_CAP',identity=observation['identity'],cap=TOTAL_CAP)
    else:
     name='engine-original-'+role+'.bin';self.P.write(self.P.OUT/name,raw);self.used+=len(raw);observation['exported']=name
     if role=='result':
      try:parsed=self.P.decode(raw);observation['JSON_status']='PARSED';observation['JSON_type']=type(parsed).__name__
      except BaseException as e:observation['JSON_status']='REFUSED';observation['JSON_error_type']=type(e).__name__
   r['files'][role]=observation
  r['conjuncts']=conjuncts(returned,value,parsed);r['captured_bytes']=self.used;self.save('native607-engine-original-diagnostic.json',r)
def engine_call(P,original,fd,sha,report_fd,area,who,base):
 capture=Capture(P,area,who);ordinary_runtime=base.runtime;returned=False;value=None;error=None
 def runtime():
  actual=ordinary_runtime();facade=types.SimpleNamespace(**vars(actual));original_runner=actual.Runner
  class Runner:
   def __init__(self,*args,**kwargs):self.original=original_runner(*args,**kwargs)
   def __getattr__(self,n):return getattr(self.original,n)
   def run(self,argv,**kwargs):return capture.original_run(self.original,argv,kwargs)
  facade.Runner=Runner;return facade
 base.runtime=runtime
 try:value=original.engine(fd,sha,report_fd);returned=True;return value
 except BaseException as original_error:error=original_error;raise
 finally:
  base.runtime=ordinary_runtime
  try:capture.finish(returned,value,error)
  except BaseException as e:
   try:os.write(2,('NATIVE607_DIAGNOSTIC_REFUSED '+type(e).__name__+'\n').encode())
   except BaseException:pass
def configure(P):
 raw=P.read(Path(P.__file__));need(pin(raw)==PROVIDER,'exact held provider before diagnostic seam');before=P._body(raw.decode(),'install_actor')
 old="code=original.engine(fd,pin(raw)['sha256'],-1)";new="code=diagnostic_engine_call(original,fd,pin(raw)['sha256'],-1,area,who,base)"
 need(before.count(old)==1 and new not in before,'one original engine call seam');after=before.replace(old,new,1);need(after.replace(new,old,1)==before,'whole install_actor inverse')
 guard="result=decode(read(area/'result.json'));need(code==0 and result['status']=='PROVISIONAL_FULL_COMPOSITION_INSTALLER'and result['committed']is True and result['package_count']==607,'actual complete native signed607 installer')"
 need(before.count(guard)==after.count(guard)==1,'required install predicate byte held');P.diagnostic_engine_call=lambda *a:engine_call(P,*a)
 exec(compile(after,'<held-install-actor-original-diagnostic-seam>','exec'),vars(P))
 return dict(before=pin(before.encode()),after=pin(after.encode()),whole_inverse=True,predicate=pin(guard.encode()),provider=PROVIDER,engine_six_native_seams='UNCHANGED')
def main():
 need(sys.argv[1:]==['--install'],'only original install actor phase');expected=os.environ.get('FRESH_INSTALL_DIAGNOSTIC_SHA256','');need(re.fullmatch('[0-9a-f]{64}',expected)is not None,'independent diagnostic entrypoint pin')
 observation,raw=snapshot(Path(__file__).resolve(),64*1024,owned=False,privacy=False);need(raw is not None and pin(raw)['sha256']==expected,'exact diagnostic code')
 path=Path('/fresh-operation/provider607.py');observation,raw=snapshot(path,PROVIDER['bytes'],owned=False,privacy=False);need(raw is not None and pin(raw)==PROVIDER,'held provider source snapshot')
 P=types.ModuleType('_diagnostic_held_provider607');P.__file__=str(path);sys.modules[P.__name__]=P;exec(compile(raw,str(path),'exec'),vars(P));proof=configure(P);P.actor_guard('install')
 need(Path(__file__).is_mount(),'explicit diagnostic readonly file mount');fd=os.open(Path(__file__),os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:need(os.fstatvfs(fd).f_flag&os.ST_RDONLY,'diagnostic code mount readonly')
 finally:os.close(fd)
 P.save(P.OUT/'native607-install-actor-diagnostic-derivation.json',proof);return P.main()
if __name__=='__main__':raise SystemExit(main())
