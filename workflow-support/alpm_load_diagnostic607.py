# SPDX-License-Identifier: MIT
"""Fixed signed-load failure DATA; original ALPM objects, calls and gates held."""
import hashlib,os,re,stat,time
from pathlib import Path
MAX_ARCHIVE=256*1024**2;MAX_SIGNATURE=1024**2;MAX_REPORT=32768
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def need(ok,why):
 if not ok:raise ValueError(why)
def scalar(value):
 t=type(value);r=dict(type_module=t.__module__,type_name=t.__qualname__)
 if value is None or t in(int,bool):r['value']=value
 else:r['value_status']='UNOBSERVED_NONSCALAR'
 return r
def hash_operand(path,expected,cap,deadline):
 """Hash only the selected failing operand, without retaining its body."""
 fd=None
 try:
  need(path==path.resolve()and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary selected operand')
  fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC);before=os.fstat(fd);state=lambda s:tuple(getattr(s,n)for n in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<=before.st_size<=cap,'held operand size/type/link bound');digest=hashlib.sha256();size=0
  while True:
   need(time.monotonic()<=deadline,'held engine deadline');block=os.read(fd,65536)
   if not block:break
   size+=len(block);need(size<=before.st_size,'selected operand grew');digest.update(block)
  need(size==before.st_size and state(before)==state(os.fstat(fd))==state(path.lstat()),'stable selected operand FD/path');actual=dict(bytes=size,sha256=digest.hexdigest())
  return dict(status='COMPLETE_ORIGINAL_HASH_NO_BODY',expected=expected,actual=actual,matches=actual==expected,identity={n:getattr(before,'st_'+n)for n in('dev','ino','mode','uid','gid','nlink','size','mtime_ns','ctime_ns')})
 except FileNotFoundError:return dict(status='MISSING',expected=expected)
 except BaseException as e:return dict(status='REFUSED_HASH',expected=expected,error_type=type(e).__name__)
 finally:
  if fd is not None:os.close(fd)
class Scope:
 def __init__(self,P,original,area,who,base,capture):
  self.P,self.original,self.area,self.who,self.base,self.capture=P,original,area,who,base,capture;self.calls=0;self.written=False;self.seen={};self.instances=[];self.modules=[]
  self.value=original.native_inputs()[2];self.rows=self.value['packages'];need(len(self.rows)==607 and len({r['name']for r in self.rows})==607,'exact selected607 package map')
  self.raw_manifest=P.read(P.BUNDLE/'manifest.json',1024**2);need(P.decode(self.raw_manifest)==self.value,'original current manifest/map equality')
  for row in self.rows:
   for field in('archive','signature'):
    name=row[field];need(type(name)is str and len(name.encode())<=1024 and not name.startswith('/')and '\\'not in name and all(x not in('','.','..')for x in name.split('/')),'contained selected operand role')
   need(row['signature']==row['archive']+'.sig'and type(row['size'])is int and 0<row['size']<=MAX_ARCHIVE and type(row['signature_size'])is int and 0<row['signature_size']<=MAX_SIGNATURE,'held selected pair sizes and signature relation')
   need(all(type(row[k])is str and re.fullmatch('[0-9a-f]{64}',row[k])for k in('sha256','signature_sha256'))and type(row['name'])is str and re.fullmatch('[a-zA-Z0-9@+_.-]{1,128}',row['name'])and type(row['version'])is str and len(row['version'])<=128 and type(row['signer'])is str and re.fullmatch('[0-9A-Fa-f]{40,64}',row['signer']),'bounded public package metadata')
  self.map_pin=pin(P.encoded(self.rows));self.by_path={os.fsencode(P.BUNDLE/r['archive']):i for i,r in enumerate(self.rows)};need(len(self.by_path)==607,'unique selected archive roles')
 def observe(self,argv,row,error,index):
  if error is not None or row is None:return
  prefix=['/usr/bin/gpg','--batch','--no-options','--no-autostart','--homedir',str(self.area.parent/'gpg'),'--no-auto-key-retrieve','--status-fd','1','--verify']
  if type(argv)is not list or argv[:len(prefix)]!=prefix or len(argv)!=len(prefix)+2:return
  encoded=os.fsencode(argv[-1]);i=self.by_path.get(encoded)
  if i is None:return
  package=self.rows[i];self.seen[i]=dict(command_index=index,expected_command_index=len(self.value['keyrings'])+2+i,archive_role_matches=argv[-1]==str(self.P.BUNDLE/package['archive']),signature_role_matches=argv[-2]==str(self.P.BUNDLE/package['signature']),standalone_home_role_matches=argv[5]==str(self.area.parent/'gpg'),returncode=scalar(row.returncode),error=None)
 def emit(self,record):
  if self.written:return
  raw=self.P.encoded(record);need(len(raw)<=MAX_REPORT,'bounded signed-load diagnostic metadata');self.P.write(self.P.OUT/'native607-alpm-load-diagnostic.json',raw);self.written=True
 def failure(self,instance,args,result,error,errno,ctor,index):
  r=dict(schema_version=1,status='ORIGINAL_ALPM_SIGNED_LOAD_FAILURE_DATA_ONLY',identity=self.who,manifest=pin(self.raw_manifest),package_map=self.map_pin,load_sequence_index=index,load_return=scalar(result)if error is None else None,load_error=None if error is None else dict(type_module=type(error).__module__,type_name=type(error).__qualname__,message='NOT_EXPORTED_PRIVACY'),errno=errno,output_pointer_inspected=False,acceptance=False,cleanup_authority=False,Root_acceptance=None,engine_six_seams='UNCHANGED',provider_install_guard='UNCHANGED')
  need(len(args)==5,'exact signed load argument count');handle,path,full,siglevel,pointer=args;i=self.by_path.get(path)if type(path)is bytes else None
  if i is None:r.update(status='REFUSED_ALPM_LOAD_ROLE_DATA',reason='UNSELECTED_ARCHIVE_OPERAND');self.emit(r);return
  package=self.rows[i];need(package['signature']==package['archive']+'.sig','detached signature role')
  r['package_index']=i;r['package']={k:package[k]for k in('name','version','archive','size','sha256','signature','signature_size','signature_sha256','signer')};r['source_order_matches']=i==index;r['call']=dict(same_handle=handle==instance.handle,full=scalar(full),siglevel=scalar(siglevel))
  root,gpgdir,log,architecture=ctor;r['context']=dict(architecture=architecture if architecture in('aarch64','x86_64')else'UNOBSERVED_OTHER',install_root_role_matches=root==self.area/'root',gpgdir_role_matches=gpgdir==self.area.parent/'gpg',log_role_matches=log==self.area/'alpm.log',configured_local_file_siglevel=1,configured_level_authority='UNCHANGED_PINNED_CONSTRUCTOR_SOURCE',actual_option_getters='UNOBSERVED_NO_BOUND_GETTERS',internal_signature_source='UNOBSERVED_API_HAS_NO_SIGNATURE_PATH_ARGUMENT',sidecar_observation='EXPECTED_MANIFEST_OPERAND_ONLY',keyring_count=len(self.value['keyrings']),keyring_map=pin(self.P.encoded(self.value['keyrings'])),private_keyring_values='NOT_READ_OR_EXPORTED')
  deadline=self.base.TASK_DEADLINE;r['archive']=hash_operand(self.P.BUNDLE/package['archive'],dict(bytes=package['size'],sha256=package['sha256']),MAX_ARCHIVE,deadline);r['signature']=hash_operand(self.P.BUNDLE/package['signature'],dict(bytes=package['signature_size'],sha256=package['signature_sha256']),MAX_SIGNATURE,deadline)
  prior=self.seen.get(i)
  if prior is None:r['standalone_gpg']=dict(status='NOT_OBSERVED')
  else:
   r['standalone_gpg']=dict(prior,status='SOURCE_LOOP_ORDER_ROLE_JOIN');name='engine-command-%03d.json'%prior['command_index']
   try:
    raw=self.P.read(self.P.OUT/name,16384);v=self.P.decode(raw);r['standalone_gpg']['record']=pin(raw);r['standalone_gpg']['record_role_matches']=v['identity']==self.who and v['role']=='PACKAGE_SIGNATURE_VERIFY'and v['returncode']==prior['returncode']and v['error']is None
   except BaseException as e:r['standalone_gpg']['record_status']='MISSING_OR_REFUSED';r['standalone_gpg']['record_error_type']=type(e).__name__
  self.emit(r)
 def factory(self,ordinary,*args,**kwargs):
  instance=ordinary(*args,**kwargs);original_load=instance.alpm_pkg_load;self.instances.append((instance,original_load));ctor=tuple(args[:4])
  def load(*call_args):
   index=self.calls;self.calls+=1
   try:result=original_load(*call_args)
   except BaseException as error:
    try:self.failure(instance,call_args,None,error,dict(status='NOT_RETURNED'),ctor,index)
    except BaseException as capture_error:self.refused(capture_error)
    raise
   if type(result)is int and result!=0:
    # This is the first ALPM call after failure; no getter/translation precedes it.
    try:errno=dict(status='OBSERVED_IMMEDIATELY',numeric=scalar(instance.alpm_errno(call_args[0])))
    except BaseException as e:errno=dict(status='REFUSED_ERRNO',error_type=type(e).__name__)
    try:self.failure(instance,call_args,result,None,errno,ctor,index)
    except BaseException as capture_error:self.refused(capture_error)
   return result
  instance.alpm_pkg_load=load;return instance
 def refused(self,error):
  try:self.emit(dict(schema_version=1,status='REFUSED_ALPM_DIAGNOSTIC_DATA',identity=self.who,error_type=type(error).__name__,acceptance=False,cleanup_authority=False))
  except BaseException:pass
 def bind_modules(self,ordinary,*args,**kwargs):
  result=ordinary(*args,**kwargs);roots=result[0]
  if not any(m is roots for m,_ in self.modules):
   constructor=roots.Alpm;self.modules.append((roots,constructor));roots.Alpm=lambda *a,**k:self.factory(constructor,*a,**k)
  return result
 def restore(self):
  for instance,load in reversed(self.instances):instance.alpm_pkg_load=load
  for roots,constructor in reversed(self.modules):roots.Alpm=constructor
def call(P,original,fd,sha,report_fd,area,who,base,capture):
 ordinary_modules=original.source_modules;ordinary_row=capture.row;scope=None
 try:scope=Scope(P,original,area,who,base,capture)
 except BaseException as error:
  try:P.save(P.OUT/'native607-alpm-load-diagnostic.json',dict(schema_version=1,status='REFUSED_ALPM_DIAGNOSTIC_SETUP',identity=who,error_type=type(error).__name__,acceptance=False,cleanup_authority=False))
  except BaseException:pass
 if scope is None:return original.engine(fd,sha,report_fd)
 def row(argv,row=None,error=None):
  index=capture.index
  try:return ordinary_row(argv,row=row,error=error)
  finally:
   try:scope.observe(argv,row,error,index)
   except BaseException:pass
 original.source_modules=lambda *a,**k:scope.bind_modules(ordinary_modules,*a,**k);capture.row=row
 try:return original.engine(fd,sha,report_fd)
 finally:original.source_modules=ordinary_modules;capture.row=ordinary_row;scope.restore()
