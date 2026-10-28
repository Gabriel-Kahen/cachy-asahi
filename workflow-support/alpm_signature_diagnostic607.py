# SPDX-License-Identifier: MIT
"""One selected load's finite ALPM log-template DATA; never consume varargs."""
import ctypes as C
import os,time

TARGET=dict(index=59,name='cachy-asahi-topmem',version='0.1.0-1',
 archive='packages/cachy-asahi-topmem-0.1.0-1-any.pkg.tar.xz',size=8092,
 sha256='583ffacd614bd741722486d5fbc64b79bb283d62c87974063fc1484dfcbe199b',
 signature='packages/cachy-asahi-topmem-0.1.0-1-any.pkg.tar.xz.sig',signature_size=119,
 signature_sha256='b90426234f869e1984e62083ceac30d8668f71e69c37862c49dbaa7d6b1f4dfd')
MAX_CALLBACKS=128;MAX_EVENTS=64;MAX_FORMAT=256
# Only exact pinned signing.c formats become these public, fixed labels.
FORMATS={
 b'missing optional signature\n':'MISSING_OPTIONAL_SIGNATURE',
 b'missing required signature\n':'MISSING_REQUIRED_SIGNATURE',
 b'signature check failed\n':'SIGNATURE_CHECK_FAILED',
 b'signature is valid\n':'SIGNATURE_IS_VALID',
 b'signature is fully trusted\n':'SIGNATURE_IS_FULLY_TRUSTED',
 b'signature is marginal trust\n':'SIGNATURE_IS_MARGINAL_TRUST',
 b'signature is unknown trust\n':'SIGNATURE_IS_UNKNOWN_TRUST',
 b'signature should never be trusted\n':'SIGNATURE_SHOULD_NEVER_BE_TRUSTED',
 b'signature is not valid\n':'SIGNATURE_IS_NOT_VALID',
 b'no signatures returned\n':'NO_SIGNATURES_RETURNED',
 b'key lookup failed, unknown key\n':'KEY_LOOKUP_FAILED_UNKNOWN_KEY',
 b'signature timestamp is greater than system time.\n':'SIGNATURE_TIMESTAMP_GREATER_THAN_SYSTEM_TIME',
 b'summary: %s\n':'SUMMARY_FORMAT_OBSERVED_VALUE_UNKNOWN',
 b'status: %s\n':'STATUS_FORMAT_OBSERVED_VALUE_UNKNOWN',
 b'validity: %s; reason: %s\n':'VALIDITY_REASON_FORMAT_OBSERVED_VALUES_UNKNOWN',
 b'GPGME error: %s\n':'GPGME_ERROR_FORMAT_OBSERVED_VALUE_UNKNOWN',
 b'timestamp: %lu\n':'SIGNATURE_TIMESTAMP_FORMAT_OBSERVED_VALUE_UNKNOWN',
 b'exp_timestamp: %lu\n':'SIGNATURE_EXPIRY_FORMAT_OBSERVED_VALUE_UNKNOWN',
 b'%d signatures returned\n':'SIGNATURE_COUNT_FORMAT_OBSERVED_VALUE_UNKNOWN',
 b'checking signature for %s\n':'CHECKING_SIGNATURE_FORMAT_OBSERVED_PATH_UNKNOWN',
 b'sig path %s could not be opened\n':'SIGNATURE_PATH_OPEN_FAILED_PATH_UNKNOWN',
}
# The selected aarch64 GNU va_list argument is ABI-lowered indirectly. Its
# pointer is deliberately ignored: no va_list reads, formatting or result scan.
LOG_CALLBACK=C.CFUNCTYPE(None,C.c_void_p,C.c_int,C.c_void_p,C.c_void_p)

def need(ok,why):
 if not ok:raise ValueError(why)
def scalar(value):
 t=type(value);r=dict(type_module=t.__module__,type_name=t.__qualname__)
 if value is None or t in(int,bool):r['value']=value
 else:r['value_status']='UNOBSERVED_NONSCALAR'
 return r
def cstring(pointer,cap):
 """Bounded read of a library-owned NUL string; never expose pointer values."""
 if isinstance(pointer,C.c_void_p):pointer=pointer.value
 need(type(pointer)is int and pointer>0,'nonNULL original library string')
 value=bytearray()
 for i in range(cap):
  b=C.string_at(pointer+i,1)
  if b==b'\0':return bytes(value)
  value+=b
 raise ValueError('bounded original library string')
def epoch():
 value=time.time()
 return int(value)if 0<=value<=253402300799 else None
def role(pointer,path,directory=False):
 wanted=os.fsencode(path);actual=cstring(pointer,min(4096,len(wanted)+2))
 return actual==wanted or(directory and actual==wanted.rstrip(b'/')+b'/')

class Observer:
 def __init__(self,instance,ctor,area,package_rows,deadline):
  self.instance,self.ctor,self.area,self.rows,self.deadline=instance,ctor,area,package_rows,deadline
  self.active=False;self.installed=False;self.callback=None;self.handle=None;self.previous_ctx=None
  self.getters={};self.functions={};self.events=[];self.calls=0;self.unknown=0;self.refused=0;self.dropped=0
  self.closed=False;self.restore_status='NOT_INSTALLED';self.current=self.empty('TARGET_NOT_SELECTED')
 def empty(self,status):
  return dict(schema_version=1,status=status,target=dict(TARGET),acceptance=False,cleanup_authority=False,
   raw_format_values='NOT_EXPORTED',varargs='NOT_READ_OR_FORMATTED',gpgme_result_values='UNKNOWN',
   internal_signature_source='UNKNOWN',extra_signature_checks=0,trust_or_siglevel_changes=False,
   callback_restore='DEFERRED_UNTIL_ORIGINAL_ENGINE_FINALLY_TO_PRESERVE_ERRNO')
 def bind(self,name,restype,args):
  f=getattr(self.instance.lib,name);f.restype=restype;f.argtypes=args;self.functions[name]=f;return f
 def selected(self,index,args):
  if index!=TARGET['index']or type(index)is not int or len(self.rows)!=607:return False
  row=self.rows[index]
  return all(row.get(k)==v for k,v in TARGET.items()if k!='index')and len(args)==5 and args[0]==self.instance.handle and type(args[1])is bytes and args[1].endswith(b'/'+TARGET['archive'].encode())and type(args[2])is type(args[3])is int and args[2]==args[3]==1
 def before(self):
  need(os.uname().machine=='aarch64'and C.sizeof(C.c_void_p)==8,'selected native aarch64 GNU callback ABI')
  need(self.instance.alpm_version()==b'16.0.1','held original libalpm ABI')
  p=C.c_void_p;self.handle=self.instance.handle;need(bool(self.handle),'live original handle')
  get=lambda n:self.bind('alpm_option_get_'+n,p,[p])(self.handle)
  prior=get('logcb');self.previous_ctx=get('logcb_ctx')
  self.current['prior_callback']='NONNULL_REFUSED'if prior else'NULL_OBSERVED'
  root,gpgdir,log,architecture=self.ctor
  self.getters=dict(status='ACTUAL_OPTION_GETTERS_BEFORE_SELECTED_LOAD',
   root_role_matches=role(get('root'),root,True),
   gpgdir_role_matches=role(get('gpgdir'),gpgdir,True),
   logfile_role_matches=role(get('logfile'),log),
   local_file_siglevel=scalar(self.bind('alpm_option_get_local_file_siglevel',C.c_int,[p])(self.handle)),
   private_values='NOT_EXPORTED',timing='BEFORE_ORIGINAL_LOAD_ONLY')
  self.current['actual_options']=self.getters
  need(not prior,'existing callback preserved without replacement')
  self.setter=self.bind('alpm_option_set_logcb',C.c_int,[p,p,p])
  self.callback=LOG_CALLBACK(self.observe)
  code=self.setter(self.handle,C.cast(self.callback,p),None)
  self.current['install_return']=scalar(code)
  need(type(code)is int and code==0,'original callback install returned zero')
  self.installed=True;self.restore_status='DEFERRED';self.active=True
 def begin(self,index,args):
  self.active=False;self.current=self.empty('TARGET_NOT_SELECTED')
  if not self.selected(index,args):return
  self.current.update(status='SELECTED_LOAD_CALLBACK_SETUP',package_index=index,load_sequence_index=index,
   started_epoch_seconds=epoch(),callback_abi='AARCH64_GNU_VA_LIST_INDIRECT_POINTER_NOT_READ')
  try:
   need(time.monotonic()<=self.deadline,'held engine deadline before observer')
   self.before();self.current['status']='SELECTED_LOAD_CALLBACK_ARMED'
  except BaseException as error:
   self.active=False;self.current.update(status='REFUSED_SELECTED_LOAD_CALLBACK_SETUP',error_type=type(error).__name__)
 def observe(self,ctx,level,fmt,args):
  if not self.active:return
  if self.calls>=MAX_CALLBACKS:self.dropped=min(self.dropped+1,MAX_CALLBACKS);return
  self.calls+=1
  try:
   need(time.monotonic()<=self.deadline,'held engine deadline during callback')
   label=FORMATS.get(cstring(fmt,MAX_FORMAT))
   if label is None:self.unknown+=1;return
   if len(self.events)>=MAX_EVENTS:self.dropped=min(self.dropped+1,MAX_CALLBACKS);return
   self.events.append(dict(label=label,level=level if type(level)is int and level in(1,2,4,8)else'OTHER'))
  except BaseException:self.refused+=1
 def after(self):
  # PURE PYTHON: no ALPM calls here, including callback restoration. Preserve
  # the first errno for the unchanged original .ok()/strerror translation.
  self.active=False
  if self.current['status']=='TARGET_NOT_SELECTED':return dict(self.current)
  self.current.update(finished_epoch_seconds=epoch(),events=[dict(row)for row in self.events],
   callback_count=self.calls,unknown_format_count=self.unknown,refused_format_count=self.refused,
   dropped_callback_count=self.dropped,limits=dict(callbacks=MAX_CALLBACKS,events=MAX_EVENTS,format_bytes=MAX_FORMAT))
  if self.current['status']=='SELECTED_LOAD_CALLBACK_ARMED':self.current['status']='ORIGINAL_SELECTED_LOAD_TEMPLATE_DATA_ONLY'
  return dict(self.current)
 def close(self):
  self.active=False
  if self.closed:return
  self.closed=True
  if not self.installed:return
  live=self.instance.handle
  if not live:self.restore_status='ORIGINAL_HANDLE_ALREADY_RELEASED';self.installed=False;return
  if live!=self.handle:self.restore_status='REFUSED_HANDLE_CHANGED_NO_NUMERIC_REUSE';return
  try:
   code=self.setter(live,None,self.previous_ctx)
   self.restore_status='RESTORED_ORIGINAL_NULL_CALLBACK_AND_CONTEXT'if type(code)is int and code==0 else'RESTORE_RETURN_REFUSED'
   if type(code)is int and code==0:self.installed=False
  except BaseException as error:self.restore_status='RESTORE_EXCEPTION_'+type(error).__name__
