"""Explicit immutable-source API; original mutable copier/lifetime code is held."""
from contextlib import contextmanager
from pathlib import Path
import os,types
import inputs,mount_proxy
P,C,_,_=inputs.broker()

def clone(function,**replacements):
 value=types.FunctionType(function.__code__,dict(function.__globals__,**replacements),function.__name__,function.__defaults__,function.__closure__);value.__kwdefaults__=function.__kwdefaults__;return value

DESCRIPTOR_QUERY_PROFILE={'name': 'GNU_IMMUTABLE_PRIVATE_DESCRIPTOR_QUERY_V1', 'query': 'SOURCE_HELD_STATX_MNT_ID_OR_ORIGINAL_FDINFO', 'observations': 'FULL_FRESH_ORIGINAL', 'mount_identity_cache': False, 'native_timeout_fit': 'NOT_ESTABLISHED'}
def descriptor_api(api):
 # Whole original source code objects; only private descriptor-query globals differ.
 original_roots=api['roots'];aux_copy=api['copy'];caps=api['caps']
 query=aux_copy._isolated(Path('/source/scripts/ci/expanded600-installer-vm/observer600.py'),'c3d804e7f2927c7889835ad187a39a3d7c618a4651700f57b0c5413c46612607')
 roots=types.SimpleNamespace(**vars(original_roots));roots._mount_id=query._mount600(original_roots._mount_id)
 roots.observe=clone(original_roots.observe,_mount_id=roots._mount_id)
 # Auxiliary Readers and their descriptor parent/root checks otherwise retain
 # the old full_root global through a separate measure_copy namespace.
 aux=aux_copy.aux;walk_space=dict(vars(aux.copy),roots=roots)
 for name in ('_parent','_root_check','_source_alias'):
  function=getattr(aux.copy,name)
  walk_space[name]=contextmanager(clone(function.__wrapped__,**walk_space)) if name=='_parent' else clone(function,**walk_space)
 walk=types.SimpleNamespace(**walk_space);aux_space=dict(vars(aux),roots=roots,copy=walk)
 methods={name:clone(value,**aux_space) if isinstance(value,types.FunctionType) else value for name,value in vars(aux.Reader).items() if name not in ('__dict__','__weakref__')}
 aux_space['Reader']=type('_ImmutableDescriptorReader',(),methods)
 for name in ('checkpoint','load_comparator'):aux_space[name]=clone(getattr(aux,name),**aux_space)
 checkpoint=types.SimpleNamespace(**aux_space)
 copy_api=types.SimpleNamespace(**vars(aux_copy));copy_api.aux=checkpoint
 copy_api._copy_binding=clone(aux_copy._copy_binding,roots=roots,aux=checkpoint)
 # Retain every original capability graph/attribute/hash/identity scan afresh.
 cap_space=dict(vars(caps),_mount=query._mount600(caps._mount))
 for name in ('_scan','observe','restore'):cap_space[name]=clone(getattr(caps,name),**cap_space)
 capability=types.SimpleNamespace(**cap_space)
 return dict(api,roots=roots,copy=copy_api,caps=capability)


_OPERATION_LABELS = ('SOURCE_OBSERVATION', 'TARGET_OBSERVATION', 'TARGET_CAPABILITIES', 'TARGET_AUXILIARY', 'COPY_DATA', 'SOURCE_ROOT_CHECK', 'SOURCE_PARENT', 'LIFETIME_ENTER', 'LIFETIME_BODY', 'LIFETIME_EXIT', 'CONTEXT_LIMITS', 'CONTEXT_ADAPTER')
def operation(label, call, *args, **kwargs):
 P.need(label in _OPERATION_LABELS, 'fixed source-owned operation label')
 try:return call(*args, **kwargs)
 except BaseException:
  validation_failure('OP_'+label)
  raise

def bind(api,channel,guest):
 api=descriptor_api(api)
 original_roots=api['roots'];aux=api['copy'];facade=types.SimpleNamespace(**vars(original_roots))
 def source(limits):return operation('SOURCE_OBSERVATION',channel.source,limits)
 def observe(root,*args,**kwargs):
  if Path(root)==Path('/held'):
   P.need(not args and set(kwargs)<={'limits','hardlinks'}and kwargs.get('hardlinks')=='generic-development-internal','exact immutable original observe operands');return source(kwargs['limits'])['observation']
  return operation('TARGET_OBSERVATION',original_roots.observe,root,*args,**kwargs)
 facade.observe=observe;api=dict(api,roots=facade)
 caps=types.SimpleNamespace(**vars(api['caps']));original_caps=caps.observe
 def capobserve(root,nodes,limits):
  if Path(root)==Path('/held'):
   value=source(limits);P.need(nodes==value['nodes'],'whole immutable nodes/capability join');return value['capabilities']
  return operation('TARGET_CAPABILITIES',original_caps,root,nodes,limits)
 caps.observe=capobserve;api['caps']=caps
 checkpoint=types.SimpleNamespace(**vars(aux.aux));original_checkpoint=checkpoint.checkpoint
 def check(root,observation,limits):
  if Path(root)==Path('/held'):
   value=source(limits);P.need(observation==value['observation'],'whole immutable observation/aux join');return value['auxiliary']
  return operation('TARGET_AUXILIARY',original_checkpoint,root,observation,limits)
 checkpoint.checkpoint=check
 binding=clone(aux._copy_binding,roots=facade,aux=checkpoint)
 def copy_data(source_root,target,*,limits,hardlinks='generic-development-internal'):
  P.need(Path(source_root)==Path('/held')and Path(target)in(Path('/work/pristine/root'),Path('/work/modified/root'))and hardlinks=='generic-development-internal'and not limits.allow_cross_device,'new exact separate-device copy purpose')
  initial=source(limits);module=binding(limits);old_parent=module._parent;old_check=module._root_check;checks=[1];R=descriptor_reader(api,limits)
  def scope_check():
   current=source(limits);parent=Path(target).parent;info=parent.lstat()
   P.need(current['nodes']==initial['nodes']and info.st_uid==0 and info.st_dev!=channel.pinned['root_identity'][0]and not os.statvfs(parent).f_flag&os.ST_RDONLY,'immutable source and disjoint owned writable target');checks[0]+=1
  @contextmanager
  def parent(root,path,mount,identities,subject,expected=None):
   if P.stable(os.fstat(root))==channel.pinned['root_identity']:
    P.need(mount==channel.pinned['source_mount']and expected==initial['nodes'],'exact authenticated source parent graph')
    try:
     with R.lookup_parent(root,path,mount,subject,expected)as value:yield value
    except BaseException:
     validation_failure('OP_SOURCE_PARENT')
     raise
   else:
    with old_parent(root,path,mount,identities,subject,expected)as value:yield value
  def root_check(*args,**kwargs):operation('SOURCE_ROOT_CHECK',old_check,*args,**kwargs);scope_check()
  module._parent=parent;module._root_check=root_check
  result=operation('COPY_DATA',module.copy_data,source_root,target,limits=limits,hardlinks=hardlinks);scope_check();P.need(checks[0]==7,'all original root checkpoints plus final scope check')
  result.update(scope='EXPLICIT_IMMUTABLE_SOURCE_SEPARATE_DEVICE_FULL_COPY',copy_byte_identical_before_initialization=True,transaction_acceptance='NOT ESTABLISHED',gnu_bind_scope=dict(purpose='GNU_VERITY_COPY_SCOPE_V1',checkpoints=checks[0],original_copier_sha256=aux.COPY_SHA256,lifetime_sha256=aux.LIFETIME_SHA256,map_index_sha256=channel.pinned['index']['sha256']))
  return result
 def copied_root(source_root,workspace,**kwargs):
  module=aux._isolated(aux.disposable_copy.__file__,aux.LIFETIME_SHA256);module.measure_copy=types.SimpleNamespace(copy_data=copy_data)
  @contextmanager
  def observed():
   phase='LIFETIME_ENTER'
   try:
    with module.copied_root(source_root,workspace,**kwargs)as value:
     phase='LIFETIME_BODY'
     yield value
     phase='LIFETIME_EXIT'
   except BaseException:
    validation_failure('OP_'+phase)
    raise
  return observed()
 def receipt(value,case):
  P.need(case in('pristine','modified')and set(value)=={'purpose','checkpoints','original_copier_sha256','lifetime_sha256','map_index_sha256'}and value==dict(purpose='GNU_VERITY_COPY_SCOPE_V1',checkpoints=7,original_copier_sha256=aux.COPY_SHA256,lifetime_sha256=aux.LIFETIME_SHA256,map_index_sha256=channel.pinned['index']['sha256']),'new complete immutable copy receipt; old bind proof never substituted');return value
 scope=types.SimpleNamespace(copied_root=copied_root,receipt=receipt);oldbridge=api['capabilities'];bridge=types.SimpleNamespace(**vars(oldbridge));original_context=contextmanager(clone(oldbridge.copied_root.__wrapped__,scope=scope));bridge.records=clone(oldbridge.records,scope=scope)
 def context(api,source_root,workspace,index,evidence=None,**kwargs):
  # Whole held CI2400 accounting and per-observation/restore600 windows.
  budget=operation('CONTEXT_LIMITS',validation_limits,guest,kwargs['limits']);kwargs['limits']=budget
  return original_context(operation('CONTEXT_ADAPTER',guest._copy_context_api,api,budget),source_root,workspace,index,evidence=evidence,**kwargs)
 bridge.copied_root=context;api['capabilities']=bridge;api['proc_probe']=mount_proxy.Proxy(channel);return api

# Explicit TEST-only copied-root observation capacity; never product timeouts.
WORKER_VALIDATION_PROFILE={'name':'GNU_IMMUTABLE_WORKER_VALIDATION_1200_4800_V1','observation_seconds':1200,'copy_context_seconds':4800,'old_600_2400_fit':'NOT_ESTABLISHED','owner_ceiling':10500,'qemu_ceiling':10800}
_VALIDATION_LABELS=tuple('SNAPSHOT_'+case.upper()+'_'+phase.upper().replace('-','_')for case in('pristine','modified')for phase in('source-before','clone','before574','precommit-refused','provider574','reinstalled574','held574','source-after'))+('COPY_SELECTED_OBSERVE','COPY_COPIED_TREE','COPY_CAPABILITY_RESTORE','COPY_COPY_DATA')
_VALIDATION_LABELS+=tuple('OP_'+name for name in _OPERATION_LABELS)
_validation_writes=0

def validation_failure(label):
 global _validation_writes
 # Exception-only fixed literals, no message/path/identity/time serialization.
 try:
  if type(label)is not str or label not in _VALIDATION_LABELS or _validation_writes>=8:return
  _validation_writes+=1;os.write(2,b'GNU_WORKER_FAILURE_DATA '+label.encode('ascii')+b'\n')
 except BaseException:pass

def validation_limits(guest,original):
 import ast
 text=Path(guest.__file__).read_text();tree=ast.parse(text)
 nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='_copy_context_limits'];P.need(len(nodes)==1,'one whole trusted copy-context function')
 before=ast.get_source_segment(text,nodes[0]);after=before
 pairs=(('<=600:', '<=1200:'),('original.deadline+1800','original.deadline+3600'),("'PARENT2400'","'PARENT4800'"),("'WINDOW600'","'WINDOW1200'"),('time.monotonic()+600','time.monotonic()+1200'))
 # The extension appears twice (diagnostic arithmetic and actual deadline).
 for old,new in dict(pairs).items():
  count=2 if old in('original.deadline+1800',"'PARENT2400'","'WINDOW600'")else 1
  P.need(after.count(old)==count,'finite worker capacity source seam');after=after.replace(old,new)
 old='            except BaseException:\n                if not state[\'failed\']:emit(state,\'failure\',state[\'expiry\'])'
 new='            except BaseException:\n                try:validation_failure(\'COPY_\'+operation)\n                except BaseException:pass\n                if not state[\'failed\']:emit(state,\'failure\',state[\'expiry\'])'
 P.need(after.count(old)==1,'one exception-only copy diagnostic seam');after=after.replace(old,new)
 restored=after.replace(new,old)
 for old,new in reversed(tuple(dict(pairs).items())):restored=restored.replace(new,old)
 P.need(restored==before,'entire original copy-context function inverse')
 space=dict(vars(guest),validation_failure=validation_failure);exec(compile(after,guest.__file__,'exec'),space)
 return space['_copy_context_limits'](original)

def install_validation(module):
 original_limits=module.limits;original_snapshot=module.snapshot
 def limits(api,seconds=1200):return original_limits(api,seconds)
 def snapshot(api,root,label):
  try:return original_snapshot(api,root,label)
  except BaseException:
   if type(label)is str:validation_failure('SNAPSHOT_'+label.upper().replace('-','_'))
   raise
 module.limits=limits;module.snapshot=snapshot

"""Private source-parent globals; original lookup/open/identity bodies remain whole."""
def descriptor_reader(api, limits):
 original=C.reader()
 query=api['copy']._isolated(Path('/source/scripts/ci/expanded600-installer-vm/observer600.py'),'c3d804e7f2927c7889835ad187a39a3d7c618a4651700f57b0c5413c46612607')
 # The held query does a real statx on EVERY call, cross-checks the first
 # against the original fdinfo API, and falls back to that API if unavailable.
 def fallback(fd, subject):return original.mount_id(fd)
 fresh=query._mount600(fallback)
 def mount(fd):return fresh(fd,limits)
 # Reuse only the process libc handle/function; NEVER an opened directory or
 # mount/result. Keep the whole original openat2 ABI/path/syscall body active.
 libc=original.ctypes.CDLL(None,use_errno=True)
 syscall=libc.syscall
 def library(name,**kwargs):
  P.need(name is None and kwargs=={'use_errno':True},'exact original process libc operand')
  return libc
 c_api=types.SimpleNamespace(**vars(original.ctypes));c_api.CDLL=library
 opener=clone(original.open_beneath,ctypes=c_api)
 reader=types.SimpleNamespace(**vars(original))
 reader.mount_id=mount
 reader.lookup_parent=contextmanager(clone(original.lookup_parent.__wrapped__,mount_id=mount,open_beneath=opener))
 return reader
