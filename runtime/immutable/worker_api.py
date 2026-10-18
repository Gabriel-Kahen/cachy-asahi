"""Explicit immutable-source API; original mutable copier/lifetime code is held."""
from contextlib import contextmanager
from pathlib import Path
import os,types
import inputs,mount_proxy
P,C,_,_=inputs.broker()

def clone(function,**replacements):
 value=types.FunctionType(function.__code__,dict(function.__globals__,**replacements),function.__name__,function.__defaults__,function.__closure__);value.__kwdefaults__=function.__kwdefaults__;return value

def bind(api,channel,guest):
 original_roots=api['roots'];aux=api['copy'];facade=types.SimpleNamespace(**vars(original_roots))
 def source(limits):return channel.source(limits)
 def observe(root,*args,**kwargs):
  if Path(root)==Path('/held'):
   P.need(not args and set(kwargs)<={'limits','hardlinks'}and kwargs.get('hardlinks')=='generic-development-internal','exact immutable original observe operands');return source(kwargs['limits'])['observation']
  return original_roots.observe(root,*args,**kwargs)
 facade.observe=observe;api=dict(api,roots=facade)
 caps=types.SimpleNamespace(**vars(api['caps']));original_caps=caps.observe
 def capobserve(root,nodes,limits):
  if Path(root)==Path('/held'):
   value=source(limits);P.need(nodes==value['nodes'],'whole immutable nodes/capability join');return value['capabilities']
  return original_caps(root,nodes,limits)
 caps.observe=capobserve;api['caps']=caps
 checkpoint=types.SimpleNamespace(**vars(aux.aux));original_checkpoint=checkpoint.checkpoint
 def check(root,observation,limits):
  if Path(root)==Path('/held'):
   value=source(limits);P.need(observation==value['observation'],'whole immutable observation/aux join');return value['auxiliary']
  return original_checkpoint(root,observation,limits)
 checkpoint.checkpoint=check
 binding=clone(aux._copy_binding,roots=facade,aux=checkpoint)
 def copy_data(source_root,target,*,limits,hardlinks='generic-development-internal'):
  P.need(Path(source_root)==Path('/held')and Path(target)in(Path('/work/pristine/root'),Path('/work/modified/root'))and hardlinks=='generic-development-internal'and not limits.allow_cross_device,'new exact separate-device copy purpose')
  initial=source(limits);module=binding(limits);old_parent=module._parent;old_check=module._root_check;checks=[1];R=C.reader()
  def scope_check():
   current=source(limits);parent=Path(target).parent;info=parent.lstat()
   P.need(current['nodes']==initial['nodes']and info.st_uid==0 and info.st_dev!=channel.pinned['root_identity'][0]and not os.statvfs(parent).f_flag&os.ST_RDONLY,'immutable source and disjoint owned writable target');checks[0]+=1
  @contextmanager
  def parent(root,path,mount,identities,subject,expected=None):
   if P.stable(os.fstat(root))==channel.pinned['root_identity']:
    P.need(mount==channel.pinned['source_mount']and expected==initial['nodes'],'exact authenticated source parent graph')
    with R.lookup_parent(root,path,mount,subject,expected)as value:yield value
   else:
    with old_parent(root,path,mount,identities,subject,expected)as value:yield value
  def root_check(*args,**kwargs):old_check(*args,**kwargs);scope_check()
  module._parent=parent;module._root_check=root_check
  result=module.copy_data(source_root,target,limits=limits,hardlinks=hardlinks);scope_check();P.need(checks[0]==7,'all original root checkpoints plus final scope check')
  result.update(scope='EXPLICIT_IMMUTABLE_SOURCE_SEPARATE_DEVICE_FULL_COPY',copy_byte_identical_before_initialization=True,transaction_acceptance='NOT ESTABLISHED',gnu_bind_scope=dict(purpose='GNU_VERITY_COPY_SCOPE_V1',checkpoints=checks[0],original_copier_sha256=aux.COPY_SHA256,lifetime_sha256=aux.LIFETIME_SHA256,map_index_sha256=channel.pinned['index']['sha256']))
  return result
 def copied_root(source_root,workspace,**kwargs):
  module=aux._isolated(aux.disposable_copy.__file__,aux.LIFETIME_SHA256);module.measure_copy=types.SimpleNamespace(copy_data=copy_data);return module.copied_root(source_root,workspace,**kwargs)
 def receipt(value,case):
  P.need(case in('pristine','modified')and set(value)=={'purpose','checkpoints','original_copier_sha256','lifetime_sha256','map_index_sha256'}and value==dict(purpose='GNU_VERITY_COPY_SCOPE_V1',checkpoints=7,original_copier_sha256=aux.COPY_SHA256,lifetime_sha256=aux.LIFETIME_SHA256,map_index_sha256=channel.pinned['index']['sha256']),'new complete immutable copy receipt; old bind proof never substituted');return value
 scope=types.SimpleNamespace(copied_root=copied_root,receipt=receipt);oldbridge=api['capabilities'];bridge=types.SimpleNamespace(**vars(oldbridge));original_context=contextmanager(clone(oldbridge.copied_root.__wrapped__,scope=scope));bridge.records=clone(oldbridge.records,scope=scope)
 def context(api,source_root,workspace,index,evidence=None,**kwargs):
  # Whole held CI2400 accounting and per-observation/restore600 windows.
  budget=guest._copy_context_limits(kwargs['limits']);kwargs['limits']=budget
  return original_context(guest._copy_context_api(api,budget),source_root,workspace,index,evidence=evidence,**kwargs)
 bridge.copied_root=context;api['capabilities']=bridge;api['proc_probe']=mount_proxy.Proxy(channel);return api
