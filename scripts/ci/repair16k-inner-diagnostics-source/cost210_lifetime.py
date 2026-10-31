# SPDX-License-Identifier: MIT
"""Private exact observer query for freshly loaded repair backend lifetimes.

This completes descriptor routing; failed tree/aux observations were already
fresh statx. No native speedup or deadline fit is established.
"""
import hashlib,types
from pathlib import Path
PINS={
 'scripts/update/full_root.py':(35970,'cece1c597b2e2eb98b0e3087cc7e7c148b54332f8a1c4f18e04e4552a71fb51d'),
 'scripts/update/disposable_copy.py':(6098,'fb05d12a0d67a598cc940e0bc7edb5aa9ffc8cf87ce7b9f695ba5fbd26747667'),
 'scripts/ci/expanded600-installer-vm/observer600.py':(2784,'c3d804e7f2927c7889835ad187a39a3d7c618a4651700f57b0c5413c46612607')}
def need(ok,why):
 if not ok:raise ValueError(why)
def clone(function,namespace):
 value=types.FunctionType(function.__code__,namespace,function.__name__,function.__defaults__,function.__closure__);value.__kwdefaults__=function.__kwdefaults__;return value
def checked(root,name,read):
 raw=read(root/name);size,digest=PINS[name];need(len(raw)==size and hashlib.sha256(raw).hexdigest()==digest,'whole repair fresh-query source: '+name);return raw
def query_api(root,roots,read):
 checked(root,'scripts/update/full_root.py',read)
 raw=checked(root,'scripts/ci/expanded600-installer-vm/observer600.py',read)
 helper=types.ModuleType('_repair_exact_observer600');exec(compile(raw,str(root/'scripts/ci/expanded600-installer-vm/observer600.py'),'exec'),helper.__dict__)
 facade=types.SimpleNamespace(**vars(roots));facade._mount_id=helper._mount600(roots._mount_id)
 facade.observe=clone(roots.observe,dict(roots.observe.__globals__,_mount_id=facade._mount_id))
 return facade

def loaded(module,path,root,read):
 """Only independent, newly loaded exact backend namespaces are adapted."""
 path=Path(path)
 if path==root/'scripts/update/full_root.py':return query_api(root,module,read)
 if path==root/'scripts/update/disposable_copy.py':
  checked(root,'scripts/update/disposable_copy.py',read)
  # Its module object is already fresh from the exact original loader. Clone
  # function globals instead of assigning any imported full_root module fields.
  roots=query_api(root,module.roots,read);view=types.ModuleType('_repair_private_'+module.__name__);view.__dict__.update(vars(module));space=view.__dict__;space['roots']=roots
  for name in ('_same','_empty'):space[name]=clone(getattr(module,name),space)
  # This adapter is used by transaction.dispose, not copied_root. Preserve that
  # complete context-manager API too, including its own private inner globals.
  from contextlib import contextmanager
  space['copied_root']=contextmanager(clone(module.copied_root.__wrapped__,space))
  return view
 return module


def closure(module,root,read):
 """Complete original aux_copy call chain; no imported/shared module edits."""
 function=module.copy_scope.copy_data.__wrapped__;old=function.__globals__['aux_copy']
 checked(root,'scripts/update/disposable_copy.py',read)
 # Source-pinned old factory already binds the fast roots/aux facade. Its
 # copy_data/copied_root functions still carried their original module globals.
 space=dict(vars(old),roots=module.roots,aux=module.aux)
 for name in ('_isolated','_copy_binding','copy_data','copied_root'):
  space[name]=clone(getattr(old,name),space)
 isolated=space['_isolated']
 def private_isolated(path,expected):
  value=isolated(path,expected)
  if Path(path)==root/'scripts/update/disposable_copy.py':
   need(expected==PINS['scripts/update/disposable_copy.py'][1],'original lifetime expected hash')
   value=loaded(value,path,root,read)
  return value
 private_isolated.__wrapped__=isolated;space['_isolated']=private_isolated
 copy=types.SimpleNamespace(**space)
 proof_space=dict(function.__globals__,roots=module.roots,aux_copy=copy)
 # Scope uses the same unchanged read/start/check code in this private namespace.
 scope=proof_space['Scope'];methods={n:clone(v,proof_space)if isinstance(v,types.FunctionType)else v
        for n,v in vars(scope).items()if n not in ('__dict__','__weakref__')}
 proof_space['Scope']=type('_RepairPrivateCopyScope',(),methods)
 proof=types.SimpleNamespace(**dict(vars(module.copy_scope),copy_data=module.fast.traced('copy-data')(clone(function,proof_space))))
 module.copy_scope=proof
 return module
