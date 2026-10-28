# SPDX-License-Identifier: MIT
"""Explicit current607→622 Core facade. Original mechanisms remain separate."""
import ctypes,inspect,json,os,re,stat,time,types
from pathlib import Path
SCOPE='CORE622_CURRENT607_COPIED_PROVISIONING_NORMAL_CORE_TWO_BOOT_GENERIC16K'
PROVISIONING='COPIED_ROOT_PROVISIONING_NOT_NORMAL_HOOK_INSTALLATION'
FLAGS=(1<<7)|(1<<10)

def need(value,message):
 if not value:raise ValueError(message)

def plan(value):
 need(type(value)is dict and value['schema']==1 and value['source']is value['ref']is value['run']is value['actual']is None,'unbound source-only composition profile')
 before,after=value['before607'],value['after622'];support=value['support'];candidate=value['candidate'];held=value['held'];old=value['before574']
 need(len(old)==574 and len(before)==607 and len(support)==13 and len(candidate)==7 and len(after)==622 and len(held)==602,'exact distinct574/607/620/622 scope')
 need('libfdk-aac'not in before and before.get('cachy-asahi-fdk-aac')=='3.0.0-1'and {n:v for n,v in old.items()if n not in before}=={'libfdk-aac':'3.0.0-1'}and all(before[n]==v for n,v in old.items()if n in before),'exact573 held old rows; one upstream codec removed, no version normalization')
 need(set(candidate)=={'pacman','systemd','systemd-libs','systemd-resolvconf','systemd-sysvcompat','systemd-tests','systemd-ukify'}and set(before)&set(candidate)==set(candidate)-{'systemd-tests','systemd-ukify'}and not set(before)&set(support),'whole five replacements/two additions/original13 support')
 supported=dict(before,**{n:r['version']for n,r in support.items()});need(len(supported)==620 and dict(supported,**candidate)==after,'complete typed620/622 inventory')
 need(held=={n:v for n,v in before.items()if n not in candidate}and all(after[n]==v for n,v in held.items()),'all602 current desktop packages preserved')
 return before,supported,after

def clone(module,**bindings):
 """Rebind executing function globals, never mutate imported library modules."""
 out=types.ModuleType('_core622_'+module.__name__);out.__dict__.update(vars(module));out.__dict__.update(bindings)
 def function(f):
  g=types.FunctionType(f.__code__,vars(out),f.__name__,f.__defaults__,f.__closure__);g.__kwdefaults__=f.__kwdefaults__;g.__annotations__=dict(f.__annotations__);g.__dict__.update(f.__dict__);return g
 for name,value in vars(module).items():
  if name not in bindings and inspect.isfunction(value)and value.__globals__ is vars(module):out.__dict__[name]=function(value)
 for name,value in vars(module).items():
  if name not in bindings and inspect.isclass(value)and value.__module__==module.__name__:
   ns={k:v for k,v in vars(value).items()if k not in('__dict__','__weakref__')}
   for key,method in list(ns.items()):
    if inspect.isfunction(method)and method.__globals__ is vars(module):ns[key]=function(method)
    elif isinstance(method,(staticmethod,classmethod))and method.__func__.__globals__ is vars(module):ns[key]=type(method)(function(method.__func__))
   out.__dict__[name]=type(value.__name__,value.__bases__,ns)
 need(all(f.__globals__ is vars(out)for n,f in vars(out).items()if n not in bindings and inspect.isfunction(f)and n in vars(module)and inspect.isfunction(vars(module)[n])and vars(module)[n].__globals__ is vars(module)),'every actual original function resolves selected facade')
 return out

def core(original,value):
 """Original51/800 gates execute before this explicit selected-only projection."""
 base,supported,installed=plan(value);legacy=original.C;legacy_profile=legacy.profile;legacy_closure=legacy.closure;original_states=legacy.states();need(original_states[0]==value['before574']and set(original_states[2])-set(original_states[0])==set(installed)-set(base),'whole old574→589 Core guard remains independent')
 rollback=legacy.rollback_rows();need({n:{k:r[k]for k in('version','size','sha256')}for n,r in rollback.items()}=={n:value['archives607'][n]for n in legacy.REPLACED},'all five actual607 baseline rollback archive identities, not version-only Core574 substitution')
 contract=clone(legacy)
 def profile():
  p=legacy_profile();need(p['counts']==dict(base=574,support=13,replacements=5,additions=2,installed=589,restored=574),'whole original800 profile before explicit607 facade')
  return dict(p,counts=dict(base=607,support=13,replacements=5,additions=2,installed=622,restored=607),base_lock=value['fresh607']['sha256'],composition_scope=SCOPE,provisioning=PROVISIONING)
 def closure():
  old=legacy_closure();need(old['base']==value['before574']and old['support']==value['support']and old['candidate']==value['candidate'],'original complete dependency/candidate closure before607 projection');return dict(old,base=dict(base))
 contract.profile=profile;contract.closure=closure;contract.states=lambda:(dict(base),dict(supported),dict(installed));fixture=clone(original.F,C=contract);container=clone(original.T,C=contract,F=fixture)
 # Only the selected whole-root observation bounds change. Original defaults,
 # source modules, clocks, mount/FD/capability and preservation bodies are held.
 def budget(api,seconds=600):return api['roots'].Limits(deadline=min(container.END,time.monotonic()+seconds),max_packages=622,max_nodes=500000,max_bytes=8*1024**3,max_file_bytes=1024**3)
 def database(api,root):return api['db'].database(root,max_packages=622,max_files=100000,max_nodes=500000)
 container.budget=budget;container.database=database
 need(container.inventory.__globals__ is vars(container)and container.public_keys.__globals__['C']is contract and container.payload.__globals__['C']is contract and fixture.capture.__globals__['C']is contract,'actual selected globals; attribute-only rebinding is insufficient')
 return types.SimpleNamespace(C=contract,F=fixture,T=container,api=original.api,root=original.root,legacy=original,scope=SCOPE)

def manifest(value,record):
 before,_,_=plan(value);rows=record['packages'];need(type(rows)is list and len(rows)==607 and len({r['name']for r in rows})==607,'complete unique607 signed manifest')
 need({r['name']:r['version']for r in rows}==before,'exact complete607 versions before Core')
 expected=value['archives607'];need({r['name']:{k:r[k]for k in('version','size','sha256')}for r in rows}==expected,'whole source-bound607 archive identities, not version-only input')
 roles=record['preparation']['signer_roles'];need(set(roles)=={'ephemeral_TEST','upstream_ALARM'}and all(type(v)is str and re.fullmatch('[A-F0-9]{40}',v)for v in roles.values())and len(set(roles.values()))==2,'original distinct fresh607 signer roles');return rows

def provision(api,root,keys,log,rows,value,deadline):
 """Held copied-root NOHOOKS/NOSCRIPTLET, not a normal hook installation.

 The caller owns the fresh copy lifetime and has freshly authenticated every
 archive/signature/metadata/payload through the unchanged607 materializer.
 Live baseline and candidate Core transactions remain the original VM dispatcher.
 """
 before,_,_=plan(value);need(type(deadline)in(int,float)and time.monotonic()<deadline,'same unreset owner deadline');need(root==Path('/measurement/current607')and keys==Path('/tmp/current607-public-gpg')and log==Path('/out/current607-provision.log'),'finite owned copied-root roles')
 need(type(rows)is list and len(rows)==607 and {r['name']:r['version']for r in rows}==before,'complete607 strict transaction operands');added={n:v for n,v in before.items()if n not in value['before574']};need(len(added)==34,'exact34 new current607 selections');wanted=added;remove={'libfdk-aac':'3.0.0-1'};old=value['before574'];need({**{n:v for n,v in old.items()if n not in remove},**wanted}==before,'complete source-derived607 after map')
 limits=api['roots'].Limits(deadline=deadline,max_packages=622,max_nodes=500000,max_bytes=8*1024**3,max_file_bytes=1024**3);alpm=api['roots'].Alpm(root,keys,log,'aarch64',limits=limits)
 try:
  need(alpm.inventory()==old,'fresh actual574 copied inventory before607 formation');alpm.ok(alpm.alpm_trans_init(alpm.handle,FLAGS),'held copied-root NOHOOKS/NOSCRIPTLET');alpm.started=True
  for row in rows:
   if row['name']not in added:continue
   need(type(row['archive'])is Path or isinstance(row['archive'],Path),'literal original signed archive path');need(row['archive'].is_relative_to(Path('/current607-inputs/packages'))and row['signature']==Path(str(row['archive'])+'.sig'),'exact bound archive/signature role');limits.tick();package=ctypes.c_void_p();alpm.ok(alpm.alpm_pkg_load(alpm.handle,os.fsencode(row['archive']),1,1,ctypes.byref(package)),'original strict SIGNATURE_REQUIRED package load')
   need(alpm.alpm_pkg_get_name(package).decode()==row['name']and alpm.alpm_pkg_get_version(package).decode()==row['version']and alpm.alpm_pkg_get_arch(package)in(b'aarch64',b'any'),'exact signed607 package identity');alpm.ok(alpm.alpm_add_pkg(alpm.handle,package),'add exact607 archive')
  package=alpm.alpm_db_get_pkg(alpm.alpm_get_localdb(alpm.handle),b'libfdk-aac');need(package and alpm.alpm_pkg_get_version(package)==b'3.0.0-1','remove only exact upstream codec');alpm.ok(alpm.alpm_remove_pkg(alpm.handle,package),'exact source-derived codec removal')
  error=api['roots'].installer.Ptr();alpm.ok(alpm.alpm_trans_prepare(alpm.handle,ctypes.byref(error)),'full dependency/conflict preparation');need(alpm.packages(alpm.alpm_trans_get_add(alpm.handle))==wanted and alpm.packages(alpm.alpm_trans_get_remove(alpm.handle))==remove,'complete add607/remove1 prepared equality');alpm.ok(alpm.alpm_trans_commit(alpm.handle,ctypes.byref(error)),'complete strict signed607 copied-root provisioning');need(alpm.inventory()==before,'complete actual607 database after formation')
  return dict(status='COMMITTED_EXACT607_COPIED_ROOT_PENDING_FULL_FD_PAYLOAD_READBACK',scope=PROVISIONING,flags=FLAGS,normal_hook_installation=False,before=old,after=before,removed=remove,actual_GUI=False,hardware='NOT_RUN')
 finally:alpm.close()
