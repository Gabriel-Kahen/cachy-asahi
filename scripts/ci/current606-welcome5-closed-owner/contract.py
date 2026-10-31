# SPDX-License-Identifier: MIT
"""Closed source roles and prospective selection; no actors in source checks."""
import hashlib,importlib.util,json,stat,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
LANE='scripts/ci/current606-welcome5-closed-owner'
ROLES={'held606':('CURRENT606_CORRECTED_COMPLETE263','f3a30f2049f57d9f3cb2433fbd59af51d4cc5720'),'heldwelcome':('WELCOME_COMPILED_COMPLETE99','85ffec834fc72ef8764cdcae828a12ec8ddf7f20'),'bridge':('OWNED606_SOURCE_BRIDGE',None),'copyworker':('WELCOME5_COPIED_ROOT_WORKER',None)}
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def read(p,maximum=4*1024**2):
 from selection import decode
 need(not any(x.is_symlink()for x in(p,*p.parents)),'ordinary contained input');s=p.lstat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<s.st_size<=maximum,'bounded single-link JSON');return decode(p.read_bytes())
def checked(p,row):
 need(type(row)is dict and set(row)=={'bytes','sha256'},'finite source pin');need(not any(q.is_symlink()for q in(p,*p.parents)),'source alias');s=p.lstat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size<=16*1024**2 and pin(p.read_bytes())==row,'whole source differs: '+str(p));return p

def roles(root=ROOT):
 data=read(HERE/'source-pins.json');need(set(data)==set(ROLES),'four complete separated roles')
 for prefix,(purpose,source)in ROLES.items():
  role=data[prefix];need(set(role)=={'purpose','source','files'}and role['purpose']==purpose and role['source']==source and type(role['files'])is dict and role['files'],'whole role identity')
  home=root/prefix
  for n,row in role['files'].items():
   need(type(n)is str and Path(n).as_posix()==n and not Path(n).is_absolute()and not any(x in('','.','..')for x in n.split('/')),'contained role path');checked(home/n,row)
  need({p.relative_to(home).as_posix()for p in home.rglob('*')if p.is_file()}==set(role['files']),'exact complete role file set')
 need(len(data['held606']['files'])==263 and len(data['heldwelcome']['files'])==99,'whole native source roles, not reduced recipes')
 return data

def verify(root=ROOT):
 need(not sys.flags.optimize,'optimized guards refused');data=roles(root)
 mf=read(HERE/'source-manifest.json');need(mf['status']=='CLOSED_SOURCE_ONLY_CURRENT606_WELCOME5_NOT_NATIVE'and all(mf[k]is None for k in('actual_source','actual_ref','actual_run')),'source only manifest')
 for n,row in mf['files'].items():checked(root/n,row)
 excluded={LANE+'/source-manifest.json','.github/workflows/native-arm-current606-welcome5-owned-copy.yml','.github/workflows/native-arm-build.yml'}
 need({p.relative_to(root).as_posix()for p in root.rglob('*')if p.relative_to(root).parts[0]!='.git'and p.is_file()}==set(mf['files'])|excluded,'closed exact owner source closure')
 return dict(status=mf['status'],roles={k:len(v['files'])for k,v in data.items()},files=len(mf['files'])+3,actual_source=None,actual_ref=None,actual_run=None)

def authorize(p):
 import selection as S
 need(type(p)is dict and p.get('status')=='ROOT_BOUND_CURRENT606_WELCOME5_INPUTS','current606 accepted Root decision NULL/UNBOUND')
 need(all(p.get(k)is None for k in('actual_source','actual_ref','actual_run','nonce','measurement','output','retirement','capture_receipt')),'prospective source policy must not claim future actors/actuals')
 d=S.decision(p.get('current606'));need(p.get('schema_version')==1 and p.get('purpose')==S.PURPOSE and p.get('welcome_source')==S.WELCOME and p.get('expected606_sha256')==S.LOCK and p.get('source_manifest606')==d['source_manifest'],'exact accepted606 and complete Welcome input roles');return p

def module(name,path,aliases=None):
 import contextlib
 old={k:sys.modules.get(k)for k in(aliases or {})};sys.modules.update(aliases or {})
 try:
  spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
 finally:
  for k,v in old.items():
   if v is None:sys.modules.pop(k,None)
   else:sys.modules[k]=v
