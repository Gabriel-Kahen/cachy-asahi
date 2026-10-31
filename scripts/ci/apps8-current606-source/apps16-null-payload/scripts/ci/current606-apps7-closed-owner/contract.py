# SPDX-License-Identifier: MIT
"""Closed source roles and prospective selection; no actors in source checks."""
import hashlib,importlib.util,json,os,stat,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
LANE='scripts/ci/current606-apps7-closed-owner'
ROLES={'held606':('CURRENT606_CORRECTED_COMPLETE263','f3a30f2049f57d9f3cb2433fbd59af51d4cc5720'),'bridge':('OWNED606_APPS_SOURCE_BRIDGE',None),'copyworker':('APPS7_COPIED_ROOT_WORKER',None)}

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def read(p,maximum=4*1024**2):
 from selection import decode
 need(not any(x.is_symlink()for x in(p,*p.parents)),'ordinary contained input');s=p.lstat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<s.st_size<=maximum,'bounded single-link JSON');return decode(p.read_bytes())
def checked(p,row):
 need(type(row)is dict and set(row)=={'bytes','sha256'},'finite source pin');need(not any(q.is_symlink()for q in(p,*p.parents)),'source alias');s=p.lstat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size<=16*1024**2 and pin(p.read_bytes())==row,'whole source differs: '+str(p));return p

def files(root):
 result=set()
 for base,dirs,names in os.walk(root):
  if Path(base)==root:dirs[:]=[n for n in dirs if n!='.git'];names=[n for n in names if n!='.git']
  for n in dirs:need(not(Path(base)/n).is_symlink(),'source directory alias')
  result.update((Path(base)/n).relative_to(root).as_posix()for n in names)
 return result

def owner_api(bridge,copyworker):
 """Both actor authorities must name the whole exact source-owned API."""
 source=HERE/'selection.py';wanted=pin(source.read_bytes());checked(source,wanted)
 path='/runner/owner/selection.py'
 need(read(bridge/'scripts/ci/current606-welcome5-source-bridge/owner-api.json')==dict(path=path,pin=wanted),'bridge whole owner API source join')
 need(read(copyworker/'scripts/ci/current606-apps7-copy/owner-api.json')==dict(path=path,**wanted),'worker whole owner API source join')
 return wanted

def renewed_signer(copyworker):
 """Whole source roles must agree on the exact renewed public TEST signer."""
 import ast
 wanted='DA8AD638E79414E661656E4C23132CAA1000DA38'
 home=copyworker/'scripts/ci/current606-apps7-copy'
 for filename,function,expression in(('lifecycle.py','operands',"new7['signer']"),('inputs.py','inspect','signer')):
  tree=ast.parse((home/filename).read_bytes())
  nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name==function]
  need(len(nodes)==1,'one exact signer authority function')
  expected=ast.dump(ast.parse(expression,mode='eval').body,include_attributes=False)
  values=[n.comparators[0].value for n in ast.walk(nodes[0])if isinstance(n,ast.Compare)and len(n.ops)==len(n.comparators)==1 and isinstance(n.ops[0],ast.Eq)and ast.dump(n.left,include_attributes=False)==expected and isinstance(n.comparators[0],ast.Constant)]
  need(values==[wanted],'lifecycle/native renewed TEST signer source join')
 return wanted

def roles(root=ROOT):
 data=read(HERE/'source-pins.json');need(set(data)==set(ROLES),'four complete separated roles')
 for prefix,(purpose,source)in ROLES.items():
  role=data[prefix];need(set(role)=={'purpose','source','files'}and role['purpose']==purpose and role['source']==source and type(role['files'])is dict and role['files'],'whole role identity')
  home=root/prefix
  for n,row in role['files'].items():
   need(type(n)is str and Path(n).as_posix()==n and not Path(n).is_absolute()and not any(x in('','.','..')for x in n.split('/')),'contained role path');checked(home/n,row)
  need(files(home)==set(role['files']),'exact complete role file set')
 need(len(data['held606']['files'])==263 ,'whole native source roles, not reduced recipes')
 owner_api(root/'bridge',root/'copyworker')
 renewed_signer(root/'copyworker')
 return data

def verify(root=ROOT):
 need(not sys.flags.optimize,'optimized guards refused');data=roles(root)
 mf=read(HERE/'source-manifest.json');need(mf['status']=='CLOSED_SOURCE_ONLY_CURRENT606_APPS7_NOT_NATIVE'and all(mf[k]is None for k in('actual_source','actual_ref','actual_run')),'source only manifest')
 for n,row in mf['files'].items():checked(root/n,row)
 excluded={LANE+'/source-manifest.json','.github/workflows/native-arm-current606-apps7-owned-copy.yml','.github/workflows/native-arm-build.yml'}
 need({p.relative_to(root).as_posix()for p in root.rglob('*')if p.relative_to(root).parts[0]!='.git'and p.is_file()}==set(mf['files'])|excluded,'closed exact owner source closure')
 return dict(status=mf['status'],roles={k:len(v['files'])for k,v in data.items()},files=len(mf['files'])+3,actual_source=None,actual_ref=None,actual_run=None)

def authorize(p):
 import selection as S
 import importlib.util
 spec=importlib.util.spec_from_file_location('_apps16_source_packet',ROOT/'apps16/packet.py');M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M);M.policy()
 need(type(p)is dict and p.get('status')=='ROOT_BOUND_CURRENT606_APPS7_INPUTS','current606 accepted Root decision NULL/UNBOUND')
 need(all(p.get(k)is None for k in('actual_source','actual_ref','actual_run','nonce','measurement','output','retirement','capture_receipt')),'prospective source policy must not claim future actors/actuals')
 d=S.decision(p.get('current606'));need(p.get('native_pair_source')==S.PAIR_SOURCE and p.get('native_pair_index')==S.PAIR_INDEX,'genuine public192 pair source/index required');need(p.get('schema_version')==1 and p.get('purpose')==S.PURPOSE and p.get('apps_source')==S.APPS and p.get('expected606_sha256')==S.LOCK and p.get('source_manifest606')==d['source_manifest'],'exact accepted606 and complete Apps7/Runtime input roles');return p

def module(name,path,aliases=None):
 import contextlib
 old={k:sys.modules.get(k)for k in(aliases or {})};sys.modules.update(aliases or {})
 try:
  spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
 finally:
  for k,v in old.items():
   if v is None:sys.modules.pop(k,None)
   else:sys.modules[k]=v

# BEGIN_APPS16_FULL380
_original_apps16_verify=verify
def verify(root=ROOT):
 result=_original_apps16_verify(root)
 M=module('_apps16_full380_source_guard',root/'apps16/source.py')
 return M.validate(root,result,{'bytes': 7572826, 'sha256': '0a8350ca6db93e6097eba670b06336f6b9ca20e3ddbfa84c9dc869bc34780b83'})
