# SPDX-License-Identifier: MIT
"""Closed source roles and prospective selection; no actors in source checks."""
import hashlib,importlib.util,json,os,stat,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
LANE='scripts/ci/current606-doctor2-closed-owner'
ROLES={'held606':('CURRENT606_CORRECTED_COMPLETE263','f3a30f2049f57d9f3cb2433fbd59af51d4cc5720'),'bridge':('OWNED606_DOCTOR_SOURCE_BRIDGE',None),'copyworker':('SETUP6_COPIED_ROOT_WORKER',None),'setup240':('WHOLE_ACCEPTED_SETUP6_REAL_MODULE_SOURCE','d41d28d870227b0256a8980d3c305287fbfb6ffb')}

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
 need(read(copyworker/'scripts/ci/current606-doctor2-copy/owner-api.json')==dict(path=path,**wanted),'worker whole owner API source join')
 return wanted

def renewed_signer(copyworker):
 home=copyworker/'scripts/ci/current606-doctor2-copy'
 original=read(home/'native-input-pins.json')
 need(original['source']=='24f8d8ed9de7f4ea1aedcc9624110e553204b36c'and original['index']=={'bytes': 140641, 'sha256': '741c5a86b66d0189c0de78a660fa6b7c83c9feca37623db1bf28389c1c9a4237'},'exact Doctor native DATA role')
 import ast
 inputs=ast.parse((home/'inputs.py').read_bytes());values={}
 for n in inputs.body:
  if not(isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id in('INDEX','NATIVE','ARCHIVE')):continue
  value=n.value
  if isinstance(value,ast.Call):
   need(isinstance(value.func,ast.Name)and value.func.id=='dict'and not value.args and all(k.arg is not None for k in value.keywords),'finite literal input constants')
   values[n.targets[0].id]={k.arg:ast.literal_eval(k.value)for k in value.keywords}
  else:values[n.targets[0].id]=ast.literal_eval(value)
 need(values==dict(INDEX=original['index'],NATIVE=original['native'],ARCHIVE=dict(bytes=27188,sha256='a4fc772da0fd460f07380c4bc6bc1396688745907a993fe2591778082dae05c8')),'Doctor input constants and source authority crossjoin')
 tree=ast.parse((home/'lifecycle.py').read_bytes());fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='operands');wanted=ast.dump(ast.parse("new2['signer']==original1['signer']",mode='eval').body,include_attributes=False)
 checks=[n for n in ast.walk(fn)if isinstance(n,ast.Compare)and ast.dump(n,include_attributes=False)==wanted]
 need(len(checks)==1,'same actual original producer TEST signer required')
 need(pin((home/'held-runtime-inputs.py').read_bytes())==dict(bytes=8834,sha256='d1d1873672f7a15f7952c6054b95048497cf6b1a9f2d8e44a2003b424588df8f'),'whole original Runtime native-pair proof')
 return original['index']

def roles(root=ROOT):
 data=read(HERE/'source-pins.json');need(set(data)==set(ROLES),'four complete separated roles')
 for prefix,(purpose,source)in ROLES.items():
  role=data[prefix];need(set(role)=={'purpose','source','files'}and role['purpose']==purpose and role['source']==source and type(role['files'])is dict and role['files'],'whole role identity')
  home=root/prefix
  for n,row in role['files'].items():
   need(type(n)is str and Path(n).as_posix()==n and not Path(n).is_absolute()and not any(x in('','.','..')for x in n.split('/')),'contained role path');checked(home/n,row)
  need(files(home)==set(role['files']),'exact complete role file set')
 need(len(data['setup240']['files'])==240 and len(data['held606']['files'])==263 ,'whole native source roles, not reduced recipes')
 owner_api(root/'bridge',root/'copyworker')
 renewed_signer(root/'copyworker')
 return data

def verify(root=ROOT):
 need(not sys.flags.optimize,'optimized guards refused');data=roles(root)
 mf=read(HERE/'source-manifest.json');need(mf['status']=='CLOSED_SOURCE_ONLY_CURRENT606_SETUP6_NOT_NATIVE'and all(mf[k]is None for k in('actual_source','actual_ref','actual_run')),'source only manifest')
 for n,row in mf['files'].items():checked(root/n,row)
 excluded={LANE+'/source-manifest.json','.github/workflows/native-arm-current606-doctor2-owned-copy.yml','.github/workflows/native-arm-build.yml'}
 need({p.relative_to(root).as_posix()for p in root.rglob('*')if p.relative_to(root).parts[0]!='.git'and p.is_file()}==set(mf['files'])|excluded,'closed exact owner source closure')
 return dict(status=mf['status'],roles={k:len(v['files'])for k,v in data.items()},files=len(mf['files'])+3,actual_source=None,actual_ref=None,actual_run=None)

def authorize(p):
 import selection as S
 need(type(p)is dict and p.get('status')=='ROOT_BOUND_CURRENT606_SETUP6_INPUTS','current606 accepted Root decision NULL/UNBOUND')
 need(all(p.get(k)is None for k in('actual_source','actual_ref','actual_run','nonce','measurement','output','retirement','capture_receipt')),'prospective source policy must not claim future actors/actuals')
 need(p.get('doctor_source')==S.DOCTOR and p.get('doctor_packet_source')==S.DOCTOR_PACKET and p.get('doctor_packet_index')==S.DOCTOR_INDEX,'exact Doctor2 accepted native DATA source/index required');d=S.decision(p.get('current606'));need(p.get('native_pair_source')==S.PAIR_SOURCE and p.get('native_pair_index')==S.PAIR_INDEX,'genuine public192 pair source/index required');need(p.get('schema_version')==1 and p.get('purpose')==S.PURPOSE and p.get('apps_source')==S.APPS and p.get('expected606_sha256')==S.LOCK and p.get('source_manifest606')==d['source_manifest'],'exact accepted606 and complete Apps7/Runtime input roles');return p

def module(name,path,aliases=None):
 import contextlib
 old={k:sys.modules.get(k)for k in(aliases or {})};sys.modules.update(aliases or {})
 try:
  spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
 finally:
  for k,v in old.items():
   if v is None:sys.modules.pop(k,None)
   else:sys.modules[k]=v
