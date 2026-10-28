#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit exact210 cost DATA and private lifetime emission; no native actors."""
import argparse,ast,hashlib,json,os,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes':72571,'sha256':'0b43836a2d7592134c0581b90e798db727b2b2d3f5b9843c197707ae96fb64cd'}
NAME='cost-data-lifetime210';BRIDGE='scripts/ci/apps7-full574-repair16k';CI=BRIDGE+'-ci';ADAPTER=BRIDGE+'/adapter.py';TEST=BRIDGE+'/test_lane.py';BM=BRIDGE+'/source-manifest.json';MF=CI+'/source-manifest.json';WORKFLOWS=('.github/workflows/native-arm-apps7-full574-repair16k.yml','.github/workflows/native-arm-build.yml')
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def path(p):
 p=Path(p);need(p.is_absolute()and'..'not in p.parts and not any(q.is_symlink()for q in(p,*p.parents)),'ordinary absolute source/output ancestry');return p
KEY=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(p):
 p=path(p);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<=before.st_size<=16*1024**2,'bounded single-link source');parts=[];total=0
  while True:
   raw=os.read(fd,1024**2)
   if not raw:break
   total+=len(raw);need(total<=before.st_size,'source grew');parts.append(raw)
  need(total==before.st_size and KEY(before)==KEY(os.fstat(fd))==KEY(p.lstat()),'stable whole atime-independent source');return b''.join(parts)
 finally:os.close(fd)
def files(root):
 root=path(root);need(root.is_dir(),'ordinary exact source root');rows={}
 for base,dirs,names in os.walk(root):
  if Path(base)==root:dirs[:]=[n for n in dirs if n!='.git'];names=[n for n in names if n!='.git']
  need(not any((Path(base)/n).is_symlink()for n in dirs),'source directory alias')
  for n in names:
   p=Path(base)/n;rows[p.relative_to(root).as_posix()]=pin(read(p))
 return rows
def relative(n):
 need(type(n)is str and n and'\\'not in n and not n.startswith('/')and all(p not in('','.','..')for p in n.split('/')),'finite source relative path');return Path(n)
def once(s,a,b):
 need(s.count(a)==1,'one exact diagnostic source seam');return s.replace(a,b,1)
def inputs():
 raw=read(HERE/'cost210-profile.json');need(pin(raw)==PROFILE,'whole cost profile pin');p=json.loads(raw);need(p['profile']==NAME and len(p['before'])==len(p['after'])==210 and set(p['before'])==set(p['after'])and set(p['changed'])=={ADAPTER,TEST,BM,MF,*WORKFLOWS},'finite exact210 six-change profile');bodies={}
 need(set(p['support'])=={'cost210_lifetime.py','cost210_diagnostics.py'},'two real source-owned emitted helpers')
 for name,want in p['support'].items():bodies[name]=read(HERE/name);need(pin(bodies[name])==want,'whole source helper pin: '+name)
 need(p['actual']is None and all(v is None for v in p['run_ids'].values())and p['maximum_diagnostic_cases']==1,'diagnostic recommendation/NULLactuals only');return p,bodies

def derive(raw,bodies):
 text=raw.decode();tree=ast.parse(text);node=next(n for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(x,ast.Name)and x.id=='FUSED_OBSERVER'for x in n.targets));fused=ast.literal_eval(node.value);old=fused
 fused=once(fused," try:\n  if stage not in COPY_SUBSTAGES", " try:\n  _repair_cost.cost(stage,'POINT')\n  if stage not in COPY_SUBSTAGES")
 fused=once(fused,"   try:return function(*args,**kwargs)\n   except BaseException:","   _repair_cost.cost(tag.decode('ascii'),'BEGIN')\n   try:\n    value=function(*args,**kwargs)\n    _repair_cost.cost(tag.decode('ascii'),'END');return value\n   except BaseException:\n    _repair_cost.cost(tag.decode('ascii'),'FAIL')")
 setup="import types as _repair_cost_types\n_repair_cost=_repair_cost_types.ModuleType('_repair_scalar_cost')\nexec(compile("+repr(bodies['cost210_diagnostics.py'].decode())+",'<repair-scalar-cost>','exec'),_repair_cost.__dict__)\n"
 fused=setup+fused
 text=once(text,ast.get_source_segment(text,node),'FUSED_OBSERVER = '+repr(fused))
 fresh=bodies['cost210_lifetime.py'].decode();text='FRESH_QUERY = '+repr(fresh)+'\n'+text
 a="replacement=\"spec.loader.exec_module(value);return _vm_fused.bind(value) if Path(path)==ROOT/'scripts/ci/apps7-full574-repair-native/closure.py' else value\""
 b="replacement=\"spec.loader.exec_module(value);value=_vm_fresh.loaded(value,path,ROOT,lambda p:B.client.read_path(p,128*1024));return _vm_fused.bind(_vm_fresh.closure(value,ROOT,value.source_bytes)) if Path(path)==ROOT/'scripts/ci/apps7-full574-repair-native/closure.py' else value\""
 text=once(text,a,b)
 a='setup="import types as _vm_fused_types\\n_vm_fused=_vm_fused_types.ModuleType(\'_private_vm_fused_predicates\')\\nexec(compile("+repr(FUSED_OBSERVER)+",\'<private-vm-fused-observer>\',\'exec\'),_vm_fused.__dict__)\\n"'
 b=a+"\n setup+=\"_vm_fresh=_vm_fused_types.ModuleType('_private_repair_fresh_lifetime')\\nexec(compile(\"+repr(FRESH_QUERY)+\",'<private-repair-fresh-lifetime>','exec'),_vm_fresh.__dict__)\\n\""
 text=once(text,a,b);compile(text,'<fresh-query-adapter>','exec');return text.encode(),dict(fused_before=pin(old.encode()),fused_after=pin(fused.encode()))

def prepare(base,output,profile=None):
 need(profile==NAME,'explicit --profile cost-data-lifetime210 required; no diagnostic default');p,bodies=inputs();base=path(base);output=path(output);need(not output.exists()and output.parent.is_dir()and not output.is_relative_to(base)and not base.is_relative_to(output),'fresh separate source-only output');need(files(base)==p['before'],'whole exact published08e809 source210 required')
 planned={n:read(base/relative(n))for n in p['before']};need({n:pin(v)for n,v in planned.items()}==p['before'],'all original210 physical source bytes');planned[ADAPTER],_=derive(planned[ADAPTER],bodies)
 text=planned[TEST].decode()
 for old,new in p['test_edits']:text=once(text,old,new)
 planned[TEST]=text.encode()
 b=json.loads(planned[BM]);b['files'][ADAPTER]=pin(planned[ADAPTER]);b['files'][TEST]=pin(planned[TEST]);planned[BM]=enc(b)
 m=json.loads(planned[MF]);m['files'][ADAPTER]=pin(planned[ADAPTER]);m['files'][TEST]=pin(planned[TEST]);m['files'][BM]=pin(planned[BM]);planned[MF]=enc(m)
 old=p['before'][MF]['sha256'].encode();new=pin(planned[MF])['sha256'].encode()
 for n in WORKFLOWS:need(planned[n].count(old)==1,'one workflow source stamp; bodies/budgets held');planned[n]=planned[n].replace(old,new,1)
 need({n:pin(v)for n,v in planned.items()}==p['after'],'whole exact published62c7 source210 emission');actual=json.loads(planned[BRIDGE+'/source-pins.json']);need(actual['actual_source']is actual['actual_ref']is None and all(v is None for v in actual['actual_runs'].values()),'emitted actual source/ref/run remainNULL');need(files(base)==p['before'],'whole input source preserved before any output')
 output.mkdir(mode=0o700)
 for n,raw in planned.items():
  target=output/relative(n);target.parent.mkdir(parents=True,exist_ok=True)
  with target.open('xb')as f:f.write(raw)
  target.chmod(0o644)
 need(files(output)==p['after']and files(base)==p['before'],'whole emitted210/source-after equality')
 return dict(status='SOURCE_ONLY_EXACT210_COST_DATA_LIFETIME_NOT_DEADLINE_CURE',profile=NAME,files=p['after'],expected_fixture_source=p['source_after'],source=None,ref=None,run_ids={'repair-bytes':None,'repair-missing':None},recommended_diagnostic_case='repair-bytes',maximum_diagnostic_cases=1,clocks='UNCHANGED',deadline_fit='NOT_ESTABLISHED',performance_gain='NOT_ESTABLISHED',hardware='NOT_RUN',release='NOT_ADMITTED')
if __name__=='__main__':
 q=argparse.ArgumentParser(description=__doc__);q.add_argument('--profile',choices=(NAME,),required=True);q.add_argument('--base-root',type=Path,required=True);q.add_argument('--output',type=Path,required=True);q.add_argument('--authorization',type=Path,required=True);a=q.parse_args();authorization=path(a.authorization.absolute());output=a.output.absolute();need(not authorization.exists()and authorization.parent.is_dir()and not authorization.is_relative_to(output),'fresh separate authorization');value=prepare(a.base_root.absolute(),output,a.profile)
 with authorization.open('xb')as f:f.write(enc(value))
 print(json.dumps({k:value[k]for k in('status','profile','source','ref','run_ids')},sort_keys=True))
