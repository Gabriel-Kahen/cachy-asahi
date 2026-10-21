#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit exact Setup6 source73 or its complete frozen Setup5 test context; no actors."""
import argparse,base64,hashlib,json,os,stat,sys
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;PROFILE='372739c19d30b1d85989100948f7bc54242545538bbd4b081eb1dbbaee669132'
MF5='scripts/ci/setup5-native/source-manifest.json';WF5='.github/workflows/native-arm-setup5-candidate.yml'
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def decode(raw):
 def pairs(rows):
  out={}
  for k,v in rows:need(k not in out,'duplicate source metadata key');out[k]=v
  return out
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite source metadata'))
def relative(n):need(type(n)is str and n and not n.startswith('/')and'\\'not in n and'\0'not in n and all(p not in('','.','..')for p in n.split('/')),'contained source name');return n
def ordinary(p):
 p=Path(p);need(p.is_absolute()and'..'not in p.parts and not any(q.is_symlink()for q in(p,*p.parents)),'ordinary absolute source/output');return p
def read(p,cap=16*1024**2):
 p=ordinary(p);fd=os.open(p,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
 try:
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<=before.st_size<=cap,'bounded singlelink source');chunks=[];total=0
  while block:=os.read(fd,1024**2):chunks.append(block);total+=len(block);need(total<=cap,'source byte bound')
  raw=b''.join(chunks);key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns);need(key(before)==key(os.fstat(fd))==key(p.lstat())and len(raw)==before.st_size,'whole stable source identity/bytes');return raw
 finally:os.close(fd)
def files(root):
 root=ordinary(root);need(root.is_dir(),'source directory');out={}
 for p in sorted(root.rglob('*')):
  n=p.relative_to(root)
  if n.parts[0]=='.git':continue
  need(not p.is_symlink()and(p.is_file()or p.is_dir()),'closed ordinary source nodes')
  if p.is_file():out[relative(n.as_posix())]=read(p)
 return out
def profile():
 raw=read(HERE/'profile.json',1024**2);need(pin(raw)['sha256']==PROFILE,'whole maintained Setup6 profile');p=decode(raw);need(p['purpose']=='MAINTAINED_EXACT_SETUP6_NATIVE_SOURCE_ONLY'and len(p['files'])==73 and all(p[k]is None for k in('actual_source','actual_ref','actual_run')),'exact source-only73 profile');return p
def context(p):
 name=p['context_path'];raw=read(HERE/relative(name));need(pin(raw)==p['delta']['predecessor.json']['proposed'],'whole original Setup5 context body');v=decode(raw);need(v['source']==p['predecessor_source']=='4cf9884dacb2816532b07c8107982d7157656046'and v['run']==p['predecessor_run']==38934198468 and len(v['files'])==44,'complete genuine Setup5 context44');values={}
 for n,row in v['files'].items():
  body=base64.b64decode(row['body'],validate=True);need(pin(body)==row['pin']==p['predecessor_files'][relative(n)],'whole original Setup5 leaf');values[n]=body
 mf=decode(values[MF5]);need(len(mf['files'])==42 and set(values)==set(mf['files'])|{MF5,WF5}and all(pin(values[n])==row for n,row in mf['files'].items()),'complete original42 manifest context');need(pin(values[WF5])['sha256']=='6f6f239cdb1a08f43c108ecdc13eaa2a216c8feb61d927e8ff77fa6ea9b2ccd6','whole original Setup5 workflow');return values

def carrier(root,p,before):
 raw=read(HERE/relative(p['carrier_path']));need(pin(raw)==p['delta']['scripts/ci/setup6-native/setup5-carrier.json']['proposed'],'whole original149 carrier policy');policy=decode(raw);need(policy['source']=='79d8d2f53510e4f3a04f39c1b1e24c999aa32e44'and policy['native_source']==p['predecessor_source']and policy['native_run']==p['predecessor_run'],'exact public Setup5 carrier identity');values=files(root);need({n:pin(b)for n,b in values.items()}==policy['files']and len(values)==149,'whole exact public149 carrier required');need(values['source/source-manifest.json']==before[MF5],'whole original Setup5 source manifest join')
 for n,body in before.items():
  if n.startswith('packages/settings/cachy-asahi-setup/'):need(values['source/cachy-asahi-setup/'+Path(n).name]==body,'whole predecessor recipe/license join')
  elif n.startswith('scripts/ci/setup5-native/')and n!=MF5:need(values['harness/'+Path(n).name]==body,'whole predecessor native control/harness join')
 proof=decode(values['source-proof.json']);need(proof['status']=='SOURCE_PROOF_PASS'and proof['source_sha']==p['predecessor_source']and proof['run_id']==str(p['predecessor_run'])and proof['source_files']==42,'original Setup5 source-proof DATA join');return policy

def render(setup5_carrier=None,setup5_context=False):
 p=profile();v=context(p);need(setup5_carrier is not None,'explicit whole public149 carrier required');carrier(Path(setup5_carrier),p,v)
 if setup5_context:return v,'SETUP5_FROZEN44_TEST_CONTEXT_ONLY'
 for n in p['removed']:need(n in v,'exact removed original source leaf');del v[n]
 for n,row in p['delta'].items():
  relative(n);need(row['before']==p['predecessor_files'].get(n),'exact original delta before pin');raw=read(HERE/relative(row['path']));need(pin(raw)==row['proposed'],'whole maintained Setup6 delta body');v[n]=raw
 need({n:pin(b)for n,b in v.items()}==p['files']and len(v)==73,'entire exact accepted-source73 output');return v,'SETUP6_SOURCE_ONLY_NATIVE_NOT_RUN_BY_FACTORY'
def emit(output,setup5_carrier=None,setup5_context=False):
 v,status=render(setup5_carrier,setup5_context);output=ordinary(output);need(output.parent.is_dir()and not output.exists(),'fresh source output required');need(setup5_carrier is None or(not output.is_relative_to(setup5_carrier)and not Path(setup5_carrier).is_relative_to(output)),'separate borrowed carrier/output');output.mkdir(mode=0o700)
 for n,raw in v.items():
  q=output/relative(n);q.parent.mkdir(parents=True,exist_ok=True)
  with q.open('xb')as f:f.write(raw)
 need(files(output)==v,'whole emitted source readback');return dict(status=status,files=len(v),actual_source=None,actual_ref=None,actual_run=None,native='NOT_RUN_BY_FACTORY',acceptance='NOT_GRANTED',hardware='NOT_RUN')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--setup5-carrier',type=Path,required=True);p.add_argument('--setup5-context',action='store_true',help='Stage complete original44 for unchanged historical tests only');a=p.parse_args();print(json.dumps(emit(a.output.absolute(),None if a.setup5_carrier is None else a.setup5_carrier.absolute(),a.setup5_context),sort_keys=True))
