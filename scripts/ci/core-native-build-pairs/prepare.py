#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit exact Core388 from pinned public373 and maintained finite deltas; no actors."""
import argparse,hashlib,json,os,stat,sys
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
PROFILE_SHA='e9d1346d86b97fe337ec0f8a37d1138140d11b938030eab1de50002d3520ffd1'
def need(ok,why):
 if not ok:raise ValueError(why)
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def decode(raw):
 def pairs(rows):
  v={}
  for k,x in rows:need(k not in v,'duplicate metadata key');v[k]=x
  return v
 def bad(_):raise ValueError('nonfinite metadata')
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=bad)
def relative(n):
 need(type(n)is str and n and not n.startswith('/')and '\\'not in n and '\0'not in n and all(x not in('','.','..')for x in n.split('/')),'contained source role');return n
def read(p,cap=64*1024**2):
 p=Path(p);need(p.is_absolute()and not any(x.is_symlink()for x in(p,*p.parents)),'ordinary absolute source');fd=os.open(p,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
 try:
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_size<=cap,'bounded ordinary single-link source');chunks=[];total=0
  while block:=os.read(fd,1024**2):chunks.append(block);total+=len(block);need(total<=cap,'source byte bound')
  after=os.fstat(fd);key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns);raw=b''.join(chunks);need(key(before)==key(after)and len(raw)==before.st_size,'source physical identity/bytes drift');return raw
 finally:os.close(fd)
def files(root):
 root=Path(root);need(root.is_absolute()and root.is_dir()and not any(x.is_symlink()for x in(root,*root.parents)),'ordinary runtime directory');v={}
 for p in root.rglob('*'):
  rel=p.relative_to(root)
  if rel.parts[0]=='.git':continue
  need(not p.is_symlink()and(p.is_dir()or p.is_file()),'ordinary complete runtime')
  if p.is_file():v[relative(rel.as_posix())]=read(p)
 return v
def profile():
 raw=read(HERE/'profile.json',1024**2);need(pin(raw)['sha256']==PROFILE_SHA,'whole maintained Core profile');p=decode(raw);need(p['schema']==1 and p['purpose']=='MAINTAINED_CORE_NATIVE_388_FACTORY_SOURCE_ONLY'and len(p['base_files'])==373 and len(p['runtime_overrides'])==24 and all(p[k]is None for k in('actual_source','actual_ref','actual_run')),'finite source-only373-to388 profile');return p
def render(runtime,binding=None):
 p=profile();v=files(Path(runtime));need({n:pin(b)for n,b in v.items()}==p['base_files'],'exact whole original373 runtime required')
 for n,row in p['runtime_overrides'].items():
  relative(n);need(row['before']==p['base_files'].get(n)and (n not in v if row['before']is None else pin(v[n])==row['before']),'complete predecessor delta pin');raw=read(HERE/relative(row['path']));need(pin(raw)==row['proposed'],'maintained source delta differs');v[n]=raw
 view='default';policies={}
 for n,row in p['policy_templates'].items():
  raw=read(HERE/relative(row['path']));need(pin(raw)==row['pin'],'whole unselected authority template');policies[n]=raw
 if binding is not None:
  selected=decode(read(Path(binding),65536));need(selected==p['reviewed_selection'],'explicit exact Root component selection required');policies={n:enc(value)for n,value in selected.items()};view='selected'
 v.update(policies);m=decode(v['source-manifest.json']);row=p['workflow_template'];wf=read(HERE/relative(row['path']));need(pin(wf)==row['pin']and wf.count(b'SOURCE_MANIFEST_SHA256=UNSTAMPED')==1,'whole workflow with one source stamp');need(m['budget']==p['bounds'],'all original clocks held');m['files']={n:pin(b)for n,b in v.items()if n not in('source-manifest.json',m['workflow'],m['workflow_alias'])};m['workflow_base']=pin(wf);v['source-manifest.json']=enc(m);wf=wf.replace(b'SOURCE_MANIFEST_SHA256=UNSTAMPED',('SOURCE_MANIFEST_SHA256='+pin(v['source-manifest.json'])['sha256']).encode())
 for n in(m['workflow'],m['workflow_alias']):v[n]=wf
 need(len(v)==388 and {n:pin(raw)for n,raw in v.items()}==p['expected_sources'][view],'entire exact default/selected388 output differs');return v,view,p['bounds']
def assemble(runtime,output,binding=None):
 v,view,bounds=render(runtime,binding);output=Path(output);need(output.is_absolute()and output.parent.is_dir()and not output.exists()and not any(x.is_symlink()for x in(output,*output.parents)),'fresh ordinary output');output.mkdir(mode=0o700)
 for n,raw in v.items():
  p=output/relative(n);p.parent.mkdir(parents=True,exist_ok=True)
  with p.open('xb')as f:f.write(raw)
 need({n:pin(raw)for n,raw in files(output).items()}=={n:pin(raw)for n,raw in v.items()},'whole emitted388 readback');return dict(status='EMITTED_EXACT_CORE388_SOURCE_ONLY',view=view,files=388,base_files=373,actual_source=None,actual_ref=None,actual_run=None,native_full4='NOT_RUN_BY_FACTORY',hardware='NOT_RUN',acceptance='NOT_GRANTED',bounds=bounds)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--runtime',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--binding',type=Path,help='Explicit exact Root component selection; never an actual run identity');a=p.parse_args();print(json.dumps(assemble(a.runtime,a.output,a.binding),sort_keys=True))
