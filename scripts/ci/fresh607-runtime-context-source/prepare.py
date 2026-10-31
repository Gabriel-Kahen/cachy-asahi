#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reproduce the closed source-only1192 installer from its exact public1189 parent."""
import argparse,hashlib,json,os,stat,sys,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
MAX=16*1024**2
PROFILE_SHA='483ad52d93f9746c0ddf907d50e63bc70405e2837b57cf6a8df79ffe95f8024c'
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def canonical(p):
 p=Path(p).absolute();need(p==p.resolve()and not any(q.is_symlink()for q in(p,*p.parents)),'canonical ordinary path required');return p
def read(p):
 p=canonical(p);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<=s.st_size<=MAX,'bounded singlelink source required');b=bytearray()
  while chunk:=os.read(fd,min(65536,s.st_size+1-len(b))):b.extend(chunk);need(len(b)<=s.st_size,'source growth refused')
  key=lambda v:tuple(getattr(v,k)for k in('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))
  need(len(b)==s.st_size and key(s)==key(os.fstat(fd))==key(p.lstat()),'stable descriptor/path source required');return bytes(b)
 finally:os.close(fd)
def tree(root):
 result={}
 for p in root.rglob('*'):
  n=p.relative_to(root)
  if n.parts[0]=='.git':continue
  need(not p.is_symlink()and(p.is_dir()or p.is_file()),'closed ordinary parent source')
  if p.is_file():result[n.as_posix()]=read(p)
 return result
def render(parent):
 profile_raw=read(HERE/'profile.json');need(pin(profile_raw)['sha256']==PROFILE_SHA,'fixed source factory profile');profile=json.loads(profile_raw)
 inputs={n:read(HERE/n)for n in('input-source.json','output-source.json','runtime_context.py','runtime_source.py.in','runtime-parent.json')}
 need({n:pin(b)for n,b in inputs.items()}==profile['files'],'pinned complete source transform inputs')
 expected=json.loads(inputs['input-source.json']);before=tree(parent)
 need(expected['source']=='606e31cf03f66043bdbc13a44dcc8559ebe81ec7'and len(before)==1189 and {n:pin(b)for n,b in before.items()}==expected['files'],'exact entire public1189 parent required')
 # The closed source library performs only its pure byte transform here.
 # Its common API is limited to these three identical DATA helpers; no parent
 # code, source guard, producer, VM or collected result is executed.
 common=types.SimpleNamespace(need=need,pin=pin,enc=encoded);missing=object();previous=sys.modules.get('common',missing);library=types.ModuleType('_closed1192_transform');library.__file__=str(HERE/'runtime_source.py.in')
 try:
  sys.modules['common']=common;exec(compile(inputs['runtime_source.py.in'],library.__file__,'exec'),library.__dict__)
 finally:
  if previous is missing:sys.modules.pop('common',None)
  else:sys.modules['common']=previous
 out=library.transformed(before,inputs['runtime_context.py'],inputs['runtime_source.py.in'],inputs['runtime-parent.json']);wanted=json.loads(inputs['output-source.json'])
 need(wanted['source']=='3a7cacaee84de54200acabaca2769fb5e757fa25'and len(out)==1192 and {n:pin(b)for n,b in out.items()}==wanted['files']and wanted['actual']is None,'exact entire published1192 source output required')
 need(tree(parent)==before and read(HERE/'profile.json')==profile_raw and all(read(HERE/n)==b for n,b in inputs.items()),'late parent/transform drift before output');return out
def build(parent,output):
 parent=canonical(parent);output=canonical(output)
 need(parent.is_dir()and output.parent.is_dir()and not os.path.lexists(output),'existing parent and absent output required')
 for root in(parent,HERE):need(not output.is_relative_to(root)and not root.is_relative_to(output),'output must be disjoint from source/factory')
 values=render(parent);output.mkdir(mode=0o700)
 for n,b in values.items():p=output/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
 return dict(status='REPRODUCED_SOURCE_ONLY1192_SCOPED_LEGACY_TOOLING_OWNED_CACHE',files={n:pin(b)for n,b in values.items()},actual_source=None,actual_ref=None,actual_run=None,Root_acceptance='NOT_ISSUED',hardware='NOT_RUN')
def main(argv=None):
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--parent',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args(argv);print(json.dumps(build(a.parent,a.output),sort_keys=True,indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
