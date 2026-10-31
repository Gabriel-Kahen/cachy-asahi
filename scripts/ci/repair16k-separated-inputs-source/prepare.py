#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reproduce fixed public239 from only fixed public237; source bytes, no actors."""
import argparse,base64,hashlib,json,os,stat,sys,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE_SHA='f8c213b9cfca4821b86ddfd2acf55bde2a0da63797211f49a7e1205452c46824'
CLOCKS=dict(source=300,collector=900,strict_failure=300,CLI=120,caller=610,backend=600,prepare=9000,validation=2400,job=21000)
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def enc(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def decode(raw):
 def pairs(rows):
  out={}
  for n,v in rows:need(n not in out,'duplicate JSON key');out[n]=v
  return out
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite JSON'))
def canonical(path):
 path=Path(path);need(path.is_absolute()and str(path)==os.path.normpath(str(path))and '..'not in path.parts and not any(p.is_symlink()for p in(path,*path.parents)),'canonical absolute ordinary path');return path
def read(path,cap=8*1024**2):
 path=canonical(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded ordinary single-link input');chunks=[];size=0
  while True:
   raw=os.read(fd,1024**2)
   if not raw:break
   size+=len(raw);need(size<=a.st_size,'source grew');chunks.append(raw)
  need(size==a.st_size and key(a)==key(os.fstat(fd))==key(path.lstat()),'input changed during read');return b''.join(chunks)
 finally:os.close(fd)
def source(root):
 root=canonical(root);need(root.is_dir(),'ordinary source directory');out={};directories=set()
 for path in sorted(root.rglob('*')):
  rel=path.relative_to(root)
  if rel.parts[0]=='.git':continue # Checkout administration is not product input.
  need('.git'not in rel.parts,'nested Git is foreign product source');s=path.lstat();need(stat.S_ISDIR(s.st_mode)or stat.S_ISREG(s.st_mode)and s.st_nlink==1,'ordinary product source nodes')
  if stat.S_ISREG(s.st_mode):need(stat.S_IMODE(s.st_mode)==0o644,'exact public100644 source mode');out[rel.as_posix()]=read(path)
  else:directories.add(rel.as_posix())
 need(directories=={p.as_posix()for n in out for p in Path(n).parents if p.as_posix()!='.'},'closed source directory namespace')
 return out
def settings():
 raw=read(HERE/'profile.json');need(pin(raw)['sha256']==PROFILE_SHA and not sys.flags.optimize,'whole fixed factory profile');p=decode(raw)
 need((p['input_source'],p['output_source'],p['input_files'],p['output_files'])==('eaad9c6379557e89dae557a9b9e84283a96e56d1','cd89f189f373dd5cc86450a7f07d0a1369238993',237,239)and p['clocks']==CLOCKS and all(p[n]is None for n in('source','ref','run','actual'))and p['native_acceptance']is False,'exact source-only context and unchanged clocks')
 for n,w in p['fixed_files'].items():need(pin(read(HERE/n))==w,'fixed source map/helper drift: '+n)
 return p
def helper():
 m=types.ModuleType('_fixed_separated_source_transform');m.__file__=str(HERE/'separated_source.py.in');exec(compile(read(Path(m.__file__)),m.__file__,'exec'),vars(m));return m
def render(old,p):
 G=helper();before=decode(read(HERE/'input-source.json'));need({n:pin(v)for n,v in old.items()}==before and len(old)==237,'whole pinned public237 source input')
 changed=[G.PREPARE,G.SELECTION,G.SUCCESSOR,*G.MANIFESTS,*G.WORKFLOWS];template=read(HERE/'separated_source.py.in')
 pub=dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE',source=p['input_source'],ref=p['input_ref'],files=237,git_joins=237,actual='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED');git=dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=p['input_source'],ref=p['input_ref'],files=before)
 profile=dict(status='SOURCE_ONLY_SEPARATED_IMMUTABLE_INPUTS',before=before,before_modes=dict.fromkeys(before,0o644),before_bodies={n:base64.b64encode(old[n]).decode()for n in(G.PREPARE,G.SELECTION,*G.WORKFLOWS)},successor_after=decode(old[G.SUCCESSOR])['after'],manifest_files={n:decode(old[n])['files']for n in G.MANIFESTS},guard_template=pin(template),parent_publication=pub,parent_git=git,source=None,ref=None,run=None,actual=None,hardware='NOT_RUN',release='NOT_ADMITTED')
 raw=enc(profile);need(len(raw)<=4*1024**2,'original profile4MiB cap');guard=template.replace(b'PROFILE_SHA_PLACEHOLDER',pin(raw)['sha256'].encode(),1);out=G.transformed(old,profile,guard,raw)
 need(len(out)==239 and{n for n in old if old[n]!=out[n]}==set(changed)and len(set(out)-set(old))==2,'eight changed/two added/229 held source operands');need({n:pin(v)for n,v in out.items()}==decode(read(HERE/'output-source.json')),'exact public239 or byte-identical frozen NULL output')
 return out
def paths(input_root,output,authorization):
 input_root=canonical(input_root);output=canonical(output);authorization=canonical(authorization)
 for p in(output,authorization):
  need(p.parent.is_dir()and not os.path.lexists(p),'fresh output/authorization');need(not any('native-actual'in x.name for x in(p,*p.parents)),'actual namespaces are not factory outputs')
  for root in(input_root,HERE):need(not p.is_relative_to(root)and not root.is_relative_to(p),'output/authorization disjoint from input/factory')
 need(not output.is_relative_to(authorization)and not authorization.is_relative_to(output),'mutually disjoint output and authorization');return input_root,output,authorization
def prepare(input_root,output,authorization,context):
 input_root,output,authorization=paths(input_root,output,authorization);need(context in('known','null'),'explicit known or null context');p=settings();old=source(input_root);out=render(old,p)
 result=dict(status='REPRODUCED_EXACT_SOURCE_BYTES_ONLY_NOT_NATIVE_AUTHORITY',context=context,public_input_source=p['input_source'],public_output_source=p['output_source']if context=='known'else None,files={n:pin(v)for n,v in sorted(out.items())},source=None,ref=None,run=None,actual=None,native_acceptance=False,hardware='NOT_RUN',release='NOT_ADMITTED')
 # Recheck complete source and maintained inputs immediately before any output.
 need(source(input_root)==old and settings()==p,'late source/profile/helper mutation');paths(input_root,output,authorization)
 output.mkdir(mode=0o700)
 for n,raw in out.items():
  path=output/n;path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as stream:stream.write(raw)
  path.chmod(0o644)
 with authorization.open('xb')as stream:stream.write(enc(result))
 return result
if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--authorization',type=Path,required=True);parser.add_argument('--context',choices=('known','null'),required=True);a=parser.parse_args();v=prepare(a.source,a.output,a.authorization,a.context);print(json.dumps(dict(status=v['status'],files=len(v['files']),actual=None)))
