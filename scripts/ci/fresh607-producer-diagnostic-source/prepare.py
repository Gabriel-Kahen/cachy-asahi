#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reproduce fixed producer-diagnostic1185 from public1182; source bytes only."""
import argparse,base64,hashlib,json,os,stat,sys,types,zlib
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE_SHA='685b9e15966f43fdfa292f74ef6a8e1839d052414d547dfc6a53d10f09927c05'
CLOCKS=dict(source=300,build=5400,term=10,kill=5,diagnostic_data=393216,existing_report=458752,transport_member=4194304)
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
 need((p['input_source'],p['output_source'],p['input_files'],p['output_files'])==('9a67f3e507c57f68ece48c253cdade47648f970c','2235c1d3c3b3de6d8a2ff30f66c5fd0df56c2ef6',1182,1185)and p['clocks']==CLOCKS and all(p[n]is None for n in('source','ref','run','actual'))and p['native_acceptance']is False,'exact source-only context and unchanged clocks')
 for n,w in p['fixed_files'].items():need(pin(read(HERE/n))==w,'fixed source map/helper drift: '+n)
 return p
def helper():
 m=types.ModuleType('_fixed_producer_diagnostic_transform');m.__file__=str(HERE/'transform.py.in');m.need=need;m.pin=pin;m.enc=enc;exec(compile(read(Path(m.__file__)),m.__file__,'exec'),vars(m));return m
def render(old,p):
 G=helper();before=decode(read(HERE/'input-source.json'));need({n:pin(v)for n,v in old.items()}==before and len(old)==1182,'whole pinned public1182 source input')
 profile=decode(read(HERE/'parent-context.json'));codecs=decode(read(HERE/'parent-codecs.json'));need(set(codecs)=={G.RUN,G.GUARD,G.MANIFEST,*G.ALIASES},'five fixed published before codecs')
 # Preserve published codec bytes across linked zlib versions; decode only DATA,
 # and require every byte equal to the supplied readable public parent operand.
 for n,value in codecs.items():
  decoder=zlib.decompressobj();body=decoder.decompress(base64.b64decode(value,validate=True),16*1024**2+1);need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail and body==old[n],'complete exact public parent codec DATA')
 profile.update(before=before,parent_authorization=before,before_bodies_zlib=codecs);profile['parent_git']['files']=before
 template=read(HERE/'producer_source.py.in');need(pin(template)==profile['proof_template'],'whole readable source guard template');raw=enc(profile);proof=template.replace(b"PARENT_PIN='PARENT_PIN_PLACEHOLDER'",b"PARENT_PIN='"+pin(raw)['sha256'].encode()+b"'",1)
 out=G.transformed(old,read(HERE/'producer_diagnostic.py'),proof,raw)
 need(len(out)==1185 and sum(out[n]==v for n,v in old.items())==1177 and len(set(out)-set(old))==3,'1177 held/five changed/three added')
 need({n:pin(v)for n,v in out.items()}==decode(read(HERE/'output-source.json')),'exact public1185 or byte-identical frozen NULL output');return out
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
