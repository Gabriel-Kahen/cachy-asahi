#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit exact failure-retaining563 from immutable555; source-only fresh graph trial."""
import argparse,base64,hashlib,json,shutil,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes': 2500, 'sha256': '79b591ef6a4ce76c1b1695e095e4cef6de869b4a669afce31e63e94a12e30f88'}
I='latest/implementation/';MANIFEST='latest/source-manifest.json';GUARD=I+'latest_guard.py'
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def ordinary(path):
 path=Path(path).absolute();need('..'not in path.parts and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary explicit source/output ancestry');return path
def read(path):
 path=ordinary(path);s=path.lstat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<=s.st_size<=16*1024**2,'bounded singlelink whole source');raw=path.read_bytes();identity=lambda v:(v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid,v.st_nlink,v.st_size,v.st_mtime_ns,v.st_ctime_ns);need(len(raw)==s.st_size and identity(path.lstat())==identity(s),'whole stable atime-independent source read');return raw
def files(root):
 root=ordinary(root);need(root.is_dir(),'original whole source directory');out={}
 for p in sorted(root.rglob('*')):
  n=p.relative_to(root)
  if n.parts[0]=='.git':continue
  need(not p.is_symlink()and(p.is_dir()or p.is_file()),'ordinary closed source nodes')
  if p.is_file():out[n.as_posix()]=pin(read(p))
 return out

def inputs():
 raw=read(HERE/'profile.json');need(pin(raw)==PROFILE,'whole fixed source-only profile');profile=json.loads(raw);bodies={}
 for name,want in profile['support'].items():
  body=read(HERE/name);need(pin(body)==want,'exact profile support body '+name);bodies[name]=body
 p=json.loads(bodies['lifecycle-successor.json']);expected=json.loads(bodies['source559.json']);final=json.loads(bodies['source561.json']);q=json.loads(bodies['prefill-path-successor.json']);need(len(p['before'])==555 and len(expected)==559 and len(final)==561 and q['before']==expected and p['publication']['source']==profile['source_before']and set(p['added'])=={I+n for n in('latest_descriptor.py','latest_graph_timing.py','lifecycle_successor.py','lifecycle-successor.json')},'one exact555 to559 profile, no generic source input');r=json.loads(bodies['failure-retention-successor.json']);last=json.loads(bodies['source563.json']);need(r['before']==final and len(last)==563,'whole fixed561-to563 failure-data profile');return profile,p,expected,final,q,r,last,bodies

def emit(source,output,profile='fresh_descriptor563'):
 need(profile=='fresh_descriptor563','explicit corrected finite graph profile');_,p,expected,final,q,r,last,bodies=inputs();source=ordinary(source);output=ordinary(output);need(files(source)==p['before'],'entire original555 source before any output');need(not output.exists()and output.parent.is_dir()and not output.is_relative_to(source)and not source.is_relative_to(output),'fresh separate source-only output');shutil.copytree(source,output,ignore=shutil.ignore_patterns('.git'));need(files(output)==p['before'],'whole original555 copied without drift')
 for name,edits in p['edits'].items():
  text=read(output/name).decode()
  for old,new in edits:need(text.count(old)==1,'one exact source-owned query/timing/reporting seam');text=text.replace(old,new,1)
  inverse=text
  for old,new in reversed(edits):need(inverse.count(new)==1,'one exact inverse seam');inverse=inverse.replace(new,old,1)
  need(inverse.encode()==read(source/name),'whole original runtime/test body inverse');(output/name).write_text(text)
 for name in p['added']:(output/name).write_bytes(bodies[Path(name).name])
 proof_pin=pin(bodies['lifecycle-successor.json']);text=read(output/GUARD).decode()+'\n# BEGIN_FINITE_LIFECYCLE_DESCRIPTOR_SUCCESSOR\ndef verify():\n import lifecycle_successor\n return lifecycle_successor.verify(ROOT, '+repr(I+'lifecycle-successor.json')+', '+repr(proof_pin)+')\n';(output/GUARD).write_text(text)
 value=json.loads(read(output/MANIFEST));value['files']={n:v for n,v in files(output).items()if n not in{MANIFEST,*p['workflows']}};(output/MANIFEST).write_bytes(encoded(value));manifest=pin(read(output/MANIFEST))
 for name in p['workflows']:
  raw=read(output/name);old=p['before'][MANIFEST]['sha256'].encode();need(raw.count(old)==1,'one exact source stamp, original workflow/clocks held');(output/name).write_bytes(raw.replace(old,manifest['sha256'].encode(),1))
 actual=files(output);need(actual==expected,'entire intermediate559 exact; never returned as runnable source')
 for name,edits in q['edits'].items():
  text=read(output/name).decode()
  for old,new in edits:need(text.count(old)==1,'one exact actual-failed prefill argv/count seam');text=text.replace(old,new,1)
  (output/name).write_text(text)
 for name in q['added']:(output/name).write_bytes(bodies[Path(name).name])
 proof_pin=pin(bodies['prefill-path-successor.json']);text=read(output/GUARD).decode()+'\n# BEGIN_EXACT_PREFILL_PATH_SUCCESSOR\ndef verify():\n import prefill_path_successor\n return prefill_path_successor.verify(ROOT, '+repr(I+'prefill-path-successor.json')+', '+repr(proof_pin)+')\n';(output/GUARD).write_text(text)
 value=json.loads(read(output/MANIFEST));value['files']={n:v for n,v in files(output).items()if n not in{MANIFEST,*q['workflows']}};(output/MANIFEST).write_bytes(encoded(value));manifest=pin(read(output/MANIFEST))
 for name in q['workflows']:
  raw=read(output/name);old=q['before'][MANIFEST]['sha256'].encode();need(raw.count(old)==1,'one exact corrected source stamp');(output/name).write_bytes(raw.replace(old,manifest['sha256'].encode(),1))
 actual=files(output);need(actual==final,'entire corrected561 exact intermediate; never returned as output')
 import importlib.util
 spec=importlib.util.spec_from_file_location('_maintained_failed_public_data',HERE/'failure_retention.py');F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
 (output/r['transport']).write_text(F.derive_transport(read(output/r['transport']).decode()))
 for name,edits in r['edits'].items():
  text=read(output/name).decode()
  for old,new in edits:need(text.count(old)==1,'one exact failure-data source seam');text=text.replace(old,new,1)
  (output/name).write_text(text)
 for name in r['added']:(output/name).write_bytes(bodies[Path(name).name])
 proof_pin=pin(bodies['failure-retention-successor.json']);text=read(output/GUARD).decode()+'\n# BEGIN_BOUNDED_FAILURE_RETENTION_SUCCESSOR\ndef verify():\n import failure_retention\n return failure_retention.verify(ROOT, '+repr(I+'failure-retention-successor.json')+', '+repr(proof_pin)+')\n';(output/GUARD).write_text(text)
 value=json.loads(read(output/MANIFEST));value['files']={n:v for n,v in files(output).items()if n not in{MANIFEST,*r['workflows']}};(output/MANIFEST).write_bytes(encoded(value));manifest=pin(read(output/MANIFEST))
 for name in r['workflows']:
  raw=read(output/name);old=r['before'][MANIFEST]['sha256'].encode();need(raw.count(old)==1,'one failure-data source stamp, workflow/clocks held');(output/name).write_bytes(raw.replace(old,manifest['sha256'].encode(),1))
 actual=files(output);need(actual==last,'whole exact published563 failure-data source');return dict(status='SOURCE_ONLY_EXACT563_FAILED_PUBLIC_DATA_CAPTURE_UNQUALIFIED',files=actual,consumer_seconds=1800,owner_seconds=6600,actual=None,native='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')
if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--profile',choices=('fresh_descriptor563',),default='fresh_descriptor563');parser.add_argument('--authorization',type=Path,required=True);a=parser.parse_args();authorization=ordinary(a.authorization);need(not authorization.exists()and authorization.parent.is_dir(),'fresh output authorization');result=emit(a.source,a.output,a.profile)
 with authorization.open('xb')as stream:stream.write(encoded(result))
