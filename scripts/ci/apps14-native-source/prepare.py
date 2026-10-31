#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit Apps14 native115 source factory; no Git, network or actors."""
import argparse,hashlib,json,os,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE_SHA='2ca5563baf5aafbefe0eef426c792c7bf7a2d476c9c4e33b1d903bde086183ed'
OLD='scripts/ci/apps13-client-native';NEW='scripts/ci/apps14-client-native';WF='.github/workflows/native-arm-build.yml'
def need(v,message):
 if not v:raise ValueError(message)

def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())

def enc(v):return(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()

def identity(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)

def ordinary(p):need(not any(x.is_symlink()for x in(p,*p.parents)),'ordinary no-alias ancestry')

def read(p):
 p=Path(p).absolute();ordinary(p);before=p.lstat();need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<=before.st_size<=16*1024**2,'bounded ordinary single-link source')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  need(identity(before)==identity(os.fstat(fd)),'opened source identity')
  with os.fdopen(os.dup(fd),'rb')as f:raw=f.read(before.st_size+1)
  need(len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(p.lstat()),'whole stable source');return raw
 finally:os.close(fd)

def tree(root,checkout=False):
 root=Path(root).absolute();ordinary(root);need(root.is_dir(),'ordinary full source root');out={}
 for directory,dirs,names in os.walk(root,followlinks=False):
  directory=Path(directory)
  if checkout and directory==root:dirs[:]=[n for n in dirs if n!='.git'];names=[n for n in names if n!='.git']
  for n in dirs:need(stat.S_ISDIR((directory/n).lstat().st_mode),'ordinary source directory')
  for n in names:p=directory/n;out[p.relative_to(root).as_posix()]=read(p)
 return out

def pins(value):return {n:pin(b)for n,b in value.items()}

def profile():
 raw=read(HERE/'profile.json');need(pin(raw)['sha256']==PROFILE_SHA,'whole fixed Apps14 source profile');v=json.loads(raw)
 need(len(v['parent'])==len(v['after'])==115 and len(v['recipe'])==42 and len(v['payload'])==21 and len(v['held'])==75,'exact complete source closure');return v
def render(parent,recipe):
 c=profile();before=tree(parent,True);recipes=tree(recipe,True);need(pins(before)==c['parent']and pins(recipes)==c['recipe'],'whole pinned Apps13 native115 and genuine Apps14 recipe42')
 payload=tree(HERE/'payload');need(pins(payload)==c['payload'],'whole readable native payload21')
 out={n:b for n,b in before.items()if not n.startswith(('packages/tools/cachy-asahi-apps13/',OLD+'/'))and n not in(WF,'.github/workflows/native-arm-apps13-client.yml')};need(pins(out)==c['held'],'all75 original infrastructure leaves held')
 for n,b in recipes.items():
  if n.startswith('packages/tools/cachy-asahi-apps14/'):out[n]=b
  else:need(out.get(n)==b,'Runtime1/client-v2/recipe helper bytes held')
 for n,b in payload.items():out[NEW+'/'+n]=b
 template=out[NEW+'/workflow.yml'].decode();materialized=template.replace('@JOB_SHA256@',pin(out[NEW+'/job.py'])['sha256']).replace('@MANIFEST_SHA256@',pin(out[NEW+'/source-manifest.json'])['sha256']).encode();out[WF]=out['.github/workflows/native-arm-apps14-client.yml']=materialized
 need(pins(out)==c['after'],'whole exact Apps14 native115 before output')
 for n,b in out.items():
  if n.endswith('.py'):compile(b,n,'exec')
 return out
def emit(parent,recipe,output):
 parent,recipe,output=map(lambda p:Path(p).absolute(),(parent,recipe,output));need(all(p==p.resolve()for p in(parent,recipe,output)),'normalized source and output paths');ordinary(output);need(not output.exists()and output.parent.is_dir(),'fresh ordinary destination')
 for source in(parent,recipe,HERE):need(not output.is_relative_to(source)and not source.is_relative_to(output),'disjoint source/output')
 bodies=render(parent,recipe);output.mkdir(mode=0o700)
 for n,b in sorted(bodies.items()):
  p=output/n;p.parent.mkdir(parents=True,exist_ok=True)
  with p.open('xb')as f:f.write(b)
 need(pins(tree(output))==profile()['after'],'whole emitted115');return dict(status='SOURCE_ONLY_EXACT_APPS14_NATIVE115',files=115,expected_source=profile()['expected_source'],recipe_source=profile()['recipe_source'],actual_source=None,actual_ref=None,actual_run=None,native='NOT_RUN',acceptance=False)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('parent','recipe','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();print(json.dumps(emit(a.parent,a.recipe,a.output),sort_keys=True))
