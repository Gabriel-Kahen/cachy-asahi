#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit exact Apps10 native source115 factory; no Git, network or actors."""
import argparse,hashlib,json,os,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE_SHA='5796a42afdf2ebee7a9bf6db35c3cb1a334dd872db1bda5082ef774e6f531c2d'
LANE='scripts/ci/apps10-client-native';OLDLANE='scripts/ci/apps9-client-native'
WF='.github/workflows/native-arm-build.yml';ALIAS='.github/workflows/native-arm-apps10-client.yml'
RECIPE='0c7fa965b38939df65034b4003260fff99097999'
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
 raw=read(HERE/'profile.json');need(pin(raw)['sha256']==PROFILE_SHA,'whole fixed Apps10 profile');v=json.loads(raw)
 need(len(v['parent'])==114 and len(v['recipe'])==42 and len(v['after'])==115 and len(v['payload'])==len(v['edits'])==5,'exact114/42/115 and five finite replacements')
 return v
def render(parent,recipe):
 c=profile();parent,recipe=Path(parent).absolute(),Path(recipe).absolute();before=tree(parent,True);recipes=tree(recipe,True)
 need(pins(before)==c['parent'],'whole pinned Apps9 parent114');need(pins(recipes)==c['recipe'],'whole pinned genuine recipe42')
 payload=tree(HERE/'payload');need(pins(payload)==c['payload'],'whole five readable payloads')
 out=dict(before)
 # Recipe/controller namespaces are explicit; all original infrastructure stays held.
 for n in list(out):
  if n.startswith('packages/tools/cachy-asahi-apps9/')or n in(WF,'.github/workflows/native-arm-apps9-client.yml'):del out[n]
  elif n.startswith(OLDLANE+'/'):
   raw=out.pop(n);name=n.replace(OLDLANE,LANE,1);text=raw.decode()
   for a,b in(('apps9','apps10'),('Apps9','Apps10'),('APPS9','APPS10'),('0.1.0-9','0.1.0-10')):text=text.replace(a,b)
   out[name]=text.encode()
 for n,w in c['recipe'].items():
  if n.startswith('packages/tools/cachy-asahi-apps10/'):out[n]=read(recipe/n)
  else:need(n in out and pin(out[n])==w,'fixed Runtime1/client-v2/helpers unchanged across recipe')
 for n,edits in c['edits'].items():
  text=out[n].decode();before=text
  for a,b,count in edits:need(text.count(a)==count,'one finite stage control source operand '+n);text=text.replace(a,b,count)
  inverse=text
  for a,b,count in reversed(edits):need(inverse.count(b)==count,'unique source inverse '+n);inverse=inverse.replace(b,a,count)
  need(inverse==before,'whole old native body inverse '+n);need(text.encode()==payload[n],'readable finite payload inverse '+n);out[n]=payload[n]
 policy=json.loads(out[LANE+'/input-policy.json']);policy['candidate_source']=RECIPE;policy['status']='ROOT_BOUND_FINAL_PRODUCT_SOURCES'
 for role,row in policy['products'].items():
  row['source_sha']=RECIPE if role=='apps'else'9f9eae97843531a41b201655100f13984d9ac01e'
  if role=='apps':
   prefix='packages/tools/cachy-asahi-apps10/';row['source_files']={n.removeprefix(prefix):w for n,w in c['recipe'].items()if n.startswith(prefix)};row['recipe_sha256']=row['source_files']['PKGBUILD']['sha256'];row['check_markers']+=['test_owned_child_sigterm_and_timeout_leave_inflight_phase_no_output']
 out[LANE+'/input-policy.json']=enc(policy)
 # Manifest excludes itself/two materialized aliases as the parent did.
 mf=json.loads(out[LANE+'/source-manifest.json']);mf.update(status='FROZEN_ROOT_FINAL_SOURCES',files={n:pin(b)for n,b in sorted(out.items())if n!=LANE+'/source-manifest.json'},workflow_ref='refs/heads/codex/apps10-pair-native-v1');out[LANE+'/source-manifest.json']=enc(mf)
 template=out[LANE+'/workflow.yml'].decode();text=template.replace('@JOB_SHA256@',pin(out[LANE+'/job.py'])['sha256']).replace('@MANIFEST_SHA256@',pin(out[LANE+'/source-manifest.json'])['sha256']);out[WF]=out[ALIAS]=text.encode();need(len(out)==115 and len(mf['files'])==112,'closed115 native child and original<=128 source cap')
 for n,b in out.items():
  if n.endswith('.py'):compile(b,n,'exec')
 need({n:pin(b)for n,b in out.items()}==c['after'],'whole exact115 result before output')
 return out
def emit(parent,recipe,output):
 parent,recipe,output=Path(parent).absolute(),Path(recipe).absolute(),Path(output).absolute();ordinary(output)
 need(not output.exists()and output.parent.is_dir(),'fresh ordinary destination')
 for source in(parent,recipe,HERE):need(not output.is_relative_to(source)and not source.is_relative_to(output),'disjoint source/output')
 bodies=render(parent,recipe)
 output.mkdir(mode=0o700)
 for n,b in sorted(bodies.items()):
  p=output/n;p.parent.mkdir(parents=True,exist_ok=True)
  with p.open('xb')as f:f.write(b)
 need(pins(tree(output))==profile()['after'],'whole emitted115')
 return dict(status='SOURCE_ONLY_EXACT115',files=115,expected_source=profile()['expected_source'],recipe_source=RECIPE,actual_source=None,actual_ref=None,actual_run=None,native='NOT_RUN',acceptance=False)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('parent','recipe','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();print(json.dumps(emit(a.parent,a.recipe,a.output),sort_keys=True))
