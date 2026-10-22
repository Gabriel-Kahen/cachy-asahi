# SPDX-License-Identifier: MIT
"""Finite whole-source, original348 and published53 derivation proof."""
import base64,hashlib,json,os,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
WORKFLOWS={'.github/workflows/native-arm-build.yml','.github/workflows/native-arm-current606-welcome7-gui.yml'}
def need(ok,why):
 if not ok:raise ValueError(why)
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def read(p,cap=16*1024**2):
 p=Path(p);need(p.is_absolute()and not any(q.is_symlink()for q in(p,*p.parents)),'ordinary absolute source ancestry');s=p.lstat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size<=cap,'bounded singlelink source leaf');b=p.read_bytes();after=p.lstat();fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns');need(all(getattr(s,k)==getattr(after,k)for k in fields),'source leaf changed during read');return b
def obj(p):return json.loads(read(p))
def closed(root,rows):
 root=Path(root).absolute();actual=set()
 for b,ds,fs in os.walk(root):
  if Path(b)==root:ds[:]=[n for n in ds if n!='.git'];fs=[n for n in fs if n!='.git']
  for n in ds:need(not(Path(b)/n).is_symlink(),'source directory alias')
  actual.update(str((Path(b)/n).relative_to(root))for n in fs)
 need(actual==set(rows),'whole closed source map')
 for n,w in rows.items():need(n and not Path(n).is_absolute()and '..'not in Path(n).parts and pin(read(root/n))==w,'source identity '+n)
 return rows
def prove(root):
 import types
 root=Path(root).absolute();manifest=obj(root/'source-manifest.json');need(manifest['status']=='SOURCE_ONLY_CURRENT606_WELCOME8_GUEST_LOADER_NOT_ACCEPTED'and manifest['actual_source']is manifest['actual_ref']is manifest['actual_run']is None,'finite guest loader NULL actual');closed(root,{**manifest['files'],'source-manifest.json':pin(read(root/'source-manifest.json'))})
 parent=obj(root/'loader-parent.json');before=parent['files'];need(parent['source']=='865cc33c8f114c15cef75b3472fbb8d1f4e8da06'and len(before)==548 and parent['actual']is None,'entire genuine published548 parent');bodies=parent['before_bodies']
 def prior_read(path,cap=16*1024**2):
  name=str(Path(path).relative_to(root));body=base64.b64decode(bodies[name],validate=True)if name in bodies else read(path,cap);need(name in before and pin(body)==before[name]and len(body)<=cap,'whole548 exact beforebody '+name);return body
 def prior_closed(where,wanted):
  prefix=''if where==root else str(where.relative_to(root))+'/'
  need({n.removeprefix(prefix):w for n,w in before.items()if n.startswith(prefix)}==wanted,'whole548 original closed namespace')
  for n,w in wanted.items():need(pin(prior_read(where/n))==w,'whole548 original leaf')
  return wanted
 prior=types.ModuleType('_whole_genuine548_admission');prior.__file__=str(root/'admission.py');exec(compile(base64.b64decode(bodies['admission.py'],validate=True),'<whole-genuine548-admission>','exec'),prior.__dict__);prior.read=prior_read;prior.obj=lambda p:json.loads(prior_read(p));prior.closed=prior_closed;fact=prior.prove(root)
 return dict(fact,status='PASS_WHOLE_PUBLISHED548_AND_DEFINED_GUEST_LOADER_SOURCE_ONLY',files=len(manifest['files'])+1,native_GUI='NOT_RUN')
