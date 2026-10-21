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
 root=Path(root).absolute();m=obj(root/'source-manifest.json');need(m['status']=='SOURCE_ONLY_CURRENT606_WELCOME7_NATIVE_GUI_NOT_ACCEPTED'and m['actual_source']is m['actual_ref']is m['actual_run']is None,'finite NULL source manifest');closed(root,{**m['files'],'source-manifest.json':pin(read(root/'source-manifest.json'))})
 v=obj(root/'derivation.json');need(v['factory_source']=='ffe2c392834e4f70fc31fbc41d801f99bc8ef758'and v['original_source']=='4bbf44cd6962c17956bce7dc2dfcc50801cd0634'and len(v['original_files'])==348 and len(v['factory_files'])==53,'entire original348 and published53 source contexts');closed(root/'original',v['original_files'])
 need(set(v['changes'])=={'factory/context606.py','factory/install606.py'},'only two explicit FDK graph successor leaves')
 for n,w in v['factory_files'].items():
  name='factory/'+n
  if name in v['changes']:
   row=v['changes'][name];need(pin(base64.b64decode(row['before'],validate=True))==row['before_pin']==w and pin(read(root/name))==row['after_pin'],'entire held factory beforebody and exact successor')
  else:need(pin(read(root/name))==w,'published factory held leaf '+n)
 need(all(pin(read(root/'support'/n))==w for n,w in v['support'].items()),'whole original native signing/verifier modules')
 return dict(status='PASS_CLOSED_SOURCE_AND_EXACT_FDK_GRAPH_SUCCESSOR_ONLY',files=len(m['files'])+1,original348=348,published_factory53=53,actual_run=None)
