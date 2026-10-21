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
 root=Path(root).absolute();m=obj(root/'source-manifest.json');need(m['status']=='SOURCE_ONLY_CURRENT606_WELCOME8_NATIVE_GUI_STOP_RETRY_NOT_ACCEPTED'and m['actual_source']is m['actual_ref']is m['actual_run']is None,'finite Welcome8 NULL source manifest');closed(root,{**m['files'],'source-manifest.json':pin(read(root/'source-manifest.json'))})
 parent=obj(root/'welcome8-parent.json');need(parent['source']=='bb72a0fc5e84af5621f0b783056137efdd780282'and len(parent['files'])==540 and parent['actual']is None,'whole corrective540 predecessor required');before=parent['files'];bodies=parent['before_bodies']
 def prior_read(p,cap=16*1024**2):
  name=str(Path(p).relative_to(root));raw=base64.b64decode(bodies[name],validate=True)if name in bodies else read(p,cap);need(name in before and pin(raw)==before[name]and len(raw)<=cap,'whole prior source body '+name);return raw
 def prior_closed(where,rows):
  prefix=''if where==root else str(where.relative_to(root))+'/'
  need({n.removeprefix(prefix):w for n,w in before.items()if n.startswith(prefix)}==rows,'entire original closed namespace')
  for n,w in rows.items():need(pin(prior_read(where/n))==w,'entire original source identity')
  return rows
 old=types.ModuleType('_whole_corrective540_admission');old.__file__=str(root/'admission.py');exec(compile(base64.b64decode(bodies['admission.py'],validate=True),'<whole-original540-admission>','exec'),old.__dict__);old.read=prior_read;old.obj=lambda p:json.loads(prior_read(p));old.closed=prior_closed;proof=old.prove(root)
 graph=obj(root/'factory/profile.json');expected=dict(line.split()for line in read(root/'factory/expected606.lock').decode().splitlines());need(len(expected)==606 and expected['cachy-asahi-welcome']=='0.1.0-8'and graph['versions']['cachy-asahi-doctor']=='0.2.0-1'and graph['native_archives']['cachy-asahi-welcome']==dict(bytes=40400,sha256='1cbb8f5f9fd5f072ba2974837cf10dc7e90edbd236cbf3a34916cd0af3d4b240'),'exact accepted Welcome8 graph operand')
 return dict(proof,status='PASS_WHOLE_CORRECTIVE540_AND_WELCOME8_INSTALLED_STOP_RETRY_SOURCE_ONLY',files=len(m['files'])+1,Welcome8_GUI='NOT_RUN')
