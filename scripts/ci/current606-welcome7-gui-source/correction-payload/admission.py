# SPDX-License-Identifier: MIT
"""Whole genuine549 inverse plus one finite source-bound Apps8 input adoption."""
import base64,hashlib,json,os,stat,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
WORKFLOWS={'.github/workflows/native-arm-build.yml','.github/workflows/native-arm-current606-welcome8-gui.yml'}
def need(ok,why):
 if not ok:raise ValueError(why)
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def read(p,cap=16*1024**2):
 p=Path(p);need(p.is_absolute()and not any(q.is_symlink()for q in(p,*p.parents)),'ordinary absolute source ancestry');s=p.lstat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size<=cap,'bounded singlelink source leaf');b=p.read_bytes();t=p.lstat();fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns');need(len(b)==s.st_size and all(getattr(s,k)==getattr(t,k)for k in fields),'stable whole source leaf');return b
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
 root=Path(root).absolute();m=obj(root/'source-manifest.json');need(m['status']=='SOURCE_ONLY_CURRENT606_WELCOME8_APPS8_NO_NEW_GUI_ACCEPTANCE'and m['actual_source']is m['actual_ref']is m['actual_run']is None,'finite Apps8 successor NULL actual');closed(root,{**m['files'],'source-manifest.json':pin(read(root/'source-manifest.json'))})
 parent=obj(root/'apps8-parent.json');before=parent['files'];bodies=parent['before_bodies'];need(parent['source']=='4e63aa1c67898417d3a47335c0af1cc8e0b7fa3f'and len(before)==549 and parent['actual']is None,'whole genuine549 parent required')
 def prior_read(path,cap=16*1024**2):
  n=str(Path(path).relative_to(root));raw=base64.b64decode(bodies[n],validate=True)if n in bodies else read(path,cap);need(n in before and pin(raw)==before[n]and len(raw)<=cap,'whole549 exact operand '+n);return raw
 def prior_closed(where,wanted):
  prefix=''if where==root else str(where.relative_to(root))+'/'
  need({n.removeprefix(prefix):w for n,w in before.items()if n.startswith(prefix)}==wanted,'whole549 original namespace')
  for n,w in wanted.items():need(pin(prior_read(where/n))==w,'whole549 original leaf')
  return wanted
 old=types.ModuleType('_whole_original549_admission');old.__file__=str(root/'admission.py');exec(compile(base64.b64decode(bodies['admission.py'],validate=True),'<whole-original549-admission>','exec'),old.__dict__);old.read=prior_read;old.obj=lambda p:json.loads(prior_read(p));old.closed=prior_closed;fact=old.prove(root)
 selection=obj(root/'apps8-selection.json');s=selection['selection'];need(selection['status']=='ROOT_BOUND_ACCEPTED_APPS8_INPUTS_ONLY_NO_GUI_AUTHORITY'and s is not None and s['actual']is None and selection['actual_source']is selection['actual_ref']is selection['actual_run']is None,'explicit accepted Apps8 input only')
 req=obj(root/'input-policy33.json')['packages'];need(len(req)==33 and req['cachy-asahi-apps']==s['package'],'exact one incoming Apps8 row');expected=dict(l.split()for l in read(root/'factory/expected606.lock').decode().splitlines());prior=dict(l.split()for l in prior_read(root/'factory/expected606.lock').decode().splitlines());need(len(expected)==606 and expected==dict(prior,**{'cachy-asahi-apps':'0.1.0-8'}),'all605 expected operands held')
 p=obj(root/'factory/profile.json');need(p['expected606']==pin(read(root/'factory/expected606.lock'))and p['versions']['cachy-asahi-apps']=='0.1.0-8'and p['native_archives']['cachy-asahi-apps']==dict(bytes=s['package']['size'],sha256=s['package']['sha256']),'exact source-selected Apps8 package and graph')
 need(read(root/'factory/install606.py').count(("hexdigest()=='"+p['expected606']['sha256']+"'").encode())==1,'actual installer guard bound to complete source-selected606 lock')
 need(read(root/'factory/original606.lock')==prior_read(root/'factory/original606.lock'),'original Apps6 desktop baseline held')
 return dict(fact,status='PASS_WHOLE549_PLUS_ACCEPTED_APPS8_INPUT_SOURCE_ONLY',files=len(m['files'])+1,native_GUI='NOT_RUN')
