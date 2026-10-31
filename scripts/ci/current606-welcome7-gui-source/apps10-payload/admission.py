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

def source_context(root):
 root=Path(root).absolute();m=obj(root/'source-manifest.json');need(m['status']=='SOURCE_ONLY_CURRENT606_WELCOME8_APPS10_NO_NEW_GUI_ACCEPTANCE'and m['actual_source']is m['actual_ref']is m['actual_run']is None,'finite Apps10 source NULL actual');closed(root,{**m['files'],'source-manifest.json':pin(read(root/'source-manifest.json'))})
 parent=obj(root/'apps10-parent.json');before=parent['files'];bodies=parent['before_bodies'];need(parent['source']=='5c22c8dbac8b6a79ebbbd19141ace4840d41e43e'and len(before)==557 and parent['actual']is None,'whole genuine557 parent required')
 def prior_read(path,cap=16*1024**2):
  n=str(Path(path).relative_to(root));raw=base64.b64decode(bodies[n],validate=True)if n in bodies else read(path,cap);need(n in before and pin(raw)==before[n]and len(raw)<=cap,'whole557 exact operand '+n);return raw
 def prior_closed(where,wanted):
  prefix=''if where==root else str(where.relative_to(root))+'/'
  need({n.removeprefix(prefix):w for n,w in before.items()if n.startswith(prefix)}==wanted,'whole557 original namespace')
  for n,w in wanted.items():need(pin(prior_read(where/n))==w,'whole557 original leaf')
  return wanted
 old=types.ModuleType('_whole_original556_admission');old.__file__=str(root/'admission.py');exec(compile(base64.b64decode(bodies['admission.py'],validate=True),'<whole-original556-admission>','exec'),old.__dict__);old.read=prior_read;old.obj=lambda p:json.loads(prior_read(p));old.closed=prior_closed;fact=old.prove(root)
 value=obj(root/'apps10-selection.json');need(set(value)=={'status','selection','actual_source','actual_ref','actual_run'}and value['actual_source']is value['actual_ref']is value['actual_run']is None,'source-only exact Apps10 selection shape');selection=value['selection']
 req=obj(root/'input-policy33.json')['packages'];prior_req=json.loads(prior_read(root/'input-policy33.json'))['packages'];need(len(req)==33 and {k:v for k,v in req.items()if k!='cachy-asahi-apps'}=={k:v for k,v in prior_req.items()if k!='cachy-asahi-apps'},'all32 nonApps inputs including exact Welcome held')
 expected=dict(l.split()for l in read(root/'factory/expected606.lock').decode().splitlines());prior=dict(l.split()for l in prior_read(root/'factory/expected606.lock').decode().splitlines());need(len(expected)==606 and expected==dict(prior,**{'cachy-asahi-apps':'0.1.0-10'}),'all605 expected operands held')
 p=obj(root/'factory/profile.json');old_profile=json.loads(prior_read(root/'factory/profile.json'));need(p['versions']==dict(old_profile['versions'],**{'cachy-asahi-apps':'0.1.0-10'})and p['expected606']==pin(read(root/'factory/expected606.lock'))and {k:v for k,v in p['native_archives'].items()if k!='cachy-asahi-apps'}=={k:v for k,v in old_profile['native_archives'].items()if k!='cachy-asahi-apps'},'one Apps10 version/archive only; all other products held')
 need(read(root/'factory/install606.py').count(("hexdigest()=='"+p['expected606']['sha256']+"'").encode())==1 and read(root/'factory/original606.lock')==prior_read(root/'factory/original606.lock'),'exact installer lock and unchanged original606 baseline')
 if selection is None:
  need(value['status']=='UNBOUND_APPS10_ACCEPTED_INPUTS_REQUIRED'and req['cachy-asahi-apps']==dict(name='cachy-asahi-apps',version='0.1.0-10',archive='cachy-asahi-apps-0.1.0-10-any.pkg.tar.xz',size=None,sha256=None)and p['native_archives']['cachy-asahi-apps']is None,'unknown Apps10 archive/carrier remainsNULL')
 else:
  need(value['status']=='ROOT_BOUND_ACCEPTED_APPS10_INPUTS_ONLY_NO_GUI_AUTHORITY'and selection['actual']is None and selection['recipe_source']=='0c7fa965b38939df65034b4003260fff99097999'and selection['pair_source']=='9d1b97e0adf704fa19b534a7db610350e36a42a5'and selection['pair_run']==39758362995 and req['cachy-asahi-apps']==selection['package']and p['native_archives']['cachy-asahi-apps']==dict(bytes=selection['package']['size'],sha256=selection['package']['sha256']),'exact qualified Apps10 input/Root selected whole carrier only')
 return dict(fact,status='PASS_WHOLE557_PLUS_APPS10_SOURCE_CONTEXT_NOT_ACTOR_ADMISSION',files=len(m['files'])+1,Apps10_inputs='UNBOUND'if selection is None else'ROOT_BOUND_INPUT_ONLY',native_GUI='NOT_RUN')
def prove(root):
 fact=source_context(root);value=obj(Path(root)/'apps10-selection.json');need(value['status']=='ROOT_BOUND_ACCEPTED_APPS10_INPUTS_ONLY_NO_GUI_AUTHORITY'and value['selection']is not None,'genuine qualified Apps10 pair/public carrier required BEFORE ACTORS');return dict(fact,status='PASS_WHOLE557_PLUS_ACCEPTED_APPS10_INPUT_SOURCE_ONLY')
