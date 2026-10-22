# SPDX-License-Identifier: MIT
"""Whole physical559 input/source inverse; selected Apps14 input grants no GUI credit."""
import base64,hashlib,json,os,stat,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
PARENT='a0c8eb9ccb2994cf2f7156a6e66bfc9715b9e464'
PARENT_MAP={'bytes': 93967, 'sha256': '1bd7e0badb8ed4e6d02ea6dd0799bb04e5db8d8fc50ebefbc4cea9c9fc2e61c6'}
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
 root=Path(root).absolute();m=obj(root/'source-manifest.json');need(m['status']=='SOURCE_ONLY_CURRENT606_WELCOME8_APPS14_NO_NEW_GUI_ACCEPTANCE'and m['actual_source']is m['actual_ref']is m['actual_run']is None,'finite Apps14 source NULL actual');closed(root,{**m['files'],'source-manifest.json':pin(read(root/'source-manifest.json'))});p=obj(root/'apps14-parent.json');before=p['files'];bodies=p['before_bodies'];need(len(before)==559 and pin(enc(before))==PARENT_MAP and p['source']==PARENT and p['actual']is None,'whole physical559 source authority');ctx=p['context'];pub=ctx['publication'];need(pub==dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE',source=PARENT,ref='codex/welcome8-apps13-gui-v1',files=559,git_joins=559,actual='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')and ctx['authorization']==before and ctx['git']==dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=PARENT,ref=pub['ref'],files=before),'genuine whole559 Root publication/full Git context')
 def prior_read(path,cap=16*1024**2):
  n=str(Path(path).relative_to(root));raw=base64.b64decode(bodies[n],validate=True)if n in bodies else read(path,cap);need(n in before and pin(raw)==before[n]and len(raw)<=cap,'whole559 exact operand '+n);return raw
 def prior_closed(where,wanted):
  prefix=''if where==root else str(where.relative_to(root))+'/'
  need({n.removeprefix(prefix):w for n,w in before.items()if n.startswith(prefix)}==wanted,'whole559 original namespace')
  for n,w in wanted.items():need(pin(prior_read(where/n))==w,'whole559 source leaf')
  return wanted
 old=types.ModuleType('_whole_original559_admission');old.__file__=str(root/'admission.py');exec(compile(prior_read(root/'admission.py'),'<whole-original559-admission>','exec'),old.__dict__);old.read=prior_read;old.obj=lambda path:json.loads(prior_read(path));old.closed=prior_closed;fact=old.source_context(root)
 selection=obj(root/'apps14-selection.json');need(set(selection)=={'status','selection','actual_source','actual_ref','actual_run'}and selection['actual_source']is selection['actual_ref']is selection['actual_run']is None,'typed Apps14 NULL actual');s=selection['selection'];req=obj(root/'input-policy33.json')['packages'];prior_req=json.loads(prior_read(root/'input-policy33.json'))['packages'];need(len(req)==33 and {k:v for k,v in req.items()if k!='cachy-asahi-apps'}=={k:v for k,v in prior_req.items()if k!='cachy-asahi-apps'},'all32 nonApps operands and exact Welcome Stop held');expected=dict(r.split()for r in read(root/'factory/expected606.lock').decode().splitlines());prior=dict(r.split()for r in prior_read(root/'factory/expected606.lock').decode().splitlines());need(len(expected)==606 and expected==dict(prior,**{'cachy-asahi-apps':'0.1.0-14'}),'all605 other expected packages held');profile=obj(root/'factory/profile.json');oldprofile=json.loads(prior_read(root/'factory/profile.json'));need(profile['versions']==dict(oldprofile['versions'],**{'cachy-asahi-apps':'0.1.0-14'})and profile['expected606']==pin(read(root/'factory/expected606.lock'))and {k:v for k,v in profile['native_archives'].items()if k!='cachy-asahi-apps'}=={k:v for k,v in oldprofile['native_archives'].items()if k!='cachy-asahi-apps'},'one Apps14 archive/version only');need(read(root/'factory/install606.py').count(("hexdigest()=='"+profile['expected606']['sha256']+"'").encode())==1 and read(root/'factory/original606.lock')==prior_read(root/'factory/original606.lock'),'actual installer whole selected lock and original606 held')
 if s is None:need(selection['status']=='UNBOUND_APPS14_ACCEPTED_INPUTS_REQUIRED'and req['cachy-asahi-apps']==dict(name='cachy-asahi-apps',version='0.1.0-14',archive='cachy-asahi-apps-0.1.0-14-any.pkg.tar.xz',size=None,sha256=None)and profile['native_archives']['cachy-asahi-apps']is None,'unqualified native pair/carrier/archive remains NULL')
 else:
  current=types.ModuleType('_source_bound_apps14_identity');exec(compile(read(root/'apps14_common.py'),'<trusted-source-apps14-identity>','exec'),current.__dict__)
  need(selection['status']=='ROOT_BOUND_ACCEPTED_APPS14_INPUTS_ONLY_NO_GUI_AUTHORITY'and s['actual']is None and s['recipe_source']==current.RECIPE=='2e58341f6fa25de5167fd8a59566b3dd7f066fe3'and s['pair_source']==current.PAIR and s['pair_ref']==current.PAIR_REF=='codex/apps14-pair-native-v1'and type(current.RUN)is int and s['pair_run']==current.RUN>0 and req['cachy-asahi-apps']==s['package']and profile['native_archives']['cachy-asahi-apps']==dict(bytes=s['package']['size'],sha256=s['package']['sha256']),'genuine future accepted Apps14 pair/public carrier only')
 return dict(status='PASS_WHOLE559_PLUS_APPS14_SOURCE_CONTEXT_NOT_ACTOR_ADMISSION',files=len(m['files'])+1,parent559=fact,Apps14_inputs='UNBOUND'if s is None else'ROOT_BOUND_INPUT_ONLY',native_GUI='NOT_RUN')
def prove(root):
 fact=source_context(root);v=obj(Path(root)/'apps14-selection.json');need(v['status']=='ROOT_BOUND_ACCEPTED_APPS14_INPUTS_ONLY_NO_GUI_AUTHORITY'and v['selection']is not None,'genuine qualified Apps14 pair/public carrier required BEFORE ACTORS');return dict(fact,status='PASS_WHOLE559_PLUS_ACCEPTED_APPS14_INPUT_SOURCE_ONLY')
