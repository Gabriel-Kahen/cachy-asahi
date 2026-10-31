# SPDX-License-Identifier: MIT
"""Whole cleanup561 inverse plus exact Apps16 inputs; no GUI acceptance."""
import base64,hashlib,json,os,stat,types
from pathlib import Path
PARENT='601195b401668f92cec35772f1ad4c3eb00e6d21'
PARENT_MAP={'bytes': 94248, 'sha256': 'a93b70a5956ab52bb4c23eeccb1b21fa9c15b265a1823a68124fc6980b63c163'}
RECIPE='a32501a76b79b65d175c8eefc2b4f741ec0388e5'
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def read(path,cap=16*1024**2):
 path=Path(path).absolute();need(path==path.resolve()and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary canonical source ancestry');s=path.lstat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<=s.st_size<=cap,'bounded singlelink source');raw=path.read_bytes();t=path.lstat();fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns');need(len(raw)==s.st_size and all(getattr(s,k)==getattr(t,k)for k in fields),'stable whole source');return raw
def obj(path):return json.loads(read(path))
def closed(root,wanted):
 root=Path(root).absolute();actual=set()
 for b,dirs,files in os.walk(root):
  if Path(b)==root:dirs[:]=[n for n in dirs if n!='.git'];files=[n for n in files if n!='.git']
  for n in dirs:need(not(Path(b)/n).is_symlink(),'source directory aliases refused')
  actual.update((Path(b)/n).relative_to(root).as_posix()for n in files)
 need(actual==set(wanted),'whole closed Apps16 source map')
 for n,w in wanted.items():need(n and not Path(n).is_absolute()and '..'not in Path(n).parts and pin(read(root/n))==w,'whole exact source byte '+n)
 return wanted
def source_context(root):
 root=Path(root).absolute();manifest=obj(root/'source-manifest.json');need(manifest['status']=='SOURCE_ONLY_CURRENT606_WELCOME8_APPS16_NO_NEW_GUI_ACCEPTANCE'and manifest['actual_source']is manifest['actual_ref']is manifest['actual_run']is None,'source-only Apps16 NULL actual authority');closed(root,{**manifest['files'],'source-manifest.json':pin(read(root/'source-manifest.json'))})
 p=obj(root/'apps16-parent.json');before=p['files'];bodies=p['before_bodies'];ctx=p['context'];need(len(before)==561 and pin(enc(before))==PARENT_MAP and p['source']==PARENT and p['ref']=='codex/welcome8-gui-failure-cleanup-v1'and p['actual']is None,'whole original cleanup561 authority');need(ctx['authorization']==before and ctx['publication']==dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE',source=PARENT,ref=p['ref'],files=561,git_joins=561,actual='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')and ctx['git']==dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=PARENT,ref=p['ref'],files=before),'whole parent561 genuine publication/Git')
 def prior_read(path,cap=16*1024**2):
  n=Path(path).relative_to(root).as_posix();raw=base64.b64decode(bodies[n],validate=True)if n in bodies else read(path,cap);need(n in before and pin(raw)==before[n]and len(raw)<=cap,'entire original561 inverse '+n);return raw
 def prior_closed(where,wanted):
  prefix=''if where==root else where.relative_to(root).as_posix()+'/'
  need({n.removeprefix(prefix):w for n,w in before.items()if n.startswith(prefix)}==wanted,'whole original561 namespace')
  for n,w in wanted.items():need(pin(prior_read(where/n))==w,'whole original561 namespace byte')
  return wanted
 for n,w in before.items():need(pin(prior_read(root/n))==w,'every original561 source byte')
 old=types.ModuleType('_whole_original_cleanup561_admission');old.__file__=str(root/'admission.py');exec(compile(prior_read(root/'admission.py'),'<whole-original-cleanup561-admission>','exec'),old.__dict__);old.read=prior_read;old.obj=lambda path:json.loads(prior_read(path));old.closed=prior_closed;fact=old.source_context(root)
 need(fact['files']==561 and fact['cleanup']=='FAILURE_RESOURCE_RETIREMENT_ONLY_NOT_GUI_ACCEPTANCE','complete original cleanup and positive source guard')
 value=obj(root/'apps16-selection.json');need(set(value)=={'status','selection','actual_source','actual_ref','actual_run'}and value['actual_source']is value['actual_ref']is value['actual_run']is None,'exact Apps16 input selector NULL actual');selection=value['selection'];request=obj(root/'input-policy33.json')['packages'];prior_request=json.loads(prior_read(root/'input-policy33.json'))['packages'];need(len(request)==33 and {k:v for k,v in request.items()if k!='cachy-asahi-apps'}=={k:v for k,v in prior_request.items()if k!='cachy-asahi-apps'},'all32 nonApps inputs held')
 lock=dict(row.split()for row in read(root/'factory/expected606.lock').decode().splitlines());oldlock=dict(row.split()for row in prior_read(root/'factory/expected606.lock').decode().splitlines());need(len(lock)==606 and lock==dict(oldlock,**{'cachy-asahi-apps':'0.1.0-16'}),'all605 nonApps expected versions held');profile=obj(root/'factory/profile.json');prior_profile=json.loads(prior_read(root/'factory/profile.json'));need(profile['versions']==dict(prior_profile['versions'],**{'cachy-asahi-apps':'0.1.0-16'})and profile['expected606']==pin(read(root/'factory/expected606.lock'))and {k:v for k,v in profile['native_archives'].items()if k!='cachy-asahi-apps'}=={k:v for k,v in prior_profile['native_archives'].items()if k!='cachy-asahi-apps'},'only Apps16 selected archive/version');need(read(root/'factory/install606.py').count(("hexdigest()=='"+profile['expected606']['sha256']+"'").encode())==1 and read(root/'factory/original606.lock')==prior_read(root/'factory/original606.lock'),'whole exact606 installer lock and original lock held')
 for n in('factory/run.py','factory/context606.py','factory/failure_cleanup.py','transport.py'):need(read(root/n)==prior_read(root/n),'original positive15/failure cleanup/transport byte held '+n)
 installed=obj(root/'factory/apps16-installed-profile.json');need((installed['GUI_command_limit_seconds'],installed['inventory_limit_seconds'],installed['required_fresh_scans'])==(35,30,2)and installed['runtime']==obj_from_bytes(prior_read(root/'factory/apps14-installed-profile.json'))['runtime']and len(installed['payload'])==8 and installed['recipe_source']==RECIPE,'exact eight payloads unchanged Runtime1 and two scans35/30')
 common=types.ModuleType('_source_owned_apps16_inputs');exec(compile(read(root/'apps16_common.py'),'<trusted-source-owned-apps16-inputs>','exec'),common.__dict__)
 if selection is None:need(value['status']=='UNBOUND_APPS16_ACCEPTED_INPUTS_REQUIRED'and request['cachy-asahi-apps']==dict(name='cachy-asahi-apps',version='0.1.0-16',archive='cachy-asahi-apps-0.1.0-16-any.pkg.tar.xz',size=None,sha256=None)and profile['native_archives']['cachy-asahi-apps']is None and common.PAIR is common.PAIR_REF is common.RUN is None,'NULL Apps16 inputs cannot dispatch')
 else:
  need(value['status']=='ROOT_BOUND_ACCEPTED_APPS16_INPUTS_ONLY_NO_GUI_AUTHORITY'and selection['actual']is None and selection['source']=='950b0699a6e3f7a56758d4d17a5d30dabc7b6e11'and selection['ref']=='codex/apps16-accepted-inputs-v1'and len(selection['files'])==94 and selection['recipe_source']==common.RECIPE==RECIPE and selection['pair_source']==common.PAIR=='135b8fb21941d0ea27da7d34b1fc7b9eb0939ee8'and selection['pair_ref']==common.PAIR_REF=='codex/apps16-pair-native-v1'and selection['pair_run']==common.RUN==40170377974 and request['cachy-asahi-apps']==selection['package']and profile['native_archives']['cachy-asahi-apps']==dict(bytes=29664,sha256='319cc1db4738945ad3b146490ea0fabd80f8c8d89d8c41a11750dd0ba5d5b8af'),'genuine exact accepted Apps16 input-only authority')
  record=selection['qualified_record'];need(record['source']=='b011fb72b8055cd1d3c5c08227839847a83ef6c5'and record['ref']=='codex/apps16-native-qualified-record-v1'and len(record['files'])==22 and record['acceptance']==selection['acceptance'],'whole selected qualified22 original decision join')
 return dict(status='PASS_WHOLE_CLEANUP561_PLUS_APPS16_SOURCE_ONLY',files=len(manifest['files'])+1,parent561=fact,Apps16_inputs='UNBOUND'if selection is None else'ROOT_BOUND_INPUT_ONLY',cleanup='ORIGINAL_POSITIVE15_AND_FAILURE_RESOURCE_RETIREMENT_HELD',native_GUI='NOT_RUN')
def obj_from_bytes(raw):return json.loads(raw)
def prove(root):
 fact=source_context(root);value=obj(Path(root)/'apps16-selection.json');need(value['status']=='ROOT_BOUND_ACCEPTED_APPS16_INPUTS_ONLY_NO_GUI_AUTHORITY'and value['selection']is not None,'genuine accepted Apps16 pair/carrier required BEFORE ACTORS');return dict(fact,status='PASS_WHOLE561_PLUS_ACCEPTED_APPS16_INPUT_SOURCE_ONLY')
