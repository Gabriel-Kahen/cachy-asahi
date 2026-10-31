# SPDX-License-Identifier: MIT
"""Same native604/full-GUI authority; each actual VM supplies only one profile."""
import ast,hashlib,json,sys,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
OLD='scripts/ci/expanded604-current-management-managed16k'
NEW='scripts/ci/expanded604-current-management-profile16k'
_pin=json.loads((HERE/'dependencies.json').read_bytes())['files'][OLD+'/contract.py']
_path=ROOT/OLD/'contract.py'
if any(p.is_symlink() for p in (_path,*_path.parents)) or _path.stat().st_nlink!=1:raise ValueError('ordinary held contract required')
_raw=_path.read_bytes()
if dict(bytes=len(_raw),sha256=hashlib.sha256(_raw).hexdigest())!=_pin:raise ValueError('held contract bytes differ')
_text=_raw.decode().replace("PREFIX='"+OLD+"/'","PREFIX='"+NEW+"/'").replace("SCOPE='GENERIC_ARM64_16384_ACTUAL_ALPM604_CURRENT_WELCOME4_MANAGEMENT_SOFTWARE_ONLY'","SCOPE='GENERIC_ARM64_16384_ACTUAL_CURRENT604_SINGLE_PROFILE_SOFTWARE_ONLY'").replace("PASS='PASS_INSTALLED604_WELCOME4_MANAGEMENT_GENERIC16K_METADATA'","PASS='PASS_INSTALLED_CURRENT604_SINGLE_PROFILE_GENERIC16K_METADATA'").replace("FINAL='PASS_INSTALLED_CURRENT604_GENERIC16K_GUI_PIXELS_PENDING_REVIEW'","FINAL='PASS_INSTALLED_CURRENT604_SINGLE_PROFILE_GENERIC16K_PIXELS_PENDING_REVIEW'")
ast.parse(_text);exec(compile(_text,'<held604-single-profile-contract>','exec'),globals())
PROFILES=('minimal','overlay')
_policy=policy

def policy(bound=True):
 value=_policy(False)
 need(value.get('profiles')==list(PROFILES) and value.get('trial_scope')=='ONE_PROFILE_NOT_FULL60416K_ACCEPTANCE','explicit independent604 profile policy required')
 if bound:
  need(value.get('status')=='ROOT_BOUND_NATIVE604_AND_WELCOME4_INDEPENDENT_PROFILES_GUI','native604/current full independent Welcome4 GUI acceptance UNBOUND; no secrets or actors')
  for key in ('native604','welcome4_gui'):
   row=value[key];need(all(re.fullmatch('[0-9a-f]{40}',row.get(k) or '') for k in ('source_sha','carrier_source')) and re.fullmatch('[0-9a-f]{64}',row.get('source_manifest_sha256') or '') and row.get('decision') is not None,'actual current decision/source binding required')
  native=value['native604'];gui=value['welcome4_gui']
  need(re.fullmatch('[1-9][0-9]{0,19}',native.get('run_id') or '') and re.fullmatch('[0-9a-f]{64}',native.get('input_policy_sha256') or ''),'actual native604 input binding required')
  need('run_id' not in gui and type(gui.get('profile_runs')) is dict and set(gui['profile_runs'])==set(PROFILES) and all(type(v) is str and re.fullmatch('[1-9][0-9]{0,19}',v) for v in gui['profile_runs'].values()) and len(set(gui['profile_runs'].values()))==2 and gui.get('asset_root') is not None and gui.get('assets_index') is not None,'two distinct actual GUI profile runs and asset binding required; no aggregate run_id')
 return value

def decisions(native,gui,value):
 out={}
 for root,key,status in ((native,'native604','ROOT_ACCEPTED_NATIVE_CURRENT604_COMPOSITION'),(gui,'welcome4_gui','ROOT_ACCEPTED_NATIVE_WELCOME4_MANAGEMENT_GUI_INDEPENDENT_PROFILES')):
  row=value[key];need(revision(root)==row['carrier_source'],'exact decision carrier revision required');doc=json_read(checked(root,row['decision'],4*1024**2))
  need(doc.get('status')==status and doc.get('source_sha')==row['source_sha'] and doc.get('cleanup')=='PASS' and doc.get('hardware')=='NOT_RUN' and doc.get('release')=='NOT_ADMITTED' and doc.get('source_manifest_sha256')==row['source_manifest_sha256'],'actual Root decision/source differs')
  if key=='native604':
   need(doc.get('run_id')==row['run_id'] and doc.get('package_count')==604 and doc.get('expected604_sha256')==TARGET and all(doc.get(k)=='PASS' for k in ('installed_lifecycle','installed_six_modules')) and doc.get('input_policy_sha256')==row['input_policy_sha256'],'complete actual native604 decision required')
  else:
   need('run_id' not in doc and doc.get('profile_runs')==row['profile_runs'] and set(doc['profile_runs'])==set(PROFILES) and all(type(v) is str and re.fullmatch('[1-9][0-9]{0,19}',v) for v in doc['profile_runs'].values()) and len(set(doc['profile_runs'].values()))==2,'two actual GUI profile runs, never aggregate run_id')
   need(doc.get('frames')==24 and doc.get('management_operations_per_profile')==17 and doc.get('profiles')==list(PROFILES) and doc.get('welcome_version')=='0.1.0-4' and doc.get('doctor_version')=='0.1.0-1' and doc.get('orphans_version')=='0.1.0-2' and doc.get('candidate_source')=='0b74d8ecea4f152bda4adfbd9bee488890db4363' and doc.get('doctor_lifetime')=='PASS_ACTUAL_CHILD_WAIT_RELEASE_AND_FIXED_PARENT' and doc.get('gui_contract')=='PASS' and doc.get('archives')=={n:dict(bytes=r[0],sha256=r[1]) for n,r in ARCHIVES.items()},'current full24-frame independent Welcome4 GUI Root decision required')
  out[key]=doc
 return out

def profile(value):need(value in PROFILES,'one explicit minimal or overlay profile required');return value

def one(text,old,new,count=1):
 need(text.count(old)==count,'exact profile604 anchor differs: '+old[:100]);return text.replace(old,new)

def module(name,path,aliases=None,adapt=lambda text:text):
 raw=read(checked(ROOT,dict(path=path,**pins()[path])))
 text=adapt(raw.decode());ast.parse(text)
 value=types.ModuleType(name);value.__file__=str(ROOT/path);sys.modules[name]=value
 missing=object();previous={key:sys.modules.get(key,missing) for key in aliases or {}}
 try:
  sys.modules.update(aliases or {});exec(compile(text,'<pinned-profile604:'+path+'>','exec'),value.__dict__)
 finally:
  for key,old in previous.items():
   if old is missing:sys.modules.pop(key,None)
   else:sys.modules[key]=old
 return value

def join_profiles(decision,components):
 """Validate a separately pinned Root aggregate, never promote lane output itself."""
 need(set(components)==set(PROFILES) and decision.get('status')=='ROOT_ACCEPTED_CURRENT604_TWO_PROFILE_GENERIC16K' and decision.get('profiles')==list(PROFILES),'separate Root two-profile decision required')
 expected_archives={n:dict(bytes=r[0],sha256=r[1]) for n,r in ARCHIVES.items()}
 for selected,doc in components.items():
  need(doc.get('status')=='ROOT_ACCEPTED_CURRENT604_SINGLE_PROFILE_GENERIC16K' and doc.get('profile')==selected and doc.get('package_count')==604 and doc.get('expected604_sha256')==TARGET and doc.get('candidate_source')=='0b74d8ecea4f152bda4adfbd9bee488890db4363' and doc.get('archives')==expected_archives,'actual current604 profile identity required')
  need(doc.get('frames')==12 and doc.get('management_operations')==17 and doc.get('page_size')==16384 and all(doc.get(k)=='PASS' for k in ('cleanup','visual_review','doctor_lifetime','installed604_preserved')) and doc.get('hardware')=='NOT_RUN' and doc.get('release')=='NOT_ADMITTED','full actual single-profile gates required')
  need(re.fullmatch('[1-9][0-9]{0,19}',str(doc.get('run_id',''))) and re.fullmatch('[0-9a-f]{40}',doc.get('source_sha') or '') and all(re.fullmatch('[0-9a-f]{64}',doc.get(k) or '') for k in ('source_manifest_sha256','input_bindings_sha256','kernel_image_sha256','kernel_config_sha256','kernel_source_sha256','native604_decision_sha256','welcome4_gui_decision_sha256')),'exact actual profile source/provenance required')
  need(decision.get('components',{}).get(selected)==dict(run_id=doc['run_id'],bytes=len(encoded(doc)),sha256=sha(encoded(doc))),'Root aggregate component byte/run binding differs')
 first=components['minimal'];last=components['overlay']
 need(str(first['run_id'])!=str(last['run_id']) and all(first[k]==last[k] for k in ('source_sha','source_manifest_sha256','input_bindings_sha256','kernel_config_sha256','kernel_source_sha256','native604_decision_sha256','welcome4_gui_decision_sha256','archives')),'distinct actual runs with same frozen source/candidate/prerequisites required')
 need(decision.get('source_sha')==first['source_sha'] and decision.get('expected604_sha256')==TARGET and decision.get('cleanup')=='PASS' and decision.get('hardware')=='NOT_RUN' and decision.get('release')=='NOT_ADMITTED','exact separate Root full60416K scope required')
 return dict(status='TWO_PROFILE_ROOT_DECISION_SCHEMA_VALID_DATA_ONLY',source_sha=first['source_sha'],profiles=list(PROFILES),hardware='NOT_RUN',release='NOT_ADMITTED')
