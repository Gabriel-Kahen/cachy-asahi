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

# Finite restore-cardinality repair; all original561 source gates stay mandatory.
_RESTORE_PARENT_MAPS={'selected': {'bytes': 94248, 'sha256': '215a7ed4f466c8fe41d286bc12651a16c8b72c18c60b3c62266164195711ce72'}, 'unbound': {'bytes': 94246, 'sha256': 'c08ddd9f9abed94357194ba320dad9db4721a4d4535a097afc4bfdc26eab8103'}}
_RESTORE_FACTORY={'bytes': 18160, 'sha256': '0142b83234fce1e6ad58cf68e2d3e1c476e10b5f593692a6aacdd42b909535c4'}
def source_context(root):
 root=Path(root).absolute();manifest=obj(root/'source-manifest.json');need(manifest['status']=='SOURCE_ONLY_APPS16_GUI_RESTORE604_NO_GUI_ACCEPTANCE'and manifest['actual_source']is manifest['actual_ref']is manifest['actual_run']is None,'restore successor grants no actual authority');closed(root,{**manifest['files'],'source-manifest.json':pin(read(root/'source-manifest.json'))})
 p=obj(root/'management-restore-parent.json');variant=p['variant'];need(variant in _RESTORE_PARENT_MAPS and p['actual']is None and len(p['files'])==561 and pin(enc(p['files']))==_RESTORE_PARENT_MAPS[variant],'whole exact561 parent map and variant')
 need((p['source'],p['ref'])==(('d34854151f578547c2f64f46d14f5d9129bf2d66','codex/welcome8-apps16-gui-v1')if variant=='selected'else(None,None)),'known parent publication versus NULL template identity')
 before=p['files'];bodies=p['before_bodies'];need(set(bodies)=={'admission.py','factory/factory.py','source-manifest.json'},'only original gate/factory/manifest before bodies')
 def prior_read(path,cap=16*1024**2):
  name=Path(path).relative_to(root).as_posix();raw=base64.b64decode(bodies[name],validate=True)if name in bodies else read(path,cap);need(name in before and pin(raw)==before[name]and len(raw)<=cap,'every complete original561 byte inverse '+name);return raw
 def prior_closed(where,wanted):
  prefix=''if where==root else where.relative_to(root).as_posix()+'/'
  need({n.removeprefix(prefix):w for n,w in before.items()if n.startswith(prefix)}==wanted,'whole original561 closed namespace')
  for name,want in wanted.items():need(pin(prior_read(where/name))==want,'whole original561 namespace byte')
  return wanted
 for name,want in before.items():need(pin(prior_read(root/name))==want,'whole original561 body '+name)
 need(pin(read(root/'factory/factory.py'))==_RESTORE_FACTORY,'sole exact source-owned restore cardinality seam')
 old=types.ModuleType('_whole_original_apps16_561_restore_parent');old.__file__=str(root/'admission.py');exec(compile(prior_read(root/'admission.py'),'<whole-original-apps16-561>','exec'),old.__dict__);old.read=prior_read;old.obj=lambda path:json.loads(prior_read(path));old.closed=prior_closed;fact=old.source_context(root);need(fact['files']==561 and fact['cleanup']=='ORIGINAL_POSITIVE15_AND_FAILURE_RESOURCE_RETIREMENT_HELD','whole original source/cleanup/Apps16 proof')
 return dict(fact,files=len(manifest['files'])+1,restore_fixture='EXACT606_BASELINE_MINUS_TWO_TOOLS_RESTORE604_ONLY')
_restore_original_prove=prove
def prove(root):
 value=_restore_original_prove(root)
 return dict(value,status='PASS_WHOLE562_RESTORE604_AND_ORIGINAL_APPS16_SOURCE_ONLY')

# Fixed post-session stage DATA only. All original562 source and runtime predicates held.
_POST_PARENT_MAPS={'selected': {'bytes': 94394, 'sha256': 'afb262e1226888a883c3dc6ec8d17508f26e81b10d35b862ef2477013dc7139d'}, 'unbound': {'bytes': 94392, 'sha256': 'bea181a7be38e85bea14755551c15759c5346ccb7809524a8d000930cc24de8f'}}
_POST_FACTORY={'bytes': 20137, 'sha256': 'afea7d5a75ca9898fa09567b50a46291e4ceb0b16d1fdd713828b7f60b0584ff'}
_POST_HELPER={'bytes': 637, 'sha256': 'f700e2f1f4fe6c9f59f583b577a6ce70ef72196d72bfca0525138fa9172e426e'}
def source_context(root):
 root=Path(root).absolute();manifest=obj(root/'source-manifest.json');need(manifest['status']=='SOURCE_ONLY_GUI_POST_SESSION_STAGE_DATA_NO_GUI_ACCEPTANCE'and manifest['actual_source']is manifest['actual_ref']is manifest['actual_run']is None,'post-session diagnostic grants no actual authority');closed(root,{**manifest['files'],'source-manifest.json':pin(read(root/'source-manifest.json'))})
 p=obj(root/'post-session-parent.json');variant=p['variant'];need(variant in _POST_PARENT_MAPS and p['actual']is None and len(p['files'])==562 and pin(enc(p['files']))==_POST_PARENT_MAPS[variant],'whole exact562 parent map and variant');need((p['source'],p['ref'])==(('37bee5c50f8808b618b90ab0a559d7fa88a8a4ab','codex/welcome8-apps16-restore604-v1')if variant=='selected'else(None,None)),'known parent source versus NULL identity')
 before=p['files'];bodies=p['before_bodies'];need(set(bodies)=={'admission.py','factory/factory.py','source-manifest.json'},'only original factory/admission/manifest before bodies')
 def prior_read(path,cap=16*1024**2):
  name=Path(path).relative_to(root).as_posix();raw=base64.b64decode(bodies[name],validate=True)if name in bodies else read(path,cap);need(name in before and pin(raw)==before[name]and len(raw)<=cap,'every complete original562 byte inverse '+name);return raw
 def prior_closed(where,wanted):
  prefix=''if where==root else where.relative_to(root).as_posix()+'/'
  need({n.removeprefix(prefix):w for n,w in before.items()if n.startswith(prefix)}==wanted,'whole original562 closed namespace')
  for name,want in wanted.items():need(pin(prior_read(where/name))==want,'every original562 namespace byte')
  return wanted
 for name,want in before.items():need(pin(prior_read(root/name))==want,'every original562 full body '+name)
 need(pin(read(root/'factory/factory.py'))==_POST_FACTORY and pin(read(root/'factory/post_session.py'))==_POST_HELPER,'exact finite diagnostic factory/helper')
 old=types.ModuleType('_whole_original562_post_session_parent');old.__file__=str(root/'admission.py');exec(compile(prior_read(root/'admission.py'),'<whole-original562>','exec'),old.__dict__);old.read=prior_read;old.obj=lambda path:json.loads(prior_read(path));old.closed=prior_closed;fact=old.source_context(root);need(fact['files']==562 and fact['cleanup']=='ORIGINAL_POSITIVE15_AND_FAILURE_RESOURCE_RETIREMENT_HELD'and fact['restore_fixture']=='EXACT606_BASELINE_MINUS_TWO_TOOLS_RESTORE604_ONLY','entire original562 restore/Apps16/cleanup/source proof')
 return dict(fact,files=len(manifest['files'])+1,post_session='FIXED_BOUNDED_STAGE_DATA_ONLY_NOT_GUI_ACCEPTANCE')
_post_original_prove=prove
def prove(root):
 value=_post_original_prove(root)
 return dict(value,files=564,status='PASS_WHOLE564_POST_SESSION_DIAGNOSTIC_AND_ALL562_SOURCE_GATES')

# Source-only isolated startup loader fix; entire published564 ancestry remains mandatory.
_ISOLATED_PARENT_MAPS={'selected': {'bytes': 94668, 'sha256': '3a6b394d8fcc0e91fc14410954f19024645f6799477e09ab7c2afc0c97e4370e'}, 'unbound': {'bytes': 94666, 'sha256': '8a5e592131e4d548013d30987a3d77dc6a843e83779b1db86bc1b59ddc671090'}}
_ISOLATED_FACTORY_BEFORE={'bytes': 20137, 'sha256': 'afea7d5a75ca9898fa09567b50a46291e4ceb0b16d1fdd713828b7f60b0584ff'}
_ISOLATED_FACTORY_AFTER={'bytes': 20658, 'sha256': '23f23fc02287ea861f5ab12cc9e197d38efed0c1ae0aad0fc2445500ce4ebe04'}
_ISOLATED_LOADER_BLOCK='    # Register only the pinned diagnostic sibling before isolated consumers.\n    for name in (\'desktop574_guest.py\',\'doctor_worker.py\'):\n        edit(name,lambda s:once(s,"load(\'management_root\',\'management_root.py\')","load(\'post_session\',\'post_session.py\')\\nload(\'management_root\',\'management_root.py\')"))\n    edit(\'service_outcome.py\',lambda s:once(s,"for name in (\'doctor_lifetime\',\'management_contract\',\'management_root\'):","for name in (\'post_session\',\'doctor_lifetime\',\'management_contract\',\'management_root\'):"))\n\n'
def source_context(root):
 root=Path(root).absolute();manifest=obj(root/'source-manifest.json');need(manifest['status']=='SOURCE_ONLY_GUI_POST_SESSION_ISOLATED_IMPORT_NO_GUI_ACCEPTANCE'and manifest['actual_source']is manifest['actual_ref']is manifest['actual_run']is None,'isolated startup source grants no current actual authority');closed(root,{**manifest['files'],'source-manifest.json':pin(read(root/'source-manifest.json'))})
 p=obj(root/'isolated-import-parent.json');variant=p['variant'];need(variant in _ISOLATED_PARENT_MAPS and p['actual']is None and len(p['files'])==564 and pin(enc(p['files']))==_ISOLATED_PARENT_MAPS[variant],'complete exact published564 parent map and variant');need((p['source'],p['ref'])==(('a1a0dea6fc4d3cf15fb82c72c52385c277eae0cc','codex/welcome8-apps16-post-session-stage-v1')if variant=='selected'else(None,None)),'published564 INPUT versus NULL context')
 before=p['files'];bodies=p['before_bodies'];need(set(bodies)=={'admission.py','source-manifest.json'},'only original admission/manifest before bodies')
 def prior_read(path,cap=16*1024**2):
  name=Path(path).relative_to(root).as_posix()
  if name=='factory/factory.py':
   raw=read(path,cap);need(pin(raw)==_ISOLATED_FACTORY_AFTER,'entire current isolated startup factory');text=raw.decode();need(text.count(_ISOLATED_LOADER_BLOCK)==1,'one finite complete loader block inverse');raw=text.replace(_ISOLATED_LOADER_BLOCK,'',1).encode();need(pin(raw)==_ISOLATED_FACTORY_BEFORE,'entire original564 factory byte inverse')
  else:raw=base64.b64decode(bodies[name],validate=True)if name in bodies else read(path,cap)
  need(name in before and pin(raw)==before[name]and len(raw)<=cap,'every entire original564 byte inverse '+name);return raw
 def prior_closed(where,wanted):
  prefix=''if where==root else where.relative_to(root).as_posix()+'/'
  need({n.removeprefix(prefix):w for n,w in before.items()if n.startswith(prefix)}==wanted,'whole original564 closed namespace')
  for name,want in wanted.items():need(pin(prior_read(where/name))==want,'every original564 namespace body')
  return wanted
 for name,want in before.items():need(pin(prior_read(root/name))==want,'complete original564 body '+name)
 old=types.ModuleType('_whole_original564_isolated_parent');old.__file__=str(root/'admission.py');exec(compile(prior_read(root/'admission.py'),'<whole-original564-isolated-parent>','exec'),old.__dict__);old.read=prior_read;old.obj=lambda path:json.loads(prior_read(path));old.closed=prior_closed;fact=old.source_context(root);need(fact['files']==564 and fact['post_session']=='FIXED_BOUNDED_STAGE_DATA_ONLY_NOT_GUI_ACCEPTANCE'and fact['cleanup']=='ORIGINAL_POSITIVE15_AND_FAILURE_RESOURCE_RETIREMENT_HELD','whole original564/562 source/security/cleanup/post-session gates')
 return dict(fact,files=len(manifest['files'])+1,isolated_startup='EXPLICIT_PINNED_POST_SESSION_BEFORE_ALL_CONSUMERS_NO_SYS_PATH_CHANGE')
_isolated_original_prove=prove
def prove(root):
 value=_isolated_original_prove(root)
 return dict(value,files=565,status='PASS_WHOLE565_ISOLATED_STARTUP_AND_ALL564_562_SOURCE_GATES')

# Explicit TCG-only inventory caller60; original product30/default35 remain whole.
_VM_PARENT_MAPS={'known': {'bytes': 94810, 'sha256': '28b3b263374b362ef00a05f5f4a376fa6386df4654a556a7093270cd40510309'}, 'null': {'bytes': 94808, 'sha256': 'c113809a9887fce7fce3bf0f4b15540c9afab057e9c1aae55ac87282e2889e41'}}
_VM_HELPER={'bytes': 5998, 'sha256': '72753a00ecf6bfb206b1651bbba1cf6940f4c0b901bdf81267d6bc8fafc203c9'}
_VM_PROFILE={'bytes': 900, 'sha256': '48e9b3b2398b78ba3b913fae6818bd33e695c57733a05301b9833a5bc177acfa'}
_VM_FACTORY={'bytes': 20774, 'sha256': 'f027487f5be2585263ff2f1797da88c875399f5e1d5a3e2af262a0697c6c0640'}
_VM_SHIM="\n# Explicit VM-test capacity only; all default35 functions above remain whole.\ndef _install_inventory_vm_capacity():\n    import importlib.util\n    path=Path(__file__).resolve().parent/'inventory_capacity.py'\n    spec=importlib.util.spec_from_file_location('_owned_tcg_inventory_capacity',path)\n    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\n    module.install(globals())\n_install_inventory_vm_capacity()\n"
_VM_BLOCK=("('apps16_runtime.py','apps16-installed-profile.json','apps16_diagnostic.py')", "('apps16_runtime.py','apps16-installed-profile.json','apps16_diagnostic.py','inventory_capacity.py','inventory-vm-profile.json')", '/runner/apps16_diagnostic.py ', '/runner/apps16_diagnostic.py /runner/inventory_capacity.py /runner/inventory-vm-profile.json ')
_VM_PROFILE_VALUE={'M2_performance': 'NOT_RUN', 'acceptance': False, 'actual': None, 'caller_seconds': 60, 'default_caller_seconds': 35, 'native_hotspot': 'UNKNOWN', 'old35_fit': 'NOT_ESTABLISHED', 'original_helpers': {'apps16_diagnostic.py': {'bytes': 6163, 'sha256': '9a39513103a495329eeb3eded4564570ae02f3e41fe7d1f149de921eecf4c1b4'}, 'apps16_runtime.py': {'bytes': 1948, 'sha256': 'df9d658794732b4a54c5eaf83037f54e64e87dde9c6d26b28672181893c77750'}, 'current_products.py': {'bytes': 7085, 'sha256': '5c0955b254813537f6b87cfad718afb05768ae12e3a5d7765b101c3c124a005e'}}, 'product_scan_seconds': 30, 'profile': 'GUI_TCG_INVENTORY_CALLER_60_V1', 'ref': None, 'run': None, 'schema_version': 1, 'scope': 'OPT_IN_VM_FUNCTIONAL_VALIDATION_ONLY_NOT_PERFORMANCE', 'source': None, 'stage_elapsed_data_limit_seconds': 65}
def _vm_original(root):
 root=Path(root).absolute();p=obj(root/'inventory-vm-parent.json');variant=p['variant'];need(variant in _VM_PARENT_MAPS and len(p['files'])==565 and pin(enc(p['files']))==_VM_PARENT_MAPS[variant]and p['actual']is None,'entire exact565 parent source map')
 need((p['source'],p['ref'])==(('b9a1195e5f5c5e439db791383e18e56511de2f5a','codex/welcome8-apps16-isolated-import-v1')if variant=='known'else(None,None)),'genuine565 history versus NULL context')
 if variant=='known':need(p['context']['authorization']==p['files']and p['context']['git']==dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=p['source'],ref=p['ref'],files=p['files'])and p['context']['publication']==dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE',source=p['source'],ref=p['ref'],files=565,git_joins=565,actual='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED'),'whole565 publication/source/Git joins')
 else:need(p['context']is None,'NULL history has no invented publication')
 before=p['files'];bodies=p['before_bodies'];need(set(bodies)=={'admission.py','factory/factory.py','factory/current_products.py','source-manifest.json'},'finite whole before bodies only')
 def prior_read(path,cap=16*1024**2):
  name=Path(path).relative_to(root).as_posix();raw=base64.b64decode(bodies[name],validate=True)if name in bodies else read(path,cap);need(name in before and pin(raw)==before[name]and len(raw)<=cap,'entire565 original byte inverse '+name);return raw
 def prior_closed(where,wanted):
  prefix=''if where==root else where.relative_to(root).as_posix()+'/'
  need({n.removeprefix(prefix):w for n,w in before.items()if n.startswith(prefix)}==wanted,'entire original565 namespace')
  for name,want in wanted.items():need(pin(prior_read(where/name))==want,'every original565 namespace byte')
  return wanted
 for name,want in before.items():need(pin(prior_read(root/name))==want,'every original565 full body')
 old=types.ModuleType('_whole_original565_caller35');old.__file__=str(root/'admission.py');exec(compile(prior_read(root/'admission.py'),'<entire-original565-caller35>','exec'),vars(old));old.read=prior_read;old.obj=lambda path:json.loads(prior_read(path));old.closed=prior_closed
 return old,prior_read

def source_context(root):
 root=Path(root).absolute();manifest=obj(root/'source-manifest.json');need(manifest['status']=='SOURCE_ONLY_GUI_TCG_INVENTORY_CALLER60_NO_GUI_ACCEPTANCE'and manifest['actual_source']is manifest['actual_ref']is manifest['actual_run']is None,'explicit new profile has no actual authority');closed(root,{**manifest['files'],'source-manifest.json':pin(read(root/'source-manifest.json'))})
 old,prior_read=_vm_original(root);fact=old.source_context(root);need(fact['files']==565 and fact['isolated_startup']=='EXPLICIT_PINNED_POST_SESSION_BEFORE_ALL_CONSUMERS_NO_SYS_PATH_CHANGE','whole565/564/562/original source/cleanup predicates')
 need(pin(read(root/'factory/inventory_capacity.py'))==_VM_HELPER and pin(read(root/'factory/inventory-vm-profile.json'))==_VM_PROFILE and obj(root/'factory/inventory-vm-profile.json')==_VM_PROFILE_VALUE,'whole fixed TCG profile and source-owned facade')
 need(pin(read(root/'factory/factory.py'))==_VM_FACTORY,'exact factory copy-only profile seam');text=read(root/'factory/factory.py').decode();need(text.replace(_VM_BLOCK[1],_VM_BLOCK[0],1).replace(_VM_BLOCK[3],_VM_BLOCK[2],1).encode()==prior_read(root/'factory/factory.py'),'entire factory body inverse')
 need(read(root/'factory/current_products.py')==prior_read(root/'factory/current_products.py')+_VM_SHIM.encode(),'entire original product/positive/failure harness body before finite footer')
 for name in('apps16_diagnostic.py','apps16_runtime.py','apps16-installed-profile.json'):
  need(read(root/'factory'/name)==prior_read(root/'factory'/name),'original default35 and product identity byte held '+name)
 need(len(manifest['files'])+1==568,'exact complete568 new source')
 return dict(fact,files=568,inventory_validation_profile=_VM_PROFILE_VALUE['profile'],inventory_product_seconds=30,inventory_caller_seconds=60,default_caller_seconds=35,old35_fit='NOT_ESTABLISHED',M2_performance='NOT_RUN',native_hotspot='UNKNOWN',actual=None)

def prove(root):
 fact=source_context(root);old,_=_vm_original(Path(root).absolute());prior=old.prove(root);need(prior['files']==565,'entire original565 preflight before profile60')
 return dict(fact,status='PASS_WHOLE565_PLUS_EXPLICIT_TCG_INVENTORY_CALLER60_SOURCE_ONLY')
