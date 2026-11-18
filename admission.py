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

# Source-control correction only; all original568 runtime and source gates remain mandatory.
_PRESECRET_MAPS={'known': {'bytes': 95236, 'sha256': '41a1d8578b37784dea92898d49d4b0d0aa54d6fa1404fbb1d60244a2d26c5217'}, 'null': {'bytes': 95234, 'sha256': '8ce58618c0811c263e98214f53db7416b732a853961800e32919b4eef50016d9'}}
_PRESECRET_HELPER={'bytes': 4897, 'sha256': 'b17b871a60dffd735504b1cbc3b1fb52feb25906911ee7afb82361a4af7b8f9c'}
_PRESECRET_CALL=" load('_fixed_caller60_presecret_controls',D/'inventory_presecret_controls.py').run(globals())\n"
_PRESECRET_OLD=' unittest.main(verbosity=2)\n'
def _presecret_original(root):
 root=Path(root).absolute();p=obj(root/'caller60-presecret-parent.json');before=p['files'];variant=p['variant'];need(variant in _PRESECRET_MAPS and len(before)==568 and pin(enc(before))==_PRESECRET_MAPS[variant]and p['actual']is None,'whole exact568 source-control predecessor')
 need((p['source'],p['ref'])==(('b693a4c5a791f71fc3b91d109cbf9e49a14e424a','codex/welcome8-apps16-inventory-caller60-v1')if variant=='known'else(None,None)),'genuine original568 publication or NULL context')
 if variant=='known':need(p['context']['authorization']==before and p['context']['publication']==dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE',source=p['source'],ref=p['ref'],files=568,git_joins=568,actual='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')and p['context']['git']==dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=p['source'],ref=p['ref'],files=before),'whole original568 Root source/publication/Git joins')
 else:need(p['context']is None,'NULL source-control predecessor no invented authority')
 bodies=p['before_bodies'];need(set(bodies)=={'apps16_common.py','admission.py','source-manifest.json'},'only three exact source-control before bodies')
 def prior_read(path,cap=16*1024**2):
  n=Path(path).relative_to(root).as_posix();raw=base64.b64decode(bodies[n],validate=True)if n in bodies else read(path,cap);need(n in before and pin(raw)==before[n]and len(raw)<=cap,'every entire original568 source byte '+n);return raw
 def prior_closed(where,wanted):
  prefix=''if where==root else where.relative_to(root).as_posix()+'/'
  need({n.removeprefix(prefix):w for n,w in before.items()if n.startswith(prefix)}==wanted,'whole original568 namespace')
  for n,w in wanted.items():need(pin(prior_read(where/n))==w,'every original568 namespace byte')
  return wanted
 for n,w in before.items():need(pin(prior_read(root/n))==w,'all original568 inverse operands')
 old=types.ModuleType('_whole_original568_inventory60_source');old.__file__=str(root/'admission.py');exec(compile(prior_read(root/'admission.py'),'<whole-original568-inventory60>','exec'),vars(old));old.read=prior_read;old.obj=lambda path:json.loads(prior_read(path));old.closed=prior_closed;return old,prior_read

def source_context(root):
 root=Path(root).absolute();manifest=obj(root/'source-manifest.json');need(manifest['status']=='SOURCE_ONLY_GUI_CALLER60_PRESECRET_CONTROLS_NO_RUNTIME_CHANGE'and manifest['actual_source']is manifest['actual_ref']is manifest['actual_run']is None,'source-control fix grants no current actual authority');closed(root,{**manifest['files'],'source-manifest.json':pin(read(root/'source-manifest.json'))});old,prior=_presecret_original(root);fact=old.source_context(root);need(fact['files']==568 and(fact['inventory_caller_seconds'],fact['inventory_product_seconds'],fact['default_caller_seconds'])==(60,30,35),'whole568/565/564/562 source and selected60/default35/product30 predicates')
 need(pin(read(root/'inventory_presecret_controls.py'))==_PRESECRET_HELPER,'exact original35 AND explicit60 source-control driver');text=prior(root/'apps16_common.py');need(text.count(_PRESECRET_OLD.encode())==1 and read(root/'apps16_common.py')==text.replace(_PRESECRET_OLD.encode(),_PRESECRET_CALL.encode(),1),'entire original source control/custody code except one main delegation');need(len(manifest['files'])+1==570,'exact closed570 source-control successor')
 return dict(fact,files=570,presecret_controls='ORIGINAL_SIX_DEFAULT35_AND_EXPLICIT_SIX_CALLER60_PLUS_FIXED_PROFILE_FD',runtime='ALL568_RUNTIME_BYTES_HELD',actual=None)
def prove(root):
 fact=source_context(root);old,_=_presecret_original(root);prior=old.prove(root);need(prior['files']==568,'complete original568 source entry mandatory');return dict(fact,status='PASS_COMPLETE568_AND_FIXED_PRESECRET_PROFILE_CONTROLS_SOURCE_ONLY')

# Explicit selected TCG service1800; whole570/default1200 route remains mandatory.
_SERVICE_PARENT_MAPS={'known': {'bytes': 95526, 'sha256': '641aceb72a3e38d9841b9402ddf3b75045ef258fe30de49295389def54c8f2ee'}, 'null': {'bytes': 95524, 'sha256': '148d0ee8d8dd5ffcec98c37671374ab5a7c8856da71e7a82b7f721897d91667e'}}
_SERVICE_PRODUCTS={'factory/service_capacity.py': {'bytes': 6609, 'sha256': '7e955650478f514a58f36ff95648569e8ae2a432fd7fa3c7cb72ec1446ebeb6d'}, 'factory/service-vm-profile.json': {'bytes': 1282, 'sha256': '6d36a067f85d68184587fd6d9e2a8af0190acba6e0b371862400766a9303ae3b'}, 'service_controls.py': {'bytes': 6608, 'sha256': '54cba30940337d04f48a257ab04fec9da20cf85599d5ed065797dd294f0a8c19'}}
_SERVICE_SEAMS={'factory/factory.py': [('', "\n# Explicit selected TCG route; every original factory function/default above is held.\ndef service1800():\n    return load('_owned_service1800_capacity',HERE/'service_capacity.py').factory(globals(),'tcg1800')\n", 1)], 'factory/run.py': [('', "\n# Explicit selected TCG route; original run/cleanup/default2200 remain whole.\ndef run_service1800(*args,**kwargs):\n    return F.load('_owned_service1800_owner',Path(__file__).resolve().parent/'service_capacity.py').owner(globals(),*args,**kwargs)\n", 1)], 'native.py': [("return load('_current606_source_bound_factory',ROOT/'factory/factory.py')", "return load('_current606_source_bound_factory',ROOT/'factory/factory.py').service1800()", 1), ('result=owner.run(ROOT/', 'result=owner.run_service1800(ROOT/', 1)], '.github/workflows/native-arm-current606-welcome8-gui.yml': [('python3 -I -B gui606-source/apps16_common.py', 'python3 -I -B gui606-source/apps16_common.py\npython3 -I -B gui606-source/service_controls.py', 1)], '.github/workflows/native-arm-build.yml': [('python3 -I -B gui606-source/apps16_common.py', 'python3 -I -B gui606-source/apps16_common.py\npython3 -I -B gui606-source/service_controls.py', 1)]}
_SERVICE_NATIVE=[("return load('_current606_source_bound_factory',ROOT/'factory/factory.py')", "return load('_current606_source_bound_factory',ROOT/'factory/factory.py').service1800()", 1), ('result=owner.run(ROOT/', 'result=owner.run_service1800(ROOT/', 1)]
_SERVICE_WF='.github/workflows/native-arm-current606-welcome8-gui.yml'
def _service_original(root):
 root=Path(root).absolute();p=obj(root/'service1800-parent.json');before=p['files'];variant=p['variant'];need(variant in _SERVICE_PARENT_MAPS and len(before)==570 and pin(enc(before))==_SERVICE_PARENT_MAPS[variant]and p['actual']is None,'whole exact570 source predecessor')
 need((p['source'],p['ref'])==(('04db51b4932bb3af6fb6dc36ea2f533996de814c','codex/welcome8-apps16-caller60-presecret-v1')if variant=='known'else(None,None)),'genuine570 publication or NULL context')
 if variant=='known':need(p['context']['authorization']==before and p['context']['publication']==dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE',source=p['source'],ref=p['ref'],files=570,git_joins=570,actual='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')and p['context']['git']==dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=p['source'],ref=p['ref'],files=before),'whole570 Root publication/source/Git')
 else:need(p['context']is None,'NULL original570 no invented authority')
 bodies=p['before_bodies'];need(set(bodies)==set(_SERVICE_SEAMS)|{'admission.py','source-manifest.json'},'finite complete570 before bodies')
 def prior_read(path,cap=16*1024**2):
  n=Path(path).relative_to(root).as_posix();raw=base64.b64decode(bodies[n],validate=True)if n in bodies else read(path,cap);need(n in before and pin(raw)==before[n]and len(raw)<=cap,'whole570 before byte '+n);return raw
 def prior_closed(where,wanted):
  prefix=''if where==root else where.relative_to(root).as_posix()+'/'
  need({n.removeprefix(prefix):w for n,w in before.items()if n.startswith(prefix)}==wanted,'whole570 namespace')
  for n,w in wanted.items():need(pin(prior_read(where/n))==w,'whole570 closed byte')
  return wanted
 for n,w in before.items():need(pin(prior_read(root/n))==w,'entire original570 source inverse')
 old=types.ModuleType('_whole570_default_service1200');old.__file__=str(root/'admission.py');exec(compile(prior_read(root/'admission.py'),'<whole570-default-service1200>','exec'),vars(old));old.read=prior_read;old.obj=lambda p:json.loads(prior_read(p));old.closed=prior_closed;return old,prior_read

def source_context(root):
 root=Path(root).absolute();manifest=obj(root/'source-manifest.json');need(manifest['status']=='SOURCE_ONLY_GUI_TCG_SERVICE1800_EXPLICIT_PROFILE_NO_ACCEPTANCE'and manifest['actual_source']is manifest['actual_ref']is manifest['actual_run']is None,'explicit service1800 no actual authority');closed(root,{**manifest['files'],'source-manifest.json':pin(read(root/'source-manifest.json'))});need(len(manifest['files'])+1==574,'closed exact574 source')
 old,prior=_service_original(root);fact=old.source_context(root);need(fact['files']==570 and fact['inventory_caller_seconds']==60 and fact['inventory_product_seconds']==30,'whole570/568/565/564/562 admission AND')
 for n,w in _SERVICE_PRODUCTS.items():need(pin(read(root/n))==w,'fixed complete service product '+n)
 for n,seams in _SERVICE_SEAMS.items():
  raw=read(root/n)
  for a,b,count in reversed(seams):need(raw.count(b.encode())==count,'counted whole service inverse '+n);raw=raw.replace(b.encode(),a.encode())
  need(raw==prior(root/n),'complete untouched original body inverse '+n)
 need(read(root/'admission.py').startswith(prior(root/'admission.py')),'whole570 admission before mandatory child AND')
 return dict(fact,files=574,service_validation_profile='GUI_TCG_SERVICE_1800_V1',service_seconds=1800,default_service_seconds=1200,loop_seconds=1900,runtime_seconds=2350,owner_wait_seconds=2800,native_owner_seconds=6600,cleanup_seconds=450,doctor_profile_seconds=1080,fullscan_seconds=600,old1200_fit='NOT_ESTABLISHED',current1800_fit='NOT_ESTABLISHED',native_hotspot='UNKNOWN',M2_performance='NOT_RUN',actual=None)
def prove(root):
 fact=source_context(root);old,_=_service_original(root);prior=old.prove(root);need(prior['files']==570,'complete original570 source preflight required');return dict(fact,status='PASS_WHOLE570_AND_EXPLICIT_TCG_SERVICE1800_SOURCE_ONLY')

# Exact service1800 installed606 diagnostics successor.
_READBACK_START='\n# Exact service1800 installed606 diagnostics successor.\n'
_READBACK_PARENT={'bytes': 100693, 'sha256': 'd62aefc197c625b66dea7d33872875baa5d30494bf1a24799e74c61a62718778'}
_READBACK_PAYLOAD={'bytes': 7005, 'sha256': 'f84ad2051f444d7a8d34136b02026c8643208340e6aefa4fa2218ffed05df9db'}
_READBACK_NEW_CALL="    changes=transform(out,mode)\n    changes['installed606_progress']=load('_installed606_progress',HERE/'installed606_progress.py').apply(out,pin)\n"
_READBACK_OLD_CALL='    changes=transform(out,mode)\n'

def _readback_parent(root):
 root=Path(root).absolute()
 context=obj(root/'readback-progress-parent.json')
 need(set(context)=={'manifest','payload','actual'} and context['actual'] is None and context['payload']==_READBACK_PAYLOAD,'exact 606 progress context')
 prior_manifest=base64.b64decode(context['manifest'],validate=True)
 need(pin(prior_manifest)==_READBACK_PARENT,'exact service1800 manifest')
 before={**json.loads(prior_manifest)['files'],'source-manifest.json':pin(prior_manifest)}
 manifest=obj(root/'source-manifest.json')
 need(manifest['status']=='SOURCE_ONLY_GUI_APPS16_INSTALLED606_PROGRESS' and all(manifest[k] is None for k in ('actual_source','actual_ref','actual_run')),'unissued diagnostics source only')
 need(set(manifest['files'])==set(before)-{'source-manifest.json'}|{'factory/installed606_progress.py','readback-progress-parent.json'},'closed exact successor file set')
 closed(root,{**manifest['files'],'source-manifest.json':pin(read(root/'source-manifest.json'))})
 need(pin(read(root/'factory/installed606_progress.py'))==_READBACK_PAYLOAD,'whole installed606 diagnostic module')
 before_admission,marker,_=read(root/'admission.py').partition(_READBACK_START.encode())
 need(marker and pin(before_admission)==before['admission.py'],'whole original service1800 admission')
 current_factory=read(root/'factory/factory.py')
 need(current_factory.count(_READBACK_NEW_CALL.encode())==1,'one exact diagnostic emission seam')
 before_factory=current_factory.replace(_READBACK_NEW_CALL.encode(),_READBACK_OLD_CALL.encode(),1)
 originals={'source-manifest.json':prior_manifest,'admission.py':before_admission,'factory/factory.py':before_factory}
 def prior_read(path,cap=16*1024**2):
  name=Path(path).relative_to(root).as_posix();raw=originals[name] if name in originals else read(path,cap)
  need(name in before and pin(raw)==before[name] and len(raw)<=cap,'whole service1800 source operand '+name);return raw
 def prior_closed(where,wanted):
  prefix='' if where==root else where.relative_to(root).as_posix()+'/'
  need({n.removeprefix(prefix):w for n,w in before.items() if n.startswith(prefix)}==wanted,'closed original service1800 namespace')
  for n in wanted:prior_read(where/n)
  return wanted
 for name in before:prior_read(root/name)
 parent=types.ModuleType('_installed606_progress_original_service1800');parent.__file__=str(root/'admission.py')
 exec(compile(before_admission,parent.__file__,'exec'),vars(parent))
 parent.read=prior_read;parent.obj=lambda p:json.loads(prior_read(p));parent.closed=prior_closed
 return parent

def _readback_fact(fact):
 need(fact['files']==574 and fact['fullscan_seconds']==600,'whole original service1800 proof and readback deadline')
 return dict(fact,files=576,installed606_progress='BOUNDED_MONOTONIC_DIAGNOSTICS_ONLY')

def source_context(root):
 return _readback_fact(_readback_parent(root).source_context(root))

def prove(root):
 fact=_readback_fact(_readback_parent(root).prove(root))
 return dict(fact,status='PASS_WHOLE574_AND_INSTALLED606_DIAGNOSTICS_SOURCE_ONLY')

_TEST_INGRESS_INVERSE={'bytes': 318137, 'sha256': 'cc0c74a246d9e1c6f004ae55c5cc9b1ebf28fe99f002fca8ab26bf91d5545f5b'}
_TEST_INGRESS_PARENT={'bytes': 100980, 'sha256': '546c0b3a374393290a217eed78040f4feaa46476a60ab51220d1b9e39c330535'}
_TEST_INGRESS_ADDED=['factory/fresh606.py', 'factory/guest_clock606.py', 'factory/kernel-keyboard/.github/actions/current606-ksm-virtio-input/action.yml', 'factory/kernel-keyboard/scripts/ci/current606-ksm-virtio-input/base-build-receipt.json', 'factory/kernel-keyboard/scripts/ci/current606-ksm-virtio-input/base.config', 'factory/kernel-keyboard/scripts/ci/current606-ksm-virtio-input/build_kernel.py', 'factory/kernel-keyboard/scripts/ci/current606-ksm-virtio-input/expected-ipv6.config', 'factory/kernel-keyboard/scripts/ci/current606-ksm-virtio-input/kernel.fragment', 'factory/kernel-keyboard/scripts/ci/current606-ksm-virtio-input/lane.py', 'factory/kernel-keyboard/scripts/ci/current606-ksm-virtio-input/test_controls.py', 'factory/kernel-keyboard/scripts/ci/current606-ksm-virtio-input/verify.py', 'factory/kernel-keyboard/scripts/ci/ksm2-kernel-native/runtime.py', 'factory/kernel-keyboard/scripts/ci/tools-generic16k/acquire_kernel.py', 'factory/kernel-keyboard/scripts/virtual/generic16k/fetch_inputs.py', 'factory/kernel-keyboard/scripts/virtual/generic16k/inputs.json', 'factory/kernel-keyboard/source-plan.json', 'factory/kernel_media_handoff.py', 'factory/public_certificate.py', 'factory/wayland_seat606.py', 'fresh-test/progress576-inverse.json', 'fresh-test/public/LICENSE', 'fresh-test/public/catalog.json', 'fresh-test/public/catalog.json.sig', 'fresh-test/public/index.json', 'fresh-test/public/public-key.asc', 'fresh-test/public/signatures/dns2.sig', 'fresh-test/public/signatures/doctor.sig', 'fresh-test/public/signatures/held77-index.sig', 'fresh-test/public/signatures/native73-index.sig', 'fresh-test/public/signatures/orphans.sig', 'fresh-test/public/signatures/welcome5.sig', 'fresh-test/selection.json']
_TEST_INGRESS_NEW={'.github/workflows/native-arm-build.yml': {'bytes': 19177, 'sha256': 'e10d4eab4528d521b7aa09fd0e7474626655ccea6fb67c72b704ed74379533eb'}, '.github/workflows/native-arm-current606-welcome8-gui.yml': {'bytes': 19177, 'sha256': 'e10d4eab4528d521b7aa09fd0e7474626655ccea6fb67c72b704ed74379533eb'}, 'factory/extend_welcome8.py': {'bytes': 8164, 'sha256': '41f05ad036c5b0ec4e613de378062644c4621d621fabfb5b2fa0243da3b7d630'}, 'factory/factory.py': {'bytes': 21549, 'sha256': '52e5c131bb44e0b687382219a106cee9f29a42163c8bad9d036e9f35043a2d06'}, 'factory/fresh606.py': {'bytes': 21863, 'sha256': 'db011d75cb75f73f3d3ca77b97397a95ef1e34c75fd66d3b4e30516d4d072cec'}, 'factory/guest_clock606.py': {'bytes': 8680, 'sha256': '6675352f4fae070843229d55de914a7c66c1f403a2a312bd40f0ac5e09e127e6'}, 'factory/kernel-keyboard/.github/actions/current606-ksm-virtio-input/action.yml': {'bytes': 2585, 'sha256': 'b4c87d6e1d0298410cb075635caf259cd6f4eb393c653eb628e8364acaefd9c2'}, 'factory/kernel-keyboard/scripts/ci/current606-ksm-virtio-input/base-build-receipt.json': {'bytes': 6955, 'sha256': 'fdd538c9e3c73f906da0c82f0b381b0385306a52d0dc1539ab13ceaa69938398'}, 'factory/kernel-keyboard/scripts/ci/current606-ksm-virtio-input/base.config': {'bytes': 63793, 'sha256': '5f1f5e507586734c0955607960ceecfe822b5c908bfc1da9d29fe80ac627a8e9'}, 'factory/kernel-keyboard/scripts/ci/current606-ksm-virtio-input/build_kernel.py': {'bytes': 20690, 'sha256': 'f165f8aca3aca2a8a9332de7b9cc085e3aed85a1eb55c3aac6a63d5c30dfd4ca'}, 'factory/kernel-keyboard/scripts/ci/current606-ksm-virtio-input/expected-ipv6.config': {'bytes': 64368, 'sha256': '8f9c37958a64701c8e0459ba29c78def06810291018a75cc657ab736a10bb917'}, 'factory/kernel-keyboard/scripts/ci/current606-ksm-virtio-input/kernel.fragment': {'bytes': 1882, 'sha256': 'a12ed0611ea50eb50e3c762d4df5cd074f81b82ef4c5b934303751ecb46bf544'}, 'factory/kernel-keyboard/scripts/ci/current606-ksm-virtio-input/lane.py': {'bytes': 7320, 'sha256': '2398cd057ebf1790f168ebfb6ffbb059ca95b9e5cb0a86a44b16e7d9e7ade2b5'}, 'factory/kernel-keyboard/scripts/ci/current606-ksm-virtio-input/test_controls.py': {'bytes': 12541, 'sha256': '792dee63c6c4e85bb3a37c2ffe26cde3d95f0a50ed605cee175dc826ae3c8813'}, 'factory/kernel-keyboard/scripts/ci/current606-ksm-virtio-input/verify.py': {'bytes': 9742, 'sha256': 'f23d2d0ab0a5aaf5fd1fa8325ca608ce8224d3ad5846e37bacb4bc9251da80b9'}, 'factory/kernel-keyboard/scripts/ci/ksm2-kernel-native/runtime.py': {'bytes': 16274, 'sha256': '4d9aa954d95032ab9ea9085ced784efc81a5db42e2f1f3401e679ee861c16090'}, 'factory/kernel-keyboard/scripts/ci/tools-generic16k/acquire_kernel.py': {'bytes': 8844, 'sha256': '4a372e1f4bfbd1f8604579873fc6fbdec91ac2555bb36f028646017b44b8c23f'}, 'factory/kernel-keyboard/scripts/virtual/generic16k/fetch_inputs.py': {'bytes': 7768, 'sha256': '212a0a9efc7c386158526ce40683a3646a899a9c7fd2c3140d6e24a02d778043'}, 'factory/kernel-keyboard/scripts/virtual/generic16k/inputs.json': {'bytes': 1057, 'sha256': 'bdfa44ed1d017c0d0e15c1f3af87bdf4a91923c20e812c861ca522d2cf428492'}, 'factory/kernel-keyboard/source-plan.json': {'bytes': 1718, 'sha256': 'f2947db5147055ab8767705ea40a3870c752f9e8fd50cbfe071a94f58e0bec47'}, 'factory/kernel_media_handoff.py': {'bytes': 7919, 'sha256': 'eafdd86618cce436ea967b01fb94026f7640c8f9a878be338b35939a11f5952f'}, 'factory/kernel_stage.py': {'bytes': 7535, 'sha256': 'aaf67829dc65bbc76125a33a01cf0ea0cbc6d2990343d5d4e6b78843217994ab'}, 'factory/public_certificate.py': {'bytes': 5557, 'sha256': '67117180079bc527f7b58d023cb4eb530a3960745f48520352da92274ac30a6f'}, 'factory/service_capacity.py': {'bytes': 7666, 'sha256': '7b840a6f340b53717dfe021bc1af93000f5999221368183ae65f40f77dbd341f'}, 'factory/wayland_seat606.py': {'bytes': 7867, 'sha256': '8395454829652e06e7690e32694b3281a1baf97a45aff800cfe682433d39df88'}, 'fresh-test/progress576-inverse.json': {'bytes': 318137, 'sha256': 'cc0c74a246d9e1c6f004ae55c5cc9b1ebf28fe99f002fca8ab26bf91d5545f5b'}, 'fresh-test/public/LICENSE': {'bytes': 1081, 'sha256': '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7'}, 'fresh-test/public/catalog.json': {'bytes': 2810, 'sha256': '6ed58fef9212df4a2a620be0b2a1981e84960e97fb2f385a089fda7e5e000f32'}, 'fresh-test/public/catalog.json.sig': {'bytes': 310, 'sha256': '0b03709612a2625b60f8087f22d61284963b847586da4e95ae9a7a0944ddd2b0'}, 'fresh-test/public/index.json': {'bytes': 1790, 'sha256': '1526818a4b16e32b6b2d2c324f78d9fa546bd86b82f89e9333ae2c98e034c509'}, 'fresh-test/public/public-key.asc': {'bytes': 1026, 'sha256': 'ef65c22af0d5b304c050220d08ef3c82bea85c17eaa37ed2c8044793a23bef04'}, 'fresh-test/public/signatures/dns2.sig': {'bytes': 310, 'sha256': 'adeafdbe4b87b3a67dcb399295292178891537ef4bfe9f2953c07f647f5fb6d9'}, 'fresh-test/public/signatures/doctor.sig': {'bytes': 310, 'sha256': '964b8dfebb559dbd16509fe73e3451ece512fbc4b84dda7a0e5455d72edae4ea'}, 'fresh-test/public/signatures/held77-index.sig': {'bytes': 310, 'sha256': '3ae5fedb737006523f657ac96aeb55b48be42a776d979e05c40badab57faf735'}, 'fresh-test/public/signatures/native73-index.sig': {'bytes': 310, 'sha256': 'aabce37b5c52da6761a3c7d6e26384095d6925c9460e3ea8a084236ff6381db3'}, 'fresh-test/public/signatures/orphans.sig': {'bytes': 310, 'sha256': 'c15065fbf529c368f9f55b7bddd072dc5e8b347d341c2518fbaa8fb2fc34987e'}, 'fresh-test/public/signatures/welcome5.sig': {'bytes': 310, 'sha256': '07ccf233b14bdb941095bc5aaa0c26479f36163e35869e79c4c87111c55e598c'}, 'fresh-test/selection.json': {'bytes': 25712, 'sha256': '4fa6ddf54bcfa7fc5a80eb80e8b6299ce0139c62e4a53bd4ce70c7a8192ee0b8'}, 'kernel-media-profile.json': {'bytes': 2681, 'sha256': '42f74b9a1b3e83b79513908f79442e6c48410bbca577e632989e49b4c0e898ff'}, 'native.py': {'bytes': 16736, 'sha256': '86e5dc11452c90603f4e9b4bdb5817b82c593d6972569fde55a4517744c0adb8'}}
_TEST_INGRESS_COUNT=608

def _ingress_original(root):
 root=Path(root).absolute()
 context=obj(root/'fresh-test/progress576-inverse.json')
 need(pin(enc(context))==_TEST_INGRESS_INVERSE,'whole progress576 ingress inverse')
 old_manifest=base64.b64decode(context['manifest'],validate=True)
 need(pin(old_manifest)==_TEST_INGRESS_PARENT,'whole immutable progress576 manifest')
 original_files={**json.loads(old_manifest)['files'],'source-manifest.json':pin(old_manifest)}
 future=obj(root/'source-manifest.json')
 need(future['actual_source'] is future['actual_ref'] is future['actual_run'] is None and future['status']=='SOURCE_ONLY_CURRENT606_EXACT_FRESH_TEST_INGRESS','unissued new GUI Source scope')
 need(set(future['files'])==set(original_files)-{'source-manifest.json'}|set(_TEST_INGRESS_ADDED),'exact fresh ingress source delta')
 closed(root,{**future['files'],'source-manifest.json':pin(read(root/'source-manifest.json'))})
 need(all(future['files'][name]==want for name,want in _TEST_INGRESS_NEW.items()),'all exact bound fresh ingress functions and public proof bytes')
 before={n:base64.b64decode(raw,validate=True) for n,raw in context['before'].items()}
 before['source-manifest.json']=old_manifest
 def prior_read(path,cap=16*1024**2):
  name=Path(path).relative_to(root).as_posix();raw=before[name] if name in before else read(path,cap)
  need(name in original_files and len(raw)<=cap and pin(raw)==original_files[name],'whole original progress576 byte '+name);return raw
 def prior_closed(where,wanted):
  prefix='' if where==root else where.relative_to(root).as_posix()+'/'
  need({n.removeprefix(prefix):w for n,w in original_files.items() if n.startswith(prefix)}==wanted,'only original progress source namespace')
  for n in wanted:prior_read(where/n)
  return wanted
 for name in original_files:prior_read(root/name)
 prior=types.ModuleType('_exact_current606_progress576');prior.__file__=str(root/'admission.py')
 exec(compile(before['admission.py'],prior.__file__,'exec'),vars(prior))
 prior.read=prior_read;prior.obj=lambda p:json.loads(prior_read(p));prior.closed=prior_closed
 return prior

def source_context(root):
 return dict(_ingress_original(root).source_context(root),files=_TEST_INGRESS_COUNT,fresh_ingress='PUBLIC_ONLY_CURRENT_TEST_INPUTS')

def prove(root):
 parent=_ingress_original(root).prove(root)
 need(parent['files']==576 and parent['fullscan_seconds']==600,'whole original progress and unchanged600 deadline')
 return dict(parent,files=_TEST_INGRESS_COUNT,fresh_ingress='PUBLIC_ONLY_CURRENT_TEST_INPUTS',status='PASS_COMPLETE_PROGRESS576_AND_FRESH_TEST_INGRESS_SOURCE_ONLY')
