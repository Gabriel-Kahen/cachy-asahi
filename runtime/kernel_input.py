# SPDX-License-Identifier: MIT
"""Explicit retained kernel DATA import. Original absolute paths stay provenance."""
import ast,copy,json,re,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C
NAMES={'Image','Image.header','config','kernel-profile.json','build-receipt.json','build_kernel.py','kernel.fragment','diagnostic.fragment','archive-header.bin','configuration-delta.json','baseline.config','baseline-build-receipt.json','source-proof.json','source-manifest.json','acquisition.json','controller.json','ordered-cleanup.json','configure.log','build.log'}|{p+'-controller'+s for p in('baseline','candidate')for s in('.json','.stdout','.stderr')}

def project_paths(original,directory):
 projected=copy.deepcopy(original)
 for field,name in(('image','Image'),('config','config')):projected[field]['path']=str(Path(directory)/name)
 inverse=copy.deepcopy(projected)
 for field in('image','config'):inverse[field]['path']=original[field]['path']
 C.need(inverse==original,'only exact two DATA path fields may project');return projected

def imported(s,inputs,root=C.HERE):
 C.need(all(s.get(k)is not None for k in('kernel_build','kernel_source','kernel_run','kernel_authority','kernel_transport')),'UNBOUND fresh kernel DATA source/run/build')
 C.need(re.fullmatch('[a-f0-9]{40}',s['kernel_source']or'')and type(s['kernel_run'])is int and s['kernel_run']>0,'exact selected kernel build source/run')
 proposal=C.decode(C.read(Path(root)/'kernel-decision-contract.json',65536));C.need(s['kernel_source']==proposal['known_source'],'exact source-owned kernel component identity');authority=C.decode(C.checked(inputs,s['kernel_authority'],65536));C.need(type(authority)is dict and set(authority)==set(proposal['required_fields'])and authority['status']==proposal['decision_status']and authority['source']==s['kernel_source']and authority['run']==s['kernel_run'],'finite same-source Root kernel build-only authority required')
 for name,value in proposal['finite_expectations'].items():C.need(authority[name]==value,'finite kernel build scope: '+name)
 transport=C.checked(inputs,s['kernel_transport'],1024**2);C.need(C.pin(transport)==authority['original_transport'],'exact original kernel transport DATA receipt pin, not aggregate PASS');C.decode(transport)
 ref=s['kernel_build'];descriptor=C.decode(C.checked(inputs,ref,2*1024**2));directory=Path(inputs)/Path(ref['path']).parent;C.need(authority['descriptor']=={k:ref[k]for k in('bytes','sha256')},'exact Root descriptor byte pin')
 C.need(descriptor['status']=='BUILT_ONLY_KSM_DIAGNOSTIC16K_NOT_BOOTED'and set(descriptor['files'])==NAMES and descriptor['receipt_paths']=='ORIGINAL_BUILD_PROVENANCE_NOT_VALID_AT_IMPORT','exact retained build-only DATA; not same-job build gate')
 total=0;raw={}
 for name,pin in descriptor['files'].items():
  cap=256*1024**2 if name=='Image'else 16*1024**2;raw[name]=C.checked(directory,dict(path=name,**pin),cap,allow_empty=name.endswith(('.stdout','.stderr','.log')));total+=len(raw[name])
 for field,name in(('source_manifest','source-manifest.json'),('configuration_delta','configuration-delta.json'),('Image','Image'),('config','config'),('build_receipt','build-receipt.json')):C.need(authority[field]==C.pin(raw[name]),'exact Root kernel file pin: '+field)
 C.need(authority['archive']==dict(bytes=262965559,sha256='874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad',source_revision='94fb23346d522edf53722357c426a3e58030beea'),'exact Root original source archive pin')
 C.need(total==descriptor['total_bytes']and total<=384*1024**2,'whole bounded retained kernel closure')
 own=Path(root)/'kernel-build-source';manifest=C.read(own/'scripts/ci/ksm2-kernel-native/source-manifest.json',1024**2);C.need(raw['source-manifest.json']==manifest,'exact source-owned closed kernel build manifest')
 proof=C.decode(raw['source-proof.json']);C.need(proof==descriptor['source']and proof['status']=='SOURCE_PROOF_PASS_BUILD_ONLY'and proof['source_sha']==proof['workflow_sha']==s['kernel_source']and proof['run_id']==str(s['kernel_run'])and proof['run_attempt']=='1'and proof['ref']==proposal['known_ref']and proof['manifest']==C.pin(manifest)and proof['profile']==C.PROFILE,'genuine selected build source/workflow/run/manifest joins')
 KP=C.load('_ksm_import_profile',Path(root)/'profile/ksm_profile.py');K=KP.contract(Path(root)/'kernel-source');H=KP.helper(Path(root)/'kernel-source');H.HERE=directory
 C.need(raw['build_kernel.py']==KP.build_helper(KP.held(Path(root)/'kernel-source','build_kernel.py'))and raw['kernel.fragment']==KP.fragment(KP.held(Path(root)/'kernel-source','kernel.fragment'))and raw['diagnostic.fragment']==raw['kernel.fragment']+H.DIAGNOSTIC_FRAGMENT.encode(),'whole derived profile helper/fragment/diagnostic source joins')
 original=C.decode(raw['build-receipt.json'])
 for field,name in(('image','Image'),('config','config')):C.need({k:original[field][k]for k in('bytes','sha256')}==C.pin(raw[name])and type(original[field]['path'])is str and Path(original[field]['path']).is_absolute(),'original receipt complete imported bytes and path provenance')
 C.load('_ksm_required_advice',Path(root)/'sharing.py').require_kernel_config(raw['config'])
 projected=project_paths(original,directory)
 profile,image,config=K.from_receipt(projected,H,raw['kernel.fragment'],C.sha(raw['build_kernel.py']),C.sha(raw['kernel.fragment']));KP.check_config(config)
 C.need(profile==descriptor['profile']==C.decode(raw['kernel-profile.json'])and raw['Image.header']==raw['Image'][:64],'exact imported profile/actual Image header')
 tree=ast.parse(C.read(own/'scripts/ci/ksm2-kernel-native/lane.py',65536));functions=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in('config_values','delta')];C.need(len(functions)==2,'whole original two pure config DATA functions');ns=dict(need=C.need,pin=C.pin,re=re);exec(compile(ast.Module(body=functions,type_ignores=[]),'held-build-config-data','exec'),ns);C.need(ns['delta'](raw['baseline.config'],raw['config'])==C.decode(raw['configuration-delta.json']),'genuine same-environment baseline advice/KSM/XXHASH-only config delta')
 acquisition=C.decode(raw['acquisition.json']);C.need(acquisition['status']in('FETCHED_HASH_VERIFIED','RETAINED_ARCHIVE_HASH_VERIFIED','RESTORED_HASH_VERIFIED')and acquisition['partial_absent']is True and acquisition['source_revision']==K.REVISION and acquisition['bytes']==262965559 and acquisition['sha256']==K.ARCHIVE,'whole source-pinned archive acquisition receipt');C.need(descriptor['archive']['sha256']==K.ARCHIVE and descriptor['archive']['bytes']==262965559 and original['archive']['sha256']==K.ARCHIVE and len(raw['archive-header.bin'])==64,'original pinned archive/source header scope')
 cleanup=C.decode(raw['ordered-cleanup.json']);C.need(cleanup==descriptor['cleanup']and cleanup['status']=='PASS_OWNED_BUILD_WORK_REMOVED'and cleanup['absence_verified']is True,'separate original kernel build work retirement')
 controller=C.decode(raw['controller.json']);C.need(controller['status']=='PASS_NATURAL_KERNEL_HELPERS'and controller['controller_seconds']==3700 and controller['baseline_retired_before_candidate']is True,'original bounded build controller')
 for name,limit in(('baseline',300),('candidate',3700)):
  row=C.decode(raw[name+'-controller.json']);C.need(row in controller['commands']and row['exit_code']==0 and row['group_absence_verified']is True and 0<row['time_limit']<=limit,'actual build helper natural group retirement')
 for key in('boot','VM','live_kernel_write','hardware'):C.need(descriptor[key]=='NOT_RUN','build-only evidence cannot grant boot or kernel write credit')
 return profile,dict(status='IMPORTED_BUILD_DATA_NOT_SAME_JOB_RECEIPT',original_receipt=C.pin(raw['build-receipt.json']),original_paths={k:original[k]['path']for k in('image','config','helper','fragment')},path_projection='IMAGE_AND_CONFIG_DATA_REFS_ONLY_ORIGINAL_RECEIPT_UNMODIFIED',source=proof,descriptor=C.pin(C.encoded(descriptor))),image,config
