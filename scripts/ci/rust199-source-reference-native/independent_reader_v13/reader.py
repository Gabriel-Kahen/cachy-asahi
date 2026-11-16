#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Offline independent Rust351 evidence DATA Reader. Never executes Source code."""
import argparse,hashlib,importlib.util,json,os,re,stat,sys,time,tarfile,zipfile
from pathlib import Path
HERE=Path(__file__).resolve().parent

def load(name):
 spec=importlib.util.spec_from_file_location('independent_rust13_'+name,HERE/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
S=load('storage');B=load('bindings');E=load('evidence');A=load('archives');A.E=load('elf')
for m in(B,E,A):m.S=S
PROGRAMS=('reader.py','storage.py','bindings.py','evidence.py','archives.py','elf.py')
MAX=dict(wall_seconds=600,address_space_bytes=1024**3,cpu_seconds=600,scratch_bytes=4*1024**3,scratch_files=8)
CORE={'profile','grant_shape','source_review','publication','dispatch','terminal_run','terminal_jobs','transfer_manifest','transfer_artifact_metadata','transfer_bootstrap_job_metadata','transfer_run_metadata','transfer_provider_host','transfer_acquisition','transfer_import','transfer_zip','operational_admission','candidate_admission','native_qualification','qualification_envelope','producer','init_finished','prepare_finished','makepkg_finished','init_inspect','prepare_inspect','makepkg_inspect','volume_initialization','volume_admission','baseline_inventory','qualified_inventory','build_export','bootstrap_daemon','build_daemon'}
CORE|={phase+'_'+name for phase in('bootstrap','build')for name in('hosted','provider','jobs_start','operations','image_retirement','artifact_metadata','artifact_zip')}
CORE|={role+'_'+kind for role in B.CARRIERS for kind in('artifact','job')}
LLVM_ROLES=dict(archive='llvm_archive',root_decision='llvm_root_decision',signature='llvm_signature',public_test_key='llvm_public_key',verification_proof='llvm_public_verification')
CORE|=set(LLVM_ROLES.values())|{'llvm_reader_binding','llvm_reader_result'}
class Corpus:
 def __init__(self,root,request):
  self.root=Path(root);self.rows=request['files'];self.roles=request['roles'];self.external=request.get('external_files',{})
  S.need(type(self.rows)is dict and 1<=len(self.rows)<=2048 and set(self.roles)==CORE and set(self.external)<=set(self.rows),'EXACT_READER_ROLE_SCHEMA')
  S.need(S.namespace(self.root)==set(self.rows)-set(self.external),'COMPLETE_RETAINED_NAMESPACE')
  for name,row in self.rows.items():
   S.relative(name);S.need(set(row)=={'bytes','sha256'}and type(row['bytes'])is int and 0<=row['bytes']<=16*S.GIB and S.digest(row['sha256']),'EXTERNAL_WHOLE_FILE_PIN')
  for name in self.roles.values():S.need(name in self.rows,'ROLE_MEMBER_MISSING')
  S.need(all(type(p)is str and Path(p).is_absolute()for p in self.external.values()),'EXTERNAL_DATA_PATH_TYPE')
  S.need(sum(r['bytes']for r in self.rows.values())<=48*S.GIB,'WHOLE_RETAINED_DATA_BOUND')
  for name,row in self.rows.items():S.need(S.hashed(self.path(name),row['bytes'])==row,'RETAINED_FILE_CHANGED_OR_WHOLE_PIN')
 def path(self,name):
  S.need(name in self.rows,'UNSELECTED_DATA_PATH');return Path(self.external[name])if name in self.external else self.root/name
 def raw(self,role,cap=8*S.MIB):return S.read(self.path(self.roles[role]),cap)
 def obj(self,role,cap=8*S.MIB):return S.decode(self.raw(role,cap))
 def member(self,name,cap=8*S.MIB):return S.read(self.path(name),cap)

def selector(request):
 S.need(type(request)is dict and type(request.get('schema'))is int and request.get('schema')==13 and request.get('kind')=='ROOT_SELECTED_RUST351_RETAINED_EVIDENCE_READER_V13'and request.get('issuer')=='Root'and request.get('approved')is True,'ROOT_READER_SELECTION_UNISSUED')
 selected=dict(request['selected']);S.need(re.fullmatch('[0-9a-f]{40}',selected.get('source')or '')and re.fullmatch(r'refs/heads/codex/rust199-source351-native-v13-[A-Za-z0-9._-]+',selected.get('ref')or '')and all(S.numeric(selected.get(k))for k in('run','bootstrap_job','build_job','bootstrap_artifact_id','build_artifact_id'))and selected['bootstrap_job']!=selected['build_job'],'ROOT_EXACT_SOURCE_RUN_JOB_SELECTORS')
 S.need(S.digest(selected.get('source_review_sha256'))and S.digest(selected.get('dispatch_sha256')),'ROOT_EXPLICIT_REVIEW_DISPATCH_PINS')
 r=request['resources'];S.need(type(r)is dict and r==MAX and all(type(v)is int for v in r.values()),'ROOT_READER_RESOURCE_PROPOSAL_UNADMITTED')
 return selected

def artifact(meta,phase,selected,pin):
 wr=meta['workflow_run'];S.need(str(meta['id'])==selected[phase+'_artifact_id']and meta['expired']is False and meta['name']=='rust199-'+phase+'-v4-'+selected['run']+'-1'and str(wr['id'])==selected['run']and wr['head_sha']==selected['source']and wr['head_branch']==selected['ref'].removeprefix('refs/heads/')and meta['size_in_bytes']==pin['bytes']and meta['digest']=='sha256:'+pin['sha256'],'CURRENT_PHASE_ORIGINAL_ARTIFACT_TUPLE')

def manifest_data(manifest,corpus,members):
 rows=manifest['files'];S.need(type(rows)is dict and 1<=len(rows)<=201 and set(members)==set(rows)|{'manifest.json'},'COMPLETE_PHASE_TRANSFER_NAMESPACE')
 for name,row in rows.items():S.relative(name);S.need(corpus.rows[members[name]]=={k:row[k]for k in('bytes','sha256')}and row['mode']==0o444,'TRANSFER_EVERY_SELECTED_FILE_PIN')
 used=set()
 def walk(v):
  if isinstance(v,dict):
   if set(v)=={'__rust_phase_file__'}:S.need(v['__rust_phase_file__']in rows,'TRANSFER_UNDECLARED_PATH_MARKER');used.add(v['__rust_phase_file__'])
   else:
    if {'bytes','sha256'}<=set(v)and('local_path'in v or'path'in v):
     ref=v.get('local_path',v.get('path'));S.need(type(ref)is dict and set(ref)=={'__rust_phase_file__'}and ref['__rust_phase_file__']in rows,'TRANSFER_DESCRIPTOR_REFERENCE')
     S.need({k:v[k]for k in('bytes','sha256')}=={k:rows[ref['__rust_phase_file__']][k]for k in('bytes','sha256')},'TRANSFER_DESCRIPTOR_WHOLE_JOIN')
    for child in v.values():walk(child)
  elif isinstance(v,list):
   for child in v:walk(child)
 walk(manifest['metadata']);S.need(used==set(rows)-{'image.tar'},'TRANSFER_ALL_MATERIAL_PROOF_REFERENCES')
 return manifest['metadata']

def relocated(v):
 if type(v)is dict:return {k:None if k in('path','local_path','proof_path')else relocated(x)for k,x in v.items()}
 if type(v)is list:return [relocated(x)for x in v]
 return v

def qualification_kernels(manifest,c,members,q,bootstrap):
 files=manifest['metadata']['qual']['files']
 def retained(name):
  S.relative(name);S.need('qualification_'+name in files,'MOUNTINFO_QUALIFICATION_FILE_REQUIRED')
  row=files['qualification_'+name];ref=row.get('local_path',row.get('path'))
  S.need(type(ref)is dict and set(ref)=={'__rust_phase_file__'}and ref['__rust_phase_file__']in members,'MOUNTINFO_QUALIFICATION_SELECTED_MEMBER')
  raw=c.member(members[ref['__rust_phase_file__']],64*S.MIB)
  S.need(S.pin(raw)=={k:row[k]for k in('bytes','sha256')},'MOUNTINFO_QUALIFICATION_SELECTED_WHOLE_BODY');return raw
 return E.qualification_kernel(q,bootstrap,c.source,retained)

def transferred_qualification(manifest,c,members,q,bootstrap,selected,custody):
 meta=manifest['metadata'];boot,qual=meta['boot'],meta['qual'];binding=dict(source=selected['source'],ref=selected['ref'],run=selected['run'],job=selected['bootstrap_job'],source_map_sha256=S.SOURCE['map_sha256'],approval=selected['source_review_sha256']);token=S.pin(S.canonical(binding))['sha256'][:24]
 owner=dict(source=selected['source'],run=selected['run'],job=selected['bootstrap_job'],token=token,base_tag='rust199-base:'+token,tag='rust199-qualified:'+token)
 S.need(manifest['owner']==boot['owner']==owner and boot['provider_binding']==bootstrap and boot['status']=='PASS_NORMAL_SIGNED_LLVM_IMAGE_DATA'and boot['errors']==[]and boot['native_acceptance']is False and boot['image']==selected['transfer']['image_id']and boot['rootfs_tree_sha256']==q['rootfs_tree_sha256'],'WHOLE_BOOTSTRAP_IMAGE_QUALIFICATION_CONTEXT')
 extraction=boot.get('extraction');S.need(type(extraction)is dict and set(extraction)=={'files','logical_bytes','rootfs_tree_sha256','digest_timing','final_modes_verified'} and
  type(extraction['files'])is int and 1<=extraction['files']<=600000 and type(extraction['logical_bytes'])is int and 0<=extraction['logical_bytes']<=16*S.GIB and
  S.digest(extraction['rootfs_tree_sha256']) and extraction['digest_timing']=='PRIVATE_READABLE_STAGING_BEFORE_EXACT_MODE_FINALIZATION' and extraction['final_modes_verified']is True and extraction['rootfs_tree_sha256']==boot['rootfs_tree_sha256']==q['rootfs_tree_sha256'],'EXACT_PRE_FINALIZATION_ROOTFS_STAGING_RECEIPT')
 S.need({k:v for k,v in qual.items()if k not in('files','proof_path','proof_sha256')}==q,'TRANSFERRED_QUALIFICATION_EXACT_PROOF')
 def retained(row):
  ref=row.get('local_path',row.get('path'));S.need(type(ref)is dict and set(ref)=={'__rust_phase_file__'}and ref['__rust_phase_file__']in members,'QUALIFICATION_DECLARED_RETAINED_REFERENCE');raw=c.member(members[ref['__rust_phase_file__']],64*S.MIB);S.need(S.pin(raw)=={k:row[k]for k in('bytes','sha256')},'QUALIFICATION_RETAINED_WHOLE_BODY');return raw
 controller=S.decode(retained(qual['files']['qualification_controller']));S.need(controller['status']=='PASS_NATIVE_SOURCE_QUALIFICATION_ONLY'and controller['errors']==[]and controller['owned_resources_absent']is True and not controller.get('forced_cleanup')and controller['result']==q,'NATIVE_QUALIFICATION_NATURAL_CLEANUP')
 S.need(controller.get('container_ids')==custody,'QUALIFICATION_ACKNOWLEDGED_CID_REPORT_JOIN')
 outputs=[]
 for receipt in q['probe_receipts']:
  stdout=retained(qual['files']['qualification_'+receipt['stdout']]);retained(qual['files']['qualification_'+receipt['stderr']]);outputs.append(stdout.decode().strip())
 S.need(len(outputs)==9 and 'release: 1.98.0'in outputs[0].splitlines()and 'host: aarch64-unknown-linux-gnu'in outputs[1].splitlines()and outputs[2]=='/stage0'and outputs[3].startswith('cargo 1.98.0 ')and outputs[4].startswith('rustdoc 1.98.0 ')and outputs[5]=='23.1.1'and 'AArch64'in outputs[6].split()and outputs[7].startswith('aarch64-')and outputs[7].endswith('linux-gnu')and '23.1.1'in outputs[8],'ACTUAL_STAGE0_LLVM_GCC_PROBE_OUTPUTS')
 return owner

def operational(a,c,grant,bootstrap,build,q,selected):
 S.need(a['schema']==1 and a['status']=='ROOT_ADMITTED_RUST199_NATIVE_PRIVATE_BUILD'and a['source']==build['source']and a['holds_preserved']is True and a['claims']==B.CLAIMS and a['image']['id']==selected['transfer']['image_id']and a['stage0_tree_sha256']==q['stage0_tree_sha256']and a['image']['rootfs_tree_sha256']==q['rootfs_tree_sha256']and a['image']['qualified_llvm_tree_sha256']==q['qualified_llvm_tree_sha256'],'EXACT_DERIVED_OPERATIONAL_QUALIFICATION')
 S.need(a['resources']==E.OPERATIONAL_RESOURCES and a['candidate']['notice_binding']==S.decode(c.source['candidate-map.json'][0])['notice_binding'],'OPERATIONAL_FIXED_RESOURCE_NOTICE_BINDING');S.need(a['candidate']['commit']=='dd6871d566661c4fe9eba055ae19e1e017e0b69d'and a['candidate']['inputs_sha256']=='4011253ed366f871b1f5e2cac1f5af0dc63049c1fa7badd293318adb44741672','EXACT_CANDIDATE_INPUTS')
 cp=c.raw('candidate_admission');S.need(S.pin(cp)=={k:a['candidate_admission'][k]for k in('bytes','sha256')},'CANDIDATE_ADMISSION_WHOLE_PIN');candidate=S.decode(cp)
 S.need(candidate['scope']=='PRIVATE_SOURCE_REFERENCE_INPUT_QUALIFICATION_ONLY'and candidate['status']=='QUALIFIED_FOR_PRIVATE_BUILD_ONLY'and candidate['holds_preserved']is True and candidate['source_audit']==grant['source_audit'],'CANDIDATE_SOURCE_AUDIT_HOLDS')
 S.need(B.without_local(a['llvm'])==B.without_local(grant['llvm']),'ROOT_LLVM_DECLARATION_UNCHANGED')
 auth=a['authorization'];expected={'dispatch':c.raw('dispatch',16384),'provider':S.canonical(dict(schema=4,status='PROVIDER_PHASE_BRIDGE',dispatch_sha256=selected['dispatch_sha256'],bootstrap=bootstrap,build=build)),'qualification':c.raw('qualification_envelope')}
 S.need(set(auth)==set(expected),'EXACT_THREE_AUTHORIZATION_PROOFS')
 for key,raw in expected.items():S.need({k:auth[key][k]for k in('bytes','sha256')}==S.pin(raw),'OPERATIONAL_AUTHORIZATION_WHOLE_PINS')
 S.need(c.raw('baseline_inventory')==c.source['expected349.lock'][0]and S.pin(c.raw('baseline_inventory'))=={k:a['image']['baseline_inventory'][k]for k in('bytes','sha256')},'COMPLETE_BASELINE349_INVENTORY')
 qualified=c.raw('qualified_inventory');S.need(S.pin(qualified)=={k:a['image']['qualified_inventory'][k]for k in('bytes','sha256')}and len(qualified.splitlines())==a['image']['qualified_inventory']['count'],'WHOLE_QUALIFIED_INVENTORY')
 initial=S.decode(c.source['packages/port/rust199-source-reference/inputs.json'][0])['archives'];S.need(len(a['materials'])==len(initial)==5 and {r['name']for r in a['materials']}==set(initial),'ALL_FIVE_EXACT_MATERIALS')
 pins={name:{k:row[k]for k in('bytes','sha256')}for name,row in initial.items()}
 for row in grant['delivery']['stage0_carrier']['members']:pins[row['name']]={k:row[k]for k in('bytes','sha256')}
 for row in a['materials']:S.need({k:row[k]for k in('bytes','sha256')}==pins[row['name']]and row['transport']=='LOCAL_READONLY','OPERATIONAL_MATERIAL_BYTES_SHA_AND_READONLY')
 return qualified

def producer_custody(producer,finished,custody):
 S.need(type(custody)is dict and set(custody)=={'init','prepare','makepkg'} and producer.get('container_ids')==custody and all(finished[k]['Id']==v for k,v in custody.items()),'PRODUCER_ACKNOWLEDGED_CID_REPORT_FINISH_JOIN')

STAGE='selection'
def read(request,source_root,evidence_root,scratch):
 global STAGE
 STAGE='selection'
 selected=selector(request);S.need(type(request['reader_files'])is dict and set(request['reader_files'])==set(PROGRAMS)and all(S.pin(S.read(HERE/name,2*S.MIB))==request['reader_files'][name]for name in PROGRAMS),'ROOT_SELECTED_WHOLE_READER_CLOSURE');S.END=time.monotonic()+request['resources']['wall_seconds'];c=Corpus(evidence_root,request)
 STAGE='source';c.source=S.source(source_root,c.raw('profile'),request['source_contract']);shape_raw=c.raw('grant_shape');S.need(S.pin(shape_raw)==dict(bytes=14249,sha256='8a564c2a68afd400abf746b8c600620a1a7fec18a814357dd2ba7107ff01074d'),'FIXED_SCHEMA5_GRANT_SHAPE')
 STAGE='root_dispatch';raw=c.raw('dispatch',16384);S.need(S.pin(raw)['sha256']==selected['dispatch_sha256'],'EXTERNAL_DISPATCH_WHOLE_PIN');selected['dispatch_raw']=raw;grant=B.dispatch(raw,S.decode(shape_raw),c.source,selected)
 review=c.obj('source_review');public=c.obj('publication');S.need(S.pin(c.raw('source_review'))['sha256']==selected['source_review_sha256']and review['issuer']=='Root'and review['approved']is True and review['status']=='ROOT_REVIEWED_EXACT_RUST351_SOURCE_V13'and review['constructor_profile_sha256']==S.SOURCE['profile_sha256']and review['source_and_factory_controls_reviewed']is True and review['holds_preserved']is True,'ROOT_EXACT_EXTERNAL_SOURCE_REVIEW')
 S.need(public['issuer']=='Root'and public['status']=='PASS_COMPLETE_PUBLIC_GIT_READBACK_DATA_ONLY'and public['source']==selected['source']and public['ref']==selected['ref']and all(public[k]==S.SOURCE[k]for k in('tree','files','bytes'))and public['source_map_sha256']==S.SOURCE['map_sha256']and public['native']==public['M2']=='NOT RUN'and review['publication_sha256']==S.pin(c.raw('publication'))['sha256'],'ROOT_PUBLIC_SOURCE_WHOLE_IDENTITY')
 STAGE='terminal_provider';B.terminal(c.obj('terminal_run'),c.obj('terminal_jobs'),selected)
 providers={};custody={}
 for phase in('bootstrap','build'):
  STAGE=phase+'_evidence'
  providers[phase]=c.obj(phase+'_provider');B.provider(providers[phase],phase,grant,selected,c.raw(phase+'_jobs_start'))
  hosted=c.obj(phase+'_hosted');S.need(hosted['phase']==phase and hosted['schema']==4 and hosted['dispatch_sha256']==selected['dispatch_sha256']and hosted['native_acceptance']is False and hosted['holds_preserved']is True and not hosted.get('error')and not hosted.get('cleanup_error'),'PHASE_HOSTED_REPORT')
  S.need(hosted['status']==('BOOTSTRAP_QUALIFIED_TRANSFER_DATA_EXPORTED'if phase=='bootstrap'else'RUST199_BUILD_EXPORTED_RETIRED_PENDING_INDEPENDENT_READER'),'PHASE_COMPLETION_STATUS')
  retirement=c.obj(phase+'_image_retirement');S.need(retirement['status']=='PASS_RETIRED'and retirement['errors']==[]and selected['transfer']['image_id']in retirement['images']and hosted['image_retirement']==retirement,'PHASE_IMAGE_NATURAL_ABSENCE')
  E.operations(c.obj(phase+'_operations'),c,phase,request['members'][phase])
  daemon=c.obj(phase+'_daemon')['info'];S.need(daemon['OSType']=='linux'and daemon['Architecture']in('aarch64','arm64')and daemon['CgroupVersion']=='2'and not any('rootless'in s for s in daemon.get('SecurityOptions',[])),'OBSERVED_NATIVE_ROOTFUL_DAEMON')
  zip_path=c.path(c.roles[phase+'_artifact_zip']);zip_pin=c.rows[c.roles[phase+'_artifact_zip']];artifact(c.obj(phase+'_artifact_metadata'),phase,selected,zip_pin);A.zip_members(zip_path,zip_pin,request['members'][phase],c,16*S.GIB)
  for role in(phase+'_hosted',phase+'_provider',phase+'_jobs_start',phase+'_operations',phase+'_image_retirement',phase+'_daemon'):S.need(c.roles[role]in request['members'][phase].values(),'PHASE_EVIDENCE_FROM_OWN_ORIGINAL')
 STAGE='initial_inputs';inputs=B.initial_carriers(grant,{role+'_'+kind:c.obj(role+'_'+kind)for role in B.CARRIERS for kind in('artifact','job')},{role+'_'+kind:c.raw(role+'_'+kind)for role in B.CARRIERS for kind in('artifact','job')})
 for name,role in LLVM_ROLES.items():S.need(c.rows[c.roles[role]]=={k:grant['llvm'][name][k]for k in('bytes','sha256')},'ACCEPTED_LLVM_INPUT_WHOLE_PROOF_PIN')
 for name in('binding','result'):S.need(c.rows[c.roles['llvm_reader_'+name]]=={k:grant['llvm']['reader'][name][k]for k in('bytes','sha256')},'ACCEPTED_LLVM_READER7_PROOF_PIN')
 STAGE='v8_transfer';manifest_raw=c.raw('transfer_manifest',4*S.MIB);manifest=S.decode(manifest_raw);policy=S.decode(c.source[B.POLICY['member']][0]);B.transfer(grant,selected,policy,c.obj('transfer_artifact_metadata'),c.obj('transfer_bootstrap_job_metadata'),c.obj('transfer_run_metadata'),c.obj('transfer_provider_host'),c.obj('transfer_acquisition'),manifest,manifest_raw,providers['bootstrap'])
 S.need(c.rows[c.roles['transfer_zip']]==selected['transfer']['artifact'],'EXTERNAL_TRANSFER_ORIGINAL_PIN');A.zip_members(c.path(c.roles['transfer_zip']),selected['transfer']['artifact'],request['members']['transfer'],c,16*S.GIB);manifest_data(manifest,c,request['members']['transfer']);transfer=c.obj('bootstrap_hosted')['transfer'];S.need(transfer['manifest_sha256']==selected['transfer']['manifest_sha256']and transfer['bootstrap_job_id']==selected['bootstrap_job']and transfer['image_id']==selected['transfer']['image_id'],'BOOTSTRAP_HOSTED_ACTUAL_NEEDS_JOIN')
 imported=c.obj('transfer_import');S.need(imported['status']=='PASS_IMPORTED_VERIFIED_BOOTSTRAP_PHASE_DATA'and imported['source']==providers['build']['source']and imported['bootstrap_provider']==providers['bootstrap']and imported['image']==selected['transfer']['image_id']and imported['load_intent']is True and not imported.get('error'),'COMPLETE_TRANSFER_IMPORT')
 STAGE='native_input_qualification';q=c.obj('native_qualification');envelope=c.obj('qualification_envelope');S.need({k:v for k,v in envelope.items()if k not in('files','proof_path','proof_sha256')}==q and envelope['proof_sha256']==S.pin(c.raw('native_qualification'))['sha256'],'OPERATIONAL_ENVELOPE_RAW_QUALIFICATION_JOIN');S.need(relocated(envelope)==relocated(manifest['metadata']['qual']),'OPERATIONAL_ENVELOPE_TRANSFER_RELOCATION_ONLY');kernel_qualification=qualification_kernels(manifest,c,request['members']['transfer'],q,providers['bootstrap']);custody['bootstrap']=E.custody_operations(c.obj('bootstrap_operations'),c,'bootstrap',selected,selected['transfer']['image_id'],kernel_qualification);image_owner=transferred_qualification(manifest,c,request['members']['transfer'],q,providers['bootstrap'],selected,custody['bootstrap']);image_checks=A.image_tar(c.path(request['members']['transfer']['image.tar']),selected['transfer']['image'],selected['transfer']['image_id'],image_owner);E.qualification(q,providers['bootstrap'],selected['transfer']['image_id']);S.need(q['source_audit']==grant['source_audit']and q['library_cargo_config_sha256']==grant['source_audit']['library_cargo_config_sha256'],'UNCHANGED_ROOT_SOURCE_AUDIT_JOIN');a=c.obj('operational_admission');inventory=operational(a,c,grant,providers['bootstrap'],providers['build'],q,selected)
 for role in('producer','operational_admission','candidate_admission','qualification_envelope','init_finished','prepare_finished','makepkg_finished','init_inspect','prepare_inspect','makepkg_inspect','volume_initialization','volume_admission','baseline_inventory','qualified_inventory','build_export','transfer_manifest','transfer_artifact_metadata','transfer_bootstrap_job_metadata','transfer_run_metadata','transfer_provider_host','transfer_acquisition','transfer_import'):S.need(c.roles[role]in request['members']['build'].values(),'BUILD_OUTPUT_ROLE_FROM_OWN_ORIGINAL')
 STAGE='rust_producer';producer=c.obj('producer');S.need(c.obj('build_hosted')['producer']==producer,'HOSTED_PRODUCER_WHOLE_JOIN');finished={r:c.obj(r+'_finished')for r in('init','prepare','makepkg')};E.producer(producer,a,selected,finished)
 for role in finished:E.inspected(c.obj(role+'_inspect'),finished[role],role,producer,a,c.source)
 volume=c.obj('volume_admission');initialized=c.obj('volume_initialization');S.need(S.pin(c.raw('volume_admission'))['sha256']==producer['volume_admission_sha256']and volume['binding']==producer['volume_binding']==initialized['binding']and initialized['status']=='INITIALIZED_EMPTY_WORK_VOLUME'and initialized['recursive']is False and initialized['capabilities']=='CHOWN_ONLY_CHMOD_BEFORE_CHOWN','EXACT_OWNED_WORK_VOLUME_INITIALIZATION')
 S.need(initialized['before']['uid']==initialized['before']['gid']==0 and initialized['after']['uid']==initialized['after']['gid']==1001 and initialized['after']['mode']==0o700 and all(initialized['before'][k]==initialized['after'][k]for k in('device','inode')),'SAME_INITIALIZED_WORK_VOLUME_NODE')
 STAGE='package_archive';scratch=Path(scratch);S.need(scratch.is_absolute()and scratch==scratch.resolve()and scratch.is_dir()and not list(scratch.iterdir())and stat.S_IMODE(scratch.stat().st_mode)==0o700 and scratch.stat().st_uid==os.getuid(),'OWNED_FRESH_READER_SCRATCH')
 expected={k:producer['export'][k]for k in('bytes','sha256')};S.need(c.rows[c.roles['build_export']]==expected,'EXTERNAL_BUILD_EXPORT_WHOLE_PIN');data,pkg_pin,package=A.export(c.path(c.roles['build_export']),expected,c.source,inventory,scratch);S.need(data['actual-packages.txt']==inventory,'ACTUAL_BUILD_INVENTORY_REJOIN');provenance=E.actor_output(data,pkg_pin,a,c.source,q,producer['volume_admission_sha256']);custody['build']=E.custody_operations(c.obj('build_operations'),c,'build',selected,selected['transfer']['image_id'],provenance['kernel_mount_proofs']);producer_custody(producer,finished,custody['build'])
 return dict(schema=13,status='PASS_RUST351_RETAINED_ARCHIVE_EVIDENCE_DATA_ONLY',source=selected['source'],ref=selected['ref'],run=selected['run'],bootstrap_job=selected['bootstrap_job'],build_job=selected['build_job'],source_contract=S.SOURCE,acknowledged_container_ids=custody,container_custody_scope='THREE_BUILD_AND_THREE_BOOTSTRAP_QUALIFICATION_ACTORS_RETAINED_OPERATION_JOIN_ONLY',initial_input_provider_joins=inputs,package=pkg_pin,archive_checks=package,provenance=provenance,
 qualification_kernel_mount_proofs=kernel_qualification,kernel_mount_proof_scope='REPLAYED_RAW_KERNEL_DATA_AND_SOURCE_ENFORCED_PREENTRY_BINDINGS_ONLY',transferred_image=image_checks,input_rootfs_staging=manifest['metadata']['boot']['extraction'],input_rootfs_digest_scope='HOST_DATA_STAGING_PROVENANCE_ONLY_NO_POSTMODE_CONTENT_REHASH',historical_license108_and_related_holds='PRESERVED',native_acceptance=False,Root_acceptance=None,M2='NOT_TESTED',release_acceptance=False,new_tool_runtime='NOT_EMITTED_NOT_QUALIFIED')

def evaluate(*args):
 global STAGE
 STAGE='selection'
 try:return read(*args)
 except S.Hold as error:return dict(schema=13,status='HOLD',reason=str(error),stage=STAGE,native_acceptance=False,Root_acceptance=None,M2='NOT_TESTED',release_acceptance=False)
 except Exception as error:return dict(schema=13,status='HOLD',reason='MALFORMED_OR_UNSUPPORTED_RETAINED_'+type(error).__name__.upper(),stage=STAGE,native_acceptance=False,Root_acceptance=None,M2='NOT_TESTED',release_acceptance=False)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for key in('request','source-root','evidence-root','scratch','output'):p.add_argument('--'+key,required=True,type=Path)
 p.add_argument('--request-sha256',required=True);a=p.parse_args()
 # No limit syscall before externally pinned, explicit Root DATA selection.
 try:
  raw=S.read(a.request,2*S.MIB);S.need(S.pin(raw)['sha256']==a.request_sha256,'EXTERNAL_REQUEST_WHOLE_PIN');request=S.decode(raw);selector(request)
  import resource
  try:
   resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_AS,(request['resources']['address_space_bytes'],)*2);resource.setrlimit(resource.RLIMIT_CPU,(request['resources']['cpu_seconds'],)*2);resource.setrlimit(resource.RLIMIT_FSIZE,(request['resources']['scratch_bytes'],)*2)
  except (OSError,ValueError):raise S.Hold('READER_RESOURCE_LIMIT_CONTEXT_REFUSED')
  value=evaluate(request,a.source_root,a.evidence_root,a.scratch)
 except S.Hold as error:value=dict(schema=13,status='HOLD',reason=str(error),stage=STAGE,native_acceptance=False,Root_acceptance=None,M2='NOT_TESTED',release_acceptance=False)
 except Exception as error:value=dict(schema=13,status='HOLD',reason='MALFORMED_OR_UNSUPPORTED_RETAINED_'+type(error).__name__.upper(),stage=STAGE,native_acceptance=False,Root_acceptance=None,M2='NOT_TESTED',release_acceptance=False)
 with a.output.open('xb')as stream:stream.write(S.canonical(value))
 print(json.dumps(dict(status=value['status'],reason=value.get('reason'),Root_acceptance=None)));raise SystemExit(0 if value['status'].startswith('PASS_')else 2)
