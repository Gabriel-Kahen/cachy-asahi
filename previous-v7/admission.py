# SPDX-License-Identifier: MIT
"""Finite schema4 Root grant and runtime bridge; no acquisition or execution.

The grant fixes Source, reviewed material pins and two bounded phases while
run/job remain NULL. Provider metadata supplies those IDs inside each job.
Only actual bootstrap qualification can produce the legacy operational view;
Root LLVM acceptance and the original compact grant remain external proofs.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re

HERE=Path(__file__).resolve().parent
OPERATION='rust199-source-reference-native-v1'
BASE_SHA='a548f56b0759ae2ecd90ee79fed8c1e254a032dbaa0726f15e673e139b946c30'
EXPECTED_SOURCE='031bf1634429446cd0068f4842d56af276cf40f4'
EXPECTED_REF='refs/heads/codex/llvm23-source-reference-native-v2-20261115-r3'
EXPECTED_TREE='a973e46f51174d1cc3523b66af7a7794b3e66c46'
EXPECTED_MAP='75426d36fae416d1bc3606b8d1a7165408964996bb6467e3223842612221e187'
EXPECTED_IDENTITY=dict(sha=EXPECTED_SOURCE,ref=EXPECTED_REF,tree=EXPECTED_TREE,map_sha256=EXPECTED_MAP,files=260,bytes=40989000,profile_sha256='e558255048be9808a08f024cad0cd8b609f8239eafb1b497b08d8149f862c383',operation='llvm23-source-reference-native-v2')
FINAL_READER={'bytes': 13709, 'files': {'architecture-profile.json': {'bytes': 1109, 'sha256': '7ef21b06256f0a1f3098e01c58ebb2cbb67bf261a39582d0626a99693141a585'}, 'base.py': {'bytes': 2723, 'sha256': 'f362c51ddbf705b0a047a26a04ee2cc368061504116b6c050e6d8eac8d53f6e5'}, 'binding.TEMPLATE.json': {'bytes': 975, 'sha256': '5add0fd3df90115655ce339db71c5d31724e5e174a4ed15bcf51035b59b3c9e5'}, 'buildinfo.py': {'bytes': 6455, 'sha256': '1e86fbac17b2cf5dad23f59c12a6b39be60d8cbecc9288a071077a338c6ca37b'}, 'derivation.json': {'bytes': 1419, 'sha256': 'a3d3cbd053e9c4c2b8302db34ac85c7d5dbe9a8015492277388b071998993ba5'}, 'inverse-frame.json': {'bytes': 4481, 'sha256': 'fd6f8d80dc0b70fc1ab97e9afdf37db8828fc06f7a18cdb99e759b8d3a78c487'}, 'pins.json': {'bytes': 9393, 'sha256': '7a01820333a4b855eec0b4a1a673657afc0261039df036a5e34ea51283278328'}, 'reader.py': {'bytes': 13709, 'sha256': '936053e2e62a7c0a8c37772f083a22b59657db91746dcbc283f5aa73c74d9fcd'}, 'storage.py': {'bytes': 4918, 'sha256': '8bd69167e5b3f6b1e200b53485c4630bdb48b717d5a24f2331418d4871652d77'}}, 'path': 'scripts/port/llvm23-native-independent-reader/v7/reader.py', 'sha256': '936053e2e62a7c0a8c37772f083a22b59657db91746dcbc283f5aa73c74d9fcd'}
EXPECTED_NATIVE_CASE={'Original': {'bytes': 194327220, 'id': '14186236728', 'sha256': '39378b519abce9168e1faf41313420fa24b9f15cb396e22ed774d3a62a2775b7'}, 'attempt': 1, 'job': '132954847327', 'run': '43760769287'}
REVIEWS={'source','bootstrap_image','stage0','upstream_source','llvm_material','build_resources','retirement','trust','privacy','scheduler'}
CLAIMS={'root_authenticated':False,'native_acceptance':False,'hardware_acceptance':False,'release_acceptance':False}
AUTH_PATHS={'dispatch':'/inputs/dispatch-admission.json','provider':'/inputs/provider-binding.json','qualification':'/inputs/native-qualification.json'}
ROLES={'archive':'llvm_archive','signature':'llvm_signature','public_test_key':'public_test_key','root_decision':'root_decision','verification_proof':'verification_proof'}
_BASE=None


def need(value,why):
    if not value:raise ValueError(why)


def encode(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def dispatch_bytes(value):return(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def same(a,b):return encode(a)==encode(b)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def sha(value,n=64):return type(value)is str and re.fullmatch('[0-9a-f]{'+str(n)+'}',value)is not None

def base():
    global _BASE
    if _BASE is None:
        path=HERE/'frozen/rust199-admission-v1.py';raw=path.read_bytes();need(pin(raw)['sha256']==BASE_SHA,'exact frozen private Rust gate')
        spec=importlib.util.spec_from_file_location('rust199_v4_frozen_gate',path);m=importlib.util.module_from_spec(spec);exec(compile(raw,str(path),'exec'),m.__dict__);_BASE=m
    return _BASE

def decode(raw):return base().decode(raw)
def read_file(*args,**kwargs):return base().read_file(*args,**kwargs)
def descriptor(*args,**kwargs):return base().descriptor(*args,**kwargs)
def read_json(*args,**kwargs):return base().read_json(*args,**kwargs)

def candidate_binding():
    path=HERE/'notice_binding.py';raw=path.read_bytes()
    need(pin(raw)['sha256']=='e763ffd24c97e425b0065c0f2fe0c7bdb20a6524dab3129c0987b370000c2dce','exact notice candidate binding program')
    return load('rust199_notice_candidate_binding',path).validate(HERE)


def metadata():
    m=decode((HERE/'llvm-v2/source.json').read_bytes());identity=m['identity']
    need(same(identity,EXPECTED_IDENTITY),'exact published LLVM260 Source identity; acceptance remains separate')
    for name,key in (('policy.json','policy_pin'),('reader.py','reader_program'),('contract.json','contract_pin'),('candidate-map.json','candidate_map_pin')):
        need(pin((HERE/'llvm-v2'/name).read_bytes())=={k:m[key][k] for k in ('bytes','sha256')},'exact corrected LLVM DATA leaf '+name)
    raw=(HERE/'llvm-v2/publication.json').read_bytes();publication=m['publication']
    need(pin(raw)==m['publication_pin'] and same(decode(raw),publication),'whole static Root public readback bytes/body pin')
    need(publication['issuer']=='Root' and publication['status']=='PASS_COMPLETE_PUBLIC_GIT_READBACK_DATA_ONLY' and publication['source']==EXPECTED_SOURCE and publication['ref']==EXPECTED_REF and publication['tree']==EXPECTED_TREE and publication['source_map_sha256']==EXPECTED_MAP and type(publication['files'])is int and publication['files']==260 and type(publication['bytes'])is int and publication['bytes']==40989000 and publication['native']==publication['M2']=='NOT RUN','exact Root LLVM260 public readback identity')
    need(same(m['expected_native_case'],EXPECTED_NATIVE_CASE),'exact retained LLVM260 native case')
    return m


def reader_contract(m=None):
    m=metadata()if m is None else m
    need(m['pending']is None and m['reader_development_commit']=='0e8af913091fb85db1d10bc1b35bb35e7be6cfbd' and same(m['independent_reader'],FINAL_READER),'exact final Root Reader code/closure pins required')
    for leaf,row in FINAL_READER['files'].items():
        need(pin((HERE/'llvm-v2/independent-reader-v7'/leaf).read_bytes())==row,'whole final Reader DATA leaf pin: '+leaf)
    return m['independent_reader']


def source_binding(value,predispatch=False):
    need(type(value)is dict and set(value)=={'sha','ref','map_sha256','approval','run','job'},'explicit Source binding')
    need(sha(value['sha'],40) and type(value['ref'])is str and re.fullmatch('refs/heads/codex/[A-Za-z0-9._/-]+',value['ref']) and sha(value['map_sha256']) and sha(value['approval']),'exact Source/ref/map/review')
    if predispatch:need(value['run']is value['job']is None,'Root source/resource admission cannot prebind future provider IDs')
    else:need(all(type(value[k])is str and re.fullmatch('[1-9][0-9]{0,19}',value[k])for k in ('run','job')),'actual provider IDs required')


def _legacy_llvm(llvm,local=False):
    fields={'source','archive','signature','public_test_key','verification_proof','root_decision','artifact','original'}
    result=copy.deepcopy({k:llvm[k] for k in fields})
    if not local:
        for key in ROLES:result[key]['local_path']=result[key]['path']
    return result


def llvm_declaration(llvm,predispatch=False):
    m=metadata();need(type(llvm)is dict and set(llvm)=={'source','archive','signature','public_test_key','verification_proof','root_decision','artifact','original','source_identity','policy','reader','publication'},'complete accepted corrected LLVM material declaration')
    identity=llvm['source_identity'];publication=llvm['publication']
    need(same(identity,m['identity']),'LLVM260 Source/tree/map/profile cannot be waived')
    need(llvm['source']['sha']==EXPECTED_SOURCE and llvm['source']['ref']==EXPECTED_REF,'exact published LLVM260 Source required')
    need(same(publication,m['publication']),'entire pinned Root LLVM260 public readback remains mandatory')
    need(all(llvm['source'][k]==EXPECTED_NATIVE_CASE[k]for k in ('run','job')) and same({k:llvm['artifact'][k]for k in ('id','bytes','sha256')},EXPECTED_NATIVE_CASE['Original']),'only the exact retained LLVM260 run/job/Original may qualify')
    expected_policy=dict(**m['policy_pin'],resources=m['policy']);need(same(llvm['policy'],expected_policy),'entire corrected LLVM policy')
    reader_contract(m)
    b=base();b.LLVM_SOURCE=EXPECTED_SOURCE;b.llvm_declaration(_legacy_llvm(llvm,local=not predispatch))
    need(0<llvm['archive']['bytes']<=m['policy']['package_bytes'],'accepted LLVM package policy bound')
    reader=llvm['reader'];need(set(reader)=={'program','binding','result'} and same(reader['program'],m['independent_reader']),'exact final Reader program')
    for key,name in (('binding','llvm-v2-reader-binding.json'),('result','llvm-v2-reader.json')):
        row=copy.deepcopy(reader[key]);row['local_path']=row['path']if predispatch else row['local_path'];descriptor(row,fixed_path='/inputs/'+name)
    if predispatch:
        for row in [llvm[k]for k in ROLES]+[reader['binding'],reader['result']]:need(row['local_path']is None,'predispatch grant contains pins, not future hosted local paths')


def validate_dispatch(value):
    need(type(value)is dict and set(value)=={'schema','status','source','resources','once','retry','holds_preserved','reviews','source_audit','delivery','bootstrap','llvm','claims'},'complete Root source/resource grant')
    need(type(value['schema'])is int and value['schema']==4 and value['status']=='ROOT_ADMITTED_RUST199_SOURCE_RESOURCE_ONCE' and value['once']is True and value['retry']is False and value['holds_preserved']is True and same(value['claims'],CLAIMS),'Root once/private qualification scope and holds')
    source_binding(value['source'],True)
    candidate_binding()
    need(same(value['resources'],decode((HERE/'resource-policy.json').read_bytes())),'exact two-job resource proposal')
    need(set(value['reviews'])==REVIEWS and all(x is True for x in value['reviews'].values()),'separate bootstrap/stage0/source/material/resource/retirement reviews')
    audit=value['source_audit'];need(type(audit)is dict and set(audit)=={'status','library_cargo_config_sha256','consumed_git_dependencies_and_paths_reviewed','compiler_rt_libunwind_members_and_notices_reviewed','retained_source_authentication_rejoined'} and audit['status']=='REVIEWED_FOR_THIS_PRIVATE_BUILD' and sha(audit['library_cargo_config_sha256']) and all(audit[k]is True for k in ('consumed_git_dependencies_and_paths_reviewed','compiler_rt_libunwind_members_and_notices_reviewed','retained_source_authentication_rejoined')),'Root source/legal audit remains separate')
    llvm_declaration(value['llvm'],True)
    module=load('rust_v4_transport_plan',HERE/'hosted/materials.py');module.validate_plan(value['delivery'])
    artifact=value['delivery']['llvm_original'];llvm=value['llvm']
    need(all(str(artifact[k])==str(llvm['artifact'][k])for k in ('id','bytes','sha256','metadata_sha256')) and artifact['source']==llvm['source']['sha'] and str(artifact['run'])==llvm['source']['run'] and str(artifact['job'])==llvm['source']['job'],'Original delivery must join Root-accepted material')
    members={r['role']:r for a in ('llvm_original','stage0_carrier','root_proof_carrier')for r in value['delivery'][a]['members']}
    for key,role in ROLES.items():need({k:members[role][k]for k in ('bytes','sha256')}=={k:llvm[key][k]for k in ('bytes','sha256')},'Root accepted proof/member pin '+role)
    for key,role in (('binding','reader_binding'),('result','reader_result')):need({k:members[role][k]for k in ('bytes','sha256')}=={k:llvm['reader'][key][k]for k in ('bytes','sha256')},'Root Reader carrier pin')
    hosts=value['bootstrap']['transfer_redirect_hosts'];need(type(hosts)is list and 1<=len(hosts)<=3 and len(set(hosts))==len(hosts) and all(type(host)is str and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}\.blob\.core\.windows\.net',host)for host in hosts),'explicit Root-selected phase-transfer hosts')
    need(value['bootstrap']['qualification_allowed']is True and value['bootstrap']['network_during_qualification']is False,'only bounded native qualification approved before producer')
    return copy.deepcopy(value)


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def provider_binding(dispatch,raw_sha,env,jobs,phase):
    need(phase in ('bootstrap','build') and sha(raw_sha),'exact actual phase and raw grant pin')
    source_binding(dispatch['source'],True);s=dispatch['source']
    need(env.get('GITHUB_JOB')==phase,'actual current workflow job key must match selected phase')
    need(env.get('GITHUB_REPOSITORY')=='Gabriel-Kahen/cachy-asahi' and env.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and env.get('GITHUB_SHA')==s['sha'] and env.get('GITHUB_REF')==s['ref'] and env.get('RUST199_OPERATION')==OPERATION and env.get('GITHUB_RUN_ATTEMPT')=='1','same-repository manual exactSource attempt1')
    run=env.get('GITHUB_RUN_ID');need(type(run)is str and re.fullmatch('[1-9][0-9]{0,19}',run),'actual provider run ID')
    need(env.get('GITHUB_WORKFLOW_REF')=='Gabriel-Kahen/cachy-asahi/.github/workflows/native-arm-build.yml@'+s['ref'],'exact dispatcher workflow ref')
    rows=jobs['jobs'];names={'rust199-bootstrap-v4','rust199-build-v4'}
    need(type(rows)is list and 1<=len(rows)<=2 and type(jobs['total_count'])is int and jobs['total_count']==len(rows) and len({r['name']for r in rows})==len(rows) and all(r['name']in names for r in rows),'only exact two-phase workflow jobs')
    need(len({r['id']for r in rows})==len(rows) and all(str(r['run_id'])==run and r['head_sha']==s['sha'] and type(r['id'])is int and r['id']>0 and type(r.get('run_attempt',1))is int and r.get('run_attempt',1)==1 for r in rows),'every visible phase belongs to exact actual Source/run/attempt')
    selected=[r for r in rows if r['name']=='rust199-'+phase+'-v4'];need(len(selected)==1,'unique current phase actualjob')
    row=selected[0];need(str(row['run_id'])==run and row['head_sha']==s['sha'] and type(row['id'])is int and row['id']>0 and row.get('run_attempt',1)==1 and row.get('status')=='in_progress' and row.get('conclusion')is None,'actual running phase job/source/run')
    source=dict(s,run=run,job=str(row['id']))
    return dict(schema=4,status='ACTUAL_PROVIDER_BINDING_ONLY',phase=phase,source=source,run_attempt=1,dispatch_sha256=raw_sha,job_metadata_sha256=pin(encode(jobs))['sha256'],manual_dispatch=True,readback_required=True,native_acceptance=False)


def _json(row):
    read_file(row['local_path'],4*1024**2,row);return read_json(row['local_path'],row['sha256'])


def _reference(row,cap):
    need(type(row)is dict and set(row)=={'path','bytes','sha256'} and type(row['bytes'])is int and 0<row['bytes']<=cap and sha(row['sha256']),'bounded whole historical Reader reference')
    base().path(row['path'])


def _reader_successor_report(binding,result):
    raw=(HERE/'llvm-v2/independent-reader-v7/pins.json').read_bytes()
    need(pin(raw)==FINAL_READER['files']['pins.json'],'exact Reader7 output profile DATA')
    specification=decode(raw)['output_namespace']
    names=set(specification['fixed_output'])|set(specification['command_receipts'].values())|set(specification['command_logs'].values())|set(specification['facts'].values())|{base().LLVM_ARCHIVE}
    namespace=result['command_namespace']
    need(type(namespace)is dict and set(namespace)=={'files','bytes','command_receipts','facts','runtime_and_build_success_separate'} and type(namespace['files'])is int and namespace['files']==len(names)+1 and type(namespace['bytes'])is int and 0<namespace['bytes']<=4*1024**3 and same(namespace['command_receipts'],specification['command_receipts']) and same(namespace['facts'],specification['facts']) and namespace['runtime_and_build_success_separate']is True,'Reader7 exact separated command receipt/fact namespace')
    def proof(before,after,seams):return dict(before_sha256=before,after_sha256=after,seams=seams,inverse='EXACT_FUNCTION_BYTES')
    projection=dict(commands=proof('c0ecf2118bc95709ef778511f0914e0684457066a49d9372c95f548f98edb3b8','ad0389032f75ac7cce845203501aa76f1d0a10c2e656fcd539708aa55292b189',5),replay=proof('8c5983d5533345eb9246f0e34551275deca04c5613143cebde8dc40da1075508','17ce8dd7407010505cba6dbc51a67bf3e2c779ab7e4d2c6f3636ca2bb1f049a0',1),absent_image_stdout=proof('c2b59ef95f7fba1738c8e3fc41674fc758c69e7cdac2d6e1f97ba30feeea1de2','6c43d85fec3c3e727bcb3404dfdb23cec1a04d008ab2bc8811e1b7efaa203d98',1),actual_tuple_projection=False)
    projection.update(buildinfo=proof('17ce8dd7407010505cba6dbc51a67bf3e2c779ab7e4d2c6f3636ca2bb1f049a0','1054bf8582245500cb8e7fa5917a3b4f1b7ace491c12645eb6a660d379c482c9',1),architecture_basis='LLVM23_SOURCE260_BASE349_ARCHITECTURE_METADATA_V1')
    need(same(result['passive_projection'],projection),'exact maintained Reader7 passive projection, absent-image stdout and BUILDINFO seams')
    architecture=dict(rows=349,architectures=dict(aarch64=300,any=49),selected_packages=256,rootfs_only_packages=93,selected_version_replacements=71,basis='SOURCE_PINNED_SIGNED_BOOTSTRAP_INPUT_METADATA_NOT_OUTPUT_BUILDINFO',required_external_architecture_input=None,fresh_signature_verification=False,rootfs_body_reread=False,output_BUILDINFO_used_as_architecture_authority=False)
    need(same(result['buildinfo_architecture'],architecture),'Reader7 complete349 architecture verdict comes only from pinned Source signed-input metadata')
    storage=result['storage']
    if binding['storage_profile']is None:
        need(same(storage,dict(mode='STRICT_REPORTED_INODES',reservation=False)),'strict Reader storage report without external profile')
    else:
        need(type(storage)is dict and set(storage)=={'mode','available_bytes','inode_accounting','fstat_device','kernel_mount_device','mount_id','reservation','quota_claim'} and storage['mode']=='ROOT_REVIEWED_BTRFS_UNREPORTED_INODES' and type(storage['available_bytes'])is int and storage['available_bytes']>=20*1024**3 and storage['inode_accounting']=='UNREPORTED' and type(storage['fstat_device'])is type(storage['mount_id'])is int and storage['fstat_device']==54 and storage['kernel_mount_device']=='0:33' and storage['mount_id']==62 and storage['reservation']is False and storage['quota_claim']is None,'Reader7 separately Root-reviewed Btrfs evidence retains20GiB/no reservation')


def _reader_evidence(llvm,binding,result,m):
    """Check supplied Reader DATA; Root's complete decision authorizes its pins.

    Provider, commit, export and complete-decode bodies stay in the Reader's
    Original evidence. This adapter does not claim to hash those bodies again.
    """
    fields={'schema','scope','actual','export_sha256','full_original_decode','holds_preserved','operation','original_archive','package_sha256','pins_sha256','policy_sha256','provider_sha256','reader_sha256','source_commit_sha256','source_map_sha256','source_tree','publication','storage_profile'}
    need(type(binding)is dict and set(binding)==fields and type(binding['schema'])is int and binding['schema']==1 and binding['scope']=='ROOT_BOUND_LLVM23_INDEPENDENT_READER_V7' and binding['holds_preserved']is True and binding['operation']==EXPECTED_IDENTITY['operation'],'exact new LLVM260 Reader binding schema/scope')
    actual=binding['actual'];required={'source','ref','run','job','attempt','approval','authority','image','artifact','reader'}
    need(type(actual)is dict and set(actual)==required and actual['source']==EXPECTED_SOURCE and actual['ref']==EXPECTED_REF and type(actual['attempt'])is int and actual['attempt']==1 and all(type(actual[k])is str and re.fullmatch('[1-9][0-9]{0,19}',actual[k])for k in ('run','job','artifact')) and all(actual[k]==llvm['source'][k]==EXPECTED_NATIVE_CASE[k]for k in ('run','job')) and actual['artifact']==llvm['artifact']['id']==EXPECTED_NATIVE_CASE['Original']['id'],'actual published260 Reader provider/Original tuple')
    need(sha(actual['approval']) and all(type(actual[k])is str and actual[k].strip()for k in ('authority','reader')) and type(actual['image'])is str and re.fullmatch('sha256:[0-9a-f]{64}',actual['image']),'actual Root approval/authority/Reader/image selectors')
    need(all(sha(binding[k])for k in ('provider_sha256','source_commit_sha256','export_sha256','package_sha256','reader_sha256','pins_sha256')),'whole actual provider/commit/export/package/Reader/pins SHA bindings')
    original=binding['original_archive'];decoded=binding['full_original_decode']
    need(type(original)is dict and set(original)=={'bytes','sha256'} and type(original['bytes'])is int and 0<original['bytes']<=8*1024**3 and sha(original['sha256']) and same(original,{k:llvm['artifact'][k]for k in ('bytes','sha256')}) and same(original,{k:EXPECTED_NATIVE_CASE['Original'][k]for k in ('bytes','sha256')}),'entire actual Original archive bytes/SHA')
    need(type(decoded)is dict and set(decoded)=={'bytes','files','map_sha256'} and type(decoded['bytes'])is int and 0<decoded['bytes']<=8*1024**3 and type(decoded['files'])is int and 0<decoded['files']<=4096 and sha(decoded['map_sha256']),'bounded typed complete Original decode binding')
    _reference(binding['publication'],16*1024**2);need(same({k:binding['publication'][k]for k in ('bytes','sha256')},m['publication_pin']),'Reader publication reference must join pinned Root readback')
    if binding['storage_profile']is not None:_reference(binding['storage_profile'],16384)
    archive={k:llvm['archive'][k]for k in ('bytes','sha256')}
    need(binding['source_map_sha256']==EXPECTED_MAP and binding['source_tree']==EXPECTED_TREE and binding['policy_sha256']==m['policy_pin']['sha256'] and binding['reader_sha256']==m['independent_reader']['sha256'] and binding['pins_sha256']==m['independent_reader']['files']['pins.json']['sha256'] and binding['package_sha256']==archive['sha256'],'exact new Reader/Source/policy/package pins')
    need(type(result['schema'])is int and result['schema']==1 and result['status']=='PASS_INDEPENDENT_LLVM23_BUILDINFO_ARCHITECTURE_SUCCESSOR_DATA_ONLY' and result['binding_sha256']==llvm['reader']['binding']['sha256'] and same(result['actual'],actual) and result['source_tree']==EXPECTED_TREE and type(result['source_files'])is int and result['source_files']==260 and same(result['verified_historical_inverse'],[256,253,251,248]) and same(result['package'],archive) and result['native_acceptance']is False and result['Root_authentication']is False and result['Root_acceptance']is None and result['holds']=='native16K/M2/performance/release remain held','new Reader DATA parity is not Root/native acceptance')
    _reader_successor_report(binding,result)


def validate_llvm_material(llvm,files):
    llvm=copy.deepcopy(llvm)
    for key,role in ROLES.items():llvm[key]['local_path']=files[role]['local_path']
    for key,role in (('binding','reader_binding'),('result','reader_result')):llvm['reader'][key]['local_path']=files[role]['local_path']
    llvm_declaration(llvm)
    signature=_json(llvm['verification_proof']);decision=_json(llvm['root_decision']);binding=_json(llvm['reader']['binding']);result=_json(llvm['reader']['result']);m=metadata()
    archive={k:llvm['archive'][k]for k in ('bytes','sha256')};sig={k:llvm['signature'][k]for k in ('bytes','sha256')};key={k:llvm['public_test_key'][k]for k in ('bytes','sha256','fingerprint','trust_scope')}
    need(type(signature['schema'])is int and signature['schema']==1 and signature['status']=='ROOT_VERIFIED_PUBLIC_TEST_SIGNATURE' and signature['verified']is True and same(signature['archive'],archive) and same(signature['signature'],sig) and same(signature['public_test_key'],key) and signature['trust_scope']=='TEST_ONLY','actual Root publicTEST verification proof')
    need(type(decision['schema'])is int and decision['schema']==1 and decision['issuer']=='Root' and decision['accepted']is True and decision['holds_preserved']is True and decision['status']=='ACCEPTED_PRIVATE_LLVM23_PACKAGE_TEST_ONLY' and same(decision['source'],llvm['source']) and same(decision['artifact'],llvm['artifact']) and same(decision['original'],llvm['original']) and same(decision['archive'],{k:llvm['archive'][k]for k in ('bytes','sha256','package','version','arch')}) and same(decision['signature'],sig) and same(decision['public_test_key'],key) and decision['verification_proof_sha256']==llvm['verification_proof']['sha256'],'actual scoped Root LLVM acceptance remains mandatory')
    _reader_evidence(llvm,binding,result,m)
    expected=dict(source_identity=llvm['source_identity'],policy=llvm['policy'],reader_program_sha256=m['independent_reader']['sha256'],source_reader_program_sha256=m['reader_program']['sha256'],reader_binding_sha256=llvm['reader']['binding']['sha256'],reader_result_sha256=llvm['reader']['result']['sha256'],reader_binding=binding,publication_sha256=m['publication_pin']['sha256'])
    need(same(decision['llvm_v2'],expected),'Root decision must explicitly rejoin entire published260 Reader binding and static publication')
    for name,cap in (('archive',2*1024**3),('signature',1024**2),('public_test_key',8*1024**2)):read_file(llvm[name]['local_path'],cap,llvm[name])
    return llvm


def natural(row):
    return row.get('natural_exit')is True and row.get('forced_cleanup')is False and row.get('group_absent')is True and row.get('retirement')=='REAPED' and row.get('ownership_lost')is False and row.get('leader_held_until_group_inspection')is True and row.get('exit_observed_via_waitpid')is True and type(row.get('exit'))is int and row.get('exit')==0


def check_phase_bridge(dispatch,provider,qualification):
    need(type(provider['schema'])is int and provider['schema']==4 and provider['status']=='PROVIDER_PHASE_BRIDGE' and set(provider)=={'schema','status','dispatch_sha256','bootstrap','build'},'explicit two-job provider bridge')
    digest=pin(dispatch_bytes(dispatch))['sha256'];need(provider['dispatch_sha256']==digest,'unaltered original Root grant')
    for phase in ('bootstrap','build'):
        p=provider[phase];source_binding(p['source'])
        need(type(p['schema'])is int and p['schema']==4 and p['status']=='ACTUAL_PROVIDER_BINDING_ONLY' and p['phase']==phase and p['run_attempt']==1 and type(p['run_attempt'])is int and p['manual_dispatch']is True and p['readback_required']is True and p['native_acceptance']is False and p['dispatch_sha256']==digest and all(p['source'][k]==dispatch['source'][k]for k in ('sha','ref','map_sha256','approval')) and sha(p['job_metadata_sha256']),'actual same-Source manual provider phase')
    need(provider['bootstrap']['source']['run']==provider['build']['source']['run'] and provider['bootstrap']['source']['job']!=provider['build']['source']['job'],'same first run and distinct genuine jobs')
    need(type(qualification['schema'])is int and qualification['schema']==4 and qualification['status']=='PASS_NATIVE_SOURCE_QUALIFICATION_ONLY' and qualification['native_acceptance']is False and qualification['holds_preserved']is True and qualification['binding']==provider['bootstrap']['source'] and qualification['dispatch_sha256']==digest and qualification['provider_phase_sha256']==pin(encode(provider['bootstrap']))['sha256'],'native evidence belongs to actual bootstrap phase')
    probes=qualification['probe_receipts'];need(type(probes)is list and len(probes)==9 and all(type(p['returncode'])is int and p['returncode']==0 and natural(p['lifecycle'])for p in probes),'all nine actual naturally retired probe children')
    expected=[['/stage0/bin/rustc','-vV'],['/stage0/bin/rustc','-vV'],['/stage0/bin/rustc','--print','sysroot'],['/stage0/bin/cargo','--version'],['/stage0/bin/rustdoc','--version'],['/opt/cachy-asahi/llvm23-source-reference/bin/llvm-config','--version'],['/opt/cachy-asahi/llvm23-source-reference/bin/llvm-config','--targets-built'],['/usr/bin/gcc','-dumpmachine'],['/opt/cachy-asahi/llvm23-source-reference/bin/ld.lld','--version']]
    need([r['argv']for r in probes]==expected,'only the exact unchanged nine runtime probes qualify stage0')
    readonly=qualification['readonly_stage0'];need(readonly['paths']==['/stage0','/work/build/stage0'] and all(readonly[k]is True for k in ('readonly','namespace_permissions_verified','write_attempts_denied','alias_write_attempts_denied')),'actual two-alias readonly qualification')
    need(len(readonly['attempts'])==2 and all(type(row['errno'])is int and row['errno']==30 and row['denied']is True for row in readonly['attempts']),'actual EROFS for both aliases')
    need(same(qualification['source_audit'],dispatch['source_audit']) and qualification['library_cargo_config_sha256']==dispatch['source_audit']['library_cargo_config_sha256'],'native source checks rejoin external Root source audit')


def _file(path,actor):
    raw=Path(path).read_bytes();Path(path).chmod(0o444);return dict(path=actor,local_path=str(Path(path)),**pin(raw))


def operational(dispatch,provider,delivered,boot,qualification,work):
    """Deterministic normalization after actual provider/native observations.

    Never changes LLVM Root acceptance. Generated qualification facts are
    authorized by the untouched Root pregrant and retained separately.
    """
    validate_dispatch(dispatch);check_phase_bridge(dispatch,provider,qualification)
    llvm=validate_llvm_material(dispatch['llvm'],delivered['files'])
    need(boot['image']==qualification['image_id'] and boot['rootfs_tree_sha256']==qualification['rootfs_tree_sha256'] and boot['llvm_archive_sha256']==llvm['archive']['sha256'],'exact installed immutable image/source qualification')
    root=Path(work)/'operational-admission';root.mkdir(mode=0o700)
    def store(name,value,actor):
        path=root/name
        with path.open('xb')as f:f.write(encode(value))
        return _file(path,actor)
    dispatch_path=root/'dispatch.json'
    with dispatch_path.open('xb')as stream:stream.write(dispatch_bytes(dispatch))
    authorization=dict(dispatch=_file(dispatch_path,AUTH_PATHS['dispatch']),provider=store('provider.json',provider,AUTH_PATHS['provider']),qualification=store('native-qualification.json',qualification,AUTH_PATHS['qualification']))
    proof=dict(schema=1,status='QUALIFIED_FOR_THIS_SOURCE',native_runtime=True,metadata_only=False,native_target=base().TARGET,stage0_version='1.98.0',assembled_tree_sha256=qualification['stage0_tree_sha256'],rust_source_sha256=base().MATERIALS['rustc-1.99.0-src.tar.xz']['sha256'],native_qualification_sha256=authorization['qualification']['sha256'])
    evidence=store('qualification.json',proof,'/inputs/qualification.json')
    # rootfs_root is the historical bootstrap export provenance path. The build
    # job imports the exact immutable image; it never recreates this host path.
    q=dict(schema=1,scope='PRIVATE_SOURCE_REFERENCE_INPUT_QUALIFICATION_ONLY',status='QUALIFIED_FOR_PRIVATE_BUILD_ONLY',holds_preserved=True,inputs_sha256=base().INPUTS_SHA,
        environment=dict(native_target=base().TARGET,llvm_version='23.1.1',llvm_prefix='/opt/cachy-asahi/llvm23-source-reference',root=boot['rootfs_root'],tree_sha256=boot['rootfs_tree_sha256']),
        stage0=dict(native_target=base().TARGET,version='1.98.0',compatibility='QUALIFIED_FOR_THIS_SOURCE',assembled_tree_sha256=qualification['stage0_tree_sha256']),source_audit=dispatch['source_audit'],qualification_evidence={k:evidence[k]for k in ('path','sha256')})
    qpin=store('candidate-admission.json',q,'/inputs/candidate-admission.json')
    readonly=dict(schema=1,status='ROOT_QUALIFIED_READONLY_VOLUME_SUBPATH',image_id=boot['image'],candidate_admission_sha256=qpin['sha256'],stage0_tree_sha256=qualification['stage0_tree_sha256'],**qualification['readonly_stage0'])
    ropin=store('readonly-volume-subpath.json',readonly,'/inputs/readonly-volume-subpath.json')
    baseline=dict(boot['baseline_inventory']);qualified=dict(boot['qualified_inventory'])
    for row,actor in ((baseline,'/inputs/baseline349.lock'),(qualified,'/inputs/qualified-inventory.lock')):
        row['local_path']=row.get('local_path',row['path']);row['path']=actor;Path(row['local_path']).chmod(0o444)
    imageproof=dict(schema=1,status='ROOT_QUALIFIED_NORMAL_ISOLATED_IMMUTABLE_IMAGE',normal_isolated=True,native_runtime=True,holds_preserved=True,image_id=boot['image'],rootfs_tree_sha256=boot['rootfs_tree_sha256'],qualified_llvm_tree_sha256=qualification['qualified_llvm_tree_sha256'],candidate_admission_sha256=qpin['sha256'],stage0_tree_sha256=qualification['stage0_tree_sha256'],llvm_package_sha256=llvm['archive']['sha256'],baseline_inventory_sha256=baseline['sha256'],qualified_inventory_sha256=qualified['sha256'],qualified_inventory_count=qualified['count'],readonly_volume_subpath_sha256=ropin['sha256'],native_qualification_sha256=authorization['qualification']['sha256'])
    imagepin=store('image-qualification.json',imageproof,'/inputs/image-qualification.json')
    image=dict(id=boot['image'],rootfs_tree_sha256=boot['rootfs_tree_sha256'],qualified_llvm_tree_sha256=qualification['qualified_llvm_tree_sha256'],qualification_proof=imagepin,baseline_inventory=baseline,qualified_inventory=qualified,readonly_volume_subpath_proof=ropin)
    a=dict(schema=1,status='ROOT_ADMITTED_RUST199_NATIVE_PRIVATE_BUILD',holds_preserved=True,source=provider['build']['source'],candidate=dict(commit=base().CANDIDATE,inputs_sha256=base().INPUTS_SHA,qualification=evidence,notice_binding=candidate_binding()),candidate_admission=qpin,materials=delivered['materials'],llvm=llvm,image=image,image_root=boot['rootfs_root'],stage0_tree_sha256=qualification['stage0_tree_sha256'],resources=copy.deepcopy(base().PROPOSAL),claims=copy.deepcopy(CLAIMS),authorization=authorization)
    validate(a,check_files=True);return a


def projection(a):
    need(type(a)is dict and 'authorization'in a,'derived operational admission requires original Root/provider/native bridge')
    need(type(a.get('candidate'))is dict and set(a['candidate'])=={'commit','inputs_sha256','qualification','notice_binding'} and same(a['candidate']['notice_binding'],candidate_binding()),'exact effective candidate binding before legacy base projection')
    result=copy.deepcopy(a);result.pop('authorization');result['candidate'].pop('notice_binding');result['llvm']=_legacy_llvm(a['llvm'],True);return result


def authorization(a):
    need(type(a['authorization'])is dict and set(a['authorization'])==set(AUTH_PATHS),'exact three authorization files')
    for key,path in AUTH_PATHS.items():descriptor(a['authorization'][key],fixed_path=path)
    dispatch=_json(a['authorization']['dispatch']);validate_dispatch(dispatch)
    need(pin(dispatch_bytes(dispatch))=={k:a['authorization']['dispatch'][k]for k in ('bytes','sha256')} and len(dispatch_bytes(dispatch))<=16384,'byte-exact compact original Root dispatch proof')
    provider=_json(a['authorization']['provider']);qualification=_json(a['authorization']['qualification']);check_phase_bridge(dispatch,provider,qualification)
    need(a['source']==provider['build']['source'] and a['image']['id']==qualification['image_id'] and a['image']['rootfs_tree_sha256']==qualification['rootfs_tree_sha256'] and a['image']['qualified_llvm_tree_sha256']==qualification['qualified_llvm_tree_sha256'] and a['stage0_tree_sha256']==qualification['stage0_tree_sha256'],'operational identity must derive only from actual current provider/native proof')
    def immutable(value):
        if type(value)is dict:return {key:immutable(child)for key,child in value.items()if key!='local_path'}
        if type(value)is list:return [immutable(child)for child in value]
        return value
    need(same(immutable(a['llvm']),immutable(dispatch['llvm'])),'Root accepted LLVM selectors/pins cannot be rewritten by normalization')
    q=_json(a['candidate_admission']);need(same(q['source_audit'],dispatch['source_audit']),'candidate source audit remains Root granted')
    return dispatch,provider,qualification


def external_proofs(a):
    authorization(a);legacy=projection(a);b=base();b.LLVM_SOURCE=a['llvm']['source']['sha'];b.external_proofs(legacy)
    files={role:a['llvm'][name]for name,role in ROLES.items()};files.update(reader_binding=a['llvm']['reader']['binding'],reader_result=a['llvm']['reader']['result'])
    validate_llvm_material(a['llvm'],files)


def validate(a,check_files=True):
    need(type(check_files)is bool,'explicit file mode');legacy=projection(a);llvm_declaration(a['llvm']);b=base();b.LLVM_SOURCE=a['llvm']['source']['sha'];b.validate(legacy,False)
    for key,path in AUTH_PATHS.items():descriptor(a['authorization'][key],fixed_path=path)
    if check_files:
        external_proofs(a)
        for row in a['materials']:read_file(row['local_path'],row['bytes'],row)
    return copy.deepcopy(a)
