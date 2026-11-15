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
EXPECTED_TREE='2f90eaaaa532d14574c0ce1f1c93b02310f44d91'
EXPECTED_MAP='5c19a2699856e081712d159c551ce496919938bd456f2182c0c905f03cbd2ef0'
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

def metadata():
    m=decode((HERE/'llvm-v2/source.json').read_bytes());identity=m['identity']
    need(identity['tree']==EXPECTED_TREE and identity['map_sha256']==EXPECTED_MAP and identity['files']==253 and sha(identity['profile_sha256']),'exact corrected LLVM253 identity; publication is separate')
    for name,key in (('policy.json','policy_pin'),('reader.py','reader_program'),('contract.json','contract_pin'),('candidate-map.json','candidate_map_pin')):
        need(pin((HERE/'llvm-v2'/name).read_bytes())=={k:m[key][k] for k in ('bytes','sha256')},'exact corrected LLVM DATA leaf '+name)
    return m


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
    need(type(identity)is dict and set(identity)==set(m['identity']) and same({k:identity[k]for k in identity if k not in ('sha','ref')},{k:v for k,v in m['identity'].items()if k not in ('sha','ref')}),'LLVM tree/map/profile cannot be waived')
    need(sha(identity['sha'],40) and identity['sha']not in ('6d0243dc8f5cf4ee5b9316b8c804f14a3236ecb0','4ceaa1c6958349451197b19acdb084a2a5be216b') and llvm['source']['sha']==identity['sha'] and llvm['source']['ref']==identity['ref'],'new actual published corrected LLVM Source required')
    need(publication['issuer']=='Root' and publication['status']=='PASS_COMPLETE_PUBLIC_GIT_READBACK_DATA_ONLY' and publication['source']==identity['sha'] and publication['ref']==identity['ref'] and publication['tree']==EXPECTED_TREE and publication['source_map_sha256']==EXPECTED_MAP and publication['files']==253 and publication['bytes']==identity['bytes'] and publication['native']==publication['M2']=='NOT RUN','exact Root public readback remains mandatory')
    expected_policy=dict(**m['policy_pin'],resources=m['policy']);need(same(llvm['policy'],expected_policy),'entire corrected LLVM policy')
    b=base();b.LLVM_SOURCE=identity['sha'];b.llvm_declaration(_legacy_llvm(llvm,local=not predispatch))
    need(0<llvm['archive']['bytes']<=m['policy']['package_bytes'],'accepted LLVM package policy bound')
    reader=llvm['reader'];need(set(reader)=={'program','binding','result'} and same(reader['program'],m['independent_reader']),'exact corrected Reader program')
    for key,name in (('binding','llvm-v2-reader-binding.json'),('result','llvm-v2-reader.json')):
        row=copy.deepcopy(reader[key]);row['local_path']=row['path'] if predispatch else row['local_path'];descriptor(row,fixed_path='/inputs/'+name)
    if predispatch:
        for row in [llvm[k]for k in ROLES]+[reader['binding'],reader['result']]:need(row['local_path']is None,'predispatch grant contains material pins, not future hosted local paths')


def validate_dispatch(value):
    need(type(value)is dict and set(value)=={'schema','status','source','resources','once','retry','holds_preserved','reviews','source_audit','delivery','bootstrap','llvm','claims'},'complete Root source/resource grant')
    need(type(value['schema'])is int and value['schema']==4 and value['status']=='ROOT_ADMITTED_RUST199_SOURCE_RESOURCE_ONCE' and value['once']is True and value['retry']is False and value['holds_preserved']is True and same(value['claims'],CLAIMS),'Root once/private qualification scope and holds')
    source_binding(value['source'],True)
    need(same(value['resources'],decode((HERE/'resource-policy.json').read_bytes())),'exact two-job resource proposal')
    need(set(value['reviews'])==REVIEWS and all(x is True for x in value['reviews'].values()),'separate bootstrap/stage0/source/material/resource/retirement reviews')
    audit=value['source_audit'];need(audit['status']=='REVIEWED_FOR_THIS_PRIVATE_BUILD' and sha(audit['library_cargo_config_sha256']) and all(audit[k]is True for k in ('consumed_git_dependencies_and_paths_reviewed','compiler_rt_libunwind_members_and_notices_reviewed','retained_source_authentication_rejoined')),'Root source/legal audit remains separate')
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


def validate_llvm_material(llvm,files):
    llvm=copy.deepcopy(llvm)
    for key,role in ROLES.items():llvm[key]['local_path']=files[role]['local_path']
    for key,role in (('binding','reader_binding'),('result','reader_result')):llvm['reader'][key]['local_path']=files[role]['local_path']
    llvm_declaration(llvm)
    signature=_json(llvm['verification_proof']);decision=_json(llvm['root_decision']);binding=_json(llvm['reader']['binding']);result=_json(llvm['reader']['result']);m=metadata()
    archive={k:llvm['archive'][k]for k in ('bytes','sha256')};sig={k:llvm['signature'][k]for k in ('bytes','sha256')};key={k:llvm['public_test_key'][k]for k in ('bytes','sha256','fingerprint','trust_scope')}
    need(signature['schema']==1 and signature['status']=='ROOT_VERIFIED_PUBLIC_TEST_SIGNATURE' and signature['verified']is True and same(signature['archive'],archive) and same(signature['signature'],sig) and same(signature['public_test_key'],key) and signature['trust_scope']=='TEST_ONLY','actual Root publicTEST verification proof')
    need(decision['schema']==1 and decision['issuer']=='Root' and decision['accepted']is True and decision['holds_preserved']is True and decision['status']=='ACCEPTED_PRIVATE_LLVM23_PACKAGE_TEST_ONLY' and same(decision['source'],llvm['source']) and same(decision['artifact'],llvm['artifact']) and same(decision['original'],llvm['original']) and same(decision['archive'],{k:llvm['archive'][k]for k in ('bytes','sha256','package','version','arch')}) and same(decision['signature'],sig) and same(decision['public_test_key'],key) and decision['verification_proof_sha256']==llvm['verification_proof']['sha256'],'actual scoped Root LLVM acceptance, not runtime qualification')
    actual=binding['actual'];required={'source','ref','run','job','attempt','approval','authority','image','artifact','reader'}
    need(set(actual)==required and all(x is not None for x in actual.values()) and all(actual[k]==llvm['source'][k] for k in ('run','job')) and actual['source']==llvm['source']['sha'] and actual['ref']==llvm['source']['ref'] and actual['artifact']==llvm['artifact']['id'] and actual['attempt']==1 and type(actual['attempt'])is int,'actual corrected Reader provider/Original tuple')
    need(binding['schema']==1 and binding['scope']=='ROOT_BOUND_LLVM23_INDEPENDENT_READER_V3' and binding['holds_preserved']is True and binding['operation']==m['identity']['operation'] and binding['source_map_sha256']==EXPECTED_MAP and binding['source_tree']==EXPECTED_TREE and binding['policy_sha256']==m['policy_pin']['sha256'] and binding['reader_sha256']==m['independent_reader']['sha256'] and binding['pins_sha256']==m['independent_reader']['pins']['sha256'] and binding['package_sha256']==archive['sha256'] and same(binding['original_archive'],{k:llvm['artifact'][k]for k in ('bytes','sha256')}),'exact corrected independent Reader program/Source/policy/Original binding')
    need(type(result['schema'])is int and result['schema']==1 and result['status']=='PASS_INDEPENDENT_ROOT_BOUND_LLVM23_CORRECTED253_DATA_ONLY' and result['binding_sha256']==llvm['reader']['binding']['sha256'] and same(result['actual'],actual) and result['source_tree']==EXPECTED_TREE and result['source_files']==253 and result['verified_historical_inverse']==[251,248] and same(result['package'],archive) and result['native_acceptance']is False and result['Root_authentication']is False and result['Root_acceptance']is None and result['holds']=='native16K/M2/performance/release remain held','independent Reader DATA parity is not Root/native acceptance')
    expected=dict(source_identity=llvm['source_identity'],policy=llvm['policy'],reader_program_sha256=m['independent_reader']['sha256'],source_reader_program_sha256=m['reader_program']['sha256'],reader_binding_sha256=llvm['reader']['binding']['sha256'],reader_result_sha256=llvm['reader']['result']['sha256'],reader_binding=binding,publication_sha256=pin(encode(llvm['publication']))['sha256'])
    need(same(decision['llvm_v2'],expected),'Root decision must explicitly rejoin corrected Source/publication/policy/independent Reader')
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
    a=dict(schema=1,status='ROOT_ADMITTED_RUST199_NATIVE_PRIVATE_BUILD',holds_preserved=True,source=provider['build']['source'],candidate=dict(commit=base().CANDIDATE,inputs_sha256=base().INPUTS_SHA,qualification=evidence),candidate_admission=qpin,materials=delivered['materials'],llvm=llvm,image=image,image_root=boot['rootfs_root'],stage0_tree_sha256=qualification['stage0_tree_sha256'],resources=copy.deepcopy(base().PROPOSAL),claims=copy.deepcopy(CLAIMS),authorization=authorization)
    validate(a,check_files=True);return a


def projection(a):
    need(type(a)is dict and 'authorization'in a,'derived operational admission requires original Root/provider/native bridge')
    result=copy.deepcopy(a);result.pop('authorization');result['llvm']=_legacy_llvm(a['llvm'],True);return result


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
