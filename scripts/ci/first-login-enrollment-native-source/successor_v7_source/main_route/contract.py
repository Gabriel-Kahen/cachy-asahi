# SPDX-License-Identifier: MIT
"""Pure DATA qualification for an externally Root-selected Source205 ONCE case.

No clock lookup, filesystem/lease/process observation, request issuance or HTTP.
Provided Root assertions are checked for consistency, never authenticated here.
"""
import ast
import copy
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

FAMILY='scripts/ci/first-login-enrollment-native-source/'
LAUNCHER=FAMILY+'payload/native/hosted_current_v3.py'
READER=FAMILY+'payload/native/reader_current_v3.py'
WORKFLOW='.github/workflows/native-arm-current-onboarding-delegated-v3.yml'
REPOSITORY='Gabriel-Kahen/cachy-asahi'
OPERATION='first-login-enrollment-ui-current-v2'
GROUP='native-arm-build'
SOURCE196='0a49872473251ad289fc8a49f51f3a27334c0b35'
CONSTRUCTOR='9e26ce819a258225cac866341e15d7099038ab9e'
SOURCE205=dict(files=205,bytes=45962607,tree='d7e48cbd6a3a638c5ecdabf8ca98a6a642dfde36',source_map=dict(bytes=40793,sha256='a6d22a528075c11f6fa2e87d894c41e0ed31befcd17f99a8b92d6c26fccdb815'))
PROGRAM=dict(path=FAMILY+'successor_v7_source/program.json',bytes=15135,sha256='623f667137fd38d9c319de729df910780fbf0fae7c0bc7e2aade27889c102dae')
PROFILE=dict(bytes=21451,sha256='99198c00308780aaf95e803c43d01ab185b55a049731287b7644c2425dd90a12')
CORE=dict(bytes=68455,sha256='d491626c309a4b0f1fc198fa1cc8515d2412326d0e4fb9947332590d9de0132e')
WORKFLOW_PIN=dict(bytes=8949,sha256='4aaa31fae8b6665d502372467d3da5ceef0bb30553d2dfb1ac9f38a41fc90165')
POLICY=dict(member=FAMILY+'payload/native/owned_current_v3.policy.PROPOSAL.json',bytes=8366,sha256='1177da4f3bfc36f8ebe8802ca6956adf3d0230511aa827bdac933688d83f0767')
LEASE_PATH='/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261025/shared-GUI-ancestor-collection.lock'
LIMITS=dict(request_bytes=49152,preflight_seconds=180,launcher_seconds=7740,address_space_bytes=536870912,cpu_seconds=7740,preflight_cpu_seconds=180,control_bytes=33554432,control_nodes=128,reference_files=1024,reference_bytes=34359738368,reference_file_bytes=8589934592,scope_stop_seconds=10)
TIMING=dict(kind='CURRENT_HOSTED_SHARED_7560_PREREQUISITE_TIMING_V3',whole_budget_seconds=7560,charge_preflight_and_prerequisites=True,allow_clipped_stage_window=True,metadata_queries=2,controller_retirement_reserve_seconds=15,Root_acceptance=None)
CAPS=dict(builder_cpus=4,builder_memory_bytes=4294967296,builder_pids=512,command_rows=512,max_command_seconds=1800,total_seconds=7200)
CONTEXT=dict(max_context_age_seconds=7560,max_delegation_seconds=7560,metadata_max_bytes=1048576,metadata_query_seconds=30)
RESOURCES=dict(classification='HEAVY_NON_KERNEL',scheduling_lane=GROUP,exemptions=[],policy=POLICY,launcher_limits=LIMITS,whole_timing=TIMING,stage_limits=CAPS,context_limits=CONTEXT,scope_limits={'cpu.max':'100000 100000','memory.max':'536870912','memory.swap.max':'0','pids.max':'64'})
STATUSES=('in_progress','pending','queued','waiting','requested')
OPERANDS=('case','admission','runtime','registration','readback','once','request')
FINAL=dict(Root_final_acceptance=None,independent_component_acceptance=False,hardware_acceptance=False,release_acceptance=False)
MAX_BYTES=131072


def need(condition,code):
    if not condition:raise ValueError(code)


def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def decode(raw):
    def pairs(items):
        value={}
        for key,item in items:need(key not in value,'HOLD_DUPLICATE_JSON');value[key]=item
        return value
    value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'HOLD_NONFINITE_JSON'))
    need(raw==encoded(value),'HOLD_NONCANONICAL_JSON');return value


def shape(value,keys,code):need(type(value)is dict and set(value)==set(keys),code)
def integer(value,low=0,high=2**53):return type(value)is int and low<=value<=high
def hexid(value,size):return type(value)is str and re.fullmatch('[0-9a-f]{%d}'%size,value)is not None
def same(a,b):return encoded(a)==encoded(b)


def whole(value,cap=MAX_BYTES):
    shape(value,('bytes','sha256'),'HOLD_WHOLE_PIN')
    need(integer(value['bytes'],1,cap)and hexid(value['sha256'],64),'HOLD_WHOLE_PIN');return value


def descriptor(value,member,cap=1024**2):
    shape(value,('member','bytes','sha256'),'HOLD_DESCRIPTOR')
    need(value['member']==member,'HOLD_DESCRIPTOR_MEMBER');whole({k:value[k]for k in ('bytes','sha256')},cap);return value


def fresh(value,now,age=120):
    need(integer(value)and 0<=now-value<=age,'HOLD_STALE_OBSERVATION')


def issued(value,kind,keys,now):
    shape(value,keys,'HOLD_'+kind+'_SHAPE')
    need(type(value['schema'])is int and value['schema']==1 and value['kind']==kind
        and value['issuer']=='Root'and value['approved']is True,'HOLD_'+kind+'_UNISSUED')
    if 'issued_epoch'in value:
        need(integer(value['issued_epoch'])and integer(value['expires_epoch'])
            and value['issued_epoch']<=now<value['expires_epoch']
            and 0<value['expires_epoch']-value['issued_epoch']<=7560,'HOLD_AUTHORITY_TIME')


def binding(case):
    return dict(case_id=case['case_id'],source=case['source']['cid'],ref=case['source']['ref'],source_lock=case['source']['source_map'],
        main=case['main']['cid'],operation=OPERATION,group=GROUP,stage=case['stage'],nonce=case['nonce'])


def canonical_lease(lease):
    shape(lease,('path','dev','inode','uid','gid','mode','nlink','bytes','mtime_ns','ctime_ns'),'HOLD_LEASE_IDENTITY')
    need(lease['path']==LEASE_PATH and integer(lease['dev'],1)and integer(lease['inode'],1)
        and integer(lease['uid'])and integer(lease['gid'])and type(lease['mode'])is int and lease['mode']==0o644
        and type(lease['nlink'])is int and lease['nlink']==1 and type(lease['bytes'])is int and lease['bytes']==0
        and integer(lease['mtime_ns'],1,2**63-1)and integer(lease['ctime_ns'],1,2**63-1),'HOLD_CANONICAL_LEASE')


def validate_case(case,now):
    issued(case,'ROOT_SOURCE205_ONCE_CASE_V1',('schema','kind','issuer','approved','case_id','source','main','workflow_id','operation','group','stage','nonce','issued_epoch','expires_epoch','canonical_lease','resources','pins'),now)
    need(hexid(case['case_id'],64)and hexid(case['nonce'],64)and case['operation']==OPERATION and case['group']==GROUP
        and case['stage']in ('backend','ui','lifecycle')and integer(case['workflow_id'],1),'HOLD_CASE_SELECTORS')
    source=case['source'];shape(source,('cid','ref',*SOURCE205,'program','profile'),'HOLD_SOURCE_SHAPE')
    need(hexid(source['cid'],40)and source['cid']not in (SOURCE196,CONSTRUCTOR)
        and type(source['ref'])is str and re.fullmatch('refs/heads/codex/[A-Za-z0-9._/-]+',source['ref'])
        and all(part not in ('','.','..')and not part.startswith('.')and not part.endswith('.lock')for part in source['ref'].split('/'))
        and not source['ref'].endswith('.')and same({k:source[k]for k in SOURCE205},SOURCE205)
        and same(source['program'],PROGRAM)and same(source['profile'],PROFILE),'HOLD_SOURCE205_IDENTITY')
    main=case['main'];shape(main,('cid','tree','launcher','reader','reader_contract','workflow'),'HOLD_MAIN_SHAPE')
    need(hexid(main['cid'],40)and main['cid']!=source['cid']and hexid(main['tree'],40),'HOLD_MAIN_SELECTOR')
    descriptor(main['launcher'],LAUNCHER);need(same(main['launcher'],dict(member=LAUNCHER,**CORE)),'HOLD_MAIN_V7_ADOPTION')
    descriptor(main['reader'],READER);need(main['reader_contract']=='SOURCE205_FINITE_TRANSPORT_V2','HOLD_MAIN_READER_CONTRACT')
    descriptor(main['workflow'],WORKFLOW);need(same(main['workflow'],dict(member=WORKFLOW,**WORKFLOW_PIN)),'HOLD_MAIN_WORKFLOW')
    need(same(case['resources'],RESOURCES),'HOLD_CASE_RESOURCE_POLICY')
    canonical_lease(case['canonical_lease'])
    shape(case['pins'],OPERANDS[1:],'HOLD_CASE_PIN_ROSTER')
    for row in case['pins'].values():whole(row)


def validate_runtime(runtime,case,now):
    issued(runtime,'ROOT_SOURCE205_ONCE_RUNTIME_V1',('schema','kind','issuer','approved','binding','issued_epoch','expires_epoch','lease_identity','custody','sweeps'),now)
    need(same(runtime['binding'],binding(case)),'HOLD_RUNTIME_BINDING')
    lease=runtime['lease_identity'];canonical_lease(lease)
    need(same(lease,case['canonical_lease']),'HOLD_CASE_RUNTIME_LEASE')
    custody=runtime['custody'];shape(custody,('held_fd','held_fd_identity','path_identity','owner_pid','owner_starttime','owner_pidfd','owner_alive','owner_starttime_verified','pidfd_identity_verified','independent_nonblocking_rejected','lock_held','release'),'HOLD_CUSTODY_SHAPE')
    need(integer(custody['held_fd'],3)and integer(custody['owner_pidfd'],3)and custody['held_fd']!=custody['owner_pidfd']
        and integer(custody['owner_pid'],1)and integer(custody['owner_starttime'],1)
        and same(custody['held_fd_identity'],lease)and same(custody['path_identity'],lease)
        and all(custody[key]is True for key in ('owner_alive','owner_starttime_verified','pidfd_identity_verified','independent_nonblocking_rejected','lock_held'))
        and custody['release']=='CLOSE_ONLY','HOLD_CANONICAL_CUSTODY')
    sweeps=runtime['sweeps'];need(type(sweeps)is list and len(sweeps)==2,'HOLD_DOUBLE_CENSUS')
    ids=[];times=[]
    for sequence,sweep in enumerate(sweeps,1):
        shape(sweep,('sequence','observation_id','observed_epoch','statuses','pages_complete','all_jobs_complete','runs'),'HOLD_CENSUS_SHAPE')
        need(type(sweep['sequence'])is int and sweep['sequence']==sequence and hexid(sweep['observation_id'],64)
            and type(sweep['statuses'])is list and len(sweep['statuses'])==5 and all(type(status)is str for status in sweep['statuses'])and set(sweep['statuses'])==set(STATUSES)
            and sweep['pages_complete']is True and sweep['all_jobs_complete']is True,'HOLD_COMPLETE_CENSUS')
        fresh(sweep['observed_epoch'],now);ids.append(sweep['observation_id']);times.append(sweep['observed_epoch'])
        runs=sweep['runs'];need(type(runs)is list and len(runs)<=1000,'HOLD_FINITE_CENSUS');seen=set()
        for run in runs:
            shape(run,('run','attempt','status','workflow_id','source','group','operation','classification','body_pin','jobs'),'HOLD_RUN_CLASSIFICATION')
            need(integer(run['run'],1)and run['run']not in seen and integer(run['attempt'],1)
                and run['status']in STATUSES and integer(run['workflow_id'],1)and hexid(run['source'],40),'HOLD_RUN_IDENTITY');seen.add(run['run']);whole(run['body_pin'])
            need(run['classification']=='LIGHT_OTHER'and type(run['group'])is str and type(run['operation'])is str
                and run['group']!=GROUP and run['operation']!=OPERATION and run['workflow_id']!=case['workflow_id']
                and run['source']!=case['source']['cid'],'HOLD_ACTIVE_HEAVY_NATIVE_OR_UNKNOWN')
            jobs=run['jobs'];need(type(jobs)is list and 0<len(jobs)<=256,'HOLD_ALL_JOBS');job_ids=set()
            for job in jobs:
                shape(job,('job','status','classification','runner_arch','body_pin'),'HOLD_JOB_CLASSIFICATION')
                need(integer(job['job'],1)and job['job']not in job_ids and job['status']in ('queued','in_progress','completed','waiting','requested')
                    and job['classification']=='LIGHT_OTHER'and job['runner_arch']=='X64','HOLD_UNKNOWN_OR_NATIVE_JOB')
                job_ids.add(job['job']);whole(job['body_pin'])
    need(ids[0]!=ids[1]and times[0]<=times[1],'HOLD_NONINDEPENDENT_CENSUS')
    def census_identity(runs):
        return [dict(run,jobs=sorted(run['jobs'],key=lambda job:job['job']))for run in sorted(runs,key=lambda run:run['run'])]
    need(same(census_identity(sweeps[0]['runs']),census_identity(sweeps[1]['runs'])),'HOLD_NONCONVERGED_CENSUS')


def core_request(core_raw,request_raw):
    """Run the unchanged whole-pinned Core.request with bounded in-memory IO.

    Only ten pure predicate definitions and two literal resource declarations are
    compiled. Imports, program loaders and every operational entry are excluded.
    This does not attest a runtime file, Main checkout or executing wrapper.
    """
    need(type(core_raw)is bytes and pin(core_raw)==CORE,'HOLD_CORE_BODY')
    names={'need','pin','encoded','decode','whole','descriptor','request','prerequisite_selected','material_selected','assembly_request'}
    tree=ast.parse(core_raw);functions=[node for node in tree.body if isinstance(node,ast.FunctionDef)and node.name in names]
    declarations=[node for node in tree.body if isinstance(node,ast.Assign)and len(node.targets)==1
        and isinstance(node.targets[0],ast.Name)and node.targets[0].id in ('LIMITS','TIMING')]
    need(len(functions)==len(names)and {node.name for node in functions}==names and len(declarations)==2
        and all(not node.decorator_list for node in functions),'HOLD_CORE_PREDICATE_CLOSURE')
    marker='/SOURCE205_DATA_ONLY_REQUEST'
    def memory_read(path,cap=2*1024**2):
        need(path==marker and len(request_raw)<=cap,'HOLD_CORE_IO_BOUNDARY');return request_raw
    scope=dict(json=json,hashlib=hashlib,re=re,Path=Path,read=memory_read)
    exec(compile(ast.Module(body=declarations+functions,type_ignores=[]),'<whole-pinned-Core.request-DATA>','exec'),scope)
    need(same(scope['LIMITS'],LIMITS)and same(scope['TIMING'],TIMING),'HOLD_CORE_RESOURCE_DECLARATIONS')
    return scope['request'](marker,pin(request_raw)['sha256'])


def validate_request(request_raw,case,core_raw,profile):
    need(len(request_raw)<=LIMITS['request_bytes'],'HOLD_REQUEST_CAP');request=core_request(core_raw,request_raw)
    need(request['trusted_main_commit']==case['main']['cid']and same(request['launcher'],case['main']['launcher'])
        and request['staged_inputs']is None and request['staged_root']is None,'HOLD_REQUEST_MAIN')
    d=decode(request['delegation_json'].encode());shape(d,('schema','kind','issuer','approved','scope','binding','stage','nonce','issued_epoch','expires_epoch','programs','materials','policy','capability','context_limits','hosted','image_ids',*FINAL),'HOLD_DELEGATION_SHAPE')
    need(type(d['schema'])is int and d['schema']==4 and d['kind']=='ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V4'
        and d['issuer']=='Root'and d['approved']is True and d['scope']=='CURRENT_PRIVATE_STAGE_ONLY'
        and same(d['binding'],dict(source=case['source']['cid'],ref=case['source']['ref'],run=None,job=None,attempt=1,source_lock=SOURCE205['source_map']))
        and d['stage']==case['stage']and d['nonce']==case['nonce']and integer(d['issued_epoch'])and integer(d['expires_epoch'])
        and d['issued_epoch']==case['issued_epoch']and d['expires_epoch']==case['expires_epoch']
        and same(d['policy'],POLICY)and same(d['context_limits'],CONTEXT)and same(d['image_ids'],dict(backend=None,ui=None,lifecycle=None))
        and all(d[key]is value for key,value in FINAL.items()),'HOLD_DELEGATION_BINDING')
    capability=dict(operation=OPERATION,stage=case['stage'],allow_provisional_context=True,allow_provisional_image_checks=True,
        allow_pair_adoption=False,allow_host_prerequisites=True,allow_material_staging=True,**CAPS)
    need(same(d['capability'],capability),'HOLD_DELEGATED_CAPABILITY')
    need(type(d['programs'])is dict and len(d['programs'])==25 and type(d['materials'])is dict and len(d['materials'])==64
        and same(d['programs'],profile['delegation_programs'])and same(d['materials'],dict(profile['materials'],**profile['staging_materials'])),'HOLD_SOURCE_PROGRAMS')
    for rows in (d['programs'],d['materials']):
        for role,row in rows.items():
            need(type(role)is str and re.fullmatch('[a-z][a-z0-9_]{0,63}',role),'HOLD_SOURCE_ROLE');shape(row,('member','bytes','sha256'),'HOLD_SOURCE_DESCRIPTOR')
            need(type(row['member'])is str and not row['member'].startswith('/')and all(part not in ('','.','..')for part in row['member'].split('/')),'HOLD_SOURCE_MEMBER')
            whole({k:row[k]for k in ('bytes','sha256')},2**31)
    expected_hosted=dict(repository=REPOSITORY,workflow_ref=REPOSITORY+'/'+WORKFLOW+'@'+case['source']['ref'],workflow_sha=case['source']['cid'],job_key='current',job_name='current-onboarding-delegated-v3',runner_environment='github-hosted',runner_os='Linux',runner_arch='ARM64')
    need(same(d['hosted'],expected_hosted)and request['control_name']=='cachy-current-hosted-'+case['nonce'],'HOLD_HOSTED_SELECTORS')
    selection=request['material_staging'];shape(selection,('grant_json','grant_pin','assembler_request'),'HOLD_MATERIAL_SELECTION')
    grant_raw=selection['grant_json'].encode();need(pin(grant_raw)==selection['grant_pin'],'HOLD_GRANT_PIN');grant=decode(grant_raw)
    shape(grant,('schema','kind','issuer','approved','source','ref','source_lock','nonce','policy','issued_epoch','expires_epoch','redirect_urls','secret_provider','scope','storage_parent'),'HOLD_GRANT_SHAPE')
    need(type(grant['schema'])is int and grant['schema']==3 and grant['kind']=='ROOT_CURRENT_COMPLETE517_STAGING_V3'
        and grant['issuer']=='Root'and grant['approved']is True and grant['source']==case['source']['cid']and grant['ref']==case['source']['ref']
        and same(grant['source_lock'],SOURCE205['source_map'])and grant['nonce']==case['nonce']and same(grant['policy'],{k:POLICY[k]for k in ('bytes','sha256')})
        and integer(grant['issued_epoch'])and integer(grant['expires_epoch'])and grant['issued_epoch']==case['issued_epoch']and grant['expires_epoch']==case['expires_epoch']
        and grant['secret_provider']=='CALLER_ONE_SHOT_EXACT22'and grant['scope']=='COMPLETE517_PUBLIC_DATA_ONLY'
        and grant['storage_parent']=='/var/lib/cachy-current-material-domain-'+case['nonce'],'HOLD_GRANT_BINDING')
    redirects=grant['redirect_urls'];need(type(redirects)is dict and len(redirects)==21,'HOLD_REDIRECT_ROSTER')
    for name,urls in redirects.items():
        need(type(name)is str and re.fullmatch('[A-Za-z0-9_.+:-]{1,256}',name)and type(urls)is list and len(urls)<=2
            and all(type(url)is str and 0<len(url)<=2048 for url in urls)and len(set(urls))==len(urls),'HOLD_REDIRECT_SHAPE')
        for url in urls:
            parsed=urlsplit(url);need(parsed.scheme=='https'and parsed.hostname and parsed.port in (None,443)
                and not(parsed.username or parsed.password or parsed.query or parsed.fragment),'HOLD_PUBLIC_REDIRECT')
    assembly=selection['assembler_request'];need(type(assembly)is dict and set(assembly)=={'json','pin'}and type(assembly['json'])is str
        and 0<len(assembly['json'].encode())<=8192 and pin(assembly['json'].encode())==assembly['pin'],'HOLD_ASSEMBLER_PIN')
    assembler=decode(assembly['json'].encode())
    base=('base_lock','bootstrap_profile','base_materials','supplemental_materials','keyring_materials')
    shape(assembler,('schema','kind','stage','source_date_epoch',*base,'official_trust','test_trust','products','retention'),'HOLD_ASSEMBLER_SHAPE')
    need(type(assembler['schema'])is int and assembler['schema']==3 and assembler['kind']=='CURRENT_ONBOARDING_INPUT_REQUEST_V3'
        and assembler['stage']==case['stage']and integer(assembler['source_date_epoch'])and all(assembler[name]is None for name in base)
        and type(assembler['products'])is dict,'HOLD_ASSEMBLER_STAGE')
    for name in ('official_trust','test_trust'):
        trust=assembler[name];shape(trust,('public_key','fingerprint','Root_admission'),'HOLD_ASSEMBLER_TRUST')
        need(all(trust[key]is not None for key in trust),'HOLD_ASSEMBLER_TRUST_UNISSUED')
    return request


def qualify(operands,expected_pins,*,now,core_raw,profile_raw):
    """Qualify externally supplied bytes only; preserve request bytes unchanged."""
    need(integer(now),'HOLD_EXPLICIT_NOW');shape(operands,OPERANDS,'HOLD_OPERAND_ROSTER');shape(expected_pins,OPERANDS,'HOLD_EXTERNAL_PIN_ROSTER')
    need(type(profile_raw)is bytes and pin(profile_raw)==PROFILE,'HOLD_EXACT_SOURCE205_PROFILE');profile=decode(profile_raw)
    values={}
    for name,raw in operands.items():
        cap=LIMITS['request_bytes']if name=='request'else MAX_BYTES
        whole(expected_pins[name],cap);need(type(raw)is bytes and 0<len(raw)<=cap and pin(raw)==expected_pins[name],'HOLD_EXTERNAL_'+name.upper()+'_PIN')
        values[name]=decode(raw)
    case=values['case'];validate_case(case,now)
    need(all(same(case['pins'][name],expected_pins[name])for name in OPERANDS[1:]),'HOLD_CASE_OPERAND_PINS')
    for name,kind in (('admission','ROOT_SOURCE205_ONCE_ADMISSION_V1'),('registration','ROOT_SOURCE205_WORKFLOW_REGISTRATION_V1'),('readback','ROOT_SOURCE205_READBACK_V1'),('once','ROOT_SOURCE205_ONCE_GUARD_V1')):
        value=values[name]
        keys=dict(admission=('schema','kind','issuer','approved','binding','issued_epoch','expires_epoch','resources','reservation'),
            registration=('schema','kind','issuer','approved','binding','observed_epoch','repository','workflow_id','path','state','body_pin'),
            readback=('schema','kind','issuer','approved','binding','observed_epoch','source','main','profile_pin','publication_complete','main_adoption_complete'),
            once=('schema','kind','issuer','approved','binding','observed_epoch','once','retry','prior_run_ids','prior_intents','uncertain','post_count','phase','output_fresh','exclusive_intent','runtime_pin','request_pin'))[name]
        issued(value,kind,keys,now);need(same(value['binding'],binding(case)),'HOLD_'+name.upper()+'_BINDING')
        if 'observed_epoch'in value:fresh(value['observed_epoch'],now)
    admission=values['admission'];need(same(admission['resources'],RESOURCES),'HOLD_ADMISSION_RESOURCES')
    reservation=admission['reservation'];shape(reservation,('held_by','active','pending','group','operation','no_exemptions'),'HOLD_RESERVATION')
    need(reservation['held_by']=='Root'and type(reservation['active'])is int and reservation['active']==0 and type(reservation['pending'])is int and reservation['pending']==0
        and reservation['group']==GROUP and reservation['operation']==OPERATION and reservation['no_exemptions']is True,'HOLD_RESOURCE_RESERVATION')
    validate_runtime(values['runtime'],case,now)
    for name in ('admission','runtime'):
        value=values[name];need(case['issued_epoch']<=value['issued_epoch']and value['expires_epoch']<=case['expires_epoch'],'HOLD_AUTHORITY_ENVELOPE')
    registration=values['registration'];need(registration['repository']==REPOSITORY and type(registration['workflow_id'])is int and registration['workflow_id']==case['workflow_id']
        and registration['path']==WORKFLOW and registration['state']=='active'and same(registration['body_pin'],WORKFLOW_PIN),'HOLD_WORKFLOW_REGISTRATION')
    readback=values['readback'];need(same(readback['source'],case['source'])and same(readback['main'],case['main'])and same(readback['profile_pin'],PROFILE)
        and readback['publication_complete']is True and readback['main_adoption_complete']is True,'HOLD_READBACK_ADOPTION')
    once=values['once'];need(once['once']is True and once['retry']is False and once['prior_run_ids']==[]and once['prior_intents']==[]
        and once['uncertain']is False and type(once['post_count'])is int and once['post_count']==0 and once['phase']=='BEFORE_POST'
        and once['output_fresh']is True and once['exclusive_intent']is True and same(once['runtime_pin'],expected_pins['runtime'])
        and same(once['request_pin'],expected_pins['request']),'HOLD_ONCE_RECONCILE_ONLY')
    need(once['observed_epoch']>=max(admission['issued_epoch'],values['runtime']['issued_epoch'],registration['observed_epoch'],readback['observed_epoch'],
        *(sweep['observed_epoch']for sweep in values['runtime']['sweeps'])),'HOLD_ONCE_CAUSAL_ORDER')
    request=validate_request(operands['request'],case,core_raw,profile)
    inputs=dict(root_request_json=operands['request'].decode('ascii'),root_request_sha256=pin(operands['request'])['sha256'])
    body=encoded(dict(ref=case['source']['ref'].removeprefix('refs/heads/'),inputs=inputs));need(len(body)<=65536,'HOLD_DISPATCH_BODY_CAP')
    return dict(status='DATA_CONTRACT_QUALIFIED_FOR_EXTERNAL_ROOT_OPERATOR',ready_for_external_root_operator=True,
        Root_authentication=False,Root_acceptance=None,lease_observed_here=False,native_entered=False,POSTs=0,
        binding=binding(case),request_raw=operands['request'],request=request,dispatch_inputs=inputs,dispatch_body=body,
        operator_argv=['gh','api','--method','POST','repos/'+REPOSITORY+'/actions/workflows/'+str(case['workflow_id'])+'/dispatches','--input','-'],
        once=True,retry=False,uncertain_outcome='RECONCILE_ONLY_NEVER_REDISPATCH')


def templates():
    """Unissued scaffolds only; these values cannot qualify for an actor."""
    return {
        'Root-case.TEMPLATE.json':dict(schema=1,kind='ROOT_SOURCE205_ONCE_CASE_V1',issuer=None,approved=None,case_id=None,
            source=dict(cid=None,ref=None,**copy.deepcopy(SOURCE205),program=copy.deepcopy(PROGRAM),profile=copy.deepcopy(PROFILE)),
            main=dict(cid=None,tree=None,launcher=dict(member=LAUNCHER,**CORE),reader=dict(member=READER,bytes=None,sha256=None),reader_contract='SOURCE205_FINITE_TRANSPORT_V2',workflow=dict(member=WORKFLOW,**WORKFLOW_PIN)),
            workflow_id=None,operation=OPERATION,group=GROUP,stage=None,nonce=None,issued_epoch=None,expires_epoch=None,
            canonical_lease=dict(path=LEASE_PATH,dev=None,inode=None,uid=None,gid=None,mode=0o644,nlink=1,bytes=0,mtime_ns=None,ctime_ns=None),
            resources=copy.deepcopy(RESOURCES),pins=dict.fromkeys(OPERANDS[1:])),
        'admission.TEMPLATE.json':dict(schema=1,kind='ROOT_SOURCE205_ONCE_ADMISSION_V1',issuer=None,approved=None,binding=None,
            issued_epoch=None,expires_epoch=None,resources=copy.deepcopy(RESOURCES),
            reservation=dict(held_by=None,active=None,pending=None,group=GROUP,operation=OPERATION,no_exemptions=None)),
        'runtime.TEMPLATE.json':dict(schema=1,kind='ROOT_SOURCE205_ONCE_RUNTIME_V1',issuer=None,approved=None,binding=None,
            issued_epoch=None,expires_epoch=None,lease_identity=None,custody=None,sweeps=None)}
