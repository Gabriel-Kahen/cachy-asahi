#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Root-pinned current onboarding hosted entry. No operation occurs on import."""
import argparse
import ast
import copy
import fcntl
import hashlib
import http.client
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import resource
import signal
import ssl
import stat
import subprocess
import sys
import time
from types import SimpleNamespace

API='CURRENT_ONBOARDING_HOSTED_LAUNCHER_V3'
OWNED_SHA='83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f'
LIMITS=dict(request_bytes=49152,preflight_seconds=180,launcher_seconds=7740,address_space_bytes=536870912,
            cpu_seconds=7740,preflight_cpu_seconds=180,control_bytes=33554432,control_nodes=128,reference_files=1024,
            reference_bytes=34359738368,reference_file_bytes=8589934592,scope_stop_seconds=10)
SCOPE={'memory.max':'536870912','memory.swap.max':'0','cpu.max':'100000 100000','pids.max':'64'}
FINAL=dict(Root_final_acceptance=None,independent_component_acceptance=False,hardware_acceptance=False,release_acceptance=False)
TIMING=dict(kind='CURRENT_HOSTED_SHARED_7560_PREREQUISITE_TIMING_V3',whole_budget_seconds=7560,
            charge_preflight_and_prerequisites=True,allow_clipped_stage_window=True,metadata_queries=2,
            controller_retirement_reserve_seconds=15,Root_acceptance=None)
PREREQUISITE_ENV=('GITHUB_ACTIONS','RUNNER_OS','RUNNER_ARCH','GITHUB_REPOSITORY','GITHUB_EVENT_NAME',
                  'GITHUB_RUN_ATTEMPT','GITHUB_RUN_ID','GITHUB_SHA','GITHUB_REF','GITHUB_JOB')
VALIDATING=False


def need(ok,why):
    if not ok:raise ValueError(why)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def decode(raw):
    def pairs(rows):
        result={}
        for k,v in rows:need(k not in result,'duplicate JSON key');result[k]=v
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda v:need(False,'nonfinite JSON'))


def read(path,cap=2*1024**2):
    path=Path(path);need(path.is_absolute()and path==path.resolve()and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary absolute DATA')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<a.st_size<=cap and not a.st_mode&0o022,'bounded ordinary non-writable-by-others DATA')
        with os.fdopen(os.dup(fd),'rb')as f:raw=f.read(cap+1)
        key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        need(len(raw)==a.st_size and key(a)==key(os.fstat(fd))==key(path.lstat()),'stable whole DATA');return raw
    finally:os.close(fd)


def whole(row,*,allow_empty=False):
    need(type(row)is dict and set(row)=={'bytes','sha256'}and type(row['bytes'])is int and row['bytes']>=(0 if allow_empty else 1)
         and type(row['sha256'])is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),'typed whole pin')
    need(row['bytes']!=0 or row['sha256']==pin(b'')['sha256'],'empty DATA requires exact empty SHA256');return row


def descriptor(row):
    need(type(row)is dict and set(row)=={'member','bytes','sha256'},'closed Source descriptor')
    p=Path(row['member']);need(not p.is_absolute()and str(p)==row['member']and all(x not in('','..','.')for x in p.parts),'Source-relative member')
    return whole({k:row[k]for k in('bytes','sha256')})


def program(root,row,name):
    raw=read(root/row['member'],128*1024);need(pin(raw)==descriptor(row),'whole Root-selected program '+name)
    spec=importlib.util.spec_from_file_location(name,root/row['member']);module=importlib.util.module_from_spec(spec);sys.modules[name]=module
    exec(compile(raw,module.__file__,'exec'),module.__dict__);return module


def request(path,expected):
    raw=read(path,LIMITS['request_bytes']);need(pin(raw)['sha256']==expected,'external whole Root launch request pin')
    r=decode(raw);need(raw==encoded(r),'canonical Root request')
    need(set(r)in({'schema','kind','issuer','approved','trusted_main_commit','launcher','delegation_json','delegation_pin','staged_inputs','staged_root','control_name','authorization'}, {'schema','kind','issuer','approved','trusted_main_commit','launcher','delegation_json','delegation_pin','staged_inputs','staged_root','control_name','authorization','material_staging'}),'finite Root launch request schema')
    need(type(r['schema'])is int and r['schema']==3 and r['kind']=='ROOT_AUTHORIZED_CURRENT_HOSTED_LAUNCH_V3'
         and r['issuer']=='Root'and r['approved']is True and re.fullmatch('[0-9a-f]{40}',r['trusted_main_commit']or ''),'Root selected private launch only')
    descriptor(r['launcher']);need(type(r['delegation_json'])is str and pin(r['delegation_json'].encode())==whole(r['delegation_pin']),'whole canonical delegation input')
    authorization=dict(jobs_metadata=True,privileged_controller=True,launcher_limits=LIMITS)
    if prerequisite_selected(decode(r['delegation_json'])):authorization.update(host_prerequisites=True,whole_timing=TIMING)
    if material_selected(r):authorization.update(material_staging=True)
    need(r['authorization']==authorization,'separate explicit finite launcher authorization')
    if material_selected(r):
        value=r['material_staging'];need(type(value)is dict and set(value)=={'grant_json','grant_pin','assembler_request'}and type(value['grant_json'])is str and pin(value['grant_json'].encode())==whole(value['grant_pin']),'exact independently whole-pinned Root staging selection')
        assembly_request(value['assembler_request']);need(r['staged_inputs']is None and r['staged_root']is None,'no pretended preexisting staged bodies on acquisition path');return r
    need(type(r['staged_inputs'])is dict and set(r['staged_inputs'])=={'path','bytes','sha256'},'externally whole-pinned staged input DATA')
    whole({k:r['staged_inputs'][k]for k in('bytes','sha256')});return r


def validation_fence(event,args):
    if not VALIDATING:return
    need(not event.startswith(('subprocess.','socket.','ctypes.'))and event not in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock','os.mkdir','os.rmdir','os.remove','os.rename','os.link','os.symlink','os.chmod','os.chown','os.truncate','os.utime','os.setxattr','os.removexattr'),'pure assembler cannot enter a role')
    if event=='open'and len(args)>=3 and type(args[2])is int:
        need(not args[2]&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND),'pure assembler cannot write')


def checked_inputs(r,d,root,H,deadline):
    global VALIDATING
    staged=Path(r['staged_root']);need(staged.is_absolute()and staged==staged.resolve()and staged.is_dir()
        and staged.stat().st_uid==os.getuid()and stat.S_IMODE(staged.stat().st_mode)==0o700,'existing private caller-staged genuine input domain')
    row=r['staged_inputs'];path=Path(row['path']);need(path.is_relative_to(staged),'staged wrapper belongs to declared domain')
    raw=read(path,4*1024**2);need(pin(raw)=={k:row[k]for k in('bytes','sha256')},'whole actual staged input wrapper')
    value=decode(raw);need(type(value)is dict and set(value)=={'schema','kind','owner_inputs','staged_refs'}and type(value['schema'])is int and value['schema']==3
        and value['kind']=='ROOT_STAGED_CURRENT_INPUTS_V3'and type(value['owner_inputs'])is dict and set(value['owner_inputs'])=={'image_inputs','stage_inputs'}and all(type(v)is dict for v in value['owner_inputs'].values())and type(value['staged_refs'])is list,'exact canonical outer wrapper and distinct inner owner inputs')
    need('inputs_assembler'in d['programs'],'committed pure input assembler descriptor required')
    VALIDATING=True
    try:
        assembler=program(root,d['programs']['inputs_assembler'],'current_hosted_inputs_assembler')
        validate=getattr(assembler,'validate_hosted_inputs_v3',None);need(callable(validate),'actual committed semantic input validator required')
        result=validate(inputs=copy.deepcopy(value),delegation=copy.deepcopy(d),source_root=root)
    finally:VALIDATING=False
    need(type(result)is dict and set(result)=={'valid','required_refs'}and result['valid']is True
         and type(result['required_refs'])is list and 0<len(result['required_refs'])<=LIMITS['reference_files']and result['required_refs']==value['staged_refs'],'complete semantic staged-reference selection exactly joins outer envelope')
    source_rows={str(root/row['member']):descriptor(row)for row in d['materials'].values()}
    found=set();total=0
    for ref in result['required_refs']:
        need(type(ref)is dict and set(ref)=={'path','bytes','sha256'},'whole semantic required file descriptor')
        p=Path(ref['path']);expected=whole({k:ref[k]for k in('bytes','sha256')},allow_empty=p.is_relative_to(staged)and not p.is_relative_to(root))
        need(str(p)not in found and p.is_absolute()and p==p.resolve()and not any(q.is_symlink()for q in(p,*p.parents)),'distinct ordinary required DATA')
        found.add(str(p));total+=ref['bytes'];need(ref['bytes']<=LIMITS['reference_file_bytes']and total<=LIMITS['reference_bytes'],'finite complete intake before reading')
        need(p.is_relative_to(staged)or source_rows.get(str(p))==expected,'only staged domain or exact declared Source material')
        need(not any(part in('.gnupg','.ssh','.aws','.config')for part in p.parts),'no private-home/keyring/credential domains')
        fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        try:
            before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_size==ref['bytes']and not before.st_mode&0o022,'genuine single-link required body')
            digest=hashlib.sha256();size=0;tail=b''
            with os.fdopen(os.dup(fd),'rb')as stream:
                while block:=stream.read(1024**2):
                    need(time.monotonic()<deadline,'whole finite preflight/intake deadline');size+=len(block);digest.update(block)
                    need(not re.search(rb'-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----',tail+block),'private key material refused');tail=block[-128:]
            key=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mode,s.st_nlink,s.st_mtime_ns,s.st_ctime_ns)
            need(dict(bytes=size,sha256=digest.hexdigest())==expected and key(before)==key(os.fstat(fd))==key(p.lstat()),'stable whole required body')
        finally:os.close(fd)
    return value['owner_inputs'],dict(files=len(found),bytes=total)


def prerequisite_selected(d):
    cap=d.get('capability',{});need(type(cap)is dict,'typed conditional capability')
    selected=cap.get('allow_host_prerequisites',False);need(type(selected)is bool,'explicit boolean prerequisite selection')
    return selected


def prerequisite_program(root,d,policy):
    if not prerequisite_selected(d):return None
    Q=program(root,d['programs']['host_prerequisites'],'current_hosted_prerequisites')
    need(Q.API=='CURRENT_ONBOARDING_HOST_PREREQUISITES_V3'and callable(Q.prepare_host_prerequisites),'actual committed prerequisite API')
    need(policy['host_prerequisites_current_v3']==Q.PROPOSAL and policy['host_prerequisite_timing_v3']==TIMING,'explicit exact separate prerequisite and shared timing policies')
    for role,(size,sha)in Q.DONORS.items():
        row=d['programs'][role];need(descriptor(row)==dict(bytes=size,sha256=sha)and pin(read(root/row['member'],128*1024))==dict(bytes=size,sha256=sha),'complete exact pinned prerequisite Source dependencies')
    return Q


def boot_pin():
    with Path('/proc/sys/kernel/random/boot_id').open('rb')as stream:raw=stream.read(65)
    need(re.fullmatch(rb'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\n',raw),'actual bounded same-boot identity')
    return pin(raw)


def timing_expiry(r,d):
    return min(d['expires_epoch'],decode(r['material_staging']['grant_json'])['expires_epoch'])if material_selected(r)else d['expires_epoch']


def make_timing(plan,context,started):
    now=time.monotonic();expiry=timing_expiry(plan.request,plan.d);deadline=min(started+7560,now+expiry-time.time())
    value=dict(schema=3,kind=TIMING['kind'],request_pin=pin(encoded(plan.request)),delegation_pin=plan.request['delegation_pin'],
        binding=context['binding'],policy_pin=descriptor(plan.d['policy']),boot_pin=boot_pin(),started_monotonic=started,
        deadline_monotonic=deadline,expires_epoch=expiry,whole_budget_seconds=7560,**FINAL)
    validate_timing(plan.request,plan.d,context,value);return value


def validate_timing(r,d,context,value):
    need(set(value)=={'schema','kind','request_pin','delegation_pin','binding','policy_pin','boot_pin','started_monotonic','deadline_monotonic','expires_epoch','whole_budget_seconds',*FINAL},'closed actual shared timing receipt')
    need(type(value['schema'])is int and value['schema']==3 and value['kind']==TIMING['kind']and type(value['whole_budget_seconds'])is int and value['whole_budget_seconds']==7560,'reviewed shared7560 timing identity')
    need(prerequisite_selected(d)and r['authorization'].get('whole_timing')==TIMING,'explicit Root selected timing consumer')
    need(value['request_pin']==pin(encoded(r))and value['delegation_pin']==r['delegation_pin']and value['binding']==context['binding']
        and value['policy_pin']==descriptor(d['policy'])and value['boot_pin']==boot_pin(),'actual request/context/policy and same-boot timing binding')
    a,b=value['started_monotonic'],value['deadline_monotonic']
    need(all(type(x)in(int,float)and math.isfinite(x)for x in(a,b))and 0<a<=time.monotonic()<b<=a+7560,'finite actual whole shared deadline')
    need(value['expires_epoch']==timing_expiry(r,d)and time.time()<value['expires_epoch']and b<=time.monotonic()+value['expires_epoch']-time.time()+.1,'actual Root expiry bounds whole deadline')
    need(all(value.get(k)==v for k,v in FINAL.items()),'timing facts never acceptance');return value


def remaining(timing):
    left=min(timing['deadline_monotonic']-time.monotonic(),timing['expires_epoch']-time.time())
    need(math.isfinite(left)and left>1,'actual shared whole deadline and Root expiry');return left


def read_timing(args,r,d,context):
    need(args.timing is not None and args.timing_sha256 is not None,'whole actual timing operand required')
    raw=read(args.timing);need(pin(raw)['sha256']==args.timing_sha256,'external actual timing pin')
    return validate_timing(r,d,context,decode(raw))


def timing_args(plan):
    if not prerequisite_selected(plan.d):return []
    return ['--timing',str(plan.timing_path),'--timing-sha256',plan.timing_sha]


def controller_seconds(plan):
    if not prerequisite_selected(plan.d):return 7560
    p=plan.policy['executor_current_v3'];seconds=math.floor(remaining(plan.timing))-15-material_close_seconds(plan)
    need(p['setup_seconds']+p['cleanup_seconds']+1<seconds<=7560,'remaining setup, clipped stage and cleanup within same whole budget')
    return seconds


def available_stage_seconds(plan):
    p=plan.policy['executor_current_v3']
    return min(p['stage_seconds'],controller_seconds(plan)-p['setup_seconds']-p['cleanup_seconds']-1)


def prerequisite_scope_tools(plan):
    facts=plan.E.probe_tools();need(set(facts['missing_or_invalid'])<={'bsdtar'},'only explicit prerequisite may be missing before scope entry')
    paths={}
    for name in ('systemd-run','python3'):
        row=facts['tools'][name]['selected'];path=plan.E.checked_tool(row)
        need(path==row['path'],'fresh rejoined canonical root-owned scope executable');paths[name]=path
    plan.scope_tools=paths;return paths


def prerequisite_argv(plan,request_path,request_sha,context_path,context_sha,environment_path,environment_sha):
    need(prerequisite_selected(plan.d)and remaining(plan.timing)>=495+15,'full finite prerequisite scope fits actual shared deadline')
    tools=getattr(plan,'scope_tools',{'systemd-run':'/usr/bin/systemd-run','python3':'/usr/bin/python3'})
    return ['/usr/bin/sudo','-n',tools['systemd-run'],'--scope','--quiet',
        '--unit=cachy-current-prerequisites-'+plan.d['nonce']+'.scope',
        '--property=MemoryMax=536870912','--property=MemorySwapMax=0','--property=CPUQuota=100%',
        '--property=CPUQuotaPeriodSec=100ms','--property=TasksMax=64','--property=RuntimeMaxSec=495s',
        '--property=TimeoutStopSec=10s','--property=KillMode=control-group','--property=OOMPolicy=kill',
        '--',tools['python3'],'-I','-B',str(Path(__file__).resolve()),'prerequisite',
        '--request',str(request_path),'--request-sha256',request_sha,'--source-root',str(plan.root),
        '--context',str(context_path),'--context-sha256',context_sha,'--environment',str(environment_path),'--environment-sha256',environment_sha,
        '--uid',str(os.getuid()),'--gid',str(os.getgid()),*timing_args(plan)]


def prerequisite_absent(nonce,deadline):
    need(re.fullmatch('[0-9a-f]{64}',nonce or ''),'exact prerequisite scope nonce')
    path=Path('/sys/fs/cgroup/system.slice/cachy-current-prerequisites-'+nonce+'.scope')
    end=min(deadline,time.monotonic()+10);absent=0
    while time.monotonic()<end:
        absent=0 if path.exists()else absent+1
        if absent==2:return dict(scope=path.name,absent_twice=True)
        time.sleep(.05)
    raise ValueError('actual prerequisite cgroup must be absent before complete tool gate')


def prerequisite_controller(args):
    need(os.getuid()==os.geteuid()==0,'root-only finite prerequisite wrapper')
    r=request(args.request,args.request_sha256);need(pin(read(Path(__file__).resolve(),128*1024))==descriptor(r['launcher']),'executing whole reviewed Main wrapper')
    root=Path(args.source_root);raw_d=r['delegation_json'].encode();preview=decode(raw_d)
    C=program(root,preview['programs']['context'],'current_prerequisite_context');d=C.validate_delegation(raw_d,r['delegation_pin']['sha256']);C.source(d,root)
    raw_c=read(args.context);need(pin(raw_c)['sha256']==args.context_sha256,'actual prerequisite context whole pin');context=decode(raw_c);C.validate_context(d,context)
    timing=read_timing(args,r,d,context);need(remaining(timing)>=495+15,'full prerequisite scope and retirement reservation')
    policy=decode(read(root/d['policy']['member']));Q=prerequisite_program(root,d,policy);need(Q is not None,'no implicit APT on old path')
    raw_e=read(args.environment);need(pin(raw_e)['sha256']==args.environment_sha256,'whole allowlisted actual public environment')
    env=decode(raw_e);need(type(env)is dict and set(env)==set(PREREQUISITE_ENV),'only exact public prerequisite environment')
    private=Path(args.request).parent;control=private.parent;public=control/'public'
    need(private.name=='private'and control.name==r['control_name']and control.stat().st_uid==args.uid and stat.S_IMODE(control.stat().st_mode)==0o700
        and public.is_dir()and not public.is_symlink()and public.stat().st_uid==args.uid,'same fresh owned control receipt domain')
    resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,)*2);resource.setrlimit(resource.RLIMIT_CPU,(500,)*2);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    report=Q.prepare_host_prerequisites(source_root=root,delegation_raw=raw_d,delegation_sha256=r['delegation_pin']['sha256'],
        context=context,environment=env,output=Path('/var/lib/cachy-current-prerequisites-'+d['nonce']))
    remaining(timing)
    need(report['status']=='PASS_CI_LIBARCHIVE_TOOLS_PREREQUISITE_ONLY'and report['binding']==context['binding']and report['cache_absent']is True
        and report['tool_count']==16 and all(report.get(k)==v for k,v in FINAL.items()),'actual provisional prerequisite outcome only')
    target=public/'host-prerequisite.json';write(target,encoded(report));os.chown(target,args.uid,args.gid)
    return 0


BASE_FIELDS=('base_lock','bootstrap_profile','base_materials','supplemental_materials','keyring_materials')
MATERIAL_STAGER_PIN=dict(bytes=35550,sha256='58c5d0842c17a914239b5f24e9e1ac2987ad8ec9ce9e2a03e63a04f2e2e99282')
MATERIAL_DOMAIN_PIN=dict(bytes=42462,sha256='ead51cfa3bcf4b74fbccc8c469926c71fbb72edefcf9525b297e1737fde3ab8f')
MATERIAL_SECRET_NAMES=tuple(['CACHY_OLD_FOUR_'+tag+'_%02d'%i for tag,count in(('JBIGKIT',2),('JBIGKIT_SIG',1),('LIBTIFF',15),('LIBTIFF_SIG',1))for i in range(1,count+1)]+['CACHY_RETAINED_BUBBLEWRAP_V1_PACKAGE_01','CACHY_RETAINED_BUBBLEWRAP_V1_PACKAGE_02','CACHY_RETAINED_BUBBLEWRAP_V1_SIGNATURE_01'])


def material_selected(r):return 'material_staging'in r


def assembly_request(row):
    need(type(row)is dict and set(row)=={'json','pin'}and type(row['json'])is str,'explicit externally selected assembly JSON and whole pin')
    raw=row['json'].encode();need(0<len(raw)<=8192 and pin(raw)==whole(row['pin']),'assembly DATA capped8192 bytes and externally whole-pinned')
    value=decode(raw);need(raw==encoded(value),'canonical assembly request DATA');return raw


def material_programs(r,d,root,policy):
    if not material_selected(r):return None,None
    need(d['capability'].get('allow_material_staging')is True and prerequisite_selected(d),'explicit staging and prerequisite capabilities share timing consumer')
    value=r['material_staging'];row=d['programs']['materials_stager']
    need(descriptor(row)==MATERIAL_STAGER_PIN,'exact committed canonical-tool staging successor')
    S=program(root,row,'current_hosted_material_stager')
    need(S.API=='CURRENT_COMPLETE517_MATERIAL_STAGING_V3'and tuple(S.secret_names())==MATERIAL_SECRET_NAMES and policy['material_staging_current_v3']==S.PROPOSAL,'actual staging API/names/separate Root resource policy')
    need(descriptor(d['programs']['material_domain_executor'])==MATERIAL_DOMAIN_PIN,'exact committed retained input-domain executor')
    M=program(root,d['programs']['material_domain_executor'],'current_hosted_material_domain_executor')
    need(M.API=='CURRENT_ONBOARDING_MATERIAL_DOMAIN_V3'and callable(getattr(M,'open_material_session',None))and type(getattr(M,'CLOSE_SECONDS',None))is int and 0<M.CLOSE_SECONDS<=180,'actual committed physical input-domain executor API and finite close reservation required')
    need(policy['material_domain_executor_current_v3']==M.PROPOSAL,'separate explicit Root retained-domain resource proposal')
    for role in('staging_base_lock','staging_bootstrap_profile'):
        row=d['materials'][role];need(pin(read(root/row['member'],2*1024**2))==descriptor(row),'whole Source staging operand '+role)
    raw=assembly_request(value['assembler_request'])
    A=program(root,d['programs']['inputs_assembler'],'current_hosted_staging_assembler')
    request=decode(raw);need(type(request)is dict and set(request)==set(A.template())and all(request[k]is None for k in BASE_FIELDS),'actual assembler request with only five unfilled base slots')
    need(request['stage']==d['stage']and type(request['source_date_epoch'])is int and request['source_date_epoch']>=0,'actual stage/epoch selection before acquisition')
    need(all(type(request[k])is dict and set(request[k])=={'public_key','fingerprint','Root_admission'}and all(v is not None for v in request[k].values())for k in('official_trust','test_trust')),'actual externally selected trust inputs before acquisition')
    need(type(request['products'])is dict,'explicit actual product selection before acquisition')
    need(pin(value['grant_json'].encode())==value['grant_pin'],'external whole staging grant before actor')
    # Pure predispatch Source-binding checks, not a fabricated poststart context.
    S.validate_grant(value['grant_json'].encode(),value['grant_pin']['sha256'],d,dict(binding={k:d['binding'][k]for k in('source','ref','source_lock')}),policy)
    return S,M


def assembly_selection(value,plan,fields,output=None,trail=()):
    """Only reviewed Source descriptors or exact staged-cache references resolve."""
    if type(value)is dict:
        if set(value)=={'json','pin'}:
            allowed={'Root_admission','producer_delegation','producer_context','pair','test','root_component','root_test','Root_decision','Root_verification'}
            need(output is not None and trail and trail[-1]in allowed,'only explicit public authority/producer metadata slots may carry exact supplied JSON')
            raw=assembly_request(value);decode(raw);need(not re.search(rb'-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----',raw),'private key material refused in public metadata')
            label=hashlib.sha256(encoded(list(trail))).hexdigest()[:24]+'.json';path=output/label
            write(path,raw);return dict(path=str(path),**pin(raw))
        if set(value)=={'member','bytes','sha256'}:
            need(value in plan.d['materials'].values(),'assembly Source ref is a declared public material')
            raw=read(plan.root/value['member']);need(pin(raw)==descriptor(value),'whole selected Source public DATA')
            return dict(path=str(plan.root/value['member']),**descriptor(value))
        if set(value)=={'cache_member','bytes','sha256'}:
            matches=[rows[value['cache_member']]for name,rows in fields.items()if name.endswith('_materials')and value['cache_member']in rows]
            need(len(matches)==1 and {k:matches[0][k]for k in('bytes','sha256')}=={k:value[k]for k in('bytes','sha256')},'exact explicit complete517 cache selection')
            return copy.deepcopy(matches[0])
        return {k:assembly_selection(v,plan,fields,output,(*trail,k))for k,v in value.items()}
    if type(value)is list:return [assembly_selection(v,plan,fields,output,(*trail,str(i)))for i,v in enumerate(value)]
    return value


def material_close_seconds(plan):
    return plan.M.CLOSE_SECONDS if getattr(plan,'S',None)is not None else 0


PUBLIC_PHASES=frozenset(('git_main','git_source','metadata','context','timing','material_grant','material_open',
    'material_stage','material_retirement','material_receipt','material_fields','assembly_selection','assembly',
    'assembly_output','input_intake','staging_retention','post_staging_tools','prerequisites','context_refresh','controller','controller_result','material_cleanup','complete'))


def failure_summary(plan,error):
    # Neither exception messages nor dynamic exception class names are public.
    kind,reason='OTHER','UNEXPECTED_FAILURE'
    for cls,code in ((TimeoutError,'DEADLINE_EXHAUSTED'),(ValueError,'VALIDATION_REFUSED'),
                     (KeyError,'REQUIRED_FIELD_MISSING'),(OSError,'OS_OPERATION_FAILED'),
                     (SystemExit,'CHILD_ENTRY_REFUSED'),(KeyboardInterrupt,'INTERRUPTED')):
        if isinstance(error,cls):kind,reason=cls.__name__,code;break
    phase=getattr(plan,'public_phase',None)
    return dict(phase=phase if type(phase)is str and phase in PUBLIC_PHASES else 'UNKNOWN',reason=reason),kind


SOURCE_FAILURE_PHASES=frozenset(('ENTRY','AUTHORIZE','SOURCE','NATIVE_CONTEXT','INPUTS','HELPERS','TOOLS','STORAGE','SCOPE',
    'TRANSPORT_PUBLIC14','TRANSPORT_NATIVE248','PRIVATE_SEED','PUBLIC14_PREPARE','NATIVE248_PREPARE','DOWNLOAD','COMPLETE517','FINALIZE','CHILD'))


def material_stage_failure(plan):
    """Validate the pinned Source's fixed diagnostic record before input cleanup."""
    try:
        try:raw=read(plan.control/'material-stage-failure.json',4096)
        except FileNotFoundError:return dict(status='NOT_OBSERVED')
        value=decode(raw)
        keys={'schema','kind','status','availability','packet','request_pin','context_pin','stdout_pin','stderr_pin','retirement_pin',*FINAL}
        need(type(value)is dict and set(value)==keys and raw==encoded(value),'canonical closed Source failure record')
        need(type(value['schema'])is int and value['schema']==1 and value['kind']=='CURRENT_MATERIAL_STAGE_FAILURE_RECORD_V1'
             and value['status']=='DIAGNOSTIC_ONLY'and value['availability']in('AVAILABLE','UNAVAILABLE')
             and all(value[k]is v for k,v in FINAL.items()),'fixed diagnostic-only Source record, never acceptance')
        session=plan.material_session;r=session.r
        need(session.control==plan.control and session.request==plan.control/'material-domain-request.json'
             and r['control_root']==str(plan.control),'same held caller control')
        request=read(plan.control/'material-domain-request.json');context=read(plan.control/'private/context.json')
        need(request==encoded(r)and context==encoded(r['context'])and value['request_pin']==whole(value['request_pin'])==pin(request)
             and value['context_pin']==whole(value['context_pin'])==pin(context),'same actual caller request and captured context pins')
        rows=session.receipts;need(type(rows)is list and len(rows)<=2,'finite original material child rows')
        stage=[row for row in rows if type(row)is dict and row.get('kind')=='STAGE'];need(len(stage)<=1,'one owned staging child')
        row=stage[0]if stage else{};supervision=row.get('supervision')
        def stream_pin(candidate):
            if candidate is None:return None
            whole(candidate,allow_empty=True);need(candidate['bytes']<=1024**2,'bounded material stream pin');return candidate
        need(stream_pin(value['stdout_pin'])==stream_pin(row.get('output_pin')),'same owned staging stdout whole pin')
        retirement=pin(encoded(supervision))if type(supervision)is dict else None
        if value['retirement_pin']is not None:whole(value['retirement_pin'])
        need(value['retirement_pin']==retirement,'same owned child retirement whole pin')
        if value['stderr_pin']is not None:
            need(stream_pin(value['stderr_pin'])==stream_pin(row.get('stderr_pin'))and type(supervision)is dict
                 and supervision.get('reaped')is True and supervision.get('ownership')=='REAPED'
                 and supervision.get('output_complete')is True and type(supervision.get('exit'))is int
                 and supervision.get('group_census')=='EMPTY_TWICE'and supervision.get('signals')==[]
                 and supervision.get('timeout')is False and supervision.get('error')is None,'complete naturally retired staging stderr pin')
        packet=value['packet']
        if value['availability']=='AVAILABLE':
            need(session.stage_submitted is True and len(stage)==1,'packet belongs to the submitted owned staging child')
            need(type(packet)is dict and set(packet)=={'schema','kind','phase','reason','command_ordinal'},'closed Source failure packet')
            need(type(packet['schema'])is int and packet['schema']==1 and packet['kind']=='CURRENT_MATERIAL_STAGE_FAILURE_V1'
                 and type(packet['phase'])is str and packet['phase']in SOURCE_FAILURE_PHASES
                 and type(packet['reason'])is str and packet['reason']in('PHASE_FAILED','COMMAND_FAILED'),'finite Source failure phase and reason')
            ordinal=packet['command_ordinal'];need(ordinal is None or(type(ordinal)is int and 0<=ordinal<=26),'finite Source command ordinal')
            body=encoded(packet);need(len(body)<=1024 and value['stderr_pin']==pin(body),'whole canonical packet equals complete staging stderr')
        else:need(packet is None,'unavailable Source reason must remain absent')
        return dict(value,record_pin=pin(raw))
    except BaseException:return dict(status='UNAVAILABLE_OR_UNSAFE')


def material_failure_data(plan,*,hold=False):
    """Project existing session DATA only; never retain argv/env/error text/streams."""
    try:
        session=plan.material_session;rows=getattr(session,'receipts',[])
        need(type(rows)is list and len(rows)<=2,'finite stage/close diagnostic records')
        state=getattr(session,'state',None)
        result=dict(state=state if state in ('OPEN','HOLD_CLOSEONLY','RETAINED_FOR_CONSUMERS','CLOSED')else 'UNKNOWN',
                    stage_submitted=getattr(session,'stage_submitted',None)is True,children=[])
        for row in rows:
            need(type(row)is dict and row.get('kind')in ('STAGE','CLOSE'),'known diagnostic child kind')
            child=dict(kind=row['kind'],natural_success=row.get('natural')is True)
            value=row.get('supervision')
            if type(value)is dict:
                child['supervision']={k:value[k]for k in ('reaped','output_complete','timeout')if type(value.get(k))is bool}
                child['supervision'].update(
                    exit=value.get('exit')if type(value.get('exit'))is int and -255<=value['exit']<=255 else None,
                    ownership=value.get('ownership')if value.get('ownership')in ('OWNED','REAPED','UNKNOWN')else 'UNKNOWN',
                    group_census='EMPTY_TWICE'if value.get('group_census')=='EMPTY_TWICE'else 'NOT_CONFIRMED_EMPTY',
                    supervisor_error=value.get('error')is not None,
                    signals_observed=bool(value.get('signals')))
            for key in ('output_pin','stderr_pin'):
                value=row.get(key)
                if type(value)is dict and set(value)=={'bytes','sha256'}and type(value.get('bytes'))is int and 0<=value['bytes']<=1024**2:
                    try:child[key]=dict(whole(value,allow_empty=True))
                    except ValueError:pass
            absence=row.get('scope_absence')
            scope='cachy-current-materials-'+('close-'if row['kind']=='CLOSE'else '')+plan.d['nonce']+'.scope'
            child['scope_absent_twice']=type(absence)is dict and absence.get('scope')==scope and absence.get('absent_twice')is True
            result['children'].append(child)
        if hold:
            result['source_failure']=material_stage_failure(plan)
            result['source_hold']=dict(status='NOT_OBSERVED')
            if result['stage_submitted']:
                path=Path(decode(plan.request['material_staging']['grant_json'].encode())['storage_parent'])/('cachy-current-materials-'+plan.d['nonce'])/'HOLD.json'
                try:
                    raw=read(path,4096);value=decode(raw)
                    need(type(value)is dict and raw==encoded(value)and set(value)=={'status','scope','Root_acceptance'}and value['Root_acceptance']is None
                         and value['status']=='HOLD_PARTIAL_OWNED_DATA_CLOSEONLY'
                         and value['scope']=='/system.slice/cachy-current-materials-'+plan.d['nonce']+'.scope','exact selected safe Source HOLD receipt')
                    result['source_hold']=dict(status=value['status'],pin=pin(raw),source_reason='NOT_EMITTED_IN_HOLD_RECEIPT')
                except FileNotFoundError:pass
                except BaseException:result['source_hold']=dict(status='UNAVAILABLE_OR_UNSAFE')
        return result
    except BaseException:return dict(status='DIAGNOSTICS_UNAVAILABLE')


def stage_and_assemble(plan,context,secrets,private,public):
    value=plan.request['material_staging'];raw_g=value['grant_json'].encode()
    plan.public_phase='material_grant'
    plan.S.validate_grant(raw_g,value['grant_pin']['sha256'],plan.d,context,plan.policy)
    plan.public_phase='material_open'
    plan.material_session=plan.M.open_material_session(source_root=plan.root,delegation_raw=plan.request['delegation_json'].encode(),delegation_sha256=plan.request['delegation_pin']['sha256'],
        context=context,grant_raw=raw_g,grant_sha256=value['grant_pin']['sha256'],shared_timing=plan.timing,control_root=plan.control,runner_uid=os.getuid(),runner_gid=os.getgid())
    session=plan.material_session;need(callable(getattr(session,'stage',None))and callable(getattr(session,'close',None)),'held concrete input session stage/close API')
    plan.public_phase='material_stage'
    try:result=session.stage(secrets=secrets)
    finally:secrets.clear()
    need(type(result)is dict and set(result)=={'receipt','references','assembler_fields','staging_scope_retirement'},'exact actual staging/session result')
    plan.public_phase='material_retirement'
    retirement=result['staging_scope_retirement'];need(retirement['natural']is True and retirement['scope_absent']is True and retirement['scope']=='cachy-current-materials-'+plan.d['nonce']+'.scope','natural actual staging scope retired before input assembly')
    plan.public_phase='material_receipt'
    receipt=result['receipt'];need(receipt['status']=='COMPLETE517_HOSTED_CACHE_DATA_ONLY'and receipt['binding']==context['binding']and receipt['verified_files']==517 and all(receipt.get(k)==v for k,v in FINAL.items()),'same actual complete517 provisional result only')
    plan.public_phase='material_fields'
    B=program(plan.root,plan.d['programs']['base_inputs'],'current_hosted_staging_base_provider')
    fields=B.assembler_fields(result['references']);need(fields==result['assembler_fields'],'exact maintained complete517 assembler fields')
    total=sum(row['bytes']for name in('base_materials','supplemental_materials','keyring_materials')for row in fields[name].values())
    need(receipt['verified_bytes']==result['references']['verified_bytes']==total,'same actual whole517 byte count')
    raw=assembly_request(value['assembler_request'])
    plan.public_phase='assembly_selection'
    storage=Path(decode(raw_g)['storage_parent']);need(storage==storage.resolve()and storage.is_dir()and storage.stat().st_uid==os.getuid()and stat.S_IMODE(storage.stat().st_mode)==0o700,'same actual held caller-owned input domain')
    metadata=storage/('cachy-current-materials-'+plan.d['nonce'])/'Root-selected-public-metadata';metadata.mkdir(mode=0o700)
    request=assembly_selection(decode(raw),plan,fields,metadata);need(all(request[k]is None for k in BASE_FIELDS),'never replace Root-selected body refs');request.update(fields)
    output=storage/('cachy-current-materials-'+plan.d['nonce'])/'assembled'
    A=program(plan.root,plan.d['programs']['inputs_assembler'],'current_hosted_actual_input_assembler')
    plan.public_phase='assembly'
    envelope=A.assemble_inputs(delegation_raw=plan.request['delegation_json'].encode(),delegation_sha256=plan.request['delegation_pin']['sha256'],source_root=plan.root,
        request=request,output=output,context=context,context_program=plan.H)
    plan.public_phase='assembly_output'
    path=output/'inputs.json';raw_inputs=read(path,4*1024**2);need(decode(raw_inputs)==envelope,'actual committed assembler wrote the same canonical wrapper')
    actual=dict(plan.request,staged_root=str(storage),staged_inputs=dict(path=str(path),**pin(raw_inputs)))
    plan.public_phase='input_intake'
    plan.inputs,plan.intake=checked_inputs(actual,plan.d,plan.root,plan.H,min(time.monotonic()+180,plan.timing['deadline_monotonic']))
    plan.public_phase='staging_retention'
    remaining(plan.timing);write(private/'inputs.json',encoded(plan.inputs))
    write(public/'material-staging.json',encoded(dict(receipt=receipt,staging_scope_retirement=retirement,wrapper_pin=pin(raw_inputs),intake=plan.intake,**FINAL)))
    return result


def preflight(r,source_root,main_root,control_root,environ,now):
    root,main,control=map(Path,(source_root,main_root,control_root))
    need(str(root)==environ.get('GITHUB_WORKSPACE')and root.is_absolute()and root==root.resolve(),'Source is actual GITHUB_WORKSPACE root')
    need(main.is_absolute()and main==main.resolve()and not main.is_relative_to(root),'separate actual trusted Main checkout')
    own=read(Path(__file__).resolve(),128*1024);need(pin(own)==descriptor(r['launcher'])and read(main/r['launcher']['member'],128*1024)==own,'executing whole-pinned Main launcher')
    raw_d=r['delegation_json'].encode();preview=decode(raw_d);need(pin(raw_d)==r['delegation_pin'],'Root delegation before selected import')
    H=program(root,preview['programs']['context'],'current_hosted_delegated_context')
    d=H.validate_delegation(raw_d,r['delegation_pin']['sha256'],now);H.source(d,root)
    expected=dict(GITHUB_SHA=d['binding']['source'],GITHUB_REF=d['binding']['ref'],GITHUB_RUN_ATTEMPT='1',GITHUB_REPOSITORY=d['hosted']['repository'],GITHUB_JOB=d['hosted']['job_key'],GITHUB_WORKFLOW_REF=d['hosted']['workflow_ref'],GITHUB_WORKFLOW_SHA=d['hosted']['workflow_sha'],RUNNER_ARCH='ARM64',RUNNER_OS='Linux',RUNNER_ENVIRONMENT='github-hosted',GITHUB_ACTIONS='true')
    need(all(environ.get(k)==v for k,v in expected.items()),'actual hosted Source/ref/workflow/stage selectors before GET or privilege')
    need(d['programs'].get('hosted_launcher')==r['launcher'],'launcher is a reviewed closed Source member')
    need(r['control_name']=='cachy-current-hosted-'+d['nonce']and control==Path(environ['RUNNER_TEMP'])/r['control_name']
         and not control.exists()and control.parent.is_dir()and control.parent.stat().st_uid==os.getuid()
         and not control.is_relative_to(root)and not root.is_relative_to(control),'fresh exact RunnerTemp control domain')
    need(os.getuid()==os.geteuid()>0 and os.uname().sysname=='Linux'and os.uname().machine=='aarch64','ordinary actual native hosted launcher before privilege')
    E=program(root,d['programs']['image_executor'],'current_hosted_owned_executor')
    policy=decode(read(root/d['policy']['member']));p=E.validate_policy(policy,d)
    Q=prerequisite_program(root,d,policy)
    if Q:need(environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch','actual explicit manual prerequisite event before privilege')
    S,M=material_programs(r,d,root,policy)
    if not S:
        observations=E.probe_tools()
        need(set(observations['missing_or_invalid'])<={'bsdtar'} if Q else not observations['missing_or_invalid'],'required fixed host tools missing before privilege')
    for tool in ('/usr/bin/git','/usr/bin/sudo'):fixed_tool(tool)
    need(E.API=='CURRENT_ONBOARDING_IMAGE_EXECUTOR_V3'and p['controller']==SCOPE
         and p['controller_AS_bytes']==512*1024**2 and p['controller_seconds']==7560,'Root selected exact777 controller policy; no implicit cap change')
    if not Q:need(d['expires_epoch']-now>=p['controller_seconds']+LIMITS['preflight_seconds'],'delegation lifetime covers actual finite launch/cleanup')
    else:need(d['expires_epoch']-now>=495+p['setup_seconds']+p['cleanup_seconds']+16,'reviewed prerequisite/setup/cleanup fit actual unexpired shared budget')
    need(pin(read(root/d['programs']['owned_process']['member'],128*1024))['sha256']==OWNED_SHA,'held supervision program')
    owner=read(root/d['programs']['owner']['member'],128*1024);tree=ast.parse(owner)
    functions={n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
    callback=functions.get('run_owned_current_v3')
    api=[n.value.value for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='API'for t in n.targets)and isinstance(n.value,ast.Constant)]
    need(api==['CURRENT_ONBOARDING_DELEGATED_OWNER_V3']and callback is not None and not callback.args.args and not callback.args.posonlyargs and callback.args.vararg is None and callback.args.kwarg is None and {a.arg for a in callback.args.kwonlyargs}=={'delegation_raw','delegation_sha256','context','source_root','inputs','executor','output','public_output'},'exact committed current owner callback before privilege')
    deadline=time.monotonic()+LIMITS['preflight_seconds'];inputs,intake=(None,dict(status='DEFERRED_UNTIL_ACTUAL_COMPLETE517'))if S else checked_inputs(r,d,root,H,deadline)
    O=program(root,d['programs']['owned_process'],'current_hosted_held_process')
    return SimpleNamespace(request=r,d=d,H=H,E=E,O=O,policy=policy,inputs=inputs,intake=intake,root=root,main=main,control=control,Q=Q,S=S,M=M,material_session=None)


def fixed_tool(name):
    need(name in('/usr/bin/git','/usr/bin/sudo'),'fixed launcher tool only')
    path=Path(name)
    need(all(not p.is_symlink() and p.stat().st_uid==0 and not p.stat().st_mode&0o022 for p in(path,*path.parents)),'root-owned fixed non-writable tool ancestry')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and 0<before.st_size<=64*1024**2 and before.st_mode&0o111,'ordinary finite executable')
        digest=hashlib.sha256()
        with os.fdopen(os.dup(fd),'rb')as f:
            while raw:=f.read(1024**2):digest.update(raw)
        after=os.fstat(fd);need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'same whole launcher tool')
        return dict(path=name,bytes=before.st_size,sha256=digest.hexdigest())
    finally:os.close(fd)


def scope_argv(plan,request_path,request_sha,context_path,context_sha,inputs_path,inputs_sha):
    nonce=plan.d['nonce'];scope='cachy-current-controller-'+nonce+'.scope'
    tools=getattr(plan,'scope_tools',{'systemd-run':'/usr/bin/systemd-run','python3':'/usr/bin/python3'})
    return ['/usr/bin/sudo','-n',tools['systemd-run'],'--scope','--quiet','--unit='+scope,
        '--property=MemoryMax=536870912','--property=MemorySwapMax=0','--property=CPUQuota=100%',
        '--property=CPUQuotaPeriodSec=100ms','--property=TasksMax=64','--property=RuntimeMaxSec='+str(controller_seconds(plan))+'s',
        '--property=TimeoutStopSec=10s','--property=KillMode=control-group','--property=OOMPolicy=kill',
        '--',tools['python3'],'-I','-B',str(Path(__file__).resolve()),'controller',
        '--request',str(request_path),'--request-sha256',request_sha,'--source-root',str(plan.root),
        '--context',str(context_path),'--context-sha256',context_sha,'--inputs',str(inputs_path),'--inputs-sha256',inputs_sha,
        '--uid',str(os.getuid()),'--gid',str(os.getgid())]+timing_args(plan)


def run(O,argv,cap,work):
    need(type(cap)in(int,float)and 1<cap<=7590,'finite child launch/retirement cap before spawn')
    need(type(argv)is list and argv and all(type(a)is str and '\0'not in a and len(a)<=8192 for a in argv),'direct bounded argv')
    # A sealed-size stderr memfd does not impose an FSIZE limit on image/storage children.
    fd=os.memfd_create('current-hosted-stderr',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING);os.ftruncate(fd,1024**2)
    fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK)
    with os.fdopen(fd,'r+b',buffering=0)as errors:
        O.prepare();child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=errors,
            cwd=work,env=dict(PATH='/usr/bin:/usr/sbin:/bin',HOME=str(work),TMPDIR=str(work),LC_ALL='C'),start_new_session=True)
        result=O.supervise(child,cap=cap,streams=[child.stdout],max_output=2*1024**2)
        size=errors.tell();need(size<1024**2,'bounded stderr');errors.seek(0);stderr=errors.read(size)
    need(result['reaped']is True and result['ownership']=='REAPED'and result['group_census']=='EMPTY_TWICE'
         and result['output_complete']is True and result['signals']==[]and result['timeout']is False
         and result['error']is None and result['exit']==0,'natural complete owned child and group absence')
    return result['output'],dict(exit=result['exit'],reaped=True,group_census='EMPTY_TWICE',stdout_pin=pin(result['output']),stderr_pin=pin(stderr),natural=True)


def metadata_url(d,run_id):
    need(re.fullmatch('[1-9][0-9]{0,19}',run_id or ''),'actual numeric run ID')
    return 'https://api.github.com/repos/'+d['hosted']['repository']+'/actions/runs/'+run_id+'/jobs?filter=latest&per_page=100'


def fetch_jobs(url,seconds,maximum):
    need(re.fullmatch(r'https://api\.github\.com/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/[1-9][0-9]{0,19}/jobs\?filter=latest&per_page=100',url)
         and type(seconds)is int and 0<seconds<=30 and type(maximum)is int and 0<maximum<=1024**2,'one fixed bounded public metadata GET')
    connection=http.client.HTTPSConnection('api.github.com',timeout=seconds,context=ssl.create_default_context())
    try:
        connection.request('GET',url.removeprefix('https://api.github.com'),headers={'Accept':'application/vnd.github+json','Accept-Encoding':'identity','User-Agent':'cachy-asahi-current-onboarding-v3'})
        response=connection.getresponse();need(response.status==200,'no metadata redirects/retries/non200')
        raw=response.read(maximum+1);need(0<len(raw)<=maximum,'bounded whole jobs metadata');return raw
    finally:connection.close()


def write(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb')as f:f.write(raw)


def _execute(args,environ=None):
    env=os.environ if environ is None else environ;secrets={}
    try:
        r=request(args.request,args.request_sha256)
        for name in MATERIAL_SECRET_NAMES:
            if material_selected(r):secrets[name]=env.pop(name,None)
            else:env.pop(name,None)
        return _execute_bound(args,env,r,secrets)
    finally:
        for name in MATERIAL_SECRET_NAMES:env.pop(name,None)
        secrets.clear()


def _execute_bound(args,env,r,secrets):
    started=time.monotonic()
    plan=preflight(r,args.source_root,args.main_root,args.control_root,env,int(time.time()))
    available=os.statvfs(plan.control.parent);need(available.f_bavail*available.f_frsize>=LIMITS['control_bytes']+64*1024**2 and available.f_favail>=LIMITS['control_nodes']+128,'finite fresh control disk/inode reserve')
    plan.control.mkdir(mode=0o700);private=plan.control/'private';public=plan.control/'public';private.mkdir(mode=0o700);public.mkdir(mode=0o700)
    report=dict(status='HOLD',request_pin=pin(read(args.request,LIMITS['request_bytes'])),intake=plan.intake,**FINAL)
    try:
        git=['/usr/bin/git','--no-replace-objects','-c','core.hooksPath=/dev/null','-c','maintenance.auto=false','-c','gc.auto=0']
        for name,root,expected in [('Main',plan.main,r['trusted_main_commit']),('Source',plan.root,plan.d['binding']['source'])]:
            plan.public_phase='git_main'if name=='Main'else'git_source'
            output,_=run(plan.O,[*git,'-C',str(root),'rev-parse','--verify','HEAD'],15,private);need(output.decode().strip()==expected,'actual '+name+' Git commit')
        plan.public_phase='metadata'
        seconds=plan.d['context_limits']['metadata_query_seconds'];maximum=plan.d['context_limits']['metadata_max_bytes'];url=metadata_url(plan.d,env.get('GITHUB_RUN_ID'))
        before=time.monotonic();body,receipt=run(plan.O,['/usr/bin/python3','-I','-B',str(Path(__file__).resolve()),'metadata','--url',url,'--seconds',str(seconds),'--maximum',str(maximum)],seconds,private)
        response=dict(url=url,status=200,body=body,received_epoch=int(time.time()),elapsed_ms=int((time.monotonic()-before)*1000))
        plan.public_phase='context'
        context=plan.H.capture_context(r['delegation_json'].encode(),r['delegation_pin']['sha256'],plan.root,environ={k:env.get(k)for k in plan.H.ENV},jobs_response=response)
        raw_c=encoded(context);raw_i=encoded(plan.inputs)if plan.inputs is not None else None;raw_r=read(args.request,LIMITS['request_bytes'])
        for name,raw in [('context.json',raw_c),('inputs.json',raw_i),('request.json',raw_r)]:
            if raw is not None:write(private/name,raw)
        write(public/'context.json',raw_c);report.update(binding=context['binding'],metadata=receipt)
        need(time.monotonic()-started<LIMITS['preflight_seconds'],'complete preprivilege wall budget')
        if plan.Q:
            plan.public_phase='timing'
            plan.timing=make_timing(plan,context,started)
            plan.timing_path=private/'timing.json';raw_t=encoded(plan.timing);plan.timing_sha=pin(raw_t)['sha256']
            write(plan.timing_path,raw_t);write(public/'timing.json',raw_t)
            if getattr(plan,'S',None):
                signal.setitimer(signal.ITIMER_REAL,remaining(plan.timing));resource.setrlimit(resource.RLIMIT_CPU,(LIMITS['cpu_seconds'],)*2)
                stage_and_assemble(plan,context,secrets,private,public);raw_i=encoded(plan.inputs);report['intake']=plan.intake
                plan.public_phase='post_staging_tools'
                observations=plan.E.probe_tools();need(set(observations['missing_or_invalid'])<={'bsdtar'},'actual fresh tools after held staging; only explicit prerequisite missing')
            plan.public_phase='prerequisites'
            environment={key:env.get(key) for key in PREREQUISITE_ENV};raw_e=encoded(environment)
            environment_path=private/'prerequisite-environment.json';write(environment_path,raw_e)
            need(not Path('/sys/fs/cgroup/system.slice/cachy-current-prerequisites-'+plan.d['nonce']+'.scope').exists(),'fresh prerequisite scope')
            fixed_tool('/usr/bin/sudo');prerequisite_scope_tools(plan);signal.setitimer(signal.ITIMER_REAL,remaining(plan.timing))
            resource.setrlimit(resource.RLIMIT_CPU,(LIMITS['cpu_seconds'],)*2)
            argv=prerequisite_argv(plan,private/'request.json',args.request_sha256,private/'context.json',pin(raw_c)['sha256'],environment_path,pin(raw_e)['sha256'])
            _,retirement=run(plan.O,argv,min(510,remaining(plan.timing)),private)
            report['prerequisite_retirement']=retirement
            report['prerequisite_scope_absence']=prerequisite_absent(plan.d['nonce'],plan.timing['deadline_monotonic'])
            tools=plan.E.probe_tools();need(not tools['missing_or_invalid'] and len(plan.E.NAMES)==16 and len(set(plan.E.NAMES))==16 and set(tools['tools'])==set(plan.E.NAMES),'fresh complete16 tools only after prerequisite retirement')
            prerequisite_scope_tools(plan)
            report['tools_after_prerequisites']=tools
            plan.public_phase='context_refresh'
            seconds=plan.d['context_limits']['metadata_query_seconds'];before=time.monotonic()
            body,receipt=run(plan.O,['/usr/bin/python3','-I','-B',str(Path(__file__).resolve()),'metadata','--url',url,'--seconds',str(seconds),'--maximum',str(maximum)],min(seconds,remaining(plan.timing)),private)
            response=dict(url=url,status=200,body=body,received_epoch=int(time.time()),elapsed_ms=int((time.monotonic()-before)*1000))
            refreshed=plan.H.capture_context(r['delegation_json'].encode(),r['delegation_pin']['sha256'],plan.root,environ={k:env.get(k) for k in plan.H.ENV},jobs_response=response)
            need(refreshed['binding']==context['binding'],'same actual context after prerequisite')
            context=refreshed;raw_c=encoded(context)
            write(private/'context-after-prerequisites.json',raw_c);write(public/'context-after-prerequisites.json',raw_c)
            report['metadata_after_prerequisites']=receipt
            report['shared_timing']=dict(whole_budget_seconds=7560,elapsed_seconds=time.monotonic()-started,
                controller_runtime_ceiling_seconds=controller_seconds(plan),available_stage_ceiling_seconds=available_stage_seconds(plan))
        plan.public_phase='controller'
        need(not Path('/sys/fs/cgroup/system.slice/cachy-current-controller-'+plan.d['nonce']+'.scope').exists(),'fresh unadopted controller cgroup')
        fixed_tool('/usr/bin/sudo');prerequisite_scope_tools(plan);signal.setitimer(signal.ITIMER_REAL,remaining(plan.timing) if plan.Q else 0)
        resource.setrlimit(resource.RLIMIT_CPU,(LIMITS['cpu_seconds'],)*2)
        context_path=private/('context-after-prerequisites.json' if plan.Q else 'context.json')
        argv=scope_argv(plan,private/'request.json',args.request_sha256,context_path,pin(raw_c)['sha256'],private/'inputs.json',pin(raw_i)['sha256'])
        _,retirement=run(plan.O,argv,min(7590,remaining(plan.timing) if plan.Q else started+LIMITS['launcher_seconds']-time.monotonic()),private);report['controller_retirement']=retirement
        report['scope_absence']=scope_absent(plan.d['nonce'])
        if plan.Q:remaining(plan.timing)
        plan.public_phase='controller_result'
        path=Path('/var/lib/cachy-current-'+plan.d['nonce'])/'executor-report.json';result=decode(read(path))
        need(result['binding']==context['binding']and result['status']=='DELEGATED_OWNED_STAGE_RETIRED_DATA_ONLY'
             and result['cleanup']['owned_storage_absent']is True and not result['cleanup']['errors']
             and all(result.get(k)==v for k,v in FINAL.items()),'same actual retired controller outcome; no inferred acceptance')
        report.update(status='DELEGATED_HOSTED_CONTROLLER_RETIRED_DATA_ONLY',cleanup=dict(owned_storage_absent=True,error_count=0));plan.public_phase='complete'
    except BaseException as error:report['failure'],report['failure_type']=failure_summary(plan,error)
    finally:
        if getattr(plan,'material_session',None)is not None:
            if report['status']=='HOLD':report['material_failure_before_cleanup']=material_failure_data(plan,hold=True)
            try:
                closed=plan.material_session.close()
                need(closed['closed']is True and closed['scope_absent']is True and closed['input_storage_absent']is True and all(closed.get(k)==v for k,v in FINAL.items()),'actual final input-domain retirement and storage absence')
                report['material_domain_cleanup']={k:closed[k]for k in('closed','scope_absent','input_storage_absent',*FINAL)}
            except BaseException as error:
                diagnostic,kind=failure_summary(SimpleNamespace(public_phase='material_cleanup'),error)
                report.update(status='HOLD',material_cleanup_failure=kind,material_cleanup_diagnostic=diagnostic)
                if 'failure'not in report:report.update(failure=diagnostic,failure_type=kind)
            if report['status']=='HOLD':report['material_children_after_cleanup']=material_failure_data(plan)
        paths=list(plan.control.rglob('*'));need(len(paths)<=LIMITS['control_nodes']and not any(p.is_symlink()for p in paths)and sum(p.stat().st_size for p in paths if p.is_file())<=LIMITS['control_bytes'],'finite ordinary control storage')
        write(public/'launcher-report.json',encoded(report))
    return 0 if report['status']=='DELEGATED_HOSTED_CONTROLLER_RETIRED_DATA_ONLY'else 2


def execute(args,environ=None):
    resource.setrlimit(resource.RLIMIT_AS,(LIMITS['address_space_bytes'],)*2)
    resource.setrlimit(resource.RLIMIT_CPU,(LIMITS['preflight_cpu_seconds'],LIMITS['cpu_seconds']))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    def expired(sig,frame):raise TimeoutError('whole preprivilege wall bound')
    previous=signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,LIMITS['preflight_seconds'])
    try:return _execute(args,environ)
    finally:signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)


def scope_absent(nonce):
    need(re.fullmatch('[0-9a-f]{64}',nonce or ''),'exact owned scope nonce')
    path=Path('/sys/fs/cgroup/system.slice/cachy-current-controller-'+nonce+'.scope')
    for _ in range(2):
        if path.exists():
            raw=(path/'cgroup.events').read_text();need(len(raw)<=1024 and 'populated 0'in raw.splitlines(),'actual scope empty after natural controller retirement')
        time.sleep(.05)
    return dict(scope=path.name,empty_twice=True)


def controller_observation(domain,properties,nonce,binding,policy_pin):
    expected='/system.slice/cachy-current-controller-'+nonce+'.scope'
    need(domain['cgroup']==expected and domain['limits']==SCOPE and type(domain['pid'])is int and domain['pid']>0 and type(domain['starttime'])is int and domain['starttime']>0,'actual same finite controller domain')
    need(properties['ControlGroup']==expected and properties['ActiveEnterTimestampMonotonic'].isdecimal()and int(properties['ActiveEnterTimestampMonotonic'])>0,'actual controller scope and activation clock')
    return dict(kind='CURRENT_HOSTED_CONTROLLER_OBSERVATION_V3',binding=binding,policy_pin=policy_pin,
                domain=domain,properties=properties,**FINAL)


def clipped_controller_observation(E,domain,properties,d,context,timing,reserve_seconds=0):
    need(type(reserve_seconds)is int and 0<=reserve_seconds<=180,'finite explicit input cleanup reserve')
    observation=controller_observation(domain,properties,d['nonce'],context['binding'],context['policy_pin'])
    runtime=E.runtime_microseconds(properties['RuntimeMaxUSec'])
    need(0<runtime<=7560*1000000 and int(properties['ActiveEnterTimestampMonotonic'])/1000000+runtime/1000000<=timing['deadline_monotonic']-reserve_seconds,'physical controller scope cannot extend shared deadline or input cleanup reservation')
    remaining(timing);return observation


def controller(args):
    need(os.getuid()==os.geteuid()==0,'root-only finite scope wrapper')
    r=request(args.request,args.request_sha256);need(pin(read(Path(__file__).resolve(),128*1024))==descriptor(r['launcher']),'whole Main controller wrapper');root=Path(args.source_root);preview=decode(r['delegation_json'])
    H=program(root,preview['programs']['context'],'current_controller_context');d=H.validate_delegation(r['delegation_json'].encode(),r['delegation_pin']['sha256']);H.source(d,root)
    for path,expected in [(args.context,args.context_sha256),(args.inputs,args.inputs_sha256)]:need(pin(read(path))['sha256']==expected,'whole actual poststart controller operand')
    E=program(root,d['programs']['image_executor'],'current_controller_executor')
    if prerequisite_selected(d):
        context=decode(read(args.context));timing=read_timing(args,r,d,context)
        need(remaining(timing)>15,'shared actual deadline before main controller')
        domain=E.kernel_domain(os.getpid());expected='/system.slice/cachy-current-controller-'+d['nonce']+'.scope'
        need(domain['cgroup']==expected and domain['limits']==SCOPE,'actual clipped controller kernel domain before any command')
        tools=E.probe_tools();need(not tools['missing_or_invalid'],'complete actual tools after prerequisite and before executor')
        O=program(root,d['programs']['owned_process'],'current_clipped_controller_observer')
        raw,_=run(O,[E.checked_tool(tools['tools']['systemctl']['selected']),'show',expected.rsplit('/',1)[1],'--no-pager','--property=RuntimeMaxUSec,ActiveEnterTimestampMonotonic,ControlGroup'],min(15,remaining(timing)),Path(args.request).parent)
        properties=dict(line.split('=',1)for line in raw.decode().splitlines()if '='in line)
        reserve=0
        if material_selected(r):
            M=program(root,d['programs']['material_domain_executor'],'current_controller_held_input_executor')
            need(M.API=='CURRENT_ONBOARDING_MATERIAL_DOMAIN_V3'and type(M.CLOSE_SECONDS)is int and 0<M.CLOSE_SECONDS<=180,'same finite input close reservation')
            reserve=M.CLOSE_SECONDS
        clipped_controller_observation(E,domain,properties,d,context,timing,reserve)
    else:need(args.timing is None and args.timing_sha256 is None,'old path has no timing override')
    # Convert cancellation into the existing controller finally/owned cleanup path.
    def cancel(sig,frame):raise KeyboardInterrupt('current controller cancellation')
    signal.signal(signal.SIGTERM,cancel);signal.signal(signal.SIGINT,cancel)
    delegation=Path(args.request).parent/'delegation.json';write(delegation,r['delegation_json'].encode())
    status=E.controller_main(SimpleNamespace(source_root=root,delegation=delegation,delegation_sha256=r['delegation_pin']['sha256'],context=args.context,inputs=args.inputs,
        output=Path('/var/lib/cachy-current-'+d['nonce']),uid=args.uid,gid=args.gid))
    if status==0:
        context=decode(read(args.context));O=program(root,d['programs']['owned_process'],'current_controller_observation_owner')
        tools=E.probe_tools();need(not tools['missing_or_invalid'],'unchanged actual controller observer tools')
        unit='cachy-current-controller-'+d['nonce']+'.scope'
        raw,_=run(O,[E.checked_tool(tools['tools']['systemctl']['selected']),'show',unit,'--no-pager','--property=RuntimeMaxUSec,ActiveEnterTimestampMonotonic,ControlGroup'],15,Path(args.request).parent)
        properties=dict(line.split('=',1)for line in raw.decode().splitlines()if '='in line)
        need(0<E.runtime_microseconds(properties['RuntimeMaxUSec'])<=7560*1000000,'observed exact finite scope runtime')
        observation=controller_observation(E.kernel_domain(os.getpid()),properties,d['nonce'],context['binding'],context['policy_pin'])
        control=Path(args.request).parent.parent;public=control/'public'
        need(control.name==r['control_name']and control.stat().st_uid==args.uid and stat.S_IMODE(control.stat().st_mode)==0o700 and public.stat().st_uid==args.uid and not public.is_symlink(),'same fresh owned public control domain')
        target=public/'controller-observation.json';write(target,encoded(observation));os.chown(target,args.uid,args.gid)
    return status


def main():
    need(sys.flags.isolated and sys.dont_write_bytecode and __debug__,'isolated unoptimized launcher')
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='mode',required=True)
    launch=sub.add_parser('launch');control=sub.add_parser('controller');prerequisite=sub.add_parser('prerequisite');metadata=sub.add_parser('metadata')
    for parser in (launch,control,prerequisite):
        for key in ('request','source-root'):parser.add_argument('--'+key,type=Path,required=True)
        parser.add_argument('--request-sha256',required=True)
    for key in ('main-root','control-root'):launch.add_argument('--'+key,type=Path,required=True)
    for parser in (control,prerequisite):
        parser.add_argument('--context',type=Path,required=True);parser.add_argument('--context-sha256',required=True)
        parser.add_argument('--timing',type=Path);parser.add_argument('--timing-sha256')
        for key in ('uid','gid'):parser.add_argument('--'+key,type=int,required=True)
    control.add_argument('--inputs',type=Path,required=True);control.add_argument('--inputs-sha256',required=True)
    prerequisite.add_argument('--environment',type=Path,required=True);prerequisite.add_argument('--environment-sha256',required=True)
    metadata.add_argument('--url',required=True);metadata.add_argument('--seconds',type=int,required=True);metadata.add_argument('--maximum',type=int,required=True)
    a=p.parse_args();sys.addaudithook(validation_fence)
    if a.mode=='metadata':sys.stdout.buffer.write(fetch_jobs(a.url,a.seconds,a.maximum));return 0
    return execute(a) if a.mode=='launch' else prerequisite_controller(a) if a.mode=='prerequisite' else controller(a)


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:print('HOLD_HOSTED_CURRENT: '+type(error).__name__,file=sys.stderr);raise SystemExit(2)
