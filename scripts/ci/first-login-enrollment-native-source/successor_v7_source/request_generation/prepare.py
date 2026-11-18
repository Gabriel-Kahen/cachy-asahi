#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Local unissued ONCE templates; never issuance, dispatch or admission."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat

def load_source206():
    path = Path(__file__).resolve().with_name("source206.py")
    spec = importlib.util.spec_from_file_location("source206_roles", path)
    source = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(source)
    return source


S = load_source206()

FAMILY='scripts/ci/first-login-enrollment-native-source/'
PREFIX=FAMILY+'successor_v7_source/'
OPERAND=PREFIX+'payload/hosted.py'
LAUNCHER=FAMILY+'payload/native/hosted_current_v3.py'
READER=FAMILY+'payload/native/reader_current_v3.py'
SOURCE196='0a49872473251ad289fc8a49f51f3a27334c0b35'
SOURCE205=dict(files=205,bytes=45962607,tree='d7e48cbd6a3a638c5ecdabf8ca98a6a642dfde36',
    source_map=dict(bytes=40793,sha256='a6d22a528075c11f6fa2e87d894c41e0ed31befcd17f99a8b92d6c26fccdb815'))
PROGRAM=dict(path=PREFIX+'program.json',bytes=15135,sha256='623f667137fd38d9c319de729df910780fbf0fae7c0bc7e2aade27889c102dae')
CONSTRUCTOR='9e26ce819a258225cac866341e15d7099038ab9e'
PROFILE_PIN=dict(bytes=21451,sha256='99198c00308780aaf95e803c43d01ab185b55a049731287b7644c2425dd90a12')
LAUNCHER_PIN=dict(bytes=68455,sha256='d491626c309a4b0f1fc198fa1cc8515d2412326d0e4fb9947332590d9de0132e')
MAX_INPUT=131072
MAX_OUTPUT=131072
PROFILE_KEYS={'schema','kind','operation','files','bytes','prospective_tree','source_map','program','delegation_programs','staging_materials','materials','transport_commit','source196_basis','source188_basis','source179_basis','original139','actual'}
ACTUAL_KEYS={'source','ref','run','job','Root_delegation','Root_trust','Root_resources','Root_runtime','actual_images','publication','artifact','Reader','Root_acceptance'}
PROGRAM_ROLES=('base_inputs','build_validator','context','encoder','host_prerequisite_plan','host_prerequisite_runner_basis','host_prerequisite_tools','host_prerequisites','hosted_launcher','image','image_executor','inputs_assembler','local_callbacks','material_domain_executor','material_transport','materials_stager','owned_process','owner','private_seed','public_reader','retained_prefill','retained_prepare','retained_transport_core','retention','route')
STAGING_ROLES=('public14_profile','retained_carrier_profile','retained_prefill_profile','staging_base_lock','staging_bootstrap_profile')
BASES={
    'source196_basis':dict(files=196,bytes=45726789,tree='e85302474308dbf579b79bd6d501f5ad86b66bbb',source_map=dict(bytes=38809,sha256='a8f5ab1c1ceee9f3450634e14dd172d7421d6fe49d8e17ce680cb4cfe43da86a')),
    'source188_basis':dict(files=188,bytes=45544942,tree='50bf7aab34ee5497f12d078709354aa69b0cdb9d',source_map=dict(bytes=37091,sha256='ba06925244cd010ab2223325e2e324d4d3b469befbea5e7eb8e0de68383d4908')),
    'source179_basis':dict(files=179,bytes=45330627,tree='5128864b3c17f230d5045361014b41ce31b72767',source_map=dict(bytes=35107,sha256='063a34c64d9e9ad21e6c2bd5c4e0a147f88890061cd79fb13587bc1e37e9d7f4')),
    'original139':dict(files=139,bytes=43544563,tree='dcab30972b74d62df099d8ae12997dc0e557ff00',source_map=dict(bytes=26734,sha256='ec752108c451d056ebbe4caa97d629bad081c256d506a3d83722f47952a9005e'))}


def need(ok,why):
    if not ok:raise ValueError(why)


def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def decode(raw):
    def pairs(rows):
        result={}
        for key,value in rows:need(key not in result,'duplicate JSON key');result[key]=value
        return result
    value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
    need(raw==encoded(value),'canonical whole DATA');return value


def whole(value):
    need(type(value)is dict and set(value)=={'bytes','sha256'} and type(value['bytes'])is int
        and 0<value['bytes']<=2**31 and type(value['sha256'])is str and re.fullmatch('[0-9a-f]{64}',value['sha256']),'whole positive DATA pin')
    return value


def member(value):
    need(type(value)is str and 0<len(value)<=1024 and not value.startswith('/')
        and all(p not in ('','.','..')for p in value.split('/'))and not any(ord(c)<33 or ord(c)>126 or c=='\\'for c in value),'canonical relative member')
    return value


def descriptor(row):
    need(type(row)is dict and set(row)=={'member','bytes','sha256'},'closed member descriptor')
    member(row['member']);whole({k:row[k]for k in ('bytes','sha256')});return row


def checked(raw,digest):
    need(type(raw)is bytes and 0<len(raw)<=MAX_INPUT and type(digest)is str
        and re.fullmatch('[0-9a-f]{64}',digest) and pin(raw)['sha256']==digest,'external exact bounded DATA pin')
    return decode(raw)


def template(*, successor=False):
    return dict(schema=1,kind='UNISSUED_SOURCE206_ONCE_REQUEST_PLAN_V1' if successor else 'UNISSUED_SOURCE205_ONCE_REQUEST_PLAN_V1',status='UNISSUED',once=True,retry=False,
        issuer=None,approved=None,issued_epoch=None,expires_epoch=None,authority=None,resources=None,
        dispatch_ready=False,route_hold='CANONICAL_MAIN_V7_LAUNCHER_AND_WORKFLOW_ADOPTION_REQUIRED',
        source=None,main=None,publication=None,root_profile=None,request_templates=None,
        actual=dict(source_publication_authentication='UNVERIFIED_DATA_ONLY',main_selectors_authentication='UNVERIFIED_DATA_ONLY',run=None,job=None,
            Root_acceptance=None,native_acceptance=False,hardware_acceptance=False,release_acceptance=False))


def render(*,published_source_cid,source_ref,main_commit,profile_raw,profile_sha256,publication_raw,publication_sha256,main_raw,main_sha256,successor=False):
    source = S.SOURCE if successor else SOURCE205
    program = S.PROGRAM if successor else PROGRAM
    profile_pin = S.PROFILE if successor else PROFILE_PIN
    selected_reader = S.READER['member'] if successor else READER
    publication_kind = 'SOURCE206_PUBLICATION_READBACK_DATA_ONLY' if successor else 'SOURCE205_PUBLICATION_READBACK_DATA_ONLY'
    if successor:
        need((published_source_cid,source_ref)==(S.CID,S.REF),'exact published C908 Source206 selector')
    for value in (published_source_cid,main_commit):need(type(value)is str and re.fullmatch('[0-9a-f]{40}',value),'required explicit full Source and Main CID')
    need(published_source_cid not in (SOURCE196,CONSTRUCTOR,main_commit),'Source205 is distinct from Source196, constructor and Main')
    need(type(source_ref)is str and re.fullmatch('refs/heads/codex/[A-Za-z0-9._/-]+',source_ref)
        and all(p not in ('','.','..')and not p.startswith('.')and not p.endswith('.lock')for p in source_ref.split('/'))
        and not source_ref.endswith('.'),'required explicit Source branch selector')
    need(type(profile_raw)is bytes and pin(profile_raw)==profile_pin,'exact deterministic Source205 profile, not retargeted descriptors')
    profile=checked(profile_raw,profile_sha256)
    need(type(profile)is dict and set(profile)==PROFILE_KEYS and type(profile['schema'])is int and profile['schema']==7
        and profile['kind']=='UNISSUED_CURRENT_ONBOARDING_TRANSPORT_SOURCE_PROFILE_V7'
        and profile['operation']=='first-login-enrollment-ui-current-v2' and profile['transport_commit']==CONSTRUCTOR,
        'exact unissued schema7 Source205 constructor profile')
    need(type(profile['files'])is int and profile['files']==source['files'] and type(profile['bytes'])is int and profile['bytes']==source['bytes']
        and profile['prospective_tree']==source['tree'] and profile['source_map']==source['source_map'] and profile['program']==program,'fixed complete corrected Source205 tuple')
    need(type(profile['actual'])is dict and set(profile['actual'])==ACTUAL_KEYS and all(v is None for v in profile['actual'].values()),'profile carries no issued/actual authority')
    need(all(profile[key]==value for key,value in BASES.items()),'retained historical bases are DATA, never selectors')
    for key,count in (('delegation_programs',25),('materials',59),('staging_materials',5)):
        rows=profile[key];need(type(rows)is dict and len(rows)==count,'fixed Source205 descriptor count')
        for role,row in rows.items():need(type(role)is str and re.fullmatch('[A-Za-z0-9_]+',role),'finite descriptor role');descriptor(row)
    need(not set(profile['materials'])&set(profile['staging_materials']),'original59 and staging5 remain distinct')
    need(set(profile['delegation_programs'])==set(PROGRAM_ROLES)and set(profile['staging_materials'])==set(STAGING_ROLES),'fixed Source205 role rosters')
    need(profile['delegation_programs'].get('hosted_launcher')==dict(member=LAUNCHER,**LAUNCHER_PIN),'v7 Source launcher whole body')
    publication=checked(publication_raw,publication_sha256)
    need(type(publication)is dict and set(publication)=={'schema','kind','status','source','ref','tree','files','bytes','source_map','profile'}
        and type(publication['schema'])is int and publication['schema']==1
        and publication['kind']==publication_kind
        and publication['status']=='PASS_COMPLETE_PUBLIC_GIT_READBACK_DATA_ONLY','closed publication-readback DATA projection')
    need(publication['source']==published_source_cid and publication['ref']==source_ref
        and all(publication[k]==source[k]for k in ('tree','files','bytes','source_map'))
        and type(publication['files'])is int and type(publication['bytes'])is int
        and publication['profile']==pin(profile_raw),'explicit publication/profile joins; not authentication')
    selected=checked(main_raw,main_sha256)
    need(type(selected)is dict and set(selected)=={'schema','kind','commit','launcher','provenance_operand','reader','workflow'}
        and type(selected['schema'])is int and selected['schema']==1 and selected['kind']=='EXPLICIT_MAIN_REQUEST_SELECTORS_DATA_ONLY'
        and selected['commit']==main_commit,'explicit selected Main DATA')
    for key in ('launcher','provenance_operand','reader','workflow'):descriptor(selected[key])
    need(selected['launcher']==dict(member=LAUNCHER,**LAUNCHER_PIN)
        and selected['provenance_operand']==dict(member=OPERAND,**LAUNCHER_PIN)
        and selected['reader']['member']==selected_reader,'future canonical Main v7 body plus separate operand; no v6/new-path fallback')
    if successor:
        need(selected['reader']==S.READER,'exact Source206 Main Reader whole body')
    workflow=selected['workflow']['member'];need(workflow.startswith('.github/workflows/')and workflow.endswith('.yml'),'explicit Main workflow whole selector')
    need(selected['reader']['bytes']<=1024**2 and selected['workflow']['bytes']<=MAX_INPUT,'finite Main Reader and workflow')
    binding=dict(source=published_source_cid,ref=source_ref,source_lock=source['source_map'],run=None,job=None,attempt=1)
    delegation=dict(schema=4,kind='ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V4',issuer=None,approved=None,
        scope='CURRENT_PRIVATE_STAGE_ONLY',binding=binding,stage=None,nonce=None,issued_epoch=None,expires_epoch=None,
        programs=profile['delegation_programs'],materials=dict(profile['materials'],**profile['staging_materials']),policy=None,
        capability=None,context_limits=None,hosted=None,image_ids=dict(backend=None,ui=None,lifecycle=None),
        Root_final_acceptance=None,independent_component_acceptance=False,hardware_acceptance=False,release_acceptance=False)
    launch=dict(schema=3,kind='ROOT_AUTHORIZED_CURRENT_HOSTED_LAUNCH_V3',issuer=None,approved=None,
        trusted_main_commit=main_commit,launcher=dict(member=LAUNCHER,**LAUNCHER_PIN),delegation_json=None,
        delegation_pin=None,staged_inputs=None,staged_root=None,control_name=None,authorization=None,material_staging=None)
    grant=dict(schema=3,kind='ROOT_CURRENT_COMPLETE517_STAGING_V3',issuer=None,approved=None,
        source=published_source_cid,ref=source_ref,source_lock=source['source_map'],nonce=None,policy=None,
        issued_epoch=None,expires_epoch=None,redirect_urls=None,secret_provider='CALLER_ONE_SHOT_EXACT22',scope='COMPLETE517_PUBLIC_DATA_ONLY',storage_parent=None)
    result=template(successor=successor);result.update(source=dict(cid=published_source_cid,ref=source_ref,**source,program=program),
        main=selected,publication=dict(receipt_pin=pin(publication_raw),authenticity='UNVERIFIED_DATA_ONLY'),root_profile=pin(profile_raw),
        request_templates=dict(launch=launch,delegation=delegation,material_grant=grant))
    need(len(encoded(result))<=MAX_OUTPUT,'bounded unissued output');return copy.deepcopy(result)


def unissued(plan,*,successor=False):
    base=template(successor=successor);need(type(plan)is dict and set(plan)==set(base),'closed unissued output schema')
    for key in ('schema','kind','status','once','retry','issuer','approved','issued_epoch','expires_epoch','authority','resources','dispatch_ready','route_hold','actual'):
        need(encoded(plan[key])==encoded(base[key]),'unissued authority/route fields cannot change')
    def walk(value):
        if type(value)is dict:
            for key,item in value.items():
                if key in ('issuer','approved','nonce','issued_epoch','expires_epoch','authorization','Root_acceptance','Root_final_acceptance'):
                    need(item is None,'no issuance, nonce, clock or authorization')
                if key in ('independent_component_acceptance','hardware_acceptance','release_acceptance','native_acceptance'):
                    need(item is False,'no acceptance claim')
                walk(item)
        elif type(value)is list:
            for item in value:walk(item)
    walk(plan)


def identity(info):return tuple(getattr(info,k)for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))


def read(path):
    path=Path(path);need(path.is_absolute()and path==path.resolve()and not any(p.is_symlink()for p in (path,*path.parents)),'explicit canonical input path')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=MAX_INPUT,'ordinary bounded input')
        with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(MAX_INPUT+1)
        need(len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'stable whole input');return raw
    finally:os.close(fd)


def publish(plan,output):
    unissued(plan)
    output=Path(output);need(output.is_absolute()and output.parent==output.parent.resolve()
        and not any(p.is_symlink()for p in (output.parent,*output.parent.parents)),'fresh canonical output parent')
    parent=output.parent.stat();need(stat.S_ISDIR(parent.st_mode)and parent.st_uid==os.getuid()and not parent.st_mode&0o022,'owned output parent')
    raw=encoded(plan);need(len(raw)<=MAX_OUTPUT,'finite output')
    output.mkdir(mode=0o700)
    fd=os.open(output/'ONCE.UNISSUED.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb')as stream:stream.write(raw)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ('published-source-cid','source-ref','main-commit'):parser.add_argument('--'+key,required=True)
    for key in ('root-profile','publication-readback','main-selectors'):
        parser.add_argument('--'+key,type=Path,required=True);parser.add_argument('--'+key+'-sha256',required=True)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    plan=render(published_source_cid=args.published_source_cid,source_ref=args.source_ref,main_commit=args.main_commit,
        profile_raw=read(args.root_profile),profile_sha256=args.root_profile_sha256,publication_raw=read(args.publication_readback),
        publication_sha256=args.publication_readback_sha256,main_raw=read(args.main_selectors),main_sha256=args.main_selectors_sha256)
    publish(plan,args.output)


if __name__=='__main__':main()
