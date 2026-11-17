# SPDX-License-Identifier: MIT
"""Pure caller DATA compatibility; never Root issuance or actor authorization."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

HERE=Path(__file__).resolve().parent
STATIC_PIN=dict(bytes=6968,sha256='3bcf327bd73c78007e587cbd0aca30a04fafcc414655b3ea913a1b21ab5acbd9')


def need(ok,why):
    if not ok:raise ValueError(why)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encode(value):return(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()


def decode(raw):
    def pairs(rows):
        result={}
        for key,value in rows:
            need(key not in result,'duplicate JSON key');result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _ : (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def expected():
    path=HERE/'STATIC.json';before=path.lstat()
    need(STATIC_PIN is not None and stat.S_ISREG(before.st_mode)and before.st_nlink==1 and
         not before.st_mode&0o022 and 0<before.st_size<=65536 and not path.is_symlink(),
         'whole bound ordinary caller static operand required')
    identity=lambda s:tuple(getattr(s,k)for k in ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        need(identity(before)==identity(os.fstat(fd)),'same caller static descriptor')
        with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(65537)
        need(len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()) and
             pin(raw)==STATIC_PIN,'exact stable whole caller static pin')
    finally:os.close(fd)
    value=decode(raw);need(type(value)is dict,'caller static object');return value


def validate_plan(plan):
    fixed=expected();need(type(plan)is dict and plan.get('kind')=='FISH62_CANONICAL_PREPARATION_V1','caller preparation kind')
    for key in ('source','workflow','normal_pair','ref_pattern'):
        need(key in plan and encode(plan[key])==encode(fixed[key]),'exact caller '+key+' contract')
    for key,fields in (('publication',fixed['publication_fields']),('root_bindings',fixed['root_binding_fields'])):
        value=plan.get(key)
        need(type(value)is dict and set(value)==set(fields)and len(fields)==len(set(fields))and fields and
             all(item is None for item in value.values()),'all required '+key+' fields remain unissued NULL')
    need(all(key in plan and plan[key]is None for key in ('Root_authority','Root_acceptance')),
         'preparation has no Root authority or acceptance')
    return fixed


def validate_caller_data(plan,publication,admission_raw,runtime_raw,env,now):
    """Check in-memory operands only; physical/canonical Root gates stay pending."""
    fixed=validate_plan(plan);source=fixed['source'];workflow=fixed['workflow']
    need(type(publication)is dict and set(publication)=={
        'kind','source','ref','tree','source_map','owner_program','policy','workflow'} and
        publication.get('kind')=='FISH62_PUBLICATION_DATA_BINDING_V1','separate exact publication DATA binding')
    cid,ref=publication.get('source'),publication.get('ref')
    need(type(cid)is str and re.fullmatch('[0-9a-f]{40}',cid)is not None and
         type(ref)is str and re.fullmatch(fixed['ref_pattern'],ref)is not None,
         'issued Source CID and preserved host-context ref namespace required')
    for key in ('tree','source_map','owner_program','policy'):
        need(encode(publication[key])==encode(source[key]),'exact published caller '+key+' join')
    registered=publication['workflow']
    need(type(registered)is dict and set(registered)=={'path','pin','id'}and
         registered['path']==workflow['path']and registered['pin']==workflow['pin']and
         type(registered['id'])is int and registered['id']>0,'exact workflow registration DATA join')
    need(type(env)is dict and all(env.get(key)==value for key,value in fixed['fixed_context'].items())and
         env.get('GITHUB_SHA')==cid and env.get('GITHUB_REF')==ref and
         type(env.get('GITHUB_RUN_ID'))is str and re.fullmatch('[1-9][0-9]{1,19}',env['GITHUB_RUN_ID'])is not None,
         'first-attempt native caller public context DATA join')
    need(type(now)is int and now>=0,'explicit caller comparison epoch')
    documents=[]
    for raw,kind in ((admission_raw,fixed['admission_kind']),(runtime_raw,fixed['runtime_kind'])):
        need(type(raw)is bytes and 0<len(raw)<=16384,'bounded whole in-memory Root document bytes')
        value=decode(raw);need(type(value)is dict and value.get('kind')==kind and
            value.get('issued_by')=='Root'and value.get('accepted')is True,'separate Root document declaration required')
        need(value.get('source')==cid and value.get('ref')==ref and
             value.get('source_map_sha256')==source['source_map']['sha256']and
             encode(value.get('resources'))==encode(fixed['resources']),'exact Root Source/ref/map/resource DATA joins')
        created,expires,nonce=value.get('created_utc'),value.get('expires_utc'),value.get('nonce')
        need(type(created)is int and type(expires)is int and created<=now<expires and expires-created<=3600 and
             type(nonce)is str and re.fullmatch('[0-9a-f]{32}',nonce)is not None,'fresh bounded Root document DATA interval')
        documents.append(value)
    admission,runtime=documents
    need(admission['nonce']==runtime['nonce'],'same Root delegation nonce')
    need(encode(runtime.get('host_tools'))==encode(fixed['host_tools'])and 'host_prerequisites'not in runtime,
         'existing-host zero-APT runtime DATA declaration')
    need(runtime.get('external_supervision')==source['owner_program']and
         runtime.get('bootstrap_resource_domain')==source['policy'],'fresh Source62 program and policy DATA pins')
    return dict(status='CALLER_DATA_COMPATIBLE_ONLY',Root_authority=None,Root_acceptance=None,
                actors_permitted=False,admission=pin(admission_raw),runtime=pin(runtime_raw),
                source_map=source['source_map'],owner_program=source['owner_program'],policy=source['policy'],
                pending_root_gates=list(plan['root_bindings']))
