#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare/verify a sealed unissued caller packet; no publication or native actor."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from types import ModuleType

HERE=Path(__file__).resolve().parent
PREFIX='scripts/ci/fish-config02-native-source/successor_v2/'
BASE='held-source32/scripts/ci/fish-config02-native-source/'
CODE_FILES=('prepare.py','contract.py','STATIC.json','README.md')
DATA_FILES=('PLAN.UNISSUED.json','admission.INTENT.UNISSUED.json','runtime.INTENT.UNISSUED.json',
            'SOURCE-CONTENT.PINS.json','SOURCE62.source-map.EXACT.json','STEPS.DATA.json')


def need(ok,why):
    if not ok:raise ValueError(why)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encode(v):return(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()


def read(path,cap=2*1024**2):
    path=Path(path);need(path.is_absolute()and path==path.resolve()and not path.is_symlink(),'canonical ordinary operand')
    before=path.lstat();need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and not before.st_mode&0o022 and
        0<before.st_size<=cap,'bounded non-writable ordinary operand')
    identity=lambda s:tuple(getattr(s,k)for k in ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        need(identity(before)==identity(os.fstat(fd)),'same operand descriptor')
        with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(cap+1)
        need(len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'whole stable operand')
        return raw
    finally:os.close(fd)


def contract():
    path=HERE/'contract.py';m=ModuleType('fish62_caller_contract');m.__file__=str(path)
    exec(compile(read(path),str(path),'exec'),m.__dict__);return m


def git_tree(bodies):
    def oid(kind,raw):return hashlib.sha1(kind.encode()+b' '+str(len(raw)).encode()+b'\0'+raw).digest()
    def tree(prefix):
        rows=[]
        for name in {n[len(prefix):].split('/')[0]for n in bodies if n.startswith(prefix)}:
            full=prefix+name
            mode,key,digest=(b'100644',name.encode(),oid('blob',bodies[full]))if full in bodies else(b'40000',(name+'/').encode(),tree(full+'/'))
            rows.append((key,mode+b' '+name.encode()+b'\0'+digest))
        return oid('tree',b''.join(v for _,v in sorted(rows)))
    return tree('').hex()


def inventory(source):
    """Whole content joins only; never import Source validators or rerun inverses."""
    C=contract();fixed=C.expected();source=Path(source)
    need(source.is_absolute()and source==source.resolve()and source.is_dir(),'canonical exact Source62 directory')
    raw=read(source/'source-map.json');need(pin(raw)==fixed['source']['source_map'],'exact Source62 map')
    value=C.decode(raw);rows=dict(value['files'],**{'source-map.json':dict(pin(raw),mode=0o644)})
    need(value['kind']=='FISH02_EXPLICIT_SOURCE_READONLY_SOURCE_V8'and len(rows)==62 and
         all(v is None for v in value['actual'].values()),'exact unissued Source62 frame')
    found=set();pending=[source];count=0
    while pending:
        directory=pending.pop()
        with os.scandir(directory)as entries:
            for entry in entries:
                if directory==source and entry.name=='.git':continue
                count+=1;need(count<=256,'finite Source62 namespace')
                path=Path(entry.path);need(not path.is_symlink(),'unaliased Source62 member')
                if path.is_dir():pending.append(path)
                else:need(path.is_file(),'ordinary Source62 leaf');found.add(path.relative_to(source).as_posix())
    need(found==set(rows),'closed exact Source62 namespace')
    bodies={}
    for name,wanted in rows.items():
        need(not Path(name).is_absolute()and '..'not in Path(name).parts,'safe Source62 member')
        body=read(source/name);need(dict(pin(body),mode=stat.S_IMODE((source/name).stat().st_mode))==wanted and wanted['mode']==0o644,'exact Source62 body/mode')
        bodies[name]=body
    need(sum(map(len,bodies.values()))==fixed['source']['bytes']and git_tree(bodies)==fixed['source']['tree'],'whole Source62 bytes/tree')
    for name,key in ((PREFIX+'owner-program.json','owner_program'),(PREFIX+'policy.json','policy')):
        need(pin(bodies[name])==fixed['source'][key],'exact Source62 '+key)
    return fixed,bodies,rows


def intents(fixed):
    admission=dict(kind=fixed['admission_kind'],accepted=False,issued_by=None,source=None,ref=None,
        source_map_sha256=fixed['source']['source_map']['sha256'],resources=fixed['resources'],nonce=None,created_utc=None,expires_utc=None)
    runtime=dict(admission,kind=fixed['runtime_kind'],external_supervision=fixed['source']['owner_program'],
        bootstrap_resource_domain=fixed['source']['policy'],host_tools=fixed['host_tools'])
    return admission,runtime


def steps():
    return dict(kind='FISH62_ROOT_ONLY_ORDERED_PREPARATION_STEPS_V1',actors_permitted=False,steps=[
        dict(id='VERIFY_LOCAL_DATA',Root_only=False,argv=['python3','-I','-B','prepare.py','verify','--source','<exact-Source62>','--output','<this-packet>']),
        dict(id='ROOT_PUBLISH_EXACT_CONTENT',Root_only=True,requires=['publication.cid','publication.ref','source_public_readback']),
        dict(id='ROOT_JOIN_WORKFLOW_REGISTRATION',Root_only=True,requires=['publication.workflow_id','workflow_registration']),
        dict(id='ROOT_REJOIN_CANONICAL_CALLER',Root_only=True,requires=['canonical_framework_runtime54_pin','canonical_caller_pin','Main_CAS','lease','two_full_global_EMPTY_sweeps','freshness_receipt']),
        dict(id='ROOT_ISSUE_FRESH_DOCUMENTS',Root_only=True,requires=['root_admission','root_runtime','nonce','canonical_role']),
        dict(id='ROOT_SCHEDULE_NORMAL_PAIR_AFTER_LLHTTP',Root_only=True,requires=['native_run','native_job']),
        dict(id='ROOT_CLOSE_AND_INTAKE',Root_only=True,requires=['retirement_receipt'])])


def packet(source):
    fixed,bodies,rows=inventory(source);C=contract()
    plan=dict(kind='FISH62_CANONICAL_PREPARATION_V1',source=fixed['source'],workflow=fixed['workflow'],
        normal_pair=fixed['normal_pair'],ref_pattern=fixed['ref_pattern'],
        publication={name:None for name in fixed['publication_fields']},
        root_bindings={name:None for name in fixed['root_binding_fields']},Root_authority=None,Root_acceptance=None)
    C.validate_plan(plan);a,r=intents(fixed)
    data=dict(zip(('admission.INTENT.UNISSUED.json','runtime.INTENT.UNISSUED.json'),map(encode,(a,r))))
    data.update({'PLAN.UNISSUED.json':encode(plan),'SOURCE-CONTENT.PINS.json':encode(rows),
        'SOURCE62.source-map.EXACT.json':bodies['source-map.json'],'STEPS.DATA.json':encode(steps())})
    data.update({name:read(HERE/name)for name in CODE_FILES})
    return data


def construct(source,output):
    source,output=map(Path,(source,output))
    need(output.is_absolute()and output==output.resolve()and output.parent.is_dir()and not output.exists()and
         not output.is_relative_to(source)and not source.is_relative_to(output),'fresh disjoint DATA packet output')
    data=packet(source)
    seal=dict(kind='FISH62_CANONICAL_PREPARATION_SEAL_V1',files={name:pin(raw)for name,raw in sorted(data.items())},
        publication=None,source_CID=None,source_ref=None,Root_authority=None,Root_roles=None)
    data['SEAL.DATA.json']=encode(seal);output.mkdir(mode=0o700)
    for name,raw in data.items():
        with (output/name).open('xb')as stream:stream.write(raw)
        (output/name).chmod(0o600)
    return verify(source,output)


def verify(source,output):
    output=Path(output);need(output.is_absolute()and output==output.resolve()and output.is_dir(),'canonical DATA packet directory')
    data=packet(source);C=contract();seal_raw=read(output/'SEAL.DATA.json');seal=C.decode(seal_raw)
    expected=dict(kind='FISH62_CANONICAL_PREPARATION_SEAL_V1',files={name:pin(raw)for name,raw in sorted(data.items())},
        publication=None,source_CID=None,source_ref=None,Root_authority=None,Root_roles=None)
    need(seal==expected,'exact preparation code/plan/intent/content seal')
    need(set(p.name for p in output.iterdir())==set(data)|{'SEAL.DATA.json'},'closed preparation packet namespace')
    for name,raw in data.items():
        need(read(output/name)==raw and stat.S_IMODE((output/name).stat().st_mode)==0o600,'exact private packet body/mode')
    need(stat.S_IMODE((output/'SEAL.DATA.json').stat().st_mode)==0o600,'private packet seal')
    return dict(status='DATA_READY_ROOT_BINDINGS_UNISSUED',files=len(data)+1,seal=pin(seal_raw),
        actors_permitted=False,publication=None,source_CID=None,source_ref=None,Root_roles=None,Root_acceptance=None,
        previous_source_tests='NOT_RERUN',predecessor_inverse='PRESERVED_BY_EXACT_CONTENT_PINS_NOT_REEXECUTED')


if __name__=='__main__':
    need(sys.flags.isolated and sys.flags.dont_write_bytecode and __debug__,'run unoptimized with Python -I -B')
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=('prepare','verify'))
    parser.add_argument('--source',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    a=parser.parse_args();print(json.dumps((construct if a.action=='prepare'else verify)(a.source,a.output),indent=2,sort_keys=True))
