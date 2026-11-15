#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Correct diagnostic expectations to the original fixed1001 image; DATA only."""
import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[2]
INPUTS_SHA='f6bacffed4149718e87b4f35a177b43da553406c93dcff74b4b463dabd09a574'
PARENT='69455e13bc99a2b2b6c2aca11f69d581769ae500'
PARENT_TREE='0850f8b2d8e3098a4e65f6cda6ba44698d3381a0'
PARENT_MAP='bf6d956b671b4c3df38aa579277319c1f4030a9e5efd14778fd9db528072a726'
ALPM='native/build_tools_alpm_v2.py'
TOOLS='native/build_tools_tools_v2.py'
CONTRACT='native/build-tools-contract-v2.json'
READER='native/build_tools_reader_v2.py'
PROJECTION='native/build_tools_projection_v2.py'
MAP='native/source-map.json'
CHANGED=frozenset((ALPM,TOOLS,CONTRACT,READER,PROJECTION,MAP))
EVIDENCE_SHA='be88555a75a6307acee3c146492fefe02b6adb9994a0cbc08f47f45659c7556b'
OUTCOME_SEAMS=[
 (b"before['egid'] == 1000 and",b"before['egid'] == 1001 and"),
 (b"after['egid'] == 1000\n",b"after['egid'] == 1001\n"),
 (b'uid_map=[[0,1000,1]],gid_map=[[0,1000,1]]',b'uid_map=[[0,1001,1]],gid_map=[[0,1001,1]]')]
SEAMS={ALPM:[(b'alarm.pw_uid == 1000 and',b'alarm.pw_uid == 1001 and'),
             (b'alarm.pw_gid == 1000 and',b'alarm.pw_gid == 1001 and'),
             (b'home.stat().st_uid == 1000 and',b'home.stat().st_uid == 1001 and')],
       TOOLS:OUTCOME_SEAMS,READER:OUTCOME_SEAMS,
       CONTRACT:[(b'"gid": 1000,',b'"gid": 1001,'),(b'"uid": 1000,',b'"uid": 1001,')]}


def need(ok,why):
    if not ok:raise ValueError(why)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def read(path,cap=4*1024**2):
    path=Path(path)
    need(path.is_absolute() and path==path.resolve() and not any(p.is_symlink()for p in(path,*path.parents)),'canonical context DATA operand')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    state=lambda s:tuple(getattr(s,n)for n in('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=cap,'bounded ordinary context DATA')
        with os.fdopen(os.dup(fd),'rb')as f:raw=f.read(cap+1)
        need(len(raw)==before.st_size and state(before)==state(os.fstat(fd))==state(path.lstat()),'stable whole context DATA')
        return raw
    finally:os.close(fd)


def constructors():
    raw=read(HERE/'constructor-inputs.json');need(pin(raw)['sha256']==INPUTS_SHA,'fixed constructor closure before importing DATA helpers')
    manifest=json.loads(raw);need(manifest['schema']==1 and len(manifest['files'])==5,'finite held observable constructor closure')
    for name,row in manifest['files'].items():need(pin(read(REPO/name))==row,'held DATA constructor operand '+name)
    path=HERE.parent/'native-build-namespace-observable/prepare.py'
    spec=importlib.util.spec_from_file_location('_held_observable_DATA_constructor',path);Q=importlib.util.module_from_spec(spec);spec.loader.exec_module(Q)
    P,old=Q.factory();return Q,P,old


def evidence():
    raw=read(HERE/'observed-mismatch.json');need(pin(raw)['sha256']==EVIDENCE_SHA,'fixed retained mismatch evidence DATA')
    value=json.loads(raw);need(value['source']==PARENT and value['run']==43662248024 and value['mapped_bodies_verified']==87,'exact original Source/run evidence')
    for row in value['operands'].values():need(pin(read(HERE/'fixtures'/row['fixture']))=={k:row[k]for k in('bytes','sha256')},'whole retained original DATA body')
    runner=json.loads(read(HERE/'fixtures/bootstrap-runner.json.data'))
    need(runner['commit']==PARENT and runner['run_id']=='43662248024' and runner['uid']==runner['gid']==1001
         and runner['kernel']['machine']==runner['docker_server_arch']=='aarch64','actual original ARM runner identity')
    dockerfile=read(HERE/'fixtures/bootstrap-Dockerfile.data')
    need(dockerfile.count(b'groupmod -g 1001 alarm && usermod -u 1001 -g alarm alarm')==1
         and dockerfile.endswith(b'USER alarm\nWORKDIR /tmp\n'),'original bootstrap fixes the actual alarm account to1001')
    return value


def baseline(Q,P,old):
    rows,blobs=Q.baseline(P,old);profile=P.decode(Q.read(Q.HERE/'profile.json'))
    need(profile['prospective_tree']==PARENT_TREE and profile['map_sha256']==PARENT_MAP and profile['actual']==dict(source=None,ref=None,run=None,job=None,artifact=None),'exact parent observable family')
    for name,sides in profile['changes'].items():
        need(rows[name]=={k:sides['before'][k]for k in('bytes','sha256','mode')} and blobs[name]==sides['before']['oid'],'complete observable parent inverse join')
        rows[name]={k:sides['after'][k]for k in('bytes','sha256','mode')};blobs[name]=sides['after']['oid']
    raw=read(HERE/'parent.raw',4096)
    need(P.oid(b'commit',raw).hex()==PARENT and raw.splitlines()[:2]==[('tree '+PARENT_TREE).encode(),('parent '+Q.PARENT).encode()],'genuine Source69455 raw and sole Source6b parent')
    return rows,blobs


def once(raw,old,new):
    need(raw.count(old)==1,'one exact finite context seam')
    return raw.replace(old,new,1)


def transform(before,Q,P,old):
    evidence()
    rows,blobs=baseline(Q,P,old)
    need(P.descriptors(before)==rows and {n:P.oid(b'blob',raw).hex()for n,(raw,mode)in before.items()}==blobs
         and P.tree(before)==PARENT_TREE,'complete genuine Source69455 body/mode/blob/tree')
    after=dict(before)
    for name,seams in SEAMS.items():
        raw,mode=before[name]
        for old_value,new_value in seams:raw=once(raw,old_value,new_value)
        inverse=raw
        for old_value,new_value in reversed(seams):inverse=once(inverse,new_value,old_value)
        need(inverse==before[name][0],'exact inverse restores every nonidentity predicate byte')
        after[name]=(raw,mode)
    for name in(READER,PROJECTION):
        raw,mode=after[name]
        for producer in(ALPM,TOOLS,CONTRACT):
            old_pin=pin(before[producer][0])['sha256'].encode();new_pin=pin(after[producer][0])['sha256'].encode()
            raw=once(raw,old_pin,new_pin)
        inverse=raw
        for producer in(CONTRACT,TOOLS,ALPM):
            raw_old=pin(before[producer][0])['sha256'].encode();raw_new=pin(after[producer][0])['sha256'].encode()
            inverse=once(inverse,raw_new,raw_old)
        need(inverse==after[name][0],'exact producer registry inverse')
        after[name]=(raw,mode)
    for name in(ALPM,TOOLS,READER,PROJECTION):ast.parse(after[name][0],filename=name)
    mapping=P.decode(before[MAP][0]);need(mapping.get('namespace_build_log_visibility')=='UNQUIET_TOOLS_IIDFILE_V1','exact unquiet parent family')
    mapping['files']={n:r for n,r in P.descriptors(after).items()if n!=MAP};after[MAP]=(P.encoded(mapping),before[MAP][1])
    need(len(after)==200 and len(mapping['files'])==199 and mapping['actual']==dict(source=None,ref=None,run=None)
         and {n for n in before if before[n]!=after[n]}==CHANGED,'six finite leaves only, complete Source200/map199')
    inverse=dict(after)
    for name in CHANGED:inverse[name]=before[name]
    need(inverse==before and P.tree(inverse)==PARENT_TREE,'complete original Source69455 inverse')
    return after


def facts(before,after,P):
    def row(value):
        raw,mode=value;return dict(**pin(raw),mode=mode,oid=P.oid(b'blob',raw).hex())
    return dict(schema=1,purpose='native-build-namespace-original-alarm1001-source-v1',operation='native-build-namespace-preflight-v1',
        parent=PARENT,parent_tree=PARENT_TREE,parent_map_sha256=PARENT_MAP,parent_raw=pin(read(HERE/'parent.raw')),
        constructor_inputs=pin(read(HERE/'constructor-inputs.json')),prospective_tree=P.tree(after),map_sha256=pin(after[MAP][0])['sha256'],
        source_files=200,map_rows=199,unchanged_files=194,changes={n:dict(before=row(before[n]),after=row(after[n]))for n in sorted(CHANGED)},
        retained_mismatch_evidence=pin(read(HERE/'observed-mismatch.json')),
        alarm_identity=dict(uid=1001,gid=1001,scope='ORIGINAL_349_IMAGE_BUILD_RUN_USER_ALARM',
                            old_1000_contract='INCORRECT',account_mutation=False,other_guards='UNCHANGED'),
        actual=dict(source=None,ref=None,run=None,job=None,artifact=None),native='NOT_RUN',Reader='NOT_RUN',
        namespace_policy_cause='UNKNOWN',physical_M2='NOT_RUN',release='NOT_ADMITTED',acceptance=False)


def compose(before,checksum):
    raw=read(HERE/'profile.json');need(pin(raw)['sha256']==checksum,'external Root whole context profile pin')
    Q,P,old=constructors();after=transform(before,Q,P,old)
    need(P.decode(raw)==facts(before,after,P),'exact complete fixed-alarm Source family facts')
    return after,P


def prepare(parent_source,checksum,output=None):
    Q,P,old=constructors();parent_source=P.absolute(parent_source);before=P.snapshot(parent_source);after,P=compose(before,checksum)
    if output is not None:
        output=P.absolute(output)
        need(output!=parent_source and parent_source not in output.parents and output not in parent_source.parents
             and output!=HERE and HERE not in output.parents and output not in HERE.parents,'fresh disjoint context Source output')
        P.publish(after,output)
    return dict(status='ORIGINAL_ALARM1001_CONTEXT_SOURCE_DATA_ONLY',source_written=output is not None,prospective_tree=P.tree(after),map_sha256=pin(after[MAP][0])['sha256'],
                actual=dict(source=None,ref=None,run=None,job=None,artifact=None),Native_POSTs=0,Original_GETs=0,Reader_calls=0,namespace_probe_calls=0,acceptance=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--parent-source',type=Path,required=True)
    parser.add_argument('--profile-sha256',required=True);parser.add_argument('--output',type=Path)
    args=parser.parse_args();print(json.dumps(prepare(args.parent_source,args.profile_sha256,args.output),sort_keys=True))
