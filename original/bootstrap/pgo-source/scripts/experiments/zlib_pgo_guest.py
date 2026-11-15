#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit future generic16K installed correctness gate; never installs or measures."""
import argparse
import binascii
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import sys
import zlib

SOURCE_SHA='bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16'
SOURCE_BYTES=1502830
PREFIXES={'baseline':'/usr/lib/cachy-asahi/experiments/zlib-baseline','candidate':'/usr/lib/cachy-asahi/experiments/zlib-pgo-v1'}
VARIANTS={'baseline':'baseline','candidate':'pgo-v1'}
PROGRAMS=('minigzip','probe','strict-gzip')
SUPERVISOR_SHA='38e10bbf57c9b83040624748967426aa829144585e5c26b7f39f56b8f58bb933'
RECIPE=Path(__file__).resolve().parents[2]/'packages/experiments/cachy-asahi-zlib-pgo-v1'


def need(ok,why):
    if not ok:raise ValueError(why)


def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(raw):return dict(bytes=len(raw),sha256=sha(raw))
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()


def decode(raw):
    def pairs(rows):
        value={}
        for key,item in rows:
            need(key not in value,'duplicate manifest/seal key');value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in()).throw(ValueError('nonfinite manifest/seal')))


def digest(value,length=64):
    need(type(value)is str and re.fullmatch('[0-9a-f]{'+str(length)+'}',value)and value!='0'*length,'concrete full hash identity required')


def fields(value,names,label):
    need(type(value)is dict and set(value)==set(names),'closed '+label+' fields required')


def ordinary(path):
    path=Path(path).absolute()
    need('..'not in path.parts and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary path without aliases required')
    return path


def read(path,cap=16*1024**2):
    path=ordinary(path);info=path.stat()
    need(stat.S_ISREG(info.st_mode)and info.st_nlink==1 and 0<=info.st_size<=cap,'bounded regular single-link input required')
    raw=path.read_bytes();need(len(raw)==info.st_size,'input changed size');return raw


def manifest(path,role):
    raw=read(path,65536);value=decode(raw)
    fields(value,{'schema','role','variant','prefix','publication_source','source_sha256','programs','profile_seal'},'expected installed manifest')
    need(type(value['schema'])is int and value['schema']==1 and value['role']==role and value['variant']==VARIANTS[role]
        and value['prefix']==PREFIXES[role]and value['source_sha256']==SOURCE_SHA,'exact manifest role/private-prefix/zlib source')
    digest(value['publication_source'],40)
    fields(value['programs'],PROGRAMS,'expected installed programs')
    for name,row in value['programs'].items():
        fields(row,{'path','bytes','sha256'},'installed '+name)
        need(row['path']==value['prefix']+'/bin/'+name and type(row['bytes'])is int and 0<row['bytes']<=8*1024**2,'fixed concrete installed executable')
        digest(row['sha256'])
    if role=='baseline':need(value['profile_seal']=='NOT_APPLICABLE_BASELINE','baseline has no PGO profile')
    else:
        row=value['profile_seal'];fields(row,{'path','bytes','sha256','binding_sha256'},'expected candidate profile seal')
        need(row['path']==value['prefix']+'/build/profile-seal.json'and type(row['bytes'])is int and 0<row['bytes']<=2*1024**2,'fixed candidate installed seal')
        digest(row['sha256']);digest(row['binding_sha256'])
    return value,raw


def installed(value):
    for row in value['programs'].values():
        raw=read(row['path'],8*1024**2)
        need(pin(raw)=={k:row[k]for k in('bytes','sha256')}and Path(row['path']).stat().st_mode&0o111,'actual installed executable bytes/permission differ')
    raw=read(value['prefix']+'/source/zlib-1.3.2.tar.gz',2*1024**2)
    need(pin(raw)==dict(bytes=SOURCE_BYTES,sha256=SOURCE_SHA),'actual installed pinned source archive differs')
    if value['role']=='candidate':
        expected=value['profile_seal'];raw=read(expected['path'],2*1024**2)
        need(pin(raw)=={k:expected[k]for k in('bytes','sha256')},'actual installed whole profile seal differs')
        seal=decode(raw);fields(seal,{'payload','payload_sha256'},'profile seal envelope')
        payload=seal['payload'];fields(payload,{'schema_version','purpose','binding','binding_sha256','profiles','gcda_version_hex'},'profile seal payload')
        need(raw==canonical(seal)and seal['payload_sha256']==sha(canonical(payload))and type(payload['schema_version'])is int
            and payload['schema_version']==1 and payload['purpose']=='frozen-zlib-pgo-profile-v1','canonical installed profile envelope/source')
        binding=payload['binding'];need(payload['binding_sha256']==expected['binding_sha256']==sha(canonical(binding)),'exact expected profile source/toolchain/training binding')
        need(binding['source_sha256']==SOURCE_SHA and binding['isa']=='armv8-a/generic'and binding['prefix']==value['prefix']
            and binding['build_path']=='/tmp/build'and binding['profile_path']=='/tmp/profile','installed profile pinned source/ISA/path identity')
    return dict(status='MATCHED_EXPECTED_INSTALLED_BYTES_AND_SOURCE',programs=value['programs'],profile_seal=value['profile_seal'])


def guard(execute):
    need(execute is True,'explicit --execute required')
    need(platform.system()=='Linux'and platform.machine()=='aarch64'and os.sysconf('SC_PAGE_SIZE')==16384,'actual generic aarch64/16384-page runtime required')
    need(os.getuid()==os.geteuid()>0 and os.environ.get('CACHY_ASAHI_PGO_GENERIC16K')=='1','explicit ordinary-user generic16K marker required')


def corpus():
    values=[b'',b'x',b'cachy-asahi public workload\n'*4096,bytes(range(256))*1024]
    return values+[bytes((i*13+i//257)&255 for i in range(n))for n in(16383,16384,16385)]


def reference():
    raw=b'cachy-asahi generic16K strict-gzip public oracle\n'*8;n=len(raw)
    packed=b'\x1f\x8b\x08\x00\0\0\0\0\x00\xff\x01'+n.to_bytes(2,'little')+(n^65535).to_bytes(2,'little')+raw
    return raw,packed+binascii.crc32(raw).to_bytes(4,'little')+n.to_bytes(4,'little')


def workload_plan():
    rows=[]
    for producer in PREFIXES:
        rows.append(dict(label='probe-'+producer,argv=[PREFIXES[producer]+'/bin/probe','--installed-check'],expected=0))
    for producer in PREFIXES:
        for index in range(7):
            for level in(1,6,9):
                label=f'{producer}-{index}-{level}'
                rows.append(dict(label=label+'-encode',argv=[PREFIXES[producer]+'/bin/minigzip','-'+str(level)],expected=0))
                for consumer in PREFIXES:rows.append(dict(label=label+'-decode-'+consumer,argv=[PREFIXES[consumer]+'/bin/strict-gzip'],expected=0))
    for consumer in PREFIXES:
        for index in range(3):rows.append(dict(label='reject-'+consumer+'-'+str(index),argv=[PREFIXES[consumer]+'/bin/strict-gzip'],expected=2))
    return rows


def workload(runner):
    rows=iter(workload_plan());observations=[];inputs=corpus();counts=dict(encodes=0,cross_decodes=0,python_decodes=0,strict_rejections=0,installed_probes=0)
    def command(data=None):
        row=next(rows);return runner.run(row['label'],row['argv'],data=data,expected=row['expected'],timeout=15)
    for role in PREFIXES:
        observed=decode(command());expected=dict(status='PASS',variant=VARIANTS[role],prefix=PREFIXES[role],zlib='1.3.2',source_sha256=SOURCE_SHA,roundtrips=21,negative_checks=42)
        need(observed==expected,'installed probe/source/prefix/check counts differ');counts['installed_probes']+=1
    for producer in PREFIXES:
        for index,original in enumerate(inputs):
            for level in(1,6,9):
                packed=command(original);counts['encodes']+=1
                decoder=zlib.decompressobj(31);decoded=decoder.decompress(packed,4*1024**2)
                need(decoded==original and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,'independent exact Python gzip decode differs');counts['python_decodes']+=1
                for consumer in PREFIXES:
                    need(command(packed)==original,'strict cross-variant decode differs');counts['cross_decodes']+=1
                observations.append(dict(producer=producer,input=index,level=level,encoded=pin(packed),decoded=pin(original),python_decode='PASS',strict_cross_decoders=list(PREFIXES)))
    plain,packed=reference();corrupt=bytearray(packed);corrupt[-8]^=1
    for consumer in PREFIXES:
        for invalid in(bytes(corrupt),packed[:-8],packed+b'garbage'):
            need(command(invalid)==plain,'strict refusal must retain complete reference plaintext before exit2');counts['strict_rejections']+=1
    try:next(rows);raise ValueError('unexecuted finite workload commands')
    except StopIteration:pass
    need(counts==dict(encodes=42,cross_decodes=84,python_decodes=42,strict_rejections=6,installed_probes=2),'complete fixed finite workload counts')
    return dict(status='PASS_FINITE_INSTALLED_GENERIC16K_CORRECTNESS',counts=counts,inputs=[pin(v)for v in inputs],observations=observations)


def inventory(runner,label):
    raw=runner.run(label,['pacman','-Q'],timeout=20);names=[]
    for line in raw.decode().splitlines():
        parts=line.split();need(len(parts)==2,'package inventory row');names.append(parts[0])
    need(names and names==sorted(set(names)),'complete sorted unique observed inventory')
    return raw


def supervisor():
    path=RECIPE/'supervisor.py';need(sha(read(path))==SUPERVISOR_SHA,'held-leader supervisor source differs')
    spec=importlib.util.spec_from_file_location('_fixed_pgo_guest_supervisor',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def write(path,raw):
    with Path(path).open('xb')as stream:stream.write(raw)


def run(baseline_manifest,candidate_manifest,output,*,execute=False):
    guard(execute);values={};originals={}
    for role,path in(('baseline',baseline_manifest),('candidate',candidate_manifest)):
        values[role],originals[role]=manifest(path,role)
    bindings={role:installed(value)for role,value in values.items()}
    output=ordinary(output);need(output.parent.is_dir(),'existing ordinary output parent required');output.mkdir(mode=0o700,exist_ok=False)
    runner=supervisor().Commands(output,seconds=600,builder_uid=os.geteuid());handlers={sig:signal.getsignal(sig)for sig in(signal.SIGINT,signal.SIGTERM)}
    report=dict(status='FAIL_GENERIC16K_CORRECTNESS',scope='ONE_GENERIC_AARCH64_16K_INSTALLED_CANDIDATE_COMPONENT',machine='aarch64',page_size=16384,
        expected_manifests={role:pin(raw)for role,raw in originals.items()},installed=bindings,hardware='NOT RUN',physical_Asahi_M2='NOT RUN',performance='NOT MEASURED',release='NOT_ADMITTED',
        profile_byte_replay='NOT RUN: installed whole seal and expected binding joined; raw GCDA not re-executed',zombie_absence='NOT_ESTABLISHED',container_vm_retirement='REQUIRED_SEPARATELY')
    try:
        for sig in handlers:signal.signal(sig,runner.cancel)
        for role,raw in originals.items():write(output/(role+'-manifest.original.json'),raw)
        before=inventory(runner,'inventory-before');write(output/'inventory-before.lock',before)
        report['correctness']=workload(runner)
        after=inventory(runner,'inventory-after');write(output/'inventory-after.lock',after);need(after==before,'package inventory changed during read-only correctness')
        need({role:installed(value)for role,value in values.items()}==bindings,'installed executable/source/seal bytes changed during correctness')
        report.update(status='PASS_FINITE_GENERIC16K_INSTALLED_CORRECTNESS_ONLY',inventory=pin(before),commands=len(runner.rows),acceptance=False)
        return report
    except BaseException as error:
        report.update(error_type=type(error).__name__,error=str(error)[:4096],acceptance=False);raise
    finally:
        for sig,handler in handlers.items():signal.signal(sig,handler)
        write(output/'receipt.json',(json.dumps(report,indent=2,sort_keys=True,allow_nan=False)+'\n').encode())


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--execute',action='store_true');parser.add_argument('--baseline-manifest',type=Path,required=True);parser.add_argument('--candidate-manifest',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    try:print(json.dumps(run(args.baseline_manifest,args.candidate_manifest,args.output,execute=args.execute),sort_keys=True));return 0
    except(OSError,ValueError,KeyError,TypeError,zlib.error)as error:print('generic16K gate refused: '+str(error),file=sys.stderr);return 2


if __name__=='__main__':raise SystemExit(main())
