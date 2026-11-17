# SPDX-License-Identifier: MIT
"""Passive GCC profile byte/identity seal; no decoder, compiler or native action."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

SOURCE_SHA256='bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16'
OBJECTS=tuple(sorted(('adler32 crc32 deflate infback inffast inflate inftrees trees zutil '
    'compress uncompr gzclose gzlib gzread gzwrite example minigzip').split()))
PROFILE_NAMES=tuple('#tmp#build#'+name+'.gcda'for name in OBJECTS)
TOOLS={'gcc','gcc-ar','gcc-ranlib','ld','gcov-tool','make','as','cc1','collect2','libgcov.a'}
FIELDS={'source_sha256','source_files','toolchain','isa','build_path','profile_path','prefix','training'}
MAX_FILE=4*1024**2
MAX_TOTAL=16*1024**2
MAX_SEAL=2*1024**2


def need(ok,message):
    if not ok:raise ValueError(message)


def encoded(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(raw):return dict(bytes=len(raw),sha256=sha(raw))


def fields(value,names,label):
    need(type(value)is dict and set(value)==set(names),'closed '+label+' fields')


def digest(value):
    need(type(value)is str and re.fullmatch('[0-9a-f]{64}',value)and value!='0'*64,'concrete full SHA256 identity')


def ordinary(value,absolute=False):
    need(type(value)is str and 0<len(value)<=4096 and all(32<=ord(c)<127 for c in value)
        and '\\'not in value and ','not in value,'ordinary POSIX identity path')
    path=PurePosixPath(value)
    need(path.is_absolute()is absolute and str(path)==value and '..'not in path.parts
        and (absolute or value not in('.', '')),'normalized POSIX identity path')


def file_pin(value,label,positive=False,limit=16*1024**2):
    fields(value,{'bytes','sha256'},label);digest(value['sha256'])
    need(type(value['bytes'])is int and (1 if positive else 0)<=value['bytes']<=limit,'bounded '+label+' bytes')


def validate_binding(binding):
    fields(binding,FIELDS,'profile binding')
    need(binding['source_sha256']==SOURCE_SHA256,'exact pinned zlib source')
    need(binding['isa']=='armv8-a/generic' and binding['build_path']=='/tmp/build'
        and binding['profile_path']=='/tmp/profile'
        and binding['prefix']=='/usr/lib/cachy-asahi/experiments/zlib-pgo-v1','exact ISA/build/profile/private-prefix identity')
    source=binding['source_files'];need(type(source)is dict and 0<len(source)<=4096,'complete bounded source-file identity map')
    for name,row in source.items():ordinary(name);file_pin(row,'source file')
    need(sum(r['bytes']for r in source.values())<=128*1024**2,'source identity aggregate bound')
    tc=binding['toolchain'];fields(tc,{'target','tools'},'toolchain')
    need(type(tc['target'])is str and re.fullmatch(r'aarch64(?:-[A-Za-z0-9_+.]+)*-linux-gnu',tc['target']),'concrete native aarch64 GNU target')
    tools=tc['tools'];need(type(tools)is dict and set(tools)==TOOLS,'exact ten toolchain identities')
    for name,row in tools.items():
        fields(row,{'path','resolved_path','bytes','sha256','version'},'tool '+name)
        ordinary(row['path'],True);ordinary(row['resolved_path'],True)
        file_pin({k:row[k]for k in('bytes','sha256')},'tool '+name,True,512*1024**2)
        need(type(row['version'])is str and 0<len(row['version'].strip())<=65536
            and '\0'not in row['version'],'concrete bounded tool version')
    training=binding['training'];fields(training,{'corpus','heldout','command_plan_sha256','results_sha256'},'training')
    for key,path in [('corpus','training.bin'),('heldout','validation.bin')]:
        row=training[key];fields(row,{'path','bytes','sha256'},key)
        need(row['path']==path,'frozen distinct training/validation path')
        file_pin({k:row[k]for k in('bytes','sha256')},key,True)
    need(training['corpus']['sha256']!=training['heldout']['sha256'],'training and validation bytes must differ')
    digest(training['command_plan_sha256']);digest(training['results_sha256'])
    need(len(encoded(binding))<=MAX_SEAL//2,'bounded complete profile binding')
    return binding


def path_guard(path):
    path=Path(path).absolute();need('..'not in path.parts,'no parent traversal')
    need(not any(p.is_symlink()for p in(path,*path.parents)),'profile/seal aliases refused')
    return path


def state(info):return tuple(getattr(info,k)for k in('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))


def read_fd(fd,limit):
    before=os.fstat(fd)
    need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<=before.st_size<=limit,'bounded single-link regular profile/seal')
    chunks=[];count=0
    while True:
        raw=os.read(fd,min(65536,limit-count+1))
        if not raw:break
        count+=len(raw);need(count<=limit,'profile/seal grew beyond bound');chunks.append(raw)
    need(state(before)==state(os.fstat(fd))and count==before.st_size,'profile/seal changed during read')
    return b''.join(chunks)


def read_file(path,limit=MAX_SEAL):
    path=path_guard(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:return read_fd(fd,limit)
    finally:os.close(fd)


def profiles(directory):
    directory=path_guard(directory);fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        need(set(os.listdir(fd))==set(PROFILE_NAMES),'all seventeen exact profile leaves required')
        result={};versions=set();total=0;observed={}
        for name in PROFILE_NAMES:
            item=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
            try:
                raw=read_fd(item,MAX_FILE);observed[name]=state(os.fstat(item))
            finally:os.close(item)
            need(len(raw)>=16 and raw[:4]in(b'adcg',b'gcda'),'GCC profile header required; not decode proof')
            version=raw[4:8];need(all(32<=v<127 for v in version),'concrete GCC profile version')
            versions.add(version.hex());result[name]=pin(raw);total+=len(raw)
        need(total<=MAX_TOTAL and len(versions)==1,'aggregate profile bound or shared GCC version differs')
        need(set(os.listdir(fd))==set(PROFILE_NAMES),'profile directory changed during read')
        need(all(state(os.stat(name,dir_fd=fd,follow_symlinks=False))==record for name,record in observed.items()),'profile set changed during complete read')
        return result,next(iter(versions))
    finally:os.close(fd)


def report(raw,payload):
    return dict(status='PASS_SOURCE_TOOLCHAIN_TRAINING_PATH_AND_PROFILE_BYTE_SEAL',seal_sha256=sha(raw),
        seal_bytes=len(raw),binding_sha256=payload['binding_sha256'],profiles=17,gcda_version_hex=payload['gcda_version_hex'],
        profile_decoding='NOT_ESTABLISHED_BY_HEADER_OR_HASH',native_execution='NOT RUN',performance_acceptance='NOT GRANTED')


def seal(profile_dir,binding,output):
    validate_binding(binding);rows,version=profiles(profile_dir)
    payload=dict(schema_version=1,purpose='frozen-zlib-pgo-profile-v1',binding=binding,
        binding_sha256=sha(encoded(binding)),profiles=rows,gcda_version_hex=version)
    raw=encoded(dict(payload=payload,payload_sha256=sha(encoded(payload))))
    need(len(raw)<=MAX_SEAL,'bounded sealed profile receipt')
    output=path_guard(output);need(output.parent.is_dir(),'existing ordinary seal parent required')
    fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    try:
        offset=0
        while offset<len(raw):offset+=os.write(fd,raw[offset:])
        os.fsync(fd)
    finally:os.close(fd)
    return verify(profile_dir,binding,output,expected_sha256=sha(raw))


def verify(profile_dir,binding,seal_path,*,expected_sha256=None):
    validate_binding(binding);raw=read_file(seal_path)
    if expected_sha256 is not None:
        digest(expected_sha256);need(sha(raw)==expected_sha256,'original whole profile seal changed')
    value=json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in()).throw(ValueError('nonfinite profile JSON')))
    fields(value,{'payload','payload_sha256'},'seal envelope');digest(value['payload_sha256'])
    payload=value['payload'];fields(payload,{'schema_version','purpose','binding','binding_sha256','profiles','gcda_version_hex'},'seal payload')
    need(type(payload['schema_version'])is int and payload['schema_version']==1
        and payload['purpose']=='frozen-zlib-pgo-profile-v1','profile seal purpose/schema')
    need(value['payload_sha256']==sha(encoded(payload)),'profile seal self-digest mismatch')
    need(encoded(payload['binding'])==encoded(binding)and payload['binding_sha256']==sha(encoded(binding)),'source/toolchain/ISA/path/training binding mismatch')
    rows,version=profiles(profile_dir)
    need(payload['profiles']==rows and payload['gcda_version_hex']==version,'sealed profile bytes/closure/version mismatch')
    need(raw==encoded(value),'canonical whole profile seal bytes required')
    return report(raw,payload)


def unique(pairs):
    value={}
    for key,item in pairs:
        need(key not in value,'duplicate sealed JSON key');value[key]=item
    return value
