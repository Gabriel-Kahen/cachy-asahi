# SPDX-License-Identifier: MIT
"""Finite Source DATA guards shared by construction and explicit Root dispatch."""
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat

FAMILY='scripts/ci/first-login-enrollment-native-source'
PREFIX=FAMILY+'/successor_v3'
OPERATION='first-login-enrollment-ui-current-v2'
API='CURRENT_ONBOARDING_OWNED_CALLBACKS_V2'
KIND='CURRENT_ONBOARDING_CLOSED_SOURCE_V3'
MAX_FILE=64*1024**2
MAX_TOTAL=128*1024**2
MAX_FILES=256
STAGES={'backend':350,'ui':374,'lifecycle':372}


def need(value,why):
    if not value:raise ValueError(why)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def encoded(value):return(json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+'\n').encode()


def decode(raw):
    def pairs(items):
        result={}
        for key,value in items:need(key not in result,'duplicate JSON key');result[key]=value
        return result
    def number(value):
        result=float(value);need(math.isfinite(result),'finite JSON number');return result
    result=json.loads(raw,object_pairs_hook=pairs,parse_float=number,
                      parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
    need(type(result)is dict,'JSON object required');return result


def relative(name):
    need(type(name)is str and 0<len(name)<=240 and '\\'not in name,'bounded relative Source name')
    value=PurePosixPath(name)
    need(not value.is_absolute() and str(value)==name and len(value.parts)<=16
         and all(re.fullmatch('[A-Za-z0-9._+-]+',part) and part not in ('.','..')for part in value.parts),'safe Source member')
    return name


def identity(info):return tuple(getattr(info,name)for name in ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))


def read(path,expected=None,cap=MAX_FILE):
    path=Path(path)
    need(path.is_absolute() and path==path.resolve(),'canonical ordinary DATA path')
    parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    fd=None
    try:
        for part in path.parent.parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            os.close(parent);parent=child
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1
                                and 0<before.st_size<=cap and not before.st_mode&0o022,'bounded single-link ordinary DATA')
        chunks=[];size=0
        while block:=os.read(fd,min(1024**2,cap+1-size)):
            chunks.append(block);size+=len(block);need(size<=cap,'whole DATA cap')
        raw=b''.join(chunks)
        need(size==before.st_size and identity(before)==identity(os.fstat(fd))==identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False)),'unchanged whole DATA')
        if expected is not None:need(pin(raw)=={k:expected[k]for k in ('bytes','sha256')},'external whole DATA pin mismatch')
        return raw,stat.S_IMODE(before.st_mode)
    finally:
        if fd is not None:os.close(fd)
        os.close(parent)


def descriptors(files):return{name:dict(pin(raw),mode=mode)for name,(raw,mode)in sorted(files.items())}


def inventory(raw,count):
    result={}
    for line in raw.decode('ascii').splitlines():
        need(re.fullmatch('[a-z0-9][a-z0-9@._+-]* [^\\s]{1,200}',line),'typed expected package row')
        name,version=line.split(' ');need(name not in result,'duplicate inventory name');result[name]=version
    need(len(result)==count and raw==''.join(n+' '+v+'\n'for n,v in sorted(result.items())).encode(),'complete sorted expected inventory')
    return result


def source(root,expected):
    root=Path(root);need(root.is_absolute() and root==root.resolve() and root.is_dir(),'canonical complete Source')
    raw,map_mode=read(root/'source-map.json',cap=1024**2)
    need(map_mode==0o644,'ordinary mode644 Source map')
    need(pin(raw)['sha256']==expected,'external complete Source map hash')
    value=decode(raw);need(value['schema']==1 and value['kind']==KIND and value['operation']==OPERATION
                           and all(item is None for item in value['actual'].values()),'unissued current Source v3')
    alias,alias_mode=read(root/'source.lock.json',cap=1024**2)
    need(alias==raw and alias_mode==0o644,'explicit ordinary byte-identical nonrecursive map/lock aliases')
    rows=value['files'];need(type(rows)is dict and len(rows)+2<=MAX_FILES,'finite Source map')
    found={str(p.relative_to(root))for p in root.rglob('*')if p.relative_to(root).parts[0]!='.git'and(p.is_file()or p.is_symlink())}
    need(found==set(rows)|{'source-map.json','source.lock.json'},'whole closed Source namespace')
    total=2*len(raw)
    for name,row in rows.items():
        relative(name);body,mode=read(root/name)
        need(dict(pin(body),mode=mode)==row and mode in (0o644,0o755),'exact Source body/mode: '+name);total+=len(body)
    need(total<=MAX_TOTAL,'whole Source byte cap')
    program=decode(read(root/PREFIX/'owner-program.json',cap=1024**2)[0])
    need(program['operation']==OPERATION and program['api']==API and program['entrypoint']=='open_current_session' and program['lifecycle_entrypoint']=='launch_lifecycle','fixed current registry ABI')
    for name,row in program['closure'].items():need(name in rows and rows[name]==row,'whole committed owner/route closure')
    need(re.fullmatch('[0-9a-f]{40}',program['closure_commit']) and all(v is None for v in program['actual'].values()),'committed program with no actual grants')
    for role in ('owner','route'):
        entry=program[role];relative(entry['path'])
        need(entry['path'] in program['closure'] and {k:entry[k]for k in ('bytes','sha256')}=={k:rows[entry['path']][k]for k in ('bytes','sha256')},'owner/route pointer belongs to whole committed closure')
    need(program['registry']==dict(path=PREFIX+'/dispatch.py',**{k:rows[PREFIX+'/dispatch.py'][k]for k in ('bytes','sha256')}),'exact emitted registry code pointer')
    for stage,count in STAGES.items():
        lock=read(root/'inputs/stages'/(stage+'.expected.lock'))[0];packages=inventory(lock,count)
        need(program['expected_inventories'][stage]==dict(pin(lock),packages=count),'typed stage lock pin')
        present=set(packages)&{'cachy-asahi-setup','cachy-asahi-first-login','cachy-asahi-repository-enrollment','cachy-asahi-first-login-ui'}
        need(present==({'cachy-asahi-setup'}if stage=='backend'else({'cachy-asahi-setup','cachy-asahi-first-login'}if stage=='ui'else set())), 'stage project dependencies')
    return value,program
