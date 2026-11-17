#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actor-free fixed-author Source196→205 DATA reconstruction.

CI setup separately proves the author Git commit/tree and exports the immutable
Source196 input before this boundary. No Git operation or Source role runs here.
"""
import argparse
import ctypes  # Initialize only the standard module before the actor fence.
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from types import ModuleType

HERE=Path(__file__).resolve().parent
CODE_ROOT=HERE.parents[3]
READER=HERE.parent/'payload/native/reader_current_v3.py'
AUTHOR_REVISION='9e26ce819a258225cac866341e15d7099038ab9e'
AUTHOR_TREE='2e14459be57b26ac7657f302c3d614bea301a13a'
FAMILY='scripts/ci/first-login-enrollment-native-source'
PREFIX=FAMILY+'/successor_v7_source'
ACTOR_ATTEMPTS=[]


def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.spawn','os.posix_spawn','os.fork')) or event in (
            'os.system','fcntl.flock','resource.setrlimit'):
        ACTOR_ATTEMPTS.append(event)
        raise RuntimeError('Source205 DATA reconstruction denies actor: '+event)


sys.dont_write_bytecode=True
sys.addaudithook(fence)


def need(condition,message):
    if not condition:raise ValueError(message)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def identity(info):
    return tuple(getattr(info,name)for name in('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))


def directory(path):
    path=Path(path)
    need(path.is_absolute()and path==path.resolve()and '..'not in path.parts,'canonical existing DATA directory required')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            os.close(fd);fd=child
        return fd
    except BaseException:
        os.close(fd);raise


def read(path,expected=None,*,cap=2*1024**2):
    path=Path(path)
    need(path.is_absolute()and path==path.resolve(),'canonical nonaliased DATA leaf required')
    parent=directory(path.parent);fd=None
    try:
        fd=os.open(path.name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=cap,'ordinary bounded single-link DATA leaf required')
        with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(cap+1)
        need(len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))==
             identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False)),'stable whole DATA leaf required')
        mode=stat.S_IMODE(before.st_mode)
        if expected is not None:need(dict(pin(raw),mode=mode)==expected,'fixed author/current DATA body or mode differs')
        return raw,mode
    finally:
        if fd is not None:os.close(fd)
        os.close(parent)


def module(name,path,raw):
    value=ModuleType(name);value.__file__=str(path)
    exec(compile(raw,str(path),'exec'),value.__dict__)
    return value


def checked_author(author):
    """Verify all five selected operands before importing the fixed constructor."""
    author=Path(author);fd=directory(author);os.close(fd)
    reader_raw,_=read(READER)
    reader=module('_ci_source205_trusted_reader',READER,reader_raw)
    need(reader.TRANSPORT_COMMIT==AUTHOR_REVISION,'trusted Reader fixed author differs')
    need(set(reader.TRANSPORT_CONSTRUCTION)=={PREFIX+'/prepare.py',PREFIX+'/README.md'}
         and set(reader.TRANSPORT_REPLACEMENTS)==set(reader.TRANSPORT_OPERANDS)
         =={'materials_stager','material_domain_executor','hosted_launcher'},'fixed five author operands required')
    construction={Path(name).name:read(author/name,row)for name,row in reader.TRANSPORT_CONSTRUCTION.items()}
    for name,row in reader.TRANSPORT_CONSTRUCTION.items():
        need(read(HERE/Path(name).name,row)==construction[Path(name).name],
             'executing constructor/README must equal selected fixed author')
    operands={role:read(author/reader.TRANSPORT_OPERANDS[role],dict(reader.whole(row),mode=0o644))
              for role,row in reader.TRANSPORT_REPLACEMENTS.items()}
    constructor=module('_ci_source205_fixed_constructor',HERE/'prepare.py',construction['prepare.py'][0])
    need(constructor.OPERANDS==reader.TRANSPORT_OPERANDS and constructor.REPLACEMENTS==reader.TRANSPORT_REPLACEMENTS,
         'constructor operands must equal trusted Reader whole pins')
    return constructor,reader,reader_raw,operands,construction


def disjoint(a,b):return a!=b and not a.is_relative_to(b)and not b.is_relative_to(a)


def destination(path,inputs):
    path=Path(path)
    need(path.is_absolute()and path==path.resolve()and '..'not in path.parts and path.name not in('','.','..'),
         'canonical fresh output leaf required')
    need(not os.path.lexists(path)and all(disjoint(path,root)for root in inputs),'fresh output outside input DATA required')
    parent=directory(path.parent)
    try:
        info=os.fstat(parent)
        need(info.st_uid==os.getuid()and not info.st_mode&0o022,'owned output parent without foreign writes required')
    finally:os.close(parent)
    return path


def verify(reader,reader_raw,constructor,files,profile):
    _,_,_,_,C,H=constructor.load_helpers()
    wanted=reader.TRANSPORT_SOURCE
    need(dict(files=len(files),bytes=sum(len(v[0])for v in files.values()),tree=H.tree(files),
              source_map=C.pin(files['source-map.json'][0]))==wanted,'exact genuine Source205 tuple required')
    program=reader.receipt(files[PREFIX+'/program.json'][0])
    need(reader.pin(files[PREFIX+'/program.json'][0])==reader.TRANSPORT_PROGRAM_PIN,'exact Source205 registry required')
    need(profile['transport_commit']==AUTHOR_REVISION and all(value is None for value in profile['actual'].values()),
         'external Source205 profile must remain unissued DATA')
    need(profile['files']==wanted['files']and profile['bytes']==wanted['bytes']
         and profile['prospective_tree']==wanted['tree']and profile['source_map']==wanted['source_map']
         and profile['program']==dict(path=PREFIX+'/program.json',**reader.TRANSPORT_PROGRAM_PIN),
         'external Source205 profile must join exact constructed DATA')
    opaque={name:raw for name,(raw,_)in files.items()}
    paths=dict(profile=FAMILY+'/successor_v2/profile.json',program=PREFIX+'/program.json',
               **{role:program['roles'][role]['member']for role in('policy','retention','encoder')})
    selection=dict(source_lock_pin=C.pin(files['source.lock.json'][0]),binding=dict(source_lock=C.pin(files['source.lock.json'][0])),
        source={role:dict(path=name,**C.pin(opaque[name]))for role,name in paths.items()},
        fingerprint=reader.SELECTED_TEST_FINGERPRINT,resources=dict(build_seconds=180,builder_cpus=4,
            builder_memory_bytes=4294967296,builder_pids=512,total_seconds=1800,command_rows=512),
        reader_pin=reader.pin(reader_raw),stage='backend')
    # These are Reader DATA selectors, never an issued Root delegation or runtime.
    _,checked,_=reader.source_data(selection,opaque,delegated=True)
    need(checked==program,'trusted Reader must accept the exact opaque Source205 program')


def reconstruct(author,basis,output,profile_path):
    author,basis=Path(author),Path(basis)
    for root in(author,basis):fd=directory(root);os.close(fd)
    output=destination(output,(author,basis,CODE_ROOT))
    profile_path=destination(profile_path,(author,basis,CODE_ROOT))
    need(disjoint(output,profile_path),'external profile must remain outside closed Source')
    constructor,reader,reader_raw,operands,construction=checked_author(author)
    files=constructor.load_basis(basis)
    candidate,profile=constructor.rebind(files,operands,commit=AUTHOR_REVISION,constructor_files=construction)
    verify(reader,reader_raw,constructor,candidate,profile)
    _,_,_,P,C,_=constructor.load_helpers()
    P.publish(candidate,output)
    raw=(json.dumps(profile,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    parent=directory(profile_path.parent);fd=None
    try:
        info=os.fstat(parent)
        need(info.st_uid==os.getuid()and not info.st_mode&0o022,'owned profile parent without foreign writes required')
        fd=os.open(profile_path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o644,dir_fd=parent)
        with os.fdopen(fd,'wb')as stream:fd=None;stream.write(raw);os.fchmod(stream.fileno(),0o644)
    finally:
        if fd is not None:os.close(fd)
        os.close(parent)
    need(read(profile_path,dict(pin(raw),mode=0o644))[0]==raw,'whole exclusive external profile differs')
    need(ACTOR_ATTEMPTS==[],'actor attempt observed during DATA reconstruction')
    return dict(status='PASS_GENUINE_SOURCE205_DATA_RECONSTRUCTION',source=reader.TRANSPORT_SOURCE,
        constructor_revision=AUTHOR_REVISION,required_setup_author_tree=AUTHOR_TREE,
        Git_identity_proved_inside_control=False,profile=pin(raw),actors=[],
        Root_authentication=False,Root_acceptance=None,native_acceptance=False,hardware_acceptance=False,release_acceptance=False)


def main():
    need(sys.flags.isolated and sys.dont_write_bytecode and __debug__,'isolated unoptimized DATA bootstrap required')
    parser=argparse.ArgumentParser(description=__doc__)
    for name in('author-data','basis','output','profile'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(reconstruct(args.author_data,args.basis,args.output,args.profile),sort_keys=True,indent=2))


if __name__=='__main__':main()
