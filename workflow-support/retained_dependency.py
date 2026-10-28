#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Join two exact public input DATA files; unchanged acquisition still verifies GPG."""
import argparse
import hashlib
import json
import math
import re
import types
import os
from pathlib import Path
import stat
import time

HERE = Path(__file__).resolve().parent
NAME = 'archlinux-contrib-20261009-1-any.pkg.tar.xz'
INPUTS = {
    NAME: dict(bytes=24792, sha256='0cda9e6618956615a9065265300af78d1c4b5693bbfe3f6aab7f58b8aa0eeca3'),
    NAME+'.sig': dict(bytes=566, sha256='747683dd22f7264d672919be36e1fa3bc433d8e980d2202927c8b1ec5ad51ff8'),
}
LOCK = '9a8064cde23ad90c2352395bdd1f6f5a8e843b3db3468cd2cc5a90829dc32704'
ACQUIRE = 'd87249d22f1184ee46d7d98db981ae394ae8e72847057b53bfecd778ab970d77'
FIELDS = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
M = 1024**2
ROLE_PROFILE = {'bytes': 332087, 'sha256': '58306d30d5c89053c08c24a1cd6d7a13c0c44f9a91b2a367f251e2c25288b9a7'}
METADATA_HELPER = {'bytes': 3826, 'sha256': '94e612507c49ef619f889eca8e805c9fe2c1b9bbca8dac014573494b46cd7a85'}


def need(ok, why):
    if not ok:
        raise ValueError(why)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def identity(s):
    return {n: getattr(s,n) for n in FIELDS}


def path(value):
    p=Path(value)
    need(p.is_absolute() and str(p)==os.path.normpath(str(p)) and p==p.resolve() and
         not any(v.is_symlink() for v in (p,*p.parents)), 'ordinary absolute path')
    return p


def tick(deadline):
    need(time.monotonic()<deadline, 'bounded exact-input join deadline')


def read(value, deadline, cap=128*M, retain=False):
    tick(deadline); p=path(value)
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        predicates=dict(regular=stat.S_ISREG(before.st_mode),single_link=before.st_nlink==1,
                        current_source_owner=before.st_uid==os.getuid(),bounded_source_bytes=0<=before.st_size<=cap)
        if not all(predicates.values()):
            raise ValueError('SOURCE_INPUT_REFUSED '+json.dumps(dict(role='published-source-or-selected-pair-byte-read',filename=p.name,observed=identity(before),expected=dict(uid=os.getuid(),nlink=1,maximum_bytes=cap),predicates=predicates,failed_predicates=[k for k,v in predicates.items() if not v],payload_read=False,acceptance=False),sort_keys=True,separators=(',',':'),ensure_ascii=True))
        digest=hashlib.sha256(); size=0; parts=[]
        while b:=os.read(fd,65536):
            tick(deadline); size+=len(b); need(size<=before.st_size,'growing input')
            digest.update(b)
            if retain: parts.append(b)
        need(size==before.st_size and identity(before)==identity(os.fstat(fd))==identity(p.lstat()),
             'stable complete FD/path identity and bytes')
        row=dict(bytes=size,sha256=digest.hexdigest(),identity=identity(before))
        return row,b''.join(parts) if retain else None
    finally:
        os.close(fd)


def lock_binding(raw):
    need(pin(raw)['sha256']==LOCK,'unchanged complete five-package dependency lock')
    lock=json.loads(raw); chosen=[v for v in lock['packages'] if v['filename']==NAME]
    need(len(lock['packages'])==5 and len(chosen)==1,'unchanged five-package selection')
    item=chosen[0]
    need((item['name'],item['version'],item['arch'])==('archlinux-contrib','20261009-1','any') and
         dict(bytes=item['size'],sha256=item['sha256'])==INPUTS[NAME] and
         dict(bytes=item['signature_size'],sha256=item['signature_sha256'])==INPUTS[NAME+'.sig'],
         'retained pair matches exact frozen package/version/archive/signature')
    return dict(lock_sha256=LOCK,acquire_sha256=ACQUIRE,package=item['name'],version=item['version'],arch=item['arch'])


def exact_pair(deadline, source=HERE/'dependency-inputs'):
    source=path(source)
    need(source.is_dir() and {p.name for p in source.iterdir()}==set(INPUTS)|{'inputs.lock.json'},
         'closed public archive/signature/frozen-lock namespace')
    bodies={}
    for name,want in INPUTS.items():
        row,body=read(source/name,deadline,65536,True)
        need({k:row[k] for k in ('bytes','sha256')}==want and
             stat.S_IMODE((source/name).stat().st_mode)==0o644,'exact retained public archive/signature')
        bodies[name]=body
    _,raw=read(source/'inputs.lock.json',deadline,M,True); lock_binding(raw)
    need(stat.S_IMODE((source/'inputs.lock.json').stat().st_mode)==0o644,'fixed source lock mode')
    return bodies


def preparation(value, deadline):
    root=path(value); prefix=root/'scripts/ci/full-development-composition/dependencies'
    _,body=read(prefix/'inputs.lock.json',deadline,M,True); binding=lock_binding(body)
    row,_=read(prefix/'acquire.py',deadline,65536)
    need(row['sha256']==ACQUIRE,'unchanged dependency acquisition and GPG flow')
    return binding


def cache_roles(deadline):
    _,raw=read(HERE/'cache-roles.json',deadline,M,True)
    need(pin(raw)==ROLE_PROFILE,'whole finite cache role profile')
    v=json.loads(raw);roles=v['files']
    need(v['schema_version']==1 and v['status']=='EXACT_SOURCE_BOUND_CACHE_ROLES_NOT_AUTHENTICATION' and
         v['prior_files']==1159 and v['selected_files']==2 and v['total_files']==len(roles)==1161 and
         v['selected_pair']==INPUTS and v['acceptance'] is False and v['cleanup_authority'] is False,
         'exact1159 producer roles plus unchanged two selected dependency leaves')
    need(sum(r['bytes']for r in roles.values())==v['total_expected_bytes']==1939322342<=2*1024**3,
         'held original2GiB aggregate bound, no capacity increase')
    for name,row in roles.items():
        need(re.fullmatch(r'[A-Za-z0-9._+@:~-]{1,255}',name) is not None and name not in ('.','..') and
             type(row['bytes']) is int and 0<=row['bytes']<=2*1024**3 and
             re.fullmatch('[0-9a-f]{64}',row['sha256']) is not None,'finite source-declared role/name/size/hash')
    for name,want in INPUTS.items():need({k:roles[name][k]for k in ('bytes','sha256')}==want,'exact selected pair role pins')
    return roles


def metadata_helper(deadline):
    _,raw=read(HERE/'cache_metadata.py',deadline,65536,True)
    need(pin(raw)==METADATA_HELPER,'exact metadata-only role observer source')
    module=types.ModuleType('_retained_dependency_cache_metadata');module.__file__=str(HERE/'cache_metadata.py')
    exec(compile(raw,module.__file__,'exec'),vars(module));return module


def snapshot(cache, deadline):
    roles=cache_roles(deadline);observer=metadata_helper(deadline);cache=path(cache)
    fd=os.open(cache,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        need(stat.S_ISDIR(before.st_mode) and before.st_uid==os.getuid() and
             stat.S_IMODE(before.st_mode)==0o700,'existing current cache-producer-owned0700 directory')
        names=os.listdir(fd);need(len(names)<=2048,'held2048 original cache-entry bound');rows={};total=0
        unknown=sorted(set(names)-set(roles));missing=sorted(set(roles)-set(INPUTS)-set(names))
        if unknown or missing:
            name=(unknown or missing)[0];observed=None
            if unknown:
                leaf=os.open(name,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                try:observed=identity(os.fstat(leaf))
                finally:os.close(leaf)
            raise observer.CacheRefusal(dict(schema_version=1,status='CACHE_ROLE_NAMESPACE_REFUSAL_DATA_ONLY',role='UNKNOWN_CACHE_ROLE'if unknown else roles[name]['role'],filename=name[:128],observed=observed,expected=roles.get(name),failed_predicates=['known_role'if unknown else'present_prior_role'],unknown_count=len(unknown),missing_count=len(missing),payload_read=False,acceptance=False))
        for name in sorted(names):
            tick(deadline);role=roles[name]
            row=observer.probe(fd,name,role=role['role'],expected_size=role['bytes'],producer_binding=ROLE_PROFILE['sha256'],deadline=deadline)
            total+=role['bytes'];need(total<=2*1024**3,'held original2GiB aggregate bound')
            if name in INPUTS:
                observed,_=read(cache/name,deadline,65536)
                need(observed['identity']==row['identity'] and {k:observed[k]for k in ('bytes','sha256')}==INPUTS[name],
                     'existing selected cache pair exact bytes/hash and same identity')
                row['selected_pin']={k:observed[k]for k in ('bytes','sha256')}
            rows[name]=row
        now=os.fstat(fd);late=cache.stat()
        keys=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink')
        need(all(getattr(before,k)==getattr(now,k)==getattr(late,k)for k in keys) and set(os.listdir(fd))==set(names),
             'stable producer directory and entire known-role namespace')
        return rows
    finally:os.close(fd)


def exclusive(value, raw, *, directory_fd=None):
    target=path(value)
    need(directory_fd is None or target.name in INPUTS,'only selected pair creation relative to held cache directory')
    fd=os.open(target if directory_fd is None else target.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,**({}if directory_fd is None else{'dir_fd':directory_fd}))
    with os.fdopen(fd,'wb') as f:
        os.fchmod(f.fileno(),0o600)
        need(f.write(raw)==len(raw),'whole exclusive input write')
        f.flush(); os.fsync(f.fileno())


def join(cache, preparation_root, receipt, deadline, source=HERE/'dependency-inputs'):
    # All pair, caller and existing-cache validation precedes the first new write.
    bodies=exact_pair(deadline,source); source_binding=preparation(preparation_root,deadline)
    cache=path(cache); receipt=path(receipt)
    protected=(HERE,path(source),path(preparation_root))
    need(all(not cache.is_relative_to(p) and not p.is_relative_to(cache) and
             not receipt.is_relative_to(p) and not p.is_relative_to(receipt) for p in protected),
         'cache and receipt disjoint from executable and retained sources')
    need(not os.path.lexists(receipt) and receipt.parent.is_dir() and
         not receipt.is_relative_to(cache) and not cache.is_relative_to(receipt),
         'fresh disjoint exact-input receipt')
    directory_fd=os.open(cache,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    keys=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink')
    anchor={k:getattr(os.fstat(directory_fd),k)for k in keys}
    def check_anchor():
        fdstat=os.fstat(directory_fd);now=cache.lstat()
        if not all(getattr(fdstat,k)==getattr(now,k)==anchor[k]for k in keys):
            raise ValueError('CACHE_DIRECTORY_REFUSED '+json.dumps(dict(role='cache-directory',filename=cache.name,expected=anchor,observed=identity(now),failed_predicates=['same_held_directory'],payload_read=False,acceptance=False),sort_keys=True,separators=(',',':'),ensure_ascii=True))
    try:
        check_anchor();before=snapshot(cache,deadline)
        for name,want in INPUTS.items():
            if name in before:
                need(before[name]['selected_pin']==want,
                     'existing mismatching archive/signature refuses repair or overwrite')
        # A competing writer must cause refusal; never unlink/replace an owned role.
        created=[]
        for name,body in bodies.items():
            tick(deadline);check_anchor()
            if name not in before:
                exclusive(cache/name,body,directory_fd=directory_fd); created.append(name)
        check_anchor();after=snapshot(cache,deadline);check_anchor()
        need(set(after)==set(before)|set(INPUTS),'exact old namespace plus fixed pair only')
        need(all(after[n]==row for n,row in before.items()),
             'all previous inode/mode/producer-owner/link/size/mtime/ctime metadata unchanged')
        need(all(after[n]['selected_pin']==want for n,want in INPUTS.items()),
             'whole exact pair in cache')
        need(exact_pair(deadline,source)==bodies and preparation(preparation_root,deadline)==source_binding,
             'same frozen public inputs and source after cache join')
        result=dict(schema_version=1,status='EXACT_DEPENDENCY_PAIR_JOINED_NOT_AUTHENTICATED',
            source=source_binding,inputs=INPUTS,created=created,retained_existing=len(before),
            all_previous_inode_metadata_unchanged=True,
            prior_body_hash_verification='NOT_PERFORMED_METADATA_ONLY',
            unselected_cache_payload_bytes_read=0,
            write_confinement='ONLY_ABSENT_TWO_SELECTED_ROLE_NAMES_EXCLUSIVE_CREATE',
            cache_role_profile=ROLE_PROFILE,
            cache_directory_identity=anchor,
            metadata_fields=list(FIELDS),before=before,after={n:after[n] for n in INPUTS},
            GPG='UNCHANGED_LATER_ACQUIRE_REQUIRED',native='NOT_RUN',acceptance=False,
            cleanup_authority=False,network='NOT_USED',retry=False)
        tick(deadline)
        exclusive(receipt,(json.dumps(result,sort_keys=True,indent=2)+'\n').encode())
        return result
    finally:os.close(directory_fd)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--check-source',action='store_true')
    p.add_argument('--preparation',type=Path);p.add_argument('--cache',type=Path);p.add_argument('--receipt',type=Path)
    p.add_argument('--seconds',type=float,default=60);a=p.parse_args()
    need(math.isfinite(a.seconds) and 0<a.seconds<=60,'finite source60 bound')
    deadline=time.monotonic()+a.seconds
    if a.check_source:
        need(not any((a.preparation,a.cache,a.receipt)),'source prefix never touches cache or callers')
        exact_pair(deadline);cache_roles(deadline);metadata_helper(deadline)
        result=dict(status='PASS_EXACT_PUBLIC_PAIR_SOURCE_ONLY',inputs=INPUTS,lock_sha256=LOCK,network='NOT_USED',GPG='NOT_RUN',native='NOT_RUN',acceptance=False)
    else:
        need(all((a.preparation,a.cache,a.receipt)),'explicit preparation/cache/fresh receipt')
        result=join(a.cache,a.preparation,a.receipt,deadline)
        result={k:result[k] for k in ('status','inputs','created','retained_existing','all_previous_inode_metadata_unchanged','unselected_cache_payload_bytes_read','GPG','native','acceptance')}
    print(json.dumps(result,sort_keys=True,indent=2))
if __name__=='__main__':main()
