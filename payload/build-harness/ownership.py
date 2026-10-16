#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read held ALPM file ownership; never install, remove or query a subprocess."""
import hashlib,re
from pathlib import Path
import stat
import time

LOCK='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
HELD='2.43+r22+g8362e8ce10b2-2'
# Exact held574 archives contain only .PKGINFO/.BUILDINFO/.MTREE for these packages.
FILELESS={'base':'3-3','base-devel':'1-2','ca-certificates':'20240618-1','dbus-units':'37-3',
          'gcc-libs':'16.1.1+r12+g301eb08fa2c5-1','linux-firmware':'20260916-1'}


def need(ok,why):
    if not ok:raise ValueError(why)


def read(path,limit):
    need(not any(p.is_symlink() for p in (path,*path.parents)), 'ordinary ALPM evidence path required')
    info=path.stat();need(stat.S_ISREG(info.st_mode) and info.st_size<=limit,'bounded ALPM file required')
    raw=path.read_bytes();need(len(raw)<=limit,'ALPM file cap');return raw


def blocks(raw):
    result={};key=None
    for line in raw.decode('utf-8','strict').splitlines():
        if line.startswith('%') and line.endswith('%'):
            need(line not in result,'duplicate ALPM field');key=line;result[key]=[]
        elif line:
            need(key is not None,'ALPM field required');result[key].append(line)
    return result


def check(database,lock,payload):
    database=Path(database).absolute();lock=Path(lock).absolute()
    need(not any(p.is_symlink() for p in (database,*database.parents)),'ordinary ALPM database required')
    raw=read(lock,65536)
    need(hashlib.sha256(raw).hexdigest()==LOCK and len(raw.splitlines())==574,'exact held574 inventory required')
    expected=dict(line.split(' ',1) for line in raw.decode().splitlines())
    need(len(expected)==574 and expected.get('glibc')==HELD,'exact held glibc baseline required')
    entries=sorted(database.iterdir());need(len(entries)==575 or len(entries)==574,'bounded held574 database required')
    seen={};collisions={};removed=0;total=0;deadline=time.monotonic()+30
    for directory in entries:
        if directory.name=='ALPM_DB_VERSION':
            need(re.fullmatch(b'[1-9][0-9]{0,3}\n?',read(directory,16)),'bounded ALPM DB version required');continue
        need(time.monotonic()<deadline and directory.is_dir() and not directory.is_symlink(),'bounded ordinary ALPM package directory required')
        desc=blocks(read(directory/'desc',65536))
        name,version=desc.get('%NAME%',[]),desc.get('%VERSION%',[])
        need(len(name)==len(version)==1 and name[0] not in seen and expected.get(name[0])==version[0],'held package DB identity differs')
        name=name[0];seen[name]=version[0]
        raw=read(directory/'files',4*1024**2);total+=len(raw);need(total<=64*1024**2,'aggregate ALPM file bound')
        # ALPM serializes a genuinely fileless package with a zero-byte files record.
        paths=[] if raw==b'' and FILELESS.get(name)==seen[name] else blocks(raw).get('%FILES%')
        need(paths is not None and len(paths)<=200000,'bounded ALPM file list required: '+name+' '+seen[name])
        for path in paths:
            need(path and not path.startswith('/') and all(p not in ('','.','..') for p in path.rstrip('/').split('/')),'canonical ALPM payload path required')
            if path.endswith('/') or path not in payload:continue
            if name=='glibc':removed+=1
            else:collisions.setdefault(path,[]).append(name)
    need(seen==expected,'complete exact574 ALPM ownership scan required')
    need(not collisions,'provider collides with held package ownership: '+repr(sorted(collisions.items())[:16]))
    return dict(status='PASS_HELD574_PROVIDER_FILE_OWNERSHIP',inventory_sha256=LOCK,
                checked_packages=len(seen),replaced_owner='glibc',replaced_version=HELD,
                overlapping_removed_glibc_paths=removed,other_owner_collisions=collisions,
                scope='archive ownership only; no dependency transaction or installed lifecycle credit')
