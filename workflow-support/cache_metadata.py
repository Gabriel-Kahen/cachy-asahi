# SPDX-License-Identifier: MIT
"""Integration fragment: fixed-role cache stat proof, never payload authentication.

Caller must derive roles from already-pinned producer locks and validate the
complete cache namespace around the two exclusive writes. This is not a catalog
loader or an authorization interface. Published-source read() stays unchanged.
"""
import json
import os
import re
import stat
import time

FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
ROLES={'base-keyring-role','base-rootfs-role','compiler6-package-role','desktop574-package-role','selected-cache-dependency-role'}


def identity(s):
    return {n:getattr(s,n) for n in FIELDS}


class CacheRefusal(ValueError):
    def __init__(self,record):
        self.record=record
        text=json.dumps(record,sort_keys=True,separators=(',',':'),ensure_ascii=True)
        if len(text.encode('ascii'))>2048:
            raise ValueError('bounded cache diagnostic envelope')
        super().__init__('CACHE_ENTRY_REFUSED '+text)


def diagnostic(name,s,*,role,stage,expected_size,expected_uid,producer_binding):
    tests=dict(regular=stat.S_ISREG(s.st_mode),single_link=s.st_nlink==1,
               owner_matches_producer=s.st_uid==expected_uid,
               exact_declared_size=s.st_size==expected_size)
    return dict(schema_version=1,status='CACHE_ENTRY_REFUSAL_DATA_ONLY',
                role=role,filename=name,stage=stage,observed=identity(s),
                expected=dict(kind='regular',nlink=1,uid=expected_uid,bytes=expected_size),
                predicates=tests,failed_predicates=[n for n,v in tests.items() if not v],
                producer_binding=producer_binding,payload_read=False,
                payload_authentication='NOT_PERFORMED',acceptance=False)


def probe(directory_fd,name,*,role,expected_size,producer_binding,deadline):
    """Metadata-only known-role leaf, with current coordinator as producer UID.

    No global root/foreign UID list. Do not call for any producer whose exact
    implementation does not establish coordinator-owned ordinary single-link
    cache outputs. Such a role remains unbound and needs diagnostics/new trial.
    """
    if not (type(name)is str and name and name not in('.', '..') and '/'not in name
            and '\0'not in name and len(os.fsencode(name))<=255):
        raise ValueError('bounded single-component cache role name')
    if not (role in ROLES and type(expected_size)is int and 0<=expected_size<=2*1024**3
            and type(producer_binding)is str and re.fullmatch('[0-9a-f]{64}',producer_binding)
            and time.monotonic()<deadline):
        raise ValueError('fixed pinned producer role/size/binding/deadline required')
    if not hasattr(os,'O_PATH'):
        raise ValueError('Linux O_PATH required; no payload-open fallback')
    fd=os.open(name,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory_fd)
    try:
        before=os.fstat(fd)
        row=diagnostic(name,before,role=role,stage='metadata-probe',
                       expected_size=expected_size,expected_uid=os.getuid(),
                       producer_binding=producer_binding)
        if row['failed_predicates']:
            raise CacheRefusal(row)
        after=os.stat(name,dir_fd=directory_fd,follow_symlinks=False)
        if identity(before)!=identity(os.fstat(fd)) or identity(before)!=identity(after):
            raise ValueError('cache role FD/path identity changed')
        if time.monotonic()>=deadline:
            raise ValueError('metadata-only cache role deadline')
        return dict(identity=identity(before),role=role,producer_binding=producer_binding,
                    expected_size=expected_size,payload_read=False,
                    payload_authentication='NOT_PERFORMED')
    finally:
        os.close(fd)
