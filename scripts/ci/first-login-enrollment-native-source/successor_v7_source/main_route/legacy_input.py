# SPDX-License-Identifier: MIT
"""One attested historical Main test operand; never a production route fallback."""
import hashlib
import json
import os
from pathlib import Path
import stat
from types import ModuleType

HERE=Path(__file__).resolve().parent
DECLARATION=dict(schema=1,kind='PINNED_HISTORICAL_HOSTED_V6_TEST_INPUT',
    author_commit='441832e1d687255434c9001d603d400e4932f26a',
    author_tree='eff62e7fbc7e3170a67aecd80c4997ee7b4f77b4',
    original_member='scripts/ci/first-login-enrollment-native-source/payload/native/hosted_current_v3.py',
    git_blob='c3f33d0022809edcb4fcf5a81294e5822b7662ac',
    fixture_member='scripts/ci/first-login-enrollment-native-source/successor_v7_source/main_route/legacy/hosted_v6.py',
    body=dict(bytes=66263,sha256='f8387c748f31698b45656998248f099a8207bb58f7f9d7e70ef53a73be286d97',mode=0o644),
    scope='TEST_ONLY_LEGACY_MAIN_SELECTORS',production_route=False,Root_authority=None)


def identity(info):
    return tuple(getattr(info,name)for name in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))


def read(path,size):
    if path!=path.resolve()or any(p.is_symlink()for p in(path,*path.parents)):
        raise ValueError('ordinary historical test operand required')
    fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode)or before.st_nlink!=1 or before.st_size!=size or stat.S_IMODE(before.st_mode)!=0o644:
            raise ValueError('exact historical test operand metadata required')
        with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(size+1)
        if len(raw)!=size or identity(before)!=identity(os.fstat(fd))or identity(before)!=identity(path.lstat()):
            raise ValueError('stable whole historical test operand required')
        return raw
    finally:os.close(fd)


def checked():
    expected=(json.dumps(DECLARATION,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    if read(HERE/'legacy/provenance.json',len(expected))!=expected:
        raise ValueError('exact historical test provenance required')
    path=HERE/'legacy/hosted_v6.py';row=DECLARATION['body'];raw=read(path,row['bytes'])
    if hashlib.sha256(raw).hexdigest()!=row['sha256']or hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()!=DECLARATION['git_blob']:
        raise ValueError('whole historical Main test body differs')
    return path,raw


def hosted_path():return checked()[0]
def hosted_bytes():return checked()[1]


def load_hosted(name):
    path,raw=checked();value=ModuleType(name);value.__file__=str(path)
    exec(compile(raw,str(path),'exec'),value.__dict__)
    return value
