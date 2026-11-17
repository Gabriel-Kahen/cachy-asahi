#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Exact5415 verifier successor: stateless public-key inspection only."""
import ast
import hashlib
import os
from pathlib import Path
import stat

HERE=Path(__file__).resolve().parent
FROZEN=HERE.parent/'verify.py'
PIN=dict(bytes=27132,sha256='be6c793d39975f044a5626650f5ed641e0a4df2f809fe0a13524e73499018dc5')
BEFORE="'--no-default-keyring', '--keyring', '/proc/self/fd/' + str(binary.fd), '--no-auto-check-trustdb'"
AFTER="'--no-keyring', '--trust-model', 'always', '--no-auto-check-trustdb'"
OLD_ROOT='ROOT = HERE.parents[2]'
NEW_ROOT='ROOT = HERE.parents[3]'


def need(ok,message):
    if not ok:raise ValueError(message)


def frozen():
    need(FROZEN==FROZEN.resolve()and not any(p.is_symlink()for p in(FROZEN,*FROZEN.parents)),'ordinary frozen verifier path')
    fd=os.open(FROZEN,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_size==PIN['bytes'],'whole ordinary frozen verifier')
        raw=os.read(fd,PIN['bytes']+1)
        identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        need(identity(before)==identity(os.fstat(fd))==identity(FROZEN.lstat())and dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())==PIN,'unchanged whole5415 verifier')
        return raw
    finally:os.close(fd)


def project(raw):
    need(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())==PIN,'whole exact predecessor only')
    text=raw.decode();need(text.count(BEFORE)==text.count(OLD_ROOT)==1 and AFTER not in text and NEW_ROOT not in text,'two exact stateless inspection/path seams')
    text=text.replace(BEFORE,AFTER).replace(OLD_ROOT,NEW_ROOT)
    need(text.replace(AFTER,BEFORE).replace(NEW_ROOT,OLD_ROOT).encode()==raw,'whole frozen verifier inverse')
    ast.parse(text);return text.encode()


def load():
    namespace=dict(__name__='minimal206_stateless_public_verifier',__file__=str(HERE/'verify.py'))
    exec(compile(project(frozen()),str(HERE/'verify.py'),'exec'),namespace)
    return namespace


if __name__=='__main__':
    raise SystemExit(load()['main']())
