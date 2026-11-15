# SPDX-License-Identifier: MIT
"""One externally Root-bound device54 seam; no discovery, lease or role entry."""
import ast
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat

LOCK=Path('/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261025/shared-GUI-ancestor-collection.lock')
HELPER=LOCK.parent.parent/'diagnostics54-root-once-helper-development-20261027/root_once.py'
HELPER_SHA='4f9a5b7242e0cc9f66230ccd2d2b82e4460bef0ee38a7d343b1ee8c774c521d2'
EXACT=dict(path=str(LOCK),dev=54,inode=59258250,uid=1000,gid=1000,mode=420,nlink=1,bytes=0,
           mtime_ns=1792920106392345934,ctime_ns=1792920106392345934)


def need(ok, why):
    if not ok: raise ValueError(why)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def obj(raw):
    def pairs(rows):
        out={}
        for key,value in rows:
            need(key not in out,'duplicate runtime54 JSON key');out[key]=value
        return out
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite runtime54 DATA'))


def state(s):
    return tuple(getattr(s,n) for n in ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))


def read(path):
    path=Path(path)
    need(path!=LOCK,'shared lock is never a DATA operand')
    need(path.is_absolute() and path==path.resolve() and not any(p.is_symlink() for p in (path,*path.parents)), 'canonical runtime54 DATA path')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=65536,'bounded ordinary runtime54 DATA')
        with os.fdopen(os.dup(fd),'rb') as stream:raw=stream.read(65537)
        need(len(raw)==before.st_size and state(before)==state(os.fstat(fd))==state(path.lstat()),'stable whole runtime54 DATA')
        return raw
    finally:os.close(fd)


def profile(value):
    need(type(value)is dict and set(value)=={'schema','issuer','status','approved','attested_at','identity','resource_authority','lock_mutation'},'exact finite Root runtime54 profile schema')
    need(value['schema']==1 and type(value['schema'])is int and value['issuer']=='Root' and value['approved']is True and
         value['status']=='ROOT_BOUND_EXACT_EXISTING_LOCK_RUNTIME54','Root runtime54 profile unissued; HOLD')
    need(value['identity']==EXACT and all(type(value['identity'][k])is type(v) for k,v in EXACT.items()),'only literal runtime54 full identity')
    need(value['resource_authority']is False and value['lock_mutation']is False,'identity attestation grants no resource authority or lock mutation')
    need(type(value['attested_at'])is str,'Root independent attestation timestamp required')
    when=datetime.fromisoformat(value['attested_at'])
    need(when.utcoffset() is not None and 0<=(datetime.now(timezone.utc)-when).total_seconds()<=3600,'fresh<=3600s Root runtime54 attestation')
    return value


def binding(path, reference_pin=None):
    raw=read(path)
    if reference_pin is not None:need(pin(raw)==reference_pin,'unchanged sealed runtime54 reference pin')
    value=obj(raw)
    need(type(value)is dict and set(value)=={'path','bytes','sha256'} and type(value['path'])is str and
         type(value['bytes'])is int and 0<value['bytes']<=65536 and type(value['sha256'])is str,'Root runtime54 profile binding unissued; HOLD')
    raw=read(Path(value['path']))
    need(pin(raw)=={k:value[k] for k in ('bytes','sha256')},'whole external Root runtime54 profile pin')
    return profile(obj(raw))


def adapted(raw):
    need(pin(raw)['sha256']==HELPER_SHA,'whole held HTTP helper before finite literal inverse')
    nodes=[n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name=='lock_identity']
    need(len(nodes)==1,'one held HTTP lock predicate')
    old=ast.get_source_segment(raw.decode(),nodes[0]);need(old.count('(52,59258250)')==1,'one exact historical52 literal seam')
    new=old.replace('(52,59258250)','(54,59258250)',1)
    need(new.replace('(54,59258250)','(52,59258250)',1)==old,'exact inverse restores original predicate bytes')
    return new


def factory(path, reference_pin):
    # The packet input index fixes the reference, which fixes the external profile.
    reference_pin=dict(reference_pin);binding(path,reference_pin)
    def runtime_lock_identity(U):
        need(U.LOCK==LOCK,'only canonical existing shared lock')
        namespace=dict(vars(U));exec(compile(adapted(U.read(HELPER)),'<Root-bound-finite-runtime54>','exec'),namespace)
        base=namespace['lock_identity']
        def identity(fd):
            expected=binding(path,reference_pin)['identity']
            result=base(fd);s=os.fstat(fd)
            actual=dict(path=str(U.canonical(U.LOCK)),dev=s.st_dev,inode=s.st_ino,uid=s.st_uid,gid=s.st_gid,
                        mode=stat.S_IMODE(s.st_mode),nlink=s.st_nlink,bytes=s.st_size,mtime_ns=s.st_mtime_ns,ctime_ns=s.st_ctime_ns)
            need(actual==expected and state(s)==state(U.LOCK.lstat()),'exact Root-attested runtime54 owner/time/FD/path identity unchanged')
            return result
        return identity
    return runtime_lock_identity
