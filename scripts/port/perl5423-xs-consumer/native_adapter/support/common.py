# SPDX-License-Identifier: MIT
"""Finite source/admission DATA guards; no authority is created by local hashes."""
import hashlib
from contextlib import contextmanager
import signal
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat

ROOT=Path(__file__).resolve().parent
MAX_JSON=1024**2


def need(ok,why):
    if not ok:raise ValueError(why)


def encode(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def path(value):
    p=Path(value)
    need(p.is_absolute() and '..' not in p.parts and not any(c in str(p) for c in '\0\n\r,:') and not any(x.is_symlink() for x in (p,*p.parents)),'ordinary absolute path required')
    return p


def read(value,limit=MAX_JSON):
    p=path(value);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=limit,'bounded single-link DATA required')
        data=bytearray()
        while chunk:=os.read(fd,min(65536,limit+1-len(data))):
            data.extend(chunk);need(len(data)<=limit,'DATA byte bound')
        key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        need(len(data)==before.st_size and key(before)==key(os.fstat(fd))==key(p.lstat()),'DATA changed during read')
        return bytes(data)
    finally:os.close(fd)


def decode(raw):
    need(type(raw) is bytes and len(raw)<=MAX_JSON,'bounded JSON bytes')
    def pairs(rows):
        out={}
        for k,v in rows:need(k not in out,'duplicate JSON key');out[k]=v
        return out
    def invalid(value):raise ValueError('nonfinite JSON')
    def real(value):
        f=float(value);need(math.isfinite(f),'finite JSON number');return f
    try:value=json.loads(raw,object_pairs_hook=pairs,parse_constant=invalid,parse_float=real)
    except RecursionError as error:raise ValueError('JSON depth') from error
    stack=[(value,0)];count=0
    while stack:
        item,depth=stack.pop();count+=1;need(depth<=32 and count<=100000,'JSON structure bound')
        if isinstance(item,dict):stack.extend((v,depth+1) for v in item.values())
        elif isinstance(item,list):stack.extend((v,depth+1) for v in item)
    return value


def load(name,file):
    spec=importlib.util.spec_from_file_location(name,file);module=importlib.util.module_from_spec(spec)
    import sys
    sys.modules[name]=module;spec.loader.exec_module(module);return module


def helper(name):
    expected=decode(read(ROOT/'helper-pins.json'))[name];file=ROOT/'helpers'/name
    need(pin(read(file,1024**2))==expected,'pinned helper changed')
    return load('perl_native_'+name.replace('.','_'),file)


def sha(value,size=64):return type(value) is str and re.fullmatch('[0-9a-f]{'+str(size)+'}',value) is not None


def natural(row,zero=True):
    return (row.get('natural_exit') is True and row.get('forced_cleanup') is False
        and row.get('retirement')=='REAPED' and row.get('group_absent') is True
        and row.get('leader_held_until_group_inspection') is True and row.get('ownership_lost') is False
        and row.get('exit_observed_via_waitpid') is True and type(row.get('exit')) is int and (not zero or row['exit']==0))


class Cancelled(BaseException):pass


@contextmanager
def cancellation_scope():
    cancelled=[False]
    previous={sig:signal.getsignal(sig) for sig in (signal.SIGINT,signal.SIGTERM)}
    def request(number,frame):cancelled[0]=True
    try:
        for sig in previous:signal.signal(sig,request)
        yield cancelled
    finally:
        for sig,handler in previous.items():signal.signal(sig,handler)


def check_cancelled(cancelled):
    if cancelled[0]:raise Cancelled('Root cancellation requested')


def qualification(q,a,c):
    keys={'schema','kind','status','source','run','job','image','domain_sha256','source_readback_sha256','native_daemon_identity_sha256','input_signature_audit_sha256','expected349_sha256','nested_invocation','nested_qualification','nested_diagnostic'}
    need(type(q) is dict and set(q)==keys and type(q['schema']) is int and q['schema']==2
        and q['kind']=='ROOT_NATIVE_CONTAINER_ADMISSION_V2' and q['status']=='ROOT_ADMITTED_CONTAINER_PRECONDITIONS','actual Root container precondition admission required')
    need(q['source']==a['source']['sha'] and q['source']!=c['namespace']['Source3937'],'same fresh Root-published adapter Source required')
    need(all(q[k]==a[k] for k in ('run','job','image','domain_sha256','input_signature_audit_sha256','expected349_sha256')),'container precondition binding mismatch')
    need(all(sha(q[k]) for k in ('source_readback_sha256','native_daemon_identity_sha256')),'Root Source readback and actual daemon identity proofs required')
    need(q['nested_invocation']=='NOT_INVOKED' and q['nested_qualification']=='NOT_QUALIFIED','unused nested namespace feature remains unqualified')
    row=q['nested_diagnostic']
    need(row is None or type(row) is dict and set(row)=={'bytes','sha256'} and type(row['bytes']) is int and 0<row['bytes']<=65536 and sha(row['sha256']),'bounded separate diagnostic DATA descriptor')


def admission(a,q,c):
    need(c['schema']==2 and c['operation']=='perl5423-native-pair-v2' and c['namespace']['build_requires_nested_namespaces'] is False
        and c['namespace']['nested_invocation']=='NOT_INVOKED' and c['namespace']['nested_qualification']=='NOT_QUALIFIED','ordinary rootless container premise v2 required')
    need(a['schema']==2 and a['operation']==c['operation'] and sha(a['source']['sha'],40)
        and type(a['source']['ref']) is str and re.fullmatch(r'codex/[A-Za-z0-9._/-]+',a['source']['ref']),'actual Root Source binding required')
    need(all(type(a[k]) is str and re.fullmatch('[1-9][0-9]{0,19}',a[k]) for k in ('run','job')),'actual run/job binding required')
    need(all(sha(a[k]) for k in ('approval','source_map_sha256','qualification_sha256','input_signature_audit_sha256')),'Root approval/map/signature/container-admission bindings required')
    need(type(a['image']) is str and re.fullmatch('sha256:[0-9a-f]{64}',a['image']),'fresh immutable native image binding')
    need(a['domain_sha256']==c['domain_sha256']==pin(encode(c['domain']))['sha256'] and a['expected349_sha256']==c['expected349_sha256'],'fixed native domain/inventory binding')
    qualification(q,a,c)


def diagnostic(q,filename):
    row=q['nested_diagnostic']
    need((filename is None)==(row is None),'separate diagnostic operand/descriptor mismatch')
    if row is None:return None
    raw=read(filename,65536)
    need(pin(raw)==row and type(decode(raw)) is dict,'whole bounded separate namespace diagnostic DATA')
    return raw


def source(root,expected):
    root=path(root);raw=read(root/'source-map.json');need(pin(raw)['sha256']==expected,'Root-bound complete adapter Source map')
    m=decode(raw);need(m['schema']==1 and m['actual']==dict(source=None,ref=None,run=None,job=None,approval=None,artifact=None,image=None),'proposed Source selectors remain NULL')
    files=m['files'];need(type(files) is dict and 1<=len(files)<=80,'finite complete source map')
    nodes=list(root.rglob('*'));need(len(nodes)<=320,'finite Source node count')
    need(all(not p.is_symlink() and (p.is_dir() or p.is_file()) for p in nodes),'ordinary alias-free complete Source')
    found={str(p.relative_to(root)) for p in nodes if p.is_file()}
    directories={str(p.relative_to(root)) for p in nodes if p.is_dir()}
    expected_directories={str(parent) for name in set(files)|{'source-map.json'} for parent in Path(name).parents if str(parent)!='.'}
    need(directories==expected_directories,'no empty/unrecorded Source directories')
    need(found==set(files)|{'source-map.json'},'complete Source namespace differs')
    total=0
    for name,row in files.items():
        need(type(name) is str and re.fullmatch('[A-Za-z0-9._+/-]+',name) and all(x not in ('','.','..') for x in name.split('/')),'relative Source leaf')
        p=path(root/name);body=read(p,32*1024**2);total+=len(body)
        need(pin(body)=={k:row[k] for k in ('bytes','sha256')} and stat.S_IMODE(p.stat().st_mode)==row['mode'],'source leaf bytes/mode changed')
    need(total<=48*1024**2,'complete Source byte bound')
    return m


def inspect_actor(row,image,volume,inputs,c):
    h,x=row['HostConfig'],row['Config'];d=c['domain']
    need(row['Image']==image and x['User']==d['user'] and x['Hostname']==d['hostname'],'actual actor identity')
    need(h['NanoCpus']==2000000000 and h['Memory']==h['MemorySwap']==4294967296 and h['PidsLimit']==256,'actual actor resources')
    need(h['NetworkMode']=='none' and h['ReadonlyRootfs'] is True and h['Init'] is True and h['CapDrop']==['ALL'] and not h.get('CapAdd') and h['SecurityOpt']==['no-new-privileges'] and not h['Privileged'] and not h.get('Devices') and not h.get('DeviceRequests'),'actual actor isolation profile')
    mounts={m['Destination']:m for m in row['Mounts']}
    need(set(mounts)=={'/inputs','/work'} and len(row['Mounts'])==2,'exact actor mount namespace')
    need(mounts['/inputs']['Type']=='bind' and not mounts['/inputs']['RW'] and mounts['/inputs']['Source']==str(inputs),'exact readonly snapshot')
    need(mounts['/work']['Type']=='volume' and mounts['/work']['RW'] and mounts['/work']['Name']==volume,'exact owned work volume')
    need(h['Tmpfs']==d['tmpfs'],'exact tmpfs resource/security profile')
