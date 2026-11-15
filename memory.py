# SPDX-License-Identifier: MIT
"""Fixed bounded cgroup-v2 numeric DATA; no process or quota operations."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import stat
import time

STAGES=('before-vm','at-qemu-exit','final')
EVENTS={'low','high','max','oom','oom_kill','oom_group_kill','sock_throttled'}
COUNTERS=('memory.peak','memory.current','memory.max','memory.swap.current','memory.swap.max')


def need(ok,why):
    if not ok:raise ValueError(why)


def number(text):
    need(re.fullmatch('[0-9]{1,20}',text) is not None and int(text)<=2**64-1,'bounded cgroup number required');return int(text)


def validate(value,nonce,stage,limit):
    need(type(value.get('schema')) is int and value['schema']==1 and value.get('nonce')==nonce and value.get('stage')==stage and stage in STAGES and value.get('source')=='fixed cgroup-v2 numeric DATA' and value.get('status') in ('OBSERVED','REFUSED'),'exact memory receipt identity required')
    need(type(value.get('utc_ns')) is int and 0<value['utc_ns']<2**64,'bounded memory receipt epoch')
    need(set(value)<={'schema','nonce','stage','source','status','utc_ns','memory.events','error_category'}|set(COUNTERS),'closed memory receipt fields')
    events=value.get('memory.events',{})
    need(type(events) is dict and set(events)<=EVENTS and all(type(n) is int and 0<=n<2**64 for n in events.values()),'bounded memory events')
    need(all(type(value[n]) is int and 0<=value[n]<2**64 for n in COUNTERS if n in value),'bounded memory counters')
    if value['status']=='OBSERVED':
        need(set(COUNTERS)<=set(value) and {'low','high','max','oom','oom_kill'}<=set(events) and value['memory.max']==limit and value['memory.swap.max']==0,'actual exact owner memory/no-swap limit required')
    else:need(re.fullmatch('[A-Za-z]{1,64}',value.get('error_category','')) is not None,'bounded diagnostic refusal category')
    return value


def snapshot(work,nonce,stage,limit,cgroup=Path('/sys/fs/cgroup')):
    need(stage in STAGES and re.fullmatch('[0-9a-f]{32}',nonce) is not None,'fixed memory receipt stage/nonce')
    value=dict(schema=1,nonce=nonce,stage=stage,source='fixed cgroup-v2 numeric DATA',utc_ns=time.time_ns(),status='OBSERVED');failure=None
    def read(name):
        fd=os.open(cgroup/name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            raw=os.read(fd,4097);need(len(raw)<=4096,'bounded cgroup DATA');return raw.decode('ascii').strip()
        finally:os.close(fd)
    try:
        events={}
        for line in read('memory.events').splitlines():
            key,text=line.split();need(key in EVENTS and key not in events,'closed unique memory events');events[key]=number(text)
        value['memory.events']=events
        for name in COUNTERS:value[name]=number(read(name))
        validate(value,nonce,stage,limit)
    except (OSError,ValueError) as error:
        failure=error;value.update(status='REFUSED',error_category=type(error).__name__)
    raw=(json.dumps(value,indent=2,sort_keys=True)+'\n').encode();work=Path(work)
    need(len(raw)<=16384 and work.is_dir() and not work.is_symlink(),'bounded owned memory receipt destination')
    directory=os.open(work,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        fd=os.open('memory-'+stage+'.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
        try:
            with os.fdopen(fd,'wb',closefd=False) as stream:os.fchmod(fd,0o600);stream.write(raw);stream.flush();os.fsync(fd)
        finally:os.close(fd)
        os.fsync(directory)
    finally:os.close(directory)
    if failure is not None:raise failure
    return value


@contextmanager
def receipts(work,nonce,limit):
    try:
        snapshot(work,nonce,'before-vm',limit)
        yield
    finally:snapshot(work,nonce,'final',limit)


def collect(work,nonce,limit):
    result={}
    for stage in STAGES:
        p=Path(work)/('memory-'+stage+'.json')
        if not p.exists():continue
        info=p.lstat();need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o600 and info.st_size<=16384,'private ordinary bounded memory receipt')
        fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            raw=os.read(fd,16385);need(len(raw)<=16384,'bounded memory receipt read')
        finally:os.close(fd)
        def pairs(rows):
            out={}
            for key,item in rows:need(key not in out,'duplicate memory JSON field');out[key]=item
            return out
        result[stage]=validate(json.loads(raw,object_pairs_hook=pairs),nonce,stage,limit)
    return result
