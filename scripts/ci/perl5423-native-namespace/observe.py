# SPDX-License-Identifier: MIT
"""Read fixed Linux process/runtime surfaces; importing performs no observations."""
import os
from pathlib import Path
import re
import socket

STATUS=('CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs','Seccomp','Seccomp_filters')
LIMITS=('cpu.max','memory.max','memory.swap.max','pids.max')


def bounded(path,cap):
    with open(path,'rb',buffering=0) as stream:raw=stream.read(cap+1)
    if len(raw)>cap:raise ValueError('bounded observation exceeded: '+str(path))
    return raw


def context(pid=None):
    selected=os.getpid() if pid is None else pid
    if type(selected) is not int or selected<=0:raise ValueError('concrete observed process')
    proc=Path('/proc')/str(selected)
    before=bounded(proc/'stat',4096).decode();fields=before.rpartition(') ')[2].split()
    status=bounded(proc/'status',16384).decode();rows={}
    for line in status.splitlines():
        key,sep,value=line.partition(':')
        if sep:rows[key]=value.strip()
    maps={}
    for name in ('uid_map','gid_map'):
        raw=bounded(proc/name,4096).decode();parsed=[line.split() for line in raw.splitlines()]
        if not(0<len(parsed)<=8 and all(len(r)==3 and all(re.fullmatch('[0-9]{1,10}',n) for n in r) for r in parsed)):raise ValueError('finite actual identity map')
        maps[name]=[[int(v) for v in r] for r in parsed]
    uids=[int(v) for v in rows['Uid'].split()];gids=[int(v) for v in rows['Gid'].split()];groups=[int(v) for v in rows['Groups'].split()]
    if len(groups)>32:raise ValueError('complete bounded groups')
    argv=bounded(proc/'cmdline',8192).split(b'\0');argv=argv[:-1] if argv[-1]==b'' else argv
    result=dict(pid=selected,ppid=int(fields[1]),pgrp=int(fields[2]),session=int(fields[3]),starttime=int(fields[19]),uid=uids[0],euid=uids[1],gid=gids[0],egid=gids[1],groups=groups,
        architecture=os.uname().machine,page_bytes=os.sysconf('SC_PAGE_SIZE'),cwd=os.readlink(proc/'cwd'),exe=os.readlink(proc/'exe'),cmdline=[v.decode() for v in argv],
        namespaces={key:os.readlink(proc/'ns'/key) for key in ('user','mnt','net','pid')},**maps,status={key:rows[key] for key in STATUS},
        limits={key:bounded(Path('/sys/fs/cgroup')/key,128).decode().strip() for key in LIMITS},cgroup=bounded(proc/'cgroup',4096).decode(),
        mountinfo=bounded(proc/'mountinfo',128*1024).decode(),interfaces=sorted(p.name for p in Path('/sys/class/net').iterdir()),hostname=socket.gethostname())
    after=bounded(proc/'stat',4096).decode().rpartition(') ')[2].split()
    if fields[19]!=after[19] or fields[1]!=after[1]:raise ValueError('process identity/parent changed during observation')
    return result
