# SPDX-License-Identifier: MIT
"""Observe actual ordinary rootless container runtime, without nested namespaces."""
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


def need(value,why):
    if not value:raise ValueError(why)


def mounts(raw):
    selected={}
    for line in raw.splitlines():
        left,sep,right=line.partition(' - ');parts=left.split();tail=right.split()
        need(sep and len(parts)>=6 and len(tail)==3,'actual complete mountinfo')
        name=parts[4]
        if name not in ('/','/inputs','/work','/tmp','/run'):continue
        need(name not in selected,'unique required runtime mount')
        selected[name]=(set(parts[5].split(',')),tail[0],set(tail[2].split(',')))
    need(set(selected)=={'/','/inputs','/work','/tmp','/run'},'all actual rootless mounts required')
    for name in ('/','/inputs'):need('ro' in selected[name][0] and 'rw' not in selected[name][0],'actual readonly root/inputs')
    need('rw' in selected['/work'][0] and 'ro' not in selected['/work'][0],'actual writable work volume')
    for name,size in [('/tmp',64*1024**2),('/run',8*1024**2)]:
        flags,kind,options=selected[name]
        need(kind=='tmpfs' and {'rw','noexec','nosuid','nodev'}<=flags and 'ro' not in flags and {'uid=1001','gid=1001'}<=options,'actual safe owned tmpfs')
        values=[x[5:] for x in options if x.startswith('size=')];need(len(values)==1,'actual tmpfs size')
        match=re.fullmatch('([1-9][0-9]*)([kKmMgG]?)',values[0]);need(match,'numeric tmpfs size')
        need(int(match[1])*{'':1,'k':1024,'m':1024**2,'g':1024**3}[match[2].lower()]==size,'actual exact tmpfs size')


def validate(entry,parent):
    limits={'cpu.max':'200000 100000','memory.max':'4294967296','memory.swap.max':'0','pids.max':'256'}
    for value in (entry,parent):
        need(all(value[k]==1001 for k in ('uid','euid','gid','egid')) and value['architecture']=='aarch64' and value['page_bytes'] in (4096,16384),'actual native alarm1001 runtime')
        need(value['limits']==limits and value['interfaces']==['lo'] and value['hostname']=='perl5423-native','actual resources/network/hostname')
        need(all(int(value['status'][k],16)==0 for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')) and value['status']['NoNewPrivs']=='1','actual cap0/NNP process')
        need(set(value['namespaces'])=={'user','mnt','net','pid'} and all(re.fullmatch(k+r':\[[1-9][0-9]{0,19}\]',v) for k,v in value['namespaces'].items()),'actual literal container namespaces')
        for key in ('uid_map','gid_map'):
            rows=value[key];need(0<len(rows)<=8,'bounded actual credential maps')
            for row in rows:need(len(row)==3 and all(type(n) is int and 0<=n<2**32 for n in row) and row[2]>0 and row[0]+row[2]<=2**32 and row[1]+row[2]<=2**32,'nonoverflowing actual maps')
            for index in (0,1):
                ordered=sorted(rows,key=lambda row:row[index]);need(all(a[index]+a[2]<=b[index] for a,b in zip(ordered,ordered[1:])),'nonoverlapping actual maps')
        mounts(value['mountinfo'])
    need(entry['pid']>1 and entry['ppid']==parent['pid']==1 and 0<parent['starttime']<=entry['starttime'],'actual direct init/entry process lineage')
    need(entry['cmdline']==['/usr/bin/python3','-I','-B','/inputs/entry.py'] and re.fullmatch(r'/usr/bin/python3(?:\.[0-9]{1,2})?',entry['exe']) and entry['cwd']=='/work/recipe','actual fixed Python entry')
    need(Path(parent['exe']).name in ('docker-init','tini') and parent['cmdline'][-5:]==['--','/usr/bin/bash','--noprofile','--norc','/inputs/entry.sh'],'actual injected init launcher')
    need(all(entry[k]==parent[k] for k in ('namespaces','uid_map','gid_map','groups','cgroup')),'actual init/entry domain continuity')
