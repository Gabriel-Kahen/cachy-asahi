#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite ordinary observation of only the run's controller startup cgroup."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

WATCH_SECONDS=24
SAMPLE_SECONDS=.05
GROUP='/system.slice/cachy-python3148-controller-'
STAMP='startup-phase.json'
RESULTS={'oom-kill','signal','timeout','exit-code','resources','success','unavailable'}
PHASES=('owner-python-entry','imports-complete','admission-verified','controller-domain-verified',
        'output-created','host-context','host-tools-probe','host-tools-ready','storage-reservation',
        'loop-attached','daemon-starting','raw-input-staging','native349-inputs-staged',
        'python-inputs-staged','ordinary-owner-starting',
        'payload-terminal','owner-finalizing','retirement-writing')
FILES={
    'memory.current':None, 'memory.peak':None, 'memory.max':None, 'pids.current':None,
    'memory.events.local':('low','high','max','oom','oom_kill','oom_group_kill'),
    'memory.events':('low','high','max','oom','oom_kill','oom_group_kill'),
    'pids.events':('max',), 'cgroup.events':('populated','frozen'),
}


def need(ok,message):
    if not ok:
        raise ValueError(message)


def ordinary(path,cap=16384):
    need(path.is_absolute() and path==path.resolve(),'canonical startup observation path')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as source:
        info=os.fstat(source.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and 0<info.st_size<=cap,
             'bounded ordinary startup evidence')
        body=source.read(cap+1)
    need(len(body)==info.st_size,'whole startup evidence')
    return json.loads(body)


def atomic(path,value,mode=0o400):
    partial=path.with_name(path.name+'.partial')
    fd=os.open(partial,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
    with os.fdopen(fd,'w') as stream:
        os.fchmod(stream.fileno(),mode)
        json.dump(value,stream,sort_keys=True);stream.write('\n')
    os.replace(partial,path)


def phase(value,out=None):
    need(value in PHASES,'fixed Python owner phase')
    print('PYTHON3148_CONTROLLER_PHASE='+value,file=sys.stderr,flush=True)
    if out is not None:
        info=out.lstat()
        need(out==out.resolve() and stat.S_ISDIR(info.st_mode) and info.st_uid==0
             and stat.S_IMODE(info.st_mode)==0o711,'same fresh root owner output for safe phase marker')
        atomic(out/STAMP,{'phase':value},0o644)


def group(run):
    need(isinstance(run,str) and re.fullmatch('[1-9][0-9]{1,19}',run),'exact positive hosted run ID')
    return GROUP+run+'-1.scope'


def parse(raw,keys):
    raw=raw.decode('ascii').strip()
    if keys is None:
        need(re.fullmatch('[0-9]{1,20}',raw),'bounded numeric cgroup counter')
        return int(raw)
    rows={}
    for line in raw.splitlines():
        key,value=line.split()
        if key in keys:
            need(key not in rows and re.fullmatch('[0-9]{1,20}',value),'bounded finite cgroup counter fields')
            rows[key]=int(value)
    return rows


def counters(path):
    try:
        root=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    except OSError:
        return None
    result={}
    try:
        for name,keys in FILES.items():
            try:
                fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=root)
                with os.fdopen(fd,'rb') as stream:
                    body=stream.read(4097)
                need(len(body)<=4096,'bounded single kernel counter')
                result[name]=parse(body,keys) if body.strip() else None
            except (OSError,ValueError,UnicodeError):
                result[name]=None
    finally:
        os.close(root)
    return result


def fold(previous,submitted):
    for name,observed in submitted.items():
        if observed is None:
            continue
        if name=='cgroup.events':
            previous[name]=observed
        elif isinstance(observed,dict):
            target=previous.setdefault(name,{})
            for key,amount in observed.items():
                target[key]=max(target.get(key,0),amount)
        else:
            previous[name]=max(previous.get(name,0),observed)


def watch(run,out,read=counters,clock=time.monotonic,sleep=time.sleep):
    need(os.geteuid()==os.getuid()>0 and out==out.resolve() and out.is_dir()
         and out.stat().st_uid==os.getuid() and stat.S_IMODE(out.stat().st_mode)==0o700,
         'private ordinary startup observer and no root')
    expected=group(run)
    path=Path('/sys/fs/cgroup'+expected)
    deadline=clock()+WATCH_SECONDS
    kept={}
    count=0
    atomic(out/'armed.json',{'cgroup':expected})
    while clock()<deadline:
        result=read(path)
        if result is not None:
            count+=1
            fold(kept,result)
            atomic(out/'sample.json',{'cgroup':expected,'seen':count,'maximum':kept})
        if (out/'done').exists():
            break
        sleep(SAMPLE_SECONDS)


def diagnose(run,out,owner,status,result):
    expected=group(run)
    need(type(status) is int and 0<=status<=255 and result in RESULTS,'finite controller wrapper outcome')
    ready=ordinary(out/'armed.json')
    need(ready=={'cgroup':expected},'same exact controller watcher')
    sample_path=out/'sample.json'
    snapshot=ordinary(sample_path) if sample_path.exists() else {'cgroup':expected,'seen':0,'maximum':{}}
    need(snapshot['cgroup']==expected and type(snapshot['seen']) is int and 0<=snapshot['seen']<=500
         and set(snapshot['maximum'])<=set(FILES),'whole bounded ordinary startup observer')
    last=None
    if not owner.is_symlink() and os.access(owner/STAMP,os.R_OK):
        last=ordinary(owner/STAMP)['phase']
        need(last in PHASES,'literal last owner startup marker')
    events=snapshot['maximum']
    observed=events.get('memory.events.local',{}).get('oom_kill',0)
    rationale='UNDETERMINED'
    if observed:
        rationale='SCOPED_CGROUP_OOM_KILL_RECORDED'
    elif result=='oom-kill':
        rationale='SYSTEMD_REPORTED_OOM_KILL'
    atomic(out/'startup.json',{'kind':'PYTHON3148_STARTUP_SCOPE_OBSERVATION_V1','run':run,'attempt':1,
           'cgroup':expected,'exit':status,'systemd_result':result,'last_owner_phase':last,'scope':snapshot,
           'kill_evidence':rationale,'Root_acceptance':None})


def validate(receipt,run):
    need(receipt['kind']=='PYTHON3148_STARTUP_SCOPE_OBSERVATION_V1' and receipt['run']==run and receipt['attempt']==1
         and receipt['cgroup']==receipt['scope']['cgroup']==group(run) and receipt['Root_acceptance'] is None
         and receipt['last_owner_phase'] in (None,*PHASES) and receipt['systemd_result'] in RESULTS
         and type(receipt['exit']) is int and 0<=receipt['exit']<=255
         and type(receipt['scope']['seen']) is int and 0<=receipt['scope']['seen']<=500,
         'exact same startup observation, present or explicitly missing')
    maxima=receipt['scope']['maximum']
    need(set(maxima)<=set(FILES),'only literal kernel counter names')
    for name,value in maxima.items():
        keys=FILES[name]
        counters=(value,) if keys is None else value.values()
        need((keys is None or set(value)<=set(keys))
             and all(type(n) is int and 0<=n<10**20 for n in counters),'exact bounded numerical counter fields')
    expected='UNDETERMINED'
    if maxima.get('memory.events.local',{}).get('oom_kill',0):
        expected='SCOPED_CGROUP_OOM_KILL_RECORDED'
    elif receipt['systemd_result']=='oom-kill':
        expected='SYSTEMD_REPORTED_OOM_KILL'
    need(receipt['kill_evidence']==expected,'reported OOM claim requires a positive exact event')


def main():
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument('mode',choices=('watch','diagnose'))
    cli.add_argument('--run',required=True)
    cli.add_argument('--output',type=Path,required=True)
    cli.add_argument('--owner',type=Path)
    cli.add_argument('--status',type=int)
    cli.add_argument('--result',choices=sorted(RESULTS))
    args=cli.parse_args()
    if args.mode=='watch':
        watch(args.run,args.output)
    else:
        diagnose(args.run,args.output,args.owner,args.status,args.result)


if __name__=='__main__':
    main()
