#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Future finite installed CLI probe; private PID/proc and empty sysfs only.

No actor starts on import. Every child transfers its exclusive wait ownership to
an exact installed copy of the existing owned_process implementation. There is
no namespace fallback, performance comparison, physical sensor or M2 acceptance.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys

NAME='cachy-asahi-measurement-tools'
FIXED=Path('/opt/native-measurement-tools-alpm-v1')
OWNER_SHA='83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f'
SCHEMA='cachy-asahi-platform-metrics-v1'
STATUS='PASS_FINITE_PRIVATE_PID_EMPTY_SYSFS_INSTALLED_PROBE'
MAX_FILE=128*1024
MAX_TOTAL=512*1024


def need(ok,why):
    if not ok:raise ValueError(why)


def encoded(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def natural(state,expected):
    need(type(state)is dict and {'exit','reaped','ownership','group_census','output_complete','timeout','signals','error','passed','seconds'}<=set(state) and type(state.get('exit'))is int and state['exit']==expected
         and state.get('reaped')is True and state.get('ownership')=='REAPED'
         and state.get('group_census')=='EMPTY_TWICE' and state.get('output_complete')is True
         and state.get('passed')is True and type(state.get('seconds'))in(int,float)and 0<=state['seconds']<20 and state.get('timeout')is False and state.get('signals')==[] and state.get('error')is None,
         'probe requires exact natural owned retirement')


def ordinary(path,cap=MAX_FILE):
    path=Path(path);need(path.is_absolute()and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary probe DATA path')
    fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<=before.st_size<=cap,'bounded single-link probe DATA')
        raw=b''
        while block:=os.read(fd,min(65536,cap+1-len(raw))):raw+=block;need(len(raw)<=cap,'probe DATA size')
        fields=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        need(len(raw)==before.st_size and fields(before)==fields(os.fstat(fd))==fields(path.lstat()),'probe DATA changed')
        return raw
    finally:os.close(fd)


def sandbox(root):
    root=Path(root)
    return ['/usr/bin/bwrap','--die-with-parent','--ro-bind','/','/','--bind',str(root),str(root),
            '--dev','/dev','--tmpfs','/sys','--unshare-net','--unshare-pid','--proc','/proc','--']


def probe_commands(cli,root):
    cli,root=Path(cli),Path(root);helper=FIXED/'source/native/measurement_installed_probe_v2.py'
    return [('namespace',['/usr/bin/python3','-I','-B',str(helper),'--namespace-check'],0),
      ('state',[str(cli),'state','--execution-context','unknown','--output',str(root/'base.json')],0),
      ('prepare-plan',[str(cli),'benchmark','prepare-plan','--config',str(root/'config.json'),'--baseline',str(root/'base.json'),'--candidate-state',str(root/'candidate.json'),'--output',str(root/'plan.json')],0),
      ('trial',[str(cli),'benchmark','run','--plan',str(root/'plan.json'),'--slot','0','--state',str(root/'base.json'),'--conditions',str(root/'conditions.json'),'--cwd',str(root),'--output',str(root/'trial'),'--platform-metrics'],0),
      ('capture',[str(cli),'metrics','capture','--machine-label','finite private empty-sysfs probe','--duration','.2','--interval','.1','--output',str(root/'capture')],0),
      ('summarize',[str(cli),'metrics','summarize','--capture',str(root/'capture'),'--output',str(root/'replay.json')],0)]


def namespace_check():
    pid=os.getpid();fd=os.open('/proc/self/stat',os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
    try:raw=os.read(fd,4097)
    finally:os.close(fd)
    need(0<len(raw)<=4096,'bounded private proc self stat')
    need(raw.split(b' ',1)[0]==str(pid).encode()and not list(Path('/sys').iterdir()),'actual private proc self and empty sysfs')
    return dict(pid=pid,proc_self_pid=pid,pid_namespace=os.readlink('/proc/self/ns/pid'),sysfs_entries=[])


def run(cli,root,label,report=None):
    report={}if report is None else report
    report.update(schema=2,status='FAIL',cli=str(cli),root=str(root),label=label,phase='initialize',commands=[],files={},optimization_acceptance='NOT RUN',performance='NOT_MEASURED',physical_M2='NOT_RUN',release='NOT_ADMITTED')
    cli,root=Path(cli),Path(root)
    expected_cli=Path('/usr/bin')/NAME if label=='system'else FIXED/'user-data/moved-prefix/usr/bin'/NAME
    expected_root=FIXED/'user-data'/('system'if label=='system'else'relocated')/'probe'
    need(label in('system','moved')and cli==expected_cli and root==expected_root and not root.exists()
         and root.parent.is_dir()and os.getuid()==os.geteuid()!=0 and sys.flags.isolated and sys.dont_write_bytecode,
         'fixed fresh ordinary-user isolated installed probe only')
    root.mkdir(mode=0o700)
    prefix=cli.parent.parent;docs=prefix/'share/doc'/NAME;runtime=prefix/'lib/cachy-asahi/measurement-tools-v1/scripts'
    owner_path=runtime/'virtual/owned_process.py';need(pin(ordinary(owner_path))['sha256']==OWNER_SHA,'exact installed owned-process implementation')
    spec=importlib.util.spec_from_file_location('measurement_probe_owned_process',owner_path);owner=importlib.util.module_from_spec(spec);spec.loader.exec_module(owner)
    config=json.loads(ordinary(docs/'experiment.example.json'));config['argv']=['/usr/bin/python3',str(docs/'smoke_workload.py')];config['inputs']=list(config['argv'])
    (root/'config.json').write_bytes(encoded(config));(root/'conditions.json').write_bytes(ordinary(docs/'conditions.example.json'))
    commands=report['commands'];outer_namespace=os.readlink('/proc/self/ns/pid');namespace=None
    for step,args,expected in probe_commands(cli,root):
        report['phase']=step;argv=sandbox(root)+args
        row=dict(step=step,argv=argv,expected=expected,supervision=None,output_base64='',output_pin=pin(b''));commands.append(row)
        owner.prepare();child=None
        previous=signal.getsignal(signal.SIGTERM)
        def cancel(number,frame):raise KeyboardInterrupt('finite installed probe cancellation')
        signal.signal(signal.SIGTERM,cancel)
        try:
            try:
                child=subprocess.Popen(argv,cwd=root,env={'PATH':'/usr/bin:/bin','HOME':str(root),'LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1'},stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
                state=owner.supervise(child,cap=20,retirement=1.0,grace=0.2,max_output=32*1024)
            except BaseException as first:
                # Only a child never accepted by supervise still permits transfer.
                # UNKNOWN ownership disables _child_created in the held owner.
                if child is not None and child.returncode is None and child._child_created:
                    try:
                        retired=owner.supervise(child,cap=2,retirement=1.0,grace=0.2,max_output=32*1024);output=retired.pop('output')
                        row.update(supervision=retired,output_base64=base64.b64encode(output).decode('ascii'),output_pin=pin(output),fallback_retirement=True)
                    except BaseException as cleanup:row['retirement_failure_type']=type(cleanup).__name__
                raise first
        finally:signal.signal(signal.SIGTERM,previous)
        output=state.pop('output');row.update(supervision=state,output_base64=base64.b64encode(output).decode('ascii'),output_pin=pin(output))
        natural(state,expected)
        if step=='namespace':
            namespace=json.loads(output);need(namespace['pid_namespace']!=outer_namespace,'actual distinct private PID namespace')
        elif step=='state':(root/'candidate.json').write_bytes(ordinary(root/'base.json'))
    report['phase']='artifact-closure';files=report['files'];total=0
    for path in sorted(root.rglob('*')):
        if path.is_dir():continue
        raw=ordinary(path);total+=len(raw);need(len(files)<32 and total<=MAX_TOTAL,'finite installed probe artifact closure')
        files[path.relative_to(root).as_posix()]=dict(pin(raw),base64=base64.b64encode(raw).decode('ascii'))
    report=dict(schema=2,status=STATUS,cli=str(cli),root=str(root),label=label,helper_sha256=pin(ordinary(Path(__file__).resolve()))['sha256'],owner_sha256=OWNER_SHA,
      outer_pid_namespace=outer_namespace,namespace=namespace,commands=commands,files=files,
      comparison=dict(status='INCOMPLETE',scope='NOT_EXECUTED_ONLY_ONE_OF_TWELVE_SLOTS'),
      optimization_acceptance='NOT RUN',workload='ONE_OWNED_PRIVATE_PID_SLOT_ONLY',sensors='EMPTY_SYSFS_NO_PHYSICAL_SENSOR_OBSERVATION',performance='NOT_MEASURED',physical_M2='NOT_RUN',release='NOT_ADMITTED')
    need(len(encoded(report))<=1024**2,'finite complete probe log')
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cli',type=Path);p.add_argument('--root',type=Path);p.add_argument('--label',choices=('system','moved'));p.add_argument('--namespace-check',action='store_true');a=p.parse_args()
    report={}
    try:value=namespace_check()if a.namespace_check else run(a.cli,a.root,a.label,report)
    except BaseException as error:
        # Preserve the first phase and every attempted bounded raw command. No
        # artifact scan, process probe, second wait or signal occurs on this path.
        value=dict(report,status='FAIL',first_failure=dict(phase=report.get('phase','namespace-check'),type=type(error).__name__))
        sys.stdout.buffer.write(encoded(value));return 2
    sys.stdout.buffer.write(encoded(value));return 0


if __name__=='__main__':raise SystemExit(main())
