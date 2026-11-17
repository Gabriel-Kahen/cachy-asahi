#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Real owned local child/PIDFD plus explicit MODEL unit/cgroup retirement control.

No systemd, cgroup mutation, Root role, shared lease, network or native actor.
"""
import importlib.util
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import tempfile

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
F=module(HERE/'failed_retirement.py','local_v3_pidfd_retirement')
O=module(ROOT/'scripts/virtual/owned_process.py','local_v3_owned_child');O.prepare()
CODE="import sys; sys.stdin.buffer.read(1); raise SystemExit(2)"
child=None;fd=None;released=False

def limit():
    resource.setrlimit(resource.RLIMIT_AS,(128*1024**2,128*1024**2));resource.setrlimit(resource.RLIMIT_CPU,(2,2));resource.setrlimit(resource.RLIMIT_CORE,(0,0))

def denied(event,args):
    if event.startswith('socket.')or event in('os.system','fcntl.flock'):raise RuntimeError('no network/shell/shared lease in local control')
    if event=='subprocess.Popen'and args[1]!=[sys.executable,'-I','-B','-c',CODE]:raise RuntimeError('only exact small owned local child')
sys.addaudithook(denied)
try:
    child=subprocess.Popen([sys.executable,'-I','-B','-c',CODE],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True,preexec_fn=limit)
    fd=os.pidfd_open(child.pid,0);identity=F.pidfd_identity(fd)
    fields=Path('/proc/'+str(child.pid)+'/stat').read_text().rpartition(')')[2].split();start=int(fields[19]);assert not F.pidfd_exited(fd,identity)
    nonce='a'*32;unit='cachy-llhttp-reference-'+nonce+'-owner.service';group='/system.slice/'+unit
    owned=dict(submitted=True,pid=child.pid,starttime=start,cgroup=group,original_pidfd=fd,original_pidfd_identity=identity)
    row=dict(Description='cachy-llhttp-reference-owned-'+nonce+'-owner',LoadState='loaded',ActiveState='failed',SubState='failed',MainPID='0',ControlGroup='',Result='exit-code',ExecMainCode='1',ExecMainStatus='2')
    censuses=[dict(cgroup=group,path_present=False,events_empty=True,procs_empty=True,pidfd_exited=True)for _ in range(2)]
    try:F.retire_failed('owner',nonce,owned,row,row,fd,censuses)
    except ValueError:pass
    else:raise AssertionError('live original process must refuse even if MODEL unit rows claim failed')
    child.stdin.write(b'X');child.stdin.close();released=True
    retirement=O.supervise(child,cap=5,retirement=.5,grace=.1,streams=(),max_output=0);retirement.pop('output',None)
    assert retirement['exit']==2 and retirement['reaped']and retirement['ownership']=='REAPED'and retirement['group_census']=='EMPTY_TWICE'and not retirement['signals']and not retirement['timeout']and retirement['error']is None
    assert F.pidfd_exited(fd,identity)
    with tempfile.TemporaryDirectory(prefix='llhttp-v3-empty-cgroup-MODEL-',dir='/home/gabe')as name:
        path=Path(name);(path/'cgroup.events').write_bytes(b'populated 0\nfrozen 0\n');(path/'cgroup.procs').write_bytes(b'')
        snapshots=[dict(cgroup=group,pidfd_exited=F.pidfd_exited(fd,identity),**F.empty_snapshot(path))for _ in range(2)]
        result=F.retire_failed('owner',nonce,owned,row,row,fd,snapshots);assert result['payload_success']is False and result['payload_exit']==2 and result['unit_reset']is False
    bad=dict(identity,inode=identity['inode']+1)
    try:F.pidfd_exited(fd,bad)
    except ValueError:pass
    else:raise AssertionError('foreign/replaced original PIDFD identity must refuse')
    os.close(fd);closed=fd;fd=None
    try:F.pidfd_exited(closed,identity)
    except (OSError,ValueError):pass
    else:raise AssertionError('closed/unknown descriptor must refuse')
    print(json.dumps(dict(status='PASS_LOCAL_PROCESS_PIDFD_PLUS_SYNTHETIC_UNIT_CONTROL_ONLY',retirement=retirement,service_rows='MODEL_ONLY_NOT_SYSTEMD',cgroup_files='MODEL_ONLY_NOT_KERNEL',result=result,Root_role='NOT RUN',native_pair='NOT RUN'),sort_keys=True))
finally:
    if child is not None and child.returncode is None:
        if not released and child.stdin and not child.stdin.closed:child.stdin.close()
        O.supervise(child,cap=5,retirement=.5,grace=.1,streams=(),max_output=0)
    if fd is not None:os.close(fd)
