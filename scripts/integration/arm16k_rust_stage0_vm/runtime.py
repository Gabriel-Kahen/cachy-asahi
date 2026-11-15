# SPDX-License-Identifier: MIT
"""Thin fixed-operation adapter; unchanged frozen primitive owns the final reap."""
from contextlib import contextmanager
import importlib.util
import json
import math
import os
from pathlib import Path
import resource
import shutil
import signal
import stat
import subprocess
import time

HERE=Path(__file__).resolve().parent
_DOCKER_SEQUENCE=0


def module(name):
    spec=importlib.util.spec_from_file_location('rust_vm_'+name,HERE/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


@contextmanager
def transport(authority):
    K=module('contracts');endpoint=K.endpoint(authority)
    previous={k:os.environ.get(k) for k in ('DOCKER_HOST','DOCKER_CONTEXT')}
    try:
        os.environ['DOCKER_HOST']=endpoint;os.environ.pop('DOCKER_CONTEXT',None)
        yield
    finally:
        for key,value in previous.items():
            if value is None:os.environ.pop(key,None)
            else:os.environ[key]=value


def natural(row):
    return row.get('passed') is True and row.get('reaped') is True and row.get('ownership')=='REAPED' and row.get('exit')==0 and row.get('group_census')=='EMPTY_TWICE' and row.get('output_complete') is True and row.get('signals')==[] and row.get('timeout') is False and row.get('error') is None and not row.get('command_cancelled') and not row.get('command_timed_out') and not row.get('original_budget_overrun') and not row.get('emergency_retirement')


def allocated(root,deadline=None):
    """Bounded lstat allocation census, including links without following them."""
    root=Path(root)
    if not root.is_absolute() or '..' in root.parts or any(p.is_symlink() for p in (root,*root.parents)) or not root.is_dir():raise ValueError('ordinary watched root required')
    count=0;total=root.lstat().st_blocks*512;pending=[root]
    while pending:
        current=pending.pop()
        with os.scandir(current) as entries:
            for entry in entries:
                if deadline is not None and time.monotonic()>=deadline:raise TimeoutError('allocation census work budget exhausted')
                info=entry.stat(follow_symlinks=False);count+=1
                if count>150000:raise ValueError('allocation census node bound')
                total+=info.st_blocks*512
                if stat.S_ISDIR(info.st_mode):pending.append(Path(entry.path))
    return total


def _cleaning_handlers(previous):
    """Deferred signals are permitted only through the active cleanup owner."""
    for handler in previous.values():
        owner=getattr(handler,'__self__',None)
        if not callable(handler) or owner is None or getattr(owner,'cleaning',False) is not True or type(getattr(owner,'pending',None)) is not list:
            raise ValueError('defer_cancel requires active bound cleanup Cancellation handlers')


def _retired(row,defer_cancel=False):
    code=row.get('exit')
    return type(code) is int and 0<=code<=255 and row.get('passed') is (code==0) and row.get('reaped') is True and row.get('ownership')=='REAPED' and row.get('group_census')=='EMPTY_TWICE' and row.get('output_complete') is True and row.get('signals')==[] and row.get('timeout') is False and row.get('error') is None and not row.get('command_timed_out') and not row.get('original_budget_overrun') and not row.get('emergency_retirement') and (defer_cancel or not row.get('command_cancelled'))


def command(argv,out,label,seconds=30,deadline=None,input_file=None,*,child_file_size_cap=None,watched_tree=None,defer_cancel=False,check=True,completed=False):
    """Fixed child with watched files/tree; WNOWAIT never reaps.

    Default return remains combined stdout/stderr bytes. completed=True returns
    CompletedProcess with separate byte streams; check=False permits natural
    nonzero exits, never forced/unknown retirement. Cleanup-only defer_cancel
    forwards pending signals to the prior cleanup owner after restoring handlers.
    A child held past its original budget gets one <=0.5s emergency retirement
    handoff. This cannot extend work or pass: overrun/emergency fields force HOLD.
    The caller reserves this tail inside its outer Root cleanup/report envelope.
    """
    K=module('contracts');O=K.helper('owned_process.py');started=time.monotonic()
    K.need(type(seconds) in (int,float) and math.isfinite(seconds) and seconds>0 and (deadline is None or type(deadline) in (int,float) and math.isfinite(deadline)),'finite command deadline required')
    cap=seconds if deadline is None else min(seconds,deadline-started);K.need(cap>3,'command/retirement budget exhausted');end=started+cap;work_end=end-2.5
    K.need(type(argv) in (list,tuple) and argv and all(type(x) is str and '\0' not in x for x in argv),'literal argv required')
    K.need(type(label) is str and label and all(c.isalnum() or c in '-_' for c in label),'literal command receipt label required')
    if child_file_size_cap is not None:
        K.need(argv[0]=='/usr/bin/qemu-system-aarch64' and type(child_file_size_cap) is int and 0<child_file_size_cap<=512*1024**2,'file-size cap is only for the fixed QEMU overlay writer')
    watch=None
    if watched_tree is not None:
        K.need(type(watched_tree) in (tuple,list) and len(watched_tree)==3,'fixed watched allocation tuple required')
        root,bound,reserve=watched_tree
        K.need(type(bound) is type(reserve) is int and bound>0 and reserve>=0,'finite watched allocation/reserve required');watch=(Path(root),bound,reserve)
    signals={signal.SIGINT,signal.SIGTERM};previous={n:signal.getsignal(n) for n in signals};pending=[];child=None;failure=None;row={};data=b'';stdout_data=stderr_data=b'';last_watch=[None]
    if defer_cancel:_cleaning_handlers(previous)
    def census(force=False):
        if watch is None:return
        now=time.monotonic()
        if force or last_watch[0] is None or now-last_watch[0]>=.5:
            root,bound,reserve=watch
            size=allocated(root,deadline=work_end)
            K.need(size<=bound,'watched allocated-byte cap exceeded')
            K.need(shutil.disk_usage(root).free>=reserve,'watched disk reserve exhausted')
            last_watch[0]=time.monotonic()
    env={'PATH':'/usr/bin:/bin','LC_ALL':'C','TZ':'UTC'}
    if argv[0] in ('docker','/usr/bin/docker'):
        K.need(os.environ.get('DOCKER_HOST','').startswith('unix:///') and not os.environ.get('DOCKER_CONTEXT'),'explicit Root local rootless transport required')
        env.update({key:os.environ[key] for key in ('HOME','XDG_RUNTIME_DIR','DOCKER_HOST') if key in os.environ})
    out=Path(out);stdout=out/(label+'.stdout');stderr=out/(label+'.stderr')
    mask=signal.pthread_sigmask(signal.SIG_BLOCK,signals)
    try:
        for number in signals:signal.signal(number,lambda n,f:pending.append(n))
    finally:signal.pthread_sigmask(signal.SIG_SETMASK,mask)
    try:
        with stdout.open('xb') as so,stderr.open('xb') as se:
            try:
                census(force=True)
                spawn_mask=signal.pthread_sigmask(signal.SIG_BLOCK,signals)
                try:
                    if not defer_cancel and (pending or signal.sigpending() & signals):raise KeyboardInterrupt('cancelled before child launch')
                    O.prepare()
                    def child_setup():
                        if child_file_size_cap is not None:
                            hard=resource.getrlimit(resource.RLIMIT_FSIZE)[1]
                            bound=child_file_size_cap if hard==resource.RLIM_INFINITY else min(child_file_size_cap,hard)
                            resource.setrlimit(resource.RLIMIT_FSIZE,(bound,bound))
                        signal.pthread_sigmask(signal.SIG_SETMASK,spawn_mask)
                    child=subprocess.Popen(argv,stdin=subprocess.DEVNULL if input_file is None else input_file,stdout=so,stderr=se,start_new_session=True,env=env,preexec_fn=child_setup)
                finally:signal.pthread_sigmask(signal.SIG_SETMASK,spawn_mask)
                while time.monotonic()<work_end and (defer_cancel or not pending):
                    if os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOWAIT|os.WNOHANG) is not None:break
                    census()
                    if os.fstat(so.fileno()).st_size+os.fstat(se.fileno()).st_size>1024**2:raise ValueError('combined command output cap')
                    time.sleep(.02)
            except BaseException as error:failure=error
            finally:
                if child is not None:
                    remaining=end-time.monotonic();overrun=remaining<=0
                    handoff=dict(original_budget_overrun=overrun,emergency_retirement=overrun,emergency_retirement_cap_seconds=.5 if overrun else None)
                    # Custody is never dropped because time already expired. The
                    # one emergency handoff is retirement only, never renewed work.
                    if overrun and failure is None:failure=TimeoutError('original command budget overrun before frozen handoff')
                    budget=.5 if overrun else remaining
                    retirement=.45 if overrun else min(1.5,budget*.75)
                    row.update(handoff)
                    observed=O.supervise(child,cap=budget,retirement=retirement,grace=min(.05 if overrun else .2,retirement*.25),streams=(),max_output=0)
                    row=observed;row.update(handoff);row.pop('output',None)
        size=stdout.stat().st_size+stderr.stat().st_size;K.need(size<=1024**2,'combined command output cap')
        stdout_data=stdout.read_bytes();stderr_data=stderr.read_bytes();data=stdout_data+stderr_data
        # Once the child is reaped, this is a final DATA-only allocation census.
        if watch is not None and failure is None:
            root,bound,reserve=watch
            K.need(allocated(root,deadline=end)<=bound and shutil.disk_usage(root).free>=reserve,'final watched allocation/reserve failed')
        row.update(command_cancelled=list(pending),command_timed_out=time.monotonic()>=end,operation_seconds=time.monotonic()-started,operation_cap_seconds=cap,child_file_size_cap=child_file_size_cap)
        (out/(label+'.log')).write_bytes(data)
    finally:
        blocked=signal.pthread_sigmask(signal.SIG_BLOCK,signals)
        try:
            for number in signals-set(blocked):
                while number in signal.sigpending():signal.sigtimedwait({number},0);pending.append(number)
            for number,handler in previous.items():signal.signal(number,handler)
            late=time.monotonic()>=end
            row.update(command_cancelled=list(pending),command_timed_out=late,original_budget_overrun=row.get('original_budget_overrun',False) or late,operation_seconds=time.monotonic()-started,operation_cap_seconds=cap)
            (out/(label+'.json')).write_text(json.dumps(dict(argv=argv,**row),indent=2,sort_keys=True)+'\n')
        finally:
            try:signal.pthread_sigmask(signal.SIG_SETMASK,blocked)
            finally:
                if pending:
                    if defer_cancel:
                        for number in pending:previous[number](number,None)
                    else:
                        handler=previous[pending[0]]
                        if callable(handler):handler(pending[0],None)
                        raise KeyboardInterrupt('owned command cancelled')
    if failure is not None:raise failure
    K.need(_retired(row,defer_cancel=defer_cancel),'command not naturally retired: '+label)
    if check:K.need(row['exit']==0,'command exited nonzero: '+label)
    return subprocess.CompletedProcess(argv,row['exit'],stdout_data,stderr_data) if completed else data


def docker_call(argv,out,deadline,*,shared_deadline,defer_cancel=False):
    """OwnedContainer.call-compatible adapter with separate DATA byte streams.

    Override call(self,argv,deadline) with this function, supplying self.out and
    the unchanged phase/global shared_deadline plus state.cleaning. No default
    daemon is selected, and naturally reaped nonzero results remain caller DATA.
    """
    global _DOCKER_SEQUENCE
    if not argv or argv[0] not in ('docker','/usr/bin/docker'):raise ValueError('fixed Docker CLI required')
    if any(type(v) not in (int,float) or not math.isfinite(v) for v in (deadline,shared_deadline)):raise ValueError('finite shared Docker deadline required')
    out=Path(out)
    for _ in range(4096):
        label='owned-docker-'+str(_DOCKER_SEQUENCE).zfill(6);_DOCKER_SEQUENCE+=1
        if not any((out/(label+suffix)).exists() for suffix in ('.stdout','.stderr','.json','.log')):break
    else:raise ValueError('owned Docker receipt namespace exhausted')
    return command(argv,out,label,seconds=8,deadline=min(deadline,shared_deadline),defer_cancel=defer_cancel,check=False,completed=True)
