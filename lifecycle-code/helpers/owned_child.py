# SPDX-License-Identifier: MIT
"""Single-threaded owned children: WNOWAIT reservation, then direct final reap.

Ownership loss is terminal. Popen wait/poll/communicate status is never evidence.
"""
import contextlib
import errno
import os
from pathlib import Path
import signal
import stat
import subprocess
import tempfile
import threading
import time


class OwnershipLost(subprocess.SubprocessError):
    pass


class ChildPolicyError(subprocess.SubprocessError):
    pass


def _owned_policy(normalize=False):
    if threading.current_thread() is not threading.main_thread() or threading.active_count()!=1:
        raise ChildPolicyError('owned children require one main Python thread')
    if signal.getsignal(signal.SIGCHLD)!=signal.SIG_DFL:
        raise ChildPolicyError('SIGCHLD must use the default disposition')
    if not all(hasattr(os,n)for n in('waitid','WNOWAIT','waitpid')) or not hasattr(signal,'pthread_sigmask'):
        raise ChildPolicyError('Linux owned wait and signal-mask APIs required')
    if normalize:
        signal.signal(signal.SIGCHLD,signal.SIG_DFL)
        saved=signal.pthread_sigmask(signal.SIG_BLOCK,set())
        signal.pthread_sigmask(signal.SIG_SETMASK,saved)


class _OwnedState:
    def __init__(self,process,lifecycle,allowed_uids):
        self.process=process;self.pid=process.pid;self.row=lifecycle;self.reaped=False;self.lost=False
        self.allowed_uids={os.geteuid()}if allowed_uids is None else set(allowed_uids)
        self.row.update(pid=self.pid,exit=None,natural_exit=False,group_absent=False,
            leader_held_until_group_inspection=False,exit_observed_via_waitpid=False,
            ownership_lost=False,retirement='UNKNOWN',forced_cleanup=False,cleanup_member_uids=[])

    def lose(self,why):
        self.lost=True;self.row.update(exit=None,exit_observed_via_waitpid=False,
            ownership_lost=True,retirement='UNKNOWN',group_absent=False,ownership_error=str(why))
        # Private destructor-detachment marker, never a public observed status.
        self.process.returncode=-9999
        return OwnershipLost(str(why))

    def witness(self):
        if self.lost or self.reaped:raise OwnershipLost('no unreaped child ownership reservation')
        try:
            _owned_policy()
            value=os.waitid(os.P_PID,self.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
        except ChildProcessError as error:raise self.lose('ECHILD: child ownership lost')from error
        except OSError as error:
            if error.errno==errno.ECHILD:raise self.lose('ECHILD: child ownership lost')from error
            raise
        except ChildPolicyError as error:raise self.lose('child policy changed: '+str(error))from error
        if value is not None and value.si_pid!=self.pid:raise self.lose('witness identifies another child')
        return value

    def members(self):
        self.witness();members=[]
        for entry in Path('/proc').iterdir():
            if not entry.name.isdecimal():continue
            try:
                self.witness();fields=(entry/'stat').read_text().rpartition(') ')[2].split()
                if len(fields)<4 or int(fields[2])!=self.pid or int(fields[3])!=self.pid or fields[0]in('Z','X'):continue
                self.witness()
                uid=int(next(line.split()[1]for line in(entry/'status').read_text().splitlines()if line.startswith('Uid:')))
                members.append((int(entry.name),uid))
            except(FileNotFoundError,ProcessLookupError):continue
        return members

    def signal_group(self):
        self.witness()
        try:os.killpg(self.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        self.row['forced_cleanup']=True

    def reap(self):
        if self.witness()is None:raise ChildPolicyError('cannot final-reap a running leader')
        prior=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM,signal.SIGCHLD})
        try:
            # There is no numeric process operation after this final waitpid.
            try:pid,status=os.waitpid(self.pid,0)
            except ChildProcessError as error:raise self.lose('ECHILD during final direct reap')from error
            except OSError as error:
                if error.errno==errno.ECHILD:raise self.lose('ECHILD during final direct reap')from error
                raise
            self.reaped=True
            if pid!=self.pid:raise self.lose('final reap returned another child')
            code=os.waitstatus_to_exitcode(status);self.process.returncode=code
            self.row.update(exit=code,exit_observed_via_waitpid=True,
                retirement='REAPED'if self.row['group_absent']else'UNKNOWN')
        finally:signal.pthread_sigmask(signal.SIG_SETMASK,prior)

    def retire(self,force=False):
        if self.lost or self.reaped:return
        self.witness();members=self.members();uids=sorted({uid for _,uid in members});self.row['cleanup_member_uids']=uids
        if not set(uids)<=self.allowed_uids:
            self.row['cleanup_error']='unexpected live group credentials; no group signal issued'
            if self.witness()is not None:self.reap()
            raise ChildPolicyError(self.row['cleanup_error'])
        if force or members:self.signal_group()
        end=time.monotonic()+2
        while True:
            state=self.witness();members=self.members()
            if state is not None and not members:break
            if time.monotonic()>=end:raise ChildPolicyError('owned group did not retire within cleanup budget')
            time.sleep(.01)
        self.row.update(group_absent=True,leader_held_until_group_inspection=True)
        self.reap()


def run(argv,*,timeout=None,input=None,stdin=None,stdout=None,stderr=None,capture_output=False,
        text=False,encoding=None,errors=None,check=False,cwd=None,env=None,lifecycle=None,
        on_tick=None,allowed_uids=None,stdout_limit=None,stderr_limit=16*1024**2,**options):
    """Bounded subprocess.run subset, without Popen's reaping/status methods."""
    if options.get('shell',False)or options.get('start_new_session',True)is not True:
        raise ChildPolicyError('shell and borrowed sessions are forbidden')
    if set(options)-{'shell','start_new_session'}:raise TypeError('unsupported owned-run options: '+str(sorted(options)))
    _owned_policy(normalize=True)
    timeout=120 if timeout is None else timeout
    if type(timeout)not in(int,float)or not 0<timeout<=3600:raise ValueError('bounded positive owned timeout')
    if input is not None and stdin is not None:raise ValueError('input and stdin are exclusive')
    if capture_output:
        if stdout is not None or stderr is not None:raise ValueError('capture_output conflicts with explicit streams')
        stdout=stderr=subprocess.PIPE
    allowed_uids={os.geteuid()}if allowed_uids is None else set(allowed_uids)
    if not allowed_uids or any(type(uid)is not int or uid<0 for uid in allowed_uids):
        raise ChildPolicyError('concrete permitted child credentials required before launch')
    stdout_limit=(16*1024**2 if stderr==subprocess.STDOUT else 8*1024**2)if stdout_limit is None else stdout_limit
    if any(type(v)is not int or not 0<v<=512*1024**2 for v in(stdout_limit,stderr_limit)):
        raise ValueError('bounded explicit owned output limits')
    row={}if lifecycle is None else lifecycle
    started=time.monotonic();process=None;owned=None;pending=None;result_stdout=result_stderr=None
    with contextlib.ExitStack()as resources:
        def output_stream(value,cap):
            if value==subprocess.DEVNULL:return subprocess.DEVNULL,None,False
            if value in(None,subprocess.PIPE):
                stream=resources.enter_context(tempfile.TemporaryFile());return stream,(stream,cap),True
            if not hasattr(value,'fileno'):raise TypeError('owned output must be a file or PIPE/DEVNULL')
            return value,(value,cap),False
        out,out_watch,out_temp=output_stream(stdout,stdout_limit)
        if stderr==subprocess.STDOUT:err=subprocess.STDOUT;err_watch=None;err_temp=False
        else:err,err_watch,err_temp=output_stream(stderr,stderr_limit)
        source=stdin if stdin is not None else subprocess.DEVNULL
        if input is not None:
            source=resources.enter_context(tempfile.TemporaryFile())
            payload=input.encode(encoding or'utf-8',errors or'strict')if isinstance(input,str)else input
            if not isinstance(payload,bytes)or len(payload)>32*1024**2:raise ValueError('bounded byte input required')
            source.write(payload);source.seek(0)
        def sizes():
            for item in(out_watch,err_watch):
                if item is not None and os.fstat(item[0].fileno()).st_size>item[1]:raise ValueError('owned child output bound')
        try:
            process=subprocess.Popen(argv,stdin=source,stdout=out,stderr=err,cwd=cwd,env=env,start_new_session=True)
            owned=_OwnedState(process,row,allowed_uids)
            while True:
                state=owned.witness();sizes()
                if state is not None:row['natural_exit']=True;break
                if time.monotonic()-started>=timeout:raise subprocess.TimeoutExpired(argv,timeout)
                if on_tick is not None:on_tick()
                time.sleep(.01)
        except BaseException as error:pending=error
        finally:
            if owned is not None:
                try:owned.retire(force=pending is not None)
                except BaseException as error:
                    row['cleanup_error']=type(error).__name__+': '+str(error)
                    if pending is None or isinstance(error,OwnershipLost):pending=error
            row['elapsed_seconds']=time.monotonic()-started
            if process is not None and not(owned and owned.reaped):process.returncode=-9999
        try:sizes()
        except BaseException as error:
            if pending is None:pending=error
        if out_temp:
            out.seek(0);body=out.read(stdout_limit+1)
            if stdout==subprocess.PIPE:result_stdout=body
            elif stdout is None and body:os.write(1,body)
        if err_temp:
            err.seek(0);body=err.read(stderr_limit+1)
            if stderr==subprocess.PIPE:result_stderr=body
            elif stderr is None and body:os.write(2,body)
        if pending is not None:raise pending
        if not row.get('exit_observed_via_waitpid')or row.get('ownership_lost'):
            raise OwnershipLost('no directly observed owned exit status')
        if text or encoding is not None:
            result_stdout=result_stdout.decode(encoding or'utf-8',errors or'strict')if result_stdout is not None else None
            result_stderr=result_stderr.decode(encoding or'utf-8',errors or'strict')if result_stderr is not None else None
        result=subprocess.CompletedProcess(argv,row['exit'],result_stdout,result_stderr)
        if check:result.check_returncode()
        return result
