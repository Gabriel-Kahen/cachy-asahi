# SPDX-License-Identifier: MIT
"""Root-selected passive entry API. No CLI, Source fetching or native execution."""
import base64
import hashlib
import json
import math
import re

REPOSITORY='Gabriel-Kahen/cachy-asahi'
PURPOSE='NATIVE_SIGNER_COMPILE_PASSIVE_OBSERVATION_V1'
CANDIDATE_MARKER='SIGNER_COMPILE_TOOLCHAIN_CANDIDATE='
FINAL_MARKER='SIGNER_COMPILE_TOOLCHAIN_FINAL='
FAIL_MARKER='SIGNER_COMPILE_TOOLCHAIN_FAIL='
MAX_RAW=4*1024**2

class Refusal(Exception):pass
class Deadline(Refusal):pass
class Cancelled(BaseException):pass

def need(value, code):
    if not value:raise Refusal(code)

def run(passive, *, entry, configuration, environment, emit, clock=None, signals=None,
        host=None, io_factory=None):
    """Root captures entry before decoding/importing both pinned Source bodies.

    IO, host runtime, Source/workflow and this invocation remain independently
    Root-selected. emit(line, deadline=original_end) must be a separately
    Root-selected bounded writer, such as the pinned StdoutEmitter below;
    no blocking stdout fallback is supplied. Candidate output never selects tools or mints an admission.
    """
    if clock is None:
        import time
        clock=time.monotonic
    if signals is None:
        import signal
        signals=signal
    if host is None:
        import os
        host=os
    if io_factory is None:io_factory=passive.PassiveIO
    first=None;first_phase=None;cancelled=False;phase='configuration';raw=None;context=None
    old_handlers={};timer_touched=False;emitted_sha=None
    def remember(error):
        nonlocal first,first_phase,cancelled
        if first is None:first=error;first_phase=phase
        cancelled |= isinstance(error,(KeyboardInterrupt,Cancelled)) or getattr(emit,'cancelled',False) is True
    def live():
        need(type(entry) in (int,float) and math.isfinite(entry),'original-entry')
        if clock()>=entry+60:raise Deadline('observation-original-deadline')
        need(not cancelled,'cancelled')
    def cancel(number, frame):
        nonlocal cancelled
        cancelled=True
        raise Cancelled()
    def expired(number, frame):raise Deadline('observation-original-deadline')
    try:
        need(callable(emit),'Root-bounded-emitter')
        now=clock()
        need(type(entry) in (int,float) and math.isfinite(entry) and 0<entry<=now,'original-entry')
        live()
        need(type(configuration) is dict and set(configuration)=={'schema_version','purpose','gcc_directory'}
             and type(configuration['schema_version']) is int and configuration['schema_version']==1
             and configuration['purpose']==PURPOSE
             and type(configuration['gcc_directory']) is str and re.fullmatch(
                 r'/usr/lib/gcc/aarch64-linux-gnu/[0-9]+(?:\.[0-9]+)*',configuration['gcc_directory']),
             'Root-observation-configuration')
        need(type(environment) is dict and environment.get('GITHUB_REPOSITORY')==REPOSITORY
             and environment.get('RUNNER_OS')=='Linux' and environment.get('RUNNER_ARCH')=='ARM64'
             and type(environment.get('GITHUB_SHA')) is str and re.fullmatch('[0-9a-f]{40}',environment['GITHUB_SHA'])
             and environment['GITHUB_SHA']==environment.get('GITHUB_WORKFLOW_SHA')
             and type(environment.get('GITHUB_RUN_ID')) is str and re.fullmatch('[1-9][0-9]{0,19}',environment['GITHUB_RUN_ID'])
             and type(environment.get('GITHUB_RUN_ATTEMPT')) is str and re.fullmatch('[1-9][0-9]{0,9}',environment['GITHUB_RUN_ATTEMPT']),
             'Root-observation-job-context')
        uid=host.getuid();gid=host.getgid()
        need(type(uid) is int and type(gid) is int and uid==host.geteuid()>0 and gid==host.getegid()>0
             and host.uname().machine=='aarch64','host-runtime-context')
        context={'source_commit':environment['GITHUB_SHA'],'workflow_commit':environment['GITHUB_WORKFLOW_SHA'],
                 'run_id':environment['GITHUB_RUN_ID'],'run_attempt':environment['GITHUB_RUN_ATTEMPT'],
                 'machine':'aarch64','uid':uid}
        phase='controls';live()
        old_timer=signals.getitimer(signals.ITIMER_REAL)
        need(type(old_timer) is tuple and len(old_timer)==2 and all(type(v) in (int,float)
             and math.isfinite(v) and v>=0 for v in old_timer),'existing-timer')
        need(old_timer==(0.0,0.0),'existing-active-timer')
        for number,handler in ((signals.SIGINT,cancel),(signals.SIGTERM,cancel),(signals.SIGALRM,expired)):
            live();old_handlers[number]=signals.getsignal(number)
            signals.signal(number,handler)
        live();timer_touched=True
        signals.setitimer(signals.ITIMER_REAL,max(0.000001,entry+60-clock()),0)
        phase='observation';live()
        result=passive.observe_candidate(io_factory(),gcc_directory=configuration['gcc_directory'],
                                        context=context,endpoint=entry+60)
        live()
        need(type(result) is dict and set(result)=={'candidate','evidence'}
             and type(result['candidate']) is dict and type(result['evidence']) is dict
             and result['candidate'].get('selected') is False
             and result['candidate'].get('execution_grant_issued') is False
             and result['evidence'].get('context')==context
             and result['evidence'].get('deadline_at')==entry+60
             and result['evidence'].get('executed_tools') is False
             and result['evidence'].get('loaded_libraries') is False
             and result['evidence'].get('compile_allowed') is False,'candidate-authority-or-context')
        phase='serialization';live()
        raw=json.dumps(result,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
        need(0<len(raw)<=MAX_RAW,'output-budget');live()
    except BaseException as error:remember(error)
    finally:
        phase='finalization'
        if timer_touched:
            try:signals.setitimer(signals.ITIMER_REAL,0,0)
            except BaseException as error:remember(error)
        for number,handler in reversed(tuple(old_handlers.items())):
            try:signals.signal(number,handler)
            except BaseException as error:remember(error)
        try:live()
        except BaseException as error:remember(error)
    if first is None:
        try:
            phase='publication';live()
            emitted_sha=hashlib.sha256(raw).hexdigest()
            emit(CANDIDATE_MARKER+base64.b64encode(raw).decode(),deadline=entry+60)
            live()
            final={'schema_version':1,'status':'OBSERVED_COMPLETE_NOT_SELECTED','candidate_sha256':emitted_sha,
                   'context':context,'deadline_at':entry+60,'selected':False,'execution_grant_issued':False,
                   'executed_tools':False,'loaded_libraries':False,'compile_allowed':False}
            emit(FINAL_MARKER+json.dumps(final,sort_keys=True,separators=(',',':')),deadline=entry+60)
            live()
        except BaseException as error:remember(error)
    if first is not None:
        kind=('CANCELLED' if isinstance(first,(KeyboardInterrupt,Cancelled)) else
              'DEADLINE' if isinstance(first,Deadline) else
              'REFUSED' if isinstance(first,Refusal) else
              'IO_FAILED' if type(first) in (OSError,PermissionError,FileNotFoundError,InterruptedError,TimeoutError) else 'OTHER')
        failure={'schema_version':1,'status':'FAIL','candidate_valid':False,'first_cause':kind,
                 'first_phase':first_phase,'cancelled':cancelled,'emitted_candidate_sha256':emitted_sha,
                 'selected':False,'execution_grant_issued':False,'compile_allowed':False}
        try:emit(FAIL_MARKER+json.dumps(failure,sort_keys=True,separators=(',',':')),deadline=entry+60)
        except BaseException:pass # Failed output cannot produce natural successful completion.
        return 1
    return 0

class StdoutEmitter:
    """Root-selected single-writer fd1; owned duplicate, bounded nonblocking writes.

    Root must own fd1 exclusively, prohibit concurrent fd/flag mutation, and
    accept scheduler and ordinary local syscall completion assumptions. These
    checks give a finite deadline loop, not a hard wall-clock syscall bound.
    """
    def __init__(self, *, host=None, flags=None, readiness=None, clock=None):
        if host is None:
            import os
            host=os
        if flags is None:
            import fcntl
            flags=fcntl
        if readiness is None:
            import select
            readiness=select
        if clock is None:
            import time
            clock=time.monotonic
        self.host,self.flags,self.readiness,self.clock=host,flags,readiness,clock
        self.original=None;self.uncertain=False;self.cancelled=False

    @staticmethod
    def identity(row):
        return (row.st_dev,row.st_ino,row.st_mode,row.st_uid,row.st_gid,row.st_nlink)

    def __call__(self,line,*,deadline):
        import stat
        def live():
            need(type(deadline) in (int,float) and math.isfinite(deadline) and deadline>0,'output-deadline')
            if self.clock()>=deadline:raise Deadline('observation-original-deadline')
        def same(fd):
            live()
            need(self.identity(self.host.fstat(fd))==self.original
                 ==self.identity(self.host.fstat(1)),'stdout-identity-drift')
        live();need(not self.uncertain and not self.cancelled,'stdout-custody-uncertain')
        need(type(line) is str and line.isascii() and '\n' not in line and '\r' not in line
             and 0<len(line)<=6*1024**2-1,'stdout-record-budget')
        payload=line.encode('ascii')+b'\n';live()
        row=self.host.fstat(1)
        need(stat.S_ISREG(row.st_mode) or stat.S_ISFIFO(row.st_mode) or stat.S_ISSOCK(row.st_mode),
             'stdout-kind')
        observed=self.identity(row)
        if self.original is None:self.original=observed
        need(observed==self.original,'stdout-identity-drift')
        fd=None;previous=None;changed=False;first=None
        def remember(error):
            nonlocal first
            if first is None:first=error
            self.cancelled |= isinstance(error,(KeyboardInterrupt,Cancelled))
        try:
            live();fd=self.host.dup(1);same(fd)
            previous=self.flags.fcntl(fd,self.flags.F_GETFL)
            need(type(previous) is int and previous&self.host.O_ACCMODE in
                 (self.host.O_WRONLY,self.host.O_RDWR),'stdout-access')
            live();changed=True
            self.flags.fcntl(fd,self.flags.F_SETFL,previous|self.host.O_NONBLOCK)
            poller=self.readiness.poll()
            errors=self.readiness.POLLERR|self.readiness.POLLHUP|self.readiness.POLLNVAL
            poller.register(fd,self.readiness.POLLOUT|errors)
            position=0
            while position<len(payload):
                same(fd)
                events=poller.poll(max(1,min(50,math.ceil((deadline-self.clock())*1000))))
                live()
                need(type(events) is list and len(events)<=1 and all(
                     type(found) is int and found==fd and type(event) is int and not event&errors
                     and not event&~(self.readiness.POLLOUT|errors) for found,event in events),
                     'stdout-readiness')
                if not events or not events[0][1]&self.readiness.POLLOUT:continue
                same(fd)
                try:written=self.host.write(fd,payload[position:position+65536])
                except (BlockingIOError,InterruptedError):continue
                need(type(written) is int and 0<written<=min(65536,len(payload)-position),'stdout-progress')
                position+=written;same(fd)
        except BaseException as error:remember(error)
        finally:
            if changed:
                try:
                    # Retire the owned effect even after expiry; never restore
                    # flags through a foreign/reused descriptor or restart output.
                    need(self.identity(self.host.fstat(fd))==self.original,'stdout-retirement-identity')
                    self.flags.fcntl(fd,self.flags.F_SETFL,previous)
                    need(self.flags.fcntl(fd,self.flags.F_GETFL)==previous,'stdout-flags-restoration')
                except BaseException as error:self.uncertain=True;remember(error)
            if fd is not None:
                try:self.host.close(fd)
                except BaseException as error:self.uncertain=True;remember(error)
        if first is not None:raise first
        live()
