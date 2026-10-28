#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""VM-only observations around the exact original substring fixture; never reap or signal."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import time

FIXTURE=Path('/fixtures/substring.py')
FIXTURE_SHA='f79eb322f34617d43ae13deaaac057f431e8e81f11a23e8a79876158c37dff00'
CASES=('noninteractive','editing','preexisting-function','preexisting-widget','preexisting-private','coexist')
CAP=3072


def need(ok,why):
    if not ok:raise ValueError(why)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def bounded(path,cap):
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
    try:
        need(stat.S_ISREG(os.fstat(fd).st_mode),'ordinary observation file required')
        raw=os.read(fd,cap+1);need(len(raw)<=cap,'observation file cap');return raw
    finally:os.close(fd)


def proc_stat(raw):
    text=raw.decode('ascii');pid,rest=text.split(' (',1);_,fields=rest.rsplit(') ',1);fields=fields.split()
    need(len(fields)>=22 and pid.isdigit(),'bounded proc stat shape')
    return dict(pid=int(pid),state=fields[0],ppid=int(fields[1]),pgid=int(fields[2]),sid=int(fields[3]),
                utime=int(fields[11]),stime=int(fields[12]),start=int(fields[19]))


def peek(process,identity=None):
    """Use only the original Popen child, never poll/wait; WNOWAIT does not consume status."""
    value=dict(returncode=process.returncode)
    if process.returncode is not None:return dict(value,status='ORIGINAL_ALREADY_REAPED')
    try:
        pid=process.pid;need(type(pid) is int and 1<pid<2**31,'original child PID required')
        # The original Popen still owns this unreaped direct child. Do not query another PID.
        waited=os.waitid(os.P_PID,pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
        if waited is not None:
            need(waited.si_pid==pid,'waitid child differs')
            value['waitid']=dict(code=waited.si_code,status=waited.si_status)
        else:value['waitid']=None
        path=Path('/proc')/str(pid);before=proc_stat(bounded(path/'stat',4096))
        status={line.split(':',1)[0]:line.split(':',1)[1].split() for line in bounded(path/'status',8192).decode('ascii').splitlines() if ':' in line}
        uid=list(map(int,status['Uid']));gid=list(map(int,status['Gid']))
        need(before['pid']==before['pgid']==before['sid']==pid and before['ppid']==os.getpid() and
             uid==[os.getuid()]*4 and gid==[os.getgid()]*4,'original terminal child identity differs')
        need(identity is None or before['start']==identity,'original child starttime differs')
        limits=bounded(path/'limits',4096).decode('ascii')
        row=re.search(r'^Max cpu time\s+(\S+)\s+(\S+)\s+seconds\s*$',limits,re.M)
        need(row is not None and all(v.isdigit() for v in row.groups()),'actual child CPU limits absent')
        after=proc_stat(bounded(path/'stat',4096))
        need(all(before[k]==after[k] for k in ('pid','ppid','pgid','sid','start')),'child changed during observation')
        value.update(status='OBSERVED_UNREAPED_CHILD',proc=after,uid=uid,gid=gid,cpu_limit=list(map(int,row.groups())))
    except (OSError,ValueError,KeyError,UnicodeError) as error:
        value.update(status='UNAVAILABLE',error_type=type(error).__name__)
    return value


def write(path,value):
    raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
    need(len(raw)<=CAP,'terminal observation cap')
    need(path.name=='terminal-exit.json' and path.parent.name in CASES and path.is_absolute() and
         not any(p.is_symlink() for p in (path,*path.parents)),'fixed terminal observation path')
    # Existing case-owned file, never an alias or history/configuration path.
    if path.exists():
        info=path.lstat();need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==os.getuid(),'private observation ownership')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_CLOEXEC|os.O_NOFOLLOW,0o600)
    try:
        info=os.fstat(fd);need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==os.getuid(),'private observation descriptor')
        os.ftruncate(fd,0);need(os.write(fd,raw)==len(raw),'complete observation write')
    finally:os.close(fd)


def instrument(original,observer_sha):
    parent=original.Terminal
    class Terminal(parent):
        def __init__(self,zsh,home):
            self._home=Path(home);self._start=time.monotonic_ns();self._identity=None
            self._last_read=None;self._read_count=0;self._failed=False
            self._value=dict(schema_version=1,status='TERMINAL_OBSERVATION_ONLY',acceptance_credit=False,
                case=self._home.name,fixture_sha256=FIXTURE_SHA,observer_sha256=observer_sha,
                clock_ticks=os.sysconf('SC_CLK_TCK'),observer_reaping='NONE',observer_signals='NONE',events=[])
            super().__init__(zsh,home)
            self._value.update(pid=self.process.pid,parent_pid=os.getpid(),uid=os.getuid(),gid=os.getgid())
            self._value['initial']=self._sample()
            self._identity=self._value['initial'].get('proc',{}).get('start')
            self._save()

        def _sample(self):
            return dict(elapsed_ns=time.monotonic_ns()-self._start,**peek(self.process,self._identity))

        def _save(self):
            try:write(self._home/'terminal-exit.json',self._value)
            except Exception:pass  # Observation cannot change original case/cleanup behavior.

        def _event(self,stage,**details):
            try:
                need(len(self._value['events'])<3,'fixed observation event count')
                self._value['events'].append(dict(stage=stage,**details,**self._sample()));self._save()
            except Exception:pass

        def read(self):
            result=super().read();self._last_read=result;self._read_count+=1;return result

        def wait(self,predicate):
            # Keep only the last wait-start observation, not a growing polling log.
            try:self._value['last_wait_before']=self._sample()
            except Exception:pass
            self._last_read=None;self._read_count=0;start=time.monotonic_ns()
            try:return super().wait(predicate)
            except BaseException as error:
                if not self._failed:
                    self._failed=True
                    self._event('WAIT_FAILURE_BEFORE_ORIGINAL_CLOSE',wait_elapsed_ns=time.monotonic_ns()-start,
                        original_read_return=self._last_read,original_read_calls=self._read_count,
                        error_type=type(error).__name__,reason=str(error)[:96])
                raise

        def close(self):
            try:self._event('BEFORE_ORIGINAL_CLOSE')
            finally:
                try:super().close()
                finally:self._event('AFTER_ORIGINAL_CLOSE')
    original.Terminal=Terminal
    noninteractive=original.noninteractive
    def no_pty(zsh,wrapper,root):
        try:return noninteractive(zsh,wrapper,root)
        finally:
            value=dict(schema_version=1,status='NO_PTY_ORIGINAL_NONINTERACTIVE_CASE',acceptance_credit=False,
                case='noninteractive',fixture_sha256=FIXTURE_SHA,observer_sha256=observer_sha,
                observer_reaping='NONE',observer_signals='NONE')
            try:write(Path(root)/'noninteractive/terminal-exit.json',value)
            except Exception:pass
    original.noninteractive=no_pty
    return original


def main():
    need(os.getresuid()==os.getresgid()==(23001,)*3 and os.getgroups()==[] and
         os.uname().machine=='aarch64' and os.sysconf('SC_PAGE_SIZE')==16384 and
         'tools16k=1' in bounded('/proc/cmdline',4096).decode().split(),'marked unprivileged16K VM required')
    raw=bounded(FIXTURE,16384);need(sha(raw)==FIXTURE_SHA,'unchanged original substring fixture required')
    spec=importlib.util.spec_from_file_location('tools16k_original_substring',FIXTURE)
    original=importlib.util.module_from_spec(spec);spec.loader.exec_module(original)
    instrument(original,sha(bounded(__file__,16384)))
    # Match the original script entry handler; signal delivery/reaping remain original.
    def interrupted(*_):raise KeyboardInterrupt
    signal.signal(signal.SIGTERM,interrupted)
    return original.main()


if __name__=='__main__':raise SystemExit(main())
