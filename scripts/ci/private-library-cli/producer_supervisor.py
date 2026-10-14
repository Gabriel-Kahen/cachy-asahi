#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Clock-bound ordinary original producer; no runtime/object-graph attestation."""
import contextlib
import fcntl
import hashlib
import importlib.abc
import importlib.util
import json
import math
import os
from pathlib import Path, PurePosixPath
import select
import signal
import stat
import subprocess as _subprocess
import sys
import threading
import time
import types
import urllib.error
import urllib.request

COMMAND_LIMIT = 1024
CHUNK, LOG_LIMIT, TOTAL_LIMIT = 65536, 4*1024**2, 512*1024**2
DATA_LIMIT = 512*1024**2
HELPERS = frozenset(('scripts/build/build.py','scripts/build/compare.py','scripts/integration/fixtures.py',
                     'scripts/ci/sign_fixture.py','scripts/integration/onboarding.py'))
MODULE_DIRS = ('scripts/checks','scripts/build','scripts/ci')
TOOLS = frozenset(('docker','gpg','gpgconf','git','lscpu','zstd','vercmp'))
HELD = []
_REAL_OS, _REAL_SUBPROCESS = os, _subprocess
_MISSING = object()


def need(condition, code):
    if not condition: raise ValueError(code)


def encoded(value):
    return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def decode(raw):
    def pairs(rows):
        result={}
        for key,value in rows:
            need(key not in result,'PRODUCER_DUPLICATE_JSON');result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'PRODUCER_NONFINITE_JSON'))


def identity(info):
    return tuple(getattr(info,n)for n in ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))


def absolute(value):
    path=Path(value)
    need(path.is_absolute() and '..' not in path.parts and all(not p.is_symlink()for p in (path,*path.parents)),
         'PRODUCER_UNALIASED_PATH')
    return path


def domain():
    info=os.stat('/proc/self/ns/time')
    return dict(clock_id='CLOCK_MONOTONIC',boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        time_namespace_device=info.st_dev,time_namespace_inode=info.st_ino)


def read_regular(path, cap=4*1024**2):
    path=absolute(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK);first=None
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=cap,'PRODUCER_REGULAR_BOUND')
        raw=os.pread(fd,cap+1,0)
        need(len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'PRODUCER_FILE_CHANGED')
        return raw
    except BaseException as error:first=error;raise
    finally:
        try:os.close(fd)
        except BaseException as error:
            HELD.append(dict(kind='PRODUCER_READ_CLOSE_UNCERTAIN',fd=fd))
            if first is None:raise
            first.add_note('PRODUCER_READ_CLOSE_UNCERTAIN:'+type(error).__name__)


class Budget:
    """One original-only durable counter shared by parent and helper reexecs."""
    def __init__(self,path,create=False):
        self.path=absolute(path);self.lock=threading.RLock()
        flags=os.O_RDWR|os.O_CLOEXEC|os.O_NOFOLLOW
        fd=os.open(self.path,flags|(os.O_CREAT|os.O_EXCL if create else 0),0o600)
        self.fd=fd;self.before=identity(os.fstat(fd));self.closed=False
        need(stat.S_ISREG(self.before[2]) and stat.S_IMODE(self.before[2])==0o600 and self.before[3]==1,'PRODUCER_BUDGET_FILE')
        if create:self._store(dict(commands=0,log_bytes=0,data_bytes=0,fetches=0,first=None,cancelled=False,rows={},tools={}))
    def _store(self,value):
        raw=encoded(value);need(len(raw)<=2*1024**2,'PRODUCER_BUDGET_RECORD_BOUND')
        os.lseek(self.fd,0,os.SEEK_SET);position=0
        while position<len(raw):
            count=os.write(self.fd,raw[position:]);need(count>0,'PRODUCER_BUDGET_SHORT_WRITE');position+=count
        os.ftruncate(self.fd,len(raw));os.fsync(self.fd)
    @contextlib.contextmanager
    def transaction(self,write=True):
        with self.lock:
            need(not self.closed,'PRODUCER_BUDGET_CLOSED')
            current=identity(os.fstat(self.fd));observed=identity(self.path.lstat())
            need(all(current[k]==observed[k]==self.before[k]for k in (0,1,2,3,4,5)),'PRODUCER_BUDGET_IDENTITY')
            fcntl.flock(self.fd,fcntl.LOCK_EX)
            first=None
            try:
                raw=os.pread(self.fd,2*1024**2+1,0);need(0<len(raw)<=2*1024**2,'PRODUCER_BUDGET_RECORD_BOUND')
                value=decode(raw)
                need(set(value)=={'commands','log_bytes','data_bytes','fetches','first','cancelled','rows','tools'} and
                     type(value['commands'])is int and 0<=value['commands']<=COMMAND_LIMIT and
                     set(value['rows'])=={str(n)for n in range(1,value['commands']+1)} and
                     0<=value['log_bytes']<=TOTAL_LIMIT and 0<=value['data_bytes']<=DATA_LIMIT and
                     0<=value['fetches']<=501 and type(value['cancelled'])is bool,'PRODUCER_BUDGET_SCHEMA')
                yield value
                if write:self._store(value)
            except BaseException as error:first=error;raise
            finally:
                try:fcntl.flock(self.fd,fcntl.LOCK_UN)
                except BaseException as error:
                    if first is None:raise
                    first.add_note('PRODUCER_BUDGET_UNLOCK_UNCERTAIN:'+type(error).__name__)
    def snapshot(self):
        with self.transaction(write=False) as value:return decode(encoded(value))
    def reserve(self,argv):
        with self.transaction() as value:
            need(value['commands']<COMMAND_LIMIT,'PRODUCER_1024_COMMAND_CAP')
            value['commands']+=1;token=value['commands']
            value['rows'][str(token)]=dict(argv_sha256=hashlib.sha256(encoded(argv)).hexdigest(),state='RESERVED',log_bytes=0,data_bytes=0)
            return token
    def charge(self,token,size,data=False):
        need(type(size)is int and 0<=size<=CHUNK,'PRODUCER_CHUNK_BOUND')
        with self.transaction() as value:
            key='data_bytes'if data else'log_bytes';limit=DATA_LIMIT if data else TOTAL_LIMIT
            row=value['rows'][str(token)]
            need(value[key]+size<=limit and row[key]+size<=(DATA_LIMIT if data else LOG_LIMIT),'PRODUCER_OUTPUT_CAP')
            value[key]+=size;row[key]+=size
    def update(self,token,**fields):
        with self.transaction() as value:value['rows'][str(token)].update(fields)
    def fail(self,error,cancel=False):
        with self.transaction() as value:
            if value['first']is None:value['first']=dict(type=type(error).__name__,detail=str(error)[:65536])
            value['cancelled']=value['cancelled']or cancel
    def fetch(self):
        with self.transaction() as value:
            need(value['fetches']<501,'PRODUCER_501_FETCH_CAP');value['fetches']+=1
    def close(self):
        if self.closed:return
        fd,self.fd=self.fd,None;self.closed=True
        try:os.close(fd)
        except BaseException:
            HELD.append(dict(kind='PRODUCER_BUDGET_CLOSE_UNCERTAIN',fd=fd));raise


class Raw:
    def __init__(self,stdout,stderr):
        self.pid=None;self.returncode=None
        self.stdout=os.fdopen(stdout,'rb',buffering=0)
        self.stderr=None if stderr is None else os.fdopen(stderr,'rb',buffering=0)
    def poll(self):
        if self.returncode is None:
            pid,status=os.waitpid(self.pid,os.WNOHANG)
            if pid:self.returncode=os.waitstatus_to_exitcode(status)
        return self.returncode


class Kernel:
    """Fixed Linux spawn, pidfd and birth; tests replace this actor backend."""
    def spawn(self,handle,argv,environment,cwd,merge=False):
        need(Path.cwd()==cwd,'PRODUCER_CWD_CHANGED')
        previous=None;temporary=[];first=None
        stdout,write=os.pipe2(os.O_CLOEXEC);temporary.append(write)
        stderr=errwrite=None
        if not merge:stderr,errwrite=os.pipe2(os.O_CLOEXEC);temporary.append(errwrite)
        handle.raw=Raw(stdout,stderr)
        try:
            null=os.open('/dev/null',os.O_RDONLY|os.O_CLOEXEC);temporary.append(null)
            actions=[]
            for target,original in ((0,null),(1,write),(2,write if merge else errwrite)):
                duplicate=fcntl.fcntl(original,fcntl.F_DUPFD_CLOEXEC,64);temporary.append(duplicate)
                actions.append((os.POSIX_SPAWN_DUP2,duplicate,target))
            if hasattr(os,'POSIX_SPAWN_CLOSEFROM'):actions.append((os.POSIX_SPAWN_CLOSEFROM,3))
            else:
                with os.scandir('/proc/self/fd')as entries:fds=[int(v.name)for v in entries if v.name.isdigit()]
                need(len(fds)<=4096,'PRODUCER_FD_BOUND')
                for fd in sorted(set(fds)-{0,1,2}):
                    try:os.fstat(fd)
                    except OSError:continue
                    actions.append((os.POSIX_SPAWN_CLOSE,fd))
            handle.owner.check(new_actor=True,cleanup=handle.cleanup)
            handle.mask_state='BLOCK_ATTEMPTED'
            previous=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM,signal.SIGALRM})
            handle.mask_original=previous;handle.mask_state='BLOCKED'
            handle.owner.check(new_actor=True,cleanup=handle.cleanup)
            handle.raw.pid=os.posix_spawn(argv[0],argv,environment,file_actions=actions,setsid=True,
                setsigmask=(),setsigdef=(signal.SIGINT,signal.SIGTERM,signal.SIGALRM,signal.SIGPIPE))
            handle.pid=handle.raw.pid;handle.pidfd=self.pidfd(handle.pid);handle.birth=self.birth(handle.pid)
            return handle.raw
        except BaseException as error:first=error;raise
        finally:
            if previous is not None:
                try:
                    handle.owner.check(cleanup=True);handle.mask_state='RESTORE_ATTEMPTED'
                    signal.pthread_sigmask(signal.SIG_SETMASK,previous);handle.mask_state='RESTORED'
                except BaseException as error:
                    handle.uncertainties.append('PRODUCER_MASK_RESTORE_UNCERTAIN')
                    if first is None:first=error
                    else:first.add_note('PRODUCER_MASK_RESTORE_UNCERTAIN:'+type(error).__name__)
            for fd in temporary:
                try:os.close(fd)
                except BaseException as error:
                    HELD.append(dict(kind='PRODUCER_LAUNCH_FD_CLOSE_UNCERTAIN',fd=fd))
                    handle.uncertainties.append('PRODUCER_LAUNCH_FD_CLOSE_UNCERTAIN')
                    if first is None:first=error
                    else:first.add_note('PRODUCER_LAUNCH_FD_CLOSE_UNCERTAIN:'+type(error).__name__)
            if first is not None and sys.exc_info()[0]is None:raise first
    def birth(self,pid):
        raw=Path('/proc/'+str(pid)+'/stat').read_bytes();need(len(raw)<=4096 and b') 'in raw,'PRODUCER_BIRTH_BOUND')
        fields=raw.rsplit(b') ',1)[1].split()
        return dict(pid=pid,ppid=int(fields[1]),sid=int(fields[3]),start_ticks=int(fields[19]))
    def pidfd(self,pid):return os.pidfd_open(pid,0)
    def poll(self,raw):return raw.poll()
    def send(self,handle,number):
        need(handle.pidfd is not None and self.birth(handle.pid)==handle.birth,'PRODUCER_FOREIGN_BIRTH')
        signal.pidfd_send_signal(handle.pidfd,number,None,0)
    def close(self,fd):os.close(fd)


class Pipe:
    def __init__(self,process,key):self.process,self.key,self.closed=process,key,False
    def read(self,size=-1):
        need(not self.closed and type(size)is int and -1<=size<=DATA_LIMIT,'PRODUCER_STREAM_READ_BOUND')
        queue=self.process.buffers[self.key]
        while not self.process.eof[self.key] and(size<0 or len(queue)<size):self.process.pump(wait=True)
        count=len(queue)if size<0 else min(size,len(queue));body=bytes(queue[:count]);del queue[:count]
        return body
    def readinto(self,buffer):
        body=self.read(len(buffer));buffer[:len(body)]=body;return len(body)
    def close(self):self.closed=True;self.process.buffers[self.key].clear()
    def fileno(self):return self.process.raw_streams[self.key].fileno()


class Process:
    def __init__(self,owner,argv,kwargs):
        self.owner,self.args=owner,argv
        self.pidfd=self.raw=None;self.pid=None;self.birth=None;self.returncode=None
        self.signalled=self.reaped=self.closed=False;self.uncertainties=[];self.first=None
        self.buffers={'stdout':bytearray(),'stderr':bytearray()};self.eof={'stdout':False,'stderr':False}
        self.targets={key:kwargs.get(key)for key in ('stdout','stderr')}
        self.merge=self.targets['stderr']==_subprocess.STDOUT
        self.text=bool(kwargs.get('text',kwargs.get('universal_newlines',False)))
        self.encoding=kwargs.get('encoding')or'utf-8';self.errors=kwargs.get('errors')or'strict'
        self.data=Path(str(argv[0])).name=='zstd' and argv[1:3]==['-dc','--']
        self.timeout=kwargs.get('timeout')
        self.end=None;self.raw_streams={};self.hash=hashlib.sha256();self.log_fd=None
        self.mask_original=None;self.mask_state='NOT_ATTEMPTED'
        self.cleanup=owner.cleanup_command(argv)
        owner.check(new_actor=True,cleanup=self.cleanup);owner.guard()
        actual,cwd=owner.command(argv,kwargs.get('cwd'))
        owner.observe_tool(actual[0])
        need(not kwargs.get('shell')and(kwargs.get('preexec_fn')is None or callable(kwargs.get('preexec_fn'))),'PRODUCER_SHELL_REFUSED')
        need(not kwargs.get('shell') and kwargs.get('stdin')in(None,_subprocess.DEVNULL),'PRODUCER_STDIN_OR_SHELL_REFUSED')
        need(set(kwargs)<= {'stdout','stderr','stdin','text','encoding','errors','universal_newlines','timeout','cwd','env',
             'start_new_session','close_fds','preexec_fn','bufsize'},'PRODUCER_POPEN_OPTIONS')
        if kwargs.get('env')is not None:need(kwargs['env']==owner.environment,'PRODUCER_ENVIRONMENT_DRIFT')
        intent=owner.bootstrap_intent(actual)
        self.token=owner.budget.reserve(actual);owner.handles.append(self)
        if intent is not None:owner.budget.update(self.token,bootstrap_intent=intent)
        self.log_path=owner.home/'logs'/('command-%04d.log'%self.token)
        target=self.targets['stdout']
        self.direct_target=self.merge and target is not None and target not in(_subprocess.PIPE,_subprocess.DEVNULL)
        if self.direct_target:
            self.log_path=Path(target.name).absolute();self.log_fd=os.dup(target.fileno())
        else:self.log_fd=os.open(self.log_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o600)
        try:
            owner.check(new_actor=True,cleanup=self.cleanup)
            self.raw=owner.kernel.spawn(self,actual,owner.environment,cwd,self.merge)
            self.pid=self.raw.pid
            if self.pidfd is None:self.pidfd=owner.kernel.pidfd(self.pid)
            if self.birth is None:self.birth=owner.kernel.birth(self.pid)
            need(self.birth['pid']==self.birth['sid']==self.pid and self.birth['ppid']==os.getpid()and self.birth['start_ticks']>0,
                 'PRODUCER_CHILD_SESSION_REQUIRED')
            self.raw_streams={'stdout':self.raw.stdout,'stderr':self.raw.stderr}
            for key,stream in self.raw_streams.items():
                if stream is None:self.eof[key]=True
                else:os.set_blocking(stream.fileno(),False)
            owner.budget.update(self.token,state='BORN',birth=self.birth,pidfd_owned=True)
        except BaseException as error:
            self.first=error;self.uncertainties.append('PRODUCER_BIRTH_UNCERTAIN');owner.fail(error)
            raise
        self.stdout=Pipe(self,'stdout')if self.targets['stdout']==_subprocess.PIPE else None
        self.stderr=Pipe(self,'stderr')if self.targets['stderr']==_subprocess.PIPE else None
        self.stdin=None
    def _write(self,body):
        position=0
        while position<len(body):
            self.owner.check(cleanup=True)
            count=os.write(self.log_fd,body[position:]);need(count>0,'PRODUCER_LOG_SHORT_WRITE');position+=count
    def pump(self,wait=False,retirement=False):
        self.owner.check(cleanup=retirement or self.cleanup)
        if self.end is not None and not retirement and time.monotonic()>=self.end:
            raise _REAL_SUBPROCESS.TimeoutExpired(self.args,self.timeout or 1800)
        streams=[stream.fileno()for key,stream in self.raw_streams.items()if stream is not None and not self.eof[key]]
        if wait and streams:select.select(streams,[],[],0.05)
        for key,stream in self.raw_streams.items():
            if stream is None or self.eof[key]:continue
            try:body=os.read(stream.fileno(),CHUNK)
            except BlockingIOError:continue
            if not body:self.eof[key]=True;continue
            data=self.data and key=='stdout'
            self.owner.budget.charge(self.token,len(body),data=data)
            if not data:self._write(body);self.hash.update(body)
            target=self.targets[key]
            if target==_subprocess.PIPE:
                pipe=getattr(self,key,None)
                if pipe is None or not pipe.closed:self.buffers[key].extend(body)
            elif target==_subprocess.DEVNULL:pass
            elif target is not None and target!=_subprocess.STDOUT and not(self.direct_target and key=='stdout'):
                position=0
                while position<len(body):
                    count=os.write(target.fileno(),body[position:]);need(count>0,'PRODUCER_TARGET_SHORT_WRITE');position+=count
            elif target is None:
                output=getattr(sys,key)
                if hasattr(output,'buffer'):output.buffer.write(body);output.flush()
                else:output.write(body.decode(self.encoding,'replace'));output.flush()
        code=self.owner.kernel.poll(self.raw)
        if code is not None:self.returncode=code;self.reaped=True
        if not streams and wait and not self.reaped:time.sleep(0.01)
    def poll(self):
        if not self.reaped:self.pump(False)
        return self.returncode
    def wait(self,timeout=None):
        if self.end is None:self.end=min(self.owner.work_cutoff,time.monotonic()+(timeout or self.timeout or 1800))
        elif timeout is not None:self.end=min(self.end,time.monotonic()+timeout)
        try:
            while not(self.reaped and all(self.eof.values())):self.pump(True)
            self.finish()
            return self.returncode
        except BaseException as error:
            if self.first is None:self.first=error
            self.owner.fail(error)
            try:self.retire()
            except BaseException as failure:
                self.owner.cleanup_error(failure);error.add_note('PRODUCER_RETIREMENT_UNCERTAIN:'+type(failure).__name__)
            raise
    def communicate(self,input=None,timeout=None):
        need(input is None,'PRODUCER_INPUT_PIPE_NOT_SELECTED')
        self.wait(timeout)
        result=[]
        for key in ('stdout','stderr'):
            value=bytes(self.buffers[key])if self.targets[key]==_subprocess.PIPE else None
            if value is not None and self.text:value=value.decode(self.encoding,self.errors)
            result.append(value)
        return tuple(result)
    def send_signal(self,number):
        if self.reaped:return
        self.owner.check(cleanup=True);need(number in(signal.SIGTERM,signal.SIGKILL),'PRODUCER_SIGNAL_ALLOWLIST')
        self.owner.kernel.send(self,number);self.signalled=True
    def terminate(self):self.send_signal(signal.SIGTERM)
    def kill(self):self.send_signal(signal.SIGKILL)
    def retire(self):
        if self.reaped:self.finish();return
        for number,grace in((signal.SIGTERM,2),(signal.SIGKILL,5)):
            try:
                self.send_signal(number);end=min(self.owner.deadline,time.monotonic()+grace)
                while time.monotonic()<end and not self.reaped:
                    self.owner.check(cleanup=True)
                    code=self.owner.kernel.poll(self.raw)
                    if code is not None:self.returncode=code;self.reaped=True;break
                    self.pump(True,retirement=True)
            except BaseException as error:self.uncertainties.append('PRODUCER_RETIREMENT_UNCERTAIN');self.owner.cleanup_error(error)
            if self.reaped:break
        if self.reaped:
            end=min(self.owner.deadline,time.monotonic()+1)
            while not all(self.eof.values())and time.monotonic()<end:
                try:self.pump(True,retirement=True)
                except BaseException as error:self.owner.cleanup_error(error);break
            self.finish()
        else:self.uncertainties.append('PRODUCER_NOT_REAPED');self.owner.uncertainties.append('PRODUCER_NOT_REAPED');HELD.append(self)
    def finish(self):
        if self.closed:return
        if not self.reaped:
            self.uncertainties.append('PRODUCER_CLOSE_UNREAPED_REFUSED');HELD.append(self);return
        if not all(self.eof.values()):self.uncertainties.append('PRODUCER_PIPE_EOF_UNKNOWN')
        for stream in self.raw_streams.values():
            if stream is not None:
                try:stream.close()
                except BaseException as error:self.uncertainties.append('PRODUCER_PIPE_CLOSE_UNCERTAIN');self.owner.cleanup_error(error)
        for name in ('log_fd','pidfd'):
            fd=getattr(self,name)
            if fd is not None:
                setattr(self,name,None)
                try:self.owner.kernel.close(fd)
                except BaseException as error:
                    HELD.append(dict(kind='PRODUCER_FD_CLOSE_UNCERTAIN',fd=fd));self.uncertainties.append('PRODUCER_FD_CLOSE_UNCERTAIN');self.owner.cleanup_error(error)
        self.closed=not self.uncertainties
        try:
            self.owner.budget.update(self.token,state='REAPED'if self.closed else'UNCERTAIN',exit_code=self.returncode,
                natural_exit=type(self.returncode)is int and self.returncode>=0 and not self.signalled,reaped=self.reaped,
                uncertainty=self.uncertainties,log_sha256=self.hash.hexdigest(),log_path=str(self.log_path))
        except BaseException as failure:
            self.closed=False;self.uncertainties.append('PRODUCER_PROCESS_JOURNAL_UNCERTAIN');HELD.append(self)
            primary=self.first or self.owner.first
            if primary is not None:primary.add_note('PRODUCER_PROCESS_JOURNAL_UNCERTAIN:'+type(failure).__name__)
            self.owner.cleanup_error(failure)
            if primary is None:raise
    def __enter__(self):return self
    def __exit__(self,kind,error,traceback):
        if error is not None:
            if self.first is None:self.first=error
            self.owner.fail(error)
        for action in ((self.retire,)if not self.reaped else())+(self.finish,):
            try:action()
            except BaseException as failure:
                if error is None:raise
                self.owner.cleanup_error(failure);error.add_note('PRODUCER_PROCESS_EXIT_UNCERTAIN:'+type(failure).__name__)
        return False


class SubprocessProxy(types.ModuleType):
    def __init__(self,owner):super().__init__('subprocess');self.owner=owner
    def __getattr__(self,name):return getattr(_REAL_SUBPROCESS,name)
    def Popen(self,args,**kwargs):return Process(self.owner,[str(v)for v in args],kwargs)
    def run(self,args,**kwargs):
        check=kwargs.pop('check',False);capture=kwargs.pop('capture_output',False);timeout=kwargs.pop('timeout',None)
        input=kwargs.pop('input',None)
        if capture:
            need('stdout'not in kwargs and'stderr'not in kwargs,'PRODUCER_CAPTURE_CONFLICT')
            kwargs.update(stdout=_subprocess.PIPE,stderr=_subprocess.PIPE)
        process=self.Popen(args,**kwargs)
        stdout,stderr=process.communicate(input,timeout)
        result=_REAL_SUBPROCESS.CompletedProcess(args,process.returncode,stdout,stderr)
        if check:result.check_returncode()
        return result
    def check_output(self,args,**kwargs):
        need('stdout'not in kwargs,'PRODUCER_STDOUT_CONFLICT');kwargs['stdout']=_subprocess.PIPE
        return self.run(args,check=True,**kwargs).stdout
    def check_call(self,args,**kwargs):return self.run(args,check=True,**kwargs).returncode
    def call(self,args,**kwargs):return self.run(args,**kwargs).returncode


class OSProxy(types.ModuleType):
    def __init__(self,owner):super().__init__('os');self.owner=owner
    def __getattr__(self,name):return getattr(_REAL_OS,name)
    def killpg(self,pid,number):
        matches=[h for h in self.owner.handles if h.pid==pid]
        need(len(matches)==1,'PRODUCER_UNOWNED_GROUP_REFUSED')
        # Only the positively held leader is signalled. No arbitrary group or
        # universal descendant retirement is claimed for the original producer.
        matches[0].send_signal(number)


class Response:
    def __init__(self,owner,response):self.owner,self.response=owner,response;self.url=response.url
    def __getattr__(self,name):return getattr(self.response,name)
    def read(self,size=-1):
        remaining=self.owner.check()
        channel=getattr(getattr(getattr(self.response,'fp',None),'raw',None),'_sock',None)
        if channel is not None:channel.settimeout(min(10,remaining))
        method=getattr(self.response,'read1',self.response.read)
        return method(CHUNK if size<0 else min(size,CHUNK))
    def __enter__(self):return self
    def __exit__(self,kind,error,traceback):
        try:self.response.close()
        except BaseException as failure:
            self.owner.cleanup_error(failure)
            if error is None:raise
            error.add_note('PRODUCER_RESPONSE_CLOSE_UNCERTAIN:'+type(failure).__name__)
        return False


class RequestProxy:
    def __init__(self,owner):self.owner=owner
    def __getattr__(self,name):return getattr(urllib.request,name)
    def urlopen(self,url,timeout=60,**kwargs):
        remaining=self.owner.check(new_actor=True)
        class Redirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(inner,*args,**fields):
                self.owner.check(new_actor=True)
                return super().redirect_request(*args,**fields)
        response=urllib.request.build_opener(Redirect()).open(url,timeout=min(timeout,remaining),**kwargs)
        return Response(self.owner,response)


class Loader(importlib.abc.Loader):
    def __init__(self,owner,name,path):self.owner,self.name,self.path=owner,name,path
    def create_module(self,spec):return None
    def exec_module(self,module):
        raw=self.owner.checked_body(self.path)
        module.__file__=str(self.path);module.__cached__=None
        exec(compile(raw,str(self.path),'exec'),module.__dict__)
        if'subprocess'in module.__dict__:module.subprocess=self.owner.proxy
        if'os'in module.__dict__:module.os=self.owner.os_proxy
        if'urllib'in module.__dict__:
            original=module.urllib
            module.urllib=types.SimpleNamespace(request=RequestProxy(self.owner),error=urllib.error,parse=original.parse)


class Finder(importlib.abc.MetaPathFinder):
    def __init__(self,owner):self.owner=owner
    def find_spec(self,fullname,path=None,target=None):
        if'.'in fullname:return None
        for directory in MODULE_DIRS:
            candidate=self.owner.load_root/directory/(fullname+'.py')
            relative=candidate.relative_to(self.owner.load_root).as_posix()
            if relative in self.owner.rows:
                return importlib.util.spec_from_loader(fullname,Loader(self.owner,fullname,candidate),origin=str(candidate))
        return None


class Producer:
    def __init__(self,source_root,source_rows,clock,original_entry,environment,private_root,*,source_checkout=None,_context=None,_helper_root=None):
        self.root=absolute(source_root);self.rows=decode(encoded(source_rows));self.clock=decode(encoded(clock));self.entry=original_entry
        self.environment=dict(environment);self.private=absolute(private_root);self.checkout=absolute(source_checkout or source_root)
        self.deadline=clock['deadline_monotonic'];self.work_cutoff=min(self.deadline-120,original_entry+10080)
        need(set(clock)=={'schema_version','purpose','source_commit','run_id','run_attempt','nonce','issued_monotonic',
            'deadline_monotonic','allowance_seconds','clock_domain','issuer_source_sha256','issuer_workflow_commit'}and
            clock['allowance_seconds']==10800 and self.deadline==clock['issued_monotonic']+10800 and
            clock['issued_monotonic']<=original_entry<self.work_cutoff,'PRODUCER_ORIGINAL_CLOCK')
        need(clock['clock_domain']==domain(),'PRODUCER_CLOCK_DOMAIN')
        need(self.environment.get('PATH')=='/usr/bin:/bin' and self.environment.get('GITHUB_SHA')==clock['source_commit'],
             'PRODUCER_TOOL_ENVIRONMENT')
        need(type(source_rows)is dict and len(source_rows)==160 and'scripts/ci/integration.lock.json'in source_rows,'PRODUCER_160_ROWS')
        for name,row in self.rows.items():
            path=PurePosixPath(name)
            need(type(name)is str and not path.is_absolute()and'..'not in path.parts and path.as_posix()==name and
                set(row)=={'sha256','mode','bytes'}and type(row['mode'])is int and row['mode']in(0o644,0o755)and
                type(row['bytes'])is int and 0<=row['bytes']<=8*1024**2 and type(row['sha256'])is str and
                len(row['sha256'])==64 and all(v in'0123456789abcdef'for v in row['sha256']),'PRODUCER_SOURCE_ROW')
        self.home=self.private/'producer-supervision';self.context_path=_context
        self.load_root=absolute(_helper_root or self.root);self.child=_context is not None
        self.kernel=Kernel();self.modules={};self.handles=[];self.files=[];self.uncertainties=[]
        self.cleanup_refusal_error=None
        self.cancelled=False;self.closed=False;self.first=None;self.entered=False
        self.proxy=SubprocessProxy(self);self.os_proxy=OSProxy(self);self.finder=Finder(self)
        self.saved_modules={};self.saved_signals={};self.previous_timer=None;self.timer_at=None;self.timer_changed=False
    def fail(self,error,cancel=False):
        if self.first is None:self.first=error
        self.cancelled=self.cancelled or cancel or isinstance(error,KeyboardInterrupt)
        try:self.budget.fail(error,self.cancelled)
        except BaseException as failure:
            error.add_note('PRODUCER_FAILURE_JOURNAL_UNCERTAIN:'+type(failure).__name__)
            self.cleanup_error(failure)
    def cleanup_error(self,error):
        self.uncertainties.append(type(error).__name__+':'+str(error)[:256])
        if self.first is None:self.first=error
    def check(self,*,new_actor=False,cleanup=False):
        now=time.monotonic()
        need(math.isfinite(now)and now<self.deadline,'PRODUCER_ORIGINAL_ENDPOINT')
        if new_actor:need(now<self.work_cutoff,'PRODUCER_WORK_CUTOFF')
        if not cleanup:
            need(now<self.work_cutoff,'PRODUCER_WORK_CUTOFF')
            if self.cancelled:raise KeyboardInterrupt('PRODUCER_CANCELLED')
            if self.first is not None:raise self.first
            if hasattr(self,'budget'):
                state=self.budget.snapshot()
                need(not state['cancelled']and state['first']is None,'PRODUCER_STICKY_FAILURE')
            integration=self.modules.get('integration')
            if integration is not None and integration.CANCEL_REQUESTED:
                self.cancelled=True;raise KeyboardInterrupt('PRODUCER_ORIGINAL_CANCELLED')
        return(self.work_cutoff if new_actor or not cleanup else self.deadline)-now
    def checked_body(self,path):
        path=absolute(path);relative=path.relative_to(self.load_root).as_posix();row=self.rows[relative]
        raw=read_regular(path,8*1024**2)
        need(len(raw)==row['bytes']and hashlib.sha256(raw).hexdigest()==row['sha256']and stat.S_IMODE(path.stat().st_mode)==row['mode'],'PRODUCER_MODULE_PIN')
        return raw
    def guard(self):
        trees=[(self.root,set(self.rows))]
        if self.load_root!=self.root:trees.append((self.load_root,set(self.rows)-{'scripts/ci/integration.lock.json'}))
        for root,expected in trees:
            absolute(root);observed=set();count=0
            for path in root.rglob('*'):
                count+=1;need(count<=4096 and not path.is_symlink(),'PRODUCER_SOURCE_TREE_CHANGED')
                if not path.is_dir():observed.add(path.relative_to(root).as_posix())
            need(observed==expected,'PRODUCER_SOURCE_TREE_CHANGED')
        for fd,path,before in self.files:
            need(identity(os.fstat(fd))==before==identity(path.lstat()),'PRODUCER_SOURCE_CHANGED')
    def observe_tool(self,path):
        path=absolute(path);raw=read_regular(path,128*1024**2);info=path.lstat()
        need(info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o755,'PRODUCER_TRUSTED_OS_TOOL')
        row=dict(sha256=hashlib.sha256(raw).hexdigest(),identity=list(identity(info)))
        with self.budget.transaction()as state:
            previous=state['tools'].get(str(path))
            need(previous is None or previous==row,'PRODUCER_OS_TOOL_DRIFT')
            state['tools'][str(path)]=row
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        need(identity(os.fstat(fd))==identity(info),'PRODUCER_TOOL_OPEN_CHANGED')
        self.files.append([fd,path,identity(info)])

    def cleanup_command(self,argv):
        a=[str(v)for v in argv];tool=Path(a[0]).name
        return tool=='docker'and (a[1:2]==['rm']or a[1:3]in(['container','ls'],['image','ls'],['image','inspect'],['image','rm']))or tool=='gpgconf'and'--kill'in a
    def command(self,argv,cwd):
        need(type(argv)is list and 0<len(argv)<=256 and all(type(v)is str and 0<len(v)<=16384 and'\0'not in v for v in argv),'PRODUCER_ARGV')
        tool=Path(argv[0]).name;cwd=absolute(cwd or self.root)
        if tool=='git':
            need(argv[1:]==['rev-parse','HEAD'],'PRODUCER_GIT_READ_ONLY');return['/usr/bin/git','-C',str(self.checkout),*argv[1:]],self.root
        if Path(argv[0]).resolve()==Path(sys.executable).resolve():
            position=1
            while position<len(argv)and argv[position]in('-B','-I','-S'):position+=1
            need(position<len(argv),'PRODUCER_FIXED_PYTHON_HELPER')
            script=absolute(argv[position]);relative=None
            for name in HELPERS:
                if script.as_posix().endswith('/'+name):relative=name;break
            need(relative is not None,'PRODUCER_HELPER_ALLOWLIST')
            root=script
            for _ in PurePosixPath(relative).parts:root=root.parent
            raw=read_regular(script,8*1024**2)
            need(hashlib.sha256(raw).hexdigest()==self.rows[relative]['sha256'],'PRODUCER_HELPER_PIN')
            return[str(Path(sys.executable).resolve()),'-I','-B','-S',str(Path(__file__).resolve()),'--helper',
                str(self.context_path),str(root),relative,*argv[position+1:]],cwd
        need(tool in TOOLS and argv[0]in(tool,'/usr/bin/'+tool),'PRODUCER_TOOL_ALLOWLIST')
        return['/usr/bin/'+tool,*argv[1:]],cwd
    def _source(self):
        trees=[(self.root,set(self.rows))]
        if self.load_root!=self.root:trees.append((self.load_root,set(self.rows)-{'scripts/ci/integration.lock.json'}))
        for root,expected in trees:
            observed=set();total=count=0
            directories={p.as_posix()for n in expected for p in PurePosixPath(n).parents}
            for path in root.rglob('*'):
                count+=1;need(count<=4096 and not path.is_symlink(),'PRODUCER_SOURCE_SYMLINK_OR_BOUND')
                if path.is_dir():
                    need(path.relative_to(root).as_posix()in directories,'PRODUCER_SOURCE_EXTRA_DIRECTORY')
                    continue
                name=path.relative_to(root).as_posix()
                need(name in expected and'__pycache__'not in path.parts and path.suffix not in('.pyc','.pyo'),'PRODUCER_SOURCE_EXTRA')
                row=self.rows[name];raw=read_regular(path,8*1024**2);info=path.stat();total+=len(raw)
                need(total<=64*1024**2 and len(raw)==row['bytes']and hashlib.sha256(raw).hexdigest()==row['sha256']and
                    stat.S_IMODE(info.st_mode)==row['mode'],'PRODUCER_SOURCE_PIN')
                fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
                self.files.append([fd,path,identity(os.fstat(fd))]);observed.add(name)
            need(observed==expected,'PRODUCER_SOURCE_SET')
        lock=decode(read_regular(self.root/'scripts/ci/integration.lock.json'))
        need(set(lock['source_files'])==set(self.rows)-{'scripts/ci/integration.lock.json'} and len(lock['source_files'])==159 and
            all(lock['source_files'][n]['sha256']==self.rows[n]['sha256']and lock['source_files'][n]['mode']==self.rows[n]['mode']for n in lock['source_files']),
            'PRODUCER_FROZEN_159_JOIN')
    def _signal(self,number,frame):
        self.cancelled=True
        if self.first is None:self.first=KeyboardInterrupt('PRODUCER_CANCELLED_OR_DEADLINE')
        raise self.first
    def __enter__(self):
        need(not self.entered,'PRODUCER_CONTEXT_REPLAY');self.entered=True
        self.check()
        self.saved_path=list(sys.path);self.saved_cwd=Path.cwd();self.saved_environment=dict(os.environ);self.saved_bytecode=sys.dont_write_bytecode
        try:
            self._source()
            if not self.child:
                self.home.mkdir(mode=0o700);(self.home/'logs').mkdir(mode=0o700)
                self.budget=Budget(self.home/'budget.json',create=True)
                self.context_path=self.home/'context.json'
                config=dict(source_root=str(self.root),source_rows=self.rows,clock=self.clock,original_entry=self.entry,
                    environment=self.environment,private_root=str(self.private),source_checkout=str(self.checkout),
                    supervisor_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
                fd=os.open(self.context_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o400)
                try:
                    raw=encoded(config);need(os.write(fd,raw)==len(raw),'PRODUCER_CONTEXT_WRITE')
                finally:os.close(fd)
            else:self.budget=Budget(self.home/'budget.json')
            self.check();sys.dont_write_bytecode=True
            for name in ('subprocess','os',*(Path(n).stem for n in self.rows if Path(n).parent.as_posix()in MODULE_DIRS and n.endswith('.py'))):
                self.saved_modules[name]=sys.modules.get(name,_MISSING)
                if name not in('subprocess','os'):sys.modules.pop(name,None)
            sys.modules['subprocess']=self.proxy;sys.modules['os']=self.os_proxy
            sys.meta_path.insert(0,self.finder);sys.path[:]=[str(self.load_root/d)for d in MODULE_DIRS]+self.saved_path
            os.chdir(self.root);os.environ.clear();os.environ.update(self.environment)
            for number in(signal.SIGINT,signal.SIGTERM,signal.SIGALRM):
                self.saved_signals[number]=signal.getsignal(number);signal.signal(number,self._signal)
            self.timer_at=time.monotonic();self.previous_timer=signal.getitimer(signal.ITIMER_REAL)
            need(self.previous_timer[1]==0,'PRODUCER_REPEATING_TIMER_REFUSED')
            remaining=self.deadline-self.timer_at
            if self.previous_timer[0]>0:remaining=min(remaining,self.previous_timer[0])
            signal.setitimer(signal.ITIMER_REAL,max(0.000001,remaining));self.timer_changed=True
            import importlib
            self.modules['native_arm']=importlib.import_module('native_arm')
            self.modules['integration']=importlib.import_module('integration')
            native=self.modules['native_arm'];original_fetch=native.fetch
            def fetch(*args,**kwargs):
                self.check(new_actor=True);self.guard();self.budget.fetch()
                value=original_fetch(*args,**kwargs);self.check();return value
            native.fetch=fetch
            commit=sys.modules.get('commit_image')
            if commit is not None:
                original_commit=commit.commit_image
                def bounded_commit(*args,**kwargs):
                    remaining=self.check(new_actor=True);previous=commit.TIMEOUT;commit.TIMEOUT=min(previous,remaining)
                    try:value=original_commit(*args,**kwargs);self.check();return value
                    finally:commit.TIMEOUT=previous
                commit.commit_image=bounded_commit;self.modules['integration'].commit_image=bounded_commit
            self.check();return self
        except BaseException as error:
            self.first=error;self.__exit__(type(error),error,error.__traceback__);raise
    def bootstrap_intent(self,argv):
        if argv[:2]!=['/usr/bin/docker','build']:return None
        need(len(argv)==8 and argv[2:6]==['--network=none','--pull=false','--platform=linux/arm64','--iidfile'],
             'PRODUCER_BOOTSTRAP_COMMAND')
        iid=absolute(argv[6]);out=iid.parent;context=absolute(argv[7])
        need(out.is_relative_to(self.private) and iid.name=='image-id' and context==out/'context' and not iid.exists(),
             'PRODUCER_BOOTSTRAP_PREEXISTING_IID')
        inputs=hashlib.sha256(read_regular(out/'inputs.lock.json')).hexdigest()
        need(inputs==self.rows['scripts/ci/inputs.lock.json']['sha256'],'PRODUCER_BOOTSTRAP_INPUT_PIN')
        dockerfile=hashlib.sha256(read_regular(context/'Dockerfile')).hexdigest()
        prior=self.proxy.run(['docker','image','ls','--no-trunc','--quiet'],capture_output=True,text=True,timeout=30,check=True)
        import re
        ids=prior.stdout.splitlines()
        need(len(ids)<=65536 and all(re.fullmatch('sha256:[0-9a-f]{64}',v)for v in ids),'PRODUCER_BASELINE_PRIOR_IMAGE_SET')
        prior_token=self.handles[-1].token
        return dict(iid_path=str(iid),context_path=str(context),dockerfile_sha256=dockerfile,inputs_sha256=inputs,
                    prior_image_ids=sorted(set(ids)),prior_command=prior_token)

    def cleanup_baseline(self,native_output,*,allow_retirement=True):
        try:
            state=self.budget.snapshot()
            need(allow_retirement and all(h.reaped and h.closed for h in self.handles)and not self.uncertainties and
                all(row.get('state')=='REAPED'for row in state['rows'].values()),'PRODUCER_BASELINE_LIFETIME_HELD')
            out=absolute(native_output);need(out.is_relative_to(self.private),'PRODUCER_BASELINE_OUTPUT')
            receipt=decode(read_regular(out/'bootstrap.json'));image=read_regular(out/'image-id',128).decode().strip()
            import re
            need(re.fullmatch('sha256:[0-9a-f]{64}',image)and receipt.get('image_id')==image and receipt.get('status')=='image-provisioned',
                'PRODUCER_BASELINE_OWNERSHIP_UNKNOWN')
            expected=['docker','build','--network=none','--pull=false','--platform=linux/arm64','--iidfile',str(out/'image-id'),str(out/'context')]
            need(receipt['command']==expected and receipt['dockerfile_sha256']==hashlib.sha256(read_regular(out/'context/Dockerfile')).hexdigest()and
                receipt['inputs_sha256']==hashlib.sha256(read_regular(out/'inputs.lock.json')).hexdigest()and
                receipt['packages_lock_sha256']==hashlib.sha256(read_regular(out/'packages.lock')).hexdigest(),'PRODUCER_BASELINE_CONTEXT_JOIN')
            actual=['/usr/bin/docker',*expected[1:]]
            rows=self.budget.snapshot()['rows']
            builds=[row for row in rows.values()if row.get('argv_sha256')==hashlib.sha256(encoded(actual)).hexdigest()]
            need(len(builds)==1,'PRODUCER_BASELINE_BUILD_RECEIPT')
            built=builds[0];intent=built.get('bootstrap_intent',{})
            need(built.get('state')=='REAPED' and built.get('exit_code')==0 and built.get('natural_exit')is True and
                built.get('reaped')is True and built.get('pidfd_owned')is True and built.get('uncertainty')==[] and
                intent.get('iid_path')==str(out/'image-id') and intent.get('context_path')==str(out/'context') and
                intent.get('dockerfile_sha256')==receipt['dockerfile_sha256'] and intent.get('inputs_sha256')==receipt['inputs_sha256'],
                'PRODUCER_BASELINE_BUILD_OWNERSHIP')
            prior=rows.get(str(intent.get('prior_command')),{});prior_argv=['/usr/bin/docker','image','ls','--no-trunc','--quiet']
            need(prior.get('argv_sha256')==hashlib.sha256(encoded(prior_argv)).hexdigest() and prior.get('state')=='REAPED' and
                prior.get('exit_code')==0 and prior.get('natural_exit')is True and prior.get('pidfd_owned')is True and
                prior.get('uncertainty')==[] and image not in intent['prior_image_ids'],'PRODUCER_BASELINE_PREEXISTING_IMAGE')
            before=self.proxy.run(['docker','image','inspect',image],capture_output=True,text=True,timeout=30,check=True)
            value=decode(before.stdout.encode());need(len(value)==1 and value[0]['Id']==image,'PRODUCER_BASELINE_IMAGE_DRIFT')
            self.proxy.run(['docker','image','rm',image],capture_output=True,timeout=30,check=True)
            after=self.proxy.run(['docker','image','ls','--no-trunc','--quiet'],capture_output=True,text=True,timeout=30,check=True)
            need(image not in after.stdout.splitlines(),'PRODUCER_BASELINE_REMAINS');return True
        except BaseException as error:
            self.cleanup_error(error);return False
    def __exit__(self,kind,error,traceback):
        primary=error or self.first
        if error is not None and self.first is None and not(isinstance(error,SystemExit)and error.code in(None,0)):self.first=error
        self.cancelled=self.cancelled or isinstance(error,KeyboardInterrupt)or bool(getattr(self.modules.get('integration'),'CANCEL_REQUESTED',False))
        for handle in list(self.handles):
            try:
                if not handle.reaped:handle.retire()
                else:handle.finish()
            except BaseException as failure:self.cleanup_error(failure)
        if self.timer_changed:
            try:signal.setitimer(signal.ITIMER_REAL,0)
            except BaseException as failure:self.cleanup_error(failure)
        for number,handler in self.saved_signals.items():
            try:signal.signal(number,handler)
            except BaseException as failure:self.cleanup_error(failure)
        if self.timer_changed:
            try:
                remaining=self.previous_timer[0]-(time.monotonic()-self.timer_at)
                if self.previous_timer[0]>0 and remaining>0:signal.setitimer(signal.ITIMER_REAL,remaining)
                elif self.previous_timer[0]>0:need(False,'PRODUCER_OUTER_TIMER_EXPIRED')
            except BaseException as failure:self.cleanup_error(failure)
        for name,module in self.saved_modules.items():
            try:
                if module is _MISSING:sys.modules.pop(name,None)
                else:sys.modules[name]=module
            except BaseException as failure:self.cleanup_error(failure)
        try:
            if self.finder in sys.meta_path:sys.meta_path.remove(self.finder)
        except BaseException as failure:self.cleanup_error(failure)
        if hasattr(self,'saved_path'):
            try:sys.path[:]=self.saved_path
            except BaseException as failure:self.cleanup_error(failure)
            try:sys.dont_write_bytecode=self.saved_bytecode
            except BaseException as failure:self.cleanup_error(failure)
            try:os.chdir(self.saved_cwd)
            except BaseException as failure:self.cleanup_error(failure)
            try:os.environ.clear()
            except BaseException as failure:self.cleanup_error(failure)
            try:os.environ.update(self.saved_environment)
            except BaseException as failure:self.cleanup_error(failure)
        shared_unresolved=False
        if hasattr(self,'budget'):
            try:
                snapshot=self.budget.snapshot()
                shared_unresolved=any(row.get('state')!='REAPED'for row in snapshot['rows'].values())
                if snapshot['first']is not None and self.first is None:
                    self.first=ValueError('PRODUCER_SHARED_SUPERVISION_FAILED:'+snapshot['first']['type'])
                self.cancelled=self.cancelled or snapshot['cancelled']
            except BaseException as failure:shared_unresolved=True;self.cleanup_error(failure)
        unresolved=shared_unresolved or any(not h.reaped or not h.closed for h in self.handles)
        if unresolved:
            self.uncertainties.append('PRODUCER_RECOVERY_CUSTODY_RETAINED');HELD.append(self)
        else:
            for row in self.files:
                fd=row[0]
                if fd is None:continue
                row[0]=None
                try:os.close(fd)
                except BaseException as failure:HELD.append(dict(kind='PRODUCER_SOURCE_CLOSE_UNCERTAIN',fd=fd));self.cleanup_error(failure)
            if hasattr(self,'budget'):
                try:self.budget.close()
                except BaseException as failure:self.cleanup_error(failure)
        self.closed=not unresolved and not self.uncertainties
        if primary is not None:
            for item in self.uncertainties:primary.add_note(item)
        if self.uncertainties and(error is None or isinstance(error,SystemExit)and error.code in(None,0)):
            failure=ValueError('PRODUCER_CLEANUP_UNCERTAIN:'+','.join(self.uncertainties))
            self.cleanup_refusal_error=failure
            raise failure
        if self.first is not None and(error is None or isinstance(error,SystemExit)and error.code in(None,0)):
            raise self.first
        return False


def helper_main(argv):
    need(len(argv)>=4 and argv[0]=='--helper','PRODUCER_FIXED_HELPER_ENTRY')
    context=absolute(argv[1]);raw=read_regular(context);config=decode(raw)
    need(set(config)=={'source_root','source_rows','clock','original_entry','environment','private_root','source_checkout','supervisor_sha256'}and
        hashlib.sha256(Path(__file__).read_bytes()).hexdigest()==config.pop('supervisor_sha256'),'PRODUCER_HELPER_CONTEXT_PIN')
    root=absolute(argv[2]);relative=argv[3];need(relative in HELPERS,'PRODUCER_HELPER_ALLOWLIST')
    with Producer(**config,_context=context,_helper_root=root)as producer:
        script=root/relative;body=producer.checked_body(script)
        module=types.ModuleType('__main__');module.__file__=str(script);module.__package__=None
        old_main=sys.modules.get('__main__');old_argv=sys.argv
        sys.modules['__main__']=module;sys.argv=[str(script),*argv[4:]]
        try:exec(compile(body,str(script),'exec'),module.__dict__)
        finally:
            sys.argv=old_argv
            if old_main is None:sys.modules.pop('__main__',None)
            else:sys.modules['__main__']=old_main
    return 0


if __name__=='__main__':
    raise SystemExit(helper_main(sys.argv[1:]))
