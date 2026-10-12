#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Linux fork supervisor for externally registered, captured trusted callbacks.

A successful callback is returned only after natural leader exit and removal of
its registered process group. This is process evidence, never native admission.
"""
import base64
from contextlib import contextmanager
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import re
import resource
import selectors
import signal
import stat
import sys
import threading
import time
import types

ROLES = {'collect-base', 'receive-base', 'consume-provenance', 'bind-metadata',
         'phase-accept', 'phase-restage', 'crypto-attest'}
RESULT_LIMIT, TOTAL_LIMIT, STREAM_LIMIT = 16 * 1024**2, 64 * 1024**2, 16 * 1024**2
SIGNALS = {signal.SIGINT, signal.SIGTERM}


class Refused(ValueError):
    def __init__(self, reason, receipt=None):
        super().__init__(reason)
        self.receipt = receipt or {}


class Cancelled(Refused):
    pass


def need(condition, reason):
    if not condition:
        raise Refused(reason)


def check(deadline):
    need(type(deadline) in (int, float) and math.isfinite(deadline) and time.monotonic() < deadline,
         'role-deadline')


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False, ensure_ascii=True).encode()
    except (TypeError, ValueError, RecursionError):
        raise Refused('role-result-json') from None


def pack(value, depth=0):
    need(depth <= 64, 'role-result-depth')
    if type(value) is bytes:
        return ['bytes', base64.b64encode(value).decode()]
    if value is None or type(value) in (bool, int, str):
        return ['scalar', value]
    if type(value) in (list, tuple):
        return ['list', [pack(item, depth+1) for item in value]]
    if type(value) is dict:
        need(all(type(key) is str for key in value), 'role-result-key')
        return ['dict', {key:pack(item, depth+1) for key, item in value.items()}]
    raise Refused('role-result-type')


def unpack(value, depth=0):
    need(depth <= 64 and type(value) is list and len(value) == 2, 'role-result-shape')
    tag, item = value
    if tag == 'scalar':
        need(item is None or type(item) in (bool, int, str), 'role-result-scalar')
        return item
    if tag == 'bytes':
        need(type(item) is str, 'role-result-bytes')
        try:
            raw = base64.b64decode(item, validate=True)
        except (ValueError, TypeError):
            raise Refused('role-result-base64') from None
        need(base64.b64encode(raw).decode() == item, 'role-result-base64')
        return raw
    if tag == 'list':
        need(type(item) is list, 'role-result-list')
        return [unpack(row, depth+1) for row in item]
    if tag == 'dict':
        need(type(item) is dict, 'role-result-dict')
        return {key:unpack(row, depth+1) for key, row in item.items()}
    raise Refused('role-result-tag')


def decode(raw):
    def pairs(rows):
        result = {}
        for key, item in rows:
            need(key not in result, 'role-result-duplicate')
            result[key] = item
        return result
    def invalid(_):
        raise Refused('role-result-number')
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
    except (ValueError, UnicodeError, RecursionError):
        raise Refused('role-result-json') from None
    need(canonical(value) == raw, 'role-result-canonical')
    return value


def source(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'role-source-path')
    fds, fd = [], None
    try:
        fds.append(os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
        for name in path.parts[1:-1]:
            fds.append(os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fds[-1]))
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fds[-1])
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= RESULT_LIMIT,
             'role-source-type')
        raw = os.read(fd, RESULT_LIMIT+1)
        fields = ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        need(len(raw) == before.st_size and all(getattr(before,key) == getattr(os.fstat(fd),key)
             == getattr(os.stat(path.name,dir_fd=fds[-1],follow_symlinks=False),key) for key in fields), 'role-source-drift')
        return (hashlib.sha256(raw).hexdigest(), tuple(getattr(before,key) for key in fields))
    finally:
        if fd is not None: os.close(fd)
        for item in reversed(fds): os.close(item)


@contextmanager
def handlers(callback):
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
    originals = {number:signal.getsignal(number) for number in SIGNALS}
    error = None
    try:
        for number in SIGNALS: signal.signal(number,callback)
        signal.pthread_sigmask(signal.SIG_SETMASK,mask)
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_BLOCK,SIGNALS)
        try:
            for number, original in originals.items():
                for _ in range(2):
                    try: signal.signal(number,original)
                    except BaseException as failure: error = error or failure
                    if signal.getsignal(number) == original: break
                else: error = error or Refused('role-handler-restore')
            for number in SIGNALS-set(mask):
                while number in signal.sigpending():
                    signal.sigtimedwait({number},0)
                    try: callback(number,None)
                    except BaseException as failure: error = error or failure
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK,mask)
        if error is not None: raise error


def subreaper(value=None):
    libc = ctypes.CDLL(None, use_errno=True)
    if value is None:
        result = ctypes.c_int()
        need(libc.prctl(37,ctypes.byref(result),0,0,0) == 0, 'role-subreaper-query')
        return result.value
    need(libc.prctl(36,value,0,0,0) == 0, 'role-subreaper-set')


def processes():
    rows = {}
    names = os.listdir('/proc')
    need(len(names) <= 65536, 'role-process-table-bound')
    for name in names:
        if not name.isdigit(): continue
        try:
            raw = Path('/proc', name, 'stat').read_bytes()
            need(len(raw) <= 4096, 'role-process-stat-bound')
            fields = raw[raw.rindex(b')')+2:].split()
            rows[int(name)] = {'ppid':int(fields[1]), 'pgid':int(fields[2]), 'start':int(fields[19])}
        except (OSError, ValueError, IndexError): pass
    return rows


def no_existing_children():
    # The kernel's direct-child list includes zombies and avoids a /proc scan's
    # fork/exit race. Never adopt a job while a foreign parent child exists.
    fd = os.open('/proc/self/task/'+str(os.getpid())+'/children',os.O_RDONLY|os.O_NOFOLLOW)
    try:
        raw = os.read(fd,65537)
    finally:
        os.close(fd)
    need(not raw.strip(),'role-preexisting-children')


def extend_owned(owned, rows, foreign, *, bounded=True):
    changed = True
    while changed:
        changed = False
        for pid, row in rows.items():
            if pid in owned or (pid, row['start']) in foreign: continue
            if row['ppid'] in owned or row['ppid'] == os.getpid():
                owned[pid] = row['start'];changed = True
    need(not bounded or len(owned) <= 128, 'role-descendant-bound')


def write(fd, raw):
    while raw:
        count = os.write(fd,raw[:65536])
        need(count > 0,'role-child-write')
        raw = raw[count:]


def child(callback, ready, barrier, result, stdout, stderr, deadline, result_limit):
    try:
        os.setsid()
        write(ready,str(os.getpid()).encode()+b'\n')
        os.close(ready)
        need(os.read(barrier,1) == b'1','role-registration-ack')
        os.close(barrier)
        null = os.open('/dev/null',os.O_RDONLY)
        os.dup2(null,0);os.dup2(stdout,1);os.dup2(stderr,2)
        sys.stdout = os.fdopen(1,'w',buffering=1,closefd=False)
        sys.stderr = os.fdopen(2,'w',buffering=1,closefd=False)
        for name in os.listdir('/proc/self/fd'):
            fd = int(name)
            if fd not in (0,1,2,result):
                try: os.close(fd)
                except OSError: pass
        for number in SIGNALS: signal.signal(number,signal.SIG_DFL)
        signal.pthread_sigmask(signal.SIG_UNBLOCK,SIGNALS)
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        resource.setrlimit(resource.RLIMIT_AS,(2*1024**3,2*1024**3))
        resource.setrlimit(resource.RLIMIT_NOFILE,(128,128))
        resource.setrlimit(resource.RLIMIT_FSIZE,(64*1024**2,64*1024**2))
        cpu = max(1,min(1200,math.ceil(deadline-time.monotonic())))
        resource.setrlimit(resource.RLIMIT_CPU,(cpu,cpu))
        check(deadline)
        value = callback()
        raw = canonical({'status':'PASS','value':pack(value)})
        need(len(raw) <= result_limit,'role-result-bound')
        write(result,raw)
        sys.stdout.flush();sys.stderr.flush()
        os.close(result)
        os._exit(0)
    except BaseException as error:
        try: write(result,canonical({'status':'FAIL','error':type(error).__name__}))
        except BaseException: pass
        os._exit(1)


class RoleSupervisor:
    def __init__(self, role_grants, *, deadline, cleanup_seconds=30, result_limit=RESULT_LIMIT,
                 stream_limit=STREAM_LIMIT, source_guard=None):
        check(deadline)
        need(type(role_grants) is dict and role_grants and set(role_grants) <= ROLES,'role-grants')
        need(type(cleanup_seconds) in (int,float) and math.isfinite(cleanup_seconds) and 0 < cleanup_seconds <= 30
             and type(result_limit) is int and 0 < result_limit <= RESULT_LIMIT
             and type(stream_limit) is int and 0 < stream_limit <= STREAM_LIMIT,'role-limits')
        need(source_guard is None or callable(source_guard),'role-source-guard')
        self.source_guard = source_guard
        if source_guard is not None:source_guard()
        self.grants,self.source_identities = {},{}
        for role,row in role_grants.items():
            need(type(row) is dict and set(row) == {'module','source_file','source_sha256'}
                 and type(row['module']) is str and row['module'] and type(row['source_sha256']) is str
                 and re.fullmatch('[0-9a-f]{64}',row['source_sha256'])
                 and isinstance(row['source_file'],(str,Path)) and Path(row['source_file']).is_absolute(),'role-grant-shape')
            identity = source(row['source_file'])
            need(identity[0] == row['source_sha256'],'role-grant-source')
            self.grants[role] = {**row,'source_file':str(row['source_file'])}
            self.source_identities[role] = identity
        self.deadline = min(deadline,time.monotonic()+1200)
        self.cleanup_seconds,self.result_limit,self.stream_limit = cleanup_seconds,result_limit,stream_limit
        self.failed,self.active,self.receipts = False,False,[]

    def guard_sources(self):
        for role,grant in self.grants.items():
            need(source(grant['source_file']) == self.source_identities[role]
                 and self.source_identities[role][0] == grant['source_sha256'],'role-callback-source')
        if self.source_guard is not None:self.source_guard()

    def __call__(self, role, captured_trusted_callback, *, deadline):
        pending = []
        def cancel(number, _): pending.append(number)
        try:
            need(threading.current_thread() is threading.main_thread(), 'role-main-thread')
            need(threading.active_count() == 1 and len(os.listdir('/proc/self/task')) == 1,'role-single-thread-parent')
            no_existing_children()
            with handlers(cancel):
                value = self._call(role, captured_trusted_callback, deadline=deadline, pending=pending)
            if pending:
                raise Cancelled('role-late-cancelled', self.receipts[-1] if self.receipts else {})
            check(min(deadline,self.deadline))
            return value
        except BaseException as error:
            self.failed = True
            if self.receipts:
                self.receipts[-1]['status'] = 'FAIL'
                if isinstance(error,Refused):error.receipt = self.receipts[-1]
            if isinstance(error,Refused):raise
            raise Refused('role-supervision-failed-'+type(error).__name__, self.receipts[-1] if self.receipts else {}) from None

    def _call(self, role, captured_trusted_callback, *, deadline, pending):
        need(threading.current_thread() is threading.main_thread() and not self.active and not self.failed,'role-supervisor-state')
        check(deadline);check(self.deadline)
        deadline = min(deadline,self.deadline)
        work_deadline = deadline-self.cleanup_seconds
        need(time.monotonic() < work_deadline,'role-insufficient-cleanup-budget')
        need(role in self.grants and type(captured_trusted_callback) is types.FunctionType,'role-callback-grant')
        grant = self.grants[role]
        need(captured_trusted_callback.__module__ == grant['module']
             and captured_trusted_callback.__globals__.get('__file__') == str(grant['source_file'])
             and captured_trusted_callback.__code__.co_filename == str(grant['source_file']),'role-callback-source')
        self.guard_sources()
        receipt = {'role':role,'status':'RUNNING','source_sha256':grant['source_sha256'],
                   'deadline':deadline,'work_deadline':work_deadline,'cleanup_seconds':self.cleanup_seconds,
                   'ownership_verified':False,'forced_kill':False,'cleanup':{'status':'NOT RUN'}}
        self.receipts.append(receipt);self.active = True
        pipes, pid, registered, old_reaper, error = [],None,False,None,None
        owned, foreign, buffers = {},set(),{}
        def cancel(number,_): pending.append(number)
        try:
            with handlers(cancel):
                old_reaper = subreaper();subreaper(1)
                initial = processes()
                foreign = {(number,row['start']) for number,row in initial.items()}
                for _ in range(5):pipes.append(os.pipe())
                ready,barrier,result,stdout,stderr = pipes
                mask = signal.pthread_sigmask(signal.SIG_BLOCK,SIGNALS)
                try:
                    need(not pending,'role-cancelled-before-fork')
                    self.guard_sources();check(work_deadline)
                    sys.stdout.flush();sys.stderr.flush()
                    pid = os.fork()
                    if pid == 0:
                        child(captured_trusted_callback,ready[1],barrier[0],result[1],stdout[1],stderr[1],work_deadline,self.result_limit)
                    receipt['pid'] = pid
                    row = processes().get(pid)
                    need(row is not None,'role-leader-identity')
                    owned[pid] = row['start']
                finally:
                    signal.pthread_sigmask(signal.SIG_SETMASK,mask)
                for fd in (ready[1],barrier[0],result[1],stdout[1],stderr[1]):os.close(fd)
                buffers = {'ready':bytearray(),'result':bytearray(),'stdout':bytearray(),'stderr':bytearray()}
                with selectors.DefaultSelector() as selector:
                    for label,fd in (('ready',ready[0]),('result',result[0]),('stdout',stdout[0]),('stderr',stderr[0])):
                        os.set_blocking(fd,False);selector.register(fd,selectors.EVENT_READ,label)
                    while True:
                        if pending:raise Cancelled('role-cancelled')
                        check(work_deadline)
                        extend_owned(owned,processes(),foreign)
                        terminal = os.waitid(os.P_PID,pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
                        if terminal is not None:
                            receipt['natural_exit'] = {'code':terminal.si_code,'status':terminal.si_status}
                        for key,_ in selector.select(max(0,min(0.02,work_deadline-time.monotonic()))):
                            try:raw = os.read(key.fd,65536)
                            except BlockingIOError:continue
                            if not raw:selector.unregister(key.fd);continue
                            buffer = buffers[key.data];buffer.extend(raw)
                            cap = 32 if key.data == 'ready' else self.result_limit if key.data == 'result' else self.stream_limit
                            need(len(buffer) <= cap and sum(map(len,buffers.values())) <= TOTAL_LIMIT,'role-output-bound')
                            if key.data == 'ready' and b'\n' in buffer:
                                need(not registered and bytes(buffer) == str(pid).encode()+b'\n'
                                     and os.getpgid(pid) == pid,'role-process-group-registration')
                                registered = True;receipt.update(pgid=pid,ownership_verified=True)
                                need(not pending,'role-cancelled-before-ack');check(work_deadline)
                                write(barrier[1],b'1');os.close(barrier[1])
                        if terminal is not None:
                            # Drain available result bytes; descendants may retain pipe ends.
                            for label,fd in (('result',result[0]),('stdout',stdout[0]),('stderr',stderr[0])):
                                while True:
                                    try:raw = os.read(fd,65536)
                                    except BlockingIOError:break
                                    if not raw:break
                                    buffers[label].extend(raw)
                                    need(len(buffers[label]) <= (self.result_limit if label == 'result' else self.stream_limit)
                                         and sum(map(len,buffers.values())) <= TOTAL_LIMIT,'role-output-bound')
                            break
                need(registered and receipt['natural_exit'] == {'code':os.CLD_EXITED,'status':0},'role-natural-exit-required')
                envelope = decode(bytes(buffers['result']))
                need(type(envelope) is dict and set(envelope) == {'status','value'} and envelope['status'] == 'PASS','role-result-required')
                value = unpack(envelope['value'])
                receipt['stdout'],receipt['stderr'] = bytes(buffers['stdout']),bytes(buffers['stderr'])
        except BaseException as failure:
            error = failure
        finally:
            # Cancellation is remembered while all owned children are removed.
            with handlers(cancel):
                cutoff = deadline
                receipt['cleanup_started'] = time.monotonic()
                try:
                    if pid is not None:
                        if registered:
                            try:
                                os.killpg(pid,signal.SIGKILL);receipt['cleanup_group_kill_sent'] = True
                            except ProcessLookupError: pass
                        while True:
                            rows = processes();extend_owned(owned,rows,foreign,bounded=False)
                            alive = {number:start for number,start in owned.items()
                                     if number in rows and rows[number]['start'] == start}
                            for number,start in alive.items():
                                current = processes().get(number)
                                if current is not None and current['start'] == start:
                                    try:
                                        os.kill(number,signal.SIGKILL)
                                        receipt.setdefault('cleanup_pid_kill_sent',[]).append(number)
                                    except ProcessLookupError:pass
                            for number in tuple(alive):
                                try:found,status = os.waitpid(number,os.WNOHANG)
                                except ChildProcessError:continue
                                if found:receipt.setdefault('reaped',[]).append({'pid':found,'status':status})
                            remaining = processes()
                            if not any(number in remaining and remaining[number]['start'] == start for number,start in owned.items()):break
                            need(time.monotonic() < cutoff,'role-cleanup-timeout')
                            time.sleep(0.01)
                        receipt['forced_kill'] = 'natural_exit' not in receipt
                        receipt['owned_processes'] = [{'pid':number,'start':start} for number,start in sorted(owned.items())]
                        if registered:
                            try:os.killpg(pid,0)
                            except ProcessLookupError:pass
                            else:raise Refused('role-process-group-remains')
                    if pid is not None:
                        for label,fd in (('result',result[0]),('stdout',stdout[0]),('stderr',stderr[0])):
                            os.set_blocking(fd,False)
                            while True:
                                need(time.monotonic() < cutoff,'role-cleanup-timeout')
                                try:raw = os.read(fd,65536)
                                except BlockingIOError:break
                                if not raw:break
                                buffers.setdefault(label,bytearray()).extend(raw)
                                need(len(buffers[label]) <= (self.result_limit if label == 'result' else self.stream_limit)
                                     and sum(map(len,buffers.values())) <= TOTAL_LIMIT,'role-output-bound')
                    receipt['cleanup_finished'] = time.monotonic()
                    check(cutoff)
                    receipt['cleanup'] = {'status':'PASS','group_absent':True,'reaped':True}
                except BaseException as failure:
                    error = error or failure;receipt['cleanup'] = {'status':'FAIL','reason':str(failure)}
                finally:
                    for label in ('stdout','stderr'):
                        raw = bytes(buffers.get(label,b''))
                        receipt[label] = raw[:self.stream_limit]
                        receipt[label+'_received_bytes'] = len(raw)
                        receipt[label+'_truncated'] = len(raw) > self.stream_limit
                    for pair in pipes:
                        for fd in pair:
                            try:os.close(fd)
                            except OSError:pass
                    if old_reaper is not None:subreaper(old_reaper)
                    self.active = False
        if pending:error = Cancelled('role-cancelled',receipt)
        if error is not None:
            self.failed = True;receipt['status'] = 'FAIL'
            if isinstance(error,Refused):error.receipt = receipt;raise error
            raise Refused('role-callback-failed-'+type(error).__name__,receipt) from None
        try:
            self.guard_sources()
            check(deadline)
        except Refused as failure:
            self.failed = True;receipt['status'] = 'FAIL';failure.receipt = receipt;raise
        receipt['status'] = 'PASS'
        return value
