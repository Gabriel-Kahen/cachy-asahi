# SPDX-License-Identifier: MIT
"""Narrow trusted compiler commands under the reviewed waitable-leader guardian."""
import hashlib
import math
import os
import resource
import signal
import stat
import subprocess
import threading
import time

GUARDIAN_SHA = 'f2a832f3e01c59a2fd61907301818cb85dc511828f0ea40b416ecb3c66ef4446'
GUARDIAN_PEER_SHA = 'ec2871f460a23556adb3b8dcefb54cf67fc2b03eccbf091b6e06946dc03e9338'
MAX_OUTPUT = 4 * 1024 * 1024

# Guard declaration identities only; no runtime caller or host strings.
GROUP_WORK_REFUSALS = {'TMPDIR-held-output-binding': 'group.OwnedCommands.run', 'bounded-held-bytes': 'group.OwnedCommands._bytes', 'clock-domain-or-rewind': 'group.OwnedCommands._live', 'command-shape': 'group.OwnedCommands.run', 'distinct-borrowed-FDs': 'group.OwnedCommands.run', 'exact-argv': 'group.OwnedCommands.run', 'fresh-private-output': 'group.OwnedCommands._bytes', 'held-Root-ELF': 'group.OwnedCommands.run', 'held-executable-SHA': 'group.OwnedCommands._bytes', 'held-file-drift': 'group.OwnedCommands._bytes', 'held-file-shape': 'group.OwnedCommands._bytes', 'held-private-cwd': 'group.OwnedCommands.run', 'inflight-output-bound': 'group.OwnedCommands.run', 'natural-zero-without-helper-residue': 'group.OwnedCommands.run', 'output-bound': 'group.OwnedCommands._bytes', 'output-limit': 'group.OwnedCommands.run', 'previous-owned-child-not-retired': 'group.NativeBackend.birth', 'private-stream-owner': 'group.OwnedCommands.run', 'single-owner-thread': 'group.NativeBackend.establish_waitability'}
GUARDIAN_WORK_REFUSALS = {'ADAPTER_ACTION_AFTER_ORIGINAL_END': 'guardian.Linux._action_guard', 'BIRTH_OWNERSHIP_UNKNOWN': 'guardian.Linux.token', 'CHILD_OWNERSHIP_RELEASED': 'guardian.Linux.peek', 'GROUP_MEMBER_BOUND': 'guardian.Linux.members', 'LEADER_OWNERSHIP_UNKNOWN': 'guardian.disposition', 'PRIVATE_SESSION_NOT_ESTABLISHED': 'guardian.Linux.token', 'PROC_NUMERIC_SHAPE': 'guardian.structural', 'PROC_SCAN_BOUND': 'guardian.Linux.members', 'PROC_STATE': 'guardian.structural', 'PROC_STAT_LIMIT': 'guardian.structural', 'PROC_STAT_SHAPE': 'guardian.structural', 'PROC_VISIBILITY_INCOMPLETE': 'guardian.Linux.members', 'SESSION_GROUP_ESCAPE': 'guardian.disposition', 'TERMINAL_LEADER_NOT_UNREAPED_ZOMBIE': 'guardian.disposition', 'WAITID_CHILD_MISMATCH': 'guardian.Linux.peek', 'WAITID_TERMINAL_CODE': 'guardian.Linux.peek'}


class Refused(ValueError):
    pass


class Deadline(Refused):
    pass


class Cancelled(BaseException):
    pass


def need(value, code):
    if not value: raise Refused(code)


def identity(row):
    return tuple(getattr(row, k) for k in
                 ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink'))


class NativeBackend:
    """Deferred real backend; Root supplies the authenticated loaded guardian.

    No cgroup, statfs, FFI, seccomp or privileged setup provider is needed.
    Selected CPython/Linux waitability and the helper no-escape Source proof remain
    actual Root prerequisites. No native methods are called by construction.
    """
    def __init__(self, guardian, *, admission, expected_admission, expected_guardian):
        need(type(admission) is object and admission is expected_admission and
             guardian is expected_guardian, 'Root-guardian-admission')
        self.guardian = guardian
        self.process = None
        self.birth_started = False
        self.cancel = None
        self.handlers = {}
        self.sigchld_established = False

    now = staticmethod(time.monotonic)
    fstat = staticmethod(os.fstat)
    pread = staticmethod(os.pread)
    pause = staticmethod(time.sleep)
    uid = staticmethod(os.getuid)
    gid = staticmethod(os.getgid)
    euid = staticmethod(os.geteuid)
    egid = staticmethod(os.getegid)

    def path_identity(self,path):
        return identity(os.stat(path,follow_symlinks=False))

    def cancelled(self):
        return self.guardian.Linux.cancelled(self)

    def _handler(self, number, frame):
        return self.guardian.Linux._handler(self, number, frame)

    def establish_waitability(self):
        need(threading.active_count() == 1 and threading.current_thread() is threading.main_thread(),
             'single-owner-thread')
        if not self.sigchld_established:
            for number in (signal.SIGCHLD,signal.SIGINT,signal.SIGTERM):
                self.handlers[number] = signal.getsignal(number)
            signal.signal(signal.SIGCHLD,signal.SIG_DFL)
            self.sigchld_established = True
            for number in (signal.SIGINT,signal.SIGTERM): signal.signal(number,self._handler)

    def birth(self, command, environment, seconds, child_uid, child_gid):
        need(self.process is None or self.process.returncode is not None, 'previous-owned-child-not-retired')
        self.process = None
        self.birth_started = True
        mask = signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
        def setup():
            os.fchdir(command['cwd_fd'])
            os.close(command['cwd_fd'])
            os.setgroups([])
            os.setgid(child_gid)
            os.setuid(child_uid)
            need(os.getuid()==os.geteuid()==child_uid and os.getgid()==os.getegid()==child_gid,
                 'selected-child-credentials')
            os.set_inheritable(command['executable_fd'],False)
            for number in (signal.SIGINT,signal.SIGTERM): signal.signal(number,signal.SIG_DFL)
            for kind,limit in ((resource.RLIMIT_CPU,math.ceil(seconds)),
                (resource.RLIMIT_AS,1024**3),(resource.RLIMIT_FSIZE,command['output_limit']),
                (resource.RLIMIT_NOFILE,64),(resource.RLIMIT_CORE,0)):
                hard=resource.getrlimit(kind)[1]
                limit=min(limit,hard) if hard != resource.RLIM_INFINITY else limit
                resource.setrlimit(kind,(limit,limit))
            signal.pthread_sigmask(signal.SIG_SETMASK,mask)
        try:
            self.process=subprocess.Popen(command['argv'],
                executable='/proc/self/fd/'+str(command['executable_fd']),env=dict(environment),
                stdin=subprocess.DEVNULL,stdout=command['stdout_fd'],stderr=command['stderr_fd'],
                close_fds=True,pass_fds=(command['executable_fd'],command['cwd_fd']),
                start_new_session=True,preexec_fn=setup)
            self.guardian.LIVE[self.process.pid]=self.process
        finally: signal.pthread_sigmask(signal.SIG_SETMASK,mask)

    def has_child(self): return self.process is not None
    def token(self,end): return self.guardian.Linux.token(self,end)
    def peek(self,token): return self.guardian.Linux.peek(self,token)
    def _stat(self,pid): return self.guardian.Linux._stat(self,pid)
    def members(self,token,end): return self.guardian.Linux.members(self,token,end)
    def _action_guard(self,end): return self.guardian.Linux._action_guard(self,end)
    def send_owned(self,token,kind,end): return self.guardian.Linux.send_owned(self,token,kind,end)
    def reap(self,token,expected,end): return self.guardian.Linux.reap(self,token,expected,end)

    def retired(self):
        return (self.process is not None and self.process.returncode is not None and
                self.process.pid not in self.guardian.LIVE)

    def restore(self):
        # Unchanged guardian refuses restoration after unknown/owned partial birth.
        self.guardian.Linux.release_handlers_after_publication(self)


class OwnedCommands:
    """Six fixed compile/inspection selections may share this one original frame.

    Borrowed executable/cwd/output FDs remain Root workspace custody. No JSON
    creates an admission or loaded guardian. No arbitrary recipe/helper is allowed.
    """
    def __init__(self,io,*,admission,expected_admission,group_selection,
                 expected_group_selection,toolchain,expected_toolchain,work_end,cleanup_end):
        need(type(admission) is object and admission is expected_admission and
             group_selection is expected_group_selection and toolchain is expected_toolchain,
             'Root-group-command-admission')
        need(type(group_selection) is dict and set(group_selection)==
             {'entered','guardian_sha256','guardian_peer_sha256','premises','child_uid','child_gid','output_path'},
             'group-selection-shape')
        need(group_selection['guardian_sha256']==GUARDIAN_SHA and
             group_selection['guardian_peer_sha256']==GUARDIAN_PEER_SHA,'selected-reviewed-guardian')
        required={'trusted_fixed_compiler_and_helper_call_paths','no_group_or_session_escape',
            'no_late_spawn_after_terminal_empty','complete_same_namespace_proc_visibility',
            'single_owner_no_competing_reaper','selected_runtime_public_SIGCHLD_waitability',
            'blocking_call_latency_and_partial_birth_uncertainty_accepted',
            'Root_loaded_Source_and_helper_no_exec_privilege_verified'}
        premises=group_selection['premises']
        need(type(premises) is dict and set(premises)==required and
             all(type(v) is bool and v for v in premises.values()),'explicit-narrow-Source-premises')
        self.io=io
        need(io.uid()==io.euid()==0 and io.gid()==io.egid()==0,'selected-Root-parent-credentials')
        self.child_uid,self.child_gid=group_selection['child_uid'],group_selection['child_gid']
        need(type(self.child_uid) is int and 0<self.child_uid<2**31 and
             type(self.child_gid) is int and 0<self.child_gid<2**31,'selected-unprivileged-child')
        self.output_path=group_selection['output_path']
        need(type(self.output_path) is str and self.output_path.startswith('/') and
             '\0' not in self.output_path and len(self.output_path)<=4096,'selected-output-path')
        self.entered=group_selection['entered']
        self.work_end,self.cleanup_end=work_end,cleanup_end
        need(all(type(n) in (int,float) and math.isfinite(n) for n in
                 (self.entered,work_end,cleanup_end)) and
             self.entered < work_end <= cleanup_end-4 and cleanup_end-self.entered<=304,
             'original-group-frame')
        need(type(toolchain) is dict and set(toolchain)=={'environment','commands'},'toolchain-shape')
        self.tools={'environment':dict(toolchain['environment']),
                    'commands':{k:dict(v) for k,v in toolchain['commands'].items()}}
        env=self.tools['environment']
        need(set(env)=={'LANG','LC_ALL','PATH','TMPDIR'} and env['LANG']==env['LC_ALL']=='C' and
             all(type(v) is str and '\0' not in v and len(v)<=4096 for v in env.values()) and
             env['PATH'].startswith('/') and env['TMPDIR']==self.output_path,'exact-selected-environment')
        need(1<=len(self.tools['commands'])<=8,'fixed-command-count')
        self._last=self.entered
        self.token=None
        self.terminal=None
        self.cleanup_cutoffs=None
        self.active=self.failed=self.closed=False
        self._live(work_end)

    def _live(self,end,*,cleanup=False):
        cancel=self.io.cancelled()
        now=self.io.now()
        need(type(now) in (int,float) and math.isfinite(now) and now>=self._last,'clock-domain-or-rewind')
        self._last=now
        if now>=end: raise Deadline('original-cleanup-end' if cleanup else 'original-work-end')
        if cancel and not cleanup: raise Cancelled()
        return now

    def _bytes(self,fd,expected,bound,*,empty=False,sha=None):
        self._live(self.work_end)
        before=self.io.fstat(fd)
        need(identity(before)==tuple(expected) and stat.S_ISREG(before.st_mode) and
             before.st_nlink==1 and not before.st_mode & (stat.S_ISUID|stat.S_ISGID) and
             0<=before.st_size<=bound,'held-file-shape')
        need(not empty or before.st_size==0,'fresh-private-output')
        body=bytearray()
        while True:
            self._live(self.work_end)
            part=self.io.pread(fd,min(65536,bound+1-len(body)),len(body))
            need(type(part) is bytes,'bounded-held-bytes')
            if not part: break
            body.extend(part);need(len(body)<=bound,'output-bound')
        after=self.io.fstat(fd)
        need(identity(after)==identity(before) and after.st_size==before.st_size==len(body) and
             after.st_mtime_ns==before.st_mtime_ns and after.st_ctime_ns==before.st_ctime_ns,'held-file-drift')
        self._live(self.work_end)
        if sha is not None: need(hashlib.sha256(body).hexdigest()==sha,'held-executable-SHA')
        return bytes(body)

    def _observe(self):
        self.terminal=self.io.peek(self.token)
        self._live(self.cleanup_end,cleanup=True)
        rows=self.io.members(self.token,self.cleanup_end)
        self._live(self.cleanup_end,cleanup=True)
        return self.io.guardian.disposition(self.terminal,rows,self.token)

    @staticmethod
    def _result():
        return dict(ownership_kind='WAITABLE_LEADER',status='FAIL',first_cause=None,
            cancelled=False,uncertain=False,natural_returncode=None,reaped_returncode=None,
            child_reaped=False,leader_reaped=False,leader_custody_retired=False,
            descendants_absent=False,stdout=b'',stderr=b'')

    def _work_refusal(self,error):
        facts=dict(operation=None,predicate=None)
        if type(error) is Refused:
            guards=GROUP_WORK_REFUSALS
        elif type(error) is self.io.guardian.Refusal:
            guards=GUARDIAN_WORK_REFUSALS
        else:
            return facts
        args=error.args
        if (type(args) is tuple and len(args)==1 and type(args[0]) is str and args[0] in guards):
            facts=dict(operation=guards[args[0]],predicate=args[0])
        return facts

    def _failure(self,result,error,stage):
        first=result['first_cause'] is None
        cancel=isinstance(error,(Cancelled,KeyboardInterrupt))
        result['first_cause']=result['first_cause'] or stage+':'+(
            'CANCELLED' if cancel else 'DEADLINE' if isinstance(error,Deadline) else
            'REFUSED' if isinstance(error,(Refused,self.io.guardian.Refusal)) else
            'IO_FAILED' if isinstance(error,OSError) else 'OTHER')
        result['cancelled'] |= cancel
        if first and result['first_cause']=='work:REFUSED':
            result['work_refusal']=dict(operation=None,predicate=None)
            try: result['work_refusal']=self._work_refusal(error)
            except BaseException as diagnostic_error:
                result['cancelled'] |= isinstance(diagnostic_error,(Cancelled,KeyboardInterrupt))
                result['uncertain']=True

    def _dispose(self,result):
        try:
            entered=self._live(self.cleanup_end,cleanup=True)
            if self.cleanup_cutoffs is None:
                self.cleanup_cutoffs=(min(self.cleanup_end,entered+2),min(self.cleanup_end,entered+3))
            if self.token is None and self.io.has_child():
                self.token=self.io.token(self.cleanup_end)
                self._live(self.cleanup_end,cleanup=True)
            if self.token is None:
                need(not self.io.birth_started,'partial-birth-unknown')
                return
            empty=self._observe()
            if not empty:
                self._failure(result,Refused('group-residue'),'forced-disposal')
                for kind,until in zip(('TERM','KILL'),self.cleanup_cutoffs):
                    self._live(self.cleanup_end,cleanup=True)
                    if self.io.now()>=until: continue
                    if self._observe(): empty=True;break
                    self._live(self.cleanup_end,cleanup=True)
                    if self.io.now()>=until: continue
                    self.io.send_owned(self.token,kind,self.cleanup_end)
                    self._live(self.cleanup_end,cleanup=True)
                    while self.io.now()<until:
                        if self._observe(): empty=True;break
                        self._live(self.cleanup_end,cleanup=True)
                        self.io.pause(max(0,min(.02,until-self.io.now())))
                    if empty: break
            need(empty,'group-absence-unproved')
            need(self._observe(),'final-group-residue')
            self._live(self.cleanup_end,cleanup=True)
            result['descendants_absent']=True
            self.io.reap(self.token,self.terminal,self.cleanup_end)
            result['child_reaped']=result['leader_reaped']=True
            result['reaped_returncode']=self.terminal
            result['leader_custody_retired']=self.io.retired() is True
            need(result['leader_custody_retired'],'leader-retirement-unproved')
            self.token=None
            self._live(self.cleanup_end,cleanup=True)
        except BaseException as error:
            result['uncertain']=True
            self._failure(result,error,'cleanup')
        try:
            if self.io.cancelled(): result['cancelled']=True;self._failure(result,Cancelled(),'cancel')
        except BaseException as error: self._failure(result,error,'cancel-observation');result['uncertain']=True

    def run(self,name):
        need(not self.closed and not self.failed and not self.active and self.token is None,'group-runner-state')
        need(name in self.tools['commands'],'selected-command')
        result=self._result();c=self.tools['commands'][name]
        self.active=True;self.cleanup_cutoffs=None
        try:
            self._live(self.work_end)
            need(set(c)=={'argv','executable_fd','executable_identity','executable_sha256',
                'cwd_fd','cwd_identity','stdout_fd','stdout_identity','stderr_fd','stderr_identity','output_limit'},
                'command-shape')
            need(type(c['argv']) is tuple and 0<len(c['argv'])<=64 and all(
                type(v) is str and '\0' not in v and len(v)<=4096 for v in c['argv']),'exact-argv')
            need(type(c['output_limit']) is int and 0<c['output_limit']<=MAX_OUTPUT,'output-limit')
            fds=[c[k] for k in ('executable_fd','cwd_fd','stdout_fd','stderr_fd')]
            need(all(type(v) is int and v>=0 for v in fds) and len(set(fds))==4,'distinct-borrowed-FDs')
            cwd=self.io.fstat(c['cwd_fd'])
            need(identity(cwd)==tuple(c['cwd_identity']) and stat.S_ISDIR(cwd.st_mode) and
                cwd.st_uid==self.child_uid and cwd.st_gid==self.child_gid and
                stat.S_IMODE(cwd.st_mode)==0o700,'held-private-cwd')
            need(self.io.path_identity(self.output_path)==tuple(c['cwd_identity']),'TMPDIR-held-output-binding')
            for stream in ('stdout','stderr'):
                row=self.io.fstat(c[stream+'_fd'])
                need(row.st_uid==self.io.uid() and row.st_gid==self.io.gid() and
                    stat.S_IMODE(row.st_mode)==0o600,'private-stream-owner')
                self._bytes(c[stream+'_fd'],c[stream+'_identity'],c['output_limit'],empty=True)
            body=self._bytes(c['executable_fd'],c['executable_identity'],64*1024**2,sha=c['executable_sha256'])
            need(body[:4]==b'\x7fELF' and self.io.fstat(c['executable_fd']).st_uid==0,'held-Root-ELF')
            self.io.establish_waitability();self._live(self.work_end)
            self.io.birth(c,self.tools['environment'],self.work_end-self._live(self.work_end),
                          self.child_uid,self.child_gid)
            self.token=self.io.token(self.cleanup_end);self._live(self.work_end)
            while True:
                self._live(self.work_end)
                for stream in ('stdout','stderr'):
                    need(self.io.fstat(c[stream+'_fd']).st_size<=c['output_limit'],'inflight-output-bound')
                empty=self._observe();self._live(self.work_end)
                if self.terminal is not None:
                    result['natural_returncode']=self.terminal
                    need(self.terminal==0 and empty,'natural-zero-without-helper-residue')
                    break
                self.io.pause(max(0,min(.02,self.work_end-self._live(self.work_end))))
        except BaseException as error:self._failure(result,error,'work')
        finally:
            self._dispose(result)
            if result['first_cause'] is None:
                try:
                    self._live(self.work_end)
                    need(identity(self.io.fstat(c['cwd_fd']))==tuple(c['cwd_identity']) and
                         self.io.path_identity(self.output_path)==tuple(c['cwd_identity']),'cwd-path-drift')
                    for stream in ('stdout','stderr'):
                        result[stream]=self._bytes(c[stream+'_fd'],c[stream+'_identity'],c['output_limit'])
                except BaseException as error:self._failure(result,error,'inspection')
            self.active=False
            self.failed |= result['first_cause'] is not None or result['cancelled'] or result['uncertain']
        if (not self.failed and result['leader_reaped'] and result['leader_custody_retired'] and
            result['descendants_absent'] and result['natural_returncode']==result['reaped_returncode']==0):
            result['status']='PASS_NATURAL_ZERO_OWNED_ABSENCE_BYTES_ONLY'
        return result

    def close(self):
        need(not self.active and not self.closed,'group-close-state')
        self.closed=True;result=self._result()
        if self.io.retired():
            result['child_reaped']=result['leader_reaped']=result['leader_custody_retired']=True
            result['descendants_absent']=True
        elif self.token is not None or self.io.birth_started:
            self._dispose(result)
        try:
            self._live(self.cleanup_end,cleanup=True)
            self.io.restore()
            self._live(self.cleanup_end,cleanup=True)
            if self.io.cancelled(): self._failure(result,Cancelled(),'close-cancel')
        except BaseException as error:result['uncertain']=True;self._failure(result,error,'close')
        if (result['first_cause'] is None and not result['cancelled'] and not result['uncertain'] and
                result['leader_custody_retired'] and result['descendants_absent']):
            result['status']='PASS_OWNED_SCOPE_CLOSED_ONLY'
        self.failed |= result['status']=='FAIL'
        return result
