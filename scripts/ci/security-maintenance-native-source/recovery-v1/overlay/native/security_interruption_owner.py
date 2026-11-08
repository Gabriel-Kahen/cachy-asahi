# SPDX-License-Identifier: MIT
"""Linux owned-child runner and nonce-scoped blocking-checkpoint interruption.

The caller must be an exclusive process owner inside the separately fenced
native root. This module never launches a package command by itself. The leader
stays WNOWAIT-reserved until its group and subreaper-adopted children are gone.
"""
import ctypes
import errno
import os
from pathlib import Path
import re
import resource
import select
import signal
import socket
import stat
import struct
import subprocess
import time
import hashlib

PR_SET_CHILD_SUBREAPER, PR_GET_CHILD_SUBREAPER = 36, 37
PROC_CAP, RECORD_CAP, FILE_CAP = 65536, 16384, 33554432


class OwnedProcessFailure(RuntimeError):
    def __init__(self, message, result=None):
        super().__init__(message)
        self.result = result


def need(ok, reason):
    if not ok:
        raise OwnedProcessFailure(reason)


def _stat(pid):
    raw = Path('/proc/%d/stat' % pid).read_bytes()
    end = raw.rfind(b') ')
    need(end > 0, 'ordinary proc stat')
    values = raw[end + 2:].split()
    return dict(pid=pid, state=values[0].decode(), ppid=int(values[1]),
                pgid=int(values[2]), sid=int(values[3]), starttime=int(values[19]),
                uid=os.stat('/proc/%d' % pid).st_uid)


def _processes():
    rows = {}
    with os.scandir('/proc') as entries:
        for entry in entries:
            if entry.name.isdecimal():
                need(len(rows) < PROC_CAP, 'bounded process inventory')
                try:
                    row = _stat(int(entry.name))
                    rows[row['pid']] = row
                except (FileNotFoundError, ProcessLookupError):
                    pass
    return rows


def _subreaper(value=None):
    libc = ctypes.CDLL(None, use_errno=True)
    old = ctypes.c_int()
    need(libc.prctl(PR_GET_CHILD_SUBREAPER, ctypes.byref(old), 0, 0, 0) == 0,
         'read Linux subreaper state')
    if value is not None:
        need(libc.prctl(PR_SET_CHILD_SUBREAPER, int(value), 0, 0, 0) == 0,
             'set Linux subreaper state')
    return old.value


def _peek(pid):
    return os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)


def _dead(fd):
    return bool(select.select([fd], [], [], 0)[0])


def _limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_CAP, FILE_CAP))


def _verify_bounded(callback, raw, identity, deadline):
    remaining = deadline - time.monotonic()
    need(remaining > 0 and signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0),
         'positive checkpoint budget and no foreign alarm timer')
    old = signal.getsignal(signal.SIGALRM)
    def expired(*args):
        raise OwnedProcessFailure('checkpoint verification deadline')
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, remaining)
    try:
        return callback(raw, identity)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


class OwnedProcessRunner:
    def __init__(self, home):
        self.home = Path(home).absolute()
        need(self.home == self.home.resolve() and self.home.is_dir(), 'ordinary owned runner home')
        s = self.home.stat()
        need(s.st_uid == os.geteuid() and stat.S_IMODE(s.st_mode) == 0o700, 'private owned runner home')
        self.counter, self.busy, self.last_result = 0, False, None

    def run(self, argv, *, env, cwd, pass_fds=(), seconds=30, output_cap=1048576):
        return self._execute(argv, env, cwd, pass_fds, seconds, output_cap, None)

    def interrupt(self, argv, *, env, cwd, record_fd, nonce, verify_checkpoint,
                  seconds=30, output_cap=1048576, pass_fds=()):
        need(type(nonce) is str and re.fullmatch('[0-9a-f]{32}', nonce), 'fresh 32-hex nonce')
        need(callable(verify_checkpoint), 'checkpoint verifier required')
        s = os.fstat(record_fd)
        need(stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode) == 0o600
             and s.st_uid == os.geteuid() and s.st_gid == os.getegid()
             and s.st_nlink == 1 and s.st_size == 0, 'fresh owned0600 checkpoint record')
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        try:
            parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            os.fchmod(parent.fileno(), 0o600); os.fchmod(child.fileno(), 0o600)
            need(3 <= child.fileno() <= 127 and 3 <= record_fd <= 127, 'bounded inherited checkpoint FDs')
            child_env = dict(env, CACHY_SECURITY_RECOVERY_FD=str(child.fileno()),
                             CACHY_SECURITY_RECOVERY_NONCE=nonce,
                             CACHY_SECURITY_OBSERVER_FD=str(record_fd),
                             CACHY_SECURITY_OBSERVER_OWNER=str(os.getpid()))
            context = dict(parent=parent, child=child, record_fd=record_fd, nonce=nonce,
                           verify=verify_checkpoint, record_identity=(s.st_dev, s.st_ino))
            return self._execute(argv, child_env, cwd,
                tuple(pass_fds) + (child.fileno(), record_fd), seconds, output_cap, context)
        finally:
            parent.close(); child.close()

    def _execute(self, argv, env, cwd, pass_fds, seconds, output_cap, checkpoint):
        need(not self.busy, 'exclusive owned command')
        need(type(argv) in (list, tuple) and 1 <= len(argv) <= 128
             and all(type(a) is str and a and '\0' not in a and len(a) <= 4096 for a in argv), 'bounded argv')
        need(type(env) is dict and all(type(k) is type(v) is str and '\0' not in k + v for k, v in env.items()), 'explicit environment')
        cwd = Path(cwd).absolute()
        need(cwd == cwd.resolve() and cwd.is_dir(), 'ordinary explicit cwd')
        need(type(seconds) is int and 1 <= seconds <= 1800
             and type(output_cap) is int and 1 <= output_cap <= FILE_CAP, 'owned command limits')
        need(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, 'default SIGCHLD disposition')
        need(len(os.listdir('/proc/self/task')) == 1, 'exclusive single-threaded owner')
        existing = [r for r in _processes().values() if r['ppid'] == os.getpid()]
        need(not existing, 'other direct children exist; do not touch them')
        self.busy = True
        self.counter += 1
        stem = self.home / ('owned-%03d' % self.counter)
        out = err = process = pidfd = None
        tracked, reaped, cleanup_uids = {}, set(), []
        old_subreaper = None
        started, wall_started = time.monotonic(), int(time.time())
        deadline = started + seconds
        failure, intentional, forced, verified, raw_records = None, False, False, None, None
        channel = None
        identity, status, leader_reaped = None, None, False
        try:
            old_subreaper = _subreaper(1)
            out = os.open(str(stem) + '.stdout', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
            err = os.open(str(stem) + '.stderr', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
            process = subprocess.Popen(list(argv), cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                stdout=out, stderr=err, pass_fds=tuple(set(pass_fds)), start_new_session=True,
                close_fds=True, preexec_fn=_limits)
            identity = _stat(process.pid)
            pidfd = os.pidfd_open(process.pid, 0)
            need(identity['pgid'] == identity['sid'] == process.pid, 'owned fresh session/group')
            if checkpoint:
                checkpoint['child'].close()
            while _peek(process.pid) is None:
                self._track(process.pid, identity, tracked, reaped)
                need(time.monotonic() < deadline, 'owned command deadline')
                need(os.fstat(out).st_size + os.fstat(err).st_size <= output_cap, 'owned output limit')
                if checkpoint:
                    readable = select.select([checkpoint['parent']], [], [], 0.01)[0]
                    if readable:
                        msg, anc, flags, _ = checkpoint['parent'].recvmsg(128, socket.CMSG_SPACE(struct.calcsize('3i')))
                        need(not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), 'complete checkpoint packet')
                        creds = [struct.unpack('3i', data) for level, kind, data in anc
                                 if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS
                                 and len(data) == struct.calcsize('3i')]
                        need(creds == [(process.pid, os.geteuid(), os.getegid())], 'actual owned sender credentials')
                        need(msg == ('RECOVERY_BLOCK_V1:' + checkpoint['nonce']).encode('ascii'), 'exact nonce checkpoint packet')
                        rs = os.fstat(checkpoint['record_fd'])
                        need((rs.st_dev, rs.st_ino) == checkpoint['record_identity']
                             and 0 < rs.st_size <= RECORD_CAP and stat.S_IMODE(rs.st_mode) == 0o600
                             and rs.st_nlink == 1, 'same complete checkpoint record')
                        raw_records = os.pread(checkpoint['record_fd'], RECORD_CAP + 1, 0)
                        need(len(raw_records) == rs.st_size and raw_records.endswith(b'\n'), 'complete bounded checkpoint records')
                        callback_identity = dict(identity, ppid=os.getpid(), uid=os.geteuid(), gid=os.getegid())
                        verified = _verify_bounded(checkpoint['verify'], raw_records, callback_identity, deadline)
                        need(type(verified) is dict, 'verified checkpoint DATA object')
                        need(os.pread(checkpoint['record_fd'], RECORD_CAP + 1, 0) == raw_records,
                             'checkpoint record changed during validation')
                        need(time.monotonic() < deadline and _peek(process.pid) is None
                             and _stat(process.pid)['starttime'] == identity['starttime'] and not _dead(pidfd),
                             'same blocked original still alive before interruption')
                        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                        intentional = True
                        channel = dict(protocol='RECOVERY_BLOCK_V1', nonce=checkpoint['nonce'],
                            sender=dict(pid=creds[0][0], uid=creds[0][1], gid=creds[0][2]),
                            record=dict(bytes=len(raw_records), sha256=hashlib.sha256(raw_records).hexdigest()))
                        break
                else:
                    time.sleep(0.005)
            if checkpoint:
                need(intentional, 'child did not reach a verified blocking checkpoint')
            # Bound the intentional wait separately within the same command deadline.
            while _peek(process.pid) is None:
                need(time.monotonic() < deadline, 'original interruption did not retire')
                self._track(process.pid, identity, tracked, reaped)
                time.sleep(0.005)
            need(time.monotonic() <= deadline, 'owned command deadline')
        except BaseException as error:
            failure = error
            forced = process is not None
        finally:
            if process is not None and identity is not None:
                try:
                    if _peek(process.pid) is None:
                        if pidfd is not None:
                            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                        else:
                            # Setup failure only, before any direct reap. This
                            # cannot produce a positive interruption receipt.
                            need(_stat(process.pid)['starttime'] == identity['starttime'], 'same setup child')
                            os.kill(process.pid, signal.SIGKILL)
                        forced = True
                    until = time.monotonic() + 5
                    while _peek(process.pid) is None:
                        need(time.monotonic() < until, 'original kill retirement timeout')
                        self._track(process.pid, identity, tracked, reaped)
                        time.sleep(0.005)
                    # Original is a reserved zombie. Reparented descendants belong
                    # to this temporary subreaper, including session escapees.
                    while True:
                        self._track(process.pid, identity, tracked, reaped)
                        live = []
                        for key, fd in tuple(tracked.items()):
                            if not _dead(fd):
                                live.append(key)
                                try:
                                    member = _stat(key[0])
                                    if member['starttime'] == key[1]:
                                        cleanup_uids.append(member['uid'])
                                except (FileNotFoundError, ProcessLookupError):
                                    pass
                                signal.pidfd_send_signal(fd, signal.SIGKILL)
                                forced = True
                            try:
                                row = os.waitid(os.P_PID, key[0], os.WEXITED | os.WNOHANG | os.WNOWAIT)
                            except ChildProcessError:
                                row = None
                                if _dead(fd):
                                    # The original may already have reaped it;
                                    # any unreaped zombie remains in inventory
                                    # and is reopened after kernel adoption.
                                    os.close(fd); del tracked[key]
                            if row is not None:
                                os.waitpid(key[0], 0)
                                reaped.add(key)
                                os.close(fd); del tracked[key]
                        active = [r for r in _processes().values() if r['pid'] != process.pid
                                  and (r['sid'] == process.pid or r['ppid'] == os.getpid())]
                        if not active and not tracked:
                            break
                        need(time.monotonic() < until, 'owned group/descendant retirement timeout')
                        time.sleep(0.005)
                    need(_stat(process.pid)['starttime'] == identity['starttime'], 'same leader reserved before reap')
                    observed = _peek(process.pid)
                    need(observed is not None, 'WNOWAIT leader exit reservation')
                    _, status = os.waitpid(process.pid, 0)
                    leader_reaped = True
                    process.returncode = os.waitstatus_to_exitcode(status)
                    # No numeric operation on the leader after this point.
                except BaseException as error:
                    if failure is None:
                        failure = error
            for fd in tracked.values():
                os.close(fd)
            if pidfd is not None:
                os.close(pidfd)
            try:
                if old_subreaper is not None:
                    _subreaper(old_subreaper)
            finally:
                self.busy = False
        if out is not None and err is not None and os.fstat(out).st_size + os.fstat(err).st_size > output_cap:
            failure = failure or OwnedProcessFailure('owned output limit')
        try:
            stdout = self._read_output(out, output_cap) if out is not None else b''
            stderr = self._read_output(err, output_cap) if err is not None else b''
        finally:
            if out is not None: os.close(out)
            if err is not None: os.close(err)
        elapsed = time.monotonic() - started
        code = None if status is None else os.waitstatus_to_exitcode(status)
        interrupted = intentional and code == -signal.SIGKILL and leader_reaped and failure is None
        natural = not intentional and not forced and leader_reaped and failure is None
        receipt = dict(exit=code, error=None if failure is None else type(failure).__name__,
            timeout=isinstance(failure, OwnedProcessFailure) and 'deadline' in str(failure),
            forced_retirement=forced, passed=(natural and code == 0) or interrupted,
            reaped=leader_reaped, group_absent=leader_reaped, descendants_absent=leader_reaped,
            pid_reserved_until_retirement=leader_reaped, pid=None if process is None else process.pid,
            starttime=None if identity is None else identity['starttime'],
            method='OWNED_PIDFD_INTERRUPT' if interrupted else 'OWNED_NATURAL_COMMAND',
            signal=9 if interrupted else None, checkpoint_blocked_until_interrupt=interrupted,
            natural_exit=natural, leader_held_until_group_inspection=leader_reaped,
            exit_observed_via_waitpid=leader_reaped, ownership_lost=False,
            retirement='REAPED' if leader_reaped else 'UNRESOLVED', forced_cleanup=forced,
            cleanup_member_uids=sorted(set(cleanup_uids)), elapsed_seconds=elapsed,
            wall_started=wall_started, wall_finished=int(time.time()))
        result = dict(stdout=stdout, stderr=stderr, retirement=receipt,
                      checkpoint=raw_records, verified=verified, checkpoint_channel=channel)
        self.last_result = result
        if failure is not None or (checkpoint and not interrupted):
            raise OwnedProcessFailure(str(failure or 'not the owned SIGKILL interruption'), result) from failure
        return result

    @staticmethod
    def _read_output(fd, maximum):
        return os.pread(fd, maximum, 0)

    @staticmethod
    def _track(leader, identity, tracked, reaped):
        rows = _processes()
        owned = {leader}
        changed = True
        while changed:
            changed = False
            for pid, row in rows.items():
                if pid != leader and (row['sid'] == leader or row['ppid'] in owned
                                      or row['ppid'] == os.getpid()) and pid not in owned:
                    owned.add(pid); changed = True
        for pid in owned - {leader}:
            row = rows[pid]; key = (pid, row['starttime'])
            if key in tracked or key in reaped:
                continue
            fd = None
            try:
                fd = os.pidfd_open(pid, 0)
                if _stat(pid)['starttime'] != row['starttime']:
                    os.close(fd); continue
                tracked[key] = fd
            except (FileNotFoundError, ProcessLookupError):
                if fd is not None:
                    os.close(fd)
