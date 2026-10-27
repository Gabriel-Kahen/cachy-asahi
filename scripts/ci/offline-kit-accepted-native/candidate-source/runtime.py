#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Finite hosted-job process groups; forked from the held kernel-stage runtime."""
from contextlib import contextmanager
import ctypes
import math
import os
from pathlib import Path
import re
import resource
import selectors
import signal
import subprocess
import threading
import time

MAX_SECONDS = 6 * 60 * 60
MAX_JOB_SECONDS = 20760
MAX_OUTPUT = 8 * 1024 * 1024
SIGNALS = (signal.SIGINT, signal.SIGTERM)
_LIBC = ctypes.CDLL(None, use_errno=True)


class Cancelled(BaseException):
    def __init__(self, signum=None):
        self.signum = signum
        super().__init__('cancelled')


@contextmanager
def _handlers(handler):
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
    previous = {number: signal.getsignal(number) for number in SIGNALS}
    try:
        for number in SIGNALS:
            signal.signal(number, handler)
        signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        yield
    finally:
        # Restore the pair without a cancellation exception leaving half of
        # the old handlers installed. Consume signals queued during restoration
        # and route them through this context's handler after both are restored.
        restore_mask = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
        pending = []
        try:
            for number, original in previous.items():
                signal.signal(number, original)
            for number in SIGNALS:
                if number not in restore_mask and number in signal.sigpending():
                    signal.sigwait({number}); pending.append(number)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, restore_mask)
        for number in pending:
            handler(number, None)


@contextmanager
def cancellation_handlers():
    def cancel(number, frame):
        raise Cancelled(number)
    with _handlers(cancel):
        yield


@contextmanager
def defer_signals():
    events = []
    with _handlers(lambda number, frame: events.append(number)):
        yield events


def _prctl(option, value):
    if _LIBC.prctl(ctypes.c_int(option), ctypes.c_ulong(value), ctypes.c_ulong(0),
                   ctypes.c_ulong(0), ctypes.c_ulong(0)) != 0:
        raise OSError(ctypes.get_errno(), 'prctl failed')


def _seconds(value):
    if type(value) not in (int, float) or not 0 < value <= MAX_SECONDS or not math.isfinite(value):
        raise ValueError('invalid-time-bound')
    return float(value)


def _child_setup(parent, mask, seconds):
    _prctl(1, signal.SIGKILL)  # PR_SET_PDEATHSIG; not inherited by grandchildren.
    if os.getppid() != parent:
        os.kill(os.getpid(), signal.SIGKILL)
    for kind, bound in ((resource.RLIMIT_CPU, math.ceil(seconds) + 5),
                        (resource.RLIMIT_AS, 10 * 1024 ** 3),
                        (resource.RLIMIT_FSIZE, 4 * 1024 ** 3),
                        (resource.RLIMIT_NOFILE, 128), (resource.RLIMIT_CORE, 0)):
        hard = resource.getrlimit(kind)[1]
        if kind == resource.RLIMIT_AS and hard != resource.RLIM_INFINITY and hard < bound:
            raise ValueError('host-address-space-limit')
        bound = min(bound, hard) if hard != resource.RLIM_INFINITY else bound
        resource.setrlimit(kind, (bound, bound))
    signal.pthread_sigmask(signal.SIG_SETMASK, mask)


class OwnershipLost(ValueError):
    """Child reservation is unknown; no later numeric operation is authorized."""


def _child_policy(*, normalize=False):
    if threading.current_thread() is not threading.main_thread() or threading.active_count() != 1:
        raise ValueError('threaded-runner')
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise ValueError('unsafe-SIGCHLD-policy')
    if normalize:
        # Clear inherited SA_NOCLDWAIT even when getsignal appears default.
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)


def _exit_code(state):
    if state is None:
        return None
    return state.si_status if state.si_code == os.CLD_EXITED else -state.si_status


def _event_matches(state, pid):
    if state is None:
        return True
    number = getattr(state, 'si_pid', None)
    code = getattr(state, 'si_code', None)
    status = getattr(state, 'si_status', None)
    return (type(number) is int and number == pid and type(code) is int and
            code in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED) and type(status) is int and
            (0 <= status <= 255 if code == os.CLD_EXITED else 0 < status < signal.NSIG))


class _OwnedGroup:
    """A waitable, unreaped leader reserves the numeric PID/PGID until retire()."""
    def __init__(self, process):
        self.process = process
        self.lost = False
        self.retired = False
        self.nonleader_members_absent_before_reap = False

    def abandon(self):
        self.lost = True
        self.nonleader_members_absent_before_reap = False
        self.process.returncode = None
        # Popen.__del__/_active must not consume unknown status or synthesize0.
        self.process._child_created = False

    def _lose(self, reason):
        self.abandon()
        raise OwnershipLost(reason)

    def observe(self):
        if self.lost or self.retired:
            raise OwnershipLost('child-reservation-unavailable')
        if self.process.returncode is not None:
            self._lose('leader-already-reaped-or-unobserved-status')
        try:
            _child_policy()
        except BaseException:
            self.abandon()
            raise
        try:
            state = os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except OSError as error:
            self._lose('leader-ownership-observation-failed:' + type(error).__name__)
        if not _event_matches(state, self.process.pid):
            self._lose('leader-wait-event-differs')
        return state

    def signal(self, number):
        self.observe()  # No numeric signal, including signal0, after loss/reap.
        try:
            os.killpg(self.process.pid, number)
        except ProcessLookupError:
            # An exited waitable leader can reserve a number without a live group.
            pass

    def members(self):
        self.observe()  # Reservation covers this group census, not a later reap.
        result = {}
        for entry in Path('/proc').iterdir():
            if not entry.name.isdecimal() or int(entry.name) == self.process.pid:
                continue
            try:
                text = (entry / 'stat').read_text()
            except (FileNotFoundError, ProcessLookupError):
                continue
            fields = text.rpartition(') ')[2].split()
            if len(fields) >= 4 and int(fields[2]) == self.process.pid:
                if int(fields[3]) != self.process.pid:
                    raise ValueError('owned-group-session-differs')
                result[int(entry.name)] = (fields[0], int(fields[1]))
        return result

    def reap_adopted(self, members):
        # Never waitpid(-pgid): it could release the reserving leader first.
        for pid, (state, parent) in members.items():
            if state != 'Z' or parent != os.getpid():
                continue
            self.observe()
            try:
                event = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            except OSError as error:
                self._lose('descendant-ownership-observation-failed:' + type(error).__name__)
            if event is None:
                continue
            if not _event_matches(event, pid):
                self._lose('descendant-wait-event-differs')
            self.observe()
            try:
                actual, _ = os.waitpid(pid, os.WNOHANG)
            except OSError as error:
                self._lose('descendant-final-reap-failed:' + type(error).__name__)
            if actual != pid:
                self._lose('descendant-final-reap-not-observed')
            # This numeric child is never probed/signalled again from this snapshot.

    def retire(self):
        # This is the last group census. No numeric group operation follows it.
        event = self.observe()
        if event is None or self.members():
            raise ValueError('process-cleanup-incomplete')
        self.nonleader_members_absent_before_reap = True
        self.retired = True  # Revoke all group methods before the consuming wait.
        try:
            pid, status = os.waitpid(self.process.pid, os.WNOHANG)
        except OSError as error:
            self._lose('leader-final-reap-failed:' + type(error).__name__)
        if pid != self.process.pid:
            self._lose('leader-final-reap-not-observed')
        code = os.waitstatus_to_exitcode(status)
        if code != _exit_code(event):
            self._lose('leader-final-status-differs')
        self.process.returncode = code  # Sole accepted status comes from waitpid.
        return code


def _cleanup(group):
    """Retire only this reserved group, consuming the leader after all operations."""
    term_sent = kill_sent = False
    deadline = time.monotonic() + 2
    while True:
        event = group.observe()
        members = group.members()
        group.reap_adopted(members)
        members = group.members()
        if event is not None and not members:
            return group.retire()
        if not term_sent:
            group.signal(signal.SIGTERM)
            term_sent = True
        if time.monotonic() >= deadline:
            if kill_sent:
                raise ValueError('process-cleanup')
            group.signal(signal.SIGKILL)
            kill_sent = True
            deadline = time.monotonic() + 1
        time.sleep(0.01 if kill_sent else 0.02)


class Runner:
    def __init__(self, deadline_seconds, env, log_dir):
        seconds = _seconds(deadline_seconds)
        if seconds > MAX_JOB_SECONDS:
            raise ValueError('invalid-job-time-bound')
        if type(env) is not dict or len(env) > 256 or any(
                type(key) is not str or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', key)
                or type(value) is not str or '\0' in value for key, value in env.items()):
            raise ValueError('invalid-environment')
        if sum(len(key.encode()) + len(value.encode()) + 2 for key, value in env.items()) > 65536:
            raise ValueError('invalid-environment')
        requested = Path(log_dir)
        if any(path.is_symlink() for path in (requested, *requested.parents)):
            raise ValueError('unsafe-log-directory')
        requested.mkdir(mode=0o700, exist_ok=True)
        if not requested.is_dir():
            raise ValueError('unsafe-log-directory')
        self.log_dir = requested.resolve()
        self.env = dict(env)
        self.deadline = time.monotonic() + seconds
        _prctl(36, 1)  # PR_SET_CHILD_SUBREAPER, process-local for group reaping.

    def run(self, argv, timeout=300, limit=MAX_OUTPUT, log=None):
        return self._run_many([argv], timeout, [log], limit)[0]

    def run_many(self, commands, timeout, lognames):
        if type(commands) not in (list, tuple) or len(commands) != 2:
            raise ValueError('parallel-command-count')
        return self._run_many(commands, timeout, lognames, MAX_OUTPUT)

    def _run_many(self, commands, timeout, lognames, limit):
        _child_policy(normalize=True)
        timeout = _seconds(timeout)
        if type(limit) is not int or not 0 < limit <= MAX_OUTPUT:
            raise ValueError('invalid-output-bound')
        if type(lognames) not in (list, tuple) or len(lognames) != len(commands):
            raise ValueError('invalid-log-count')
        for argv in commands:
            if type(argv) not in (list, tuple) or not 0 < len(argv) <= 256 or any(
                    type(arg) is not str or '\0' in arg for arg in argv):
                raise ValueError('invalid-argv')
            if not argv[0] or sum(len(arg.encode()) + 1 for arg in argv) > 65536:
                raise ValueError('invalid-argv')
        paths = []
        for name in lognames:
            if name is None:
                paths.append(None)
                continue
            path = Path(name)
            if not path.is_absolute():
                path = self.log_dir / path
            if path.parent != self.log_dir or path.name in ('', '.', '..'):
                raise ValueError('unsafe-log-path')
            paths.append(path)
        if len(set(p for p in paths if p is not None)) != sum(p is not None for p in paths):
            raise ValueError('duplicate-log-path')
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError('deadline-exhausted')
        end = time.monotonic() + min(timeout, remaining)
        processes, groups, targets = [], [], []
        outputs = [bytearray() for _ in commands]
        selector = selectors.DefaultSelector()

        def append(index, data):
            room = limit - len(outputs[index])
            outputs[index].extend(data[:room])
            if len(data) > room:
                raise ValueError('output-bound')

        try:
            for path in paths:
                targets.append(path.open('xb') if path is not None else None)
            for index, argv in enumerate(commands):
                mask = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
                try:
                    parent = os.getpid()
                    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, env=self.env, start_new_session=True, close_fds=True,
                        preexec_fn=lambda: _child_setup(parent, mask, min(timeout, remaining)))
                    processes.append(process)  # Track before delivering pending cancellation.
                    groups.append(_OwnedGroup(process))
                    groups[-1].observe()
                finally:
                    signal.pthread_sigmask(signal.SIG_SETMASK, mask)
                os.set_blocking(process.stdout.fileno(), False)
                selector.register(process.stdout, selectors.EVENT_READ, index)
            while True:
                codes = [_exit_code(group.observe()) for group in groups]
                if all(code is not None for code in codes) or any(code not in (None, 0) for code in codes):
                    break
                left = end - time.monotonic()
                if left <= 0:
                    raise ValueError('command-timeout')
                for key, _ in selector.select(min(left, 0.05)):
                    data = os.read(key.fd, 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                    else:
                        append(key.data, data)
        finally:
            with defer_signals() as deferred:
                errors = []
                for group in groups:
                    try:
                        _cleanup(group)
                    except BaseException as error:
                        group.abandon()
                        errors.append(error)
                for process in processes:
                    if not any(group.process is process and group.retired and not group.lost for group in groups):
                        process.returncode = None
                        process._child_created = False
                for index, process in enumerate(processes):
                    try:
                        os.set_blocking(process.stdout.fileno(), False)
                        while True:
                            try:
                                data = os.read(process.stdout.fileno(), 65536)
                            except BlockingIOError:
                                raise ValueError('process-output-incomplete') from None
                            if not data:
                                break
                            append(index, data)
                    except BaseException as error:
                        errors.append(error)
                    finally:
                        process.stdout.close()
                selector.close()
                for index, target in enumerate(targets):
                    if target is not None:
                        try:
                            target.write(outputs[index])
                        except BaseException as error:
                            errors.append(error)
                        finally:
                            target.close()
            if deferred:
                raise Cancelled(deferred[0])
            if errors:
                raise errors[0]
        return [subprocess.CompletedProcess(argv, process.returncode, bytes(output), None)
                for argv, process, output in zip(commands, processes, outputs)]
