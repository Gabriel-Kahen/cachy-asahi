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


def _group_signal(group, number):
    try:
        os.killpg(group, number)
        return True
    except ProcessLookupError:
        return False


def _reap(process):
    while True:
        try:
            pid, status = os.waitpid(-process.pid, os.WNOHANG)
        except ChildProcessError:
            break
        if not pid:
            break
        if pid == process.pid:
            process.returncode = os.waitstatus_to_exitcode(status)


def _cleanup(process):
    # Reap only this command's group; adopted grandchildren are owned descendants.
    _group_signal(process.pid, signal.SIGTERM)
    end = time.monotonic() + 2
    while True:
        process.poll()
        _reap(process)
        if not _group_signal(process.pid, 0):
            break
        if time.monotonic() >= end:
            _group_signal(process.pid, signal.SIGKILL)
            break
        time.sleep(0.02)
    end = time.monotonic() + 1
    while _group_signal(process.pid, 0):
        process.poll()
        _reap(process)
        if time.monotonic() >= end:
            raise ValueError('process-cleanup')
        time.sleep(0.01)
    process.wait(timeout=1)


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
        self.parallel_first_failure = None
        if threading.current_thread() is not threading.main_thread() or threading.active_count() != 1:
            raise ValueError('threaded-runner')
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
        processes, targets = [], []
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
                finally:
                    signal.pthread_sigmask(signal.SIG_SETMASK, mask)
                os.set_blocking(process.stdout.fileno(), False)
                selector.register(process.stdout, selectors.EVENT_READ, index)
            while True:
                codes = [process.poll() for process in processes]
                if all(code is not None for code in codes) or any(code not in (None, 0) for code in codes):
                    if len(codes) == 2 and any(code not in (None, 0) for code in codes):
                        self.parallel_first_failure = tuple(codes)
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
                for process in processes:
                    try:
                        _cleanup(process)
                    except BaseException as error:
                        errors.append(error)
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
