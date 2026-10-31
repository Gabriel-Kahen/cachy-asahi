#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Finite Linux job runner; larger pinned rootfs files and bounded separate streams."""
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

MAX_SECONDS = 3 * 60 * 60
MAX_OUTPUT = 8 * 1024 * 1024
SIGNALS = (signal.SIGINT, signal.SIGTERM)
_LIBC = ctypes.CDLL(None, use_errno=True)


class Cancelled(BaseException):
    def __init__(self, signum=None):
        self.signum = signum
        super().__init__('cancelled')


@contextmanager
def _handlers(handler):
    previous = {number: signal.getsignal(number) for number in SIGNALS}
    try:
        for number in SIGNALS:
            signal.signal(number, handler)
        yield
    finally:
        for number, original in previous.items():
            signal.signal(number, original)


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
                        (resource.RLIMIT_AS, 2 * 1024 ** 3),
                        (resource.RLIMIT_FSIZE, 2 * 1024 ** 3),
                        (resource.RLIMIT_NOFILE, 128), (resource.RLIMIT_CORE, 0)):
        hard = resource.getrlimit(kind)[1]
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

    def run(self, argv, timeout=300, limit=MAX_OUTPUT, log=None, separate_stderr=False):
        if type(separate_stderr) is not bool:
            raise ValueError('invalid-stream-mode')
        if threading.active_count() != 1:
            raise ValueError('threaded-runner')
        timeout = _seconds(timeout)
        if type(limit) is not int or not 0 < limit <= MAX_OUTPUT:
            raise ValueError('invalid-output-bound')
        if type(argv) not in (list, tuple) or not 0 < len(argv) <= 256 or any(
                type(arg) is not str or '\0' in arg for arg in argv):
            raise ValueError('invalid-argv')
        if not argv[0] or sum(len(arg.encode()) + 1 for arg in argv) > 65536:
            raise ValueError('invalid-argv')
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError('deadline-exhausted')
        end = time.monotonic() + min(timeout, remaining)
        target = None
        if log is not None:
            path = Path(log)
            if not path.is_absolute():
                path = self.log_dir / path
            if path.parent != self.log_dir or path.name in ('', '.', '..'):
                raise ValueError('unsafe-log-path')
            target = path.open('xb')
        process, output, errors, combined = None, bytearray(), bytearray(), bytearray()
        selector = selectors.DefaultSelector()

        def append(data, is_error=False):
            room = limit - len(combined)
            combined.extend(data[:room])
            (errors if is_error else output).extend(data[:room])
            if len(data) > room:
                raise ValueError('output-bound')

        try:
            mask = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
            try:
                parent = os.getpid()
                process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE if separate_stderr else subprocess.STDOUT, env=self.env, start_new_session=True, close_fds=True,
                    preexec_fn=lambda: _child_setup(parent, mask, min(timeout, remaining)))
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, mask)
            for stream, is_error in ((process.stdout, False), (process.stderr, True)):
                if stream is not None:
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, is_error)
            while process.poll() is None:
                left = end - time.monotonic()
                if left <= 0:
                    raise ValueError('command-timeout')
                for key, _ in selector.select(min(left, 0.05)):
                    data = os.read(key.fd, 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                    else:
                        append(data, key.data)
        finally:
            with defer_signals() as deferred:
                try:
                    if process is not None:
                        try:
                            _cleanup(process)
                            for stream, is_error in ((process.stdout, False), (process.stderr, True)):
                                if stream is not None:
                                    while True:
                                        data = os.read(stream.fileno(), 65536)
                                        if not data:
                                            break
                                        append(data, is_error)
                        finally:
                            process.stdout.close()
                            if process.stderr is not None:
                                process.stderr.close()
                finally:
                    selector.close()
                    if target is not None:
                        try:
                            target.write(combined)
                        finally:
                            target.close()
            if deferred:
                raise Cancelled(deferred[0])
        return subprocess.CompletedProcess(argv, process.returncode, bytes(output), bytes(errors) if separate_stderr else None)
