#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Adapted from held kernel-native-job/runtime.py; own finite process groups."""
from contextlib import contextmanager, nullcontext
import ctypes
import fcntl
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
import subprocess
import threading
import time
from types import MappingProxyType

MAX_JOB_SECONDS = 8460
MAX_OUTPUT, MAX_PRIVATE, MIN_FREE = 8 * 1024**2, 16 * 1024**3, 8 * 1024**3
MAX_NODES, MAX_DEPTH, RESOURCE_INTERVAL = 8192, 16, .25
CLEANUP_OUTPUT, CLEANUP_SECONDS = 128 * 1024, 180
SIGNALS = (signal.SIGINT, signal.SIGTERM)
_LIBC = ctypes.CDLL(None, use_errno=True)
_ACTIVE = None


def need(value, message):
    if not value:
        raise ValueError(message)


class Cancelled(BaseException):
    def __init__(self, signum=None):
        self.signum = signum
        super().__init__('cancelled')


class ResourceFailure(ValueError):
    def __init__(self, observation):
        self.observation = observation
        super().__init__(observation['reason'])


class _Cancellation:
    def __init__(self):
        self.signum, self.deferrals = None, 0

    def interrupt(self, signum, *_):
        self.signum = signum
        if not self.deferrals:
            raise Cancelled(signum)

    def check(self):
        if self.signum is not None:
            raise Cancelled(self.signum)

    @contextmanager
    def defer(self):
        self.deferrals += 1
        try:
            yield
        finally:
            self.deferrals -= 1


@contextmanager
def cancellation_handlers():
    global _ACTIVE
    if _ACTIVE is not None:
        _ACTIVE.check()
        yield _ACTIVE
        _ACTIVE.check()
        return
    need(threading.current_thread() is threading.main_thread(), 'main-thread-required')
    state, previous = _Cancellation(), {}
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
    try:
        for signum in SIGNALS:
            previous[signum] = signal.signal(signum, state.interrupt)
        _ACTIVE = state
        signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        yield state
        state.check()
    finally:
        signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        _ACTIVE = None
        signal.pthread_sigmask(signal.SIG_SETMASK, mask)


@contextmanager
def defer_signals():
    """Remember bounded events; the caller inspects them before state.check()."""
    state, events, previous = _ACTIVE, [], {}
    def remember(signum, *_):
        if len(events) < 32: events.append(signum)
        if state is not None: state.signum = signum
    with state.defer() if state is not None else nullcontext():
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
        try:
            for signum in SIGNALS: previous[signum] = signal.signal(signum, remember)
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
            yield events
        finally:
            signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
            for signum, handler in previous.items(): signal.signal(signum, handler)
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)


def mark_cancelled(signum=signal.SIGTERM):
    """Bridge a held helper's remembered cancellation into this job scope."""
    need(_ACTIVE is not None and signum in SIGNALS, 'active-cancellation-scope-required')
    if _ACTIVE.signum is None: _ACTIVE.signum = signum


def check_cancelled():
    if _ACTIVE is not None: _ACTIVE.check()


def _cleanup_grammar(argv):
    need(len(argv) >= 3 and argv[1] in {'--host=unix:///run/docker.sock', '--host=unix:///var/run/docker.sock'},
         'cleanup-local-endpoint-required')
    args = list(argv[2:])
    cid, image = r'[0-9a-f]{64}', r'sha256:[0-9a-f]{64}'
    name = r'(?:cachy-asahi-[0-9a-f]{16}|ksm-inventory-[0-9a-f]{32})'
    allowed = args == ['info', '--format', '{{.ID}}']
    if len(args) == 3 and args[:2] == ['container', 'inspect']:
        allowed = bool(re.fullmatch(cid + '|' + name, args[2]))
    if len(args) == 3 and args[:2] == ['image', 'inspect']:
        allowed = bool(re.fullmatch(image, args[2]))
    if len(args) == 4 and args[:3] == ['image', 'rm', '--no-prune']:
        allowed = bool(re.fullmatch(image, args[3]))
    if len(args) == 4 and args[:3] == ['rm', '--force', '--volumes']:
        allowed = bool(re.fullmatch(cid, args[3]))
    if len(args) == 7 and args[:6] == ['container', 'ls', '--all', '--quiet', '--no-trunc', '--filter']:
        allowed = bool(re.fullmatch(r'id=' + cid + r'|name=\^/' + name + r'\$', args[6]))
    if len(args) == 6 and args[:5] == ['image', 'ls', '--quiet', '--no-trunc', '--filter']:
        allowed = bool(re.fullmatch(r'reference=ksm-native-[0-9a-f]{32}|label=org\.cachy-asahi\.ksm-job=[0-9a-f]{32}', args[5]))
    need(allowed, 'cleanup-command-refused')


def _prctl(option, value):
    if _LIBC.prctl(ctypes.c_int(option), ctypes.c_ulong(value), ctypes.c_ulong(0),
                   ctypes.c_ulong(0), ctypes.c_ulong(0)) != 0:
        raise OSError(ctypes.get_errno(), 'prctl failed')


def _seconds(value):
    need(type(value) in (int, float) and math.isfinite(value) and 0 < value <= MAX_JOB_SECONDS, 'invalid-time-bound')
    return float(value)


def _child_setup(parent, mask, seconds):
    seconds = _seconds(seconds)
    _prctl(1, signal.SIGKILL)  # PR_SET_PDEATHSIG; not inherited by grandchildren.
    if os.getppid() != parent:
        os.kill(os.getpid(), signal.SIGKILL)
    for kind, bound in ((resource.RLIMIT_CPU, math.ceil(seconds) + 5),
                        (resource.RLIMIT_AS, 10 * 1024**3), (resource.RLIMIT_FSIZE, 4 * 1024**3),
                        (resource.RLIMIT_NOFILE, 128), (resource.RLIMIT_CORE, 0)):
        hard = resource.getrlimit(kind)[1]
        if kind == resource.RLIMIT_AS and hard != resource.RLIM_INFINITY and hard < bound:
            raise ValueError('host-address-space-limit')
        bound = min(bound, hard) if hard != resource.RLIM_INFINITY else bound
        resource.setrlimit(kind, (bound, bound))
    signal.pthread_sigmask(signal.SIG_SETMASK, mask)


def _group_signal(group, signum):
    try:
        os.killpg(group, signum)
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
    _group_signal(process.pid, signal.SIGTERM)
    end = time.monotonic() + 3
    while True:
        process.poll(); _reap(process)
        if not _group_signal(process.pid, 0):
            process.wait(timeout=max(.001, end - time.monotonic()))
            return
        if time.monotonic() >= end:
            raise ValueError('owned-process-group-remains')
        if time.monotonic() >= end - 1:
            _group_signal(process.pid, signal.SIGKILL)
        time.sleep(.01)


def _directory(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'absolute-private-directory-required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _identity(fd):
    info = os.fstat(fd)
    return info.st_dev, info.st_ino


class _LifecycleOutputs:
    """Authenticate one held controller's root receipt metadata, never its contents."""
    SOURCES = {'scripts/client/stage.py', 'scripts/ci/source_suites.py',
               'scripts/port/ksm-lifecycle/stage.py', 'scripts/port/ksm-lifecycle/worker.py',
               'scripts/port/ksm-lifecycle/contract.py'}
    FIELDS = {'schema_version', 'purpose', 'scope', 'phase', 'source_commit', 'run_id', 'daemon_id',
              'image_id', 'uid', 'package', 'approved_inputs_sha256', 'bootstrap_sha256',
              'packages_sha256', 'current_inputs_sha256', 'source_sha256'}
    LIMIT = 1024**2

    def __init__(self, runner, expected, sources, inputs):
        self.runner, self.fds, self.stage, self.leaf, self.contract_sha = runner, {}, None, None, None
        need(os.getuid() == os.geteuid() > 0 and os.getgid() == os.getegid() > 0,
             'lifecycle-output-positive-coordinator-required')
        need(type(expected) is dict and set(expected) == self.FIELDS and type(sources) is dict and
             set(sources) == self.SOURCES, 'exact-lifecycle-output-contract-required')
        self.expected = self.canonical(expected)
        self.sources = dict(sources)
        package = expected['package']
        need(type(package) is dict and type(package.get('filename')) is str and
             re.fullmatch(r'cachy-asahi-ksmctl-0\.1\.0-1-any\.pkg\.tar\.(?:xz|gz)', package['filename']),
             'exact-lifecycle-output-package-required')
        known = {'bootstrap.json', 'packages.lock', 'current-inputs.json', 'approved-inputs.json', package['filename']}
        need(type(inputs) is dict and set(inputs) == known and
             all(type(pin) is str and re.fullmatch(r'[0-9a-f]{64}', pin) for pin in (*sources.values(), *inputs.values())),
             'exact-lifecycle-output-input-pins-required')
        need(type(expected['schema_version']) is int and expected['schema_version'] == 1 and
             expected['purpose'] == 'ksm-diagnostic-development-lifecycle' and expected['scope'] == 'DEVELOPMENT TEST ONLY' and
             expected['phase'] == 'lifecycle' and type(expected['uid']) is int and expected['uid'] == os.geteuid() and
             expected['source_sha256'] == sources and type(expected['source_commit']) is str and
             re.fullmatch(r'[0-9a-f]{40}', expected['source_commit']) and type(expected['run_id']) is str and
             re.fullmatch(r'[1-9][0-9]{0,19}', expected['run_id']) and type(expected['daemon_id']) is str and
             re.fullmatch(r'[A-Za-z0-9:-]{8,128}', expected['daemon_id']) and type(expected['image_id']) is str and
             re.fullmatch(r'sha256:[0-9a-f]{64}', expected['image_id']), 'typed-lifecycle-output-binding-required')
        for field, name in [('bootstrap_sha256', 'bootstrap.json'), ('packages_sha256', 'packages.lock'),
                            ('current_inputs_sha256', 'current-inputs.json'), ('approved_inputs_sha256', 'approved-inputs.json')]:
            need(expected[field] == inputs[name], 'lifecycle-output-input-binding-required')
        need(package.get('sha256') == inputs[package['filename']], 'lifecycle-output-package-pin-required')
        self.inputs = dict(inputs)
        self.package_filename = package['filename']
        self.tmp = runner.private_root / 'tmp'
        need(runner.env.get('TMPDIR') == str(self.tmp), 'exact-lifecycle-output-tmpdir-required')
        try:
            self.hold(self.tmp)
            with os.scandir(self.fds[self.tmp][0]) as entries:
                need(next(entries, None) is None, 'fresh-lifecycle-output-tmpdir-required')
        except BaseException:
            self.close()
            raise

    @staticmethod
    def canonical(value):
        def typed(item, depth=0):
            need(depth <= 16, 'lifecycle-output-contract-depth')
            if type(item) is dict:
                need(all(type(key) is str for key in item), 'lifecycle-output-contract-key')
                for child in item.values(): typed(child, depth + 1)
            elif type(item) is list:
                for child in item: typed(child, depth + 1)
            else:
                need(type(item) in (str, int, bool, type(None)), 'lifecycle-output-contract-type')
        typed(value)
        data = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        need(len(data) <= _LifecycleOutputs.LIMIT, 'lifecycle-output-contract-bound')
        return data

    def alive(self):
        check_cancelled()
        need(time.monotonic() < self.runner.phase_deadline, 'lifecycle-output-deadline')

    @staticmethod
    def identity(info):
        return info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)

    def hold(self, path):
        self.alive()
        with defer_signals() as events:
            fd = _directory(path)
            try:
                info = os.fstat(fd)
                need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and info.st_gid == os.getegid() and
                     stat.S_IMODE(info.st_mode) == 0o700, 'owned-lifecycle-output-directory-required')
                self.fds[path] = fd, self.identity(info)
            except BaseException:
                os.close(fd)
                raise
        if events: raise Cancelled(events[0])
        self.alive()

    def directories(self):
        self.alive()
        need(self.runner._root_fd is not None, 'closed-lifecycle-output-runner')
        with defer_signals() as events:
            root = _directory(self.runner.private_root)
            try: need(_identity(root) == _identity(self.runner._root_fd), 'lifecycle-output-root-drift')
            finally: os.close(root)
            for path, (retained, expected) in self.fds.items():
                current = _directory(path)
                try:
                    need(self.identity(os.fstat(current)) == self.identity(os.fstat(retained)) == expected,
                         'lifecycle-output-directory-drift')
                finally: os.close(current)
        if events: raise Cancelled(events[0])
        self.alive()

    def read(self, path, limit, *, mode=None):
        self.alive()
        parent, fd = None, None
        try:
            with defer_signals() as events:
                parent = _directory(path.parent)
                fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
            if events: raise Cancelled(events[0])
            self.alive()
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid() and
                 before.st_gid == os.getegid() and stat.S_IMODE(before.st_mode) in {0o600, 0o644, 0o755} and
                 (mode is None or stat.S_IMODE(before.st_mode) == mode) and
                 0 <= before.st_size <= limit, 'owned-bounded-lifecycle-input-required')
            data = bytearray()
            while block := os.read(fd, min(65536, before.st_size - len(data) + 1)):
                self.alive(); data.extend(block)
                need(len(data) <= before.st_size, 'lifecycle-input-size-drift')
            after = os.fstat(fd)
            fields = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            need(len(data) == before.st_size and all(getattr(before, key) == getattr(after, key) for key in fields) and
                 (named.st_dev, named.st_ino) == (after.st_dev, after.st_ino), 'lifecycle-input-metadata-drift')
            self.alive()
            return bytes(data)
        finally:
            with defer_signals():
                if fd is not None: os.close(fd)
                if parent is not None: os.close(parent)

    def active_contract(self):
        source = self.stage / 'source'
        data = self.read(source / 'inputs.json', self.LIMIT, mode=0o644)
        def pairs(rows):
            result = {}
            for key, value in rows:
                need(key not in result, 'duplicate-lifecycle-output-contract-field')
                result[key] = value
            return result
        try:
            record = json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'nonfinite-lifecycle-contract'))
        except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
            raise ValueError('invalid-bounded-lifecycle-contract') from error
        need(type(record) is dict and set(record) == self.FIELDS | {'nonce', 'signing'} and
             self.canonical({key: record[key] for key in self.FIELDS}) == self.expected and
             type(record['nonce']) is str and re.fullmatch(r'[0-9a-f]{32}', record['nonce']), 'active-lifecycle-contract-required')
        signing = record['signing']
        need(type(signing) is dict and set(signing) == {'fingerprint', 'signature_sha256', 'public_key_sha256'} and
             type(signing['fingerprint']) is str and re.fullmatch(r'[0-9A-F]{40}', signing['fingerprint']) and
             all(type(signing[key]) is str and re.fullmatch(r'[0-9a-f]{64}', signing[key])
                 for key in ('signature_sha256', 'public_key_sha256')), 'active-lifecycle-signing-binding-required')
        digest = hashlib.sha256(data).hexdigest()
        need(self.contract_sha is None or self.contract_sha == digest, 'active-lifecycle-contract-drift')
        return digest

    def observe(self, relative, info):
        parts = Path(relative).parts
        if len(parts) == 2 and parts[0] == 'tmp' and parts[1].startswith('ksm-private-stage-'):
            need(re.fullmatch(r'ksm-private-stage-[a-z0-9_]{8}', parts[1]) and stat.S_ISDIR(info.st_mode),
                 'exact-lifecycle-stage-directory-required')
            stage = self.tmp / parts[1]
            need(self.stage is None or self.stage == stage, 'second-root-lifecycle-stage-refused')
            self.stage = stage
            if stage not in self.fds: self.hold(stage)
            self.directories()

    def allow(self, relative, info):
        parts = Path(relative).parts
        need(len(parts) == 4 and parts[0] == 'tmp' and re.fullmatch(r'ksm-private-stage-[a-z0-9_]{8}', parts[1]) and
             parts[2:] == ('installed', 'worker-receipt.json'), 'ungranted-root-lifecycle-output')
        stage = self.runner.private_root / 'tmp' / parts[1]
        need(self.stage is None or self.stage == stage, 'second-root-lifecycle-stage-refused')
        self.leaf_info(info)
        if self.contract_sha is None:
            self.stage = stage
            for path in (stage, stage / 'source', stage / 'installed'):
                if path not in self.fds: self.hold(path)
            self.directories()
            digest = self.active_contract()
            total = 0
            for name, pin in {**self.sources, **self.inputs}.items():
                maximum = min(16 * 1024**2 if name == self.package_filename else 2 * 1024**2,
                              32 * 1024**2 - total)
                data = self.read(stage / 'source' / name, maximum)
                total += len(data)
                need(total <= 32 * 1024**2, 'lifecycle-source-input-aggregate-bound')
                need(hashlib.sha256(data).hexdigest() == pin, 'lifecycle-source-input-pin-drift')
            self.directories()
            self.contract_sha = digest
        self.directories()
        need(self.active_contract() == self.contract_sha, 'active-lifecycle-contract-drift')
        identity = info.st_dev, info.st_ino
        need(self.leaf is None or self.leaf == identity, 'root-lifecycle-receipt-inode-drift')
        self.leaf = identity
        return True

    def leaf_info(self, info):
        need(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 1 and
             stat.S_IMODE(info.st_mode) in {0o600, 0o644} and 0 <= info.st_size <= self.LIMIT,
             'bounded-root-lifecycle-receipt-required')

    def close(self):
        with defer_signals():
            for fd, _ in self.fds.values(): os.close(fd)
            self.fds.clear()


class RunObservation:
    """Existing observations plus one authorized poll before process cleanup."""
    def __init__(self):
        self.started = False
        self.natural_poll_code = None
        self.runner_return_code = None
        self.reaping = 'NOT RUN'
        self.reaped_code = None
        self.before_cleanup = {'state': 'unavailable', 'returncode': None}

    @staticmethod
    def code(value):
        return value if type(value) is int and -128 <= value <= 255 else None

    def observe_before_cleanup(self, process):
        self.before_cleanup = {'state': 'unavailable', 'returncode': None}
        try:
            value = process.poll()
            if value is None:
                self.before_cleanup = {'state': 'alive', 'returncode': None}
            elif self.code(value) is not None:
                self.before_cleanup = {'state': 'exited', 'returncode': value}
        except BaseException:
            pass  # Missing diagnostics must not replace the active failure.

    def summary(self):
        return {'started': self.started, 'natural_poll_code': self.code(self.natural_poll_code),
            'runner_return_code': self.code(self.runner_return_code), 'reaping': self.reaping,
            'reaped_code': self.code(self.reaped_code), 'before_cleanup': dict(self.before_cleanup)}


class Runner:
    """Runner(env, private_root, log_dir, deadline_seconds=8460, deadline_at=None).

    run(..., service=None) calls a trusted callable or service.poll() each loop.
    Nested runners share the aggregate deadline and explicitly scope their
    phase_scope(outer.phase_deadline). cleanup=True only permits sealed ELF
    disposal commands under a parent cancellation scope; failure stays sticky.
    Resource observations are periodic; unknown state is a hard failure.
    """
    def __init__(self, env, private_root, log_dir, deadline_seconds=MAX_JOB_SECONDS, *, deadline_at=None, allowed_sockets=None):
        need(threading.current_thread() is threading.main_thread() and threading.active_count() == 1, 'threaded-runner')
        seconds = _seconds(deadline_seconds)
        now = time.monotonic()
        if deadline_at is not None:
            need(type(deadline_at) in (int, float) and math.isfinite(deadline_at)
                 and 0 < deadline_at - now <= seconds, 'invalid-aggregate-deadline')
        self.deadline = min(now + seconds, deadline_at if deadline_at is not None else now + seconds)
        self._phase_caps = []
        need(type(env) is dict and len(env) <= 256 and all(type(k) is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', k)
             and type(v) is str and '\0' not in v for k, v in env.items())
             and sum(len(k.encode()) + len(v.encode()) + 2 for k, v in env.items()) <= 65536, 'invalid-environment')
        self.env = MappingProxyType(dict(env))
        self.private_root, self.log_dir = Path(private_root), Path(log_dir)
        need(self.private_root.is_absolute() and '..' not in self.private_root.parts, 'unsafe-private-root')
        if not self.log_dir.is_absolute():
            self.log_dir = self.private_root / self.log_dir
        relative = self.log_dir.relative_to(self.private_root)
        need('..' not in relative.parts and len(relative.parts) <= MAX_DEPTH, 'unsafe-log-directory')
        self._root_fd = self._log_fd = None
        self._allowed_sockets = {}
        self._lifecycle_outputs = None
        self.resource_observation = {'status': 'FAIL', 'known': False, 'reason': 'not-observed'}
        try:
            self._root_fd = _directory(self.private_root)
            root_info = os.fstat(self._root_fd)
            need(root_info.st_uid == os.geteuid() and stat.S_IMODE(root_info.st_mode) == 0o700, 'unsafe-private-root-mode')
            self._log_fd = os.dup(self._root_fd)
            for part in relative.parts:
                try:
                    os.mkdir(part, 0o700, dir_fd=self._log_fd)
                except FileExistsError:
                    pass
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self._log_fd)
                os.close(self._log_fd); self._log_fd = next_fd
            info = os.fstat(self._log_fd)
            need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, 'unsafe-log-directory-mode')
            need(allowed_sockets is None or type(allowed_sockets) is dict, 'invalid-owned-sockets')
            for path, identity in (allowed_sockets or {}).items(): self.register_socket(path, identity)
            _prctl(36, 1)  # PR_SET_CHILD_SUBREAPER; reaping below is group-scoped.
            self.check_resources()
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    @property
    def phase_deadline(self):
        return min([self.deadline, *self._phase_caps])

    @contextmanager
    def phase_scope(self, deadline_at):
        need(type(deadline_at) in (int, float) and math.isfinite(deadline_at)
             and time.monotonic() < deadline_at <= self.deadline, 'invalid-phase-deadline')
        self._phase_caps.append(min(deadline_at, self.phase_deadline))
        try:
            yield
        finally:
            self._phase_caps.pop()

    @contextmanager
    def lifecycle_outputs(self, expected_contract, source_pins, input_pins):
        """Temporarily permit only authenticated held lifecycle receipt metadata.

        Source and input authentication authorizes a root-owned path, not receipt
        contents or native PASS. The held controller still validates final bytes.
        """
        need(threading.current_thread() is threading.main_thread() and self._lifecycle_outputs is None,
             'single-lifecycle-output-scope-required')
        check_cancelled()
        grant = None
        try:
            with defer_signals() as events:
                grant = _LifecycleOutputs(self, expected_contract, source_pins, input_pins)
                self._lifecycle_outputs = grant
            if events: raise Cancelled(events[0])
            check_cancelled()
            yield grant
        finally:
            with defer_signals():
                self._lifecycle_outputs = None
                if grant is not None: grant.close()

    def __exit__(self, *_):
        self.close()

    def close(self):
        with defer_signals() as events:
            if self._lifecycle_outputs is not None:
                grant, self._lifecycle_outputs = self._lifecycle_outputs, None
                grant.close()
            for name in ('_log_fd', '_root_fd'):
                fd = getattr(self, name, None)
                if fd is not None:
                    setattr(self, name, None); os.close(fd)
        if events: raise Cancelled(events[0])

    @property
    def allowed_sockets(self):
        return MappingProxyType(self._allowed_sockets)

    def register_socket(self, path, identity):
        path = Path(path)
        need(path.is_absolute() and '..' not in path.parts, 'unsafe-owned-socket-path')
        path.relative_to(self.private_root)
        need(type(identity) in (tuple, list) and len(identity) == 5 and all(type(n) is int and n >= 0 for n in identity),
             'invalid-owned-socket-identity')
        identity = tuple(identity)
        need(identity[2] == os.geteuid() and identity[4] & 0o077 == 0, 'unsafe-owned-socket-permissions')
        need(not self._allowed_sockets or str(path) in self._allowed_sockets, 'one-owned-socket-only')
        need(str(path) not in self._allowed_sockets or self._allowed_sockets[str(path)] == identity, 'owned-socket-rebinding-refused')
        directory = _directory(path.parent)
        try:
            info = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            actual = (info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
            need(stat.S_ISSOCK(info.st_mode) and info.st_nlink == 1 and actual == identity, 'owned-socket-identity-mismatch')
        finally: os.close(directory)
        self._allowed_sockets[str(path)] = identity

    def unregister_socket(self, path):
        path = Path(path)
        need(str(path) in self._allowed_sockets, 'unregistered-owned-socket')
        directory = _directory(path.parent)
        try:
            try: os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError: pass
            else: raise ValueError('owned-socket-still-present')
        finally: os.close(directory)
        del self._allowed_sockets[str(path)]

    def _check_log(self, target, name):
        info = os.fstat(target.fileno())
        current = os.stat(name, dir_fd=self._log_fd, follow_symlinks=False)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
             and stat.S_IMODE(info.st_mode) == 0o600 and (current.st_dev, current.st_ino) == (info.st_dev, info.st_ino),
             'private-log-identity-changed')

    def check_resources(self):
        observation = {'status': 'FAIL', 'known': False, 'reason': 'resource-state-unknown',
                       'files': 0, 'entries': 0, 'bytes': 0, 'byte_limit': MAX_PRIVATE,
                       'minimum_free_bytes': MIN_FREE, 'maximum_entries': MAX_NODES, 'maximum_depth': MAX_DEPTH,
                       'owned_rpc_sockets': 0, 'rebinding_entries': 0,
                       'scope': 'periodic nofollow metadata observation'}
        try:
            need(self._root_fd is not None and time.monotonic() < self.phase_deadline, 'deadline-exhausted')
            chain = []
            def validate_directories():
                for path, retained in ((self.private_root, self._root_fd), (self.log_dir, self._log_fd)):
                    current = _directory(path)
                    try:
                        need(_identity(current) == _identity(retained), 'private-directory-identity-changed')
                        info = os.fstat(current)
                        need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
                             'unsafe-private-root-mode')
                    finally: os.close(current)
                for parent, name, fd, before in chain:
                    opened = os.fstat(fd)
                    named = os.stat(name, dir_fd=parent, follow_symlinks=False)
                    identity = lambda info: (info.st_dev, info.st_ino, info.st_uid, stat.S_IFMT(info.st_mode))
                    need(identity(opened) == identity(before) == identity(named) and
                         stat.S_ISDIR(opened.st_mode), 'private-directory-identity-changed')
            validate_directories()
            seen_sockets, file_sizes = set(), {}
            def account(info):
                identity = info.st_dev, info.st_ino
                previous = file_sizes.get(identity)
                if previous is None:
                    observation['files'] += 1
                    need(observation['files'] <= MAX_NODES, 'private-file-bound')
                size = max(0 if previous is None else previous, info.st_size)
                observation['bytes'] += size - (0 if previous is None else previous)
                file_sizes[identity] = size
                need(observation['bytes'] <= MAX_PRIVATE, 'private-byte-bound')
            def metadata(relative, info):
                grant, granted = self._lifecycle_outputs, False
                if grant is not None: grant.observe(relative, info)
                if info.st_uid != os.geteuid():
                    need(grant is not None, 'private-foreign-owner')
                    granted = grant.allow(relative, info)
                if stat.S_ISSOCK(info.st_mode):
                    path = str(self.private_root / relative)
                    actual = (info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
                    need(info.st_nlink == 1 and self.allowed_sockets.get(path) == actual, 'unbound-private-socket')
                else:
                    need(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), 'unsupported-private-node')
                    if stat.S_ISREG(info.st_mode):
                        need(info.st_nlink == 1, 'private-hardlink-refused'); account(info)
                return grant, granted
            def absent(directory, name):
                # Only a vanished enumerated name is tolerated. Keep all named
                # retained directories bound, and refuse a reappearing entry.
                validate_directories()
                try: os.stat(name, dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError: return
                raise ValueError('private-node-reappeared')
            @contextmanager
            def entries_at(directory):
                # A dup shares the outer scandir offset. Open the same directory
                # afresh so nested/repeated enumeration starts independently.
                scan = None
                try:
                    with defer_signals() as events:
                        scan = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                       dir_fd=directory)
                    if events: raise Cancelled(events[0])
                    need(_identity(scan) == _identity(directory), 'private-directory-identity-changed')
                    with os.scandir(scan) as entries: yield entries
                finally:
                    if scan is not None:
                        with defer_signals(): os.close(scan)
            def walk(directory, depth, prefix=Path()):
                need(depth <= MAX_DEPTH, 'private-depth-bound')
                seen, charged, missing_names, observed_nodes = set(), set(), set(), {}
                def charge(name):
                    if name not in charged:
                        charged.add(name); observation['entries'] += 1
                        need(observation['entries'] <= MAX_NODES, 'private-entry-bound')
                def stable(info):
                    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
                            info.st_nlink, info.st_size, info.st_mtime_ns)
                def rebound(name, retained, opened):
                    # This is a quota observation, not immutable-input capture.
                    # Keep an opened inode bound to a real same-parent name.
                    need(stat.S_ISREG(opened.st_mode) and opened.st_uid == os.geteuid() and
                         opened.st_nlink == 1, 'private-regular-rebinding-refused')
                    validate_directories(); absent(directory, name)
                    candidates = []
                    with entries_at(directory) as entries:
                        for candidate in entries:
                            need(time.monotonic() < self.phase_deadline, 'deadline-exhausted')
                            observation['rebinding_entries'] += 1
                            need(observation['rebinding_entries'] <= MAX_NODES, 'private-rebinding-entry-bound')
                            charge(candidate.name)
                            try: observed = os.stat(candidate.name, dir_fd=directory, follow_symlinks=False)
                            except FileNotFoundError:
                                absent(directory, candidate.name); missing_names.add(candidate.name); continue
                            if candidate.name in missing_names:
                                raise ValueError('private-node-reappeared')
                            previous = observed_nodes.get(candidate.name)
                            if previous is not None and (stat.S_ISDIR(previous[4]) or stat.S_ISDIR(observed.st_mode)):
                                need(previous == (observed.st_dev, observed.st_ino, observed.st_uid,
                                                  observed.st_gid, observed.st_mode), 'private-directory-identity-changed')
                            metadata(prefix / candidate.name, observed)
                            if (observed.st_dev, observed.st_ino) == (opened.st_dev, opened.st_ino):
                                need(candidate.name != name and stable(observed) == stable(opened), 'private-node-changed')
                                candidates.append(candidate.name)
                    need(len(candidates) == 1, 'private-regular-rebinding-unconfirmed')
                    target = candidates[0]; candidate_fd = None
                    try:
                        with defer_signals() as events:
                            candidate_fd = os.open(target, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
                        if events: raise Cancelled(events[0])
                        check_cancelled(); validate_directories(); absent(directory, name)
                        observed = os.fstat(candidate_fd)
                        current = os.stat(target, dir_fd=directory, follow_symlinks=False)
                        final = os.fstat(retained)
                        need(stable(opened) == stable(observed) == stable(current) == stable(final), 'private-node-changed')
                        metadata(prefix / target, current); account(final)
                        validate_directories(); absent(directory, name)
                        return current
                    finally:
                        if candidate_fd is not None:
                            with defer_signals(): os.close(candidate_fd)
                for attempt in range(3):
                    vanished = False
                    with entries_at(directory) as entries:
                        for entry in entries:
                            need(time.monotonic() < self.phase_deadline, 'deadline-exhausted')
                            if entry.name in seen:
                                if entry.name in missing_names:
                                    absent(directory, entry.name); vanished = True
                                continue
                            seen.add(entry.name)
                            charge(entry.name)
                            try: before = os.stat(entry.name, dir_fd=directory, follow_symlinks=False)
                            except FileNotFoundError:
                                absent(directory, entry.name); missing_names.add(entry.name); vanished = True; continue
                            grant, granted = metadata(prefix / entry.name, before)
                            observed_nodes[entry.name] = (before.st_dev, before.st_ino, before.st_uid,
                                                         before.st_gid, before.st_mode)
                            if stat.S_ISSOCK(before.st_mode):
                                path = str(self.private_root / prefix / entry.name)
                                seen_sockets.add(path); observation['owned_rpc_sockets'] += 1
                                continue
                            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                            if granted: flags = os.O_PATH | os.O_NOFOLLOW
                            if stat.S_ISDIR(before.st_mode): flags |= os.O_DIRECTORY
                            try: fd = os.open(entry.name, flags, dir_fd=directory)
                            except FileNotFoundError:
                                absent(directory, entry.name); missing_names.add(entry.name); vanished = True; continue
                            try:
                                info = os.fstat(fd)
                                if granted: grant.leaf_info(info)
                                need((before.st_dev, before.st_ino, before.st_uid, stat.S_IFMT(before.st_mode)) ==
                                     (info.st_dev, info.st_ino, info.st_uid, stat.S_IFMT(info.st_mode)), 'private-node-changed')
                                if stat.S_ISDIR(info.st_mode):
                                    chain.append((directory, entry.name, fd, before))
                                    try:
                                        validate_directories(); walk(fd, depth + 1, prefix / entry.name)
                                        validate_directories()
                                    finally: chain.pop()
                                else:
                                    try: named = os.stat(entry.name, dir_fd=directory, follow_symlinks=False)
                                    except FileNotFoundError:
                                        if granted: raise
                                        named = rebound(entry.name, fd, info)
                                        missing_names.add(entry.name); vanished = True
                                    if granted: grant.leaf_info(named)
                                    need((named.st_dev, named.st_ino, named.st_uid, stat.S_IFMT(named.st_mode)) ==
                                         (info.st_dev, info.st_ino, info.st_uid, stat.S_IFMT(info.st_mode)), 'private-node-changed')
                                    need(info.st_nlink == named.st_nlink == 1, 'private-hardlink-refused')
                                    # Each observed inode retains its largest charged size;
                                    # rename, shrink or loss cannot erase earlier bytes.
                                    account(info); account(named)
                            finally: os.close(fd)
                    validate_directories()
                    if not vanished: return
                raise ValueError('private-scan-unstable')
            walk(self._root_fd, 0)
            validate_directories()
            need(seen_sockets == set(self.allowed_sockets), 'owned-private-socket-missing')
            disk = os.fstatvfs(self._root_fd)
            observation['free_bytes'] = disk.f_bavail * disk.f_frsize
            need(observation['free_bytes'] >= MIN_FREE, 'private-disk-reserve')
            need(time.monotonic() < self.phase_deadline, 'deadline-exhausted')
            observation.update(status='PASS-observed-resources', known=True, reason=None)
        except (ValueError, OSError) as error:
            observation['reason'] = str(error) if isinstance(error, ValueError) else 'resource-observation-unavailable'
            self.resource_observation = observation
            raise ResourceFailure(observation) from error
        self.resource_observation = observation
        self._resource_due = time.monotonic() + RESOURCE_INTERVAL
        return dict(observation)

    def run(self, argv, timeout=300, limit=MAX_OUTPUT, log=None, pass_fds=(), service=None, *, cleanup=False):
        need(type(cleanup) is bool, 'invalid-cleanup-mode')
        if cleanup:
            need(_ACTIVE is not None and (_ACTIVE.signum is None or _ACTIVE.deferrals > 0), 'cleanup-parent-deferred-scope-required')
            with defer_signals():
                return self._run(argv, timeout, limit, log, pass_fds, service, _ACTIVE, cleanup=True)
        with cancellation_handlers() as cancellation:
            return self._run(argv, timeout, limit, log, pass_fds, service, cancellation)

    def _run(self, argv, timeout, limit, log, pass_fds, service, cancellation, *, cleanup=False):
        observation = getattr(self, 'observation', None)
        if type(observation) is not RunObservation: observation = None
        if observation is not None: observation.before_cleanup = {'state': 'unavailable', 'returncode': None}
        need(threading.current_thread() is threading.main_thread() and threading.active_count() == 1, 'threaded-runner')
        timeout = _seconds(timeout)
        need(type(limit) is int and 0 < limit <= MAX_OUTPUT, 'invalid-output-bound')
        need(type(argv) in (list, tuple) and 0 < len(argv) <= 256 and all(type(a) is str and '\0' not in a for a in argv)
             and Path(argv[0]).is_absolute() and sum(len(a.encode()) + 1 for a in argv) <= 65536, 'invalid-argv')
        argv = tuple(argv)
        need(type(pass_fds) in (list, tuple) and len(pass_fds) <= 8 and len(set(pass_fds)) == len(pass_fds)
             and all(type(fd) is int and fd >= 3 for fd in pass_fds), 'invalid-pass-fds')
        pass_fds = tuple(pass_fds)
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        for fd in pass_fds:
            need(stat.S_ISREG(os.fstat(fd).st_mode) and fcntl.fcntl(fd, fcntl.F_GET_SEALS) & seals == seals, 'unsealed-pass-fd')
        if cleanup:
            need(log is None and service is None and len(pass_fds) == 1, 'cleanup-sealed-no-log-only')
            fd = pass_fds[0]
            info = os.fstat(fd)
            need(argv[0] in {f'/proc/self/fd/{fd}', f'/proc/{os.getpid()}/fd/{fd}'}
                 and info.st_uid == os.geteuid() and info.st_nlink == 0 and 0 < info.st_size <= 128 * 1024**2
                 and os.pread(fd, 4, 0) == b'\x7fELF', 'cleanup-owned-sealed-elf-only')
            _cleanup_grammar(argv)
            timeout, limit = min(timeout, CLEANUP_SECONDS), min(limit, CLEANUP_OUTPUT)
        callback = getattr(service, 'poll', service) if service is not None else None
        need(callback is None or callable(callback), 'invalid-service')
        need(time.monotonic() < self.phase_deadline, 'phase-deadline-exhausted')
        if not cleanup: self.check_resources()
        end = min(self.phase_deadline, time.monotonic() + timeout)
        need(time.monotonic() < end, 'phase-deadline-exhausted')
        output, process, target, mask = bytearray(), None, None, None
        log_name = None
        selector = selectors.DefaultSelector()
        def append(data):
            room = limit - len(output)
            output.extend(data[:room])
            need(len(data) <= room, 'output-bound')
        try:
            if log is not None:
                need(isinstance(log, (str, Path)), 'unsafe-log-name')
                path = Path(log)
                need('..' not in path.parts and (path.parent == self.log_dir if path.is_absolute() else path.parent == Path('.'))
                     and path.name not in {'', '.', '..'} and not re.search(r'[\x00-\x1f\x7f]', path.name), 'unsafe-log-name')
                log_name = path.name
                fd = os.open(log_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self._log_fd)
                target = os.fdopen(fd, 'wb'); os.fchmod(target.fileno(), 0o600)
                self._check_log(target, log_name)
            mask = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
            try:
                parent = os.getpid()
                process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    env=self.env, start_new_session=True, close_fds=True, pass_fds=pass_fds,
                    preexec_fn=lambda: _child_setup(parent, mask, min(timeout, end - time.monotonic())))
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, mask)
            if observation is not None: observation.started = True
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                if not cleanup: cancellation.check()
                if not cleanup and time.monotonic() >= self._resource_due: self.check_resources()
                if callback is not None: callback()
                if not cleanup and time.monotonic() >= self._resource_due: self.check_resources()
                need(time.monotonic() < end, 'command-timeout')
                code = process.poll()
                if observation is not None and code is not None: observation.natural_poll_code = observation.code(code)
                if code is not None:
                    break
                for key, _ in selector.select(min(end - time.monotonic(), .05)):
                    data = os.read(key.fd, min(65536, limit - len(output) + 1))
                    if data: append(data)
                    else: selector.unregister(key.fileobj)
        finally:
            with cancellation.defer():
                errors = []
                if mask is not None: signal.pthread_sigmask(signal.SIG_SETMASK, mask)
                if process is not None:
                    if observation is not None: observation.started = True
                    if observation is not None:
                        try: observation.observe_before_cleanup(process)
                        except BaseException: pass
                    try:
                        _cleanup(process)
                        if observation is not None:
                            observation.reaping = 'COMPLETED'; observation.reaped_code = observation.code(process.returncode)
                    except BaseException as error:
                        if observation is not None:
                            observation.reaping = 'FAILED'; observation.reaped_code = observation.code(process.returncode)
                        errors.append(error)
                    try:
                        os.set_blocking(process.stdout.fileno(), False)
                        while True:
                            data = os.read(process.stdout.fileno(), min(65536, limit - len(output) + 1))
                            if not data: break
                            append(data)
                    except BaseException as error: errors.append(error)
                    finally: process.stdout.close()
                selector.close()
                if target is not None:
                    try:
                        self.check_resources()
                        self._check_log(target, log_name)
                        target.write(output); target.flush(); os.fsync(target.fileno())
                        self._check_log(target, log_name)
                    except BaseException as error: errors.append(error)
                    finally: target.close()
                if not cleanup:
                    try: self.check_resources()
                    except BaseException as error: errors.append(error)
            if not cleanup: cancellation.check()
            if errors: raise errors[0]
        need(time.monotonic() < end, 'phase-deadline-exhausted')
        if observation is not None: observation.runner_return_code = observation.code(process.returncode)
        return subprocess.CompletedProcess(argv, process.returncode, bytes(output), None)
