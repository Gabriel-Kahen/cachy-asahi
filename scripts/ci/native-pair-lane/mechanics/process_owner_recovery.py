"""Private Linux direct-child owner; executable pins confer no actor authorization.

No process-group or escaped-descendant claim. Docker daemon/container custody and
service suppression belong to the reviewed caller. Deadlines are supplied once
in the caller's CLOCK_MONOTONIC domain; cleanup never renews them. Python and OS
allocation, spawn and close syscalls are finite attempts, not hard-time bounds.
"""
import hashlib
import ctypes
import errno
import math
import os
import platform
import selectors
import signal
import stat
import subprocess
import time
from contextlib import contextmanager

RECOVERY_BOUND = 180


class Refused(ValueError):
    pass


class OwnershipFailure(RuntimeError):
    pass


def fork_filter(machine):
    """Classic BPF tuples: architecture, ABI, clone flags, syscall confinement.

    clone3 returns ENOSYS so runtimes can retry classic clone for threads. This
    policy prohibits host process descendants; daemon containers are outside it.
    Exec in the same PID is allowed, retaining the direct pidfd identity.
    """
    tables = {'aarch64': (0xc00000b7, 220, 435, ()),
              'x86_64': (0xc000003e, 56, 435, (57, 58))}
    need(machine in tables, 'unsupported native seccomp architecture')
    arch, clone, clone3, forks = tables[machine]
    allow, deny, kill = 0x7fff0000, 0x50000 | errno.EPERM, 0x80000000
    program = [(0x20, 0, 0, 4), (0x15, 1, 0, arch), (0x06, 0, 0, kill),
               (0x20, 0, 0, 0), (0x45, 0, 1, 0x40000000), (0x06, 0, 0, deny),
               (0x15, 0, 1, clone3), (0x06, 0, 0, 0x50000 | errno.ENOSYS)]
    for number in forks:
        program += [(0x15, 0, 1, number), (0x06, 0, 0, deny)]
    program += [(0x15, 1, 0, clone), (0x06, 0, 0, allow),
                (0x20, 0, 0, 20), (0x15, 1, 0, 0), (0x06, 0, 0, deny),
                (0x20, 0, 0, 16), (0x54, 0, 0, 0x10100),
                (0x15, 1, 0, 0x10100), (0x06, 0, 0, deny), (0x06, 0, 0, allow)]
    return tuple(program)


def single_threaded():
    tasks = os.listdir('/proc/self/task')
    need(len(tasks) == 1 and all(x.isascii() and x.isdigit() for x in tasks),
         'single-threaded parent required for preexec confinement')
    need(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL,
         'default SIGCHLD required: child must remain unreaped during pidfd registration')


class SockFilter(ctypes.Structure):
    _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
               ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint32)]


class SockFprog(ctypes.Structure):
    _fields_ = [('len', ctypes.c_ushort), ('filter', ctypes.POINTER(SockFilter))]


class NoFork:
    """Prepare all ctypes state in the parent, install only in the direct child.

    Preexec cannot safely run Python after a multithreaded fork; run refuses a
    parent with more than one /proc/self/task entry. No other thread creator is
    authorized between that check and Popen. Same-UID hostile interference,
    dynamic-loader/toolchain provenance and broader syscall sandboxing are not
    established by this membership filter.
    """
    def __init__(self, machine):
        self.instructions = fork_filter(machine)
        self.array = (SockFilter * len(self.instructions))(
            *(SockFilter(*row) for row in self.instructions))
        self.program = SockFprog(len(self.instructions), self.array)
        self.prctl = ctypes.CDLL(None, use_errno=True).prctl
        self.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p,
                               ctypes.c_ulong, ctypes.c_ulong]
        self.prctl.restype = ctypes.c_int
        self.child_mask = None

    def install(self):
        need(self.child_mask is not None, 'original child control mask not supplied')
        if self.prctl(38, 1, None, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
            raise OSError(ctypes.get_errno(), 'NO_NEW_PRIVS refused')
        if self.prctl(22, 2, ctypes.byref(self.program), 0, 0) != 0:
            raise OSError(ctypes.get_errno(), 'SECCOMP_MODE_FILTER refused')
        signal.pthread_sigmask(signal.SIG_SETMASK, self.child_mask)


def need(value, message):
    if not value:
        raise Refused(message)


def deadline(value):
    need(type(value) in (int, float) and math.isfinite(value) and value > 0,
         'finite positive absolute monotonic deadline required')
    return value


def eligible(end):
    need(time.monotonic() < end, 'original work deadline expired')


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_gid, value.st_nlink, value.st_size, value.st_mtime_ns,
            value.st_ctime_ns)


class VerifiedTool:
    """Caller-owned held executable descriptor; caller must close it exactly once.

    Parents must be absolute real directories, root-owned, and not group/world
    writable. The leaf must be root-owned mode 0755, regular and single-link.
    Tool verification is read-only and bounded by bytes and the original end.
    """
    def __init__(self, path, sha256, *, end, cap=128 * 1024 * 1024):
        deadline(end)
        need(type(path) is str and os.path.isabs(path) and
             os.path.normpath(path) == path, 'canonical absolute tool path required')
        need(type(sha256) is str and len(sha256) == 64 and
             all(c in '0123456789abcdef' for c in sha256), 'exact SHA256 required')
        need(type(cap) is int and 1 <= cap <= 128 * 1024 * 1024, 'tool cap invalid')
        eligible(end)
        ancestors = ['/']
        for part in path.split('/')[1:-1]:
            ancestors.append(os.path.join(ancestors[-1], part))
        for current in ancestors:
            value = os.lstat(current)
            need(stat.S_ISDIR(value.st_mode) and value.st_uid == 0 and
                 not value.st_mode & 0o022, 'unsafe tool ancestor')
            eligible(end)
        self.path, self.sha256, self.fd = path, sha256, None
        fd = None
        try:
            with masked():
                fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and
                 stat.S_IMODE(before.st_mode) == 0o755 and before.st_nlink == 1,
                 'unsafe executable identity')
            need(0 < before.st_size <= cap, 'tool byte cap exceeded')
            need(identity(before) == identity(os.lstat(path)), 'tool named identity differs')
            digest, total = hashlib.sha256(), 0
            while True:
                eligible(end)
                raw = os.read(fd, min(65536, cap + 1 - total))
                if not raw:
                    break
                total += len(raw)
                need(total <= cap, 'tool byte cap exceeded')
                digest.update(raw)
            need(total == before.st_size and digest.hexdigest() == sha256,
                 'tool size or SHA256 differs')
            need(identity(before) == identity(os.fstat(fd)) == identity(os.lstat(path)),
                 'tool identity changed during read')
            eligible(end)
            self.held_identity, self.fd = identity(before), fd
        except BaseException as first:
            if fd is not None:
                try:
                    os.close(fd)
                except BaseException as error:
                    first.add_note('tool FD close failed: ' + type(error).__name__)
            raise

    def verify(self, end):
        eligible(end)
        need(self.fd is not None and
             identity(os.fstat(self.fd)) == self.held_identity == identity(os.lstat(self.path)),
             'held executable identity changed')
        eligible(end)

    def close(self):
        fd, self.fd = self.fd, None
        if fd is not None:
            os.close(fd)


CONTROL_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGALRM)


@contextmanager
def masked():
    """Defer asynchronous controls only across custody registration/retirement."""
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, CONTROL_SIGNALS)
    cause = None
    try:
        yield previous
    except BaseException as error:
        cause = error
        raise
    finally:
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        except BaseException as error:
            if cause is None:
                raise
            cause.add_note('control mask restoration failed: ' + type(error).__name__)


def _cleanup(proc, pidfd, pipe, selector, end, *, observe, retained):
    faults = []

    def fault(label, error=None):
        nonlocal end
        faults.append(label + (': ' + type(error).__name__ if error is not None else ''))
        end = min(end, observe(error))

    def attempt(label, action):
        try:
            eligible(end)
            action()
            return True
        except BaseException as error:
            fault(label, error)

    def send(sig):
        try:
            eligible(end)
            signal.pidfd_send_signal(pidfd, sig, None, 0)
        except ProcessLookupError:
            pass  # The retained identity is already dead; reap still required.

    def wait(seconds):
        remaining = max(0.0, min(seconds, end - time.monotonic()))
        eligible(end)
        return proc.wait(timeout=remaining)

    if proc is not None and proc.returncode is None:
        if pidfd is None:
            fault('pidfd acquisition failed: child retirement not proved')
        else:
            attempt('pidfd TERM', lambda: send(signal.SIGTERM))
        try:
            wait(1.0)
        except subprocess.TimeoutExpired:
            if pidfd is not None:
                attempt('pidfd KILL', lambda: send(signal.SIGKILL))
            attempt('bounded reap', lambda: wait(max(0.0, end - time.monotonic())))
        except BaseException as error:
            fault('bounded reap', error)
            if pidfd is not None:
                attempt('pidfd KILL', lambda: send(signal.SIGKILL))
                attempt('bounded reap retry', lambda: wait(max(0.0, end - time.monotonic())))
        if proc.returncode is None:
            fault('direct child remains unreaped')
    if proc is not None and proc.returncode is not None:
        retained['process'] = None
    if selector is not None and attempt('selector close', selector.close):
        retained['selector'] = None
    if pipe is not None and attempt('stdout close', pipe.close):
        retained['stdout'] = None
    if pidfd is not None and attempt('pidfd close', lambda: os.close(pidfd)):
        retained['pidfd'] = None
    return faults


def _run(argv, env, cwd, *, tool, work_end, cleanup_end, pass_fds=(),
        limit=4 * 1024 * 1024):
    """Run one explicitly pinned direct actor; no default arbitrary-call authority.

    Caller retains tool/pass_fds ownership. Child stdout/stderr are merged with a
    finite byte cap, DEVNULL stdin, no shell, and no implicit environment. The
    executable is the pinned held FD, avoiding a named-path exec replacement.
    A nonzero exit is returned for the actor graph to interpret. Cancellation or
    cleanup uncertainty raises and cannot become success. The caller installs
    raising TERM/ALRM handlers and uses service-suppression actor arguments.
    """
    deadline(work_end)
    deadline(cleanup_end)
    need(work_end <= cleanup_end, 'cleanup end precedes work end')
    need(type(tool) is VerifiedTool, 'mandatory verified executable owner')
    need(callable(getattr(os, 'pidfd_open', None)) and
         callable(getattr(signal, 'pidfd_send_signal', None)) and
         callable(getattr(signal, 'pthread_sigmask', None)), 'pidfd/control APIs unavailable')
    need(type(limit) is int and 1 <= limit <= 64 * 1024 * 1024, 'output cap invalid')
    args, environment, descriptors = list(argv), dict(env), tuple(pass_fds)
    need(args and args[0] == tool.path and all(type(x) is str and '\0' not in x for x in args),
         'argv must start with exact pinned tool path')
    need(all(type(k) is str and type(v) is str and '\0' not in k + v and '=' not in k
             for k, v in environment.items()), 'invalid explicit environment')
    need(type(cwd) is str and os.path.isabs(cwd) and '\0' not in cwd, 'absolute cwd required')
    need(all(type(fd) is int and fd >= 0 for fd in descriptors) and
         len(set(descriptors)) == len(descriptors), 'invalid passed descriptors')
    tool.verify(work_end)
    need(tool.fd not in descriptors, 'tool descriptor separately passed')
    descriptors += (tool.fd,)
    single_threaded()
    confinement = NoFork(platform.machine())
    proc = pidfd = pipe = selector = None
    first = result = None
    failure_at = None

    def observe(error=None):
        nonlocal failure_at
        now = time.monotonic()
        try:
            inherited = getattr(error, 'first_failure_at', None)
        except BaseException:
            inherited = None
        if type(inherited) in (int, float) and math.isfinite(inherited) and 0 < inherited <= now:
            now = min(now, inherited)
        failure_at = now if failure_at is None else min(failure_at, now)
        return min(cleanup_end, failure_at + RECOVERY_BOUND)

    def recovery_end():
        return cleanup_end if failure_at is None else min(cleanup_end, failure_at + RECOVERY_BOUND)

    output = bytearray()
    try:
        with masked() as child_mask:
            tool.verify(work_end)
            single_threaded()
            confinement.child_mask = child_mask
            executable = '/proc/self/fd/' + str(tool.fd)
            eligible(work_end)  # Last gate after all argv/env/descriptor allocation.
            proc = subprocess.Popen(args, executable=executable, env=environment, cwd=cwd,
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, close_fds=True,
                                    pass_fds=descriptors, shell=False,
                                    preexec_fn=confinement.install)
            pipe = proc.stdout  # Registered before any unmask can deliver cancellation.
            pidfd = os.pidfd_open(proc.pid, 0)  # Unreaped child PID cannot be reused.
        eligible(work_end)
        os.set_blocking(pipe.fileno(), False)
        selector = selectors.DefaultSelector()
        selector.register(pipe, selectors.EVENT_READ, 'stdout')
        selector.register(pidfd, selectors.EVENT_READ, 'child')
        eof = exited = False
        while not (eof and exited):
            eligible(work_end)
            events = selector.select(max(0.0, work_end - time.monotonic()))
            if not events:
                eligible(work_end)
                continue
            eligible(work_end)
            for key, _ in events:
                eligible(work_end)
                if key.data == 'child':
                    exited = True
                    selector.unregister(pidfd)
                    continue
                try:
                    raw = os.read(pipe.fileno(), min(65536, limit + 1 - len(output)))
                except BlockingIOError:
                    continue
                if not raw:
                    eof = True
                    selector.unregister(pipe)
                else:
                    output.extend(raw)
                    need(len(output) <= limit, 'actor output cap exceeded')
        eligible(work_end)
        code = proc.wait(timeout=0)  # Retained pidfd readiness proved direct exit.
        if code != 0:
            observe()  # Classify nonzero before any cleanup or result allocation.
        eligible(work_end)
        result = {'code': code, 'stdout': bytes(output),
                  'identity': {'pid': proc.pid, 'pidfd_used': True,
                               'tool_sha256': tool.sha256},
                  'scope': 'direct-child-only', 'first_failure_at': failure_at}
    except BaseException as error:
        observe(error)  # Earliest captured work cause, before cleanup can delay it.
        first = error
    faults = []
    retained = {'process': proc, 'pidfd': pidfd, 'stdout': pipe, 'selector': selector}
    try:
        with masked():
            faults = _cleanup(proc, pidfd, pipe, selector, recovery_end(),
                              observe=observe, retained=retained)
    except BaseException as error:
        observe(error)
        if first is None:
            first = error
        else:
            faults.append('cleanup controls: ' + type(error).__name__)
    if faults:
        if first is None:
            first = OwnershipFailure('; '.join(faults))
        else:
            first.add_note('cleanup uncertainty: ' + '; '.join(faults))
    if first is None and time.monotonic() >= recovery_end():
        observe()
        first = Refused('original or first-failure cleanup deadline expired')
    if first is not None:
        try:
            first.first_failure_at = failure_at
            # Strong internal custody prevents implicit Python destruction of
            # skipped/unproved resources. Never serialize these capabilities.
            first.retained_process_resources = {key: value for key, value in retained.items()
                                                if value is not None}
            first.captured_stdout = bytes(output[:limit])
        except BaseException as error:
            first.add_note('bounded failure transcript unavailable: ' + type(error).__name__)
        raise first
    return result


def run(argv, env, cwd, *, tool, work_end, cleanup_end, pass_fds=(),
        limit=4 * 1024 * 1024):
    """Sealed owner's API plus an earliest-failure, original-clipped 180s bound.

    No process actor starts during API/preparation refusal. That refusal still
    exposes its observation timestamp. Work/cancellation/nonzero classification
    precedes direct-child retirement; the same endpoint is never renewed by
    subsequent cleanup faults. Successful results carry first_failure_at=None.
    Root must reuse this timestamp for its separate daemon-resource recovery.
    OS operations remain finite attempts, not hard-time-clipped syscalls.
    """
    try:
        return _run(argv, env, cwd, tool=tool, work_end=work_end,
                    cleanup_end=cleanup_end, pass_fds=pass_fds, limit=limit)
    except BaseException as error:
        now = time.monotonic()
        try:
            old = getattr(error, 'first_failure_at', None)
        except BaseException:
            old = None
        if not (type(old) in (int, float) and math.isfinite(old) and 0 < old <= now):
            try:
                error.first_failure_at = now
            except BaseException:
                error.add_note('first-failure timestamp attribute unavailable')
        raise
