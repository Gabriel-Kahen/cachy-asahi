#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fixed private-library protocol and Linux owned runner; no admission shortcut."""
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import select
import signal
import stat
import sys
import time

import boundary

INPUT_FD, RECEIPT_FD = 3, 4
INPUT_LIMIT, RECEIPT_LIMIT, LOG_LIMIT = 1024**2, 1024**2, 4*1024**2
CHUNK = 65536
CLI = 'scripts/ci/private-library-cli/'
CLEANUP_COMMANDS = frozenset(('container-inspect','container-wait','container-remove','container-absence',
    'image-inspect','image-remove','image-absence','parent-container-absence','parent-image-absence',
    'baseline-info','baseline-inspect'))
HELD = []  # Failed/unreturned custody stays reachable; an exception is not disposal.
USED_SESSIONS = set()


def need(value, code):
    if not value:
        raise ValueError(code)


def remember(state, error, *, cleanup=False, cancel=False):
    """A bounded cleanup-reporting failure cannot replace the original cause."""
    try:
        state.fail(error, cleanup=cleanup, cancel=cancel)
        return True
    except BaseException:
        # Boundary's finite cleanup list is already failure-bearing at its cap.
        # Preserve the caller's primary exception and retain uncertainty explicitly.
        HELD.append({'kind':'FAILURE_RETENTION_UNCERTAIN','exception_type':type(error).__name__})
        return False


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+'\n').encode()


def decode(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    def invalid(_):
        raise ValueError('NONFINITE_JSON')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def identity(row):
    return [getattr(row, name) for name in ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid',
                                          'st_size','st_mtime_ns','st_ctime_ns')]


def relative(name):
    need(type(name) is str and 0 < len(name) <= 512 and '\\' not in name, 'SOURCE_RELATIVE_PATH')
    path = PurePosixPath(name)
    need(not path.is_absolute() and '..' not in path.parts and path.as_posix() == name and name != '.',
         'SOURCE_RELATIVE_PATH')
    return name


def checked_path(value):
    path = Path(value)
    need(path.is_absolute() and '..' not in path.parts and
         all(not p.is_symlink() for p in (path, *path.parents)), 'ABSOLUTE_UNALIASED_PATH')
    return path


def capsule_inventory(record):
    """Exact readonly leaf/directory set; no private bytecode or hidden imports."""
    root = checked_path(record['sources']['root'])
    files = record['sources']['files']
    expected_dirs = {''}
    for name in files:
        relative(name)
        need('__pycache__' not in PurePosixPath(name).parts and not name.endswith(('.pyc','.pyo')), 'PRIVATE_BYTECODE_REFUSED')
        expected_dirs.update(str(p) for p in PurePosixPath(name).parents if str(p) != '.')
    found_files, found_dirs, pending, count = set(), set(), [root], 0
    while pending:
        directory = pending.pop()
        name = '' if directory == root else directory.relative_to(root).as_posix()
        found_dirs.add(name)
        info = directory.lstat()
        need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) in (0o500,0o555), 'READONLY_CAPSULE_DIRECTORY')
        with os.scandir(directory) as entries:
            for entry in entries:
                count += 1
                need(count <= 4096, 'CAPSULE_ENTRY_LIMIT')
                selected = Path(entry.path).relative_to(root).as_posix()
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    need(selected in expected_dirs and entry.name != '__pycache__', 'UNSELECTED_CAPSULE_DIRECTORY')
                    pending.append(Path(entry.path))
                else:
                    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and selected in files and
                         not selected.endswith(('.pyc','.pyo')) and stat.S_IMODE(info.st_mode) == files[selected]['mode'],
                         'UNSELECTED_CAPSULE_LEAF')
                    found_files.add(selected)
    need(found_files == set(files) and found_dirs == expected_dirs, 'CAPSULE_INVENTORY_MISMATCH')
    return [root/name for name in sorted(expected_dirs)]


def clock_domain():
    def text(path):
        with open(path, 'r', encoding='ascii') as stream:
            return stream.read(4097).strip()
    namespace = os.stat('/proc/self/ns/time')
    return {'boot_id': text('/proc/sys/kernel/random/boot_id'), 'clock_id': 'CLOCK_MONOTONIC',
            'time_namespace_device': namespace.st_dev, 'time_namespace_inode': namespace.st_ino}


def read_fd(fd, cap):
    info = os.fstat(fd)
    need(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= cap, 'BOUNDED_REGULAR_FD')
    before = identity(info)
    chunks, count = [], 0
    while True:
        chunk = os.pread(fd, min(CHUNK, cap+1-count), count)
        if not chunk:
            break
        chunks.append(chunk)
        count += len(chunk)
        need(count <= cap, 'FD_BYTE_LIMIT')
    need(count == info.st_size and identity(os.fstat(fd)) == before, 'FD_CHANGED')
    return b''.join(chunks)


def input_record(fd=INPUT_FD):
    need(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY, 'READ_ONLY_INPUT_FD_REQUIRED')
    seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
    need(fcntl.fcntl(fd, fcntl.F_GET_SEALS) & seals == seals, 'SEALED_INPUT_FD_REQUIRED')
    return decode(read_fd(fd, INPUT_LIMIT))


def receipt_frame(value):
    raw = encoded(value)
    need(len(raw) <= RECEIPT_LIMIT, 'RECEIPT_LIMIT')
    return ('%08x\n' % len(raw)).encode()+raw


def parse_receipt(raw):
    need(type(raw) is bytes and 9 <= len(raw) <= RECEIPT_LIMIT+9 and raw[8:9] == b'\n', 'RECEIPT_FRAME')
    need(all(c in b'0123456789abcdef' for c in raw[:8]), 'RECEIPT_LENGTH')
    length = int(raw[:8], 16)
    need(0 < length <= RECEIPT_LIMIT and len(raw) == 9+length, 'RECEIPT_LENGTH')
    return decode(raw[9:])


class Custody:
    """Pin bytes once, then retain FD/path identities at every selected boundary."""
    def __init__(self, record, state):
        self.record, self.state = record, state
        self.files, self.directories, self.closed = [], [], False
        HELD.append(self)

    def _file(self, path, expected, *, runtime=False):
        self.state.check()
        path = checked_path(path)
        fd = os.open(path, os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
        # Retain immediately, including partial authentication failures.
        row = [fd, path, None, 'HELD']
        self.files.append(row)
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_size <= 128*1024**2, 'SELECTED_FILE_TYPE_SIZE')
        need(not stat.S_IMODE(info.st_mode) & (0o022 if runtime else 0o222), 'WRITABLE_SELECTED_FILE')
        raw = read_fd(fd, 128*1024**2)
        need(hashlib.sha256(raw).hexdigest() == expected['sha256'], 'SELECTED_FILE_HASH')
        if 'bytes' in expected:
            need(len(raw) == expected['bytes'], 'SELECTED_FILE_ROW')
        if 'mode' in expected:
            need(stat.S_IMODE(info.st_mode) == expected['mode'], 'SELECTED_FILE_MODE')
        if 'identity' in expected:
            need(identity(info) == expected['identity'], 'SELECTED_RUNTIME_IDENTITY')
        row[2] = identity(info)
        need(identity(path.lstat()) == row[2], 'SELECTED_FILE_PATH_CHANGED')
        self.state.check()
        return raw

    def authenticate(self):
        root = checked_path(self.record['sources']['root'])
        source = self.record['sources']
        need(hashlib.sha256(encoded(source['files'])).hexdigest() == source['manifest_sha256'], 'SOURCE_MANIFEST_PIN')
        need(all(CLI+name in source['files'] for name in ('entry.py','parent_bridge.py','boundary.py','operations.py','owned_build.py','baseline_bridge.py','evidence.py','consumer_adapter.py')),
             'EIGHT_SELECTED_CLI_BODIES_REQUIRED')
        for path in capsule_inventory(self.record):
            fd = os.open(path, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            self.directories.append([fd,path,identity(os.fstat(fd)),'HELD'])
        total = 0
        for name, row in source['files'].items():
            path = root/relative(name)
            for parent in (path.parent, *path.parent.parents):
                if parent == root.parent:
                    break
                need(not stat.S_IMODE(parent.lstat().st_mode) & 0o222, 'WRITABLE_IMPORT_DIRECTORY')
            body = self._file(path, row)
            total += len(body)
            need(total <= 128*1024**2, 'SOURCE_TOTAL_LIMIT')
        runtime = self.record['runtime']
        for name in ('interpreter','docker','gpgv'):
            self._file(runtime[name]['path'], runtime[name], runtime=True)
        output = checked_path(self.record['output']['path'])
        fd = os.open(output, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        self.directories.append([fd, output, identity(os.fstat(fd)), 'HELD'])
        observed = identity(os.fstat(fd)); expected = self.record['output']['identity']
        need(all(observed[k] == expected[k] for k in (0,1,2,4,5)) and
             stat.S_IMODE(os.fstat(fd).st_mode) == 0o700, 'OWNED_OUTPUT_ROOT_REQUIRED')
        self.guard()
        return self

    def guard(self, cleanup=False):
        self.state.check(cleanup=cleanup)
        need(not self.closed and self.files, 'CUSTODY_NOT_AUTHENTICATED')
        need(os.getuid() == self.record['credentials']['uid'] and os.getgid() == self.record['credentials']['gid'],
             'EXECUTION_CREDENTIAL_DRIFT')
        capsule_inventory(self.record)
        for fd, path, before, state in self.files:
            need(state == 'HELD' and before is not None and identity(os.fstat(fd)) == before and identity(path.lstat()) == before,
                 'SELECTED_FILE_IDENTITY_DRIFT')
        for fd, path, before, state in self.directories:
            need(state == 'HELD', 'OUTPUT_DESCRIPTOR_NOT_HELD')
            current = identity(os.fstat(fd))
            need(all(current[k] == identity(path.lstat())[k] == before[k] for k in (0,1,2,4,5)), 'OUTPUT_ROOT_DRIFT')
        socket = self.record['runtime']['socket']
        info = checked_path(socket['path']).lstat()
        need(stat.S_ISSOCK(info.st_mode) and [info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink]
             == socket['identity'], 'DAEMON_SOCKET_DRIFT')
        self.state.check(cleanup=cleanup)

    def check_modules(self):
        """Check project import locations; OS/interpreter/stdlib are trusted."""
        root = Path(self.record['sources']['root'])
        selected = {str(root/name) for name in self.record['sources']['files']}
        for name in ('boundary', 'parent_bridge', 'operations'):
            module = sys.modules.get(name)
            need(module is not None and getattr(module, '__file__', None) is not None and
                 Path(module.__file__).absolute() == root/CLI/(name+'.py'), 'PROJECT_MODULE_ORIGIN')
        need(len(sys.modules) <= 4096, 'IMPORTED_MODULE_LIMIT')
        for module in tuple(sys.modules.values()):
            origin = getattr(module, '__file__', None)
            if origin and Path(origin).absolute().is_relative_to(root):
                need(str(Path(origin).absolute()) in selected, 'UNSELECTED_PROJECT_MODULE')

    def close(self):
        errors = []
        for row in self.files + self.directories:
            if row[3] != 'HELD':
                continue
            try:
                self.state.check(cleanup=True)
                row[3] = 'CLOSE_ATTEMPTED'
                os.close(row[0])
                row[0] = None
                row[3] = 'CLOSED'
                self.state.check(cleanup=True)
            except BaseException as error:
                remember(self.state, error, cleanup=True)
                errors.append('CUSTODY_CLOSE_UNCERTAIN')
        if not errors and all(row[3] == 'CLOSED' for row in self.files+self.directories):
            self.closed = True
            if self in HELD:
                HELD.remove(self)
        return errors


class Handle:
    def __init__(self):
        self.pid = self.pidfd = self.stdout = None
        self.birth = None
        self.code = None
        self.reaped = self.eof = self.signalled = False
        self.uncertainty = []
        self.unknown_fds = {}
        self.mask_original = None
        self.mask_state = 'NOT_ATTEMPTED'
        self.first = None
        HELD.append(self)


class Host:
    """Linux-only syscalls. Tests replace this class, never a serialized callback."""
    def __init__(self, state):
        self.state = state

    def birth(self, pid):
        with open('/proc/'+str(pid)+'/stat', 'rb') as stream:
            raw = stream.read(4097)
        need(len(raw) <= 4096 and b') ' in raw, 'PROCESS_BIRTH_UNAVAILABLE')
        fields = raw.rsplit(b') ', 1)[1].split()
        return dict(pid=pid, ppid=int(fields[1]), sid=int(fields[3]), start_ticks=int(fields[19]))

    def verify(self, handle):
        need(handle.pidfd is not None and handle.birth is not None and self.birth(handle.pid) == handle.birth,
             'PROCESS_BIRTH_CHANGED')

    def start(self, argv, environment, inherited, *, cleanup=False):
        need(hasattr(os, 'pidfd_open') and
             hasattr(os, 'P_PIDFD') and hasattr(signal, 'pidfd_send_signal'), 'LINUX_PIDFD_SPAWN_CAPABILITY_REQUIRED')
        need(set(inherited) in (set(), {INPUT_FD, RECEIPT_FD}) and
             all(type(fd) is int and fd >= 0 for fd in inherited.values()), 'FIXED_INHERITED_FDS')
        h = Handle()
        temporary = []
        previous = None
        try:
            self.state.check(cleanup=cleanup)
            h.stdout, write_end = os.pipe2(os.O_CLOEXEC)
            os.set_blocking(h.stdout, False)
            temporary.append(write_end)
            null = os.open('/dev/null', os.O_RDONLY|os.O_CLOEXEC)
            temporary.append(null)
            actions = []
            for target, original in {0:null, 1:write_end, 2:write_end, **inherited}.items():
                duplicate = fcntl.fcntl(original, fcntl.F_DUPFD_CLOEXEC, 64)
                temporary.append(duplicate)
                actions.append((os.POSIX_SPAWN_DUP2, duplicate, target))
            if hasattr(os, 'POSIX_SPAWN_CLOSEFROM'):
                actions.append((os.POSIX_SPAWN_CLOSEFROM, 5 if inherited else 3))
            else:
                # Ordinary trusted process: no concurrent thread changes the FD
                # table between this bounded snapshot and spawn. Owned FDs are
                # CLOEXEC; only the fixed child targets survive file actions.
                with os.scandir('/proc/self/fd') as entries:
                    descriptors = [int(row.name) for row in entries if row.name.isdigit()]
                need(len(descriptors) <= 4096, 'OPEN_FD_LIMIT')
                keep = {0, 1, 2, *inherited}
                for descriptor in sorted(set(descriptors)-keep):
                    try:
                        os.fstat(descriptor)
                    except OSError:
                        continue
                    actions.append((os.POSIX_SPAWN_CLOSE, descriptor))
            self.state.check(cleanup=cleanup)
            h.mask_state = 'BLOCK_ATTEMPTED'
            previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT,signal.SIGTERM,signal.SIGALRM})
            h.mask_original, h.mask_state = previous, 'BLOCKED'
            self.state.check(cleanup=cleanup)
            h.pid = os.posix_spawn(argv[0], argv, environment, file_actions=actions, setsid=True,
                setsigmask=(), setsigdef=(signal.SIGINT,signal.SIGTERM,signal.SIGALRM,signal.SIGPIPE))
            h.pidfd = os.pidfd_open(h.pid, 0)
            h.birth = self.birth(h.pid)
            need(h.birth['sid'] == h.pid and h.birth['ppid'] == os.getpid() and h.birth['start_ticks'] > 0,
                 'CHILD_SESSION_BIRTH_REQUIRED')
        except BaseException as error:
            h.first = error
            h.uncertainty.append('BIRTH_OR_SUBMISSION_UNCERTAIN')
        finally:
            if previous is not None:
                try:
                    self.state.check(cleanup=True)
                    h.mask_state = 'RESTORE_ATTEMPTED'
                    signal.pthread_sigmask(signal.SIG_SETMASK, previous)
                    h.mask_state = 'RESTORE_RETURNED'
                    self.state.check(cleanup=True)
                    h.mask_state = 'RESTORED'
                except BaseException as error:
                    remember(self.state, error, cleanup=True)
                    if h.first is None:
                        h.first = error
                    h.uncertainty.append('SIGNAL_MASK_RESTORATION_UNCERTAIN')
            for fd in temporary:
                try:
                    self.state.check(cleanup=True)
                    os.close(fd)
                    self.state.check(cleanup=True)
                except BaseException as error:
                    h.unknown_fds['launch-'+str(fd)] = fd
                    remember(self.state, error, cleanup=True)
                    if h.first is None:
                        h.first = error
                    h.uncertainty.append('LAUNCH_FD_CLOSE_UNCERTAIN')
        return h

    def read(self, h, size):
        try:
            body = os.read(h.stdout, size)
        except BlockingIOError:
            return None
        if not body:
            h.eof = True
        return body

    def poll(self, h):
        if h.reaped:
            return h.code
        need(h.pidfd is not None, 'PIDFD_NOT_HELD')
        ready = os.waitid(os.P_PIDFD, h.pidfd, os.WEXITED|os.WNOHANG|os.WNOWAIT)
        if ready is None:
            return None
        pid, status = os.waitpid(h.pid, os.WNOHANG)
        need(pid == h.pid, 'OWNED_REAP_FAILED')
        h.code, h.reaped = os.waitstatus_to_exitcode(status), True
        return h.code

    def pause(self, h, duration):
        fds = [fd for fd in (h.stdout,h.pidfd) if fd is not None]
        select.select(fds, [], [], max(0, min(duration, 0.05)))

    def send(self, h, number):
        self.verify(h)
        signal.pidfd_send_signal(h.pidfd, number, None, 0)
        h.signalled = True

    def close(self, h):
        if not h.reaped:
            if 'PROCESS_NOT_REAPED' not in h.uncertainty:
                h.uncertainty.append('PROCESS_NOT_REAPED')
            if h not in HELD:HELD.append(h)
            return
        for name in ('stdout','pidfd'):
            fd = getattr(h, name)
            if fd is None:
                continue
            try:
                self.state.check(cleanup=True)
                # The close may have happened even when it raises: never retry
                # that numeric descriptor after an ambiguous return.
                setattr(h, name, None)
                os.close(fd)
                self.state.check(cleanup=True)
            except BaseException as error:
                h.unknown_fds[name] = fd
                remember(self.state, error, cleanup=True)
                h.uncertainty.append('PROCESS_FD_CLOSE_UNCERTAIN')
        if h.reaped and not h.uncertainty and h in HELD:
            HELD.remove(h)


class OwnedRunner:
    def __init__(self, record, state, custody):
        self.record, self.state, self.custody = record, state, custody
        self.host = Host(state)

    def _retire(self, h):
        for number, grace in ((signal.SIGTERM,2.0),(signal.SIGKILL,5.0)):
            try:
                self.state.check(cleanup=True)
                if self.host.poll(h) is not None:
                    break
                self.host.send(h, number)
                end = min(self.record['cutoff_monotonic'], time.monotonic()+grace)
                while time.monotonic() < end:
                    self.state.check(cleanup=True)
                    if self.host.poll(h) is not None:
                        break
                    self.host.pause(h, 0.05)
            except BaseException as error:
                remember(self.state, error, cleanup=True)
                h.uncertainty.append('PROCESS_RETIREMENT_UNCERTAIN')
        if not h.reaped:
            h.uncertainty.append('PROCESS_NOT_REAPED')

    def _run(self, argv, timeout, cleanup, *, token=None, inherited=None, receipt_fd=None, receipt_writer=None,
             selected_log=None):
        self.custody.guard(cleanup=cleanup)
        need(type(timeout) in (int,float) and 0 < timeout <= 10080, 'FIXED_COMMAND_TIMEOUT')
        token = self.state.command(cleanup=cleanup) if token is None else token
        output = selected_log if selected_log is not None else Path(self.record['output']['path'])/('command-%03d.log' % token)
        output = checked_path(output)
        directory = output.parent.stat()
        need(stat.S_ISDIR(directory.st_mode) and stat.S_IMODE(directory.st_mode) == 0o700 and
             directory.st_uid == self.record['credentials']['uid'] and directory.st_gid == self.record['credentials']['gid'],
             'OWNED_LOG_DIRECTORY')
        fd = os.open(output, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC, 0o600)
        h, first, body, receipt = None, None, bytearray(), bytearray()
        receipt_eof = receipt_fd is None
        pidfd_seen = False
        try:
            self.custody.guard(cleanup=cleanup)
            end = min(time.monotonic()+timeout, self.record['cutoff_monotonic']-(5 if cleanup else 90))
            need(time.monotonic() < end, 'COMMAND_RESERVE_EXHAUSTED')
            h = self.host.start(argv, dict(self.record['environment']), inherited or {}, cleanup=cleanup)
            pidfd_seen = h.pidfd is not None
            if receipt_writer is not None:
                writer = receipt_writer.pop()
                try:
                    os.close(writer)
                except BaseException:
                    h.uncertainty.append('RECEIPT_PARENT_WRITER_CLOSE_UNCERTAIN')
                    raise
            if h.first is not None:
                raise h.first
            while not (h.reaped and h.eof and receipt_eof):
                self.state.check(cleanup=cleanup)
                need(time.monotonic() < end, 'COMMAND_TIMEOUT')
                if receipt_fd is not None and not receipt_eof:
                    try:
                        part = os.read(receipt_fd, min(CHUNK, RECEIPT_LIMIT+10-len(receipt)))
                    except BlockingIOError:
                        part = None
                    if part == b'':
                        receipt_eof = True
                    elif part:
                        receipt.extend(part)
                        need(len(receipt) <= RECEIPT_LIMIT+9, 'RECEIPT_LIMIT')
                block = self.host.read(h, min(CHUNK, LOG_LIMIT+1-len(body)))
                if block:
                    self.state.log_bytes(token, len(block))
                    need(len(body)+len(block) <= LOG_LIMIT, 'COMMAND_LOG_LIMIT')
                    body.extend(block)
                    position = 0
                    while position < len(block):
                        self.state.check(cleanup=cleanup)
                        written = os.write(fd, block[position:])
                        need(written > 0, 'SHORT_LOG_WRITE')
                        position += written
                self.host.poll(h)
                if not (h.reaped and h.eof and receipt_eof):
                    self.host.pause(h, min(0.05, max(0, end-time.monotonic())))
            self.custody.guard(cleanup=cleanup)
            need(h.code == 0, 'COMMAND_EXIT_NONZERO')
        except BaseException as error:
            first = error
            remember(self.state, error, cancel=isinstance(error,KeyboardInterrupt))
            if not cleanup and self.state.first_cause is not None:
                first = self.state.first_cause
        finally:
            if h is not None and not h.reaped:
                self._retire(h)
            try:
                self.state.check(cleanup=True)
                os.close(fd)
                self.state.check(cleanup=True)
            except BaseException as error:
                remember(self.state, error, cleanup=True)
                HELD.append({'kind':'LOG_FD_CLOSE_UNCERTAIN','fd':fd,'path':str(output)})
                if h is not None:
                    h.uncertainty.append('LOG_CLOSE_UNCERTAIN')
                if first is None:
                    first = error
            if h is not None:
                try:
                    self.host.close(h)
                except BaseException as error:
                    remember(self.state, error, cleanup=True)
                    h.uncertainty.append('PROCESS_CLOSE_UNRETURNED')
                    if first is None:
                        first = error
        return dict(exit_code=h.code if h else None, log=bytes(body), log_path=str(output),
            sha256=hashlib.sha256(body).hexdigest(), bytes=len(body),
            natural_exit=bool(h and h.reaped and type(h.code) is int and h.code >= 0 and not h.signalled),
            reaped=bool(h and h.reaped), birth=h.birth if h else None, pidfd_owned=pidfd_seen,
            receipt=bytes(receipt), receipt_eof=receipt_eof,
            uncertainty=list(h.uncertainty) if h else ['NO_PROCESS_HANDLE'],
            first_failure=None if first is None else {'kind':type(first).__name__,'code':str(first)[:256]})

    def run(self, command_id, fields, *, timeout, cleanup=False):
        import operations
        self.custody.guard(cleanup=cleanup)
        need(not cleanup or command_id in CLEANUP_COMMANDS, 'NEW_WORK_IS_NOT_CLEANUP')
        argv = operations.command(self.record, command_id, fields)
        need(type(argv) is list and 0 < len(argv) <= 256 and all(type(arg) is str and '\0' not in arg for arg in argv),
             'FIXED_COMMAND_GRAMMAR')
        need(argv[0] in (self.record['runtime']['docker']['path'], self.record['runtime']['gpgv']['path']),
             'FIXED_TOOL_REQUIRED')
        selected_log = None
        if command_id == 'container-start-attach' and fields.get('role') in boundary.BUILDS:
            key, number = fields['role'].rsplit('-',1)
            selected_log = Path(self.record['output']['path'])/(key+'-attempt-'+number)/'build.log'
        return self._run(argv, timeout, cleanup, selected_log=selected_log)


def sealed_record(record):
    raw = encoded(record)
    need(len(raw) <= INPUT_LIMIT, 'INPUT_LIMIT')
    fd = os.memfd_create('private-library-input', os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    first = readonly = None
    try:
        position = 0
        while position < len(raw):
            count = os.write(fd, raw[position:])
            need(count > 0, 'SHORT_INPUT_WRITE')
            position += count
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
        readonly = os.open('/proc/self/fd/'+str(fd), os.O_RDONLY|os.O_CLOEXEC)
    except BaseException as error:
        first = error
    finally:
        try:
            os.close(fd)
        except BaseException as error:
            HELD.append({'kind':'INPUT_WRITE_FD_CLOSE_UNCERTAIN','fd':fd})
            if first is None:
                first = error
            else:
                first.add_note('INPUT_WRITE_FD_CLOSE_UNCERTAIN:'+type(error).__name__)
    if first is not None:
        if readonly is not None:
            try:
                os.close(readonly)
            except BaseException as error:
                HELD.append({'kind':'INPUT_READ_FD_CLOSE_UNCERTAIN','fd':readonly})
                first.add_note('INPUT_READ_FD_CLOSE_UNCERTAIN:'+type(error).__name__)
        raise first
    return readonly


def launch(record, lease):
    """One child; actual in-memory baseline authority and cumulative budgets."""
    import operations
    need(lease is not None, 'ACTUAL_BASELINE_LEASE_REQUIRED')
    import baseline_bridge
    need(type(lease) is baseline_bridge.Lease, 'ACTUAL_BASELINE_LEASE_REQUIRED')
    observed = clock_domain()
    record = boundary.validate_input(record, observed_domain=observed)
    need(record['budget'] == {'commands':1,'command_log_bytes':{'1':0},'log_bytes':0,'fetches':0,'fetch_bytes':0},
         'PARENT_INITIAL_BUDGET')
    session = (record['identity']['run_id'],record['identity']['run_attempt'],record['nonce'])
    need(session not in USED_SESSIONS, 'CHILD_INPUT_REPLAY_REFUSED')
    USED_SESSIONS.add(session)
    state = boundary.Boundary(record, observed_domain=observed, clock=time.monotonic)
    custody = Custody(record, state)
    input_fd = receipt_read = receipt_write = None
    result = process = child = issued = None
    child_submission_attempted = False
    previous = {}
    def cancelled(number, frame):
        remember(state, KeyboardInterrupt('PARENT_CANCELLED'), cancel=True)
    try:
        for number in (signal.SIGINT, signal.SIGTERM):
            state.check()
            previous[number] = signal.getsignal(number)
            signal.signal(number, cancelled)
        custody.authenticate()
        operations.parent_preflight(record, custody, lease)
        issued = state.snapshot()
        need(issued['commands'] == 3 and issued['fetches'] == issued['fetch_bytes'] == 0 and
             issued['command_log_bytes']['1'] == 0, 'BASELINE_PREFLIGHT_BUDGET')
        record['budget'] = issued
        boundary.validate_input(record, observed_domain=observed)
        input_fd = sealed_record(record)
        receipt_read, receipt_write = os.pipe2(os.O_CLOEXEC|os.O_NONBLOCK)
        argv = [record['runtime']['interpreter']['path'], '-I', '-B', '-S',
                str(Path(record['sources']['root'])/CLI/'entry.py')]
        runner = OwnedRunner(record, state, custody)
        writer = [receipt_write]
        try:
            child_submission_attempted = True
            lease.child_submission_attempted = True
            process = runner._run(argv, 10080, False, token=1,
                inherited={INPUT_FD:input_fd, RECEIPT_FD:receipt_write}, receipt_fd=receipt_read, receipt_writer=writer)
        finally:
            if not writer:
                receipt_write = None
    except BaseException as error:
        remember(state, error, cancel=isinstance(error,KeyboardInterrupt))
    finally:
        retired = process is not None and process_retired(process)
        if retired:
            lease.child_retired = True
            try:
                need(process['receipt_eof'], 'CHILD_RECEIPT_NOT_EOF')
                child = parse_receipt(process['receipt'])
                boundary.validate_terminal(child, record)
                # Early failure can precede the child's self-observation. The
                # parent's actual birth/reap and the fixed private receipt pipe
                # still bind a valid partial budget; a positive terminal needs
                # the independent matching self-observation as well.
                if child['child'] is not None:
                    need(child['child']['pid'] == process['birth']['pid'] and
                         child['child']['session_id'] == process['birth']['sid'] and
                         child['child']['start_time_ticks'] == process['birth']['start_ticks'] and
                         child['child']['reaped'] is False and child['child']['exit_code'] is None and
                         child['child']['natural'] is False, 'CHILD_BIRTH_RECEIPT_JOIN')
                state.merge_child_budget(issued, child['budget'])
                if child['status'] != 'CHILD_COMPLETE' or process['exit_code'] != 0 or not process['natural_exit'] or                        process['uncertainty'] or process['first_failure'] is not None:
                    remember(state, ValueError('CHILD_NOT_COMPLETE'))
            except BaseException as error:
                child = None
                state.budget_known = False
                remember(state, error)
                remember(state, ValueError('CHILD_BUDGET_UNKNOWN'), cleanup=True)
            try:
                result = operations.parent_terminal(record, child, process, custody, lease)
                boundary.validate_terminal(result, record, parent_checked=True)
            except BaseException as error:
                remember(state, error)
                result = None
        elif process is not None or child_submission_attempted:
            state.budget_known = False
            remember(state, ValueError('CHILD_NOT_POSITIVELY_RETIRED'))
            remember(state, ValueError('CHILD_BUDGET_UNKNOWN'), cleanup=True)
        retained = child_submission_attempted and not retired
        if retained:
            HELD.append(dict(kind='CHILD_RETIREMENT_RECOVERY',lease=lease,custody=custody,
                record=record,process=process,protocol_fds=(input_fd,receipt_read,receipt_write)))
        for fd in (() if retained else (input_fd,receipt_read,receipt_write)):
            if fd is not None:
                try:
                    os.close(fd)
                except BaseException as error:
                    remember(state, error, cleanup=True)
                    HELD.append({'kind':'PROTOCOL_FD_CLOSE_UNCERTAIN','fd':fd})
        if not retained:custody.close()
        for number, handler in previous.items():
            try:
                state.check(cleanup=True)
                signal.signal(number, handler)
                state.check(cleanup=True)
            except BaseException as error:
                remember(state, error, cleanup=True)
                HELD.append({'kind':'PARENT_HANDLER_RESTORE_UNCERTAIN','signal':number,'handler':handler})
    return terminal_after_cleanup(record, state, result)


def process_retired(process):
    birth = process.get('birth')
    return (process.get('reaped') is True and process.get('pidfd_owned') is True and
        type(process.get('exit_code')) is int and type(birth) is dict and
        all(type(birth.get(k)) is int and birth[k] > 0 for k in ('pid','sid','ppid','start_ticks')) and
        birth['pid'] == birth['sid'] and birth['ppid'] == os.getpid())


def terminal_after_cleanup(record, state, result=None):
    if result is not None and (state.first_cause is not None or state.cleanup_errors or state.cancelled):
        result['status'] = 'FAIL'
        result['first_cause'] = boundary.failure_record(state.first_cause) if state.first_cause else result['first_cause']
        result['cleanup_errors'] += [boundary.failure_record(error) for error in state.cleanup_errors]
        result['cancelled'] = result['cancelled'] or state.cancelled
        boundary.validate_terminal(result, record, parent_checked=True)
    return result if result is not None else state.terminal(status='INCOMPLETE')


def recheck(record, custody, cleanup=False):
    need(type(custody) is Custody and custody.record == record, 'SELECTED_CUSTODY_REQUIRED')
    custody.guard(cleanup=cleanup)
