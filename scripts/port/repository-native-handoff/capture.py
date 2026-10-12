# SPDX-License-Identifier: MIT
"""Bounded private custody. Capturing bytes never grants native admission."""
from contextlib import contextmanager
import base64
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import time

FILE_LIMIT, TOTAL_LIMIT, COUNT = 16 * 1024**2, 64 * 1024**2, 2048
SIGNALS = {signal.SIGINT, signal.SIGTERM}
MARKER, ACK_MARKER = b'\x1eRCNH1 ', b'\x1eRCNH1-ACK '
PHASES = ('pre-A-revocation', 'post-public-export')
PRIVATE = re.compile(rb'(?m)^-----BEGIN (?:[A-Z0-9 ]* )?PRIVATE KEY|\((?:protected-)?private-key')


class Refused(ValueError):
    pass


class Cancelled(Refused):
    pass


def need(ok, reason):
    if not ok:
        raise Refused(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()


def decode(raw, limit=FILE_LIMIT):
    need(type(raw) is bytes and 0 < len(raw) <= limit, 'json-bound')
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'json-duplicate')
            result[key] = value
        return result
    def invalid(_):
        raise Refused('json-number')
    result = json.loads(raw, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
    need(type(result) is dict, 'json-object')
    return result


def check(deadline=None, cancelled=None):
    need(deadline is None or type(deadline) in (int, float) and math.isfinite(deadline), 'finite-deadline')
    if cancelled and cancelled():
        raise Cancelled('cancelled')
    need(deadline is None or time.monotonic() < deadline, 'deadline-expired')


def relative(name):
    need(type(name) is str and 0 < len(name.encode()) <= 4096 and '\\' not in name
         and not any(ord(c) < 32 or ord(c) == 127 for c in name), 'relative-path')
    path = PurePosixPath(name)
    need(not path.is_absolute() and path.as_posix() == name and
         all(part not in ('', '.', '..') for part in name.split('/')), 'relative-path')
    need(not any(part in {'private-keys-v1.d', 'openpgp-revocs.d', 'TEST-revocation.asc',
                         'trustdb.gpg', 'S.gpg-agent'} for part in path.parts), 'private-path')
    return path


def identity(info):
    return tuple(getattr(info, field) for field in
                 ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                  'st_size', 'st_mtime_ns', 'st_ctime_ns'))


@contextmanager
def directory(path, *, deadline=None):
    path = Path(path).absolute()
    need('..' not in path.parts, 'directory-path')
    opened, prior = [], []
    try:
        opened.append(os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
        current = Path('/')
        prior.append((current, os.fstat(opened[-1])))
        for part in path.parts[1:]:
            check(deadline)
            opened.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=opened[-1]))
            current /= part
            prior.append((current, os.fstat(opened[-1])))
        check(deadline)
        yield opened[-1]
        for name, before in prior:
            now = name.lstat()
            need((now.st_dev, now.st_ino, now.st_mode) == (before.st_dev, before.st_ino, before.st_mode), 'directory-drift')
    finally:
        for fd in reversed(opened):
            os.close(fd)


def read(path, limit=FILE_LIMIT, *, deadline=None):
    path = Path(path).absolute()
    need(type(limit) is int and 0 <= limit <= 64 * 1024**2, 'read-bound')
    with directory(path.parent, deadline=deadline) as parent:
        check(deadline)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit, 'file-type-bound')
            chunks, size = [], 0
            while True:
                check(deadline)
                block = os.read(fd, min(65536, limit + 1 - size))
                check(deadline)
                if not block:
                    break
                chunks.append(block); size += len(block)
                need(size <= limit, 'read-bound')
            need(size == before.st_size and identity(before) == identity(os.fstat(fd))
                 == identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'file-drift')
            return b''.join(chunks)
        finally:
            os.close(fd)


def write_atomic(path, raw, expected_parent=None, *, deadline=None):
    """Exclusive, unbuffered, durable private write; ACK only after directory fsync."""
    need(type(raw) is bytes and len(raw) <= FILE_LIMIT, 'write-bound')
    path = Path(path).absolute()
    with directory(path.parent, deadline=deadline) as parent:
        before = os.fstat(parent)
        need(before.st_uid == os.geteuid() and not before.st_mode & 0o022, 'private-parent')
        if expected_parent is not None:
            need((before.st_dev, before.st_ino) == expected_parent, 'private-parent-drift')
        check(deadline)
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            offset = 0
            while offset < len(raw):
                check(deadline)
                size = os.write(fd, raw[offset:offset + 65536])
                check(deadline)
                need(0 < size <= min(65536, len(raw) - offset), 'short-write')
                offset += size
            os.fsync(fd); check(deadline)
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == len(raw)
                 and stat.S_IMODE(info.st_mode) == 0o600, 'written-file-drift')
            os.fsync(parent); check(deadline)
            need(identity(info) == identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'written-file-drift')
        finally:
            os.close(fd)
    need(read(path, deadline=deadline) == raw, 'durable-byte-drift')
    return {'sha256': digest(raw), 'bytes': len(raw)}


class Cancellation:
    """Handlers remember cancellation; only explicit checks raise it."""
    def __init__(self):
        self.signum = None
        self.deferrals = 0
    def remember(self, signum, _):
        self.signum = signum
    def check(self):
        if self.signum and not self.deferrals:
            raise Cancelled('cancelled')
    @contextmanager
    def defer(self):
        self.deferrals += 1
        try:
            yield
        finally:
            self.deferrals -= 1


@contextmanager
def cancellation():
    state = Cancellation()
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
    previous = {sig: signal.getsignal(sig) for sig in SIGNALS}
    try:
        for sig in SIGNALS:
            signal.signal(sig, state.remember)
        signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        yield state
        state.check()
    finally:
        closing_mask = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
        fault = None
        try:
            for _ in range(2):
                for sig, handler in previous.items():
                    try:
                        if signal.getsignal(sig) != handler:
                            signal.signal(sig, handler)
                    except BaseException as error:
                        fault = fault or error
            # Delivery remains blocked while both old dispositions are restored.
            # Consume only signals originally unblocked, including ones arriving
            # during a setter; blocked caller signals remain pending untouched.
            pending = (signal.sigpending() & SIGNALS) - mask
            for sig in pending:
                signal.sigtimedwait({sig}, 0)
                state.signum = sig
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, closing_mask)
        if fault:
            raise fault
        state.check()


class Checkpoints:
    def __init__(self, root, nonce, *, deadline, cancelled=None):
        need(re.fullmatch(r'[0-9a-f]{32}', nonce or ''), 'checkpoint-nonce')
        self.root, self.nonce = Path(root).absolute(), nonce
        self.deadline, self.cancelled = deadline, cancelled
        self.previous, self.records, self.failed = '0' * 64, [], False
        with directory(self.root) as fd:
            info = os.fstat(fd)
            need(info.st_uid == os.geteuid() and not info.st_mode & 0o077, 'checkpoint-private-root')
            self.parent = (info.st_dev, info.st_ino)
    def receive(self, frame, deadline):
        try:
            check(min(deadline, self.deadline), self.cancelled)
            sequence = len(self.records) + 1
            need(not self.failed and sequence <= 2 and type(frame) is dict and set(frame) ==
                 {'schema_version', 'purpose', 'nonce', 'sequence', 'phase', 'payload', 'payload_sha256', 'previous_frame_sha256'}, 'checkpoint-shape')
            need(type(frame['schema_version']) is int and frame['schema_version'] == 1
                 and frame['purpose'] == 'repository-native-checkpoint' and frame['nonce'] == self.nonce
                 and type(frame['sequence']) is int and frame['sequence'] == sequence
                 and frame['phase'] == PHASES[sequence - 1] and frame['previous_frame_sha256'] == self.previous,
                 'checkpoint-order-identity')
            payload = base64.b64decode(frame['payload'], validate=True)
            need(0 < len(payload) <= 4 * 1024**2 and digest(payload) == frame['payload_sha256']
                 and not PRIVATE.search(payload), 'checkpoint-payload')
            decode(payload, 4 * 1024**2)
            frame_raw = encoded(frame).rstrip(b'\n')
            need(len(frame_raw) <= 6 * 1024**2, 'checkpoint-wire-bound')
            pin = digest(frame_raw)
            write_atomic(self.root / f'checkpoint-{sequence}.json', frame_raw + b'\n', self.parent, deadline=min(deadline, self.deadline))
            check(min(deadline, self.deadline), self.cancelled)
            self.records.append({'sequence': sequence, 'phase': frame['phase'], 'sha256': pin,
                                 'payload_sha256': frame['payload_sha256'], 'durable_host_digest': True})
            self.previous = pin
            return ACK_MARKER + encoded({'schema_version': 1, 'purpose': 'repository-native-checkpoint-ack',
                                        'nonce': self.nonce, 'sequence': sequence, 'phase': frame['phase'],
                                        'frame_sha256': pin, 'durable_host_digest': True})
        except BaseException:
            self.failed = True
            raise


def parents(root, name, *, deadline):
    """Create owned descendants through directory descriptors, never symlinks."""
    with directory(root, deadline=deadline) as start:
        fds = []
        current = start
        try:
            for part in PurePosixPath(name).parts:
                check(deadline)
                try:
                    os.mkdir(part, mode=0o700, dir_fd=current)
                except FileExistsError:
                    pass
                current = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                fds.append(current)
                info = os.fstat(current)
                need(info.st_uid == os.geteuid() and not info.st_mode & 0o077, 'capture-parent')
            check(deadline)
        finally:
            for fd in reversed(fds):
                os.close(fd)


def capture_files(selections, output, *, deadline, cancelled=None, index=True):
    """Explicit finite map only; caller supplies named actual paths, never a walk."""
    need(type(selections) is dict and 0 < len(selections) <= COUNT, 'capture-count')
    need(type(index) is bool and (not index or 'capture.json' not in selections), 'capture-index-name')
    output = Path(output).absolute()
    need(not output.exists() and not output.is_symlink(), 'fresh-capture')
    with directory(output.parent, deadline=deadline) as fd:
        check(deadline, cancelled)
        os.mkdir(output.name, mode=0o700, dir_fd=fd)
    with directory(output, deadline=deadline) as root_fd:
        before = os.fstat(root_fd)
        def current():
            check(deadline, cancelled)
            fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid')
            need(all(getattr(output.lstat(), key) == getattr(before, key) == getattr(os.fstat(root_fd), key)
                     for key in fields), 'capture-root-drift')
        result, total = {}, 0
        for name, source in selections.items():
            current(); relative(name)
            data = read(source, deadline=deadline)
            need(not PRIVATE.search(data), 'private-content')
            total += len(data); need(total <= TOTAL_LIMIT, 'capture-total')
            target = output / name
            parents(output, str(relative(name).parent), deadline=deadline)
            current()
            result[name] = write_atomic(target, data, deadline=deadline)
            current()
        for name, source in selections.items():
            current()
            need(read(source, deadline=deadline) == read(output / name, deadline=deadline), 'capture-source-drift')
        receipt = {'schema_version': 1, 'purpose': 'pending-private-repository-capture', 'status': 'PENDING',
                   'files': result, 'native_admission': 'NOT RUN'}
        current()
        if index:
            write_atomic(output / 'capture.json', encoded(receipt), (before.st_dev, before.st_ino), deadline=deadline)
        current()
    return receipt
