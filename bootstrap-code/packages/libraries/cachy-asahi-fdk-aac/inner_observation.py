#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite FDK observations only; no build, installation or acceptance authority."""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import threading

LIMIT = 2048
PHASES = ('UNKNOWN', 'PREPARE', 'BUILD', 'CHECK', 'PACKAGE')
PREDICATES = frozenset(('UNKNOWN', 'SELECTED_PATH', 'SELECTED_BYTES', 'SELECTED_GRANT',
                       'COMPILER_NONZERO', 'COMPILER_CALL', 'COMPILER_TIMEOUT'))
REASONS = frozenset(('UNKNOWN', 'NONZERO', 'TIMEOUT', 'CANCELLED', 'IO', 'INVALID_DATA'))
BINDINGS = frozenset(('entry_sha256', 'recipe_sha256', 'observer_sha256', 'selected_sha256', 'layout_sha256'))
FIELDS = frozenset(('schema_version', 'bindings', 'phase', 'first_failure', 'cancelled', 'write_failed',
    'compiler_attempted', 'compiler_attempt_count', 'compiler_natural_count', 'first_compiler_attempt',
    'first_compiler_natural', 'publication'))
SELECTED = 'fdk-aac-3.0.0-selected-source.tar'


def need(value):
    if not value:
        raise ValueError('invalid finite FDK inner observation')


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'


def event(value):
    if value is None:
        return
    need(type(value) is dict and set(value) == {'kind', 'index', 'natural', 'returncode'})
    need(value['kind'] in ('COMPILE', 'LINK') and type(value['index']) is int and
         0 <= value['index'] <= (394 if value['kind'] == 'COMPILE' else 1))
    need(type(value['natural']) is bool)
    code = value['returncode']
    need(code is None or type(code) is int and -64 <= code <= 255)
    need(value['natural'] == (code is not None))


def validate(value):
    need(type(value) is dict and set(value) == FIELDS and type(value['schema_version']) is int and value['schema_version'] == 1)
    pins = value['bindings']
    need(type(pins) is dict and set(pins) == BINDINGS)
    for pin in pins.values():
        need(pin is None or type(pin) is str and re.fullmatch('[0-9a-f]{64}', pin))
    need(type(value['phase']) is str and value['phase'] in PHASES and value['publication'] == 'NOT ACCEPTED')
    for key in ('cancelled', 'write_failed', 'compiler_attempted'):
        need(type(value[key]) is bool)
    for key in ('compiler_attempt_count', 'compiler_natural_count'):
        need(type(value[key]) is int and 0 <= value[key] <= 397)
    attempted, natural = value['compiler_attempt_count'], value['compiler_natural_count']
    need(natural <= attempted and value['compiler_attempted'] == (attempted > 0))
    for key in ('first_compiler_attempt', 'first_compiler_natural'):
        event(value[key])
    need((value['first_compiler_attempt'] is not None) == (attempted > 0))
    need((value['first_compiler_natural'] is not None) == (natural > 0))
    if attempted:
        need(not value['first_compiler_attempt']['natural'])
    if natural:
        need(value['first_compiler_natural']['natural'])
        if attempted == 1:
            need(all(value['first_compiler_attempt'][key] == value['first_compiler_natural'][key]
                     for key in ('kind', 'index')))
    first = value['first_failure']
    need(not natural or value['first_compiler_natural']['returncode'] == 0 or first is not None)
    if first is not None:
        need(type(first) is dict and set(first) == {'phase', 'predicate', 'reason', 'command'})
        need(type(first['phase']) is str and first['phase'] in PHASES and
             type(first['predicate']) is str and first['predicate'] in PREDICATES and
             type(first['reason']) is str and first['reason'] in REASONS)
        event(first['command'])
        need(first['reason'] != 'CANCELLED' or value['cancelled'])
        cmd = first['command']
        if cmd is not None:
            need(attempted > 0 and (not cmd['natural'] or natural > 0))
            if attempted == 1:
                need(all(cmd[key] == value['first_compiler_attempt'][key] for key in ('kind', 'index')))
            if natural == 1 and cmd['natural']:
                need(cmd == value['first_compiler_natural'])
        need(first['reason'] != 'NONZERO' or first['predicate'] == 'COMPILER_NONZERO')
        if first['predicate'] == 'COMPILER_NONZERO':
            need(first['reason'] == 'NONZERO' and first['command'] is not None and
                 first['command']['natural'] and first['command']['returncode'] != 0)
    need(len(encoded(value)) <= LIMIT)
    return value


def loads(data):
    need(type(data) is bytes and len(data) <= LIMIT)
    def unique(rows):
        result = {}
        for key, value in rows:
            need(key not in result); result[key] = value
        return result
    def invalid(_):
        raise ValueError('nonfinite FDK observation')
    return validate(json.loads(data, object_pairs_hook=unique, parse_constant=invalid))


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


# Linux EBADF alone proves that a queried descriptor is no longer open.
_UNCERTAIN = {}
_OWNERSHIP_MUTEX = threading.RLock()


def close_owned(fd):
    original = sys.exc_info()[1]
    object_id = lambda info: (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), info.st_rdev)
    with _OWNERSHIP_MUTEX:
        fresh = fd not in _UNCERTAIN
        owned = _UNCERTAIN.setdefault(fd, dict(identity=None, error=None, control=None))
        for slot in range(3):
            try:
                current = object_id(os.fstat(fd))
            except BaseException as error:
                if isinstance(error, OSError) and error.errno == 9:
                    _UNCERTAIN.pop(fd)
                    break
                owned['error'] = owned['error'] or error
                if not isinstance(error, Exception):
                    owned['control'] = owned['control'] or error
                continue
            # Only the first query can establish fresh ownership. A failed
            # acquisition stays unknown; later queries can prove only EBADF.
            if fresh and slot == 0:
                owned['identity'] = current
            if owned['identity'] is None:
                continue
            if current != owned['identity']:
                owned['error'] = owned['error'] or OSError('FDK descriptor ownership is uncertain')
                break
            try:
                os.close(fd)
            except BaseException as error:
                owned['error'] = owned['error'] or error
                if not isinstance(error, Exception):
                    owned['control'] = owned['control'] or error
                continue
            _UNCERTAIN.pop(fd)
            break
        first, control = owned['error'], owned['control']
    if control is not None and (original is None or isinstance(original, Exception)):
        raise control from (original or first if first is not control else original)
    if first is not None and original is None:
        raise first


def directory(path):
    """Walk each component through owned no-follow descriptors, never a path alias."""
    path = Path(os.path.abspath(path))
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        for name in path.parts[1:]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            old, fd = fd, child
            close_owned(old)
        return fd, os.fstat(fd)
    except BaseException:
        close_owned(fd)
        raise


def named_directory(path, before):
    fd, info = directory(path)
    try:
        need((info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid) ==
             (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid))
    finally:
        close_owned(fd)


def regular_at(root, name, limit, mode=None):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit
             and before.st_uid == os.getuid() and before.st_gid == os.getgid()
             and (mode is None or stat.S_IMODE(before.st_mode) == mode))
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        need(identity(before) == identity(os.fstat(fd)) ==
             identity(os.stat(name, dir_fd=root, follow_symlinks=False)) and len(data) == before.st_size)
        return bytes(data)
    finally:
        close_owned(fd)


def regular(path, limit):
    path = Path(path)
    root, before = directory(path.parent)
    try:
        data = regular_at(root, path.name, limit)
        named_directory(path.parent, before)
        return data
    finally:
        close_owned(root)



def binding_values(inputs=Path('/inputs'), entry=Path('/builder-entry.sh')):
    paths = {'entry_sha256': (Path(entry), 4 * 1024**2),
        'recipe_sha256': (Path(inputs)/'PKGBUILD', 65536),
        'observer_sha256': (Path(__file__), 128 * 1024),
        'selected_sha256': (Path(inputs)/SELECTED, 20 * 1024**2),
        'layout_sha256': (Path(inputs)/'build-layout.json', 1024**2)}
    pins = dict.fromkeys(BINDINGS)
    for key, (path, limit) in paths.items():
        try:
            data = regular(path, limit)
            if key == 'observer_sha256':
                need(data == regular(Path(inputs)/'inner_observation.py', limit))
            pins[key] = hashlib.sha256(data).hexdigest()
        except Exception:
            pass
    return pins


def reason(error):
    if isinstance(error, (KeyboardInterrupt, SystemExit)):
        return 'CANCELLED'
    if type(error).__name__ == 'TimeoutExpired':
        return 'TIMEOUT'
    if isinstance(error, OSError):
        return 'IO'
    if isinstance(error, (ValueError, TypeError, KeyError)):
        return 'INVALID_DATA'
    return 'UNKNOWN'


def command(kind, index, code=None):
    value = {'kind': kind, 'index': index, 'natural': code is not None, 'returncode': code}
    event(value)
    return value


class Recorder:
    def __init__(self, output=Path('/out'), bindings=None):
        self.output = Path(output)
        self._mutex = threading.RLock()
        self._attempts, self._returns = set(), set()
        self._published_identity, self._parent_identity, self._root_identity = None, None, None
        self._row = dict(schema_version=1, bindings=dict(binding_values() if bindings is None else bindings),
            phase='UNKNOWN', first_failure=None, cancelled=False, write_failed=False, compiler_attempted=False,
            compiler_attempt_count=0, compiler_natural_count=0, first_compiler_attempt=None,
            first_compiler_natural=None, publication='NOT ACCEPTED')
        self._change(lambda row: None)

    def _root(self):
        parent, info = directory(self.output)
        root = None
        try:
            need(info.st_uid == os.getuid() and info.st_gid == os.getgid() and not stat.S_IMODE(info.st_mode) & 0o022)
            parent_identity = (info.st_dev, info.st_ino)
            need(self._parent_identity in (None, parent_identity))
            self._parent_identity = parent_identity
            named_directory(self.output, info)
            try:
                os.mkdir('fdk-inner', 0o700, dir_fd=parent)
            except FileExistsError:
                pass
            root = os.open('fdk-inner', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                inside = os.fstat(root)
                need(inside.st_uid == os.getuid() and inside.st_gid == os.getgid() and stat.S_IMODE(inside.st_mode) == 0o700)
                root_identity = (inside.st_dev, inside.st_ino)
                need(self._root_identity in (None, root_identity))
                self._root_identity = root_identity
                need(identity(inside) == identity(os.stat('fdk-inner', dir_fd=parent, follow_symlinks=False)))
                named_directory(self.output, info)
            except BaseException:
                close_owned(root)
                raise
            return root, inside
        finally:
            try:
                close_owned(parent)
            except BaseException:
                if root is not None:
                    close_owned(root)
                raise

    def _invalidate(self, expected):
        root, _ = self._root()
        lock = None
        try:
            lock = os.open('.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=root)
            stamp = os.fstat(lock)
            need(stat.S_ISREG(stamp.st_mode) and stamp.st_nlink == 1 and stamp.st_uid == os.getuid()
                 and stamp.st_gid == os.getgid() and stat.S_IMODE(stamp.st_mode) == 0o600 and stamp.st_size <= LIMIT)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            need(identity(stamp) == identity(os.stat('.lock', dir_fd=root, follow_symlinks=False)))
            data = encoded(validate(self._row))
            pending, offset = memoryview(data), 0
            while pending:
                count = os.pwrite(lock, pending, offset); need(count > 0)
                pending, offset = pending[count:], offset + count
            os.ftruncate(lock, len(data))
            need(identity(os.fstat(lock)) == identity(os.stat('.lock', dir_fd=root, follow_symlinks=False)))
            os.fsync(lock)
            if expected is None:
                return
            info = os.stat('observation.json', dir_fd=root, follow_symlinks=False)
            need((info.st_dev, info.st_ino) == expected and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                 and info.st_uid == os.getuid() and info.st_gid == os.getgid() and stat.S_IMODE(info.st_mode) == 0o600)
            os.unlink('observation.json', dir_fd=root)
            self._published_identity = None
            os.fsync(root)
        finally:
            if lock is not None:
                try:
                    close_owned(lock)
                finally:
                    close_owned(root)
            else:
                close_owned(root)

    def _merge(self, other):
        need(other['bindings'] == self._row['bindings'])
        row = self._row
        row['phase'] = max((row['phase'], other['phase']), key=PHASES.index)
        for key in ('cancelled', 'write_failed', 'compiler_attempted'):
            row[key] |= other[key]
        for key in ('compiler_attempt_count', 'compiler_natural_count'):
            row[key] = max(row[key], other[key])
        for key in ('first_failure', 'first_compiler_attempt', 'first_compiler_natural'):
            if other[key] is not None:
                row[key] = other[key]

    def _ownership_refusal(self):
        with _OWNERSHIP_MUTEX:
            if not _UNCERTAIN:
                return False
            self._row['write_failed'] = True
            for owned in _UNCERTAIN.values():
                if owned['control'] is not None:
                    self._failure(self._row, 'UNKNOWN', owned['control'], None)
            return True

    def _publish(self):
        root, lock, temporary, temporary_inode, published = None, None, None, None, self._published_identity
        original, failed = sys.exc_info()[1], False
        failed |= self._ownership_refusal()
        try:
            root, before = self._root()
            lock = os.open('.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=root)
            info = os.fstat(lock)
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                 and info.st_gid == os.getgid() and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= LIMIT)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            need(identity(info) == identity(os.stat('.lock', dir_fd=root, follow_symlinks=False)))
            marker = os.read(lock, LIMIT + 1); need(len(marker) <= LIMIT)
            if marker:
                blocked = loads(marker); need(blocked['write_failed'])
                self._merge(blocked)
            try:
                other = loads(regular_at(root, 'observation.json', LIMIT, 0o600))
                named = os.stat('observation.json', dir_fd=root, follow_symlinks=False)
                published = (named.st_dev, named.st_ino)
                self._merge(other)
            except FileNotFoundError:
                need(self._published_identity is None)
            failed |= self._ownership_refusal()
            data = encoded(validate(self._row))
            temporary = '.observation-' + os.urandom(8).hex()
            fd = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=root)
            try:
                opened = os.fstat(fd); temporary_inode = (opened.st_dev, opened.st_ino)
                pending = memoryview(data)
                while pending:
                    count = os.write(fd, pending); need(count > 0); pending = pending[count:]
                os.fsync(fd)
                need(identity(os.fstat(fd)) == identity(os.stat(temporary, dir_fd=root, follow_symlinks=False)))
                need(regular_at(root, temporary, LIMIT, 0o600) == data)
                named_directory(self.output/'fdk-inner', before)
                os.replace(temporary, 'observation.json', src_dir_fd=root, dst_dir_fd=root)
                temporary = None
                named = os.stat('observation.json', dir_fd=root, follow_symlinks=False)
                published = (named.st_dev, named.st_ino)
                need(published == temporary_inode and identity(named) == identity(os.fstat(fd)))
                need(regular_at(root, 'observation.json', LIMIT, 0o600) == data)
                os.fsync(root)
                named_directory(self.output/'fdk-inner', before)
                need(identity(info) == identity(os.stat('.lock', dir_fd=root, follow_symlinks=False)))
                self._published_identity = published
            finally:
                close_owned(fd)
        except Exception:
            failed = True; self._row['write_failed'] = True
        except BaseException as control:
            failed = True; self._row['write_failed'] = True
            self._failure(self._row, 'UNKNOWN', control, None)
            raise
        finally:
            active, first_control = sys.exc_info()[1] or original, None
            if temporary is not None and root is not None:
                for _ in range(3):
                    try:
                        named = os.stat(temporary, dir_fd=root, follow_symlinks=False)
                        need(temporary_inode == (named.st_dev, named.st_ino))
                        os.unlink(temporary, dir_fd=root)
                        break
                    except FileNotFoundError:
                        break
                    except BaseException as error:
                        failed = True; self._row['write_failed'] = True
                        if not isinstance(error, Exception):
                            first_control = first_control or error
                            self._failure(self._row, 'UNKNOWN', error, None)
            for fd in (lock, root):
                if fd is not None:
                    try:
                        if fd == lock:
                            try:
                                fcntl.flock(fd, fcntl.LOCK_UN)
                            finally:
                                close_owned(fd)
                        else:
                            close_owned(fd)
                    except BaseException as error:
                        failed = True; self._row['write_failed'] = True
                        if not isinstance(error, Exception):
                            first_control = first_control or error
                            self._failure(self._row, 'UNKNOWN', error, None)
            failed |= self._ownership_refusal()
            if failed:
                try:
                    self._invalidate(published)
                except BaseException as error:
                    if not isinstance(error, Exception):
                        self._failure(self._row, 'UNKNOWN', error, None)
                        first_control = first_control or error
                    elif active is None and first_control is None:
                        raise RuntimeError('FDK observation finalization could not be revoked')
            if first_control is not None and (active is None or isinstance(active, Exception)):
                raise first_control

    def _change(self, action):
        with self._mutex:
            local = json.loads(json.dumps(self._row))
            action(local)
            self._row = local  # Issued facts precede all diagnostic filesystem I/O.
            self._publish()

    def _failure(self, row, predicate, error, cmd):
        kind = reason(error)
        row['cancelled'] |= kind == 'CANCELLED'
        if row['first_failure'] is None:
            row['first_failure'] = dict(phase=row['phase'], predicate=predicate, reason=kind, command=cmd)

    def phase(self, name):
        need(name in PHASES[1:])
        self._change(lambda row: row.update(phase=name))

    def fail(self, predicate, error, command=None):
        need(predicate in PREDICATES); event(command)
        self._change(lambda row: self._failure(row, predicate, error, command))

    def attempt(self, kind, index):
        item = command(kind, index); identity = (kind, index)
        with self._mutex:
            need(identity not in self._attempts)
            self._attempts.add(identity)
            def apply(row):
                row['compiler_attempted'] = True; row['compiler_attempt_count'] += 1
                if row['first_compiler_attempt'] is None:
                    row['first_compiler_attempt'] = item
            self._change(apply)

    def returned(self, kind, index, code):
        need(type(code) is int)
        item = command(kind, index, code); identity = (kind, index)
        with self._mutex:
            need(identity in self._attempts and identity not in self._returns)
            self._returns.add(identity)
            def apply(row):
                row['compiler_natural_count'] += 1
                if row['first_compiler_natural'] is None:
                    row['first_compiler_natural'] = item
                if code and row['first_failure'] is None:
                    row['first_failure'] = dict(phase=row['phase'], predicate='COMPILER_NONZERO', reason='NONZERO', command=item)
            self._change(apply)

    def snapshot(self):
        with self._mutex:
            return json.loads(json.dumps(self._row))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['phase'])
    parser.add_argument('phase', choices=PHASES[1:])
    args = parser.parse_args()
    try:
        Recorder().phase(args.phase)
    except Exception:
        # Ordinary observation failure is unavailable evidence, not a new
        # recipe command failure. Control exceptions retain their semantics.
        pass
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
