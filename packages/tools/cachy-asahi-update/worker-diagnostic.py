#!/usr/bin/env python3
"""Finite private worker diagnostics; never authorizes compilation or publication."""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

OPERATIONS = frozenset(('startup', 'entry-worker-import', 'entry-observe', 'entry-guard', 'entry-controller', 'entry-recipe-copy', 'entry-home', 'entry-builder-lock', 'entry-inventory', 'entry-config-copy', 'entry-srcinfo', 'entry-verifysource', 'entry-makepkg', 'entry-package', 'entry-log-copy', 'entry-receipt', 'metadata-observe', 'metadata-guard', 'metadata-paths', 'metadata-ambient', 'metadata-output', 'metadata-controller', 'metadata-builder', 'metadata-source', 'metadata-home', 'metadata-inventory', 'metadata-rust-version', 'metadata-target-cfg', 'metadata-cargo', 'metadata-recheck', 'metadata-receipt', 'compile-worker-import', 'compile-controller', 'compile-metadata', 'compile-gate', 'compile-target', 'compile-cargo', 'compile-elf', 'compile-units', 'compile-readelf', 'compile-copy', 'compile-receipt', 'complete'))
PREDICATES = frozenset(('UNKNOWN', 'worker-boundary', 'worker-identity', 'root-readonly', 'mount-contract', 'mount-nesting', 'private-tmpfs', 'unexpected-mount', 'mask-readonly', 'system-readonly', 'entry-readonly', 'runtime-filesystem', 'worker-limits', 'controller-hash-format', 'controller-input-paths', 'controller-digest', 'controller-binding', 'controller-hash-field', 'tool-ledger', 'builder-lock', 'tool-pin-path', 'tool-resolution', 'entry-digest', 'recipe-ledger', 'recipe-input', 'scratch-paths', 'ambient-cargo-config', 'metadata-output', 'builder-pin', 'source-pins', 'audit-lock', 'builder-inventory', 'forbidden-tool', 'rust-version', 'source-drift', 'vendor-ledger', 'vendor-directories', 'vendor-directory', 'vendor-registry', 'vendor-file-ledger', 'vendor-path', 'vendor-traversal', 'vendor-link', 'vendor-expanded', 'vendor-file', 'command-spawn', 'command-timeout', 'command-output-limit', 'command-nonzero', 'command-wait-timeout', 'command-cleanup', 'entry-inventory', 'entry-srcinfo', 'entry-package-count', 'fresh-target', 'unit-source', 'unit-build-script', 'unit-feature', 'unit-gettext', 'unit-system-deps', 'unit-complete', 'unit-build-script-record', 'compile-destination', 'compile-binary-drift'))
COMMANDS = frozenset(('inventory-entry', 'srcinfo', 'source-verification', 'makepkg', 'inventory', 'rustc-version', 'target-cfg', 'cargo-metadata', 'compile-gate', 'cargo-build', 'elf-inspection'))
ERROR_KINDS = frozenset(('ValueError', 'TypeError', 'KeyError', 'RuntimeError', 'OSError', 'TimeoutExpired', 'Cancelled', 'UNKNOWN'))
LIMIT = 4096
LOG_LIMIT = 16 * 1024**2
FIELDS = frozenset(('schema_version', 'controller_sha256', 'image_id', 'entry_script_sha256', 'controller_validated', 'status', 'operation', 'first_failure', 'command', 'compiler_launch_attempted', 'compiler_return_observed', 'compiler_returncode', 'compilation_accepted', 'cancelled', 'diagnostic_write_failed', 'publication', 'hardware'))


def need(value):
    if not value:
        raise ValueError('invalid finite worker diagnostic')


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'


def nullable_hash(value, image=False):
    need(value is None or type(value) is str and re.fullmatch(('sha256:' if image else '') + '[0-9a-f]{64}', value))


def command(value):
    if value is None:
        return
    need(type(value) is dict and set(value) == {'kind', 'launch_attempted', 'return_observed', 'returncode', 'stdout', 'stderr'})
    need(type(value['kind']) is str and value['kind'] in COMMANDS)
    need(type(value['launch_attempted']) is type(value['return_observed']) is bool)
    code = value['returncode']
    need(code is None or type(code) is int and -64 <= code <= 255)
    need(value['return_observed'] == (code is not None) and (not value['return_observed'] or value['launch_attempted']))
    total = 0
    for key in ('stdout', 'stderr'):
        row = value[key]
        if row is not None:
            need(type(row) is dict and set(row) == {'bytes', 'sha256'})
            need(type(row['bytes']) is int and 0 <= row['bytes'] <= LOG_LIMIT)
            nullable_hash(row['sha256']); need(row['sha256'] is not None)
            total += row['bytes']
    need(total <= LOG_LIMIT)


def validate(value):
    need(type(value) is dict and set(value) == FIELDS and type(value['schema_version']) is int and value['schema_version'] == 1)
    for key in ('controller_sha256', 'entry_script_sha256'):
        nullable_hash(value[key])
    nullable_hash(value['image_id'], True)
    for key in ('controller_validated', 'compiler_launch_attempted', 'compiler_return_observed',
                'compilation_accepted', 'cancelled', 'diagnostic_write_failed'):
        need(type(value[key]) is bool)
    need(type(value['operation']) is str and value['operation'] in OPERATIONS)
    need(type(value['status']) is str and value['status'] in {'RUNNING', 'PASS', 'FAIL', 'CANCELLED'})
    need(value['publication'] == 'NOT ACCEPTED' and value['hardware'] == 'NOT RUN')
    need(value['status'] != 'CANCELLED' or value['cancelled'])
    command(value['command'])
    first = value['first_failure']
    if first is not None:
        need(type(first) is dict and set(first) == {'operation', 'predicate', 'error_kind', 'command'})
        need(type(first['operation']) is str and first['operation'] in OPERATIONS)
        need(type(first['predicate']) is str and first['predicate'] in PREDICATES)
        need(type(first['error_kind']) is str and first['error_kind'] in ERROR_KINDS)
        command(first['command'])
        need(value['status'] in {'FAIL', 'CANCELLED'})
        if first['error_kind'] == 'Cancelled':
            need(value['cancelled'] and value['status'] == 'CANCELLED')
    elif value['status'] == 'FAIL':
        need(value['diagnostic_write_failed'])
    elif value['status'] == 'CANCELLED':
        need(value['cancelled'])
    if value['controller_validated']:
        need(all(value[key] is not None for key in ('controller_sha256', 'image_id', 'entry_script_sha256')))
    if value['status'] == 'PASS':
        need(first is None and value['controller_validated'] and not value['cancelled'] and not value['diagnostic_write_failed'])
    code = value['compiler_returncode']
    need(code is None or type(code) is int and -64 <= code <= 255)
    need(value['compiler_return_observed'] == (code is not None))
    need(not value['compiler_return_observed'] or value['compiler_launch_attempted'])
    if value['compilation_accepted']:
        need(value['compiler_launch_attempted'] and value['compiler_return_observed'] and code == 0)
    need(len(encoded(value)) <= LIMIT)
    return value


def loads(data):
    need(type(data) is bytes and len(data) <= LIMIT)
    def unique(items):
        result = {}
        for key, value in items:
            need(key not in result); result[key] = value
        return result
    def invalid(_):
        raise ValueError('nonfinite worker diagnostic')
    return validate(json.loads(data, object_pairs_hook=unique, parse_constant=invalid))


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def close_owned(fd):
    original = sys.exc_info()[1]
    try:
        os.close(fd)
    except Exception:
        if original is None:
            raise


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


def binding_values(entry_path=Path('/builder-entry.sh')):
    def finite(value, image=False):
        return value if type(value) is str and re.fullmatch(('sha256:' if image else '') + '[0-9a-f]{64}', value) else None
    result = {'controller_sha256': finite(os.environ.get('CACHY_ASAHI_CONTROLLER_SHA256')),
              'image_id': finite(os.environ.get('CACHY_ASAHI_IMAGE_ID'), True), 'entry_script_sha256': None}
    try:
        result['entry_script_sha256'] = hashlib.sha256(regular(entry_path, 4 * 1024**2)).hexdigest()
    except Exception:
        pass
    return result


def error_kind(error):
    if isinstance(error, (KeyboardInterrupt, SystemExit)):
        return 'Cancelled'
    if isinstance(error, OSError):
        return 'OSError'
    name = type(error).__name__
    return name if name in ERROR_KINDS else 'UNKNOWN'


class Recorder:
    def __init__(self, output=Path('/out'), bindings=None):
        self.output = Path(output)
        self.bindings = dict(binding_values() if bindings is None else bindings)
        self.operation = 'startup'
        self._published, self._durable_first, self._published_identity = False, None, None
        self._row = dict(schema_version=1, **self.bindings, controller_validated=False, status='RUNNING',
            operation='startup', first_failure=None, command=None, compiler_launch_attempted=False,
            compiler_return_observed=False, compiler_returncode=None, compilation_accepted=False,
            cancelled=False, diagnostic_write_failed=False, publication='NOT ACCEPTED', hardware='NOT RUN')
        self._update(lambda row: None)

    def _root(self):
        fd, info = directory(self.output)
        try:
            need(info.st_uid == os.getuid() and info.st_gid == os.getgid() and stat.S_IMODE(info.st_mode) == 0o700)
            named_directory(self.output, info)
        except BaseException:
            close_owned(fd)
            raise
        return fd, info

    def _invalidate(self, published_identity):
        """Remove only our exact published inode if completion failed; no PASS remains."""
        if published_identity is None:
            return
        root, before = self._root()
        try:
            info = os.stat('worker-diagnostic.json', dir_fd=root, follow_symlinks=False)
            need((info.st_dev, info.st_ino) == published_identity and stat.S_ISREG(info.st_mode)
                 and info.st_nlink == 1 and info.st_uid == os.getuid() and info.st_gid == os.getgid()
                 and stat.S_IMODE(info.st_mode) == 0o600)
            named_directory(self.output, before)
            os.unlink('worker-diagnostic.json', dir_fd=root)
            self._published, self._published_identity = False, None
            os.fsync(root)
        finally:
            close_owned(root)

    def _logs(self, stem):
        need(stem in COMMANDS)
        folder = self.output if stem in {'inventory-entry', 'srcinfo', 'source-verification', 'makepkg'} else self.output / 'target-metadata'
        result = {}
        for stream in ('stdout', 'stderr'):
            try:
                data = regular(folder / (stem + '.' + stream), LOG_LIMIT)
                result[stream] = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
            except FileNotFoundError:
                result[stream] = None
        return result

    def _status(self, row):
        if row['cancelled']:
            row['status'] = 'CANCELLED'
        elif row['first_failure'] is not None:
            row['status'] = 'FAIL'
        elif row['diagnostic_write_failed']:
            row['status'] = 'FAIL'

    def _update(self, action):
        root, lock, temporary, temporary_identity, published_identity = None, None, None, None, None
        original, update_failed = sys.exc_info()[1], False
        published_identity = self._published_identity
        try:
            # Keep the issued cause in memory even if the very first write fails.
            local = json.loads(json.dumps(self._row))
            local['operation'] = self.operation
            action(local)
            self._status(local)
            self._row = local
            validate(local)
            root, before = self._root()
            lock = os.open('.worker-diagnostic.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=root)
            info = os.fstat(lock)
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                 and info.st_gid == os.getgid() and stat.S_IMODE(info.st_mode) == 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            need(identity(info) == identity(os.stat('.worker-diagnostic.lock', dir_fd=root, follow_symlinks=False)))
            try:
                row = loads(regular_at(root, 'worker-diagnostic.json', LIMIT, 0o600))
                existing = os.stat('worker-diagnostic.json', dir_fd=root, follow_symlinks=False)
                published_identity = (existing.st_dev, existing.st_ino)
                need({key: row[key] for key in self.bindings} == self.bindings)
            except FileNotFoundError:
                need(not self._published)
                row = json.loads(json.dumps(local))
            if self._durable_first is not None:
                need(row['first_failure'] == self._durable_first)
            # A child has completed before its parent observes its enclosing error.
            # Its already-recorded failure takes precedence over that new outer one.
            first = row['first_failure'] if row['first_failure'] is not None else local['first_failure']
            for key in ('controller_validated', 'compiler_launch_attempted', 'compiler_return_observed',
                        'compilation_accepted', 'cancelled', 'diagnostic_write_failed'):
                local[key] |= row[key]
            if row['compiler_return_observed']:
                need(local['compiler_returncode'] in (None, row['compiler_returncode']))
                local['compiler_returncode'] = row['compiler_returncode']
            local['first_failure'] = first
            self._status(local)
            self._row = local
            data = encoded(validate(local))
            temporary = '.worker-diagnostic-' + os.urandom(8).hex()
            fd = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=root)
            try:
                created = os.fstat(fd)
                temporary_identity = (created.st_dev, created.st_ino)
                remaining = memoryview(data)
                while remaining:
                    count = os.write(fd, remaining); need(count > 0); remaining = remaining[count:]
                os.fsync(fd)
                need(identity(os.fstat(fd)) == identity(os.stat(temporary, dir_fd=root, follow_symlinks=False)))
                need(regular_at(root, temporary, LIMIT, 0o600) == data)
                need(identity(info) == identity(os.fstat(lock)) == identity(os.stat('.worker-diagnostic.lock', dir_fd=root, follow_symlinks=False)))
                named_directory(self.output, before)
                os.replace(temporary, 'worker-diagnostic.json', src_dir_fd=root, dst_dir_fd=root)
                temporary = None
                published = os.stat('worker-diagnostic.json', dir_fd=root, follow_symlinks=False)
                published_identity = (published.st_dev, published.st_ino)
                need(published_identity == temporary_identity and identity(os.fstat(fd)) == identity(published))
                need(regular_at(root, 'worker-diagnostic.json', LIMIT, 0o600) == data)
                os.fsync(root)
                need(identity(info) == identity(os.stat('.worker-diagnostic.lock', dir_fd=root, follow_symlinks=False)))
                named_directory(self.output, before)
            finally:
                close_owned(fd)

            self._published, self._published_identity = True, published_identity
            self._durable_first = json.loads(json.dumps(local['first_failure']))
        except Exception:
            update_failed = True
            self._row['diagnostic_write_failed'] = True
            self._status(self._row)
        except BaseException as control:
            update_failed = True
            self._row['diagnostic_write_failed'] = True
            if error_kind(control) == 'Cancelled':
                self._row['cancelled'] = True
            if self._row['first_failure'] is None:
                self._row['first_failure'] = {'operation': self.operation, 'predicate': 'UNKNOWN',
                    'error_kind': error_kind(control), 'command': self._row['command']}
            self._status(self._row)
            raise
        finally:
            active, close_error, close_control = sys.exc_info()[1] or original, None, None
            if temporary is not None and root is not None:
                try:
                    named = os.stat(temporary, dir_fd=root, follow_symlinks=False)
                    need(temporary_identity == (named.st_dev, named.st_ino))
                    os.unlink(temporary, dir_fd=root)
                except Exception:
                    update_failed = True
                    self._row['diagnostic_write_failed'] = True
            for fd in (lock, root):
                if fd is not None:
                    try:
                        os.close(fd)
                    except BaseException as error:
                        update_failed = True
                        self._row['diagnostic_write_failed'] = True
                        if isinstance(error, Exception):
                            close_error = close_error or error
                        else:
                            close_control = close_control or error
                            if error_kind(error) == 'Cancelled':
                                self._row['cancelled'] = True
                            if self._row['first_failure'] is None:
                                self._row['first_failure'] = {'operation': self.operation, 'predicate': 'UNKNOWN',
                                    'error_kind': error_kind(error), 'command': self._row['command']}
            self._status(self._row)
            if published_identity is not None and update_failed:
                try:
                    self._invalidate(published_identity)
                except Exception:
                    # A record whose finalization cannot be revoked is never silent success.
                    if active is None and close_control is None:
                        raise close_error or RuntimeError('diagnostic finalization could not be revoked')
            if close_control is not None and (active is None or isinstance(active, Exception)):
                raise close_control

    @contextlib.contextmanager
    def step(self, operation):
        need(operation in OPERATIONS)
        self.operation = operation
        self._update(lambda row: row.update(command=None))
        try:
            yield
        except BaseException as error:
            self.fail('UNKNOWN', error)
            raise

    def fail(self, predicate, error):
        def apply(row):
            need(predicate in PREDICATES)
            kind = error_kind(error)
            if kind == 'Cancelled':
                row['cancelled'] = True
            if row['first_failure'] is None:
                row['first_failure'] = {'operation': self.operation, 'predicate': predicate,
                    'error_kind': kind, 'command': row['command']}
        self._update(apply)

    def controller_validated(self):
        self._update(lambda row: row.update(controller_validated=True))

    def command_start(self, stem):
        def apply(row):
            need(stem in COMMANDS)
            row['command'] = {'kind': stem, 'launch_attempted': True, 'return_observed': False,
                              'returncode': None, 'stdout': None, 'stderr': None}
            if stem == 'cargo-build':
                row['compiler_launch_attempted'] = True
        self._update(apply)

    def command_result(self, stem, launch_attempted, return_observed, returncode, failure_code=None, error=None):
        def apply(row):
            row['command'] = {'kind': stem, 'launch_attempted': launch_attempted, 'return_observed': return_observed,
                              'returncode': returncode, 'stdout': None, 'stderr': None}
            if stem == 'cargo-build':
                row['compiler_launch_attempted'] |= launch_attempted
                if return_observed:
                    row['compiler_return_observed'] = True; row['compiler_returncode'] = returncode
            if error is not None:
                kind = error_kind(error)
                if kind == 'Cancelled':
                    row['cancelled'] = True
                if row['first_failure'] is None:
                    need(failure_code in PREDICATES)
                    row['first_failure'] = {'operation': self.operation, 'predicate': failure_code,
                                           'error_kind': kind, 'command': row['command']}
        # Cache and persist the issued facts before any diagnostic log access.
        self._update(apply)
        issued = self.snapshot()['command']
        try:
            logs = self._logs(stem)
        except Exception:
            self._update(lambda row: row.update(diagnostic_write_failed=True))
            return
        except BaseException as control:
            self.fail('UNKNOWN', control)
            raise
        def attach(row):
            row['command'].update(logs)
            first = row['first_failure']
            if first is not None and first['operation'] == self.operation and first['command'] == issued:
                first['command'].update(logs)
        self._update(attach)

    def compiler_accepted(self):
        self._update(lambda row: row.update(compilation_accepted=True))

    def finish(self, success):
        self.operation = 'complete' if success else self.operation
        def apply(row):
            if success and row['first_failure'] is None and not row['cancelled'] and not row['diagnostic_write_failed']:
                row['status'] = 'PASS'
        self._update(apply)

    def snapshot(self):
        return json.loads(json.dumps(self._row))
