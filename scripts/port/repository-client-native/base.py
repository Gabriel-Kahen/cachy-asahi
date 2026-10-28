#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded generic immutable-base observation; no target hardware acceptance.

Local parser fixtures do not establish native execution. The production worker
only queries a read-only aarch64 root, and never installs or changes trust.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
import types

COUNT = 341
RECORD_LIMIT = 4 * 1024**2
TOTAL_LIMIT = 64 * 1024**2
COMMAND_LIMIT = 16 * 1024**2
NAME = r'[a-z0-9][a-z0-9@._+-]{0,127}'
VERSION = r'[A-Za-z0-9][A-Za-z0-9._+:~-]{0,255}'
DESC_FIELDS = {'NAME', 'VERSION', 'BASE', 'DESC', 'URL', 'ARCH', 'BUILDDATE', 'INSTALLDATE', 'PACKAGER',
               'SIZE', 'ISIZE', 'REASON', 'VALIDATION', 'LICENSE', 'GROUPS', 'DEPENDS', 'OPTDEPENDS',
               'PROVIDES', 'CONFLICTS', 'REPLACES', 'XDATA'}


class Refused(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise Refused(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def text(raw, limit=RECORD_LIMIT):
    need(type(raw) is bytes and len(raw) <= limit, 'unbounded metadata bytes')
    try:
        result = raw.decode('utf-8')
    except UnicodeError:
        raise Refused('invalid metadata UTF-8') from None
    need(not any(ord(c) < 32 and c not in '\n\t' or ord(c) == 127 for c in result), 'metadata control character')
    need(not result or result.endswith('\n'), 'metadata missing terminal LF')
    return result


def sections(raw, allowed):
    """ALPM records: unique known sections, blank separators, no stray values."""
    result, current = {}, None
    for line in text(raw).splitlines():
        if not line:
            current = None
        elif re.fullmatch(r'%[A-Z][A-Z0-9]*%', line):
            need(current is None, 'missing ALPM section separator')
            key = line[1:-1]
            need(key in allowed and key not in result, 'unknown or duplicate ALPM section')
            result[key] = []
            current = key
        else:
            need(current is not None and not line.startswith('%'), 'ALPM value outside section')
            need(line not in result[current], 'duplicate ALPM value')
            result[current].append(line)
    return result


def inventory(raw):
    rows = text(raw, 256 * 1024).splitlines(keepends=True)
    need(len(rows) == COUNT and rows == sorted(rows), 'exact sorted 341-package lock required')
    result = {}
    for row in rows:
        need(re.fullmatch(NAME + ' ' + VERSION + r'\n', row), 'invalid package lock row')
        name, version = row[:-1].split(' ')
        need(name not in result, 'duplicate package lock name')
        result[name] = version
    return result


def canonical_file(value):
    need(isinstance(value, str) and value and len(value.encode()) <= 4096 and '\\' not in value
         and not any(ord(c) < 32 or ord(c) == 127 for c in value), 'unsafe file ownership path')
    directory = value.endswith('/')
    item = value[:-1] if directory else value
    path = PurePosixPath(item)
    need(item and not path.is_absolute() and str(path) == item and '..' not in path.parts
         and item != '.', 'noncanonical file ownership path')
    return item, directory


def parse_local(records, lock):
    """Consume exact desc/files bytes. Absent optional ALPM relations mean []."""
    wanted = inventory(lock)
    need(isinstance(records, dict) and len(records) == COUNT, 'exact local package set required')
    packages, raw_map, owners, names, total = [], {}, {}, set(), 0
    for dirname, record in sorted(records.items()):
        need(isinstance(dirname, str) and re.fullmatch(NAME + '-' + VERSION, dirname), 'unsafe local package directory')
        need(isinstance(record, dict) and set(record) == {'desc', 'files'}, 'exact desc/files record required')
        for key, value in record.items():
            need(type(value) is bytes and len(value) <= RECORD_LIMIT, 'unbounded local record')
            total += len(value)
            need(total <= TOTAL_LIMIT, 'local metadata total exceeded')
            raw_map[dirname + '/' + key] = {'sha256': digest(value), 'bytes': len(value)}
        desc = sections(record['desc'], DESC_FIELDS)
        for field in ('NAME', 'VERSION', 'ARCH'):
            need(len(desc.get(field, [])) == 1, 'missing or repeated scalar ' + field)
        name, version, arch = (desc[field][0] for field in ('NAME', 'VERSION', 'ARCH'))
        need(re.fullmatch(NAME, name) and re.fullmatch(VERSION, version), 'invalid package identity')
        need(dirname == name + '-' + version and name in wanted and wanted[name] == version
             and name not in names, 'local package/lock mismatch')
        need(arch in {'aarch64', 'any'}, 'non-ARM base architecture')
        names.add(name)
        files = sections(record['files'], {'FILES', 'BACKUP'})
        need('FILES' in files, 'missing FILES section')
        paths = []
        for value in files['FILES']:
            item, directory = canonical_file(value)
            if not directory:
                need(item not in owners, 'duplicate base file ownership')
                owners[item] = name
                paths.append(item)
        for value in files.get('BACKUP', []):
            parts = value.split('\t')
            need(len(parts) == 2 and re.fullmatch('[0-9a-f]{32}', parts[1]), 'invalid backup ownership record')
            item, directory = canonical_file(parts[0])
            need(not directory and item in paths, 'backup missing from FILES')
        row = {'name': name, 'version': version, 'arch': arch, 'files': sorted(paths)}
        for section, field in (('DEPENDS', 'depend'), ('PROVIDES', 'provides'), ('CONFLICTS', 'conflict')):
            values = desc.get(section, [])
            need(all(re.fullmatch(NAME + r'(?:(?:<=|>=|=|<|>)' + VERSION + ')?', value) for value in values),
                 'invalid package relation')
            row[field] = sorted(values)
        packages.append(row)
    need(names == set(wanted), 'missing local package')
    return {'schema_version': 1, 'kind': 'complete-target-transaction', 'target_arch': 'aarch64',
            'snapshot_id': 'packages-lock-' + digest(lock), 'platform_scope': 'generic-builder-only',
            'supported_models': [], 'packages_lock_sha256': digest(lock), 'package_count': COUNT,
            'packages': sorted(packages, key=lambda row: row['name']), 'local_records': raw_map}


def nofollow_read(path, limit=RECORD_LIMIT):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'absolute safe path required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            new = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new
        filefd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            before = os.fstat(filefd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit, 'nonregular bounded input required')
            chunks, size = [], 0
            while True:
                chunk = os.read(filefd, min(65536, limit + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                need(size <= limit, 'input grew beyond bound')
            after = os.fstat(filefd)
            need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                 (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'input changed while read')
            return b''.join(chunks)
        finally:
            os.close(filefd)
    finally:
        os.close(fd)


@contextmanager
def cancellation():
    old = {}
    def stop(signum, frame):
        raise KeyboardInterrupt('cancelled signal ' + str(signum))
    for signum in (signal.SIGTERM, signal.SIGINT):
        old[signum] = signal.signal(signum, stop)
    try:
        yield
    finally:
        for signum, handler in old.items():
            signal.signal(signum, handler)


def run_command(argv, timeout=30, limit=COMMAND_LIMIT):
    """Real CLI, bounded dual streams, spawn assignment and whole-group reap."""
    process, streams, started = None, [bytearray(), bytearray()], time.monotonic()
    blocked = {signal.SIGINT, signal.SIGTERM}
    with cancellation():
        try:
            previous = signal.pthread_sigmask(signal.SIG_BLOCK, blocked)
            try:
                process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           start_new_session=True, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': '/tmp'})
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous)
            with selectors.DefaultSelector() as selector:
                for index, pipe in enumerate((process.stdout, process.stderr)):
                    os.set_blocking(pipe.fileno(), False)
                    selector.register(pipe, selectors.EVENT_READ, index)
                while selector.get_map():
                    need(time.monotonic() - started < timeout, 'metadata command timeout')
                    for key, events in selector.select(min(0.1, timeout)):
                        data = os.read(key.fd, 65536)
                        if data:
                            streams[key.data].extend(data)
                            need(sum(map(len, streams)) <= limit, 'metadata command output exceeded')
                        else:
                            selector.unregister(key.fileobj)
                process.wait(timeout=max(0.001, timeout - (time.monotonic() - started)))
            need(process.returncode == 0 and not streams[1], 'metadata command failed or diagnosed on stderr')
            return bytes(streams[0]), bytes(streams[1])
        finally:
            if process is not None:
                previous = signal.pthread_sigmask(signal.SIG_BLOCK, blocked)
                try:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
                    for pipe in (process.stdout, process.stderr):
                        if pipe:
                            pipe.close()
                finally:
                    signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def validate_queries(base, records, query, listing):
    rows = text(query, COMMAND_LIMIT).splitlines()
    expected = [row['name'] + ' ' + row['version'] for row in base['packages']]
    need(len(rows) == COUNT and sorted(rows) == expected, 'pacman -Q differs from exact local lock')
    expected_paths = set()
    for dirname, record in records.items():
        name = sections(record['desc'], DESC_FIELDS)['NAME'][0]
        for path in sections(record['files'], {'FILES', 'BACKUP'})['FILES']:
            canonical_file(path)
            expected_paths.add(name + ' /' + path)
    actual = text(listing, COMMAND_LIMIT).splitlines()
    need(len(actual) == len(set(actual)) and set(actual) == expected_paths, 'pacman -Ql differs from exact local FILES')


def bind_inputs(base, raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate inputs field")
            result[key] = value
        return result
    try:
        inputs = json.loads(text(raw), object_pairs_hook=pairs)
    except (ValueError, UnicodeError, RecursionError):
        raise Refused("invalid inputs JSON") from None
    snapshot_id = inputs.get("snapshot_id") if isinstance(inputs, dict) else None
    need(isinstance(snapshot_id, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:+-]{0,255}", snapshot_id),
         "actual pinned input snapshot_id required")
    base["snapshot_id"] = snapshot_id
    base["inputs_sha256"] = digest(raw)
    return base


def worker(lock_path, inputs_path, output):
    need(os.uname().machine == 'aarch64', 'actual native aarch64 worker required')
    mount = nofollow_read(Path('/proc') / str(os.getpid()) / 'mountinfo')
    root_mounts = [line.split() for line in text(mount).splitlines() if len(line.split()) > 6 and line.split()[4] == '/']
    need(len(root_mounts) == 1 and 'ro' in root_mounts[0][5].split(','), 'read-only root required')
    lock = nofollow_read(Path(lock_path), 256 * 1024)
    inventory(lock)
    local = Path('/var/lib/pacman/local')
    fd = os.open(local, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        entries = sorted(os.listdir(fd))
        need(len(entries) == COUNT + 1 and 'ALPM_DB_VERSION' in entries, 'exact local database inventory required')
        records = {}
        for dirname in entries:
            if dirname == 'ALPM_DB_VERSION':
                need(nofollow_read(local / dirname, 32) == b'9\n', 'unsupported local database version')
                continue
            need(re.fullmatch(NAME + '-' + VERSION, dirname), 'unsafe local database entry')
            records[dirname] = {kind: nofollow_read(local / dirname / kind) for kind in ('desc', 'files')}
        base = bind_inputs(parse_local(records, lock), nofollow_read(Path(inputs_path)))
        query, stderr_q = run_command(['/usr/bin/pacman', '-Q'])
        listing, stderr_ql = run_command(['/usr/bin/pacman', '-Ql'])
        validate_queries(base, records, query, listing)
        after = {dirname: {kind: nofollow_read(local / dirname / kind) for kind in ('desc', 'files')} for dirname in records}
        need(records == after and entries == sorted(os.listdir(fd)), 'local metadata drift during queries')
    finally:
        os.close(fd)
    observations = {'schema_version': 1, 'purpose': 'actual-immutable-generic-base-metadata', 'status': 'PASS',
                    'architecture': os.uname().machine, 'root_readonly': True, 'packages_lock_sha256': digest(lock),
                    'package_count': COUNT, 'inputs_sha256': base['inputs_sha256'], 'snapshot_id': base['snapshot_id'],
                    'commands': [{'argv': ['/usr/bin/pacman', '-Q'], 'exit_code': 0,
                        'stdout_sha256': digest(query), 'stderr_sha256': digest(stderr_q)},
                        {'argv': ['/usr/bin/pacman', '-Ql'], 'exit_code': 0, 'stdout_sha256': digest(listing),
                         'stderr_sha256': digest(stderr_ql)}], 'hardware_validation': 'NOT RUN'}
    exports = {'pacman-Q.stdout': query, 'pacman-Q.stderr': stderr_q, 'pacman-Ql.stdout': listing,
               'pacman-Ql.stderr': stderr_ql, 'base.json': encoded(base), 'observations.json': encoded(observations)}
    exports.update({'local/' + dirname + '/' + kind: raw for dirname, row in records.items() for kind, raw in row.items()})
    need(len(exports) == 688 and all(len(raw) <= COMMAND_LIMIT for raw in exports.values())
         and sum(map(len, exports.values())) <= TOTAL_LIMIT, 'complete observation output bound exceeded')
    output = Path(output)
    need(output.is_absolute() and output.is_dir() and not output.is_symlink() and not list(output.iterdir()),
         'empty output directory required')
    for name, raw in exports.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    return observations


def authenticated_common(source_map):
    """Authenticate exact source closure before compiling common; never import PYC."""
    root = Path(__file__).absolute().parent
    need(isinstance(source_map, dict) and set(source_map) == {'base.py', 'common.py', 'worker.py'},
         'exact collector source closure required')
    captures = {}
    for name, row in source_map.items():
        need(isinstance(row, dict) and set(row) == {'sha256', 'mode'} and type(row['mode']) is int
             and row['mode'] in {0o644, 0o755} and isinstance(row['sha256'], str)
             and re.fullmatch('[0-9a-f]{64}', row['sha256']), 'typed source pin required')
        raw = nofollow_read(root / name, 1024**2)
        need(digest(raw) == row['sha256'] and stat.S_IMODE((root / name).lstat().st_mode) == row['mode'],
             'collector source bytes/mode differ')
        captures[name] = raw
    common = types.ModuleType('native_base_authenticated_common')
    common.__file__ = str(root / 'common.py')
    exec(compile(captures['common.py'], common.__file__, 'exec'), common.__dict__)
    return common


@contextmanager
def private_temporary(common):
    temporary = tempfile.TemporaryDirectory(prefix='repository-client-native-base-')
    try:
        yield Path(temporary.name)
    finally:
        # Complete all private removal before delivering a pending signal.
        with common.defer_cancellation():
            temporary.cleanup()


class Publication:
    """Keep the original inode available through writes and terminal closure."""
    def __init__(self, common, output):
        self.common, self.output, self.fd, self.root_identity = common, output, None, None
        self.ancestors = [(path, self.identity(path.lstat())) for path in reversed(output.parents)]
        self.proof = {'status': 'NOT RUN', 'receipt_absence_verified': False}

    @staticmethod
    def identity(info):
        return info.st_dev, info.st_ino, info.st_mode

    def current(self):
        for path, before in self.ancestors:
            need(self.identity(path.lstat()) == before, 'publication ancestor replaced')
        need(self.identity(self.output.lstat()) == self.root_identity, 'publication output replaced')

    def create(self):
        with self.common.defer_cancellation():
            with self.common.directory(self.output.parent) as parent:
                os.mkdir(self.output.name, 0o700, dir_fd=parent)
                self.fd = os.open(self.output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                self.root_identity = self.identity(os.fstat(self.fd))
            self.current()

    def close(self):
        if self.fd is not None:
            descriptor, self.fd = self.fd, None
            os.close(descriptor)

    def invalidate(self):
        """Use held inode, or recover only that inode beneath proven ancestors."""
        temporary = None
        if self.root_identity is None:
            self.proof = {'status': 'PASS', 'receipt_absence_verified': True, 'output_created': False}
            return
        try:
            if self.fd is not None:
                descriptor = self.fd
                need(self.identity(os.fstat(descriptor)) == self.root_identity, 'held publication inode changed')
            else:
                # Cancellation after close needs exact inode recovery. A replacement
                # output is never a deletion target; a renamed original may be found
                # only beneath this unchanged recorded parent.
                for path, before in self.ancestors:
                    need(self.identity(path.lstat()) == before, 'publication ancestor replaced before recovery')
                with self.common.directory(self.output.parent) as parent:
                    entries = os.listdir(parent)
                    need(len(entries) <= 1024, 'publication recovery directory bound')
                    matches = []
                    for name in entries:
                        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                        if self.identity(info) == self.root_identity:
                            matches.append(name)
                    need(len(matches) == 1, 'original publication inode unavailable')
                    temporary = os.open(matches[0], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                    need(self.identity(os.fstat(temporary)) == self.root_identity, 'publication recovery inode changed')
                descriptor = temporary
            try:
                os.unlink('result.json', dir_fd=descriptor)
                os.fsync(descriptor)
            except FileNotFoundError:
                pass
            try:
                os.stat('result.json', dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                self.proof = {'status': 'PASS', 'receipt_absence_verified': True, 'output_created': True}
            else:
                raise Refused('authoritative collector receipt remains')
        except BaseException as error:
            self.proof = {'status': 'FAIL', 'receipt_absence_verified': False, 'error_type': type(error).__name__}
            raise
        finally:
            if temporary is not None:
                os.close(temporary)

    def publish(self, captured, result):
        try:
            self.create()
            for name, raw in captured.items():
                self.current()
                path = self.output / 'observed' / name
                with self.common.defer_cancellation():
                    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    self.common.write_new(path, raw)
                self.current()
            with self.common.defer_cancellation():
                self.current()
                self.common.write_new(self.output / 'result.json', encoded(result))
                self.current()
                self.close()
            self.proof = {'status': 'PASS', 'receipt_published': True}
            return result
        except BaseException:
            with self.common.defer_cancellation():
                try:
                    self.invalidate()
                finally:
                    self.close()
            raise


def collect_base(image_id, bootstrap_raw, bootstrap_pin, packages_raw, packages_pin, source_map, output,
                 *, inputs_raw, inputs_pin):
    """Pinned same-job inputs and real cleanup required; no native fixture promotion."""
    common = authenticated_common(source_map)
    state = {}
    try:
        with common.cancellation_handlers():
            result = _collect_base(common, image_id, bootstrap_raw, bootstrap_pin, packages_raw, packages_pin,
                                   source_map, output, inputs_raw, inputs_pin, state)
        return result
    except BaseException as error:
        worker_receipt = state.get('worker', getattr(error, 'receipt', {}))
        error.receipt = {'schema_version': 1, 'purpose': 'collected-immutable-generic-base', 'status': 'FAIL',
                         'cleanup': worker_receipt.get('cleanup', 'NOT RUN'), 'worker': worker_receipt,
                         'publication': state['publication'].proof if 'publication' in state else {'status': 'NOT RUN'},
                         'error_type': type(error).__name__}
        raise


def _collect_base(common, image_id, bootstrap_raw, bootstrap_pin, packages_raw, packages_pin,
                  source_map, output, inputs_raw, inputs_pin, state):
    need(re.fullmatch(r'sha256:[0-9a-f]{64}', image_id or ''), 'immutable image ID required')
    for raw, pin in ((bootstrap_raw, bootstrap_pin), (packages_raw, packages_pin), (inputs_raw, inputs_pin)):
        need(type(raw) is bytes and isinstance(pin, str) and re.fullmatch('[0-9a-f]{64}', pin)
             and digest(raw) == pin, 'external prerequisite pin mismatch')
    boot = common.decode(bootstrap_raw)
    need(boot.get('status') == 'image-provisioned' and boot.get('image_id') == image_id
         and boot.get('packages_lock_sha256') == packages_pin and boot.get('inputs_sha256') == inputs_pin,
         'bootstrap/image/lock/inputs binding differs')
    parse_bound = bind_inputs({'packages_lock_sha256': packages_pin}, inputs_raw)
    inventory(packages_raw)
    output = Path(output)
    need(output.is_absolute() and not output.exists() and not output.is_symlink()
         and all(not parent.is_symlink() for parent in output.parents), 'fresh absolute output required')
    with private_temporary(common) as work:
        source = common.snapshot(Path(__file__).absolute().parent, source_map, work / 'source')
        inputs, observed = work / 'inputs', work / 'observed'
        inputs.mkdir(mode=0o700)
        observed.mkdir(mode=0o700)
        common.write_new(inputs / 'packages.lock', packages_raw)
        common.write_new(inputs / 'inputs.lock.json', inputs_raw)
        receipt = common.run_owned(image_id, source, inputs, observed,
            ['/source/base.py', '--worker', '--lock', '/inputs/packages.lock', '--inputs', '/inputs/inputs.lock.json', '--output', '/out'],
            expected_arch='aarch64')
        state['worker'] = receipt
        need(receipt.get('status') == 'PASS' and receipt.get('cleanup') == 'PASS'
             and receipt.get('image_id') == image_id and receipt.get('ownership_verified') is True
             and re.fullmatch('[0-9a-f]{64}', receipt.get('container_id', '') or '')
             and all(receipt.get(key) is True for key in ('id_absence_verified', 'name_absence_verified', 'absence_verified')),
             'owned worker/name/CID cleanup did not pass')
        records = {}
        with common.directory(observed / 'local') as parent:
            entries = sorted(os.listdir(parent))
            need(len(entries) == COUNT, 'collected package directory count differs')
            for dirname in entries:
                need(re.fullmatch(NAME + '-' + VERSION, dirname), 'unsafe collected package directory')
                package = observed / 'local' / dirname
                with common.directory(package) as directory:
                    need(set(os.listdir(directory)) == {'desc', 'files'}, 'extra collected local record')
                    records[dirname] = {kind: common.read(package / kind, RECORD_LIMIT) for kind in ('desc', 'files')}
        base = bind_inputs(parse_local(records, packages_raw), inputs_raw)
        need(common.read(observed / 'base.json') == encoded(base), 'worker base differs from independent parsing')
        query = common.read(observed / 'pacman-Q.stdout', COMMAND_LIMIT)
        listing = common.read(observed / 'pacman-Ql.stdout', COMMAND_LIMIT)
        validate_queries(base, records, query, listing)
        need(not common.read(observed / 'pacman-Q.stderr') and not common.read(observed / 'pacman-Ql.stderr'),
             'worker pacman stderr differs')
        observation_raw = common.read(observed / 'observations.json')
        observations = common.decode(observation_raw)
        expected_commands = [{'argv': ['/usr/bin/pacman', '-Q'], 'exit_code': 0, 'stdout_sha256': digest(query),
                              'stderr_sha256': digest(b'')}, {'argv': ['/usr/bin/pacman', '-Ql'], 'exit_code': 0,
                              'stdout_sha256': digest(listing), 'stderr_sha256': digest(b'')}]
        need(observations == {'schema_version': 1, 'purpose': 'actual-immutable-generic-base-metadata', 'status': 'PASS',
             'architecture': 'aarch64', 'root_readonly': True, 'packages_lock_sha256': packages_pin, 'package_count': COUNT,
             'inputs_sha256': inputs_pin, 'snapshot_id': parse_bound['snapshot_id'], 'commands': expected_commands,
             'hardware_validation': 'NOT RUN'}, 'actual worker observation differs')
        files = {'local/' + path: row for path, row in base['local_records'].items()}
        for filename in ('base.json', 'observations.json', 'pacman-Q.stdout', 'pacman-Q.stderr', 'pacman-Ql.stdout', 'pacman-Ql.stderr'):
            raw = common.read(observed / filename)
            files[filename] = {'sha256': digest(raw), 'bytes': len(raw)}
        allowed_dirs = {parent.as_posix() for path in files for parent in PurePosixPath(path).parents if parent.as_posix() != '.'}
        count = 0
        for current, directories, filenames in os.walk(observed, followlinks=False):
            for dirname in directories:
                path = Path(current) / dirname
                need(not path.is_symlink() and path.relative_to(observed).as_posix() in allowed_dirs,
                     'extra or unsafe observed directory')
                count += 1
                need(count <= len(allowed_dirs), 'observed directory bound')
        captured = common.mapped(observed, files)
        result = {'schema_version': 1, 'purpose': 'collected-immutable-generic-base', 'status': 'PASS',
                  'image_id': image_id, 'bootstrap_sha256': bootstrap_pin, 'packages_lock_sha256': packages_pin,
                  'inputs_sha256': inputs_pin, 'snapshot_id': base['snapshot_id'], 'source_map': source_map,
                  'base_sha256': digest(encoded(base)), 'observations_sha256': digest(observation_raw),
                  'worker': receipt, 'files': files, 'platform_scope': 'generic-builder-only', 'hardware_validation': 'NOT RUN'}
    # Finalize private teardown before any durable PASS. Publish only captured finite bytes.
    publication = Publication(common, output)
    state['publication'] = publication
    return publication.publish(captured, result)


def decode_record(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate receiver JSON field')
            result[key] = value
        return result
    def invalid(value):
        raise Refused('receiver JSON noninteger number refused')
    try:
        result = json.loads(text(raw, COMMAND_LIMIT), object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
    except (ValueError, UnicodeError, RecursionError):
        raise Refused('invalid receiver JSON') from None
    need(isinstance(result, dict), 'receiver JSON object required')
    return result


def exact_tree(root, expected):
    """Visit only finite declared ancestors, rejecting unknown entries before read."""
    directories = {parent.as_posix() for name in expected for parent in PurePosixPath(name).parents
                   if parent.as_posix() != '.'}
    found = set()
    rootfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    def visit(descriptor, prefix):
        entries = os.listdir(descriptor)
        need(len(entries) <= 1024, 'receiver directory count bound')
        for name in entries:
            path = prefix + name
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                need(path in directories, 'receiver extra directory')
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                try:
                    visit(child, path + '/')
                finally:
                    os.close(child)
            else:
                need(path in expected and stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                     'receiver extra or nonregular file')
                found.add(path)
                need(len(found) <= 689, 'receiver file count bound')
    try:
        visit(rootfd, '')
    finally:
        os.close(rootfd)
    need(found == set(expected), 'receiver missing file')


def verify_worker(worker, image_id, source_map):
    fields = {'status', 'image_id', 'container', 'container_id', 'ownership_verified', 'name_absence_verified',
              'id_absence_verified', 'absence_verified', 'cleanup', 'commands', 'tool_sha256'}
    need(isinstance(worker, dict) and set(worker) == fields and worker['status'] == worker['cleanup'] == 'PASS'
         and worker['image_id'] == image_id and isinstance(worker['container_id'], str)
         and re.fullmatch('[0-9a-f]{64}', worker['container_id']) and isinstance(worker['container'], str)
         and re.fullmatch('cachy-asahi-repository-client-[0-9a-f]{32}', worker['container'])
         and all(worker[key] is True for key in ('ownership_verified', 'name_absence_verified',
                                                'id_absence_verified', 'absence_verified')), 'receiver worker ownership/cleanup differs')
    tools = worker['tool_sha256']
    need(isinstance(tools, dict) and set(tools) == {'docker'} and isinstance(tools['docker'], str)
         and re.fullmatch('[0-9a-f]{64}', tools['docker']), 'receiver Docker tool pin required')
    commands = worker['commands']
    need(isinstance(commands, list) and len(commands) == 9, 'receiver exact owned-container command sequence required')
    for row in commands:
        need(isinstance(row, dict) and set(row) == {'argv', 'exit_code', 'stdout_sha256', 'stderr_sha256',
              'stdout_bytes', 'stderr_bytes'} and type(row['exit_code']) is int and row['exit_code'] == 0,
              'receiver successful command record required')
        need(isinstance(row['argv'], list) and row['argv'] and all(isinstance(item, str) and 0 < len(item) <= 4096
             and not any(ord(c) < 32 or ord(c) == 127 for c in item) for item in row['argv'])
             and Path(row['argv'][0]).is_absolute() and Path(row['argv'][0]).name == 'docker', 'receiver command argv differs')
        for channel in ('stdout', 'stderr'):
            value, size = row[channel + '_sha256'], row[channel + '_bytes']
            need(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) and type(size) is int
                 and 0 <= size <= 1024**2 and (size != 0 or value == digest(b'')), 'receiver command stream map differs')
        need(row['stdout_bytes'] + row['stderr_bytes'] <= 1024**2, 'receiver command output bound')
    docker = commands[0]['argv'][0]
    need(all(row['argv'][0] == docker for row in commands), 'receiver tool executable changes')
    cid = worker['container_id']
    expected = {0: ['info', '--format', '{{.Architecture}}'], 1: ['image', 'inspect', image_id],
                3: ['container', 'inspect', cid], 4: ['start', '--attach', cid], 5: ['container', 'inspect', cid],
                6: ['container', 'inspect', cid], 7: ['container', 'rm', '-f', cid],
                8: ['container', 'ls', '-a', '--no-trunc', '--format', '{{.ID}} {{.Names}}']}
    need(all(commands[index]['argv'][1:] == argv for index, argv in expected.items()), 'receiver command ownership/order differs')
    need(commands[0]['stdout_sha256'] in {digest(b'aarch64\n'), digest(b'arm64\n')}, 'receiver native daemon observation differs')
    for index in (2, 7):
        need(commands[index]['stdout_sha256'] == digest((cid + '\n').encode())
             and commands[index]['stdout_bytes'] == 65, 'receiver created/removed CID observation differs')
    argv = commands[2]['argv'][1:]
    prefix = ['create', '--name', worker['container'], '--cidfile']
    need(argv[:4] == prefix and len(argv) == 40, 'receiver exact creation shape differs')
    need(Path(argv[4]).is_absolute() and Path(argv[4]).name == 'container-id', 'receiver private CID path differs')
    fixed = ['--pull=never', '--platform=linux/arm64', '--user']
    need(argv[5:8] == fixed and re.fullmatch('[0-9]+:[0-9]+', argv[8]), 'receiver native creation identity differs')
    need(argv[9:21] == ['--network=none', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only',
         '--pids-limit=128', '--memory=2g', '--cpus=2', '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777',
         '--mount', argv[19], '--mount'], 'receiver isolated creation bounds differ')
    # Mount sources are ephemeral actual paths; destination and read-only policy are fixed.
    for index, destination, readonly in ((19, '/source', True), (21, '/inputs', True), (23, '/out', False)):
        value = argv[index]
        suffix = ',dst=' + destination + (',readonly' if readonly else '')
        need(value.startswith('type=bind,src=/') and value.endswith(suffix)
             and ',' not in value[len('type=bind,src='):-len(suffix)], 'receiver creation mount policy differs')
    need(argv[22] == '--mount' and argv[24:] == ['--entrypoint=/usr/bin/python3', image_id, '-I', '-B',
        '/source/worker.py', '--source-map-sha256', digest(encoded(source_map)), '--module', 'base', '--worker',
        '--lock', '/inputs/packages.lock', '--inputs', '/inputs/inputs.lock.json', '--output', '/out'],
        'receiver authenticated worker entry differs')


def receive_base(output_root, result_raw, result_pin):
    """Read-only finite exporter admission. External authority is never self-minted."""
    need(type(result_raw) is bytes and isinstance(result_pin, str) and re.fullmatch('[0-9a-f]{64}', result_pin)
         and digest(result_raw) == result_pin, 'receiver external result pin differs')
    result = decode_record(result_raw)
    fields = {'schema_version', 'purpose', 'status', 'image_id', 'bootstrap_sha256', 'packages_lock_sha256',
              'inputs_sha256', 'snapshot_id', 'source_map', 'base_sha256', 'observations_sha256', 'worker', 'files',
              'platform_scope', 'hardware_validation'}
    need(set(result) == fields and type(result['schema_version']) is int and result['schema_version'] == 1
         and result['purpose'] == 'collected-immutable-generic-base' and result['status'] == 'PASS'
         and result['platform_scope'] == 'generic-builder-only' and result['hardware_validation'] == 'NOT RUN',
         'receiver generic collector scope differs')
    image = result['image_id']
    need(isinstance(image, str) and re.fullmatch('sha256:[0-9a-f]{64}', image), 'receiver immutable image required')
    for field in ('bootstrap_sha256', 'packages_lock_sha256', 'inputs_sha256', 'base_sha256', 'observations_sha256'):
        need(isinstance(result[field], str) and re.fullmatch('[0-9a-f]{64}', result[field]), 'receiver pin field differs')
    snapshot = result['snapshot_id']
    need(isinstance(snapshot, str) and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._:+-]{0,255}', snapshot), 'receiver snapshot identity differs')
    source_map = result['source_map']
    need(isinstance(source_map, dict) and set(source_map) == {'common.py', 'base.py', 'worker.py'}, 'receiver exact source closure required')
    for row in source_map.values():
        need(isinstance(row, dict) and set(row) == {'sha256', 'mode'} and type(row['mode']) is int
             and row['mode'] in {0o644, 0o755} and isinstance(row['sha256'], str)
             and re.fullmatch('[0-9a-f]{64}', row['sha256']), 'receiver source pin/mode differs')
    verify_worker(result['worker'], image, source_map)
    root = Path(output_root)
    need(root.is_absolute() and '..' not in root.parts, 'receiver absolute root required')
    need(nofollow_read(root / 'result.json', COMMAND_LIMIT) == result_raw, 'receiver actual result bytes differ')
    base_raw = nofollow_read(root / 'observed/base.json', COMMAND_LIMIT)
    need(digest(base_raw) == result['base_sha256'], 'receiver base byte pin differs')
    metadata = decode_record(base_raw)
    packages = metadata.get('packages')
    need(isinstance(packages, list) and len(packages) == COUNT, 'receiver complete 341 metadata required')
    names = []
    for row in packages:
        need(isinstance(row, dict) and isinstance(row.get('name'), str) and re.fullmatch(NAME, row['name'])
             and isinstance(row.get('version'), str) and re.fullmatch(VERSION, row['version']), 'receiver package identity differs')
        names.append((row['name'], row['version']))
    lock = ''.join(name + ' ' + version + '\n' for name, version in sorted(names)).encode()
    inventory(lock)
    need(digest(lock) == result['packages_lock_sha256'], 'receiver reconstructed package lock differs')
    expected = {'local/' + name + '-' + version + '/' + kind for name, version in names for kind in ('desc', 'files')}
    expected |= {'base.json', 'observations.json', 'pacman-Q.stdout', 'pacman-Q.stderr', 'pacman-Ql.stdout', 'pacman-Ql.stderr'}
    files = result['files']
    need(isinstance(files, dict) and set(files) == expected and len(files) == 688, 'receiver exact observation map required')
    approved = {'result.json': {'sha256': result_pin, 'bytes': len(result_raw)}}
    total, captured = len(result_raw), {}
    for name, row in files.items():
        need(isinstance(row, dict) and set(row) == {'sha256', 'bytes'} and isinstance(row['sha256'], str)
             and re.fullmatch('[0-9a-f]{64}', row['sha256']) and type(row['bytes']) is int
             and 0 <= row['bytes'] <= COMMAND_LIMIT, 'receiver typed observation byte map required')
        raw = nofollow_read(root / 'observed' / name, RECORD_LIMIT if name.startswith('local/') else COMMAND_LIMIT)
        total += len(raw)
        need(total <= TOTAL_LIMIT and len(raw) == row['bytes'] and digest(raw) == row['sha256'], 'receiver observation drift or bound')
        captured[name] = raw
        approved['observed/' + name] = dict(row)
    exact_tree(root, approved)
    records = {name + '-' + version: {kind: captured['local/' + name + '-' + version + '/' + kind]
               for kind in ('desc', 'files')} for name, version in names}
    reparsed = parse_local(records, lock)
    reparsed['snapshot_id'], reparsed['inputs_sha256'] = snapshot, result['inputs_sha256']
    need(encoded(reparsed) == base_raw, 'receiver independent local metadata reconstruction differs')
    query, listing = captured['pacman-Q.stdout'], captured['pacman-Ql.stdout']
    validate_queries(reparsed, records, query, listing)
    need(captured['pacman-Q.stderr'] == captured['pacman-Ql.stderr'] == b'', 'receiver pacman diagnostics refused')
    expected_observations = {'schema_version': 1, 'purpose': 'actual-immutable-generic-base-metadata', 'status': 'PASS',
        'architecture': 'aarch64', 'root_readonly': True, 'packages_lock_sha256': digest(lock), 'package_count': COUNT,
        'inputs_sha256': result['inputs_sha256'], 'snapshot_id': snapshot, 'hardware_validation': 'NOT RUN',
        'commands': [{'argv': ['/usr/bin/pacman', '-Q'], 'exit_code': 0, 'stdout_sha256': digest(query), 'stderr_sha256': digest(b'')},
                     {'argv': ['/usr/bin/pacman', '-Ql'], 'exit_code': 0, 'stdout_sha256': digest(listing), 'stderr_sha256': digest(b'')}]}
    need(decode_record(captured['observations.json']) == expected_observations
         and digest(captured['observations.json']) == result['observations_sha256'], 'receiver actual query observation differs')
    # Re-read only approved bytes to refuse changes during admission.
    for name, row in approved.items():
        need(digest(nofollow_read(root / name, COMMAND_LIMIT)) == row['sha256'], 'receiver file changed during admission')
    exact_tree(root, approved)
    return {'status': 'PASS', 'purpose': 'validated-immutable-generic-base', 'base': reparsed,
            'approved_files': approved, 'result_sha256': result_pin, 'platform_scope': 'generic-builder-only',
            'hardware_validation': 'NOT RUN'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', action='store_true', required=True)
    parser.add_argument('--lock', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--inputs', type=Path, required=True)
    args = parser.parse_args()
    try:
        worker(args.lock, args.inputs, args.output)
    except (Refused, OSError, KeyboardInterrupt) as error:
        print('base metadata refused: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
