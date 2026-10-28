#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture an exact reviewed Git source packet; no writes to the checkout."""
import ast
import builtins
from contextlib import contextmanager, nullcontext
from functools import wraps
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import time
from types import MappingProxyType, ModuleType

FILE_LIMIT, TOTAL_LIMIT, GIT_LIMIT = 2 * 1024**2, 32 * 1024**2, 8 * 1024**2
MAX_FILES, GIT_SECONDS, CAPTURE_SECONDS = 256, 10, 180
SIGNALS = {signal.SIGINT, signal.SIGTERM}
_ACTIVE = None


class Cancelled(KeyboardInterrupt):
    pass


class Cancellation:
    def __init__(self):
        self.cancelled, self.deferrals = False, 0

    def interrupt(self, *_):
        self.cancelled = True
        if not self.deferrals:
            raise Cancelled('source capture cancelled')

    @contextmanager
    def defer(self):
        self.deferrals += 1
        try:
            yield
        finally:
            self.deferrals -= 1


@contextmanager
def cancellations():
    global _ACTIVE
    if _ACTIVE is not None:
        if _ACTIVE.cancelled:
            raise Cancelled('source capture cancelled')
        yield _ACTIVE
        if _ACTIVE.cancelled:
            raise Cancelled('source capture cancelled')
        return
    state, previous = Cancellation(), {}
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
    try:
        for signum in SIGNALS:
            previous[signum] = signal.signal(signum, state.interrupt)
        _ACTIVE = state
        signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        yield state
        if state.cancelled:
            raise Cancelled('source capture cancelled')
    finally:
        signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        _ACTIVE = None
        signal.pthread_sigmask(signal.SIG_SETMASK, mask)


def cancellation_bound(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        with cancellations():
            return function(*args, **kwargs)
    return wrapped


def need(value, message):
    if not value:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def alive(deadline):
    if _ACTIVE is not None and _ACTIVE.cancelled and not _ACTIVE.deferrals:
        raise Cancelled('source capture cancelled')
    need(deadline is None or time.monotonic() < deadline, 'acceptance aggregate deadline exceeded')


def relative(name):
    need(isinstance(name, str) and 0 < len(name) <= 1024 and not name.startswith('/')
         and not re.search(r'[\x00-\x1f\x7f]', name)
         and all(p not in {'', '.', '..'} for p in name.split('/')), 'unsafe packet path')
    return name


def captured_file(path, *, expected_size=None, deadline=None):
    """Walk with directory descriptors; bytes and metadata come from one fd."""
    path = Path(path)
    alive(deadline)
    need(path.is_absolute() and '..' not in path.parts, 'absolute canonical input required')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    fd = None
    try:
        for part in path.parts[1:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory); directory = next_fd
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 <= before.st_size <= FILE_LIMIT, 'unsafe or oversized source file')
        need(expected_size is None or before.st_size == expected_size, 'source size mismatch')
        data = bytearray()
        while block := os.read(fd, min(65536, before.st_size - len(data) + 1)):
            alive(deadline)
            data.extend(block)
            need(len(data) <= before.st_size, 'source read bound')
        after = os.fstat(fd)
        attributes = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                      'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(len(data) == before.st_size and all(getattr(before, k) == getattr(after, k) for k in attributes),
             'source changed during capture')
        alive(deadline)
        return bytes(data), f'{stat.S_IMODE(before.st_mode):04o}'
    finally:
        with _ACTIVE.defer() if _ACTIVE is not None else nullcontext():
            if fd is not None:
                os.close(fd)
            os.close(directory)


def decode(data):
    def pairs(items):
        result = {}
        for name, value in items:
            need(name not in result, 'duplicate packet field')
            result[name] = value
        return result
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite packet value'))


@cancellation_bound
def git(root, home, arguments, *, deadline=None):
    """Drain both pipes with one byte/deadline bound; invoke builtins only."""
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'XDG_CONFIG_HOME': str(home), 'LC_ALL': 'C',
           'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
           'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0', 'GIT_NO_REPLACE_OBJECTS': '1',
           'GIT_NO_LAZY_FETCH': '1', 'GIT_LITERAL_PATHSPECS': '1', 'GIT_PAGER': 'cat'}
    command = ['/usr/bin/git', '--no-optional-locks', '-c', 'core.hooksPath=/dev/null',
               '-c', 'core.fsmonitor=false', '-c', 'core.pager=cat', '-c', 'gc.auto=0',
               '-c', 'maintenance.auto=false', '-c', 'protocol.allow=never', '-C', str(root), *arguments]
    alive(deadline)
    deadline = min(time.monotonic() + GIT_SECONDS, deadline if deadline is not None else float('inf'))
    process, mask = None, signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
    buffers, total = [bytearray(), bytearray()], 0
    try:
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       env=env, start_new_session=True,
                                       preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, mask))
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        with selectors.DefaultSelector() as selector:
            for index, stream in enumerate((process.stdout, process.stderr)):
                selector.register(stream, selectors.EVENT_READ, index)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                need(remaining > 0, 'Git deadline exceeded')
                for key, _ in selector.select(min(remaining, .2)):
                    block = os.read(key.fd, min(65536, GIT_LIMIT - total + 1))
                    if not block:
                        selector.unregister(key.fileobj)
                    else:
                        total += len(block)
                        need(total <= GIT_LIMIT, 'Git output bound exceeded')
                        buffers[key.data].extend(block)
        code = process.wait(timeout=max(.001, deadline - time.monotonic()))
        need(code == 0, 'Git read failed')
        need(time.monotonic() < deadline, 'Git deadline exceeded')
        return bytes(buffers[0])
    finally:
        with _ACTIVE.defer():
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
            if process is not None:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=1)
                process.stdout.close(); process.stderr.close()


class Snapshot:
    def __init__(self, root, files, provenance):
        self.root = root
        self.files = MappingProxyType(dict(files))
        self.provenance = MappingProxyType(provenance)

    def module(self, path, name, *, imports=None):
        """Execute captured source with explicit bound imports; not a sandbox.

        The caller supplies trusted interpreter modules or already captured
        helper modules. No relative import, path search or bytecode fallback.
        """
        relative(path)
        need(path in self.files and isinstance(name, str) and bool(name), 'unbound module source')
        bound = dict(imports or {})
        need(all(isinstance(k, str) and isinstance(v, ModuleType) for k, v in bound.items()), 'bound modules required')

        def importer(module, globals=None, locals=None, fromlist=(), level=0):
            need(level == 0 and module in bound, 'unbound transitive import: ' + str(module))
            if fromlist:
                need('*' not in fromlist, 'wildcard imports refused')
                for field in fromlist:
                    value = getattr(bound[module], field, None)
                    if isinstance(value, ModuleType):
                        need(bound.get(module + '.' + field) is value, 'unbound transitive submodule')
                return bound[module]
            top = module.split('.')[0]
            need(top in bound, 'unbound parent import: ' + top)
            parent, prefix = bound[top], top
            for field in module.split('.')[1:]:
                prefix += '.' + field
                need(prefix in bound and getattr(parent, field, None) is bound[prefix], 'unbound transitive submodule')
                parent = bound[prefix]
            return bound[top]

        tree = ast.parse(self.files[path], filename=str(self.root / path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    importer(alias.name)
            elif isinstance(node, ast.ImportFrom):
                importer(node.module, fromlist=tuple(alias.name for alias in node.names), level=node.level)
        module = ModuleType(name)
        module.__file__, module.__package__ = str(self.root / path), name.rpartition('.')[0]
        module.__dict__['__builtins__'] = {**vars(builtins), '__import__': importer}
        exec(compile(tree, module.__file__, 'exec'), module.__dict__)
        return module


@cancellation_bound
def capture(root, packet_path, packet_sha256, expected_paths, workflow_path, expected_commit, *, environ=None,
            packet_relative_path='scripts/port/ksm-native-job/packet.lock.json'):
    """Bind packet, current files and committed blobs; return inert snapshots."""
    deadline = time.monotonic() + CAPTURE_SECONDS
    root, packet_path = Path(root), Path(packet_path)
    need(root.is_absolute() and '..' not in root.parts, 'absolute checkout required')
    relative(packet_relative_path)
    need(packet_path == root / packet_relative_path and '..' not in packet_path.parts, 'packet must be at reviewed checkout path')
    need(isinstance(packet_sha256, str) and re.fullmatch('[0-9a-f]{64}', packet_sha256), 'packet checksum required')
    need(isinstance(expected_commit, str) and re.fullmatch('[0-9a-f]{40}', expected_commit), 'exact commit required')
    env = os.environ if environ is None else environ
    need(env.get('GITHUB_SHA') == env.get('GITHUB_WORKFLOW_SHA') == expected_commit, 'job/workflow commit mismatch')
    expected = set(expected_paths)
    need(0 < len(expected) <= MAX_FILES, 'finite expected source set required')
    for path in expected:
        relative(path)
    need(packet_relative_path not in expected, 'packet self-hash entry refused')
    relative(workflow_path)
    need(workflow_path in expected and workflow_path.startswith('.github/workflows/')
         and workflow_path.endswith(('.yml', '.yaml')), 'reviewed workflow required')
    packet_bytes, packet_mode = captured_file(packet_path, deadline=deadline)
    alive(deadline)
    need(packet_mode == '0644' and digest(packet_bytes) == packet_sha256, 'packet checksum/mode mismatch')
    packet = decode(packet_bytes)
    need(isinstance(packet, dict) and set(packet) == {'schema_version', 'files'}
         and type(packet['schema_version']) is int and packet['schema_version'] == 1
         and isinstance(packet['files'], dict) and set(packet['files']) == expected, 'exact packet schema/source set required')
    total, files = len(packet_bytes), {}
    for path in sorted(expected):
        record = packet['files'][path]
        need(isinstance(record, dict) and set(record) == {'sha256', 'size_bytes', 'mode'}
             and isinstance(record['sha256'], str) and re.fullmatch('[0-9a-f]{64}', record['sha256'])
             and type(record['size_bytes']) is int and 0 <= record['size_bytes'] <= FILE_LIMIT
             and isinstance(record['mode'], str) and record['mode'] in {'0644', '0755'}, 'source pin schema refused')
        total += record['size_bytes']
        need(total <= TOTAL_LIMIT, 'aggregate source bound')
        data, mode = captured_file(root / path, expected_size=record['size_bytes'], deadline=deadline)
        alive(deadline)
        need(len(data) == record['size_bytes'] and digest(data) == record['sha256'] and mode == record['mode'],
             'source bytes/mode mismatch: ' + path)
        files[path] = data
    with tempfile.TemporaryDirectory(prefix='ksm-git-read-') as temporary:
        home = Path(temporary)
        def query(arguments):
            alive(deadline)
            data = git(root, home, arguments, deadline=deadline)
            alive(deadline)
            return data
        need(query(['rev-parse', '--verify', 'HEAD']).strip().decode('ascii') == expected_commit, 'checkout HEAD mismatch')
        committed_paths = expected | {packet_relative_path}
        listing = query(['ls-tree', '-r', '-z', '--full-tree', expected_commit, '--', *sorted(committed_paths)])
        objects = {}
        for entry in listing.split(b'\0'):
            if not entry:
                continue
            metadata, path = entry.split(b'\t', 1)
            mode, kind, oid = metadata.decode('ascii').split(' ')
            path = path.decode('utf-8')
            need(path in committed_paths and path not in objects and kind == 'blob' and mode in {'100644', '100755'}
                 and re.fullmatch('[0-9a-f]{40}', oid), 'committed source identity refused')
            expected_mode = '0644' if path == packet_relative_path else packet['files'][path]['mode']
            need(mode[2:] == expected_mode, 'committed source mode mismatch')
            objects[path] = oid
        need(set(objects) == committed_paths, 'committed source set incomplete')
        for path, oid in objects.items():
            data = packet_bytes if path == packet_relative_path else files[path]
            need(query(['cat-file', 'blob', oid]) == data, 'committed source bytes mismatch: ' + path)
        need(query(['rev-parse', '--verify', 'HEAD']).strip().decode('ascii') == expected_commit, 'checkout HEAD changed')
    alive(deadline)
    return Snapshot(root, files, {'schema_version': 1, 'kind': 'reviewed-committed-source-packet-capture',
                                 'packet_sha256': packet_sha256, 'commit': expected_commit, 'workflow': workflow_path,
                                 'packet_path': packet_relative_path, 'packet_git_blob': objects[packet_relative_path],
                                 'files': packet['files'], 'hardware_accepted': False, 'installation_accepted': False,
                                 'native_lifecycle_accepted': False, 'git_mutation': False})
