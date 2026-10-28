"""Data-only committed source binding; no project helper is imported here.

The controller authenticates this module and the returned contract externally
before importing helpers. Contracts exclude private archives and bytecode caches.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time

PACKAGE = 'packages/tools/cachy-asahi-update/'
STAGE = 'scripts/port/updater-native-stage/'
READY = PACKAGE + 'runner-ready-pins.json'
HELPERS = frozenset({'scripts/build/compare.py', 'scripts/build/container-entry.sh',
                     'scripts/ci/log_evidence.py'})
CONTROLLERS = frozenset(STAGE + n for n in ('stage.py', 'source.py', 'runtime.py',
                                          'broker.py', 'test_source.py'))
EXTERNAL_FREEZES = frozenset(STAGE + n for n in ('stage.lock.json', 'source.lock.json'))
MAX_FILES = 128
MAX_BYTES = 32 * 1024**2
GIT_SECONDS = 60


class SourceCancelled(KeyboardInterrupt):
    def __init__(self, events, cleanup_failed=False):
        self.signum = events[0]
        self.cancelled_signals = [signal.Signals(s).name for s in events]
        self.cleanup_failed = cleanup_failed
        super().__init__('source-git-cancelled')


class _Signals:
    """Nonraising handlers remain installed through registration and teardown."""
    def __init__(self):
        self.signals = {signal.SIGINT, signal.SIGTERM, signal.SIGALRM}
        self.events = []
        self.cleanup_failed = False

    def record(self, number, _frame=None):
        if number not in self.events:
            self.events.append(number)

    def __enter__(self):
        self.prior_mask = signal.pthread_sigmask(signal.SIG_BLOCK, self.signals)
        self.handlers = {s: signal.getsignal(s) for s in self.signals}
        try:
            for number in self.signals:
                signal.signal(number, self.record)
        except BaseException:
            for number, handler in self.handlers.items():
                signal.signal(number, handler)
            raise
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, self.prior_mask)
        return self

    def __exit__(self, *_exception):
        try:
            signal.pthread_sigmask(signal.SIG_BLOCK, self.signals)
            # Finite even if a caller supplied a periodic real-time alarm.
            for _ in range(8):
                pending = signal.sigpending() & self.signals
                if not pending:
                    break
                for number in pending:
                    self.record(number)
                signal.sigtimedwait(self.signals, 0)
        except BaseException:
            self.cleanup_failed = True
        finally:
            # Consumption errors must never skip any caller handler or mask.
            for number, handler in self.handlers.items():
                try:
                    signal.signal(number, handler)
                except BaseException:
                    self.cleanup_failed = True
                    try: signal.signal(number, handler)
                    except BaseException: pass
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, self.prior_mask)
            except BaseException:
                self.cleanup_failed = True
                try: signal.pthread_sigmask(signal.SIG_SETMASK, self.prior_mask)
                except BaseException: pass


def _subreaper(value=None):
    libc = ctypes.CDLL(None, use_errno=True)
    result = ctypes.c_int()
    status = libc.prctl(37, ctypes.byref(result), 0, 0, 0) if value is None else libc.prctl(36, value, 0, 0, 0)
    need(status == 0, 'source-subreaper')
    return result.value


def _group_exists(group):
    try:
        os.killpg(group, 0)
        return True
    except ProcessLookupError:
        return False


def _cleanup(process):
    if process is None:
        return
    # Git has no legitimate external helpers here; terminate every owned group
    # member even if the direct child already exited after closing its output.
    if _group_exists(process.pid):
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    end, escalated = time.monotonic() + 3, False
    grace = time.monotonic() + .3
    while time.monotonic() < end:
        if not escalated and time.monotonic() >= grace and _group_exists(process.pid):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            escalated = True
        if process.poll() is not None:
            while True:
                try:
                    pid, _ = os.waitpid(-process.pid, os.WNOHANG)
                except ChildProcessError:
                    break
                if not pid:
                    break
        if not _group_exists(process.pid) and process.poll() is not None:
            return
        time.sleep(.05)
    raise ValueError('source-git-cleanup')


def need(value, reason):
    if not value:
        raise ValueError(reason)


def relative(name):
    need(type(name) is str and len(name) <= 240 and
         re.fullmatch(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', name) and
         all(p not in ('.', '..') for p in name.split('/')), 'source-path')
    return name


def digest(data):
    return hashlib.sha256(data).hexdigest()


def hash_value(value, length=64):
    need(type(value) is str and re.fullmatch('[0-9a-f]{' + str(length) + '}', value), 'source-hash')
    return value


def source_root(root):
    raw = Path(root)
    need('..' not in raw.parts, 'source-root')
    root = Path(os.path.abspath(raw))
    for path in (root, *root.parents):
        need(stat.S_ISDIR(path.lstat().st_mode), 'source-root-directory')
    return root


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def directory(path):
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except OSError as error:
        os.close(fd)
        raise ValueError('source-parent-directory') from error


def read(root, name):
    path = root / relative(name)
    parent = directory(path.parent)
    fd = None
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        mode = stat.S_IMODE(before.st_mode)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             mode in (0o644, 0o755), 'source-regular-mode')
        need(before.st_size <= MAX_BYTES, 'source-file-bound')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(MAX_BYTES + 1)
        after = os.fstat(fd)
        need(len(data) <= MAX_BYTES and identity(before) == identity(after) ==
             identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'source-read-drift')
        current = directory(path.parent)
        try:
            need(identity(os.stat(path.name, dir_fd=current, follow_symlinks=False)) == identity(after),
                 'source-read-drift')
        finally:
            os.close(current)
        return data, mode
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def _git(root, args, limit, deadline):
    """Bound read-only Git output and wall time; ignore environment Git overrides."""
    command = ['/usr/bin/git', '--no-optional-locks', '--no-replace-objects',
               '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
               '-C', str(root), *args]
    env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
           'HOME': '/nonexistent', 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0',
           'GIT_NO_LAZY_FETCH': '1'}
    need(time.monotonic() < deadline, 'source-git-deadline')
    process, primary, cleanup_error, prior_reaper = None, None, None, None
    output = bytearray()
    scope = _Signals()
    with scope:
        try:
            if scope.events:
                raise SourceCancelled(scope.events)
            prior_reaper = _subreaper()
            _subreaper(1)
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                       env=env, start_new_session=True,
                                       preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, scope.prior_mask))
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                eof = False
                while not eof or process.poll() is None:
                    if scope.events:
                        raise SourceCancelled(scope.events)
                    left = deadline - time.monotonic()
                    need(left > 0, 'source-git-deadline')
                    if eof:
                        time.sleep(min(.05, left))
                        continue
                    events = selector.select(min(.1, left))
                    if not events:
                        continue
                    block = os.read(process.stdout.fileno(), min(65536, limit + 1 - len(output)))
                    if not block:
                        eof = True
                        continue
                    output.extend(block)
                    need(len(output) <= limit, 'source-git-output-bound')
            need(process.returncode == 0, 'source-git-query')
        except BaseException as error:
            primary = error
        finally:
            try:
                _cleanup(process)
            except BaseException as error:
                cleanup_error = error
            finally:
                if process is not None:
                    process.stdout.close()
                if prior_reaper is not None:
                    try:
                        _subreaper(prior_reaper)
                    except BaseException as error:
                        cleanup_error = cleanup_error or error
    if scope.cleanup_failed:
        cleanup_error = cleanup_error or ValueError('source-git-signal-cleanup')
    if scope.events:
        raise SourceCancelled(scope.events, cleanup_error is not None)
    if primary is not None:
        raise primary
    if cleanup_error is not None:
        raise ValueError('source-git-cleanup') from cleanup_error
    return bytes(output)


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, 'source-json-duplicate')
        result[key] = value
    return result


def tree_files(root, prefix):
    """Finite source directory enumeration, never following links or caches."""
    found, pending, count = set(), [root / prefix], 0
    while pending:
        directory = pending.pop()
        need(stat.S_ISDIR(directory.lstat().st_mode), 'source-tree-directory')
        with os.scandir(directory) as entries:
            for entry in entries:
                count += 1
                need(count <= 512, 'source-tree-bound')
                mode = entry.stat(follow_symlinks=False).st_mode
                if stat.S_ISDIR(mode):
                    if entry.name != '__pycache__':
                        pending.append(Path(entry.path))
                else:
                    need(stat.S_ISREG(mode), 'source-tree-regular')
                    found.add(relative(Path(entry.path).relative_to(root).as_posix()))
    return found


def closure(root, stage_files, ready_sha):
    hash_value(ready_sha)
    need(type(stage_files) in (list, tuple) and len(stage_files) <= MAX_FILES, 'source-stage-list')
    stage = {relative(name) for name in stage_files}
    need(len(stage) == len(stage_files) and CONTROLLERS <= stage and
         all(name.startswith(STAGE) for name in stage), 'source-stage-set')
    available = tree_files(root, STAGE)
    need(stage <= available and available <= stage | EXTERNAL_FREEZES, 'source-stage-closure')
    data, _ = read(root, READY)
    need(digest(data) == ready_sha, 'source-ready-pin')
    ready = json.loads(data, object_pairs_hook=pairs)
    need(type(ready) is dict and type(ready.get('schema_version')) is int and
         ready['schema_version'] == 1, 'source-ready-schema')
    package, roots = ready.get('files_sha256'), ready.get('root_files_sha256')
    need(type(package) is dict and len(package) == 64 and type(roots) is dict and len(roots) == 8,
         'source-ready-file-count')
    expected = {READY: ready_sha}
    for name, value in package.items():
        expected[PACKAGE + relative(name)] = hash_value(value)
    need(set(expected) == tree_files(root, PACKAGE), 'source-package-closure')
    for name, value in roots.items():
        name = relative(name)
        need(name.startswith('scripts/') and name not in expected, 'source-ready-root-path')
        expected[name] = hash_value(value)
    required = set(expected) | HELPERS | stage
    need(len(required) <= MAX_FILES, 'source-file-count')
    return required, expected


def collect(root, commit, stage_files, ready_sha):
    """Bind the reviewed ready map and controller closure to exact Git HEAD."""
    root = source_root(root)
    hash_value(commit, 40)
    required, expected = closure(root, stage_files, ready_sha)
    deadline = time.monotonic() + GIT_SECONDS
    need(_git(root, ['rev-parse', '--show-toplevel'], 4096, deadline).rstrip(b'\n') == os.fsencode(root),
         'source-git-root')
    need(_git(root, ['rev-parse', '--verify', 'HEAD'], 128, deadline) == (commit + '\n').encode(),
         'source-head-commit')
    records, total = {}, 0
    for name in sorted(required):
        data, mode = read(root, name)
        total += len(data)
        need(total <= MAX_BYTES, 'source-total-bound')
        checksum = digest(data)
        need(name not in expected or checksum == expected[name], 'source-reviewed-byte-drift')
        row = _git(root, ['ls-tree', '-z', commit, '--', name], 1024, deadline)
        match = re.fullmatch(rb'(100644|100755) blob ([0-9a-f]{40})\t' + re.escape(name.encode()) + b'\x00', row)
        need(match, 'source-tracked-blob')
        git_mode, blob = (part.decode('ascii') for part in match.groups())
        need(mode == int(git_mode[-3:], 8), 'source-git-mode-drift')
        committed = _git(root, ['cat-file', 'blob', blob], MAX_BYTES, deadline)
        need(committed == data and hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == blob,
             'source-git-byte-drift')
        records[name] = {'sha256': checksum, 'git_blob': blob, 'git_mode': git_mode, 'file_mode': mode}
    # Refuse changes occurring while Git was queried, including HEAD movement.
    need(_git(root, ['rev-parse', '--verify', 'HEAD'], 128, deadline) == (commit + '\n').encode(),
         'source-head-drift')
    for name, record in records.items():
        data, mode = read(root, name)
        need(digest(data) == record['sha256'] and mode == record['file_mode'], 'source-final-drift')
    need(closure(root, stage_files, ready_sha)[0] == required, 'source-closure-drift')
    return {'schema_version': 1, 'source_commit': commit, 'ready_sha256': ready_sha,
            'stage_files': sorted(stage_files), 'files': records, 'total_bytes': total}


def verify(root, contract):
    """Re-observe committed bytes/modes; caller authenticates contract bytes first."""
    need(type(contract) is dict and set(contract) ==
         {'schema_version', 'source_commit', 'ready_sha256', 'stage_files', 'files', 'total_bytes'} and
         type(contract['schema_version']) is int and contract['schema_version'] == 1 and
         type(contract['files']) is dict and type(contract['total_bytes']) is int and
         len(contract['files']) <= MAX_FILES and
         0 <= contract['total_bytes'] <= MAX_BYTES, 'source-contract-schema')
    for name, row in contract['files'].items():
        relative(name)
        need(type(row) is dict and set(row) == {'sha256', 'git_blob', 'git_mode', 'file_mode'} and
             row['git_mode'] in ('100644', '100755') and type(row['file_mode']) is int and
             row['file_mode'] == int(row['git_mode'][-3:], 8), 'source-contract-row')
        hash_value(row['sha256']); hash_value(row['git_blob'], 40)
    need(collect(root, contract['source_commit'], contract['stage_files'], contract['ready_sha256']) == contract,
         'source-contract-drift')
