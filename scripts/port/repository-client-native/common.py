#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded native follow-up runtime; no host installation or trust mutation."""
from contextlib import contextmanager
import hashlib
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import resource
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import threading
import types
import zlib

FILE_LIMIT, TOTAL_LIMIT, COUNT = 16 * 1024**2, 64 * 1024**2, 2048
PIN = re.compile(r'[0-9a-f]{64}\Z')
PENDING = []
SIGNAL_SCOPES = []
CANCELLATION_EVENTS = set()
CANCELLATION_UNCERTAIN = set()
SIGNALS = (signal.SIGINT, signal.SIGTERM)


class Refused(ValueError):
    pass


def need(value, reason):
    cancellation_checkpoint()
    if not value:
        raise Refused(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def bounded_tar_payload(raw, limit=32 * 1024**2):
    """Bound decompression before tar can allocate a hostile PAX/header body."""
    need(isinstance(raw, bytes) and 0 < len(raw) <= FILE_LIMIT, 'compressed archive byte bound')
    try:
        if raw.startswith(b'\xfd7zXZ\x00'):
            decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=64 * 1024**2)
            payload = decoder.decompress(raw, max_length=limit + 1)
            need(len(payload) <= limit and decoder.eof and not decoder.unused_data, 'xz expanded/trailing archive bound')
        elif raw.startswith(b'\x1f\x8b'):
            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
            payload = decoder.decompress(raw, limit + 1)
            need(len(payload) <= limit and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,
                 'gzip expanded/trailing archive bound')
        else:
            payload = raw
            need(len(payload) <= limit, 'raw archive byte bound')
    except (lzma.LZMAError, zlib.error):
        raise Refused('bounded archive decompression refused') from None
    return payload


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode()


def decode(raw):
    need(isinstance(raw, bytes) and 0 < len(raw) <= FILE_LIMIT, 'bounded JSON required')
    def pairs(rows):
        result = {}
        for name, value in rows:
            need(name not in result, 'duplicate JSON field')
            result[name] = value
        return result
    def invalid(_):
        raise Refused('JSON float/nonfinite refused')
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
    except (ValueError, UnicodeError, RecursionError):
        raise Refused('invalid JSON') from None
    need(isinstance(value, dict), 'JSON object required')
    return value


def relative(name):
    need(isinstance(name, str) and 0 < len(name) <= 512 and
         re.fullmatch(r'[A-Za-z0-9_./+:-]+', name) and
         not PurePosixPath(name).is_absolute() and PurePosixPath(name).as_posix() == name and
         all(part not in ('', '.', '..') for part in name.split('/')), 'unsafe relative path')
    return name


def identity(info):
    return tuple(getattr(info, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_nlink',
                 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


@contextmanager
def directory(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'absolute directory required')
    fds, identities = [], []
    try:
        fds.append(os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
        identities.append((Path('/'), os.fstat(fds[-1])))
        current = Path('/')
        for part in path.parts[1:]:
            fds.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fds[-1]))
            current /= part
            identities.append((current, os.fstat(fds[-1])))
        yield fds[-1]
        for current, before in identities:
            after = current.lstat()
            need((before.st_dev, before.st_ino, before.st_mode) == (after.st_dev, after.st_ino, after.st_mode),
                 'directory identity changed')
    finally:
        for fd in reversed(fds):
            os.close(fd)


def read(path, limit=FILE_LIMIT):
    path = Path(path).absolute()
    with directory(path.parent) as parent:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit,
                 'bounded single-link regular file required')
            data = stream.read(limit + 1)
            need(len(data) == before.st_size and identity(before) == identity(os.fstat(stream.fileno()))
                 == identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'read identity drift')
            return data


def tool_digest(path):
    """Hash installed tools incrementally; Docker binaries can exceed data bounds."""
    path = Path(path).absolute()
    with directory(path.parent) as parent:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                 0 < before.st_size <= 128 * 1024**2, 'bounded installed tool required')
            hasher, length = hashlib.sha256(), 0
            while chunk := os.read(fd, 65536):
                length += len(chunk)
                need(length <= 128 * 1024**2, 'tool hash byte bound')
                hasher.update(chunk)
            need(length == before.st_size and identity(before) == identity(os.fstat(fd)) ==
                 identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'tool hash identity drift')
            return hasher.hexdigest()
        finally:
            os.close(fd)


def write_new(path, raw, mode=0o600):
    path = Path(path).absolute()
    need(isinstance(raw, bytes) and len(raw) <= FILE_LIMIT, 'write byte bound')
    with directory(path.parent) as parent:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(parent)


def pinned(raw, pin):
    need(isinstance(pin, str) and PIN.fullmatch(pin) and digest(raw) == pin, 'external byte pin differs')
    return decode(raw)


def mapped(root, files, *, exact=True):
    root = Path(root).absolute()
    need(isinstance(files, dict) and 0 < len(files) <= COUNT, 'finite file map required')
    data, total = {}, 0
    for name, row in files.items():
        relative(name)
        need(isinstance(row, dict) and set(row) == {'sha256', 'bytes'} and
             isinstance(row['sha256'], str) and PIN.fullmatch(row['sha256']) and
             type(row['bytes']) is int and 0 <= row['bytes'] <= FILE_LIMIT, 'typed byte map required')
        raw = read(root / name)
        total += len(raw)
        need(total <= TOTAL_LIMIT and len(raw) == row['bytes'] and digest(raw) == row['sha256'], 'mapped bytes differ')
        data[name] = raw
    if exact:
        found = set()
        for current, dirs, names in os.walk(root, followlinks=False):
            for name in dirs:
                path = Path(current) / name
                need(not path.is_symlink(), 'mapped directory link refused')
            for name in names:
                found.add((Path(current) / name).relative_to(root).as_posix())
                need(len(found) <= COUNT, 'tree count bound')
        need(found == set(files), 'mapped tree extras or omissions')
    return data


def snapshot(root, pins, target):
    """Copy authenticated source bytes only; never read/import cached bytecode."""
    root, target = Path(root).absolute(), Path(target).absolute()
    need(isinstance(pins, dict) and 0 < len(pins) <= COUNT, 'source map required')
    captures = {}
    for name, row in pins.items():
        relative(name)
        need('__pycache__' not in Path(name).parts and not name.endswith(('.pyc', '.pyo')),
             'bytecode source refused')
        need(isinstance(row, dict) and set(row) == {'sha256', 'mode'} and
             type(row['mode']) is int and row['mode'] in (0o644, 0o755), 'source mode map required')
        raw = read(root / name)
        need(PIN.fullmatch(row['sha256']) and digest(raw) == row['sha256'] and
             stat.S_IMODE((root / name).lstat().st_mode) == row['mode'], 'source bytes/mode differ')
        captures[name] = raw
    need(sum(map(len, captures.values())) <= TOTAL_LIMIT, 'source total bound')
    with directory(target.parent):
        target.mkdir(mode=0o700)
    try:
        for name, raw in captures.items():
            dest = target / name
            dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            write_new(dest, raw, pins[name]['mode'])
        write_new(target / '.source-map.json', encoded(pins))
        for name in captures:
            need(read(root / name) == captures[name] == read(target / name), 'source changed during snapshot')
    except BaseException:
        shutil.rmtree(target)
        raise
    return target


def load_snapshot(root, names):
    """Execute verified source strings, not importlib's on-disk/PYC machinery."""
    root = Path(root)
    pins = decode(read(root / '.source-map.json'))
    for name, row in pins.items():
        need(digest(read(root / name)) == row['sha256'] and
             stat.S_IMODE((root / name).lstat().st_mode) == row['mode'], 'snapshot source drift')
    modules, old = {}, {}
    try:
        for name in names:
            need(name + '.py' in pins, 'module absent from authenticated snapshot')
            module = types.ModuleType(name)
            module.__file__ = str(root / (name + '.py'))
            old[name] = sys.modules.get(name)
            sys.modules[name] = module
            exec(compile(read(root / (name + '.py')), module.__file__, 'exec'), module.__dict__)
            modules[name] = module
        return modules
    finally:
        for name, previous in old.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous


def cancellation_state():
    """Closed live data: scopes may invoke only the two exact Source callbacks."""
    def number(value):
        return type(value) in (int, type(SIGNALS[0])) and value in SIGNALS
    if type(SIGNAL_SCOPES) is not list or len(SIGNAL_SCOPES) > 64 or type(PENDING) is not list or len(PENDING) > 64 or any(
            type(pending) is not list or any(not number(item) for item in pending) for pending in PENDING):
        raise Refused('cancellation scope registry differs')
    expected = {code.co_name: code for factory in (defer_cancellation, cancellation_handlers)
                for code in factory.__wrapped__.__code__.co_consts if type(code) is types.CodeType}
    for scope in SIGNAL_SCOPES:
        if type(scope) is not tuple or len(scope) != 3:
            raise Refused('cancellation scope row differs')
        callback, opaque, mask = scope
        if type(callback) is not types.FunctionType or type(callback.__name__) is not str or callback.__globals__ is not globals() or callback.__code__ is not expected.get(callback.__name__) or callback.__name__ not in ('remember', 'interrupted') or callback.__defaults__ is not None or callback.__kwdefaults__ is not None:
            raise Refused('cancellation scope callback differs')
        cells = callback.__closure__
        if callback.__name__ == 'remember':
            if type(cells) is not tuple or len(cells) != 1 or type(cells[0]) is not types.CellType or type(cells[0].cell_contents) is not list or any(not number(item) for item in cells[0].cell_contents):
                raise Refused('cancellation scope callback cells differ')
        elif cells is not None:
            raise Refused('cancellation scope callback cells differ')
        if type(opaque) is not tuple or len(opaque) > 2 or any(not number(item) for item in opaque) or len(set(opaque)) != len(opaque) or type(mask) is not set or any(type(item) not in (int, type(SIGNALS[0])) for item in mask):
            raise Refused('cancellation scope signal data differs')
    if type(CANCELLATION_EVENTS) is not set or len(CANCELLATION_EVENTS) > 3 or any(
            not number(item) and not (type(item) is str and item == 'INTERRUPT') for item in CANCELLATION_EVENTS):
        raise Refused('cancellation event registry differs')

    if type(CANCELLATION_UNCERTAIN) is not set or any(type(item) is not str or item not in
            ('block','set','get','handler','pending','wait','mask','registry','replay') for item in CANCELLATION_UNCERTAIN):
        raise Refused('cancellation uncertainty registry differs')


def cancellation_requested():
    """Sticky closed signal disposition, independent of the primary failure."""
    cancellation_state()
    return bool(CANCELLATION_EVENTS)


def cancellation_checkpoint():
    """Opaque native handlers stay untouched; main-thread guards poll blocked INT/TERM."""
    if SIGNAL_SCOPES:
        cancellation_state()
        handler, opaque, _ = SIGNAL_SCOPES[-1]
        queued = []
        pending = signal.sigpending()
        for number in opaque:
            if number in pending:
                signal.sigwait({number})
                queued.append(number)
        for number in queued:
            handler(number, None)


def wait_process(process, deadline):
    """Preserve cancellation checkpoints even after both command pipes reach EOF."""
    while True:
        cancellation_checkpoint()
        left = deadline - time.monotonic()
        if left <= 0:
            raise subprocess.TimeoutExpired(process.args, 0)
        try:
            return process.wait(timeout=min(.05, left))
        except subprocess.TimeoutExpired:
            if time.monotonic() >= deadline:
                raise


def cancellation_uncertain():
    cancellation_state()
    return bool(CANCELLATION_UNCERTAIN)


def _raise_signal_faults(body_error, faults):
    """Keep the original object primary and retain every distinct secondary cause."""
    if not faults:
        return
    causes = []
    if body_error is not None and body_error.__cause__ is not None:
        causes.append(body_error.__cause__)
    for fault in faults:
        if fault is not body_error and not any(fault is item for item in causes):
            causes.append(fault)
    if not causes:
        return
    cause = causes[0] if len(causes) == 1 else BaseExceptionGroup('signal teardown failed', causes)
    if body_error is not None:
        raise body_error from cause
    raise cause


@contextmanager
def _signal_handlers(handler):
    global SIGNAL_SCOPES, CANCELLATION_EVENTS, CANCELLATION_UNCERTAIN
    if threading.current_thread() is not threading.main_thread():
        raise Refused('main-thread cancellation required')
    cancellation_state()
    registry, events, uncertain = SIGNAL_SCOPES, CANCELLATION_EVENTS, CANCELLATION_UNCERTAIN
    prefix = tuple(registry)
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
    previous = {}
    scope = None
    body_error = None
    try:
        previous = {number: signal.getsignal(number) for number in SIGNALS}
        inherited = registry[-1][1] if registry else ()
        opaque = tuple(number for number in SIGNALS if previous[number] is None and
                       (number not in mask or number in inherited))
        for number, original in previous.items():
            if original is not None:
                signal.signal(number, handler)
        scope = (handler, opaque, set(mask))
        registry.append(scope)
        signal.pthread_sigmask(signal.SIG_SETMASK, set(mask) | {
            number for number, original in previous.items() if original is None})
        yield
    except BaseException as error:
        body_error = error
        raise
    finally:
        faults, queued, unsafe = [], [], set()
        def failed(site, error):
            uncertain.add(site)
            if isinstance(error, KeyboardInterrupt):
                events.add('INTERRUPT')
            faults.append(error)
        try:
            blocked = False
            for _ in range(2):
                try:
                    signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
                    blocked = True
                    break
                except BaseException as error:
                    failed('block', error)
            if not blocked:
                unsafe.update(SIGNALS)
            for number, original in previous.items():
                if original is None:
                    continue
                if not blocked:
                    # No safe restoration transaction was established.
                    unsafe.add(number)
                    uncertain.add('handler')
                    continue
                restored = False
                for _ in range(2):
                    try:
                        signal.signal(number, original)
                    except BaseException as error:
                        failed('set', error)
                    try:
                        restored = signal.getsignal(number) == original
                    except BaseException as error:
                        failed('get', error)
                    if restored:
                        break
                if not restored:
                    unsafe.add(number)
                    failed('get', Refused('signal handler restoration differs'))
            if blocked:
                for number in SIGNALS:
                    if number in mask and (scope is None or number not in scope[1]):
                        continue
                    try:
                        pending = number in signal.sigpending()
                    except BaseException as error:
                        unsafe.add(number)
                        failed('pending', error)
                        continue
                    if pending:
                        # An observed eligible event is cancellation even if consumption fails.
                        queued.append(number)
                        consumed = False
                        for _ in range(2):
                            try:
                                signal.sigwait({number})
                                consumed = True
                                break
                            except BaseException as error:
                                failed('wait', error)
                        if not consumed:
                            unsafe.add(number)
        finally:
            try:
                expected = prefix + ((scope,) if scope is not None else ())
                if SIGNAL_SCOPES is not registry or len(registry) != len(expected) or any(
                        actual is not wanted for actual, wanted in zip(registry, expected)):
                    failed('registry', Refused('signal scope restoration differs'))
                registry[:] = prefix
                SIGNAL_SCOPES = registry
                if CANCELLATION_EVENTS is not events:
                    failed('registry', Refused('signal event registry differs'))
                    CANCELLATION_EVENTS = events
                if CANCELLATION_UNCERTAIN is not uncertain:
                    failed('registry', Refused('signal uncertainty registry differs'))
                    CANCELLATION_UNCERTAIN = uncertain
            finally:
                # Failed consumption/checks cannot safely expose pending unblocked defaults.
                target_mask = set(mask) | unsafe
                if unsafe:
                    uncertain.add('mask')
                for _ in range(2):
                    try:
                        signal.pthread_sigmask(signal.SIG_SETMASK, target_mask)
                        break
                    except BaseException as error:
                        failed('mask', error)
        for number in queued:
            try:
                handler(number, None)
            except BaseException as error:
                if isinstance(error, KeyboardInterrupt):
                    events.add(number)
                    faults.append(error)
                else:
                    failed('replay', error)
        _raise_signal_faults(body_error, faults)

@contextmanager
def defer_cancellation():
    pending = []
    body_error = None
    def remember(sig, _):
        CANCELLATION_EVENTS.add(sig)
        pending.append(sig)
    try:
        with _signal_handlers(remember):
            PENDING.append(pending)
            try:
                yield
            finally:
                PENDING.pop()
    except BaseException as error:
        body_error = error
        raise
    finally:
        if pending:
            if PENDING:
                PENDING[-1].extend(pending)
            elif body_error is not None:
                _raise_signal_faults(body_error, [KeyboardInterrupt('cancelled')])
            else:
                raise KeyboardInterrupt('cancelled')


@contextmanager
def cancellation_handlers():
    def interrupted(*_):
        CANCELLATION_EVENTS.add(_[0])
        raise KeyboardInterrupt('cancelled')
    with _signal_handlers(interrupted):
        yield


def limits():
    # Owned child setup: polling blocks belong to its parent, not the exec target.
    if SIGNAL_SCOPES:
        cancellation_state()
        signal.pthread_sigmask(signal.SIG_SETMASK, SIGNAL_SCOPES[0][2])
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    resource.setrlimit(resource.RLIMIT_CPU, (45, 46))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    resource.setrlimit(resource.RLIMIT_FSIZE, (TOTAL_LIMIT, TOTAL_LIMIT))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


class Commands:
    def __init__(self, work, allowed=('docker',), *, timeout=45, total_seconds=300):
        self.work = Path(work)
        self.paths = {}
        for name in allowed:
            path = shutil.which(name, path='/usr/bin:/bin')
            need(path is not None, 'required tool absent')
            self.paths[name] = Path(path).resolve()
        self.pins = {name: tool_digest(path) for name, path in self.paths.items()}
        self.env = {'PATH': '/usr/bin:/bin', 'HOME': str(self.work), 'GNUPGHOME': str(self.work / 'signing-home'),
                    'LC_ALL': 'C', 'TZ': 'UTC', 'TMPDIR': str(self.work)}
        self.records = []
        self.timeout = timeout
        self.deadline = time.monotonic() + total_seconds

    def teardown(self):
        self.timeout = 10
        self.deadline = time.monotonic() + 30

    def run(self, argv, expected=0):
        argv = [str(value) for value in argv]
        name = Path(argv[0]).name
        need(name in self.paths and (argv[0] == name or Path(argv[0]).resolve() == self.paths[name]), 'unreviewed tool')
        need(tool_digest(self.paths[name]) == self.pins[name], 'tool changed before command')
        argv[0] = str(self.paths[name])
        process, out, err = None, bytearray(), bytearray()
        started = time.monotonic()
        deadline = min(self.deadline, started + self.timeout)
        selector = selectors.DefaultSelector()
        try:
            need(started < deadline, 'whole command budget exhausted')
            with defer_cancellation():
                process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           env=self.env, cwd=self.work, start_new_session=True, preexec_fn=limits)
            for stream, dest in ((process.stdout, out), (process.stderr, err)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, dest)
            while selector.get_map():
                need(time.monotonic() < deadline, 'command deadline exceeded')
                for key, _ in selector.select(min(.05, max(0, deadline - time.monotonic()))):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if chunk:
                        key.data.extend(chunk)
                        need(len(out) + len(err) <= 1024**2, 'command output bound exceeded')
                    else:
                        selector.unregister(key.fileobj)
            code = wait_process(process, deadline)
            need(expected is None or (code == 0 if expected == 0 else code != 0), 'command exit differs')
            need(tool_digest(self.paths[name]) == self.pins[name], 'tool changed after command')
            self.records.append({'argv': argv, 'exit_code': code, 'stdout_sha256': digest(bytes(out)),
                                 'stderr_sha256': digest(bytes(err)), 'stdout_bytes': len(out), 'stderr_bytes': len(err)})
            return bytes(out), bytes(err)
        finally:
            with defer_cancellation():
                selector.close()
                if process is not None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    wait_process(process, time.monotonic() + 10)
                    process.stdout.close()
                    process.stderr.close()


def run_owned(image_id, source_root, inputs_root, output_root, worker_args, expected_arch='aarch64'):
    with cancellation_handlers():
        return _run_owned(image_id, source_root, inputs_root, output_root, worker_args, expected_arch)


def _run_owned(image_id, source_root, inputs_root, output_root, worker_args, expected_arch='aarch64'):
    """Create/register CID before start; cleanup by proven ID plus name absence."""
    need(re.fullmatch(r'sha256:[0-9a-f]{64}', image_id or ''), 'immutable image ID required')
    need(expected_arch == 'aarch64', 'native ARM scope required')
    source_root, inputs_root, output_root = map(lambda p: Path(p).absolute(), (source_root, inputs_root, output_root))
    source_pin = digest(read(source_root / '.source-map.json'))
    pins = decode(read(source_root / '.source-map.json'))
    need({'worker.py', 'common.py', 'base.py'} <= set(pins), 'authenticated worker closure required')
    for name, row in pins.items():
        need(digest(read(source_root / name)) == row['sha256'], 'worker source drift')
    for path in (source_root, inputs_root, output_root):
        with directory(path):
            pass
    need(not any(a == b or a in b.parents or b in a.parents for a, b in
                 ((source_root, inputs_root), (source_root, output_root), (inputs_root, output_root))), 'worker mount overlap')
    name = 'cachy-asahi-repository-client-' + os.urandom(16).hex()
    result = {'status': 'FAIL', 'image_id': image_id, 'container': name, 'container_id': None, 'ownership_verified': False, 'name_absence_verified': False,
              'id_absence_verified': False, 'absence_verified': False}
    with tempfile.TemporaryDirectory(prefix='cachy-asahi-rcn-owner-') as temporary:
        work = Path(temporary)
        commands = Commands(work)
        cidfile = work / 'container-id'
        cid = None
        submitted = False
        original = None
        try:
            daemon, _ = commands.run(['docker', 'info', '--format', '{{.Architecture}}'])
            need(daemon.strip() in (b'aarch64', b'arm64'), 'non-native Docker daemon refused')
            raw, _ = commands.run(['docker', 'image', 'inspect', image_id])
            image = json.loads(raw)
            need(len(image) == 1 and image[0]['Id'] == image_id and image[0]['Architecture'] == 'arm64'
                 and image[0]['Os'] == 'linux', 'native immutable image differs')
            need(worker_args and worker_args[0] == '/source/base.py', 'reviewed worker entry required')
            create = ['docker', 'create', '--name', name, '--cidfile', cidfile, '--pull=never', '--platform=linux/arm64',
                      '--user', f'{os.getuid()}:{os.getgid()}', '--network=none', '--cap-drop=ALL',
                      '--security-opt=no-new-privileges', '--read-only', '--pids-limit=128', '--memory=2g', '--cpus=2',
                      '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777']
            for source, dest, readonly in ((source_root, '/source', True), (inputs_root, '/inputs', True), (output_root, '/out', False)):
                need(',' not in str(source), 'mount path separator refused')
                create += ['--mount', f'type=bind,src={source},dst={dest}' + (',readonly' if readonly else '')]
            create += ['--entrypoint=/usr/bin/python3', image_id, '-I', '-B', '/source/worker.py',
                       '--source-map-sha256', source_pin, '--module', 'base', *worker_args[1:]]
            submitted = True
            commands.run(create)
            cid = read(cidfile, 128).decode().strip()
            need(re.fullmatch(r'[0-9a-f]{64}', cid), 'full creation CID required')
            result['container_id'] = cid
            raw, _ = commands.run(['docker', 'container', 'inspect', cid])
            observed = json.loads(raw)
            need(len(observed) == 1 and observed[0]['Id'] == cid and observed[0]['Name'] == '/' + name
                 and observed[0]['Image'] == image_id, 'created container ownership differs')
            result['ownership_verified'] = True
            commands.run(['docker', 'start', '--attach', cid])
            raw, _ = commands.run(['docker', 'container', 'inspect', cid])
            observed = json.loads(raw)[0]
            need(observed['Id'] == cid and observed['State']['Status'] == 'exited' and
                 type(observed['State']['ExitCode']) is int and observed['State']['ExitCode'] == 0,
                 'worker terminal exit differs')
            result['status'] = 'PASS'
        except BaseException as error:
            original = error
            result['error_type'] = type(error).__name__
        finally:
            try:
                with defer_cancellation():
                    commands.teardown()
                    if submitted:
                        if cid is None and cidfile.exists():
                            cid = read(cidfile, 128).decode().strip()
                        need(cid is not None and re.fullmatch(r'[0-9a-f]{64}', cid), 'creation CID absent; cleanup uncertain')
                        result['container_id'] = cid
                        raw, _ = commands.run(['docker', 'container', 'inspect', cid])
                        owned = json.loads(raw)
                        need(len(owned) == 1 and owned[0]['Id'] == cid and owned[0]['Name'] == '/' + name
                             and owned[0]['Image'] == image_id, 'cleanup ownership differs')
                        result['container_id'] = cid
                        commands.run(['docker', 'container', 'rm', '-f', cid])
                        listing, _ = commands.run(['docker', 'container', 'ls', '-a', '--no-trunc', '--format', '{{.ID}} {{.Names}}'])
                        rows = [line.split() for line in listing.decode().splitlines()]
                        need(all(len(row) == 2 and re.fullmatch(r'[0-9a-f]{64}', row[0]) for row in rows), 'cleanup daemon query malformed')
                        result['id_absence_verified'] = all(row[0] != cid for row in rows)
                        result['name_absence_verified'] = all(name not in row[1].split(',') for row in rows)
                        need(result['id_absence_verified'] and result['name_absence_verified'], 'container name or ID remains')
                        result['absence_verified'] = True
                    result['cleanup'] = 'PASS' if not submitted or result['absence_verified'] else 'FAIL'
            except BaseException as error:
                result.update(status='FAIL', cleanup='FAIL', cleanup_error_type=type(error).__name__)
                original = original or error
            result['commands'] = commands.records
            result['tool_sha256'] = commands.pins
            for filename, row in pins.items():
                if digest(read(source_root / filename)) != row['sha256']:
                    result['status'] = 'FAIL'
                    original = original or Refused('worker source changed')
        if original is not None:
            setattr(original, 'receipt', result)
            raise original
        return result
