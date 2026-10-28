"""Bounded private process groups and registered /tmp directory teardown.

No command, environment, output text or filesystem path appears in receipts.
Linux subreaper state is process-local and restored after owned group cleanup.
"""
import ctypes
import errno
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time

TERM_GRACE = 10
KILL_REAP = 3
MAX_LOG = 16 * 1024**2
MAX_MEMBERS = 200000
MAX_DISK = 16 * 1024**3
MARKER = '.cachy-asahi-owned.json'
_REGISTERED = {}


class Receipt(dict):
    """JSON-compatible, typed lifecycle evidence."""


class RuntimeFailure(RuntimeError):
    def __init__(self, receipt):
        self.receipt = receipt
        super().__init__(receipt['reason_code'])


class RuntimeCancelled(RuntimeFailure):
    pass


class _Cancel(BaseException):
    pass


class _Fault(Exception):
    def __init__(self, code):
        self.code = code


def _need(value, code):
    if not value:
        raise _Fault(code)


def _signals():
    result = {signal.SIGTERM, signal.SIGINT}
    if signal.getitimer(signal.ITIMER_REAL)[0] or callable(signal.getsignal(signal.SIGALRM)):
        result.add(signal.SIGALRM)
    return result


class _SignalScope:
    def __init__(self):
        self.signals, self.cancelled, self.defer = _signals(), [], False

    def handler(self, number, _frame):
        if number not in self.cancelled:
            self.cancelled.append(number)

    def __enter__(self):
        prior = signal.pthread_sigmask(signal.SIG_BLOCK, self.signals)
        self.handlers = {s: signal.getsignal(s) for s in self.signals}
        try:
            for s in self.signals:
                signal.signal(s, self.handler)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, prior)
        return self

    def defer_now(self):
        prior = signal.pthread_sigmask(signal.SIG_BLOCK, self.signals)
        self.defer = True
        signal.pthread_sigmask(signal.SIG_SETMASK, prior)

    def finish(self):
        """Consume deferred pending events before restoring caller handlers."""
        prior = signal.pthread_sigmask(signal.SIG_BLOCK, self.signals)
        failed = False
        try:
            for _ in range(8):
                pending = signal.sigpending() & self.signals
                if not pending:
                    break
                for s in pending:
                    self.handler(s, None)
                signal.sigtimedwait(self.signals, 0)
            else:
                pending = signal.sigpending() & self.signals
                for s in pending:
                    self.handler(s, None)
                failed = bool(pending)
        except BaseException:
            failed = True
        finally:
            try:
                for s, handler in self.handlers.items():
                    try:
                        signal.signal(s, handler)
                    except BaseException:
                        failed = True
            finally:
                try:
                    signal.pthread_sigmask(signal.SIG_SETMASK, prior)
                except BaseException:
                    failed = True
        _need(not failed, 'signal-state-restore')


def _check_cancel(scope):
    if scope.cancelled:
        raise _Cancel()


def _subreaper(value=None):
    # linux/prctl.h: PR_SET_CHILD_SUBREAPER=36, PR_GET_CHILD_SUBREAPER=37.
    libc = ctypes.CDLL(None, use_errno=True)
    result = ctypes.c_int()
    if value is None:
        status = libc.prctl(37, ctypes.byref(result), 0, 0, 0)
    else:
        status = libc.prctl(36, int(value), 0, 0, 0)
    _need(status == 0, 'subreaper-unavailable')
    return result.value


def _group_exists(group):
    try:
        os.killpg(group, 0)
        return True
    except ProcessLookupError:
        return False


def _reap_group(child):
    reaped = 0
    if child.poll() is None:
        return reaped
    while True:
        try:
            pid, _ = os.waitpid(-child.pid, os.WNOHANG)
        except ChildProcessError:
            return reaped
        if not pid:
            return reaped
        reaped += 1


def _teardown(child, deadline, drain):
    result = {'group_absent': child is None, 'group_reaped': 0, 'teardown_errors': []}
    if child is None:
        return result
    group = child.pid
    kill_end = None
    try:
        if _group_exists(group):
            try:
                os.killpg(group, signal.SIGTERM)
            except ProcessLookupError:
                pass
        grace = time.monotonic() + TERM_GRACE
        while time.monotonic() < grace:
            drain()
            result['group_reaped'] += _reap_group(child)
            if not _group_exists(group):
                break
            time.sleep(.1)
        if _group_exists(group):
            try:
                os.killpg(group, signal.SIGKILL)
            except ProcessLookupError:
                pass
        kill_end = time.monotonic() + KILL_REAP
        while time.monotonic() < kill_end:
            drain()
            result['group_reaped'] += _reap_group(child)
            if not _group_exists(group) and child.poll() is not None:
                result['group_absent'] = True
                break
            time.sleep(.1)
        if child.poll() is None:
            result['teardown_errors'].append('direct-child-not-reaped')
        if not result['group_absent']:
            result['teardown_errors'].append('process-group-remains')
        drain()
    except BaseException:
        # A failure in observation/draining must not suppress a final kill.
        result['teardown_errors'].append('group-cleanup-error')
        try:
            os.killpg(group, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except BaseException:
            result['teardown_errors'].append('group-kill-error')
        try:
            if kill_end is None:
                kill_end = time.monotonic() + KILL_REAP
            child.wait(timeout=max(0, kill_end - time.monotonic()))
            result['group_reaped'] += _reap_group(child)
            result['group_absent'] = not _group_exists(group)
        except BaseException:
            result['teardown_errors'].append('group-reap-error')
    return result


def _log(path):
    path = Path(path).absolute()
    _need(not any(p.is_symlink() for p in (path, *path.parents)), 'unsafe-log')
    info = path.parent.stat()
    _need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'nonprivate-log-parent')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _pid_start(pid):
    data = Path('/proc/' + str(pid) + '/stat').read_text()
    return int(data.rsplit(')', 1)[1].split()[19])


def run_process(argv, stdout_path, stderr_path, deadline, env, cwd, on_tick=None, on_spawn=None):
    """Run one owned session; safe typed exceptions carry failure receipts.

    deadline is absolute time.monotonic(). on_tick has no arguments. on_spawn
    receives private {pid,group,start_ticks} while cancellation is masked. The
    stdout/stderr paths must be fresh files in an owned0700 private directory.
    """
    receipt = Receipt(kind='process-lifecycle', schema_version=1, status='FAIL', reason_code='runtime-failed',
                      returncode=None, stdout_bytes=0, stderr_bytes=0, group_absent=True,
                      group_reaped=0, teardown_errors=[], cancelled_signals=[])
    child, scope, prior_reaper, selector, logs = None, None, None, None, []
    streams = {}
    error = None
    try:
        _need(isinstance(deadline, (float, int)) and math.isfinite(deadline), 'invalid-deadline')
        _need(time.monotonic() < deadline, 'timeout')
        _need(isinstance(argv, (list, tuple)) and argv and all(isinstance(x, str) and '\0' not in x for x in argv), 'invalid-command')
        scope = _SignalScope()
        scope.__enter__()
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, scope.signals)
        try:
            logs.append(_log(stdout_path))
            logs.append(_log(stderr_path))
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        prior_reaper = _subreaper()
        _subreaper(1)
        _check_cancel(scope)
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, scope.signals)
        try:
            def child_mask():
                for s in scope.signals:
                    signal.signal(s, signal.SIG_DFL)
                signal.pthread_sigmask(signal.SIG_SETMASK, mask)
            try:
                child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         stdin=subprocess.DEVNULL, env=env, cwd=cwd,
                                         start_new_session=True, preexec_fn=child_mask)
            except Exception:
                raise _Fault('spawn-failed') from None
            # Registration is complete before pending cancellation is unmasked.
            receipt['group_absent'] = False
            if on_spawn:
                try:
                    identity = {'pid': child.pid, 'group': child.pid, 'start_ticks': _pid_start(child.pid)}
                    on_spawn(identity)
                except Exception:
                    raise _Fault('registration-failed') from None
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        _check_cancel(scope)
        selector = selectors.DefaultSelector()
        for stream, fd, field in ((child.stdout, logs[0], 'stdout_bytes'), (child.stderr, logs[1], 'stderr_bytes')):
            os.set_blocking(stream.fileno(), False)
            streams[stream] = (fd, field)
            selector.register(stream, selectors.EVENT_READ)

        def drain(wait=0):
            if selector is None:
                return
            for key, _ in selector.select(wait):
                data = os.read(key.fileobj.fileno(), 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                fd, field = streams[key.fileobj]
                remaining = MAX_LOG - receipt[field]
                retained = data[:remaining]
                view = memoryview(retained)
                while view:
                    count = os.write(fd, view)
                    _need(count > 0, 'log-write')
                    view = view[count:]
                receipt[field] += len(retained)
                if len(data) > remaining:
                    raise _Fault('log-limit')

        while selector.get_map() or child.poll() is None:
            _check_cancel(scope)
            _need(time.monotonic() < deadline, 'timeout')
            if on_tick:
                try:
                    on_tick()
                except _Cancel:
                    raise
                except Exception:
                    raise _Fault('tick-failed') from None
            drain(min(.1, max(0, deadline - time.monotonic())))
        _check_cancel(scope)
        receipt['returncode'] = child.wait(timeout=max(.001, deadline - time.monotonic()))
        error = None if receipt['returncode'] == 0 else 'process-failed'
    except _Cancel:
        error = 'cancelled'
    except _Fault as fault:
        error = fault.code
    except BaseException:
        error = 'runtime-failed'
    finally:
        try:
            if scope:
                scope.defer_now()
            # Spawn-gap cancellation may happen before pipes are registered.
            if child is not None and selector is None:
                selector = selectors.DefaultSelector()
                for stream, fd, field in ((child.stdout, logs[0], 'stdout_bytes'), (child.stderr, logs[1], 'stderr_bytes')):
                    os.set_blocking(stream.fileno(), False)
                    streams[stream] = (fd, field)
                    selector.register(stream, selectors.EVENT_READ)
            def final_drain():
                if selector is None:
                    return
                for _ in range(1024):
                    ready = selector.select(0)
                    if not ready:
                        break
                    for key, _ in ready:
                            data = os.read(key.fileobj.fileno(), 65536)
                            if not data:
                                selector.unregister(key.fileobj)
                            else:
                                fd, field = streams[key.fileobj]
                                retained = data[:max(0, MAX_LOG - receipt[field])]
                                view = memoryview(retained)
                                while view:
                                    count = os.write(fd, view)
                                    if count <= 0:
                                        raise _Fault('log-write')
                                    view = view[count:]
                                receipt[field] += len(retained)
            receipt.update(_teardown(child, deadline, final_drain))
            if child is not None:
                receipt['returncode'] = child.returncode
            for resource in ([selector] if selector else []) + list(streams):
                try:
                    resource.close()
                except BaseException:
                    receipt['teardown_errors'].append('runtime-close-error')
            for fd in logs:
                try:
                    os.close(fd)
                except BaseException:
                    receipt['teardown_errors'].append('runtime-close-error')
            if prior_reaper is not None:
                try:
                    _subreaper(prior_reaper)
                except BaseException:
                    receipt['teardown_errors'].append('subreaper-restore-error')
        except BaseException:
            receipt['teardown_errors'].append('runtime-teardown-error')
        finally:
            if scope:
                try:
                    scope.finish()
                except (KeyboardInterrupt, _Cancel, RuntimeCancelled):
                    error = 'cancelled'
                except BaseException:
                    receipt['teardown_errors'].append('signal-restore-error')
                receipt['cancelled_signals'] = sorted(scope.cancelled)
                if scope.cancelled:
                    error = 'cancelled'
    if error == 'cancelled' and not receipt['teardown_errors'] and receipt['group_absent']:
        receipt.update(status='CANCELLED', reason_code='cancelled')
        raise RuntimeCancelled(receipt) from None
    if receipt['teardown_errors'] or not receipt['group_absent']:
        error = 'group-cleanup' if error == 'cancelled' else error or 'group-cleanup'
    if error:
        receipt.update(status='FAIL', reason_code=error)
        raise RuntimeFailure(receipt) from None
    receipt.update(status='PASS', reason_code=None)
    return receipt


def _identity(parent, name, token):
    parent = Path(parent).absolute()
    _need(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,95}', name or '') and name not in ('.', '..'), 'unsafe-owned-name')
    _need(re.fullmatch(r'[a-f0-9]{32}', token or ''), 'invalid-owned-token')
    _need(parent.is_relative_to('/tmp') and parent.resolve(strict=True) == parent
          and not any(p.is_symlink() for p in (parent, *parent.parents)), 'unsafe-owned-parent')
    return parent, name, token


def owned_create(parent, childname, token):
    """Create and register only a fresh0700 child; caller retains nonce/name."""
    scope, parentfd, childfd = None, None, None
    created = False
    mask = None
    try:
        parent, name, token = _identity(parent, childname, token)
        scope = _SignalScope()
        scope.defer = True
        scope.__enter__()
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, scope.signals)
        parentfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parentinfo = os.fstat(parentfd)
        os.mkdir(name, 0o700, dir_fd=parentfd)
        created = True
        info = os.stat(name, dir_fd=parentfd, follow_symlinks=False)
        _REGISTERED[(str(parent), name, token)] = {'parent': (parentinfo.st_dev, parentinfo.st_ino),
                    'child': (info.st_dev, info.st_ino), 'uid': os.getuid(), 'complete': False}
        childfd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parentfd)
        fd = os.open(MARKER, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=childfd)
        try:
            markerinfo = os.fstat(fd)
            _REGISTERED[(str(parent), name, token)]['marker'] = (markerinfo.st_dev, markerinfo.st_ino)
            data = json.dumps({'nonce': token, 'uid': os.getuid()}, sort_keys=True).encode() + b'\n'
            view = memoryview(data)
            while view:
                count = os.write(fd, view)
                _need(count > 0, 'owned-marker-write')
                view = view[count:]
            os.fsync(fd)
        finally:
            os.close(fd)
        _REGISTERED[(str(parent), name, token)]['complete'] = True
    except BaseException:
        if not created:
            raise RuntimeFailure(Receipt(kind='owned-directory', status='FAIL', reason_code='owned-create-refused', registered=False)) from None
        raise RuntimeFailure(Receipt(kind='owned-directory', status='FAIL', reason_code='owned-create-partial', registered=True)) from None
    finally:
        if mask is not None:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        close_failed = False
        for fd in (childfd, parentfd):
            if fd is not None:
                try:
                    os.close(fd)
                except BaseException:
                    close_failed = True
        if scope:
            try:
                scope.finish()
            except BaseException:
                close_failed = True
            if scope.cancelled and not close_failed:
                raise RuntimeCancelled(Receipt(kind='owned-directory', status='CANCELLED', reason_code='cancelled', registered=created)) from None
        if close_failed:
            raise RuntimeFailure(Receipt(kind='owned-directory', status='FAIL', reason_code='owned-create-close-failed', registered=created)) from None
    return parent / name


def _record_validate(parent, name, token, record):
    required = {'parent', 'child', 'uid', 'complete'}
    _need(required <= set(record) <= required | {'marker'}, 'invalid-owned-record')
    _need(type(record['uid']) is int and record['uid'] == os.getuid()
          and type(record['complete']) is bool, 'invalid-owned-record')
    for field in ('parent', 'child', *(['marker'] if 'marker' in record else [])):
        pair = record[field]
        _need(isinstance(pair, (list, tuple)) and len(pair) == 2
              and all(type(v) is int and v >= 0 for v in pair), 'invalid-owned-record')
    _need(not record['complete'] or 'marker' in record, 'invalid-owned-record')
    root = parent / name
    _need(not any(p == str(root) or p.startswith(str(root) + '/') for p in _mounts()), 'owned-mount-refused')
    parentinfo = parent.stat()
    info = root.lstat()
    _need(tuple(record['parent']) == (parentinfo.st_dev, parentinfo.st_ino)
          and tuple(record['child']) == (info.st_dev, info.st_ino)
          and info.st_dev == parentinfo.st_dev and info.st_uid == record['uid']
          and stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700, 'owned-identity-changed')
    marker = root / MARKER
    try:
        fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        _need(not record['complete'], 'owned-marker-missing')
    else:
        try:
            observed = os.fstat(fd)
            _need(tuple(record.get('marker', ())) == (observed.st_dev, observed.st_ino)
                  and stat.S_ISREG(observed.st_mode) and observed.st_uid == record['uid']
                  and observed.st_nlink == 1 and observed.st_size <= 4096
                  and stat.S_IMODE(observed.st_mode) == 0o600, 'unsafe-owned-marker')
            data = os.read(fd, 4097)
            expected = json.dumps({'nonce': token, 'uid': record['uid']}, sort_keys=True).encode() + b'\n'
            _need(data == expected if record['complete'] else data == expected[:len(data)], 'owned-marker-mismatch')
        finally:
            os.close(fd)


def owned_record(parent, childname, token):
    """Copy original ownership facts for a caller-authenticated private receipt."""
    try:
        parent, name, token = _identity(parent, childname, token)
        record = _REGISTERED.get((str(parent), name, token))
        _need(record is not None, 'owned-not-registered')
        _record_validate(parent, name, token, record)
        return {'schema_version': 1, 'nonce': token,
                **{k: list(v) if isinstance(v, tuple) else v for k, v in record.items()}}
    except BaseException:
        raise RuntimeFailure(Receipt(kind='owned-directory', status='FAIL', reason_code='owned-record-refused')) from None


def owned_adopt(parent, childname, token, record):
    """Restore exact ownership after the caller authenticates its external pin.

    This function cannot authenticate a JSON record's origin or prove the old
    process dead. The recovery controller must establish both before calling.
    """
    try:
        parent, name, token = _identity(parent, childname, token)
        _need(isinstance(record, dict) and record.get('schema_version') == 1
              and record.get('nonce') == token, 'invalid-owned-record')
        value = {k: v for k, v in record.items() if k not in ('schema_version', 'nonce')}
        _record_validate(parent, name, token, value)
        value = {k: tuple(v) if k in ('parent', 'child', 'marker') else v for k, v in value.items()}
        key = (str(parent), name, token)
        _need(key not in _REGISTERED or _REGISTERED[key] == value, 'owned-registration-conflict')
        _REGISTERED[key] = value
    except BaseException:
        raise RuntimeFailure(Receipt(kind='owned-directory', status='FAIL', reason_code='owned-adopt-refused')) from None


def _mounts():
    paths = []
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        raw = line.split()[4]
        paths.append(re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), raw))
    return paths


def owned_remove(parent, childname, token, deadline):
    """Delete only this process's registered child via nofollow descriptor paths.

    Cancellation is deferred through cleanup then returned as CANCELLED. Foreign
    UID, regular hardlink, nested/bind mount, identity or bound errors are FAIL.
    """
    receipt = Receipt(kind='owned-directory', schema_version=1, status='FAIL', reason_code='cleanup-refused',
                      removed=False, members=0, bytes=0, deleted=0, cancelled_signals=[])
    scope, parentfd, childfd, key = None, None, None, None
    try:
        _need(isinstance(deadline, (float, int)) and math.isfinite(deadline), 'invalid-deadline')
        end = min(deadline, time.monotonic() + 120)
        parent, name, token = _identity(parent, childname, token)
        key = (str(parent), name, token)
        registered = _REGISTERED.get(key)
        _need(registered is not None, 'owned-not-registered')
        scope = _SignalScope()
        scope.defer = True
        scope.__enter__()
        parentfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parentinfo = os.fstat(parentfd)
        _need((parentinfo.st_dev, parentinfo.st_ino) == registered['parent'], 'owned-parent-changed')
        root = parent / name
        _need(not any(p == str(root) or p.startswith(str(root) + '/') for p in _mounts()), 'owned-mount-refused')
        childfd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parentfd)
        info = os.fstat(childfd)
        _need((info.st_dev, info.st_ino) == registered['child'] and info.st_dev == parentinfo.st_dev
              and info.st_uid == registered['uid'] == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
              'owned-identity-changed')
        try:
            fd = os.open(MARKER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=childfd)
        except FileNotFoundError:
            _need(not registered['complete'], 'owned-marker-missing')
        else:
            try:
                markerinfo = os.fstat(fd)
                _need(stat.S_ISREG(markerinfo.st_mode) and markerinfo.st_uid == info.st_uid
                      and markerinfo.st_nlink == 1 and markerinfo.st_size <= 4096
                      and stat.S_IMODE(markerinfo.st_mode) == 0o600, 'unsafe-owned-marker')
                _need((markerinfo.st_dev, markerinfo.st_ino) == registered.get('marker'), 'owned-marker-replaced')
                data = os.read(fd, 4097)
                expected = json.dumps({'nonce': token, 'uid': os.getuid()}, sort_keys=True).encode() + b'\n'
                if registered['complete']:
                    _need(data == expected, 'owned-marker-mismatch')
                else:
                    _need(data == expected[:len(data)], 'owned-partial-marker-mismatch')
                receipt['members'] = 1
                receipt['bytes'] = markerinfo.st_size
                _need(receipt['members'] <= MAX_MEMBERS, 'cleanup-member-bound')
                _need(receipt['bytes'] <= MAX_DISK, 'cleanup-disk-bound')
            finally:
                os.close(fd)

        def validate_root():
            _need(parent.resolve(strict=True) == parent, 'owned-parent-changed')
            current_parent = parent.stat()
            _need((current_parent.st_dev, current_parent.st_ino) == registered['parent'], 'owned-parent-changed')
            current_root = os.stat(name, dir_fd=parentfd, follow_symlinks=False)
            _need((current_root.st_dev, current_root.st_ino) == registered['child'], 'owned-root-changed')

        def delete(directory, depth=0):
            _need(depth <= 64, 'cleanup-depth-bound')
            validate_root()
            with os.scandir(directory) as entries:
                for entry in entries:
                    if depth == 0 and entry.name == MARKER:
                        continue
                    validate_root()
                    _need(time.monotonic() < end, 'cleanup-deadline')
                    receipt['members'] += 1
                    _need(receipt['members'] <= MAX_MEMBERS, 'cleanup-member-bound')
                    item = os.stat(entry.name, dir_fd=directory, follow_symlinks=False)
                    _need(item.st_uid == registered['uid'] and item.st_dev == info.st_dev, 'foreign-cleanup-entry')
                    if stat.S_ISDIR(item.st_mode):
                        _need(not any(p == str(root) or p.startswith(str(root) + '/') for p in _mounts()), 'owned-mount-refused')
                        fd = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                        try:
                            actual = os.fstat(fd)
                            _need((actual.st_dev, actual.st_ino) == (item.st_dev, item.st_ino), 'cleanup-entry-changed')
                            delete(fd, depth + 1)
                        finally:
                            os.close(fd)
                        current = os.stat(entry.name, dir_fd=directory, follow_symlinks=False)
                        _need((current.st_dev, current.st_ino, current.st_uid) == (item.st_dev, item.st_ino, item.st_uid), 'cleanup-entry-changed')
                        os.rmdir(entry.name, dir_fd=directory)
                    elif stat.S_ISREG(item.st_mode) or stat.S_ISLNK(item.st_mode):
                        _need(item.st_nlink == 1, 'cleanup-hardlink-refused')
                        receipt['bytes'] += item.st_size
                        _need(receipt['bytes'] <= MAX_DISK, 'cleanup-disk-bound')
                        current = os.stat(entry.name, dir_fd=directory, follow_symlinks=False)
                        _need((current.st_dev, current.st_ino, current.st_uid, current.st_nlink) ==
                              (item.st_dev, item.st_ino, item.st_uid, 1), 'cleanup-entry-changed')
                        os.unlink(entry.name, dir_fd=directory)
                    else:
                        raise _Fault('cleanup-special-entry')
                    receipt['deleted'] += 1
        delete(childfd)
        validate_root()
        _need(time.monotonic() < end, 'cleanup-deadline')
        try:
            final_marker = os.stat(MARKER, dir_fd=childfd, follow_symlinks=False)
            _need((final_marker.st_dev, final_marker.st_ino) == registered.get('marker')
                  and final_marker.st_uid == registered['uid'] and final_marker.st_nlink == 1, 'owned-marker-replaced')
            os.unlink(MARKER, dir_fd=childfd)
        except FileNotFoundError:
            _need(not registered['complete'], 'owned-marker-missing')
        current = os.stat(name, dir_fd=parentfd, follow_symlinks=False)
        _need((current.st_dev, current.st_ino) == registered['child'], 'owned-root-changed')
        os.rmdir(name, dir_fd=parentfd)
        try:
            os.stat(name, dir_fd=parentfd, follow_symlinks=False)
        except FileNotFoundError:
            receipt.update(status='PASS', reason_code=None, removed=True)
            _REGISTERED.pop(key)
        else:
            raise _Fault('owned-absence-unverified')
    except _Fault as error:
        receipt['reason_code'] = error.code
    except BaseException:
        receipt['reason_code'] = 'cleanup-io-failed'
    finally:
        for fd in (childfd, parentfd):
            if fd is not None:
                try:
                    os.close(fd)
                except BaseException:
                    receipt.update(status='FAIL', reason_code='cleanup-close-failed')
        if scope:
            signal_failed = False
            try:
                scope.finish()
            except (KeyboardInterrupt, _Cancel, RuntimeCancelled):
                receipt.update(status='CANCELLED', reason_code='cancelled')
            except BaseException:
                signal_failed = True
                receipt.update(status='FAIL', reason_code='cleanup-signal-state')
            receipt['cancelled_signals'] = sorted(scope.cancelled)
            if scope.cancelled and not signal_failed:
                receipt.update(status='CANCELLED', reason_code='cancelled')
    return receipt
