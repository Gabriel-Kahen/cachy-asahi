#!/usr/bin/env python3
"""Bounded local orchestration helpers; no package or trust mutation."""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import time

LIMIT = 8 * 1024**2
LOG_LIMIT = 4 * 1024**2
SIGNALS = {signal.SIGINT, signal.SIGTERM, signal.SIGALRM}


def require(condition, code):
    if not condition:
        raise ValueError(code)


def check_deadline(deadline):
    if deadline is None:
        return None
    valid = type(deadline) in (int, float)
    try:
        valid = valid and math.isfinite(deadline)
    except OverflowError:
        valid = False
    require(valid, 'stage-deadline-exceeded')
    remaining = deadline - time.monotonic()
    require(math.isfinite(remaining) and remaining > 0, 'stage-deadline-exceeded')
    return remaining


def _write(stream, data, deadline):
    check_deadline(deadline)
    require(stream.write(data) == len(data), 'stage-write-failed')
    check_deadline(deadline)


def read_regular(path, max_bytes=LIMIT, *, deadline=None):
    check_deadline(deadline)
    path = Path(path).absolute()
    require('..' not in path.parts, 'input-path-invalid')
    for parent in path.parents:
        check_deadline(deadline)
        require(stat.S_ISDIR(parent.lstat().st_mode), 'input-parent-invalid')
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= max_bytes,
            'regular-bounded-input-required')
    check_deadline(deadline)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        opened = os.fstat(stream.fileno())
        require(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1 and opened.st_size <= max_bytes and
                (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), 'input-changed')
        data = bytearray()
        while True:
            check_deadline(deadline)
            block = stream.read(min(65536, max_bytes + 1 - len(data)))
            check_deadline(deadline)
            if not block:
                break
            data.extend(block)
            require(len(data) <= max_bytes, 'regular-bounded-input-required')
        data = bytes(data)
        after = os.fstat(stream.fileno())
    require(len(data) <= max_bytes and len(data) == before.st_size and
            (before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_mode, before.st_nlink) ==
            (after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_mode, after.st_nlink), 'input-changed')
    require((path.lstat().st_dev, path.lstat().st_ino) == (before.st_dev, before.st_ino), 'input-changed')
    check_deadline(deadline)
    return data


def digest(path, *, deadline=None):
    check_deadline(deadline)
    path = Path(path).absolute()
    require('..' not in path.parts and all(stat.S_ISDIR(p.lstat().st_mode) for p in path.parents), 'input-parent-invalid')
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= 2 * 1024**3, 'regular-bounded-input-required')
    check_deadline(deadline)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        opened = os.fstat(stream.fileno())
        require(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1 and opened.st_size <= 2 * 1024**3 and
                (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), 'input-changed')
        hasher, total = hashlib.sha256(), 0
        while True:
            check_deadline(deadline)
            block = stream.read(1024**2)
            check_deadline(deadline)
            if not block:
                break
            total += len(block)
            require(total <= 2 * 1024**3, 'input-hash-bound-exceeded')
            hasher.update(block)
        result = hasher.hexdigest()
        after = os.fstat(stream.fileno())
    require((before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_mode, before.st_nlink) ==
            (after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_mode, after.st_nlink) and
            total == before.st_size and
            (path.lstat().st_dev, path.lstat().st_ino) == (before.st_dev, before.st_ino), 'input-changed')
    check_deadline(deadline)
    return result


def read_json(path, max_bytes=LIMIT, *, deadline=None):
    check_deadline(deadline)
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'duplicate-json-field')
            result[key] = value
        return result
    value = json.loads(read_regular(path, max_bytes, deadline=deadline).decode('utf-8'), object_pairs_hook=pairs,
                       parse_constant=lambda _: require(False, 'nonfinite-json'))
    require(isinstance(value, dict), 'json-object-required')
    check_deadline(deadline)
    return value


def save(path, value, *, deadline=None):
    check_deadline(deadline)
    path = Path(path)
    temporary, descriptor = None, None
    try:
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
        try:
            descriptor, name = tempfile.mkstemp(prefix=path.name + '.', suffix='.partial', dir=path.parent)
            temporary = Path(name)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        with os.fdopen(descriptor, 'w') as stream:
            descriptor = None
            if deadline is None:
                json.dump(value, stream, indent=2, sort_keys=True)
            else:
                for block in json.JSONEncoder(indent=2, sort_keys=True).iterencode(value):
                    _write(stream, block, deadline)
            _write(stream, '\n', deadline)
            stream.flush(); check_deadline(deadline); os.fsync(stream.fileno())
        check_deadline(deadline)
        temporary.replace(path)
        check_deadline(deadline)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def copy_regular(source, target, max_bytes=LIMIT, *, deadline=None):
    data = read_regular(source, max_bytes, deadline=deadline)
    target = Path(target)
    check_deadline(deadline)
    target.parent.mkdir(parents=True, exist_ok=True)
    created = None
    try:
        check_deadline(deadline)
        with target.open('xb') as stream:
            info = os.fstat(stream.fileno()); created = (info.st_dev, info.st_ino)
            for offset in range(0, len(data), 65536):
                check_deadline(deadline)
                _write(stream, data[offset:offset + 65536], deadline)
            check_deadline(deadline)
        target.chmod(0o600)
        require(read_regular(target, max_bytes, deadline=deadline) == data, 'copy-changed')
        result = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
        check_deadline(deadline)
        return result
    except BaseException:
        if created is not None:
            try:
                info = target.lstat()
                if (info.st_dev, info.st_ino) == created:
                    target.unlink()
            except BaseException:
                pass  # Preserve the original refusal; uncertain disposal is no success.
        raise


def copy_pinned(source, target, sha256, max_bytes=LIMIT, *, deadline=None):
    check_deadline(deadline)
    require(re.fullmatch('[0-9a-f]{64}', sha256 or ''), 'full-pin-required')
    require(digest(source, deadline=deadline) == sha256, 'input-pin-differs')
    result = copy_regular(source, target, max_bytes, deadline=deadline)
    require(result['sha256'] == sha256, 'copy-pin-differs')
    check_deadline(deadline)
    return result


def controlled_env():
    return {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': os.environ['HOME'], 'LC_ALL': 'C',
            'PYTHONDONTWRITEBYTECODE': '1', 'GITHUB_SHA': os.environ.get('GITHUB_SHA', '')}


class CleanupFailure(ValueError):
    code = 'stage-cleanup-failed'

    def __init__(self, natural_returncode=None):
        require(natural_returncode is None or type(natural_returncode) is int and
                -128 <= natural_returncode <= 255, 'stage-returncode-invalid')
        super().__init__(self.code)
        self.natural_returncode = natural_returncode


def _stop(process, grace=90, *, deadline=None):
    require(type(grace) in (int, float) and 0 <= grace <= 120 and math.isfinite(grace),
            'finite-command-bounds-required')
    if deadline is not None:
        # Expired custody still requires zero-wait force-stop/reap attempts.
        try:
            require(type(deadline) in (int, float) and math.isfinite(deadline), 'stage-deadline-exceeded')
        except OverflowError:
            raise ValueError('stage-deadline-exceeded') from None
    previous, errors, events = {}, [], None
    end = None if deadline is None else min(time.monotonic() + grace, deadline - 10)
    def attempt(operation):
        try:
            return operation()
        except BaseException as error:
            errors.append(error)
    try:
        for sig in SIGNALS:
            def ignore(sig=sig):
                previous[sig] = signal.signal(sig, signal.SIG_IGN)
            attempt(ignore)
        def send(sig):
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                pass
        attempt(lambda: send(signal.SIGTERM))
        if end is None:
            end = time.monotonic() + grace
        try:
            events = selectors.DefaultSelector()
            events.register(process.stdout, selectors.EVENT_READ)
            while (events.get_map() or process.poll() is None) and time.monotonic() < end:
                for key, _ in events.select(min(.1, max(0, end - time.monotonic()))):
                    if not os.read(key.fd, 65536):
                        events.unregister(key.fileobj)
            unfinished = bool(events.get_map()) or process.poll() is None
        except BaseException as error:
            errors.append(error); unfinished = True
        finally:
            if events is not None:
                attempt(events.close)
        if unfinished or errors:
            attempt(lambda: send(signal.SIGKILL))
        remaining = 10 if deadline is None else max(0, min(10, deadline - time.monotonic()))
        def reap():
            code = process.wait(timeout=remaining)
            require(type(code) is int and -128 <= code <= 255, 'stage-returncode-invalid')
        attempt(reap)
        if deadline is not None:
            attempt(lambda: check_deadline(deadline))
    finally:
        for sig, handler in previous.items():
            attempt(lambda sig=sig, handler=handler: signal.signal(sig, handler))
        if deadline is not None:
            attempt(lambda: check_deadline(deadline))
    if errors:
        if not isinstance(errors[0], Exception):
            raise errors[0]
        raise CleanupFailure() from errors[0]


def command(argv, log, timeout, *, cleanup_grace=90, deadline=None):
    """One work cutoff and original cleanup allowance inside the captured deadline."""
    require(type(timeout) in (int, float) and 0 < timeout <= 3600 and math.isfinite(timeout) and
            type(cleanup_grace) in (int, float) and 0 <= cleanup_grace <= 120 and
            math.isfinite(cleanup_grace), 'finite-command-bounds-required')
    check_deadline(deadline)
    work_end = None
    if deadline is not None:
        now = time.monotonic()
        work_end = min(now + timeout, deadline - cleanup_grace - 10)
        require(now < work_end, 'stage-deadline-exceeded')
    process, failure, events, stream, natural_code = None, None, None, None, None
    try:
        check_deadline(deadline)
        stream = Path(log).open('xb')
        events = selectors.DefaultSelector()
        require(work_end is None or time.monotonic() < work_end, 'stage-deadline-exceeded')
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
        spawning_error = None
        try:
            arguments = [str(item) for item in argv]
            environment = controlled_env()
            check_deadline(deadline)
            require(work_end is None or time.monotonic() < work_end, 'stage-deadline-exceeded')
            process = subprocess.Popen(arguments, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, env=environment, start_new_session=True,
                                       preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, mask))
        except BaseException as error:
            spawning_error = error
            raise
        finally:
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, mask)
            except BaseException:
                if spawning_error is None:
                    raise
        events.register(process.stdout, selectors.EVENT_READ)
        size = 0
        if work_end is None:
            work_end = time.monotonic() + timeout
        while events.get_map():
            require(time.monotonic() < work_end, 'stage-deadline-exceeded')
            for key, _ in events.select(min(.25, max(0, work_end - time.monotonic()))):
                block = os.read(key.fd, 65536)
                if deadline is not None:
                    require(time.monotonic() < work_end, 'stage-deadline-exceeded')
                if not block:
                    events.unregister(key.fileobj)
                else:
                    size += len(block)
                    require(size <= LOG_LIMIT, 'stage-log-bound-exceeded')
                    _write(stream, block, deadline)
        remaining = work_end - time.monotonic()
        if deadline is not None:
            require(remaining > 0, 'stage-deadline-exceeded')
        code = process.wait(timeout=remaining if deadline is not None else max(.1, remaining))
        require(type(code) is int and -128 <= code <= 255, 'stage-returncode-invalid')
        natural_code = code
        if deadline is not None:
            require(time.monotonic() < work_end, 'stage-deadline-exceeded')
        return code
    except BaseException as error:
        failure = error
        if process is not None:
            try:
                _stop(process, grace=cleanup_grace, deadline=deadline)
            except BaseException:
                pass  # Cleanup cannot replace the first business/control failure.
        raise
    finally:
        errors = []
        for resource in (events, process.stdout if process is not None else None, stream):
            if resource is not None:
                try:
                    resource.close()
                except BaseException as error:
                    errors.append(error)
        try:
            check_deadline(deadline)
        except BaseException as error:
            errors.append(error)
        if errors and failure is None:
            if not isinstance(errors[0], Exception):
                raise errors[0]
            raise CleanupFailure(natural_code) from errors[0]


def base_prerequisite(controller, *, deadline=None):
    check_deadline(deadline)
    out = Path(controller.native_out)
    result, bootstrap, inputs = (read_json(out / name, deadline=deadline) for name in
                                ('result.json', 'bootstrap.json', 'inputs.lock.json'))
    require(result.get('native_build') == 'PASS', 'native-original-builds-required')
    require(re.fullmatch('sha256:[0-9a-f]{64}', controller.image or '') and
            read_regular(out / 'image-id', deadline=deadline).decode().strip() == controller.image, 'actual-builder-required')
    require(re.fullmatch('[0-9a-f]{40}', controller.commit or ''), 'accepted-source-commit-required')
    lock = read_regular(out / 'packages.lock', deadline=deadline).decode('utf-8')
    expected = {row['name'][0]: row['version'][0] for row in inputs['rootfs_packages']}
    expected.update({row['name']: row['version'] for row in inputs['packages']})
    require(len(expected) == 341 and lock == ''.join(f'{name} {version}\n' for name, version in sorted(expected.items())),
            'exact-authenticated-341-base-required')
    require(bootstrap.get('status') == 'image-provisioned' and bootstrap.get('image_id') == controller.image and
            bootstrap.get('packages_lock_sha256') == digest(out / 'packages.lock', deadline=deadline) and
            bootstrap.get('inputs_sha256') == digest(out / 'inputs.lock.json', deadline=deadline) == result.get('reviewed_inputs_sha256'),
            'actual-bootstrap-binding-required')
    return {'status': 'PASS', 'image_id': controller.image, 'packages_lock': str((out / 'packages.lock').absolute()),
            'packages_sha256': digest(out / 'packages.lock', deadline=deadline), 'package_count': 341, 'source_commit': controller.commit}
