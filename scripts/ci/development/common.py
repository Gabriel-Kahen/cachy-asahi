#!/usr/bin/env python3
"""Bounded local orchestration helpers; no package or trust mutation."""
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

LIMIT = 8 * 1024**2
LOG_LIMIT = 4 * 1024**2
SIGNALS = {signal.SIGINT, signal.SIGTERM, signal.SIGALRM}


def require(condition, code):
    if not condition:
        raise ValueError(code)


def read_regular(path, max_bytes=LIMIT):
    path = Path(path).absolute()
    require('..' not in path.parts, 'input-path-invalid')
    for parent in path.parents:
        require(stat.S_ISDIR(parent.lstat().st_mode), 'input-parent-invalid')
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= max_bytes,
            'regular-bounded-input-required')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        opened = os.fstat(stream.fileno())
        require(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1 and opened.st_size <= max_bytes and
                (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), 'input-changed')
        data = stream.read(max_bytes + 1)
        after = os.fstat(stream.fileno())
    require(len(data) <= max_bytes and len(data) == before.st_size and
            (before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_mode, before.st_nlink) ==
            (after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_mode, after.st_nlink), 'input-changed')
    require((path.lstat().st_dev, path.lstat().st_ino) == (before.st_dev, before.st_ino), 'input-changed')
    return data


def digest(path):
    path = Path(path).absolute()
    require('..' not in path.parts and all(stat.S_ISDIR(p.lstat().st_mode) for p in path.parents), 'input-parent-invalid')
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= 2 * 1024**3, 'regular-bounded-input-required')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        opened = os.fstat(stream.fileno())
        require(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1 and opened.st_size <= 2 * 1024**3 and
                (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), 'input-changed')
        hasher, total = hashlib.sha256(), 0
        while block := stream.read(1024**2):
            total += len(block)
            require(total <= 2 * 1024**3, 'input-hash-bound-exceeded')
            hasher.update(block)
        result = hasher.hexdigest()
        after = os.fstat(stream.fileno())
    require((before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_mode, before.st_nlink) ==
            (after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_mode, after.st_nlink) and
            total == before.st_size and
            (path.lstat().st_dev, path.lstat().st_ino) == (before.st_dev, before.st_ino), 'input-changed')
    return result


def read_json(path, max_bytes=LIMIT):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'duplicate-json-field')
            result[key] = value
        return result
    value = json.loads(read_regular(path, max_bytes).decode('utf-8'), object_pairs_hook=pairs,
                       parse_constant=lambda _: require(False, 'nonfinite-json'))
    require(isinstance(value, dict), 'json-object-required')
    return value


def save(path, value):
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
            json.dump(value, stream, indent=2, sort_keys=True); stream.write('\n')
            stream.flush(); os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def copy_regular(source, target, max_bytes=LIMIT):
    data = read_regular(source, max_bytes)
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open('xb') as stream:
        stream.write(data)
    target.chmod(0o600)
    require(read_regular(target, max_bytes) == data, 'copy-changed')
    return {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}


def copy_pinned(source, target, sha256, max_bytes=LIMIT):
    require(re.fullmatch('[0-9a-f]{64}', sha256 or ''), 'full-pin-required')
    require(digest(source) == sha256, 'input-pin-differs')
    result = copy_regular(source, target, max_bytes)
    require(result['sha256'] == sha256, 'copy-pin-differs')
    return result


def controlled_env():
    return {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': os.environ['HOME'], 'LC_ALL': 'C',
            'PYTHONDONTWRITEBYTECODE': '1', 'GITHUB_SHA': os.environ.get('GITHUB_SHA', '')}


def _stop(process, grace=90):
    previous = {sig: signal.signal(sig, signal.SIG_IGN) for sig in SIGNALS}
    try:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + grace
        # Drain without retaining more bytes: a full output pipe must not
        # prevent the owner from writing its final cleanup receipt. A child
        # may keep the pipe alive after its launcher exits.
        with selectors.DefaultSelector() as events:
            events.register(process.stdout, selectors.EVENT_READ)
            while (events.get_map() or process.poll() is None) and time.monotonic() < deadline:
                for key, _ in events.select(0.1):
                    if not os.read(key.fd, 65536):
                        events.unregister(key.fileobj)
            unfinished = bool(events.get_map()) or process.poll() is None
        try:
            if unfinished:
                os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=10)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def command(argv, log, timeout, *, cleanup_grace=90):
    """Signal the owned launcher before force-stop, allowing its image cleanup."""
    require(type(timeout) in (int, float) and 0 < timeout <= 3600 and
            type(cleanup_grace) in (int, float) and 0 <= cleanup_grace <= 120, 'finite-command-bounds-required')
    process = None
    with Path(log).open('xb') as stream, selectors.DefaultSelector() as events:
        try:
            mask = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
            try:
                process = subprocess.Popen([str(item) for item in argv], stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT, env=controlled_env(), start_new_session=True,
                                           preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, mask))
            finally:
                # Delivery resumes only after the new process is tracked.
                signal.pthread_sigmask(signal.SIG_SETMASK, mask)
            events.register(process.stdout, selectors.EVENT_READ)
            deadline, size = time.monotonic() + timeout, 0
            while events.get_map():
                require(time.monotonic() < deadline, 'stage-deadline-exceeded')
                for key, _ in events.select(min(0.25, max(0, deadline - time.monotonic()))):
                    block = os.read(key.fd, 65536)
                    if not block:
                        events.unregister(key.fileobj)
                    else:
                        size += len(block)
                        require(size <= LOG_LIMIT, 'stage-log-bound-exceeded')
                        stream.write(block)
            return process.wait(timeout=max(0.1, deadline - time.monotonic()))
        except BaseException:
            if process is not None:
                _stop(process, grace=cleanup_grace)
            raise
        finally:
            if process is not None and process.stdout is not None:
                process.stdout.close()


def base_prerequisite(controller):
    out = Path(controller.native_out)
    result, bootstrap, inputs = (read_json(out / name) for name in
                                ('result.json', 'bootstrap.json', 'inputs.lock.json'))
    require(result.get('native_build') == 'PASS', 'native-original-builds-required')
    require(re.fullmatch('sha256:[0-9a-f]{64}', controller.image or '') and
            read_regular(out / 'image-id').decode().strip() == controller.image, 'actual-builder-required')
    require(re.fullmatch('[0-9a-f]{40}', controller.commit or ''), 'accepted-source-commit-required')
    lock = read_regular(out / 'packages.lock').decode('utf-8')
    expected = {row['name'][0]: row['version'][0] for row in inputs['rootfs_packages']}
    expected.update({row['name']: row['version'] for row in inputs['packages']})
    require(len(expected) == 341 and lock == ''.join(f'{name} {version}\n' for name, version in sorted(expected.items())),
            'exact-authenticated-341-base-required')
    require(bootstrap.get('status') == 'image-provisioned' and bootstrap.get('image_id') == controller.image and
            bootstrap.get('packages_lock_sha256') == digest(out / 'packages.lock') and
            bootstrap.get('inputs_sha256') == digest(out / 'inputs.lock.json') == result.get('reviewed_inputs_sha256'),
            'actual-bootstrap-binding-required')
    return {'status': 'PASS', 'image_id': controller.image, 'packages_lock': str((out / 'packages.lock').absolute()),
            'packages_sha256': digest(out / 'packages.lock'), 'package_count': 341, 'source_commit': controller.commit}
