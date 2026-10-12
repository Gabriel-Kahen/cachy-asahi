#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Closed Zsh native addon; registration/dispatch and final acceptance belong to CI.

Importing this module performs no actors. Docker is available only through the
private gate created by run_zsh; tests use inert command and source models.
"""
import argparse
import ast
import contextlib
import dis
import hashlib
import importlib.abc
import importlib.util
import json
import math
import os
from pathlib import Path, PurePosixPath, PurePath
import platform
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
import types
import weakref

DIRECT_ALIASES = types.MappingProxyType({'repository_inventory_validation': 'scripts/ci/lifecycle_inventory.py',
           'desktop_public_policy': 'scripts/ci/integration_export.py',
           'development_package_checks': 'scripts/checks/package_checks.py',
           'development_public_policy': 'scripts/ci/integration_export.py',
           'development_text_exporter': 'scripts/ci/integration_export.py',
           'development_virtual_exporter': 'scripts/ci/integration_export.py',
           'development_local_endpoint': 'scripts/ci/commit_image.py',
           'development_arm_corpus': 'scripts/experiments/corpus.py',
           'development_arm_policy': 'scripts/experiments/arm_c01.py'})

PACKAGE = 'cachy-asahi-zsh-autosuggestions'
CONTRACT = 'manifests/reviewed/zsh-native-addon.json'
INITIAL = 'scripts/ci/integration.lock.json'
LOCK = 'scripts/ci/development/packet.lock.json'
HEX = re.compile(r'[0-9a-f]{64}\Z')
IMAGE = re.compile(r'sha256:[0-9a-f]{64}\Z')
NAME = re.compile(r'cachy-asahi-[0-9a-f]{16}\Z')
META = {'.PKGINFO', '.BUILDINFO', '.MTREE'}
MAX_FILE = 8 * 1024**2
MAX_TOTAL = 64 * 1024**2


class Refusal(ValueError):
    """A stable refusal code, never raw private subprocess output."""


def need(value, code):
    if not value:
        raise Refusal(code)


def relative(name):
    need(isinstance(name, str) and name and len(name) <= 512 and
         all(32 <= ord(c) < 127 for c in name), 'path-invalid')
    path = PurePosixPath(name)
    need(not path.is_absolute() and '\\' not in name and str(path) == name and
         all(part not in ('', '.', '..', '.git', '__pycache__') for part in path.parts), 'path-invalid')
    return name


def read(path, limit=MAX_FILE):
    path = Path(path).absolute()
    need('..' not in path.parts and all(stat.S_ISDIR(p.lstat().st_mode) for p in path.parents), 'path-parent-invalid')
    before = path.lstat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit, 'input-not-bounded-regular')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        need(identity(os.fstat(stream.fileno())) == identity(before), 'input-raced')
        data = stream.read(limit + 1)
        need(identity(os.fstat(stream.fileno())) == identity(before), 'input-raced')
    need(identity(path.lstat()) == identity(before) and len(data) == before.st_size <= limit, 'input-raced')
    return data


def sha(data):
    return hashlib.sha256(data).hexdigest()


def decode(data):
    def unique(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate-json-key')
            result[key] = value
        return result
    result = json.loads(data, object_pairs_hook=unique,
                        parse_constant=lambda _: need(False, 'nonfinite-json'))
    need(isinstance(result, dict), 'json-object-required')
    return result


_RECEIPT_FILES, _RECEIPT_FDS, _RECEIPT_UNCERTAIN = {}, {}, {}


def first_failure(first, later):
    return later if first is None or isinstance(first, Exception) and not isinstance(later, Exception) else first


def receipt_identity(row):
    return row.st_dev, row.st_ino, row.st_mode, row.st_nlink, row.st_uid, row.st_gid, row.st_size


def receipt_open(path, flags, *, dir_fd=None):
    need(len(_RECEIPT_FDS) < 16, 'receipt-descriptor-bound')
    fd = os.open(path, flags, 0o600, dir_fd=dir_fd)
    _RECEIPT_FDS[fd] = None
    row = os.fstat(fd)
    _RECEIPT_FDS[fd] = (row.st_dev, row.st_ino, stat.S_IFMT(row.st_mode), row.st_rdev)
    return fd


def receipt_close(fd):
    expected, first = _RECEIPT_FDS.get(fd), None
    if expected is None:
        return Refusal('receipt-descriptor-unknown')
    for _ in range(3):
        try:
            row = os.fstat(fd)
            need((row.st_dev, row.st_ino, stat.S_IFMT(row.st_mode), row.st_rdev) == expected,
                 'receipt-descriptor-foreign')
            os.close(fd)
            del _RECEIPT_FDS[fd]
            return first
        except BaseException as error:
            if isinstance(error, OSError) and error.errno == 9:
                _RECEIPT_FDS.pop(fd, None)
                return first
            first = first_failure(first, error)
            if type(error) is Refusal:
                break
    return first


def receipt_parent(path):
    need('..' not in path.parts and all(stat.S_ISDIR(p.lstat().st_mode) for p in path.parents),
         'receipt-parent-refused')
    before = path.parent.lstat()
    need(before.st_uid == os.getuid() and before.st_gid == os.getgid() and
         not stat.S_IMODE(before.st_mode) & 0o022, 'receipt-parent-refused')
    fd = receipt_open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        key = (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid, opened.st_gid)
        need(key == (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid), 'receipt-parent-raced')
        return fd, key
    except BaseException as error:
        later = receipt_close(fd)
        raise first_failure(error, later) if later is not None else error


def receipt_destination(path, parent, key):
    need((lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid))(path.parent.lstat()) == key,
         'receipt-parent-raced')
    owned = _RECEIPT_FILES.get(str(path))
    need(owned is None or owned['parent'] == key, 'receipt-parent-foreign')
    try:
        row = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return None
    need(owned is not None and receipt_identity(row) == owned['identity'] and
         stat.S_ISREG(row.st_mode) and row.st_nlink == 1 and sha(read(path)) == owned['sha256'],
         'receipt-destination-foreign')
    return row


def receipt_remove_owned(path):
    """Invalidate only the matching previously committed owned receipt."""
    path, parent, first = Path(path).absolute(), None, None
    try:
        parent, key = receipt_parent(path)
        for _ in range(3):
            try:
                if receipt_destination(path, parent, key) is None:
                    _RECEIPT_FILES.pop(str(path), None)
                    return first
                os.unlink(path.name, dir_fd=parent)
            except BaseException as error:
                first = first_failure(first, error)
                if type(error) is Refusal:
                    break
        if receipt_destination(path, parent, key) is None:
            _RECEIPT_FILES.pop(str(path), None)
        else:
            first = first_failure(first, Refusal('receipt-invalidation-unproved'))
    except BaseException as error:
        first = first_failure(first, error)
    finally:
        if parent is not None:
            error = receipt_close(parent)
            if error is not None:
                first = first_failure(first, error)
    return first


def receipt_remove(path):
    first = None
    try:
        with defer_cancel():
            first = receipt_remove_owned(path)
    except BaseException as error:
        first = first_failure(first, error)
    return first


def save(path, value):
    """Exclusive owned temporaries; faults remain failures after bounded retries."""
    path = Path(path).absolute()
    data = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    need(len(data) <= MAX_FILE and not _RECEIPT_FDS and not _RECEIPT_UNCERTAIN, 'receipt-write-refused')
    need(str(path) in _RECEIPT_FILES or len(_RECEIPT_FILES) < 256, 'receipt-registry-bound')
    first, parent = None, None
    try:
        with defer_cancel():
            parent, key = receipt_parent(path)
            receipt_destination(path, parent, key)
            for _ in range(3):
                fd, temporary, expected, ready, committed = None, None, None, False, False
                try:
                    temporary = path.name + '.partial-' + os.urandom(8).hex()
                    fd = receipt_open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, dir_fd=parent)
                    expected = _RECEIPT_FDS[fd]
                    position = 0
                    while position < len(data):
                        written = os.write(fd, data[position:])
                        need(written > 0, 'receipt-write-short')
                        position += written
                    os.fchmod(fd, 0o600)
                    os.fsync(fd)
                    ready = True
                    receipt_destination(path, parent, key)
                    staged = os.stat(temporary, dir_fd=parent, follow_symlinks=False)
                    need((staged.st_dev, staged.st_ino, stat.S_IFMT(staged.st_mode), staged.st_rdev) == expected and
                         receipt_identity(staged) == receipt_identity(os.fstat(fd)) and staged.st_nlink == 1,
                         'receipt-temporary-foreign')
                    os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
                    committed = True
                    _RECEIPT_FILES[str(path)] = {'parent': key, 'identity': receipt_identity(os.fstat(fd)), 'sha256': sha(data)}
                    need(sha(read(path)) == sha(data), 'receipt-commit-raced')
                    os.fsync(parent)
                except BaseException as error:
                    first = first_failure(first, error)
                finally:
                    if fd is not None and expected is not None:
                        # Reconcile an after-effect rename error from the same captured FD.
                        try:
                            row = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                            if ready and (row.st_dev, row.st_ino, stat.S_IFMT(row.st_mode), row.st_rdev) == expected:
                                need(sha(read(path)) == sha(data), 'receipt-commit-raced')
                                committed = True
                                _RECEIPT_FILES[str(path)] = {'parent': key, 'identity': receipt_identity(row), 'sha256': sha(data)}
                        except FileNotFoundError:
                            pass
                        except BaseException as error:
                            first = first_failure(first, error)
                        for slot in range(3):
                            try:
                                row = os.stat(temporary, dir_fd=parent, follow_symlinks=False)
                                need((row.st_dev, row.st_ino, stat.S_IFMT(row.st_mode), row.st_rdev) == expected and
                                     row.st_nlink == 1 and row.st_uid == os.getuid() and row.st_gid == os.getgid(),
                                     'receipt-temporary-foreign')
                                os.unlink(temporary, dir_fd=parent)
                            except FileNotFoundError:
                                break
                            except BaseException as error:
                                first = first_failure(first, error)
                                if type(error) is Refusal or slot == 2:
                                    _RECEIPT_UNCERTAIN[(key, temporary)] = error
                                    break
                        error = receipt_close(fd)
                        if error is not None:
                            first = first_failure(first, error)
                    if fd is None and temporary is not None and not isinstance(first, Exception):
                        _RECEIPT_UNCERTAIN[(key, temporary)] = first
                if committed or _RECEIPT_UNCERTAIN or len(_RECEIPT_FDS) > 1 or not isinstance(first, Exception):
                    break
    except BaseException as error:
        first = first_failure(first, error)
    finally:
        if parent is not None:
            error = receipt_close(parent)
            if error is not None:
                first = first_failure(first, error)
    if first is not None:
        # Preserve a witnessed FAIL; otherwise revoke any matching prior PASS/data.
        try:
            if not (type(value) is dict and value.get('status') == 'FAIL' and
                    str(path) in _RECEIPT_FILES and sha(read(path)) == sha(data)):
                removal = receipt_remove(path)
                if removal is not None:
                    first = first_failure(first, removal)
        except BaseException as error:
            first = first_failure(first, error)
        raise first


def nodes(root, deadline=None, cleanup=False):
    """Charge each scandir entry before retention; never materialize a wide dir."""
    root = Path(root)
    need(stat.S_ISDIR(root.lstat().st_mode), 'tree-root-invalid')
    stack, count = [(root, 0)], 0
    while stack:
        directory, depth = stack.pop()
        need(depth <= 24, 'tree-node-bound')
        with os.scandir(directory) as entries:
            for entry in entries:
                if deadline is not None:
                    deadline.remaining(1, cleanup)
                count += 1
                need(count <= 1024, 'tree-node-bound')
                path = directory / entry.name
                relative(path.relative_to(root).as_posix())
                row = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(row.st_mode):
                    need(depth < 24, 'tree-node-bound')
                    stack.append((path, depth + 1))
                else:
                    need(stat.S_ISREG(row.st_mode) and row.st_nlink == 1, 'tree-node-invalid')
                yield path, row


def tree(root, max_files=256, max_bytes=MAX_TOTAL, deadline=None, cleanup=False):
    result, total = {}, 0
    for path, row in nodes(root, deadline, cleanup):
        if stat.S_ISDIR(row.st_mode):
            continue
        data = read(path)
        total += len(data)
        need(len(result) < max_files and total <= max_bytes, 'tree-bound-exceeded')
        result[path.relative_to(root).as_posix()] = {'sha256': sha(data), 'bytes': len(data), 'mode': stat.S_IMODE(row.st_mode)}
        if deadline is not None:
            deadline.remaining(1, cleanup)
    return result


def quota(root, deadline=None):
    """Live size/node checks avoid reading files while an actor writes them."""
    files = size = 0
    for path, row in nodes(root, deadline):
        if stat.S_ISDIR(row.st_mode):
            continue
        files += 1
        size += row.st_size
        need(row.st_size <= MAX_FILE and files <= 256 and size <= MAX_TOTAL, 'workspace-quota-refused')


class Deadline:
    def __init__(self, clock=time.monotonic, total=1200, work=1080):
        need(type(work) in (int, float) and type(total) in (int, float) and
             math.isfinite(work) and math.isfinite(total) and 0 < work < total <= 1200, 'deadline-invalid')
        self.clock, self.start = clock, clock()
        self.end, self.work_end = self.start + total, self.start + work

    def remaining(self, cap, cleanup=False):
        need(type(cap) in (int, float) and math.isfinite(cap) and 0 < cap <= 1200, 'operation-cap-invalid')
        left = (self.end if cleanup else self.work_end) - self.clock()
        need(left > 0, 'deadline-expired')
        return min(left, cap)


_PROCESS_DISPOSAL_UNCERTAIN = []


def process_cleanup_status(error):
    if _PROCESS_DISPOSAL_UNCERTAIN:
        return 'UNKNOWN'
    value = getattr(error, 'process_cleanup_status', 'NOTRUN')
    return value if type(value) is str and value in ('PASS', 'UNKNOWN', 'NOTRUN') else 'UNKNOWN'


def dispose_process(process, deadline, new_group, completed, first):
    if process is None:
        return first, 'NOTRUN'
    def alive():
        if not new_group:
            return process.poll() is None
        try:
            os.killpg(process.pid, 0)
            return True
        except ProcessLookupError:
            return False
    try:
        unfinished = not completed or alive()
    except BaseException as error:
        first, unfinished = first_failure(first, error), True
    if not unfinished:
        # The completed leader and its already absent group need no second query.
        try:
            need(process.poll() is not None, 'process-group-disposal-unproved')
        except BaseException as error:
            first = first_failure(first, error)
            return first, 'UNKNOWN'
        return first, 'PASS'
    if unfinished:
        for signum in (signal.SIGTERM, signal.SIGKILL):
            try:
                if new_group:
                    os.killpg(process.pid, signum)
                else:
                    process.send_signal(signum)
            except ProcessLookupError:
                pass
            except BaseException as error:
                first = first_failure(first, error)
            try:
                process.wait(timeout=max(0, min(2, deadline.end - deadline.clock())))
            except subprocess.TimeoutExpired:
                pass
            except BaseException as error:
                first = first_failure(first, error)
    try:
        need(process.poll() is not None and not alive(), 'process-group-disposal-unproved')
    except BaseException as error:
        first = first_failure(first, error)
        return first, 'UNKNOWN'
    return first, 'PASS'


def supervised(argv, env, deadline, cap, log=None, cleanup=False, new_group=True, quota_root=None):
    """Signal-safe spawn, finite output, and witnessed process-group disposal."""
    cutoff = deadline.clock() + deadline.remaining(cap, cleanup)
    need(all(isinstance(v, str) and '\x00' not in v for v in argv), 'argv-invalid')
    process, stream, completed = None, None, False
    data = bytearray()
    next_quota = 0
    try:
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGALRM})
        try:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, env=env, start_new_session=new_group, close_fds=True,
                preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, previous))
        finally:
            # A pending handler can raise here only after process is retained.
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        if log is not None:
            stream = Path(log).open('xb')
        with selectors.DefaultSelector() as events:
            events.register(process.stdout, selectors.EVENT_READ)
            while events.get_map() or process.poll() is None:
                need(deadline.clock() < cutoff, 'process-timeout')
                if quota_root is not None and deadline.clock() >= next_quota:
                    quota(quota_root, deadline)
                    need(deadline.clock() < cutoff, 'process-timeout')
                    next_quota = deadline.clock() + 0.5
                for key, _ in events.select(min(0.1, max(0, cutoff - deadline.clock()))):
                    block = os.read(key.fd, 65536)
                    if not block:
                        events.unregister(key.fileobj)
                    else:
                        need(len(data) + len(block) <= 4 * 1024**2, 'process-output-bound')
                        data.extend(block)
                        if stream:
                            stream.write(block)
            code = process.wait(timeout=deadline.remaining(1, cleanup))
            completed = True
            return code, bytes(data)
    finally:
        first, disposal_started, proof = sys.exc_info()[1], False, 'UNKNOWN' if process is not None else 'NOTRUN'
        try:
            with defer_cancel():
                disposal_started = True
                first, proof = dispose_process(process, deadline, new_group, completed, first)
        except BaseException as error:
            first = first_failure(first, error)
        finally:
            mask = None
            try:
                mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGALRM})
            except BaseException as error:
                first = first_failure(first, error)
            try:
                if not disposal_started:
                    # Context entry failed before any signal was sent; one fallback only.
                    disposal_started = True
                    try:
                        first, proof = dispose_process(process, deadline, new_group, completed, first)
                    except BaseException as error:
                        first = first_failure(first, error)
                for owned_stream in (process.stdout if process is not None else None, stream):
                    if owned_stream is not None:
                        try:
                            owned_stream.close()
                        except BaseException as error:
                            first = first_failure(first, error)
                            if getattr(owned_stream, 'closed', False) is not True:
                                proof = 'UNKNOWN'
            finally:
                if mask is not None:
                    try:
                        signal.pthread_sigmask(signal.SIG_SETMASK, mask)
                    except BaseException as error:
                        first = first_failure(first, error)
        if proof == 'UNKNOWN' and not _PROCESS_DISPOSAL_UNCERTAIN:
            _PROCESS_DISPOSAL_UNCERTAIN.append(True)
        if first is not None:
            try:
                first.process_cleanup_status = proof
            except BaseException:
                if not _PROCESS_DISPOSAL_UNCERTAIN:
                    _PROCESS_DISPOSAL_UNCERTAIN.append(True)
            raise first


def validate_contract(root, contract):
    need(contract.get('name') == PACKAGE and contract.get('version') == '0.7.1-1' and
         contract.get('arch') == 'any' and contract.get('license') == ['MIT'] and
         contract.get('depends') == ['zsh>=4.3.11'] and
         contract.get('upstream_revision') == '85919cd1ffa7d2d5412f6d3fe437ebdbeeec4fc5', 'package-contract-invalid')
    need(contract.get('source_root') == 'packages/shells/' + PACKAGE, 'recipe-root-invalid')
    rows = contract.get('source_files', {})
    need(len(rows) == 12 and set(rows) == {'.SRCINFO', 'PKGBUILD', 'LICENSE.project', 'LICENSE.upstream',
         'NOTICE', 'README.md', 'check-module.py', 'integration-proposal.json', 'opt-in.zsh',
         'source-provenance.json', 'usage.md', 'zsh-autosuggestions.zsh'}, 'recipe-file-set-invalid')
    actual = tree(Path(root) / contract['source_root'], 12, 54910)
    need(actual == rows and sum(v['bytes'] for v in rows.values()) == 54910, 'recipe-source-drift')
    need(contract.get('build_helper_reviewed_inputs') == {k: v['sha256'] for k, v in rows.items()}, 'recipe-input-map-invalid')
    payload = contract.get('expected_payloads', {})
    expected = {'usr/share/cachy-asahi/zsh-autosuggestions/zsh-autosuggestions.zsh': 'zsh-autosuggestions.zsh',
                'usr/share/cachy-asahi/zsh-autosuggestions/opt-in.zsh': 'opt-in.zsh',
                'usr/share/cachy-asahi/zsh-autosuggestions/README.md': 'usage.md',
                'usr/share/licenses/' + PACKAGE + '/LICENSE.upstream': 'LICENSE.upstream',
                'usr/share/licenses/' + PACKAGE + '/LICENSE.project': 'LICENSE.project',
                'usr/share/licenses/' + PACKAGE + '/NOTICE': 'NOTICE'}
    need(set(payload) == set(expected), 'payload-map-invalid')
    for name, source in expected.items():
        need(payload[name] == {'source': source, 'sha256': rows[source]['sha256'], 'bytes': rows[source]['bytes'],
                              'type': 'regular', 'mode': 0o644, 'uid': 0, 'gid': 0}, 'payload-map-invalid')


def prepare_initial_view(full, target, packet):
    """Copy only the unchanged 159 sources and the separately pinned lock."""
    full, target = Path(full).absolute(), Path(target).absolute()
    need(not target.exists() and not target.is_symlink() and not target.is_relative_to(full) and
         all(stat.S_ISDIR(p.lstat().st_mode) for p in target.parents), 'view-target-invalid')
    rows = packet.get('initial_source_files', {})
    need(len(rows) == 159 and all(packet['source_files'].get(k) == v for k, v in rows.items()), 'initial-map-invalid')
    pin = packet['metadata_pins'][INITIAL]
    data = read(full / INITIAL)
    initial = decode(data)
    need(sha(data) == pin and initial['source_files'] == rows and
         len(initial['generated_fixture_files']) == 125, 'initial-lock-drift')
    recipes = decode(read(full / 'scripts/ci/recipes.lock.json'))
    need(set(recipes) == {'packages/desktop/cachy-asahi-hyprland-settings', 'packages/settings/cachy-asahi-setup',
                         'packages/shells/cachy-asahi-fish-config', 'packages/shells/cachy-asahi-zsh-config'} and
         sum(len(v) for v in recipes.values()) == 71,
         'original-recipes-invalid')
    target.mkdir(mode=0o700)
    for name, row in {**rows, INITIAL: {'sha256': pin, 'mode': 0o644}}.items():
        relative(name)
        content = read(full / name)
        need(sha(content) == row['sha256'] and stat.S_IMODE((full / name).lstat().st_mode) == row['mode'], 'view-source-drift')
        destination = target / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open('xb') as stream:
            stream.write(content)
        destination.chmod(row['mode'])
        need(read(destination) == content, 'view-copy-drift')
    actual = tree(target, 160)
    need({k: {'sha256': v['sha256'], 'mode': v['mode']} for k, v in actual.items()} ==
         {**rows, INITIAL: {'sha256': pin, 'mode': 0o644}}, 'view-set-drift')
    return target


MAX_NODES, MAX_DEPTH, MAX_TEXT = 40000, 32, 16 * 1024**2
METADATA = frozenset(('__loader__', '__spec__', '__cached__'))
# These identities remain bound, but their contents are checked by the separate
# import-context and actor/environment policies, not this execution-state guard.
LIVE_DEPENDENCIES = frozenset((('sys', 'modules'), ('sys', 'path'), ('os', 'environ')))


def _exec_require(value):
    if not value:
        raise Refusal('loaded-code-identity-drift')


def dependency_paths(source, namespace):
    """Only explicit attribute chains rooted at actual imported module globals."""
    result = set()
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Attribute):
            continue
        names, current = [], node
        while isinstance(current, ast.Attribute):
            names.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name) and isinstance(namespace.get(current.id), types.ModuleType):
            result.add((current.id, *reversed(names)))
    return tuple(sorted(result))


def execution_guard(module, source, *, runtime=None, interfaces=None):
    """Return a private checker; do not expose or replace its frozen closure.

    runtime is an exact symbol -> checker table selected by root, not by modules.
    Unsupported opaque values retain identity only. Root must reject such values
    if they are execution policy, rather than claiming their contents are bound.
    """
    namespace = module.__dict__
    runtime = dict(runtime or {})
    interfaces = dict(interfaces or {})
    names = tuple(sorted(key for key in namespace if key not in METADATA))
    _exec_require(set(runtime) <= set(names))
    paths = dependency_paths(source, namespace)
    _exec_require(set(interfaces) <= set(paths))
    builtin_value = namespace.get('__builtins__')
    builtin_namespace = vars(builtin_value) if isinstance(builtin_value, types.ModuleType) else builtin_value
    _exec_require(type(builtin_namespace) is dict)
    builtin_names = tuple(sorted({node.id for node in ast.walk(ast.parse(source))
                                 if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
                                 and node.id not in namespace and node.id in builtin_namespace}))
    holders = []  # Retain baseline objects so identity integers cannot be reused.

    def snapshot(retain):
        seen, nodes, text = set(), 0, 0

        def freeze(value, depth=0):
            nonlocal nodes, text
            nodes += 1
            _exec_require(nodes <= MAX_NODES and depth <= MAX_DEPTH)
            kind = type(value)
            if kind in (type(None), bool, int, float, str, bytes):
                if kind is float:
                    _exec_require(math.isfinite(value))
                if kind in (str, bytes):
                    text += len(value)
                    _exec_require(text <= MAX_TEXT)
                return ('scalar', kind.__name__, value)
            key = id(value)
            if retain:
                holders.append(value)
            if key in seen:
                return ('reference', key)
            seen.add(key)
            child = lambda item: freeze(item, depth + 1)
            if kind in (tuple, list):
                return (kind.__name__, key, tuple(child(item) for item in value))
            if kind is dict:
                rows = [(child(k), child(v)) for k, v in value.items()]
                return ('dict', key, tuple(sorted(rows, key=lambda row: repr(row[0]))))
            if kind in (set, frozenset):
                return (kind.__name__, key, tuple(sorted((child(v) for v in value), key=repr)))
            if isinstance(value, re.Pattern):
                return ('pattern', key, value.pattern, value.flags)
            if isinstance(value, PurePath):
                # Explicitly selected CPython pathlib representation, never an
                # arbitrary object-state walker. Root must review its runtime.
                attribute = '_raw_paths' if hasattr(value, '_raw_paths') else '_parts'
                raw = object.__getattribute__(value, attribute)
                _exec_require(type(raw) in (list, tuple) and all(type(p) is str for p in raw))
                return ('path', key, attribute, child(raw), str(value), value.parts)
            if isinstance(value, types.CodeType):
                return ('code', key)
            if isinstance(value, types.FunctionType):
                cells = tuple((id(cell), child(cell.cell_contents)) for cell in (value.__closure__ or ()))
                return ('function', key, id(value.__code__), id(value.__globals__),
                        child(value.__defaults__), child(value.__kwdefaults__),
                        child(value.__dict__), child(value.__annotations__), cells)
            if isinstance(value, (staticmethod, classmethod)):
                return (kind.__name__, key, child(value.__func__))
            if isinstance(value, property):
                return ('property', key, child(value.fget), child(value.fset), child(value.fdel))
            if isinstance(value, type) and value.__module__ == module.__name__:
                rows = tuple((name, child(item)) for name, item in sorted(vars(value).items())
                             if name not in ('__dict__', '__weakref__'))
                return ('owned-class', key, tuple(id(base) for base in value.__bases__), rows)
            if isinstance(value, types.BuiltinMethodType) and value.__self__ is not None and not isinstance(value.__self__, types.ModuleType):
                return ('builtin-method', id(value.__self__), value.__name__,
                        id(vars(type(value.__self__)).get(value.__name__)))
            # Imported module/class/function identity is retained. Relevant
            # mutable module attributes are separately included below.
            return ('identity', kind.__module__, kind.__qualname__, key)

        bindings = tuple((name, ('runtime',) if name in runtime else freeze(namespace[name])) for name in names)
        dependencies = [(('__builtins__', name), freeze(builtin_namespace[name])) for name in builtin_names]
        for path in paths:
            value = namespace[path[0]]
            for index, name in enumerate(path[1:], 1):
                value = getattr(value, name)
                if path[:index + 1] in interfaces:
                    interfaces[path[:index + 1]](value)
                    dependencies.append((path[:index + 1], ('private-role',)))
                    break
                if path[:index + 1] in LIVE_DEPENDENCIES:
                    dependencies.append((path[:index + 1], ('live-identity', id(value))))
                    break
            else:
                dependencies.append((path, freeze(value)))
        return bindings, tuple(dependencies)

    baseline = snapshot(True)
    for name, check in runtime.items():
        check(namespace[name])

    def check():
        _exec_require(module.__dict__ is namespace and tuple(sorted(key for key in namespace if key not in METADATA)) == names)
        for name, validator in runtime.items():
            validator(namespace[name])
        _exec_require(snapshot(False) == baseline)
    return check


def sticky_bool(initial):
    _exec_require(type(initial) is bool)
    latched = initial

    def check(value):
        nonlocal latched
        _exec_require(type(value) is bool and (not latched or value))
        latched |= value
    return check





def _private_kernel():
    records = weakref.WeakKeyDictionary()
    allowed = frozenset()
    namespace, frame_at, refusal = globals(), sys._getframe, Refusal
    def access(owner, event='read', value=None):
        nonlocal allowed
        caller = frame_at(1)
        if event == 'configure':
            if allowed or caller.f_globals is not namespace or caller.f_code is not namespace['_initialize_entry_guard'].__code__:
                raise refusal('authority-kernel-already-bound')
            allowed = frozenset(value)
            return records
        if caller.f_globals is not namespace or caller.f_code not in allowed:
            raise refusal('authority-private-access-refused')
        if event == 'create':
            need(owner not in records, 'authority-already-created')
            records[owner] = value
            return
        need(owner in records, 'source-authority-unregistered')
        return records[owner]
    return access


_KERNEL = _private_kernel()


class BytesLoader(importlib.abc.Loader):
    __slots__ = ('authority', 'path')
    def __init__(self, authority, path):
        self.authority, self.path = authority, Path(path)

    def create_module(self, spec):
        module = self.authority.loaded.get(spec.name)
        if module is not None:
            self.authority.verify_loaded()
        return module

    def exec_module(self, module):
        self.authority.module_path(module.__name__, self.path)
        content = self.authority.bytes(self.path)
        if self.authority.loaded.get(module.__name__) is module:
            self.authority.verify_loaded()
            return
        need(module.__name__ not in sys.modules or sys.modules[module.__name__] is module, 'module-alias-preloaded')
        sys.modules[module.__name__] = module
        module.__file__, module.__cached__ = str(self.path), None
        try:
            exec(compile(content, str(self.path), 'exec'), module.__dict__)
            checker = self.authority.state(module, content)
            state = _KERNEL(self.authority)
            state['loaded'][module.__name__] = module
            state['checks'][module.__name__] = checker
        except BaseException:
            if sys.modules.get(module.__name__) is module:
                del sys.modules[module.__name__]
            raise


class SourceAuthority(importlib.abc.MetaPathFinder):
    """Closed captured-byte authority; public data is detached or readonly.

    Private records may be accessed only by the original source methods. Callback
    custody additionally requires real captured producer/controller frames.
    This is a cooperative in-process protocol, not a hostile-memory sandbox.
    """
    __slots__ = ()

    def __setattr__(self, name, value):
        raise Refusal('authority-fields-readonly')

    def __init__(self, root, packet_sha256, view=None):
        root = Path(root).absolute()
        data = read(root / LOCK)
        need(HEX.fullmatch(packet_sha256) and sha(data) == packet_sha256, 'packet-pin-drift')
        packet = decode(data)
        view = Path(view).absolute() if view else None
        paths, mapping, buffers = {}, {}, {}
        for name, row in packet['source_files'].items():
            if not name.endswith('.py'):
                continue
            path = view / name if view and name in packet['initial_source_files'] else root / name
            paths[str(path)] = types.MappingProxyType(dict(row))
            paths[str(root / name)] = types.MappingProxyType(dict(row))
            parts = PurePosixPath(name).parts
            if parts[:2] in (('scripts', 'ci'), ('scripts', 'checks'), ('scripts', 'integration'), ('scripts', 'build')):
                module = Path(name).stem
                if len(parts) <= 3 and module.isidentifier() and not module.startswith('test_'):
                    need(module not in mapping, 'module-name-collision')
                    mapping[module] = str(path)
        for module in ('packet', 'common', 'controller', 'base_stages', 'virtual_stage',
                       'initial_artifacts', 'repository_authority', 'repository_handoff'):
            name = 'scripts/ci/development/' + module + '.py'
            if name in packet['source_files']:
                mapping[module] = str(root / name)
        for path in paths:
            buffers[path] = read(path)
        sealed = (str(root), str(view) if view else None, packet_sha256, data,
                  types.MappingProxyType(paths), types.MappingProxyType(mapping), types.MappingProxyType(buffers))
        _KERNEL(self, 'create', {'sealed': sealed, 'loaded': {}, 'checks': {}, 'phase': 'idle', 'saved': None})
        self.verify()

    @property
    def root(self): return Path(_KERNEL(self)['sealed'][0])
    @property
    def view(self):
        value = _KERNEL(self)['sealed'][1]
        return Path(value) if value else None
    @property
    def pin(self): return _KERNEL(self)['sealed'][2]
    @property
    def packet(self): return decode(_KERNEL(self)['sealed'][3])
    @property
    def paths(self): return _KERNEL(self)['sealed'][4]
    @property
    def mapping(self): return types.MappingProxyType({n: Path(p) for n, p in _KERNEL(self)['sealed'][5].items()})
    @property
    def buffers(self): return _KERNEL(self)['sealed'][6]
    @property
    def loaded(self): return types.MappingProxyType(_KERNEL(self)['loaded'])
    @property
    def states(self): return types.MappingProxyType({name: None for name in _KERNEL(self)['checks']})
    @property
    def active(self): return _KERNEL(self)['phase'] == 'active'

    def verify(self):
        self.verify_loaded()
        packet = self.packet
        for name, row in packet['source_files'].items():
            data = read(self.root / relative(name))
            need(sha(data) == row['sha256'] and stat.S_IMODE((self.root / name).lstat().st_mode) == row['mode'], 'authority-source-drift')
        # Serialized bytes, decoded ledger and every lookup remain anchored to
        # the originally supplied packet, never the caller's detached packet.
        need(read(self.root / LOCK) == _KERNEL(self)['sealed'][3], 'packet-pin-drift')
        if self.view:
            expected = {**packet['initial_source_files'], INITIAL: {'sha256': packet['metadata_pins'][INITIAL], 'mode': 0o644}}
            for name, row in expected.items():
                need(sha(read(self.view / name)) == row['sha256'] and
                     stat.S_IMODE((self.view / name).lstat().st_mode) == row['mode'], 'view-source-drift')
            actual = tree(self.view, 160)
            need({k: {'sha256': v['sha256'], 'mode': v['mode']} for k, v in actual.items()} == expected, 'view-set-drift')

    def state(self, module, source=None):
        if source is None:
            source = self.bytes(Path(module.__file__))
        runtime = {}
        if module.__name__ == 'integration' and 'CANCEL_REQUESTED' in module.__dict__:
            runtime['CANCEL_REQUESTED'] = sticky_bool(module.CANCEL_REQUESTED)
        if module.__name__ == 'controller':
            if 'CANCELLED' in module.__dict__: runtime['CANCELLED'] = sticky_bool(module.CANCELLED)
            if 'POLICY' in module.__dict__:
                cached = module.POLICY
                def policy(value):
                    nonlocal cached
                    need(value is None and cached is None or
                         value is not None and value is self.loaded.get('development_public_policy') and
                         (cached is None or value is cached), 'policy-cache-drift')
                    cached = value
                runtime['POLICY'] = policy
        return execution_guard(module, source, runtime=runtime)

    def verify_loaded(self):
        state = _KERNEL(self)
        need(set(state['checks']) == set(state['loaded']), 'loaded-module-registry-drift')
        for name, module in state['loaded'].items():
            need(sys.modules.get(name) is module, 'loaded-module-identity-drift')
            state['checks'][name]()

    def bytes(self, path):
        path = Path(path).absolute()
        row = self.paths.get(str(path))
        need(row is not None, 'unregistered-module-path')
        data = read(path)
        need(sha(data) == row['sha256'] and data == self.buffers[str(path)] and
             stat.S_IMODE(path.lstat().st_mode) == row['mode'], 'module-source-drift')
        return self.buffers[str(path)]

    def find_spec(self, fullname, path=None, target=None):
        if fullname in self.mapping:
            return self.spec(fullname, self.mapping[fullname])
        if '.' not in fullname:
            for entry in sys.path:
                base = Path(entry or os.getcwd()).absolute()
                if base.is_relative_to(self.root) or self.view and base.is_relative_to(self.view):
                    need(not (base / (fullname + '.py')).exists() and not (base / fullname).exists(), 'unknown-project-import')
        return None

    def module_path(self, name, path):
        path = Path(path).absolute()
        canonical, alias = self.mapping.get(name), DIRECT_ALIASES.get(name)
        need(canonical is not None and path == canonical or alias is not None and
             path in (self.root / alias, self.view / alias if self.view else self.root / alias),
             'module-name-path-refused')

    def spec(self, name, path):
        need(self.active and self in sys.meta_path, 'inactive-source-authority')
        self.module_path(name, path)
        self.bytes(path)
        return importlib.util.spec_from_loader(name, BytesLoader(self, path), origin=str(path))

    def direct_spec(self, name, location=None, *, loader=None, submodule_search_locations=None):
        need(loader is None and submodule_search_locations is None, 'custom-loader-refused')
        path = Path(location).absolute()
        expected = DIRECT_ALIASES.get(name)
        need(expected is not None and path in (self.root / expected, self.view / expected if self.view else self.root / expected), 'direct-module-alias-refused')
        return self.spec(name, path)

    def __enter__(self):
        need(not self.active and all(name not in sys.modules for name in self.mapping), 'preloaded-project-module-refused')
        own = sys.modules.get(__name__)
        need(not any(m is not own and getattr(m, '__file__', None) and
                     (Path(m.__file__).absolute().is_relative_to(self.root) or self.view and
                      Path(m.__file__).absolute().is_relative_to(self.view)) for m in list(sys.modules.values())), 'preloaded-project-alias-refused')
        state = _KERNEL(self)
        state['saved'] = (importlib.util.spec_from_file_location, list(sys.path), os.environ.get('PYTHONDONTWRITEBYTECODE'), sys.dont_write_bytecode)
        os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
        sys.dont_write_bytecode = True
        sys.meta_path.insert(0, self)
        importlib.util.spec_from_file_location = self.direct_spec
        state['phase'] = 'active'
        return self

    def __exit__(self, *unused):
        state = _KERNEL(self)
        original_spec, original_path, original_cache, original_dont_write = state['saved']
        importlib.util.spec_from_file_location = original_spec
        sys.meta_path.remove(self)
        sys.path[:] = original_path
        if original_cache is None: os.environ.pop('PYTHONDONTWRITEBYTECODE', None)
        else: os.environ['PYTHONDONTWRITEBYTECODE'] = original_cache
        sys.dont_write_bytecode = original_dont_write
        for name, module in state['loaded'].items():
            if sys.modules.get(name) is module: del sys.modules[name]
        state['loaded'].clear()
        state['checks'].clear()
        state['saved'] = None
        state['phase'] = 'idle'

    def controller(self, controller):
        need(type(self) is SourceAuthority and self.active, 'source-authority-required')
        module, native = self.loaded.get('integration'), self.loaded.get('native_arm')
        need(module is not None and native is not None and sys.modules.get('integration') is module and
             type(controller) is module.Controller and module.ROOT == self.view, 'real-initial-controller-required')
        # Actual source frames carry custody. Public flags/objects cannot grant it.
        frames, frame = [], sys._getframe(1)
        while frame is not None and len(frames) < 128:
            frames.append(frame)
            frame = frame.f_back
        run_code = _RAW_CODES['SourceAuthority.run_native']
        consume_code = next(c for c in run_code.co_consts if isinstance(c, types.CodeType) and c.co_name == 'consume')
        need(any(f.f_code is run_code and f.f_locals.get('self') is self for f in frames) and
             any(f.f_code is consume_code and f.f_locals.get('controller') is controller and f.f_locals.get('self') is self for f in frames) and
             any(f.f_code is native.main.__code__ for f in frames) and
             any(f.f_code is module.Controller.run.__code__ and f.f_locals.get('self') is controller for f in frames), 'real-native-callback-required')
        actual = tree(controller.source, 159)
        need({k: {'sha256': v['sha256'], 'mode': v['mode']} for k, v in actual.items()} == self.packet['initial_source_files'], 'controller-source-snapshot-drift')
        self.verify()

    def run_native(self, argv, consumers):
        need(self.active and self.view is not None, 'native-authority-context-required')
        native = __import__('native_arm')
        self.verify()
        need(self.loaded.get('native_arm') is native and native.ROOT == self.view, 'canonical-native-required')
        def consume(controller):
            self.controller(controller)
            return consumers(controller)
        return native.main(argv, integration_consumers=consume)


def exact_run(config, argv):
    need(len(argv) > 4 and argv[:3] == ['run', '--rm', '--name'] and NAME.fullmatch(argv[3]), 'docker-run-refused')
    name = argv[3]
    attempt = Path(config['attempt'])
    expected = ['run', '--rm', '--name', name, '--pull=never', '--platform', 'linux/arm64',
                '--user', f"{config['uid']}:{config['gid']}", '--cap-drop=ALL', '--security-opt=no-new-privileges',
                '--read-only', '--pids-limit', '512', '--memory', '4g', '--cpus', '4', '--network', 'none',
                '--tmpfs', '/tmp:rw,nosuid,nodev,exec,size=4g', '--env', 'CACHY_ASAHI_CONTAINER=1',
                '--env', f"SOURCE_DATE_EPOCH={config['epoch']}",
                '--mount', f'type=bind,src={attempt / "inputs"},dst=/inputs,readonly',
                '--mount', f'type=bind,src={attempt / "artifacts"},dst=/out',
                '--mount', f'type=bind,src={config["entry"]},dst=/builder-entry.sh,readonly',
                '--mount', f'type=bind,src={attempt / "expected-packages.lock"},dst=/expected-packages.lock,readonly',
                '--entrypoint', '/bin/bash', config['image'], '/builder-entry.sh']
    need(argv == expected and IMAGE.fullmatch(config['image']) and config['uid'] > 0 and config['gid'] >= 0, 'docker-run-refused')
    need(all(Path(config[k]).is_absolute() and '..' not in Path(config[k]).parts and
             ',' not in config[k] and '\n' not in config[k] for k in ('attempt', 'entry', 'cidfile')), 'docker-bind-path-invalid')
    return {'name': name, 'original': argv, 'create': ['create', '--cidfile', config['cidfile'], *argv[2:]]}


def validate_container(config, info, name, cid):
    need(HEX.fullmatch(cid) and NAME.fullmatch(name) and info.get('Id') == cid and
         info.get('Name') == '/' + name and info.get('Image') == config['image'], 'container-identity-refused')
    c, h = info['Config'], info['HostConfig']
    need(c.get('Image') == config['image'] and c.get('User') == f"{config['uid']}:{config['gid']}" and
         c.get('Entrypoint') == ['/bin/bash'] and c.get('Cmd') == ['/builder-entry.sh'] and
         c.get('WorkingDir', '') == config['base_config'].get('WorkingDir', '') and
         c.get('Tty') is False and c.get('OpenStdin') is False and c.get('StdinOnce') is False,
         'container-config-refused')
    base_env = config['base_config'].get('Env') or []
    env = dict(v.split('=', 1) for v in base_env)
    env.update(CACHY_ASAHI_CONTAINER='1', SOURCE_DATE_EPOCH=str(config['epoch']))
    need(c.get('Env') is not None and len(c['Env']) == len(env) and
         dict(v.split('=', 1) for v in c['Env']) == env, 'container-env-refused')
    need(h.get('NetworkMode') == 'none' and h.get('ReadonlyRootfs') is True and h.get('Privileged') is False and
         h.get('AutoRemove') is False and h.get('CapAdd') in (None, []) and h.get('CapDrop') == ['ALL'] and
         h.get('SecurityOpt') == ['no-new-privileges'] and h.get('PidsLimit') == 512 and
         h.get('Memory') == 4 * 1024**3 and h.get('NanoCpus') == 4 * 10**9 and
         h.get('Tmpfs') == {'/tmp': 'rw,nosuid,nodev,exec,size=4g'} and
         h.get('IpcMode') == 'private' and h.get('CgroupnsMode') == 'private' and
         h.get('UsernsMode') == '' and h.get('Isolation', '') == '' and
         h.get('Runtime') == config.get('runtime', 'runc') and
         not any(h.get(k) for k in ('Binds', 'VolumesFrom', 'Devices', 'DeviceRequests', 'ExtraHosts',
                                  'Links', 'PortBindings', 'PublishAllPorts', 'PidMode', 'UTSMode', 'CgroupParent',
                                  'GroupAdd', 'Sysctls', 'Dns', 'DnsOptions', 'DnsSearch', 'Cgroup', 'Annotations')),
         'container-resource-refused')
    attempt = Path(config['attempt'])
    expected = {'/inputs': (str(attempt / 'inputs'), False), '/out': (str(attempt / 'artifacts'), True),
                '/builder-entry.sh': (config['entry'], False),
                '/expected-packages.lock': (str(attempt / 'expected-packages.lock'), False)}
    mounts = info.get('Mounts', [])
    need(len(mounts) == 4 and {m['Destination'] for m in mounts} == set(expected), 'container-mount-refused')
    for mount in mounts:
        need(mount.get('Type') == 'bind' and type(mount.get('RW')) is bool and
             (mount.get('Source'), mount.get('RW')) == expected[mount['Destination']] and
             mount.get('Propagation') in ('rprivate', ''), 'container-mount-refused')
    declared = h.get('Mounts', [])
    need(len(declared) == 4 and {m['Target'] for m in declared} == set(expected), 'container-declared-mount-refused')
    for mount in declared:
        need(mount.get('Type') == 'bind' and type(mount.get('ReadOnly', False)) is bool and
             (mount.get('Source'), not mount.get('ReadOnly', False)) == expected[mount['Target']] and
             mount.get('BindOptions', {}).get('Propagation', 'rprivate') == 'rprivate' and
             not mount.get('VolumeOptions') and not mount.get('TmpfsOptions'), 'container-declared-mount-refused')
    need(c.get('Volumes') in (None, {}) and h.get('RestartPolicy') == {'Name': 'no', 'MaximumRetryCount': 0} and
         c.get('ExposedPorts') == config['base_config'].get('ExposedPorts') and
         c.get('Healthcheck') == config['base_config'].get('Healthcheck'), 'container-extra-grant-refused')


def validate_pair(comparison):
    need(comparison.get('status') == 'contents-reproduced' and comparison.get('errors') == [] and
         len(comparison.get('packages', {})) == 1, 'comparison-refused')
    for name, row in comparison['packages'].items():
        need(re.fullmatch(PACKAGE + r'-0\.7\.1-1-any\.pkg\.tar\.(xz|zst|gz)', name) and
             all(row.get(k) is True for k in ('installed_contents_equal', 'pkginfo_equal', 'bytes_equal')) and
             type(row.get('buildinfo_equal')) is bool, 'byte-reproducibility-refused')


def identity(path):
    info = Path(path).stat()
    return {'dev': info.st_dev, 'ino': info.st_ino, 'mode': info.st_mode, 'uid': info.st_uid, 'gid': info.st_gid}


class Docker:
    def __init__(self, config, deadline):
        self.config, self.deadline = config, deadline
        self.env = {'PATH': '/usr/bin:/bin', 'HOME': config['home'], 'LC_ALL': 'C', 'DOCKER_CONFIG': config['docker_config']}

    def tools(self, cleanup=False):
        self.deadline.remaining(1, cleanup)
        c = self.config
        need(sha(read(c['docker'], 64 * 1024**2)) == c['docker_sha256'] and identity(c['docker']) == c['docker_identity'] and
             identity(c['socket']) == c['socket_identity'] and stat.S_ISSOCK(Path(c['socket']).stat().st_mode), 'docker-binding-drift')
        need(not any(Path(c['docker_config']).iterdir()), 'docker-config-drift')
        need(str(Path(sys.executable).resolve()) == c['python'] and identity(c['python']) == c['python_identity'] and
             sha(read(c['python'], 64 * 1024**2)) == c['python_sha256'], 'python-binding-drift')
        need(c['docker_identity']['uid'] == c['python_identity']['uid'] == 0 and
             not (c['docker_identity']['mode'] | c['python_identity']['mode']) & 0o022, 'trusted-host-tool-mode-required')
        self.deadline.remaining(1, cleanup)

    def execute(self, argv, cap=30, cleanup=False):
        self.tools(cleanup)
        c = self.config
        if 'daemon_binding' in c:
            self.binding(cleanup)
        try:
            return supervised([c['docker'], '--host', c['endpoint'], '--config', c['docker_config'], *argv],
                              self.env, self.deadline, cap, cleanup=cleanup, new_group=not c.get('inside_helper', False),
                              quota_root=None if cleanup else c['quota_root'])
        finally:
            self.tools(cleanup)
            if 'daemon_binding' in c:
                self.binding(cleanup)

    def call(self, argv, cap=30, cleanup=False):
        code, data = self.execute(argv, cap, cleanup)
        need(code == 0, 'docker-command-failed')
        return data

    def binding(self, cleanup=False):
        self.tools(cleanup)
        c = self.config
        code, data = supervised([c['docker'], '--host', c['endpoint'], '--config', c['docker_config'],
                                 'info', '--format', '{{json .}}'], self.env, self.deadline, 30, cleanup=cleanup,
                                new_group=not c.get('inside_helper', False))
        self.tools(cleanup)
        need(code == 0, 'daemon-query-failed')
        info = decode(data)
        need({k: info.get(k) for k in self.config['daemon_binding']} == self.config['daemon_binding'], 'daemon-binding-drift')

    def inspect(self, cid, cleanup=False):
        data = json.loads(self.call(['container', 'inspect', cid], cleanup=cleanup))
        need(isinstance(data, list) and len(data) == 1, 'container-inspect-invalid')
        return data[0]

    def absence(self, name, cid=None, cleanup=False):
        data = self.call(['container', 'ls', '--all', '--no-trunc', '--format', '{{.ID}} {{.Names}}'], cleanup=cleanup).decode()
        need(len(data.splitlines()) <= 4096, 'container-inventory-bound')
        seen = set()
        for line in data.splitlines():
            fields = line.split()
            need(len(fields) == 2 and HEX.fullmatch(fields[0]) and fields[0] not in seen and
                 re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,255}', fields[1]), 'container-inventory-invalid')
            seen.add(fields[0])
            need(fields[0] != cid and fields[1] != name, 'container-absence-unproved')


def gate(config, argv):
    """Only two helper queries and one exact create/inspect/start transformation."""
    config = {**config, 'inside_helper': True}
    # CLI descendants stay in the builder's owned group. The outer supervisor
    # proves disposal of that group; this gate never forks an orphan session.
    deadline = Deadline()
    deadline.end, deadline.work_end = config['stage_end'], config['work_end']
    deadline.work_end = min(deadline.work_end, config['gate_end'])
    docker = Docker(config, deadline)
    if argv == ['image', 'inspect', config['image']]:
        docker.binding()
        return 0, docker.call(argv)
    if argv == ['info', '--format', '{{.Architecture}}']:
        docker.binding()
        return 0, docker.call(argv)
    run = exact_run(config, argv)
    docker.binding()
    owned = Path(config['owned'])
    need(not owned.exists() and not Path(config['cidfile']).exists(), 'attempt-already-used')
    intent = {'status': 'INTENT', **run, 'image': config['image'], 'endpoint': config['endpoint'],
              'daemon_id': config['daemon_id'], 'cid': None, 'observed': False}
    save(owned, intent)
    docker.absence(run['name'])
    reply = docker.call(run['create']).decode().strip()
    cid = read(config['cidfile'], 128).decode().strip()
    need(HEX.fullmatch(cid) and reply == cid, 'create-cid-unproved')
    intent.update(cid=cid, status='CREATED')
    save(owned, intent)
    docker.binding()
    info = docker.inspect(cid)
    validate_container(config, info, run['name'], cid)
    need(info['State']['Status'] == 'created' and all(info['State'].get(k) is False for k in
         ('Running', 'Paused', 'Restarting', 'Dead', 'OOMKilled')), 'container-started-before-inspection')
    intent.update(status='OBSERVED_BEFORE_START', observed=True, configuration_sha256=sha(json.dumps(info, sort_keys=True).encode()))
    save(owned, intent)
    # start --attach's client code is not the container exit code; inspect State.
    code, output = docker.execute(['start', '--attach', cid], deadline.remaining(270))
    intent['attach_exit_code'] = code
    save(owned, intent)
    docker.binding()
    info = docker.inspect(cid)
    validate_container(config, info, run['name'], cid)
    need(info['State']['Status'] == 'exited' and all(info['State'].get(k) is False for k in
         ('Running', 'Paused', 'Restarting', 'Dead', 'OOMKilled')) and
         type(info['State']['ExitCode']) is int and 0 <= info['State']['ExitCode'] <= 255 and
         not info['State'].get('Error') and not info['State'].get('OOMKilled'), 'container-terminal-state-unproved')
    intent.update(status='EXITED', exit_code=info['State']['ExitCode'])
    save(owned, intent)
    need(code == 0, 'docker-attach-failed')
    return info['State']['ExitCode'], output


def cleanup_attempt(config, deadline):
    docker = Docker(config, deadline)
    owned = Path(config['owned'])
    need(not owned.is_symlink() and not Path(config['cidfile']).is_symlink(), 'cleanup-evidence-node-refused')
    if not owned.exists():
        need(not Path(config['cidfile']).exists(), 'cleanup-intent-missing-with-cid')
        return {'status': 'PASS', 'container_submitted': False}
    intent = decode(read(owned))
    run = exact_run(config, intent['original'])
    need(intent['create'] == run['create'] and intent['image'] == config['image'] and
         intent['endpoint'] == config['endpoint'] and intent['daemon_id'] == config['daemon_id'], 'cleanup-intent-drift')
    docker.binding(True)
    cid = intent.get('cid')
    if cid is None:
        # A interrupted create may leave only cidfile; it is never alone a grant.
        if Path(config['cidfile']).exists():
            cid = read(config['cidfile'], 128).decode().strip()
        else:
            docker.absence(run['name'], cleanup=True)
            return {'status': 'PASS', 'submitted_intent': True, 'observed_absent': True}
    need(HEX.fullmatch(cid), 'cleanup-cid-invalid')
    info = docker.inspect(cid, True)
    validate_container(config, info, run['name'], cid)
    docker.call(['container', 'rm', '--force', cid], 60, True)
    docker.binding(True)
    docker.absence(run['name'], cid, True)
    return {'status': 'PASS', 'cid': cid, 'name': run['name'], 'observed_absent': True}


def validate_attempt(authority, attempt, package, prerequisite, owned):
    record = decode(read(attempt / 'provenance.json'))
    need(record.get('status') == 'built-package-static-pass' and record.get('exit_code') == 0 and
         record.get('mode') == 'native' and record.get('network') == 'none' and
         record.get('image') == record.get('image_id') == prerequisite['image_id'] and
         record.get('recipe_inputs') == package['build_helper_reviewed_inputs'] and
         record.get('source_date_epoch') == prerequisite['epoch'] and
         record.get('expected_packages_sha256') == prerequisite['packages_sha256'] and
         record.get('entry_script_sha256') == authority.packet['initial_source_files']['scripts/build/container-entry.sh']['sha256'] and
         record.get('clean_environment_id') == owned['name'] and owned['status'] == 'EXITED' and
         owned.get('observed') is True and owned['exit_code'] == 0, 'attempt-binding-refused')
    validation = decode(read(attempt / 'validation.json'))
    need(validation.get('errors') == [] and len(validation.get('artifacts', [])) == 1, 'attempt-validation-refused')
    required = {'build.log', 'validation.json', 'expected-packages.lock', 'artifacts/packages.lock',
                'artifacts/generated.SRCINFO', 'artifacts/environment.txt', 'artifacts/config.sha256',
                'artifacts/makepkg.conf', 'artifacts/pacman.conf'}
    need(isinstance(record.get('files'), dict) and required <= record['files'].keys(), 'attempt-files-missing')
    for name, checksum in record['files'].items():
        need(HEX.fullmatch(checksum) and sha(read(attempt / relative(name))) == checksum, 'attempt-file-drift')
    for name in ('expected-packages.lock', 'artifacts/packages.lock'):
        need(sha(read(attempt / name)) == prerequisite['packages_sha256'], 'attempt-inventory-drift')
    snapshot = tree(attempt / 'inputs', 12, 54910)
    need(snapshot == package['source_files'], 'attempt-input-snapshot-drift')
    artifacts = record['artifacts']
    need(len(artifacts) == 1, 'artifact-count-refused')
    archive_name, checksum = next(iter(artifacts.items()))
    name = archive_name
    need(re.fullmatch(PACKAGE + r'-0\.7\.1-1-any\.pkg\.tar\.(xz|zst|gz)', name), 'artifact-name-refused')
    archive = attempt / 'artifacts' / name
    need(sha(read(archive)) == checksum, 'artifact-hash-drift')
    # The unchanged helper produced this report; the unchanged comparator later
    # reopens both actual archives under its finite subprocess supervisor. Avoid
    # the checker's unbounded parent-side zstd subprocess here.
    inspected = validation['artifacts'][0]
    need(inspected.get('artifact') == archive_name and inspected.get('sha256') == checksum and
         inspected.get('status') == 'artifact-static-pass', 'artifact-report-binding-refused')
    need(inspected['errors'] == [] and not inspected['elf'], 'artifact-inspection-refused')
    metadata = inspected['metadata']['.PKGINFO']
    for field, values in {'pkgname': [PACKAGE], 'pkgver': ['0.7.1-1'], 'arch': ['any'], 'license': ['MIT'],
                          'depend': ['zsh>=4.3.11'], 'optdepend': package['optdepends']}.items():
        need(metadata.get(field) == values, 'artifact-metadata-refused')
    need(inspected['metadata']['.BUILDINFO'].get('pkgbuild_sha256sum') == [package['build_helper_reviewed_inputs']['PKGBUILD']], 'artifact-pkgbuild-refused')
    members, payload = inspected['members'], package['expected_payloads']
    files = {k for k, v in members.items() if v['type'] == '0'}
    need(files == set(payload) | META, 'artifact-member-set-refused')
    dirs = {str(parent) for name in files for parent in PurePosixPath(name).parents}
    for name, row in members.items():
        need(row['uid'] == row['gid'] == 0 and row['type'] in ('0', '5'), 'artifact-node-refused')
        if row['type'] == '5':
            need(name in dirs and row['mode'] == 0o755, 'artifact-directory-refused')
        else:
            need(row['mode'] == 0o644, 'artifact-mode-refused')
            if name in payload:
                need(row['sha256'] == payload[name]['sha256'] and row['size'] == payload[name]['bytes'], 'artifact-payload-refused')
    return {'name': archive_name, 'sha256': checksum, 'bytes': archive.stat().st_size, 'clean_environment_id': owned['name'], 'cid': owned['cid']}


def run_zsh(controller, root, output, cache=None, *, authority):
    """Return a provisional stage PASS; the outer producer/aggregate is authority."""
    _AUTHORITY_ENTRY(authority)
    need(type(authority) is SourceAuthority, 'source-authority-required')
    SourceAuthority.controller(authority, controller)
    need(Path(root).absolute() == authority.root and authority.view is not None, 'root-authority-drift')
    output = Path(output).absolute()
    need(not output.exists() and not output.is_symlink() and not output.is_relative_to(authority.root) and
         not output.is_relative_to(authority.view) and not output.is_relative_to(Path(controller.native_out)) and
         all(stat.S_ISDIR(p.lstat().st_mode) for p in output.parents), 'output-invalid')
    deadline = Deadline()
    output.mkdir(mode=0o700, parents=False)
    result = {'stage': 'zsh-addon', 'status': 'FAIL', 'provisional': True, 'cleanup': {'status': 'UNKNOWN'},
              'attempts': [], 'comparison': None, 'hardware_status': 'NOT RUN', 'installation': 'NOT RUN',
              'selected_for_release': False, 'public': [], 'source_packet_sha256': authority.pin}
    configs, first = [], None
    try:
        contract_bytes = read(authority.root / CONTRACT)
        need(sha(contract_bytes) == authority.packet['source_files'][CONTRACT]['sha256'], 'contract-pin-drift')
        contract = decode(contract_bytes)
        need(contract['schema_version'] == 1 and contract['acceptance'] == 'strict-native-byte-pair' and
             contract['docker_adaptation'] == 'run-to-create-inspect-start-retain', 'contract-policy-refused')
        package = contract['package']
        validate_contract(root, package)
        common = authority.loaded.get('common')
        need(common is not None and sys.modules.get('common') is common, 'common-source-authority-required')
        prerequisite = common.base_prerequisite(controller)
        inputs = decode(read(Path(controller.native_out) / 'inputs.lock.json'))
        prerequisite['epoch'] = inputs['source_date_epoch']
        runner = decode(read(Path(controller.native_out) / 'runner.json'))
        need(platform.system() == 'Linux' and platform.machine() in ('aarch64', 'arm64') and os.getuid() > 0 and
             runner['uid'] == os.getuid() and runner['gid'] == os.getgid() and
             runner['commit'] == controller.commit == os.environ.get('GITHUB_SHA') and
             isinstance(runner['run_id'], str) and re.fullmatch(r'[0-9]{1,30}', runner['run_id']) and
             runner['run_id'] == os.environ.get('GITHUB_RUN_ID') and
             runner['python'] == sys.version and runner['docker_server_arch'] in ('aarch64', 'arm64') and
             runner['docker_endpoint'] in ('unix:///var/run/docker.sock', 'unix:///run/docker.sock'), 'same-job-native-runner-required')
        real = Path(shutil.which('docker') or '').resolve()
        need(real.is_file() and os.access(real, os.X_OK), 'docker-cli-required')
        sock = runner['docker_endpoint'][7:]
        docker_config = output / 'docker-config'
        docker_config.mkdir(mode=0o700)
        config = {'docker': str(real), 'docker_sha256': sha(read(real, 64 * 1024**2)), 'docker_identity': identity(real),
                  'docker_config': str(docker_config), 'quota_root': str(output),
                  'python': str(Path(sys.executable).resolve()), 'python_identity': identity(Path(sys.executable).resolve()),
                  'python_sha256': sha(read(Path(sys.executable).resolve(), 64 * 1024**2)),
                  'socket': sock, 'socket_identity': identity(sock), 'endpoint': runner['docker_endpoint'],
                  'home': os.environ['HOME'], 'image': prerequisite['image_id'], 'uid': os.getuid(), 'gid': os.getgid(),
                  'epoch': prerequisite['epoch'], 'stage_end': deadline.end, 'work_end': deadline.work_end}
        need(stat.S_ISSOCK(Path(sock).stat().st_mode), 'local-socket-required')
        docker = Docker(config, deadline)
        daemon = decode(docker.call(['info', '--format', '{{json .}}']))
        need(daemon.get('Architecture') in ('aarch64', 'arm64') and daemon.get('OSType') == 'linux' and
             isinstance(daemon.get('ID'), str) and 0 < len(daemon['ID']) <= 256, 'native-daemon-required')
        config['daemon_id'] = daemon['ID']
        config['daemon_binding'] = {k: daemon[k] for k in ('ID', 'Architecture', 'OSType', 'ServerVersion', 'DockerRootDir', 'DefaultRuntime')}
        config['runtime'] = daemon['DefaultRuntime']
        image = json.loads(docker.call(['image', 'inspect', config['image']]))
        need(len(image) == 1 and image[0]['Id'] == config['image'] and image[0]['Architecture'] == 'arm64' and
             image[0]['Os'] == 'linux', 'same-base-image-required')
        config['base_config'] = image[0]['Config']
        config['entry'] = str(authority.view / 'scripts/build/container-entry.sh')
        result['actor_binding'] = {k: config[k] for k in ('image', 'endpoint', 'daemon_id', 'docker_sha256', 'socket_identity',
                                                       'python_sha256', 'uid', 'gid', 'epoch')}
        result['source_binding'] = {'contract_sha256': sha(contract_bytes), 'recipe_inputs': package['build_helper_reviewed_inputs'],
                                    'packages_sha256': prerequisite['packages_sha256'], 'source_commit': controller.commit}
        reviewed = output / 'reviewed-inputs.json'
        save(reviewed, package['build_helper_reviewed_inputs'])
        for attempt_number in (1, 2):
            deadline.remaining(1)
            authority.verify()
            deadline.remaining(1)
            lane = output / f'lane-{attempt_number}'
            lane.mkdir(mode=0o700)
            attempt = output / f'attempt-{attempt_number}'
            attempt_config = {**config, 'attempt': str(attempt), 'cidfile': str(lane / 'cid'), 'owned': str(lane / 'owned.json'),
                              'gate_end': min(deadline.work_end, deadline.clock() + 270)}
            config_path = lane / 'gate.json'
            save(config_path, attempt_config)
            configs.append(attempt_config)
            shim = lane / 'docker'
            source = Path(__file__).absolute()
            own = authority.bytes(source)
            # Only the pinned bytes are executed, including the child gate module.
            launcher = (f'#!{Path(sys.executable).resolve()} -I\nimport sys\n'
                        f'p={str(source)!r};d={own!r}\n'
                        f'sys.argv=[p,"--gate",{str(config_path)!r},"--config-sha256",{sha(read(config_path))!r},"--",*sys.argv[1:]]\n'
                        'exec(compile(d,p,"exec"),{"__name__":"__main__","__file__":p})\n').encode()
            need(len(launcher) <= MAX_FILE, 'shim-bound')
            with shim.open('xb') as stream:
                stream.write(launcher)
            shim.chmod(0o755)
            env = {'PATH': str(lane) + ':/usr/bin:/bin', 'HOME': os.environ['HOME'], 'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1'}
            script = authority.view / 'scripts/build/build.py'
            bootstrap = output / f'build-{attempt_number}.py'
            write_bootstrap(bootstrap, authority, script)
            argv = [sys.executable, '-I', '-B', str(bootstrap), str(Path(root) / package['source_root']),
                    '--image', config['image'], '--mode', 'native', '--network', 'none', '--source-date-epoch', str(config['epoch']),
                    '--expected-packages', prerequisite['packages_lock'], '--reviewed-inputs', str(reviewed), '--timeout', '300', '--output', str(attempt)]
            code, _ = supervised(argv, env, deadline, 360, output / f'attempt-{attempt_number}.log', quota_root=output)
            need(code == 0, 'native-build-failed')
            owned = decode(read(lane / 'owned.json'))
            archive = validate_attempt(authority, attempt, package, prerequisite, owned)
            deadline.remaining(1)
            result['attempts'].append({'status': 'PASS', 'exit_code': code, 'archive': archive, 'shim_sha256': sha(launcher)})
            result['attempts'][-1]['cleanup'] = cleanup_attempt(attempt_config, deadline)
        need(result['attempts'][0]['archive']['cid'] != result['attempts'][1]['archive']['cid'] and
             result['attempts'][0]['archive']['clean_environment_id'] != result['attempts'][1]['archive']['clean_environment_id'], 'clean-pair-identity-refused')
        compare = output / 'compare.py'
        write_bootstrap(compare, authority, authority.view / 'scripts/build/compare.py')
        code, data = supervised([sys.executable, '-I', '-B', str(compare), str(output / 'attempt-1'),
                                 str(output / 'attempt-2'), '--require-bytes'],
                                {'PATH': '/usr/bin:/bin', 'HOME': os.environ['HOME'], 'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1'},
                                deadline, 120, output / 'comparison.log', quota_root=output)
        need(code == 0, 'native-comparison-failed')
        comparison = decode(data)
        validate_pair(comparison)
        result['comparison'] = comparison
        authority.verify()
        deadline.remaining(1)
        result['status'] = 'PASS'
    except BaseException as error:
        first = str(error) if type(error) is Refusal else 'addon-interrupted' if isinstance(error, (KeyboardInterrupt, SystemExit)) else 'addon-refused'
        result['status'], result['first_failure'] = 'FAIL', first
        result['process_cleanup'] = process_cleanup_status(error)
    finally:
        finalize_stage(output, result, configs, deadline, authority)
    return result


def finalize_stage(output, result, configs, deadline, authority):
    """Pure terminal receipt boundary; producer custody is enforced by run_zsh."""
    cleanups = []
    try:
        with defer_cancel() as cancelled:
            for c in configs:
                try:
                    # Successful lanes were already disposed; preserve their witnessed result.
                    index = configs.index(c)
                    if index < len(result['attempts']) and result['attempts'][index].get('cleanup', {}).get('status') == 'PASS':
                        Docker(c, deadline).binding(True)
                        Docker(c, deadline).absence(result['attempts'][index]['archive']['clean_environment_id'],
                                                    result['attempts'][index]['archive']['cid'], True)
                        cleanups.append(result['attempts'][index]['cleanup'])
                    else:
                        cleanups.append(cleanup_attempt(c, deadline))
                except BaseException:
                    cleanups.append({'status': 'UNKNOWN', 'error_code': 'owned-cleanup-unproved'})
            result['cleanup'] = {'status': 'PASS' if all(c['status'] == 'PASS' for c in cleanups) and
                                 result.get('process_cleanup') != 'UNKNOWN' else 'UNKNOWN', 'attempts': cleanups}
            if result['cleanup']['status'] != 'PASS':
                result['status'] = 'FAIL'
            try:
                authority.verify()
                tree(output)
                deadline.remaining(1, True)
            except BaseException:
                result['status'] = 'FAIL'
                result.setdefault('first_failure', 'final-source-or-output-drift')
            if cancelled:
                result['status'] = 'FAIL'
                result.setdefault('first_failure', 'addon-cancelled-during-finalization')
            finish(output, result)
            quota(output)
            if deadline.clock() >= deadline.end:
                result['status'] = 'FAIL'
                result.setdefault('first_failure', 'stage-deadline-expired')
            if cancelled or result['status'] != 'PASS':
                result['status'] = 'FAIL'
                if cancelled:
                    result.setdefault('first_failure', 'addon-cancelled-during-finalization')
                save(output / 'adapter-status/result.json', {k: v for k, v in result.items() if k != 'public'})
                save(output / 'public/receipt.json', {k: v for k, v in result.items() if k != 'public'})
                save(output / 'result.json', result)
    except BaseException as error:
        result["status"] = "FAIL"
        result.setdefault("first_failure", "finalization-interrupted")
        try:
            revoke(output, result)
        except BaseException:
            pass
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
    return result


@contextlib.contextmanager
def defer_cancel():
    cancelled = []
    signals = {signal.SIGINT, signal.SIGTERM, signal.SIGALRM}
    previous = {sig: signal.getsignal(sig) for sig in signals}
    oldmask = signal.pthread_sigmask(signal.SIG_BLOCK, signals)
    try:
        for sig in signals:
            signal.signal(sig, lambda signum, frame: cancelled.append(signum))
        signal.pthread_sigmask(signal.SIG_SETMASK, oldmask)
        yield cancelled
    finally:
        oldmask = signal.pthread_sigmask(signal.SIG_BLOCK, signals)
        try:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, oldmask)
        if cancelled:
            handler = previous[cancelled[0]]
            if callable(handler):
                handler(cancelled[0], None)
            else:
                raise KeyboardInterrupt()


def revoke(output, result):
    """Independently revoke every owned selector; never overwrite foreign nodes."""
    result['status'] = 'FAIL'
    result['public'] = []
    signals = {signal.SIGINT, signal.SIGTERM, signal.SIGALRM}
    first, rows = None, []
    oldmask = signal.pthread_sigmask(signal.SIG_BLOCK, signals)
    try:
        for name in ('adapter-status', 'public'):
            try:
                directory = output / name
                directory.mkdir(mode=0o700, exist_ok=True)
                need(stat.S_ISDIR(directory.lstat().st_mode), 'revocation-directory-refused')
            except BaseException as error:
                first = first_failure(first, error)
        record = {k: v for k, v in result.items() if k != 'public'}
        for name in ('adapter-status/result.json', 'public/receipt.json', 'result.json'):
            path, value, outcome = output / name, result if name == 'result.json' else record, 'UNAVAILABLE'
            try:
                save(path, value)
                outcome = 'FAIL'
            except BaseException as error:
                first = first_failure(first, error)
                try:
                    expected = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
                    owned = _RECEIPT_FILES.get(str(path.absolute()))
                    current_parent = path.parent.lstat()
                    parent_key = (current_parent.st_dev, current_parent.st_ino, current_parent.st_mode,
                                  current_parent.st_uid, current_parent.st_gid)
                    if owned is not None and owned['parent'] == parent_key and owned['identity'] == receipt_identity(path.lstat()) and \
                            owned['sha256'] == sha(expected) and sha(read(path)) == sha(expected):
                        outcome = 'FAIL'
                    else:
                        removed = receipt_remove(path)
                        if removed is not None:
                            first = first_failure(first, removed)
                        if str(path.absolute()) not in _RECEIPT_FILES and not path.exists() and not path.is_symlink():
                            outcome = 'ABSENT'
                except BaseException as invalidation_error:
                    first = first_failure(first, invalidation_error)
            rows.append({'selector': name, 'status': outcome})
        result['revocation'] = rows
    finally:
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, oldmask)
        except BaseException as error:
            first = first_failure(first, error)
    if first is not None:
        raise first
    return rows


def write_bootstrap(path, authority, script):
    """Embed the closed build/compare/checker graph, never reopen source/PYC."""
    modules = {name: {'path': str(authority.mapping[name]), 'data': authority.bytes(authority.mapping[name])}
               for name in ('build', 'compare', 'package_checks')}
    need(str(script) == modules[Path(script).stem]['path'], 'bootstrap-script-refused')
    content = ('import sys,importlib.abc,importlib.util,pathlib\n'
               f'M={modules!r}\n'
               f'ROOTS={[str(authority.root), str(authority.view)]!r}\n'
               'class L(importlib.abc.Loader):\n'
               ' def __init__(self,r): self.r=r\n'
               ' def create_module(self,s): return None\n'
               ' def exec_module(self,m):\n'
               '  p=self.r["path"];m.__file__=p;m.__cached__=None;exec(compile(self.r["data"],p,"exec"),m.__dict__)\n'
               'class F(importlib.abc.MetaPathFinder):\n'
               ' def find_spec(self,n,path=None,target=None):\n'
               '  if n in M: return importlib.util.spec_from_loader(n,L(M[n]),origin=M[n]["path"])\n'
               '  if "." not in n:\n'
               '   for e in sys.path:\n'
               '    b=pathlib.Path(e).absolute()\n'
               '    if any(b.is_relative_to(r) for r in ROOTS):\n'
               '     assert not (b/(n+".py")).exists() and not (b/n).exists()\n'
               '  return None\n'
               'sys.meta_path.insert(0,F())\n'
               f'r=M[{Path(script).stem!r}];p=r["path"];sys.argv[0]=p\n'
               'exec(compile(r["data"],p,"exec"),{"__name__":"__main__","__file__":p})\n')
    need(len(content.encode()) <= MAX_FILE, 'bootstrap-bound')
    with Path(path).open('x') as stream:
        stream.write(content)
    Path(path).chmod(0o600)


def finish(output, result):
    public = output / 'public'
    status = output / 'adapter-status'
    public.mkdir(mode=0o700)
    status.mkdir(mode=0o700)
    # No raw log, workspace traversal, package archive or arbitrary exception export.
    record = {k: v for k, v in result.items() if k != 'public'}
    save(status / 'result.json', record)
    save(public / 'receipt.json', record)
    tree(public, 32, 2 * 1024**2)
    tree(status, 32, 2 * 1024**2)
    need(all(r['bytes'] <= 256 * 1024 for r in tree(public).values()), 'public-file-bound')
    result['public'] = [str(status), str(public)]
    save(output / 'result.json', result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gate', type=Path, required=True)
    parser.add_argument('--config-sha256', required=True)
    parser.add_argument('argv', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        data = read(args.gate)
        need(HEX.fullmatch(args.config_sha256) and sha(data) == args.config_sha256, 'gate-config-drift')
        config = decode(data)
        argv = args.argv[1:] if args.argv[:1] == ['--'] else args.argv
        code, output = gate(config, argv)
        sys.stdout.buffer.write(output)
        return code
    except BaseException:
        print('addon-docker-gate-refused', file=sys.stderr)
        return 125


def _initialize_entry_guard():
    """Seal only authority/loader code and its transitive execution dependencies.

    Mutable actor APIs, receipt writers and live private records are outside this
    baseline. Trusted captured import and a cooperative stable stdlib are required;
    this is not protection against arbitrary interpreter-memory inspection.
    """
    namespace, error = globals(), Refusal
    classes = (SourceAuthority, BytesLoader)
    originals, raw_codes, pending = {}, {}, []
    for cls in classes:
        for name, descriptor in vars(cls).items():
            functions = (descriptor.fget, descriptor.fset, descriptor.fdel) if isinstance(descriptor, property) else (
                descriptor.__func__,) if isinstance(descriptor, (staticmethod, classmethod)) else (descriptor,)
            for function in functions:
                if isinstance(function, types.FunctionType):
                    pending.append(function)
                    raw_codes[cls.__name__ + '.' + name] = function.__code__
            originals[cls.__name__ + '.' + name] = descriptor
    namespace['_RAW_CODES'] = types.MappingProxyType(dict(raw_codes))
    # Original methods are the only public route to private kernel records.
    kernel = _KERNEL
    records = kernel(None, 'configure', tuple(raw_codes.values()))
    kernel_code, kernel_cells = kernel.__code__, tuple(kernel.__closure__ or ())
    kernel_values = tuple(cell.cell_contents for cell in kernel_cells)
    critical, visited, code_graph = {}, set(), []
    while pending:
        function = pending.pop()
        if id(function) in visited:
            continue
        visited.add(id(function))
        stack = [function.__code__]
        while stack:
            code = stack.pop()
            code_graph.append(code)
            stack.extend(value for value in code.co_consts if isinstance(value, types.CodeType))
            # LOAD_GLOBAL distinguishes global names from attributes and locals.
            # These code objects are the executed capture, never reopened source.
            for instruction in dis.get_instructions(code):
                if instruction.opname != 'LOAD_GLOBAL':
                    continue
                name = instruction.argval
                if name not in namespace or name in ('SourceAuthority', 'BytesLoader'):
                    continue
                critical[name] = namespace[name]
                if isinstance(namespace[name], types.FunctionType) and namespace[name].__globals__ is namespace:
                    pending.append(namespace[name])
    critical['_KERNEL'], critical['_RAW_CODES'] = kernel, namespace['_RAW_CODES']
    critical['__builtins__'] = namespace['__builtins__']
    critical['__name__'] = namespace['__name__']
    critical['raw_descriptors'] = originals
    model = types.ModuleType(namespace['__name__'])
    model.__dict__.update(critical)
    function_codes = tuple((value, value.__code__) for value in critical.values() if isinstance(value, types.FunctionType))
    builtin_table = namespace['__builtins__']
    if isinstance(builtin_table, types.ModuleType):
        builtin_table = vars(builtin_table)
    builtin_bindings = tuple((name, builtin_table[name]) for name in
        ('type', 'isinstance', 'getattr', 'hasattr', 'id', 'sorted', 'tuple', 'list', 'dict', 'set',
         'frozenset', 'len', 'all', 'any', 'vars', 'str', 'repr', 'object', 'compile', 'exec', '__import__'))
    original_meta, original_spec, original_bytecode = sys.meta_path, importlib.util.spec_from_file_location, sys.dont_write_bytecode
    original_finders = tuple(original_meta)
    sys_module, util, environment, module_cache = sys, importlib.util, os.environ, sys.modules
    installed, wrapper_codes, class_shapes = {}, [], []
    loaders = weakref.WeakKeyDictionary()

    def fail():
        raise error('loaded-code-identity-drift')

    def path_state(path):
        attribute = '_raw_paths' if hasattr(path, '_raw_paths') else '_parts'
        raw = object.__getattribute__(path, attribute)
        if type(raw) not in (list, tuple) or not all(type(part) is str for part in raw):
            fail()
        return attribute, tuple(raw), str(path)

    def active_owner():
        owners = [owner for owner, state in list(records.items()) if state['phase'] == 'active']
        if len(owners) > 1:
            fail()
        return owners[0] if owners else None

    def meta_policy(value):
        owner = active_owner()
        expected = (owner, *original_finders) if owner is not None else original_finders
        if value is not original_meta or len(value) != len(expected) or any(a is not b for a, b in zip(value, expected)):
            fail()

    def spec_policy(value):
        owner = active_owner()
        if owner is None:
            if value is not original_spec:
                fail()
        elif not isinstance(value, types.MethodType) or value.__self__ is not owner or value.__func__ is not installed[(SourceAuthority, 'direct_spec')]:
            fail()

    def bytecode_policy(value):
        if type(value) is not bool or value != (True if active_owner() is not None else original_bytecode):
            fail()

    def kernel_policy(value):
        if value is not kernel or value.__code__ is not kernel_code or tuple(value.__closure__ or ()) != kernel_cells or any(
                cell.cell_contents is not before for cell, before in zip(kernel_cells, kernel_values)):
            fail()

    # Feed the existing AST-based state checker harmless attribute expressions
    # derived only from the actual executed bytecode. No own-source file is read.
    chains, bare_names = set(), set()
    for code in code_graph:
        chain = None
        for instruction in dis.get_instructions(code):
            if instruction.opname == 'LOAD_GLOBAL':
                name = instruction.argval
                if name not in critical and name in builtin_table:
                    bare_names.add(name)
                chain = (name,) if isinstance(critical.get(name), types.ModuleType) else None
            elif instruction.opname in ('LOAD_ATTR', 'LOAD_METHOD') and chain is not None:
                chain += (instruction.argval,)
                chains.add(chain)
            elif instruction.opname not in ('CACHE', 'EXTENDED_ARG'):
                chain = None
    fragment = '\n'.join(sorted({'.'.join(chain) for chain in chains} | bare_names))
    checker = execution_guard(model, fragment, runtime={'_KERNEL': kernel_policy}, interfaces={
        ('sys', 'meta_path'): meta_policy, ('sys', 'dont_write_bytecode'): bytecode_policy,
        ('importlib', 'util', 'spec_from_file_location'): spec_policy})

    def verify(owner=None, initializing_loader=False):
        if namespace.get('_AUTHORITY_ENTRY') is not verify:
            fail()
        for cls in classes:
            if namespace.get(cls.__name__) is not cls:
                fail()
        for cls, names, bases in class_shapes:
            if tuple(sorted(vars(cls))) != names or cls.__bases__ is not bases:
                fail()
        for name, value in builtin_bindings:
            if builtin_table.get(name) is not value:
                fail()
        for name, value in critical.items():
            if name not in ('raw_descriptors', '__name__') and namespace.get(name) is not value:
                fail()
        for function, code in function_codes:
            if function.__code__ is not code:
                fail()
        for function, code, cells, contents in wrapper_codes:
            if function.__code__ is not code or tuple(function.__closure__ or ()) != cells or any(
                    cell.cell_contents is not value for cell, value in zip(cells, contents)):
                fail()
        for (cls, name), descriptor in installed.items():
            if vars(cls).get(name) is not descriptor:
                fail()
        if owner is not None and type(owner) in classes:
            try:
                shadows = object.__getattribute__(owner, '__dict__')
            except AttributeError:
                shadows = {}
            if any(name in shadows for name in vars(type(owner))):
                fail()
        if owner is not None and type(owner) is BytesLoader and not initializing_loader:
            binding = loaders.get(owner)
            if binding is None:
                fail()
            authority, path, representation = binding
            actual_authority = object.__getattribute__(owner, 'authority')
            actual_path = object.__getattribute__(owner, 'path')
            state = records.get(authority)
            if actual_authority is not authority or actual_path is not path or path_state(actual_path) != representation or not state or state['phase'] != 'active':
                fail()
        checker()

    def restore(owner):
        state = records.get(owner)
        if not state or state['saved'] is None:
            return
        saved_spec, saved_path, saved_cache, saved_bytecode = state['saved']
        util.spec_from_file_location = saved_spec
        original_meta[:] = [finder for finder in original_meta if finder is not owner]
        sys_module.path[:] = saved_path
        if saved_cache is None:
            environment.pop('PYTHONDONTWRITEBYTECODE', None)
        else:
            environment['PYTHONDONTWRITEBYTECODE'] = saved_cache
        sys_module.dont_write_bytecode = saved_bytecode
        for name, loaded in state['loaded'].items():
            if module_cache.get(name) is loaded:
                del module_cache[name]
        state['loaded'].clear()
        state['checks'].clear()
        state['saved'] = None
        state['phase'] = 'idle'

    def wrap(function, cleanup=False, loader_init=False):
        verify_code = verify.__code__
        def guarded(*args, **kwargs):
            try:
                if verify.__code__ is not verify_code:
                    fail()
                verify(args[0] if args else None, loader_init)
            except BaseException:
                if cleanup and args:
                    restore(args[0])
                raise
            result = function(*args, **kwargs)
            if loader_init:
                owner = args[0]
                authority = object.__getattribute__(owner, 'authority')
                path = object.__getattribute__(owner, 'path')
                state = records.get(authority)
                if type(owner) is not BytesLoader or type(authority) is not SourceAuthority or not state or str(path) not in state['sealed'][4]:
                    fail()
                loaders[owner] = (authority, path, path_state(path))
            return result
        guarded.__name__, guarded.__qualname__, guarded.__module__ = function.__name__, function.__qualname__, function.__module__
        guarded.__doc__, guarded.__wrapped__ = function.__doc__, function
        cells = tuple(guarded.__closure__ or ())
        wrapper_codes.append((guarded, guarded.__code__, cells, tuple(cell.cell_contents for cell in cells)))
        return guarded

    for cls in classes:
        for name, descriptor in list(vars(cls).items()):
            if isinstance(descriptor, property):
                replacement = property(*(wrap(function) if function else None for function in (descriptor.fget, descriptor.fset, descriptor.fdel)), doc=descriptor.__doc__)
            elif isinstance(descriptor, (staticmethod, classmethod)):
                replacement = type(descriptor)(wrap(descriptor.__func__))
            elif isinstance(descriptor, types.FunctionType):
                replacement = wrap(descriptor, cls is SourceAuthority and name == '__exit__', cls is BytesLoader and name == '__init__')
            else:
                replacement = descriptor
            installed[(cls, name)] = replacement
            if replacement is not descriptor:
                setattr(cls, name, replacement)
        class_shapes.append((cls, tuple(sorted(vars(cls))), cls.__bases__))
    return verify


_AUTHORITY_ENTRY = _initialize_entry_guard()


if __name__ == '__main__':
    sys.exit(main())
