#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Assemble one exact closed native Source from retained, verified DATA.

No source operand is imported, evaluated, built, fetched or installed. A native
run remains a separate Root action after actual Git publication and binding.
"""
import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tempfile

HERE = Path(__file__).resolve().parent
GENUINE_PARENT = 'c5e2c80a6dc2c66b471b4ea5d5162963c08a36b8'
PARENT_TREE = 'f45820b0ef37b48f50bbc361a22f53b5dd309506'
MAIN_BASE = '39af4cc7d12573ac73d13c8832b42b72be1e1174'
OPERATION = 'build-tools-alpm-v2'
MAX_FILE, MAX_TOTAL, MAX_FILES = 64 * 1024**2, 128 * 1024**2, 256
MAP = 'native/source-map.json'
SEAMS = frozenset((MAP, 'native/owner.py', 'native/invocation.json',
    '.github/workflows/native-arm-build.yml', '.github/workflows/native-arm-developer-workflows.yml', 'bootstrap/scripts/ci/native_arm.py', 'native/failure_retention.py'))
ADDITIONS = frozenset('native/' + name for name in (
    'build_tools_alpm_v2.py', 'build_tools_tools_v2.py', 'build_tools_guest_v2.py',
    'build_tools_probe_v2.py', 'build_tools_reader_v2.py', 'build_tools_projection_v2.py',
    'build-tools-contract-v2.json', 'build-tools-makepkg-v2.conf', 'build-tools-sources-v2.tar'))
FIELDS = frozenset(('schema', 'purpose', 'genuine_parent', 'parent_tree', 'parent_files',
    'overlay', 'producer_overlay', 'source_map_sha256', 'prospective_tree', 'operation', 'actual', 'main_base', 'source_files'))


def need(ok, message):
    if not ok:
        raise ValueError(message)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def oid(kind, raw):
    return hashlib.sha1(kind + b' ' + str(len(raw)).encode() + b'\0' + raw).digest()


def absolute(path):
    path = Path(path)
    need(path.is_absolute() and path.anchor == '/' and '..' not in path.parts, 'canonical absolute path required')
    return path


def relative(name):
    need(type(name) is str and 0 < len(name) <= 240 and '\\' not in name, 'bounded relative source path required')
    path = PurePosixPath(name)
    need(not path.is_absolute() and path.as_posix() == name and len(path.parts) <= 16 and
         all(part not in ('.', '..') and re.fullmatch(r'[A-Za-z0-9._+-]+', part) for part in path.parts), 'unsafe source path')
    return path


def decode(raw):
    need(len(raw) <= 1024**2, 'profile/manifest JSON cap')
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    def invalid(_):
        raise ValueError('noninteger/nonfinite JSON refused')
    value = json.loads(raw, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
    need(type(value) is dict, 'JSON object required')
    return value


def directory(path):
    path = absolute(path)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def identity(info):
    return tuple(getattr(info, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_nlink',
        'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def read_at(parent, leaf, cap):
    fd = os.open(leaf, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= cap,
             'bounded regular single-link source required')
        chunks, size = [], 0
        while block := os.read(fd, min(65536, cap + 1 - size)):
            chunks.append(block); size += len(block)
            need(size <= cap, 'source file byte cap')
        need(size == before.st_size and identity(before) == identity(os.fstat(fd)) ==
             identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False)), 'source changed while reading')
        return b''.join(chunks), stat.S_IMODE(before.st_mode)
    finally:
        os.close(fd)


def read(path, cap=MAX_FILE):
    path = absolute(path); fd = directory(path.parent)
    try:
        return read_at(fd, path.name, cap)
    finally:
        os.close(fd)


def snapshot(root):
    """Descriptor-relative finite regular tree; no symlinks or empty directories."""
    files, dirs, total = {}, set(), 0
    fd = directory(root)
    def walk(parent, prefix=''):
        nonlocal total
        before = os.fstat(parent)
        for leaf in sorted(os.listdir(parent)):
            name = prefix + leaf; relative(name)
            info = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            need(len(files) + len(dirs) < MAX_FILES * 4, 'source node cap')
            if stat.S_ISDIR(info.st_mode):
                dirs.add(name)
                child = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    need(identity(info) == identity(os.fstat(child)), 'source directory changed before read')
                    walk(child, name + '/')
                    need(identity(info) == identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False)), 'source directory changed after read')
                finally:
                    os.close(child)
            else:
                need(len(files) < MAX_FILES and stat.S_ISREG(info.st_mode), 'source aliases/special files refused')
                raw, mode = read_at(parent, leaf, min(MAX_FILE, MAX_TOTAL - total))
                need(mode in (0o644, 0o755), 'source file mode must be 0644/0755')
                total += len(raw); need(total <= MAX_TOTAL, 'source aggregate cap')
                files[name] = (raw, mode)
        need(identity(before) == identity(os.fstat(parent)), 'source directory changed during scan')
    try:
        walk(fd)
    finally:
        os.close(fd)
    wanted = {str(parent) for name in files for parent in PurePosixPath(name).parents if str(parent) != '.'}
    need(dirs == wanted, 'empty or unrecorded source directory refused')
    return files


def descriptors(files):
    return {name: dict(**pin(raw), mode=mode) for name, (raw, mode) in files.items()}


def tree(files):
    nodes = {}
    for name, value in files.items():
        path = relative(name); target = nodes
        for part in path.parts[:-1]:
            target = target.setdefault(part, {})
            need(type(target) is dict, 'source file/directory collision')
        need(path.name not in target, 'source file/directory collision')
        target[path.name] = value
    def body(node):
        raw = b''
        for name, value in sorted(node.items(), key=lambda row: row[0].encode() + (b'/' if type(row[1]) is dict else b'')):
            if type(value) is dict:
                mode, digest = b'40000', body(value)
            else:
                data, mode_value = value
                mode, digest = (b'100755' if mode_value == 0o755 else b'100644'), oid(b'blob', data)
            raw += mode + b' ' + name.encode() + b'\0' + digest
        return oid(b'tree', raw)
    return body(nodes).hex()


def publish(files, output):
    """Own only a fresh staging tree; atomically refuse preexisting destinations."""
    output = absolute(output)
    need(output != Path('/') and output.name not in ('', '.', '..'), 'fresh output child required')
    parent = directory(output.parent); staging = None
    try:
        info = os.fstat(parent)
        need(info.st_uid == os.getuid() and not stat.S_IMODE(info.st_mode) & 0o022, 'owned output parent without group/world writes required')
        try:
            os.stat(output.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError('fresh absent output required')
        staging = Path(tempfile.mkdtemp(prefix='.build-tools-v2-stage-', dir=output.parent))
        held = staging.lstat()
        for name, (raw, mode) in sorted(files.items()):
            target = staging / relative(name)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw); stream.flush(); os.fchmod(stream.fileno(), mode)
        need(snapshot(staging) == files, 'written Source differs before publication')
        need(identity(staging.lstat())[:2] == identity(held)[:2], 'owned staging root identity changed')
        libc = ctypes.CDLL(None, use_errno=True)
        rename = libc.renameat2
        rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        if rename(parent, os.fsencode(staging.name), parent, os.fsencode(output.name), 1):
            error = ctypes.get_errno()
            if error == errno.EEXIST:
                raise ValueError('fresh absent output required')
            raise OSError(error, os.strerror(error))
        staging = None
    finally:
        if staging is not None and staging.exists():
            need(identity(staging.lstat())[:2] == identity(held)[:2], 'unowned staging cleanup refused')
            shutil.rmtree(staging)
        os.close(parent)
