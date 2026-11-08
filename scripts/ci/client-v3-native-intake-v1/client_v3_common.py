# SPDX-License-Identifier: MIT
"""Strict passive DATA primitives; no extraction, source imports or actor fallback."""
import contextlib
import hashlib
import io
import json
import os
import re
from pathlib import Path
import stat
import sys
import zipfile

CAP = 192 * 1024**2
ZIP_CAP = 224 * 1024**2
LEAF_CAP = 256
ACTIVE = 0
ATTEMPTS = []

def need(ok, why):
    if not ok:
        raise ValueError(why)

def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

def typed_pin(row, cap=CAP):
    need(type(row) is dict and set(row) == {'bytes', 'sha256'} and type(row['bytes']) is int and
         0 <= row['bytes'] <= cap and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']),
         'typed bounded whole DATA pin required')
    return row

def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def decode(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    def integer(text):
        need(len(text) <= 20, 'bounded JSON integer')
        value = int(text)
        need(-(2**63) <= value < 2**63, 'JSON integer overflow')
        return value
    return json.loads(raw, object_pairs_hook=pairs, parse_int=integer,
                      parse_float=lambda _: need(False, 'JSON floats refused'),
                      parse_constant=lambda _: need(False, 'nonfinite JSON refused'))

def name(value):
    need(type(value) is str and value and not value.startswith('/') and '\\' not in value and
         not any(c in value for c in '\0\r\n') and all(p not in ('', '.', '..') for p in value.split('/')),
         'ordinary canonical relative DATA name required')
    return value

def ordinary(path, cap):
    path = Path(path)
    need(path.is_absolute() and path == path.resolve() and not any(p.is_symlink() for p in (path, *path.parents)),
         'canonical ordinary input path required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid() and
             not stat.S_IMODE(before.st_mode) & 0o111 and 0 <= before.st_size <= cap,
             'bounded owned nonexecutable single-link input required')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(before.st_size + 1)
        key = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(len(raw) == before.st_size and key(before) == key(os.fstat(fd)) == key(path.lstat()),
             'complete stable descriptor/path input required')
        return raw
    finally:
        os.close(fd)

def _audit(event, args):
    if not ACTIVE:
        return
    denied = event.startswith(('subprocess.', 'socket.', 'ctypes.', 'os.exec', 'os.spawn', 'os.fork', 'os.posix_spawn')) or event in (
        'os.system', 'pty.spawn', 'os.kill', 'os.killpg', 'os.mkdir', 'os.remove', 'os.rmdir', 'os.rename', 'os.link',
        'os.symlink', 'os.chmod', 'os.chown', 'os.utime', 'os.truncate')
    if event == 'open':
        mode, flags = args[1:3]
        denied = denied or (isinstance(mode, str) and any(c in mode for c in 'wax+')) or bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
    if denied:
        ATTEMPTS.append(event)
        raise RuntimeError('passive DATA actor/write denied: ' + event)

sys.addaudithook(_audit)

@contextlib.contextmanager
def passive():
    global ACTIVE
    ACTIVE += 1
    try:
        yield
    finally:
        ACTIVE -= 1

def zip_files(raw):
    need(0 < len(raw) <= ZIP_CAP, 'bounded original ZIP required')
    files, directories, seen, total = {}, set(), set(), 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        need(len(archive.infolist()) <= LEAF_CAP * 8, 'ZIP member count cap')
        for item in archive.infolist():
            n = name(item.filename[:-1] if item.is_dir() else item.filename)
            need(item.filename == n + ('/' if item.is_dir() else '') and n not in seen, 'duplicate/noncanonical ZIP member')
            seen.add(n)
            mode = item.external_attr >> 16
            need(not item.flag_bits & 1 and stat.S_IFMT(mode) in ((0, stat.S_IFDIR) if item.is_dir() else (0, stat.S_IFREG)) and
                 not mode & 0o7000, 'ZIP encryption/alias/special/mode refused')
            if item.is_dir():
                directories.add(n)
                continue
            total += item.file_size
            need(0 <= item.file_size <= 16 * 1024**2 and total <= CAP and len(files) < LEAF_CAP, 'ZIP expanded DATA caps')
            value = archive.read(item)
            need(len(value) == item.file_size, 'whole ZIP member required')
            files[n] = value
    for n in files:
        need(not any('/'.join(n.split('/')[:i]) in files for i in range(1, len(n.split('/')))), 'file used as ZIP parent')
    ancestors = {'/'.join(n.split('/')[:i]) for n in files for i in range(1, len(n.split('/')))}
    need(directories <= ancestors and not directories & set(files), 'unknown/empty ZIP directory refused')
    return files

def git_tree(rows):
    root = {}
    for n, row in rows.items():
        parts = name(n).split('/')
        target = root
        for part in parts[:-1]:
            need(type(target.get(part, {})) is dict, 'Source file used as directory')
            target = target.setdefault(part, {})
        need(parts[-1] not in target, 'duplicate Source tree name')
        target[parts[-1]] = (row['mode'], row['oid'])
    def descend(tree):
        values = []
        for n, value in tree.items():
            mode, oid = ('40000', descend(value)) if type(value) is dict else value
            values.append((n.encode() + (b'/' if mode == '40000' else b''), mode.encode() + b' ' + n.encode() + b'\0' + bytes.fromhex(oid)))
        raw = b''.join(v for _, v in sorted(values))
        return hashlib.sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    return descend(root)
