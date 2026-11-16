#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Bounded control DATA reads and frozen Bankstown consumer loading."""
import builtins
import hashlib
import importlib.util
import importlib.machinery
import json
import os
from pathlib import Path
import re
import stat
import types

FAMILY = 'scripts/port/bankstown-qt3-native-v1/'
PINS = {
    FAMILY + 'admission.py': (8276, '6408b84bdf54e604ae6d734dedbbc5b179a7d2ded7c68abfa8451e8b7a16cf02'),
    FAMILY + 'profile.py': (19342, 'a2543a08d750dbf27cfc278bec09d61229ee9f9f3d47c56d018451f6c032d855'),
    FAMILY + 'builder.py': (26504, '6d5c19922091163ab612ceeceb96deef034e3274b80e2d17aa36704c87e30366'),
    FAMILY + 'entry.sh': (934, '3a73d1defb7f4463d5e1cb2a9b20c58c86211bdb8008a0b39ca3c04de6e51bf3'),
    'packages/port/bankstown-source-candidate/build_guard.py':
        (8777, '778c22cb52a4ffe4103a0e7a2c907def00bd9cd2411d0fdbca339a4cc010e21a'),
}


def need(value, code):
    if not value:
        raise ValueError(code)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def sha(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'EXTERNAL_SHA256_REQUIRED')
    return value


def descriptor(value, cap=64 * 1024**2):
    need(type(value) is dict and set(value) == {'bytes', 'sha256'}
         and type(value['bytes']) is int and 0 < value['bytes'] <= cap, 'WHOLE_FILE_PIN_REQUIRED')
    sha(value['sha256'])
    return value


def ordinary(path):
    need(isinstance(path, (str, Path)), 'ABSOLUTE_PATH_REQUIRED')
    value = str(path)
    path = Path(value)
    need(path.is_absolute() and str(path) == value and len(value.encode()) <= 4096
         and all(ord(c) >= 32 and ord(c) != 127 for c in value)
         and '..' not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)),
         'UNALIASED_ABSOLUTE_PATH_REQUIRED')
    return path


def identity(s):
    return tuple(getattr(s, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_nlink',
                 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def read(path, *, cap=2 * 1024**2, expected=None):
    path = ordinary(path)
    if expected is not None:
        descriptor(expected, cap)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 < before.st_size <= cap, 'BOUNDED_SINGLE_LINK_CONTROL_REQUIRED')
        chunks, remaining = [], before.st_size + 1
        while remaining:
            part = os.read(fd, min(1024**2, remaining))
            if not part:
                break
            chunks.append(part)
            remaining -= len(part)
        raw = b''.join(chunks)
        need(identity(before) == identity(os.fstat(fd)) == identity(path.lstat())
             and len(raw) == before.st_size, 'CONTROL_CHANGED')
        need(expected is None or pin(raw) == expected, 'CONTROL_PIN_DIFFERS')
        return raw
    finally:
        os.close(fd)


def ref(path, *, cap=2 * 1024**2):
    return dict(path=str(ordinary(path)), **pin(read(path, cap=cap)))


def read_ref(row, cap=2 * 1024**2):
    need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}
         and type(row['path']) is str, 'EXACT_FILE_REF_REQUIRED')
    return read(row['path'], cap=cap, expected={k: row[k] for k in ('bytes', 'sha256')})


def _pairs(rows):
    d = {}
    for key, value in rows:
        need(key not in d, 'DUPLICATE_JSON_KEY')
        d[key] = value
    return d


def decoded(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 64 * 1024**2, 'JSON_BYTE_BOUND')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                      parse_constant=lambda _: need(False, 'NONFINITE_JSON'))


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def write(path, raw):
    path = ordinary(path)
    need(not path.exists() and 0 < len(raw) <= 2 * 1024**2, 'FRESH_BOUNDED_OUTPUT_REQUIRED')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
    read(path, expected=pin(raw))


def consumers(source_root):
    """Import only the reviewed immutable consumer files; never invoke a builder."""
    source_root = ordinary(source_root)
    bodies = {relative: read(source_root / relative, expected={'bytes': size, 'sha256': digest})
              for relative, (size, digest) in PINS.items()}
    admission_path = source_root / FAMILY / 'admission.py'

    class AdmissionLoader:
        def create_module(self, spec):
            return None

        def exec_module(self, module):
            module.__file__ = str(admission_path)
            exec(compile(bodies[FAMILY + 'admission.py'], str(admission_path), 'exec'), module.__dict__)

    def admission_spec(name, path):
        need(name == 'bankstown_qt3_admission_v1' and Path(path) == admission_path,
             'EXACT_FROZEN_LOCAL_IMPORT_REQUIRED')
        return importlib.machinery.ModuleSpec(name, AdmissionLoader())

    # The frozen profile has one local admission import. Supply its exact retained
    # bytes without reopening either code pathname after validation. Other stdlib
    # imports retain normal Python semantics; no process-global importer changes.
    proxy = types.SimpleNamespace(util=types.SimpleNamespace(
        spec_from_file_location=admission_spec, module_from_spec=importlib.util.module_from_spec))
    def importing(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'importlib.util' and level == 0:
            return proxy
        return builtins.__import__(name, globals, locals, fromlist, level)

    path = source_root / FAMILY / 'profile.py'
    module = types.ModuleType('bankstown_qt3_frozen_profile')
    module.__file__ = str(path)
    module.__dict__['__builtins__'] = dict(vars(builtins), __import__=importing)
    exec(compile(bodies[FAMILY + 'profile.py'], str(path), 'exec'), module.__dict__)
    return module



def verify_blob(row, *, deadline):
    """Stream the selected image-export archive without decoding or extraction."""
    import time
    need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}, 'ARCHIVE_REF_REQUIRED')
    expected = {k: row[k] for k in ('bytes', 'sha256')}
    descriptor(expected, 16 * 1024**3)
    path = ordinary(row['path'])
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_size == row['bytes'], 'PINNED_ORDINARY_ARCHIVE_REQUIRED')
        digest, total = hashlib.sha256(), 0
        while True:
            need(time.monotonic() < deadline, 'PASSIVE_READ_DEADLINE')
            part = os.read(fd, min(1024**2, row['bytes'] + 1 - total))
            if not part:
                break
            total += len(part); digest.update(part)
            need(total <= row['bytes'], 'ARCHIVE_GREW')
        need(identity(before) == identity(os.fstat(fd)) == identity(path.lstat())
             and {'bytes': total, 'sha256': digest.hexdigest()} == expected, 'ARCHIVE_PIN_OR_IDENTITY_DIFFERS')
        return identity(before)
    finally:
        os.close(fd)
