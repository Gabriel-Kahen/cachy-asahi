#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Small data-only contracts shared by the finite kernel stage."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

HERE = Path(__file__).resolve().parent
PREFIX = 'scripts/port/kernel-native-stage/'
SOURCE = 'scripts/port/kernel-candidates/'
BASE_SHA = '89bdb06fea1862b5a6e02b77a4b98f6e04755b02327d875a716bd792929f3a4f'
INPUTS_SHA = '3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650'
TOOLS = ('gcc', 'g++', 'ld', 'as', 'ar', 'nm', 'objcopy', 'objdump', 'readelf', 'ranlib',
         'make', 'rustc', 'bindgen', 'pahole', 'dtc', 'clang', 'llvm-config', 'python3')


def need(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024**2), b''):
            h.update(block)
    return h.hexdigest()


def regular(path, limit=4 * 1024**2):
    path = Path(path)
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'symlink data path')
    info = path.stat()
    need(stat.S_ISREG(info.st_mode) and info.st_size <= limit, 'bounded regular input required')
    return info


def unique(rows):
    value = {}
    for key, item in rows:
        need(key not in value, 'duplicate JSON key'); value[key] = item
    return value


def load(path, pin=None):
    path = Path(path); regular(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_size <= 4 * 1024**2, 'bounded immutable JSON bytes required')
        data = stream.read(4 * 1024**2 + 1)
    need(len(data) <= 4 * 1024**2 and (pin is None or hashlib.sha256(data).hexdigest() == pin), 'JSON pin differs')
    return json.loads(data, object_pairs_hook=unique)


def save(path, value):
    path = Path(path)
    data = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    need(len(data) <= 4 * 1024**2, 'receipt bound exceeded')
    temp = path.with_name('.' + path.name + '-' + os.urandom(8).hex())
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    os.replace(temp, path)


def inventory(data):
    need(type(data) is bytes and len(data) <= 1024**2, 'bounded inventory bytes')
    rows = data.splitlines(keepends=True)
    need(rows and rows == sorted(rows) and all(re.fullmatch(rb'[A-Za-z0-9@+_.-]+ [^\s]+\n', row) for row in rows),
         'canonical package inventory required')
    value = {row.split()[0].decode(): row.split()[1].decode() for row in rows}
    need(len(value) == len(rows), 'duplicate inventory package')
    return value


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


def code_contract(root, files):
    for name, row in files.items():
        need(re.fullmatch(r'[A-Za-z0-9_./-]+', name) and '..' not in Path(name).parts and not Path(name).is_absolute(),
             'relative code name required')
        path = Path(root) / name; regular(path)
        need(digest(path) == row['sha256'] and stat.S_IMODE(path.stat().st_mode) == row['mode'], 'code snapshot differs: ' + name)


def delta_config(before, after, policy):
    delta = {key: {'before': before.get(key), 'after': after.get(key)} for key in before.keys() | after.keys()
             if before.get(key) != after.get(key)}
    allowed = set(policy['version_symbols'])
    need(set(delta) <= allowed | {'CONFIG_RUSTC_HAS_SUSPICIOUS_RUNTIME_SYMBOL_DEFINITIONS'}, 'unreviewed config change: ' + ','.join(sorted(set(delta) - allowed)))
    if 'CONFIG_RUSTC_HAS_SUSPICIOUS_RUNTIME_SYMBOL_DEFINITIONS' in delta:
        row = delta['CONFIG_RUSTC_HAS_SUSPICIOUS_RUNTIME_SYMBOL_DEFINITIONS']
        need(row['before'] in (None, 'n') and row['after'] == 'y', 'Rust lint capability differs')
    return delta
