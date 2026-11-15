# SPDX-License-Identifier: MIT
"""Finite passive DATA operations; never import producer, actor or package code."""
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time

MIB = 1024**2
HERE = Path(__file__).resolve().parent
_deadline = None
_evidence_names = set()
_modules = {}
PINS = {'support/perl_reader.py': '406333604f7b1ca17e986d16ac61cb1c9188f15b5f364a48323e258882f28def',
        'support/data_export.py': 'ac59342608cc8279ccb0aa218da792e72d903960769ab2f4553ee8ea9b5d334e',
        'support/helpers/archive_stream.py': '10f1a4c0ac5b98852d9ebb150af28f9ce345c800935a64fa463bc90f72fcb838',
        'support/helpers/elf64le_aarch64.py': '7c89596b854457897a6addb5b28794c2e0d9ffeffee44369a19b5a70f0a3cc53'}


def need(value, why):
    if not value:
        raise ValueError(why)


def start(seconds=240):
    global _deadline
    need(type(seconds) is int and 0 < seconds <= 300, 'finite passive Reader deadline')
    _deadline = time.monotonic() + seconds


def tick():
    need(_deadline is not None and time.monotonic() < _deadline, 'passive Reader DATA deadline')


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def sha(value, length=64):
    return type(value) is str and re.fullmatch('[0-9a-f]{' + str(length) + '}', value) is not None


def relative(name):
    need(type(name) is str and 0 < len(name) <= 4096 and re.fullmatch('[A-Za-z0-9._+/-]+', name)
         and all(part not in ('', '.', '..') for part in name.split('/')), 'ordinary bounded relative DATA path')
    return name


def absolute(value):
    value = str(value)
    need(value.startswith('/') and value != '/', 'nonroot absolute DATA path')
    relative(value[1:])
    p = Path(value)
    need(not any(parent.is_symlink() for parent in (p, *p.parents)), 'DATA path aliases refused')
    return p


def decode(raw, cap=2*MIB):
    tick()
    need(type(raw) is bytes and len(raw) <= cap, 'bounded JSON DATA')
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    def real(value):
        result = float(value)
        need(math.isfinite(result), 'finite JSON number')
        return result
    def invalid(_):
        raise ValueError('nonfinite JSON refused')
    try:
        result = json.loads(raw, object_pairs_hook=pairs, parse_float=real, parse_constant=invalid)
    except RecursionError as error:
        raise ValueError('JSON depth bound') from error
    pending = [(result, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        need(depth <= 32 and count <= 200000, 'JSON structure bound')
        if type(item) is dict:
            pending.extend((value, depth+1) for value in item.values())
        elif type(item) is list:
            pending.extend((value, depth+1) for value in item)
    return result


def read(root, name, cap=16*MIB):
    tick()
    root = absolute(root)
    parts = relative(name).split('/')
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            before = os.fstat(leaf)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= cap,
                 'bounded ordinary single-link DATA file')
            pieces = []
            size = 0
            while block := os.read(leaf, min(65536, cap+1-size)):
                tick()
                size += len(block)
                need(size <= cap, 'DATA byte bound')
                pieces.append(block)
            key = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            need(size == before.st_size and key(before) == key(os.fstat(leaf)) ==
                 key(os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)), 'DATA changed during read')
            return b''.join(pieces)
        finally:
            os.close(leaf)
    finally:
        os.close(fd)


def natural(row, zero=True, max_seconds=3600):
    tick()
    need(type(row) is dict and row.get('natural_exit') is True and row.get('forced_cleanup') is False
         and row.get('retirement') == 'REAPED' and row.get('group_absent') is True
         and row.get('leader_held_until_group_inspection') is True and row.get('ownership_lost') is False
         and row.get('exit_observed_via_waitpid') is True and 'cleanup_error' not in row
         and type(row.get('pid')) is int and row['pid'] > 0 and type(row.get('exit')) is int
         and (not zero or row['exit'] == 0), 'natural directly reaped owned exit required')
    seconds = row.get('elapsed_seconds')
    need(type(seconds) in (int, float) and math.isfinite(seconds) and 0 < seconds <= max_seconds,
         'bounded observed command elapsed time')
    return row['exit']


def inventory(root, max_files, byte_cap, ignore_git=False):
    root = absolute(root)
    names, directories, total, count = set(), set(), 0, 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        tick()
        base = Path(directory)
        if ignore_git and base == root and '.git' in dirs:
            need(not (base / '.git').is_symlink(), 'Git directory alias')
            dirs.remove('.git')
        for name in dirs + files:
            count += 1
            need(count <= max_files*5 and not (base / name).is_symlink(), 'finite alias-free DATA tree')
            path = base / name
            info = path.lstat()
            name = relative(str(path.relative_to(root)))
            if stat.S_ISDIR(info.st_mode):
                directories.add(name)
            else:
                need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'ordinary DATA tree leaves')
                names.add(name)
                total += info.st_size
                need(len(names) <= max_files and total <= byte_cap, 'DATA tree file/byte bound')
    expected = {str(parent) for name in names for parent in Path(name).parents if str(parent) != '.'}
    need(directories == expected, 'empty or unrecorded DATA directories refused')
    return names


def set_names(values):
    global _evidence_names
    _evidence_names = set(values)


def names(prefix):
    relative(prefix)
    return {name[len(prefix)+1:] for name in _evidence_names if name.startswith(prefix+'/')}


def passive(name):
    tick()
    if name not in _modules:
        path = HERE / relative(name)
        body = read(HERE, name, 128*1024)
        need(pin(body)['sha256'] == PINS[name], 'whole pinned passive helper differs')
        spec = importlib.util.spec_from_file_location('xs_passive_' + Path(name).stem, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        exec(compile(body, str(path), 'exec'), module.__dict__)
        _modules[name] = module
    return _modules[name]


def package(raw):
    tick()
    result = passive('support/perl_reader.py').archive(raw)
    tick()
    return result


def elf(raw):
    return passive('support/helpers/elf64le_aarch64.py').parse_elf(raw)


def export(raw):
    tick()
    result = passive('support/data_export.py').parse(raw)
    tick()
    return result
