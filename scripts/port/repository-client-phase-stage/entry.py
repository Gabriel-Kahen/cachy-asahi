#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Authenticate the successor closure before executing captured Python bytes.

The coordinator authenticates this launcher and supplies an external source-map
pin. Production launch requires python -I -B; PYC is never consumed.
"""
import sys
if __name__ == '__main__' and (not sys.flags.isolated or not sys.flags.dont_write_bytecode):
    raise SystemExit('Launch requires python -I -B')
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import types

MODULES = ('dependencies', 'phases', 'gate', 'adapter')
SOURCES = {name + '.py' for name in (*MODULES, 'entry')}


def read(path, limit=1024**2):
    path = Path(path).absolute()
    if '..' in path.parts:
        raise ValueError('bootstrap parent traversal')
    dirs, observed, fd = [], [], None
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    try:
        dirs.append(os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
        current = Path('/')
        observed.append((current, os.fstat(dirs[-1])))
        for part in path.parts[1:-1]:
            dirs.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dirs[-1]))
            current /= part
            observed.append((current, os.fstat(dirs[-1])))
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dirs[-1])
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 <= before.st_size <= limit:
            raise ValueError('bounded single-link bootstrap input required')
        chunks, size = [], 0
        while chunk := os.read(fd, min(65536, limit + 1 - size)):
            chunks.append(chunk); size += len(chunk)
            if size > limit: raise ValueError('bootstrap byte bound')
        after, live = os.fstat(fd), path.lstat()
        if size != before.st_size or any(getattr(before, key) != getattr(after, key) or
                                        getattr(before, key) != getattr(live, key) for key in fields):
            raise ValueError('bootstrap file identity drift')
        for ancestor, prior in observed:
            now = ancestor.lstat()
            if (now.st_dev, now.st_ino, now.st_mode) != (prior.st_dev, prior.st_ino, prior.st_mode):
                raise ValueError('bootstrap ancestor identity drift')
        return b''.join(chunks), before
    finally:
        if fd is not None: os.close(fd)
        for item in reversed(dirs): os.close(item)


def authenticated(map_path, pin, *, source_root=None, repo_root=None):
    root = Path(source_root or Path(__file__).absolute().parent)
    raw, _ = read(map_path)
    if not isinstance(pin, str) or hashlib.sha256(raw).hexdigest() != pin:
        raise ValueError('external successor source-map pin differs')
    def pairs(rows):
        result = {}
        for key, row in rows:
            if key in result: raise ValueError('duplicate source-map key')
            result[key] = row
        return result
    pins = json.loads(raw, object_pairs_hook=pairs)
    if not isinstance(pins, dict) or set(pins) != SOURCES:
        raise ValueError('exact successor closure required')
    captured = {}
    for name, row in pins.items():
        if not isinstance(row, dict) or set(row) != {'sha256', 'mode'} or type(row['mode']) is not int or row['mode'] != 0o644:
            raise ValueError('typed successor source-map required')
        source, info = read(root / name)
        if stat.S_IMODE(info.st_mode) != row['mode'] or hashlib.sha256(source).hexdigest() != row['sha256']:
            raise ValueError('successor source bytes/mode differ')
        captured[name] = source
    # Authenticate external dependencies before compiling phase/gate/adapter.
    prior, loaded = {}, {}
    try:
        for name in MODULES:
            module = types.ModuleType(name); module.__file__ = str(root / (name + '.py'))
            prior[name] = sys.modules.get(name); sys.modules[name] = module
            exec(compile(captured[name + '.py'], module.__file__, 'exec'), module.__dict__)
            loaded[name] = module
            if name == 'dependencies':
                module.authenticate_all(Path(repo_root) if repo_root else module.ROOT)
    finally:
        for name, previous in prior.items():
            if previous is None: sys.modules.pop(name, None)
            else: sys.modules[name] = previous
    return loaded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-map', required=True)
    parser.add_argument('--source-map-sha256', required=True)
    actions = parser.add_subparsers(dest='action', required=True)
    for action in ('accept', 'restage'):
        sub = actions.add_parser(action)
        sub.add_argument('--inputs', required=True)
        sub.add_argument('--authority', required=True)
        sub.add_argument('--authority-sha256', required=True)
        if action == 'restage':
            sub.add_argument('--metadata')
            sub.add_argument('--metadata-sha256')
            sub.add_argument('--output', required=True)
    args = parser.parse_args()
    try:
        modules = authenticated(args.source_map, args.source_map_sha256)
        common = modules['dependencies'].load_collector()['common']
        with common.cancellation_handlers():
            authority = read(args.authority, 4 * 1024**2)[0]
            if args.action == 'accept':
                result = modules['gate'].accept(Path(args.inputs), authority, args.authority_sha256)
            else:
                result = modules['adapter'].execute(Path(args.inputs), authority, args.authority_sha256,
                    read(args.metadata, 16 * 1024**2)[0] if args.metadata else None,
                    args.metadata_sha256, Path(args.output))
        print(json.dumps(result, sort_keys=True))
        return 0 if result['status'] in ('PASS', 'PASS-input-acceptance') else 2 if result['status'] == 'NOT RUN' else 1
    except BaseException as error:
        print(json.dumps({'status': 'FAIL', 'error_type': type(error).__name__, 'native_end_to_end': 'NOT RUN'}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
