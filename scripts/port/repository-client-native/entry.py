#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""CLI bootstrap: authenticate source bytes before imports, never consume PYC.

The coordinator must authenticate this launcher's own SHA before launching Python.
The externally pinned source map then authenticates its complete module closure.
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

MODULES = ('common', 'base', 'provenance', 'crypto', 'orchestrator')
SOURCES = {name + '.py' for name in (*MODULES, 'entry', 'worker')}


def bootstrap_read(path, limit):
    path = Path(path).absolute()
    if '..' in path.parts:
        raise ValueError('source parent traversal refused')
    dirs, fd = [], None
    try:
        dirs.append(os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
        for part in path.parts[1:-1]:
            dirs.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dirs[-1]))
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dirs[-1])
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
            raise ValueError('bounded regular bootstrap input required')
        data = bytearray()
        while chunk := os.read(fd, min(65536, limit + 1 - len(data))):
            data.extend(chunk)
            if len(data) > limit:
                raise ValueError('bootstrap byte bound')
        after, current = os.fstat(fd), path.lstat()
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if len(data) != before.st_size or any(getattr(before, key) != getattr(after, key) or
                                            getattr(before, key) != getattr(current, key) for key in fields):
            raise ValueError('bootstrap input identity drift')
        return bytes(data), before
    finally:
        if fd is not None: os.close(fd)
        for item in reversed(dirs): os.close(item)


def authenticated(map_path, external_pin):
    root = Path(__file__).absolute().parent
    if any(path.is_symlink() for path in (root, *root.parents)):
        raise ValueError('source directory link refused')
    raw, _ = bootstrap_read(map_path, 1024**2)
    if hashlib.sha256(raw).hexdigest() != external_pin or len(raw) > 1024**2:
        raise ValueError('external source-map pin differs')
    def pairs(rows):
        value = {}
        for name, row in rows:
            if name in value: raise ValueError('duplicate source map key')
            value[name] = row
        return value
    pins = json.loads(raw, object_pairs_hook=pairs)
    if set(pins) != SOURCES:
        raise ValueError('exact source closure required; bytecode excluded')
    captures = {}
    for name, row in pins.items():
        if not isinstance(row, dict) or set(row) != {'sha256', 'mode'} or type(row['mode']) is not int or row['mode'] not in (0o644, 0o755):
            raise ValueError('typed source map required')
        path = root / name
        data, before = bootstrap_read(path, 1024**2)
        if stat.S_IMODE(before.st_mode) != row['mode'] or hashlib.sha256(data).hexdigest() != row['sha256']:
            raise ValueError('source bytes/mode differ')
        captures[name] = data
    loaded = {}
    for name in MODULES:
        module = types.ModuleType(name); module.__file__ = str(root / (name + '.py'))
        sys.modules[name] = module
        exec(compile(captures[name + '.py'], module.__file__, 'exec'), module.__dict__)
        loaded[name] = module
    return loaded, pins


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-map', required=True)
    parser.add_argument('--source-map-sha256', required=True)
    commands = parser.add_subparsers(dest='action', required=True)
    collect = commands.add_parser('collect-base')
    collect.add_argument('--image', required=True)
    for name in ('bootstrap', 'packages', 'inputs'):
        collect.add_argument('--' + name, required=True)
        collect.add_argument('--' + name + '-sha256', required=True)
    collect.add_argument('--output', required=True)
    for action in ('attest', 'consume-provenance'):
        sub = commands.add_parser(action)
        sub.add_argument('--inputs', required=True)
        sub.add_argument('--request', required=True)
        sub.add_argument('--request-sha256', required=True)
        sub.add_argument('--output', required=True)
        if action == 'consume-provenance':
            sub.add_argument('--base', required=True)
            sub.add_argument('--base-sha256', required=True)
    post = commands.add_parser('post-terminal')
    post.add_argument('--inputs', required=True)
    for name in ('authority', 'crypto', 'metadata'):
        post.add_argument('--' + name, required=True)
        post.add_argument('--' + name + '-sha256', required=True)
    args = parser.parse_args()
    try:
        modules, pins = authenticated(args.source_map, args.source_map_sha256)
        common = modules['common']
        with common.cancellation_handlers():
            if args.action == 'collect-base':
                value = modules['base'].collect_base(args.image, common.read(args.bootstrap), args.bootstrap_sha256,
                    common.read(args.packages), args.packages_sha256, {name: pins[name] for name in ('common.py', 'base.py', 'worker.py')},
                    Path(args.output), inputs_raw=common.read(args.inputs), inputs_pin=args.inputs_sha256)
            elif args.action == 'attest':
                value = modules['crypto'].attest(Path(args.inputs), common.read(args.request), args.request_sha256, Path(args.output))
            elif args.action == 'consume-provenance':
                value = modules['provenance'].consume(Path(args.inputs), common.read(args.request), args.request_sha256,
                    common.read(args.base), args.base_sha256)
                raw = common.encoded(value)
                common.need(len(raw) <= common.FILE_LIMIT, 'metadata publication bound')
                modules['crypto'].Publication(Path(args.output).absolute()).publish(raw)
            else:
                value = modules['orchestrator'].post_terminal(Path(args.inputs), common.read(args.authority), args.authority_sha256,
                    common.read(args.crypto), args.crypto_sha256, common.read(args.metadata), args.metadata_sha256)
        print(json.dumps(value, sort_keys=True))
        return 0 if value['status'] == 'PASS' else 2 if value['status'] == 'NOT RUN' else 1
    except BaseException as error:
        print(json.dumps({'status': 'FAIL', 'error_type': type(error).__name__, 'native_end_to_end': 'NOT RUN'}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
