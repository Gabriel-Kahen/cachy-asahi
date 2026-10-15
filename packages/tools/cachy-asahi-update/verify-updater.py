#!/usr/bin/env python3
"""Rehash patched updater inputs before executing Makefile/check/package code."""
import argparse
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import sys
import tarfile
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
LEDGER_SHA256 = '0c32e24733618a6ad734d1908e78d4ebe72fb5f4d089ae7074cac6045b97863e'


def verify(root):
    spec = importlib.util.spec_from_file_location('updater_input_reader', HERE / 'worker-metadata.py')
    worker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(worker)
    raw = worker.regular(HERE / 'patched-source-ledger.json', 1024 * 1024)
    if hashlib.sha256(raw).hexdigest() != LEDGER_SHA256:
        raise ValueError('frozen patched source ledger changed')
    ledger = worker.load(raw)
    expected = ledger['files']
    if ledger['schema_version'] != 1 or len(expected) != 98:
        raise ValueError('complete original patched source ledger required')
    if not root.is_relative_to('/tmp') or root.resolve(strict=True) != root:
        raise ValueError('canonical private source directory required')
    allowed = {'doc/man/arch-update.1', 'doc/man/arch-update.conf.5'}
    allowed |= {path[:-3] + '.mo' for path in expected if path.startswith('po/') and path.endswith('.po')}
    found, count, deadline = set(), 0, time.monotonic() + 30
    for directory, dirs, names in os.walk(root, followlinks=False):
        directory = Path(directory)
        for name in list(dirs):
            path = directory / name
            if path.is_symlink():
                raise ValueError('source directory symlink refused')
            if path == root / 'src/tray/target':
                if path.resolve(strict=True) != path:
                    raise ValueError('unsafe Cargo output directory')
                dirs.remove(name)
        for name in names:
            path = directory / name
            relative = path.relative_to(root).as_posix()
            count += 1
            if count > 512 or time.monotonic() > deadline:
                raise ValueError('source traversal bound')
            data = worker.regular(path, 8 * 1024 * 1024)
            if relative in expected:
                item = expected[relative]
                if (hashlib.sha256(data).hexdigest() != item['sha256']
                        or stat.S_IMODE(path.stat().st_mode) != item['mode']):
                    raise ValueError('patched input changed: ' + relative)
                found.add(relative)
            elif relative not in allowed:
                raise ValueError('unreviewed extra updater input: ' + relative)
    if found != set(expected):
        raise ValueError('patched updater input missing')
    return len(found)


def materialize_notices(destination):
    """Read exact authenticated vendor bytes; never trust mutable LICENSES copies."""
    spec = importlib.util.spec_from_file_location('updater_notice_reader', HERE / 'worker-metadata.py')
    worker = importlib.util.module_from_spec(spec);spec.loader.exec_module(worker)
    if (not destination.is_relative_to('/tmp') or destination.exists() or destination.is_symlink()
            or destination.parent.resolve(strict=True) != destination.parent):
        raise ValueError('fresh canonical private notice directory required')
    raw = worker.regular(HERE / 'cachy-update-vendor.tar.gz', 512 * 1024 * 1024)
    if hashlib.sha256(raw).hexdigest() != 'e44dd795d5c392e37f44f63e041f25055924b75784b990788b24a80b442d5a9c':
        raise ValueError('immutable vendor archive changed')
    destination.mkdir(mode=0o700)
    found, expanded, notice_bytes, deadline = set(), 0, 0, time.monotonic() + 120
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r|gz') as archive:
        for count, member in enumerate(archive, 1):
            parts = member.name.rstrip('/').split('/')
            expanded += member.size
            if (count > 20000 or expanded > 512 * 1024 * 1024 or time.monotonic() > deadline
                    or member.name.startswith('/') or '\\' in member.name
                    or any(part in ('', '.', '..') for part in parts)
                    or not (member.isdir() or member.isfile())):
                raise ValueError('bounded regular vendor archive required')
            if not member.name.startswith('LICENSES/') or member.isdir():
                continue
            name = member.name[len('LICENSES/'):]
            notice_bytes += member.size
            if name in found or member.size > 8 * 1024 * 1024 or notice_bytes > 32 * 1024 * 1024:
                raise ValueError('notice path/size bound')
            found.add(name)
            path = destination / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('xb') as output:
                output.write(archive.extractfile(member).read())
            path.chmod(0o644)
    if len(found) != 1113 or notice_bytes != 11735034:
        raise ValueError('complete frozen notice data required')
    return len(found)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--materialize-notices', type=Path)
    args = parser.parse_args()
    if args.source:
        print('Verified ' + str(verify(args.source.absolute())) + ' patched source inputs')
    elif args.materialize_notices:
        print('Retained ' + str(materialize_notices(args.materialize_notices.absolute())) + ' immutable notice inputs; distribution NOT ACCEPTED')
    else:
        parser.error('source or fresh notice destination required')
