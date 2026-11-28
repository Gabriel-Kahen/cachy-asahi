#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Copy an exact subset of retained native inputs into the private build cache."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat

ROOT = Path(__file__).resolve().parents[3]


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def planned_files():
    adapter = runpy.run_path(str(ROOT / 'packages/tools/cachy-asahi-update/updater-native.py'))
    inputs, _ = adapter['plan']()
    files = {row['filename']: (row['size'], row['sha256']) for row in inputs['keyring_files']}
    for row in [inputs['rootfs'], *inputs['packages']]:
        files[row['filename']] = (row['size'], row['sha256'])
        files[row['filename'] + '.sig'] = (row['signature_size'], row['signature_sha256'])
    need(len(files) == 527, 'exact native input closure required')
    return files


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def copy_member(source, target, name, expected):
    size, checksum = expected
    read_only = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(name, read_only, dir_fd=source), 'rb') as reader:
        before = os.fstat(reader.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1
             and not before.st_mode & 0o077 and before.st_size == size, 'retained input identity')
        digest, remaining = hashlib.sha256(), size
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        with os.fdopen(os.open(name, flags, 0o600, dir_fd=target), 'wb') as writer:
            while remaining:
                data = reader.read(min(remaining, 1024**2))
                need(data, 'truncated retained input')
                digest.update(data)
                writer.write(data)
                remaining -= len(data)
            need(not reader.read(1) and digest.hexdigest() == checksum, 'retained input bytes')
            named = os.stat(name, dir_fd=source, follow_symlinks=False)
            need(identity(before) == identity(os.fstat(reader.fileno())) == identity(named),
                 'retained input changed')


def seed(source, target, expected):
    need(source.is_absolute() and source.resolve(strict=True) == source
         and target.is_absolute() and target.parent.resolve(strict=True) == target.parent
         and source == target.parent.parent.parent / 'retained-cache',
         'retained cache must be a separate canonical control directory')
    uid = os.getuid()
    need(uid == os.geteuid() > 0, 'ordinary caller required')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    source_fd = os.open(source, flags)
    try:
        before = os.fstat(source_fd)
        need(before.st_uid == uid and stat.S_IMODE(before.st_mode) == 0o700
             and identity(before) == identity(source.lstat()), 'private retained directory required')
        names = set()
        with os.scandir(source_fd) as entries:
            for entry in entries:
                need(entry.name in expected, 'foreign retained input')
                names.add(entry.name)
        need(names, 'nonempty retained cache required')
        target.mkdir(mode=0o700)
        target_fd = os.open(target, flags)
        try:
            info = os.fstat(target_fd)
            need(info.st_uid == uid and stat.S_IMODE(info.st_mode) == 0o700
                 and identity(info) == identity(target.lstat()), 'private build cache required')
            for name in sorted(names):
                copy_member(source_fd, target_fd, name, expected[name])
        finally:
            os.close(target_fd)
        need(identity(before) == identity(os.fstat(source_fd)) == identity(source.lstat()),
             'retained directory changed')
    finally:
        os.close(source_fd)
    return {'copied': len(names), 'bytes': sum(expected[name][0] for name in names)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--target', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(seed(args.source, args.target, planned_files()), sort_keys=True))
