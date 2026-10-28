#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite offline recipe source delivery; no bundled program is executed."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile

PROFILE_SHA256 = 'cafd87217ae5fd3e461b36637ae4acfb223bd54e231daf841bb7d45eb327df4f'
PROFILE_NAME = 'security_maintenance_source_profile_v2.json'
ADAPTER_NAME = 'security_maintenance_source_delivery_v2.py'
MAX_FILE = 2 * 1024**2
MAX_BUNDLE = 16 * 1024**2
MAX_FILES = 128
HEX = re.compile(r'[0-9a-f]{64}\Z')
LEAF = re.compile(r'[A-Za-z0-9._+-]{1,128}\Z')


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def absolute(path):
    path = Path(path)
    need(path.is_absolute() and path.anchor == '/' and '..' not in path.parts,
         'canonical absolute path required')
    return path


def directory(path):
    path = absolute(path)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def read(path, limit=MAX_FILE):
    path = absolute(path)
    parent = directory(path.parent)
    fd = None
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit,
             'ordinary bounded single-link source file required')
        chunks, count = [], 0
        while True:
            block = os.read(fd, min(65536, limit - count + 1))
            if not block:
                break
            count += len(block)
            need(count <= limit, 'source byte bound')
            chunks.append(block)
        after = os.fstat(fd)
        need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
             'source changed during read')
        return b''.join(chunks)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def profile(raw, expected):
    need(type(expected) is str and HEX.fullmatch(expected) and sha(raw) == expected,
         'source profile checksum mismatch')
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate profile key')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs)
    need(type(value) is dict and set(value) == {'schema_version', 'purpose', 'package', 'version', 'files'},
         'source profile fields')
    need(type(value['schema_version']) is int and value['schema_version'] == 1 and
         value['purpose'] == 'security-maintenance-recipe-source' and
         value['package'] == 'cachy-asahi-security-maintenance' and
         type(value['version']) is str and re.fullmatch(r'[0-9][A-Za-z0-9.+_-]{0,63}', value['version']),
         'source profile identity')
    files = value['files']
    need(type(files) is dict and 2 <= len(files) <= MAX_FILES and {'PKGBUILD', '.SRCINFO'} <= set(files),
         'finite complete recipe profile required')
    for name, row in files.items():
        need(type(name) is str and LEAF.fullmatch(name) and name not in ('.', '..'), 'flat recipe paths required')
        need(type(row) is dict and set(row) == {'sha256', 'bytes', 'mode'}, 'source descriptor fields')
        need(type(row['sha256']) is str and HEX.fullmatch(row['sha256']) and
             type(row['bytes']) is int and 0 < row['bytes'] <= MAX_FILE and
             type(row['mode']) is int and row['mode'] in (0o644, 0o755), 'source descriptor bounds')
    need(sum(row['bytes'] for row in files.values()) <= MAX_BUNDLE // 2, 'recipe total byte bound')
    return value


def entries(value, recipe, profile_raw, adapter_raw):
    result = {}
    for name, row in value['files'].items():
        raw = read(recipe / name)
        need(len(raw) == row['bytes'] and sha(raw) == row['sha256'], 'recipe input mismatch: ' + name)
        result['recipe/' + name] = (raw, row['mode'])
    # Reject unexpected files before exporting a purportedly complete recipe.
    fd = directory(recipe)
    try:
        need(set(os.listdir(fd)) == set(value['files']), 'recipe file set differs from finite profile')
    finally:
        os.close(fd)
    result['delivery/' + PROFILE_NAME] = (profile_raw, 0o644)
    result['delivery/' + ADAPTER_NAME] = (adapter_raw, 0o755)
    return result


def archive(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as target:
        for name, (raw, mode) in sorted(files.items()):
            item = tarfile.TarInfo(name)
            item.size, item.mode = len(raw), mode
            item.uid = item.gid = item.mtime = 0
            item.uname = item.gname = ''
            target.addfile(item, io.BytesIO(raw))
    raw = stream.getvalue()
    need(len(raw) <= MAX_BUNDLE, 'source bundle byte bound')
    return raw


def verified(raw, expected, value, profile_raw, adapter_raw):
    need(type(expected) is str and HEX.fullmatch(expected) and sha(raw) == expected,
         'source bundle checksum mismatch')
    need(len(raw) <= MAX_BUNDLE, 'source bundle byte bound')
    required = {'recipe/' + name: row for name, row in value['files'].items()}
    required.update({'delivery/' + PROFILE_NAME: dict(sha256=sha(profile_raw), bytes=len(profile_raw), mode=0o644),
                     'delivery/' + ADAPTER_NAME: dict(sha256=sha(adapter_raw), bytes=len(adapter_raw), mode=0o755)})
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as source:
        for item in source:
            need(len(files) < MAX_FILES + 2 and item.name in required and item.name not in files,
                 'unexpected/duplicate source member')
            row = required[item.name]
            need(item.isfile() and not item.pax_headers and item.size == row['bytes'] and item.size <= MAX_FILE and
                 item.mode == row['mode'] and item.uid == item.gid == item.mtime == 0 and
                 item.uname == item.gname == '', 'unsafe/noncanonical source member')
            with source.extractfile(item) as stream:
                body = stream.read(MAX_FILE + 1)
            need(len(body) == row['bytes'] and sha(body) == row['sha256'], 'source member checksum mismatch')
            files[item.name] = (body, row['mode'])
    need(set(files) == set(required), 'source bundle member coverage mismatch')
    need(archive(files) == raw, 'source bundle encoding differs from canonical USTAR')
    return files


def write_file(parent, name, raw, mode):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            need(count > 0, 'short source output write')
            view = view[count:]
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)


def publish(path, raw):
    path = absolute(path)
    parent = directory(path.parent)
    try:
        write_file(parent, path.name, raw, 0o600)
        os.fsync(parent)
    finally:
        os.close(parent)


def unpack(path, files):
    path = absolute(path)
    parent = directory(path.parent)
    root = None
    try:
        os.mkdir(path.name, 0o700, dir_fd=parent)
        root = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        os.fchmod(root, 0o700)
        for dirname in ('delivery', 'recipe'):
            os.mkdir(dirname, 0o700, dir_fd=root)
            child = os.open(dirname, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
            try:
                for name, (raw, mode) in sorted(files.items()):
                    parts = PurePosixPath(name).parts
                    need(len(parts) == 2, 'flat bundle member required')
                    if parts[0] == dirname:
                        write_file(child, parts[1], raw, mode)
                os.fsync(child)
            finally:
                os.close(child)
        os.fsync(root)
        os.fsync(parent)
    finally:
        if root is not None:
            os.close(root)
        os.close(parent)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest='action', required=True)
    pack = subs.add_parser('pack')
    pack.add_argument('--recipe', type=Path, required=True)
    pack.add_argument('--output', type=Path, required=True)
    for action in ('verify', 'unpack'):
        child = subs.add_parser(action)
        child.add_argument('--bundle', type=Path, required=True)
        child.add_argument('--sha256', required=True)
        if action == 'unpack':
            child.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        own = Path(__file__).absolute()
        profile_raw, adapter_raw = read(own.with_name(PROFILE_NAME)), read(own)
        value = profile(profile_raw, PROFILE_SHA256)
        if args.action == 'pack':
            raw = archive(entries(value, absolute(args.recipe), profile_raw, adapter_raw))
            publish(args.output, raw)
        else:
            raw = read(args.bundle, MAX_BUNDLE)
            files = verified(raw, args.sha256, value, profile_raw, adapter_raw)
            if args.action == 'unpack':
                unpack(args.output, files)
        print(json.dumps(dict(status='SOURCE_BYTES_ONLY', package=value['package'], version=value['version'],
                             sha256=sha(raw), bytes=len(raw), native='NOT_RUN', installed='NOT_RUN',
                             legal_acceptance=False, source_completeness_accepted=False), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, tarfile.TarError) as error:
        print('security maintenance source: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
