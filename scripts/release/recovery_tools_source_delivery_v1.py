#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Export/verify/unpack exact offline recovery-tools recipe sources, without execution.

The caller supplies an independently trusted profile SHA-256. A source bundle
and its observed checksum establish byte custody, never release acceptance.
"""
import argparse
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import tempfile

sys.dont_write_bytecode = True
PROFILE_NAME = 'recovery-tools-source-profile-v1.json'
ADAPTER_NAME = 'recovery_tools_source_delivery_v1.py'
MAX_FILE, MAX_TOTAL, MAX_FILES = 4 * 1024**2, 32 * 1024**2, 256
HEX = re.compile(r'[0-9a-f]{64}\Z')
LEAF = re.compile(r'[A-Za-z0-9._+-]{1,128}\Z')


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def absolute(path):
    path = Path(path)
    need(path.is_absolute() and path.anchor == '/' and '..' not in path.parts,
         'canonical absolute path required')
    return path


def relative(name):
    need(type(name) is str and 0 < len(name) <= 240, 'bounded relative source path required')
    path = PurePosixPath(name)
    need(not path.is_absolute() and path.as_posix() == name and len(path.parts) <= 12
         and all(LEAF.fullmatch(part) and part not in ('.', '..') for part in path.parts),
         'safe relative source path required')
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
             'bounded regular single-link source file required')
        chunks, count = [], 0
        while True:
            block = os.read(fd, min(65536, limit - count + 1))
            if not block:
                break
            count += len(block)
            need(count <= limit, 'source byte bound exceeded')
            chunks.append(block)
        after = os.fstat(fd)
        fields = ('st_dev', 'st_ino', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(all(getattr(before, field) == getattr(after, field) for field in fields),
             'source changed during read')
        return b''.join(chunks), stat.S_IMODE(after.st_mode)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def profile(raw, expected):
    need(type(expected) is str and HEX.fullmatch(expected) and sha(raw) == expected,
         'source profile checksum mismatch')
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate profile key')
            value[key] = item
        return value
    value = json.loads(raw, object_pairs_hook=pairs,
                       parse_constant=lambda _: need(False, 'nonfinite source profile number refused'))
    need(type(value) is dict and set(value) == {'schema_version', 'purpose', 'package', 'version', 'files'},
         'source profile fields differ')
    need(type(value['schema_version']) is int and value['schema_version'] == 1
         and value['purpose'] == 'recovery-tools-recipe-source'
         and value['package'] == 'cachy-asahi-recovery-tools'
         and type(value['version']) is str and re.fullmatch(r'[0-9][A-Za-z0-9.+_-]{0,63}', value['version']),
         'source profile identity differs')
    files = value['files']
    need(type(files) is dict and 2 <= len(files) <= MAX_FILES
         and {'PKGBUILD', '.SRCINFO'} <= set(files), 'finite complete recipe profile required')
    for name, row in files.items():
        path = relative(name)
        need(not any(parent.as_posix() in files for parent in path.parents if parent.as_posix() != '.'),
             'file/directory collision in profile')
        need(type(row) is dict and set(row) == {'sha256', 'bytes', 'mode'}, 'source descriptor fields differ')
        need(type(row['sha256']) is str and HEX.fullmatch(row['sha256'])
             and type(row['bytes']) is int and 0 <= row['bytes'] <= MAX_FILE
             and type(row['mode']) is int and row['mode'] in (0o644, 0o755),
             'source descriptor bounds refused')
    need(sum(row['bytes'] for row in files.values()) <= MAX_TOTAL // 2, 'recipe total byte bound exceeded')
    return value


def scan(recipe):
    """Descriptor-relative enumeration rejects symlinks, hardlinks and special nodes."""
    files, dirs, count = set(), set(), 0
    root = directory(recipe)
    try:
        def walk(fd, prefix=''):
            nonlocal count
            for leaf in sorted(os.listdir(fd)):
                name = prefix + leaf
                relative(name)
                count += 1
                need(count <= MAX_FILES * 4, 'source node bound exceeded')
                info = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    dirs.add(name)
                    child = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        walk(child, name + '/')
                    finally:
                        os.close(child)
                else:
                    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                         'regular single-link recipe members required')
                    files.add(name)
                    need(len(files) <= MAX_FILES, 'recipe file count exceeded')
        walk(root)
    finally:
        os.close(root)
    wanted_dirs = {p.as_posix() for name in files for p in PurePosixPath(name).parents if p.as_posix() != '.'}
    need(dirs == wanted_dirs, 'empty or unrecorded source directory refused')
    return files


def entries(value, recipe, profile_raw, adapter_raw):
    wanted = set(value['files'])
    need(scan(recipe) == wanted, 'recipe file set differs from finite profile')
    result = {}
    for name, row in value['files'].items():
        raw, mode = read(recipe / name)
        need(len(raw) == row['bytes'] and sha(raw) == row['sha256'] and mode == row['mode'],
             'recipe input mismatch: ' + name)
        result['recipe/' + name] = (raw, mode)
    need(scan(recipe) == wanted, 'recipe changed during export')
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
    need(len(raw) <= MAX_TOTAL, 'source bundle byte bound exceeded')
    return raw


def verified(raw, expected, value, profile_raw, adapter_raw):
    need(type(expected) is str and HEX.fullmatch(expected) and sha(raw) == expected,
         'source bundle checksum mismatch')
    need(len(raw) <= MAX_TOTAL, 'source bundle byte bound exceeded')
    required = {'recipe/' + name: row for name, row in value['files'].items()}
    required.update({'delivery/' + PROFILE_NAME: dict(sha256=sha(profile_raw), bytes=len(profile_raw), mode=0o644),
                     'delivery/' + ADAPTER_NAME: dict(sha256=sha(adapter_raw), bytes=len(adapter_raw), mode=0o755)})
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as source:
        for item in source:
            need(len(files) < MAX_FILES + 2 and item.name in required and item.name not in files,
                 'unexpected/duplicate source member')
            row = required[item.name]
            need(item.isfile() and not item.pax_headers and item.size == row['bytes'] and item.size <= MAX_FILE
                 and item.mode == row['mode'] and item.uid == item.gid == item.mtime == 0
                 and item.uname == item.gname == '', 'unsafe/noncanonical source member')
            with source.extractfile(item) as stream:
                body = stream.read(MAX_FILE + 1)
            need(len(body) == row['bytes'] and sha(body) == row['sha256'], 'source member checksum mismatch')
            files[item.name] = (body, row['mode'])
    need(set(files) == set(required), 'source bundle member coverage mismatch')
    need(archive(files) == raw, 'source bundle encoding differs from canonical USTAR')
    return files


def write_file(parent, leaf, raw, mode):
    fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent)
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


def fresh(path, files):
    """Publish a complete private tree atomically; never reuse/delete foreign output."""
    path = absolute(path)
    parent = directory(path.parent)
    try:
        info = os.fstat(parent)
        need(info.st_uid == os.geteuid() and not info.st_mode & 0o022,
             'caller-owned output parent without group/world writes required')
        with tempfile.TemporaryDirectory(prefix='.recovery-source-', dir=path.parent) as temporary:
            staging = Path(temporary) / 'output'
            staging.mkdir(mode=0o700)
            for name, (raw, mode) in sorted(files.items()):
                relative(name)
                target = staging / name
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                fd = directory(target.parent)
                try:
                    write_file(fd, target.name, raw, mode)
                finally:
                    os.close(fd)
            source = directory(Path(temporary))
            try:
                libc = ctypes.CDLL(None, use_errno=True)
                rename = getattr(libc, 'renameat2', None)
                need(rename is not None, 'Linux renameat2 required for no-replace publication')
                rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
                rename.restype = ctypes.c_int
                before = os.stat('output', dir_fd=source, follow_symlinks=False)
                if rename(source, b'output', parent, os.fsencode(path.name), 1):
                    error = ctypes.get_errno()
                    raise OSError(error, os.strerror(error))
                after = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                need((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino),
                     'published source identity differs')
                visible = directory(path.parent)
                try:
                    seen = os.fstat(visible)
                    need((info.st_dev, info.st_ino) == (seen.st_dev, seen.st_ino), 'output parent changed')
                finally:
                    os.close(visible)
                os.fsync(parent)
            finally:
                os.close(source)
    finally:
        os.close(parent)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest='action', required=True)
    pack = subs.add_parser('pack')
    pack.add_argument('--recipe', type=Path, required=True)
    pack.add_argument('--output', type=Path, required=True, help='Absent output directory with private parent')
    for action in ('verify', 'unpack'):
        child = subs.add_parser(action)
        child.add_argument('--bundle', type=Path, required=True)
        child.add_argument('--sha256', required=True)
        if action == 'unpack':
            child.add_argument('--output', type=Path, required=True)
    for child in subs.choices.values():
        child.add_argument('--profile', type=Path, required=True)
        child.add_argument('--profile-sha256', required=True)
    args = parser.parse_args(argv)
    try:
        profile_raw, _ = read(absolute(args.profile))
        adapter_raw, _ = read(Path(__file__).absolute())
        value = profile(profile_raw, args.profile_sha256)
        if args.action == 'pack':
            bodies = entries(value, absolute(args.recipe), profile_raw, adapter_raw)
            raw = archive(bodies)
            verified(raw, sha(raw), value, profile_raw, adapter_raw)
            receipt = dict(schema_version=1, purpose='recovery-tools-source-delivery',
                package=value['package'], version=value['version'], source_sha256=sha(raw),
                source_bytes=len(raw), profile_sha256=args.profile_sha256, recipe_files=len(value['files']),
                code_executed=False, network=False, release_accepted=False)
            fresh(args.output, {'source.tar': (raw, 0o600), 'receipt.json': (encoded(receipt), 0o600)})
            result = dict(status='EXPORTED_EXACT_RECOVERY_TOOL_SOURCES', **receipt)
        else:
            raw, _ = read(absolute(args.bundle), MAX_TOTAL)
            bodies = verified(raw, args.sha256, value, profile_raw, adapter_raw)
            if args.action == 'unpack':
                fresh(args.output, bodies)
            result = dict(status='UNPACKED_EXACT_SOURCES' if args.action == 'unpack' else 'VERIFIED_EXACT_SOURCES',
                          package=value['package'], recipe_files=len(value['files']),
                          source_sha256=args.sha256, code_executed=False, release_accepted=False)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError, tarfile.TarError, EOFError) as error:
        print('recovery-tools source refused: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
