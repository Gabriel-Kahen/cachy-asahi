#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify/export the exact Source102 PGO view; never build, train or acquire."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys

ROOT = Path(__file__).resolve().parents[2]
PROFILE = 'scripts/experiments/zlib_pgo102-profile.json'
PROFILE_SHA256 = 'f1b7f2f35dacfe84e77aa1e17383781aea94d2737c23198d6f5796493a0c6a25'
RECIPE = 'packages/experiments/cachy-asahi-zlib-pgo-v1'
MAX_FILE, MAX_TOTAL = 8 * 1024**2, 16 * 1024**2


def need(ok, message):
    if not ok:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def relative(name):
    need(type(name) is str and name and '\\' not in name and '\x00' not in name, 'ordinary relative name required')
    path = PurePosixPath(name)
    need(not path.is_absolute() and path.as_posix() == name and
         all(part not in ('.', '..') for part in path.parts), 'relative path alias refused')
    return path.parts


def directory(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and not str(path).startswith('//'), 'absolute ordinary directory required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def read(root, name):
    parts = relative(name); parent = directory(root); fd = None
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent); parent = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= MAX_FILE,
             'bounded ordinary single-link source required')
        chunks = []; count = 0
        while True:
            block = os.read(fd, min(65536, MAX_FILE-count+1))
            if not block: break
            count += len(block); need(count <= MAX_FILE, 'source byte cap'); chunks.append(block)
        need(identity(before) == identity(os.fstat(fd)) and count == before.st_size, 'source changed while reading')
        raw = b''.join(chunks)
        return raw, dict(bytes=count, sha256=digest(raw), mode=stat.S_IMODE(before.st_mode))
    finally:
        if fd is not None: os.close(fd)
        os.close(parent)


def checked(root=ROOT):
    root = Path(root); raw, row = read(root, PROFILE)
    need(row['sha256'] == PROFILE_SHA256 and row['mode'] == 0o644, 'immutable PGO102 adoption profile changed')
    profile = json.loads(raw)
    need(profile['schema'] == 1 and profile['purpose'] == 'zlib-pgo102-canonical-view-v1' and
         profile['qualified_source'] == '3ee4b0ae221429385e738f4df01eac1b730f36ee', 'Source102 profile identity')
    files = profile['files']; need(len(files) == 39, 'complete Source102 view required')
    contents = {}; total = 0
    for virtual, expected in files.items():
        relative(virtual); body, actual = read(root, expected['source'])
        need(actual == {k: expected[k] for k in ('bytes', 'sha256', 'mode')}, 'pinned canonical source differs: '+virtual)
        total += len(body); need(total <= MAX_TOTAL, 'whole PGO source view cap')
        contents[virtual] = body
    manifest = json.loads(contents['PGO-SOURCE.json'])
    need(digest(contents['PGO-SOURCE.json']) == profile['pgo_manifest_sha256'] and
         manifest['actual'] is None and set(manifest['files']) | {'PGO-SOURCE.json'} == set(files),
         'original exact closed source map differs')
    need(all(manifest['files'][name] == {k: files[name][k] for k in ('bytes', 'sha256', 'mode')}
             for name in manifest['files']), 'original map/material binding differs')
    admission = profile['admission']; body, actual = read(root, admission['source'])
    need(actual == {k: admission[k] for k in ('bytes', 'sha256', 'mode')}, 'Root component record changed')
    return profile, contents


def verify_export(output, profile):
    output = Path(output); fd = directory(output); os.close(fd)
    expected = set(profile['files']); actual = set(); dirs = set()
    expected_dirs = {p.as_posix() for name in expected for p in PurePosixPath(name).parents if p != PurePosixPath('.')}
    for base, directories, names in os.walk(output, followlinks=False):
        for name in directories:
            path = Path(base)/name
            need(stat.S_ISDIR(path.lstat().st_mode), 'export directory alias refused')
            dirs.add(path.relative_to(output).as_posix())
        for name in names:
            path = Path(base)/name; virtual = path.relative_to(output).as_posix()
            need(virtual in expected, 'extra export file')
            _, row = read(output, virtual)
            need(row == {k: profile['files'][virtual][k] for k in ('bytes', 'sha256', 'mode')}, 'export byte/mode mismatch')
            actual.add(virtual)
    need(actual == expected and dirs == expected_dirs, 'exact export namespace required')


def export(output, root=ROOT):
    profile, contents = checked(root); output = Path(output); root = Path(root)
    need(output.is_absolute() and '..' not in output.parts and not str(output).startswith('//') and
         output.name not in ('', '.', '..') and not output.is_relative_to(root) and not root.is_relative_to(output),
         'fresh export outside the executable checkout required')
    parent = directory(output.parent)
    try:
        os.mkdir(output.name, 0o700, dir_fd=parent)
        target = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        for virtual, body in sorted(contents.items()):
            parts = relative(virtual); current = os.dup(target)
            try:
                for part in parts[:-1]:
                    try: os.mkdir(part, 0o700, dir_fd=current)
                    except FileExistsError: pass
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                    os.close(current); current = child
                fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=current)
                try:
                    view = memoryview(body)
                    while view:
                        size = os.write(fd, view); need(size > 0, 'short export write'); view = view[size:]
                    os.fchmod(fd, profile['files'][virtual]['mode']); os.fsync(fd)
                finally:
                    os.close(fd)
            finally:
                os.close(current)
        os.fsync(target)
    finally:
        os.close(target)
    verify_export(output, profile)
    return dict(status='EXACT_SOURCE102_VIEW_EXPORTED_NOT_EXECUTED', source=profile['qualified_source'],
                profile_sha256=PROFILE_SHA256, files=39, recipe=str(output/RECIPE),
                plan_entrypoint=str(output/'scripts/experiments/zlib_pgo_native_plan.py'),
                builder=str(output/'scripts/build/build_v2.py'), native_execution='NOT_RUN',
                performance_acceptance=False, release_acceptance=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    sub.add_parser('verify')
    child = sub.add_parser('export'); child.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.mode == 'export': result = export(args.output)
        else:
            profile, _ = checked()
            result = dict(status='EXACT_SOURCE102_CANONICAL_INPUTS_VERIFIED', files=39,
                          source=profile['qualified_source'], native_execution='NOT_RUN')
        print(json.dumps(result, sort_keys=True, indent=2)); return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr); return 1


if __name__ == '__main__':
    raise SystemExit(main())
