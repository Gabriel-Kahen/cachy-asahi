#!/usr/bin/env python3
"""Reproduce one fixed diagnostic source tree; never execute its actors."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

HERE = Path(__file__).resolve().parent
PROFILE_SHA = 'cc9b01a54815b8972a19b4cd4b739143b581256b254ade06d33b804f0d03e2f2'


def need(condition, message):
    if not condition:
        raise ValueError(message)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def identity(value):
    # Reading a regular file can change atime under relatime.
    return tuple(getattr(value, name) for name in (
        'st_mode', 'st_dev', 'st_ino', 'st_nlink', 'st_uid', 'st_gid',
        'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def read(path):
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'ordinary single-link file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        need(identity(os.fstat(stream.fileno())) == identity(before), 'opened file identity')
        raw = stream.read()
        need(identity(os.fstat(stream.fileno())) == identity(before), 'stable file identity')
    need(identity(path.lstat()) == identity(before), 'stable path identity')
    return raw


def tree(root, checkout=False):
    need(root.is_dir() and not root.is_symlink(), 'ordinary source root')
    result = {}
    for directory, dirs, names in os.walk(root, followlinks=False):
        directory = Path(directory)
        if directory == root and checkout:
            dirs[:] = [name for name in dirs if name != '.git']
            names = [name for name in names if name != '.git']
        for name in dirs:
            need(stat.S_ISDIR((directory / name).lstat().st_mode), 'ordinary source directory')
        for name in names:
            path = directory / name
            result[path.relative_to(root).as_posix()] = read(path)
    return result


def pins(rows):
    return {name: pin(raw) for name, raw in rows.items()}


def profile():
    raw = read(HERE / 'profile.json')
    need(pin(raw)['sha256'] == PROFILE_SHA, 'whole fixed source profile')
    value = json.loads(raw)
    need(len(value['before']) == len(value['after']) == 489, 'closed source489')
    need(value['before'].keys() == value['after'].keys(), 'same closed membership')
    changed = {name: dict(before=value['before'][name], after=value['after'][name])
               for name in value['before'] if value['before'][name] != value['after'][name]}
    need(changed == value['changed'] and len(changed) == 6 and value['held'] == 483,
         'six changed and483 held')
    return value


def emit(parent, output):
    parent, output = Path(parent).absolute(), Path(output).absolute()
    need(not output.is_symlink(), 'fresh ordinary output path')
    need(not parent.is_symlink(), 'ordinary source root')
    # resolve() also catches a symlink in an ancestor of the proposed output.
    parent, output = parent.resolve(), output.resolve()
    need(not output.exists(), 'fresh output required')
    for source in (parent, HERE):
        need(not output.is_relative_to(source) and not source.is_relative_to(output),
             'disjoint output required')
    value = profile()
    original = tree(parent, checkout=True)
    need(pins(original) == value['before'], 'whole pinned parent489')
    replacements = tree(HERE / 'payload')
    need(pins(replacements) == {name: row['after'] for name, row in value['changed'].items()},
         'whole six replacement payloads')
    rows = original | replacements
    need(pins(rows) == value['after'], 'complete output489 before creation')
    # All source gates run before creating anything at the requested output.
    output.mkdir(mode=0o700, parents=False)
    for name, raw in sorted(rows.items()):
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(raw)
    need(pins(tree(output)) == value['after'], 'complete emitted output489')
    return dict(status='SOURCE_ONLY', files=489, changed=6, held=483,
                parent_source=value['parent_source'], expected_source=value['expected_source'],
                native_fit='UNQUALIFIED', acceptance=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', required=True, type=Path,
                        help='complete immutable5c7e4c9 source checkout')
    parser.add_argument('--output', required=True, type=Path, help='fresh disjoint output directory')
    args = parser.parse_args()
    print(json.dumps(emit(args.parent, args.output), sort_keys=True))


if __name__ == '__main__':
    main()
