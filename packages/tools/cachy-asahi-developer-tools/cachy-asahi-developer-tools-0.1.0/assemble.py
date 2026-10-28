#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Copy a verified finite payload into a fresh private DESTDIR; never install live."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat


def verified_rows(source):
    manifest = json.loads((source / 'payload-map.json').read_text())
    rows, expected = [], set()
    for row in manifest['files']:
        relative = PurePosixPath(row['path'])
        if (relative.is_absolute() or '..' in relative.parts or str(relative) != row['path']
                or str(relative) in expected or row['mode'] not in (0o644, 0o755)):
            raise ValueError('invalid payload map')
        expected.add(str(relative))
        path = source / 'payload' / relative
        for ancestor in (path, *path.parents):
            if ancestor.is_symlink():
                raise ValueError('source aliases refused')
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size != row['bytes'] or info.st_size > 1024 * 1024:
            raise ValueError('bounded ordinary payload file required')
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != row['sha256'] or stat.S_IMODE(info.st_mode) != row['mode']:
            raise ValueError('payload bytes or mode differ')
        rows.append((relative, raw, row['mode']))
    observed = set()
    for path in (source / 'payload').rglob('*'):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('payload links and special files refused')
        observed.add(str(path.relative_to(source / 'payload')))
    if observed != expected:
        raise ValueError('payload file set differs')
    return rows


def assemble(source, destdir, prefix='/usr'):
    rows = verified_rows(Path(source))  # Verify everything before creating output.
    destdir = Path(destdir).absolute()
    relative = PurePosixPath(prefix)
    if not relative.is_absolute() or '..' in relative.parts or str(relative) != prefix:
        raise ValueError('normalized absolute prefix required')
    if destdir in (Path('/'), Path('/usr'), Path('/usr/local'), Path.home()):
        raise ValueError('live installation destination refused')
    for path in (destdir, *destdir.parents):
        if path.is_symlink():
            raise ValueError('destination aliases refused')
    if destdir.exists() and (not destdir.is_dir() or any(destdir.iterdir())):
        raise ValueError('fresh or empty private DESTDIR required')
    destdir.mkdir(mode=0o700, exist_ok=True)
    target = destdir.joinpath(*relative.parts[1:])
    for name, raw, mode in rows:
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(raw)
        path.chmod(mode)
    return target


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destdir', required=True, type=Path)
    parser.add_argument('--prefix', default='/usr')
    args = parser.parse_args()
    try:
        print(assemble(Path(__file__).resolve().parent, args.destdir, args.prefix))
    except (OSError, ValueError) as error:
        parser.exit(2, str(error) + '\n')
