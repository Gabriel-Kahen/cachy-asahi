#!/usr/bin/env python3
"""Validate disposable CI archive caches against a fresh APT SHA256 URI plan.

This helper never executes APT, installs packages, or trusts cache metadata.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile


def read_plan(path):
    rows = {}
    for line in path.read_text().splitlines():
        if not line.startswith("'"):
            continue  # APT's human-readable dependency summary.
        match = re.fullmatch(r"'[^'\r\n]+' ([A-Za-z0-9][A-Za-z0-9.+%:~_-]*\.deb) ([0-9]+) SHA256:([a-fA-F0-9]{64})", line)
        if match is None:
            raise ValueError('APT URI row lacks a safe filename, size or SHA256')
        name, size, digest = match.groups()
        if name in rows or not 0 < int(size) <= 1024**3:
            raise ValueError('duplicate archive or unreasonable size')
        rows[name] = {'size': int(size), 'sha256': digest.lower()}
    return rows


def plan_key(rows):
    return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def checked_bytes(path, row):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except (FileNotFoundError, OSError):
        return None
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size != row['size']:
            return None
        data = stream.read(row['size'] + 1)
    if len(data) != row['size'] or hashlib.sha256(data).hexdigest() != row['sha256']:
        return None
    return data


def transfer(rows, source, target, *, fresh):
    if source.is_symlink() or target.is_symlink():
        raise ValueError('cache roots must not be symlinks')
    target.mkdir(mode=0o755, parents=False, exist_ok=not fresh)
    accepted = []
    for name, row in rows.items():
        data = checked_bytes(source / name, row)
        if data is None:
            continue  # Cache miss: APT fetches the selected archive normally.
        fd, temporary = tempfile.mkstemp(prefix='.archive-', dir=target)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
            os.chmod(temporary, 0o644)
            os.replace(temporary, target / name)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        accepted.append(name)
    return {'expected': len(rows), 'verified': len(accepted), 'archives': accepted}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('key', 'stage', 'export'))
    parser.add_argument('plan', type=Path)
    parser.add_argument('source', type=Path, nargs='?')
    parser.add_argument('target', type=Path, nargs='?')
    args = parser.parse_args()
    rows = read_plan(args.plan)
    if args.mode == 'key':
        print(plan_key(rows))
    else:
        if args.source is None or args.target is None:
            parser.error('stage/export requires source and target directories')
        print(json.dumps(transfer(rows, args.source, args.target, fresh=args.mode == 'stage'), sort_keys=True))


if __name__ == '__main__':
    main()
