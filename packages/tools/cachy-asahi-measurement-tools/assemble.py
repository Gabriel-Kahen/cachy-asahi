#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Install only the declared payload below a fresh caller-owned prefix."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil


def install(source, prefix):
    source = source.resolve(strict=True)
    prefix = prefix.absolute()
    if prefix == Path('/') or any(p.is_symlink() for p in (prefix, *prefix.parents)):
        raise ValueError('ordinary private staging prefix required')
    if prefix.exists() and any(prefix.iterdir()):
        raise ValueError('fresh or empty staging prefix required')
    rows = json.loads((source / 'payload-map.json').read_text())['files']
    checked = []
    for row in rows:
        rel = Path(row['installed'])
        path = source / row['source']
        if rel.is_absolute() or '..' in rel.parts or path.is_symlink() or not path.is_file():
            raise ValueError('ordinary source and relative payload path required')
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != row['sha256']:
            raise ValueError('payload source differs: ' + row['source'])
        checked.append((row, rel))
    prefix.mkdir(parents=True, exist_ok=True)
    for row, rel in checked:
        destination = prefix / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / row['source'], destination)
        destination.chmod(int(row['mode'], 8))
    metadata = prefix / json.loads((source / 'payload-map.json').read_text())['self_path']
    metadata.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source / 'payload-map.json', metadata)
    metadata.chmod(0o644)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--prefix', type=Path, required=True)
    args = parser.parse_args()
    install(args.source, args.prefix)
