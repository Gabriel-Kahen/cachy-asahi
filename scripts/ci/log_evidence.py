#!/usr/bin/env python3
"""Encode small build evidence in workflow logs; no artifact/cache storage billing."""
import argparse
import base64
import hashlib
import io
import tarfile
from pathlib import Path


def bundle(root):
    if not root.is_dir() or root.is_symlink():
        raise ValueError('evidence directory is missing or a symlink')
    output = io.BytesIO()
    count = 0
    with tarfile.open(fileobj=output, mode='w:gz') as archive:
        size = 0
        for path in sorted(root.rglob('*')):
            rel = path.relative_to(root)
            if rel.parts[0] in ('context', 'gpg'):
                continue
            if path.is_symlink():
                raise ValueError('symlink evidence forbidden')
            if path.is_file():
                count += 1
                size += path.stat().st_size
                if size > 16 * 1024**2:
                    raise ValueError('evidence exceeds 16 MiB; inspect logs and retry with a bounded record')
                archive.add(path, arcname=str(Path(root.name) / rel), recursive=False)
    if not count:
        raise ValueError('empty evidence directory')
    data = output.getvalue()
    if len(data) > 8 * 1024**2:
        raise ValueError('compressed evidence exceeds 8 MiB')
    return data


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    data = bundle(args.directory)
    print(f'CACHY_ASAHI_EVIDENCE_BEGIN {args.directory.name} sha256={hashlib.sha256(data).hexdigest()} bytes={len(data)}')
    print(base64.encodebytes(data).decode(), end='')
    print(f'CACHY_ASAHI_EVIDENCE_END {args.directory.name}')
