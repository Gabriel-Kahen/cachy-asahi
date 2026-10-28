#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Rebuild the finite source archive from exact local source-map bytes; no network."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import stat
import tarfile

NAME = 'cachy-asahi-desktop-tools-0.1.0'


def export(source, output):
    source, output = Path(source), Path(output)
    manifest = source / 'source-map.json'
    if manifest.is_symlink() or not manifest.is_file():
        raise ValueError('ordinary source map required')
    rows = json.loads(manifest.read_text())['files']
    if not rows or len(rows) > 64:
        raise ValueError('finite source map required')
    observed, payload = set(), []
    for row in rows:
        rel = PurePosixPath(row['path'])
        if rel.is_absolute() or '..' in rel.parts or str(rel) != row['path'] or row['path'] in observed or row['mode'] not in (0o644, 0o755):
            raise ValueError('invalid source map row')
        path = source / row['path']
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError('source symlink refused')
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 1024*1024:
            raise ValueError('bounded ordinary source file required')
        raw = path.read_bytes()
        if len(raw) != row['bytes'] or hashlib.sha256(raw).hexdigest() != row['sha256'] or stat.S_IMODE(info.st_mode) != row['mode']:
            raise ValueError('source bytes/mode differ')
        observed.add(row['path']); payload.append((row['path'], raw, row['mode']))
    actual = set()
    for path in source.rglob('*'):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError('source links/specials refused')
        if path.is_file():
            actual.add(str(path.relative_to(source)))
    if actual != observed | {'source-map.json'}:
        raise ValueError('source file set differs')
    payload.append(('source-map.json', manifest.read_bytes(), 0o644))
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode='wb', filename='', mtime=0, compresslevel=9) as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for name, raw, mode in sorted(payload):
                info = tarfile.TarInfo(NAME + '/' + name)
                info.size, info.mode, info.mtime = len(raw), mode, 0
                info.uid = info.gid = 0
                info.uname = info.gname = 'root'
                archive.addfile(info, io.BytesIO(raw))
    # Complete validation and encoding precede output creation.
    with output.open('xb') as stream:
        stream.write(buffer.getvalue())
    return dict(bytes=len(buffer.getvalue()), sha256=hashlib.sha256(buffer.getvalue()).hexdigest())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(export(Path(__file__).resolve().parent / NAME, args.output), sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(2, str(exc) + '\n')
