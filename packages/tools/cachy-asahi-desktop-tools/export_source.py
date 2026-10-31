#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Rebuild the finite source archive from exact local source-map bytes; no network."""
import argparse
import gzip
import hashlib
import io
import json
import os
import re
import zlib
from pathlib import Path, PurePosixPath
import stat
import tarfile

NAME = 'cachy-asahi-desktop-tools-0.1.0'
MAX_ARCHIVE = 1024 * 1024
MAX_TAR = 2 * 1024 * 1024


def ordinary(path, cap):
    path = Path(path)
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError('ordinary nonaliased input required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > cap:
            raise ValueError('bounded regular input required')
        raw = bytearray()
        while len(raw) <= cap:
            block = os.read(fd, min(65536, cap + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        after = os.fstat(fd)
        keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode')
        if len(raw) > cap or len(raw) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in keys):
            raise ValueError('input changed or exceeded byte cap')
        return bytes(raw)
    finally:
        os.close(fd)


def canonical_tar(source):
    """Canonical source namespace, file bytes, modes and USTAR metadata."""
    source = Path(source)
    manifest = source / 'source-map.json'
    if manifest.is_symlink() or not manifest.is_file():
        raise ValueError('ordinary source map required')
    manifest_raw = ordinary(manifest, MAX_ARCHIVE)
    rows = json.loads(manifest_raw)['files']
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
        raw = ordinary(path, 1024 * 1024)
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
    payload.append(('source-map.json', manifest_raw, 0o644))
    if sum(len(raw) for _, raw, _ in payload) + (len(payload) + 20) * 1024 > MAX_TAR:
        raise ValueError('finite source tar byte cap exceeded')
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw, mode in sorted(payload):
            info = tarfile.TarInfo(NAME + '/' + name)
            info.size, info.mode, info.mtime = len(raw), mode, 0
            info.uid = info.gid = 0
            info.uname = info.gname = 'root'
            archive.addfile(info, io.BytesIO(raw))
    raw = buffer.getvalue()
    if len(raw) > MAX_TAR:
        raise ValueError('finite source tar byte cap exceeded')
    return raw


def validate_archive(source, archive, expected_sha256):
    """Authenticate transport bytes, then bind exact decoded source semantics."""
    if not isinstance(expected_sha256, str) or not re.fullmatch('[0-9a-f]{64}', expected_sha256):
        raise ValueError('explicit archive SHA256 required')
    body = ordinary(archive, MAX_ARCHIVE)
    if hashlib.sha256(body).hexdigest() != expected_sha256:
        raise ValueError('archive byte pin differs')
    canonical = canonical_tar(source)
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        raw = decoder.decompress(body, len(canonical) + 1)
    except zlib.error as error:
        raise ValueError('invalid gzip source archive') from error
    if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail or raw != canonical:
        raise ValueError('source archive differs or is incomplete, concatenated or trailing')
    return dict(bytes=len(body), sha256=expected_sha256, tar_bytes=len(raw),
                tar_sha256=hashlib.sha256(raw).hexdigest(),
                status='PASS_EXACT_CANONICAL_SOURCE_ARCHIVE')


def export(source, output):
    raw = canonical_tar(source)
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode='wb', filename='', mtime=0, compresslevel=9) as compressed:
        compressed.write(raw)
    # Complete validation and encoding precede output creation.
    with Path(output).open('xb') as stream:
        stream.write(buffer.getvalue())
    return dict(bytes=len(buffer.getvalue()), sha256=hashlib.sha256(buffer.getvalue()).hexdigest())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--output', type=Path)
    mode.add_argument('--verify-archive', type=Path)
    parser.add_argument('--sha256')
    args = parser.parse_args()
    try:
        source = Path(__file__).resolve().parent / NAME
        if args.verify_archive is not None:
            result = validate_archive(source, args.verify_archive, args.sha256)
        else:
            if args.sha256 is not None:
                raise ValueError('--sha256 is only valid with --verify-archive')
            result = export(source, args.output)
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(2, str(exc) + '\n')
