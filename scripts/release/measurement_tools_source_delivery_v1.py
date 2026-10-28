#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Export the exact finite measurement-tools proposal; no acquisition or install."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile

SCHEMA = 'measurement-tools-source-closure-v1'
PROFILE_NAME = 'manifests/measurement-tools-source-20261028.json'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def ordinary(path, cap):
    if any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file() or path.stat().st_size > cap:
        raise ValueError('bounded ordinary file required: ' + str(path))
    raw = path.read_bytes()
    if len(raw) > cap:
        raise ValueError('source grew beyond byte bound')
    return raw


def export(root, profile_path, profile_sha256, output):
    root = root.absolute()
    profile_path = profile_path.absolute()
    raw_profile = ordinary(profile_path, 128 * 1024)
    if digest(raw_profile) != profile_sha256:
        raise ValueError('profile SHA256 differs from caller pin')
    profile = json.loads(raw_profile)
    if profile.get('schema') != SCHEMA or profile.get('base_commit') != '852d1b7324e4ad840fa94ea7c9fc994b1aa07280':
        raise ValueError('unsupported source profile')
    rows = profile.get('files')
    if not isinstance(rows, list) or not 1 <= len(rows) <= 128:
        raise ValueError('finite source list required')
    bodies = {PROFILE_NAME: (raw_profile, 0o644)}
    total = len(raw_profile)
    for row in rows:
        rel = Path(row['path'])
        if (not row['path'] or rel.is_absolute() or '..' in rel.parts or str(rel) != row['path']
                or row['path'] in bodies or row['mode'] not in ('0644', '0755')):
            raise ValueError('unique normalized relative source path required')
        raw = ordinary(root / rel, 3 * 1024**2)
        if len(raw) != row['bytes'] or digest(raw) != row['sha256']:
            raise ValueError('source bytes differ: ' + row['path'])
        if (root / rel).stat().st_mode & 0o777 != int(row['mode'], 8):
            raise ValueError('source mode differs: ' + row['path'])
        bodies[row['path']] = (raw, int(row['mode'], 8))
        total += len(raw)
    if total > 16 * 1024**2:
        raise ValueError('source closure byte bound')
    recipe = 'packages/tools/cachy-asahi-measurement-tools/'
    actual = {str(p.relative_to(root)) for p in (root / recipe).rglob('*') if p.is_file() or p.is_symlink()}
    if actual != {name for name in bodies if name.startswith(recipe)}:
        raise ValueError('recipe namespace differs from finite profile')
    output = output.absolute()
    if output.exists() or any(p.is_symlink() for p in (output, *output.parents)):
        raise ValueError('fresh ordinary output required')
    with tempfile.NamedTemporaryFile(dir=output.parent, prefix='.measurement-export-', delete=False) as stream:
        temporary = Path(stream.name)
    try:
        with tarfile.open(temporary, 'w', format=tarfile.USTAR_FORMAT) as archive:
            for name, (raw, mode) in sorted(bodies.items()):
                item = tarfile.TarInfo(name)
                item.size = len(raw)
                item.mode = mode
                item.uid = item.gid = item.mtime = 0
                item.uname = item.gname = ''
                archive.addfile(item, io.BytesIO(raw))
        os.link(temporary, output)  # Atomic no-overwrite publication inside caller's private output directory.
    finally:
        temporary.unlink(missing_ok=True)
    return dict(schema=SCHEMA, archive=str(output), sha256=digest(output.read_bytes()),
                bytes=output.stat().st_size, files=len(bodies), profile_sha256=profile_sha256,
                scope='exact local source transport only', native_build='NOT RUN',
                installation='NOT RUN', hardware_validation='NOT RUN', release='NOT ADMITTED')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--profile', type=Path, required=True)
    parser.add_argument('--profile-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(export(args.root, args.profile, args.profile_sha256, args.output), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print('measurement source delivery refused: ' + str(error)[:300], file=__import__('sys').stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
