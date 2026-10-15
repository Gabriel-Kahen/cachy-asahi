#!/usr/bin/env python3
"""Copy twelve exact public input files to the existing private CI cache."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

INDEX_BYTES = 2394
INDEX_SHA256 = '758ec321b51183d32cffef26648ac9d805c680d44580cd035f22c1b39e37bb66'
TOTAL_BYTES = 4045396


def read_exact(path, size, digest):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size != size:
        raise ValueError('ordinary exact input required: ' + path.name)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        data = stream.read(size + 1)
        after = os.fstat(stream.fileno())
    def identity(row):
        return (row.st_dev, row.st_ino, row.st_mode, row.st_uid, row.st_gid,
                row.st_nlink, row.st_size, row.st_mtime_ns, row.st_ctime_ns)
    if (identity(info) != identity(opened) or identity(opened) != identity(after)
            or identity(path.lstat()) != identity(after) or len(data) != size
            or hashlib.sha256(data).hexdigest() != digest):
        raise ValueError('input byte pin or identity differs: ' + path.name)
    return data


def seed(source, cache):
    source, cache = Path(source), Path(cache)
    for directory in (source, source / 'inputs', cache):
        if not directory.is_absolute() or not stat.S_ISDIR(directory.lstat().st_mode):
            raise ValueError('ordinary absolute seed/cache directory required')
    info = cache.lstat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('owned private existing cache required')
    index = json.loads(read_exact(source / 'index.json', INDEX_BYTES, INDEX_SHA256))
    rows = index['files']
    if (index['schema_version'] != 1 or len(rows) != 12
            or sum(row['size'] for row in rows) != TOTAL_BYTES or index['total_bytes'] != TOTAL_BYTES):
        raise ValueError('fixed twelve input index required')
    names = {row['filename'] for row in rows}
    if len(names) != 12 or any(Path(name).name != name or name.startswith('.') for name in names):
        raise ValueError('fixed input names required')
    if {path.name for path in (source / 'inputs').iterdir()} != names:
        raise ValueError('exact twelve source files required')
    data, missing = {}, []
    for row in rows:
        name = row['filename']
        data[name] = read_exact(source / 'inputs' / name, row['size'], row['sha256'])
        target = cache / name
        if os.path.lexists(target):
            read_exact(target, row['size'], row['sha256'])
        else:
            missing.append(name)
    # All source and existing cache files pass before any missing target appears.
    # Individual publishes never replace an existing file; a valid prefix is safe
    # to retain after interruption, and a later seed checks it again.
    with tempfile.TemporaryDirectory(prefix='.retained-public-', dir=cache) as temporary:
        for name in missing:
            staged = Path(temporary) / name
            with staged.open('xb') as stream:
                stream.write(data[name]); stream.flush(); os.fsync(stream.fileno())
            os.link(staged, cache / name)
    return {'status': 'SEEDED_EXACT_PUBLIC_INPUTS', 'files': 12, 'bytes': TOTAL_BYTES,
            'copied': len(missing), 'existing': 12 - len(missing),
            'signature_authentication': 'NOT RUN; unchanged native gate required'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(seed(Path(__file__).resolve().parent, args.cache), sort_keys=True))


if __name__ == '__main__':
    main()
