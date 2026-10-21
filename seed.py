"""Copy exact public inputs into a new owned build cache; no trust authority."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

HERE = Path(__file__).resolve().parent


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def ordinary(path):
    path = Path(path).absolute()
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('symlink path refused')
    return path


def seed(core):
    core = ordinary(core)
    cache = ordinary(core / 'builder-context/deps')
    info = cache.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('new caller-owned mode0700 build cache required')
    index = json.loads((HERE / 'index.json').read_bytes())
    if pin((core / 'builder-inputs.lock.json').read_bytes()) != index['original_lock']:
        raise ValueError('original signed64 lock differs')
    if {p.name for p in cache.iterdir()} != {'SHA256SUMS'}:
        raise ValueError('fresh checksum-only cache required')
    expected = index['files']
    if len(expected) != 128 or {p.name for p in (HERE / 'packages').iterdir()} != set(expected):
        raise ValueError('closed128-leaf public recovery input required')
    blobs = {}
    for name, row in expected.items():
        if Path(name).name != name:
            raise ValueError('simple package filename required')
        source = ordinary(HERE / 'packages' / name)
        info = source.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('ordinary single-link recovery input required')
        raw = source.read_bytes()
        if pin(raw) != row:
            raise ValueError('recovery package pin differs')
        blobs[name] = raw
    for name, raw in blobs.items():
        fd = os.open(cache / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as out:
            out.write(raw)
    return dict(status='ALL128_EXACT_PUBLIC_INPUTS_SEEDED_NOT_AUTHENTICATED',
                files=expected, trust='ORIGINAL_FULL64_GPG_AND_METADATA_CHECKS_REQUIRED')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(seed(args.core), sort_keys=True))
