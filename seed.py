# SPDX-License-Identifier: MIT
"""Seed complete496 exact public archive/signature bytes; original authentication remains mandatory."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

HERE = Path(__file__).resolve().parent
LOCK = dict(bytes=328101, sha256='beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f')



def need(ok, message):
    if not ok:
        raise ValueError(message)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def ordinary(path):
    path = Path(path).absolute()
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary path ancestry required')
    return path


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
            info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read(path, cap=32*1024**2):
    path = ordinary(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= cap,
             'bounded ordinary single-link input required')
        raw = stream.read(cap+1)
        need(len(raw) == before.st_size and identity(os.fstat(stream.fileno())) == identity(before)
             and identity(path.lstat()) == identity(before), 'whole stable input required')
    return raw


def seed(lock, cache):
    lock, cache = ordinary(lock), ordinary(cache)
    raw = read(lock, 1024**2)
    need(pin(raw) == LOCK, 'entire original native-base lock required')
    selected = json.loads(raw)['packages']
    need(len(selected) == 248 and len({r['filename'] for r in selected}) == 248, 'complete original248 packages required')
    expected = {}
    for row in selected:
        expected[row['filename']] = dict(bytes=row['size'], sha256=row['sha256'])
        expected[row['filename']+'.sig'] = dict(bytes=row['signature_size'], sha256=row['signature_sha256'])
    need(not cache.exists() and cache.parent.is_dir() and cache.parent.stat().st_uid == os.getuid(),
         'fresh cache under caller-owned parent required')
    need(len(expected) == 496 and sum(p['bytes'] for p in expected.values()) == 702251555,
         'complete496 original byte closure required')
    need(json.loads(read(HERE/'index.json')) == dict(original_lock=LOCK, files=expected), 'exact complete eight-input index required')
    need({p.name for p in (HERE/'packages').iterdir()} == set(expected), 'closed496-leaf carrier required')
    for name, expected_pin in expected.items():
        need(Path(name).name == name and name not in ('.', '..'), 'simple original filename required')
        need(pin(read(HERE/'packages'/name, 128*1024**2)) == expected_pin,
             'exact original archive/signature pin required')
    cache.mkdir(mode=0o700)
    for name, expected_pin in expected.items():
        body = read(HERE/'packages'/name, 128*1024**2)
        need(pin(body) == expected_pin, 'whole original input recheck required')
        fd = os.open(cache/name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(body)
    need(all(pin(read(cache/n, 128*1024**2)) == p for n,p in expected.items()), 'complete exact seeded cache required')
    return dict(status='COMPLETE496_EXACT_ORIGINAL_INPUTS_SEEDED_NOT_AUTHENTICATED', files=expected,
                written=496, original_lock=LOCK, versions='UNCHANGED',
                trust='ORIGINAL_FULL_SIGNATURE_METADATA_AND_NATIVE_BASE_CHECKS_REQUIRED')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lock', type=Path, required=True)
    parser.add_argument('--cache', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(seed(args.lock, args.cache), sort_keys=True))
