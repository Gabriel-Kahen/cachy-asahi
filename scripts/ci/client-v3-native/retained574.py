# SPDX-License-Identifier: MIT
"""Copy exact retained574 package DATA; no network, Source imports or authentication."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time

LOCK = {'bytes': 623664, 'sha256': 'b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9'}
SOURCE = '4659076d3a1d3e5cf87c185a3ff383fbc38e734d'
TREE = 'e21f947bac3afdfbd67e4e65c8234b35ae42b00f'

def need(ok, message):
    if not ok:
        raise ValueError(message)

def identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)

def ordinary(path, directory=False):
    path = Path(path).absolute()
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary ancestry required')
    s = path.lstat()
    need((stat.S_ISDIR if directory else stat.S_ISREG)(s.st_mode), 'ordinary input required')
    return path, s

def tick(deadline):
    need(time.monotonic() < deadline, 'original retained-input deadline exhausted')

def exact(path, row, deadline, output=None):
    path, before = ordinary(path)
    need(before.st_uid == os.getuid() and before.st_nlink == 1 and before.st_size == row['bytes'], 'owned single-link exact input required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        need(identity(os.fstat(fd)) == identity(before), 'input changed before open')
        hasher = hashlib.sha256(); count = 0
        while True:
            tick(deadline); raw = os.read(fd, 1024**2)
            if not raw:
                break
            count += len(raw); need(count <= row['bytes'], 'input exceeds exact bound'); hasher.update(raw)
            if output is not None:
                output.write(raw)
        need(count == row['bytes'] and hasher.hexdigest() == row['sha256'], 'input size/hash differs')
        need(identity(before) == identity(os.fstat(fd)) == identity(path.lstat()), 'input changed while reading')
    finally:
        os.close(fd)
    return identity(before)

def package_rows(raw):
    need({'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()} == LOCK, 'original574 whole lock required')
    value = json.loads(raw); rows = {}
    need(len(value['packages']) == 574, 'exact574 package membership')
    for r in value['packages']:
        for suffix, size, sha in (('', r['size'], r['sha256']), ('.sig', r['signature_size'], r['signature_sha256'])):
            name = r['filename'] + suffix
            need(re.fullmatch(r'[A-Za-z0-9._+@:~-]{1,255}', name) and name not in rows, 'unique simple input filename')
            rows[name] = {'bytes': size, 'sha256': sha}
    need(len(rows) == 1148, 'exact1148 archive/signature rows')
    return rows

def join(packages, cache, rows, deadline):
    """All source/current-cache bodies pass before any addition; never clobber."""
    tick(deadline); packages, _ = ordinary(packages, True); cache, info = ordinary(cache, True)
    need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'existing private caller cache required')
    key = (info.st_dev, info.st_ino, info.st_mode, info.st_uid)
    need({p.name for p in packages.iterdir()} == set(rows), 'closed full retained package namespace')
    before = {}
    for path in cache.iterdir():
        need(path.name in rows, 'foreign cache input refused')
        before[path.name] = exact(path, rows[path.name], deadline)
    for name, row in rows.items():
        exact(packages / name, row, deadline)
    added = []
    for name, row in rows.items():
        if name in before:
            continue
        tick(deadline); target = cache / name; partial = cache / (name + '.retained574.partial'); created = False
        try:
            fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600); created = True
            with os.fdopen(fd, 'wb') as output:
                exact(packages / name, row, deadline, output); output.flush(); os.fsync(output.fileno())
            # link is exclusive and preserves a target created concurrently; no rename clobber.
            os.link(partial, target, follow_symlinks=False); partial.unlink(); created = False
            exact(target, row, deadline); added.append(name)
        finally:
            if created:
                partial.unlink()
    need({p.name for p in cache.iterdir()} == set(rows), 'exact completed cache namespace')
    for name, row in rows.items():
        value = exact(cache / name, row, deadline)
        need(name not in before or value == before[name], 'existing inode metadata changed')
    now = cache.lstat(); need((now.st_dev, now.st_ino, now.st_mode, now.st_uid) == key, 'cache directory changed')
    return dict(status='EXACT_RETAINED574_PACKAGES_SEEDED_NOT_AUTHENTICATED', source=SOURCE, tree=TREE,
                files=len(rows), added=len(added), existing=len(before), bytes=sum(r['bytes'] for r in rows.values()),
                network_requests=0, Source_imports=0, signature_authentication='ORIGINAL_NATIVE_GATE_REQUIRED',
                native='NOT_RUN', hardware='NOT_RUN', release='NOT_ADMITTED')

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--lock', type=Path, required=True); p.add_argument('--carrier', type=Path, required=True)
    p.add_argument('--cache', type=Path, required=True); p.add_argument('--deadline', type=float, required=True)
    a = p.parse_args(); need(math.isfinite(a.deadline) and 0 < a.deadline - time.monotonic() <= 120, 'finite original120s seed deadline required'); tick(a.deadline)
    path, info = ordinary(a.lock); need(info.st_size == LOCK['bytes'], 'bounded exact lock required')
    exact(path, LOCK, a.deadline); rows = package_rows(path.read_bytes())
    print(json.dumps(join(a.carrier / 'packages', a.cache, rows, a.deadline), sort_keys=True))

if __name__ == '__main__':
    main()
