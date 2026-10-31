#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only exact recipe/provenance check; ignores live makepkg outputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat

NAME = 'cachy-asahi-security-maintenance'
SOURCES = {'build.py', 'build_v2.py', 'compare.py', 'compare_v2.py', 'container-entry-v2.sh',
           'container-entry.sh', 'source_materials.py', 'package_checks.py', 'build_batch.py',
           'build_batch_v2.py', 'build_outputs_v2.py', 'campaign.py', 'rebuild_plan.py',
           'security_advisories.py', 'security_campaign.py', 'source_cache.py', 'update_plan.py',
           'check_source_pins.py', 'release.py', 'source_delivery.py', NAME, 'payload-pins.json',
           'source-provenance.json', 'check_source.py', 'test_package.py', 'fixture_security.py',
           'README.md', 'installed-files.txt', 'NOTICE', 'LICENSE', 'advisory_cache.py', 'owned_process.py'}


def need(value, message):
    if not value: raise ValueError(message)


def check(root):
    def read(name):
        fd = os.open(root / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= 2 * 1024**2,
                 'ordinary bounded single-link input required: ' + name)
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                raw = stream.read(2 * 1024**2 + 1)
            after = os.fstat(fd)
            identity = lambda v: (v.st_dev, v.st_ino, v.st_size, v.st_mtime_ns, v.st_ctime_ns)
            need(identity(before) == identity(after) and len(raw) == before.st_size, 'source changed: ' + name)
            return raw
        finally:
            os.close(fd)
    recipe = read('PKGBUILD').decode()
    def array(key): return shlex.split(re.search(r'^' + key + r'=\((.*?)\)', recipe, re.M | re.S)[1])
    sources, checksums = array('source'), array('sha256sums')
    need(len(sources) == len(checksums) == len(set(sources)) and set(sources) == SOURCES,
         'exact declared local source set required')
    for name, checksum in zip(sources, checksums):
        raw = read(name)
        need(re.fullmatch('[0-9a-f]{64}', checksum) and hashlib.sha256(raw).hexdigest() == checksum,
             'recipe source checksum differs: ' + name)
        if name.endswith('.py') or name == NAME: compile(raw, name, 'exec')
    info = {}
    for line in read('.SRCINFO').decode().splitlines():
        if line.strip():
            key, value = line.strip().split(' = ', 1)
            info.setdefault(key, []).append(value)
    for key, values in dict(pkgbase=[NAME], pkgname=[NAME], pkgver=['0.1.0'], pkgrel=['2'], arch=['any'],
                            license=['MIT'], depends=['python>=3.11', 'libarchive', 'pacman', 'zstd', 'ca-certificates'],
                            optdepends=['docker: explicit reviewed offline batch execution only'],
                            source=sources, sha256sums=checksums).items():
        need(info.get(key) == values, '.SRCINFO differs: ' + key)
    need(not any(info.get(key) for key in ('install', 'backup', 'replaces', 'conflicts', 'provides')),
         'hooks/global config/replacement refused')
    pins = json.loads(read('payload-pins.json'))
    provenance = json.loads(read('source-provenance.json'))['files']
    need(set(pins) == set(provenance) and len(pins) == 22, 'exact twenty-two-file closure required')
    for path, checksum in pins.items():
        row = provenance[path]
        body = read(row['source'])
        need(row['source'] == Path(path).name and row['sha256'] == checksum and len(body) == row['bytes']
             and row['license'] == 'MIT' and hashlib.sha256(body).hexdigest() == checksum,
             'frozen source/provenance differs: ' + path)
    need('Permission is hereby granted' in read('LICENSE').decode(), 'MIT grant missing')
    return pins


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe-root', type=Path, default=Path(__file__).resolve().parent)
    print('PASS exact recipe and runtime closure:', len(check(parser.parse_args().recipe_root)))
