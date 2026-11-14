#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate recipe DATA/local materials; never source shell code or fetch."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import tarfile

TAR_SHA = 'c2215904f02b175596dc49351585104f4bc20341e1c47378b26a2c274360ce73'
LICENSE_SHA = 'b0e25a78cffb43f4d92de8b61ccfa1f1f98ecbc22330b54b5251e7b6ba010231'


def fields(text):
    value = {}
    for line in text.splitlines():
        if line.strip() and not line.lstrip().startswith('#'):
            key, item = line.strip().split(' = ', 1)
            value.setdefault(key, []).append(item)
    return value


def check(root, archive=None):
    root = root.resolve(strict=True)
    data = fields((root / '.SRCINFO').read_text())
    for key, expected in {'pkgname': ['python'], 'pkgbase': ['python'], 'pkgver': ['3.14.8'],
                          'pkgrel': ['1.1'], 'arch': ['aarch64']}.items():
        assert data[key] == expected, key
    assert not any(key in data for key in ('install', 'backup', 'replaces', 'conflicts'))
    recipe = (root / 'PKGBUILD').read_text()
    for key in ('pkgname', 'pkgver', 'pkgrel'):
        assert re.search(r'^' + key + '=' + re.escape(data[key][0]) + r'$', recipe, re.M), key
    for key in ('arch', 'source', 'sha256sums', 'depends', 'makedepends', 'optdepends', 'provides', 'license', 'options'):
        found = re.search(r'^' + key + r'=\((.*?)\)', recipe, re.M | re.S)
        assert found and shlex.split(found[1]) == data[key], key + ' SRCINFO/recipe drift'
    assert len(data['source']) == len(data['sha256sums']) == 8
    assert data['sha256sums'][0] == TAR_SHA
    assert data['source'][0] == 'https://www.python.org/ftp/python/3.14.8/Python-3.14.8.tar.xz'
    for name, expected in zip(data['source'][1:], data['sha256sums'][1:]):
        path = root / name
        assert path.parent == root and path.is_file() and not path.is_symlink(), name
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected, name + ' digest'
    assert hashlib.sha256((root / 'CPython-LICENSE').read_bytes()).hexdigest() == LICENSE_SHA
    provenance = json.loads((root / 'source-provenance.json').read_text())
    assert provenance['version'] == '3.14.8-1.1'
    assert provenance['sources'][0]['sha256'] == TAR_SHA
    status = 'HOLD source archive not supplied'
    if archive:
        assert archive.is_file() and not archive.is_symlink() and archive.stat().st_size == 24130644
        with archive.open('rb') as stream:
            assert hashlib.file_digest(stream, 'sha256').hexdigest() == TAR_SHA
        with tarfile.open(archive, 'r:xz') as stream:
            notice = stream.extractfile('Python-3.14.8/LICENSE').read(20000)
        assert notice == (root / 'CPython-LICENSE').read_bytes()
        status = 'PASS exact source/material/metadata checks only'
    return {'status': status, 'version': '3.14.8-1.1', 'historical_binary_correspondence': 'UNBOUND',
            'native_ARM': 'NOT RUN', 'hardware': 'NOT RUN'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--archive', type=Path)
    parser.add_argument('--recipe', type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args(); print(json.dumps(check(args.recipe, args.archive), sort_keys=True))
