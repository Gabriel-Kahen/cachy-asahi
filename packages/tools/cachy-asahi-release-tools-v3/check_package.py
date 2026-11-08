#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite source/payload checks and private staging; never installs packages."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import tempfile

NAME, VERSION = 'cachy-asahi-release-tools', '0.3.0-1'
DEPENDENCIES = ['python>=3.14', 'zstd', 'gnupg', 'libarchive', 'pacman']


def need(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def array(text, name):
    matches = re.findall(r'^' + re.escape(name) + r'=\(([^)]*)\)$', text, re.M)
    need(len(matches) == 1, 'one literal recipe array required: ' + name)
    return shlex.split(matches[0])


def verify_sources(recipe_root):
    root = Path(recipe_root).resolve()
    text = (root / 'PKGBUILD').read_text()
    names, hashes = array(text, 'source'), array(text, 'sha256sums')
    need(len(names) == len(set(names)) == len(hashes), 'exact unique source pins required')
    need(all(Path(name).name == name for name in names), 'makepkg local source basenames required')
    need(array(text, 'noextract') == ['fixture__legacy-v2.tar.gz'], 'legacy TEST recipe must not auto-extract')
    need(array(text, 'depends') == DEPENDENCIES, 'exact runtime dependencies required')
    need(array(text, 'arch') == ['any'] and array(text, 'license') == ['MIT'], 'recipe architecture/license')
    need(re.search(r'^pkgname=' + NAME + r'$', text, re.M) and
         re.search(r'^pkgver=0\.3\.0$', text, re.M) and re.search(r'^pkgrel=1$', text, re.M), 'fixed package identity')
    for name, pin in zip(names, hashes):
        need(not Path(name).is_absolute() and '..' not in Path(name).parts, 'local source path required')
        path = root / name
        need(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)), 'regular local source required')
        need(digest(path) == pin, 'source checksum mismatch: ' + name)
    srcinfo = {}
    for line in (root / '.SRCINFO').read_text().splitlines():
        if ' = ' in line:
            key, value = line.strip().split(' = ', 1); srcinfo.setdefault(key, []).append(value)
    for key, expected in [('pkgbase', [NAME]), ('pkgname', [NAME]), ('pkgver', ['0.3.0']),
                          ('pkgrel', ['1']), ('arch', ['any']), ('license', ['MIT']),
                          ('depends', DEPENDENCIES), ('source', names), ('sha256sums', hashes)]:
        need(srcinfo.get(key) == expected, 'SRCINFO mismatch: ' + key)
    provenance = json.loads((root / 'source-provenance.json').read_bytes())
    need(len(provenance['files']) == 15, 'finite seven endpoint plus eight legacy code closure required')
    for name, row in provenance['files'].items():
        need(name in names and row['license'] == 'MIT' and digest(root / name) == row['sha256']
             and (root / name).stat().st_size == row['bytes'], 'retained code pin: ' + name)
        need(re.fullmatch('[0-9a-f]{40}', row['origin_commit']), 'full source revision required')
    need(digest(root / 'LICENSE') == provenance['license_file_sha256'], 'project MIT license pin')
    return {'sources': len(names), 'runtime_code_files': 15, 'version': VERSION}


def verify_payload(recipe_root, prefix):
    root, prefix = Path(recipe_root), Path(prefix)
    payload = json.loads((root / 'payload-map.json').read_bytes())['files']
    paths = {p.relative_to(prefix).as_posix(): p for p in prefix.rglob('*') if not p.is_dir()}
    need(set(paths) == set(payload), 'installed payload set differs')
    parents = {str(parent) for name in payload for parent in Path(name).parents if str(parent) != '.'}
    need({p.relative_to(prefix).as_posix() for p in prefix.rglob('*') if p.is_dir()} == parents,
         'installed directory set differs')
    for name, row in payload.items():
        path = paths[name]
        need(not path.is_symlink() and stat.S_ISREG(path.stat().st_mode) and
             stat.S_IMODE(path.stat().st_mode) == row['mode'] and
             path.read_bytes() == (root / row['source']).read_bytes(), 'installed payload bytes/mode: ' + name)
    return {'files': len(payload), 'version': VERSION}


def stage(recipe_root, prefix):
    root, prefix = Path(recipe_root).resolve(), Path(prefix).absolute()
    verify_sources(root)
    need(not os.path.lexists(prefix) and prefix.parent.is_dir(), 'fresh private staging prefix required')
    with tempfile.TemporaryDirectory(prefix='release-tools-v3-stage-') as temporary:
        sources = Path(temporary) / 'sources'; sources.mkdir(mode=0o700)
        for name in array((root / 'PKGBUILD').read_text(), 'source'):
            path = sources / name; path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / name, path)
        subprocess.run(['bash', '-euc', 'source "$1/PKGBUILD"; srcdir=$2; pkgdir=$3; package',
                        'package-stage', str(root), str(sources), str(prefix)], check=True)
    verify_payload(root, prefix)
    return prefix


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe-root', type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    print(json.dumps(verify_sources(args.recipe_root), sort_keys=True))


if __name__ == '__main__':
    main()
