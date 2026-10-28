#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only Setup8 source/snapshot synchronization; never execute copied helpers."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import sys


def need(ok, message):
    if not ok:raise ValueError(message)


def read(path):
    need(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary source file required')
    need(path.stat().st_nlink == 1 and path.stat().st_size <= 4 * 1024**2, 'bounded single-link source required')
    return path.read_bytes()


def digest(path):return hashlib.sha256(read(path)).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', action='store_true', help='verify fixed packaged input pins without canonical paths')
    parser.add_argument('--root', type=Path, help='explicit canonical source root')
    args = parser.parse_args()
    package = Path(__file__).resolve().parent
    if not args.snapshot:
        root = args.root or package.parents[2]
    try:
        data = json.loads(read(package / 'source-provenance.json'))
        need(type(data['schema_version']) is int and data['schema_version'] == 1, 'provenance schema differs')
        for name, expected in data['input_sha256'].items():
            need(type(name) is str and PurePosixPath(name).name == name and re.fullmatch('[0-9a-f]{64}', expected), 'invalid source identity')
            need(digest(package / name) == expected, 'packaged source differs: ' + name)
        for name, relative in data['canonical_sources'].items():
            need(not PurePosixPath(relative).is_absolute() and all(p not in ('', '.', '..') for p in relative.split('/')), 'unsafe canonical mapping')
            if not args.snapshot:
                need(digest(root / relative) == data['input_sha256'][name], 'canonical source differs: ' + relative)
        need(read(package / 'setup.py') == read(package / 'cachy-asahi-setup'), 'private/CLI setup mirrors differ')
        adaptation = data['test_adapter']
        before, after = adaptation['before'], adaptation['after']
        original, adapted = read(package / 'test_config_migrate.original.py').decode(), read(package / 'test_config_migrate.py').decode()
        need(original.count(before) == adapted.count(after) == 1 and original.replace(before, after, 1) == adapted, 'original29 test adapter differs beyond the fixed lookup')
        raw = read(package / 'PKGBUILD').decode()
        array = lambda name: shlex.split(re.search(r'^' + name + r'=\((.*?)\)', raw, re.M | re.S)[1])
        names, sums = array('source'), array('sha256sums')
        need(len(names) == len(sums) and len(set(names)) == len(names), 'unique complete recipe sources required')
        need(set(names) == set(data['input_sha256']) | {'source-provenance.json'}, 'exact complete recipe input set required')
        need(all(digest(package / name) == expected for name, expected in zip(names, sums)), 'recipe source checksum differs')
        srcinfo = read(package / '.SRCINFO').decode()
        need(re.findall(r'^\s*source = (.+)$', srcinfo, re.M) == names and re.findall(r'^\s*sha256sums = (.+)$', srcinfo, re.M) == sums, 'recipe/SRCINFO source arrays differ')
        need('pkgver=0.3.0\n' in raw and 'pkgrel=1\n' in raw and 'pkgver = 0.3.0\n' in srcinfo and 'pkgrel = 1\n' in srcinfo, 'distinct Setup8 version identity required')
        need(data['input_sha256']['config_migrate.py'] == '1368a1fa0586d946f33945b0be7e5c1deb4fe929509e34a81d55cfb9f5cb800b', 'original migration engine pin differs')
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        print('FAIL: ' + str(error), file=sys.stderr)
        return 1
    print('PASS: Setup8 canonical/snapshot, original engine, corrected setup/private mirror,29-test adapter and recipe pins')
    return 0


if __name__ == '__main__':raise SystemExit(main())
