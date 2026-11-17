#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify own Qt source/notices/configuration; copy notices only into DESTDIR."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

REVISION = '025bdad181de241e81bf853c8a2d7bf3d19261a9'
PACKAGE = 'cachy-asahi-qt612-gui-source-reference'


def need(value, why):
    if not value:
        raise ValueError(why)


def ordinary(path, cap=4 * 1024**2):
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary source/notice path required')
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= cap, 'bounded whole notice/input required')
    raw = path.read_bytes()
    identity = lambda s: tuple(getattr(s, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_nlink',
        'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))
    need(len(raw) == info.st_size and identity(path.lstat()) == identity(info), 'stable whole source/notice bytes required')
    return raw


def notices(root, policy):
    root = Path(root).resolve(); rows = json.loads(ordinary(Path(policy).resolve()))
    need(set(rows) == {'schema_version', 'source_notices'} and type(rows['schema_version']) is int
         and rows['schema_version'] == 1 and type(rows['source_notices']) is dict
         and 1 <= len(rows['source_notices']) <= 512, 'complete finite notice policy')
    need(ordinary(root / '.tag').decode().strip() == REVISION, 'exact Qt release revision')
    need(b'set(QT_REPO_MODULE_VERSION "6.12.0")' in ordinary(root / '.cmake.conf'), 'actual Qt6.12.0 source version')
    result = {}; total = 0
    for name, digest in rows['source_notices'].items():
        path = PurePosixPath(name)
        need(type(name) is str and not path.is_absolute() and path.as_posix() == name
             and '..' not in path.parts and type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest), 'canonical pinned notice reference')
        raw = ordinary(root / name); total += len(raw)
        need(total <= 4 * 1024**2 and hashlib.sha256(raw).hexdigest() == digest, 'complete exact source notice bytes')
        result[name] = raw
    return result


def install_notices(root, policy, stage):
    stage = Path(stage)
    # fakeroot virtualizes getuid/stat, but not this kernel identity readback.
    uid = next(line.split()[1:] for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('Uid:'))
    need(len(uid) == 4 and len(set(uid)) == 1 and int(uid[0]) > 0, 'real unprivileged package process required')
    need(stage.is_absolute() and stage == stage.resolve() and stage != Path('/') and stage.is_dir()
         and stage.name == PACKAGE and stage.stat().st_uid == os.getuid()
         and not stage.stat().st_mode & 0o022, 'private nonroot-owned package DESTDIR required')
    target = stage / 'usr/share/licenses' / PACKAGE / 'source'
    need(not target.exists() and not any(p.is_symlink() for p in target.parents), 'fresh ordinary notice DESTDIR')
    rows = notices(root, policy)
    for name, raw in rows.items():
        path = target / name; path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(raw); os.fchmod(stream.fileno(), 0o644)
    return dict(status='PASS_NOTICE_DESTDIR_COPY_ONLY', notices=len(rows), bytes=sum(map(len, rows.values())))


def configuration(build, profile):
    expected = dict(re.findall(r'^set\((\w+) (\S+) CACHE (?:BOOL|STRING) "" FORCE\)$',
                              ordinary(Path(profile).resolve()).decode(), re.MULTILINE))
    need(len(expected) >= 40, 'complete finite configuration profile')
    observed = {}
    for line in ordinary(Path(build).resolve() / 'CMakeCache.txt').decode().splitlines():
        # Our profile uses simple keys. Qt also emits quoted namespace keys
        # containing '::'; those are separate internal metadata, not options.
        match = re.fullmatch(r'([A-Za-z0-9_]+):[^=]+=(.*)', line)
        if match:
            key, value = match.groups(); need(key not in observed, 'unique CMake cache setting'); observed[key] = value
    for key, value in expected.items():
        actual = 'QT_' + key if key.startswith('FEATURE_') else key
        need(observed.get(actual) == value, 'actual configured profile differs: ' + actual)
    return dict(status='PASS_CONFIGURED_PROFILE_ONLY', settings=len(expected), native='NOT_ESTABLISHED')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('verify', 'install-notices', 'configuration'))
    for name in ('root', 'policy', 'stage', 'build', 'profile'):
        parser.add_argument('--' + name, type=Path)
    args = parser.parse_args()
    if args.operation == 'configuration':
        result = configuration(args.build, args.profile)
    elif args.operation == 'install-notices':
        result = install_notices(args.root, args.policy, args.stage)
    else:
        rows = notices(args.root, args.policy)
        result = dict(status='PASS_QT612_SOURCE_NOTICES_ONLY', notices=len(rows), bytes=sum(map(len, rows.values())))
    print(json.dumps(result, sort_keys=True))
