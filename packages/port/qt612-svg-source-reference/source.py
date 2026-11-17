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
import struct

REVISION = '883a58532078d003cefef0a549bfe9f885ce41f5'
PACKAGE = 'cachy-asahi-qt612-svg-source-reference'
BASE_MODULES = ('Core', 'Gui', 'Widgets')
BASE_CONFIGS = ('Qt6', 'Qt6BuildInternals', 'Qt6Core', 'Qt6Gui', 'Qt6Widgets',
                'Qt6CorePrivate', 'Qt6GuiPrivate', 'Qt6WidgetsPrivate', 'Qt6CoreTools', 'Qt6WidgetsTools')
PRIVATE_HEADERS = ('QtCore/6.12.0/QtCore/private/qglobal_p.h',
                   'QtGui/6.12.0/QtGui/private/qpaintengine_p.h',
                   'QtGui/6.12.0/QtGui/private/qcssparser_p.h',
                   'QtWidgets/6.12.0/QtWidgets/private/qwidget_p.h')
GENERATED_CONFIGS = ('Qt6Svg/Qt6SvgConfig.cmake', 'Qt6SvgWidgets/Qt6SvgWidgetsConfig.cmake',
                     'Qt6SvgPrivate/Qt6SvgPrivateConfig.cmake', 'Qt6Gui/Qt6QSvgPluginConfig.cmake',
                     'Qt6Gui/Qt6QSvgIconPluginConfig.cmake')


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
    need(len(expected) >= 20, 'complete finite configuration profile')
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


def dependencies(prefix):
    """Read installed inputs before CMake can perform any compiler probes."""
    prefix = Path(prefix)
    need(prefix.is_absolute() and prefix == prefix.resolve() and prefix != Path('/'),
         'explicit canonical installed Qtbase prefix required')
    files = {}
    def observe(name, elf=False, shared=False):
        raw = ordinary(prefix / name, 64 * 1024**2 if elf else 4 * 1024**2)
        if elf:
            need(len(raw) >= 64 and raw[:7] == b'\x7fELF\x02\x01\x01'
                 and struct.unpack_from('<H', raw, 18)[0] == 183
                 and struct.unpack_from('<H', raw, 16)[0] in ((3,) if shared else (2, 3)),
                 'native AArch64 Qtbase library/tool structure required')
            need(shared or (prefix / name).stat().st_mode & 0o111, 'native Qtbase tools must be executable')
        files[name] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        return raw
    # Version refusal comes first: an installed Qt6.11 is not a configure experiment.
    for module in BASE_MODULES:
        name = f'include/qt6/Qt{module}/qt{module.lower()}version.h'
        raw = observe(name)
        need(re.search(rb'^#define\s+QT' + module.upper().encode() + rb'_VERSION_STR\s+"6\.12\.0"\s*$',
                       raw, re.MULTILINE), 'installed Qtbase header version must be exactly 6.12.0')
    for module in BASE_CONFIGS:
        observe(f'lib/cmake/{module}/{module}Config.cmake')
    for name in PRIVATE_HEADERS: observe('include/qt6/' + name)
    for module in BASE_MODULES: observe(f'lib/libQt6{module}.so.6.12.0', elf=True, shared=True)
    for tool in ('moc', 'rcc', 'uic'): observe('lib/qt6/' + tool, elf=True)
    observe('lib/qt6/plugins/platforms/libqoffscreen.so', elf=True, shared=True)
    return dict(status='PASS_STRUCTURAL_QT612_PREFIX_ONLY', prefix=str(prefix), files=files,
                source_ABI_provider='ROOT_PINNED_PROVIDER_STILL_REQUIRED', native_execution='NOT_ESTABLISHED')


def targets(build):
    build = Path(build)
    need(build.is_absolute() and build == build.resolve(), 'canonical own build tree required')
    rows = {}
    for name in GENERATED_CONFIGS:
        raw = ordinary(build / 'lib/cmake' / name)
        rows[name] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    return dict(status='PASS_GENERATED_SVG_TARGET_METADATA_ONLY', files=rows, native='NOT_ESTABLISHED')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('verify', 'install-notices', 'configuration', 'dependencies', 'targets'))
    for name in ('root', 'policy', 'stage', 'build', 'profile', 'prefix'):
        parser.add_argument('--' + name, type=Path)
    args = parser.parse_args()
    try:
        if args.operation == 'configuration': result = configuration(args.build, args.profile)
        elif args.operation == 'dependencies': result = dependencies(args.prefix)
        elif args.operation == 'targets': result = targets(args.build)
        elif args.operation == 'install-notices': result = install_notices(args.root, args.policy, args.stage)
        else:
            rows = notices(args.root, args.policy)
            result = dict(status='PASS_QT612_SOURCE_NOTICES_ONLY', notices=len(rows), bytes=sum(map(len, rows.values())))
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, TypeError) as error:
        print(json.dumps(dict(status='HOLD_QT612_SVG_INPUTS', reason=str(error)), sort_keys=True))
        raise SystemExit(1)
