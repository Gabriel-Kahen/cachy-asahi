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

REVISION = 'c4f85cd060e3e80a7d71829defac9cf5a40e8ffa'
PACKAGE = 'cachy-asahi-qt612-wayland-source-reference'


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



def dependency_inputs(prefix, policy):
    prefix = Path(prefix)
    need(prefix.is_absolute() and prefix == prefix.resolve() and prefix.is_dir(),
         'canonical explicit dependency prefix required')
    rows = json.loads(ordinary(Path(policy).resolve()))
    need(set(rows) == {'schema', 'kind', 'qtbase_revision', 'files', 'actual_native_prefix', 'source_legal_acceptance'}
         and rows['schema'] == 1 and rows['kind'] == 'QT612_WAYLAND_EXTERNAL_QTBASE_PROTOCOL_INPUTS_V1'
         and rows['qtbase_revision'] == '025bdad181de241e81bf853c8a2d7bf3d19261a9'
         and type(rows['files']) is dict and len(rows['files']) == 52,
         'complete pinned Qtbase protocol dependency policy')
    result = {}
    for name, row in rows['files'].items():
        rel = PurePosixPath(name)
        need(not rel.is_absolute() and str(rel) == name and '..' not in rel.parts
             and name.startswith('share/qt6/wayland/'), 'finite dependency protocol path')
        raw = ordinary(prefix / name)
        need(set(row) == {'bytes', 'sha256'} and row == dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()),
             'matching Qt6.12 installed protocol/attribution/license bytes required')
        result[name] = raw
    return result


def install_dependency_notices(prefix, policy, stage):
    # Reuse the same kernel-unprivileged/fresh-DESTDIR custody as own notices.
    stage = Path(stage)
    uid = next(line.split()[1:] for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('Uid:'))
    need(len(uid) == 4 and len(set(uid)) == 1 and int(uid[0]) > 0,
         'real unprivileged package process required')
    need(stage.is_absolute() and stage == stage.resolve() and stage.name == PACKAGE and stage.is_dir()
         and stage.stat().st_uid == os.getuid() and not stage.stat().st_mode & 0o022,
         'private named package DESTDIR required')
    target = stage / 'usr/share/licenses' / PACKAGE / 'dependencies/qtbase'
    need(not target.exists() and not any(v.is_symlink() for v in target.parents), 'fresh dependency notice DESTDIR')
    rows = dependency_inputs(prefix, policy)
    for name, raw in rows.items():
        destination = target / name
        destination.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
        with destination.open('xb') as stream:
            stream.write(raw); os.fchmod(stream.fileno(),0o644)
    return dict(status='PASS_DEPENDENCY_NOTICE_DESTDIR_COPY_ONLY', files=len(rows),bytes=sum(map(len,rows.values())))


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
    ninja = ordinary(Path(build).resolve() / 'build.ninja', 16 * 1024**2).decode()
    libraries = sorted(re.findall(r'^build (lib/libQt6[^: ]+\.so\.6\.12\.0):', ninja, re.MULTILINE))
    required = sorted('lib/libQt6' + module + '.so.6.12.0' for module in (
        'WaylandCompositor', 'WaylandEglCompositorHwIntegration', 'WaylandCompositorXdgShell',
        'WaylandCompositorIviapplication', 'WaylandCompositorWLShell', 'WaylandCompositorPresentationTime'))
    need(libraries == required, 'full six Wayland shared target declarations required; no empty/partial configure')
    for uri in ('QtWayland.Compositor', 'QtWayland.Compositor.XdgShell', 'QtWayland.Compositor.IviApplication',
                'QtWayland.Compositor.WlShell', 'QtWayland.Compositor.QtShell', 'QtWayland.Compositor.PresentationTime',
                'QtWayland.Compositor.TextureSharingExtension', 'QtWayland.Client.TextureSharing'):
        prefix = 'lib/qt6/qml/' + uri.replace('.', '/') + '/'
        need(re.search(r'^build ' + re.escape(prefix) + r'[^: ]+\.so:', ninja, re.MULTILINE),
             'full required QML plugin target declaration missing: ' + uri)
    for plugin in ('wayland-shell-integration/libivi-shell.so', 'wayland-shell-integration/libqt-shell.so',
                   'wayland-decoration-client/libadwaita.so'):
        need('build lib/qt6/plugins/' + plugin + ':' in ninja, 'required client plugin target declaration')
    return dict(status='PASS_FULL_WAYLAND_CONFIGURED_TARGETS_ONLY', settings=len(expected),
                shared_targets=libraries, required_QML_targets=8, native='NOT_ESTABLISHED')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('verify', 'install-notices', 'configuration', 'dependency-inputs', 'install-dependency-notices'))
    for name in ('root', 'policy', 'stage', 'build', 'profile', 'prefix', 'dependency-policy'):
        parser.add_argument('--' + name, type=Path)
    args = parser.parse_args()
    if args.operation == 'dependency-inputs':
        rows = dependency_inputs(args.prefix, args.dependency_policy)
        result = dict(status='PASS_QT612_DEPENDENCY_PROTOCOL_BYTES_ONLY', files=len(rows),bytes=sum(map(len,rows.values())))
    elif args.operation == 'install-dependency-notices':
        result = install_dependency_notices(args.prefix,args.dependency_policy,args.stage)
    elif args.operation == 'configuration':
        result = configuration(args.build, args.profile)
    elif args.operation == 'install-notices':
        result = install_notices(args.root, args.policy, args.stage)
    else:
        rows = notices(args.root, args.policy)
        result = dict(status='PASS_QT612_SOURCE_NOTICES_ONLY', notices=len(rows), bytes=sum(map(len, rows.values())))
    print(json.dumps(result, sort_keys=True))
