#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Passive original Qt GUI package archive inspection; no native acceptance.

inspect_archive(path, work, recipe_root) requires canonical absolute paths. work
is an existing caller-owned directory. recipe_root is the exact b052 checkout;
only the whole-pinned check_stage.py is imported. No recipe/payload is executed.
Temporary decoding/materialization occurs only under work and is removed.
"""
import argparse
import hashlib
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile
import types

RECIPE_COMMIT = 'b05267833d497ef034576741bf31968019a526c3'
RECIPE_PATH = 'packages/port/qt612-gui-source-reference'
PACKAGE = 'cachy-asahi-qt612-gui-source-reference'
VERSION = '6.12.0-1'
MAX_COMPRESSED, MAX_EXPANDED, MAX_MEMBER, MAX_NODES = 512 * 1024**2, 2 * 1024**3, 128 * 1024**2, 100000
MAX_METADATA, MAX_PAX = 4 * 1024**2, 65536
RECIPE_FILES = {'.SRCINFO': {'bytes': 3626, 'mode': 420, 'sha256': '22a70c92318dc7aaadbc9c30f8beb5098c7d6c4c734d8dbcca5ec12f138c91ea'}, 'CVE-2026-105924-qtbase-6.12.diff': {'bytes': 5019, 'mode': 420, 'sha256': 'c27d27b86aaf2cdab0c18d513fbb94a432e98782eddfc5f856387e4be68be50b'}, 'CVE-2026-105943-qtbase-6.12.diff': {'bytes': 2291, 'mode': 420, 'sha256': 'dd22629ce948cf0a900421323cca331907180242a9b51c3fd75b25c75f068099'}, 'CVE-2026-116337-qtbase-6.12-0001.diff': {'bytes': 3262, 'mode': 420, 'sha256': '74c5028985dcc0455255909de4dc80f50cf5472dbf465ce46ebc791a7b080f12'}, 'CVE-2026-116337-qtbase-6.12-0002.diff': {'bytes': 5186, 'mode': 420, 'sha256': '83abc89d507dbd9a94dc5718b0125492c1c37b0609a8f404a1f164925940faec'}, 'LICENSE.packaging': {'bytes': 1070, 'mode': 420, 'sha256': '67fe503b5c407bca1c340e14fb7ceb6849b1af4d531a783b30d09cb76e65a3aa'}, 'LICENSE.third-party': {'bytes': 639, 'mode': 420, 'sha256': '277c4d14792c236a96f02612b4f134f84707eb33fc6a1d954ec9c5ad20490585'}, 'PKGBUILD': {'bytes': 5865, 'mode': 420, 'sha256': '7962cdc0d8648ae6f96b76f13bb2ae75cee5892940c93d57b8ee57f5163e9c95'}, 'SmokeCMakeLists.txt': {'bytes': 4273, 'mode': 420, 'sha256': 'e2786c21fdf000d5956fdf02b33d452d0c9d02c8459134b36a276618e3bc9533'}, 'check_stage.py': {'bytes': 19545, 'mode': 420, 'sha256': '291053598bd806eed9be622f495d51725aae5f579f5f3241a83111ded254cee5'}, 'configure.cmake': {'bytes': 5696, 'mode': 420, 'sha256': '1d394895a6a9fd42944ff70c3cbf801cebc2986c3f52b4f49b2359c3d5d3f24a'}, 'smoke.cpp': {'bytes': 2876, 'mode': 420, 'sha256': '208e306973a4e3ee33f737071629a54b0a07ac029a632215c5e67960661ecbb1'}, 'source-notices.json': {'bytes': 20042, 'mode': 420, 'sha256': '3651e4bca7846caee61183c2bc55bf4988c6f4f2a56af81f3948afe03d41cfda'}, 'source.py': {'bytes': 5245, 'mode': 420, 'sha256': '402e4fde4bf176b92dda602d71d4ad1e1dbf0ee832347f0e6452ea9c53de6632'}}
DEPENDS = ['brotli', 'dbus', 'double-conversion', 'fontconfig', 'freetype2', 'glib2', 'glibc', 'harfbuzz', 'icu', 'libb2', 'libgcc', 'libgl', 'libice', 'libjpeg-turbo', 'libpng', 'libsm', 'libstdc++', 'libx11', 'libxcb', 'libxkbcommon', 'libxkbcommon-x11', 'md4c>=0.5.3', 'md4c<0.6', 'openssl', 'pcre2', 'shared-mime-info', 'sqlite', 'xcb-util-cursor', 'xcb-util-image', 'xcb-util-keysyms', 'xcb-util-renderutil', 'xcb-util-wm', 'xdg-utils', 'zlib', 'zstd', 'libdrm', 'libglvnd', 'mesa', 'wayland>=1.15']
PROVIDES = ['qt6-base=6.12.0', 'libQt6Core.so.6', 'libQt6Concurrent.so.6', 'libQt6DBus.so.6', 'libQt6Gui.so.6', 'libQt6Network.so.6', 'libQt6OpenGL.so.6', 'libQt6OpenGLWidgets.so.6', 'libQt6PrintSupport.so.6', 'libQt6Sql.so.6', 'libQt6Test.so.6', 'libQt6Widgets.so.6', 'libQt6Xml.so.6', 'libQt6XcbQpa.so.6', 'libQt6EglFSDeviceIntegration.so.6', 'libQt6EglFsKmsGbmSupport.so.6', 'libQt6EglFsKmsSupport.so.6', 'libQt6WaylandClient.so.6', 'libQt6WlShellIntegration.so.6']
CONFLICTS = ['qt6-base', 'cachy-asahi-qt612-base-source-reference']
LICENSES = ['GPL-3.0-only', 'LGPL-3.0-only', 'Qt-GPL-exception-1.0', 'LicenseRef-Qt-ThirdParty']


def need(value, reason):
    if not value:
        raise ValueError(reason)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def canonical_path(value):
    raw = os.fspath(value)
    path = Path(raw)
    need(raw == str(path) and path.is_absolute() and '..' not in path.parts and not raw.startswith('//'), 'canonical absolute path required')
    for item in (*reversed(path.parents), path):
        need(not stat.S_ISLNK(item.lstat().st_mode), 'symlink path component refused')
    return path


def open_regular(path, cap):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not info.st_mode & 0o7022
         and 0 < info.st_size <= cap, 'single-link bounded safe ordinary file required')
    stream = os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), 'rb')
    try:
        need(identity(os.fstat(stream.fileno())) == identity(info), 'file identity changed at open')
    except BaseException:
        stream.close()
        raise
    return stream, info


def recipe_inputs(recipe_root):
    root = canonical_path(recipe_root) / RECIPE_PATH
    raw, observed = {}, {}
    for name, expected in RECIPE_FILES.items():
        path = canonical_path(root / name)
        stream, before = open_regular(path, MAX_METADATA)
        with stream:
            body = stream.read(expected['bytes'] + 1)
            need(pin(body) == {k: expected[k] for k in ('bytes', 'sha256')}
                 and stat.S_IMODE(before.st_mode) == expected['mode'], 'exact b052 active14 recipe pin required: ' + name)
            need(identity(os.fstat(stream.fileno())) == identity(before), 'recipe input changed during read')
        raw[name], observed[path] = body, identity(before)
    return root, raw, observed


def load_stage(raw):
    # The only imported local code is an entire, fixed source-audited helper.
    need(pin(raw) == {k: RECIPE_FILES['check_stage.py'][k] for k in ('bytes', 'sha256')}, 'whole-pinned b052 stage helper required')
    module = types.ModuleType('qt612_gui_b052_stage')
    module.__file__ = str(Path(__file__).resolve())
    exec(compile(raw, '<whole-pinned-b052-check_stage.py>', 'exec'), module.__dict__)
    return module


def decode_xz(path, destination):
    stream, before = open_regular(path, MAX_COMPRESSED)
    digest, total, expanded = hashlib.sha256(), 0, 0
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=256 * 1024**2)
    with stream, destination.open('xb') as output:
        while not decoder.eof:
            block = stream.read(1024**2) if decoder.needs_input else b''
            if decoder.needs_input:
                need(block, 'truncated XZ stream')
                total += len(block)
                digest.update(block)
            decoded = decoder.decompress(block, max_length=1024**2)
            expanded += len(decoded)
            need(expanded <= MAX_EXPANDED, 'expanded archive byte cap')
            output.write(decoded)
        need(not decoder.unused_data and not stream.read(1), 'single XZ stream without trailing bytes required')
        need(total == before.st_size and identity(os.fstat(stream.fileno())) == identity(before)
             and identity(path.lstat()) == identity(before), 'original archive changed during decode')
    return dict(bytes=total, sha256=digest.hexdigest()), expanded, identity(before)


def integer(raw):
    need(not raw or not raw[0] & 0x80, 'base256 tar numeric field refused')
    text = raw.rstrip(b'\0 ').lstrip(b' ')
    need(not text or re.fullmatch(b'[0-7]+', text), 'ordinary octal tar number required')
    return int(text or b'0', 8)


def cstring(raw):
    return raw.split(b'\0', 1)[0].decode('utf-8', 'strict')


def relative(name, directory=False):
    if name.startswith('./'):
        name = name[2:]
    if directory:
        name = name.removesuffix('/')
    path = PurePosixPath(name)
    need(name and str(path) == name and not path.is_absolute() and '..' not in path.parts
         and all(32 <= ord(c) < 127 for c in name), 'canonical ordinary tar member required')
    return name


def pax_fields(raw):
    fields, position = {}, 0
    while position < len(raw):
        space = raw.find(b' ', position)
        need(space > position and raw[position:space].isdigit(), 'PAX record length required')
        length = int(raw[position:space])
        need(length > space - position + 2 and position + length <= len(raw), 'PAX record bounds')
        record = raw[space + 1:position + length]
        need(record.endswith(b'\n') and b'=' in record, 'PAX record syntax')
        key, value = record[:-1].decode('utf-8', 'strict').split('=', 1)
        need(key not in fields and 'sparse' not in key.lower(), 'duplicate/sparse PAX field refused')
        fields[key] = value
        position += length
    return fields


def materialize(decoded, stage):
    rows, metadata, pending, global_pax, headers = {}, {}, {}, {}, 0
    with decoded.open('rb') as archive:
        while True:
            header = archive.read(512)
            need(len(header) == 512, 'complete tar header/end markers required')
            if header == bytes(512):
                need(not pending and archive.read(512) == bytes(512), 'two tar end markers required')
                while block := archive.read(1024**2):
                    need(not any(block), 'nonzero tar trailing bytes refused')
                need(archive.tell() % 512 == 0, 'complete tar zero padding required')
                break
            headers += 1
            need(headers <= MAX_NODES, 'tar node/header cap')
            need(integer(header[148:156]) == sum(header[:148]) + 8 * 32 + sum(header[156:]), 'tar header checksum')
            need(header[257:263] in (b'ustar\0', b'ustar '), 'USTAR/PAX header required')
            kind, size = header[156:157], integer(header[124:136])
            need(size <= (MAX_PAX if kind in (b'x', b'g') else MAX_MEMBER), 'tar member byte cap')
            body = archive.read(size)
            need(len(body) == size, 'complete tar member body required')
            padding = archive.read((-size) % 512)
            need(len(padding) == (-size) % 512 and not any(padding), 'complete zero tar member padding required')
            if kind in (b'x', b'g'):
                fields = pax_fields(body)
                if kind == b'g':
                    need(not set(fields) & {'path', 'linkpath', 'size', 'uid', 'gid'}, 'global PAX identity override refused')
                    global_pax.update(fields)
                    need(sum(len(key) + len(value) for key, value in global_pax.items()) <= MAX_PAX, 'global PAX byte cap')
                else:
                    need(not pending, 'consecutive PAX member overrides refused')
                    pending = fields
                continue
            attributes = global_pax | pending
            pending = {}
            name = cstring(header[:100])
            prefix = cstring(header[345:500])
            if prefix:
                name = prefix + '/' + name
            name = relative(attributes.get('path', name), kind == b'5')
            need(name not in rows, 'duplicate/alias tar member refused')
            need(int(attributes.get('size', size)) == size, 'PAX/body size correspondence required')
            uid, gid = int(attributes.get('uid', integer(header[108:116]))), int(attributes.get('gid', integer(header[116:124])))
            need(uid == gid == 0, 'root-owned archive metadata required')
            mode = integer(header[100:108])
            need(0 <= mode <= 0o7777 and (kind == b'2' or not mode & 0o7022), 'unsafe tar mode refused')
            row = dict(mode=mode, uid=uid, gid=gid, mtime=attributes.get('mtime', integer(header[136:148])), pax=attributes)
            target = stage / name
            if name.startswith('.'):
                need(name in ('.PKGINFO', '.BUILDINFO', '.MTREE') and kind in (b'0', b'\0')
                     and size <= MAX_METADATA, 'only ordinary required package metadata allowed')
                metadata[name] = body
                row.update(type='file', **pin(body))
            elif kind == b'5':
                safe_parents(target, stage)
                need(not size, 'directory body refused')
                need(not target.is_symlink() and (not target.exists() or target.is_dir()), 'directory/file tar collision')
                target.mkdir(parents=True, exist_ok=True)
                target.chmod(mode)
                row['type'] = 'directory'
            elif kind in (b'0', b'\0'):
                safe_parents(target, stage)
                with target.open('xb') as output:
                    output.write(body)
                target.chmod(mode)
                row.update(type='file', **pin(body))
            elif kind == b'2':
                need(not size, 'symlink body refused')
                link = attributes.get('linkpath', cstring(header[157:257]))
                need(link and not PurePosixPath(link).is_absolute() and all(32 <= ord(c) < 127 for c in link), 'relative printable symlink required')
                safe_parents(target, stage)
                target.symlink_to(link)
                row.update(type='symlink', target=link)
            else:
                raise ValueError('hardlink/device/FIFO/sparse/unknown tar member refused')
            rows[name] = row
    need(set(metadata) == {'.PKGINFO', '.BUILDINFO', '.MTREE'} and metadata['.MTREE'], 'all three original package metadata operands required')
    return rows, metadata


def safe_parents(target, root):
    current = root
    for part in target.relative_to(root).parts[:-1]:
        current /= part
        need(not current.is_symlink(), 'symlink tar parent refused')
        current.mkdir(exist_ok=True)
        need(current.is_dir(), 'ordinary tar parent directory required')


def parse_metadata(raw):
    need(len(raw) <= MAX_METADATA and b'\0' not in raw, 'bounded UTF8 package metadata required')
    text, fields = raw.decode('utf-8', 'strict'), {}
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        need(' = ' in line, 'package metadata assignment required')
        key, value = line.split(' = ', 1)
        need(re.fullmatch('[a-z][a-z0-9_]*', key) and value, 'package metadata field syntax')
        fields.setdefault(key, []).append(value)
    return text, fields


def metadata_contract(metadata):
    pkgraw, pkg = parse_metadata(metadata['.PKGINFO'])
    buildraw, build = parse_metadata(metadata['.BUILDINFO'])
    for key, expected in dict(pkgname=PACKAGE, pkgver=VERSION, arch='aarch64').items():
        need(pkg.get(key) == [expected], 'exact GUI package metadata: ' + key)
    for key, expected in dict(depend=DEPENDS, provides=PROVIDES, conflict=CONFLICTS, license=LICENSES).items():
        need(sorted(pkg.get(key, [])) == sorted(expected), 'exact GUI package metadata: ' + key)
    need(not any(pkg.get(key) for key in ('replaces', 'backup', 'install', 'hook', 'optdepend')), 'no replaces/backup/install/hooks/optional dependencies')
    need(pkg.get('pkgbase', [PACKAGE]) == [PACKAGE], 'exact package base')
    for key, expected in dict(format='2', pkgname=PACKAGE, pkgbase=PACKAGE, pkgver=VERSION,
                              pkgarch='aarch64', pkgbuild_sha256sum=RECIPE_FILES['PKGBUILD']['sha256']).items():
        need(build.get(key) == [expected], 'exact BUILDINFO field: ' + key)
    need(len(pkg.get('builddate', [])) == 1 and re.fullmatch('[0-9]{1,12}', pkg['builddate'][0])
         and build.get('builddate') == pkg['builddate'], 'unchanged matching original source/build date required')
    return dict(PKGINFO=dict(raw=pkgraw, pin=pin(metadata['.PKGINFO']), fields=pkg),
                BUILDINFO=dict(raw=buildraw, pin=pin(metadata['.BUILDINFO']), fields=build),
                MTREE=dict(pin=pin(metadata['.MTREE']), semantic_validation=None),
                original_builddate=pkg['builddate'][0])


def inspect_archive(path, work, recipe_root):
    path, work = canonical_path(path), canonical_path(work)
    info = work.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o022, 'owned safe explicit work directory required')
    recipe, raw, observed = recipe_inputs(recipe_root)
    stage_api = load_stage(raw['check_stage.py'])
    with tempfile.TemporaryDirectory(prefix='qt612-gui-archive-', dir=work) as temporary:
        temporary = Path(temporary)
        stage = temporary / 'stage'
        stage.mkdir()
        archive_pin, expanded, original_identity = decode_xz(path, temporary / 'decoded.tar')
        rows, metadata = materialize(temporary / 'decoded.tar', stage)
        parsed = metadata_contract(metadata)
        report = stage_api.inspect(stage, license_manifest=recipe / 'source-notices.json')
        need(identity(path.lstat()) == original_identity, 'original archive changed after inspection')
        for operand, before in observed.items():
            need(identity(operand.lstat()) == before, 'recipe changed after inspection')
        return dict(schema=1, kind='QT612_GUI_ORIGINAL_ARCHIVE_PASSIVE_DATA_ONLY', recipe_commit=RECIPE_COMMIT,
            archive=dict(path=str(path), **archive_pin), expanded_bytes=expanded, tar_nodes=len(rows),
            archive_inventory=rows, metadata=parsed, stage=report, active_recipe_files=RECIPE_FILES,
            native_acceptance=False, native_execution=None, installation=None, M2=None,
            pair_receipts=None, dependency_transaction_acceptance=None, Root_grants=None)


def no_actors(event, args):
    need(not event.startswith(('subprocess.', 'socket.', 'ctypes.'))
         and event not in ('os.system', 'os.exec', 'os.fork', 'os.forkpty', 'os.posix_spawn'), 'PASSIVE_ARCHIVE_NO_ACTORS')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('path', 'work', 'recipe-root'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    sys.addaudithook(no_actors)
    print(json.dumps(inspect_archive(args.path, args.work, args.recipe_root), sort_keys=True))


if __name__ == '__main__':
    main()
