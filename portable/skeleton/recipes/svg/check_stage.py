#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only private QtSvg DESTDIR contract; never load ELF or install files."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct

PACKAGE, VERSION = 'cachy-asahi-qt612-svg-source-reference', '6.12.0'
MODULES = ('Svg', 'SvgWidgets')
PLUGINS = ('imageformats/libqsvg.so', 'iconengines/libqsvgicon.so')
PRI = ('qt_lib_svg.pri', 'qt_lib_svg_private.pri', 'qt_lib_svgwidgets.pri')
LICENSE_ROOT = f'usr/share/licenses/{PACKAGE}'
NOTICE_ROOT = LICENSE_ROOT + '/source'
REFERENCE_DIR = Path(__file__).resolve().parent
MAX_ENTRIES, MAX_FILE_BYTES, MAX_PAYLOAD_BYTES = 32768, 64 * 1024**2, 256 * 1024**2
MAX_NOTICES, MAX_NOTICE_BYTES = 512, 4 * 1024**2
PRIVATE = {'.git', '.ssh', '.gnupg', '.aws', '.config', '.cache', '.codex'}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(body):
    return hashlib.sha256(body).hexdigest()


def elf_info(body, machine):
    """Parse bounded ELF64LE dynamic strings without executing a loader."""
    need(len(body) >= 64 and body[:7] == b'\x7fELF\x02\x01\x01', 'ELF64 little-endian required')
    kind, actual, version = struct.unpack_from('<HHI', body, 16)
    need(kind in (2, 3) and actual == machine and version == 1, 'ELF architecture/type/version mismatch')
    phoff = struct.unpack_from('<Q', body, 32)[0]
    size, count = struct.unpack_from('<HH', body, 54)
    need(size == 56 and 0 < count < 1024 and 64 <= phoff <= len(body)
         and phoff + size * count <= len(body), 'ELF program headers malformed')
    segments = [struct.unpack_from('<IIQQQQQQ', body, phoff + n * size) for n in range(count)]
    need(all(s[2] + s[5] <= len(body) and s[5] <= s[6] for s in segments), 'ELF segment outside file/memory bounds')
    load_segments = [s for s in segments if s[0] == 1]
    need(load_segments and all(s[7] >= 16384 and s[7] & (s[7] - 1) == 0
                              and s[2] % 16384 == s[3] % 16384 and s[2] % s[7] == s[3] % s[7]
                              for s in load_segments), 'ELF static 16K PT_LOAD geometry required')
    dynamic = [s for s in segments if s[0] == 2]
    need(len(dynamic) <= 1, 'ambiguous ELF dynamic segment')
    entries, needed = {}, []
    for segment in dynamic:
        need(segment[5] % 16 == 0, 'ELF dynamic segment malformed')
        terminated = False
        for offset in range(segment[2], segment[2] + segment[5], 16):
            tag, value = struct.unpack_from('<qQ', body, offset)
            if tag == 0:
                terminated = True
                break
            if tag == 1:
                needed.append(value)
            elif tag in (5, 10, 14):
                need(tag not in entries, 'duplicate ELF dynamic string metadata')
                entries[tag] = value
        need(terminated, 'ELF dynamic segment unterminated')
    strings = needed + ([entries[14]] if 14 in entries else [])
    values = []
    if strings:
        need(5 in entries and 10 in entries and entries[10] > 0, 'ELF dynamic string table missing')
        loads = [s for s in load_segments if s[3] <= entries[5]
                 and entries[5] + entries[10] <= s[3] + s[5]]
        need(len(loads) == 1, 'ELF dynamic string table outside load segment')
        table = loads[0][2] + entries[5] - loads[0][3]
        for index in strings:
            need(index < entries[10], 'ELF dynamic string index outside table')
            stop = body.find(b'\0', table + index, table + entries[10])
            need(stop > table + index, 'ELF dynamic string empty/unterminated')
            try:
                values.append(body[table + index:stop].decode('ascii'))
            except UnicodeDecodeError as error:
                raise ValueError('ELF dynamic string must be ASCII') from error
    return {'type': kind, 'machine': actual, 'soname': values[-1] if 14 in entries else None,
            'needed': values[:len(needed)], 'load_geometry': 'PASS_STATIC_16K_PT_LOAD_ONLY',
            'load_segments': [{'offset': s[2], 'vaddr': s[3], 'file_bytes': s[5],
                               'memory_bytes': s[6], 'alignment': s[7]} for s in load_segments]}


def owned(name):
    directories = ('usr', 'usr/include', 'usr/include/qt6', 'usr/lib', 'usr/lib/cmake',
                   'usr/lib/cmake/Qt6Gui', 'usr/lib/pkgconfig', 'usr/lib/qt6',
                   'usr/lib/qt6/plugins', 'usr/lib/qt6/plugins/imageformats',
                   'usr/lib/qt6/plugins/iconengines', 'usr/lib/qt6/mkspecs',
                   'usr/lib/qt6/mkspecs/modules', 'usr/lib/qt6/modules', 'usr/lib/qt6/metatypes',
                   'usr/share', 'usr/share/licenses', LICENSE_ROOT, NOTICE_ROOT)
    if name in directories:
        return True
    if any(name == tree or name.startswith(tree + '/') for tree in (
            'usr/include/qt6/QtSvg', 'usr/include/qt6/QtSvgWidgets',
            'usr/lib/cmake/Qt6Svg', 'usr/lib/cmake/Qt6SvgPrivate', 'usr/lib/cmake/Qt6SvgWidgets', NOTICE_ROOT)):
        return True
    if name in {f'usr/lib/libQt6{module}{suffix}' for module in MODULES
                for suffix in ('.prl', '.so', '.so.6', '.so.' + VERSION)}:
        return True
    if re.fullmatch(r'usr/lib/cmake/Qt6Gui/Qt6QSvg(?:Plugin|IconPlugin)[A-Za-z0-9_-]*\.cmake', name):
        return True
    return name in ({'usr/lib/qt6/plugins/' + plugin for plugin in PLUGINS}
                    | {'usr/lib/qt6/mkspecs/modules/' + name for name in PRI}
                    | {f'usr/lib/pkgconfig/Qt6{module}.pc' for module in MODULES}
                    | {f'usr/lib/qt6/modules/{module}.json' for module in MODULES}
                    | {f'usr/lib/qt6/metatypes/qt6{module.lower()}_metatypes.json' for module in MODULES}
                    | {LICENSE_ROOT + '/' + name for name in ('LICENSE.packaging', 'LicenseRef-Qt-ThirdParty.txt',
                                                             'source-notices.json')})


def inspect(root, arch='aarch64', license_manifest=None):
    root = Path(root)
    need(root.is_absolute() and root == root.resolve() and root != Path('/') and root.is_dir(),
         'canonical private QtSvg staging root required')
    need(arch in ('aarch64', 'x86_64'), 'unsupported architecture')
    machine = {'aarch64': 183, 'x86_64': 62}[arch]
    files, links, directories, elf = {}, {}, {}, {}
    total = 0
    expected_links = {f'usr/lib/libQt6{module}{suffix}': target for module in MODULES
                      for suffix, target in (('.so', f'libQt6{module}.so.6'),
                                             ('.so.6', f'libQt6{module}.so.{VERSION}'))}
    for count, path in enumerate(root.rglob('*'), 1):
        need(count <= MAX_ENTRIES, 'QtSvg stage entry cap')
        name = path.relative_to(root).as_posix()
        info = path.lstat(); mode = stat.S_IMODE(info.st_mode)
        need(not PRIVATE.intersection(part.casefold() for part in Path(name).parts), 'private payload path forbidden')
        need(owned(name), 'outside QtSvg ownership: ' + name)
        need(info.st_uid in (0, os.geteuid()), 'foreign staged owner: ' + name)
        need(stat.S_ISLNK(info.st_mode) or not mode & 0o7022, 'unsafe payload mode: ' + name)
        if stat.S_ISLNK(info.st_mode):
            target = path.readlink()
            need(name in expected_links and str(target) == expected_links[name], 'only exact QtSvg ABI links permitted')
            try:
                resolved = path.resolve(strict=True)
            except (OSError, RuntimeError) as error:
                raise ValueError('dangling/cyclic staged link: ' + name) from error
            need(not target.is_absolute() and resolved.is_relative_to(root), 'escaping staged link: ' + name)
            links[name] = {'target': str(target), 'sha256': sha(str(target).encode()), 'mode': mode}
        elif stat.S_ISDIR(info.st_mode):
            directories[name] = mode
        else:
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'ordinary single-link staged file required: ' + name)
            need(info.st_size <= MAX_FILE_BYTES and total + info.st_size <= MAX_PAYLOAD_BYTES, 'QtSvg stage byte cap')
            body = path.read_bytes(); total += len(body)
            files[name] = {'bytes': len(body), 'sha256': sha(body), 'mode': mode}
            if body.startswith(b'\x7fELF'):
                elf[name] = elf_info(body, machine)
    for module in MODULES:
        library = f'usr/lib/libQt6{module}.so.{VERSION}'
        need(library in elf and elf[library]['type'] == 3 and elf[library]['soname'] == f'libQt6{module}.so.6',
             'QtSvg module shared library/SONAME required: ' + module)
        for name in (f'usr/include/qt6/Qt{module}/Qt{module}', f'usr/lib/pkgconfig/Qt6{module}.pc',
                     f'usr/lib/cmake/Qt6{module}/Qt6{module}Config.cmake', f'usr/lib/libQt6{module}.prl'):
            need(name in files, 'module development metadata required: ' + name)
        header = f'usr/include/qt6/Qt{module}/qt{module.lower()}version.h'
        need(header in files and re.search(r'^#define\s+QT' + module.upper() + r'_VERSION_STR\s+"6\.12\.0"\s*$',
                                          (root / header).read_text(), re.MULTILINE), 'QtSvg 6.12.0 version header required')
    need(set(links) == set(expected_links), 'complete QtSvg ABI link chain required')
    for name in ('usr/include/qt6/QtSvg/6.12.0/QtSvg/private/qsvghandler_p.h',
                 'usr/include/qt6/QtSvg/QSvgRenderer', 'usr/include/qt6/QtSvg/qsvgrenderer.h',
                 'usr/include/qt6/QtSvg/QSvgGenerator', 'usr/include/qt6/QtSvg/qsvggenerator.h',
                 'usr/include/qt6/QtSvgWidgets/QSvgWidget', 'usr/include/qt6/QtSvgWidgets/qsvgwidget.h',
                 'usr/lib/cmake/Qt6SvgPrivate/Qt6SvgPrivateConfig.cmake',
                 *(f'usr/lib/qt6/mkspecs/modules/{name}' for name in PRI),
                 'usr/lib/cmake/Qt6Gui/Qt6QSvgPluginConfig.cmake',
                 'usr/lib/cmake/Qt6Gui/Qt6QSvgIconPluginConfig.cmake'):
        need(name in files, 'own private/plugin metadata required: ' + name)
    for name in ('usr/lib/qt6/plugins/' + plugin for plugin in PLUGINS):
        need(name in elf and elf[name]['type'] == 3 and files[name]['mode'] & 0o111, 'QtSvg shared plugin required: ' + name)
    policy_path = Path(license_manifest) if license_manifest else REFERENCE_DIR / 'source-notices.json'
    need(policy_path.stat().st_size <= MAX_NOTICE_BYTES, 'notice policy byte cap')
    policy_raw = policy_path.read_bytes()
    need(len(policy_raw) <= MAX_NOTICE_BYTES, 'notice policy byte cap')
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate notice policy key'); value[key] = item
        return value
    policy = json.loads(policy_raw, object_pairs_hook=pairs)
    need(type(policy) is dict and set(policy) == {'schema_version', 'source_notices'}
         and type(policy['schema_version']) is int and policy['schema_version'] == 1
         and type(policy['source_notices']) is dict and 0 < len(policy['source_notices']) <= MAX_NOTICES,
         'exact pinned source notice policy required')
    expected = {}
    for name, digest in policy['source_notices'].items():
        relative = Path(name)
        need(relative.parts and not relative.is_absolute() and '..' not in relative.parts and str(relative) == name
             and type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest), 'invalid source notice pin')
        expected[NOTICE_ROOT + '/' + name] = digest
    actual = {name: row['sha256'] for name, row in files.items() if name.startswith(NOTICE_ROOT + '/')}
    need(actual == expected and sum(files[name]['bytes'] for name in actual) <= MAX_NOTICE_BYTES,
         'complete staged source notice corpus differs')
    for staged, raw in (('LICENSE.packaging', (REFERENCE_DIR / 'LICENSE.packaging').read_bytes()),
                        ('LicenseRef-Qt-ThirdParty.txt', (REFERENCE_DIR / 'LICENSE.third-party').read_bytes()),
                        ('source-notices.json', policy_raw)):
        need(files.get(LICENSE_ROOT + '/' + staged, {}).get('sha256') == sha(raw), 'staged packaging license/policy differs: ' + staged)
    return {'status': 'PASS_QT612_SVG_DESTDIR_CONTRACT_ONLY', 'architecture': arch,
            'evidence_scope': 'HOST_X86_64_STAGE_ONLY' if arch == 'x86_64' else 'STAGED_AARCH64_ELF_ONLY',
            'files': files, 'symlinks': links, 'directories': directories, 'elf': elf, 'payload_bytes': total,
            'native_execution': 'NOT_ESTABLISHED', 'installation': 'NOT_RUN', 'hardware': 'NOT_RUN'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--host-only-x86_64', action='store_true')
    parser.add_argument('--license-manifest', type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(args.root, 'x86_64' if args.host_only_x86_64 else 'aarch64', args.license_manifest), sort_keys=True))
