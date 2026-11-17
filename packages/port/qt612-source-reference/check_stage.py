#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read a private Qt DESTDIR. Never execute payloads or install packages."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import struct

PACKAGE = 'cachy-asahi-qt612-base-source-reference'
VERSION = '6.12.0'
MODULES = ('Core', 'Concurrent', 'DBus', 'Gui', 'Network', 'OpenGL',
           'OpenGLWidgets', 'PrintSupport', 'Sql', 'Test', 'Widgets', 'Xml')
PRIVATE_MODULES = ('XcbQpa',)
TOOLS = ('usr/lib/qt6/bin/qmake', 'usr/lib/qt6/moc', 'usr/lib/qt6/uic', 'usr/lib/qt6/rcc')
PLUGINS = ('platforms/libqoffscreen.so', 'platforms/libqxcb.so', 'sqldrivers/libqsqlite.so')
NOTICE_ROOT = f'usr/share/licenses/{PACKAGE}/source'
MAX_ENTRIES, MAX_FILE_BYTES, MAX_PAYLOAD_BYTES = 32768, 128 * 1024**2, 1024**3


def need(condition, message):
    if not condition:
        raise ValueError(message)


def elf_info(body, machine):
    """Read ELF64 little-endian headers and SONAME without loading the image."""
    need(len(body) >= 64 and body[:7] == b'\x7fELF\x02\x01\x01', 'ELF64 little-endian required')
    kind, actual, version = struct.unpack_from('<HHI', body, 16)
    need(actual == machine and kind in (2, 3) and version == 1, 'ELF architecture/type/version mismatch')
    phoff = struct.unpack_from('<Q', body, 32)[0]
    phentsize, phnum = struct.unpack_from('<HH', body, 54)
    need(phentsize == 56 and 0 < phnum < 1024 and phoff + phentsize * phnum <= len(body), 'ELF program headers malformed')
    segments = [struct.unpack_from('<IIQQQQQQ', body, phoff + n * phentsize) for n in range(phnum)]
    for segment in segments:
        need(segment[2] + segment[5] <= len(body), 'ELF segment outside file')
    dynamic = [segment for segment in segments if segment[0] == 2]
    soname = None
    for segment in dynamic:
        need(segment[5] % 16 == 0, 'ELF dynamic segment malformed')
        entries = {}
        for offset in range(segment[2], segment[2] + segment[5], 16):
            tag, value = struct.unpack_from('<qQ', body, offset)
            if tag == 0:
                break
            entries[tag] = value
        if 14 not in entries:
            continue
        need(5 in entries and 10 in entries, 'ELF SONAME string table missing')
        tables = [s for s in segments if s[0] == 1 and s[3] <= entries[5]
                  and entries[5] + entries[10] <= s[3] + s[5]]
        need(len(tables) == 1 and entries[14] < entries[10], 'ELF SONAME string table outside load segment')
        table = tables[0][2] + entries[5] - tables[0][3]
        start, end = table + entries[14], table + entries[10]
        stop = body.find(b'\0', start, end)
        need(stop >= start, 'ELF SONAME unterminated')
        try:
            soname = body[start:stop].decode('ascii')
        except UnicodeDecodeError as error:
            raise ValueError('ELF SONAME must be ASCII') from error
    return {'type': kind, 'machine': actual, 'soname': soname}


def owned(name):
    trees = ('usr/include/qt6', 'usr/lib/qt6', 'usr/share/qt6', 'usr/share/doc/qt6',
             f'usr/share/licenses/{PACKAGE}')
    if name in ('usr', 'usr/bin', 'usr/include', 'usr/lib', 'usr/lib/cmake', 'usr/lib/pkgconfig',
                'usr/share', 'usr/share/doc', 'usr/share/licenses'):
        return True
    if any(name == tree or name.startswith(tree + '/') for tree in trees):
        return True
    if name in ('usr/bin/qmake6', 'usr/bin/qtpaths6'):
        return True
    if name.startswith('usr/lib/cmake/Qt6') or name.startswith('usr/lib/pkgconfig/Qt6'):
        return True
    return name.startswith('usr/lib/libQt6') and '/' not in name[len('usr/lib/'):]


def inspect(root, arch='aarch64', license_manifest=None):
    root = Path(root)
    need(root.is_absolute() and root == root.resolve() and root != Path('/') and root.is_dir(),
         'canonical private staging directory required')
    need(arch in ('aarch64', 'x86_64'), 'unsupported architecture')
    machine = {'aarch64': 183, 'x86_64': 62}[arch]
    files, links, directories, elf = {}, {}, {}, {}
    total_bytes = 0
    for count, path in enumerate(root.rglob('*'), 1):
        need(count <= MAX_ENTRIES, 'Qt stage entry limit exceeded')
        name = path.relative_to(root).as_posix()
        info = path.lstat()
        mode = stat.S_IMODE(info.st_mode)
        need(owned(name), f'outside Qt package ownership: {name}')
        need(stat.S_ISLNK(info.st_mode) or not mode & 0o7022, f'unsafe payload mode: {name}')
        if stat.S_ISLNK(info.st_mode):
            target = path.readlink()
            try:
                resolved = path.resolve(strict=True)
            except (OSError, RuntimeError) as error:
                raise ValueError(f'dangling/cyclic stage link: {name}') from error
            need(not target.is_absolute() and resolved.is_relative_to(root), f'escaping stage link: {name}')
            links[name] = {'target': str(target), 'sha256': hashlib.sha256(str(target).encode()).hexdigest(), 'mode': mode}
        elif stat.S_ISDIR(info.st_mode):
            directories[name] = mode
        else:
            need(stat.S_ISREG(info.st_mode), f'ordinary staged file required: {name}')
            need(info.st_size <= MAX_FILE_BYTES and total_bytes + info.st_size <= MAX_PAYLOAD_BYTES,
                 f'Qt stage byte limit exceeded: {name}')
            body = path.read_bytes()
            total_bytes += len(body)
            files[name] = {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(), 'mode': mode}
            if body.startswith(b'\x7fELF'):
                elf[name] = elf_info(body, machine)
    for module in MODULES + PRIVATE_MODULES:
        library = f'usr/lib/libQt6{module}.so.{VERSION}'
        need(library in elf and elf[library]['type'] == 3
             and elf[library]['soname'] == f'libQt6{module}.so.6', f'Qt {module} shared library/SONAME required')
        for suffix, target in (('.so.6', f'libQt6{module}.so.{VERSION}'), ('.so', f'libQt6{module}.so.6')):
            need(links.get(f'usr/lib/libQt6{module}{suffix}', {}).get('target') == target,
                 f'Qt {module} library link required: {suffix}')
        if module in PRIVATE_MODULES:
            continue
        required = (f'usr/include/qt6/Qt{module}/Qt{module}',
                    f'usr/lib/pkgconfig/Qt6{module}.pc',
                    f'usr/lib/cmake/Qt6{module}/Qt6{module}Config.cmake')
        for name in required:
            need(name in files, f'Qt module development file required: {name}')
    for name in TOOLS + tuple('usr/lib/qt6/plugins/' + plugin for plugin in PLUGINS):
        need(name in elf and files[name]['mode'] & 0o111, f'Qt executable/plugin required: {name}')
    header = 'usr/include/qt6/QtCore/qtcoreversion.h'
    need(header in files and re.search(r'^#define\s+QTCORE_VERSION_STR\s+"6\.12\.0"\s*$',
                                      (root / header).read_text(), re.MULTILINE), 'QtCore 6.12.0 version header required')
    for name in files.keys() | links.keys():
        if name.startswith('usr/lib/qt6/plugins/sqldrivers/'):
            need(name == 'usr/lib/qt6/plugins/sqldrivers/libqsqlite.so', 'SQLite-only SQL plugin profile required')
        need(not name.startswith(tuple('usr/lib/qt6/plugins/' + suffix for suffix in (
            'platforms/libqeglfs', 'platforms/libqlinuxfb', 'platforms/libqvkkhrdisplay',
            'platforms/libqdirectfb', 'platforms/libqwayland', 'platforms/libqvnc', 'platformthemes/libqgtk3'))),
            f'disabled platform plugin present: {name}')
    policy_path = Path(license_manifest) if license_manifest else Path(__file__).with_name('source-notices.json')
    policy = json.loads(policy_path.read_text())
    need(policy.get('schema_version') == 1 and isinstance(policy.get('source_notices'), dict)
         and policy['source_notices'], 'pinned source notice policy required')
    expected = {}
    for name, digest in policy['source_notices'].items():
        rel = Path(name)
        need(not rel.is_absolute() and '..' not in rel.parts and str(rel) == name
             and isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest), 'invalid source notice policy entry')
        expected[NOTICE_ROOT + '/' + name] = digest
    actual = {name: item['sha256'] for name, item in files.items() if name.startswith(NOTICE_ROOT + '/')}
    need(actual == expected and not any(name.startswith(NOTICE_ROOT + '/') for name in links),
         'staged source notices differ from pinned inventory')
    return {'status': 'PASS_QT612_DESTDIR_CONTRACT_ONLY', 'architecture': arch,
            'evidence_scope': 'HOST_X86_64_STAGE_ONLY' if arch == 'x86_64' else 'STAGED_AARCH64_ELF_ONLY',
            'files': files, 'symlinks': links, 'directories': directories, 'elf': elf,
            'payload_bytes': sum(item['bytes'] for item in files.values()),
            'native_execution': 'NOT_ESTABLISHED', 'installation': 'NOT_RUN', 'hardware': 'NOT_RUN'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--host-only-x86_64', action='store_true', help='inspect explicitly non-native host evidence')
    parser.add_argument('--license-manifest', type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(args.root, 'x86_64' if args.host_only_x86_64 else 'aarch64', args.license_manifest), sort_keys=True))
