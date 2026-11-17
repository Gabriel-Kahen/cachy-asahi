#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read private GUI Qt DESTDIR bytes; never execute or install payloads.

Extends base checker SHA597e2874df52be41a02896abae57fc7ef16975e5f6e858cc9705c5d637dbe5a6.
Qt6.12 source: INTERNAL_MODULE targets use Private CMake package names, while
QtModuleHelpers strips Private from library and header interface names. Private
headers below are declared by the four module CMakeLists. Plugin filenames are
OUTPUT_NAME plus PLUGIN_TYPE from qtbase src/plugins/platforms/eglfs and wayland.
All ELF metadata and 16K geometry are byte observations, never native acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys

PACKAGE = 'cachy-asahi-qt612-gui-source-reference'
VERSION = '6.12.0'
MODULES = ('Core', 'Concurrent', 'DBus', 'Gui', 'Network', 'OpenGL',
           'OpenGLWidgets', 'PrintSupport', 'Sql', 'Test', 'Widgets', 'Xml', 'WaylandClient')
PRIVATE_MODULES = ('XcbQpa', 'EglFSDeviceIntegration', 'EglFsKmsGbmSupport',
                   'EglFsKmsSupport', 'WlShellIntegration')
PRIVATE_HEADERS = dict(EglFSDeviceIntegration='qeglfsdeviceintegration_p.h',
    EglFsKmsGbmSupport='qeglfskmsgbmintegration_p.h', EglFsKmsSupport='qeglfskmsintegration_p.h',
    WlShellIntegration='qwaylandwlshellintegration_p.h')
TOOLS = ('usr/lib/qt6/bin/qmake', 'usr/lib/qt6/moc', 'usr/lib/qt6/uic', 'usr/lib/qt6/rcc', 'usr/lib/qt6/qtwaylandscanner')
PLUGINS = ('platforms/libqoffscreen.so', 'platforms/libqxcb.so', 'sqldrivers/libqsqlite.so',
           'platforms/libqeglfs.so', 'platforms/libqwayland.so', 'platforms/libqminimalegl.so',
           'wayland-decoration-client/libbradient.so',
           'egldeviceintegrations/libqeglfs-emu-integration.so',
           'egldeviceintegrations/libqeglfs-kms-integration.so',
           'wayland-shell-integration/libwl-shell-plugin.so',
           'wayland-shell-integration/libxdg-shell.so',
           'wayland-graphics-integration-client/libqt-plugin-wayland-egl.so')
NOTICE_ROOT = f'usr/share/licenses/{PACKAGE}/source'
NOTICE_POLICY_PIN = dict(bytes=20042, sha256='3651e4bca7846caee61183c2bc55bf4988c6f4f2a56af81f3948afe03d41cfda')
MAX_ENTRIES, MAX_FILE_BYTES, MAX_PAYLOAD_BYTES = 32768, 128 * 1024**2, 1024**3


def need(condition, message):
    if not condition:
        raise ValueError(message)


def elf_info(body, machine=183):
    """Bounded ELF64 byte parser; no loader, readelf, or external providers."""
    need(len(body) >= 64 and body[:7] == b'\x7fELF\x02\x01\x01', 'ELF64 little-endian required')
    kind, actual, version = struct.unpack_from('<HHI', body, 16)
    need(machine == actual == 183 and kind in (2, 3) and version == 1, 'ELF AArch64 architecture/type/version mismatch')
    phoff = struct.unpack_from('<Q', body, 32)[0]
    ehsize, phentsize, phnum = struct.unpack_from('<HHH', body, 52)
    need(ehsize == 64 and phentsize == 56 and 0 < phnum < 1024
         and phoff >= 64 and phoff + phentsize * phnum <= len(body), 'ELF program headers malformed')
    segments = [struct.unpack_from('<IIQQQQQQ', body, phoff + n * phentsize) for n in range(phnum)]
    interpreters = [s for s in segments if s[0] == 3]
    need(len(interpreters) <= 1, 'ELF duplicate interpreter segment')
    interpreter = None
    if interpreters:
        segment = interpreters[0]
        need(1 < segment[5] <= 4096 and segment[2] + segment[5] <= len(body),
             'ELF bounded interpreter segment required')
        raw = body[segment[2]:segment[2] + segment[5]]
        need(raw[-1:] == b'\0' and b'\0' not in raw[:-1]
             and all(32 < c < 127 for c in raw[:-1]), 'ELF interpreter string malformed')
        interpreter = raw[:-1].decode('ascii')
    loads = [s for s in segments if s[0] == 1]
    need(loads, 'ELF load segments required')
    for segment in segments:
        need(segment[2] + segment[5] <= len(body), 'ELF segment outside file')
    for s in loads:
        need(s[5] <= s[6] and s[3] + s[6] < 2**64
             and s[7] >= 16384 and not s[7] & (s[7] - 1)
             and s[2] % s[7] == s[3] % s[7], 'ELF 16K load geometry required')

    def offset(address, size):
        matches = [s for s in loads if s[3] <= address and address + size <= s[3] + s[5]]
        need(size > 0 and len(matches) == 1, 'ELF metadata outside unique file-backed load segment')
        return matches[0][2] + address - matches[0][3]

    dynamic = [s for s in segments if s[0] == 2]
    need(len(dynamic) <= 1, 'ELF duplicate dynamic segment')
    tags, needed_offsets = {}, []
    if dynamic:
        segment = dynamic[0]
        need(segment[5] and segment[5] % 16 == 0 and segment[5] // 16 <= 65536,
             'ELF dynamic segment malformed')
        need(offset(segment[3], segment[5]) == segment[2], 'ELF dynamic segment load mapping mismatch')
        terminated = False
        for start in range(segment[2], segment[2] + segment[5], 16):
            tag, value = struct.unpack_from('<qQ', body, start)
            if tag == 0:
                terminated = True
                break
            if tag == 1:
                needed_offsets.append(value)
            else:
                if tag in (5, 10, 14, 0x6ffffffc, 0x6ffffffd, 0x6ffffffe, 0x6fffffff):
                    need(tag not in tags, 'ELF duplicate dynamic metadata tag')
                tags[tag] = value
        need(terminated, 'ELF dynamic segment unterminated')
    uses_strings = needed_offsets or any(t in tags for t in (14, 0x6ffffffc, 0x6ffffffe))
    table, table_bytes = 0, 0
    if uses_strings:
        need(5 in tags and 10 in tags and 0 < tags[10] <= len(body), 'ELF dynamic string table missing')
        table_bytes = tags[10]
        table = offset(tags[5], table_bytes)

    def text(index):
        need(0 <= index < table_bytes, 'ELF dynamic string outside table')
        end = body.find(b'\0', table + index, table + table_bytes)
        need(end > table + index, 'ELF dynamic string unterminated/empty')
        raw = body[table + index:end]
        need(all(32 < c < 127 for c in raw) and b'/' not in raw, 'ELF metadata string must be printable basename')
        return raw.decode('ascii')

    def versions(address_tag, count_tag, definitions):
        need((address_tag in tags) == (count_tag in tags), 'ELF GNU version table/count pair required')
        if address_tag not in tags:
            return None
        count = tags[count_tag]
        need(0 < count <= 4096, 'ELF GNU version count bound')
        address, result, visited, total_aux = tags[address_tag], [], set(), 0
        for number in range(count):
            need(address not in visited, 'ELF GNU version chain cycle')
            visited.add(address)
            start = offset(address, 20 if definitions else 16)
            if definitions:
                version, flags, index, aux_count, digest, aux, next_entry = struct.unpack_from('<HHHHIII', body, start)
                row = dict(flags=flags, index=index, hash=digest, names=[])
            else:
                version, aux_count, filename, aux, next_entry = struct.unpack_from('<HHIII', body, start)
                row = dict(file=text(filename), versions=[])
            need(version == 1 and 0 < aux_count <= 4096 and aux > 0, 'ELF GNU version record malformed')
            total_aux += aux_count
            need(total_aux <= 65536, 'ELF GNU total auxiliary bound')
            aux_address, aux_seen = address + aux, set()
            for auxiliary in range(aux_count):
                need(aux_address not in aux_seen, 'ELF GNU version auxiliary cycle')
                aux_seen.add(aux_address)
                start = offset(aux_address, 8 if definitions else 16)
                if definitions:
                    name, next_aux = struct.unpack_from('<II', body, start)
                    row['names'].append(text(name))
                else:
                    digest, flags, other, name, next_aux = struct.unpack_from('<IHHII', body, start)
                    row['versions'].append(dict(name=text(name), hash=digest, flags=flags, other=other))
                need(bool(next_aux) == (auxiliary + 1 < aux_count), 'ELF GNU auxiliary chain count mismatch')
                aux_address += next_aux
            result.append(row)
            need(bool(next_entry) == (number + 1 < count), 'ELF GNU version chain count mismatch')
            address += next_entry
        return result

    return dict(type=kind, machine=actual, interpreter=interpreter, soname=text(tags[14]) if 14 in tags else None,
        needed=[text(index) for index in needed_offsets],
        version_needs=versions(0x6ffffffe, 0x6fffffff, False),
        version_definitions=versions(0x6ffffffc, 0x6ffffffd, True),
        load_segments=[dict(offset=s[2], virtual_address=s[3], file_bytes=s[5], memory_bytes=s[6], alignment=s[7]) for s in loads],
        geometry_16k=True, metadata_scope='ELF_BYTES_ONLY_NO_NATIVE_OR_PROVIDER_ACCEPTANCE')


def file_identity(info):
    return (info.st_dev, info.st_ino, info.st_nlink, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def regular_bytes(path, info, limit):
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not info.st_mode & 0o7022
         and info.st_size <= limit, 'single-link safe bounded ordinary file required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        need(file_identity(os.fstat(stream.fileno())) == file_identity(info), 'stage input changed at open')
        body = stream.read(info.st_size + 1)
        need(len(body) == info.st_size and file_identity(os.fstat(stream.fileno())) == file_identity(info),
             'stage input changed during read')
    need(file_identity(path.lstat()) == file_identity(info), 'stage input path changed')
    return body


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
    need(arch == 'aarch64', 'AArch64 stage architecture required')
    machine = 183
    files, links, directories, elf = {}, {}, {}, {}
    total_bytes, observed = 0, {}
    for count, path in enumerate(root.rglob('*'), 1):
        need(count <= MAX_ENTRIES, 'Qt stage entry limit exceeded')
        name = path.relative_to(root).as_posix()
        info = path.lstat()
        mode = stat.S_IMODE(info.st_mode)
        observed[path] = file_identity(info)
        need(owned(name), f'outside Qt package ownership: {name}')
        module_path = re.fullmatch(r'usr/lib/libQt6(.+)\.so\.6\.12\.0', name)
        need(module_path is None or module_path[1] in MODULES + PRIVATE_MODULES,
             f'outside exact18 Qt shared library profile: {name}')
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
            body = regular_bytes(path, info, MAX_FILE_BYTES)
            total_bytes += len(body)
            files[name] = {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(), 'mode': mode}
            if body.startswith(b'\x7fELF'):
                elf[name] = elf_info(body, machine)
                module_soname = re.fullmatch(r'libQt6(.+)\.so\.6', elf[name]['soname'] or '')
                need(module_soname is None or module_soname[1] in MODULES + PRIVATE_MODULES,
                     f'outside exact18 Qt shared SONAME profile: {name}')
    for module in MODULES + PRIVATE_MODULES:
        library = f'usr/lib/libQt6{module}.so.{VERSION}'
        need(library in elf and elf[library]['type'] == 3
             and elf[library]['soname'] == f'libQt6{module}.so.6', f'Qt {module} shared library/SONAME required')
        for suffix, target in (('.so.6', f'libQt6{module}.so.{VERSION}'), ('.so', f'libQt6{module}.so.6')):
            need(links.get(f'usr/lib/libQt6{module}{suffix}', {}).get('target') == target,
                 f'Qt {module} library link required: {suffix}')
        if module in PRIVATE_MODULES:
            if module in PRIVATE_HEADERS:
                for name in (f'usr/include/qt6/Qt{module}/{VERSION}/Qt{module}/private/{PRIVATE_HEADERS[module]}',
                             f'usr/lib/cmake/Qt6{module}Private/Qt6{module}PrivateConfig.cmake'):
                    need(name in files, f'Qt private module development file required: {name}')
            continue
        required = (f'usr/include/qt6/Qt{module}/Qt{module}',
                    f'usr/lib/pkgconfig/Qt6{module}.pc',
                    f'usr/lib/cmake/Qt6{module}/Qt6{module}Config.cmake')
        for name in required:
            need(name in files, f'Qt module development file required: {name}')
    for name in TOOLS + tuple('usr/lib/qt6/plugins/' + plugin for plugin in PLUGINS):
        need(name in elf and files[name]['mode'] & 0o111, f'Qt executable/plugin required: {name}')
        if name.startswith('usr/lib/qt6/plugins/'):
            need(elf[name]['type'] == 3, f'Qt shared-object plugin required: {name}')
    header = 'usr/include/qt6/QtCore/qtcoreversion.h'
    need(header in files and re.search(r'^#define\s+QTCORE_VERSION_STR\s+"6\.12\.0"\s*$',
                                      (root / header).read_text(), re.MULTILINE), 'QtCore 6.12.0 version header required')
    for name in files.keys() | links.keys():
        if name.startswith(tuple('usr/lib/qt6/plugins/' + group + '/' for group in (
                'egldeviceintegrations', 'wayland-shell-integration', 'wayland-graphics-integration-client',
                'wayland-decoration-client'))):
            need(name in {'usr/lib/qt6/plugins/' + plugin for plugin in PLUGINS},
                 f'disabled GUI plugin profile: {name}')
        if name.startswith('usr/lib/qt6/plugins/sqldrivers/'):
            need(name == 'usr/lib/qt6/plugins/sqldrivers/libqsqlite.so', 'SQLite-only SQL plugin profile required')
        need(not name.startswith(tuple('usr/lib/qt6/plugins/' + suffix for suffix in (
            'platforms/libqlinuxfb', 'platforms/libqvkkhrdisplay',
            'platforms/libqdirectfb', 'platforms/libqvnc', 'platformthemes/libqgtk3'))),
            f'disabled platform plugin present: {name}')
    policy_path = Path(license_manifest) if license_manifest else Path(__file__).with_name('source-notices.json')
    policy_info = policy_path.lstat()
    policy_raw = regular_bytes(policy_path, policy_info, 256 * 1024)
    observed[policy_path] = file_identity(policy_info)
    policy_pin = dict(bytes=len(policy_raw), sha256=hashlib.sha256(policy_raw).hexdigest())
    need(policy_pin == NOTICE_POLICY_PIN, 'exact pinned173 source notice policy bytes required')
    policy = json.loads(policy_raw)
    need(policy.get('schema_version') == 1 and isinstance(policy.get('source_notices'), dict)
         and len(policy['source_notices']) == 173, 'complete173 source notice policy required')
    expected = {}
    for name, digest in policy['source_notices'].items():
        rel = Path(name)
        need(not rel.is_absolute() and '..' not in rel.parts and str(rel) == name
             and isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest), 'invalid source notice policy entry')
        expected[NOTICE_ROOT + '/' + name] = digest
    actual = {name: item['sha256'] for name, item in files.items() if name.startswith(NOTICE_ROOT + '/')}
    need(actual == expected and not any(name.startswith(NOTICE_ROOT + '/') for name in links),
         'staged source notices differ from pinned inventory')
    providers = {}
    for name, info in elf.items():
        if info['soname'] is not None:
            providers.setdefault(info['soname'], []).append(name)
    for info in elf.values():
        info['version_provider_observations'] = []
        for requirement in info['version_needs'] or []:
            observations = []
            for provider in sorted(providers.get(requirement['file'], [])):
                definitions = elf[provider]['version_definitions']
                names = None if definitions is None else sorted({name for row in definitions for name in row['names']})
                observations.append(dict(staged_path=provider, observed_definition_names=names))
            info['version_provider_observations'].append(dict(file=requirement['file'],
                required_names=[row['name'] for row in requirement['versions']],
                staged_providers=observations, runtime_resolution=None))
        info['needed_providers'] = {name: dict(staged_paths=sorted(providers.get(name, [])),
            availability='STAGED_BYTES_ONLY' if name in providers else 'UNAVAILABLE_IN_STAGE',
            runtime_resolution=None) for name in info['needed']}
    for path, before in observed.items():
        need(file_identity(path.lstat()) == before, 'stage input changed after read')
    return {'status': 'PASS_QT612_GUI_DESTDIR_CONTRACT_ONLY', 'architecture': arch,
            'evidence_scope': 'STAGED_AARCH64_ELF_16K_GEOMETRY_ONLY',
            'files': files, 'symlinks': links, 'directories': directories, 'elf': elf,
            'payload_bytes': sum(item['bytes'] for item in files.values()),
            'license_policy_pin': policy_pin,
            'native_execution': 'NOT_ESTABLISHED', 'installation': 'NOT_ESTABLISHED',
            'hardware': 'NOT_ESTABLISHED', 'provider_transaction': None, 'native_acceptance': None}


def no_actors(event, args):
    need(not event.startswith(('subprocess.', 'socket.', 'ctypes.'))
         and event not in ('os.system', 'os.exec', 'os.fork', 'os.forkpty', 'os.posix_spawn'), 'STAGE_ONLY_NO_ACTORS')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--license-manifest', type=Path)
    args = parser.parse_args()
    sys.addaudithook(no_actors)
    print(json.dumps(inspect(args.root, license_manifest=args.license_manifest), sort_keys=True))
