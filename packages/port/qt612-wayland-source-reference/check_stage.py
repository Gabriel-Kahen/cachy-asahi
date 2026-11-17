#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""QtWayland6.12 DESTDIR bytes only; never execute a compositor or payload.

Qtbase GUI18 owns core WaylandClient/QPA/scanner; this stage must not overlap
that component. Full QML/Quick compositor output is required, not disabled.
ELF parser below is a verbatim AST source extraction from the whole-pinned
b052 GUI18 checker, independently tested as the exact same algorithm.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import sys

PACKAGE = 'cachy-asahi-qt612-wayland-source-reference'
VERSION = '6.12.0'
ELF_ORIGIN_PIN = dict(bytes=19545, sha256='291053598bd806eed9be622f495d51725aae5f579f5f3241a83111ded254cee5')
ELF_FUNCTION_PIN = dict(bytes=6580, sha256='86ce19239b8152676d75dc1b5d07ac2c794eec9938b4f54fded818fbdadc5400')
QML_HELPER_REVISION = '4332fbbb4c340463dc8cee36dda0c85d932122d8'
QML_HELPER_PINS = {
    'src/qml/Qt6QmlBuildInternals.cmake': dict(bytes=17551, sha256='699b9035494afd822f4d95da12e2079b5d8b8064c0b64db2b453197ad403fbce'),
    'src/qml/Qt6QmlMacros.cmake': dict(bytes=258880, sha256='03db83a43d724ffa3ae3320c0e0f63af03fe2be2c97112969e488cf2072bb9e9'),
}
MODULES = ('WaylandCompositor', 'WaylandCompositorXdgShell', 'WaylandCompositorIviapplication',
           'WaylandCompositorWLShell', 'WaylandCompositorPresentationTime')
PRIVATE_MODULES = ('WaylandEglCompositorHwIntegration',)
HEADER_MODULE = 'WaylandClientFeaturesPrivate'
QML_MODULES = {
    'QtWayland.Compositor': ('qwaylandcompositorplugin', 'qwaylandcompositorplugin'),
    'QtWayland.Compositor.XdgShell': ('waylandcompositorxdgshellplugin', 'WaylandCompositorXdgShellplugin'),
    'QtWayland.Compositor.IviApplication': ('waylandcompositoriviapplicationplugin', 'WaylandCompositorIviapplicationplugin'),
    'QtWayland.Compositor.WlShell': ('waylandcompositorwlshellplugin', 'WaylandCompositorWLShellplugin'),
    'QtWayland.Compositor.QtShell': ('waylandcompositorqtshellplugin', 'WaylandCompositorQtShell'),
    'QtWayland.Compositor.PresentationTime': ('waylandcompositorpresentationtimeplugin', 'WaylandCompositorPresentationTimeplugin'),
    'QtWayland.Compositor.TextureSharingExtension': ('waylandtexturesharingextensionplugin', 'WaylandTextureSharingExtension'),
    'QtWayland.Client.TextureSharing': ('waylandtexturesharingplugin', 'WaylandTextureSharing'),
}
PLUGINS = ('wayland-shell-integration/libivi-shell.so', 'wayland-shell-integration/libqt-shell.so',
    'wayland-decoration-client/libadwaita.so',
    'wayland-graphics-integration-server/libqt-wayland-compositor-wayland-egl.so',
    'wayland-graphics-integration-server/libqt-wayland-compositor-wayland-eglstream-controller.so',
    'wayland-graphics-integration-server/libqt-wayland-compositor-linux-dmabuf-v1.so',
    'wayland-graphics-integration-server/libqt-wayland-compositor-linux-dmabuf-unstable-v1.so')
QML_SOURCE_FILES = {
    'qmlfiles/WaylandCursorItem.qml': dict(bytes=1515, sha256='eb1bb8617f40aa0b8a5f2a62a9bf954d5b07739dc4ea615b981174db815cb75a'),
    'qmlfiles/WaylandOutputWindow.qml': dict(bytes=637, sha256='9e4354c0bf9452a36832fa971da7103625b83d218eee21a807bf59e2d163de95'),
}
NOTICE_ROOT = 'usr/share/licenses/' + PACKAGE + '/source'
NOTICE_POLICY_PIN = dict(bytes=1748, sha256='c4e6a5bf9a58e79ec40c83c2394bf2bdfdef4ab172471e8abaca4b64b8c746d8')
DEPENDENCY_POLICY_PIN = dict(bytes=9460, sha256='21ac9d87755c0a4efaa37bde993566da910bba99393ae68a73f0be20bb38d01f')
DEPENDENCY_NOTICE_ROOT = 'usr/share/licenses/' + PACKAGE + '/dependencies/qtbase'
MAX_ENTRIES, MAX_FILE_BYTES, MAX_PAYLOAD_BYTES = 32768, 128 * 1024**2, 1024**3


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


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


def identity(info):
    return (info.st_dev, info.st_ino, info.st_nlink, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def ordinary(path, info, cap):
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not info.st_mode & 0o7022
         and 0 <= info.st_size <= cap, 'single-link bounded safe ordinary file required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        need(identity(os.fstat(stream.fileno())) == identity(info), 'input changed at open')
        raw = stream.read(info.st_size + 1)
        need(len(raw) == info.st_size and identity(os.fstat(stream.fileno())) == identity(info)
             and identity(path.lstat()) == identity(info), 'input changed during read')
    return raw


def below(name, root):
    return name == root or name.startswith(root + '/')


def owned(name):
    shared = {'usr', 'usr/include', 'usr/lib', 'usr/lib/cmake', 'usr/lib/pkgconfig',
              'usr/share', 'usr/share/licenses', 'usr/lib/qt6', 'usr/lib/qt6/plugins',
              'usr/lib/qt6/qml', 'usr/lib/qt6/qml/QtWayland', 'usr/lib/qt6/qml/QtWayland/Client',
              'usr/lib/qt6/mkspecs', 'usr/lib/qt6/mkspecs/modules', 'usr/lib/qt6/modules',
              'usr/lib/qt6/metatypes'}
    if name in shared or below(name, 'usr/share/licenses/' + PACKAGE):
        return True
    if any(below(name, 'usr/include/qt6/Qt'+module) for module in MODULES + PRIVATE_MODULES):
        return True
    if name == 'usr/include/qt6':
        return True
    targets = set(MODULES) | {module+'Private' for module in MODULES + PRIVATE_MODULES} | {HEADER_MODULE}
    targets |= {target for plugin, target in QML_MODULES.values()}
    targets |= {'QWaylandIviShellIntegrationPlugin', 'QWaylandQtShellIntegrationPlugin',
        'QWaylandAdwaitaDecorationPlugin', 'QWaylandEglClientBufferIntegrationPlugin',
        'QWaylandEglStreamClientBufferIntegrationPlugin', 'QWaylandDmabufClientBufferIntegrationPlugin',
        'QWaylandDmabufUnstableClientBufferIntegrationPlugin'}
    if any(below(name, 'usr/lib/cmake/Qt6'+target) for target in targets):
        return True
    if name.startswith('usr/lib/pkgconfig/'):
        return name[len('usr/lib/pkgconfig/'):] in {'Qt6'+module+'.pc' for module in MODULES}
    if name.startswith('usr/lib/libQt6'):
        return any(re.fullmatch(r'usr/lib/libQt6'+module+r'(?:\.so(?:\.6(?:\.12\.0)?)?|\.prl|\.a)', name)
                   for module in MODULES + PRIVATE_MODULES)
    for uri, (plugin, target) in QML_MODULES.items():
        directory = 'usr/lib/qt6/qml/'+uri.replace('.', '/')
        typeinfo = 'WaylandCompositor.qmltypes' if uri == 'QtWayland.Compositor' else 'plugins.qmltypes'
        if name == directory or name in {directory+'/'+member for member in ('qmldir', typeinfo, 'lib'+plugin+'.so')}:
            return True
        if uri == 'QtWayland.Compositor' and (name == directory+'/qmlfiles' or name in {directory+'/'+member for member in QML_SOURCE_FILES}):
            return True
    if name.startswith('usr/lib/qt6/plugins/'):
        rel = name[len('usr/lib/qt6/plugins/'):]
        return rel in PLUGINS or rel in {str(PurePosixPath(plugin).parent) for plugin in PLUGINS}
    if name.startswith(('usr/lib/qt6/modules/', 'usr/lib/qt6/metatypes/')):
        metadata_targets = set(MODULES + PRIVATE_MODULES) | targets
        return any(re.fullmatch(r'(?:usr/lib/qt6/modules|usr/lib/qt6/metatypes)/(?:qt6)?'+target+r'(?:_[^/]*)?\.json', name, re.IGNORECASE)
                   for target in metadata_targets)
    if name.startswith('usr/lib/qt6/mkspecs/modules/'):
        rel = name[len('usr/lib/qt6/mkspecs/modules/'):]
        return bool(re.fullmatch(r'qt_lib_wayland(?:compositor[a-z_]*|egl_compositor_hw_integration[a-z_]*|clientfeatures[a-z_]*)\.pri', rel))
    return False


def qml_contract(root, files, elf):
    result = {}
    for uri, (plugin, target) in QML_MODULES.items():
        directory = 'usr/lib/qt6/qml/' + uri.replace('.', '/')
        metadata = directory + '/qmldir'
        need(metadata in files, 'full Quick QML qmldir required: ' + uri)
        lines = (root/metadata).read_text().splitlines()
        need([line for line in lines if line.startswith('module ')] == ['module ' + uri], 'exact QML module URI required')
        declarations = [line.removeprefix('optional ') for line in lines
                        if line.startswith(('plugin ', 'optional plugin '))]
        need(declarations == ['plugin ' + plugin], 'exact source-generator QML plugin declaration required')
        typeinfos = [line.split(' ', 1)[1] for line in lines if line.startswith('typeinfo ')]
        expected_typeinfo = 'WaylandCompositor.qmltypes' if uri == 'QtWayland.Compositor' else 'plugins.qmltypes'
        need(typeinfos == [expected_typeinfo]
             and directory+'/'+typeinfos[0] in files and files[directory+'/'+typeinfos[0]]['bytes'] > 0,
             'generated QML typeinfo body required')
        library = directory + '/lib' + plugin + '.so'
        need(library in elf and elf[library]['type'] == 3, 'full Quick QML plugin ELF required: ' + uri)
        need('linktarget Qt6::'+target in lines, 'exact source-generator QML linktarget required')
        result[uri] = dict(qmldir=metadata, plugin=library, typeinfo=directory+'/'+typeinfos[0])
    directory = 'usr/lib/qt6/qml/QtWayland/Compositor/'
    for name, expected in QML_SOURCE_FILES.items():
        need(directory+name in files and {key: files[directory+name][key] for key in ('bytes', 'sha256')} == expected,
             'original full Quick source QML file required: ' + name)
    return result


def inspect(root, arch='aarch64', license_manifest=None, dependency_policy=None):
    root = Path(root)
    need(root.is_absolute() and root == root.resolve() and root != Path('/') and root.is_dir()
         and all(not path.is_symlink() for path in (root, *root.parents)), 'canonical private staging directory required')
    need(arch == 'aarch64', 'AArch64 stage architecture required')
    files, links, directories, elf, observed, total = {}, {}, {}, {}, {}, 0
    for count, path in enumerate(root.rglob('*'), 1):
        need(count <= MAX_ENTRIES, 'QtWayland stage entry cap')
        name, info = path.relative_to(root).as_posix(), path.lstat()
        observed[path] = identity(info)
        mode = stat.S_IMODE(info.st_mode)
        need(owned(name), 'outside QtWayland component ownership/no GUI18 overlap: ' + name)
        need(stat.S_ISLNK(info.st_mode) or not mode & 0o7022, 'unsafe payload mode: ' + name)
        if stat.S_ISLNK(info.st_mode):
            target = path.readlink()
            try:
                resolved = path.resolve(strict=True)
            except (OSError, RuntimeError) as error:
                raise ValueError('dangling/cyclic stage link: ' + name) from error
            need(not target.is_absolute() and resolved.is_relative_to(root), 'escaping stage link: ' + name)
            links[name] = dict(target=str(target), sha256=hashlib.sha256(str(target).encode()).hexdigest(), mode=mode)
        elif stat.S_ISDIR(info.st_mode):
            directories[name] = mode
        else:
            need(info.st_size <= MAX_FILE_BYTES and total + info.st_size <= MAX_PAYLOAD_BYTES, 'QtWayland stage byte cap')
            raw = ordinary(path, info, MAX_FILE_BYTES)
            total += len(raw)
            files[name] = dict(**pin(raw), mode=mode)
            if raw.startswith(b'\x7fELF'):
                elf[name] = elf_info(raw)
                soname = elf[name]['soname']
                if soname and soname.startswith('libQt6') and soname.endswith('.so.6'):
                    need(soname in {'libQt6'+module+'.so.6' for module in MODULES + PRIVATE_MODULES}, 'foreign Qt SONAME/GUI18 overlap refused')
    for module in MODULES + PRIVATE_MODULES:
        library = 'usr/lib/libQt6' + module
        need(library+'.so.'+VERSION in elf and elf[library+'.so.'+VERSION]['soname'] == 'libQt6'+module+'.so.6',
             'full QtWayland shared module/SONAME required: ' + module)
        for suffix, target in (('.so.6', 'libQt6'+module+'.so.'+VERSION), ('.so', 'libQt6'+module+'.so.6')):
            need(links.get(library+suffix, {}).get('target') == target, 'QtWayland shared library alias required')
        names = (('usr/include/qt6/Qt'+module+'/Qt'+module, 'usr/lib/pkgconfig/Qt6'+module+'.pc',
                  'usr/lib/cmake/Qt6'+module+'/Qt6'+module+'Config.cmake') if module in MODULES else
                 ('usr/include/qt6/Qt'+module+'/'+VERSION+'/Qt'+module+'/private/waylandeglclientbufferintegration_p.h',
                  'usr/lib/cmake/Qt6'+module+'Private/Qt6'+module+'PrivateConfig.cmake'))
        need(all(name in files for name in names), 'QtWayland module development metadata required: ' + module)
    header_config = 'usr/lib/cmake/Qt6'+HEADER_MODULE+'/Qt6'+HEADER_MODULE+'Config.cmake'
    need(header_config in files, 'header-only client features CMake package required')
    for plugin in PLUGINS:
        path = 'usr/lib/qt6/plugins/' + plugin
        need(path in elf and elf[path]['type'] == 3, 'required QtWayland client/server plugin ELF: ' + plugin)
    qml = qml_contract(root, files, elf)
    policy_path = Path(license_manifest) if license_manifest else Path(__file__).with_name('source-notices.json')
    info = policy_path.lstat()
    policy_raw = ordinary(policy_path, info, 256 * 1024)
    observed[policy_path] = identity(info)
    need(pin(policy_raw) == NOTICE_POLICY_PIN, 'exact frozen QtWayland source notice policy required')
    policy = json.loads(policy_raw)
    need(set(policy) == {'schema_version', 'source_notices'} and policy['schema_version'] == 1
         and isinstance(policy['source_notices'], dict) and policy['source_notices'], 'complete QtWayland source notices')
    expected = {}
    for name, digest in policy['source_notices'].items():
        rel = PurePosixPath(name)
        need(str(rel) == name and not rel.is_absolute() and '..' not in rel.parts
             and re.fullmatch('[0-9a-f]{64}', digest), 'canonical source notice entry required')
        expected[NOTICE_ROOT+'/'+name] = digest
    need({name: row['sha256'] for name, row in files.items() if name.startswith(NOTICE_ROOT+'/')} == expected
         and not any(name.startswith(NOTICE_ROOT+'/') for name in links), 'complete actual QtWayland source notice inventory required')
    dependency_path = Path(dependency_policy) if dependency_policy else Path(__file__).with_name('dependency-inputs.json')
    info = dependency_path.lstat()
    dependency_raw = ordinary(dependency_path, info, 256 * 1024)
    observed[dependency_path] = identity(info)
    need(pin(dependency_raw) == DEPENDENCY_POLICY_PIN, 'exact frozen Qtbase dependency notice policy required')
    dependency = json.loads(dependency_raw)
    need(dependency['schema'] == 1 and dependency['kind'] == 'QT612_WAYLAND_EXTERNAL_QTBASE_PROTOCOL_INPUTS_V1'
         and dependency['qtbase_revision'] == '025bdad181de241e81bf853c8a2d7bf3d19261a9'
         and dependency['actual_native_prefix'] is None and dependency['source_legal_acceptance'] is None
         and isinstance(dependency['files'], dict) and len(dependency['files']) == 52,
         'complete source-only external Qtbase protocol/attribution policy')
    dependency_expected = {}
    for name, row in dependency['files'].items():
        rel = PurePosixPath(name)
        need(str(rel) == name and not rel.is_absolute() and '..' not in rel.parts
             and name.startswith('share/qt6/wayland/') and set(row) == {'bytes', 'sha256'}
             and type(row['bytes']) is int and 0 < row['bytes'] <= MAX_FILE_BYTES
             and re.fullmatch('[0-9a-f]{64}', row['sha256']), 'canonical Qtbase dependency notice descriptor')
        dependency_expected[DEPENDENCY_NOTICE_ROOT+'/'+name] = row
    dependency_actual = {name: {key: row[key] for key in ('bytes', 'sha256')} for name, row in files.items()
                         if name.startswith(DEPENDENCY_NOTICE_ROOT+'/')}
    need(dependency_actual == dependency_expected
         and not any(name.startswith(DEPENDENCY_NOTICE_ROOT+'/') for name in links),
         'complete actual Qtbase dependency protocol/attribution/license bytes required')
    providers = {}
    for name, row in elf.items():
        if row['soname']:
            providers.setdefault(row['soname'], []).append(name)
    for row in elf.values():
        row['version_provider_observations'] = []
        for requirement in row['version_needs'] or []:
            observations = []
            for provider in sorted(providers.get(requirement['file'], [])):
                definitions = elf[provider]['version_definitions']
                names = None if definitions is None else sorted({name for definition in definitions for name in definition['names']})
                observations.append(dict(staged_path=provider, observed_definition_names=names))
            row['version_provider_observations'].append(dict(file=requirement['file'],
                required_names=[version['name'] for version in requirement['versions']],
                staged_providers=observations, runtime_resolution=None))
        row['needed_providers'] = {name: dict(staged_paths=sorted(providers.get(name, [])),
            availability='STAGED_BYTES_ONLY' if name in providers else 'UNAVAILABLE_IN_STAGE', runtime_resolution=None)
            for name in row['needed']}
    for path, before in observed.items():
        need(identity(path.lstat()) == before, 'stage input changed after inspection')
    return dict(status='PASS_QT612_WAYLAND_DESTDIR_CONTRACT_ONLY', architecture=arch,
        evidence_scope='STAGED_AARCH64_ELF_16K_GEOMETRY_ONLY', files=files, symlinks=links,
        directories=directories, elf=elf, qml=qml, payload_bytes=total,
        license_policy_pin=NOTICE_POLICY_PIN, native_execution='NOT_ESTABLISHED',
        dependency_policy_pin=DEPENDENCY_POLICY_PIN, dependency_notice_files=len(dependency_expected),
        dependency_notice_bytes=sum(row['bytes'] for row in dependency_actual.values()),
        dependency_feature_gate='HELD_GUI18_WAYLAND_SERVER_OFF_NO_FEATURE_WAIVER',
        installation='NOT_ESTABLISHED', hardware='NOT_ESTABLISHED', provider_transaction=None, native_acceptance=None)


def no_actors(event, args):
    need(not event.startswith(('subprocess.', 'socket.', 'ctypes.'))
         and event not in ('os.system', 'os.exec', 'os.fork', 'os.forkpty', 'os.posix_spawn'), 'STAGE_ONLY_NO_ACTORS')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--license-manifest', type=Path)
    parser.add_argument('--dependency-policy', type=Path)
    args = parser.parse_args()
    sys.addaudithook(no_actors)
    print(json.dumps(inspect(args.root, license_manifest=args.license_manifest,
                             dependency_policy=args.dependency_policy), sort_keys=True))
