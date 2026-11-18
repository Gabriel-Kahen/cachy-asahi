#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Finite configuration/shader byte envelopes; no compiler, loader or authority."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

COMPONENTS = {'gui_server', 'shadertools', 'svg', 'declarative', 'wayland'}
MAX_BYTES, MAX_FILES, MAX_JSON = 64*1024**2, 256, 96*1024**2
SHADER_FILES = {'qsb-version.txt'} | {stage+'.'+ext for stage in ('vertex', 'fragment')
                                      for ext in ('qsb', 'json', 'spv', 'glsl', 'hlsl', 'msl')}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+'\n').encode()


def decode(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_JSON, 'FINITE_PROOF_JSON')
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'DUPLICATE_PROOF_JSON_KEY')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'NONFINITE_PROOF_JSON'))


def member(name):
    need(type(name) is str and 0 < len(name) <= 512 and not name.startswith('/')
         and all(re.fullmatch('[A-Za-z0-9_+.-]+', part) and part not in ('.', '..')
                 for part in name.split('/')), 'CANONICAL_PROOF_MEMBER')
    return name


def identity(info):
    return tuple(getattr(info, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid',
        'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def ordinary(path):
    path = Path(path).absolute()
    need('..' not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)), 'ORDINARY_PROOF_PATH')
    return path


def read(path, cap=MAX_BYTES):
    path = ordinary(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and not before.st_mode & 0o022
             and before.st_uid in (0, os.geteuid()) and 0 <= before.st_size <= cap, 'BOUNDED_ORDINARY_PROOF_FILE')
        parts, size = [], 0
        while block := os.read(fd, min(1024**2, before.st_size+1-size)):
            size += len(block)
            need(size <= before.st_size, 'PROOF_FILE_GREW')
            parts.append(block)
        need(size == before.st_size and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()),
             'STABLE_WHOLE_PROOF_FILE')
        return b''.join(parts), identity(before)
    finally:
        os.close(fd)


def build_files(component, contract):
    need(component in COMPONENTS and type(contract) is dict, 'KNOWN_FAMILY_PROOF_COMPONENT')
    names = {'CMakeCache.txt'}
    if component == 'gui_server':
        names |= {'lib/cmake/Qt6Gui/Qt6GuiTargets.cmake', 'src/gui/qtgui-config_p.h'}
    elif component == 'shadertools':
        names.add('build.ninja')
        names |= {'lib/cmake/'+name+'/'+name+'Config.cmake' for name in (
            'Qt6ShaderTools', 'Qt6ShaderToolsPrivate', 'Qt6ShaderToolsTools')}
    elif component == 'declarative':
        for key in ('required_shared_modules', 'required_cmake_packages', 'required_cmake_helpers'):
            need(type(contract.get(key)) is list and len(contract[key]) <= MAX_FILES, 'FINITE_DECLARATIVE_PROOF_CONTRACT')
        names |= {'lib/cmake/Qt6'+name+'/Qt6'+name+'Config.cmake' for name in contract['required_shared_modules']}
        names |= {'lib/cmake/'+name+'/'+name+'Config.cmake' for name in contract['required_cmake_packages']}
        names |= {'lib/cmake/'+name for name in contract['required_cmake_helpers']}
    elif component == 'wayland':
        names.add('build.ninja')
    need(0 < len(names) <= MAX_FILES, 'FINITE_BUILD_PROOF_FILES')
    return {member(name) for name in names}


def expected_files(component, contract):
    names = {'build/'+name for name in build_files(component, contract)}
    if component == 'shadertools':
        names |= {'shader/'+name for name in SHADER_FILES}
    need(len(names) <= MAX_FILES, 'FINITE_COMPLETE_PROOF_FILES')
    return names


def capture(*, component, build, contract, shader_output=None):
    """Capture only each pinned helper's necessary inputs, with whole byte pins."""
    build = ordinary(build)
    need(build.is_dir() and build != Path('/'), 'PRIVATE_BUILD_PROOF_ROOT')
    if not isinstance(contract, dict):
        contract = decode(read(contract, 4*1024**2)[0])
    inputs = {'build/'+name: build/name for name in build_files(component, contract)}
    if component == 'shadertools':
        need(shader_output is not None, 'COMPLETE_SHADER_OUTPUT_REQUIRED')
        shader = ordinary(shader_output)
        need(shader.is_dir() and {p.name for p in shader.iterdir()} == SHADER_FILES, 'EXACT_SHADER_OUTPUT_NAMESPACE')
        inputs.update({'shader/'+name: shader/name for name in SHADER_FILES})
    else:
        need(shader_output is None, 'NO_FOREIGN_SHADER_OUTPUT')
    files, observed, total = {}, {}, 0
    for name, path in sorted(inputs.items()):
        raw, before = read(path)
        total += len(raw)
        need(total <= MAX_BYTES, 'COMPLETE_PROOF_TOTAL_BYTE_CAP')
        observed[path] = before
        files[name] = dict(pin(raw), base64=base64.b64encode(raw).decode('ascii'))
    need(all(identity(path.lstat()) == before for path, before in observed.items()), 'PROOF_OPERAND_CHANGED_AFTER_READ')
    result = dict(schema=1, kind='QT612_FAMILY_BUILD_PROOF_V1', component=component, files=files)
    need(len(encoded(result)) <= MAX_JSON, 'COMPLETE_PROOF_JSON_CAP')
    return result


def validate(value, *, component, contract):
    need(type(value) is dict and set(value) == {'schema', 'kind', 'component', 'files'}
         and type(value['schema']) is int and value['schema'] == 1
         and value['kind'] == 'QT612_FAMILY_BUILD_PROOF_V1' and value['component'] == component,
         'EXACT_BUILD_PROOF_ENVELOPE')
    need(type(value['files']) is dict and set(value['files']) == expected_files(component, contract),
         'EXACT_REQUIRED_BUILD_PROOF_NAMESPACE')
    result, total = {}, 0
    for name, row in value['files'].items():
        member(name)
        need(type(row) is dict and set(row) == {'bytes', 'sha256', 'base64'} and type(row['bytes']) is int
             and 0 <= row['bytes'] <= MAX_BYTES and type(row['sha256']) is str
             and re.fullmatch('[0-9a-f]{64}', row['sha256']) and type(row['base64']) is str
             and len(row['base64']) <= 4*((row['bytes']+2)//3), 'FINITE_WHOLE_PROOF_DESCRIPTOR')
        try:
            raw = base64.b64decode(row['base64'], validate=True)
        except (ValueError, UnicodeError):
            raise ValueError('CANONICAL_PROOF_BASE64') from None
        need(base64.b64encode(raw).decode('ascii') == row['base64']
             and pin(raw) == {k: row[k] for k in ('bytes', 'sha256')}, 'CURRENT_WHOLE_BUILD_PROOF_PIN')
        total += len(raw)
        need(total <= MAX_BYTES, 'COMPLETE_PROOF_TOTAL_BYTE_CAP')
        result[name] = raw
    return result


def unpack(value, *, component, contract, output):
    """Write verified passive bytes into a fresh ordinary private tree."""
    rows = validate(value, component=component, contract=contract)
    output = ordinary(output)
    need(not output.exists() and output.parent.is_dir(), 'FRESH_PROOF_READBACK_ROOT')
    os.mkdir(output, 0o700)
    root = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name, raw in sorted(rows.items()):
            parts = name.split('/')
            fd = os.dup(root)
            try:
                for part in parts[:-1]:
                    try:
                        os.mkdir(part, 0o700, dir_fd=fd)
                    except FileExistsError:
                        pass
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    os.close(fd)
                    fd = child
                leaf = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=fd)
                with os.fdopen(leaf, 'wb') as stream:
                    os.fchmod(stream.fileno(), 0o644)
                    stream.write(raw)
            finally:
                os.close(fd)
    finally:
        os.close(root)
    for name, expected in value['files'].items():
        raw, _ = read(output/name)
        need(pin(raw) == {k: expected[k] for k in ('bytes', 'sha256')}, 'WHOLE_PRIVATE_PROOF_READBACK')
    return output


def no_actors(event, args):
    need(not event.startswith(('subprocess.', 'socket.', 'ctypes.')) and event not in (
        'os.system', 'os.exec', 'os.fork', 'os.forkpty', 'os.posix_spawn'), 'PASSIVE_BUILD_PROOF_NO_ACTORS')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('capture',))
    parser.add_argument('--component', choices=sorted(COMPONENTS), required=True)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--contract', type=Path, required=True)
    parser.add_argument('--shader-output', type=Path)
    args = parser.parse_args()
    sys.addaudithook(no_actors)
    print(encoded(capture(component=args.component, build=args.build, contract=args.contract,
                          shader_output=args.shader_output)).decode(), end='')
