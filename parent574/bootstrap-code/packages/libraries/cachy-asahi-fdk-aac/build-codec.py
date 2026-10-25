#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Independent native-container build from factual codec source/API inventories."""
import argparse
import contextlib
import fcntl
import hashlib
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
import threading
import shlex
import subprocess
from source_check import read_regular, sha


OBSERVER = None
COMMAND_IDENTITIES = {}


def observe(method, *args):
    if OBSERVER is not None:
        try:
            return getattr(OBSERVER, method)(*args)
        except Exception:
            pass  # Observation failures never replace an original result.


def selected_failure(message, predicate):
    error = ValueError(message)
    observe('fail', predicate, error)
    raise error


def load_observer(inputs=Path('/inputs'), output=Path('/out')):
    """Execute only checksum-bound helper bytes from readonly recipe inputs."""
    fields = {}
    for line in read_regular(inputs / '.SRCINFO', 65536).decode().splitlines():
        match = re.fullmatch(r'\s*(source|sha256sums) = (.*)', line)
        if match:
            fields.setdefault(match[1], []).append(match[2])
    names, sums = fields.get('source', []), fields.get('sha256sums', [])
    if len(names) != len(sums) or names.count('inner_observation.py') != 1:
        raise ValueError('reviewed observer checksum required')
    raw = read_regular(inputs / 'inner_observation.py', 128 * 1024)
    expected = sums[names.index('inner_observation.py')]
    if not re.fullmatch('[0-9a-f]{64}', expected) or sha(raw) != expected:
        raise ValueError('reviewed observer source changed')
    allowed = {name: sys.modules[name] for name in
        ('argparse', 'contextlib', 'fcntl', 'hashlib', 'json', 'os', 'pathlib', 're', 'stat', 'sys', 'threading')}
    def imports(name, globals=None, locals=None, fromlist=(), level=0):
        if level or name not in allowed or fromlist and not (name == 'pathlib' and tuple(fromlist) == ('Path',)):
            raise ValueError('observer stdlib import refused')
        return allowed[name]
    builtins = __builtins__ if type(__builtins__) is dict else vars(__builtins__)
    namespace = {'__name__': 'captured_fdk_observer', '__file__': str(inputs / 'inner_observation.py'),
                 '__builtins__': dict(builtins, __import__=imports)}
    exec(compile(raw, str(inputs / 'inner_observation.py'), 'exec'), namespace)
    return namespace['Recorder'](output=output, bindings=namespace['binding_values'](inputs=inputs))


def plan(source, output, layout, environment):
    """Produce commands only; no compiler invocation or directory creation."""
    source, output = Path(source).resolve(), Path(output).resolve()
    compile_commands, link_commands = [], []
    for name, lib in layout['libraries'].items():
        objects = []
        includes = ['-I' + str(source / p) for p in lib['include_dirs']]
        for path in lib['sources']:
            obj = output / 'objects' / (path + '.o')
            cxx = path.endswith('.cpp')
            compiler = shlex.split(environment.get('CXX' if cxx else 'CC', 'c++' if cxx else 'cc'))
            flags = shlex.split(environment.get('CXXFLAGS' if cxx else 'CFLAGS', '-O2'))
            flags += shlex.split(environment.get('CPPFLAGS', ''))
            if cxx:
                flags += ['-fno-exceptions', '-fno-rtti']
            compile_commands.append(compiler + flags + ['-fPIC'] + includes +
                                    ['-c', str(source / path), '-o', str(obj)])
            objects.append(str(obj))
        linker = shlex.split(environment.get('CC', 'cc'))
        flags = shlex.split(environment.get('LDFLAGS', ''))
        link_commands.append(linker + flags + ['-shared', '-Wl,--no-undefined',
                             '-Wl,-soname,' + lib['soname'],
                             '-Wl,--version-script=' + str(output / (name + '.exports'))] +
                             objects + ['-lm', '-o', str(output / lib['file'])])
    return compile_commands, link_commands


def verify_selected(source, layout):
    source = Path(source).resolve()
    for path, record in layout['selected_implementation_files'].items():
        full = source / path
        if not full.resolve().is_relative_to(source):
            selected_failure('selected implementation path escapes source', 'SELECTED_PATH')
        data = read_regular(full, 8 * 1024 * 1024)
        if len(data) != record['bytes'] or sha(data) != record['sha256']:
            selected_failure('selected implementation changed: ' + path, 'SELECTED_BYTES')
        if b'Fraunhofer' not in data or b'Redistribution and use in source and binary forms' not in data:
            selected_failure('selected implementation grant absent: ' + path, 'SELECTED_GRANT')


def run(command):
    identity = COMMAND_IDENTITIES.get(id(command))
    if identity is not None:
        observe('attempt', *identity)
    natural, code = False, None
    try:
        result = subprocess.run(command, check=True, timeout=180)
    except subprocess.CalledProcessError as error:
        code = error.returncode if type(error.returncode) is int and -64 <= error.returncode <= 255 else None
        natural = code is not None
        if identity is not None:
            if natural:
                observe('returned', *identity, code)
            else:
                observe('fail', 'COMPILER_CALL', error,
                        dict(kind=identity[0], index=identity[1], natural=False, returncode=None))
        raise
    except BaseException as error:
        if identity is not None:
            observe('fail', 'COMPILER_TIMEOUT' if isinstance(error, subprocess.TimeoutExpired) else 'COMPILER_CALL',
                    error, dict(kind=identity[0], index=identity[1], natural=False, returncode=None))
        raise
    else:
        if isinstance(result, subprocess.CompletedProcess) and type(result.returncode) is int and -64 <= result.returncode <= 255:
            if identity is not None:
                observe('returned', *identity, result.returncode)


def main():
    if os.environ.get('CACHY_ASAHI_CONTAINER') != '1' or platform.machine() != 'aarch64':
        raise SystemExit('requires the explicit native aarch64 container; no host build')
    global OBSERVER, COMMAND_IDENTITIES
    try:
        OBSERVER = load_observer()
    except Exception:
        OBSERVER = None  # Missing/unavailable diagnostics cannot authorize a build.
    try:
        observe('phase', 'BUILD')
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--source', type=Path, required=True)
        parser.add_argument('--output', type=Path, required=True)
        args = parser.parse_args()
        layout = json.loads(read_regular(Path(__file__).resolve().with_name('build-layout.json'), 1024 * 1024))
        verify_selected(args.source, layout)
        output = args.output.resolve()
        if output.is_relative_to(args.source.resolve()):
            raise SystemExit('build output must be outside implementation source')
        commands, links = plan(args.source, output, layout, os.environ)
        COMMAND_IDENTITIES = {id(command): ('COMPILE', index) for index, command in enumerate(commands)}
        COMMAND_IDENTITIES.update({id(command): ('LINK', index) for index, command in enumerate(links)})
        output.mkdir(parents=True, exist_ok=False)
        for command in commands:
            Path(command[-1]).parent.mkdir(parents=True, exist_ok=True)
        for name, lib in layout['libraries'].items():
            (output / (name + '.exports')).write_text('{\n global:\n' +
                ''.join('  ' + symbol + ';\n' for symbol in lib['exports']) + ' local: *;\n};\n')
        record = {'schema_version': 1, 'compile_commands': commands, 'link_commands': links,
                  'build_system': 'independently authored; upstream scaffold not executed',
                  'hardware_status': 'NOT RUN', 'source_publication': 'NOT RUN; selected corresponding-source bundle accompanies release'}
        (output / 'build-commands.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(run, commands))
        for command in links:
            run(command)
        for name, lib in layout['libraries'].items():
            (output / lib['soname']).symlink_to(lib['file'])
            (output / (name + '.so')).symlink_to(lib['soname'])
            pc = ('prefix=/usr\nlibdir=${prefix}/lib\nincludedir=${prefix}/include\n\n' +
                  'Name: ' + lib['pkgconfig'] + '\nDescription: FDK AAC codec library\n' +
                  'Version: 3.0.0\nLibs: -L${libdir} -l' + name.removeprefix('lib') +
                  '\nLibs.private: -lm\nCflags: -I${includedir}/' + lib['pkgconfig'] + '\n')
            (output / (lib['pkgconfig'] + '.pc')).write_text(pc)
        print('PASS: native source compilation/link; codec smoke and package checks follow')
    except BaseException as error:
        observe('fail', 'UNKNOWN', error)
        raise


if __name__ == '__main__':
    main()
