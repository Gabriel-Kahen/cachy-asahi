#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Independent native-container build from factual codec source/API inventories."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import platform
import shlex
import subprocess
from source_check import read_regular, sha


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
            raise ValueError('selected implementation path escapes source')
        data = read_regular(full, 8 * 1024 * 1024)
        if len(data) != record['bytes'] or sha(data) != record['sha256']:
            raise ValueError('selected implementation changed: ' + path)
        if b'Fraunhofer' not in data or b'Redistribution and use in source and binary forms' not in data:
            raise ValueError('selected implementation grant absent: ' + path)


def run(command):
    subprocess.run(command, check=True, timeout=180)


def main():
    if os.environ.get('CACHY_ASAHI_CONTAINER') != '1' or platform.machine() != 'aarch64':
        raise SystemExit('requires the explicit native aarch64 container; no host build')
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


if __name__ == '__main__':
    main()
