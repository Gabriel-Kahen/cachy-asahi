#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Configure one original local C project for Make or Ninja; execute no process.

Build tools interpret only these fixed recipes. Ninja uses its intrinsic shell;
compiler arguments are quoted for the shell, then escaped for the build syntax.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex

FLAGS = '-Wall -Wextra -Werror -O2'


def command_path(value):
    if not value or any(c in value for c in '\x00\n\r'):
        raise ValueError('compiler path contains an unsupported control character')
    path = Path(value)
    if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError('absolute existing executable compiler path required')
    # Both backends consume dollar escapes before the shell sees its quotes.
    return shlex.quote(value).replace('$', '$$')


def graph(backend, compiler):
    cc = command_path(compiler)
    compile_command = f'{cc} {FLAGS} -c hello.c -o build/hello.o'
    link_command = f'{cc} build/hello.o -o build/hello'
    test_command = './build/hello --self-test'
    if backend == 'make':
        return ('# SPDX-License-Identifier: MIT\n'
                'SHELL := /bin/sh\n.SUFFIXES:\n.DELETE_ON_ERROR:\n'
                '.PHONY: all test\nall: build/hello\n'
                'build/hello.o: hello.c\n\t' + compile_command + '\n'
                'build/hello: build/hello.o\n\t' + link_command + '\n'
                'test: build/hello\n\t' + test_command + '\n')
    if backend == 'ninja':
        return ('# SPDX-License-Identifier: MIT\n'
                'rule compile\n  command = ' + compile_command + '\n'
                'rule link\n  command = ' + link_command + '\n'
                'rule self_test\n  command = ' + test_command + '\n'
                'build build/hello.o: compile hello.c\n'
                'build build/hello: link build/hello.o\n'
                'build all: phony build/hello\n'
                'build always: phony\n'
                'build test: self_test build/hello | always\n'
                'default all\n')
    raise ValueError('unsupported backend')


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backend', required=True, choices=('make', 'ninja'))
    parser.add_argument('--cc', required=True)
    args = parser.parse_args()
    try:
        raw = graph(args.backend, args.cc).encode()
    except ValueError as error:
        parser.error(str(error))
    if not Path('hello.c').is_file():
        parser.error('run in the private project containing hello.c')
    Path('build').mkdir(exist_ok=True)
    name = 'Makefile' if args.backend == 'make' else 'build.ninja'
    Path(name).write_bytes(raw)
    result = dict(backend=args.backend, compiler=args.cc, graph=name, graph_pin=pin(raw),
                  source=pin(Path('hello.c').read_bytes()),
                  configure=pin(Path(__file__).read_bytes()),
                  recipe_scope='FIXED_ORIGINAL_PROJECT_BUILD_SYSTEM_RECIPES')
    Path('configuration.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
