#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check exact Apps10 sources and execute its unchanged disposable package tests."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import time

HERE = Path(__file__).absolute().parent


def pin(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('ordinary single-link input required: ' + str(path))
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repository-source', type=Path, required=True)
    p.add_argument('--recipe-root', type=Path)
    p.add_argument('--expected-source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    source = a.repository_source.absolute()
    recipe = (a.recipe_root or source/'packages/tools/cachy-asahi-apps10').absolute()
    output = a.output.absolute()
    if any(q.is_symlink() for path in (source, recipe, output) for q in (path, *path.parents)):
        raise ValueError('symlinked source/output ancestry')
    if output.exists() or not output.parent.is_dir() or any(
            output == q or output in q.parents or q in output.parents for q in (source, recipe)):
        raise ValueError('fresh disjoint output under ordinary existing parent required')
    profile = json.loads((HERE/'profile.json').read_bytes())
    prefix = 'packages/tools/cachy-asahi-apps10/'
    expected = {n.removeprefix(prefix): v for n, v in profile['recipe'].items()}
    if {p.name for p in recipe.iterdir()} != set(expected):
        raise ValueError('exact seventeen recipe leaves required')
    for name, value in expected.items():
        if pin(recipe/name) != value:
            raise ValueError('recipe differs: ' + name)
    for name, value in profile['held'].items():
        if pin(source/name) != value:
            raise ValueError('held canonical input differs: ' + name)
    expected_source = a.expected_source.absolute()
    if any(p.is_symlink() for p in (expected_source, *expected_source.parents)) or any(p.is_symlink() for p in expected_source.rglob('*')):
        raise ValueError('ordinary exact public recipe fixture required')
    actual = {p.relative_to(expected_source).as_posix(): pin(p) for p in expected_source.rglob('*')
              if p.is_file() and '.git' not in p.relative_to(expected_source).parts}
    if actual != profile['source_files'] or len(actual) != 42:
        raise ValueError('whole exact published recipe42 required')
    spec = importlib.util.spec_from_file_location('package_checks', source/'scripts/checks/package_checks.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    report = module.recipe(recipe/'PKGBUILD')
    if report['errors'] or report['status'] != 'static-pass':
        raise ValueError('canonical recipe inspector refused: ' + repr(report))
    output.mkdir(mode=0o700)
    (output/'recipe-check.json').write_text(json.dumps(report, indent=2, sort_keys=True)+'\n')
    src = output/'makepkg-src'
    src.mkdir(mode=0o700)
    text = (recipe/'PKGBUILD').read_text()
    names = shlex.split(re.search(r'^source=\((.*?)\)', text, re.M|re.S)[1])
    for name in names:
        (src/name).symlink_to(recipe/name)
    # Exercise the complete actual check() body with makepkg-style local-source
    # links. It stages private regular files before the unchanged45 plus8 inventory and8 stage tests.
    tools = output/'bin'
    tools.mkdir()
    (tools/'python').symlink_to(sys.executable)
    env = dict(os.environ, PATH=str(tools)+':'+os.environ['PATH'], PYTHONDONTWRITEBYTECODE='1',
               srcdir=str(src), startdir=str(recipe),
               CACHY_ASAHI_REPOSITORY_SOURCE=str(source),
               CACHY_ASAHI_RUNTIME_RECIPE=str(source/'packages/tools/cachy-asahi-repository-runtime'))
    started = time.monotonic()
    with (output/'check.stdout').open('wb') as out, (output/'check.stderr').open('wb') as err:
        subprocess.run(['/bin/bash', '--noprofile', '--norc', '-c',
                        'set -euo pipefail; source "$1"; check', 'apps10-check', str(recipe/'PKGBUILD')],
                       env=env, stdout=out, stderr=err, check=True, timeout=180)
    errors = (output/'check.stderr').read_text()
    if re.findall(r'Ran ([0-9]+) tests in .*\n\nOK\n', errors) != ['45', '8', '8']:
        raise ValueError('all three complete test suites must pass without skips')
    stage = output/'package'
    stage.mkdir()
    subprocess.run(['/bin/bash', '--noprofile', '--norc', '-c',
                    'set -euo pipefail; source "$1"; package', 'apps10-package', str(recipe/'PKGBUILD')],
                   env=dict(env, pkgdir=str(stage)), check=True, timeout=30)
    subprocess.run([sys.executable, '-I', '-B', str(recipe/'check_source.py'),
                    '--recipe-root', str(recipe), '--repository-source', str(source), '--stage', str(stage)],
                   check=True, timeout=30)
    result = dict(status='PASS_EXACT_SOURCE_AND_DISPOSABLE_PACKAGE_TESTS', tests=[45, 8, 8],
                  elapsed=time.monotonic()-started, python=sys.version, executable=sys.executable,
                  makepkg_source_links=len(names), package_files=8,
                  native_build='NOT_RUN', native_acceptance='NOT_INFERRED', hardware='NOT_RUN')
    (output/'result.json').write_text(json.dumps(result, indent=2, sort_keys=True)+'\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
