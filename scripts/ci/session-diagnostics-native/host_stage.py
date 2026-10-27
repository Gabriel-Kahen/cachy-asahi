#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Exact copied package controls and private layout help; no host collection."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import contract as C


def run(recipe, output):
    C.safe(recipe)
    C.safe(output)
    C.need(os.getuid() == os.geteuid() > 0 and not output.exists(), 'ordinary user and fresh private output required')
    C.verify_package(recipe)
    before = {name: C.digest(recipe / name) for name in C.frozen_files()}
    output.mkdir(mode=0o700)
    private = output / 'recipe'
    shutil.copytree(recipe, private)
    commands = []

    def command(argv, label, env=None, cwd=None):
        row = subprocess.run(argv, capture_output=True, timeout=45, cwd=cwd,
                             env=env or dict(PATH='/usr/bin:/bin', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1'))
        C.need(len(row.stdout) + len(row.stderr) <= 4 * 1024**2, 'bounded source control output required')
        (output / (label + '.stdout')).write_bytes(row.stdout)
        (output / (label + '.stderr')).write_bytes(row.stderr)
        commands.append(dict(case=label, returncode=row.returncode, argv=list(map(str, argv))))
        C.need(row.returncode == 0, 'source/stage control failed: ' + label)
        return row

    for test in ('test_session_probe.py', 'test_package.py'):
        command([sys.executable, '-I', '-B', '-Werror::ResourceWarning', str(private / test)], test)
    stage = output / 'stage'
    command(['/bin/bash', '--noprofile', '--norc', '-c',
             'set -eu; umask 022; source "$1/PKGBUILD"; srcdir="$1"; pkgdir="$2"; package',
             'diagnostics-private-stage', str(private), str(stage)], 'package-stage')
    checker = C.load('diagnostics_host_source_check', private / 'check_package.py')
    checker.check_source(private)
    checker.check_stage(private, stage)
    unrelated = output / 'unrelated'
    unrelated.mkdir(mode=0o700)
    poison = unrelated / 'poison'
    poison.mkdir()
    for name in ('sitecustomize.py', 'session_probe.py'):
        (poison / name).write_text('raise RuntimeError("USER_PYTHON_IMPORT_MUST_BE_IGNORED")\n')
    row = command([str(stage / 'usr/bin' / C.NAMES[0]), '--help'], 'unrelated-help',
                  dict(PATH='/nonexistent', PYTHONPATH=str(poison), PYTHONHOME=str(poison), LC_ALL='C'), unrelated)
    C.need(b'--baseline-sha256' in row.stdout and b'USER_PYTHON' not in row.stdout + row.stderr,
           'isolated installed help differs')
    C.need(before == {name: C.digest(recipe / name) for name in C.frozen_files()}, 'source package changed')
    result = dict(status='PASS_HOST_COPIED_PACKAGE_CONTROLS_AND_STAGE', architecture=os.uname().machine,
                  uid=os.getuid(), commands=commands, probe_controls=35, package_controls=7,
                  source_files=before, payload_files=len(C.files(C.NAMES[0])), source_preserved=True,
                  diagnostic_collection='NOT_RUN_ON_HOST', native='NOT_RUN', ALPM='NOT_RUN', M2='NOT_RUN')
    (output / 'report.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('recipe', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.recipe.absolute(), args.output.absolute()), sort_keys=True))
