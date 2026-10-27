#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Unprivileged real stage and actual-time TEST controls; never grants native credit."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import contract as C
import cli_fixture as F


def run(recipe, output):
    C.safe(recipe)
    C.safe(output)
    C.need(os.getuid() == os.geteuid() > 0 and not output.exists(), 'ordinary user and fresh output required')
    C.verify_package(recipe)
    before = {name: C.digest(recipe / name) for name in C.frozen_files()}
    output.mkdir(mode=0o700)
    stage = output / 'stage'
    command = ['/bin/bash', '-c', 'set -eu; source "$1/PKGBUILD"; srcdir="$1"; pkgdir="$2"; package',
               'stage-maintenance-native-fixture', str(recipe), str(stage)]
    result = subprocess.run(command, capture_output=True, timeout=30)
    (output / 'package.stdout').write_bytes(result.stdout)
    (output / 'package.stderr').write_bytes(result.stderr)
    C.need(result.returncode == 0, 'unprivileged package staging failed')
    verifier = C.load('maintenance_host_stage_check', recipe / 'check_source.py')
    source_check = verifier.check(recipe, stage)
    work = output / 'private-cli'
    work.mkdir(mode=0o700)
    proof = F.run(stage / 'usr/bin/cachy-asahi-maintenance', work)
    C.validate_fixture(proof, os.uname().machine, os.sysconf('SC_PAGE_SIZE'))
    C.need(before == {name: C.digest(recipe / name) for name in C.frozen_files()}, 'frozen package changed')
    value = dict(status='PASS_HOST_STAGE_AND_FRESH_SIGNED_TEST_CONTROLS', architecture=os.uname().machine,
                 page_size=os.sysconf('SC_PAGE_SIZE'), uid=os.getuid(), installed_files=source_check['installed_files'],
                 source_check=source_check, fixture=proof, native='NOT_RUN', alpm_installed_lifecycle='NOT_RUN',
                 physical_m2='NOT_RUN', performance='NOT_MEASURED', release='NOT_ADMITTED')
    (output / 'report.json').write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
    return value


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('recipe', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    value = run(args.recipe.absolute(), args.output.absolute())
    print(json.dumps({key: row for key, row in value.items() if key not in ('fixture', 'source_check')}, sort_keys=True))
