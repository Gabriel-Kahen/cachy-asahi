# SPDX-License-Identifier: MIT
"""Private repository view for the frozen v2 constructor controls."""
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
FAMILY = HERE.parent.relative_to(ROOT)
CHECKER = 'scripts/checks/package_checks.py'
BUILD_HELPERS = ROOT / 'packages/tools/cachy-asahi-security-maintenance'
# These checked-in copies match the frozen v2 profile's bytes and modes.
HELD_HELPERS = {
    'scripts/build/build.py': BUILD_HELPERS / 'build.py',
    'scripts/build/compare.py': BUILD_HELPERS / 'compare.py',
    'scripts/build/container-entry.sh': BUILD_HELPERS / 'container-entry.sh',
    CHECKER: (ROOT / 'scripts/ci/llhttp-minimal-native-source-data/fixtures/Source95/held-source'
              / 'scripts/ci/llhttp-reference-native-source/base/runtime' / CHECKER),
}


def stage_inputs(output):
    profile = json.loads((HERE / 'profile.json').read_bytes())
    spec = importlib.util.spec_from_file_location('onboarding_v2_fixture_basis', ROOT / FAMILY / 'prepare.py')
    basis = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(basis)
    files = {}
    for recipe in profile['packages'].values():
        prefix = recipe['path']
        files.update({prefix + '/' + name: value for name, value in basis.snapshot(ROOT / prefix).items()})
    for name in profile['helpers']:
        files[name] = basis.read(HELD_HELPERS.get(name, ROOT / name))
    for name in profile['prior_factory']:
        member = (FAMILY / name).as_posix()
        files[member] = basis.read(ROOT / member)

    output.mkdir(mode=0o700)
    for name, (body, mode) in files.items():
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(body)
        target.chmod(mode)
    return output
