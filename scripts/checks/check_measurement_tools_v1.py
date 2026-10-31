#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit source/static checks for the unselected measurement package."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

ORIGINAL_SHA256 = 'e01eb55ee54133b60a7b73121ad8926d45769937ab058aac0868db0df60b6cd8'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--archive', type=Path)
    args = parser.parse_args()
    original = Path(__file__).with_name('measurement_tools_package_checks_original_v1.py')
    if hashlib.sha256(original.read_bytes()).hexdigest() != ORIGINAL_SHA256:
        raise ValueError('retained original package checker differs')
    spec = importlib.util.spec_from_file_location('measurement_static_original', original)
    checks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checks)
    recipe = args.root / 'packages/tools/cachy-asahi-measurement-tools/PKGBUILD'
    report = checks.recipe(recipe)
    generated = subprocess.run(['makepkg', '--printsrcinfo'], cwd=recipe.parent,
                               capture_output=True, text=True, check=True).stdout
    if generated != (recipe.parent / '.SRCINFO').read_text():
        report['errors'].append('.SRCINFO differs from actual makepkg output')
    result = {'recipe': report, 'scope': 'source/static only', 'native_build': 'NOT RUN',
              'installation': 'NOT RUN', 'hardware_validation': 'NOT RUN'}
    if args.archive:
        result['archive'] = checks.package(args.archive)
    print(json.dumps(result, indent=2, sort_keys=True))
    return int(bool(report['errors'] or (args.archive and result['archive']['errors'])))


if __name__ == '__main__':
    raise SystemExit(main())
