#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Export the exact support 0.2.0-1 source recipe; preserve the v1 transport.

Source-only export establishes no archive association, install or native result.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

NAME = 'cachy-asahi-support'
RECIPE_SHA256 = 'd1b471b58dc3aefdb902b28751df248cd30bae4f92ded78dd6470c57c8186f50'
SRCINFO_SHA256 = '7bf546798aece3cf6c124e9a2abb75dd6021ca4e9ac23784d5e38bd18dfdfa51'
HELPERS = {'recipe_source_delivery.py': '779f8147a13d3f90d11b9e5610f2d7d74fce28d0732797331fc832f0e87323be',
           'source_delivery.py': '8fc7757579bb0e97ccee1f3e1634ad3f827899c8ace6823cfda9f226214df36e'}


def transport():
    root = next(p for p in Path(__file__).resolve().parents if (p / 'scripts/release/recipe_source_delivery.py').is_file())
    folder = root / 'scripts/release'
    for name, checksum in HELPERS.items():
        if hashlib.sha256((folder / name).read_bytes()).hexdigest() != checksum:
            raise ValueError('original source transport changed')
    spec = importlib.util.spec_from_file_location('support_source_transport_v2', folder / 'recipe_source_delivery.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    # This private module instance selects one new pair. No v1 profile, helper
    # or recipe byte is rewritten, and neither version silently accepts another.
    value.PROFILES = {NAME: dict(version='0.2.0-1', recipe=RECIPE_SHA256, srcinfo=SRCINFO_SHA256,
        docs=['README.md', 'support-bundle.md', 'collect-support.md', 'source-provenance.json', 'payload-map.json'],
        required_sources=['NOTICE', 'LICENSE', 'source-provenance.json', 'payload-map.json'],
        checks=[['python', '-I', '-B', 'check_package.py', '--recipe-root', '.'],
                ['python', '-I', '-B', '-Werror::ResourceWarning', 'test_package.py', '--recipe-root', '.']])}
    value.LEGACY_PROFILES = {}
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    pack = commands.add_parser('pack')
    pack.add_argument('--recipe', type=Path, required=True)
    pack.add_argument('--source-revision', required=True)
    pack.add_argument('--output', type=Path, required=True)
    unpack = commands.add_parser('unpack')
    unpack.add_argument('--bundle', type=Path, required=True)
    unpack.add_argument('--sha256', required=True)
    unpack.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        selected = transport()
        if args.command == 'pack':
            result = selected.pack(args.recipe, NAME, args.source_revision, args.output)
        else:
            raw = selected.s.read_file(args.bundle, selected.MAX_TOTAL)
            saved, bodies = selected.unpacked(raw, args.sha256)
            selected.write_fresh(args.output, bodies)
            result = dict(status='UNPACKED_SOURCE_ONLY', package=saved['package'], native_build='NOT_RUN')
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception:
        print('support v2 source delivery: refused invalid source or transport', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
