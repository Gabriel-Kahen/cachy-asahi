#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One exact support recipe profile using the unchanged original source transport.

Source-only export: no package archive association, install, native or release credit.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

NAME = 'cachy-asahi-support'
RECIPE_SHA256 = 'f22af78c12d4f6364da1860ab8b6a12cc6978dd7019b0a8c45e6640d80a728d1'
SRCINFO_SHA256 = 'dd9f44fe0fdd29b534dff7ede19552698e40589dcf621a0fb895014d0d6104ae'
HELPERS = {'recipe_source_delivery.py': '779f8147a13d3f90d11b9e5610f2d7d74fce28d0732797331fc832f0e87323be',
           'source_delivery.py': '8fc7757579bb0e97ccee1f3e1634ad3f827899c8ace6823cfda9f226214df36e'}


def transport():
    root = next(p for p in Path(__file__).resolve().parents if (p / 'scripts/release/recipe_source_delivery.py').is_file())
    folder = root / 'scripts/release'
    for name, checksum in HELPERS.items():
        if hashlib.sha256((folder / name).read_bytes()).hexdigest() != checksum:
            raise ValueError('original source transport changed')
    spec = importlib.util.spec_from_file_location('support_source_transport_v1', folder / 'recipe_source_delivery.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    # A private module instance; original entrypoints/profiles/bytes remain unchanged.
    value.PROFILES = {NAME: dict(version='0.1.0-1', recipe=RECIPE_SHA256, srcinfo=SRCINFO_SHA256,
        docs=['README.md', 'support-bundle.md', 'source-provenance.json', 'payload-map.json'],
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
        d = transport()
        if args.command == 'pack':
            result = d.pack(args.recipe, NAME, args.source_revision, args.output)
        else:
            raw = d.s.read_file(args.bundle, d.MAX_TOTAL)
            saved, bodies = d.unpacked(raw, args.sha256)
            d.write_fresh(args.output, bodies)
            result = dict(status='UNPACKED_SOURCE_ONLY', package=saved['package'], native_build='NOT_RUN')
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        # Maintainer tool: paths may be explicit, but never echo source JSON bodies.
        print('support source delivery: refused invalid source or transport', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
