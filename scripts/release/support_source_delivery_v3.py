#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pack or unpack the exact support 0.2.0-2 source recipe without executing it."""
import argparse
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import sys
import tarfile
import tempfile
from types import ModuleType

NAME = 'cachy-asahi-support'
VERSION = '0.2.0-2'
RECIPE_SHA256 = '755b121f7dc60ce410ee3ad248b4e085f5da47aa4edb92579fa5e1750dad7fb4'
SRCINFO_SHA256 = '9d7a8344ba11afc0db53ec1b83667d380eb68a25eb0dc296335d93ff9383802c'
HELPERS = {
    'recipe_source_delivery.py': 'd5f44aadc7fb84908a645c6d7dd4c7962c728d76871fd7751cea7fc05312b229',
    'source_delivery.py': '8fc7757579bb0e97ccee1f3e1634ad3f827899c8ace6823cfda9f226214df36e',
}


@contextmanager
def transport():
    source = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix='support3-transport-') as temporary:
        private = Path(temporary)
        # The transport imports its sibling. Make both imports use checked bytes.
        for name, checksum in HELPERS.items():
            with (source / name).open('rb') as stream:
                raw = stream.read(256 * 1024 + 1)
            if hashlib.sha256(raw).hexdigest() != checksum:
                raise ValueError('reviewed support3 transport changed')
            (private / name).write_bytes(raw)
        path = private / 'recipe_source_delivery.py'
        module = ModuleType('support_source_transport_v3')
        module.__file__ = str(path)
        exec(compile(path.read_bytes(), module.__file__, 'exec'), module.__dict__)
        module.PROFILES = {NAME: dict(
            version=VERSION, recipe=RECIPE_SHA256, srcinfo=SRCINFO_SHA256,
            docs=['README.md', 'support-bundle.md', 'collect-support.md', 'source-provenance.json', 'payload-map.json'],
            required_sources=['NOTICE', 'LICENSE', 'source-provenance.json', 'payload-map.json'],
            checks=[['python', '-I', '-B', 'check_package.py', '--recipe-root', '.'],
                    ['python', '-I', '-B', '-Werror::ResourceWarning', 'test_package.py', '--recipe-root', '.']])}
        module.LEGACY_PROFILES = {}
        yield module


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    pack = commands.add_parser('pack')
    pack.add_argument('--recipe', type=Path, required=True)
    pack.add_argument('--source-revision', required=True)
    unpack = commands.add_parser('unpack')
    unpack.add_argument('--bundle', type=Path, required=True)
    unpack.add_argument('--sha256', required=True)
    for command in (pack, unpack):
        command.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        with transport() as selected:
            if args.command == 'pack':
                result = selected.pack(args.recipe, NAME, args.source_revision, args.output)
            else:
                raw = selected.s.read_file(args.bundle, selected.MAX_TOTAL)
                saved, bodies = selected.unpacked(raw, args.sha256)
                selected.s.need(saved['archive_binding'] is None, 'source-only bundle required')
                selected.write_fresh(args.output, bodies)
                result = dict(status='UNPACKED_SOURCE_ONLY', package=saved['package'], native_build='NOT_RUN')
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, tarfile.TarError):
        print('support v3 source delivery: refused invalid source or transport', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
