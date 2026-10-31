#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Successor-only production source export and preserved-v1 refusal checks."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('security_maintenance_source_delivery_v2.py').absolute()
PROFILE = SCRIPT.with_name('security_maintenance_source_profile_v2.json')
RECIPE = SCRIPT.parents[2] / 'packages/tools/cachy-asahi-security-maintenance'
V1 = SCRIPT.with_name('security_maintenance_source_delivery.py')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class SuccessorSource(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='security-source-v2-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def cli(self, *args, script=SCRIPT, expected=0):
        result = subprocess.run([sys.executable, '-I', '-B', str(script), *map(str, args)],
                                cwd='/', capture_output=True, timeout=30)
        self.assertEqual(result.returncode, expected, result.stderr)
        if expected:
            self.assertEqual(result.stdout, b'')
            return result
        return json.loads(result.stdout)

    def pack(self):
        bundle = self.root / 'successor.tar'
        report = self.cli('pack', '--recipe', RECIPE, '--output', bundle)
        self.assertEqual(report['version'], '0.1.0-2')
        self.assertEqual(report['sha256'], digest(bundle.read_bytes()))
        self.assertEqual(report['status'], 'SOURCE_BYTES_ONLY')
        return bundle, report

    def test_successor_export_move_repack_exact_profile(self):
        bundle, report = self.pack()
        profile = json.loads(PROFILE.read_bytes())
        self.assertEqual(profile['version'], '0.1.0-2')
        self.cli('verify', '--bundle', bundle, '--sha256', report['sha256'])
        with tarfile.open(bundle, mode='r:') as source:
            names = set(source.getnames())
            self.assertEqual(names, {'recipe/' + name for name in profile['files']} |
                             {'delivery/' + SCRIPT.name, 'delivery/' + PROFILE.name})
            # The export carries package/program source, including advisory-cache
            # code; real advisory DATA is independently licensed and excluded.
            for name, row in profile['files'].items():
                with source.extractfile('recipe/' + name) as stream:
                    self.assertEqual(digest(stream.read()), row['sha256'])
        output = self.root / 'unpacked'
        self.cli('unpack', '--bundle', bundle, '--sha256', report['sha256'], '--output', output)
        moved = self.root / 'unrelated-prefix'
        output.rename(moved)
        repacked = self.root / 'repacked.tar'
        second = self.cli('pack', '--recipe', moved / 'recipe', '--output', repacked,
                          script=moved / 'delivery' / SCRIPT.name)
        self.assertEqual(repacked.read_bytes(), bundle.read_bytes())
        self.assertEqual(second['sha256'], report['sha256'])
        self.assertEqual(second['native'], 'NOT_RUN')
        self.assertEqual(second['installed'], 'NOT_RUN')
        self.assertFalse(second['legal_acceptance'])
        self.assertFalse(second['source_completeness_accepted'])

    def test_preserved_v1_profile_refuses_successor_recipe_and_bundle(self):
        before = {path: path.read_bytes() for path in (V1, V1.with_name('security_maintenance_source_profile.json'))}
        bundle, report = self.pack()
        refused = self.root / 'v1-must-not-export.tar'
        self.cli('pack', '--recipe', RECIPE, '--output', refused, script=V1, expected=2)
        self.assertFalse(refused.exists())
        self.cli('verify', '--bundle', bundle, '--sha256', report['sha256'], script=V1, expected=2)
        self.assertEqual(before, {path: path.read_bytes() for path in before})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--recipe-root', type=Path)
    parser.add_argument('--v1-delivery-root', type=Path)
    options, rest = parser.parse_known_args()
    if options.recipe_root:
        RECIPE = options.recipe_root.absolute()
    if options.v1_delivery_root:
        V1 = options.v1_delivery_root.absolute() / 'security_maintenance_source_delivery.py'
    unittest.main(argv=[sys.argv[0], *rest])
