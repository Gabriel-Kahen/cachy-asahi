# SPDX-License-Identifier: MIT
"""Closed public Source95 fixture refusal controls; never run an actor."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest

CI = None


class FixtureControls(unittest.TestCase):
    def test_whole_source95_public_fixture_has_only_original_data(self):
        bodies = CI.verify_fixture()
        self.assertEqual(len(bodies), 95)
        self.assertEqual(sum(map(len, bodies.values())), 1318237)
        self.assertEqual(CI.git_tree(bodies), CI.PARENT_TREE)
        self.assertTrue(all(v is None for v in json.loads(bodies['source-map.json'])['actual'].values()))
        archives = {n: len(b) for n, b in bodies.items() if n.endswith(('.tar.gz', '.tar.xz', '.tar.zst'))}
        self.assertEqual(archives, {'held-source/scripts/ci/llhttp-reference-native-source/base/recipe/llhttp-9.3.1.tar.gz': 39211})
        self.assertEqual(len(CI.verify_projection()['changed']), 30)
        expected = json.loads((CI.SOURCE / 'validation.DATA.json').read_bytes())['physical_export']
        actual = CI.AUTHOR_MODULE.Controls.report
        self.assertEqual(actual, expected)
        corrected = CI.AUTHOR_MODULE.Controls.b
        self.assertEqual((len(corrected), sum(map(len, corrected.values())), CI.git_tree(corrected)),
                         (96, 1629237, '8a8f0baa349399a5546883acd67f43d4fe0f15f1'))

    def test_fixture_missing_extra_body_mode_and_alias_refuse(self):
        with tempfile.TemporaryDirectory(prefix='MODEL-source95-fixture-') as name:
            root = Path(name) / 'Source95'; shutil.copytree(CI.FIXTURE, root)
            extra = root / 'MODEL-unlisted'; extra.write_bytes(b'MODEL')
            self.assertRaises(ValueError, CI.verify_fixture, root); extra.unlink()
            leaf = root / 'source-map.json'; raw = leaf.read_bytes()
            leaf.write_bytes(raw + b'x'); self.assertRaises(ValueError, CI.verify_fixture, root)
            leaf.write_bytes(raw); leaf.chmod(0o600); self.assertRaises(ValueError, CI.verify_fixture, root)
            leaf.chmod(0o644); leaf.rename(root / 'MODEL-map')
            self.assertRaises((ValueError, FileNotFoundError), CI.verify_fixture, root)
            leaf.symlink_to(root / 'MODEL-map'); self.assertRaises(ValueError, CI.verify_fixture, root)
            projection = Path(name) / 'MODEL-projection.json'; projection.write_bytes(CI.PROJECTION.read_bytes() + b'x')
            self.assertRaises(ValueError, CI.verify_projection, projection)
