# SPDX-License-Identifier: MIT
"""Portable exact-source and genuine archive-copy regressions; no native actors."""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('repair_relative_factory', HERE / 'prepare.py')
F = importlib.util.module_from_spec(spec)
spec.loader.exec_module(F)
SOURCE = Path(os.environ['REPAIR_RELATIVE_INPUT']).absolute()
EXPECTED = Path(os.environ['REPAIR_RELATIVE_EXPECTED']).absolute()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class Controls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('REPAIR_RELATIVE_WORK'))
        self.work = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def helper(self):
        values, profile = F.compose(SOURCE)
        self.assertEqual(F.tree(EXPECTED), values)
        return load(EXPECTED / F.HELPER, 'exact_public_inspect_helper')

    def test_both_real_cli_contexts_and_complete_source_entry(self):
        expected = F.tree(EXPECTED)
        for context in ('known', 'null'):
            output = self.work / context
            process = subprocess.run([
                sys.executable, '-I', '-B', '-Werror', str(HERE / 'prepare.py'),
                '--source', str(SOURCE), '--output', str(output), '--context', context],
                capture_output=True, timeout=30, check=True)
            receipt = json.loads(process.stdout)
            self.assertEqual(F.tree(output), expected)
            self.assertEqual(receipt['source'] is None, context == 'null')
            self.assertIsNone(receipt['actual'])
            self.assertFalse(receipt['native_acceptance'])
            self.assertEqual(process.stderr, b'')
        # Both contexts emit identical source. Execute this full guard once per Python.
        output = self.work / 'known'
        process = subprocess.run([
            sys.executable, '-I', '-B', '-Werror', str(output / 'apps16-repair/entry.py'),
            '--source-only', '--require-selection'], capture_output=True, timeout=300,
            check=True)
        result = json.loads(process.stdout)
        self.assertEqual(result['source_files'], 245)
        self.assertIsNone(result['actual'])
        self.assertEqual(process.stderr, b'')

    def test_entire_before_after_held_and_counted_source_inverse(self):
        values, profile = F.compose(SOURCE)
        before = F.tree(SOURCE)
        self.assertEqual(values, F.tree(EXPECTED))
        self.assertEqual(profile['counts'], dict(before=242, after=245, held=234,
                                                 changed=8, added=3))
        guard = load(EXPECTED / F.GUARD, 'exact_public_inspect_source_guard')
        p = guard.profile(EXPECTED)
        self.assertEqual(guard.bodies(EXPECTED, p), before)
        self.assertEqual(guard.transformed(before, values[F.HELPER], values[F.GUARD],
                                           values[F.PROFILE]), values)
        for name in profile['held']:
            self.assertEqual(values[name], before[name])

    def test_input_drift_missing_extra_directory_symlink_hardlink_prewrite(self):
        for variant in ('drift', 'missing', 'extra', 'empty-directory', 'symlink', 'hardlink'):
            with self.subTest(variant=variant):
                source = self.work / variant
                shutil.copytree(SOURCE, source)
                leaf = source / F.SELECT
                if variant == 'drift':
                    leaf.write_bytes(leaf.read_bytes() + b'\n')
                elif variant == 'missing':
                    leaf.unlink()
                elif variant == 'extra':
                    (source / 'foreign').write_bytes(b'foreign')
                elif variant == 'empty-directory':
                    (source / 'foreign').mkdir()
                elif variant == 'symlink':
                    leaf.unlink()
                    leaf.symlink_to(SOURCE / F.SELECT)
                else:
                    leaf.unlink()
                    os.link(source / F.A, leaf)
                output = self.work / (variant + '-output')
                with self.assertRaises(ValueError):
                    F.emit(source, output, 'known')
                self.assertFalse(output.exists())

    def test_canonical_disjoint_fresh_context_and_late_drift_refusals(self):
        source = self.work / 'source'
        shutil.copytree(SOURCE, source)
        alias = self.work / 'alias'
        alias.symlink_to(source, target_is_directory=True)
        for incoming, output in ((source, source), (source, source / 'nested'),
                                 (alias, self.work / 'output'), (source, Path('relative')),
                                 (source, HERE / 'nested'),
                                 (source, self.work / 'x/../out'),
                                 (source, self.work / 'future-native-actual' / 'source')):
            with self.assertRaises(ValueError):
                F.emit(incoming, output, 'known')
        with self.assertRaises(ValueError):
            F.emit(source, self.work / 'wrong-context', 'other')
        original = F.tree
        calls = []

        def changed(root):
            result = original(root)
            if root == source:
                calls.append(None)
                if len(calls) == 2:
                    result[F.SELECT] += b'late drift'
            return result

        output = self.work / 'late-output'
        with patch.object(F, 'tree', side_effect=changed), self.assertRaises(ValueError):
            F.emit(source, output, 'known')
        self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
