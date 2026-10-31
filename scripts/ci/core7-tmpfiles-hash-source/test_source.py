# SPDX-License-Identifier: MIT
"""Portable exact-source and prewrite refusal controls; no native actors."""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('tmpfiles_hash_factory', HERE / 'prepare.py')
factory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(factory)
SOURCE = Path(os.environ['CORE_TMPFILES_INPUT']).absolute()
EXPECTED = Path(os.environ['CORE_TMPFILES_EXPECTED']).absolute()


class SourceControls(unittest.TestCase):
    def test_both_real_cli_contexts_and_complete_entry(self):
        expected = factory.tree(EXPECTED)
        with tempfile.TemporaryDirectory() as directory:
            for context in ('known', 'null'):
                output = Path(directory) / context
                result = subprocess.run(
                    [sys.executable, '-I', '-B', '-Werror', str(HERE / 'prepare.py'),
                     '--source', str(SOURCE), '--output', str(output), '--context', context],
                    capture_output=True, check=True, timeout=30)
                receipt = json.loads(result.stdout)
                self.assertFalse(receipt['native_acceptance'])
                self.assertIsNone(receipt['actual'])
                self.assertEqual(receipt['source'] is None, context == 'null')
                self.assertEqual(factory.tree(output), expected)
                subprocess.run([sys.executable, '-I', '-B', '-Werror',
                                str(output / 'entry.py'), 'source', '--source', str(output)],
                               capture_output=True, check=True, timeout=30)

    def test_every_output_and_held_leaf(self):
        values, profile = factory.compose(SOURCE)
        self.assertEqual(values, factory.tree(EXPECTED))
        self.assertEqual(len(values), 47)
        self.assertEqual(len(profile['held']), 41)
        before = factory.tree(SOURCE)
        for name in profile['held']:
            self.assertEqual(values[name], before[name])
        namespace = {'__file__': str(EXPECTED / 'tmpfiles_hash.py')}
        exec(compile(values['tmpfiles_hash.py'], 'tmpfiles_hash.py', 'exec'), namespace)
        self.assertEqual(namespace['inverse'](values), before)

    def test_drift_missing_extra_and_link_refuse_before_output(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for variant in ('drift', 'missing', 'extra', 'symlink', 'hardlink'):
                source = base / variant
                shutil.copytree(SOURCE, source)
                leaf = source / 'guest.py'
                if variant == 'drift':
                    leaf.write_bytes(leaf.read_bytes() + b'\n')
                elif variant == 'missing':
                    leaf.unlink()
                elif variant == 'extra':
                    (source / 'foreign').write_bytes(b'foreign')
                elif variant == 'symlink':
                    leaf.unlink()
                    leaf.symlink_to(SOURCE / 'guest.py')
                else:
                    leaf.unlink()
                    os.link(source / 'entry.py', leaf)
                output = base / (variant + '-output')
                with self.assertRaises(ValueError):
                    factory.emit(source, output, 'known')
                self.assertFalse(output.exists())

    def test_existing_nested_alias_relative_output_refusals(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / 'source'
            shutil.copytree(SOURCE, source)
            alias = base / 'alias'
            alias.symlink_to(source, target_is_directory=True)
            for input_path, output in ((source, source / 'nested'), (source, source),
                                       (alias, base / 'output'), (source, Path('relative'))):
                with self.assertRaises(ValueError):
                    factory.emit(input_path, output, 'null')


class TmpfilesRegression(unittest.TestCase):
    @staticmethod
    def policy(root):
        spec = importlib.util.spec_from_file_location('literal_hash_effects', root / 'effects.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.tmpfiles_rules

    def test_real_failure_rules_and_literal_hash_nodes(self):
        raw = (b'# whole-line comment\n'
               b'd /var/lib/literal#name 0755 0 0 -\n'
               b'R! /var/lib/machines/.#*\n'
               b'R! /.#machine.*\n'
               b'x /var/lib/systemd/coredump/.#core*.%b*\n'
               b'r! /var/lib/systemd/coredump/.#*\n')
        with self.assertRaisesRegex(ValueError, 'literal tmpfiles path'):
            self.policy(SOURCE)(raw, {}, {})
        result = self.policy(EXPECTED)(raw, {}, {})
        self.assertEqual(result, {'var/lib/literal#name': {
            'type': 'directory', 'mode': 0o755, 'uid': 0, 'gid': 0}})

    def test_hash_fix_preserves_traversal_and_dynamic_exclusion(self):
        policy = self.policy(EXPECTED)
        for name in ('/var/lib/a/../b', '/var//lib/a', '/var/lib/./a'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                policy(('d ' + name + ' 0755 0 0 -\n').encode(), {}, {})
        self.assertEqual(policy(b'd /var/lib/a#* 0755 0 0 -\n'
                                b'd /var/lib/%b#name 0755 0 0 -\n', {}, {}), {})


if __name__ == '__main__':
    unittest.main()
