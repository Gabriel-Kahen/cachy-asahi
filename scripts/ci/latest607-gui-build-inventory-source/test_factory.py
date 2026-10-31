# SPDX-License-Identifier: MIT
"""Portable fixed-source controls. No archives, actors, network, or native claim."""
import contextlib
import copy
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
spec = importlib.util.spec_from_file_location('exact_gui_factory', HERE / 'prepare.py')
factory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(factory)
SOURCE = factory.ordinary(os.environ['GUI_BUILD_INPUT'])
EXPECTED = factory.ordinary(os.environ['GUI_BUILD_EXPECTED'])


class SourceControls(unittest.TestCase):
    def test_real_cli_known_null_exact692_receipts_public_parent_context(self):
        expected = factory.tree(EXPECTED)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for context in ('known', 'null'):
                output = root / context
                result = subprocess.run([sys.executable, '-I', '-B', '-Werror',
                    str(HERE / 'prepare.py'), '--source', str(SOURCE), '--output', str(output),
                    '--context', context], capture_output=True, timeout=30, check=True)
                receipt = json.loads(result.stdout)
                self.assertFalse(receipt['native_acceptance'])
                self.assertIsNone(receipt['actual'])
                self.assertEqual(receipt['source'] is None, context == 'null')
                self.assertEqual(receipt['files'], 692)
                self.assertEqual(factory.tree(output), expected)
                parent = json.loads((output / 'implementation/build-inventory-parent.json').read_bytes())
                self.assertEqual(parent['variant'], 'known')
                self.assertEqual(parent['source'], '7e38a1cdd122af0a514f267bb30c91a29d400a17')

    def test_whole687_inverse_all670_held_defaults_and_runtime_clocks(self):
        import ast
        values, profile, unused, inputs = factory.compose(SOURCE)
        self.assertEqual(values, factory.tree(EXPECTED))
        self.assertEqual(profile['counts'], dict(parent=687, result=692, held=670, changed=17, added=5))
        before = factory.tree(SOURCE)
        for name in profile['held']:
            self.assertEqual(values[name], before[name], name)
        for name in ('implementation/factory/run.py', 'implementation/factory/installed607.py',
                     'implementation/observer_apply.py', 'implementation/observer_stage.py',
                     'implementation/expected607.lock'):
            self.assertEqual(values[name], before[name], name)
        for name in ('build_scope.py', 'failure_cleanup.py'):
            path = 'implementation/factory/' + name
            self.assertTrue(values[path].startswith(before[path]))
            old = ast.parse(before[path]); new = ast.parse(values[path])
            functions = lambda tree: {n.name: ast.dump(n, include_attributes=False) for n in tree.body
                                      if isinstance(n, ast.FunctionDef)}
            for key, value in functions(old).items():
                original = next(n for n in new.body if isinstance(n, ast.FunctionDef) and n.name == key)
                self.assertEqual(ast.dump(original, include_attributes=False), value)
        old = json.loads(before['implementation/factory/service-vm-profile.json'])
        new = json.loads(values['implementation/factory/service-vm-profile.json'])
        old['original_helpers']['factory.py'] = new['original_helpers']['factory.py']
        self.assertEqual(old, new)
        self.assertEqual(before['implementation/test_observer.py'].count(b'(687,676,607,605)'), 1)
        self.assertEqual(values['implementation/test_observer.py'].count(b'(692,676,607,605)'), 1)

    def test_constructor_treats_supplied_code_as_data_and_uses_no_actor_or_decoder(self):
        import base64
        import builtins
        from unittest.mock import patch
        with (patch.object(builtins, 'exec', side_effect=AssertionError('NO_PARENT_EXEC')),
              patch.object(subprocess, 'Popen', side_effect=AssertionError('NO_CONSTRUCTOR_ACTOR')),
              patch.object(base64, 'b64decode', side_effect=AssertionError('NO_CODE_DECODE'))):
            values, unused, unused2, unused3 = factory.compose(SOURCE)
        self.assertEqual(values, factory.tree(EXPECTED))

    def test_exact_new607_role_private_fd_alias_and_owner_controls(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); output = root / 'source692'
            factory.emit(SOURCE, output, 'known')
            self.assertEqual(factory.tree(output), factory.tree(EXPECTED))
            result = subprocess.run([sys.executable, '-I', '-B', '-Werror',
                str(output / 'implementation/test_build_inventory.py')],
                capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertIn(b'Ran 8 tests', result.stderr)
            self.assertIn(b'OK', result.stderr)
            self.assertEqual(factory.tree(output), factory.tree(EXPECTED))

    def test_drift_missing_foreign_emptydir_links_and_special_input_refuse(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for variant in ('drift', 'missing', 'foreign', 'emptydir', 'symlink', 'hardlink', 'fifo'):
                source = root / variant
                shutil.copytree(SOURCE, source)
                leaf = source / 'implementation/native.py'
                if variant == 'drift':
                    leaf.write_bytes(leaf.read_bytes() + b'\n')
                elif variant == 'missing':
                    leaf.unlink()
                elif variant == 'foreign':
                    (source / 'foreign').write_bytes(b'foreign')
                elif variant == 'emptydir':
                    (source / 'foreign-empty').mkdir()
                elif variant == 'symlink':
                    leaf.unlink()
                    leaf.symlink_to(SOURCE / 'implementation/native.py')
                elif variant == 'hardlink':
                    leaf.unlink()
                    os.link(source / 'implementation/test_source.py', leaf)
                else:
                    leaf.unlink()
                    os.mkfifo(leaf)
                output = root / (variant + '-output')
                with self.subTest(variant=variant), self.assertRaises(ValueError):
                    factory.emit(source, output, 'known')
                self.assertFalse(output.exists())

    def test_early_and_late_path_alias_existing_relative_and_context_refusals(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / 'source'
            shutil.copytree(SOURCE, source)
            alias = root / 'alias'
            alias.symlink_to(source, target_is_directory=True)
            actual_named = root / 'private-native-actual-fixture'
            actual_named.mkdir()
            cases = ((source, actual_named / 'output'), (source, source), (source, source / 'nested'), (alias, root / 'out'),
                     (source, 'relative'), (source, str(root) + '/x/../out'),
                     (source, HERE / 'must-not-write'))
            for supplied, output in cases:
                with self.assertRaises(ValueError):
                    factory.emit(supplied, output, 'null')
            with self.assertRaises(ValueError):
                factory.emit(source, root / 'invalid', 'native')
            self.assertFalse((root / 'invalid').exists())

    def test_late_real_source_replacement_and_profile_drift_precede_all_writes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for kind in ('source', 'profile'):
                source, local = root / (kind + '-source'), root / (kind + '-factory')
                shutil.copytree(SOURCE, source)
                shutil.copytree(HERE, local)
                previous, original, calls = factory.HERE, factory.scan, 0
                def scan(path):
                    nonlocal calls
                    value = original(path)
                    if Path(path) == source:
                        calls += 1
                        if calls == 1:
                            if kind == 'source':
                                leaf = source / 'implementation/native.py'
                                replacement = source / 'replacement'
                                replacement.write_bytes(leaf.read_bytes())
                                os.replace(replacement, leaf)  # Same bytes, different inode/ctime.
                            else:
                                leaf = local / 'profile.json'
                                leaf.write_bytes(leaf.read_bytes() + b' ')
                    return value
                try:
                    factory.HERE, factory.scan = local, scan
                    output = root / (kind + '-output')
                    with self.assertRaises(ValueError):
                        factory.emit(source, output, 'known')
                    self.assertFalse(output.exists())
                finally:
                    factory.HERE, factory.scan = previous, original

    def test_stable_fd_read_ignores_read_atime_and_profile_payload_pin_refusals(self):
        self.assertNotIn('st_atime_ns', factory.identity.__code__.co_consts)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            leaf = root / 'read'
            leaf.write_bytes(b'ordinary')
            os.utime(leaf, ns=(0, leaf.stat().st_mtime_ns))
            before = factory.identity(leaf.stat())
            self.assertEqual(factory.read(leaf), b'ordinary')
            self.assertEqual(factory.identity(leaf.stat()), before)
            for name in ('profile.json', 'build_inventory.py.in', 'runner-context-policy.json.in', 'build-scope-footer.py.in'):
                local = root / name.replace('.', '_')
                shutil.copytree(HERE, local)
                target = local / name
                target.write_bytes(target.read_bytes() + b' ')
                previous = factory.HERE
                try:
                    factory.HERE = local
                    with self.assertRaises(ValueError):
                        factory.emit(SOURCE, root / ('output-' + name), 'null')
                finally:
                    factory.HERE = previous


if __name__ == '__main__':
    unittest.main(verbosity=2)
