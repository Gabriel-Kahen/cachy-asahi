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
spec = importlib.util.spec_from_file_location('exact_page_factory', HERE / 'prepare.py')
factory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(factory)
SOURCE = factory.canonical(os.environ['FRESH_PAGE_PARENT'])
EXPECTED = factory.canonical(os.environ['FRESH_PAGE_EXPECTED'])


class SourceControls(unittest.TestCase):
    def test_real_cli_known_null_exact1203_and_null_actual_selectors(self):
        expected = factory.tree(EXPECTED)
        with tempfile.TemporaryDirectory() as td:
            for context in ('known','null'):
                out = Path(td) / context
                done = subprocess.run([sys.executable,'-I','-B','-Werror',
                    str(HERE/'prepare.py'),'--parent',str(SOURCE),'--output',str(out),
                    '--context',context],capture_output=True,timeout=60,check=True)
                receipt = json.loads(done.stdout)
                self.assertEqual(len(receipt['files']),1203)
                self.assertEqual(receipt['context'],context)
                self.assertTrue(all(receipt[k] is None for k in
                    ('actual_source','actual_ref','actual_run','Root_acceptance')))
                self.assertEqual(factory.tree(out),expected)

    def test_pure_transform_restores_common_never_decodes_or_runs_parent(self):
        import types,zlib
        from unittest.mock import patch
        sentinel = types.SimpleNamespace(held='EXISTING_MODULE')
        missing = object()
        old = sys.modules.get('common',missing)
        try:
            sys.modules['common'] = sentinel
            with patch.object(zlib,'decompressobj',side_effect=AssertionError('NO_CODEC_EXECUTION')), \
                 patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS_OR_PARENT_CODE')):
                values,unused,inputs = factory.render(SOURCE)
            self.assertIs(sys.modules['common'],sentinel)
            self.assertEqual(values,factory.tree(EXPECTED))
        finally:
            if old is missing:sys.modules.pop('common',None)
            else:sys.modules['common']=old

    def test_whole1197_held_runtime_and_exact_source_partition(self):
        values,unused,inputs = factory.render(SOURCE)
        before = factory.tree(SOURCE)
        q=json.loads(factory.read(HERE/'profile.json'))
        self.assertEqual(len(before),1197)
        self.assertEqual(len(values),1203)
        self.assertEqual(set(values)-set(before),set(q['added']))
        self.assertEqual({n for n in before if values[n]!=before[n]},set(q['changed']))
        self.assertEqual(sum(values[n]==before[n]for n in before),1189)
        for n in ('implementation/runtime_context.py','parent604/prepare.py',
                  'implementation/profile.json','installer604/scripts/ci/expanded604-apps6-public-pair-installer/ci.py'):
            self.assertEqual(values[n],before[n],n)
        self.assertIn(b'--page-mode',values['implementation/workflow-template.yml']);self.assertIn(b'PAGE_MODE: ${{ inputs.page_mode }}',values['implementation/workflow-template.yml'])

    def test_drift_missing_foreign_emptydir_links_and_special_input_refuse(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for variant in ('drift', 'missing', 'foreign', 'emptydir', 'symlink', 'hardlink', 'fifo'):
                source = root / variant
                shutil.copytree(SOURCE, source)
                leaf = source / 'implementation/run.py'
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
                    leaf.symlink_to(SOURCE / 'implementation/run.py')
                elif variant == 'hardlink':
                    leaf.unlink()
                    os.link(source / 'implementation/test_source.py', leaf)
                else:
                    leaf.unlink()
                    os.mkfifo(leaf)
                output = root / (variant + '-output')
                with self.subTest(variant=variant), self.assertRaises(ValueError):
                    factory.build(source, output, 'known')
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
                    factory.build(supplied, output, 'null')
            for supplied, output in ((source, '//' + str(source).lstrip('/') + '/double-slash-output'),
                                     ('//' + str(source).lstrip('/'), root / 'alias-output')):
                command = [sys.executable, '-I', '-B', '-Werror', str(HERE / 'prepare.py'),
                           '--parent', str(supplied), '--output', str(output), '--context', 'null']
                before = factory.scan(source)
                result = subprocess.run(command, capture_output=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b'canonical resolved path required', result.stderr)
                self.assertFalse(Path(output).exists())
                self.assertEqual(factory.scan(source), before)
            with self.assertRaises(ValueError):
                factory.build(source, root / 'invalid', 'native')
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
                                leaf = source / 'implementation/run.py'
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
                        factory.build(source, output, 'known')
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
            for name in ('profile.json', 'page_mode.py.in', 'page_source.py.in'):
                local = root / name.replace('.', '_')
                shutil.copytree(HERE, local)
                target = local / name
                target.write_bytes(target.read_bytes() + b' ')
                previous = factory.HERE
                try:
                    factory.HERE = local
                    with self.assertRaises(ValueError):
                        factory.build(SOURCE, root / ('output-' + name), 'null')
                finally:
                    factory.HERE = previous


if __name__ == '__main__':
    unittest.main(verbosity=2)
