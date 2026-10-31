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
spec = importlib.util.spec_from_file_location('exact_mime_factory', HERE / 'prepare.py')
factory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(factory)
SOURCE = factory.ordinary(os.environ['CORE_MIME_INPUT'])
EXPECTED = factory.ordinary(os.environ['CORE_MIME_EXPECTED'])


@contextlib.contextmanager
def policy(root):
    saved, paths = dict(sys.modules), sys.path[:]
    try:
        sys.path.insert(0, str(root))
        for path in root.glob('*.py'):
            sys.modules.pop(path.stem, None)
        spec = importlib.util.spec_from_file_location('_fixed_current_mime', root / 'mime_cache.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        yield module
    finally:
        sys.path[:] = paths
        for name in set(sys.modules) - set(saved):
            sys.modules.pop(name, None)
        sys.modules.update(saved)


class SourceControls(unittest.TestCase):
    def test_real_cli_known_null_exact49_full_entry_and_current_seven(self):
        expected = factory.tree(EXPECTED)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for context in ('known', 'null'):
                output = root / context
                command = [sys.executable, '-I', '-B', '-Werror', str(HERE / 'prepare.py'),
                           '--source', str(SOURCE), '--output', str(output), '--context', context]
                result = subprocess.run(command, capture_output=True, timeout=30, check=True)
                receipt = json.loads(result.stdout)
                self.assertFalse(receipt['native_acceptance'])
                self.assertIsNone(receipt['actual'])
                self.assertEqual(receipt['source'] is None, context == 'null')
                self.assertEqual(receipt['files'], 49)
                self.assertEqual(factory.tree(output), expected)
                proof = subprocess.run([sys.executable, '-I', '-B', '-Werror',
                                        str(output / 'entry.py'), 'source', '--source', str(output)],
                                       capture_output=True, timeout=30, check=True)
                self.assertEqual(json.loads(proof.stdout)['files'], 49)
                if context == 'known':
                    tests = subprocess.run([sys.executable, '-I', '-B', '-Werror',
                                            str(output / 'test_initramfs.py')],
                                           capture_output=True, timeout=30, check=True)
                    self.assertIn(b'Ran 7 tests', tests.stderr)

    def test_whole47_inverse_and_all_held_runtime_security_clocks(self):
        values, profile, unused, inputs = factory.compose(SOURCE)
        self.assertEqual(values, factory.tree(EXPECTED))
        self.assertEqual(profile['counts'], dict(parent=47, result=49, held=39, changed=8, added=2))
        before = factory.tree(SOURCE)
        for name in profile['held']:
            self.assertEqual(values[name], before[name], name)
        with policy(EXPECTED) as module:
            self.assertEqual(module.inverse(values), before)
        self.assertEqual(values['workflow.yml.in'], before['workflow.yml.in'])
        self.assertEqual(values['case.py'], before['case.py'])
        self.assertEqual(values['candidate_capacity.py'], before['candidate_capacity.py'])
        self.assertEqual(values['acl_policy.py'], before['acl_policy.py'])

    def test_drift_missing_foreign_emptydir_links_and_special_input_refuse(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for variant in ('drift', 'missing', 'foreign', 'emptydir', 'symlink', 'hardlink', 'fifo'):
                source = root / variant
                shutil.copytree(SOURCE, source)
                leaf = source / 'guest.py'
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
                    leaf.symlink_to(SOURCE / 'guest.py')
                elif variant == 'hardlink':
                    leaf.unlink()
                    os.link(source / 'entry.py', leaf)
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
                                leaf = source / 'guest.py'
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
            for name in ('profile.json', 'mime_cache.py.in', 'mime-profile.json'):
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


class MimePolicyControls(unittest.TestCase):
    def test_fixed_six_inputs_mechanisms_and_1084_complete_nodes(self):
        with policy(EXPECTED) as module:
            p = module.policy()
            before = dict(p['before'], **p['mechanisms'])
            after = dict(before, **p['generated'])
            self.assertEqual(len(p['inputs']), 6)
            self.assertEqual(len(p['generated']), 1084)
            self.assertEqual(module.closed(before, after), set(p['generated']))
            self.assertEqual(module.baseline(before, after)['total'], 1092)
            for field, value in (('mode', 0o600), ('uid', 1), ('gid', 1),
                                 ('type', 'symlink'), ('sha256', '0' * 64), ('bytes', 0)):
                bad = copy.deepcopy(after)
                name = next(n for n, row in p['generated'].items() if row['type'] == 'file')
                bad[name][field] = value
                with self.subTest(field=field), self.assertRaises(ValueError):
                    module.closed(before, bad)
            for name in (*p['inputs'], *p['mechanisms']):
                bad = copy.deepcopy(after)
                bad[name]['sha256'] = '0' * 64
                with self.subTest(name=name), self.assertRaises(ValueError):
                    module.closed(before, bad)
            for name in ('usr/share/mime/foreign', 'usr/share/mime/packages/foreign.xml'):
                bad = dict(after, **{name: dict(type='file', mode=0o644, uid=0, gid=0,
                                                bytes=0, sha256='0' * 64)})
                with self.assertRaises(ValueError):
                    module.closed(before, bad)
            self.assertNotIn('usr/share/mime-foreign', module.closed(before, after))

    def test_exact_cumulative_hook_roles_and_namespace_restoration(self):
        before_modules, before_paths = dict(sys.modules), sys.path[:]
        with policy(EXPECTED) as module:
            baseline = b"[ALPM] running '30-update-mime-database.hook'\n"
            candidate = baseline + b"[ALPM] next transaction\n" + baseline
            module.log_pair(baseline, candidate)
            for first, second in ((baseline, baseline), (baseline, b'foreign' + candidate),
                                  (baseline, candidate + baseline)):
                with self.assertRaises(ValueError):
                    module.log_pair(first, second)
        self.assertEqual(sys.path, before_paths)
        self.assertEqual(sys.modules, before_modules)


if __name__ == '__main__':
    unittest.main(verbosity=2)
