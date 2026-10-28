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
spec = importlib.util.spec_from_file_location('exact_lf_factory', HERE / 'prepare.py')
factory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(factory)
SOURCE = factory.ordinary(os.environ['CORE_LF_INPUT'])
EXPECTED = factory.ordinary(os.environ['CORE_LF_EXPECTED'])
VM = factory.ordinary(os.environ['CORE_LF_VM'])


@contextlib.contextmanager
def policy(root):
    saved, paths = dict(sys.modules), sys.path[:]
    try:
        sys.path.insert(0, str(root))
        for path in root.glob('*.py'):
            sys.modules.pop(path.stem, None)
        spec = importlib.util.spec_from_file_location('_fixed_current_lf', root / 'serial_result.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        yield module
    finally:
        sys.path[:] = paths
        for name in set(sys.modules) - set(saved):
            sys.modules.pop(name, None)
        sys.modules.update(saved)


class SourceControls(unittest.TestCase):
    def test_real_cli_known_null_exact51_and_real_source_owned_writers(self):
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
                self.assertEqual(receipt['files'], 51)
                self.assertEqual(factory.tree(output), expected)
                # Exact current51/source facts are retained after complete byte joins.
                # Run the changed real writer/strict fixture here, not old ancestry again.
                if context == 'known':
                    vm_files = json.loads(factory.read(EXPECTED / 'profile.json'))['source_profiles']['ksm637']['files']
                    self.assertEqual({n: factory.pin(b) for n, b in factory.tree(VM).items()}, vm_files)
                    route = subprocess.run([sys.executable, '-I', '-B', '-Werror',
                                            str(output / 'test_route.py'), '--vm-source', str(VM)],
                                           capture_output=True, timeout=30, check=True)
                    self.assertIn(b'Ran 4 tests', route.stderr)
                    self.assertEqual({n: factory.pin(b) for n, b in factory.tree(VM).items()}, vm_files)

    def test_whole51_and49_inverses_and_all_held_runtime_security_clocks(self):
        values, profile, unused, inputs = factory.compose(SOURCE)
        self.assertEqual(values, factory.tree(EXPECTED))
        self.assertEqual(profile['counts'], dict(parent=51, result=51, held=45, changed=6, added=0))
        before = factory.tree(SOURCE)
        for name in profile['held']:
            self.assertEqual(values[name], before[name], name)
        with policy(SOURCE) as original:
            old49 = original.inverse(before)
        with policy(EXPECTED) as module:
            self.assertEqual(module.inverse(values), old49)
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
            for supplied, output in ((source, '//' + str(source).lstrip('/') + '/double-slash-output'),
                                     ('//' + str(source).lstrip('/'), root / 'alias-output')):
                command = [sys.executable, '-I', '-B', '-Werror', str(HERE / 'prepare.py'),
                           '--source', str(supplied), '--output', str(output), '--context', 'null']
                before = factory.scan(source)
                result = subprocess.run(command, capture_output=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b'canonical resolved path required', result.stderr)
                self.assertFalse(Path(output).exists())
                self.assertEqual(factory.scan(source), before)
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
            for name in ('profile.json',):
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



class SerialControls(unittest.TestCase):
    def test_full_receipts_resolve_before_original_validator_and_unchanged_protocol(self):
        with policy(EXPECTED) as module:
            import case as C
            import test_protocol as T
            selected, expected, value = T.fixture()
            value['custody']['nonce'] = selected['nonce']
            wire = module.project(value)
            self.assertEqual(C.protocol(T.frames(wire), selected, 1, expected), wire)
            self.assertLess(len(T.frames(wire)), 16384)
            with tempfile.TemporaryDirectory() as td:
                root = Path(td)
                second = copy.deepcopy(value)
                second['phase'] = second['custody']['phase'] = 2
                second['custody']['wallclock']['phase'] = 2
                second['pid1']['boot_id'] = '22222222-1111-1111-1111-111111111111'
                second['previous'] = C.pin(C.encoded(value['custody']))
                second['custody']['previous'] = second['previous']
                records = []
                for phase, full in enumerate((value, second), 1):
                    (root / ('phase%d-observer.json' % phase)).write_bytes(C.encoded(full))
                    (root / ('phase%d-custody.json' % phase)).write_bytes(C.encoded(full['custody']))
                    records.append(dict(phase=phase, result=module.project(full)))
                self.assertEqual(module.resolve(root, selected, records)[0]['result'], value)
                (root / 'phase1-observer.json').write_bytes(b'changed')
                with self.assertRaises(ValueError):
                    module.resolve(root, selected, records)

    def test_full_custody_hashes_and_closed_typed_references(self):
        with policy(EXPECTED) as module:
            import case as C
            import test_protocol as T
            value = T.fixture()[2]
            value['custody']['padding'] = 'x' * (2 * 1024**2)
            raw = C.encoded(value)
            wire = module.project(value)
            self.assertEqual(wire['custody']['full_observer'], C.pin(raw))
            self.assertEqual(module.custody_pin(wire['custody']), C.pin(C.encoded(value['custody'])))
            self.assertLess(len(C.encoded(wire)), 16384)
            for key, bad in (('bytes', True), ('bytes', 0), ('sha256', 'G' * 64)):
                changed = copy.deepcopy(wire['custody'])
                changed['full_custody'][key] = bad
                with self.assertRaises(ValueError):
                    module.custody_pin(changed)
            changed = copy.deepcopy(wire['custody'])
            changed['full_observer']['file'] = '../../foreign'
            with self.assertRaises(ValueError):
                module.custody_pin(changed)


if __name__ == '__main__':
    unittest.main(verbosity=2)
