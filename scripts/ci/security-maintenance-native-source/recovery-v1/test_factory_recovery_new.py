"""Focused finite recovery factory render controls; never call its emitter.

Inputs are explicit CLI paths so the same script can run from maintained CI.
All tampering occurs in ordinary temporary copies; no project Source is imported.
"""
import argparse
import ctypes  # Import is allowed; subsequent FFI loads are denied by the audit hook.
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import unittest

EXPECTED_TREE = '6e6660003155b24307d7e3cd8780d7f1a27f77bc'
ALIASES = ('.github/workflows/native-arm-build.yml', '.github/workflows/native-arm-developer-workflows.yml')
NEW_LEAVES = {'native/security_interruption_owner.py', 'native/security_recovery.py',
    'native/security_recovery_adapter.py', 'native/security_recovery_fs.py',
    'native/security_recovery_journal.py', 'native/security_recovery_metadata.py',
    'native/security_recovery_native.py', 'native/security_recovery_reader.py',
    'native/security_recovery_state.py'}
SOURCE_ROOTS, DENIED = set(), []


def audit(event, args):
    if event in {'subprocess.Popen', 'os.system', 'os.fork', 'os.forkpty', 'os.posix_spawn',
                 'socket.__new__', 'socket.connect', 'ctypes.dlopen', 'ctypes.dlsym'}:
        DENIED.append(event)
        raise RuntimeError('actor forbidden during factory DATA controls: ' + event)
    if event == 'exec' and args:
        filename = args[0].co_filename
        if not filename.startswith('<'):
            path = Path(filename).absolute()
            if any(path.is_relative_to(root) for root in SOURCE_ROOTS):
                DENIED.append('Source.exec')
                raise RuntimeError('Source actor import/exec forbidden')


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def independent_tree(bodies, modes):
    def digest(kind, raw):
        return hashlib.sha1(kind + b' ' + str(len(raw)).encode() + b'\0' + raw).digest()
    root = {}
    for name, body in bodies.items():
        node = root
        for part in name.split('/')[:-1]:
            node = node.setdefault(part, {})
        node[name.split('/')[-1]] = (body, modes[name])
    def walk(node):
        rows = []
        for name, value in node.items():
            directory = type(value) is dict
            mode = b'40000' if directory else (b'100755' if value[1] == 0o755 else b'100644')
            obj = walk(value) if directory else digest(b'blob', value[0])
            rows.append((name.encode() + (b'/' if directory else b''),
                         mode + b' ' + name.encode() + b'\0' + obj))
        return digest(b'tree', b''.join(row for _, row in sorted(rows)))
    return walk(root).hex()


def maintained(factory):
    path = factory / 'prepare.py'
    spec = importlib.util.spec_from_file_location('finite_recovery_factory_data', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # render() has no reason to reach either operation. Both the explicit guard
    # and the global audit hook make that boundary visible in test failures.
    def forbidden(*args, **kwargs):
        raise AssertionError('assemble/emitter must not run')
    module.assemble = forbidden
    return module


class FactoryData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        SOURCE_ROOTS.add(cls.parent_source)
        cls.factory_module = maintained(cls.factory)
        cls.value, cls.bodies, cls.modes = cls.factory_module.render(cls.parent_source)

    def temp_factory(self):
        tmp = tempfile.TemporaryDirectory(prefix='recovery-factory-data-')
        self.addCleanup(tmp.cleanup)
        dest = Path(tmp.name) / 'factory'
        shutil.copytree(self.factory, dest)
        return dest, maintained(dest)

    def temp_parent(self):
        tmp = tempfile.TemporaryDirectory(prefix='recovery-parent-data-')
        self.addCleanup(tmp.cleanup)
        dest = Path(tmp.name) / 'parent'
        shutil.copytree(self.parent_source, dest)
        SOURCE_ROOTS.add(dest)
        return dest

    def test_exact_render209_map208_and_independent_tree(self):
        self.assertEqual(len(self.bodies), 209)
        self.assertEqual(len(self.value['expected']['files']), 209)
        self.assertEqual(self.value['files'], 209)
        self.assertEqual(self.value['map_rows'], 208)
        self.assertEqual(self.value['expected']['tree'], EXPECTED_TREE)
        self.assertEqual(independent_tree(self.bodies, self.modes), EXPECTED_TREE)
        rows = {n: dict(**pin(b), mode=self.modes[n]) for n, b in self.bodies.items()}
        self.assertEqual(rows, self.value['expected']['files'])

    def test_exact_nine_new_leaves_and_all_held_parent_rows(self):
        before = self.value['parent']['files']
        self.assertEqual(set(self.bodies) - set(before), NEW_LEAVES)
        held = set(before) - set(self.value['payload']) - {'native/source-map.json'}
        self.assertEqual(len(held), 189)
        for name in held:
            self.assertEqual(dict(**pin(self.bodies[name]), mode=self.modes[name]), before[name])
            self.assertEqual(self.bodies[name], (self.parent_source / name).read_bytes())

    def test_exact_null_actual_selectors_and_nonrecursive_map(self):
        mapping = json.loads(self.bodies['native/source-map.json'])
        self.assertEqual(self.value['actual'], dict(source=None, ref=None, run=None, job=None, artifact=None))
        self.assertEqual(mapping['actual'], dict(source=None, ref=None, run=None))
        self.assertEqual(len(mapping['files']), 208)
        self.assertNotIn('native/source-map.json', mapping['files'])
        self.assertEqual(mapping['files'], {n: dict(**pin(b), mode=self.modes[n])
            for n, b in self.bodies.items() if n != 'native/source-map.json'})

    def test_aliases_identical_and_bind_actual_common_sha(self):
        self.assertEqual(self.bodies[ALIASES[0]], self.bodies[ALIASES[1]])
        common = hashlib.sha256(self.bodies['native/common.py']).hexdigest().encode()
        for name in ALIASES:
            self.assertEqual(re.findall(rb"'([0-9a-f]{64})' native/common.py \| sha256sum --check",
                                        self.bodies[name]), [common])

    def test_old_normal_observer_c_and_pin_are_unchanged(self):
        old = json.loads((self.parent_source / 'native/security-contract-v1.json').read_bytes())
        new = json.loads(self.bodies['native/security-contract-v1.json'])
        a, b = old['upgrade']['observation'], new['upgrade']['observation']
        self.assertEqual(a['source'], b['source'])
        self.assertEqual(a['source_pin'], b['source_pin'])
        self.assertEqual(pin(b['source'].encode('ascii')), b['source_pin'])

    def test_parent_byte_tampering_refused(self):
        parent = self.temp_parent()
        path = parent / 'native/invocation.json'
        path.write_bytes(path.read_bytes() + b'\n')
        with self.assertRaises(ValueError):
            self.factory_module.render(parent)

    def test_parent_mode_tampering_refused(self):
        parent = self.temp_parent()
        path = parent / 'native/invocation.json'
        path.chmod(0o755 if stat.S_IMODE(path.stat().st_mode) == 0o644 else 0o644)
        with self.assertRaises(ValueError):
            self.factory_module.render(parent)

    def test_parent_extra_leaf_refused(self):
        parent = self.temp_parent()
        (parent / 'unexpected-source-leaf.txt').write_bytes(b'unbound DATA')
        with self.assertRaises(ValueError):
            self.factory_module.render(parent)

    def test_profile_bytes_tampering_refused(self):
        dest, module = self.temp_factory()
        path = dest / 'profile.json'
        path.write_bytes(path.read_bytes() + b'\n')
        with self.assertRaises(ValueError):
            module.render(self.parent_source)

    def test_profile_actual_source_rejected_even_with_test_repin(self):
        dest, module = self.temp_factory()
        path = dest / 'profile.json'; value = json.loads(path.read_bytes())
        value['actual']['source'] = 'f' * 40
        path.write_bytes(module.encoded(value))
        module.PROFILE_SHA256 = hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaises(ValueError):
            module.render(self.parent_source)

    def test_source_map_run_selector_rejected_even_with_test_repin(self):
        dest, module = self.temp_factory()
        path = dest / 'profile.json'; value = json.loads(path.read_bytes())
        value['source_map_metadata']['actual']['run'] = '9000000000009'
        path.write_bytes(module.encoded(value))
        module.PROFILE_SHA256 = hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaises(ValueError):
            module.render(self.parent_source)

    def test_overlay_byte_tampering_refused(self):
        dest, module = self.temp_factory()
        path = dest / 'overlay/native/security_recovery_state.py'
        path.write_bytes(path.read_bytes() + b'\n# UNBOUND tamper\n')
        with self.assertRaises(ValueError):
            module.render(self.parent_source)

    def test_overlay_mode_tampering_refused(self):
        dest, module = self.temp_factory()
        (dest / 'overlay/native/security_recovery_state.py').chmod(0o755)
        with self.assertRaises(ValueError):
            module.render(self.parent_source)

    def test_overlay_extra_leaf_refused(self):
        dest, module = self.temp_factory()
        (dest / 'overlay/native/unexpected.py').write_bytes(b'# UNBOUND DATA\n')
        with self.assertRaises(ValueError):
            module.render(self.parent_source)

    def test_raw_parent_commit_tampering_refused(self):
        dest, module = self.temp_factory()
        path = dest / 'parent-commit.raw'
        path.write_bytes(path.read_bytes() + b'\n')
        with self.assertRaises(ValueError):
            module.render(self.parent_source)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--factory', type=Path, required=True)
    parser.add_argument('--parent-source', type=Path, required=True)
    parser.add_argument('--results', type=Path)
    args = parser.parse_args()
    factory, parent = args.factory.resolve(), args.parent_source.resolve()
    if not factory.is_dir() or not parent.is_dir():
        parser.error('factory and parent Source must be existing directories')
    FactoryData.factory, FactoryData.parent_source = factory, parent
    sys.addaudithook(audit)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(FactoryData))
    report = dict(status='PASS' if result.wasSuccessful() and not DENIED else 'FAIL',
        tests=result.testsRun, failures=len(result.failures), errors=len(result.errors),
        fixture='PURE_FACTORY_RENDER_AND_TEMPORARY_DATA_TAMPERING_ONLY',
        expected_files=209, expected_map_rows=208, expected_tree=EXPECTED_TREE,
        factory_profile=pin((factory/'profile.json').read_bytes()),
        factory_prepare=pin((factory/'prepare.py').read_bytes()),
        denied_actor_events=DENIED, assemble_emitter_calls=0, Source_actor_imports=0,
        FFI_native_pacman_GPG_network_GET_capsule_Reader_calls=0, old62_replayed=False)
    if args.results is not None:
        with args.results.open('x') as stream:
            json.dump(report, stream, sort_keys=True, indent=2);stream.write('\n')
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
