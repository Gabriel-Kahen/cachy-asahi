#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source-authentication tests; no native acceptance or repository fixture."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import dependencies
import entry

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


class SourceClosure(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='phase-source-tests-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'scripts/port/repository-client-phase-stage'
        self.source.mkdir(parents=True)
        for name in entry.SOURCES:
            shutil.copyfile(HERE / name, self.source / name)
            (self.source / name).chmod(0o644)
        for name in dependencies.COLLECTOR:
            target = self.root / 'scripts/port/repository-client-native' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / 'scripts/port/repository-client-native' / name, target)
        for name in dependencies.PREDECESSORS:
            target = self.root / name; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
            target.chmod(dependencies.PREDECESSOR_MODES[name])
        self.map = self.root / 'sources.json'
        self.pins = {name: {'sha256': hashlib.sha256((self.source / name).read_bytes()).hexdigest(), 'mode': 0o644}
                     for name in entry.SOURCES}
        self.map.write_bytes(encoded(self.pins))
        self.pin = hashlib.sha256(self.map.read_bytes()).hexdigest()

    def load(self):
        return entry.authenticated(self.map, self.pin, source_root=self.source, repo_root=self.root)

    def test_exact_closure_loaded_without_module_alias_leaks(self):
        previous = {name: sys.modules.get(name) for name in entry.MODULES}
        loaded = self.load()
        self.assertEqual(set(loaded), set(entry.MODULES))
        self.assertTrue(callable(loaded['gate'].accept))
        self.assertTrue(callable(loaded['adapter'].execute))
        self.assertEqual(previous, {name: sys.modules.get(name) for name in entry.MODULES})
        self.assertEqual(dependencies.COLLECTOR_MAP_SHA256,
                         loaded['dependencies'].COLLECTOR_MAP_SHA256)

    def test_all_own_source_poison_refused_before_compile(self):
        for name in entry.SOURCES:
            with self.subTest(name=name):
                path = self.source / name; original = path.read_bytes()
                path.write_bytes(original + b'\nraise RuntimeError("must never execute")\n')
                with mock.patch('builtins.compile', side_effect=AssertionError('compile before authentication')):
                    with self.assertRaises(ValueError): self.load()
                path.write_bytes(original)

    def test_external_map_pin_and_duplicate_keys_refused(self):
        with self.assertRaises(ValueError):
            entry.authenticated(self.map, '0' * 64, source_root=self.source, repo_root=self.root)
        self.map.write_bytes(b'{"entry.py":{},"entry.py":{}}')
        with self.assertRaises(ValueError):
            entry.authenticated(self.map, hashlib.sha256(self.map.read_bytes()).hexdigest(),
                                source_root=self.source, repo_root=self.root)

    def test_incomplete_or_extra_source_closure_refused(self):
        for alter in ('missing', 'extra'):
            pins = dict(self.pins)
            if alter == 'missing': pins.pop('adapter.py')
            else: pins['unreviewed.py'] = pins['adapter.py']
            self.map.write_bytes(encoded(pins))
            with self.assertRaises(ValueError):
                entry.authenticated(self.map, hashlib.sha256(self.map.read_bytes()).hexdigest(),
                                    source_root=self.source, repo_root=self.root)

    def test_symlink_hardlink_mode_and_ancestor_refused(self):
        path = self.source / 'adapter.py'; original = path.read_bytes()
        path.chmod(0o755)
        with self.assertRaises(ValueError): self.load()
        path.chmod(0o644)
        outside = self.root / 'outside.py'; outside.write_bytes(original)
        path.unlink(); path.symlink_to(outside)
        with self.assertRaises(OSError): self.load()
        path.unlink(); path.hardlink_to(outside)
        with self.assertRaises(ValueError): self.load()
        path.unlink(); path.write_bytes(original)
        linked = self.root / 'linked'; linked.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(OSError):
            entry.authenticated(self.map, self.pin, source_root=linked, repo_root=self.root)

    def test_no_pyc_consumed(self):
        cache = self.source / '__pycache__'; cache.mkdir()
        for name in entry.MODULES:
            (cache / (name + '.cpython-313.pyc')).write_bytes(b'untrusted malformed PYC')
            (self.source / (name + '.pyc')).write_bytes(b'untrusted malformed PYC')
        self.assertEqual(set(self.load()), set(entry.MODULES))

    def test_every_collector_dependency_is_authenticated_before_phase_compile(self):
        for name in dependencies.COLLECTOR:
            with self.subTest(name=name):
                path = self.root / 'scripts/port/repository-client-native' / name
                original = path.read_bytes(); path.write_bytes(original + b'\n# poison\n')
                with self.assertRaises(ValueError): self.load()
                path.write_bytes(original)

    def test_every_predecessor_and_frozen_consumer_dependency_is_authenticated(self):
        for name in dependencies.PREDECESSORS:
            with self.subTest(name=name):
                path = self.root / name; original = path.read_bytes()
                path.write_bytes(original + b'\n# poison\n')
                with self.assertRaises(ValueError): self.load()
                path.write_bytes(original)

    def test_cached_external_modules_still_reauthenticate(self):
        first = dependencies.load_collector(self.root)
        path = self.root / 'scripts/port/repository-client-native/common.py'
        path.write_bytes(path.read_bytes() + b'\n# after cache\n')
        with self.assertRaises(ValueError): dependencies.load_collector(self.root)
        self.assertIn('crypto', first)

    def test_isolated_authenticated_phase_call_retains_dependency_module(self):
        code = """import importlib.util, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location('tested_entry', sys.argv[1])
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
loaded = module.authenticated(sys.argv[2], sys.argv[3], source_root=Path(sys.argv[4]), repo_root=Path(sys.argv[5]))
envelope = {'schema_version':2, 'purpose':'external-repository-cryptographic-phase-acceptance', 'status':'PASS', 'request':{}, 'receipt':{}}
try:
    loaded['phases'].validate({'crypto':envelope}, {}, {}, {}, '', {}, [], {}, repo_root=Path(sys.argv[5]))
except ValueError as error:
    assert str(error) == 'phase-reference-map-differs', str(error)
else:
    raise AssertionError('incomplete phase input accepted')
"""
        process = subprocess.run([sys.executable, '-I', '-B', '-c', code, str(HERE / 'entry.py'),
            str(self.map), self.pin, str(self.source), str(self.root)], capture_output=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr.decode())

    def test_cli_requires_isolation_and_bytecode_disabled(self):
        for flags in ([], ['-I'], ['-B']):
            process = subprocess.run([sys.executable, *flags, str(HERE / 'entry.py'), '--help'],
                                     capture_output=True, timeout=10)
            self.assertNotEqual(process.returncode, 0)
            self.assertIn(b'python -I -B', process.stderr)
        process = subprocess.run([sys.executable, '-I', '-B', str(HERE / 'entry.py'), '--help'],
                                 capture_output=True, timeout=10)
        self.assertEqual(process.returncode, 0)
        self.assertIn(b'restage', process.stdout)

    def test_cli_rejects_source_before_inputs_or_tool_execution(self):
        process = subprocess.run([sys.executable, '-I', '-B', str(HERE / 'entry.py'),
            '--source-map', str(self.map), '--source-map-sha256', '0' * 64, 'accept',
            '--inputs', '/does/not/exist', '--authority', '/does/not/exist', '--authority-sha256', '0' * 64],
            capture_output=True, timeout=10)
        self.assertEqual(process.returncode, 1)
        result = json.loads(process.stdout)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['error_type'], 'ValueError')


if __name__ == '__main__':
    unittest.main()
