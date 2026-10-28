#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Packaging boundary controls; does not repeat workflow author suites."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('assemble', HERE / 'assemble.py')
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)
NAME, VERSION = 'cachy-asahi-developer-tools', '0.1.0'


class PackageControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='package-controls-', dir=HERE.parent)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.stage = self.root / 'stage'
        self.prefix = A.assemble(HERE, self.stage)
        self.launcher = self.prefix / 'bin' / NAME
        self.runtime = self.prefix / 'lib' / NAME / VERSION

    def launch(self, *argv, **kwargs):
        return subprocess.run([str(self.launcher), *map(str, argv)], cwd=self.root,
                              capture_output=True, text=True, timeout=10, **kwargs)

    def test_exact_payload_modes_and_set(self):
        rows = A.verified_rows(HERE)
        observed = {str(p.relative_to(self.prefix)) for p in self.prefix.rglob('*') if p.is_file()}
        self.assertEqual(observed, {str(row[0]) for row in rows})
        for name, raw, mode in rows:
            self.assertEqual((self.prefix / name).read_bytes(), raw)
            self.assertEqual((self.prefix / name).stat().st_mode & 0o777, mode)

    def test_moved_prefix_and_no_bytecode(self):
        moved = self.root / 'moved SDK with spaces'
        self.prefix.rename(moved)
        result = subprocess.run([str(moved / 'bin' / NAME), 'verify'], cwd='/',
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['status'], 'PASS_PACKAGED_RUNTIME')
        self.assertFalse(list(moved.rglob('__pycache__')))

    def test_version_help_and_explicit_selection(self):
        self.assertEqual(self.launch('--version').stdout.strip(), NAME + ' ' + VERSION)
        for command in ('workflow', 'build-systems', 'debugger', 'python', 'verify'):
            result = self.launch(command, '--help')
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(self.launch('python', '--output', self.root / 'result').returncode, 0)
        self.assertNotEqual(self.launch('run-user-file', '/tmp/user.py').returncode, 0)

    def test_isolated_interpreter_ignores_pythonpath(self):
        poison = self.root / 'poison'; poison.mkdir()
        sentinel = self.root / 'injected'
        (poison / 'sitecustomize.py').write_text('open(' + repr(str(sentinel)) + ', "w").write("bad")')
        result = self.launch('verify', env=dict(os.environ, PYTHONPATH=str(poison), PYTHONSTARTUP=str(poison)))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(sentinel.exists())

    def assert_refused_before_output(self):
        output = self.root / 'must-not-exist'
        result = self.launch('workflow', '--output', output)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(output.exists())

    def test_tampered_runner_refused_before_launch(self):
        path = self.runtime / 'scripts/workflows/developer_workflow.py'
        path.write_bytes(path.read_bytes() + b'\n# changed\n')
        self.assert_refused_before_output()

    def test_missing_fixture_refused_before_launch(self):
        (self.runtime / 'tests/workflows/fixtures/debugger/hello.c').unlink()
        self.assert_refused_before_output()

    def test_alias_runtime_refused_before_launch(self):
        path = self.runtime / 'scripts/virtual/owned_process.py'
        other = self.root / 'same-owned-process.py'; other.write_bytes(path.read_bytes())
        path.unlink(); path.symlink_to(other)
        self.assert_refused_before_output()

    def test_extra_runtime_code_refused(self):
        (self.runtime / 'scripts/workflows/unreviewed.py').write_text('raise RuntimeError')
        self.assert_refused_before_output()

    def test_output_cannot_write_package_or_relative_path(self):
        for output in (self.prefix / 'output', self.stage, Path('relative-output')):
            result = self.launch('workflow', '--output', output)
            self.assertEqual(result.returncode, 2)
        self.assertFalse((self.prefix / 'output').exists())

    def test_nonempty_destination_preserved(self):
        marker = self.stage / 'user-owned'; marker.write_text('keep')
        with self.assertRaises(ValueError):
            A.assemble(HERE, self.stage)
        self.assertEqual(marker.read_text(), 'keep')

    def test_alias_and_live_destinations_refused(self):
        alias = self.root / 'alias'; alias.symlink_to(self.root, target_is_directory=True)
        for dest in (alias / 'output', Path('/'), Path('/usr'), Path.home()):
            with self.assertRaises(ValueError):
                A.assemble(HERE, dest)
        self.assertFalse((self.root / 'output').exists())

    def test_source_tamper_traversal_extra_file_refused(self):
        source = self.root / 'source'; shutil.copytree(HERE, source)
        manifest_path = source / 'payload-map.json'
        original = manifest_path.read_text()
        manifest = json.loads(original)
        manifest['files'][0]['path'] = '../escape'
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaises(ValueError):
            A.assemble(source, self.root / 'out-one')
        manifest_path.write_text(original)
        (source / 'payload/extra').write_text('extra')
        with self.assertRaises(ValueError):
            A.assemble(source, self.root / 'out-two')
        (source / 'payload/extra').unlink()
        selected = source / 'payload' / json.loads(original)['files'][0]['path']
        selected.write_bytes(selected.read_bytes() + b'changed')
        with self.assertRaises(ValueError):
            A.assemble(source, self.root / 'out-three')
        self.assertFalse(any((self.root / n).exists() for n in ('out-one', 'out-two', 'out-three')))

    def test_private_remove_reinstall_preserves_sibling_data(self):
        evidence = self.root / 'user-evidence'; evidence.write_text('retain')
        before = self.launch('verify').stdout
        shutil.rmtree(self.stage)
        self.prefix = A.assemble(HERE, self.stage)
        self.assertEqual(self.launch('verify').stdout, before)
        self.assertEqual(evidence.read_text(), 'retain')


if __name__ == '__main__':
    unittest.main(verbosity=2)
