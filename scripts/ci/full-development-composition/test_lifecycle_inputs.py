#!/usr/bin/env python3
"""Focused lifecycle input checks; no package/container/build/network execution."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


inputs = load('lifecycle_inputs_under_test', 'lifecycle_inputs.py')
runner = load('lifecycle_host_under_test', 'run.py')
container = load('lifecycle_container_under_test', 'container.py')


class InputChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source, self.target = self.root / 'source', self.root / 'target'
        self.source.mkdir(); self.target.mkdir()
        self.row = {'filename': 'libfdk-aac-3.0.0-1-aarch64.pkg.tar.xz'}
        for suffix, prefix in (('', ''), ('.sig', 'signature_')):
            data = ('inert archive' + suffix).encode()
            path = self.source / (self.row['filename'] + suffix)
            path.write_bytes(data)
            self.row[prefix + 'size'] = len(data)
            self.row[prefix + 'sha256'] = runner.sha(path)

    def test_restore_preserves_existing_signature_and_refuses_drift(self):
        inputs.copy_pinned(self.row, self.source, self.target, runner)
        for path in self.source.iterdir():
            self.assertEqual(path.read_bytes(), (self.target / path.name).read_bytes())
        for suffix in ('', '.sig'):
            with self.subTest(suffix=suffix):
                target = self.root / ('target-' + (suffix or 'archive')); target.mkdir()
                path = self.source / (self.row['filename'] + suffix)
                before = path.read_bytes(); path.write_bytes(b'x' * len(before))
                with self.assertRaises(AssertionError):
                    inputs.copy_pinned(self.row, self.source, target, runner)
                path.write_bytes(before)

    def test_restore_path_escape_is_refused_before_copy(self):
        self.row['filename'] = '../escape.pkg.tar.xz'
        with self.assertRaises(AssertionError):
            inputs.copy_pinned(self.row, self.source, self.target, runner)
        self.assertEqual(list(self.target.iterdir()), [])

    def test_payload_preserves_bytes_mode_and_link_expectations(self):
        digest = hashlib.sha256(b'payload').hexdigest()
        report = {'members': {
            '.PKGINFO': {'type': '0'}, 'usr/bin': {'type': '5'},
            'usr/bin/tool': {'type': '0', 'mode': 0o755, 'sha256': digest},
            'usr/bin/alias': {'type': '2', 'mode': 0o777, 'link': 'tool'}}}
        rows = runner.payload(report)
        self.assertEqual(rows, [
            {'path': '/usr/bin/tool', 'type': 'file', 'mode': 0o755, 'sha256': digest},
            {'path': '/usr/bin/alias', 'type': 'symlink', 'mode': 0o777, 'target': 'tool'}])
        for name, kind in (('etc/pacman.conf', '0'), ('usr/bin/fifo', '6')):
            with self.subTest(name=name), self.assertRaises(AssertionError):
                runner.payload({'members': {name: {'type': kind}}})

    def test_helper_drift_blocks_loading(self):
        data = b'# inert fixed helper\n'
        digest = hashlib.sha256(data).hexdigest()
        pins = {name: digest for name in container.HELPERS}
        plan = {'helpers': {name: {'sha256': digest, 'size': len(data)} for name in pins}}
        for name in pins: (self.source / name).write_bytes(data)
        with patch.dict(container.HELPERS, pins, clear=True), patch.object(container, 'load') as execute:
            (self.source / 'core-lifecycle.py').write_bytes(b'x' * len(data))
            with self.assertRaisesRegex(ValueError, 'byte pin'):
                container.lifecycle_helpers(plan, self.source)
            execute.assert_not_called()
            (self.source / 'core-lifecycle.py').write_bytes(data)
            plan['helpers']['core-lifecycle.py']['sha256'] = 'f' * 64
            with self.assertRaisesRegex(ValueError, 'helper pin'):
                container.lifecycle_helpers(plan, self.source)
            execute.assert_not_called()


if __name__ == '__main__':
    unittest.main()
