#!/usr/bin/env python3
"""Exercise real file/symlink restoration checks without invoking pacman."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('provider_container', Path(__file__).with_name('container.py'))
container = importlib.util.module_from_spec(spec); spec.loader.exec_module(container)


class UpstreamRestore(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.real = self.root / 'libfdk-xhe-aac.so.0.0.0'
        self.real.write_bytes(b'inert upstream library fixture')
        self.alias = self.root / 'libfdk-xhe-aac.so.0'
        self.alias.symlink_to(self.real.name)
        self.owner = patch.object(container, 'run', return_value=subprocess.CompletedProcess(
            [], 0, stdout='libfdk-aac\n', stderr='')).start()
        self.addCleanup(patch.stopall)
        self.before = container.library_identity(self.alias, 'libfdk-aac')

    def test_present_upstream_library_restores(self):
        self.assertTrue(self.alias.exists())  # The old absence assertion rejected this valid baseline.
        self.assertEqual(container.library_identity(self.alias, 'libfdk-aac', self.before), self.before)
        self.owner.assert_called_with(['pacman', '-Qqo', str(self.real)])

    def test_changed_bytes_refused(self):
        self.real.write_bytes(b'wrong restored bytes')
        with self.assertRaises(AssertionError):
            container.library_identity(self.alias, 'libfdk-aac', self.before)

    def test_changed_target_refused_even_with_same_bytes(self):
        other = self.root / 'other.so'; other.write_bytes(self.real.read_bytes())
        self.alias.unlink(); self.alias.symlink_to(other.name)
        with self.assertRaises(AssertionError):
            container.library_identity(self.alias, 'libfdk-aac', self.before)

    def test_wrong_owner_refused(self):
        self.owner.return_value.stdout = 'cachy-asahi-fdk-aac\n'
        with self.assertRaises(AssertionError):
            container.library_identity(self.alias, 'libfdk-aac', self.before)

    def test_missing_restored_library_refused(self):
        self.real.unlink()
        with self.assertRaises(FileNotFoundError):
            container.library_identity(self.alias, 'libfdk-aac', self.before)


if __name__ == '__main__':
    unittest.main()
