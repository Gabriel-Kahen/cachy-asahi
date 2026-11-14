#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('python_candidate_source', Path(__file__).with_name('check_source.py'))
c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)


class SourceChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='python-candidate-source-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'recipe'
        shutil.copytree(Path(__file__).parent, self.root, ignore=shutil.ignore_patterns('__pycache__'))

    def test_local_metadata_preserves_missing_archive_hold(self):
        self.assertIn('HOLD', c.check(self.root)['status'])

    def test_tampered_local_patch_and_notice_refuse(self):
        for name in ('posix-2024.patch', 'CPython-LICENSE'):
            with self.subTest(name=name):
                path = self.root / name; original = path.read_bytes(); path.write_bytes(original + b'changed')
                with self.assertRaises(AssertionError): c.check(self.root)
                path.write_bytes(original)

    def test_candidate_release_and_dependency_drift_refuse(self):
        path = self.root / 'PKGBUILD'; original = path.read_text()
        for changed in (original.replace('pkgrel=1.1', 'pkgrel=1'), original.replace("'expat'", "'different-expat'")):
            path.write_text(changed)
            with self.assertRaises(AssertionError): c.check(self.root)
        path.write_text(original)

    def test_foreign_source_and_symlink_input_refuse(self):
        bad = self.root / 'foreign.tar.xz'; bad.write_bytes(b'foreign')
        with self.assertRaises(AssertionError): c.check(self.root, bad)
        path = self.root / 'posix-2024.patch'; path.unlink(); path.symlink_to('/etc/passwd')
        with self.assertRaises(AssertionError): c.check(self.root)


if __name__ == '__main__':
    unittest.main(verbosity=2)
