#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import hashlib
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('desktop_source_export', HERE / 'export_source.py')
exporter = importlib.util.module_from_spec(spec); spec.loader.exec_module(exporter)


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='desktop-tools-source-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base / exporter.NAME
        shutil.copytree(HERE / exporter.NAME, self.source)
        self.output = self.base / 'source.tar.gz'

    def refused(self):
        with self.assertRaises((ValueError, OSError)):
            exporter.export(self.source, self.output)
        self.assertFalse(self.output.exists())

    def test_relocated_finite_source_exact_archive_and_recipe_pin(self):
        result = exporter.export(self.source, self.output)
        retained = (HERE / (exporter.NAME + '.tar.gz')).read_bytes()
        self.assertEqual(self.output.read_bytes(), retained)
        self.assertEqual(result['sha256'], hashlib.sha256(retained).hexdigest())
        self.assertIn("sha256sums=('" + result['sha256'] + "')", (HERE / 'PKGBUILD').read_text())

    def test_changed_source(self):
        (self.source / 'test_package.py').write_text('changed')
        self.refused()

    def test_missing_source(self):
        (self.source / 'LICENSE').unlink()
        self.refused()

    def test_extra_source(self):
        (self.source / 'unexpected.py').write_text('unexpected')
        self.refused()

    def test_symlink_source(self):
        target = self.source / 'LICENSE'; target.unlink(); target.symlink_to('/etc/passwd')
        self.refused()

    def test_fifo_source(self):
        import os
        os.mkfifo(self.source / 'unexpected-fifo')
        self.refused()

    def test_existing_output_preserved(self):
        self.output.write_text('preserve')
        with self.assertRaises(FileExistsError):
            exporter.export(self.source, self.output)
        self.assertEqual(self.output.read_text(), 'preserve')


if __name__ == '__main__':
    unittest.main(verbosity=2)
