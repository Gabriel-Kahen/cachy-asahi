#!/usr/bin/env python3
"""Host-safe data-only source sanitizer regression checks."""
import importlib.util
import io
import tarfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('audit_source', Path(__file__).with_name('audit-source.py'))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def archive(name, kind=tarfile.REGTYPE, size=1):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:gz') as tar:
        entry = tarfile.TarInfo(name)
        entry.type, entry.size = kind, size if kind == tarfile.REGTYPE else 0
        tar.addfile(entry, io.BytesIO(b'x' * size) if kind == tarfile.REGTYPE else None)
    return buffer.getvalue()


class SourceTests(unittest.TestCase):
    def test_regular_source_is_data(self):
        data = audit.inspect(archive(audit.ROOT + '/build.rs'))
        self.assertEqual(data['build.rs'][0], b'x')

    def test_escape_absolute_wrong_root_and_links_refused(self):
        for name in ('/host/file', audit.ROOT + '/../escape', 'other/file'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                audit.inspect(archive(name))
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                audit.inspect(archive(audit.ROOT + '/file', kind))

    def test_original_icons_all_have_explicit_grant(self):
        root = Path(__file__).with_name('icons')
        self.assertEqual({p.name for p in root.iterdir()}, audit.ICONS)
        for path in root.iterdir():
            self.assertIn('SPDX-License-Identifier: MIT', path.read_text())


if __name__ == '__main__':
    unittest.main()
