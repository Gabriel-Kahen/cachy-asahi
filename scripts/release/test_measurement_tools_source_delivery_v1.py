# SPDX-License-Identifier: MIT
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest

ROOT = None


class Closure(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='measurement-source-')
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.root = self.work / 'relocated source'
        shutil.copytree(ROOT, self.root)
        self.profile = self.root / 'manifests/measurement-tools-source-20261028.json'
        self.pin = hashlib.sha256(self.profile.read_bytes()).hexdigest()
        spec = importlib.util.spec_from_file_location('measurement_export', self.root / 'scripts/release/measurement_tools_source_delivery_v1.py')
        self.exporter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.exporter)

    def export(self, name, pin=None):
        return self.exporter.export(self.root, self.profile, pin or self.pin, self.work / name)

    def test_exact_relocated_deterministic_closure(self):
        first, second = self.export('one.tar'), self.export('two.tar')
        self.assertEqual(first['sha256'], second['sha256'])
        with tarfile.open(first['archive']) as archive:
            members = archive.getmembers()
            self.assertEqual(len(members), len(json.loads(self.profile.read_text())['files']) + 1)
            self.assertEqual([m.name for m in members], sorted(m.name for m in members))
            self.assertTrue(all(m.isfile() and m.uid == m.gid == m.mtime == 0 for m in members))
            self.assertIn('packages/tools/cachy-asahi-measurement-tools/PKGBUILD', archive.getnames())

    def test_changed_source_refused_before_output(self):
        source = self.root / 'packages/tools/cachy-asahi-measurement-tools/benchmark.py'
        source.write_bytes(source.read_bytes() + b'\n')
        with self.assertRaisesRegex(ValueError, 'source bytes differ'):
            self.export('tampered.tar')
        self.assertFalse((self.work / 'tampered.tar').exists())

    def test_profile_pin_symlink_and_extra_recipe_refused(self):
        with self.assertRaisesRegex(ValueError, 'profile SHA256'):
            self.export('pin.tar', '0' * 64)
        source = self.root / 'packages/tools/cachy-asahi-measurement-tools/NOTICE'
        raw = source.read_bytes()
        replacement = self.work / 'notice'
        replacement.write_bytes(raw)
        source.unlink()
        source.symlink_to(replacement)
        with self.assertRaisesRegex(ValueError, 'ordinary file'):
            self.export('symlink.tar')
        source.unlink()
        source.write_bytes(raw)
        (source.parent / 'unlisted.py').write_text('# unexpected source\n')
        with self.assertRaisesRegex(ValueError, 'namespace differs'):
            self.export('extra.tar')

    def test_output_overwrite_and_mode_tamper_refused(self):
        self.export('held.tar')
        with self.assertRaisesRegex(ValueError, 'fresh ordinary output'):
            self.export('held.tar')
        source = self.root / 'packages/tools/cachy-asahi-measurement-tools/cachy-asahi-measurement-tools'
        source.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'source mode differs'):
            self.export('mode.tar')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', required=True, type=Path)
    args = parser.parse_args()
    ROOT = args.root.resolve(strict=True)
    unittest.main(argv=[__file__], verbosity=2)
