#!/usr/bin/env python3
"""Focused refusal checks; never calls Docker, downloads, or package managers."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('trial', Path(__file__).with_name('trial.py'))
trial = importlib.util.module_from_spec(spec); spec.loader.exec_module(trial)


class Handoff(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.native = self.root / 'native'; self.native.mkdir()
        self.fdk = self.root / 'fdk'; self.fdk.mkdir()
        self.image = 'sha256:' + 'a' * 64
        lock = b'glibc 2.43\n'
        self.pin = hashlib.sha256(lock).hexdigest()
        (self.native / 'packages.lock').write_bytes(lock)
        (self.native / 'image-id').write_text(self.image)
        self.write(self.native / 'bootstrap.json', {'status': 'image-provisioned',
            'image_id': self.image, 'packages_lock_sha256': self.pin})
        self.write(self.native / 'result.json', {'native_build': 'PASS'})
        (self.fdk / 'result.txt').write_text('FDK_PAIR=PASS\nEXIT=0\n')
        self.name = 'cachy-asahi-fdk-aac-3.0.0-1-aarch64.pkg.tar.xz'
        self.write(self.fdk / 'compare.json', {'errors': [], 'packages': {self.name: {'bytes_equal': True}}})
        for i in (1, 2):
            path = self.fdk / f'build-{i}/artifacts'; path.mkdir(parents=True)
            (path / self.name).write_bytes(b'inert fixture, not a package')
            self.write(path.parent / 'provenance.json', {'status': 'built-package-static-pass',
                'mode': 'native', 'image_id': self.image, 'exit_code': 0,
                'expected_packages_sha256': self.pin,
                'recipe_inputs': {'PKGBUILD': '774803633213d77e9879005608ff23528b6780465c7bd00f3234430c9a7346df'},
                'artifacts': {self.name: trial.sha(path / self.name)}})

    def write(self, path, value):
        path.write_text(json.dumps(value))

    def check(self):
        return trial.package_input(self.native, self.fdk, {'base_packages_sha256': self.pin})

    def test_matching_pair(self):
        self.assertEqual(self.check()[0], self.image)

    def test_lock_drift_refused(self):
        (self.native / 'packages.lock').write_text('glibc other\n')
        with self.assertRaises(AssertionError): self.check()

    def test_skipped_pair_refused(self):
        (self.fdk / 'result.txt').write_text('FDK_PAIR=SKIPPED\nEXIT=0\n')
        with self.assertRaises(AssertionError): self.check()

    def test_changed_binary_refused(self):
        (self.fdk / f'build-2/artifacts/{self.name}').write_bytes(b'changed bytes')
        with self.assertRaises(AssertionError): self.check()

    def test_old_or_other_builder_refused(self):
        path = self.fdk / 'build-2/provenance.json'
        data = json.loads(path.read_text()); data['image_id'] = 'sha256:' + 'b' * 64
        self.write(path, data)
        with self.assertRaises(AssertionError): self.check()


if __name__ == '__main__':
    unittest.main()
