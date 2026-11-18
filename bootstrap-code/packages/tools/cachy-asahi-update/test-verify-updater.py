#!/usr/bin/env python3
"""Private source/archive fixtures only; no updater, Cargo or compiler execution."""
import hashlib
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

BASE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('verify_updater', BASE / 'verify-updater.py')
verify = importlib.util.module_from_spec(spec);spec.loader.exec_module(verify)
spec = importlib.util.spec_from_file_location('sanitizer', BASE / 'audit-source.py')
sanitizer = importlib.util.module_from_spec(spec);spec.loader.exec_module(sanitizer)
ARCHIVE = Path('/tmp/cachy-update-portable-review-20261012/sanitized/cachy-update-e2b1b7144be71cf392809f48d1440f8da1d9c81a-sanitized.tar.gz')
VENDOR = Path('/tmp/cachy-update-portable-review-20261012/cachy-update-vendor.tar.gz')


class VerifyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='cachy-update-input-fixtures-')
        cls.original = Path(cls.temp.name) / 'original';cls.original.mkdir()
        raw = ARCHIVE.read_bytes()
        if hashlib.sha256(raw).hexdigest() != '86196b4d7be8336c321e3a033984a17e602a5e70ec5ea11126d1a249ddda8eab':
            raise ValueError('fixture source pin differs')
        for name, (data, mode) in sanitizer.inspect(raw).items():
            path = cls.original / name;path.parent.mkdir(parents=True, exist_ok=True);path.write_bytes(data);path.chmod(mode)
        for patch in ('behavior.patch', 'apple-policy.patch'):
            subprocess.run(['patch','--batch','--forward','--fuzz=0','-d',str(cls.original),'-p1','-i',str(BASE/patch)], check=True, stdout=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.temp_case = tempfile.TemporaryDirectory(prefix='cachy-update-input-case-')
        self.root = Path(self.temp_case.name) / 'source'
        shutil.copytree(self.original, self.root)

    def tearDown(self):
        self.temp_case.cleanup()

    def test_all98_patched_inputs_and_only_named_generated_outputs(self):
        self.assertEqual(verify.verify(self.root), 98)
        (self.root/'doc/man/arch-update.1').write_text('generated fixture')
        target = self.root/'src/tray/target';target.mkdir();(target/'compiled-fixture').write_text('generated')
        self.assertEqual(verify.verify(self.root), 98)

    def test_changed_shell_makefile_or_mode_refused(self):
        for name in ('Makefile', 'src/lib/full_upgrade.sh'):
            path=self.root/name;old=path.read_bytes();path.write_bytes(old+b'changed')
            with self.subTest(name=name), self.assertRaises(ValueError): verify.verify(self.root)
            path.write_bytes(old)
        path=self.root/'Makefile';path.chmod(0o755)
        with self.assertRaises(ValueError): verify.verify(self.root)

    def test_extra_library_and_missing_source_refused(self):
        path=self.root/'src/lib/unreviewed.sh';path.write_text('fixture')
        with self.assertRaisesRegex(ValueError,'extra updater input'): verify.verify(self.root)
        path.unlink();(self.root/'Makefile').unlink()
        with self.assertRaisesRegex(ValueError,'input missing'): verify.verify(self.root)

    def test_source_or_target_symlink_refused(self):
        target=self.root/'src/tray/target';target.symlink_to(self.root/'src')
        with self.assertRaisesRegex(ValueError,'symlink'): verify.verify(self.root)

    def test_wrong_vendor_pin_creates_no_notice_directory(self):
        prior=verify.HERE
        try:
            verify.HERE=Path(self.temp_case.name)/'inputs';verify.HERE.mkdir()
            shutil.copyfile(BASE/'worker-metadata.py',verify.HERE/'worker-metadata.py')
            (verify.HERE/'cachy-update-vendor.tar.gz').write_bytes(b'wrong fixture')
            destination=Path(self.temp_case.name)/'notices'
            with self.assertRaisesRegex(ValueError,'archive changed'): verify.materialize_notices(destination)
            self.assertFalse(destination.exists())
        finally: verify.HERE=prior

    def test_complete_notices_materialize_only_from_exact_vendor_bytes(self):
        prior=verify.HERE
        try:
            verify.HERE=Path(self.temp_case.name)/'inputs';verify.HERE.mkdir()
            shutil.copyfile(BASE/'worker-metadata.py',verify.HERE/'worker-metadata.py')
            shutil.copyfile(VENDOR,verify.HERE/'cachy-update-vendor.tar.gz')
            destination=Path(self.temp_case.name)/'notices'
            self.assertEqual(verify.materialize_notices(destination),1113)
            paths=[p for p in destination.rglob('*') if p.is_file()]
            self.assertEqual(len(paths),1113)
            self.assertEqual(sum(p.stat().st_size for p in paths),11735034)
            with self.assertRaisesRegex(ValueError,'fresh'): verify.materialize_notices(destination)
        finally: verify.HERE=prior


if __name__ == '__main__':
    unittest.main()
