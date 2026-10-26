import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('static_apt_cache', Path(__file__).with_name('static_apt_cache.py'))
cache = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cache)


class CacheControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'raw'
        self.source.mkdir()
        self.target = self.root / 'verified'
        self.data = b'authenticated archive fixture'
        self.name = 'test_1%3a2.0-1_amd64.deb'
        self.row = {'size': len(self.data), 'sha256': hashlib.sha256(self.data).hexdigest()}
        self.rows = {self.name: self.row}

    def parse(self, row):
        path = self.root / 'plan'
        path.write_text(row)
        return cache.read_plan(path)

    def test_plan_uses_fresh_sha256_and_safe_apt_escaped_filename(self):
        self.assertEqual(self.parse(f"Reading package lists...\n'https://mirror/pool/test.deb' {self.name} {len(self.data)} SHA256:{self.row['sha256']}\n"), self.rows)

    def test_weak_missing_malformed_duplicate_or_path_hash_rows_refused(self):
        valid = f"'https://mirror/test.deb' {self.name} {len(self.data)} SHA256:{self.row['sha256']}"
        for text in (valid.replace('SHA256:', 'MD5Sum:'), valid.replace(self.name, '../test.deb'), valid.replace(self.name, '/test.deb'), valid.replace(str(len(self.data)), '0'), valid + '\n' + valid, "'https://mirror/test.deb' malformed"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.parse(text)

    def test_changed_dependency_bytes_or_version_changes_cache_key(self):
        for rows in ({'test_2_amd64.deb': self.row}, {self.name: dict(self.row, sha256='0' * 64)}, {self.name: dict(self.row, size=100)}):
            self.assertNotEqual(cache.plan_key(self.rows), cache.plan_key(rows))

    def test_valid_hit_copied_to_fresh_directory(self):
        (self.source / self.name).write_bytes(self.data)
        report = cache.transfer(self.rows, self.source, self.target, fresh=True)
        self.assertEqual(report['verified'], 1)
        self.assertEqual((self.target / self.name).read_bytes(), self.data)

    def test_same_size_poison_missing_truncated_symlink_and_fifo_are_misses(self):
        archive = self.source / self.name
        for kind in ('missing', 'poison', 'truncated', 'symlink', 'fifo'):
            with self.subTest(kind=kind):
                if archive.exists() or archive.is_symlink():
                    archive.unlink()
                if kind == 'poison': archive.write_bytes(b'X' * len(self.data))
                if kind == 'truncated': archive.write_bytes(self.data[:-1])
                if kind == 'symlink': archive.symlink_to(self.root / 'external')
                if kind == 'fifo': cache.os.mkfifo(archive)
                target = self.root / kind
                self.assertEqual(cache.transfer(self.rows, self.source, target, fresh=True)['verified'], 0)
                self.assertEqual(list(target.iterdir()), [])

    def test_unrequested_archive_never_staged(self):
        (self.source / 'extra.deb').write_bytes(self.data)
        self.assertEqual(cache.transfer(self.rows, self.source, self.target, fresh=True)['verified'], 0)
        self.assertEqual(list(self.target.iterdir()), [])

    def test_existing_stage_and_symlink_roots_refused(self):
        self.target.mkdir()
        with self.assertRaises(FileExistsError):
            cache.transfer(self.rows, self.source, self.target, fresh=True)
        self.target.rmdir()
        self.target.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(ValueError):
            cache.transfer(self.rows, self.source, self.target, fresh=True)

    def test_export_rechecks_bytes_and_replaces_destination_symlink(self):
        archive = self.source / self.name
        archive.write_bytes(self.data)
        self.target.mkdir()
        external = self.root / 'external'
        external.write_bytes(b'untouched')
        (self.target / self.name).symlink_to(external)
        self.assertEqual(cache.transfer(self.rows, self.source, self.target, fresh=False)['verified'], 1)
        self.assertEqual(external.read_bytes(), b'untouched')
        self.assertFalse((self.target / self.name).is_symlink())
        archive.write_bytes(b'X' * len(self.data))
        self.assertEqual(cache.transfer(self.rows, self.source, self.target, fresh=False)['verified'], 0)

    def test_empty_plan_is_valid_no_download_transaction(self):
        self.assertEqual(self.parse('0 newly installed\n'), {})


if __name__ == '__main__':
    unittest.main()
