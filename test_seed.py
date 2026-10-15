"""Finite byte-copy/cache regressions; no package execution or network."""
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('retained_seed', HERE / 'seed.py')
seed = importlib.util.module_from_spec(spec); spec.loader.exec_module(seed)


class SeedTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.source, self.cache = root / 'source', root / 'cache'
        self.source.mkdir(); self.cache.mkdir(mode=0o700)
        shutil.copyfile(HERE / 'index.json', self.source / 'index.json')
        shutil.copytree(HERE / 'inputs', self.source / 'inputs')
        self.names = sorted(path.name for path in (self.source / 'inputs').iterdir())

    def test_exact_copy_repeat_and_unrelated_cache_preservation(self):
        (self.cache / 'existing-unrelated').write_bytes(b'preserve')
        result = seed.seed(self.source, self.cache)
        self.assertEqual((result['files'], result['bytes'], result['copied']), (12, 4045396, 12))
        self.assertEqual(seed.seed(self.source, self.cache)['existing'], 12)
        for name in self.names:
            self.assertEqual((self.source / 'inputs' / name).read_bytes(), (self.cache / name).read_bytes())
            self.assertEqual((self.cache / name).stat().st_nlink, 1)
        self.assertEqual((self.cache / 'existing-unrelated').read_bytes(), b'preserve')
        self.assertFalse(list(self.cache.glob('.retained-public-*')))

    def test_missing_signature_or_extra_source_fails_before_cache_writes(self):
        signature = next(name for name in self.names if name.endswith('.sig'))
        original = (self.source / 'inputs' / signature).read_bytes()
        (self.source / 'inputs' / signature).unlink()
        with self.assertRaises(ValueError): seed.seed(self.source, self.cache)
        self.assertFalse(list(self.cache.iterdir()))
        (self.source / 'inputs' / signature).write_bytes(original)
        (self.source / 'inputs/unexpected').write_bytes(b'unselected')
        with self.assertRaises(ValueError): seed.seed(self.source, self.cache)
        self.assertFalse(list(self.cache.iterdir()))

    def test_same_size_source_tamper_or_index_tamper_refuses(self):
        path = self.source / 'inputs' / self.names[0]
        original = path.read_bytes(); path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
        with self.assertRaises(ValueError): seed.seed(self.source, self.cache)
        self.assertFalse(list(self.cache.iterdir()))
        path.write_bytes(original)
        index = self.source / 'index.json'; raw = index.read_bytes()
        index.write_bytes(raw.replace(b'"schema_version": 1', b'"schema_version": 2'))
        with self.assertRaises(ValueError): seed.seed(self.source, self.cache)
        self.assertFalse(list(self.cache.iterdir()))

    def test_existing_bad_or_symlink_cache_target_is_never_replaced(self):
        path = self.cache / self.names[0]
        path.write_bytes(b'operator bytes')
        with self.assertRaises(ValueError): seed.seed(self.source, self.cache)
        self.assertEqual(path.read_bytes(), b'operator bytes')
        path.unlink(); path.symlink_to(self.cache / 'missing')
        with self.assertRaises(ValueError): seed.seed(self.source, self.cache)
        self.assertTrue(path.is_symlink())

    def test_source_symlink_and_unsafe_cache_refuse(self):
        path = self.source / 'inputs' / self.names[0]
        path.unlink(); path.symlink_to(HERE / 'inputs' / self.names[0])
        with self.assertRaises(ValueError): seed.seed(self.source, self.cache)
        self.assertFalse(list(self.cache.iterdir()))
        self.cache.chmod(0o755)
        with self.assertRaises(ValueError): seed.seed(HERE, self.cache)

    def test_publish_collision_preserves_new_foreign_target_and_cleans_stage(self):
        link = seed.os.link
        def collision(source, target):
            target.write_bytes(b'new foreign bytes')
            return link(source, target)
        with patch.object(seed.os, 'link', side_effect=collision):
            with self.assertRaises(FileExistsError): seed.seed(self.source, self.cache)
        targets = list(self.cache.iterdir())
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].read_bytes(), b'new foreign bytes')
        self.assertFalse(list(self.cache.glob('.retained-public-*')))


if __name__ == '__main__':
    unittest.main()
