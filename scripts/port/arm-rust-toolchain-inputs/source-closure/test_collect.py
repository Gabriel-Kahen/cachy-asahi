#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
import urllib.error
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('collect', HERE / 'collect.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class SourceControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cache = self.root / 'cache'
        self.cache.mkdir()
        self.manifest = json.loads((HERE / 'source-inputs.json').read_text())

    def test_all_retained_recipe_bytes_still_mismatch_BUILDINFO(self):
        rows = m.recipe_correspondence()
        self.assertEqual(len(rows), 4)
        self.assertFalse(any(row['exact_byte_match'] for row in rows))

    def test_local_materials_exact_and_data_only(self):
        for name, record in self.manifest['materials'].items():
            m.verify_file(HERE / name, {'bytes': record['bytes'], 'checksums': {'sha256': record['sha256']}})

    def test_checksum_tamper_refusal(self):
        path = self.cache / 'source'
        path.write_bytes(b'original')
        record = {'checksums': m.checksums(path)}
        path.write_bytes(b'changed!')
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            m.verify_file(path, record)

    def test_persistent_four_request_cap(self):
        (self.root / 'http-ledger.json').write_text(json.dumps([{}] * 4))
        budget = m.Budget(self.cache, self.manifest['budgets'], self.manifest['archives'])
        budget.opener = Mock()
        with self.assertRaisesRegex(ValueError, 'four-request budget'):
            budget.open('https://static.rust-lang.org/source', 10**30)
        budget.opener.open.assert_not_called()

    def test_redirects_count_and_queries_are_redacted(self):
        budget = m.Budget(self.cache, self.manifest['budgets'], self.manifest['archives'])
        url = 'https://github.com/llvm/source'
        redirect = urllib.error.HTTPError(url, 302, 'redirect',
                                         {'Location': 'https://release-assets.githubusercontent.com/source?token=private'}, None)
        response = SimpleNamespace(status=200)
        budget.opener = Mock()
        budget.opener.open.side_effect = [redirect, response]
        self.assertIs(budget.open(url, 10**30), response)
        self.assertEqual(len(budget.requests), 2)
        self.assertTrue(budget.requests[1]['query_redacted'])
        self.assertNotIn('private', (self.root / 'http-ledger.json').read_text())

    def test_three_GiB_free_floor_refuses(self):
        budget = m.Budget(self.cache, self.manifest['budgets'], self.manifest['archives'])
        with patch.object(m.os, 'statvfs', return_value=SimpleNamespace(f_bavail=3 * 1024**3, f_frsize=1)):
            with self.assertRaisesRegex(ValueError, 'below3GiB'):
                budget.free(1)

    def test_archive_cap_and_symlink_refusal(self):
        path = self.cache / 'rustc-1.99.0-src.tar.xz'
        path.symlink_to(self.root)
        budget = m.Budget(self.cache, self.manifest['budgets'], self.manifest['archives'])
        with self.assertRaisesRegex(ValueError, 'nonregular'):
            budget.archive_bytes()

    def test_tmp_only(self):
        with self.assertRaisesRegex(ValueError, 'below /tmp'):
            m.tmp_path(Path('/home/forbidden-source-cache'))


if __name__ == '__main__':
    unittest.main()
