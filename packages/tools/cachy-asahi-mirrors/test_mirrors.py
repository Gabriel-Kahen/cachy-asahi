# SPDX-License-Identifier: MIT
import copy
import hashlib
import io
import json
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

M = runpy.run_path(str(Path(__file__).with_name('cachy-asahi-mirrors')))
BODY = b'exact selected repository database\n'


def fixture():
    return dict(schema_version=1, architecture='aarch64', base='asahi-alarm', repository='core',
        database=dict(bytes=len(BODY), sha256=hashlib.sha256(BODY).hexdigest()),
        mirrors=[dict(id='one', server='https://one.example/$arch/$repo'),
                 dict(id='two', server='https://two.example/$arch/$repo')])


class Response(io.BytesIO):
    status = 200
    headers = {}


class Mirrors(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def read(self, value):
        p = self.root/'catalog.json'
        p.write_text(json.dumps(value))
        return M['catalog'](p)

    def test_valid_catalog_is_local(self):
        with patch('urllib.request.build_opener', side_effect=AssertionError('network')):
            value, digest = self.read(fixture())
        self.assertEqual(value, fixture())
        self.assertEqual(len(digest), 64)

    def test_platform_and_reference_required(self):
        for field, replacement in [('architecture', 'x86_64'), ('base', 'archlinux'),
                                   ('repository', 'core\nServer=bad'), ('database', {'bytes': 1})]:
            value = fixture(); value[field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.read(value)

    def test_bad_server_templates(self):
        for server in ['http://one.example/$arch/$repo', 'https://u:p@one.example/$arch/$repo',
                       'https://one.example/$arch/$repo?token=x', 'https://one.example/$architecture/$repo',
                       'https://one.example/$arch/../$repo', 'https://one.example/$arch/$repo\n',
                       'https://one.example/$arch/%2e%2e/$repo', 'https://$arch.example/$repo']:
            value = fixture(); value['mirrors'][0]['server'] = server
            with self.subTest(server=server), self.assertRaises(ValueError):
                self.read(value)

    def test_duplicate_ids_and_servers(self):
        for field in ['id', 'server']:
            value = fixture(); value['mirrors'][1][field] = value['mirrors'][0][field]
            with self.assertRaises(ValueError):
                self.read(value)

    def test_duplicate_json_keys_refused(self):
        p = self.root/'catalog.json'; p.write_text('{"base":1,"base":2}')
        with self.assertRaises(ValueError):
            M['catalog'](p)

    def probe(self, body, headers=None, deadline=1000):
        response = Response(body)
        response.headers = headers or {}
        class Opener:
            def open(self, request, timeout):
                self.request = request; self.timeout = timeout
                return response
        opener = Opener()
        with patch('time.monotonic', return_value=1):
            result = M['probe'](fixture()['mirrors'][0], fixture(), opener, deadline)
        return result, opener

    def test_exact_bytes_and_url_required(self):
        result, opener = self.probe(BODY)
        self.assertEqual(result['status'], 'PASS_EXACT_SNAPSHOT')
        self.assertEqual(opener.request.full_url, 'https://one.example/aarch64/core/core.db')
        self.assertEqual(opener.timeout, 10)

    def test_stale_truncated_and_oversized_database_refused(self):
        for body in [BODY[:-1], BODY+b'x', b'x'*len(BODY)]:
            result, _ = self.probe(body)
            self.assertEqual(result['status'], 'FAIL')

    def test_headers_and_total_deadline(self):
        for headers in [{'Content-Length': '1'}, {'Content-Encoding': 'gzip'}]:
            self.assertEqual(self.probe(BODY, headers)[0]['status'], 'FAIL')
        self.assertEqual(self.probe(BODY, deadline=0)[0]['status'], 'FAIL')

    def test_redirects_never_followed(self):
        with self.assertRaises(ValueError):
            M['NoRedirect']().redirect_request(None, None, 302, 'moved', {}, 'https://other.example')

    def test_candidate_has_only_exact_matches_in_measured_order(self):
        output = self.root/'candidate'
        def result(row, config, opener, deadline):
            return dict(row, status='PASS_EXACT_SNAPSHOT', elapsed_seconds=2 if row['id']=='one' else 1)
        with patch.dict(M['rank'].__globals__, probe=result):
            report = M['rank'](fixture(), 'a'*64, output)
        self.assertEqual(report['status'], 'PASS_CANDIDATE_WRITTEN')
        text = output.read_text()
        self.assertLess(text.index('two.example'), text.index('one.example'))
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(report['activation'], 'NOT_PERFORMED')

    def test_all_failed_creates_no_candidate(self):
        output = self.root/'candidate'
        def failed(row, config, opener, deadline):
            return dict(row, status='FAIL', elapsed_seconds=1, reason='different snapshot')
        with patch.dict(M['rank'].__globals__, probe=failed):
            report = M['rank'](fixture(), 'a'*64, output)
        self.assertEqual(report['status'], 'FAIL')
        self.assertFalse(output.exists())

    def test_publication_preserves_existing_file_and_symlink(self):
        output = self.root/'existing'; output.write_bytes(b'user data')
        alias = self.root/'alias'; alias.symlink_to(output.name)
        for target in [output, alias]:
            with self.assertRaises(FileExistsError):
                M['publish'](target, b'candidate')
        self.assertEqual(output.read_bytes(), b'user data')
        self.assertTrue(alias.is_symlink())
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ['alias', 'existing'])


if __name__ == '__main__':
    unittest.main()
