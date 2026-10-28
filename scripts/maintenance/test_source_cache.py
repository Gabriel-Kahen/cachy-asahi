#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real private-tree/CLI controls; narrowly mocked HTTPS transport only."""
import copy
import hashlib
import io
import json
import multiprocessing
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import source_cache as m


def pin(raw):
    return dict(sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))


class Response(io.BytesIO):
    status = 200
    url = 'https://example.invalid/revision.tar.gz'

    def __init__(self, raw, headers=None):
        super().__init__(raw)
        self.headers = headers if headers is not None else {'Content-Length': str(len(raw))}


class Sender:
    def send(self, value): self.value = value
    def close(self): pass


def stalled(*args):
    time.sleep(5)


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.cache = self.base / 'cache'
        self.raw = b'opaque source data, never extracted\x00\xff'
        self.notice = b'SYNTHETIC MIT license evidence\n'
        (self.base / 'NOTICE').write_bytes(self.notice)
        self.row = dict(material=dict(id='source-1', path='upstream/source.tar.gz', **pin(self.raw)),
                        url=Response.url, revision='SYNTHETIC-exact-revision', license='MIT',
                        license_evidence=[dict(id='notice-1', path='NOTICE', **pin(self.notice))])
        self.data = dict(schema_version=1, purpose='source-cache-inputs', sources=[self.row])
        self.path = self.base / 'inputs.json'
        self.save()
        m.initialize(self.cache)

    def save(self):
        self.path.write_bytes(m.encoded(self.data))
        self.sha = pin(self.path.read_bytes())['sha256']

    def run_cache(self, offline=True, **kwargs):
        return m.run(self.cache, self.path, self.sha, ['source-1'], offline, **kwargs)

    def seed(self):
        (self.cache / 'objects' / self.row['material']['sha256']).write_bytes(self.raw)
        (self.cache / 'objects' / self.row['material']['sha256']).chmod(0o600)
        # Offline reuse in acquire requires no network when the object exists.
        with patch.object(m, 'transport', side_effect=AssertionError('network attempted')):
            return self.run_cache(False)

    def cli(self, command, *args):
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        env['PYTHONPATH'] = str(Path(m.sd.__file__).parent)
        return subprocess.run([sys.executable, '-B', str(Path(m.__file__)), command,
                               '--cache', str(self.cache), *args], capture_output=True, text=True, env=env, timeout=10)

    def cli_inputs(self):
        return ['--inputs', str(self.path), '--inputs-sha256', self.sha, '--id', 'source-1']

    def test_real_cli_reuse_and_verify_exact_provenance(self):
        self.seed()
        for command in ('acquire', 'verify'):
            result = self.cli(command, *self.cli_inputs())
            self.assertEqual(result.returncode, 0, result.stderr)
            value = json.loads(result.stdout)
            self.assertEqual(value['sources'][0]['status'], 'verified')
            self.assertFalse(value['legal_acceptance'])
        receipt = json.loads(next((self.cache / 'receipts').iterdir()).read_bytes())
        self.assertEqual(receipt['source'], self.row)
        self.assertEqual(receipt['inputs_sha256'], self.sha)
        self.assertFalse(receipt['source_completeness_accepted'])

    def test_real_cli_initialization_is_fresh_and_private(self):
        result = self.cli('init')
        self.assertEqual(result.returncode, 1)
        self.cache = self.base / 'fresh'
        self.assertEqual(self.cli('init').returncode, 0)
        self.assertEqual(self.cache.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.cache / 'FORMAT').stat().st_mode & 0o777, 0o600)

    def test_offline_missing_object_never_calls_transport(self):
        with patch.object(m, 'transport', side_effect=AssertionError('network attempted')):
            self.assertEqual(self.cli('verify', *self.cli_inputs()).returncode, 1)
            with self.assertRaisesRegex(m.sd.Error, 'offline source object missing'):
                self.run_cache()

    def test_offline_missing_receipt_is_read_only(self):
        self.seed()
        next((self.cache / 'receipts').iterdir()).unlink()
        with self.assertRaisesRegex(m.sd.Error, 'offline provenance receipt missing'):
            self.run_cache()
        self.assertEqual(list((self.cache / 'receipts').iterdir()), [])

    def test_tampered_object_retained_without_redownload(self):
        self.seed(); obj = self.cache / 'objects' / self.row['material']['sha256']
        obj.write_bytes(b'corrupt')
        with patch.object(m, 'transport', side_effect=AssertionError('network attempted')):
            with self.assertRaises(m.sd.Error): self.run_cache(False)
        self.assertEqual(obj.read_bytes(), b'corrupt')

    def test_tampered_receipt_retained(self):
        self.seed(); receipt = next((self.cache / 'receipts').iterdir()); receipt.write_bytes(b'corrupt')
        with self.assertRaisesRegex(m.sd.Error, 'provenance receipt mismatch'): self.run_cache(False)
        self.assertEqual(receipt.read_bytes(), b'corrupt')

    def test_input_checksum_and_license_evidence_required(self):
        for target in (self.path, self.base / 'NOTICE'):
            old = target.read_bytes(); target.write_bytes(old + b'!')
            with self.assertRaises(m.sd.Error): self.run_cache(False)
            target.write_bytes(old)

    def test_explicit_selection(self):
        for selected in ([], ['missing'], ['source-1', 'source-1']):
            with self.assertRaises(m.sd.Error):
                m.run(self.cache, self.path, self.sha, selected)

    def test_unselected_sources_not_acquired(self):
        extra = copy.deepcopy(self.row); extra['material']['id'] = 'not-selected'
        extra['material']['sha256'] = 'f' * 64
        self.data['sources'].append(extra); self.save(); self.seed()
        self.assertEqual(len(list((self.cache / 'objects').iterdir())), 1)

    def test_descriptor_schema_rejections(self):
        original = copy.deepcopy(self.data)
        changes = [lambda: self.row['material'].update(bytes=True),
                   lambda: self.row['material'].update(bytes=m.sd.MAX_FILE + 1),
                   lambda: self.row['material'].update(sha256='A' * 64),
                   lambda: self.row['material'].update(path='../escape'),
                   lambda: self.row.update(license=''),
                   lambda: self.row.update(revision=''),
                   lambda: self.row.update(license_evidence=[]),
                   lambda: self.data.update(extra=True),
                   lambda: self.data.update(schema_version=True),
                   lambda: self.data['sources'].append(copy.deepcopy(self.row))]
        for mutate in changes:
            self.data = copy.deepcopy(original); self.row = self.data['sources'][0]
            mutate(); self.save()
            with self.subTest(data=self.data):
                with self.assertRaises(m.sd.Error): self.run_cache(False)

    def test_duplicate_json_keys_refused(self):
        self.path.write_bytes(b'{"schema_version":1,"schema_version":1}')
        self.sha = pin(self.path.read_bytes())['sha256']
        with self.assertRaises(m.sd.Error): self.run_cache(False)

    def test_credentials_queries_fragments_and_non_https_refused(self):
        for url in ('http://example.invalid/x', 'https://user:pass@example.invalid/x',
                    'https://example.invalid/x?token=secret', 'https://example.invalid/x#secret',
                    'https://example.invalid/x?', 'https://example.invalid:444/x',
                    'https://example.invalid/\nx', 'https://example.invalid\\other/x',
                    'https://%75ser@example.invalid/x', 'file:///tmp/data'):
            self.row['url'] = url; self.save()
            with self.subTest(url=url):
                with self.assertRaises((m.sd.Error, ValueError)): self.run_cache(False)

    def test_byte_and_time_bounds(self):
        for kwargs in (dict(maximum=1), dict(maximum=True), dict(maximum=m.sd.MAX_TOTAL + 1),
                       dict(seconds=0), dict(seconds=float('nan')), dict(seconds=float('inf')),
                       dict(seconds=m.MAX_SECONDS + 1), dict(seconds=True)):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(m.sd.Error): self.run_cache(False, **kwargs)

    def test_unsafe_root_child_and_object_controls(self):
        self.seed()
        targets = [self.cache, self.cache / 'objects', self.cache / 'receipts', self.cache / '.partial',
                   self.cache / 'objects' / self.row['material']['sha256']]
        for target in targets:
            target.rename(str(target) + '-real'); target.symlink_to(str(target) + '-real')
            with self.subTest(path=target):
                with self.assertRaises((m.sd.Error, OSError)): self.run_cache(False)
            target.unlink(); Path(str(target) + '-real').rename(target)
        for target in targets:
            mode = target.stat().st_mode & 0o777; target.chmod(mode | 0o020)
            with self.assertRaises(m.sd.Error): self.run_cache(False)
            target.chmod(mode)

    def test_symlink_ancestor_and_unsafe_initialization(self):
        alias = self.base / 'alias'; alias.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(OSError): m.initialize(alias / 'new')
        with self.assertRaises(m.sd.Error): m.initialize(Path('relative'))
        with self.assertRaises(m.sd.Error): m.initialize(self.base / '..' / 'escape')
        self.assertFalse((self.base / 'new').exists())

    def test_fifo_and_hardlink_refused(self):
        obj = self.cache / 'objects' / self.row['material']['sha256']
        os.mkfifo(obj, 0o600)
        with self.assertRaises(m.sd.Error): self.run_cache(False)
        obj.unlink(); self.seed(); os.link(obj, self.base / 'hardlink')
        with self.assertRaises(m.sd.Error): self.run_cache(False)

    def test_atomic_no_replace_publication(self):
        root = m.sd.directory(self.cache)
        pfd = m.open_dir('.partial', root)
        ofd = m.open_dir('objects', root)
        try:
            name, fd = m.temporary(pfd); os.close(fd)
            (self.cache / 'objects' / 'existing').write_bytes(b'preserved')
            with self.assertRaises(FileExistsError): m.publish(pfd, name, ofd, 'existing')
            self.assertEqual((self.cache / 'objects' / 'existing').read_bytes(), b'preserved')
        finally:
            os.close(pfd); os.close(ofd); os.close(root)

    def test_real_worker_deadline_and_partial_cleanup(self):
        started = time.monotonic(); children = {child.pid for child in multiprocessing.active_children()}
        with patch.object(m, 'download', stalled):
            with self.assertRaisesRegex(m.sd.Error, 'wall-clock deadline'):
                self.run_cache(False, seconds=0.05)
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual({child.pid for child in multiprocessing.active_children()}, children)
        self.assertEqual(list((self.cache / '.partial').iterdir()), [])
        self.assertEqual(list((self.cache / 'objects').iterdir()), [])

    def test_transport_rejections_do_not_publish(self):
        for response in (Response(self.raw[:-1], {}), Response(self.raw + b'!', {}),
                         Response(b'x' * len(self.raw), {}), Response(self.raw, {'Content-Length': '0'}),
                         Response(self.raw, {'Content-Encoding': 'gzip'})):
            with self.subTest(response=response):
                with patch.object(m.urllib.request, 'build_opener') as factory:
                    factory.return_value.open.return_value = response
                    with self.assertRaises(m.sd.Error): self.run_cache(False)
                self.assertEqual(list((self.cache / '.partial').iterdir()), [])
                self.assertEqual(list((self.cache / 'objects').iterdir()), [])
                self.assertEqual(list((self.cache / 'receipts').iterdir()), [])

    def test_unexpected_response_status_and_url_refused(self):
        for field, value in (('status', 206), ('url', 'https://elsewhere.invalid/x')):
            response = Response(self.raw); setattr(response, field, value)
            with patch.object(m.urllib.request, 'build_opener') as factory:
                factory.return_value.open.return_value = response
                with self.assertRaises(m.sd.Error): self.run_cache(False)
            self.assertEqual(list((self.cache / 'objects').iterdir()), [])

    def test_mocked_https_success_real_process_and_files(self):
        with patch.object(m.urllib.request, 'build_opener') as factory:
            factory.return_value.open.return_value = Response(self.raw)
            result = self.run_cache(False)
        self.assertEqual(result['sources'][0]['status'], 'acquired')
        self.assertEqual(self.run_cache()['sources'][0]['status'], 'verified')
        self.assertEqual(list((self.cache / '.partial').iterdir()), [])
        self.assertEqual((self.cache / 'objects' / self.row['material']['sha256']).read_bytes(), self.raw)

    def test_redirect_and_network_exception_refused(self):
        with self.assertRaises(m.sd.Error):
            m.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://elsewhere.invalid/x')
        with patch.object(m.urllib.request, 'build_opener') as factory:
            factory.return_value.open.side_effect = OSError('synthetic transport failure')
            with self.assertRaises(m.sd.Error): self.run_cache(False)
        self.assertEqual(list((self.cache / '.partial').iterdir()), [])

    def test_separate_provenance_for_identical_content(self):
        self.seed(); self.row['revision'] = 'second caller provenance'; self.save()
        self.seed()
        self.assertEqual(len(list((self.cache / 'objects').iterdir())), 1)
        self.assertEqual(len(list((self.cache / 'receipts').iterdir())), 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
