"""Offline staging controls: no network, compiler, extraction or native actor."""
import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('offline_zlib', Path(__file__).with_name('fetch_zlib_source.py'))
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
PAYLOAD = gzip.compress(b'controlled local archive fixture', mtime=0)
FIXTURE_SHA = hashlib.sha256(PAYLOAD).hexdigest()


class LocalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'input.tar.gz'
        self.source.write_bytes(PAYLOAD)
        self.source.chmod(0o600)
        self.destination = self.root / 'output'
        self.destination.mkdir()
        self.output = self.destination / F.FILENAME
        self.enterContext(patch.object(F, 'build_opener', side_effect=AssertionError('network forbidden')))

    def stage(self, **kwargs):
        return F._local_source(self.output, self.source, expected_sha256=FIXTURE_SHA, **kwargs)

    def refused(self, reason, **kwargs):
        with self.assertRaisesRegex(F.Refused, '^' + reason + '$'):
            self.stage(**kwargs)
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_owned_private_and_regular_644_sources_publish_mode600_without_headers(self):
        for mode in (0o600, 0o644):
            with self.subTest(mode=mode):
                self.source.chmod(mode)
                result = self.stage()
                self.assertEqual(self.output.read_bytes(), PAYLOAD)
                self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
                self.assertEqual(result['source_kind'], 'local_archive')
                for key in ('source_url', 'final_origin', 'content_type', 'http_status'):
                    self.assertIsNone(result[key])
                self.assertEqual(result['bytes'], len(PAYLOAD))
                self.assertEqual(result['sha256'], FIXTURE_SHA)
                self.assertEqual(result['total_received_bytes'], len(PAYLOAD))
                self.output.unlink()

    def test_tamper_truncation_and_non_gzip_refuse_and_remove_owned_partial(self):
        for raw, reason in ((PAYLOAD + b'changed', 'sha256'), (PAYLOAD[:-1], 'sha256'), (b'plain text', 'gzip-magic')):
            with self.subTest(reason=reason):
                self.source.write_bytes(raw)
                self.refused(reason)
                self.assertEqual(self.source.read_bytes(), raw)

    def test_empty_and_oversized_sources_refuse_before_copy(self):
        for raw in (b'', b'x' * (F.MAX_BYTES + 1)):
            self.source.write_bytes(raw)
            self.refused('local-size')

    def test_symlink_and_symlink_parent_refuse(self):
        target = self.root / 'retained'
        self.source.rename(target)
        self.source.symlink_to(target)
        self.refused('local-symlink')
        self.source.unlink()
        folder = self.root / 'ordinary'
        folder.mkdir()
        (folder / 'input').write_bytes(PAYLOAD)
        link = self.root / 'parent'
        link.symlink_to(folder, target_is_directory=True)
        self.source = link / 'input'
        self.refused('local-symlink')

    def test_hardlink_fifo_directory_and_executable_sources_refuse(self):
        alias = self.root / 'alias'
        os.link(self.source, alias)
        self.refused('local-file')
        alias.unlink()
        self.source.chmod(0o700)
        self.refused('local-file')
        self.source.unlink()
        os.mkfifo(self.source)
        self.refused('local-file')
        self.source.unlink()
        self.source.mkdir()
        self.refused('local-file')

    def test_input_identity_change_before_publication_refuses(self):
        original = F._stage
        def changed(*args, **kwargs):
            self.source.write_bytes(PAYLOAD)
            return original(*args, **kwargs)
        with patch.object(F, '_stage', side_effect=changed):
            self.refused('local-changed')
        self.assertEqual(self.source.read_bytes(), PAYLOAD)

    def test_replaced_input_path_refuses_before_publication(self):
        original = F.os.fsync
        first = True
        def replaced(fd):
            nonlocal first
            original(fd)
            if first:
                first = False
                elsewhere = self.root / 'replacement'
                elsewhere.write_bytes(PAYLOAD)
                self.source.unlink()
                self.source.symlink_to(elsewhere)
        with patch.object(F.os, 'fsync', side_effect=replaced):
            self.refused('local-changed')

    def test_existing_output_and_same_source_destination_preserve_inputs(self):
        self.output.write_bytes(b'caller-owned')
        with self.assertRaisesRegex(F.Refused, '^destination-exists$'):
            self.stage()
        self.assertEqual(self.output.read_bytes(), b'caller-owned')
        self.assertEqual(self.source.read_bytes(), PAYLOAD)
        self.output.unlink()
        self.source.rename(self.output)
        self.source = self.output
        with self.assertRaisesRegex(F.Refused, '^destination-exists$'):
            self.stage()
        self.assertEqual(self.output.read_bytes(), PAYLOAD)

    def test_deadline_refuses_and_cleans(self):
        ticks = iter((0, F.SECONDS + 1))
        self.refused('deadline', clock=lambda: next(ticks))

    def test_unowned_and_symlink_loop_refuse_without_network(self):
        with patch.object(F.os, 'getuid', return_value=os.getuid() + 1):
            self.refused('local-file')
        self.source.unlink()
        self.source.symlink_to(self.source)
        self.refused('local-symlink')

    def test_missing_source_never_uses_network(self):
        self.source.unlink()
        with self.assertRaisesRegex(F.Refused, '^local-filesystem$'):
            self.stage()
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_public_cli_enforces_fixed_sha_and_safe_receipt_without_input_path(self):
        receipt = self.destination / 'zlib-source-retrieval.json'
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = F.main(['--output', str(self.output), '--receipt', str(receipt), '--local-archive', str(self.source)])
        self.assertEqual(code, 1)
        result = json.loads(receipt.read_bytes())
        self.assertEqual(result['reason'], 'sha256')
        self.assertEqual(result['source_kind'], 'local_archive')
        self.assertNotIn(str(self.source), json.dumps(result))
        self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o600)
        self.assertEqual(list(self.destination.iterdir()), [receipt])


if __name__ == '__main__':
    unittest.main()
