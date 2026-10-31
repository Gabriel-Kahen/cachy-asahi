#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import hashlib
import copy
import gzip
import io
import json
import os
import sys
import tarfile
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('desktop_source_export', HERE / 'export_source.py')
exporter = importlib.util.module_from_spec(spec); spec.loader.exec_module(exporter)


def deny_actors(event, args):
    if event.startswith(('subprocess.', 'socket.')) or event in {'os.system', 'os.posix_spawn', 'os.fork', 'os.exec'}:
        raise AssertionError('source DATA controls prohibit actor: ' + event)
sys.addaudithook(deny_actors)


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='desktop-tools-source-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base / exporter.NAME
        shutil.copytree(HERE / exporter.NAME, self.source)
        self.output = self.base / 'source.tar.gz'

    def refused(self):
        with self.assertRaises((ValueError, OSError)):
            exporter.export(self.source, self.output)
        self.assertFalse(self.output.exists())

    def assert_semantic(self, path):
        raw = path.read_bytes()
        result = exporter.validate_archive(self.source, path, hashlib.sha256(raw).hexdigest())
        self.assertEqual(result['status'], 'PASS_EXACT_CANONICAL_SOURCE_ARCHIVE')
        self.assertEqual(result['tar_sha256'], hashlib.sha256(exporter.canonical_tar(self.source)).hexdigest())
        return result

    def archive(self, raw):
        path = self.base / 'alternative.tar.gz'
        path.write_bytes(gzip.compress(raw, compresslevel=1, mtime=0))
        return path

    def tar_variant(self, change):
        canonical = exporter.canonical_tar(self.source)
        with tarfile.open(fileobj=io.BytesIO(canonical), mode='r:') as archive:
            rows = [(copy.copy(member), archive.extractfile(member).read()) for member in archive]
        rows = change(rows)
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for info, raw in rows:
                archive.addfile(info, io.BytesIO(raw))
        return self.archive(buffer.getvalue())

    def assert_archive_refused(self, path):
        with self.assertRaises(ValueError):
            exporter.validate_archive(self.source, path, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_relocated_finite_source_semantics_and_independent_recipe_pin(self):
        result = exporter.export(self.source, self.output)
        generated = self.output.read_bytes()
        self.assertEqual(result, dict(bytes=len(generated), sha256=hashlib.sha256(generated).hexdigest()))
        retained = HERE / (exporter.NAME + '.tar.gz')
        retained_sha = hashlib.sha256(retained.read_bytes()).hexdigest()
        self.assertEqual(retained_sha, '69d8c7bb3a13086d4b3ae5a46fa79db14ef4a034912bacb9f185ccc4d54b0ba4')
        self.assertIn("sha256sums=('" + retained_sha + "')", (HERE / 'PKGBUILD').read_text())
        self.assertEqual(self.assert_semantic(self.output)['tar_sha256'], self.assert_semantic(retained)['tar_sha256'])

    def test_repeat_export_same_backend_is_byte_deterministic(self):
        exporter.export(self.source, self.output)
        other = self.base / 'second.tar.gz'
        exporter.export(self.source, other)
        self.assertEqual(self.output.read_bytes(), other.read_bytes())
        self.assertEqual(self.output.read_bytes()[:8], b'\x1f\x8b\x08\x00\x00\x00\x00\x00')

    def test_different_gzip_encodings_preserve_source_semantics(self):
        canonical = exporter.canonical_tar(self.source)
        first = self.base / 'level1.tar.gz'; second = self.base / 'level9.tar.gz'
        first.write_bytes(gzip.compress(canonical, compresslevel=1, mtime=0))
        second.write_bytes(gzip.compress(canonical, compresslevel=9, mtime=0))
        self.assertNotEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(self.assert_semantic(first)['tar_sha256'], self.assert_semantic(second)['tar_sha256'])

    def test_actual_prior_backend_encoding_is_semantically_exact(self):
        # Default generation plus retained transport already span backend behavior;
        # this checks canonical tar independently of transport equality.
        retained = HERE / (exporter.NAME + '.tar.gz')
        result = self.assert_semantic(retained)
        self.assertEqual(result['tar_bytes'], 122880)
        with tarfile.open(fileobj=io.BytesIO(exporter.canonical_tar(self.source)), mode='r:') as archive:
            members = list(archive)
        self.assertEqual(len(members), 14)
        self.assertTrue(all(member.isfile() and member.uid == member.gid == member.mtime == 0 for member in members))

    def test_changed_tar_file_bytes_refused(self):
        def change(rows):
            member, raw = rows[0]; rows[0] = (member, bytes([raw[0] ^ 1]) + raw[1:]); return rows
        self.assert_archive_refused(self.tar_variant(change))

    def test_tar_namespace_and_metadata_mutations_refused(self):
        def metadata(rows, attribute, value):
            setattr(rows[0][0], attribute, value); return rows
        extra = tarfile.TarInfo(exporter.NAME + '/unexpected'); extra.size = 1
        for change in (lambda r:r[:-1], lambda r:r + [r[0]], lambda r:r + [(extra, b'x')], lambda r:list(reversed(r)),
                       lambda r:metadata(r, 'mode', 0o600), lambda r:metadata(r, 'uid', 123),
                       lambda r:metadata(r, 'mtime', 1), lambda r:metadata(r, 'name', '../escape')):
            with self.subTest(change=change):
                self.assert_archive_refused(self.tar_variant(change))

    def test_symlink_tar_member_refused(self):
        def change(rows):
            member, _ = rows[0]; member.type = tarfile.SYMTYPE; member.linkname = '/etc/passwd'; member.size = 0
            rows[0] = (member, b''); return rows
        self.assert_archive_refused(self.tar_variant(change))

    def test_tar_trailing_bytes_refused(self):
        self.assert_archive_refused(self.archive(exporter.canonical_tar(self.source) + b'ignored trailing tar bytes'))

    def test_concatenated_gzip_and_trailing_transport_refused(self):
        original = gzip.compress(exporter.canonical_tar(self.source), mtime=0)
        for tail in (gzip.compress(b'', mtime=0), gzip.compress(b'other member', mtime=0), b'trailing'):
            self.output.write_bytes(original + tail)
            with self.subTest(tail=tail[:10]):self.assert_archive_refused(self.output)

    def test_truncated_or_corrupt_gzip_refused(self):
        raw = gzip.compress(exporter.canonical_tar(self.source), mtime=0)
        for body in (raw[:-1], raw[:-8], raw[:-8] + bytes([raw[-8] ^ 1]) + raw[-7:]):
            self.output.write_bytes(body); self.assert_archive_refused(self.output)

    def test_decoded_byte_budget_refuses_bomb(self):
        self.assert_archive_refused(self.archive(b'x' * (exporter.MAX_TAR + 1)))

    def test_wrong_archive_pin_refused_before_source_read(self):
        self.output.write_bytes(b'data')
        with self.assertRaisesRegex(ValueError, 'byte pin'):
            exporter.validate_archive(self.base / 'absent-source', self.output, '0' * 64)

    def test_fifo_and_symlink_archive_refused_without_read(self):
        os.mkfifo(self.output)
        with self.assertRaisesRegex(ValueError, 'regular'):
            exporter.validate_archive(self.source, self.output, 'a' * 64)
        self.output.unlink(); self.output.symlink_to(HERE / (exporter.NAME + '.tar.gz'))
        with self.assertRaisesRegex(ValueError, 'nonaliased'):
            exporter.validate_archive(self.source, self.output, 'a' * 64)

    def test_manifest_fifo_refused_without_blocking(self):
        path = self.source / 'source-map.json'; path.unlink(); os.mkfifo(path)
        self.refused()

    def test_changed_source(self):
        (self.source / 'test_package.py').write_text('changed')
        self.refused()

    def test_missing_source(self):
        (self.source / 'LICENSE').unlink()
        self.refused()

    def test_extra_source(self):
        (self.source / 'unexpected.py').write_text('unexpected')
        self.refused()

    def test_symlink_source(self):
        target = self.source / 'LICENSE'; target.unlink(); target.symlink_to('/etc/passwd')
        self.refused()

    def test_fifo_source(self):
        import os
        os.mkfifo(self.source / 'unexpected-fifo')
        self.refused()

    def test_existing_output_preserved(self):
        self.output.write_text('preserve')
        with self.assertRaises(FileExistsError):
            exporter.export(self.source, self.output)
        self.assertEqual(self.output.read_text(), 'preserve')


if __name__ == '__main__':
    unittest.main(verbosity=2)
