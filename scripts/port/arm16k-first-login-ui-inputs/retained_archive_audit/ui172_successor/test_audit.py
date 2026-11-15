#!/usr/bin/env python3
"""Synthetic source and signature-status controls; no retained archive or gpgv reads."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('ui172_successor_under_test', HERE/'audit.py')
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


class SourceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = json.loads((HERE/'inputs.json').read_text())
        audit.checked(cls.config['old_reader'])
        cls.old = audit.load('ui172_pinned_status_reader_under_test', Path(cls.config['old_reader']['path']))

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ui172-synthetic-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root/'source'
        self.path.write_bytes(b'original')
        self.expected = audit.pin(b'original')
        self.limits = copy.deepcopy(self.config['limits'])
        self.budget = {'deadline': time.monotonic()+10, 'compressed_allowance': 0,
                       'logical_bytes': 0, 'headers': 0}

    def source(self, **kwargs):
        return audit.Source(self.path, self.expected, self.budget, self.limits, **kwargs)

    def test_full_hash_matches_same_stream_snapshot_and_descriptor(self):
        snapshot = self.root/'snapshot'
        source = self.source(snapshot=snapshot)
        with source.open('rb') as stream:
            self.assertEqual(stream.read(3), b'ori')
            self.assertEqual(stream.read(65536), b'ginal')
            self.assertEqual(stream.read(1), b'')
        self.assertEqual(snapshot.read_bytes(), b'original')
        self.assertEqual(source.count, 8)
        self.assertEqual(source.digest.hexdigest(), self.expected['sha256'])
        self.assertEqual(self.budget['compressed_allowance'], 8)
        self.assertEqual(source.identity['st_ino'], self.path.stat().st_ino)

    def test_wrong_same_size_hash_and_partial_reads_refuse(self):
        self.path.write_bytes(b'changed!')
        with self.assertRaisesRegex(ValueError, 'SHA256/source identity'):
            with self.source().open('rb') as stream:
                stream.read(8)
        self.assertEqual(self.budget['compressed_allowance'], 8)
        self.path.write_bytes(b'original')
        with self.assertRaisesRegex(ValueError, 'SHA256/source identity'):
            with self.source().open('rb') as stream:
                stream.read(3)
        self.assertEqual(self.budget['compressed_allowance'], 11)

    def test_same_bytes_changed_descriptor_identity_refuses(self):
        with self.assertRaisesRegex(ValueError, 'source identity'):
            with self.source().open('rb') as stream:
                stream.read(8)
                old = self.path.stat()
                os.utime(self.path, ns=(old.st_atime_ns, old.st_mtime_ns+1_000_000))

    def test_size_type_and_snapshot_overwrite_refuse(self):
        self.path.write_bytes(b'short')
        with self.assertRaisesRegex(ValueError, 'size/type'):
            self.source().open('rb')
        self.path.unlink()
        self.path.mkdir()
        with self.assertRaises((ValueError, IsADirectoryError)):
            self.source().open('rb')
        self.path.rmdir()
        self.path.write_bytes(b'original')
        target = self.root/'snapshot'
        target.write_bytes(b'preserved')
        source = self.source(snapshot=target)
        with self.assertRaises(FileExistsError):
            source.open('rb')
        self.assertTrue(source.stream.closed)
        self.assertEqual(target.read_bytes(), b'preserved')

    def test_symlink_leaf_and_parent_refuse(self):
        link = self.root/'link'
        link.symlink_to(self.path)
        with self.assertRaisesRegex(ValueError, 'linked'):
            audit.Source(link, self.expected, self.budget, self.limits)
        directory = self.root/'directory'
        directory.mkdir()
        (directory/'source').write_bytes(b'original')
        parent = self.root/'parent'
        parent.symlink_to(directory, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'linked'):
            audit.Source(parent/'source', self.expected, self.budget, self.limits)

    def test_object_and_aggregate_caps_refuse_before_open(self):
        self.limits['archive_object_bytes'] = 7
        with self.assertRaisesRegex(ValueError, 'compressed cap'):
            self.source()
        self.limits['archive_object_bytes'] = 8
        self.limits['compressed_archive_read_allowance'] = 10
        self.budget['compressed_allowance'] = 3
        with self.assertRaisesRegex(ValueError, 'compressed cap'):
            self.source()
        self.assertEqual(self.budget['compressed_allowance'], 3)

    def test_read_size_deadline_and_remaining_caps(self):
        with self.source().open('rb') as stream:
            for size in [-1, 65537, True, 1.5]:
                with self.subTest(size=size), self.assertRaisesRegex(ValueError, 'bounded'):
                    stream.read(size)
            self.limits['compressed_archive_read_allowance'] = 7
            with self.assertRaisesRegex(ValueError, 'aggregate'):
                stream.read(8)
            self.assertEqual(self.budget['compressed_allowance'], 0)
            self.limits['compressed_archive_read_allowance'] = 8
            self.budget['deadline'] = time.monotonic()-1
            with self.assertRaisesRegex(TimeoutError, 'deadline'):
                stream.read(8)
            self.budget['deadline'] = time.monotonic()+10
            stream.read(8)

    def test_failed_read_charge_cannot_be_reset_by_new_source(self):
        self.limits['compressed_archive_read_allowance'] = 15
        self.path.write_bytes(b'changed!')
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            with self.source().open('rb') as stream:
                stream.read(8)
        with self.assertRaisesRegex(ValueError, 'compressed cap'):
            self.source()
        self.assertEqual(self.budget['compressed_allowance'], 8)

    def test_checked_byte_pin_change_link_and_size_caps(self):
        ref = {'path': str(self.path), **self.expected}
        self.assertEqual(audit.checked(ref), b'original')
        with self.assertRaisesRegex(ValueError, 'size/type/cap'):
            audit.checked(ref, maximum=7)
        self.path.write_bytes(b'changed!')
        with self.assertRaisesRegex(ValueError, 'full pin'):
            audit.checked(ref)
        self.path.unlink()
        target = self.root/'target'; target.write_bytes(b'original')
        self.path.symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'linked'):
            audit.checked(ref)

    def status(self, primary):
        return ('[GNUPG:] VALIDSIG %s 2026-11-15 1794700000 0 4 0 1 8 00 %s\n'
                % (primary, primary)).encode()

    def call_signature(self, repo, result):
        item = {'repo': repo, 'archive': {'bytes': 8}}
        with patch.object(audit.resource, 'setrlimit') as resource_limit, \
             patch.object(audit.subprocess, 'run', return_value=result) as run:
            row = audit.signature(self.old, self.config, item, self.root/'snapshot', self.root/'signature',
                                  self.root, self.budget, self.limits)
        self.assertEqual(resource_limit.call_count, 2)
        return row, run

    def test_signature_roles_use_separate_rings_and_direct_primary(self):
        for role in ['official', 'project']:
            primary = self.config[role+'_primary']
            result = subprocess.CompletedProcess([], 0, self.status(primary), b'')
            with self.subTest(role=role):
                row, run = self.call_signature(role, result)
                self.assertEqual(row['status'], 'PASS_SIGNATURE_MATHEMATICS')
                self.assertEqual(row['primary'], primary)
                self.assertIn(str(self.root/(role+'-public.gpg')), run.call_args.args[0])
                self.assertEqual(row['stdout'], result.stdout.decode())
                self.assertEqual(row['freshness_external_trust_native_build'], 'HOLD')
        self.assertEqual(self.budget['compressed_allowance'], 16)

    def test_wrong_role_expiry_bad_signature_and_exit_preserved_as_hold(self):
        project = self.config['project_primary']
        official = self.config['official_primary']
        for code, status in [(0, self.status(official)), (1, self.status(project)),
                (0, self.status(project)+b'[GNUPG:] EXPKEYSIG key TEST\n'),
                (0, self.status(project)+b'[GNUPG:] BADSIG key TEST\n'),
                (0, self.status(project)*2), (0, b'')]:
            result = subprocess.CompletedProcess([], code, status, b'actual error text')
            with self.subTest(code=code, status=status):
                row, _ = self.call_signature('project', result)
                self.assertEqual(row['status'], 'HOLD_CURRENT_SIGNATURE_POLICY')
                self.assertEqual(row['expected_primary'], project)
                self.assertEqual(row['exit'], code)
                self.assertEqual(row['stdout'], status.decode())
                self.assertEqual(row['stderr'], 'actual error text')
                self.assertNotIn('primary', row)

    def test_signature_budget_refusal_never_invokes_subprocess(self):
        self.limits['compressed_archive_read_allowance'] = 7
        with patch.object(audit.subprocess, 'run') as run, self.assertRaisesRegex(ValueError, 'signature compressed'):
            audit.signature(self.old, self.config, {'repo':'project','archive':{'bytes':8}},
                            self.root/'a', self.root/'s', self.root, self.budget, self.limits)
        run.assert_not_called()
        self.assertEqual(self.budget['compressed_allowance'], 0)


if __name__ == '__main__':
    unittest.main()
