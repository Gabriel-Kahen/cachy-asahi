#!/usr/bin/env python3
"""Real inert file copies/fault injection; no package actors."""
import functools
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import disposable_copy as copy

class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='owned-copy-'); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name); self.source = self.base / 'source'; self.source.mkdir()
        self.workspace = self.base / 'work'
        for name, data in {'var/lib/pacman/local/package/desc': b'package database\n', 'home/user/config': b'user content\n',
                           'usr/share/data': b'inert shared bytes\n'}.items():
            path = self.source / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
        os.link(self.source / 'usr/share/data', self.source / 'usr/share/alias')
        self.original = copy.roots.observe(self.source, limits=self.limits(), hardlinks='generic-development-internal')
        original, statvfs = copy.measure_copy.check_capacity, os.statvfs
        def fixture_space(path):
            row = statvfs(path)
            if row.f_files == row.f_favail == 0:
                fields = list(row); fields[5] = fields[6] = fields[7] = 1000000
                return os.statvfs_result(fields)
            return row
        capacity = patch.object(copy.measure_copy, 'check_capacity', functools.partial(original, statvfs=fixture_space))
        capacity.start(); self.addCleanup(capacity.stop)

    def limits(self, **values):
        defaults = dict(deadline=time.monotonic()+20, max_nodes=100, max_bytes=1024**2, max_file_bytes=1024**2)
        defaults.update(values); return copy.roots.Limits(**defaults)

    def run_copy(self, **values): return copy.copied_root(self.source, self.workspace, limits=self.limits(), **values)
    def fds(self): return len(os.listdir('/proc/self/fd'))
    def source_unchanged(self):
        self.assertEqual(copy.roots.observe(self.source, limits=self.limits(), hardlinks='generic-development-internal')['nodes'], self.original['nodes'])

    def test_complete_copy_preserves_database_users_and_internal_groups_then_disposes(self):
        count = self.fds()
        with self.run_copy() as (root, report):
            copied = copy.roots.observe(root, limits=self.limits(), hardlinks='generic-development-internal')
            self.assertEqual(copied['nodes'], self.original['nodes'])
            self.assertEqual((root/'usr/share/data').stat().st_ino, (root/'usr/share/alias').stat().st_ino)
            self.assertNotEqual((root/'usr/share/data').stat().st_ino, (self.source/'usr/share/data').stat().st_ino)
            # Simulate unrelated updater workspace files and copied user edits.
            (self.workspace/'diagnostic').write_bytes(b'private log')
            (root/'home/user/config').write_bytes(b'copy only')
        self.assertEqual(report['cleanup'], 'PASS-owned-workspace-removed')
        self.assertFalse(self.workspace.exists()); self.source_unchanged(); self.assertEqual(self.fds(), count)

    def test_partial_stream_failure_disposes_and_retains_primary(self):
        failure = ValueError('inert stream failed'); count = self.fds()
        with patch.object(copy.measure_copy, '_write', side_effect=failure):
            with self.assertRaises(ValueError) as caught:
                with self.run_copy(): self.fail('must not yield')
        self.assertIs(caught.exception, failure); self.assertFalse(self.workspace.exists())
        self.source_unchanged(); self.assertEqual(self.fds(), count)

    def test_expired_work_budget_does_not_disable_cleanup(self):
        def expired(*args, **kwargs):
            (self.workspace/'root').mkdir(); (self.workspace/'root/partial').write_bytes(b'partial')
            raise ValueError('root observation deadline')
        with patch.object(copy.measure_copy, 'copy_data', side_effect=expired):
            with self.assertRaisesRegex(ValueError, 'deadline'):
                with self.run_copy(): self.fail('must not yield')
        self.assertFalse(self.workspace.exists()); self.source_unchanged()

    def test_update_exception_and_readonly_directory_cleanup(self):
        with self.assertRaisesRegex(RuntimeError, 'update failed'):
            with self.run_copy() as (root, report):
                (root/'home/user').chmod(0o500)
                raise RuntimeError('update failed')
        self.assertFalse(self.workspace.exists()); self.source_unchanged()

    def test_cleanup_unlinks_external_symlink_without_following(self):
        outside = self.base/'outside'; outside.mkdir(); (outside/'keep').write_bytes(b'keep')
        with self.run_copy() as (root, report): (root/'external').symlink_to(outside)
        self.assertEqual((outside/'keep').read_bytes(), b'keep'); self.assertFalse(self.workspace.exists())

    def test_existing_workspace_and_overlap_refused_without_deletion(self):
        self.workspace.mkdir(); marker=self.workspace/'keep'; marker.write_bytes(b'keep')
        with self.assertRaises(FileExistsError):
            with self.run_copy(): self.fail('must not yield')
        self.assertEqual(marker.read_bytes(), b'keep')
        with self.assertRaisesRegex(ValueError, 'overlapping'):
            with copy.copied_root(self.source, self.source/'new', limits=self.limits()): self.fail('must not yield')
        self.source_unchanged()

    def test_rebound_workspace_retained_and_primary_preserved(self):
        moved = self.base/'moved'; failure=RuntimeError('inert update failed')
        with self.assertRaises(RuntimeError) as caught:
            with self.run_copy() as (root, report):
                self.workspace.rename(moved); self.workspace.mkdir(); (self.workspace/'keep').write_bytes(b'keep')
                raise failure
        self.assertIs(caught.exception, failure)
        self.assertEqual(report['cleanup'], 'FAIL-owned-workspace-retained-or-partial')
        self.assertEqual((self.workspace/'keep').read_bytes(), b'keep'); self.assertTrue((moved/'root').exists())
        self.assertIn('owned workspace cleanup failed; dispose outer container', failure.__notes__)

    def test_caller_handled_exception_cannot_hide_cleanup_failure(self):
        try: raise RuntimeError('unrelated caller exception')
        except RuntimeError:
            with self.assertRaisesRegex(ValueError, 'node limit'):
                with self.run_copy(cleanup_extra_nodes=0) as (root, report):
                    for i in range(101): (self.workspace/str(i)).write_bytes(b'')
        self.assertEqual(report['cleanup'], 'FAIL-owned-workspace-retained-or-partial')

    def test_cleanup_mount_change_refuses_before_unlink(self):
        original = copy.roots._mount_id; changed=False
        def mount(fd, limits): return original(fd, limits) + (1000 if changed else 0)
        with patch.object(copy.roots, '_mount_id', side_effect=mount):
            with self.assertRaisesRegex(ValueError, 'mount drift'):
                with self.run_copy() as (root, report): changed=True
        self.assertTrue((self.workspace/'root/home/user/config').exists()); self.source_unchanged()

    def test_cleanup_budget_failure_is_visible(self):
        with self.assertRaisesRegex(ValueError, 'node limit'):
            with self.run_copy(cleanup_extra_nodes=0) as (root, report):
                for i in range(101): (self.workspace/str(i)).write_bytes(b'')
        self.assertEqual(report['cleanup'], 'FAIL-owned-workspace-retained-or-partial'); self.source_unchanged()

if __name__ == '__main__': unittest.main()
