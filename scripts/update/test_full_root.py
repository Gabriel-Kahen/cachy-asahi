#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure data and owned temporary-file tests; no real ALPM/package actors."""
import ctypes as C
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
import time
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = next(parent for parent in HERE.parents if (parent / 'scripts/install/local_transaction.py').is_file())


class FullRootTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Import in canonical layout without changing production ROOT/global limits.
        cls.module_tree = tempfile.TemporaryDirectory(prefix='full-root-module-')
        root = Path(cls.module_tree.name)
        target = root / 'scripts/update/full_root.py'
        target.parent.mkdir(parents=True)
        shutil.copyfile(HERE / 'full_root.py', target)
        install = root / 'scripts/install'
        install.mkdir()
        (install / 'local_transaction.py').symlink_to(ROOT / 'scripts/install/local_transaction.py')
        spec = importlib.util.spec_from_file_location('scoped_full_root', target)
        cls.module = importlib.util.module_from_spec(spec)
        # dataclass annotation lookup expects the module registered during exec.
        import sys
        sys.modules[spec.name] = cls.module
        spec.loader.exec_module(cls.module)

    @classmethod
    def tearDownClass(cls):
        cls.module_tree.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='full-root-data-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.limits = self.module.Limits(deadline=time.monotonic() + 30)

    def limits_with(self, **kwargs):
        return self.module.Limits(deadline=time.monotonic() + 30, **kwargs)

    def test_exact_587_model_inventory_accepts_and_588_or_version_drift_refuse(self):
        expected = {f'model-package-{i}': '1-1' for i in range(587)}
        self.assertEqual(self.module.inventory_exact(expected, expected, limits=self.limits), expected)
        with self.assertRaisesRegex(ValueError, 'limit'):
            self.module.package_map(dict(expected, extra='1'), limits=self.limits)
        changed = dict(expected, **{'model-package-0': '2-1'})
        with self.assertRaisesRegex(ValueError, 'drift'):
            self.module.inventory_exact(changed, expected, limits=self.limits)
        self.assertEqual(self.module.installer.MAX_PACKAGES, 128)

    def test_subclass_observes_587_actual_list_nodes_without_loading_library(self):
        alpm = object.__new__(self.module.Alpm)
        alpm.limits = self.limits
        rows = [self.module.installer.List() for _ in range(588)]
        for i, row in enumerate(rows):
            row.data = i + 1
            if i + 1 < len(rows):
                row.next = C.pointer(rows[i + 1])
        alpm.alpm_pkg_get_name = lambda pointer: f'model-package-{pointer}'.encode()
        alpm.alpm_pkg_get_version = lambda pointer: b'1-1'
        rows[586].next = self.module.installer.Ptr()
        self.assertEqual(len(alpm.packages(C.pointer(rows[0]))), 587)
        rows[586].next = C.pointer(rows[587])
        with self.assertRaisesRegex(ValueError, 'limit'):
            alpm.packages(C.pointer(rows[0]))
        self.assertEqual(self.module.installer.FLAGS, (1 << 7) | (1 << 10))

    def test_owned_file_observations_use_per_caller_caps_without_global_mutation(self):
        alpm = object.__new__(self.module.Alpm)
        alpm.limits = self.limits
        alpm.handle = 123
        rows = (self.module.installer.File * 20001)()
        for index, row in enumerate(rows):
            row.name = f'usr/share/model/{index}'.encode()
        files = self.module.installer.Files(len(rows), rows)
        alpm.alpm_get_localdb = lambda handle: 321
        alpm.alpm_db_get_pkg = lambda db, name: 7
        alpm.alpm_pkg_get_files = lambda package: C.pointer(files)
        self.assertEqual(len(alpm.owned_files(['model-package'])), 20001)
        alpm.limits = self.limits_with(max_package_files=20000)
        with self.assertRaisesRegex(ValueError, 'file count limit'):
            alpm.owned_files(['model-package'])
        self.assertEqual(self.module.installer.MAX_TREE, 128 * 1024**2)

    def test_streams_file_larger_than_old_tree_limit_and_reports_database_footprint(self):
        folder = self.root / 'var/lib/pacman/local'
        folder.mkdir(parents=True)
        path = folder / 'large-fixture'
        size = 129 * 1024**2 + 7
        with path.open('wb') as stream:
            stream.truncate(size)  # Owned sparse zero data; no large allocation.
        calls = []
        original_read = os.read

        def read(fd, count):
            calls.append(count)
            return original_read(fd, count)

        with patch.object(self.module.os, 'read', side_effect=read):
            report = self.module.observe(self.root, limits=self.limits)
        self.assertTrue(report['eligible'], report)
        self.assertEqual(report['footprint']['bytes'], size)
        self.assertEqual(report['footprint']['database_bytes'], size)
        self.assertEqual(report['footprint']['database_files'], 1)
        self.assertEqual(report['footprint']['largest_file_bytes'], size)
        self.assertEqual(report['footprint']['allocated_bytes'], path.stat().st_blocks * 512)
        self.assertLessEqual(max(calls), 1024**2)
        self.assertGreater(len(calls), 128)
        self.assertIn('filesystem_free_inodes', report['footprint'])
        self.assertEqual(self.module.node(self.root, 'var/lib/pacman/local/large-fixture', limits=self.limits),
                         report['nodes']['var/lib/pacman/local/large-fixture'])

    def test_large_node_count_uses_explicit_budget_and_tiny_budget_refuses(self):
        # More than the old 20,000-node cap; all files are owned empty data.
        for i in range(20001):
            (self.root / str(i)).touch()
        report = self.module.observe(self.root, limits=self.limits)
        self.assertTrue(report['eligible'])
        self.assertEqual(report['footprint']['nodes'], 20001)
        partial = self.module.observe(self.root, limits=self.limits_with(max_nodes=2))
        self.assertFalse(partial['complete'])
        self.assertFalse(partial['eligible'])
        self.assertEqual(partial['footprint']['nodes'], 2)
        with self.assertRaises(ValueError):
            self.module.require_eligible(partial)

    def test_links_and_special_nodes_are_reported_and_never_eligible(self):
        (self.root / 'data').write_bytes(b'owned')
        os.link(self.root / 'data', self.root / 'hard')
        (self.root / 'absolute').symlink_to('/outside')
        (self.root / 'escape').symlink_to('../outside')
        (self.root / 'cycle-a').symlink_to('cycle-b')
        (self.root / 'cycle-b').symlink_to('cycle-a')
        os.mkfifo(self.root / 'fifo')
        report = self.module.observe(self.root, limits=self.limits)
        self.assertTrue(report['complete'])
        self.assertFalse(report['eligible'])
        self.assertEqual(report['footprint']['hardlinks'], 2)
        self.assertEqual(report['footprint']['hardlink_entries'], 2)
        self.assertEqual(report['footprint']['hardlink_inodes'], 1)
        self.assertEqual(report['footprint']['hardlink_declared_links'], 2)
        self.assertEqual(report['footprint']['allocated_bytes'], (self.root / 'data').stat().st_blocks * 512)
        self.assertEqual(report['footprint']['allocated_bytes_by_entry'], 2 * (self.root / 'data').stat().st_blocks * 512)
        self.assertEqual(report['footprint']['symlinks'], 4)
        self.assertEqual(report['unsupported_counts']['special-node'], 1)
        self.assertEqual(report['unsupported_counts']['absolute-symlink'], 1)
        self.assertEqual(report['unsupported_counts']['escaping-symlink'], 1)
        self.assertEqual(report['unsupported_counts']['cyclic-symlink'], 2)
        with self.assertRaises(ValueError):
            self.module.node(self.root, 'hard', limits=self.limits)
        with self.assertRaises(ValueError):
            self.module.node(self.root, 'absolute', limits=self.limits)

    def test_internal_link_is_recorded_but_parent_links_are_never_followed(self):
        (self.root / 'folder').mkdir()
        (self.root / 'folder/data').write_bytes(b'inert')
        (self.root / 'alias').symlink_to('folder')
        report = self.module.observe(self.root, limits=self.limits)
        self.assertTrue(report['eligible'])
        with self.assertRaises(OSError):
            self.module.node(self.root, 'alias/data', limits=self.limits)
        with self.assertRaises(ValueError):
            self.module.node(self.root, '../escape', limits=self.limits)

    def test_cross_device_child_is_recorded_without_opening_it(self):
        (self.root / 'cross').mkdir()
        (self.root / 'cross/never-read').write_bytes(b'x')
        original_stat = os.stat

        def modified(path, *args, **kwargs):
            value = original_stat(path, *args, **kwargs)
            if path == 'cross' and 'dir_fd' in kwargs:
                fields = {name: getattr(value, name) for name in dir(value) if name.startswith('st_')}
                fields['st_dev'] += 1
                return types.SimpleNamespace(**fields)
            return value

        with patch.object(self.module.os, 'stat', side_effect=modified):
            report = self.module.observe(self.root, limits=self.limits)
        self.assertFalse(report['eligible'])
        self.assertEqual(report['unsupported_counts']['cross-device'], 1)
        self.assertNotIn('cross/never-read', report['nodes'])

    def test_content_drift_is_not_accepted(self):
        path = self.root / 'data'
        path.write_bytes(b'initial')
        original_read = os.read
        changed = False

        def read(fd, count):
            nonlocal changed
            data = original_read(fd, count)
            if not changed:
                changed = True
                path.write_bytes(b'mutated-longer')
            return data

        with patch.object(self.module.os, 'read', side_effect=read):
            report = self.module.observe(self.root, limits=self.limits)
        self.assertFalse(report['eligible'])
        self.assertFalse(report['complete'])
        self.assertTrue(any('drift' in reason or 'grew' in reason for reason in report['unsupported_counts']))

    def test_unreported_inode_capacity_is_unknown_but_reported_zero_is_zero(self):
        original = os.fstatvfs
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            actual = original(descriptor)
        finally:
            os.close(descriptor)
        for total, free, expected in ((0, 0, None), (100, 0, 0)):
            values = {name: getattr(actual, name) for name in dir(actual) if name.startswith('f_')}
            values.update(f_files=total, f_favail=free)
            with self.subTest(total=total), patch.object(self.module.os, 'fstatvfs',
                                                       return_value=types.SimpleNamespace(**values)):
                footprint = self.module.observe(self.root, limits=self.limits)['footprint']
            self.assertEqual(footprint['filesystem_free_inodes'], expected)
            self.assertEqual(footprint['filesystem_inode_counts_known'], total > 0)

    def test_limits_deadline_depth_and_bytes_are_enforced(self):
        (self.root / 'data').write_bytes(b'123')
        for limits in (self.limits_with(max_bytes=2), self.limits_with(max_file_bytes=2)):
            self.assertFalse(self.module.observe(self.root, limits=limits)['eligible'])
        expired = self.module.Limits(deadline=time.monotonic() - 1)
        with self.assertRaisesRegex(ValueError, 'deadline'):
            self.module.observe(self.root, limits=expired)
        calls = 0

        def clock():
            nonlocal calls
            calls += 1
            return self.limits.deadline + (1 if calls >= 4 else -1)

        with patch.object(self.module.time, 'monotonic', side_effect=clock):
            partial = self.module.observe(self.root, limits=self.limits)
        self.assertFalse(partial['complete'])
        self.assertIn('root observation deadline', partial['unsupported_counts'])
        (self.root / 'a/b').mkdir(parents=True)
        self.assertFalse(self.module.observe(self.root, limits=self.limits_with(max_depth=1))['eligible'])
        for bad in ({'max_nodes': True}, {'max_bytes': 0}, {'deadline': float('inf')}):
            values = {'deadline': time.monotonic() + 10, **bad}
            with self.assertRaises(ValueError):
                self.module.Limits(**values)

    def test_projection_retains_links_ldconfig_alias_and_explicit_bounds(self):
        file = {'type': 'file', 'bytes': 129 * 1024**2, 'sha256': '0' * 64}
        self.assertEqual(self.module.projected_paths({}, {'data': file}, limits=self.limits), {'data': file})
        invalid = [({'usr/bin/ldconfig': file}, {}),
                   ({'usr/bin': {'type': 'symlink', 'target': '../../bin'}, 'bin/ldconfig': file}, {}),
                   ({}, {'escape': {'type': 'symlink', 'target': '../escape'}}),
                   ({}, {'absolute': {'type': 'symlink', 'target': '/outside'}}),
                   ({}, {'fifo': {'type': 'special'}}),
                   ({}, {'unhashed': {'type': 'file', 'bytes': 1}})]
        for seed, added in invalid:
            with self.subTest(seed=seed, added=added), self.assertRaises(ValueError):
                self.module.projected_paths(seed, added, limits=self.limits)
        with self.assertRaisesRegex(ValueError, 'byte limit'):
            self.module.projected_paths({}, {'data': file}, limits=self.limits_with(max_bytes=1))


if __name__ == '__main__':
    unittest.main()
