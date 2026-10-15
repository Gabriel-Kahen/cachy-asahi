#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Owned inert copy tests; no package, Docker, native, or updater actors."""
import errno
import functools
import os
from pathlib import Path
import shutil
import stat
import tempfile
import time
import types
import unittest
from unittest.mock import patch

import full_root as roots
import measure_copy as measure

MODE = 'generic-development-internal'


class InternalHardlinkCopyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='copy-hardlinks-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.source = self.base / 'source'; self.source.mkdir()
        self.target = self.base / 'copy'
        self.data = b'bounded inert shared bytes\n'
        # Like existing copy fixtures: retain actual available bytes, explicitly
        # supply test-only inode capacity where Btrfs reports it as unknown.
        original, real_statvfs = measure.check_capacity, os.statvfs

        def fixture_space(path):
            value = real_statvfs(path)
            if value.f_files == value.f_favail == 0:
                fields = list(value); fields[5] = fields[6] = fields[7] = 1000000
                return os.statvfs_result(fields)
            return value

        capacity = patch.object(measure, 'check_capacity', functools.partial(original, statvfs=fixture_space))
        capacity.start(); self.addCleanup(capacity.stop)

    def limits(self, **changes):
        values = dict(deadline=time.monotonic() + 20, max_nodes=100,
                      max_bytes=1024**2, max_file_bytes=1024**2)
        values.update(changes)
        return roots.Limits(**values)

    def group(self):
        directory = self.source / 'child'; directory.mkdir()
        directory.chmod(0o751)
        first = directory / 'a'; first.write_bytes(self.data); first.chmod(0o640)
        os.link(first, directory / 'b')
        (self.source / 'relative').symlink_to('child/a')
        return first

    def invoke(self, mode=MODE, **options):
        options.setdefault('limits', self.limits())
        return measure.copy_data(self.source, self.target, hardlinks=mode, **options)

    def fds(self):
        return len(os.listdir('/proc/self/fd'))

    def refused(self, mode=MODE, **options):
        before = self.fds()
        with self.assertRaises((ValueError, OSError)):
            self.invoke(mode, **options)
        self.assertEqual(self.fds(), before, 'all owned descriptors must close on refusal')

    def test_default_keeps_legacy_schema_and_hardlink_refusal(self):
        self.group()
        report = self.invoke('refuse')
        self.assertFalse(report['eligible'])
        self.assertNotIn('hardlink_groups', report)
        self.assertNotIn('nodes', report)
        self.assertEqual((self.target / 'child/a').stat().st_ino,
                         (self.target / 'child/b').stat().st_ino)
        self.assertEqual(report['unsupported_observation']['hardlink'], 2)

    def test_complete_group_preserves_topology_content_metadata_and_safe_links(self):
        first = self.group()
        original_link, original_observe, original_open = os.link, roots.observe, os.open
        links, passes, aliases = [], [], {'a': 0, 'b': 0}
        phase = 'before'

        def observed(path, **kwargs):
            nonlocal phase
            phase = 'observation'
            passes.append(Path(path))
            report = original_observe(path, **kwargs)
            phase = 'copy' if len(passes) == 1 else 'after-copy'
            return report

        def opened(*args, **kwargs):
            fd = original_open(*args, **kwargs)
            name = Path(os.fsdecode(args[0])).name
            if phase == 'copy' and name in aliases and os.fstat(fd).st_ino == first.stat().st_ino:
                aliases[name] += 1
            return fd

        def linked(source, destination, **kwargs):
            self.assertNotIn('/', os.fsdecode(source)); self.assertNotIn('/', os.fsdecode(destination))
            self.assertIsNotNone(kwargs.get('src_dir_fd')); self.assertIsNotNone(kwargs.get('dst_dir_fd'))
            self.assertIs(kwargs.get('follow_symlinks'), False)
            for name in ('src_dir_fd', 'dst_dir_fd'):
                parent = Path(os.readlink('/proc/self/fd/' + str(kwargs[name])))
                self.assertTrue(parent.is_relative_to(self.target))
            links.append((source, destination))
            return original_link(source, destination, **kwargs)

        before = self.fds()
        with patch.object(roots, 'observe', side_effect=observed), \
                patch.object(measure.os, 'open', side_effect=opened), \
                patch.object(measure.os, 'link', side_effect=linked):
            report = self.invoke()
        self.assertEqual(self.fds(), before)
        self.assertTrue(report['eligible'], report)
        self.assertTrue(report['copy_complete'])
        self.assertEqual(passes, [self.source, self.target, self.source])
        self.assertEqual(len(links), 1)
        for name, count in aliases.items(): self.assertGreaterEqual(count, 2, name)
        copied = (self.target / 'child/a').stat()
        self.assertEqual(copied.st_ino, (self.target / 'child/b').stat().st_ino)
        self.assertNotEqual(copied.st_ino, first.stat().st_ino)
        self.assertEqual(copied.st_nlink, 2)
        self.assertEqual((self.target / 'child/b').read_bytes(), self.data)
        self.assertEqual(stat.S_IMODE(copied.st_mode), 0o640)
        self.assertEqual((copied.st_uid, copied.st_gid), (first.stat().st_uid, first.stat().st_gid))
        self.assertEqual(stat.S_IMODE((self.target / 'child').stat().st_mode), 0o751)
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o700)
        self.assertEqual(os.readlink(self.target / 'relative'), 'child/a')
        self.assertNotIn('nodes', report); self.assertNotIn('hardlink_groups', report)

    def test_modes_scope_and_capacity_refuse_before_allocation(self):
        self.group()
        for mode in (True, None, 'allow', 'apple'):
            with self.subTest(mode=mode): self.refused(mode)
            self.assertFalse(self.target.exists())
        self.refused(excluded={'child'})
        self.assertFalse(self.target.exists())
        self.refused(limits=self.limits(allow_cross_device=True))
        self.assertFalse(self.target.exists())
        with patch.object(measure, 'check_capacity', side_effect=ValueError('capacity refusal')):
            self.refused()
        self.assertFalse(self.target.exists())

    def test_source_overlap_and_bind_alias_parent_refuse(self):
        self.group()
        self.target = self.source / 'nested'
        self.refused(); self.assertFalse(self.target.exists())
        self.target = self.base / 'copy'
        original = roots._mount_id
        parent_identity = self.base.stat().st_ino

        def other_mount(fd, limits):
            value = original(fd, limits)
            return value + 100000 if os.fstat(fd).st_ino == parent_identity else value

        with patch.object(roots, '_mount_id', side_effect=other_mount): self.refused()
        self.assertFalse(self.target.exists())

    def test_owned_0755_parent_accepts_but_shared_write_or_other_owner_refuse(self):
        self.group()
        self.base.chmod(0o755)
        self.assertTrue(self.invoke()['eligible'])
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o700)
        shutil.rmtree(self.target)
        self.base.chmod(0o777)
        self.refused(); self.assertFalse(self.target.exists())
        self.base.chmod(0o700)
        original = os.fstat
        identity = (self.base.stat().st_dev, self.base.stat().st_ino)

        def foreign_parent(fd):
            info = original(fd)
            if (info.st_dev, info.st_ino) != identity: return info
            values = {name: getattr(info, name) for name in dir(info) if name.startswith('st_')}
            values['st_uid'] = os.geteuid() + 1
            return types.SimpleNamespace(**values)

        with patch.object(measure.os, 'fstat', side_effect=foreign_parent): self.refused()
        self.assertFalse(self.target.exists())

    def test_outside_alias_and_independent_unsupported_shapes_refuse(self):
        first = self.group()
        os.link(first, self.base / 'outside')
        self.refused(); self.assertFalse(self.target.exists())
        (self.base / 'outside').unlink()
        for kind in ('absolute', 'fifo', 'auxiliary'):
            with self.subTest(kind=kind):
                node = self.source / kind
                if kind == 'absolute': node.symlink_to('/outside/not-read')
                elif kind == 'fifo': os.mkfifo(node)
                else:
                    node = self.source / 'usr/bin/ldconfig'; node.parent.mkdir(parents=True); node.write_bytes(b'inert')
                self.refused(); self.assertFalse(self.target.exists())
                node.unlink()

    def test_source_changes_before_copy_and_after_destination_readback_refuse(self):
        for point in ('before-copy', 'source-after'):
            with self.subTest(point=point):
                first = self.group()
                original = roots.observe; calls = 0

                def observed(path, **kwargs):
                    nonlocal calls
                    calls += 1
                    if point == 'source-after' and calls == 3:
                        first.write_bytes(b'changed after destination readback\n')
                    report = original(path, **kwargs)
                    if point == 'before-copy' and calls == 1:
                        first.write_bytes(b'changed after source preflight\n')
                    return report

                with patch.object(roots, 'observe', side_effect=observed): self.refused()
                shutil.rmtree(self.source); self.source.mkdir()
                if self.target.exists(): shutil.rmtree(self.target)

    def test_source_content_drift_during_stream_and_alias_mount_change_refuse(self):
        first = self.group()
        original_read, original_observe = os.read, roots.observe
        copying = False; changed = False

        def observed(path, **kwargs):
            nonlocal copying
            copying = False
            report = original_observe(path, **kwargs)
            if Path(path) == self.source and not changed: copying = True
            return report

        def read(fd, count):
            nonlocal changed
            data = original_read(fd, count)
            if copying and not changed and os.fstat(fd).st_ino == first.stat().st_ino and data:
                changed = True; first.write_bytes(b'mutated while stream read\n')
            return data

        with patch.object(roots, 'observe', side_effect=observed), patch.object(measure.os, 'read', side_effect=read):
            self.refused()
        self.assertTrue(changed)
        if self.target.exists(): shutil.rmtree(self.target)
        first.write_bytes(self.data)
        original_mount = roots._mount_id
        copying = False; calls = 0

        def preflight(path, **kwargs):
            nonlocal copying
            copying = False
            report = original_observe(path, **kwargs)
            copying = Path(path) == self.source
            return report

        def mounted(fd, limits):
            nonlocal calls
            value = original_mount(fd, limits)
            if copying and os.fstat(fd).st_ino == first.stat().st_ino:
                calls += 1
                if calls > 1: return value + 100000
            return value

        with patch.object(roots, 'observe', side_effect=preflight), patch.object(roots, '_mount_id', side_effect=mounted):
            self.refused()
        self.assertGreater(calls, 1)

    def test_link_eexist_exdev_and_resource_limits_refuse_without_fd_leaks(self):
        self.group()
        for code in (errno.EEXIST, errno.EXDEV):
            with self.subTest(code=code):
                with patch.object(measure.os, 'link', side_effect=OSError(code, 'inert link refusal')):
                    self.refused()
                if self.target.exists(): shutil.rmtree(self.target)
        (self.source / 'child/deeper').mkdir()
        for changes in ({'max_nodes': 1}, {'max_bytes': 1}, {'max_file_bytes': 1},
                        {'max_depth': 1}, {'max_hardlink_aliases': 1},
                        {'deadline': time.monotonic() - 1}):
            with self.subTest(changes=changes): self.refused(limits=self.limits(**changes))
            if self.target.exists(): shutil.rmtree(self.target)

    def test_legacy_acquisition_failures_close_earlier_descriptors(self):
        (self.source / 'child').mkdir(); (self.source / 'child/data').write_bytes(self.data)
        for point in ('target-mkdir', 'target-open', 'child-mkdir', 'child-open', 'new-file-open'):
            with self.subTest(point=point):
                original_open, original_mkdir, original_path_mkdir = os.open, os.mkdir, Path.mkdir
                injected = False

                def opened(path, flags, *args, **kwargs):
                    nonlocal injected
                    parent = kwargs.get('dir_fd')
                    parent_is_target = parent is not None and self.target.exists() and os.fstat(parent).st_ino == self.target.stat().st_ino
                    match = ((point == 'target-open' and Path(path) == self.target)
                             or (point == 'child-open' and path == 'child' and parent_is_target)
                             or (point == 'new-file-open' and flags & os.O_CREAT))
                    if match: injected = True; raise OSError(errno.EACCES, point)
                    return original_open(path, flags, *args, **kwargs)

                def mkdir(path, *args, **kwargs):
                    nonlocal injected
                    if point == 'child-mkdir' and path == 'child':
                        injected = True; raise OSError(errno.EACCES, point)
                    return original_mkdir(path, *args, **kwargs)

                def path_mkdir(path, *args, **kwargs):
                    nonlocal injected
                    if point == 'target-mkdir' and path == self.target:
                        injected = True; raise OSError(errno.EACCES, point)
                    return original_path_mkdir(path, *args, **kwargs)

                with patch.object(measure.os, 'open', side_effect=opened), \
                        patch.object(measure.os, 'mkdir', side_effect=mkdir), \
                        patch.object(Path, 'mkdir', new=path_mkdir):
                    self.refused('refuse')
                self.assertTrue(injected, point)
                if self.target.exists(): shutil.rmtree(self.target)

    def test_close_eio_after_real_release_preserves_primary_and_closes_rest(self):
        (self.source / 'data').write_bytes(self.data)
        primary = ValueError('primary inert stream failure')
        original_close = os.close; attempted = []; raised = False; failing = False

        def write(fd, data):
            nonlocal failing
            failing = True
            raise primary

        def close(fd):
            nonlocal raised
            if failing: attempted.append(fd)
            original_close(fd)
            if failing and not raised:
                raised = True; raise OSError(errno.EIO, 'inert close after real release')

        before = self.fds()
        with patch.object(measure.os, 'write', side_effect=write), patch.object(measure.os, 'close', side_effect=close):
            with self.assertRaises(ValueError) as caught: self.invoke('refuse')
        self.assertIs(caught.exception, primary)
        self.assertTrue(raised)
        self.assertEqual(len(attempted), len(set(attempted)), 'never blindly retry a released FD')
        self.assertEqual(self.fds(), before)

    def test_open_root_handoff_real_close_eio_and_open_failure_cleanup(self):
        original_open, original_close = os.open, os.close
        before = self.fds()
        fd = roots._open_root(self.source)
        try:
            self.assertEqual(os.fstat(fd).st_ino, self.source.stat().st_ino)
        finally:
            original_close(fd)
        self.assertEqual(self.fds(), before)
        open_error = OSError(errno.EACCES, 'inert owned child open refusal')

        def refused_child(path, *args, **kwargs):
            if path == self.source.name and kwargs.get('dir_fd') is not None:
                raise open_error
            return original_open(path, *args, **kwargs)

        with patch.object(roots.os, 'open', side_effect=refused_child):
            with self.assertRaises(OSError) as caught: roots._open_root(self.source)
        self.assertIs(caught.exception, open_error)
        self.assertEqual(self.fds(), before)
        for cleanup_eio in (False, True):
            with self.subTest(cleanup_eio=cleanup_eio):
                primary = OSError(errno.EIO, 'inert parent close after real release')
                child = None; attempted = []; primary_raised = False

                def opened(path, *args, **kwargs):
                    nonlocal child
                    fd = original_open(path, *args, **kwargs)
                    if path == self.source.name and kwargs.get('dir_fd') is not None: child = fd
                    return fd

                def closed(fd):
                    nonlocal primary_raised
                    if child is not None: attempted.append(fd)
                    original_close(fd)
                    if child is not None and not primary_raised:
                        primary_raised = True
                        raise primary
                    if child is not None and fd == child and cleanup_eio:
                        raise OSError(errno.EIO, 'inert child cleanup after real release')

                with patch.object(roots.os, 'open', side_effect=opened), \
                        patch.object(roots.os, 'close', side_effect=closed):
                    with self.assertRaises(OSError) as caught: roots._open_root(self.source)
                self.assertIs(caught.exception, primary)
                self.assertTrue(primary_raised)
                self.assertEqual(len(attempted), 2)
                self.assertNotEqual(attempted[0], child)
                self.assertEqual(attempted.count(child), 1)
                self.assertEqual(self.fds(), before)
                if cleanup_eio:
                    self.assertIn('root descriptor cleanup failed', primary.__notes__)

    def test_short_writes_complete_but_zero_progress_refuses_both_modes(self):
        (self.source / 'data').write_bytes(self.data)
        original = os.write
        for mode in ('refuse', MODE):
            with self.subTest(mode=mode):
                with patch.object(measure.os, 'write', side_effect=lambda fd, data: original(fd, data[:2])):
                    report = self.invoke(mode)
                self.assertTrue(report['eligible'], report)
                self.assertEqual((self.target / 'data').read_bytes(), self.data)
                shutil.rmtree(self.target)
                with patch.object(measure.os, 'write', return_value=0): self.refused(mode)
                if self.target.exists(): shutil.rmtree(self.target)

    def test_partial_write_loop_checks_shared_deadline(self):
        (self.source / 'data').write_bytes(self.data)
        original_write, original_tick = os.write, roots.Limits.tick
        for mode in ('refuse', MODE):
            expired = False; writes = 0

            def write(fd, data):
                nonlocal expired, writes
                writes += 1
                result = original_write(fd, data[:1]); expired = True
                return result

            def tick(limits):
                if expired: raise ValueError('forced shared deadline')
                return original_tick(limits)

            with self.subTest(mode=mode):
                with patch.object(measure.os, 'write', side_effect=write), patch.object(roots.Limits, 'tick', new=tick):
                    self.refused(mode)
                self.assertEqual(writes, 1)
                if self.target.exists(): shutil.rmtree(self.target)


if __name__ == '__main__':
    unittest.main(verbosity=2)
