"""New recovery filesystem controls; mutations are confined to TemporaryDirectory."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'overlay/native'))
import security_recovery_fs as fs


class Filesystem(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='security-recovery-fs-')
        self.root = Path(self.temp.name)
        self.local = self.root / fs.LOCAL
        (self.local / 'base-1').mkdir(parents=True)
        (self.local / 'base-1/desc').write_bytes(b'unchanged base database\n')
        (self.root / 'usr/bin').mkdir(parents=True)
        self.candidate = self.local / fs.CANDIDATE
        self.candidate.mkdir(mode=0o755)
        self.candidate.chmod(0o755)
        self.lock = self.root / fs.LOCK
        self.lock.write_bytes(b'')
        self.lock.chmod(0)
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.names = ('bin/security-test', 'share/security-test/old-only')
        self.owner = dict(owner_uid=os.geteuid(), owner_gid=os.getegid())

    def tearDown(self):
        os.close(self.fd)
        self.temp.cleanup()

    def snap(self):
        return fs.snapshot(self.fd, self.names, **self.owner)

    def cleanup(self, expected):
        return fs.cleanup(self.fd, self.names, expected, **self.owner)

    def test_capture_and_exact_cleanup(self):
        before = self.snap()
        self.assertEqual(before['db'][fs.CANDIDATE]['kind'], 'dir')
        self.assertEqual(before['lock']['mode'], 0)
        self.assertEqual(before['payload'], dict.fromkeys(self.names))
        result = self.cleanup(before)
        self.assertEqual(result['before_sha256'], fs.snapshot_sha256(before))
        self.assertNotIn(fs.CANDIDATE, result['after_directory']['db'])
        self.assertIsNotNone(result['after_directory']['lock'])
        self.assertIsNone(result['after_unlock']['lock'])
        self.assertEqual(self.snap(), result['after_unlock'])
        self.assertEqual((self.local / 'base-1/desc').read_bytes(), b'unchanged base database\n')
        self.assertFalse(self.candidate.exists())
        self.assertFalse(self.lock.exists())

    def test_epoch_version_database_directory_is_preserved(self):
        epoch = self.local / 'less-1:690-1'
        epoch.mkdir()
        (epoch / 'desc').write_bytes(b'epoch-versioned baseline package\n')
        before = self.snap()
        self.assertIn('less-1:690-1/desc', before['db'])
        self.cleanup(before)
        self.assertEqual((epoch / 'desc').read_bytes(), b'epoch-versioned baseline package\n')

    def test_database_drift_stops_before_mutation(self):
        before = self.snap()
        (self.local / 'base-1/desc').write_bytes(b'changed base database\n')
        with self.assertRaises(fs.Refusal):
            self.cleanup(before)
        self.assertTrue(self.candidate.exists())
        self.assertTrue(self.lock.exists())

    def test_nonempty_candidate_never_removed(self):
        (self.candidate / 'desc').write_bytes(b'partial candidate')
        before = self.snap()
        with self.assertRaises(fs.Refusal):
            self.cleanup(before)
        self.assertEqual((self.candidate / 'desc').read_bytes(), b'partial candidate')
        self.assertTrue(self.lock.exists())

    def test_prior_database_never_removed(self):
        (self.local / fs.PRIOR).mkdir()
        with self.assertRaises(fs.Refusal):
            self.cleanup(self.snap())
        self.assertTrue((self.local / fs.PRIOR).exists())

    def test_payload_presence_stops_cleanup(self):
        payload = self.root / 'usr/bin/security-test'
        payload.write_bytes(b'partial payload')
        with self.assertRaises(fs.Refusal):
            self.cleanup(self.snap())
        self.assertEqual(payload.read_bytes(), b'partial payload')

    def test_lock_replaced_before_cleanup(self):
        before = self.snap()
        held = os.open(self.lock, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            self.lock.unlink()
            self.lock.write_bytes(b'')
            self.lock.chmod(0)
            self.assertNotEqual(os.fstat(held).st_ino, self.lock.stat().st_ino)
            with self.assertRaises(fs.Refusal):
                self.cleanup(before)
        finally:
            os.close(held)
        self.assertTrue(self.candidate.exists())
        self.assertTrue(self.lock.exists())

    def test_change_after_directory_removal_preserves_lock(self):
        before = self.snap()
        remove = os.rmdir
        def changed(name, **kwargs):
            remove(name, **kwargs)
            (self.local / 'base-1/desc').write_bytes(b'drift after first mutation')
        with patch.object(fs.os, 'rmdir', side_effect=changed):
            with self.assertRaises(fs.Refusal):
                self.cleanup(before)
        self.assertFalse(self.candidate.exists())
        self.assertTrue(self.lock.exists())

    def test_candidate_populated_at_rmdir_is_not_recursively_deleted(self):
        before = self.snap()
        remove = os.rmdir
        def populated(name, **kwargs):
            (self.candidate / 'unexpected').write_bytes(b'keep')
            remove(name, **kwargs)
        with patch.object(fs.os, 'rmdir', side_effect=populated):
            with self.assertRaises(OSError):
                self.cleanup(before)
        self.assertEqual((self.candidate / 'unexpected').read_bytes(), b'keep')
        self.assertTrue(self.lock.exists())

    def test_lock_mode_refused_without_chmod(self):
        self.lock.chmod(0o600)
        with self.assertRaises(fs.Refusal):
            self.snap()
        self.assertEqual(self.lock.stat().st_mode & 0o777, 0o600)

    def test_lock_nonempty_refused(self):
        self.lock.chmod(0o600)
        self.lock.write_bytes(b'busy')
        self.lock.chmod(0)
        with self.assertRaises(fs.Refusal):
            self.snap()

    def test_db_symlink_refused(self):
        (self.local / 'alias').symlink_to('base-1/desc')
        with self.assertRaises(fs.Refusal):
            self.snap()

    def test_payload_ancestor_symlink_refused(self):
        (self.root / 'usr/share').symlink_to('bin')
        with self.assertRaises(fs.Refusal):
            self.snap()

    def test_hardlinked_db_file_refused(self):
        os.link(self.local / 'base-1/desc', self.local / 'alias')
        with self.assertRaises(fs.Refusal):
            self.snap()

    def test_special_file_refused_without_opening(self):
        os.mkfifo(self.local / 'pipe')
        with self.assertRaises(fs.Refusal):
            self.snap()

    def test_path_traversal_absolute_and_overlap_refused(self):
        for names in [('../var/db',), ('/bin/file',), ('bin', 'bin/file'), ('a//b',)]:
            with self.subTest(names=names):
                with self.assertRaises(fs.Refusal):
                    fs.snapshot(self.fd, names, **self.owner)

    def test_wrong_owner_refused(self):
        with self.assertRaises(fs.Refusal):
            fs.snapshot(self.fd, self.names, owner_uid=os.geteuid() + 1, owner_gid=os.getegid())

    def test_regular_input_read_and_bounds(self):
        raw, entry = fs.read_regular(self.fd, 'var/lib/pacman/local/base-1/desc', maximum=64)
        self.assertEqual(raw, b'unchanged base database\n')
        self.assertEqual(entry['bytes'], len(raw))
        with self.assertRaises(fs.Refusal):
            fs.read_regular(self.fd, 'var/lib/pacman/local/base-1/desc', maximum=2)
        with self.assertRaises(fs.Refusal):
            fs.read_regular(self.fd, '../outside')

    def test_regular_input_symlink_refused(self):
        (self.root / 'input-link').symlink_to('var/lib/pacman/local/base-1/desc')
        with self.assertRaises(fs.Refusal):
            fs.read_regular(self.fd, 'input-link')

    def test_file_node_and_snapshot_caps(self):
        with patch.object(fs, 'LEAF_CAP', 2):
            with self.assertRaises(fs.Refusal):
                self.snap()
        with patch.object(fs, 'NODE_CAP', 1):
            with self.assertRaises(fs.Refusal):
                self.snap()
        with patch.object(fs, 'SNAPSHOT_CAP', 2):
            with self.assertRaises(fs.Refusal):
                self.snap()

    def test_oversized_real_directory_is_bounded_without_listdir(self):
        for number in range(4):
            (self.local / 'base-1' / ('extra-' + str(number))).write_bytes(b'bounded')
        with patch.object(fs, 'NODE_CAP', 2), patch.object(
                fs.os, 'listdir', side_effect=AssertionError('unbounded enumeration')):
            with self.assertRaises(fs.Refusal):
                self.snap()
        self.assertTrue(self.candidate.exists())
        self.assertTrue(self.lock.exists())

    def test_mutating_file_during_capture_is_refused(self):
        read = os.read
        changed = False
        def mutation(fd, count):
            nonlocal changed
            if not changed:
                changed = True
                (self.local / 'base-1/desc').write_bytes(b'new database contents\n')
            return read(fd, count)
        with patch.object(fs.os, 'read', side_effect=mutation):
            with self.assertRaises(fs.Refusal):
                self.snap()


if __name__ == '__main__':
    unittest.main()
