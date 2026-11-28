# SPDX-License-Identifier: MIT
"""Local owned-directory controls. Archive data are inert test fixtures."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest

import seed_archives as seeds


class ArchiveSeed(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='updater-retained-test-')
        self.addCleanup(temp.cleanup)
        self.control = Path(temp.name)
        self.source = self.control / 'retained-cache'
        self.source.mkdir(mode=0o700)
        self.target = self.control / 'stage/private/archives'
        self.target.parent.mkdir(parents=True, mode=0o700)
        self.name = 'fixture.pkg.tar.xz'
        self.payload = b'fixture\n'
        self.expected = {self.name: (len(self.payload), hashlib.sha256(self.payload).hexdigest())}

    def write(self, name, data):
        path = self.source / name
        path.write_bytes(data)
        path.chmod(0o600)
        return path

    def test_copies_only_present_pinned_bytes_to_fresh_private_cache(self):
        source = self.write(self.name, self.payload)
        self.expected['absent'] = (0, hashlib.sha256(b'').hexdigest())
        result = seeds.seed(self.source, self.target, self.expected)
        self.assertEqual(result, {'copied': 1, 'bytes': len(self.payload)})
        target, = self.target.iterdir()
        self.assertEqual(target.read_bytes(), source.read_bytes())
        self.assertNotEqual(target.stat().st_ino, source.stat().st_ino)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            seeds.seed(self.source, self.target, self.expected)

    def test_extra_and_empty_sets_refused_before_target_creation(self):
        with self.assertRaisesRegex(ValueError, 'nonempty retained cache'):
            seeds.seed(self.source, self.target, self.expected)
        self.write('.git-credentials', b'inert fixture')
        with self.assertRaisesRegex(ValueError, 'foreign retained input'):
            seeds.seed(self.source, self.target, self.expected)
        self.assertFalse(self.target.exists())

    def test_changed_bytes_refused(self):
        self.write(self.name, b'changed\n')
        with self.assertRaisesRegex(ValueError, 'retained input bytes'):
            seeds.seed(self.source, self.target, self.expected)

    def test_rejects_hardlink_symlink_fifo_and_loose_file_modes(self):
        victim = self.control / 'fixture'
        victim.write_bytes(self.payload)
        victim.chmod(0o600)
        path = self.source / self.name
        for make in (lambda: os.link(victim, path), lambda: path.symlink_to(victim),
                     lambda: os.mkfifo(path, 0o600),
                     lambda: self.write(self.name, self.payload).chmod(0o644)):
            with self.subTest(make=make):
                make()
                with self.assertRaises((OSError, ValueError)):
                    seeds.seed(self.source, self.target, self.expected)
                path.unlink()
                self.target.rmdir()

    def test_outside_control_or_alias_source_refused(self):
        elsewhere = self.control / 'elsewhere'
        elsewhere.mkdir(mode=0o700)
        self.source.rmdir()
        self.source.symlink_to(elsewhere)
        for source in (elsewhere, self.source):
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, 'canonical control'):
                seeds.seed(source, self.target, self.expected)

    def test_production_file_set_reuses_updater_plan(self):
        files = seeds.planned_files()
        self.assertEqual(len(files), 527)
        self.assertEqual(files['parallel-20260922-1-any.pkg.tar.xz'],
                         (369204, 'abd4a16e9348cc1bb0f39b7affb92a18c81efae1e791dee30c548b170a7ba4ec'))
