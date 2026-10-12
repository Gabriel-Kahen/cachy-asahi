"""Fresh committed-image verifier tests, temp state and mocked queries only."""
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import verify_derived as v


class DerivedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.system, self.inputs = self.root / 'system', self.root / 'inputs'
        self.system.mkdir(); self.inputs.mkdir()
        for name in ('root', 'tmp', 'home/alarm', 'var/cache/pacman/pkg', 'etc/pacman.d', 'var/lib', 'var/log', 'usr/share/test'):
            (self.system / name).mkdir(parents=True, exist_ok=True)
        self.payload = self.system / 'usr/share/test/data'; self.payload.write_text('baseline')
        self.lock = self.inputs / 'installed-packages.lock'; self.lock.write_text('base 1-1\noverlay 1-1\n')
        self.contract = {'script_sha256': v.sha(Path(v.__file__)), 'installed_packages_sha256': v.sha(self.lock),
                         'image_id': 'sha256:' + 'a' * 64, 'source_commit': 'b' * 40,
                         'baseline': [{'name': 'overlay', 'payload_sha256': {'usr/share/test/data': v.sha(self.payload)}}]}
        self.addCleanup(patch.stopall)
        patch.object(v, 'INPUTS', self.inputs).start()
        def query(argv):
            if argv[1] == '-Q':
                return self.lock.read_text()
            self.assertEqual(argv, ['/usr/bin/pacman', '-Ql', 'overlay'])
            return 'overlay /usr/share/test/\noverlay /usr/share/test/data\n'
        patch.object(v, 'command', side_effect=query).start()
        original = Path.lstat
        def observed(path, *args, **kwargs):
            result = original(path, *args, **kwargs)
            if path == self.payload:
                values = list(result); values[4] = values[5] = 0
                return os.stat_result(values)
            return result
        patch.object(Path, 'lstat', observed).start()
        patch.object(v.subprocess, 'run', side_effect=AssertionError('unexpected subprocess')).start()

    def test_fresh_image_payload_and_actual_empty_views(self):
        self.assertEqual(v.verify(self.contract, self.system)['status'], 'PASS')

    def test_underlying_tmp_residue_blocks_acceptance(self):
        (self.system / 'tmp/disabled-hooks.txt').write_text('underlying image residue')
        with self.assertRaises(ValueError):
            v.verify(self.contract, self.system)

    def test_private_keyring_or_payload_drift_blocks_acceptance(self):
        (self.system / 'etc/pacman.d/gnupg').mkdir()
        with self.assertRaises(ValueError):
            v.verify(self.contract, self.system)
        (self.system / 'etc/pacman.d/gnupg').rmdir()
        self.payload.write_text('changed')
        with self.assertRaises(ValueError):
            v.verify(self.contract, self.system)

    def test_symlinked_private_view_ancestor_refused(self):
        (self.system / 'home').rename(self.system / 'relocated-home')
        (self.system / 'home').symlink_to(self.system / 'relocated-home', target_is_directory=True)
        with self.assertRaises(ValueError):
            v.verify(self.contract, self.system)

    def test_hidden_tmp_or_external_runtime_mount_refused(self):
        table = {'/': {'fs': 'overlay', 'options': ['ro']}, '/inputs': {'fs': 'ext4', 'options': ['ro']},
                 '/runner': {'fs': 'ext4', 'options': ['ro']}, '/out': {'fs': 'ext4', 'options': ['rw']},
                 '/sys': {'fs': 'sysfs', 'options': ['ro', 'nosuid', 'nodev', 'noexec'], 'root': '/'},
                 '/proc': {'fs': 'proc', 'options': ['rw', 'nosuid', 'nodev', 'noexec'], 'root': '/'}}
        v.validate_mounts(table)
        for point, value in [('/tmp', {'fs': 'tmpfs', 'options': ['rw']}),
                             ('/sys/private-home', {'fs': 'tmpfs', 'options': ['ro']}),
                             ('/sys', {'fs': 'ext4', 'options': ['rw']})]:
            changed = copy.deepcopy(table); changed[point] = value
            with self.subTest(point=point), self.assertRaises(ValueError):
                v.validate_mounts(changed)

    def test_pseudo_filesystems_cannot_supply_data_or_runtime_files(self):
        table = {'/': {'fs': 'overlay', 'options': ['ro']},
                 '/inputs': {'fs': 'ext4', 'options': ['ro']},
                 '/runner': {'fs': 'ext4', 'options': ['ro']},
                 '/out': {'fs': 'ext4', 'options': ['rw']}}
        v.validate_mounts(table)
        for point in ('/inputs', '/runner', '/out', '/etc/hosts', '/etc/hostname', '/etc/resolv.conf'):
            for filesystem in ('proc', 'sysfs', 'cgroup2'):
                changed = copy.deepcopy(table)
                changed[point] = {'fs': filesystem, 'options': ['rw' if point == '/out' else 'ro']}
                with self.subTest(point=point, filesystem=filesystem), self.assertRaises(ValueError):
                    v.validate_mounts(changed)
        for options in ([], ['ro', 'rw']):
            changed = copy.deepcopy(table)
            changed['/inputs']['options'] = options
            with self.subTest(options=options), self.assertRaises(ValueError):
                v.validate_mounts(changed)


if __name__ == '__main__':
    unittest.main()
