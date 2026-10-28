"""Fresh committed-image verifier tests, temp state and mocked queries only."""
import copy
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import verify_derived as v


class ExposureTests(unittest.TestCase):
    def setUp(self):
        self.scanner = v.runtime_exposure
        self.addCleanup(patch.stopall)
        patch.object(v.subprocess, 'run', side_effect=AssertionError('unexpected subprocess')).start()
        patch.object(Path, 'open', side_effect=AssertionError('device content must not be opened')).start()

    def inspect(self, entries):
        rows = [(str(Path(name).parent), [], [Path(name).name]) for name in entries]
        with patch.object(v.os, 'walk', return_value=rows), patch.object(Path, 'lstat', lambda path: entries[str(path)]):
            self.scanner()

    def node(self, kind, major=0, minor=0):
        return SimpleNamespace(st_mode=kind | 0o600, st_rdev=os.makedev(major, minor), st_uid=0, st_gid=0)

    def test_exact_standard_character_nodes_and_pty_are_accepted(self):
        entries = {name: self.node(stat.S_IFCHR, *identity) for name, identity in v.DEVICE_NODES.items()}
        entries['/dev/pts/4'] = self.node(stat.S_IFCHR, 136, 4)
        entries['/usr/share/data'] = self.node(stat.S_IFREG)
        self.inspect(entries)

    def test_renamed_block_character_and_socket_nodes_are_refused_everywhere(self):
        for path in ('/dev/alias-disk', '/run/alias-control.sock', '/opt/alias',
                     '/inputs/alias', '/runner/alias', '/out/alias', '/tmp/alias', '/var/lib/alias'):
            for kind, identity in ((stat.S_IFBLK, (8, 1)), (stat.S_IFCHR, (10, 232)), (stat.S_IFSOCK, (0, 0))):
                with self.subTest(path=path, kind=kind), self.assertRaises(ValueError):
                    self.inspect({path: self.node(kind, *identity)})

    def test_standard_name_requires_exact_type_identity_and_location(self):
        for path, kind, identity in (('/dev/null', stat.S_IFCHR, (1, 1)),
                                      ('/dev/null', stat.S_IFBLK, (1, 3)),
                                      ('/dev/renamed-null', stat.S_IFCHR, (1, 3)),
                                      ('/dev/pts/4', stat.S_IFBLK, (136, 4)),
                                      ('/dev/pts/4', stat.S_IFCHR, (136, 5)),
                                      ('/dev/pts/4', stat.S_IFCHR, (10, 232)),
                                      ('/opt/pts/4', stat.S_IFCHR, (136, 4))):
            with self.subTest(path=path, kind=kind, identity=identity), self.assertRaises(ValueError):
                self.inspect({path: self.node(kind, *identity)})

    def test_traversal_prunes_only_validated_kernel_trees_and_symlink_directories(self):
        seen = []
        def walk(root, *, topdown, followlinks, onerror):
            self.assertEqual(root, '/'); self.assertTrue(topdown); self.assertFalse(followlinks)
            dirs = ['proc', 'sys', 'dev', 'run', 'opt', 'alias']
            yield '/', dirs, []
            seen.extend(dirs)
        def info(path):
            return self.node(stat.S_IFLNK if str(path) == '/alias' else stat.S_IFDIR)
        with patch.object(v.os, 'walk', side_effect=walk), patch.object(Path, 'lstat', info):
            v.runtime_exposure()
        self.assertEqual(seen, ['dev', 'run', 'opt'])

    def test_scan_error_and_size_bound_fail_closed_without_exception_content(self):
        def walk(*args, **kwargs):
            kwargs['onerror'](PermissionError('PRIVATE_FIXTURE'))
            return iter(())
        with patch.object(v.os, 'walk', side_effect=walk), self.assertRaisesRegex(ValueError, 'could not be completed') as raised:
            v.runtime_exposure()
        self.assertNotIn('PRIVATE_FIXTURE', str(raised.exception))
        with patch.object(Path, 'lstat', side_effect=OSError('PRIVATE_FIXTURE')):
            with patch.object(v.os, 'walk', return_value=[('/', [], ['alias'])]), self.assertRaisesRegex(ValueError, 'could not be completed'):
                v.runtime_exposure()
        with patch.object(v, 'EXPOSURE_LIMIT', 1), self.assertRaisesRegex(ValueError, 'exceeds bound'):
            self.inspect({'/run/a': self.node(stat.S_IFREG), '/run/b': self.node(stat.S_IFREG)})

    def test_alias_guard_refuses_before_contract_read_or_package_query(self):
        status = 'NoNewPrivs: 1\n' + ''.join(name + ': cb\n' for name in ('CapEff', 'CapPrm', 'CapBnd', 'CapInh', 'CapAmb'))
        mounts = '\n'.join(f'{n} 0 0:1 / {point} {mode} - {fs} none {mode}'
                           for n, (point, fs, mode) in enumerate((('/', 'overlay', 'ro'), ('/inputs', 'ext4', 'ro'),
                                                                ('/runner', 'ext4', 'ro'), ('/out', 'ext4', 'rw'))))
        def text(path):
            if str(path) == '/proc/self/status':
                return status
            self.assertEqual(str(path), '/proc/self/mountinfo')
            return mounts
        def exposure():
            self.inspect({'/run/alias-control.sock': self.node(stat.S_IFSOCK)})
        with patch.object(sys, 'argv', ['verify_derived.py', '--contract-sha256', 'a' * 64]), \
             patch.object(v.platform, 'machine', return_value='aarch64'), patch.object(v.os, 'geteuid', return_value=0), \
             patch.object(Path, 'is_file', return_value=True), patch.object(Path, 'is_symlink', return_value=False), \
             patch.object(Path, 'stat', return_value=SimpleNamespace(st_uid=0)), \
             patch.object(Path, 'lstat', return_value=self.node(stat.S_IFREG)), \
             patch.object(Path, 'iterdir', return_value=iter([Path('lo')])), patch.object(Path, 'exists', return_value=False), \
             patch.object(Path, 'read_text', text), patch.object(v, 'runtime_exposure', side_effect=exposure), \
             patch.object(v, 'sha') as checksum, patch.object(v, 'verify') as verify:
            with self.assertRaisesRegex(ValueError, 'sockets refused'):
                v.main()
            checksum.assert_not_called(); verify.assert_not_called()


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
