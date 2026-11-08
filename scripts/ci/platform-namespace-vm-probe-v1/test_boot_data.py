# SPDX-License-Identifier: MIT
"""Actor-denied bootstrap DATA controls; no mount, VM or guest execution."""
import contextlib
import ctypes
import io
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import Mock, mock_open, patch
sys.path.insert(0, str(Path(__file__).resolve().parent))
import boot as B

NONCE = 'b' * 32
RELEASE = 'MODELED-generic16k-NOT-OBSERVED'


class BootstrapData(unittest.TestCase):
    def setUp(self):
        for name in ('subprocess.Popen', 'subprocess.run', 'os.execve', 'socket.socket',
                     'ctypes.CDLL', 'os.makedirs'):
            self.enterContext(patch(name, side_effect=AssertionError('BOOT_DATA_ACTOR_DENIED:' + name)))

    def modeled_guard(self):
        for name, value in (('uname', types.SimpleNamespace(machine='aarch64', release=RELEASE)),
                            ('sysconf', 16384), ('getuid', 0), ('geteuid', 0),
                            ('getgid', 0), ('getegid', 0), ('getppid', 1), ('getpid', 2)):
            self.enterContext(patch.object(B.os, name, return_value=value))
        self.enterContext(patch.object(B.Path, 'is_dir', return_value=True))
        self.enterContext(patch.object(B.Path, 'is_symlink', return_value=False))
        self.enterContext(patch.object(B.Path, 'iterdir', return_value=iter(())))

    def modeled_boot(self, cmdline=None, mount_result=0):
        self.modeled_guard()
        library = Mock()
        library.mount.return_value = mount_result
        load = self.enterContext(patch.object(B.ctypes, 'CDLL', return_value=library))
        directories = self.enterContext(patch.object(B.os, 'makedirs'))
        command = ('namespace_vm_probe_v1=' + NONCE).encode() if cmdline is None else cmdline
        opened = self.enterContext(patch('builtins.open', mock_open(read_data=command)))
        return library, load, directories, opened

    def test_host_refuses_before_library_or_filesystem_mutation(self):
        with patch.object(B.os, 'uname', return_value=types.SimpleNamespace(machine='x86_64', release=RELEASE)):
            with self.assertRaisesRegex(ValueError, 'guest bootstrap only'):
                B.main(NONCE, RELEASE)

    def test_literal_identity_refuses_before_actor(self):
        for nonce, release in [('', RELEASE), (NONCE, '../kernel'), (NONCE.upper(), RELEASE)]:
            with self.subTest(nonce=nonce, release=release), self.assertRaisesRegex(ValueError, 'literal'):
                B.main(nonce, release)

    def test_nonroot_wrongpage_or_nonpid1_parent_refuses(self):
        self.modeled_guard()
        for name, value in [('geteuid', 23001), ('getegid', 23001), ('sysconf', 4096), ('getppid', 100), ('getpid', 1)]:
            with self.subTest(name=name), patch.object(B.os, name, return_value=value):
                with self.assertRaisesRegex(ValueError, 'guest bootstrap only'):
                    B.main(NONCE, RELEASE)

    def test_existing_proc_refuses_host_or_bootstrap_reentry(self):
        self.modeled_guard()
        with patch.object(B.Path, 'iterdir', return_value=iter([Path('/proc/1')])):
            with self.assertRaisesRegex(ValueError, 'empty harness proc'):
                B.main(NONCE, RELEASE)

    def test_fixed_mounts_types_flags_and_directories_without_applets(self):
        library, load, directories, opened = self.modeled_boot()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(B.main(NONCE, RELEASE), 0)
        load.assert_called_once_with(None, use_errno=True)
        self.assertEqual(library.mount.argtypes, [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                                               ctypes.c_ulong, ctypes.c_void_p])
        self.assertIs(library.mount.restype, ctypes.c_int)
        self.assertEqual([c.args for c in library.mount.call_args_list],
                         [(b'proc', b'/proc', b'proc', 14, None), (b'devtmpfs', b'/dev', b'devtmpfs', 2, None)])
        self.assertEqual([c.args for c in directories.call_args_list],
                         [('/dev',), ('/tmp',), ('/home',), ('/var/lib/pacman',)])
        opened.assert_called_once_with('/proc/cmdline', 'rb')
        self.assertEqual(output.getvalue(), 'NSVM_BOOT_READY_V1 ' + NONCE + '\n')

    def test_failed_proc_mount_stops_before_cmdline_or_devtmpfs(self):
        library, _, directories, opened = self.modeled_boot(mount_result=-1)
        with patch.object(B.ctypes, 'get_errno', return_value=1):
            with self.assertRaises(OSError) as error:
                B.main(NONCE, RELEASE)
        self.assertEqual(error.exception.errno, 1)
        self.assertEqual(library.mount.call_count, 1)
        directories.assert_not_called()
        opened.assert_not_called()

    def test_wrong_or_overlong_nonce_commandline_stops_before_devtmpfs(self):
        for command in [b'namespace_vm_probe_v1=' + b'c' * 32, b'x' * 8193]:
            with self.subTest(command_bytes=len(command)):
                with contextlib.ExitStack() as stack:
                    library = Mock(); library.mount.return_value = 0
                    stack.enter_context(patch.object(B, 'guard'))
                    stack.enter_context(patch.object(B.ctypes, 'CDLL', return_value=library))
                    stack.enter_context(patch('builtins.open', mock_open(read_data=command)))
                    with self.assertRaisesRegex(ValueError, 'exact marked guest'):
                        B.main(NONCE, RELEASE)
                    self.assertEqual(library.mount.call_count, 1)

    def test_symlink_directory_refuses_before_devtmpfs(self):
        library, _, _, _ = self.modeled_boot()
        with patch.object(B, 'guard'), patch.object(B.Path, 'is_symlink', return_value=True):
            with self.assertRaisesRegex(ValueError, 'ordinary guest bootstrap directory'):
                B.main(NONCE, RELEASE)
        self.assertEqual(library.mount.call_count, 1)

    def test_failed_devtmpfs_never_emits_boot_ready(self):
        library, _, _, _ = self.modeled_boot()
        library.mount.side_effect = [0, -1]
        output = io.StringIO()
        with patch.object(B.ctypes, 'get_errno', return_value=19), contextlib.redirect_stdout(output):
            with self.assertRaises(OSError):
                B.main(NONCE, RELEASE)
        self.assertEqual(output.getvalue(), '')


if __name__ == '__main__':
    unittest.main()
