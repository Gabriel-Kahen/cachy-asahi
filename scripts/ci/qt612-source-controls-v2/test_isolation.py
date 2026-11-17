# SPDX-License-Identifier: MIT
"""Actual Python I/O boundaries over inert MODEL files; no private material or actors."""
import importlib.util
import os
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location('qt612_isolation_boundary', Path(__file__).with_name('isolation.py'))
ISOLATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ISOLATION)


class IsolationBoundaryControls(unittest.TestCase):
    def test_absolute_and_directory_fd_boundaries(self):
        # The controller owns TMPDIR and removes it only after this process exits.
        # The permanent inner guard deliberately prevents cleanup of these siblings.
        base = Path(os.environ['TMPDIR']).resolve()
        workspace, scratch, cache = (base / name for name in (
            'inner-MODEL-workspace', 'inner-MODEL-scratch', 'unbound-MODEL-cache'))
        for directory in (workspace, scratch, cache):
            directory.mkdir()
        body = b'Inert MODEL pinned public source bytes\n'
        public = workspace / 'pinned-public.txt'
        public.write_bytes(body)
        unknown = workspace / 'unpinned-public.txt'
        unknown.write_bytes(b'Inert MODEL unpinned public bytes\n')
        cached = cache / 'MODEL-cache.txt'
        cached.write_bytes(b'Inert MODEL cache bytes; no actual private material\n')
        workspace_fd, scratch_fd, cache_fd = (
            os.open(directory, os.O_RDONLY | os.O_DIRECTORY) for directory in (workspace, scratch, cache))

        def denied_open(name, flags, directory):
            fd = None
            try:
                with self.assertRaises(PermissionError):
                    fd = os.open(name, flags, 0o600, dir_fd=directory)
            finally:
                if fd is not None:
                    os.close(fd)

        try:
            seen = ISOLATION.install(workspace, scratch, ['pinned-public.txt'], wrapper_actor_fence=True)
            with self.subTest(boundary='pinned absolute read allowed'):
                self.assertEqual(public.read_bytes(), body)
                self.assertEqual(seen, {'pinned-public.txt'})
            with self.subTest(boundary='pinned directory-fd read allowed'):
                fd = os.open(public.name, os.O_RDONLY, dir_fd=workspace_fd)
                try:
                    self.assertEqual(os.read(fd, len(body) + 1), body)
                finally:
                    os.close(fd)
            with self.subTest(boundary='unpinned workspace absolute read denied'):
                with self.assertRaises(PermissionError):
                    unknown.read_bytes()
            with self.subTest(boundary='unbound MODEL cache absolute read denied'):
                with self.assertRaises(PermissionError):
                    cached.read_bytes()
            with self.subTest(boundary='unpinned workspace directory-fd read denied'):
                denied_open(unknown.name, os.O_RDONLY, workspace_fd)
            with self.subTest(boundary='unbound MODEL cache directory-fd read denied'):
                denied_open(cached.name, os.O_RDONLY, cache_fd)
            with self.subTest(boundary='owned scratch absolute and directory-fd writes allowed'):
                (scratch / 'absolute-write.txt').write_bytes(body)
                self.assertEqual((scratch / 'absolute-write.txt').read_bytes(), body)
                fd = os.open('directory-fd-write.txt', os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                             0o600, dir_fd=scratch_fd)
                try:
                    self.assertEqual(os.write(fd, body), len(body))
                finally:
                    os.close(fd)
                self.assertEqual((scratch / 'directory-fd-write.txt').read_bytes(), body)
            with self.subTest(boundary='outside absolute write denied'):
                outside = cache / 'must-not-create-absolute.txt'
                with self.assertRaises(PermissionError):
                    outside.write_bytes(body)
                self.assertFalse(outside.exists())
            with self.subTest(boundary='outside directory-fd write denied'):
                denied_open('must-not-create-directory-fd.txt', os.O_WRONLY | os.O_CREAT | os.O_EXCL, cache_fd)
                self.assertFalse((cache / 'must-not-create-directory-fd.txt').exists())
            with self.subTest(boundary='synthetic actor audit denied without an actor'):
                with self.assertRaisesRegex(ValueError, 'NO_ACTORS'):
                    sys.audit('socket.connect')
        finally:
            for fd in (workspace_fd, scratch_fd, cache_fd):
                os.close(fd)


if __name__ == '__main__':
    unittest.main(verbosity=2)
