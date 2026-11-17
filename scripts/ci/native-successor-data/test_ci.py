#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Adversarial CI transport/result guards; no Root or native fixture."""
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('successor_ci_guards', HERE / 'ci.py')
C = importlib.util.module_from_spec(spec); spec.loader.exec_module(C)


def archive(rows):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as stream:
        for name, kind, raw in rows:
            row = tarfile.TarInfo(name); row.type = kind
            row.mode = 0o755 if kind == tarfile.DIRTYPE else 0o644
            if kind == tarfile.REGTYPE: row.size = len(raw)
            if kind == tarfile.SYMTYPE: row.linkname = 'target'
            stream.addfile(row, io.BytesIO(raw) if kind == tarfile.REGTYPE else None)
    return output.getvalue()


class Controls(unittest.TestCase):
    def setUp(self): self.fs = C.filesystem()

    def test_traversal_refused(self):
        for name in ('../escape', '/absolute', 'a/../escape'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                C.tar_files(archive([(name, tarfile.REGTYPE, b'DATA')]), self.fs)

    def test_symlink_and_hardlink_refused(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                C.tar_files(archive([('alias', kind, b'')]), self.fs)

    def test_duplicate_member_refused(self):
        with self.assertRaises(ValueError):
            C.tar_files(archive([('same', tarfile.REGTYPE, b'a'), ('same', tarfile.REGTYPE, b'b')]), self.fs)

    def test_complete_directory_census_required(self):
        for rows in ([('a/leaf', tarfile.REGTYPE, b'a')], [('extra', tarfile.DIRTYPE, b''), ('leaf', tarfile.REGTYPE, b'a')]):
            with self.subTest(rows=rows), self.assertRaises(ValueError): C.tar_files(archive(rows), self.fs)

    def test_nonzero_tail_and_truncation_refused(self):
        raw = archive([('leaf', tarfile.REGTYPE, b'a')])
        for wrong in (raw[:-1], raw[:-1] + b'x'):
            with self.subTest(size=len(wrong)), self.assertRaises(ValueError): C.tar_files(wrong, self.fs)

    def test_body_mode_and_alias_pin_refusals(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'input'; path.write_bytes(b'original'); path.chmod(0o644)
            expected = C.pin(path.read_bytes()); self.assertEqual(C.checked_file(path, expected, self.fs), b'original')
            path.write_bytes(b'changed!')
            with self.assertRaises(ValueError): C.checked_file(path, expected, self.fs)
            path.write_bytes(b'original'); path.chmod(0o600)
            with self.assertRaises(ValueError): C.checked_file(path, expected, self.fs)
            link = path.with_name('alias'); link.symlink_to(path)
            with self.assertRaises((ValueError, OSError)): C.checked_file(link, expected, self.fs)

    def test_skips_count_drift_and_actor_attempts_refuse(self):
        result = unittest.TestResult(); result.testsRun = 1
        self.assertEqual(C.require_result(result, [], 1)['tests'], 1)
        for attempts, count in (([], 2), (['socket.connect'], 1)):
            with self.subTest(attempts=attempts, count=count), self.assertRaises(ValueError): C.require_result(result, attempts, count)
        selection = dict(original_count=2, registered_count=1, registered_methods=['test_registered'],
                         blocked_methods={'test_unavailable': 'explicit missing public carrier'})
        raw = b'class Controls:\n def test_registered(self): pass\n def test_unavailable(self): pass\n'
        C.native_members(raw, selection)
        with self.assertRaises(ValueError): C.native_members(raw + b' def test_new(self): pass\n', selection)
        result.skipped.append(('MODEL', 'unavailable fixture'))
        with self.assertRaises(ValueError): C.require_result(result, [], 1)

    def test_portability_preserves_input_paths_and_actor_fence(self):
        target = Path('/owned/ci-tmp')
        for value in ('/home/gabe', Path('/home/gabe/.cache')): self.assertEqual(C.temporary_parent(value, target), target)
        for value in (None, '/tmp', '/owned/real-input'): self.assertEqual(C.temporary_parent(value, target), value)
        for event in ('socket.connect', 'subprocess.Popen', 'os.fork', 'resource.setrlimit', 'fcntl.flock'):
            self.assertTrue(C.actor_forbidden(event, ()))
        self.assertFalse(C.actor_forbidden('ctypes.dlopen', (None,)))
        self.assertTrue(C.actor_forbidden('ctypes.dlopen', ('/tmp/foreign.so',)))


if __name__ == '__main__': unittest.main(verbosity=2)
