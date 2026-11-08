"""Decompressor resource ownership with inert streams and no child processes."""
import io
from pathlib import Path
import sys
import tarfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts/checks'))
import package_checks as checks


def package_bytes():
    stream = io.BytesIO()
    contents = {
        '.PKGINFO': b'pkgname = fixture\npkgver = 1-1\narch = any\nlicense = MIT\n',
        '.BUILDINFO': ('format = 2\npkgname = fixture\npkgver = 1-1\npkgarch = any\n'
                       'pkgbuild_sha256sum = ' + 'a' * 64 + '\n').encode(),
        '.MTREE': b'inert metadata fixture',
    }
    with tarfile.open(fileobj=stream, mode='w') as archive:
        for name, content in contents.items():
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return stream.getvalue()


class Process:
    def __init__(self, output=None, diagnostic=b'diagnostic', status=0):
        self.stdout = io.BytesIO(package_bytes() if output is None else output)
        self.stderr = io.BytesIO(diagnostic)
        self.status = status
        self.wait_calls = 0

    def wait(self):
        self.wait_calls += 1
        return self.status


class PackageDecompressorTests(unittest.TestCase):
    def run_reader(self, raw, process):
        with patch.object(checks.Path, 'open', return_value=raw), \
                patch.object(checks.subprocess, 'Popen', return_value=process), \
                patch.object(checks, 'digest', return_value='a' * 64):
            return checks.package('fixture.pkg.tar.zst')

    def assert_retired(self, raw, process):
        self.assertTrue(raw.closed)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)
        self.assertEqual(process.wait_calls, 1)

    def test_archive_closes_if_spawn_fails_or_is_cancelled(self):
        for error in (FileNotFoundError('zstd missing'), KeyboardInterrupt()):
            raw = io.BytesIO()
            self.addCleanup(raw.close)
            with self.subTest(error=type(error).__name__), \
                    patch.object(checks.Path, 'open', return_value=raw), \
                    patch.object(checks.subprocess, 'Popen', side_effect=error):
                with self.assertRaises(type(error)) as raised:
                    checks.package('fixture.pkg.tar.zst')
                self.assertIs(raised.exception, error)
                self.assertTrue(raw.closed)

    def test_success_closes_all_streams_and_reaps_the_process(self):
        raw, process = io.BytesIO(), Process()
        result = self.run_reader(raw, process)
        self.assertEqual(result['status'], 'artifact-static-pass')
        self.assert_retired(raw, process)

    def test_nonzero_exit_retains_diagnostic_and_closes_resources(self):
        raw, process = io.BytesIO(), Process(status=1)
        with self.assertRaisesRegex(ValueError, 'zstd decompression failed: diagnostic'):
            self.run_reader(raw, process)
        self.assert_retired(raw, process)

    def test_archive_rejection_also_closes_resources(self):
        raw, process = io.BytesIO(), Process(output=b'not a tar archive')
        with self.assertRaises(tarfile.TarError):
            self.run_reader(raw, process)
        self.assert_retired(raw, process)

    def test_diagnostic_read_error_still_closes_and_reaps(self):
        for error in (OSError('diagnostic pipe failed'), KeyboardInterrupt()):
            for status in (0, 2):
                raw, process = io.BytesIO(), Process(status=status)
                with self.subTest(error=type(error).__name__, status=status):
                    with patch.object(process.stderr, 'read', side_effect=error):
                        with self.assertRaises(type(error)) as raised:
                            self.run_reader(raw, process)
                    self.assertIs(raised.exception, error)
                    self.assert_retired(raw, process)

    def test_stderr_close_error_does_not_skip_process_wait(self):
        raw, process = io.BytesIO(), Process()
        self.addCleanup(process.stderr.close)
        error = OSError('cannot close diagnostic pipe')
        with patch.object(process.stderr, 'close', side_effect=error) as close:
            with self.assertRaises(OSError) as raised:
                self.run_reader(raw, process)
        self.assertIs(raised.exception, error)
        close.assert_called_once_with()
        self.assertTrue(raw.closed)
        self.assertTrue(process.stdout.closed)
        self.assertEqual(process.wait_calls, 1)

    def test_stdout_close_error_still_closes_stderr_and_waits(self):
        raw, process = io.BytesIO(), Process()
        self.addCleanup(process.stdout.close)
        error = OSError('cannot close output pipe')
        with patch.object(process.stdout, 'close', side_effect=error) as close:
            with self.assertRaises(OSError) as raised:
                self.run_reader(raw, process)
        self.assertIs(raised.exception, error)
        close.assert_called_once_with()
        self.assertTrue(raw.closed)
        self.assertTrue(process.stderr.closed)
        self.assertEqual(process.wait_calls, 1)

    def test_diagnostic_decoding_and_message_bound_remain(self):
        raw, process = io.BytesIO(), Process(diagnostic=b'\xff' * 800, status=2)
        with self.assertRaises(ValueError) as raised:
            self.run_reader(raw, process)
        self.assertLess(len(str(raised.exception)), 550)
        self.assertIn('\ufffd', str(raised.exception))
        self.assert_retired(raw, process)

    def test_uncompressed_path_never_launches_a_decompressor(self):
        raw = io.BytesIO(package_bytes())
        with patch.object(checks.Path, 'open', return_value=raw), \
                patch.object(checks.subprocess, 'Popen') as spawn, \
                patch.object(checks, 'digest', return_value='a' * 64):
            self.assertEqual(checks.package('fixture.pkg.tar')['status'], 'artifact-static-pass')
        spawn.assert_not_called()
        self.assertTrue(raw.closed)


if __name__ == '__main__':
    unittest.main()
