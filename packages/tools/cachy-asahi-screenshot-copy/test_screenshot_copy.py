# SPDX-License-Identifier: MIT
"""Private executable recorders only; no screen or clipboard connection."""
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zlib

HERE = Path(__file__).resolve().parent
loader = importlib.machinery.SourceFileLoader('screenshot_copy', str(HERE / 'cachy-asahi-screenshot-copy'))
spec = importlib.util.spec_from_loader(loader.name, loader)
copy = importlib.util.module_from_spec(spec)
loader.exec_module(copy)


def png():
    def chunk(kind, data):
        return struct.pack('!I', len(data)) + kind + data + struct.pack('!I', zlib.crc32(kind + data))
    return (copy.PNG + chunk(b'IHDR', struct.pack('!2I5B', 1, 1, 8, 6, 0, 0, 0)) +
            chunk(b'IDAT', zlib.compress(b'\0\x11\x22\x33\xff')) + chunk(b'IEND', b''))


class Workflow(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='screenshot-copy-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.image = self.root / 'Saved image; literal.png'
        self.image.write_bytes(png()); self.image.chmod(0o600)
        self.capture_log = self.root / 'capture.json'
        self.clip_log = self.root / 'clipboard.bin'
        self.clip_args = self.root / 'clipboard.json'
        self.capture = self.root / 'capture'
        self.copier = self.root / 'copier'
        self.capture_script()
        self.copier_script()
        self.addCleanup(patch.stopall)
        patch.object(copy.shutil, 'which', side_effect=lambda name: str(
            {'wl-copy': self.copier, 'cachy-asahi-screenshot': self.capture}[name])).start()

    def script(self, path, body):
        path.write_text(f'#!{sys.executable}\n' + body)
        path.chmod(0o700)

    def capture_script(self, *, output=None, status=0):
        output = str(self.image).encode() + b'\n' if output is None else output
        self.script(self.capture, 'import sys,json\nfrom pathlib import Path\n' +
                    f'Path({str(self.capture_log)!r}).write_text(json.dumps(sys.argv[1:]))\n' +
                    f'sys.stdout.buffer.write({output!r})\nsys.exit({status})\n')

    def copier_script(self, *, status=0, wait=False):
        self.script(self.copier, 'import sys,json,time\nfrom pathlib import Path\n' +
                    f'Path({str(self.clip_args)!r}).write_text(json.dumps(sys.argv[1:]))\n' +
                    f'Path({str(self.clip_log)!r}).write_bytes(sys.stdin.buffer.read())\n' +
                    ('time.sleep(10)\n' if wait else '') + f'sys.exit({status})\n')

    def run_copy(self, *args):
        output, error = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            status = copy.main(list(args) or ['full'])
        return status, output.getvalue(), error.getvalue()

    def test_full_copies_exact_binary_png_with_explicit_mime_and_retains_file(self):
        before = self.image.read_bytes()
        status, output, error = self.run_copy()
        self.assertEqual(status, 0, error)
        self.assertEqual(output, str(self.image) + '\n')
        self.assertEqual(json.loads(self.capture_log.read_text()), ['full'])
        self.assertEqual(json.loads(self.clip_args.read_text()), ['--type', 'image/png'])
        self.assertEqual(self.clip_log.read_bytes(), before)
        self.assertEqual(self.image.read_bytes(), before)
        self.assertEqual(self.image.stat().st_mode & 0o777, 0o600)

    def test_region_and_explicit_directory_are_literal_arguments(self):
        directory = self.root / 'space; $(must not execute)'
        status, _, error = self.run_copy('region', '--directory', str(directory))
        self.assertEqual(status, 0, error)
        self.assertEqual(json.loads(self.capture_log.read_text()), ['region', '--directory', str(directory)])
        self.assertFalse(directory.exists())

    def test_capture_cancellation_never_invokes_clipboard_or_full_fallback(self):
        self.capture_script(output=b'', status=1)
        status, _, error = self.run_copy('region')
        self.assertEqual(status, 1)
        self.assertIn('not requested', error)
        self.assertFalse(self.clip_log.exists())
        self.assertEqual(json.loads(self.capture_log.read_text()), ['region'])

    def test_capture_failure_after_publication_keeps_saved_path_visible_without_copy(self):
        self.capture_script(status=1)
        status, output, _ = self.run_copy()
        self.assertEqual(status, 1)
        self.assertEqual(output, str(self.image) + '\n')
        self.assertTrue(self.image.exists()); self.assertFalse(self.clip_log.exists())

    def test_missing_clipboard_tool_refuses_before_capture(self):
        with patch.object(copy.shutil, 'which', return_value=None):
            status, _, error = self.run_copy()
        self.assertEqual(status, 1)
        self.assertIn('Missing wl-copy', error)
        self.assertFalse(self.capture_log.exists()); self.assertFalse(self.clip_log.exists())

    def test_invalid_capture_paths_preserve_file_and_do_not_copy(self):
        for output in (b'relative.png\n', b'/one\n/two\n', b'/invalid-\xff\n', b'', b'/no-newline'):
            with self.subTest(output=output):
                self.capture_script(output=output)
                status, _, _ = self.run_copy()
                self.assertEqual(status, 1)
                self.assertFalse(self.clip_log.exists()); self.assertTrue(self.image.exists())

    def test_symlink_public_mode_and_hardlink_refused_before_clipboard(self):
        for kind in ('symlink', 'mode', 'hardlink'):
            with self.subTest(kind=kind):
                extra = self.root / 'extra'
                if kind == 'symlink':
                    self.image.rename(extra); self.image.symlink_to(extra)
                elif kind == 'mode': self.image.chmod(0o644)
                else: os.link(self.image, extra)
                status, _, _ = self.run_copy()
                self.assertEqual(status, 1); self.assertFalse(self.clip_log.exists())
                if kind == 'symlink': self.image.unlink(); extra.rename(self.image)
                elif kind == 'mode': self.image.chmod(0o600)
                else: extra.unlink()
        self.assertEqual(self.image.read_bytes(), png())

    def test_invalid_png_and_size_limit_refuse_without_removing_file(self):
        for data in (b'not png' * 20, png()[:-1]):
            self.image.write_bytes(data)
            status, _, _ = self.run_copy()
            self.assertEqual(status, 1); self.assertFalse(self.clip_log.exists())
            self.assertEqual(self.image.read_bytes(), data)
        self.image.write_bytes(png())
        with patch.object(copy, 'MAX_BYTES', 45):
            self.assertEqual(self.run_copy()[0], 1)
        self.assertFalse(self.clip_log.exists())

    def test_clipboard_failure_preserves_file_and_reports_unknown_outcome(self):
        self.copier_script(status=3)
        status, output, error = self.run_copy()
        self.assertEqual(status, 1)
        self.assertEqual(output, str(self.image) + '\n')
        self.assertIn('outcome is unknown', error)
        self.assertIn('Saved PNG retained', error)
        self.assertEqual(self.image.read_bytes(), png())

    def test_real_clipboard_recorder_timeout_retains_png(self):
        self.copier_script(wait=True)
        with patch.object(copy, 'COPY_TIMEOUT', 0.2):
            status, _, error = self.run_copy()
        self.assertEqual(status, 1)
        self.assertIn('timed out', error)
        self.assertIn('outcome is unknown', error)
        self.assertEqual(self.image.read_bytes(), png())


if __name__ == '__main__':
    unittest.main()
