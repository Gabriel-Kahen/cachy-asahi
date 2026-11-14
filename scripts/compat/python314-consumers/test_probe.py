#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Filesystem/real-child safety controls; consumer compilation lives in probe.py."""
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

import probe


class SafetyControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='python314-consumer-tests-')
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def test_output_inside_origin_refused_before_creation(self):
        original = self.root / 'original'
        original.mkdir()
        output = original / 'must-not-exist'
        result = subprocess.run(['/usr/bin/python3', '-B', str(probe.HERE / 'probe.py'),
                                 '--origin', str(original), '--output', str(output)],
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('output must be outside input evidence', result.stderr)
        self.assertEqual(list(original.iterdir()), [])

    def test_symlink_parent_cannot_hide_output_inside_origin(self):
        original = self.root / 'original'
        original.mkdir()
        alias = self.root / 'alias'
        alias.symlink_to(original, target_is_directory=True)
        result = subprocess.run(['/usr/bin/python3', '-B', str(probe.HERE / 'probe.py'),
                                 '--origin', str(original), '--output', str(alias / 'new')],
                                capture_output=True, text=True, timeout=10)
        self.assertIn('output must be outside input evidence', result.stderr)
        self.assertEqual(list(original.iterdir()), [])

    def test_escape_symlink_refused(self):
        tree = self.root / 'stage'
        tree.mkdir()
        (tree / 'outside').symlink_to('../other')
        (self.root / 'other').write_text('outside')
        with self.assertRaisesRegex(probe.Refusal, 'external stage symlink'):
            probe.inventory(tree)

    def test_fifo_refused_without_reading(self):
        os.mkfifo(self.root / 'pipe')
        with self.assertRaisesRegex(probe.Refusal, 'special stage file'):
            probe.inventory(self.root)

    def test_changed_file_mode_refused(self):
        (self.root / 'bin').mkdir()
        (self.root / 'lib').mkdir()
        (self.root / 'bin/python3.14').write_bytes(b'fixture')
        library = self.root / 'lib/libpython3.14.so.1.0'
        library.write_bytes(b'fixture')
        seal = probe.inventory(self.root)
        library.chmod(0o600)
        with self.assertRaisesRegex(probe.Refusal, 'changed'):
            probe.gate(self.root, seal, self.root / 'bin/python3.14')

    def test_timeout_kills_real_child(self):
        runner = probe.Runner(self.root)
        runner.deadline = time.monotonic() + 0.3
        with self.assertRaises(subprocess.TimeoutExpired):
            runner.run(['/usr/bin/python3', '-I', '-S', '-c',
                        'import os,time; print(os.getpid(), flush=True); time.sleep(10)'])
        pid = int((self.root / 'logs/00.txt').read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_foreign_archive_refused_before_extraction(self):
        evidence = self.root / 'evidence'
        (evidence / 'export').mkdir(parents=True)
        (evidence / 'export/python-3.14.8-1.1-x86_64.pkg.tar.zst').write_bytes(b'changed')
        output = self.root / 'output'
        output.mkdir()
        with self.assertRaisesRegex(probe.Refusal, 'unrecognized full-profile archive'):
            probe.extract_full(evidence, output)
        self.assertEqual(list(output.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
