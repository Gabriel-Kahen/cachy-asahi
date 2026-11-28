#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Filesystem/real-child safety controls; consumer compilation lives in probe.py."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'python314_consumer_probe', Path(__file__).resolve().with_name('probe.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class SafetyControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='python314-consumer-tests-')
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def test_output_inside_origin_refused_before_creation(self):
        original = self.root / 'original'
        original.mkdir()
        output = original / 'must-not-exist'
        result = subprocess.run([sys.executable, '-B', str(probe.HERE / 'probe.py'),
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
        result = subprocess.run([sys.executable, '-B', str(probe.HERE / 'probe.py'),
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
            runner.run([sys.executable, '-I', '-S', '-c',
                        'import os,time; print(os.getpid(), flush=True); time.sleep(10)'])
        pid = int((self.root / 'logs/00.txt').read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_zero_exit_with_live_descendant_refuses_and_retires_group(self):
        runner = probe.Runner(self.root)
        code = ('import os,time\n'
                'from pathlib import Path\n'
                'child = os.fork()\n'
                'if child == 0:\n'
                '    until = time.monotonic() + 10\n'
                '    while time.monotonic() < until and not Path("release-test-child").exists():\n'
                '        time.sleep(.01)\n'
                'else:\n'
                '    print(child, flush=True)\n')

        def live(pid):
            try:
                return (Path('/proc') / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()[0] not in ('Z', 'X')
            except FileNotFoundError:
                return False

        try:
            with self.assertRaisesRegex(probe.Refusal, 'owned process group|descendants'):
                runner.run([sys.executable, '-I', '-S', '-c', code])
        finally:
            try:
                pid = int((self.root / 'logs/00.txt').read_text())
                retired = not live(pid)
            finally:
                (self.root / 'release-test-child').touch()
            deadline = time.monotonic() + 2
            while live(pid) and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertTrue(retired, 'runner returned with live owned descendant')
        self.assertFalse(runner.commands)

    def test_clean_group_preserves_allowed_exit_and_output(self):
        runner = probe.Runner(self.root)
        with patch.object(probe.os, 'killpg', wraps=os.killpg) as group:
            result = runner.run([sys.executable, '-I', '-S', '-c', 'print("fixture"); raise SystemExit(3)'], allowed=(3,))
        self.assertEqual(result, (3, 'fixture\n'))
        self.assertEqual(runner.commands[0]['exit'], 3)
        self.assertTrue(group.called)
        self.assertTrue(all(call.args[1] == 0 for call in group.call_args_list))

    def test_still_present_group_refuses_with_bounded_wait(self):
        runner = probe.Runner(self.root)
        started = time.monotonic()
        with patch.object(probe.os, 'killpg') as group:
            with self.assertRaisesRegex(probe.Refusal, 'owned process group absence unverified'):
                runner.run([sys.executable, '-I', '-S', '-c', 'pass'])
        self.assertLess(time.monotonic() - started, 4)
        self.assertTrue(group.called)
        self.assertTrue(all(call.args[1] == 0 for call in group.call_args_list))
        self.assertFalse(runner.commands)

    def test_foreign_archive_refused_before_extraction(self):
        evidence = self.root / 'evidence'
        (evidence / 'export').mkdir(parents=True)
        (evidence / 'export/python-3.14.8-1.1-x86_64.pkg.tar.zst').write_bytes(b'changed')
        output = self.root / 'output'
        output.mkdir()
        with self.assertRaisesRegex(probe.Refusal, 'unrecognized full-profile archive'):
            probe.extract_full(evidence, output)
        self.assertEqual(list(output.iterdir()), [])

    def environment_cli(self, *, tamper):
        runner = self.root / 'python314-environments/run.py'
        helper = self.root / 'python314-consumers/probe.py'
        runner.parent.mkdir()
        helper.parent.mkdir()
        shutil.copyfile(probe.HERE.parent / 'python314-environments/run.py', runner)
        shutil.copyfile(probe.HERE / 'probe.py', helper)
        if tamper:
            with helper.open('ab') as stream:
                stream.write(b'\nraise AssertionError("unreviewed helper ran")\n')
        return subprocess.run([sys.executable, '-I', '-B', str(runner), '--help'],
                              capture_output=True, text=True, timeout=10)

    def test_environment_cli_loads_reviewed_helper(self):
        result = self.environment_cli(tamper=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--full-evidence', result.stdout)

    def test_environment_cli_refuses_changed_helper_before_execution(self):
        result = self.environment_cli(tamper=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('reviewed consumer support pin differs', result.stderr)
        self.assertNotIn('AssertionError: unreviewed helper ran', result.stderr)


if __name__ == '__main__':
    unittest.main()
