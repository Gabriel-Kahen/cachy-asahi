# SPDX-License-Identifier: MIT
"""Focused real-child and failure controls; source-only checkout invocation."""
import importlib.util
import os
from pathlib import Path
import shutil
import signal
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('developer_workflow', ROOT / 'scripts/workflows/developer_workflow.py')
W = importlib.util.module_from_spec(spec)
spec.loader.exec_module(W)


class WorkflowTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='developer-workflow-test-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.logs = self.base / 'logs'; self.logs.mkdir()
        self.home = self.base / 'home'; self.home.mkdir()
        self.commands = W.Commands(self.logs, self.home, os.defpath, timeout=3, total=30, max_output=4096)

    def python(self, code, expected=0):
        return self.commands.run('control', [sys.executable, '-I', '-B', '-c', code], self.base, expected)

    def test_real_raw_output_and_retirement(self):
        self.assertEqual(self.python('import os;os.write(1,b"raw\\x00\\xff")'), b'raw\x00\xff')
        row = self.commands.records[0]
        self.assertTrue(row['success'])
        self.assertEqual(row['supervision']['group_census'], 'EMPTY_TWICE')
        self.assertEqual((self.logs / row['log']).read_bytes(), b'raw\x00\xff')

    def test_expected_failure_requires_real_nonzero(self):
        self.python('raise SystemExit(7)', 'nonzero')
        self.assertEqual(self.commands.records[0]['supervision']['exit'], 7)
        with self.assertRaises(W.Failure):
            self.python('pass', 'nonzero')

    def test_timeout_fails_and_reaps(self):
        with self.assertRaises(W.Failure):
            self.python('import time;time.sleep(30)')
        row = self.commands.records[0]['supervision']
        self.assertTrue(row['reaped'])
        self.assertTrue(row['timeout'])
        self.assertIn('SIGTERM', row['signals'])

    def test_overflow_fails_and_caps_raw_log(self):
        with self.assertRaises(W.Failure):
            self.python('import os;os.write(1,b"x"*100000)')
        row = self.commands.records[0]
        self.assertEqual((self.logs / row['log']).stat().st_size, 4096)
        self.assertIn('output cap exceeded', row['supervision']['error'])
        self.assertTrue(row['supervision']['reaped'])

    def test_missing_executable_is_not_success(self):
        with self.assertRaises(W.Failure):
            self.commands.run('missing', [str(self.base / 'absent')], self.base)
        self.assertIn('launch_error', self.commands.records[0])
        self.assertIsNone(self.commands.records[0]['supervision'])

    def test_late_log_failure_has_no_signal_authority(self):
        original = Path.write_bytes
        signals = []
        real_killpg = os.killpg
        def note(pid, sig):
            signals.append((pid, sig)); return real_killpg(pid, sig)
        def refuse(path, raw):
            if path.suffix == '.log':
                raise OSError('intentional late log failure')
            return original(path, raw)
        with mock.patch.object(os, 'killpg', side_effect=note), mock.patch.object(Path, 'write_bytes', refuse):
            with self.assertRaisesRegex(OSError, 'late log failure'):
                self.python('print("finished")')
        self.assertEqual(signals, [])

    def test_echild_never_becomes_success_or_signals(self):
        real = self.commands.core.supervise
        def stolen(child, **kwargs):
            os.waitpid(child.pid, 0)
            with mock.patch.object(self.commands.core, '_stat', side_effect=AssertionError('post-ECHILD probe')), \
                    mock.patch.object(os, 'killpg', side_effect=AssertionError('post-ECHILD signal')):
                return real(child, **kwargs)
        with mock.patch.object(self.commands.core, 'supervise', side_effect=stolen):
            with self.assertRaises(W.Failure):
                self.python('pass')
        result = self.commands.records[0]['supervision']
        self.assertEqual(result['ownership'], 'UNKNOWN')
        self.assertIsNone(result['exit'])
        self.assertFalse(result['reaped'])

    def test_core_pin_refuses_changed_dependency(self):
        with mock.patch.object(W, 'CORE_PIN', '0'*64):
            with self.assertRaisesRegex(ValueError, 'pin differs'):
                W.load_core()

    def test_missing_required_and_optional_are_explicit(self):
        tools = self.base / 'empty-tools'; tools.mkdir()
        report = W.run(self.base / 'missing', str(tools), timeout=2, total=5)
        self.assertEqual(report['status'], 'MISSING_TOOLS')
        self.assertEqual(report['missing_required'], list(W.REQUIRED))
        self.assertEqual(report['commands'], [])
        self.assertTrue(all(report['tools'][n]['status'] == 'MISSING_OPTIONAL' for n in W.OPTIONAL))
        self.assertEqual(report['physical_M2'], 'NOT_RUN')

    def test_present_tool_probe_is_not_a_completed_workflow(self):
        git = shutil.which('git', path=os.defpath)
        if git is None:
            self.skipTest('Git unavailable; partial inventory control NOT RUN')
        tools = self.base / 'partial-tools'; tools.mkdir()
        (tools / 'git').symlink_to(git)
        report = W.run(self.base / 'partial', str(tools), timeout=3, total=10)
        self.assertEqual(report['status'], 'MISSING_TOOLS')
        self.assertEqual(report['tools']['git']['workflow'], 'VERSION_ONLY_WORKFLOW_NOT_RUN')

    def test_elapsed_cap_is_required_even_after_reap(self):
        real = self.commands.core.supervise
        def delayed(child, **kwargs):
            result = real(child, **kwargs)
            result['seconds'] = kwargs['cap']
            return result
        with mock.patch.object(self.commands.core, 'supervise', side_effect=delayed):
            with self.assertRaises(W.Failure):
                self.python('pass')
        self.assertFalse(self.commands.records[0]['success'])

    def test_cancellation_defers_until_owned_child_retires(self):
        before = signal.getsignal(signal.SIGTERM)
        with self.assertRaises(W.Failure):
            self.python('import os,signal;os.kill(os.getppid(),signal.SIGTERM);print("retired")')
        result = self.commands.records[0]['supervision']
        self.assertTrue(result['reaped'])
        self.assertEqual(result['group_census'], 'EMPTY_TWICE')
        self.assertEqual(signal.getsignal(signal.SIGTERM), before)

    def test_output_reuse_and_alias_refused(self):
        with self.assertRaises(FileExistsError):
            W.run(self.logs)
        alias = self.base / 'alias'; alias.symlink_to(self.logs, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'aliases'):
            W.run(alias / 'new')

    def test_invalid_bounds_and_shell_strings_refused_before_launch(self):
        for timeout, total in ((float('nan'), 30), (1, 30), (61, 90), (15, 601), (20, 10)):
            with self.assertRaises(ValueError):
                W.run(self.base / 'not-created', timeout=timeout, total=total)
        with self.assertRaises(ValueError):
            self.commands.run('string', 'echo unsafe', self.base)
        with self.assertRaises(ValueError):
            self.commands.run('relative', ['python3', '--version'], self.base)
        self.assertFalse((self.base / 'not-created').exists())

    def test_real_incremental_compile_changed_source_and_failure(self):
        compiler = shutil.which('cc', path=os.defpath)
        if compiler is None:
            self.skipTest('cc unavailable; native compile controls NOT RUN')
        source = self.base / 'tiny.c'
        source.write_text('#include <stdio.h>\nint main(void){puts("first");}\n')
        target = self.base / 'tiny'
        builder = W.IncrementalBuild(self.commands)
        builder.build('first', compiler, source, target)
        self.assertEqual(self.commands.run('run-first', [str(target)], self.base), b'first\n')
        count = len(self.commands.records)
        builder.build('unchanged', compiler, source, target)
        self.assertEqual(len(self.commands.records), count)
        self.assertEqual(builder.records[-1]['outcome'], 'UNCHANGED')
        before = source.stat()
        source.write_text(source.read_text().replace('first', 'later'))
        os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns))
        builder.build('changed', compiler, source, target)
        self.assertEqual(self.commands.run('run-later', [str(target)], self.base), b'later\n')
        target.write_bytes(b'corrupt executable')
        builder.build('binary-tamper-rebuild', compiler, source, target)
        self.assertEqual(self.commands.run('run-restored', [str(target)], self.base), b'later\n')
        source.write_text('#error INTENTIONAL_TEST_FAILURE\n')
        builder.build('failure', compiler, source, target, expected='nonzero')
        self.assertFalse(target.exists())
        self.assertFalse(target.with_suffix('.state.json').exists())
        self.assertEqual(builder.records[-1]['outcome'], 'EXPECTED_COMPILE_FAILURE')


if __name__ == '__main__':
    unittest.main(verbosity=2)
