#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Actual local process fixtures; no Docker, network or package mutation."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('kernel_job_test_runtime', Path(__file__).with_name('runtime.py'))
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.runner = runtime.Runner(10, {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, self.base / 'logs')

    def tearDown(self):
        self.temp.cleanup()

    def command(self, code):
        return [sys.executable, '-I', '-B', '-c', code]

    def gone(self, pid):
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_parallel_shared_start_and_separate_outputs(self):
        first, second = self.base / 'first', self.base / 'second'
        def barrier(own, peer, word):
            return self.command(f"import time;from pathlib import Path;Path({str(own)!r}).touch();"
                                f"end=time.monotonic()+1\nwhile not Path({str(peer)!r}).exists():\n"
                                " if time.monotonic()>end:raise RuntimeError('not parallel')\n time.sleep(.01)\n"
                                f"print({word!r})")
        rows = self.runner.run_many([barrier(first, second, 'first'), barrier(second, first, 'second')], 3,
                                    ['first.log', 'second.log'])
        self.assertEqual([row.returncode for row in rows], [0, 0])
        self.assertEqual([row.stdout for row in rows], [b'first\n', b'second\n'])
        self.assertEqual((self.runner.log_dir / 'second.log').read_bytes(), b'second\n')

    def test_nonzero_exit_stops_peer_and_returns_actual_codes(self):
        rows = self.runner.run_many([self.command('import sys;sys.exit(7)'),
                                    self.command('import time;time.sleep(30)')], 3, [None, None])
        self.assertEqual(rows[0].returncode, 7)
        self.assertLess(rows[1].returncode, 0)

    def test_shared_deadline_is_not_per_child(self):
        began = time.monotonic()
        with self.assertRaisesRegex(ValueError, 'command-timeout'):
            self.runner.run_many([self.command('import time;time.sleep(.1)'),
                                  self.command('import time;time.sleep(30)')], .2, [None, None])
        self.assertLess(time.monotonic() - began, 2)

    def test_runner_deadline_dominates_requested_timeout(self):
        self.runner.deadline = time.monotonic() + .15
        began = time.monotonic()
        with self.assertRaisesRegex(ValueError, 'command-timeout'):
            self.runner.run(self.command('import time;time.sleep(30)'), timeout=3)
        self.assertLess(time.monotonic() - began, 2)

    def test_timeout_kills_and_reaps_stubborn_group_descendant(self):
        pidfile = self.base / 'pids'
        command = self.command("import os,signal,time;from pathlib import Path;"
                               "signal.signal(signal.SIGTERM,signal.SIG_IGN);child=os.fork();"
                               f"Path({str(pidfile)!r}).write_text(str(os.getpid())+' '+str(child)) if child else None;"
                               "time.sleep(30)")
        with self.assertRaisesRegex(ValueError, 'command-timeout'):
            self.runner.run_many([command, self.command('import time;time.sleep(30)')], .2, [None, None])
        for pid in map(int, pidfile.read_text().split()):
            self.gone(pid)

    def test_cancellation_pending_during_spawn_is_tracked(self):
        original = runtime.subprocess.Popen
        spawned = []
        def launch(*args, **kwargs):
            process = original(*args, **kwargs)
            spawned.append(process.pid)
            os.kill(os.getpid(), signal.SIGTERM)
            return process
        with runtime.cancellation_handlers(), patch.object(runtime.subprocess, 'Popen', side_effect=launch):
            with self.assertRaises(runtime.Cancelled):
                self.runner.run_many([self.command('import time;time.sleep(30)')] * 2, 3, [None, None])
        self.assertEqual(len(spawned), 1)
        self.gone(spawned[0])

    def test_second_spawn_failure_cleans_first(self):
        original = runtime.subprocess.Popen
        spawned = []
        def launch(*args, **kwargs):
            if spawned:
                raise OSError('second spawn failed')
            process = original(*args, **kwargs)
            spawned.append(process.pid)
            return process
        with patch.object(runtime.subprocess, 'Popen', side_effect=launch):
            with self.assertRaisesRegex(OSError, 'second spawn failed'):
                self.runner.run_many([self.command('import time;time.sleep(30)')] * 2, 3, [None, None])
        self.gone(spawned[0])

    def test_children_restore_spawn_signal_mask(self):
        command = self.command("import signal,json;print(json.dumps(sorted(int(s) for s in "
                               "signal.pthread_sigmask(signal.SIG_BLOCK,[]))))")
        rows = self.runner.run_many([command, command], 2, [None, None])
        for row in rows:
            blocked = json.loads(row.stdout)
            self.assertNotIn(signal.SIGINT, blocked)
            self.assertNotIn(signal.SIGTERM, blocked)

    def test_cancellation_during_cleanup_still_cleans_both(self):
        original = runtime._cleanup
        cleaned = []
        def cleanup(process):
            original(process)
            cleaned.append(process.pid)
            if len(cleaned) == 1:
                os.kill(os.getpid(), signal.SIGINT)
        with runtime.cancellation_handlers(), patch.object(runtime, '_cleanup', side_effect=cleanup):
            with self.assertRaises(runtime.Cancelled):
                self.runner.run_many([['/bin/true']] * 2, 2, [None, None])
        self.assertEqual(len(cleaned), 2)
        for pid in cleaned:
            self.gone(pid)

    def test_cleanup_failure_does_not_skip_peer(self):
        original = runtime._cleanup
        cleaned = []
        def cleanup(process):
            original(process)
            cleaned.append(process.pid)
            if len(cleaned) == 1:
                raise ValueError('first cleanup failed')
        with patch.object(runtime, '_cleanup', side_effect=cleanup):
            with self.assertRaisesRegex(ValueError, 'first cleanup failed'):
                self.runner.run_many([['/bin/true']] * 2, 2, [None, None])
        self.assertEqual(len(cleaned), 2)
        for pid in cleaned:
            self.gone(pid)

    def test_threaded_runner_refuses_before_spawn(self):
        with patch.object(runtime.threading, 'active_count', return_value=2), \
                patch.object(runtime.subprocess, 'Popen') as launch:
            with self.assertRaisesRegex(ValueError, 'threaded-runner'):
                self.runner.run_many([['/bin/true']] * 2, 2, [None, None])
            launch.assert_not_called()

    def test_output_bound_keeps_logs_finite_and_kills_peer(self):
        with self.assertRaisesRegex(ValueError, 'output-bound'):
            self.runner.run_many([self.command(f"import sys;sys.stdout.buffer.write(b'x'*{runtime.MAX_OUTPUT + 1})"),
                                  self.command('import time;time.sleep(30)')], 3, ['large.log', 'peer.log'])
        self.assertEqual((self.runner.log_dir / 'large.log').stat().st_size, runtime.MAX_OUTPUT)

    def test_single_command_limit_and_log_api(self):
        row = self.runner.run(self.command("print('ok')"), timeout=2, limit=4096, log='single.log')
        self.assertEqual((row.returncode, row.stdout), (0, b'ok\n'))
        self.assertEqual((self.runner.log_dir / 'single.log').read_bytes(), row.stdout)

    def test_exact_environment_and_child_limits(self):
        with patch.dict(os.environ, {'KERNEL_JOB_TEST_SECRET': 'must-not-inherit'}):
            row = self.runner.run(self.command("import os,json,resource;print(json.dumps({'env':dict(os.environ),"
                "'as':resource.getrlimit(resource.RLIMIT_AS),'core':resource.getrlimit(resource.RLIMIT_CORE)}))"), timeout=2)
        data = json.loads(row.stdout)
        self.assertEqual(data['env'], self.runner.env)
        self.assertGreaterEqual(data['as'][0], 10 * 1024**3)
        self.assertEqual(data['core'], [0, 0])

    def test_invalid_bounds_and_argv_refuse_before_spawn(self):
        cases = [(0, {}, 'invalid-time-bound'), (21600, {}, 'invalid-job-time-bound'),
                 (10, {'x': '\0'}, 'invalid-environment')]
        for seconds, env, error in cases:
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                runtime.Runner(seconds, env, self.base / 'other')
        with patch.object(runtime.subprocess, 'Popen') as launch:
            with self.assertRaisesRegex(ValueError, 'invalid-argv'):
                self.runner.run([''])
            with self.assertRaisesRegex(ValueError, 'parallel-command-count'):
                self.runner.run_many([['/bin/true']], 1, [None])
            launch.assert_not_called()

    def test_duplicate_logs_and_symlink_refuse(self):
        with self.assertRaisesRegex(ValueError, 'duplicate-log-path'):
            self.runner.run_many([['/bin/true']] * 2, 1, ['same.log'] * 2)
        outside = self.base / 'outside'; outside.write_text('untouched')
        (self.runner.log_dir / 'link.log').symlink_to(outside)
        with self.assertRaises(FileExistsError):
            self.runner.run(['/bin/true'], log='link.log')
        self.assertEqual(outside.read_text(), 'untouched')

    def test_real_term_during_handler_restoration_restores_both_before_cancel(self):
        previous = {number: signal.getsignal(number) for number in runtime.SIGNALS}
        actual = signal.signal; armed = False; injected = False
        def restore(number, handler):
            nonlocal injected
            result = actual(number, handler)
            if armed and not injected and number == signal.SIGINT and handler == previous[number]:
                injected = True; os.kill(os.getpid(), signal.SIGTERM)
            return result
        try:
            with patch.object(signal, 'signal', side_effect=restore):
                with self.assertRaises(runtime.Cancelled):
                    with runtime.cancellation_handlers(): armed = True
            self.assertTrue(injected)
            self.assertEqual({number: signal.getsignal(number) for number in runtime.SIGNALS}, previous)
        finally:
            for number, handler in previous.items(): actual(number, handler)

    def test_real_term_during_handler_installation_also_restores_pair(self):
        previous = {number: signal.getsignal(number) for number in runtime.SIGNALS}
        actual = signal.signal; injected = False
        def install(number, handler):
            nonlocal injected
            result = actual(number, handler)
            if not injected and number == signal.SIGINT and handler != previous[number]:
                injected = True; os.kill(os.getpid(), signal.SIGTERM)
            return result
        try:
            with patch.object(signal, 'signal', side_effect=install):
                with self.assertRaises(runtime.Cancelled):
                    with runtime.cancellation_handlers(): self.fail('pending cancellation reached work')
            self.assertEqual({number: signal.getsignal(number) for number in runtime.SIGNALS}, previous)
        finally:
            for number, handler in previous.items(): actual(number, handler)

    def test_deferred_term_during_restoration_is_recorded_after_pair_restore(self):
        previous = {number: signal.getsignal(number) for number in runtime.SIGNALS}
        actual = signal.signal; armed = False; injected = False
        def restore(number, handler):
            nonlocal injected
            result = actual(number, handler)
            if armed and not injected and number == signal.SIGINT and handler == previous[number]:
                injected = True; os.kill(os.getpid(), signal.SIGTERM)
            return result
        try:
            with patch.object(signal, 'signal', side_effect=restore):
                with runtime.defer_signals() as events: armed = True
            self.assertEqual(events, [signal.SIGTERM])
            self.assertEqual({number: signal.getsignal(number) for number in runtime.SIGNALS}, previous)
        finally:
            for number, handler in previous.items(): actual(number, handler)


if __name__ == '__main__':
    unittest.main()
