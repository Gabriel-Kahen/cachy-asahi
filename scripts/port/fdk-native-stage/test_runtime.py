#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Owned Python process fixtures only; no Docker, compiler, or installer."""
import sys
sys.dont_write_bytecode = True

import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock

import runtime


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='fdk-runtime-fixture-')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.env = {'HOME': str(self.work), 'PATH': '/usr/bin:/bin',
                    'PYTHONDONTWRITEBYTECODE': '1', 'LC_ALL': 'C'}

    def runner(self, seconds=5):
        return runtime.Runner(seconds, self.env, self.work / 'logs')

    def python(self, code):
        return [sys.executable, '-B', '-c', code]

    def gone(self, pid):
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)
        with self.assertRaises(ChildProcessError):
            os.waitpid(pid, os.WNOHANG)

    def test_success_merged_bytes_explicit_env_and_exclusive_log(self):
        runner = self.runner()
        with mock.patch.dict(os.environ, {'DOCKER_HOST': 'must-not-inherit', 'LEAK': 'must-not-inherit'}):
            result = runner.run(self.python("import os;os.write(1,b'out');os.write(2,b'err');assert 'LEAK' not in os.environ;assert 'DOCKER_HOST' not in os.environ"), log='one.log')
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'outerr', None))
        self.assertEqual((self.work / 'logs/one.log').read_bytes(), b'outerr')
        with self.assertRaises(FileExistsError):
            runner.run(self.python("raise AssertionError('should not start')"), log='one.log')
        self.assertEqual((self.work / 'logs/one.log').read_bytes(), b'outerr')

    def test_nonzero_is_returned_for_adapter_classification(self):
        result = self.runner().run(self.python("import os;os.write(1,b'failed');raise SystemExit(7)"))
        self.assertEqual((result.returncode, result.stdout), (7, b'failed'))

    def test_timeout_kills_and_reaps_child_and_stubborn_grandchild(self):
        marker = self.work / 'pids'
        code = """import os,signal,time
pid=os.fork()
if pid==0:
 signal.signal(signal.SIGTERM,signal.SIG_IGN)
 while True:time.sleep(1)
open(%r,'w').write(str(os.getpid())+' '+str(pid))
while True:time.sleep(1)
""" % str(marker)
        start = time.monotonic()
        with self.assertRaisesRegex(ValueError, '^command-timeout$'):
            self.runner(6).run(self.python(code), timeout=.15)
        self.assertLess(time.monotonic() - start, 4)
        for pid in map(int, marker.read_text().split()):
            self.gone(pid)

    def test_leader_exit_does_not_leave_descendant_or_held_pipe(self):
        marker = self.work / 'pid'
        code = """import os,time
pid=os.fork()
if pid==0:
 while True:time.sleep(1)
open(%r,'w').write(str(pid))
os.write(1,b'leader output')
os._exit(0)
""" % str(marker)
        start = time.monotonic()
        result = self.runner().run(self.python(code), timeout=3)
        self.assertEqual((result.returncode, result.stdout), (0, b'leader output'))
        self.assertLess(time.monotonic() - start, 1.5)
        self.gone(int(marker.read_text()))

    def test_closed_stdout_does_not_bypass_timeout(self):
        code = "import os,time;os.close(1);os.close(2);time.sleep(10)"
        with self.assertRaisesRegex(ValueError, '^command-timeout$'):
            self.runner().run(self.python(code), timeout=.1)

    def test_output_bomb_is_bounded_logged_and_reaped(self):
        marker = self.work / 'pid'
        code = "import os;open(%r,'w').write(str(os.getpid()));\nwhile True:os.write(1,b'x'*65536)" % str(marker)
        with self.assertRaisesRegex(ValueError, '^output-bound$'):
            self.runner().run(self.python(code), timeout=2, limit=1024, log='bomb.log')
        self.assertEqual((self.work / 'logs/bomb.log').read_bytes(), b'x' * 1024)
        self.gone(int(marker.read_text()))

    def test_exact_output_limit_is_accepted(self):
        result = self.runner().run(self.python("import os;os.write(1,b'x'*1024)"), limit=1024)
        self.assertEqual(result.stdout, b'x' * 1024)

    def test_overall_deadline_caps_command_and_exhaustion_prevents_spawn(self):
        runner = self.runner(.12)
        with self.assertRaisesRegex(ValueError, '^command-timeout$'):
            runner.run(self.python('import time;time.sleep(10)'), timeout=3)
        with mock.patch.object(runtime.subprocess, 'Popen', side_effect=AssertionError('spawn after deadline')):
            with self.assertRaisesRegex(ValueError, '^deadline-exhausted$'):
                runner.run(self.python('pass'))

    def test_child_resource_limits_and_signal_mask_restored(self):
        code = """import ctypes,json,os,resource,signal
libc=ctypes.CDLL(None);v=ctypes.c_int();libc.prctl(2,ctypes.byref(v),0,0,0)
print(json.dumps({'limits':{n:resource.getrlimit(getattr(resource,n)) for n in ['RLIMIT_CPU','RLIMIT_AS','RLIMIT_FSIZE','RLIMIT_NOFILE','RLIMIT_CORE']},'mask':list(signal.pthread_sigmask(signal.SIG_BLOCK,[])),'pdeath':v.value,'group':os.getpgrp(),'pid':os.getpid()}))
"""
        before = signal.pthread_sigmask(signal.SIG_BLOCK, [])
        result = self.runner().run(self.python(code), timeout=.5)
        data = json.loads(result.stdout)
        self.assertEqual(data['mask'], sorted(map(int, before)))
        self.assertEqual(data['pdeath'], signal.SIGKILL)
        self.assertEqual(data['group'], data['pid'])
        maxima = {'RLIMIT_CPU': 6, 'RLIMIT_AS': 2 * 1024 ** 3,
                  'RLIMIT_FSIZE': 64 * 1024 ** 2, 'RLIMIT_NOFILE': 128, 'RLIMIT_CORE': 0}
        for name, maximum in maxima.items():
            soft, hard = data['limits'][name]
            self.assertLessEqual(soft, maximum)
            self.assertLessEqual(hard, maximum)
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, []), before)

    def test_invalid_bounds_arguments_environment_and_log_paths_never_spawn(self):
        for value in (0, -1, True, float('nan'), float('inf'), 10801, 2 ** 10000, '1'):
            with self.assertRaises(ValueError):
                self.runner(value)
        for env in (None, {'X': 1}, {'X': 'a\0b'}, {'BAD=KEY': 'x'}, {'X': 'x' * 65536}):
            with self.assertRaises(ValueError):
                runtime.Runner(2, env, self.work / 'logs')
        runner = self.runner()
        with mock.patch.object(runtime.subprocess, 'Popen', side_effect=AssertionError('invalid input spawned')):
            for args in ('shell text', [], [1], [''], ['x\0y'], ['x'] * 257, ['x' * 65536]):
                with self.assertRaises(ValueError):
                    runner.run(args)
            for value in (0, -1, True, float('nan'), float('inf'), 10801):
                with self.assertRaises(ValueError):
                    runner.run(self.python('pass'), timeout=value)
            for value in (0, -1, True, 8 * 1024 * 1024 + 1, 1.0):
                with self.assertRaises(ValueError):
                    runner.run(self.python('pass'), limit=value)
            for value in ('../escape', self.work / 'outside.log', 'nested/log'):
                with self.assertRaises(ValueError):
                    runner.run(self.python('pass'), log=value)

    def test_symlink_log_roots_and_threaded_preexec_are_refused(self):
        actual = self.work / 'actual'
        actual.mkdir()
        alias = self.work / 'alias'
        alias.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(ValueError):
            runtime.Runner(2, self.env, alias / 'logs')
        self.assertFalse((actual / 'logs').exists())
        runner = self.runner()
        event = threading.Event()
        thread = threading.Thread(target=event.wait)
        thread.start()
        try:
            with self.assertRaisesRegex(ValueError, '^threaded-runner$'):
                runner.run(self.python('pass'))
        finally:
            event.set()
            thread.join(timeout=1)

    def test_signal_contexts_restore_handlers_and_defer_cleanup_events(self):
        originals = {number: signal.getsignal(number) for number in runtime.SIGNALS}
        with runtime.cancellation_handlers():
            with self.assertRaises(runtime.Cancelled) as error:
                os.kill(os.getpid(), signal.SIGINT)
            self.assertEqual(error.exception.signum, signal.SIGINT)
            with runtime.defer_signals() as events:
                os.kill(os.getpid(), signal.SIGTERM)
                os.kill(os.getpid(), signal.SIGINT)
            self.assertEqual(events, [signal.SIGTERM, signal.SIGINT])
        self.assertEqual({number: signal.getsignal(number) for number in runtime.SIGNALS}, originals)

    def test_real_sigterm_cancellation_reaps_owned_tree(self):
        marker, ready = self.work / 'pids', self.work / 'ready'
        child = """import os,time
pid=os.fork()
if pid==0:
 while True:time.sleep(1)
open(%r,'w').write(str(os.getpid())+' '+str(pid))
while True:time.sleep(1)
""" % str(marker)
        helper = """import sys,time
sys.path.insert(0,%r)
import runtime
from pathlib import Path
with runtime.cancellation_handlers():
 try:
  runtime.Runner(10,%r,%r).run(%r,timeout=9)
 except runtime.Cancelled:
  Path(%r).write_text('cancelled')
 else:raise SystemExit(9)
""" % (str(Path(runtime.__file__).parent), self.env, str(self.work / 'helper-logs'),
        self.python(child), str(ready))
        process = subprocess.Popen(self.python(helper), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   env=self.env, start_new_session=True)
        try:
            end = time.monotonic() + 3
            while not marker.exists():
                self.assertIsNone(process.poll())
                self.assertLess(time.monotonic(), end)
                time.sleep(.01)
            os.kill(process.pid, signal.SIGTERM)
            output = process.communicate(timeout=5)[0]
            self.assertEqual(process.returncode, 0, output)
            self.assertEqual(ready.read_text(), 'cancelled')
            for pid in map(int, marker.read_text().split()):
                self.gone(pid)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
            process.stdout.close()


if __name__ == '__main__':
    unittest.main()
