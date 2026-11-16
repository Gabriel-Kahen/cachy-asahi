#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Disposable watcher/locker processes; no Wayland clients or system services."""
from contextlib import redirect_stderr
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import signal
import subprocess
import sys
import threading
import time
import unittest

T = runpy.run_path(str(Path(__file__).with_name('test_session_lock.py')))
S = T['S']
SOURCE = T['SOURCE']
WATCHER = r'''
import json, os, signal, sys, time
from pathlib import Path
log, mode = sys.argv[1:3]
with open(log, 'a') as output:
    output.write(json.dumps({'name': 'watcher-start', 'pid': os.getpid(), 'argv': sys.argv[3:], 'env': dict(os.environ)}) + '\n')
if mode == 'failed':
    sys.exit(7)
if mode == 'stubborn':
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
if mode not in ('silent', 'stubborn'):
    time.sleep(.03)
    os.write(1, b'bad' if mode == 'invalid' else b'\n' * (4096 if mode == 'flood' else 1))
if mode == 'twice':
    time.sleep(.4)
    os.write(1, b'\n')
if mode == 'backlog':
    time.sleep(.08)
    os.write(1, b'\n')
if mode == 'one':
    time.sleep(.3)
    sys.exit(7)
if mode == 'during-lock':
    time.sleep(.06)
    sys.exit(7)
time.sleep(60)
'''


class Idle(unittest.TestCase):
    command, events, names = (T['SessionLock'].command, T['SessionLock'].events, T['SessionLock'].names)

    def setUp(self):
        T['SessionLock'].setUp(self)
        self.watcher = self.work / 'watcher.py'
        self.watcher.write_text(WATCHER)
        self.env = {**self.env, 'PATH': '/usr/bin', 'LC_ALL': 'C.UTF-8'}

    def watcher_command(self, mode='one'):
        return (sys.executable, '-I', '-B', str(self.watcher), str(self.log), mode)

    def cancel_when(self, cancelled, predicate, delay=0):
        def watch():
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline and not predicate():
                time.sleep(.01)
            time.sleep(delay)
            cancelled.append(signal.SIGTERM)
        thread = threading.Thread(target=watch)
        thread.start()
        self.addCleanup(thread.join)

    def run_idle(self, mode='one', cancelled=None, locker_mode='ready'):
        return S.run_idle(self.env, cancelled if cancelled is not None else [], 300,
                          idle_command=self.watcher_command(mode),
                          locker_command=self.command('locker', locker_mode))

    def assert_watcher_reaped(self):
        pid = next(e['pid'] for e in self.events() if e['name'] == 'watcher-start')
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_idle_event_uses_existing_ready_confirmed_lock_and_fixed_argv(self):
        with self.assertRaises(S.Refused):
            self.run_idle()
        self.assertEqual(self.names(), ['watcher-start', 'locker-start', 'ready', 'locker-exit'])
        watcher = self.events()[0]
        self.assertEqual(watcher['argv'], ['-C', '/dev/null', '-w', 'timeout', '300', S.IDLE_EVENT])
        self.assertEqual(watcher['env'], self.env)
        self.assert_watcher_reaped()

    def test_repeated_idle_cycles_lock_twice_and_cancellation_retires_watcher(self):
        cancelled = []
        self.cancel_when(cancelled, lambda: self.names().count('locker-exit') == 2)
        self.assertEqual(self.run_idle('twice', cancelled), 1)
        self.assertEqual(self.names().count('ready'), 2)
        self.assertNotIn('request-start', self.names())
        self.assertNotIn('locker-signalled', self.names())
        self.assert_watcher_reaped()

    def test_events_during_lock_are_discarded_after_unlock(self):
        cancelled = []
        self.cancel_when(cancelled, lambda: self.names().count('locker-exit') == 1, delay=.2)
        self.assertEqual(self.run_idle('backlog', cancelled), 1)
        self.assertEqual(self.names().count('locker-start'), 1)
        self.assert_watcher_reaped()

    def test_missing_watcher_or_precancellation_starts_no_locker(self):
        self.assertEqual(self.run_idle(cancelled=[signal.SIGTERM]), 1)
        with self.assertRaises(OSError):
            S.run_idle(self.env, [], 300, idle_command=('/missing/swayidle',))
        self.assertEqual(self.events(), [])
        with S.session_guard(self.env, 'idle:'):
            pass

    def test_failed_watcher_does_not_fall_back_to_a_locker(self):
        with self.assertRaises(S.Refused):
            self.run_idle('failed')
        self.assertEqual(self.names(), ['watcher-start'])
        self.assert_watcher_reaped()

    def test_watcher_exit_during_lock_preserves_normal_authentication(self):
        with self.assertRaises(S.Refused):
            self.run_idle('during-lock')
        self.assertEqual(self.names(), ['watcher-start', 'locker-start', 'ready', 'locker-exit'])
        self.assert_watcher_reaped()

    def test_invalid_or_excessive_notifications_refuse_and_retire_watcher(self):
        for mode in ('invalid', 'flood'):
            with self.subTest(mode=mode), self.assertRaises(S.Refused):
                self.run_idle(mode)
        self.assertEqual(self.names().count('locker-start'), 0)
        for event in self.events():
            with self.assertRaises(ProcessLookupError):
                os.kill(event['pid'], 0)

    def test_stubborn_watcher_is_killed_after_bounded_termination_wait(self):
        cancelled = []
        self.cancel_when(cancelled, lambda: 'watcher-start' in self.names())
        self.assertEqual(self.run_idle('stubborn', cancelled), 1)
        self.assert_watcher_reaped()

    def test_second_idle_guard_refuses_before_watcher_start(self):
        with S.session_guard(self.env, 'idle:'), self.assertRaises(S.AlreadyActive):
            self.run_idle()
        self.assertEqual(self.events(), [])

    def test_active_manual_guard_skips_event_without_stopping_owner(self):
        cancelled = []
        timer = threading.Timer(.2, lambda: cancelled.append(signal.SIGTERM))
        timer.start()
        self.addCleanup(timer.join)
        with S.session_guard(self.env):
            self.assertEqual(self.run_idle('backlog', cancelled), 1)
        self.assertEqual(self.names(), ['watcher-start'])
        self.assert_watcher_reaped()

    def test_unsafe_manual_guard_is_not_treated_as_an_active_lock(self):
        suffix = hashlib.sha256(b'wayland-1').hexdigest()[:16]
        guard = self.runtime / f'{S.NAME}-{suffix}.lock'
        guard.write_text('preserve')
        guard.chmod(0o644)
        with self.assertRaisesRegex(S.Refused, 'unsafe'):
            self.run_idle('backlog')
        self.assertEqual(guard.read_text(), 'preserve')
        self.assertEqual(self.names(), ['watcher-start'])
        self.assert_watcher_reaped()

    def test_lock_failure_stops_automatic_locking_without_sleep_request(self):
        self.assertEqual(self.run_idle('backlog', locker_mode='exit'), 1)
        self.assertEqual(self.names(), ['watcher-start', 'locker-start'])
        self.assert_watcher_reaped()

    def test_actual_sigterm_preserves_locker_and_reaps_watcher(self):
        driver = self.work / 'driver.py'
        driver.write_text('import runpy, sys\n' + f'm = runpy.run_path({str(SOURCE)!r})\n' +
                          "with m['cancellation_signals']() as cancelled:\n" +
                          f"    status = m['run_idle']({self.env!r}, cancelled, 300,\n" +
                          f"        idle_command={self.watcher_command('backlog')!r},\n" +
                          f"        locker_command={self.command('locker', lifetime=.3)!r})\n" +
                          'sys.exit(status)\n')
        process = subprocess.Popen([sys.executable, '-I', '-B', str(driver)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 3
            while 'ready' not in self.names() and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertIn('ready', self.names())
            process.send_signal(signal.SIGTERM)
            _, error = process.communicate(timeout=4)
            self.assertEqual(process.returncode, 1, error)
            self.assertEqual(self.names(), ['watcher-start', 'locker-start', 'ready', 'locker-exit'])
            self.assert_watcher_reaped()
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=4)

    def test_cli_requires_explicit_bounded_idle_timeout_before_session_access(self):
        for args in (['idle'], ['idle', '--idle-seconds', '29'], ['idle', '--idle-seconds', '86401'],
                     ['idle', '--idle-seconds', 'nan'], ['idle', '--idle-seconds', '3.5'],
                     ['idle', '--idle-seconds', '３００'], ['lock', '--idle-seconds', '300']):
            with self.subTest(args=args):
                result = subprocess.run([str(SOURCE), *args], env={}, capture_output=True, timeout=3)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertNotIn(b'XDG_RUNTIME_DIR', result.stderr)
        for value in ('30', '300', '86400'):
            self.assertEqual(S.idle_seconds(value), int(value))
        result = subprocess.run(['/usr/bin/sh', '-c', S.IDLE_EVENT], env={'PATH': '/absent'},
                                capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'\n')


if __name__ == '__main__':
    unittest.main()
