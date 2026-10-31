# SPDX-License-Identifier: MIT
"""Real fresh children only. Wrappers audit real syscalls; no modeled results."""
import contextlib
import ctypes
import importlib.util
import os
from pathlib import Path
import signal
import select
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('owned_process', ROOT / 'scripts/virtual/owned_process.py')
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)
WAITID, WAITPID, KILL, KILLPG = os.waitid, os.waitpid, os.kill, os.killpg


def terminal(pid, seconds=2):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        row = WAITID(os.P_PID, pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
        if row is not None:
            return row
        time.sleep(.005)
    raise AssertionError('fresh test child did not terminate')


@contextlib.contextmanager
def audit(pid, after_signal=None):
    """Trace the core without replacing any child/process result."""
    events = []
    released = False
    lost = False
    stat = R._stat

    def waitid(*args):
        nonlocal lost
        if args[1] == pid:
            if lost:
                raise AssertionError('probe after ECHILD')
            events.append('peek')
        try:
            return WAITID(*args)
        except ChildProcessError:
            if args[1] == pid:
                lost = True
                events.append('ECHILD')
            raise

    def waitpid(*args):
        nonlocal released
        events.append('raw_wait')
        got = WAITPID(*args)
        if got[0] == pid:
            released = True
        return got

    def read_stat(target):
        if lost:
            raise AssertionError('numeric proc probe after ECHILD')
        return stat(target)

    def send(target, sig, group):
        if target != pid or released or lost:
            raise AssertionError('foreign/released numeric signal')
        WAITID(os.P_PID, pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
        events.append(('group:' if group else 'direct:') + signal.Signals(sig).name)
        (KILLPG if group else KILL)(target, sig)
        if after_signal is not None:
            after_signal(sig)

    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.object(R.os, 'waitid', waitid))
        stack.enter_context(patch.object(R.os, 'waitpid', waitpid))
        stack.enter_context(patch.object(R.os, 'kill', lambda p, s: send(p, s, False)))
        stack.enter_context(patch.object(R.os, 'killpg', lambda p, s: send(p, s, True)))
        stack.enter_context(patch.object(R, '_stat', read_stat))
        yield events


class FreshChildren(unittest.TestCase):
    def setUp(self):
        R.prepare()
        self.children = []

    def tearDown(self):
        for child, group in self.children:
            pid = child.pid if isinstance(child, subprocess.Popen) else child
            try:
                WAITID(os.P_PID, pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
            except ChildProcessError:
                continue  # No signals or probes against released identities.
            R.supervise(child, cap=.8, retirement=.5, grace=.05, group=group)

    def launch(self, code, **kwargs):
        child = subprocess.Popen([sys.executable, '-I', '-B', '-c', code],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, start_new_session=True,
                                 **kwargs)
        self.children.append((child, True))
        return child

    def test_natural_exit_raw_status_and_bounded_output(self):
        child = self.launch("import os; os.write(1,b'out'); os.write(2,b'err')")
        with audit(child.pid) as events:
            result = R.supervise(child, cap=1, retirement=.5)
        self.assertTrue(result['passed'], result)
        self.assertEqual((result['exit'], child.returncode), (0, 0))
        self.assertEqual(events.count('raw_wait'), 1)
        self.assertFalse(result['signals'])
        self.assertEqual(len(result['output']), 6)
        self.assertEqual(result['group_census'], 'EMPTY_TWICE')

    def test_timeout_ignoring_term_kills_before_raw_reap(self):
        ready, announce = os.pipe()
        try:
            child = self.launch(f'import os,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); os.write({announce},b"R"); os.close({announce}); time.sleep(60)',
                                pass_fds=(announce,))
            os.close(announce)
            announce = None
            self.assertTrue(select.select([ready], [], [], 2)[0])
            self.assertEqual(os.read(ready, 1), b'R')
        finally:
            os.close(ready)
            if announce is not None:
                os.close(announce)
        with audit(child.pid) as events:
            result = R.supervise(child, cap=.7, retirement=.35, grace=.06)
        self.assertTrue(result['timeout'] and result['reaped'], result)
        self.assertEqual(result['exit'], -signal.SIGKILL)
        self.assertEqual(result['signals'], ['SIGTERM', 'SIGKILL'])
        self.assertLess(events.index('group:SIGKILL'), events.index('raw_wait'))
        self.assertLess(result['seconds'], .95)

    def test_same_group_descendant_term_and_leader_reaps_its_child(self):
        child = self.launch('''import os,signal,time
pid=os.fork()
if pid==0:
 def stop(sig,frame):
  os.write(1,b'descendant TERM\\n'); os._exit(0)
 signal.signal(signal.SIGTERM,stop)
 os.write(1,b'descendant ready\\n')
 while True: time.sleep(1)
def stop(sig,frame):
 os.waitpid(pid,0); os.write(1,b'leader reaped descendant\\n'); os._exit(0)
signal.signal(signal.SIGTERM,stop)
while True: time.sleep(1)
''')
        with audit(child.pid):
            result = R.supervise(child, cap=1, retirement=.5, grace=.2)
        self.assertTrue(result['reaped'] and result['timeout'], result)
        self.assertEqual(result['signals'], ['SIGTERM'])
        self.assertIn(b'descendant TERM', result['output'])
        self.assertIn(b'leader reaped descendant', result['output'])
        self.assertEqual(result['group_census'], 'EMPTY_TWICE')

    def test_stolen_wait_returns_unknown_without_any_numeric_probe(self):
        child = self.launch('import os; os._exit(23)')
        terminal(child.pid)
        got, status = WAITPID(child.pid, 0)
        self.assertEqual((got, os.waitstatus_to_exitcode(status)), (child.pid, 23))
        with audit(child.pid) as events:
            result = R.supervise(child, cap=.6, retirement=.3)
        self.assertEqual(result['ownership'], 'UNKNOWN')
        self.assertFalse(result['reaped'] or result['passed'] or result['signals'])
        self.assertIsNone(result['exit'])
        self.assertIsNone(child.returncode)
        self.assertFalse(child._child_created)
        self.assertEqual(events, ['peek', 'ECHILD'])
        self.assertEqual(result['group_census'], 'NOT_OBSERVED')

    def test_terminal_leader_reserved_through_descendant_kill(self):
        # This test process becomes a subreaper only for its fresh subtree, so
        # it can collect its known grandchild without relying on host PID 1.
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
        old = ctypes.c_int()
        self.assertEqual(libc.prctl(37, ctypes.addressof(old), 0, 0, 0), 0)
        self.assertEqual(libc.prctl(36, 1, 0, 0, 0), 0)
        ready, announce = os.pipe()
        grandchild = None
        try:
            child = self.launch(f'''import os,signal,time
pid=os.fork()
if pid==0:
 signal.signal(signal.SIGTERM,signal.SIG_IGN)
 os.write({announce},str(os.getpid()).encode()+b'\\n'); os.close({announce})
 while True: time.sleep(1)
os.close({announce}); os._exit(0)
''', pass_fds=(announce,))
            os.close(announce)
            announce = None
            grandchild = int(os.read(ready, 32))
            terminal(child.pid)
            terminal_seen = []

            def check_reserved(sig):
                row = WAITID(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
                terminal_seen.append(row is not None and row.si_status == 0)

            with audit(child.pid, check_reserved) as events:
                result = R.supervise(child, cap=.8, retirement=.35, grace=.04)
            self.assertTrue(result['reaped'], result)
            self.assertEqual(result['exit'], 0)
            self.assertEqual(result['signals'], ['SIGTERM', 'SIGKILL'])
            self.assertEqual(terminal_seen, [True, True])
            self.assertLess(events.index('group:SIGKILL'), events.index('raw_wait'))
            # Census is honest about a zombie that this test must still reap.
            self.assertIn(result['group_census'], ('PRESENT_OR_REUSED', 'UNKNOWN', 'NOT_OBSERVED'))
            terminal(grandchild)
            got, status = WAITPID(grandchild, 0)
            self.assertEqual((got, os.waitstatus_to_exitcode(status)), (grandchild, -signal.SIGKILL))
            grandchild = None
        finally:
            os.close(ready)
            if announce is not None:
                os.close(announce)
            if grandchild is not None:
                try:
                    WAITID(os.P_PID, grandchild, os.WEXITED | os.WNOWAIT | os.WNOHANG)
                except ChildProcessError:
                    pass
                else:
                    R.supervise(grandchild, cap=.7, retirement=.4, grace=.03, group=False)
            self.assertEqual(libc.prctl(36, old.value, 0, 0, 0), 0)

    def test_stolen_wait_after_term_suppresses_kill_and_census(self):
        child = self.launch('import time; time.sleep(60)')

        def steal(sig):
            self.assertEqual(sig, signal.SIGTERM)
            terminal(child.pid)
            self.assertEqual(WAITPID(child.pid, 0)[0], child.pid)

        with audit(child.pid, steal) as events:
            result = R.supervise(child, cap=.7, retirement=.35, grace=.03)
        self.assertEqual(result['ownership'], 'UNKNOWN', result)
        self.assertIsNone(result['exit'])
        self.assertEqual(result['signals'], ['SIGTERM'])
        self.assertEqual(events[-1], 'ECHILD')
        self.assertEqual(result['group_census'], 'NOT_OBSERVED')

    def test_buffered_log_failure_after_leader_exit(self):
        reader, writer = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        release = threading.Event()

        def logger():
            release.wait(2)
            os.close(reader)  # No PID, signals or ownership decisions here.

        thread = threading.Thread(target=logger)
        thread.start()
        try:
            child = self.launch("import os; os.write(1,b'buffered after leader exit')")
            terminal(child.pid)
            release.set()
            thread.join(2)
            self.assertFalse(thread.is_alive())
            with audit(child.pid) as events:
                result = R.supervise(child, cap=.8, retirement=.4, log_fd=writer)
            self.assertTrue(result['reaped'], result)
            self.assertEqual(result['exit'], 0)
            self.assertFalse(result['passed'] or result['signals'])
            self.assertIn('BrokenPipeError', result['error'])
            self.assertIn(b'buffered after leader exit', result['output'])
            self.assertEqual(events.count('raw_wait'), 1)
        finally:
            release.set()
            thread.join(2)
            os.close(writer)

    def test_combined_stdout_stderr_cap(self):
        child = self.launch("import os,time; os.write(1,b'a'*6000); os.write(2,b'b'*6000); time.sleep(60)")
        with audit(child.pid):
            result = R.supervise(child, cap=.8, retirement=.4, max_output=8192)
        self.assertTrue(result['reaped'], result)
        self.assertEqual(len(result['output']), 8192)
        self.assertIn('combined output cap', result['error'])
        self.assertFalse(result['passed'])

    def test_direct_fork_natural_exit(self):
        pid = os.fork()
        if pid == 0:
            os._exit(7)
        self.children.append((pid, False))
        with audit(pid) as events:
            result = R.supervise(pid, cap=.6, retirement=.3, group=False)
        self.assertTrue(result['reaped'], result)
        self.assertEqual(result['exit'], 7)
        self.assertEqual(result['group_census'], 'NOT_OBSERVED')
        self.assertFalse(result['signals'])
        self.assertEqual(events.count('raw_wait'), 1)

    def test_direct_fork_timeout_never_signals_callers_group(self):
        ready, write_ready = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(ready)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            os.write(write_ready, b'R')
            os.close(write_ready)
            time.sleep(.05)
            os.setsid()  # Direct custody remains valid across session changes.
            time.sleep(60)
            os._exit(0)
        os.close(write_ready)
        self.children.append((pid, False))
        try:
            self.assertEqual(os.read(ready, 1), b'R')
        finally:
            os.close(ready)
        with audit(pid) as events:
            result = R.supervise(pid, cap=.6, retirement=.3, grace=.03, group=False)
        self.assertTrue(result['reaped'] and result['timeout'], result)
        self.assertEqual(result['exit'], -signal.SIGKILL)
        self.assertIn('direct:SIGKILL', events)
        self.assertNotIn('group:SIGKILL', events)

    def test_lease_fd_retained_in_parent_and_child_through_retirement(self):
        lease, unused = os.pipe()
        try:
            child = self.launch(f'''import os,signal,time
fd={lease}
os.fstat(fd)
def stop(sig,frame):
 os.fstat(fd); os.write(1,b'lease open at retirement'); os._exit(0)
signal.signal(signal.SIGTERM,stop)
while True: time.sleep(1)
''', pass_fds=(lease,))
            with audit(child.pid):
                result = R.supervise(child, cap=.8, retirement=.4)
            self.assertIn(b'lease open at retirement', result['output'])
            self.assertTrue(result['reaped'], result)
            os.fstat(lease)
        finally:
            os.close(lease)
            os.close(unused)

    def test_ignored_sigchld_refused_before_creating_any_child(self):
        signal.signal(signal.SIGCHLD, signal.SIG_IGN)
        try:
            with self.assertRaises(ValueError):
                R.prepare()
        finally:
            signal.signal(signal.SIGCHLD, signal.SIG_DFL)

    def test_finite_caps(self):
        child = self.launch('import os; os._exit(0)')
        for cap in (float('nan'), float('inf'), -1, True):
            with self.assertRaises(ValueError):
                R.supervise(child, cap=cap)
        result = R.supervise(child, cap=.6, retirement=.3)
        self.assertTrue(result['passed'], result)


if __name__ == '__main__':
    unittest.main(verbosity=2)
