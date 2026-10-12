"""Real bounded child-process checks; no signing or native acceptance evidence."""
import os
from pathlib import Path
import signal
import tempfile
import time
import unittest
from unittest import mock

import adapter


class CommandsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='restage-command-regression-')
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.commands = adapter.Commands(self.work)

    def test_output_flood_is_refused_without_unbounded_capture(self):
        with self.assertRaisesRegex(adapter.Refused, 'output limit'):
            self.commands.run(['python3', '-I', '-c', 'import sys; sys.stdout.buffer.write(b"x" * 3000000)'])
        self.assertFalse(self.commands.records)

    def test_timeout_kills_descendants_holding_output_pipes(self):
        pidfile = self.work / 'child-pid'
        program = ('import pathlib, subprocess, sys; '
                   'p = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(30)"]); '
                   f'pathlib.Path({str(pidfile)!r}).write_text(str(p.pid))')
        with mock.patch.object(adapter, 'TIMEOUT', 1):
            with self.assertRaisesRegex(adapter.Refused, 'timeout'):
                self.commands.run(['python3', '-I', '-c', program])
        pid = int(pidfile.read_text())
        self.addCleanup(self.stop_if_alive, pid)
        deadline = time.monotonic() + 3
        while Path(f'/proc/{pid}/stat').exists():
            raw = Path(f'/proc/{pid}/stat').read_bytes()
            if raw.rsplit(b')', 1)[1].split()[0] == b'Z':
                break
            self.assertLess(time.monotonic(), deadline, 'descendant survived timeout cleanup')
            time.sleep(0.02)

    @staticmethod
    def stop_if_alive(pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def test_tool_drift_is_refused_before_execution(self):
        self.commands.pins['python3'] = '0' * 64
        with mock.patch.object(adapter.subprocess, 'Popen', side_effect=AssertionError('must not launch')):
            with self.assertRaisesRegex(adapter.Refused, 'tool changed before'):
                self.commands.run(['python3', '-I', '-c', 'pass'])

    def test_parent_traversal_cannot_alias_an_input_read(self):
        (self.work / 'sub').mkdir()
        (self.work / 'input').write_bytes(b'retained input')
        with self.assertRaisesRegex(adapter.Refused, 'canonical absolute input'):
            adapter.read(self.work / 'sub' / '..' / 'input')

    def test_parent_traversal_cannot_redirect_output_creation(self):
        (self.work / 'sub').mkdir()
        with self.assertRaisesRegex(adapter.Refused, 'canonical absolute output'):
            adapter.Publication(self.work / 'sub' / '..' / 'output')
        self.assertFalse((self.work / 'output').exists())

    def test_spawn_assignment_cancellation_reaps_real_owned_child(self):
        real = adapter.subprocess.Popen
        for sig in (signal.SIGTERM, signal.SIGINT):
            children = []
            def spawn(*args, **kwargs):
                child = real(*args, **kwargs)
                children.append(child)
                os.kill(os.getpid(), sig)
                return child
            try:
                with self.subTest(signal=sig), adapter.cancellation_handlers(), \
                     mock.patch.object(adapter.subprocess, 'Popen', side_effect=spawn):
                    with self.assertRaises(KeyboardInterrupt):
                        self.commands.run(['python3', '-I', '-c', 'import time; time.sleep(30)'])
                self.assertEqual(len(children), 1)
                self.assertIsNotNone(children[0].poll(), 'spawned child survived assignment cancellation')
                self.assertTrue(children[0].stdout.closed)
                self.assertTrue(children[0].stderr.closed)
                self.assertFalse(self.commands.records)
            finally:
                for child in children:
                    self.stop_if_alive(child.pid)
                    child.wait(timeout=5)
                    child.stdout.close(); child.stderr.close()

    def test_secondary_signal_during_spawn_cleanup_cannot_leave_child_alive(self):
        real_spawn, real_kill = adapter.subprocess.Popen, os.killpg
        children = []
        def spawn(*args, **kwargs):
            child = real_spawn(*args, **kwargs); children.append(child)
            os.kill(os.getpid(), signal.SIGTERM)
            return child
        def kill(pid, sig):
            os.kill(os.getpid(), signal.SIGINT)
            return real_kill(pid, sig)
        try:
            with adapter.cancellation_handlers(), \
                 mock.patch.object(adapter.subprocess, 'Popen', side_effect=spawn), \
                 mock.patch.object(adapter.os, 'killpg', side_effect=kill):
                with self.assertRaises(KeyboardInterrupt):
                    self.commands.run(['python3', '-I', '-c', 'import time; time.sleep(30)'])
            self.assertEqual(len(children), 1)
            self.assertIsNotNone(children[0].poll(), 'second signal interrupted owned-child cleanup')
            self.assertTrue(children[0].stdout.closed and children[0].stderr.closed)
            self.assertFalse(self.commands.records)
        finally:
            for child in children:
                try:
                    real_kill(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait(timeout=5)
                child.stdout.close(); child.stderr.close()

    def test_nested_spawn_guard_relays_signal_until_outer_cleanup_finishes(self):
        completed = []
        with adapter.cancellation_handlers(), self.assertRaises(KeyboardInterrupt):
            with adapter.defer_cancellation():
                with adapter.defer_cancellation():
                    os.kill(os.getpid(), signal.SIGTERM)
                completed.append('inner spawn assigned')
                completed.append('outer private cleanup finished')
        self.assertEqual(completed, ['inner spawn assigned', 'outer private cleanup finished'])
        self.assertEqual(adapter.common_runtime().PENDING, [])


if __name__ == '__main__':
    unittest.main()
