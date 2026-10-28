#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Owned inert child commands only; no package or service execution."""
import os
import sys
import tempfile
import time
import unittest
from unittest import mock
import subprocess
import signal
import supervision

from supervision import run


class Supervision(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.cwd = self.temporary.name
        self.env = {'PATH':'/usr/bin:/bin'}

    def command(self, source, **kwargs):
        return run([sys.executable, '-I', '-B', '-c', source], env=self.env, cwd=self.cwd, **kwargs)

    def test_finite_stdout_stderr_and_nonzero_return_are_preserved(self):
        row = self.command('import sys; print("ok"); print("failure", file=sys.stderr); sys.exit(7)',timeout=3)
        self.assertEqual((row['stdout'],row['stderr'],row['returncode']),(b'ok\n',b'failure\n',7))
        self.assertIsNone(row['termination'])
        self.assertTrue(row['direct_child_reaped'])

    def test_timeout_does_not_wait_for_lingering_pipe_descendant(self):
        started=time.monotonic()
        row=self.command('import os,time; child=os.fork(); time.sleep(30) if child==0 else None',timeout=.2)
        self.assertEqual(row['termination'],'timeout')
        self.assertLess(time.monotonic()-started,3)
        self.assertTrue(row['group_kill_sent'])

    def test_output_flood_is_bounded_and_killed(self):
        row=self.command('import os;\nwhile True: os.write(1,b"x"*4096)',timeout=3,output_limit=8192)
        self.assertEqual(row['termination'],'output-limit')
        self.assertLessEqual(len(row['stdout'])+len(row['stderr']),8192)
        self.assertTrue(row['direct_child_reaped'])

    def test_group_signals_precede_the_only_reap_after_natural_exit(self):
        events=[];actual_popen=subprocess.Popen;actual_kill=os.killpg
        def spawn(*args,**kwargs):
            process=actual_popen(*args,**kwargs);wait=process.wait
            def reap(*a,**kw):events.append('wait');return wait(*a,**kw)
            process.wait=reap;return process
        def kill(pid,sig):events.append(sig);return actual_kill(pid,sig)
        with mock.patch.object(supervision.subprocess,'Popen',spawn),mock.patch.object(supervision.os,'killpg',kill):
            self.command('print("done")',timeout=3)
        self.assertEqual(events[-1],'wait')
        self.assertEqual(events.count('wait'),1)
        self.assertIn(signal.SIGTERM,events[:-1]);self.assertIn(signal.SIGKILL,events[:-1])

    def test_selector_setup_exception_still_terminates_and_reaps_owned_child(self):
        children=[];actual_popen=subprocess.Popen
        def spawn(*args,**kwargs):
            process=actual_popen(*args,**kwargs);children.append(process);return process
        with mock.patch.object(supervision.subprocess,'Popen',spawn), \
             mock.patch.object(supervision.selectors,'DefaultSelector',side_effect=OSError('TEST selector failure')):
            with self.assertRaises(OSError):self.command('import time;time.sleep(30)',timeout=3)
        self.assertEqual(len(children),1);self.assertIsNotNone(children[0].returncode)

    def test_invalid_bounds_refuse_before_any_child(self):
        with self.assertRaises(ValueError):
            self.command('raise AssertionError',timeout=0)


if __name__=='__main__': unittest.main(verbosity=2)
