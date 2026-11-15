# SPDX-License-Identifier: MIT
"""Four bounded controls. Only the fixed Python child below may execute."""
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('runner', HERE / 'run.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
owned = r.load_module('test_owned', HERE / 'helpers/owned_child.py', r.HELPER_SHA)
CHILD = [sys.executable, '-I', '-B', '-c', 'import time; time.sleep(10)']


class Controls(unittest.TestCase):
    def test_whole_plan_substitution(self):
        plan = b'{"commands":[["pinned-perl","Makefile.PL"]]}\n'
        r.identical(plan, plan)
        with self.assertRaisesRegex(ValueError, 'substituted'):
            r.identical(plan.replace(b'pinned-perl', b'/usr/bin/perl'), plan)

    def test_cancellation_is_sticky(self):
        cancel = r.Cancellation()
        cancel.check()
        cancel.signal(signal.SIGTERM, None)
        for _ in range(2):
            with self.assertRaisesRegex(ValueError, 'cancelled'):
                cancel.check()

    def test_zero_or_forced_cleanup_is_not_success(self):
        self.assertFalse(r.natural_zero({'exit': 0}))
        row = dict(retirement='REAPED', group_absent=True,
                   leader_held_until_group_inspection=True, exit_observed_via_waitpid=True,
                   ownership_lost=False, natural_exit=True, forced_cleanup=True, exit=0)
        self.assertTrue(r.retired(row))
        self.assertFalse(r.natural_zero(row))
        row['ownership_lost'] = True
        self.assertFalse(r.retired(row))

    def test_cancel_reaps_owned_python_child(self):
        original = subprocess.Popen

        def fence(argv, **kwargs):
            if argv != CHILD:
                raise AssertionError('actor fence: only fixed sleeping Python child allowed')
            return original(argv, **kwargs)

        cancel = r.Cancellation()
        row = {}

        def tick():
            cancel.signal(signal.SIGTERM, None)
            cancel.check()

        with patch.object(subprocess, 'Popen', fence):
            with self.assertRaisesRegex(ValueError, 'cancelled'):
                owned.run(CHILD, timeout=2, env={}, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, lifecycle=row, on_tick=tick,
                          allowed_uids={os.getuid()})
        self.assertTrue(r.retired(row), row)
        self.assertTrue(row['forced_cleanup'], row)
        self.assertFalse(r.natural_zero(row), row)
        with self.assertRaises(ChildProcessError):
            os.waitpid(row['pid'], os.WNOHANG)


if __name__ == '__main__':
    unittest.main(verbosity=2)
