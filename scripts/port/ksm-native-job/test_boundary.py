# SPDX-License-Identifier: MIT
"""Accepted-transport facade tests; no real daemon or CLI execution."""
from contextlib import nullcontext
import os
from pathlib import Path
import signal
import stat
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import boundary
import runtime


class BoundaryTests(unittest.TestCase):
    def test_bootstrap_and_each_raw_operation_use_sealed_capture_and_runtime(self):
        checked, invoked = [], []
        class Docker:
            def __init__(self, endpoint, expected, pin, device, inode):
                self.endpoint, self.expected, self.cli_sha256 = endpoint, expected, pin
                self.executable, self.exec_fd = '/proc/owned/fd/7', 7
            def check_files(self): checked.append('check')
            def identity(self):
                code, data = self.raw(['docker', '--host=' + self.endpoint, 'info', '--format', '{{.ID}}'])
                if code != 0 or data.decode().strip() != self.expected: raise ValueError('drift')
            def bounded(self, argv, **options):
                self.identity()
                try: return self.raw(argv, **options)
                finally: self.identity()
        def run(argv, **options):
            invoked.append((argv, options))
            return subprocess.CompletedProcess(argv, 0, b'daemon-identity\n')
        stage = SimpleNamespace(Docker=Docker, base=SimpleNamespace(docker_command=lambda endpoint,*args:
                                ['docker', '--host='+endpoint, *args], CANCELLED=False))
        info = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_uid=0, st_dev=1, st_ino=2)
        with patch.object(Path, 'resolve', lambda path: path), patch.object(Path, 'lstat', return_value=info):
            bound = boundary.create(stage, SimpleNamespace(defer_signals=lambda: nullcontext([]),
                                    check_cancelled=lambda: None, mark_cancelled=lambda: None),
                                    SimpleNamespace(run=run), 'a'*64)
            result = bound.call(['docker', '--host='+bound.endpoint, 'info'])
        self.assertEqual(result.returncode, 0)
        self.assertTrue(all(command[0] == '/proc/owned/fd/7' and options['pass_fds'] == (7,)
                            for command, options in invoked))
        self.assertEqual(len(checked), len(invoked)*2)

    def test_real_signal_in_post_identity_cannot_be_swallowed_into_another_state(self):
        class Docker:
            def __init__(self, endpoint, expected, pin, device, inode):
                self.endpoint, self.expected = endpoint, expected
                self.executable, self.exec_fd, self.identities = '/proc/owned/fd/7', 7, 0
            def check_files(self): pass
            def identity(self):
                self.identities += 1
                if self.identities == 3:
                    os.kill(os.getpid(), signal.SIGTERM)
        base = SimpleNamespace(CANCELLED=False, docker_command=lambda endpoint,*args:
                               ['docker','--host='+endpoint,*args])
        stage = SimpleNamespace(Docker=Docker, base=base)
        info = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_uid=0, st_dev=1, st_ino=2)
        runner = SimpleNamespace(run=lambda argv,**kw: subprocess.CompletedProcess(argv,0,b'daemon-identity\n'))
        with patch.object(Path,'resolve',lambda path:path), patch.object(Path,'lstat',return_value=info):
            with self.assertRaises(runtime.Cancelled):
                with runtime.cancellation_handlers() as state:
                    bound = boundary.create(stage,runtime,runner,'a'*64,daemon='daemon-identity')
                    bound.call(['docker','--host='+bound.endpoint,'info'])
            self.assertEqual(state.signum,signal.SIGTERM)

    def test_existing_held_base_cancel_memory_also_refuses_new_operations(self):
        class Docker:
            def __init__(self, endpoint, expected, *args):
                self.endpoint,self.expected=endpoint,expected
                self.executable,self.exec_fd='/proc/owned/fd/7',7
            def check_files(self): pass
            def identity(self): self.raw(['docker','--host='+self.endpoint,'info'])
        base=SimpleNamespace(CANCELLED=True,docker_command=lambda endpoint,*args:['docker','--host='+endpoint,*args])
        info=SimpleNamespace(st_mode=stat.S_IFSOCK|0o660,st_uid=0,st_dev=1,st_ino=2)
        calls=[]
        runner=SimpleNamespace(run=lambda argv,**kw:calls.append(argv))
        with patch.object(Path,'resolve',lambda path:path),patch.object(Path,'lstat',return_value=info):
            with self.assertRaises(runtime.Cancelled):
                with runtime.cancellation_handlers() as state:
                    boundary.create(SimpleNamespace(Docker=Docker,base=base),runtime,runner,'a'*64,daemon='daemon-identity')
            self.assertEqual(state.signum,signal.SIGTERM)
        self.assertEqual(calls,[])


if __name__ == '__main__':
    unittest.main()
