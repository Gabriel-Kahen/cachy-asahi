# SPDX-License-Identifier: MIT
"""Execute the guest capture code with inert child, I/O and clock models."""

import json
import os
from pathlib import Path
import resource
from runpy import run_path
import selectors
import signal
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).parent
SOURCE = (HERE / "guest.sh").read_text()
WORKER = SOURCE.split("<<'PYTHON'\n", 1)[1].split("\nPYTHON\n", 1)[0]
PREFLIGHT = run_path(str(HERE / "preflight.py"))
COMMAND = ["/usr/bin/cmake", "--build", "/qt-recipe/src/build", "--parallel", "1",
           "--target", "lib/libQt6Core.so"]


def fence(event, _args):
    if event.startswith(("subprocess.", "socket.", "os.exec", "os.posix_spawn", "os.system")):
        raise AssertionError("Child process or socket forbidden in guest controls: " + event)


sys.addaudithook(fence)


class GuestControls(unittest.TestCase):
    def capture(self, chunks, *, status=0, stalled=False):
        clock = 0.0
        signals = []
        child = Mock(pid=10001)
        child.stdout.fileno.return_value = 55
        child.wait.return_value = status
        alive = stalled or sum(map(len, chunks)) > 8 * 1024**2

        def signal_child(pid, signum):
            nonlocal alive
            self.assertEqual(pid, child.pid)
            if not alive:
                raise ProcessLookupError
            if signum:
                signals.append(signum)
                alive = False

        def now():
            nonlocal clock
            clock += 0.01
            return clock

        env = {key: f"fixture-{key}" for key in (
            "PATH", "LC_ALL", "TZ", "HOME", "XDG_CONFIG_HOME", "TMPDIR", "SOURCE_DATE_EPOCH",
            "MAKEFLAGS", "CMAKE_BUILD_PARALLEL_LEVEL", "MAX_JOBS")}
        selector = Mock()
        selector.__enter__ = Mock(return_value=selector)
        selector.__exit__ = Mock()
        selector.select.return_value = [] if stalled else [(None, selectors.EVENT_READ)]
        with (
            TemporaryDirectory() as directory,
            patch.object(sys, "argv", ["-", directory]),
            patch.dict(os.environ, env | {"INHERITED_FLAG": "exclude"}, clear=True),
            patch.object(resource, "setrlimit"),
            patch.object(resource, "getrusage", return_value=SimpleNamespace(ru_maxrss=3241)),
            patch.object(signal, "signal"),
            patch.object(time, "monotonic", side_effect=now),
            patch.object(os, "read", side_effect=chunks),
            patch.object(os, "killpg", side_effect=signal_child),
            patch.object(selectors, "DefaultSelector", return_value=selector),
            patch.object(subprocess, "Popen", return_value=child) as popen,
        ):
            with self.assertRaises(SystemExit) as completed:
                exec(compile(WORKER, str(HERE / "guest.sh"), "exec"), {})
            popen.assert_called_once_with(COMMAND, env=env, stdin=subprocess.DEVNULL,
                                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                          start_new_session=True)
            child.stdout.close.assert_called_once_with()
            log = (Path(directory) / "build.log").read_bytes()
            metrics = json.loads((Path(directory) / "metrics.json").read_bytes())
        self.assertEqual(metrics["compile_exit"], completed.exception.code)
        self.assertEqual(metrics["peak_child_rss_kib"], 3241)
        return log, metrics, signals

    def test_success_and_compiler_failure_preserve_complete_log(self):
        for status in (0, 2):
            with self.subTest(status=status):
                log, metrics, signals = self.capture([b"first\n", b"last\n", b""], status=status)
                self.assertEqual(log, b"first\nlast\n")
                self.assertEqual(metrics["compile_exit"], status)
                self.assertTrue(metrics["log_complete"])
                self.assertEqual(signals, [])

    def test_output_overflow_bounds_partial_log_and_retires_group(self):
        log, metrics, signals = self.capture([bytes(65536)] * 128 + [b"x"])
        self.assertEqual(len(log), 8 * 1024**2)
        self.assertEqual(metrics["compile_exit"], 125)
        self.assertFalse(metrics["log_complete"])
        self.assertEqual(signals, [signal.SIGTERM])

    def test_timeout_retires_group_and_records_hold(self):
        log, metrics, signals = self.capture([], stalled=True)
        self.assertEqual(log, b"")
        self.assertEqual(metrics["compile_exit"], 124)
        self.assertFalse(metrics["log_complete"])
        self.assertEqual(signals, [signal.SIGTERM])

    def test_guest_pins_agree_with_preflight(self):
        pins = SOURCE.split("<<'PINS'\n", 1)[1].split("\nPINS\n", 1)[0]
        observed = dict((path, digest) for digest, path in (line.split() for line in pins.splitlines()))
        self.assertEqual(observed, {name: pin[1] for name, pin in PREFLIGHT["OPERANDS"].items()})
        core = PREFLIGHT["TARGETS"]["core"]
        self.assertIn(f'/usr/bin/ninja -t commands {core[0]}', SOURCE)
        self.assertIn(f"'{core[1]} {core[4][0]}'", SOURCE)
        self.assertIn(core[4][1], SOURCE)
        self.assertIn(f'deadline = started + {PREFLIGHT["CORE_LIMITS"]["guest_build_seconds"]}', WORKER)


if __name__ == "__main__":
    unittest.main(verbosity=2)
