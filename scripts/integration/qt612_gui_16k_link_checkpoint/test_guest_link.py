# SPDX-License-Identifier: MIT
"""Verify the QtGui guest contract with inert process and graph models."""

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

HERE = Path(__file__).resolve().parent
G = run_path(str(HERE / "guest_link.py"))
Q3 = run_path(str(HERE.parent / "qt612_base_16k_link_preflight/preflight.py"))


def fence(event, _args):
    if event.startswith(("subprocess.", "socket.", "os.exec", "os.posix_spawn", "os.system")):
        raise AssertionError("Child or socket operation in offline controls: " + event)


sys.addaudithook(fence)


class GuestControls(unittest.TestCase):
    def test_q3_pins_and_exact_selected_target(self):
        self.assertEqual(G["Q3_PINS"], Q3["OPERANDS"])
        self.assertEqual(G["CORE_COMMANDS"], Q3["TARGETS"]["core"][4])
        self.assertEqual(G["GUI_COMMANDS"], Q3["TARGETS"]["gui"][4])
        self.assertEqual(G["GUI_LINK"], Q3["LINKS"]["gui"])
        self.assertEqual(Q3["TARGETS"]["gui"][1:4], (639, 597, ("Core", "DBus", "Gui")))
        self.assertEqual(G["BUILD_ARGV"], ["/usr/bin/cmake", "--build", "/qt-recipe/src/build",
                                           "--parallel", "1", "--target", "lib/libQt6Gui.so"])

    def test_guest_requires_exact_pinned_unissued_plan_and_external_limits(self):
        plan = dict(kind="QTGUI_LINK_GUEST_PLAN_V1", authority=None, nonce="0" * 32, target=G["TARGET"],
                    core=dict(bytes=7020001, sha256="a" * 64),
                    limits=dict(guest_build_seconds=8000, build_log_bytes=3000, artifact_bytes=2097152))
        with TemporaryDirectory() as tmp:
            leaf = Path(tmp) / "plan.json"

            def store(selected):
                raw = (json.dumps(selected, sort_keys=True, separators=(",", ":")) + "\n").encode()
                leaf.write_bytes(raw)
                return G["body_pin"](raw)[1]

            self.assertEqual(G["read_plan"](leaf, store(plan)), plan)
            with self.assertRaisesRegex(ValueError, "Exact guest plan SHA-256"):
                G["read_plan"](leaf, "c" * 64)
            for bad in (plan | {"authority": "Root"}, plan | {"target": "all"},
                        plan | {"limits": plan["limits"] | {"guest_build_seconds": True}},
                        plan | {"limits": {"build_log_bytes": 3000, "artifact_bytes": 2097152}}):
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    G["read_plan"](leaf, store(bad))

    def test_incremental_dry_run_requires_ordered_pinned_successor_commands(self):
        core = b"compile core\nlink core\n"
        gui = core + b"compile dbus\ncompile gui\nlink gui\nmake gui aliases\n"
        observed = b"[1/4] compile dbus\n[2/4] compile gui\n[3/4] link gui\n[4/4] make gui aliases\n"
        self.assertEqual(G["dry_run_steps"](observed, core, gui, b"link gui\n"), 4)
        for modified in (observed.replace(b"compile dbus", b"compile core"),
                         observed.replace(b"compile dbus", b"compile other"),
                         observed.replace(b"[3/4]", b"[4/4]"),
                         observed.replace(b"link gui", b"compile dbus"),
                         b"ninja: no work to do.\n"):
            with self.subTest(modified=modified), self.assertRaises(ValueError):
                G["dry_run_steps"](modified, core, gui, b"link gui\n")

    def test_core_state_binds_body_and_symlink_identity(self):
        with TemporaryDirectory() as tmp:
            build = Path(tmp)
            libraries = build / "lib"
            libraries.mkdir()
            versioned = libraries / "libQt6Core.so.6.12.0"
            versioned.write_bytes(b"accepted_core")
            dev = libraries / "libQt6Core.so"
            soname = libraries / "libQt6Core.so.6"
            dev.symlink_to(soname.name)
            soname.symlink_to(versioned.name)
            size, digest = G["body_pin"](versioned.read_bytes())
            plan = dict(core=dict(bytes=size, sha256=digest))
            with patch.dict(G["core_state"].__globals__, {"BUILD": build}):
                original = G["core_state"](plan)
                self.assertEqual(original, G["core_state"](plan))
                dev.unlink()
                dev.symlink_to(versioned.name)
                with self.assertRaisesRegex(ValueError, "Exact SONAME symlink"):
                    G["core_state"](plan)
                dev.unlink()
                dev.symlink_to(soname.name)
                self.assertNotEqual(original, G["core_state"](plan))
                versioned.write_bytes(b"replaced_core")
                with self.assertRaisesRegex(ValueError, "Exact file pin"):
                    G["core_state"](plan)

    def capture(self, chunks, *, stalled=False, cap=9, status=0):
        signals = []
        alive = bool(stalled or sum(map(len, chunks)) > cap)
        elapsed = 0
        child = Mock(pid=11, returncode=None)
        child.stdout.fileno.return_value = 44

        def wait(*, timeout):
            child.returncode = status
            return status

        def poll():
            if not alive:
                child.returncode = status
            return child.returncode

        def kill(pid, signum):
            nonlocal alive
            self.assertEqual(pid, 11)
            if not alive:
                raise ProcessLookupError
            if signum:
                signals.append(signum)
                alive = False

        def now():
            nonlocal elapsed
            elapsed += .01
            return elapsed

        child.wait.side_effect = wait
        child.poll.side_effect = poll
        watcher = Mock()
        watcher.__enter__ = Mock(return_value=watcher)
        watcher.__exit__ = Mock()
        watcher.select.return_value = [] if stalled else [(None, selectors.EVENT_READ)]
        with (TemporaryDirectory() as tmp, patch.object(os, "read", side_effect=chunks),
              patch.object(os, "killpg", side_effect=kill), patch.object(time, "monotonic", side_effect=now),
              patch.object(resource, "getrusage", return_value=SimpleNamespace(ru_maxrss=1831)),
              patch.object(selectors, "DefaultSelector", return_value=watcher),
              patch.object(subprocess, "Popen", return_value=child) as popen):
            path = Path(tmp) / "log"
            result = G["capture"](G["BUILD_ARGV"], path, 500, cap, cwd=G["RECIPE"])
            self.assertEqual(result["peak_child_rss_kib"], 1831)
            popen.assert_called_once_with(G["BUILD_ARGV"], cwd=G["RECIPE"], env=G["ENV"], stdin=subprocess.DEVNULL,
                                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
            return path.read_bytes(), result, signals

    def test_natural_complete_capture_and_nonzero_exit(self):
        for status in (0, 2):
            log, result, signals = self.capture([b"one", b"two", b""], status=status)
            self.assertEqual(log, b"onetwo")
            self.assertEqual(result["exit_code"], status)
            self.assertTrue(result["natural"] and result["log_complete"] and result["group_empty"])
            self.assertEqual(signals, [])

    def test_limit_captures_prefix_and_retires_the_group(self):
        log, result, signals = self.capture([b"123456", b"789a"])
        self.assertEqual(log, b"123456789")
        self.assertTrue(result["group_empty"] and result["overflow"])
        self.assertFalse(result["natural"] or result["log_complete"])
        self.assertEqual(signals, [signal.SIGTERM])
        log, result, signals = self.capture([], stalled=True)
        self.assertEqual(log, b"")
        self.assertTrue(result["group_empty"] and result["timeout"])
        self.assertFalse(result["natural"] or result["log_complete"])
        self.assertEqual(signals, [signal.SIGTERM])


if __name__ == "__main__":
    unittest.main(verbosity=2)
