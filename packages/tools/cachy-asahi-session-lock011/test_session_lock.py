#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Real subprocess fixtures only: never invoke swaylock, systemctl or a desktop."""
from contextlib import redirect_stderr
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "cachy-asahi-session-lock"
SPEC = importlib.util.spec_from_loader("session_lock", importlib.machinery.SourceFileLoader("session_lock", str(SOURCE)))
S = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(S)

FIXTURE = r'''
import json, os, signal, sys, time
from pathlib import Path
kind, log, mode, delay, lifetime = sys.argv[1:6]
def event(name):
    with open(log, "a") as output:
        output.write(json.dumps({"name": name, "pid": os.getpid(), "argv": sys.argv[6:], "env": dict(os.environ)}) + "\n")
if kind == "locker":
    def interrupted(number, _):
        event("locker-signalled")
        sys.exit(91)
    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(number, interrupted)
    event("locker-start")
    fd = int(sys.argv[sys.argv.index("--ready-fd") + 1])
    if mode == "exit":
        sys.exit(2)
    if mode == "closed":
        os.close(fd)
    time.sleep(float(delay))
    if mode not in ("silent", "closed"):
        event("ready")
        os.write(fd, b"\n" if mode != "invalid" else b"xx")
        os.close(fd)
    time.sleep(float(lifetime))
    event("locker-exit")
elif kind == "request":
    event("request-start")
    events = [json.loads(line) for line in Path(log).read_text().splitlines()]
    if "ready" not in [item["name"] for item in events]:
        sys.exit(92)
    locker = next(item["pid"] for item in events if item["name"] == "locker-start")
    os.kill(locker, 0)
    if mode == "hang":
        time.sleep(60)
    sys.exit(7 if mode == "failed" else 0)
'''


class SessionLock(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="session-lock-test-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.runtime = self.work / "runtime"
        self.runtime.mkdir(mode=0o700)
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.bind(str(self.runtime / "wayland-1"))
        self.addCleanup(self.socket.close)
        self.env = {"XDG_RUNTIME_DIR": str(self.runtime), "WAYLAND_DISPLAY": "wayland-1"}
        self.fixture = self.work / "fixture.py"
        self.fixture.write_text(FIXTURE)
        self.log = self.work / "events.jsonl"

    def command(self, kind, mode="ready", delay=.03, lifetime=.15):
        return (sys.executable, "-I", "-B", str(self.fixture), kind, str(self.log), mode, str(delay), str(lifetime))

    def events(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def names(self):
        return [item["name"] for item in self.events()]

    def run_case(self, action="suspend", mode="ready", delay=.03, lifetime=.15,
                 request="ready", ready_timeout=1, cancelled=None, request_timeout=.2):
        errors = io.StringIO()
        with redirect_stderr(errors):
            status = S.run_session(action, self.env, cancelled if cancelled is not None else [], ready_timeout,
                                   locker_command=self.command("locker", mode, delay, lifetime),
                                   suspend_command=self.command("request", request), request_timeout=request_timeout)
        return status, errors.getvalue()

    def test_lock_waits_for_normal_unlock_without_requesting_suspend(self):
        status, message = self.run_case(action="lock")
        self.assertEqual(status, 0, message)
        self.assertEqual(self.names(), ["locker-start", "ready", "locker-exit"])
        self.assertIn("confirmed readiness", message)
        self.assertEqual(self.events()[0]["argv"][:-1],
                         ["--config", "/dev/null", "--color", "000000", "--ready-fd"])

    def test_suspend_request_occurs_after_readiness_and_before_unlock(self):
        status, message = self.run_case()
        self.assertEqual(status, 0, message)
        self.assertEqual(self.names(), ["locker-start", "ready", "request-start", "locker-exit"])
        request = self.events()[2]
        self.assertEqual(request["argv"], ["--no-ask-password", "--check-inhibitors=yes", "suspend"])
        self.assertIn("request queued", message)
        self.assertNotIn("slept successfully", message)

    def test_preexisting_locker_refusal_never_requests_suspend(self):
        status, message = self.run_case(mode="exit")
        self.assertEqual(status, 1)
        self.assertEqual(self.names(), ["locker-start"])
        self.assertIn("readiness", message)

    def test_closed_readiness_pipe_preserves_locker_until_normal_exit(self):
        status, message = self.run_case(mode="closed")
        self.assertEqual(status, 1)
        self.assertEqual(self.names(), ["locker-start", "locker-exit"])
        self.assertIn("closed readiness pipe", message)

    def test_invalid_readiness_never_requests_suspend_or_kills_locker(self):
        status, message = self.run_case(mode="invalid")
        self.assertEqual(status, 1)
        self.assertEqual(self.names(), ["locker-start", "ready", "locker-exit"])
        self.assertIn("invalid", message)

    def test_timeout_then_late_ack_has_no_sigpipe_and_no_suspend(self):
        status, message = self.run_case(delay=.12, ready_timeout=.02)
        self.assertEqual(status, 1)
        self.assertEqual(self.names(), ["locker-start", "ready", "locker-exit"])
        self.assertIn("timed out", message)

    def test_silent_timeout_preserves_locker(self):
        status, message = self.run_case(mode="silent", ready_timeout=.02)
        self.assertEqual(status, 1)
        self.assertEqual(self.names(), ["locker-start", "locker-exit"])
        self.assertIn("timed out", message)

    def test_cancellation_before_readiness_preserves_late_ack_and_locker(self):
        cancelled = []
        timer = threading.Timer(.05, lambda: cancelled.append(signal.SIGINT))
        timer.start()
        self.addCleanup(timer.join)
        status, message = self.run_case(delay=.12, cancelled=cancelled)
        self.assertEqual(status, 1)
        self.assertEqual(self.names(), ["locker-start", "ready", "locker-exit"])
        self.assertIn("cancelled", message)

    def test_already_cancelled_request_does_not_start_a_locker(self):
        status, message = self.run_case(cancelled=[signal.SIGTERM])
        self.assertEqual(status, 1)
        self.assertEqual(self.events(), [])
        self.assertEqual(list(self.runtime.glob("*.lock")), [])
        self.assertIn("before locker startup", message)

    def test_cancellation_after_readiness_preserves_locker_until_unlock(self):
        cancelled = []
        timer = threading.Timer(.1, lambda: cancelled.append(signal.SIGHUP))
        timer.start()
        self.addCleanup(timer.join)
        status, message = self.run_case(action="lock", lifetime=.25, cancelled=cancelled)
        self.assertEqual(status, 1)
        self.assertEqual(self.names(), ["locker-start", "ready", "locker-exit"])
        self.assertIn("normal unlock", message)

    def test_suspend_refusal_preserves_locker_and_reports_failure(self):
        status, message = self.run_case(request="failed")
        self.assertEqual(status, 1)
        self.assertEqual(self.names()[-1], "locker-exit")
        self.assertNotIn("locker-signalled", self.names())
        self.assertIn("status 7", message)

    def test_hung_suspend_client_stopped_without_stopping_locker(self):
        status, message = self.run_case(request="hang", lifetime=.35, request_timeout=.1)
        self.assertEqual(status, 1)
        self.assertEqual(self.names(), ["locker-start", "ready", "request-start", "locker-exit"])
        request_pid = self.events()[2]["pid"]
        with self.assertRaises(ProcessLookupError):
            os.kill(request_pid, 0)
        self.assertIn("outcome is unknown", message)

    def test_locker_exit_during_request_cancels_client_with_unknown_outcome(self):
        status, message = self.run_case(request="hang", lifetime=.1, request_timeout=1)
        self.assertEqual(status, 1)
        self.assertEqual(self.names()[-1], "locker-exit")
        self.assertIn("outcome is unknown", message)
        with self.assertRaises(ProcessLookupError):
            os.kill(self.events()[2]["pid"], 0)

    def test_cancellation_during_request_stops_client_and_preserves_locker(self):
        cancelled = []
        def cancel_after_request():
            deadline = time.monotonic() + 2
            while "request-start" not in self.names() and time.monotonic() < deadline:
                time.sleep(.01)
            cancelled.append(signal.SIGINT)
        thread = threading.Thread(target=cancel_after_request)
        thread.start()
        self.addCleanup(thread.join)
        status, message = self.run_case(request="hang", lifetime=.35, cancelled=cancelled, request_timeout=2)
        self.assertEqual(status, 1)
        self.assertEqual(self.names(), ["locker-start", "ready", "request-start", "locker-exit"])
        self.assertIn("outcome is unknown", message)
        with self.assertRaises(ProcessLookupError):
            os.kill(self.events()[2]["pid"], 0)

    def test_missing_suspend_client_preserves_locker(self):
        errors = io.StringIO()
        with redirect_stderr(errors):
            status = S.run_session("suspend", self.env, [], locker_command=self.command("locker"),
                                   suspend_command=(str(self.work / "absent"),))
        self.assertEqual(status, 1)
        self.assertEqual(self.names(), ["locker-start", "ready", "locker-exit"])
        self.assertIn("cannot start suspend client", errors.getvalue())

    def test_missing_locker_releases_guard_and_descriptors(self):
        with self.assertRaises(FileNotFoundError):
            S.run_session("suspend", self.env, [], locker_command=(str(self.work / "absent"),))
        with S.session_guard(self.env):
            pass
        self.assertEqual(self.events(), [])

    def test_guard_refuses_concurrent_helpers_without_starting_locker(self):
        with S.session_guard(self.env):
            with self.assertRaisesRegex(S.Refused, "already has"):
                self.run_case()
        self.assertEqual(self.events(), [])
        with S.session_guard(self.env):
            pass

    def test_guard_file_persists_with_private_mode_and_no_content(self):
        with S.session_guard(self.env):
            pass
        guard, = self.runtime.glob("*.lock")
        inode = guard.stat().st_ino
        self.assertEqual(guard.stat().st_mode & 0o777, 0o600)
        self.assertEqual(guard.read_bytes(), b"")
        with S.session_guard(self.env):
            self.assertEqual(guard.stat().st_ino, inode)

    def test_symlink_and_nonprivate_guard_refused_without_modification(self):
        suffix = hashlib.sha256(b"wayland-1").hexdigest()[:16]
        guard = self.runtime / f"{S.NAME}-{suffix}.lock"
        target = self.work / "keep"
        target.write_text("preserve")
        guard.symlink_to(target)
        with self.assertRaises(OSError):
            self.run_case()
        self.assertEqual(target.read_text(), "preserve")
        guard.unlink()
        guard.write_text("preserve")
        guard.chmod(0o644)
        with self.assertRaisesRegex(S.Refused, "unsafe"):
            self.run_case()
        self.assertEqual(guard.read_text(), "preserve")
        self.assertEqual(self.events(), [])

    def test_environment_discards_alternate_sockets_bus_and_path(self):
        supplied = {**self.env, "PATH": "/untrusted", "WAYLAND_SOCKET": "0", "LD_PRELOAD": "/untrusted",
                    "DBUS_SYSTEM_BUS_ADDRESS": "unix:path=/untrusted", "HOME": "/untrusted"}
        clean = S.session_environment(supplied)
        self.assertEqual(clean, {**self.env, "PATH": "/usr/bin", "LC_ALL": "C.UTF-8"})
        self.env = clean
        status, message = self.run_case()
        self.assertEqual(status, 0, message)
        for event in self.events():
            self.assertNotIn("/untrusted", str(event["env"]))

    def test_invalid_environment_is_refused_before_any_guard_or_subprocess(self):
        cases = [{}, {**self.env, "XDG_RUNTIME_DIR": "relative"},
                 {**self.env, "WAYLAND_DISPLAY": "../wayland-1"},
                 {**self.env, "WAYLAND_DISPLAY": str(self.runtime / "wayland-1")},
                 {**self.env, "WAYLAND_DISPLAY": "."}]
        for env in cases:
            with self.subTest(env=env), self.assertRaises((S.Refused, OSError)):
                S.session_environment(env)
        self.runtime.chmod(0o755)
        with self.assertRaises(S.Refused):
            S.session_environment(self.env)
        self.runtime.chmod(0o700)
        (self.runtime / "link").symlink_to(self.runtime / "wayland-1")
        with self.assertRaises(S.Refused):
            S.session_environment({**self.env, "WAYLAND_DISPLAY": "link"})
        (self.runtime / "ordinary").write_text("")
        with self.assertRaises(S.Refused):
            S.session_environment({**self.env, "WAYLAND_DISPLAY": "ordinary"})
        with patch.object(S.os, "getuid", return_value=0), self.assertRaises(S.Refused):
            S.session_environment(self.env)
        self.assertEqual(list(self.runtime.glob("*.lock")), [])

    def test_cli_help_and_invalid_inputs_never_access_current_session(self):
        for args, status in ((["--help"], 0), (["hibernate"], 2), (["suspend", "--ready-timeout", "nan"], 2),
                             (["lock", "--ready-timeout", "0"], 2), (["lock", "--ready-timeout", "61"], 2),
                             (["lock", "--ready-timeout", "inf"], 2), (["lock", "--ready-timeout", "oops"], 2)):
            with self.subTest(args=args):
                result = subprocess.run([str(SOURCE), *args], env={"PATH": "/absent", "PYTHONHOME": "/absent",
                                        "PYTHONPATH": "/absent"}, capture_output=True, timeout=3)
                self.assertEqual(result.returncode, status, result.stderr)
        result = subprocess.run([str(SOURCE), "lock"], env={}, capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"XDG_RUNTIME_DIR", result.stderr)

    def test_direct_python_without_isolated_mode_refused_before_session_access(self):
        result = subprocess.run([sys.executable, "-B", str(SOURCE), "suspend"],
                                env={}, capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"isolated mode (-I) is required", result.stderr)
        self.assertNotIn(b"XDG_RUNTIME_DIR", result.stderr)
        self.assertEqual(list(self.runtime.glob("*.lock")), [])

    def test_actual_sigterm_cancels_pending_suspend_without_signalling_locker(self):
        driver = self.work / "driver.py"
        driver.write_text("import runpy, sys\n" + f"m = runpy.run_path({str(SOURCE)!r})\n" +
                          "with m['cancellation_signals']() as cancelled:\n" +
                          f"    status = m['run_session']('suspend', {self.env!r}, cancelled,\n" +
                          f"        locker_command={self.command('locker', delay=.25)!r},\n" +
                          f"        suspend_command={self.command('request')!r})\n" + "sys.exit(status)\n")
        process = subprocess.Popen([sys.executable, "-I", "-B", str(driver)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 3
            while "locker-start" not in self.names() and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertIn("locker-start", self.names())
            process.send_signal(signal.SIGTERM)
            _, error = process.communicate(timeout=3)
            self.assertEqual(process.returncode, 1, error)
            self.assertEqual(self.names(), ["locker-start", "ready", "locker-exit"])
            self.assertIn(b"cancelled", error)
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=3)


if __name__ == "__main__":
    unittest.main()
