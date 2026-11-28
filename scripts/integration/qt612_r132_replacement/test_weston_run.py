#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert controls for Weston startup, PID-bound trace and retirement."""

import errno
import os
from pathlib import Path
from runpy import run_path
import stat
import struct
from subprocess import TimeoutExpired
from tempfile import TemporaryDirectory, TemporaryFile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


W = run_path(str(Path(__file__).with_name("weston_run.py")))
PID, TICKS = 812, 26100


def trace(events, pid=PID, client="0x1234"):
    return b"".join(f"[2026-11-27 14:10:20.123][proto] client {client} (PID {pid}) {event}\n".encode()
                    for event in events)


WINDOW = (
    "rq wl_compositor@4.create_surface(new id wl_surface@13)",
    "rq xdg_wm_base@5.get_xdg_surface(new id xdg_surface@14, wl_surface@13)",
    "rq xdg_surface@14.get_toplevel(new id xdg_toplevel@15)",
    "rq wl_surface@13.commit()",
    "ev xdg_toplevel@15.configure(256, 256, array)",
    "ev xdg_surface@14.configure(41)",
    "rq xdg_surface@14.ack_configure(41)",
)


def paint(buffer, cb):
    return (
        f"rq wl_shm_pool@21.create_buffer(new id wl_buffer@{buffer}, 0, 256, 256, 1024, 0)",
        f"rq wl_surface@13.attach(wl_buffer@{buffer}, 0, 0)",
        f"rq wl_surface@13.frame(new id wl_callback@{cb})",
        "rq wl_surface@13.commit()",
        f"ev wl_callback@{cb}.done(5210)",
    )


class TraceTests(unittest.TestCase):
    def test_requires_shm_configured_surface_and_matching_callback_for_second_frame(self):
        log = trace(WINDOW + paint(30, 31) + paint(32, 33))
        observed = W["presentation"](log, PID, 2)
        self.assertEqual(observed["connection"], "0x1234")
        self.assertEqual(observed["surface"], 13)
        self.assertEqual([row["buffer"] for row in observed["commits"]], [30, 32])
        self.assertEqual(observed["callback"], 33)
        self.assertGreater(observed["callback_line"], observed["commits"][-1]["line"])
        self.assertEqual(W["presentation"](trace(WINDOW + paint(30, 31)), PID, 1)["callback"], 31)

    def test_cannot_stitch_connections_or_pids_even_with_same_ids(self):
        for log in (trace(WINDOW) + trace(paint(30, 31), pid=PID + 1),
                    trace(WINDOW) + trace(paint(30, 31), client="0xabcd"),
                    trace(WINDOW + paint(30, 31)) + trace(WINDOW + paint(30, 31), client="0xabcd")):
            with self.subTest(log=log[-105:]), self.assertRaisesRegex(ValueError, "PID-bound Weston"):
                W["presentation"](log, PID, 1)

    def test_rejects_unacknowledged_null_unpresented_and_truncated_traces(self):
        log = trace(WINDOW + paint(30, 31))
        controls = (
            log.replace(b"ack_configure(41)", b"ack_configure(40)"),
            log.replace(b"attach(wl_buffer@30", b"attach(nil"),
            log.replace(b"wl_shm_pool@21", b"zwp_linux_buffer_params_v1@21"),
            log.replace(b"wl_callback@31.done", b"wl_callback@32.done"),
            log[:log.rfind(b"\n", 0, -1) + 1],
            log[:-1],
        )
        for altered in controls:
            with self.subTest(trace=altered[-100:]), self.assertRaises(ValueError):
                W["presentation"](altered, PID, 1)
        with self.assertRaisesRegex(ValueError, "frame callback"):
            W["presentation"](log + trace(paint(32, 33)[:-1]), PID, 2)

    def test_session_attests_selected_socket_pid_start_ticks_and_bounded_slice(self):
        with TemporaryFile() as log:
            session = W["Session"](log)
            session.process = Mock(pid=151, **{"poll.return_value": None})
            initial = b"[ignored before the launch]\n"
            body = trace(WINDOW + paint(30, 31))
            log.write(initial)
            log.flush()
            session.begin("vendor-raster")
            log.write(body)
            log.flush()
            proof = session.attest("vendor-raster", PID, TICKS)
            self.assertEqual(proof["status"], "PASS")
            self.assertEqual(proof["trace"], W["pin"](body))
            self.assertEqual((proof["socket"], proof["pid"], proof["start_ticks"], proof["start"], proof["end"]),
                             (W["SOCKET"], PID, TICKS, len(initial), len(initial + body)))
            session.begin("replacement-raster")
            log.write(body)
            log.flush()
            self.assertEqual(session.attest("replacement-raster", PID, TICKS)["status"], "HOLD")


class SocketFixture:
    def __init__(self, wire):
        self.wire = wire
        self.sent = []

    def recv(self, count):
        count = min(count, 3)
        value, self.wire = self.wire[:count], self.wire[count:]
        return value

    def sendall(self, value):
        self.sent.append(value)

    def settimeout(self, timeout):
        assert timeout > 0


def server_mode(width=256, interface="wl_output"):
    message, word, text = (W[key] for key in ("message", "word", "wire_string"))
    globals_seen = ("wl_compositor", "wl_shm", "xdg_wm_base", interface)
    return b"".join(message(2, 0, word(index) + text(name) + word(4)) for index, name in enumerate(globals_seen, 1)) + b"".join((
        message(3, 0, word(0)), message(1, 1, word(3)), message(4, 4, text("headless")),
        message(4, 1, struct.pack("=Iiii", 3, width, 256, 60000)), message(4, 2, b""), message(5, 0, word(0)),
    ))


class ReadinessTests(unittest.TestCase):
    def test_active_wayland_roundtrip_checks_current_mode_and_globals(self):
        client = SocketFixture(server_mode())
        self.assertEqual(W["roundtrip"](client, time.monotonic() + 1),
                         dict(name="headless", width=256, height=256, refresh_millihz=60000))
        self.assertIn(b"wl_output\0", client.sent[1])
        for wire in (server_mode(width=640), server_mode(interface="wl_seat"), server_mode()[:-4]):
            with self.subTest(length=len(wire)), self.assertRaises(ValueError):
                W["roundtrip"](SocketFixture(wire), time.monotonic() + 1)

    def test_wrong_socket_peer_fails_before_readiness_traffic(self):
        path = Mock()
        path.lstat.return_value = SimpleNamespace(st_dev=1, st_ino=2, st_mode=stat.S_IFSOCK | 0o700,
                                                  st_uid=65534, st_gid=65534, st_nlink=1)
        path.resolve.return_value = path
        path.__fspath__ = Mock(return_value="/fixture/wayland-0")
        connector = unittest.mock.MagicMock()
        connection = connector.return_value.__enter__.return_value
        connection.getsockopt.return_value = struct.pack("=iii", PID - 1, 65534, 65534)
        with patch.object(W["socket"], "socket", connector):
            with self.assertRaisesRegex(ValueError, "socket peer"):
                W["ready_socket"](path, SimpleNamespace(pid=PID), time.monotonic() + 1)
        connection.sendall.assert_not_called()


class ProcessTests(unittest.TestCase):
    def test_command_is_exact_headless_kiosk_pixman_scoped_and_bounded(self):
        argv = W["command"]()
        for item in ("--reuid=65534", "--regid=65534", "--clear-groups", "--no-new-privs", "--bounding-set=-all",
                     "--renderer=pixman", "--shell=kiosk", "--logger-scopes=log,proto", "--fsize=1048576:1048576"):
            self.assertIn(item, argv)
        self.assertIn("/tmp/qt629-weston/usr/bin/weston", argv)
        self.assertIn("XDG_RUNTIME_DIR=/run/qt629-wl", argv)
        self.assertNotIn("--debug", argv)

    def test_retirement_signals_only_owned_group_and_marks_forced_kill(self):
        function = W["retire"]
        os_module = W["os"]
        for forced in (False, True):
            with self.subTest(forced=forced):
                process = Mock(pid=PID, returncode=None, **{"poll.return_value": None})
                original = []

                def wait(timeout):
                    original.append(timeout)
                    if forced and len(original) == 1:
                        raise TimeoutExpired("weston", timeout)
                    process.returncode = -9 if forced else 0

                process.wait.side_effect = wait
                with patch.object(os_module, "getpgid", return_value=PID), patch.object(os_module, "getsid", return_value=PID), \
                        patch.object(os_module, "killpg") as kill, patch.dict(function.__globals__, group_absent=lambda _pid: True):
                    outcome = function(process)
                self.assertEqual(outcome["signals"], ["SIGTERM", "SIGKILL"] if forced else ["SIGTERM"])
                self.assertEqual(outcome["forced"], forced)
                self.assertTrue(outcome["group_absent"])
                self.assertEqual(len(kill.call_args_list), 2 if forced else 1)

    def test_never_signals_an_unowned_or_previously_reaped_group(self):
        os_module = W["os"]
        process = Mock(pid=PID, **{"poll.return_value": None})
        with patch.object(os_module, "getpgid", return_value=PID - 1), patch.object(os_module, "killpg") as kill:
            with self.assertRaisesRegex(ValueError, "unowned Weston"):
                W["retire"](process)
            kill.assert_not_called()
        process.poll.return_value = process.returncode = 0
        with patch.object(os_module, "killpg", side_effect=ProcessLookupError) as kill:
            self.assertTrue(W["retire"](process)["group_absent"])
            kill.assert_called_once_with(PID, 0)


class StartupCleanupTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.target = self.root / "target"
        for directory in (self.target / "tmp", self.target / "run", self.root / "work"):
            directory.mkdir(parents=True)
        self.fixture = self.target / W["FIXTURE"].lstrip("/")
        self.runtime = self.target / W["RUNTIME"].lstrip("/")
        self.guard = Mock()
        self.validate = Mock(side_effect=lambda _receipt: W["identity"](self.fixture))
        self.report = Mock()
        self.dependencies = Mock()
        self.retire = Mock(return_value=dict(signals=["SIGTERM"], forced=False, exit=0, reaped=True, group_absent=True))
        self.spawn = self.enterContext(patch.object(W["subprocess"], "Popen"))
        self.enterContext(patch.object(W["os"], "chown"))
        self.entry = W["supervise"]
        self.globals = self.entry.__wrapped__.__globals__
        self.enterContext(patch.dict(self.globals, TARGET=self.target, WORK=self.root / "work", environment=self.guard,
                                     claim_fixture=W["identity"], validate_fixture=self.validate, publish=self.report,
                                     dependencies=self.dependencies, retire=self.retire))

    def stage(self, destination):
        self.assertEqual(destination, self.fixture)
        destination.mkdir(mode=0o700)
        (destination / "partial-member").write_bytes(b"fixture")
        return {"staged": True}

    def start(self, stage_fixture):
        with self.entry(nonce="a" * 32, stage_fixture=stage_fixture):
            self.fail("A failed startup must not yield a compositor")

    def test_early_boot_or_log_failure_does_not_start_extraction(self):
        stage = Mock()
        self.guard.side_effect = ValueError("wrong boot nonce")
        with self.assertRaisesRegex(ValueError, "wrong boot nonce"):
            self.start(stage)
        self.guard.side_effect = None
        with patch.dict(self.globals, TemporaryFile=Mock(side_effect=OSError("log unavailable"))):
            with self.assertRaisesRegex(OSError, "log unavailable"):
                self.start(stage)
        stage.assert_not_called()
        self.assertFalse(self.fixture.exists())

    def test_fixture_is_removed_on_validation_or_partial_extraction_failure(self):
        self.validate.side_effect = ValueError("fixture pin mismatch")
        with self.assertRaisesRegex(ValueError, "fixture pin mismatch"):
            self.start(self.stage)
        self.assertFalse(self.fixture.exists())
        report, _ = self.report.call_args.args
        self.assertEqual(report["status"], "HOLD")
        self.assertTrue(report["retirement"]["fixture_removed"])

        def partial(destination):
            self.stage(destination)
            raise OSError("extractor failed after creating fixture")

        with self.assertRaisesRegex(OSError, "extractor failed"):
            self.start(partial)
        self.assertFalse(self.fixture.exists())
        self.assertTrue(self.report.call_args.args[0]["retirement"]["fixture_removed"])
        self.spawn.assert_not_called()

    def test_lstat_io_error_after_partial_extraction_requires_discard(self):
        real_lstat = os.lstat
        extracted = False

        def partial(destination):
            nonlocal extracted
            self.stage(destination)
            extracted = True
            raise OSError("extractor failed after creating fixture")

        def inspect(path, *args, **kwargs):
            if extracted and os.fspath(path) == str(self.fixture):
                raise OSError(errno.EIO, "cannot inspect partially extracted fixture", path)
            return real_lstat(path, *args, **kwargs)

        with patch.object(os, "lstat", inspect), patch.object(Path, "lstat", inspect):
            with self.assertRaisesRegex(ValueError, "HOLD_DISCARD"):
                self.start(partial)
        self.assertTrue(self.fixture.is_dir())
        self.spawn.assert_not_called()
        report = self.report.call_args.args[0]
        self.assertEqual(report["status"], "HOLD_DISCARD")
        self.assertFalse(report["retirement"]["fixture_removed"])
        self.assertIn("cannot inspect partially extracted fixture", report["cleanup_error"])

    def test_spawn_failure_removes_runtime_and_fixture(self):
        self.spawn.side_effect = OSError("cannot launch Weston")
        with self.assertRaisesRegex(OSError, "cannot launch Weston"):
            self.start(self.stage)
        self.assertFalse(self.fixture.exists())
        self.assertFalse(self.runtime.exists())
        self.retire.assert_not_called()

    def test_readiness_failure_reaps_process_and_cleans_lingering_socket(self):
        socket_path = self.target / W["SOCKET"].lstrip("/")

        def fail_ready(_session):
            socket_path.touch()
            socket_path.with_suffix(".lock").touch()
            raise ValueError("readiness failed")

        with patch.object(W["Session"], "wait_ready", fail_ready):
            with self.assertRaisesRegex(ValueError, "readiness failed"):
                self.start(self.stage)
        self.retire.assert_called_once_with(self.spawn.return_value)
        self.assertFalse(self.fixture.exists())
        self.assertFalse(self.runtime.exists())
        retirement = self.report.call_args.args[0]["retirement"]
        self.assertTrue(retirement["reaped"])
        self.assertFalse(retirement["socket_removed_by_weston"])
        self.assertTrue(retirement["runtime_removed"] and retirement["fixture_removed"])

    def test_unreaped_group_requires_explicit_discard_and_keeps_its_paths(self):
        self.retire.return_value = {"reaped": False, "group_absent": False}
        with patch.object(W["Session"], "wait_ready", side_effect=ValueError("output missing")):
            with self.assertRaisesRegex(ValueError, "HOLD_DISCARD"):
                self.start(self.stage)
        self.assertTrue(self.fixture.exists())
        self.assertTrue(self.runtime.exists())
        self.assertEqual(self.report.call_args.args[0]["status"], "HOLD_DISCARD")
        self.assertEqual(self.report.call_args.args[0]["error"]["reason"], "output missing")

    def test_runtime_cleanup_failure_still_retires_owned_fixture(self):
        self.spawn.side_effect = OSError("cannot launch Weston")
        original = W["remove_owned"]

        def remove(path, resource):
            if path == self.runtime:
                raise OSError("runtime cleanup denied")
            return original(path, resource)

        with patch.dict(self.globals, remove_owned=remove):
            with self.assertRaisesRegex(ValueError, "HOLD_DISCARD"):
                self.start(self.stage)
        self.assertTrue(self.runtime.exists())
        self.assertFalse(self.fixture.exists())
        report = self.report.call_args.args[0]
        self.assertTrue(report["retirement"]["fixture_removed"])
        self.assertIn("runtime cleanup denied", report["cleanup_error"])

    def test_unowned_preexisting_fixture_is_left_for_clone_discard(self):
        self.fixture.mkdir()
        stage = Mock()
        with self.assertRaisesRegex(ValueError, "HOLD_DISCARD"):
            self.start(stage)
        stage.assert_not_called()
        self.assertTrue(self.fixture.exists())
        self.assertFalse(self.report.call_args.args[0]["retirement"]["fixture_removed"])

    def test_unproved_fixture_identity_requires_clone_discard(self):
        claim = Mock(side_effect=ValueError("fixture identity changed"))
        with patch.dict(self.globals, claim_fixture=claim):
            with self.assertRaisesRegex(ValueError, "HOLD_DISCARD"):
                self.start(self.stage)
        self.assertTrue(self.fixture.exists())
        self.spawn.assert_not_called()
        report = self.report.call_args.args[0]
        self.assertEqual(report["error"]["reason"], "fixture identity changed")
        self.assertFalse(report["retirement"]["fixture_removed"])

    def test_clean_complete_run_keeps_the_existing_pass_receipt(self):
        with patch.object(W["Session"], "wait_ready", return_value={"output": "fixture is ready"}):
            with self.entry(nonce="a" * 32, stage_fixture=self.stage) as session:
                session.log.write(b"Weston trace fixture\n")
                session.log.flush()
                session.entries.update({role: {"status": "PASS"} for role in W["PROBES"]})
        self.assertFalse(self.fixture.exists())
        self.assertFalse(self.runtime.exists())
        report = self.report.call_args.args[0]
        self.assertEqual(report["status"], "PASS")
        self.assertNotIn("cleanup_error", report)
        self.assertTrue(all(report["retirement"][key] for key in (
            "reaped", "group_absent", "socket_removed_by_weston", "runtime_removed", "fixture_removed")))

    def test_parity_lifecycle_holds_without_both_restored_presentations(self):
        with patch.object(W["Session"], "wait_ready", return_value={"output": "fixture is ready"}):
            with self.assertRaisesRegex(ValueError, "Weston lifecycle HOLD"):
                with self.entry(nonce="a" * 32, stage_fixture=self.stage, parity=True) as session:
                    session.log.write(b"Weston trace fixture\n")
                    session.log.flush()
                    session.entries.update({role: {"status": "PASS"} for role in W["PROBES"]})
        report = self.report.call_args.args[0]
        self.assertEqual(report["missing_presentations"], ["restoration-raster", "restoration-qrhi"])
        self.assertTrue(report["retirement"]["fixture_removed"])


if __name__ == "__main__":
    unittest.main()
