#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert fixtures for Qt runtime probe classification and execution bounds."""

import json
import os
from pathlib import Path
from runpy import run_path
from types import SimpleNamespace
import socket
import stat
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch


P = run_path(str(Path(__file__).with_name("runtime_probes.py")))
COLLECT = P["collect"]
STATE = P["socket_state"]
SOCKET = "/run/qt-probe/wayland-0"
NONCE = "a" * 32
MARKS = {
    "offscreen": "QT629_GUI_OK 6.12.0 offscreen",
    "software": "QT629_QUICK_OK software pixels=verified",
    "wayland": "QT629_GUI_OK 6.12.0 wayland",
    "loader": "QT629_VULKAN_OK devices=1",
    "vulkan": "QT629_QRHI_OK wayland vulkan frame=swapped",
}


def step(output="", exit=0, problem=None):
    return dict(argv=[], exit=exit, problem=problem, output=output, pid=0, start_ticks=0)


class FakeGuest:
    inner = "/tmp/test-qt"

    def __init__(self, root):
        self.root = root
        self.builds = {}
        self.fixtures = {name: step(mark + "\n") for name, mark in MARKS.items()}
        self.commands = []
        icd = self.path(P["LAVAPIPE"])
        icd.parent.mkdir(parents=True)
        icd.touch()

    def path(self, path):
        return self.root / path.lstrip("/")

    def build(self, name, module):
        self.builds.setdefault(name, [step(), step()])
        return self.builds[name]

    def command(self, args, timeout, **settings):
        role = "loader" if args[0] == "/usr/bin/python3" else args[1]
        self.commands.append((role, settings))
        return self.fixtures[role] | {"pid": 100 + len(self.commands), "start_ticks": 1000 + len(self.commands)}


class FakeWeston:
    socket = SOCKET

    def __init__(self):
        self.calls = []
        self.hold = set()

    def begin(self, role):
        self.calls.append(("begin", role))

    def attest(self, role, pid, start_ticks):
        self.calls.append(("attest", role, pid, start_ticks))
        return {"status": "HOLD" if role in self.hold else "PASS"}


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.target = self.root / "target"
        self.guest = FakeGuest(self.target)
        self.weston = FakeWeston()

    def selected_socket(self):
        fixture = self.target / SOCKET.lstrip("/")
        fixture.parent.mkdir(parents=True)
        server = self.enterContext(socket.socket(socket.AF_UNIX))
        server.bind(os.fspath(fixture))
        self.enterContext(patch.dict(STATE.__globals__, USER=os.getuid()))
        return SOCKET

    def test_complete_positive_controls_require_exact_runtime_markers(self):
        checks = COLLECT(self.guest, self.selected_socket(), self.weston)
        self.assertEqual({name: row["status"] for name, row in checks.items()}, dict.fromkeys(P["PHASES"], "PASS"))
        self.assertIn(("wayland", dict(QT_QPA_PLATFORM="wayland", WAYLAND_DISPLAY=SOCKET)), self.guest.commands)
        vulkan = dict(self.guest.commands)["vulkan"]
        self.assertEqual(vulkan["VK_DRIVER_FILES"], P["LAVAPIPE"])
        self.assertEqual(vulkan["QT_QPA_PLATFORM"], "wayland")
        self.assertIsNone(P["write_result"](self.root, checks, SOCKET, nonce=NONCE))
        report = json.loads((self.root / "runtime-probes.json").read_bytes())
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["nonce"], NONCE)
        self.assertEqual(report["checks"], checks)
        self.assertEqual(self.weston.calls, [
            ("begin", "replacement-raster"), ("attest", "replacement-raster", 103, 1003),
            ("begin", "replacement-qrhi"), ("attest", "replacement-qrhi", 105, 1005),
        ])
        self.assertEqual(checks["vulkan_qrhi"]["process"], dict(pid=105, start_ticks=1005))

    def test_live_socket_or_client_marker_without_server_attestation_cannot_pass(self):
        socket = self.selected_socket()
        checks = COLLECT(self.guest, socket)
        self.assertEqual(checks["wayland"]["status"], "FAIL")
        self.weston.hold.add("replacement-qrhi")
        check = COLLECT(self.guest, socket, self.weston)["vulkan_qrhi"]
        self.assertEqual(check["status"], "FAIL")
        self.assertEqual(check["reason"], "PID_BOUND_WESTON_PRESENTATION_MISSING")

    def test_absent_compositor_is_partial_even_if_loader_and_offscreen_pass(self):
        checks = COLLECT(self.guest, None)
        self.assertEqual(checks["wayland"]["reason"], "NO_WAYLAND_COMPOSITOR_SELECTED")
        self.assertEqual(checks["vulkan_qrhi"]["reason"], "WAYLAND_QPA_PATH_UNAVAILABLE")
        self.assertEqual(checks["vulkan_loader"]["status"], "PASS")
        self.assertEqual(set(dict(self.guest.commands)), {"loader", "offscreen", "software"})
        with self.assertRaisesRegex(RuntimeError, r"PARTIAL.*wayland=SKIP.*vulkan_qrhi=SKIP"):
            P["write_result"](self.root, checks, None, nonce=NONCE)
        self.assertEqual(json.loads((self.root / "runtime-probes.json").read_bytes())["status"], "PARTIAL")

    def test_explicit_missing_bad_and_non_socket_paths_fail(self):
        for path in ("/tmp/wayland-0", "/run/../run/wayland-0", "/run/./wayland-1", True):
            with self.subTest(path=path):
                self.assertEqual(STATE(self.guest, path), ("FAIL", "INVALID_SELECTED_WAYLAND_SOCKET_PATH"))
        checks = COLLECT(self.guest, SOCKET)
        self.assertEqual(checks["wayland"]["reason"], "SELECTED_WAYLAND_SOCKET_MISSING")
        path = self.guest.path(SOCKET)
        path.parent.mkdir(parents=True)
        path.touch()
        self.assertEqual(STATE(self.guest, SOCKET), ("FAIL", "SELECTED_WAYLAND_SOCKET_WRONG_TYPE_PATH_OR_OWNER"))
        with self.assertRaisesRegex(RuntimeError, r"FAIL.*wayland=FAIL"):
            P["write_result"](self.root, checks, SOCKET, nonce=NONCE)

    def test_explicit_lavapipe_zero_devices_or_error_fails(self):
        self.selected_socket()
        self.guest.fixtures["loader"] = step("QT629_VULKAN_OK devices=0\n")
        checks = COLLECT(self.guest, SOCKET, self.weston)
        self.assertEqual((checks["vulkan_loader"]["status"], checks["vulkan_qrhi"]["status"]), ("FAIL", "SKIP"))
        self.assertEqual(checks["vulkan_loader"]["reason"], "PINNED_LAVAPIPE_EXPOSED_NO_VULKAN_DEVICE")
        self.guest.fixtures["loader"] = step("vkCreateInstance failed with VkResult -9\n", exit=1)
        checks = COLLECT(self.guest, SOCKET, self.weston)
        self.assertEqual((checks["vulkan_loader"]["status"], checks["vulkan_qrhi"]["status"]), ("FAIL", "SKIP"))
        self.guest.path(P["LAVAPIPE"]).unlink()
        checks = COLLECT(self.guest, SOCKET, self.weston)
        self.assertEqual(checks["vulkan_loader"]["reason"], "PINNED_LAVAPIPE_ICD_MISSING")

    def test_successful_launch_without_vulkan_marker_is_a_failure(self):
        self.guest.fixtures["vulkan"] = step("software fallback\n")
        check = COLLECT(self.guest, self.selected_socket(), self.weston)["vulkan_qrhi"]
        self.assertEqual(check["status"], "FAIL")
        self.assertEqual(check["reason"], "EXPECTED_RUNTIME_MARKER_MISSING_OR_DUPLICATED")

    def test_build_failure_does_not_suppress_independent_checks(self):
        self.guest.builds["quick"] = [step(), step("missing symbol", exit=1)]
        checks = COLLECT(self.guest, self.selected_socket(), self.weston)
        self.assertEqual(checks["quick_offscreen"]["status"], "FAIL")
        self.assertEqual(checks["wayland"]["status"], "PASS")
        self.assertEqual(checks["vulkan_loader"]["status"], "PASS")
        self.assertEqual(checks["vulkan_qrhi"]["reason"], "QT_QUICK_FIXTURE_BUILD_FAILED")


class LauncherTests(unittest.TestCase):
    def test_vulkan_loader_accepts_only_cpu_devices(self):
        import ctypes as c

        def create(_info, _alloc, handle):
            c.cast(handle, c.POINTER(c.c_void_p)).contents.value = 789
            return 0

        def enumerate_device(_instance, count, devices):
            c.cast(count, c.POINTER(c.c_uint32)).contents.value = 1
            if devices is not None:
                devices[0] = 333
            return 0

        lib = SimpleNamespace(vkCreateInstance=Mock(side_effect=create),
                              vkEnumeratePhysicalDevices=Mock(side_effect=enumerate_device),
                              vkGetPhysicalDeviceProperties=Mock(), vkDestroyInstance=Mock())
        ids = {name: Mock(return_value=65534) for name in ("getuid", "geteuid", "getgid", "getegid")}
        ids["getgroups"] = Mock(return_value=[])
        with patch.object(c, "CDLL", return_value=lib), patch.multiple(os, **ids):
            for device_type in (2, 4):
                with self.subTest(device_type=device_type):
                    def properties(_device, buffer):
                        memory = c.cast(buffer, c.POINTER(c.c_uint32))
                        memory[4] = device_type

                    lib.vkGetPhysicalDeviceProperties.side_effect = properties
                    if device_type == 4:
                        with patch("builtins.print") as output:
                            exec(P["VULKAN"], {})
                        output.assert_called_once_with("QT629_VULKAN_OK devices=1")
                    else:
                        with self.assertRaisesRegex(SystemExit, "non-CPU"):
                            exec(P["VULKAN"], {})

    def test_root_fixtures_and_qml_directory_readable_only_by_probe_identity(self):
        root = Path(self.enterContext(TemporaryDirectory()))
        probes, evidence = root / "probes", root / "evidence"
        probes.mkdir(mode=0o700)
        evidence.mkdir(mode=0o700)

        def mode(path):
            return stat.S_IMODE(path.stat().st_mode)

        old = os.umask(0o077)
        try:
            control = root / "default-root-fixture"
            control.write_text("unreadable to the ordinary guest UID")
            self.assertEqual(mode(control), 0o600)
            with patch.dict(P["Guest"].__init__.__globals__, TARGET=root), patch.object(os, "chown") as chown:
                P["Guest"](probes)
            self.assertEqual(mode(probes), 0o750)
            chown.assert_any_call(probes, -1, P["USER"])
            for fixture in ("gui.cpp", "quick.cpp", "fixture.qml", "vulkan.py"):
                self.assertEqual(mode(probes / fixture), 0o444)
            for private in ("work", "run"):
                self.assertEqual(mode(probes / private), 0o700)
                chown.assert_any_call(probes / private, P["USER"], P["USER"])
            P["write_result"](evidence, {name: P["result"]("PASS", "mode fixture") for name in P["PHASES"]},
                              SOCKET, nonce=NONCE)
            self.assertEqual(mode(evidence), 0o700)
            self.assertEqual(mode(evidence / "runtime-probes.json"), 0o600)
        finally:
            os.umask(old)

    def test_chroot_command_uses_numeric_user_and_empty_environment(self):
        guest = P["Guest"].__new__(P["Guest"])
        guest.inner = "/tmp/probe"
        captured = []
        with patch.dict(P["Guest"].command.__globals__, execute=lambda argv, limit: captured.append((argv, limit))):
            guest.command(["/tmp/probe/program"], 9, QT_QPA_PLATFORM="offscreen")
        argv, limit = captured[0]
        self.assertEqual(limit, 9)
        self.assertEqual(argv[:3], ["/usr/bin/chroot", "/trial-scratch", "/usr/bin/setpriv"])
        self.assertIn("--reuid=65534", argv)
        self.assertIn("--regid=65534", argv)
        self.assertIn("--clear-groups", argv)
        self.assertIn("--no-new-privs", argv)
        self.assertEqual(argv[argv.index("/usr/bin/env") + 1], "-i")
        self.assertNotIn("DISPLAY=", " ".join(argv))
        self.assertNotIn("LD_LIBRARY_PATH=", " ".join(argv))

    def test_process_timeout_and_output_are_bounded(self):
        execute = P["execute"]
        over = execute([sys.executable, "-c", "print('a' * 100000)"], 3)
        self.assertEqual(over["problem"], "OUTPUT_LIMIT")
        self.assertEqual(len(over["output"]), P["MAX_OUTPUT"])
        timeout = execute([sys.executable, "-c", "import time; time.sleep(10)"], 0.15)
        self.assertEqual(timeout["problem"], "TIMEOUT")
        self.assertLess(timeout["exit"], 0)
        self.assertGreater(timeout["pid"], 0)
        self.assertGreater(timeout["start_ticks"], 0)


if __name__ == "__main__":
    unittest.main()
