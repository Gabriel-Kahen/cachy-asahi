"""Synthetic/portable contract tests; no desktop, devices or native ARM claim."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("desktop", Path(__file__).with_name("desktop.py"))
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)


class DesktopTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="desktop-contract-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def facts(self):
        return {"marker_env": "1", "marker": True, "arch": "aarch64", "uid": 1001,
                "nonce": "a" * 32, "image_id": "sha256:" + "b" * 64,
                "capabilities": {"CapEff": 0, "CapPrm": 0, "CapBnd": 0}, "no_new_privileges": "1",
                "interfaces": ["lo"], "runner": "/runner/desktop.py",
                "mounts": {point: {"flags": [flag], "type": kind} for point, flag, kind in
                           (("/", "ro", "overlay"), ("/inputs", "ro", "bind"),
                            ("/runner", "ro", "bind"), ("/out", "rw", "bind"), ("/tmp", "rw", "tmpfs"))}}

    def test_host_and_privileged_context_are_refused(self):
        for changed in ({"marker": False}, {"marker_env": None}, {"uid": 0}, {"arch": "x86_64"}):
            with self.assertRaises(d.Refused):
                d.validate_container(self.facts() | changed)

    def test_mount_capability_and_network_contract(self):
        facts = self.facts()
        d.validate_container(facts)
        for changed in ({"capabilities": {"CapEff": 1}}, {"no_new_privileges": "0"},
                        {"interfaces": ["eth0", "lo"]}, {"runner": "/host/desktop.py"}, {"nonce": ""}):
            with self.assertRaises(d.Refused):
                d.validate_container(facts | changed)
        for point in ("/", "/inputs", "/runner", "/out", "/tmp"):
            bad = self.facts()
            del bad["mounts"][point]
            with self.assertRaises(d.Refused):
                d.validate_container(bad)
        bad = self.facts()
        bad["mounts"]["/home"] = {"flags": ["ro"], "type": "bind"}
        with self.assertRaisesRegex(d.Refused, "host/system"):
            d.validate_container(bad)

    def test_nested_mount_cannot_override_readonly_input_or_tmpfs_scratch(self):
        for point in ("/inputs/runtime.lock", "/runner/desktop.py", "/tmp/host-home", "/out/desktop"):
            for flags in (["rw"], ["ro"]):
                bad = self.facts()
                bad["mounts"][point] = {"flags": flags, "type": "ext4"}
                with self.assertRaisesRegex(d.Refused, "nested"):
                    d.validate_container(bad)

    def test_inherited_display_connection_is_refused(self):
        with patch.dict(os.environ, {"WAYLAND_DISPLAY": "wayland-host"}, clear=True), \
                patch.object(d, "container_facts", return_value=self.facts()), self.assertRaisesRegex(d.Refused, "WAYLAND_DISPLAY"):
            d.isolation_guard()

    def test_excluded_device_is_refused(self):
        present = lambda path: str(path) in ("/.dockerenv", "/dev/dri")
        with patch.dict(os.environ, {"CACHY_ASAHI_INTEGRATION_CONTAINER": "1"}, clear=True), \
                patch.object(d.Path, "exists", present), \
                patch.object(d, "container_facts", return_value=self.facts()), self.assertRaisesRegex(d.Refused, "/dev/dri"):
            d.isolation_guard()

    def test_inventory_and_metadata_preserve_exact_values(self):
        self.assertEqual(d.inventory("hyprland 0.56.2-4\n"), {"hyprland": "0.56.2-4"})
        for text in ("", "x 1\nx 2\n", "invalid\n"):
            with self.assertRaises(d.Refused):
                d.inventory(text)
        self.assertEqual(d.metadata("# comment\npkgname = desktop\narch = any\n"),
                         {"pkgname": ["desktop"], "arch": ["any"]})

    def test_strict_json_rejects_shadowed_values_and_nonfinite(self):
        self.assertEqual(d.unique_json('{"modules-left": ["clock"]}'), {"modules-left": ["clock"]})
        for text in ('{"x": 1, "x": 2}', '{"x": NaN}'):
            with self.assertRaises(d.Refused):
                d.unique_json(text)

    def test_mako_subset_is_explicit_and_rejects_unknown_options(self):
        text = "background-color=#20242c\ntext-color=#eceff4\nborder-color=#88c0d0\nborder-size=2\ndefault-timeout=5000\n"
        self.assertEqual(len(d.mako_subset(text)), 5)
        for bad in (text + "include=/host/file\n", text.replace("size=2", "size=-1"),
                    text.replace("#20242c", "red"), text + "border-size=3\n"):
            with self.assertRaises(d.Refused):
                d.mako_subset(bad)

    def test_optional_callback_is_enabled_without_executing_it(self):
        text = '-- keep comment\n-- hl.on("hyprland.start", function()\n--     hl.exec_cmd("mako")\n-- end)\n'
        enabled = d.optional_startup(text)
        self.assertIn('-- keep comment\nhl.on(', enabled)
        self.assertIn('    hl.exec_cmd("mako")', enabled)
        for bad in (text.replace("-- end)", ""), text + text, text.replace('--     hl.exec_cmd', 'hl.exec_cmd')):
            with self.assertRaises(d.Refused):
                d.optional_startup(bad)

    def payload_fixture(self):
        content = {name: "data for " + name + "\n" for name in d.PAYLOAD}
        for name, text in content.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        def checked(argv):
            if "-tf" in argv:
                return "\n".join([".PKGINFO", ".BUILDINFO", ".MTREE", *sorted(content)])
            if "-Qoq" in argv:
                return d.PACKAGE + "\n"
            return content[argv[-1]]
        return checked, content

    def test_actual_installed_bytes_are_required(self):
        checked, content = self.payload_fixture()
        self.assertEqual(len(d.bind_payload(checked, self.root / "archive", self.root)), 7)
        name = next(iter(content))
        (self.root / name).write_text("locally changed")
        with self.assertRaisesRegex(d.Refused, "bytes differ"):
            d.bind_payload(checked, self.root / "archive", self.root)

    def test_installed_symlink_or_unexpected_owner_is_refused(self):
        checked, content = self.payload_fixture()
        name = next(iter(content))
        (self.root / name).unlink()
        (self.root / name).symlink_to(self.root / next(n for n in content if n != name))
        with self.assertRaisesRegex(d.Refused, "symlink"):
            d.bind_payload(checked, self.root / "archive", self.root)
        (self.root / name).unlink()
        (self.root / name).write_text(content[name])
        with self.assertRaisesRegex(d.Refused, "owner"):
            d.bind_payload(lambda argv: "other" if "-Qoq" in argv else checked(argv), self.root / "archive", self.root)

    def test_extra_hook_or_duplicate_archive_member_is_refused(self):
        checked, _ = self.payload_fixture()
        for extra in (".INSTALL", next(iter(d.PAYLOAD))):
            with self.assertRaisesRegex(d.Refused, "payload"):
                d.bind_payload(lambda argv: checked(argv) + "\n" + extra if "-tf" in argv else checked(argv),
                               self.root / "archive", self.root)

    def test_timeout_reaps_original_process_group(self):
        code = "import os,time;print(os.getpid(),flush=True);time.sleep(.5)"
        log = self.root / "timeout.txt"
        result = d.command([sys.executable, "-c", code], self.root, os.environ.copy(), log, .08)
        self.assertEqual(result["error"], "timeout")
        self.assertNotEqual(result["returncode"], 0)
        pid = int(log.read_text())
        self.assertFalse(Path("/proc", str(pid)).exists())

    def test_output_cap_kills_noisy_process_before_unbounded_retention(self):
        result = d.command([sys.executable, "-c", "import sys,time;sys.stdout.write('x'*2097152);sys.stdout.flush();time.sleep(.5)"],
                           self.root, os.environ.copy(), self.root / "noisy.txt", 1)
        self.assertIn("evidence limit", result["error"])
        self.assertEqual((self.root / "noisy.txt").stat().st_size, d.MAX_TEXT)

    def test_sigterm_at_completion_is_not_swallowed(self):
        real = subprocess.Popen
        class TermAtCompletion(real):
            sent = False
            def poll(self):
                result = super().poll()
                if result == 0 and not self.sent:
                    self.sent = True
                    os.kill(os.getpid(), signal.SIGTERM)
                return result
        with patch.object(d.subprocess, "Popen", TermAtCompletion):
            result = d.command([sys.executable, "-c", "pass"], self.root, os.environ.copy(), self.root / "signal.txt", 1)
        self.assertEqual(result["error"], "SIGTERM")

    def test_failed_guard_does_not_write_or_execute(self):
        output = self.root / "no-output"
        argv = ["desktop.py", "--package", str(self.root / "absent"), "--package-sha256", "0" * 64,
                "--runtime-lock", str(self.root / "lock"), "--output", str(output)]
        with patch.object(sys, "argv", argv), patch.object(d, "isolation_guard", side_effect=d.Refused("refused")), \
                patch.object(d, "command") as run:
            self.assertEqual(d.main(), 2)
        self.assertFalse(output.exists())
        run.assert_not_called()

    def test_failed_input_is_retained_without_claims(self):
        output = self.root / "evidence"
        output.mkdir()
        args = argparse.Namespace(package=self.root / "absent", package_sha256="0" * 64,
                                  runtime_lock=self.root / "absent", timeout=1)
        with patch.object(d, "isolation_guard", return_value=self.facts()):
            self.assertEqual(d.verify(args, output), 2)
        record = json.loads((output / "desktop.json").read_text())
        self.assertEqual(record["status"], "FAILED")
        self.assertEqual(record["commands"], [])
        for key in ("hardware_validation", "graphics_acceleration", "portal_audio_session", "optimization_acceptance"):
            self.assertEqual(record[key], "NOT RUN")
        self.assertFalse(record["headless_compositor"]["attempted"])

    def test_synthetic_success_keeps_session_and_hardware_unaccepted(self):
        checked, content = self.payload_fixture()
        prefix = self.root / "usr/share/cachy-asahi/hyprland"
        content["usr/share/cachy-asahi/hyprland/hyprland.lua"] = (
            '-- hl.on("hyprland.start", function()\n--     hl.exec_cmd("mako")\n-- end)\n')
        content["usr/share/cachy-asahi/hyprland/waybar.json"] = '{"modules-left": ["clock"]}\n'
        content["usr/share/cachy-asahi/hyprland/mako.conf"] = (
            "background-color=#20242c\ntext-color=#eceff4\nborder-color=#88c0d0\nborder-size=2\ndefault-timeout=5000\n")
        for name, text in content.items():
            (self.root / name).write_text(text)
        package = self.root / "package"
        package.write_bytes(b"synthetic archive")
        lock = self.root / "runtime.lock"
        lock.write_text("hyprland 0.56.2-4\naquamarine 0.15.1-1\nlua 1\ngtk3 1\npython 1\nlibarchive 1\n")
        output = self.root / "evidence"
        output.mkdir()
        args = argparse.Namespace(package=package, package_sha256=d.sha(package.read_bytes()), runtime_lock=lock, timeout=1)
        def fake_command(argv, cwd, env, log, timeout):
            if argv == ["/usr/bin/pacman", "-Q"]:
                text = lock.read_text() + d.PACKAGE + " 0.1.0-1\n"
            elif argv[-1] == ".PKGINFO":
                text = f"pkgname = {d.PACKAGE}\narch = any\npkgver = 0.1.0-1\n"
            elif argv[-1] == "--version":
                text = "Hyprland 0.56.2 " + d.HYPRLAND_COMMIT
            elif "--verify-config" in argv:
                text = "config ok"
            elif "--gtk-css" in argv:
                text = '{"status": "PASS", "display_created": false}'
            elif "-p" in argv:
                text = ""
            else:
                text = checked(argv)
            Path(log).write_text(text)
            return {"argv": argv, "returncode": 0, "error": None, "stdout": text, "log_sha256": d.sha(text.encode())}
        real_bind = d.bind_payload
        with patch.object(d, "isolation_guard", return_value=self.facts()), patch.object(d, "command", fake_command), \
                patch.object(d, "PREFIX", prefix), \
                patch.object(d, "bind_payload", side_effect=lambda run, archive: real_bind(run, archive, self.root)):
            self.assertEqual(d.verify(args, output), 0)
        record = json.loads((output / "desktop.json").read_text())
        self.assertEqual(record["status"], "desktop-container-verifier-pass")
        self.assertEqual(len(record["installed_payload_sha256"]), 7)
        self.assertEqual(record["application_runtime"]["waybar"]["status"], "NOT RUN")
        self.assertEqual(record["application_runtime"]["mako"]["status"], "NOT RUN")
        self.assertFalse(record["headless_compositor"]["attempted"])
        self.assertEqual(record["optimization_acceptance"], "NOT RUN")


if __name__ == "__main__":
    unittest.main()
