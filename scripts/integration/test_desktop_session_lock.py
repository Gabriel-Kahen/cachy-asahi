#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Portable offline pair controls; no package installation or payload execution."""
from copy import deepcopy
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("desktop_session_lock.py")
SPEC = importlib.util.spec_from_file_location("pair_verifier", SCRIPT)
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)
ROOT = Path(__file__).resolve().parents[2]
SOURCE_PROFILE = Path(__file__).with_name("profiles") / "desktop-session-lock011.json"


class DesktopSessionLock(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="desktop-pair-test-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.prefix = self.work / "prefix"
        self.prefix.mkdir(mode=0o700)
        self.profile = json.loads(SOURCE_PROFILE.read_bytes())
        self.profile_path = self.work / "profile.json"
        self.payload = {}
        for package, recipe in ((V.SETTINGS, ROOT / "packages/desktop/cachy-asahi-hyprland-settings011"),
                                (V.LOCKER, ROOT / "packages/tools/cachy-asahi-session-lock")):
            self.payload[package] = {path: (recipe / Path(path).name).read_bytes()
                                     for path in self.profile["packages"][package]["payload"]}
        self.archives = {name: self.work / f"{name}.tar" for name in V.VERSIONS}
        self.write_profile()
        self.assemble()
        for package in V.VERSIONS:
            self.write_archive(package)

    def write_profile(self):
        self.profile_path.write_text(json.dumps(self.profile, sort_keys=True, indent=2) + "\n")

    def assemble(self):
        for package, files in self.payload.items():
            for name, data in files.items():
                path = self.prefix / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                path.chmod(self.profile["packages"][package]["payload"][name]["mode"])
        for path in self.prefix.rglob("*"):
            if path.is_dir():
                path.chmod(0o755)

    def write_archive(self, package, mutate=None):
        members = []
        for name in sorted(V.directories(self.payload[package])):
            item = tarfile.TarInfo(name)
            item.type, item.mode = tarfile.DIRTYPE, 0o755
            members.append((item, b""))
        info = deepcopy(self.profile["packages"][package]["metadata"])
        info.update({"builddate": ["1794667200"], "packager": ["Fixture Packager"],
                     "size": [str(sum(map(len, self.payload[package].values())))]})
        metadata = {".PKGINFO": ("\n".join(f"{key} = {value}" for key, values in info.items() for value in values) + "\n").encode(),
                    ".BUILDINFO": b"format = 2\n", ".MTREE": b"fixture archive metadata\n"}
        for name, data in {**metadata, **self.payload[package]}.items():
            item = tarfile.TarInfo(name)
            item.mode = self.profile["packages"][package]["payload"].get(name, {}).get("mode", 0o644)
            members.append((item, data))
        if mutate:
            members = mutate(members)
        with tarfile.open(self.archives[package], "w", format=tarfile.USTAR_FORMAT) as archive:
            for item, data in members:
                item.size = len(data) if item.isfile() else 0
                archive.addfile(item, io.BytesIO(data) if item.isfile() else None)

    def args(self):
        return SimpleNamespace(profile=self.profile_path, profile_sha256=V.sha(self.profile_path.read_bytes()),
                               settings_package=self.archives[V.SETTINGS], settings_sha256=V.sha(self.archives[V.SETTINGS].read_bytes()),
                               session_lock_package=self.archives[V.LOCKER], session_lock_sha256=V.sha(self.archives[V.LOCKER].read_bytes()),
                               prefix=self.prefix)

    def refused(self, pattern=None):
        if pattern:
            with self.assertRaisesRegex((ValueError, OSError), pattern):
                V.verify(self.args())
        else:
            with self.assertRaises((ValueError, OSError)):
                V.verify(self.args())

    def alter_member(self, name, transform, package=V.SETTINGS):
        def mutate(members):
            return [(item, transform(data)) if item.name == name else (item, data) for item, data in members]
        self.write_archive(package, mutate)

    def snapshot(self):
        return {str(path.relative_to(self.prefix)): (path.stat().st_mode, path.stat().st_mtime_ns,
                V.sha(path.read_bytes()) if path.is_file() else None) for path in self.prefix.rglob("*")}

    def test_exact_pair_prefix_passes_without_executing_any_payload_or_mutating_prefix(self):
        before = self.snapshot()
        with patch.object(V.subprocess, "Popen", side_effect=AssertionError("raw archives require no subprocess")):
            report = V.verify(self.args())
        self.assertEqual(report["status"], "desktop-session-lock-prefix-pass")
        self.assertEqual(report["payload_files"], 13)
        self.assertEqual(before, self.snapshot())
        self.assertTrue(report["read_only"])
        self.assertFalse(report["payload_executed"])
        for key in ("native_build", "dependency_resolution", "installed_database_ownership", "session_runtime", "hardware_validation"):
            self.assertEqual(report[key], "NOT RUN")

    def test_source_profile_pins_actual_recipe_payloads(self):
        for package, files in self.payload.items():
            for name, data in files.items():
                entry = self.profile["packages"][package]["payload"][name]
                self.assertEqual(V.sha(data), entry["sha256"], name)
                self.assertEqual(len(data), entry["bytes"], name)
        self.assertEqual(len(self.payload[V.SETTINGS]), 9)
        self.assertEqual(len(self.payload[V.LOCKER]), 4)

    def test_zstd_archives_are_read_from_held_bytes_and_bounded(self):
        for package, path in self.archives.items():
            compressed = subprocess.run(["/usr/bin/zstd", "-q", "-c"], input=path.read_bytes(), capture_output=True, timeout=5)
            self.assertEqual(compressed.returncode, 0)
            path.write_bytes(compressed.stdout)
        self.assertEqual(V.verify(self.args())["payload_files"], 13)

    def test_archive_digest_mismatch_refused_before_decompression(self):
        args = self.args()
        args.settings_sha256 = "0" * 64
        with patch.object(V, "decompress", side_effect=AssertionError("must not decompress unbound bytes")):
            with self.assertRaisesRegex(V.Refused, "checksum mismatch"):
                V.verify(args)

    def test_source_profile_digest_mismatch_refused_before_archive_reads(self):
        args = self.args()
        args.profile_sha256 = "0" * 64
        with patch.object(V, "verify_archive", side_effect=AssertionError("must validate source profile first")):
            with self.assertRaisesRegex(V.Refused, "profile checksum mismatch"):
                V.verify(args)

    def test_missing_helper_archive_refused(self):
        args = self.args()
        self.archives[V.LOCKER].unlink()
        with self.assertRaises(FileNotFoundError):
            V.verify(args)

    def test_symlink_archive_refused(self):
        path = self.archives[V.LOCKER]
        original = path.with_suffix(".real")
        path.rename(original)
        path.symlink_to(original)
        self.refused()

    def test_missing_and_added_profile_payloads_refused(self):
        path = "usr/bin/cachy-asahi-screenshot"
        del self.profile["packages"][V.SETTINGS]["payload"][path]
        self.write_profile()
        self.refused("exact reviewed payload")
        self.profile = json.loads(SOURCE_PROFILE.read_bytes())
        self.profile["packages"][V.LOCKER]["payload"]["usr/bin/unreviewed"] = {"bytes": 1, "mode": 0o755, "sha256": "0" * 64}
        self.write_profile()
        self.refused("exact reviewed payload")

    def test_helper_dependency_bounds_cannot_be_dropped_from_profile(self):
        self.profile["packages"][V.SETTINGS]["metadata"]["depend"].remove(V.HELPER_DEPS[1])
        self.write_profile()
        self.refused("dependency bounds")

    def test_duplicate_and_nonfinite_profile_json_refused(self):
        self.profile_path.write_text(self.profile_path.read_text().replace('"schema": 1', '"schema": 1, "schema": 1'))
        self.refused("duplicate JSON")
        self.profile_path.write_text('{"schema": NaN}')
        self.refused("nonfinite")

    def test_old_settings_version_or_privileged_helper_dependency_refused(self):
        self.alter_member(".PKGINFO", lambda data: data.replace(b"pkgver = 0.1.1-1", b"pkgver = 0.1.0-3"))
        self.refused("metadata differs")
        self.write_archive(V.SETTINGS)
        self.alter_member(".PKGINFO", lambda data: data + b"depend = sudo\n", V.LOCKER)
        self.refused("metadata differs")

    def test_duplicate_identity_or_unreviewed_metadata_refused(self):
        self.alter_member(".PKGINFO", lambda data: data + b"pkgname = cachy-asahi-hyprland-settings\n")
        self.refused("metadata differs")
        self.alter_member(".PKGINFO", lambda data: data + b"conflict = protected-platform\n")
        self.refused("metadata differs")

    def test_package_declared_size_must_match_actual_payload(self):
        self.alter_member(".PKGINFO", lambda data: data.replace(b"size = 30846", b"size = 1"))
        self.refused("payload size differs")

    def test_missing_payload_or_build_metadata_refused(self):
        self.write_archive(V.SETTINGS, lambda members: [(item, data) for item, data in members if item.name != "usr/bin/cachy-asahi-screenshot"])
        self.refused("files/directories missing")
        self.write_archive(V.SETTINGS, lambda members: [(item, data) for item, data in members if item.name != ".BUILDINFO"])
        self.refused("files/directories missing")

    def test_changed_helper_archive_bytes_refused_with_updated_archive_receipt(self):
        self.alter_member(f"usr/bin/{V.LOCKER}", lambda data: data + b"\n# tamper\n", V.LOCKER)
        self.refused("archive payload differs")

    def test_duplicate_archive_members_refused(self):
        self.write_archive(V.SETTINGS, lambda members: members + [next((deepcopy(item), data) for item, data in members if item.name == ".PKGINFO")])
        self.refused("duplicate archive")

    def test_unexpected_archive_file_or_install_hook_refused(self):
        for name in ("usr/bin/extra", ".INSTALL", "../escape"):
            with self.subTest(name=name):
                item = tarfile.TarInfo(name)
                item.mode = 0o644
                self.write_archive(V.SETTINGS, lambda members: members + [(item, b"unreviewed")])
                self.refused()

    def test_symlink_hardlink_fifo_and_setuid_archive_members_refused(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.REGTYPE):
            with self.subTest(kind=kind):
                def mutate(members):
                    for item, _ in members:
                        if item.name == "usr/bin/cachy-asahi-screenshot":
                            item.type = kind
                            if kind == tarfile.REGTYPE:
                                item.mode = 0o4755
                            elif kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                                item.linkname = "/outside"
                    return members
                self.write_archive(V.SETTINGS, mutate)
                self.refused()

    def test_nonroot_archive_ownership_refused(self):
        def mutate(members):
            members[-1][0].uid = 1000
            return members
        self.write_archive(V.SETTINGS, mutate)
        self.refused("ownership/mode")

    def test_missing_prefix_helper_or_settings_file_refused(self):
        for name in (f"usr/bin/{V.LOCKER}", "usr/share/cachy-asahi/hyprland/hyprland.lua"):
            with self.subTest(name=name):
                path = self.prefix / name
                data = path.read_bytes()
                mode = stat.S_IMODE(path.stat().st_mode)
                path.unlink()
                self.refused("prefix files/directories missing")
                path.write_bytes(data)
                path.chmod(mode)

    def test_changed_prefix_bytes_or_mode_refused(self):
        path = self.prefix / f"usr/bin/{V.LOCKER}"
        original = path.read_bytes()
        path.write_bytes(original + b"# changed")
        self.refused("prefix payload differs")
        path.write_bytes(original)
        path.chmod(0o644)
        self.refused("prefix payload differs")

    def test_unexpected_prefix_file_and_empty_directory_refused(self):
        path = self.prefix / "unexpected"
        path.write_text("preserve")
        self.refused("unexpected prefix")
        self.assertEqual(path.read_text(), "preserve")
        path.unlink()
        path.mkdir(mode=0o755)
        self.refused("unexpected prefix directory")

    def test_symlink_prefix_file_and_parent_directory_refused_without_following(self):
        path = self.prefix / f"usr/bin/{V.LOCKER}"
        outside = self.work / "private"
        outside.write_text("preserve")
        path.unlink()
        path.symlink_to(outside)
        self.refused()
        self.assertEqual(outside.read_text(), "preserve")
        path.unlink()
        self.assemble()
        moved = self.work / "outside-usr"
        (self.prefix / "usr").rename(moved)
        (self.prefix / "usr").symlink_to(moved, target_is_directory=True)
        self.refused("unexpected prefix")

    def test_hardlinked_prefix_file_refused(self):
        os.link(self.prefix / f"usr/bin/{V.LOCKER}", self.work / "other-name")
        self.refused("regular file required")

    def test_changed_lua_cannot_be_admitted_by_merely_updating_profile_hashes(self):
        name = "usr/share/cachy-asahi/hyprland/hyprland.lua"
        data = self.payload[V.SETTINGS][name].replace(b"cachy-asahi-session-lock suspend", b"systemctl suspend")
        self.payload[V.SETTINGS][name] = data
        self.profile["packages"][V.SETTINGS]["payload"][name].update({"sha256": V.sha(data), "bytes": len(data)})
        self.write_profile()
        self.write_archive(V.SETTINGS)
        self.assemble()
        self.refused("required lock/suspend bindings")

    def test_unrelated_lua_delta_rejected_even_with_matching_profile_and_prefix(self):
        name = "usr/share/cachy-asahi/hyprland/hyprland.lua"
        data = self.payload[V.SETTINGS][name].replace(b"gaps_in = 3", b"gaps_in = 99")
        self.payload[V.SETTINGS][name] = data
        self.profile["packages"][V.SETTINGS]["payload"][name].update({"sha256": V.sha(data), "bytes": len(data)})
        self.write_profile()
        self.write_archive(V.SETTINGS)
        self.assemble()
        self.refused("beyond reviewed lock/suspend delta")

    def test_oversized_archive_and_zstd_expansion_refused(self):
        path = self.archives[V.SETTINGS]
        path.write_bytes(b"x" * (V.MAX_ARCHIVE + 1))
        self.refused("size limit")
        compressed = subprocess.run(["/usr/bin/zstd", "-q", "-c"], input=b"\0" * (V.MAX_ARCHIVE + 65536), capture_output=True, timeout=5)
        path.write_bytes(compressed.stdout)
        self.refused("decompression exceeds limit")

    def test_nonzero_trailing_archive_data_refused(self):
        path = self.archives[V.SETTINGS]
        path.write_bytes(path.read_bytes() + b"hidden trailing bytes")
        self.refused("nonzero data after archive")

    def test_source_cli_accepts_pair_with_hostile_environment_without_session_access(self):
        args = self.args()
        argv = [sys.executable, "-I", "-B", str(SCRIPT)]
        for key, value in vars(args).items():
            argv.extend(("--" + key.replace("_", "-"), str(value)))
        result = subprocess.run(argv, env={"PATH": "/absent", "PYTHONPATH": "/absent", "PYTHONHOME": "/absent",
                                          "WAYLAND_DISPLAY": "host", "DBUS_SESSION_BUS_ADDRESS": "invalid"}, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(json.loads(result.stdout)["status"], "desktop-session-lock-prefix-pass")
        (self.prefix / f"usr/bin/{V.LOCKER}").write_bytes(b"tampered")
        refused = subprocess.run(argv, env={}, capture_output=True, timeout=5)
        self.assertEqual(refused.returncode, 2, refused.stderr + refused.stdout)
        self.assertEqual(json.loads(refused.stdout)["status"], "refused")
        self.assertFalse(json.loads(refused.stdout)["payload_executed"])
        direct = subprocess.run([sys.executable, "-B", str(SCRIPT), "--help"], env={}, capture_output=True, timeout=5)
        self.assertEqual(direct.returncode, 2)
        self.assertIn(b"isolated mode", direct.stderr)


if __name__ == "__main__":
    unittest.main()
