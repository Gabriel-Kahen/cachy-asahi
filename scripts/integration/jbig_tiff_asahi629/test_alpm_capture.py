# SPDX-License-Identifier: MIT
"""Use only tiny synthetic stopped ext4 images and the read-only metadata helper."""

import os
from pathlib import Path
from runpy import run_path
import shutil
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
T = SimpleNamespace(**run_path(str(HERE.parents[1] / "install/overlay583_trial/trial.py")))
A = run_path(str(HERE / "alpm_capture.py"))
CAPTURE = A["capture"]
NONCE = "12" * 16
PACKAGE = "python-3.14.7-1"
OTHER = "grub-2:2.16-3"
LOCK = b"grub 2:2.16-3\npython 3.14.7-1\n"
LOCAL = "var/lib/pacman/local/"
UUID = "725346d2-f127-47bc-b464-9dd46155e8d6"
MKE2FS = shutil.which("mke2fs")
DEBUGFS = shutil.which("debugfs")


def desc(name, version, arch="aarch64"):
    return f"%NAME%\n{name}\n\n%VERSION%\n{version}\n\n%ARCH%\n{arch}\n\n".encode()


def image(path, *, changes=None, link=None):
    inputs = {
        f"{LOCAL}ALPM_DB_VERSION": b"9\n",
        f"{LOCAL}{PACKAGE}/desc": desc("python", "3.14.7-1"),
        f"{LOCAL}{PACKAGE}/files": b"%FILES%\nusr/bin/python\n\n",
        f"{LOCAL}{PACKAGE}/mtree": b"opaque bounded metadata",
        f"{LOCAL}{OTHER}/desc": desc("grub", "2:2.16-3"),
        f"{LOCAL}{OTHER}/files": b"%FILES%\nusr/bin/grub-install\n\n",
        f"{LOCAL}{OTHER}/install": b"package script retained only as data\n",
    } | (changes or {})
    directories = {str(parent) for leaf in inputs for parent in Path(leaf).parents} - {"."}
    with tempfile.TemporaryDirectory(prefix="fixture-", dir=path.parent) as fixture:
        root = Path(fixture)
        for name, data in sorted(inputs.items()):
            dest = root / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            if link and name == link[0]:
                kind, target = link[1:]
                if kind == "symlink":
                    dest.symlink_to(target)
                else:
                    os.link(root / target, dest)
            else:
                dest.write_bytes(data)
        with path.open("xb") as output:
            output.truncate(16 << 20)
        subprocess.run([MKE2FS, "-q", "-F", "-t", "ext4", "-b", "4096", "-U", UUID,
                        "-d", fixture, str(path)], capture_output=True, check=True, timeout=10)
    # Set fixture ownership inside the image without needing host root privileges.
    commands = "".join(f"set_inode_field /{name} {field} 0\n" for name in sorted(directories | inputs.keys())
                       for field in ("uid", "gid"))
    subprocess.run([DEBUGFS, "-w", "-f", "-", str(path)], input=commands.encode(),
                   capture_output=True, check=True, timeout=10)
    return inputs


@unittest.skipUnless(MKE2FS and DEBUGFS, "e2fsprogs is required for synthetic ext4 captures")
class CaptureTests(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory(prefix="asahi629-alpm-capture-test-")
        self.addCleanup(work.cleanup)
        self.root = Path(work.name)
        self.scratch = self.root / "scratch.raw"
        self.pending = self.root / "alpm-local.pending"
        debugfs = Path(DEBUGFS).resolve(strict=True)
        self.enterContext(patch.dict(CAPTURE.__globals__, DEBUGFS=debugfs))
        self.tool_pin = T.read(debugfs, cap=1 << 20, collect=False)

    def capture(self, lock=LOCK, **overrides):
        operands = dict(expected_size=16 << 20, expected_uuid=UUID, debugfs_pin=self.tool_pin)
        with patch.dict(CAPTURE.__globals__, COUNT=2):
            return CAPTURE(T, self.scratch, lock, NONCE, self.pending, **(operands | overrides))

    def absent(self):
        self.assertFalse(self.pending.exists())
        self.assertFalse(list(self.root.glob(".alpm-capture-*")))

    def test_stopped_database_yields_only_complete_pending_evidence(self):
        inputs = image(self.scratch)
        saved = self.scratch.read_bytes()
        before = T.identity(self.scratch.stat())
        result = self.capture()
        self.assertEqual(T.identity(self.scratch.stat()), before)
        self.assertEqual(self.scratch.read_bytes(), saved)
        self.assertEqual({path.name for path in self.pending.iterdir()}, {"local", "rollback.lock", "manifest.json"})
        self.assertEqual((self.pending / "rollback.lock").read_bytes(), LOCK)
        receipt = (self.pending / "manifest.json").read_bytes()
        self.assertEqual(T.pin(receipt), result)
        manifest = T.decode(receipt)
        pins = {name.removeprefix(LOCAL): T.pin(value) for name, value in inputs.items()}
        self.assertEqual(manifest["files"], pins)
        self.assertGreater(manifest["directories"]["/var/lib/pacman/local"]["listing"]["bytes"], 0)
        self.assertEqual((manifest["nonce"], manifest["packages"], manifest["lock"], manifest["scratch"]["uuid"]),
                         (NONCE, 2, T.pin(LOCK), UUID))
        for name, value in inputs.items():
            relative = name.removeprefix(LOCAL)
            path = self.pending / "local" / relative
            self.assertEqual(path.read_bytes(), value)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertFalse(list(self.root.glob(".alpm-capture-*")))

    def test_production_entry_requires_629_canonical_rows(self):
        with self.assertRaisesRegex(ValueError, "Exact sorted pacman lock"):
            CAPTURE(T, self.scratch, LOCK, NONCE, self.pending, expected_size=16 << 20,
                    expected_uuid=UUID, debugfs_pin=self.tool_pin)
        self.absent()

    def test_production_count_reads_full_synthetic_namespace(self):
        names = [f"fixture-{num:03d}" for num in range(627)]
        records = {f"{LOCAL}{name}-1.0-1/{member}": data for name in names
                   for member, data in (("desc", desc(name, "1.0-1", "any")), ("files", b"%FILES%\n\n"),
                                        ("mtree", b"opaque bounded metadata"))}
        image(self.scratch, changes=records)
        lock = b"".join(sorted(LOCK.splitlines(keepends=True) + [f"{name} 1.0-1\n".encode() for name in names]))
        pin = CAPTURE(T, self.scratch, lock, NONCE, self.pending, expected_size=16 << 20,
                      expected_uuid=UUID, debugfs_pin=self.tool_pin)
        manifest = T.decode(T.read(self.pending / "manifest.json", pin, cap=1 << 20))
        self.assertEqual(manifest["packages"], 629)
        self.assertEqual(len(manifest["files"]), 1888)
        self.assertEqual(len(manifest["directories"]), 634)

    def test_restored_lock_mismatch_is_refused_without_output(self):
        image(self.scratch)
        with self.assertRaisesRegex(ValueError, "directory identities differ"):
            self.capture(LOCK.replace(b"3.14.7", b"3.14.8"))
        self.absent()

    def test_descriptor_identity_mismatch_is_refused_without_output(self):
        image(self.scratch, changes={f"{LOCAL}{PACKAGE}/desc": desc("python", "3.14.8-1")})
        with self.assertRaisesRegex(ValueError, "descriptor identity differs"):
            self.capture()
        self.absent()

    def test_database_lock_or_extra_package_file_refuses(self):
        cases = (("var/lib/pacman/db.lck", "still has a pacman lock"),
                 (f"{LOCAL}{PACKAGE}/extra", "Unexpected local database package members"))
        for name, detail in cases:
            with self.subTest(name=name):
                self.scratch.unlink(missing_ok=True)
                image(self.scratch, changes={name: b"extra"})
                with self.assertRaisesRegex(ValueError, detail):
                    self.capture()
                self.absent()

    def test_symlink_and_hardlink_metadata_are_refused(self):
        target = f"{LOCAL}{PACKAGE}/mtree"
        cases = (("symlink", "../../elsewhere", "root-owned bounded local database file"),
                 ("hardlink", "other", "another link"))
        for kind, where, detail in cases:
            with self.subTest(kind=kind):
                self.scratch.unlink(missing_ok=True)
                image(self.scratch, changes={"other": b"outside database"}, link=(target, kind, where))
                with self.assertRaisesRegex(ValueError, detail):
                    self.capture()
                self.absent()

    def test_dirty_and_changed_scratch_do_not_publish(self):
        image(self.scratch)
        with self.scratch.open("r+b") as fd:
            os.pwrite(fd.fileno(), b"\x00\x00", 1024 + 58)
        with self.assertRaisesRegex(ValueError, "clean shutdown differs"):
            self.capture()
        self.absent()
        self.scratch.unlink()
        image(self.scratch)
        command = A["command"]
        changed = False

        def mutate(*args):
            nonlocal changed
            response = command(*args)
            if not changed:
                with self.scratch.open("r+b") as fd:
                    os.pwrite(fd.fileno(), b"touched", 0)
                changed = True
            return response

        with patch.dict(CAPTURE.__globals__, command=mutate), self.assertRaisesRegex(ValueError, "scratch image changed"):
            self.capture()
        self.absent()

    def test_concurrent_pending_name_is_never_replaced(self):
        image(self.scratch)
        original = A["publish"]

        def race(*args):
            self.pending.mkdir()
            original(*args)

        with patch.dict(CAPTURE.__globals__, publish=race), self.assertRaises(FileExistsError):
            self.capture()
        self.assertEqual(list(self.pending.iterdir()), [])
        self.assertFalse(list(self.root.glob(".alpm-capture-*")))

    def test_wrong_debugfs_pin_never_dispatches(self):
        image(self.scratch)
        self.tool_pin = self.tool_pin | {"sha256": "0" * 64}
        with patch.dict(CAPTURE.__globals__, command=lambda *_: self.fail("debugfs started")):
            with self.assertRaisesRegex(ValueError, "debugfs tool pin differs"):
                self.capture()
        self.absent()

    def test_wrong_expected_size_or_uuid_never_dispatches(self):
        image(self.scratch)
        cases = (({"expected_size": 8 << 20}, "scratch image of the selected size"),
                 ({"expected_uuid": "12345678-f127-47bc-b464-9dd46155e8d6"}, "UUID differs"))
        with patch.dict(CAPTURE.__globals__, command=lambda *_: self.fail("debugfs started")):
            for override, detail in cases:
                with self.subTest(override=override), self.assertRaisesRegex(ValueError, detail):
                    self.capture(**override)
        self.absent()


if __name__ == "__main__":
    unittest.main()
