#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise runner path admission with an inert kernel-metadata fixture."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("runner_inputs", Path(__file__).with_name("runner_inputs.py"))
ingress = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ingress)


class RunnerInputsTests(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory(prefix="qt-volume-")
        self.addCleanup(work.cleanup)
        self.root = Path(work.name)
        self.device, self.inode = self.root.stat().st_dev, self.root.stat().st_ino
        mount_device = f"{os.major(self.device)}:{os.minor(self.device)}"
        self.mountinfo = f"42 12 {mount_device} / {self.root} rw - ext4 /dev/loop7 rw\n"
        self.fdinfo = "pos:\t0\nflags:\t02300000\nmnt_id:\t42\n"

    def kernel_metadata(self, path):
        return self.mountinfo if path.name == "mountinfo" else self.fdinfo

    def test_workspace_requires_the_root_fstat_and_exact_mountinfo(self):
        with patch.object(Path, "read_text", autospec=True, side_effect=self.kernel_metadata):
            with ingress.owned_workspace(self.root, self.device, self.inode, 42) as admitted:
                self.assertEqual(admitted, self.root)
            for device, inode, mount in ((self.device + 1, self.inode, 42),
                                         (self.device, self.inode + 1, 42), (self.device, self.inode, 41)):
                with self.assertRaisesRegex(ValueError, "EXACT_OWNED_EXT4"):
                    with ingress.owned_workspace(self.root, device, inode, mount):
                        self.fail("admitted a different workspace identity")

    def test_workspace_refuses_non_ext4_or_submount_drift(self):
        with patch.object(Path, "read_text", autospec=True, side_effect=self.kernel_metadata):
            with self.assertRaisesRegex(ValueError, "EXACT_OWNED_EXT4"):
                with ingress.owned_workspace(self.root, self.device, self.inode, 42):
                    self.mountinfo += f"99 42 0:99 / {self.root}/foreign rw - tmpfs tmpfs rw\n"
            self.mountinfo = self.mountinfo.splitlines()[0].replace("- ext4", "- btrfs")
            with self.assertRaisesRegex(ValueError, "EXACT_OWNED_EXT4"):
                with ingress.owned_workspace(self.root, self.device, self.inode, 42):
                    self.fail("admitted a non-ext4 mount")

    def test_flat_archive_leaf_accepts_epoch_preserves_pin_and_refuses_escapes(self):
        pin = dict(bytes=1, sha256="a" * 64)
        leaf = "pkg-2:1.3-2-aarch64.pkg.tar.xz"
        self.assertEqual(ingress.local_ref(self.root, "dependencies", leaf, pin),
                         dict(pin, path=str(self.root / "dependencies" / leaf)))
        for name in ("../../else", "sub/file", "/other", "a\nb"):
            with self.assertRaisesRegex(ValueError, "FLAT_OPERAND"):
                ingress.local_ref(self.root, "dependencies", name, pin)

    def test_binding_refuses_outside_or_nested_outputs_before_opening_inputs(self):
        for output in (self.root.parent / "outside", self.root / "operands" / "in-package-directory"):
            with self.assertRaisesRegex(ValueError, "FRESH_DISJOINT_IN_VOLUME_INPUTS"):
                ingress.bind_inputs(self.root / "portable", "b" * 64, self.root / "operands",
                                    self.root / "public", output, self.root)


if __name__ == "__main__":
    unittest.main()
