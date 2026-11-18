# SPDX-License-Identifier: MIT
"""Portable pre-GnuPG controls for the companion Q2 trust regression."""

import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("qt_rootfs_check", Path(__file__).with_name("check.py"))
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)
P = check.public


class Controls(unittest.TestCase):
    def setUp(self):
        scratch = TemporaryDirectory(prefix="qt-rootfs-plan-")
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        builder = P.decode(P.read_pinned(P.SOURCE / "builder.lock.json", P.BUILDER))
        rootfs = builder["rootfs"]
        files = {
            check.ARCHIVE: dict(bytes=rootfs["size"], sha256=rootfs["sha256"]),
            check.SIGNATURE: dict(bytes=rootfs["signature_size"], sha256=rootfs["signature_sha256"]),
        }
        for row in builder["keyring_files"]:
            files["official/" + row["filename"]] = dict(bytes=row["size"], sha256=row["sha256"])
        self.plan = dict(kind=check.PLAN_KIND, Root_authority=None, files=files)

    def write_plan(self):
        raw = P.encoded(self.plan)
        (self.root / "plan.json").write_bytes(raw)
        return P.pin(raw)["sha256"]

    def test_plan_keeps_only_five_anchored_operands(self):
        self.plan["files"]["unrelated-to-rootfs"] = P.pin(b"ignored")
        pin = self.write_plan()
        _, materials = check.selected_inputs(self.root, pin)
        self.assertEqual(set(materials), {check.ARCHIVE, check.SIGNATURE, check.ARMOR, check.TRUSTED, check.REVOKED})
        self.assertEqual(materials[check.REVOKED], P.pin(b""))

    def test_changed_whole_plan_pin_and_issued_plan_refuse(self):
        pin = self.write_plan()
        self.plan["Root_authority"] = "not unissued"
        updated_pin = self.write_plan()
        with self.assertRaisesRegex(ValueError, "operand size/SHA256 mismatch"):
            check.selected_inputs(self.root, pin)
        with self.assertRaisesRegex(ValueError, "Expected unissued"):
            check.selected_inputs(self.root, updated_pin)

    def test_new_plan_digest_cannot_replace_any_rootfs_or_trust_pin(self):
        for name in self.plan["files"]:
            with self.subTest(name=name):
                original = self.plan["files"][name]
                self.plan["files"][name] = dict(original, sha256="f" * 64)
                with self.assertRaisesRegex(ValueError, "exact independent rootfs"):
                    check.selected_inputs(self.root, self.write_plan())
                self.plan["files"][name] = original

    def test_changed_physical_rootfs_refuses_before_gnupg(self):
        (self.root / check.ARCHIVE).write_bytes(b"short untrusted body")
        with patch.object(check.lifecycle, "bounded_process") as crypto:
            with self.assertRaisesRegex(ValueError, "exact ordinary single-link leaf"):
                check.verify(self.root, self.write_plan())
            crypto.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
