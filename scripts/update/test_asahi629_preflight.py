#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Synthetic pinned input and refusal controls with no update or GPG actors."""

from pathlib import Path
from runpy import run_path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


P = run_path(str(Path(__file__).with_name("asahi629_preflight.py")))
T, O, A = (P[key] for key in ("T", "O", "A"))


class Asahi629PreflightTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.old = {name: versions[0] for name, versions in O["REVERSED"].items()}
        self.old.update({f"base-{index:03}": "1-1" for index in range(626)})
        self.new = self.old | {name: versions[1] for name, versions in O["REVERSED"].items()}
        self.paths = {role: self.root / (role + ".lock") for role in P["LOCKS"]}
        self.refs = {}
        for role, path in self.paths.items():
            contents = self.new if role == "candidate" else self.old
            raw = self.save_lock(path, contents)
            self.refs[P["LOCKS"][role]] = (629, len(raw), T["pin"](raw)["sha256"])
        self.pins, self.pairs = {}, {}
        self.key = "keys/alarm.gpg"
        self.save(self.key, b"synthetic public certificate")
        signer = A["FINGERPRINT"]
        for role, phase in P["ARCHIVE_PHASES"].items():
            self.pairs[phase] = {}
            for name in O["REVERSED"]:
                version = (self.new if role == "candidate" else self.old)[name]
                leaf = f"{phase}/{name}-{version}-aarch64.pkg.tar.xz"
                self.pairs[phase][name] = dict(archive=leaf, scope="vendor", signer=signer)
                self.save(leaf, f"archive {leaf}".encode())
                self.save(leaf + ".sig", f"signature {leaf}".encode())
        manifest = dict(kind=O["KIND"], keys={"alarm": dict(file=self.key, scope="vendor", fingerprint=signer)},
                        files=self.pins, packages=self.pairs)
        raw = T["encoded"](manifest)
        (self.root / "manifest.json").write_bytes(raw)
        self.enterContext(patch.dict(O, REFS=self.refs))
        self.enterContext(patch.dict(P["audit"].__globals__, TRANSPORT=T["pin"](raw),
                                     public_keyring=lambda _key, home: home / "alarm.gpg"))
        self.enterContext(patch.dict(A, verify_signature=self.verify_pair))

    @staticmethod
    def save_lock(path, inventory):
        raw = "".join(f"{name} {version}\n" for name, version in sorted(inventory.items())).encode()
        path.write_bytes(raw)
        return raw

    def save(self, leaf, raw):
        path = self.root / leaf
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        self.pins[leaf] = T["pin"](raw)

    def verify_pair(self, row, home, keyring):
        self.assertEqual(row["signer"], A["FINGERPRINT"])
        self.assertEqual(row["archive"]["path"], self.root / row["filename"])
        self.assertEqual(row["signature"]["path"], self.root / (row["filename"] + ".sig"))
        self.assertEqual(keyring.parent, home)
        return T["pin"](b"simulated verification")

    def audit(self, **paths):
        return P["audit"](**(self.paths | paths), media=self.root)

    def test_complete_vendor_operands_remain_held_for_unselected_update(self):
        result = self.audit()
        self.assertEqual(result["status"], "HOLD_ASAHI629_COORDINATED_UPDATE_INPUTS")
        self.assertIsNone(result["authority"])
        self.assertEqual(result["inventories"]["before"], result["inventories"]["recovery"])
        self.assertEqual(result["missing_retained_files"], [])
        self.assertTrue(result["unselected_prerequisites"])
        for phase in ("candidate", "recovery"):
            self.assertEqual(result["operands"][phase].keys(), O["REVERSED"].keys())
            self.assertTrue(all("gpgv_status" in row for row in result["operands"][phase].values()))

    def test_candidate_cannot_reuse_recovery_even_with_all_629_names(self):
        with self.assertRaisesRegex(ValueError, "Changed pinned bytes: recovery.lock"):
            self.audit(candidate=self.paths["recovery"])

    def test_recovery_cannot_change_one_unrelated_row_at_same_count(self):
        self.save_lock(self.paths["recovery"], self.old | {"base-000": "2-1"})
        with self.assertRaisesRegex(ValueError, "Changed pinned bytes: recovery.lock"):
            self.audit()

    def test_missing_recovery_signature_leaves_only_that_pair_unverified(self):
        leaf = self.pairs["rollback"]["python"]["archive"] + ".sig"
        (self.root / leaf).unlink()
        result = self.audit()
        self.assertEqual(result["missing_retained_files"], [leaf])
        self.assertNotIn("gpgv_status", result["operands"]["recovery"]["python"])
        self.assertIn("gpgv_status", result["operands"]["candidate"]["python"])

    def test_signed_operands_cannot_be_exchanged_between_candidate_and_recovery(self):
        left, right = (self.root / (self.pairs[phase]["perl"]["archive"] + ".sig") for phase in ("forward", "rollback"))
        old, new = left.read_bytes(), right.read_bytes()
        left.write_bytes(new)
        right.write_bytes(old)
        with self.assertRaisesRegex(ValueError, "Expected file length or digest differs|Changed pinned bytes"):
            self.audit()

    def test_manifest_pins_cannot_override_a_cryptographic_refusal(self):
        def refuse(_row, _home, _keyring):
            raise ValueError("ALARM detached signature refused")

        with patch.dict(A, verify_signature=refuse), self.assertRaisesRegex(ValueError, "detached signature refused"):
            self.audit()

    def test_symlinked_signature_refused_instead_of_treated_as_absent(self):
        path = self.root / (self.pairs["forward"]["perl"]["archive"] + ".sig")
        path.unlink()
        path.symlink_to(self.root / "missing")
        with self.assertRaisesRegex(ValueError, "Canonical ordinary absolute path"):
            self.audit()


if __name__ == "__main__":
    unittest.main()
