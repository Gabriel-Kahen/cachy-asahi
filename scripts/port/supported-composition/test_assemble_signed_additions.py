#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Contract substitution and staged readback controls for signed addition DATA."""

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("signed_additions", Path(__file__).with_name("assemble_signed_additions.py"))
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


class SignedAdditionTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.path = Path(scratch.name)
        self.name = "project-package"
        self.pin = "a" * 64
        self.fingerprint = "F" * 40
        self.original, original_archive = self.report("1-1", b"original body")
        self.selected, self.archive = self.report("2-1", b"selected body")
        self.signature = self.ref(Path(self.archive["path"]).name + ".sig", b"detached signature")
        self.key = self.ref("scope.gpg", b"synthetic public certificate")
        self.contract = {
            "kind": a.KIND, "schema_version": 1, "byte_limit": 4096,
            "original": self.ref("original.json", self.original),
            "composition": self.ref("selected.json", self.selected),
            "alternatives": [{
                "name": self.name, "before": a.artifact(self.original["proposed_final_inventory"][0]),
                "after": a.artifact(self.selected["proposed_final_inventory"][0]),
                "evidence": self.ref("custody.json", {"source": "fixture"})}],
            "keys": [dict(id=self.name, role="project-test", fingerprint=self.fingerprint, certificate=self.key)],
            "operands": [dict(self.selected["prepare"]["add"][0], key=self.name, archive=self.archive, signature=self.signature)],
        }

    def ref(self, name, data):
        if isinstance(data, dict):
            data = json.dumps(data).encode()
        path = self.path / name
        path.write_bytes(data)
        return {"path": str(path), "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    def report(self, version, body):
        archive = self.ref(f"{self.name}-{version}-any.pkg.tar.xz", body)
        package = dict(name=self.name, repo="project", version=version)
        md = dict(NAME=[self.name], VERSION=[version], ARCH=["any"], DEPENDS=["sh"], LICENSE=["MIT"],
                  FILENAME=[Path(archive["path"]).name], CSIZE=[str(archive["size"])], SHA256SUM=[archive["sha256"]])
        report = dict.fromkeys(a.POLICY_FIELDS, [])
        report.update(kind=a.REPORT, schema_version=1, private_database_removed=True, status="FAIL",
                      metadata_prepare_status="FAIL", final_package_count=1, added_package_count=1,
                      blockers=[{"code": "fixture-original-policy-hold"}], installation="NOT RUN",
                      native_build="NOT RUN", hardware="NOT RUN", transaction_accepted=False,
                      full_supported_system_accepted=False, system_mutation=False, payload_execution=False,
                      network_used=False, proposed_final_inventory=[dict(package, metadata=md)],
                      prepare={"add": [package], "remove": [], "prepare_exit": 0, "prepare_errno": 0, "callback_errors": []})
        return report, archive

    def test_exact_alternative_preserves_proposal_failure(self):
        selected, _, operands, keys, size = a.contract_inputs(self.contract)
        self.assertEqual(selected["status"], "FAIL")
        self.assertEqual(selected["blockers"], self.original["blockers"])
        self.assertEqual(set(operands), {self.name})
        self.assertEqual(keys[self.name]["role"], "project-test")
        self.assertEqual(size, self.archive["size"] + self.signature["size"])

    def test_original_only_and_normal_hold(self):
        self.selected.update(status="HOLD", metadata_prepare_status="PASS")
        report = self.ref("hold.json", self.selected)
        self.contract.update(original=report, composition=report, alternatives=[])
        self.assertEqual(a.contract_inputs(self.contract)[0]["status"], "HOLD")

    def test_undeclared_archive_substitution_refused(self):
        self.contract["alternatives"] = []
        with self.assertRaisesRegex(ValueError, "undeclared"):
            a.contract_inputs(self.contract)

    def test_alternate_evidence_and_archive_identity_are_pinned(self):
        self.contract["alternatives"][0]["after"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "alternate archive pin"):
            a.contract_inputs(self.contract)
        self.contract["alternatives"][0]["after"]["sha256"] = self.archive["sha256"]
        evidence = Path(self.contract["alternatives"][0]["evidence"]["path"])
        evidence.write_bytes(evidence.read_bytes().replace(b"fixture", b"changed"))
        with self.assertRaisesRegex(ValueError, "file digest mismatch"):
            a.contract_inputs(self.contract)

    def test_semantic_dependency_change_refused_even_with_alternate(self):
        self.selected["proposed_final_inventory"][0]["metadata"]["DEPENDS"] = ["different"]
        self.contract["composition"] = self.ref("replaced.json", self.selected)
        with self.assertRaisesRegex(ValueError, "changed dependency"):
            a.contract_inputs(self.contract)

    def test_missing_operand_and_wrong_signer_role_refused(self):
        row = self.contract["operands"].pop()
        with self.assertRaisesRegex(ValueError, "requires one signed pair"):
            a.contract_inputs(self.contract)
        self.contract["operands"].append(row)
        self.contract["keys"][0]["role"] = "vendor"
        with self.assertRaisesRegex(ValueError, "TEST certificate scope"):
            a.contract_inputs(self.contract)

    def test_fail_while_copying_emits_no_success_receipt(self):
        destination = self.path / "staged"
        inputs = a.contract_inputs(self.contract)
        Path(self.signature["path"]).write_bytes(b"replaced signature")
        with patch.object(a, "public_ring"), self.assertRaisesRegex(ValueError, "file digest mismatch"):
            a.assemble(self.contract, self.pin, destination, *inputs)
        self.assertFalse((destination / "receipt.json").exists())

    def test_readback_rejects_extra_leaves_and_same_size_substitution(self):
        destination = self.path / "staged"
        selected, inventory, operands, keys, total = a.contract_inputs(self.contract)
        observed = dict(status="cryptographic-signature-valid", primary_fingerprint=self.fingerprint,
                        independent_owner_trust_accepted=False, fresh_verification=True, pkginfo_sha256=self.pin)
        with patch.object(a, "verify_pair", return_value=observed), patch.object(a, "public_ring"):
            a.assemble(self.contract, self.pin, destination, selected, inventory, operands, keys, total)
        receipt_digest = a.auth.hash_file(destination / "receipt.json")

        def reread(pin=receipt_digest):
            return a.readback(self.contract, self.pin, destination, selected, operands, keys, total, pin)

        self.assertEqual(reread()["operand_count"], 1)
        with self.assertRaisesRegex(ValueError, "JSON digest mismatch"):
            reread("0" * 64)
        sig = destination / "cache" / Path(self.signature["path"]).name
        extra = sig.with_name("unexpected")
        extra.touch()
        with self.assertRaisesRegex(ValueError, "leaf set mismatch"):
            reread()
        extra.unlink()
        sig.chmod(0o600)
        sig.write_bytes(b"replaced signature")
        sig.chmod(0o444)
        with self.assertRaisesRegex(ValueError, "file digest mismatch"):
            reread()


if __name__ == "__main__":
    unittest.main()
