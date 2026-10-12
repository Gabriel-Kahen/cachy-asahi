# SPDX-License-Identifier: MIT
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("coordinated_python", Path(__file__).with_name("coordinated_python.py"))
proposal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proposal)


def metadata(name, version="1-1", depends=(), provides=()):
    return {"NAME": [name], "VERSION": [version], "ARCH": ["aarch64"], "DEPENDS": list(depends),
            "PROVIDES": list(provides), "LICENSE": ["MIT"],
            "FILENAME": [name + "-" + version + "-aarch64.pkg.tar.xz"], "SHA256SUM": ["a" * 64], "CSIZE": ["100"], "ISIZE": ["100"]}


class CoordinatedPythonTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.enterContext(patch.object(proposal, "CERTIFICATE_SHA256", hashlib.sha256(b"retained public certificate fixture").hexdigest()))
        self.count = 0
        self.old = metadata("python", "3.14.7-1", ["platform-lib"], ["python3"])
        self.new = metadata("python", "3.14.8-1", ["platform-lib"], ["python3"])
        self.image = [self.old, metadata("asahi-fwextract", depends=["python"]), metadata("platform-lib")]
        self.image += [metadata("protected-" + str(i)) for i in range(198)]
        self.protected = copy.deepcopy(self.image)
        self.image += [metadata("baseline-" + str(i)) for i in range(60)]
        self.roots = [{"name": "python", "version": "3.14.8-1"}, {"name": "hyprland", "version": "1-1"}]
        self.roots += [{"name": "target-" + str(i), "version": "1-1"} for i in range(43)]
        self.providers = [{"name": name, "version": "1-1"} for name in ("mesa", "pipewire-jack", "dbus-broker-units", "perl")]
        self.targets = [r | {"repo": "core" if r["name"] in {"python", "dbus-broker-units", "perl"} else "extra",
                             "origin": "unchanged-generic-proposal"} for r in self.roots + self.providers]
        self.targets += [{"name": name, "version": "1-1", "repo": repo, "origin": "explicit-Asahi-addition"}
                         for name, repo in proposal.transaction.ADDITIONAL.items()]
        self.catalogs = {name: {} for name in ("asahi-alarm", "core", "extra")}
        for target in self.targets:
            self.catalogs[target["repo"]][target["name"]] = self.new if target["name"] == "python" else metadata(target["name"])
        self.catalogs["core"]["platform-lib"] = metadata("platform-lib", "2-1")

    def save(self, name, data):
        self.count += 1
        path = self.root / (str(self.count) + "-" + name)
        if isinstance(data, dict):
            data = json.dumps(data).encode()
        path.write_bytes(data)
        return {"path": str(path), "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    def source_hashes(self):
        return {name: proposal.preview.digest(module.__file__) for name, module in (
            ("transaction.py", proposal.transaction), ("tuple_audit.py", proposal.audit), ("preview.py", proposal.preview))}

    def contract(self):
        text = "pkgname = python\npkgver = 3.14.8-1\narch = aarch64\ndepend = platform-lib\nprovides = python3\nlicense = MIT\n"
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:xz") as archive:
            member = tarfile.TarInfo(".PKGINFO");member.size = len(text.encode());archive.addfile(member, io.BytesIO(text.encode()))
            member = tarfile.TarInfo("usr/bin/python");member.size = 7;archive.addfile(member, io.BytesIO(b"fixture"))
        archive_ref = self.save("python.pkg.tar.xz", stream.getvalue())
        signature = self.save("python.sig", b"retained signature fixture; not real crypto")
        certificate = self.save("certificate", b"retained public certificate fixture")
        self.new["SHA256SUM"], self.new["CSIZE"] = [archive_ref["sha256"]], [str(archive_ref["size"])]
        image_ref = self.save("image.json", {"packages": [{"metadata": p} for p in self.image]})
        tuple_ref = self.save("tuple.json", {"input_sha256": {"image": image_ref["sha256"]},
                              "proposed_installed_dependency_graph": [{"name": p["NAME"][0], "version": p["VERSION"][0]} for p in self.protected]})
        source_proposal = self.save("proposal.json", {"roots": self.roots, "provider_constraints": self.providers})
        repositories = []
        for repo, records in self.catalogs.items():
            path = self.root / (repo + ".db")
            proposal.transaction.write_catalog(path, records)
            reference = {"path": str(path), "size": path.stat().st_size, "sha256": proposal.preview.digest(path), "name": repo}
            repositories.append(reference)
        strict = {"schema_version": 1, "image_inventory": image_ref, "tuple_report": tuple_ref, "proposal": source_proposal,
                  "repositories": repositories, "additional_roots": [{k: t[k] for k in ("name", "version", "repo")}
                                                                     for t in self.targets if t["origin"] == "explicit-Asahi-addition"]}
        strict_ref = self.save("strict.json", strict)
        strict_final = {p["NAME"][0]: p for p in self.image}
        for repo, records in self.catalogs.items():
            for name, record in records.items():
                if name not in {p["NAME"][0] for p in self.protected}:
                    strict_final[name] = record | {"repo": repo}
        previous = {"schema_version": 1, "kind": "private-Asahi-metadata-transaction-prepare",
                    "status": "FAIL-incomplete-or-policy-rejected", "input_references": strict,
                    "contract_sha256": strict_ref["sha256"], "source_sha256": self.source_hashes(),
                    "dependency_transaction_accepted": False, "commit_called": False, "all_protected_versions_preserved": True,
                    "transaction": {"errors": [{"kind": "protected-root-version-rejected", "target": {"name": "python", "version": "3.14.8-1"}, "protected_version": "3.14.7-1"}]},
                    "protected_preservation": [{"name": p["NAME"][0], "expected": p["VERSION"][0], "final": p["VERSION"][0], "preserved": True} for p in self.protected],
                    "targets": self.targets, "proposed_final_inventory": [{"name": n, "version": p["VERSION"][0], "repo": p.get("repo", "installed"), "metadata": p}
                                                                          for n, p in strict_final.items()]}
        previous_ref = self.save("strict-transaction.json", previous)
        frozen_files = {"scripts/platform/transaction.py": proposal.preview.digest(proposal.transaction.__file__)}
        prior = self.save("prior-checkpoint.json", {"files": frozen_files})
        checkpoint = self.save("checkpoint.json", {"schema_version": 1, "status": "frozen-data-only-transaction-followup",
                            "dependency_transaction_accepted": False, "files": frozen_files,
                            "private_evidence": [{"path": r["path"], "bytes": r["size"], "sha256": r["sha256"]} for r in (strict_ref, previous_ref)],
                            "prior_checkpoint_reference": {"path": prior["path"], "bytes": prior["size"], "sha256": prior["sha256"]}})
        core = next(r for r in repositories if r["name"] == "core")
        receipt = {"schema_version": 1, "status": "signed-coordinated-python-candidate-data", "metadata": self.new,
                   "archive": archive_ref, "signature": signature, "public_certificate": certificate,
                   "source_db": {k: core[k] for k in ("path", "size", "sha256")},
                   "signature_verification": {"status": "cryptographic-signature-valid", "primary_fingerprint": proposal.SIGNER,
                                              "independent_owner_trust_accepted": False},
                   "pkginfo": {"text": text, "bytes": len(text.encode()), "sha256": hashlib.sha256(text.encode()).hexdigest()}}
        return {"schema_version": 1, "proposal_kind": "unadopted-coordinated-python-change", "change": proposal.CHANGE,
                "strict_contract": strict_ref, "strict_transaction": previous_ref, "strict_checkpoint": checkpoint,
                "python_receipt": self.save("python-receipt.json", receipt), "python_archive": archive_ref, "python_signature": signature}

    def execute(self, mutate=None):
        contract = self.contract()
        if mutate:
            mutate(contract)
        ref = self.save("contract.json", contract)
        return proposal.run(Path(ref["path"]), ref["sha256"], self.root / "output.json")

    def mutate_receipt(self, contract, mutate):
        receipt = json.loads(Path(contract["python_receipt"]["path"]).read_text())
        mutate(receipt)
        contract["python_receipt"] = self.save("changed-receipt.json", receipt)

    def rebind_strict_transaction(self, contract, previous):
        old = contract["strict_transaction"]
        new = self.save("changed-strict.json", previous)
        checkpoint = json.loads(Path(contract["strict_checkpoint"]["path"]).read_text())
        checkpoint["private_evidence"] = [({"path": new["path"], "bytes": new["size"], "sha256": new["sha256"]}
                                           if row["sha256"] == old["sha256"] else row) for row in checkpoint["private_evidence"]]
        contract["strict_transaction"] = new
        contract["strict_checkpoint"] = self.save("rebound-checkpoint.json", checkpoint)

    def attach_history(self, contract):
        self.enterContext(patch.object(proposal, "ROOT", self.root))
        current = self.root / "scripts/platform"
        current.mkdir(parents=True, exist_ok=True)
        (current / "transaction.py").write_bytes(Path(proposal.transaction.__file__).read_bytes())
        (current / "ownership.py").write_bytes(b"corrected ownership fixture\n")
        retained = self.save("historical-ownership.py", b"original ownership fixture\n")
        name = "scripts/platform/ownership.py"
        checkpoint = json.loads(Path(contract["strict_checkpoint"]["path"]).read_text())
        checkpoint["files"][name] = retained["sha256"]
        contract["strict_checkpoint"] = self.save("history-checkpoint.json", checkpoint)
        contract["strict_source_snapshots"] = {name: retained}
        return name

    def test_corrected_current_source_uses_authentic_retained_history(self):
        result = self.execute(self.attach_history)
        self.assertEqual(result["status"], "PASS-private-metadata-prepare")
        validation = result["strict_source_validation"]
        self.assertFalse(validation["snapshot_sources_executed"])
        source = validation["historical_checkpoint_sources"]["scripts/platform/ownership.py"]
        self.assertEqual(source["validated_history_source"], "retained-snapshot")
        self.assertNotEqual(source["current_sha256"], source["original_sha256"])
        self.assertEqual(source["snapshot_reference"]["sha256"], source["original_sha256"])

    def test_corrected_current_without_snapshot_still_refused(self):
        def edit(contract):
            self.attach_history(contract)
            del contract["strict_source_snapshots"]
        with self.assertRaisesRegex(ValueError, "strict source checkpoint drift"):
            self.execute(edit)

    def test_retained_source_wrong_original_pin_refused(self):
        def edit(contract):
            name = self.attach_history(contract)
            contract["strict_source_snapshots"][name] = self.save("wrong-original.py", b"different historical bytes")
        with self.assertRaisesRegex(ValueError, "snapshot original pin mismatch"):
            self.execute(edit)

    def test_retained_source_tamper_unknown_name_and_bounds_refused(self):
        for case in ("tamper", "unknown", "oversized"):
            def edit(contract):
                name = self.attach_history(contract)
                ref = contract["strict_source_snapshots"][name]
                if case == "tamper":
                    Path(ref["path"]).write_bytes(b"changed after receipt")
                elif case == "unknown":
                    contract["strict_source_snapshots"]["outside-original-checkpoint.py"] = ref
                else:
                    ref["size"] = 1024**2 + 1
            message = {"tamper": "binary size/checksum", "unknown": "unknown strict source snapshot", "oversized": "binary size bound"}[case]
            with self.subTest(case=case), self.assertRaisesRegex(ValueError, message):
                self.execute(edit)
            for path in self.root.glob("*.db"):
                path.unlink()

    def test_retained_history_does_not_relax_original77_source_checks(self):
        def edit(contract):
            self.attach_history(contract)
            checkpoint = json.loads(Path(contract["strict_checkpoint"]["path"]).read_text())
            prior = self.save("changed-prior.json", {"files": {"scripts/platform/transaction.py": "0" * 64}})
            checkpoint["prior_checkpoint_reference"] = {"path": prior["path"], "bytes": prior["size"], "sha256": prior["sha256"]}
            contract["strict_checkpoint"] = self.save("changed-history-checkpoint.json", checkpoint)
        with self.assertRaisesRegex(ValueError, "prior source checkpoint drift"):
            self.execute(edit)

    def test_retained_history_does_not_relax_protected_preservation(self):
        def edit(contract):
            self.attach_history(contract)
            previous = json.loads(Path(contract["strict_transaction"]["path"]).read_text())
            previous["protected_preservation"][0]["final"] = "3.14.8-1"
            self.rebind_strict_transaction(contract, previous)
        with self.assertRaisesRegex(ValueError, "strict per-package preservation"):
            self.execute(edit)

    def test_real_full_55_target_prepare_and_only_python_change(self):
        r = self.execute()
        self.assertEqual(r["status"], "PASS-private-metadata-prepare")
        self.assertEqual(len(r["targets"]), 55)
        self.assertTrue(r["all_targets_satisfied"])
        self.assertTrue(r["all_protected_versions_preserved"])
        self.assertEqual(r["ignorepkg_policy"]["count"], 200)
        self.assertEqual(r["strict_to_proposal_version_deltas"], [{"name": "python", "strict_version": "3.14.7-1", "proposal_version": "3.14.8-1"}])
        self.assertFalse(r["adopted"])
        self.assertFalse(r["dependency_transaction_accepted"])
        self.assertFalse(r["hardware_accepted"])
        self.assertFalse(r["fresh_signature_verification"])
        self.assertFalse(r["scoped_change_graph"]["original_pkginfo_available"])
        self.assertFalse(r["scoped_change_graph"]["original_pkginfo_supplied_to_contract"])
        self.assertIn("not supplied to this contract", r["scoped_change_graph"]["original_fields_source"])
        self.assertEqual(r["scoped_change_graph"]["direct_original_consumers"][0]["package"], "asahi-fwextract")

    def test_indirect_other_protected_update_fails(self):
        self.catalogs["extra"]["hyprland"]["DEPENDS"] = ["platform-lib>=2"]
        r = self.execute()
        self.assertEqual(r["status"], "FAIL-incomplete-or-policy-rejected")
        self.assertTrue(r["all_protected_versions_preserved"])
        self.assertFalse(any(p["name"] == "platform-lib" for p in r["transaction"]["add"]))

    def test_reverse_consumer_graph_includes_transitive_meta_edge(self):
        self.image[3]["DEPENDS"] = ["asahi-fwextract"]
        self.protected[3]["DEPENDS"] = ["asahi-fwextract"]
        report = self.execute()
        edges = report["scoped_change_graph"]["all_original_consumer_edges"]
        self.assertEqual({(e["package"], e["requires"]) for e in edges},
                         {("asahi-fwextract", "python"), ("protected-0", "asahi-fwextract")})

    def test_other_protected_explicit_target_cannot_bypass_ignorepkg(self):
        self.roots[-1] = {"name": "platform-lib", "version": "2-1"}
        self.targets[44] = self.roots[-1] | {"repo": "core", "origin": "unchanged-generic-proposal"}
        r = self.execute()
        self.assertTrue(r["status"].startswith("FAIL"))
        self.assertTrue(any(e["kind"] == "protected-root-version-rejected" and e["target"]["name"] == "platform-lib" for e in r["transaction"]["errors"]))

    def test_removed_target_not_silently_accepted(self):
        def edit(contract):
            previous = json.loads(Path(contract["strict_transaction"]["path"]).read_text());previous["targets"].pop()
            self.rebind_strict_transaction(contract, previous)
        with self.assertRaisesRegex(ValueError, "all 55 strict targets"):
            self.execute(edit)

    def test_signature_failure_gates_before_prepare(self):
        def edit(contract):
            self.mutate_receipt(contract, lambda r: r["signature_verification"].update(status="failed"))
        with patch.object(proposal.transaction, "prepare") as prepared:
            with self.assertRaisesRegex(ValueError, "signature observation/signer"):
                self.execute(edit)
            prepared.assert_not_called()

    def test_wrong_signer_and_claimed_owner_trust_refused(self):
        for field, value in (("primary_fingerprint", "F" * 40), ("independent_owner_trust_accepted", True)):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "signature observation/signer"):
                self.execute(lambda c: self.mutate_receipt(c, lambda r: r["signature_verification"].update({field: value})))
            for path in self.root.glob("*.db"):
                path.unlink()

    def test_archive_signature_and_receipt_pkginfo_bindings(self):
        def edit(contract):
            self.mutate_receipt(contract, lambda r: r["pkginfo"].update(sha256="0" * 64))
        with self.assertRaisesRegex(ValueError, "actual PKGINFO mismatch"):
            self.execute(edit)

    def test_signature_bytes_rehashed_before_prepare(self):
        def edit(contract):
            Path(contract["python_signature"]["path"]).write_bytes(b"tampered")
        with patch.object(proposal.transaction, "prepare") as prepared:
            with self.assertRaisesRegex(ValueError, "binary size/checksum"):
                self.execute(edit)
            prepared.assert_not_called()

    def test_old_python_refusal_and_helper_source_binding_required(self):
        def edit(contract):
            previous = json.loads(Path(contract["strict_transaction"]["path"]).read_text());previous["source_sha256"]["transaction.py"] = "0" * 64
            self.rebind_strict_transaction(contract, previous)
        with self.assertRaisesRegex(ValueError, "helper provenance drift"):
            self.execute(edit)

    def test_current_core_receipt_metadata_binding(self):
        with self.assertRaisesRegex(ValueError, "receipt/current core metadata mismatch"):
            self.execute(lambda c: self.mutate_receipt(c, lambda r: r["metadata"].update(PROVIDES=["unexpected"])))

    def test_contract_disallows_additional_scoped_change(self):
        with self.assertRaisesRegex(ValueError, "single unadopted"):
            self.execute(lambda c: c.update(change={"name": "platform-lib", "from": "1-1", "to": "2-1"}))

    def test_ignorepkg_registration_failure_never_produces_report(self):
        original = proposal.transaction.Alpm
        class Refused(original):
            def __init__(self):
                super().__init__()
                self.alpm_option_add_ignorepkg = lambda handle, name: -1
        with patch.object(proposal.transaction, "Alpm", Refused):
            with self.assertRaisesRegex(ValueError, "IgnorePkg registration failed"):
                self.execute()
        self.assertFalse((self.root / "output.json").exists())

    def test_checkpoint_must_pair_to_exact_strict_refusal_receipt(self):
        def edit(contract):
            checkpoint = json.loads(Path(contract["strict_checkpoint"]["path"]).read_text())
            checkpoint["private_evidence"][1]["sha256"] = "0" * 64
            contract["strict_checkpoint"] = self.save("unpaired-checkpoint.json", checkpoint)
        with self.assertRaisesRegex(ValueError, "checkpoint/evidence pairing"):
            self.execute(edit)

    def test_different_certificate_consistent_hash_still_refused(self):
        def edit(contract):
            self.mutate_receipt(contract, lambda r: r.update(public_certificate=self.save("other-certificate", b"other key")))
        with patch.object(proposal.transaction, "prepare") as prepared:
            with self.assertRaisesRegex(ValueError, "certificate source pin"):
                self.execute(edit)
            prepared.assert_not_called()

    def test_bool_contract_schema_refused(self):
        with self.assertRaisesRegex(ValueError, "single unadopted"):
            self.execute(lambda c: c.update(schema_version=True))

    def test_bool_receipt_schema_refused(self):
        with self.assertRaisesRegex(ValueError, "receipt scope"):
            self.execute(lambda c: self.mutate_receipt(c, lambda r: r.update(schema_version=True)))


if __name__ == "__main__":
    unittest.main()
