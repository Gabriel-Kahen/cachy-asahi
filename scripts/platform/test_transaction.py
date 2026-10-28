# SPDX-License-Identifier: MIT
import copy
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("platform_transaction", Path(__file__).with_name("transaction.py"))
transaction = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transaction)


def package(name, version="1-1", depends=(), provides=(), conflicts=()):
    return {"NAME": [name], "VERSION": [version], "ARCH": ["aarch64"],
            "DEPENDS": list(depends), "PROVIDES": list(provides), "CONFLICTS": list(conflicts),
            "FILENAME": [name + "-" + version + "-aarch64.pkg.tar.xz"],
            "CSIZE": ["100"], "ISIZE": ["100"], "SHA256SUM": ["a" * 64]}


def database(records, extra=None):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:") as archive:
        for record in records:
            body = "".join("%" + key + "%\n" + "\n".join(values) + "\n\n"
                           for key, values in record.items()).encode()
            entry = tarfile.TarInfo(record["NAME"][0] + "-" + record["VERSION"][0] + "/desc")
            entry.size = len(body)
            archive.addfile(entry, io.BytesIO(body))
        if extra:
            archive.addfile(extra)
    return gzip.compress(raw.getvalue())


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self.tmp.name)
        self.image = [package("python", "3.14.7-1"), package("platform", depends=["python"])]
        self.protected = copy.deepcopy(self.image)
        self.roots = [{"name": "desktop", "version": "1-1"}]
        self.providers = [{"name": "mesa", "version": "1:26.2-1"}]
        self.catalogs = {
            "core": [package("python", "3.14.8-1")],
            "extra": [package("desktop", depends=["mesa", "platform"]),
                      package("mesa", "1:26.2-1", provides=["opengl-driver"]),
                      package("vulkan-asahi", "1:26.2-1")],
            "asahi-alarm": [package(name) for name in transaction.ADDITIONAL if name != "vulkan-asahi"],
        }

    def tearDown(self):
        self.tmp.cleanup()

    def save(self, name, data):
        path = self.directory / name
        if isinstance(data, dict):
            data = json.dumps(data).encode()
        path.write_bytes(data)
        return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}

    def contract(self):
        image = self.save("image.json", {"packages": [{"metadata": p} for p in self.image]})
        tuple_ref = self.save("tuple.json", {"kind": "offline-platform-metadata-witnesses",
            "input_sha256": {"image": image["sha256"]},
            "proposed_installed_dependency_graph": [{"name": p["NAME"][0], "version": p["VERSION"][0]}
                                                    for p in self.protected]})
        proposal = self.save("proposal.json", {"roots": self.roots, "provider_constraints": self.providers})
        refs = [self.save(name + ".db", database(self.catalogs[name])) | {"name": name}
                for name in ("asahi-alarm", "core", "extra")]
        additional = [{"name": name, "version": "1:26.2-1" if name == "vulkan-asahi" else "1-1", "repo": repo}
                      for name, repo in transaction.ADDITIONAL.items()]
        return {"schema_version": 1, "image_inventory": image, "tuple_report": tuple_ref,
                "proposal": proposal, "repositories": refs, "additional_roots": additional}

    def execute(self, mutate=None):
        contract = self.contract()
        if mutate:
            mutate(contract)
        reference = self.save("contract.json", contract)
        output = self.directory / "report.json"
        return transaction.run(Path(reference["path"]), reference["sha256"], output)

    def test_real_prepare_adds_dependencies_without_commit(self):
        self.catalogs["extra"] += [package("dependency")]
        self.catalogs["extra"][0]["DEPENDS"].append("dependency")
        report = self.execute()
        self.assertEqual(report["status"], "PASS-private-metadata-prepare")
        self.assertEqual(report["transaction"]["prepare_exit"], 0)
        self.assertIn("dependency", [p["name"] for p in report["transaction"]["add"]])
        self.assertEqual(report["transaction"]["remove"], [])
        self.assertTrue(report["all_protected_versions_preserved"])
        self.assertFalse(report["commit_called"])
        self.assertFalse(report["dependency_transaction_accepted"])
        self.assertFalse(report["downloads_or_repository_updates"])
        self.assertEqual((self.directory / "report.json").stat().st_mode & 0o777, 0o600)

    def test_all_requested_targets_retained_when_python_policy_rejects(self):
        self.roots += [{"name": "python", "version": "3.14.8-1"}]
        report = self.execute()
        self.assertTrue(report["status"].startswith("FAIL"))
        target = next(p for p in report["targets"] if p["name"] == "python")
        self.assertEqual(target["version"], "3.14.8-1")
        self.assertEqual(target["final_version"], "3.14.7-1")
        self.assertFalse(target["satisfied"])
        self.assertEqual(report["transaction"]["errors"][0]["kind"], "protected-root-version-rejected")
        self.assertTrue(report["all_protected_versions_preserved"])

    def test_indirect_dependency_cannot_upgrade_protected_python(self):
        self.catalogs["extra"][0]["DEPENDS"].append("python>=3.14.8")
        report = self.execute()
        self.assertTrue(report["status"].startswith("FAIL"))
        self.assertEqual(report["transaction"]["prepare_errno"], 45)
        self.assertTrue(any(e["kind"] == "unsatisfied-dependency" for e in report["transaction"]["errors"]))
        self.assertTrue(report["all_protected_versions_preserved"])
        self.assertFalse(any(p["name"] == "python" for p in report["transaction"]["add"]))

    def test_new_conflict_cannot_remove_protected_platform(self):
        self.catalogs["extra"][0]["CONFLICTS"] = ["platform"]
        report = self.execute()
        self.assertTrue(report["status"].startswith("FAIL"))
        self.assertEqual(report["transaction"]["remove"], [])
        self.assertTrue(report["all_protected_versions_preserved"])
        self.assertTrue(any(q["type"] == 4 and q["answer"] == 0 for q in report["transaction"]["questions"]))

    def test_unprotected_explicit_upgrade_is_reported(self):
        self.image += [package("tool", "1-1")]
        self.roots += [{"name": "tool", "version": "2-1"}]
        self.catalogs["extra"] += [package("tool", "2-1")]
        report = self.execute()
        self.assertEqual(report["status"], "PASS-private-metadata-prepare")
        self.assertIn({"name": "tool", "version": "2-1", "repo": "extra", "old_version": "1-1", "change_kind": "change"},
                      report["transaction"]["add"])

    def test_mesa_dummy_filtered_even_if_it_provides_mesa(self):
        self.catalogs["asahi-alarm"] += [package("mesa-dummy", "99-1", provides=["mesa", "opengl-driver"])]
        report = self.execute()
        mesa = next(p for p in report["transaction"]["add"] if p["name"] == "mesa")
        self.assertEqual(mesa["repo"], "extra")
        self.assertFalse(any(p["name"] == "mesa-dummy" for p in report["transaction"]["add"]))

    def test_unselected_uppercase_community_entry_diagnosed_and_excluded(self):
        self.catalogs["asahi-alarm"] += [package("FEX-Emu", "2604-1")]
        report = self.execute()
        self.assertEqual(report["status"], "PASS-private-metadata-prepare")
        diagnostic = next(d for d in report["catalog_diagnostics"] if d.get("declared_name") == ["FEX-Emu"])
        self.assertFalse(diagnostic["selectable"])
        self.assertEqual(diagnostic["classification"], "unsupported-by-preview-metadata-grammar")
        self.assertFalse(any(p["name"] == "FEX-Emu" for p in report["transaction"]["add"]))

    def test_unsupported_required_community_entry_fails_whole_candidate(self):
        next(p for p in self.catalogs["asahi-alarm"] if p["NAME"] == ["asahi-audio"])["ARCH"] = ["x86_64"]
        report = self.execute()
        self.assertTrue(report["status"].startswith("FAIL"))
        target = next(t for t in report["targets"] if t["name"] == "asahi-audio")
        self.assertFalse(target["satisfied"])
        self.assertTrue(any(e["kind"] == "pinned-target-unavailable-in-filtered-catalog"
                            and e["target"]["name"] == "asahi-audio" for e in report["transaction"]["errors"]))
        self.assertTrue(any(d.get("declared_name") == ["asahi-audio"] and d.get("selectable") is False
                            for d in report["catalog_diagnostics"]))

    def test_unselected_extra_entry_over_field_bound_is_diagnosed(self):
        self.catalogs["extra"] += [package("texlive-fontsextra", provides=["font-" + str(i) for i in range(257)])]
        report = self.execute()
        self.assertEqual(report["status"], "PASS-private-metadata-prepare")
        diagnostic = next(d for d in report["catalog_diagnostics"] if d.get("name") == "texlive-fontsextra")
        self.assertFalse(diagnostic["selectable"])
        self.assertEqual(diagnostic["classification"], "unsupported-by-preview-metadata-grammar")
        self.assertFalse(any(p["name"] == "texlive-fontsextra" for p in report["transaction"]["add"]))

    def test_stale_root_pin_is_reported_not_updated(self):
        self.roots[0]["version"] = "0.9-1"
        report = self.execute()
        self.assertTrue(report["status"].startswith("FAIL"))
        self.assertTrue(any(e["kind"] == "pinned-target-unavailable-in-filtered-catalog"
                            for e in report["transaction"]["errors"]))
        self.assertEqual(report["targets"][0]["version"], "0.9-1")

    def test_stale_input_checksum_before_private_prepare(self):
        def mutate(contract):
            contract["image_inventory"]["sha256"] = "0" * 64
        with patch.object(transaction, "prepare") as prepared:
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                self.execute(mutate)
            prepared.assert_not_called()
        self.assertFalse((self.directory / "report.json").exists())

    def test_tuple_bound_to_correct_image(self):
        def mutate(contract):
            record = json.loads(Path(contract["tuple_report"]["path"]).read_text())
            record["input_sha256"]["image"] = "0" * 64
            contract["tuple_report"] = self.save("tuple.json", record)
        with self.assertRaisesRegex(ValueError, "tuple/image binding"):
            self.execute(mutate)

    def test_protected_tuple_version_mismatch_refused(self):
        self.protected[0]["VERSION"] = ["different"]
        with self.assertRaisesRegex(ValueError, "protected tuple/image version"):
            self.execute()

    def test_duplicate_target_refused(self):
        self.roots.append(copy.deepcopy(self.roots[0]))
        with self.assertRaisesRegex(ValueError, "duplicate target"):
            self.execute()

    def test_missing_asahi_root_refused(self):
        def mutate(contract):
            contract["additional_roots"].pop()
        with self.assertRaisesRegex(ValueError, "complete additional"):
            self.execute(mutate)

    def test_descriptor_path_and_field_injection_refused(self):
        for record in (package("bad", "../escape"), package("safe") | {"DESC": ["value\n%NAME%\nunsafe"]}):
            with self.assertRaises(ValueError):
                transaction.clean(record)

    def test_repository_archive_link_refused(self):
        link = tarfile.TarInfo("unsafe/desc")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        with self.assertRaisesRegex(ValueError, "unsafe repository member"):
            transaction.repository_records(database([], link))

    def test_sparse_metadata_not_extracted_or_reconstructed(self):
        sparse = tarfile.TarInfo("findnewest-0.3-4/desc")
        sparse.pax_headers = {"GNU.sparse.name": "findnewest-0.3-4/desc"}
        diagnostics = []
        original = tarfile.TarFile.extractfile
        def guarded(archive, member):
            self.assertFalse(any(k.startswith("GNU.sparse.") for k in member.pax_headers))
            return original(archive, member)
        with patch.object(tarfile.TarFile, "extractfile", guarded):
            records = transaction.repository_records(database([package("valid")], sparse), diagnostics, "extra")
        self.assertEqual(list(records), ["valid-1-1"])
        self.assertEqual(diagnostics[0]["entry"], "extra/findnewest-0.3-4")
        self.assertFalse(diagnostics[0]["selectable"])
        self.assertIn("never reconstructed", diagnostics[0]["reason"])

    def test_reused_database_parser_receives_only_regular_derived_metadata(self):
        original = transaction.preview.databases
        def inspect(directory, references, diagnostics):
            for reference in references:
                with tarfile.open(directory / (reference["name"] + ".db")) as archive:
                    for member in archive:
                        self.assertIsNone(member.sparse)
                        self.assertFalse(any(k.startswith("GNU.sparse.") for k in member.pax_headers))
            return original(directory, references, diagnostics)
        with patch.object(transaction.preview, "databases", side_effect=inspect) as checked:
            report = self.execute()
        self.assertEqual(checked.call_count, 2)
        self.assertEqual(report["status"], "PASS-private-metadata-prepare")

    def test_decode_limit_and_input_size_limit(self):
        with patch.object(transaction, "DECODED_LIMIT", 32):
            with self.assertRaisesRegex(ValueError, "decode bound"):
                transaction.repository_records(gzip.compress(b"a" * 100))
        reference = self.save("too-large", b"a" * 33)
        with patch.object(transaction, "LIMIT", 32):
            with self.assertRaisesRegex(ValueError, "input size"):
                transaction.bound(reference)

    def test_no_commit_update_download_or_system_upgrade_symbols(self):
        forbidden = {"alpm_trans_commit", "alpm_db_update", "alpm_fetch_pkgurl", "alpm_sync_sysupgrade",
                     "alpm_remove_pkg", "alpm_pkg_load", "alpm_db_add_server"}
        self.assertFalse(forbidden & set(transaction.Alpm.SYMBOLS))
        self.assertTrue({"alpm_trans_prepare", "alpm_trans_init"} <= set(transaction.Alpm.SYMBOLS))

    def file_reference(self, contract, bad=None):
        entries = []
        for p in self.image:
            name = p["NAME"][0]
            text = "" if name == "platform" else "%FILES%\nusr/\nusr/bin/\nusr/bin/python\n\n"
            entries.append({"name": name, "directory": name + "-" + p["VERSION"][0],
                            "text": text, "bytes": len(text.encode()), "sha256": hashlib.sha256(text.encode()).hexdigest(),
                            "fields": transaction.tuple_audit.parse_desc(text), "empty_filelist": not text})
        document = {"schema_version": 1, "kind": "observed-image-local-file-ownership-metadata",
                    "inventory_sha256": contract["image_inventory"]["sha256"], "physical_target": False,
                    "installed_payload_verified": False, "packages": entries}
        if bad:
            bad(document)
        contract["local_files"] = self.save("files.json", document)

    def test_raw_local_files_and_legitimate_empty_metapackage_loaded(self):
        original = transaction.prepare
        def inspect(work, image, protected, catalogs, targets):
            self.assertEqual((work / "db/local/platform-1-1/files").read_bytes(), b"")
            self.assertIn(b"usr/bin/python", (work / "db/local/python-3.14.7-1/files").read_bytes())
            return original(work, image, protected, catalogs, targets)
        with patch.object(transaction, "prepare", side_effect=inspect):
            report = self.execute(self.file_reference)
        self.assertTrue(report["image_local_file_metadata_loaded"])
        self.assertEqual(report["image_local_file_metadata_package_count"], 2)
        self.assertFalse(report["file_conflicts_checked"])
        self.assertEqual(len(report["proposed_final_inventory"]), report["proposed_final_count"])

    def test_missing_file_descriptor_rejected_instead_of_empty_fallback(self):
        def mutate(contract):
            self.file_reference(contract, lambda d: d["packages"].pop())
        with self.assertRaisesRegex(ValueError, "complete image local file metadata"):
            self.execute(mutate)

    def test_file_metadata_checksum_and_image_binding(self):
        for edit, diagnostic in ((lambda d: d["packages"][0].update(sha256="0" * 64), "checksum/size"),
                                 (lambda d: d.update(inventory_sha256="0" * 64), "inventory binding")):
            with self.assertRaisesRegex(ValueError, diagnostic):
                self.execute(lambda c: self.file_reference(c, edit))

    def test_file_metadata_traversal_rejected(self):
        def edit(document):
            entry = document["packages"][0]
            text = "%FILES%\n../outside\n\n"
            entry.update(text=text, bytes=len(text.encode()), sha256=hashlib.sha256(text.encode()).hexdigest(),
                         fields={"FILES": ["../outside"]})
        with self.assertRaisesRegex(ValueError, "unsafe image file metadata path"):
            self.execute(lambda c: self.file_reference(c, edit))

    def test_unapproved_ambiguous_provider_is_whole_failure(self):
        self.catalogs["extra"][0]["DEPENDS"].append("virtual")
        self.catalogs["extra"] += [package("one", provides=["virtual"]), package("two", provides=["virtual"])]
        report = self.execute()
        self.assertTrue(report["status"].startswith("FAIL"))
        self.assertTrue(any(q["type"] == 32 and q["policy"].startswith("unapproved")
                            for q in report["transaction"]["questions"]))


if __name__ == "__main__":
    unittest.main()
