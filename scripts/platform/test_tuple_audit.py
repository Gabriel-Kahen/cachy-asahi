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

spec = importlib.util.spec_from_file_location("tuple_audit", Path(__file__).with_name("tuple_audit.py"))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def package(name, version="1-1", depends=(), provides=()):
    return {"NAME": [name], "VERSION": [version], "ARCH": ["aarch64"], "BASE": [name],
            "DEPENDS": list(depends), "PROVIDES": list(provides)}


def db_bytes(records, extra=None):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:") as archive:
        for record in records:
            data = "".join("%" + key + "%\n" + "\n".join(values) + "\n\n"
                           for key, values in record.items()).encode()
            member = tarfile.TarInfo(record["NAME"][0] + "-fixture/desc")
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        if extra is not None:
            archive.addfile(extra)
    return gzip.compress(stream.getvalue())


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self.tmp.name)
        self.published = [package(n) for n in audit.BOOT + audit.AUDIO]
        self.published[-2]["DEPENDS"] = ["bankstown>=1.1", "speakersafetyd"]
        self.published[-1]["DEPENDS"] = ["alsa-lib"]
        self.image = [copy.deepcopy(p) for p in self.published[:5]]
        self.image.append(package("asahi-meta", depends=audit.BOOT))
        self.repo = copy.deepcopy(self.published) + [package("bankstown", "1.1-2", depends=["lv2"])]

    def tearDown(self):
        self.tmp.cleanup()

    def inputs(self, mutator=None, repository=True):
        signed = {"repository_sha256": audit.digest(db_bytes(self.repo)), "packages": []}
        inspected = []
        mapping = {"NAME": "pkgname", "VERSION": "pkgver", "ARCH": "arch", "BASE": "pkgbase",
                   "DEPENDS": "depend", "PROVIDES": "provides", "CONFLICTS": "conflict", "REPLACES": "replaces"}
        for p in self.published:
            name = p["NAME"][0]
            text = "".join(mapping[k] + " = " + v + "\n" for k in mapping for v in p.get(k, []))
            archive_hash = hashlib.sha256(name.encode()).hexdigest()
            signed["packages"].append({"metadata": copy.deepcopy(p), "archive": {"sha256": archive_hash}})
            inspected.append({"name": name, "archive_sha256": archive_hash,
                              "selected_data": {".PKGINFO": {"text": text, "bytes": len(text.encode()),
                                                             "sha256": audit.digest(text.encode())}}})
        image = {"packages": [{"metadata": p} for p in self.image]}
        if mutator:
            mutator(image, signed, inspected)
        docs = {"image": json.dumps(image).encode(), "signed": json.dumps(signed).encode(),
                "metadata": json.dumps(inspected).encode()}
        if repository:
            docs["repository"] = db_bytes(self.repo)
        paths, hashes = {}, {}
        for key, data in docs.items():
            paths[key] = self.directory / key
            paths[key].write_bytes(data)
            hashes[key] = audit.digest(data)
        return paths, hashes

    def run_fixture(self, mutator=None, repository=True):
        paths, hashes = self.inputs(mutator, repository)
        return audit.run(paths["image"], paths["signed"], paths["metadata"],
                         paths.get("repository"), expected_hashes=hashes)

    def test_five_same_two_absent_and_unaccepted(self):
        report = self.run_fixture()
        self.assertEqual([p["relation"] for p in report["published_comparison"]], ["same"] * 5 + ["absent"] * 2)
        self.assertEqual(report["remaining_audio_requirements"], ["alsa-lib", "lv2"])
        self.assertEqual(report["repository_extension_candidates"], [{"name": "bankstown", "version": "1.1-2"}])
        for key in ("hardware_accepted", "installation_accepted", "dependency_transaction_accepted",
                    "image_authentication_accepted", "independent_owner_trust_accepted", "system_mutation"):
            self.assertIs(report[key], False)

    def test_without_repository_keeps_unresolved_direct_requirement(self):
        report = self.run_fixture(repository=False)
        self.assertEqual(report["remaining_audio_requirements"], ["alsa-lib", "bankstown>=1.1"])

    def test_different_version_reported_without_pretending_upgrade(self):
        self.image[0]["VERSION"] = ["0.9-1"]
        self.assertEqual(self.run_fixture()["published_comparison"][0]["relation"], "different")

    def test_missing_baseline_relation_and_multiple_providers(self):
        self.image += [package("consumer", depends=["virtual>=2", "missing"]),
                       package("one", provides=["virtual=2"]), package("two", provides=["virtual=3"])]
        report = self.run_fixture()
        self.assertEqual(report["baseline_missing_requirements"][0]["requires"], "missing")
        self.assertEqual(len(report["multiple_provider_relations"][0]["witnesses"]), 2)

    def test_versioned_and_unversioned_providers(self):
        inventory = audit.packages([package("old", provides=["virtual=1"]),
                                    package("bare", provides=["virtual"]),
                                    package("new", provides=["virtual=2"])] )
        versions = audit.Versions()
        self.assertEqual([w["package"] for w in audit.witnesses("virtual>=2", inventory, versions)], ["new"])
        self.assertEqual(len(audit.witnesses("virtual", inventory, versions)), 3)

    def test_alpm_epoch_and_package_release_relations(self):
        versions = audit.Versions()
        self.assertTrue(versions.satisfies("1:1-1", ">", "99-9"))
        self.assertFalse(versions.satisfies("2-1", ">=", "2-2"))
        self.assertTrue(versions.satisfies("2-2", "=", "2-2"))
        self.assertTrue(versions.satisfies("0:1-1", "<", "1:0"))

    def test_protected_graph_cycle_terminates_with_exact_versions(self):
        self.image += [package("grub", "2:2-3", depends=["asahi-meta"])]
        self.image[-2]["DEPENDS"].append("grub")
        graph = self.run_fixture()["proposed_installed_dependency_graph"]
        self.assertEqual(len(graph), 7)
        self.assertIn({"name": "grub", "version": "2:2-3"}, graph)

    def test_pkginfo_dependency_mismatch(self):
        def mutate(image, signed, inspection):
            signed["packages"][0]["metadata"]["DEPENDS"] = ["injected"]
        with self.assertRaisesRegex(ValueError, "PKGINFO/repository mismatch"):
            self.run_fixture(mutate)

    def test_pkginfo_architecture_mismatch(self):
        def mutate(image, signed, inspection):
            signed["packages"][0]["metadata"]["ARCH"] = ["any"]
        with self.assertRaisesRegex(ValueError, "PKGINFO/repository mismatch"):
            self.run_fixture(mutate)

    def test_pkginfo_checksum_mismatch(self):
        def mutate(image, signed, inspection):
            inspection[0]["selected_data"][".PKGINFO"]["text"] += "# altered\n"
        with self.assertRaisesRegex(ValueError, "PKGINFO content"):
            self.run_fixture(mutate)

    def test_archive_binding_mismatch(self):
        def mutate(image, signed, inspection):
            inspection[0]["archive_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "inspection/archive"):
            self.run_fixture(mutate)

    def test_duplicate_inspection_rejected(self):
        def mutate(image, signed, inspection):
            inspection[-1] = inspection[0]
        with self.assertRaisesRegex(ValueError, "duplicate inspection"):
            self.run_fixture(mutate)

    def test_repository_capture_binding(self):
        def mutate(image, signed, inspection):
            signed["repository_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "capture/repository checksum"):
            self.run_fixture(mutate)

    def test_repository_metadata_mismatch(self):
        self.repo[0]["VERSION"] = ["different"]
        with self.assertRaisesRegex(ValueError, "capture/repository metadata mismatch"):
            self.run_fixture()

    def test_inventory_duplicate_or_wrong_architecture(self):
        self.image.append(copy.deepcopy(self.image[0]))
        with self.assertRaisesRegex(ValueError, "duplicate package"):
            self.run_fixture()
        self.image.pop()
        self.image[0]["ARCH"] = ["x86_64"]
        with self.assertRaisesRegex(ValueError, "wrong architecture"):
            self.run_fixture()

    def test_input_checksum_and_symlink_rejected(self):
        paths, hashes = self.inputs()
        paths["image"].write_bytes(b"modified")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            audit.read_bound(paths["image"], hashes["image"])
        link = self.directory / "link"
        link.symlink_to(paths["signed"])
        with self.assertRaises(OSError):
            audit.read_bound(link, hashes["signed"])

    def test_input_and_decompression_limits(self):
        path = self.directory / "large"
        path.write_bytes(b"a" * 33)
        with patch.object(audit, "MAX_BYTES", 32):
            with self.assertRaisesRegex(ValueError, "size/checksum"):
                audit.read_bound(path, audit.digest(path.read_bytes()))
            with self.assertRaisesRegex(ValueError, "decoded size"):
                audit.repository(gzip.compress(b"a" * 100))

    def test_json_duplicates_and_nonfinite_values(self):
        for data in (b'{"a":1,"a":2}', b'{"a":NaN}'):
            with self.assertRaises(ValueError):
                audit.load_json(data)

    def test_malformed_relations_and_provisions(self):
        for relation in ("a >=2", "x>=", "$(command)"):
            with self.assertRaises(ValueError):
                audit.relation(relation)
        inventory = audit.packages([package("bad", provides=["virtual>=2"])])
        with self.assertRaisesRegex(ValueError, "provision operator"):
            audit.witnesses("virtual", inventory, audit.Versions())

    def test_missing_libalpm_refuses_without_fallback(self):
        with patch.object(audit.ctypes.util, "find_library", return_value=None):
            with self.assertRaisesRegex(ValueError, "preinstalled libalpm"):
                audit.Versions()

    def test_metadata_list_limit(self):
        record = package("oversized", depends=["a"] * 257)
        with self.assertRaisesRegex(ValueError, "metadata fields"):
            audit.packages([record])

    def test_repository_links_and_duplicate_records_rejected(self):
        link = tarfile.TarInfo("evil/desc")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        with self.assertRaisesRegex(ValueError, "unexpected repository"):
            audit.repository(db_bytes([], link))
        with self.assertRaisesRegex(ValueError, "duplicate package"):
            audit.repository(db_bytes([package("same"), package("same")]))

    def test_private_output_new_only(self):
        report = self.run_fixture()
        output = self.directory / "result.json"
        audit.write_private(output, report)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(output.read_text()), report)
        with self.assertRaises(FileExistsError):
            audit.write_private(output, {})
        self.assertEqual(json.loads(output.read_text()), report)

    def test_nonprivate_and_symlink_parent_rejected(self):
        exposed = self.directory / "exposed"
        exposed.mkdir(mode=0o755)
        with self.assertRaisesRegex(ValueError, "0700"):
            audit.write_private(exposed / "result", {})
        link = self.directory / "linked"
        link.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlinks"):
            audit.write_private(link / "result", {})
        self.assertFalse((self.directory / "result").exists())

    def test_failed_write_removes_only_new_report(self):
        output = self.directory / "new"
        with patch.object(audit.os, "fsync", side_effect=OSError("injected failure")):
            with self.assertRaises(OSError):
                audit.write_private(output, {})
        self.assertFalse(output.exists())

    def test_serialized_report_limit_before_creation(self):
        output = self.directory / "large-report"
        with patch.object(audit, "MAX_BYTES", 32):
            with self.assertRaisesRegex(ValueError, "serialized report size limit"):
                audit.write_private(output, {"large": "a" * 100})
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
