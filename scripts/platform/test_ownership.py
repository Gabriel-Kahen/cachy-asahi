import gzip
import contextlib
import hashlib
import importlib.util
import io
import json
import lzma
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import ownership as audit


def metadata(name="alpha", version="1-1"):
    return {"NAME": [name], "VERSION": [version], "ARCH": ["aarch64"],
            "FILENAME": [name + "-" + version + "-aarch64.pkg.tar.xz"], "SHA256SUM": ["a" * 64]}


def descriptor(values):
    return "".join("%" + key + "%\n" + "\n".join(value) + "\n\n" for key, value in values.items()).encode()


def archive(records):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:", format=tarfile.USTAR_FORMAT) as tar:
        for name, data, kind in records:
            member = tarfile.TarInfo(name); member.type = kind; member.size = len(data)
            tar.addfile(member, io.BytesIO(data))
    return gzip.compress(out.getvalue(), mtime=0)


class OwnershipTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.count = 0

    def reference(self, data):
        self.count += 1; path = self.root / str(self.count); path.write_bytes(data)
        return {"path": str(path), "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    def json(self, obj):
        return self.reference(json.dumps(obj).encode())

    def fixture(self, filepaths=None, empty=False):
        meta = metadata(); image = self.json({"packages": [{"metadata": meta}]})
        text = b"" if empty else descriptor({"FILES": ["usr/", "usr/bin/", "usr/bin/old"]})
        files = {"inventory_sha256": image["sha256"], "packages": [{"name": "alpha", "version": "1-1",
                 "text": text.decode(), "fields": {} if empty else audit.fields(text), "bytes": len(text),
                 "sha256": hashlib.sha256(text).hexdigest(), "empty_filelist": empty}]}
        repo = {"name": "core", "db": self.reference(archive([("alpha-1-1/desc", descriptor(meta), tarfile.REGTYPE)])),
                "files": self.reference(archive([("alpha-1-1/desc", descriptor(meta), tarfile.REGTYPE),
                          ("alpha-1-1/files", descriptor({"FILES": filepaths or ["usr/", "usr/bin/", "usr/bin/new"]}), tarfile.REGTYPE)]))}
        final = {"packages": [{"name": "alpha", "version": "1-1", "repo": "core", "metadata": meta}],
                 "transaction_status": "PASS-private-metadata-prepare", "dependency_transaction_accepted": False}
        return {"schema_version": 1, "image_files": self.json(files), "image_inventory": image,
                "repositories": [repo], "final_inventory": self.json(final)}, final

    def test_paired_snapshot_and_relinquished_file(self):
        contract, _ = self.fixture(); result = audit.run(contract)
        self.assertTrue(result["ownership_findings_complete"])
        self.assertEqual(result["selected_packages"][0]["declared_paths"], ["usr/", "usr/bin/", "usr/bin/new"])
        self.assertEqual(result["removed_or_relinquished_owners"][0]["relinquished_paths"], [{"path": "usr/bin/old", "final_declared_owners": []}])
        self.assertFalse(result["filesystem_collisions_verified"])
        self.assertEqual(result["source_sha256"]["ownership.py"], hashlib.sha256(Path(audit.__file__).read_bytes()).hexdigest())

    def test_zero_byte_image_metapackage(self):
        contract, _ = self.fixture(empty=True)
        self.assertEqual(audit.run(contract)["initial_package_count"], 1)

    def test_zero_byte_repository_metapackage(self):
        contract, _ = self.fixture(); meta = metadata()
        contract["repositories"][0]["files"] = self.reference(archive([("alpha-1-1/desc", descriptor(meta), tarfile.REGTYPE), ("alpha-1-1/files", b"", tarfile.REGTYPE)]))
        self.assertEqual(audit.run(contract)["selected_packages"][0]["declared_paths"], [])

    def test_files_in_desc_cannot_forge_physical_file_list(self):
        contract, _ = self.fixture()
        forged = metadata() | {"FILES": ["usr/bin/forged"]}
        contract["repositories"][0]["files"] = self.reference(archive([("alpha-1-1/desc", descriptor(forged), tarfile.REGTYPE)]))
        with self.assertRaisesRegex(ValueError, "FILES outside physical files"):
            audit.run(contract)

    def test_files_in_depends_cannot_forge_physical_file_list(self):
        contract, _ = self.fixture()
        contract["repositories"][0]["files"] = self.reference(archive([
            ("alpha-1-1/desc", descriptor(metadata()), tarfile.REGTYPE),
            ("alpha-1-1/depends", descriptor({"FILES": ["usr/bin/forged"]}), tarfile.REGTYPE)]))
        with self.assertRaisesRegex(ValueError, "FILES outside physical files"):
            audit.run(contract)

    def test_missing_physical_file_list_is_explicitly_unavailable(self):
        contract, _ = self.fixture()
        contract["repositories"][0]["files"] = self.reference(archive([("alpha-1-1/desc", descriptor(metadata()), tarfile.REGTYPE)]))
        result = audit.run(contract)
        self.assertEqual(result["unavailable_packages"][0]["reason"], "unavailable physical files member")
        self.assertFalse(result["ownership_findings_complete"])
        self.assertEqual(result["selected_packages"], [])

    def test_identity_must_come_from_physical_desc(self):
        for rows in [[("alpha-1-1/depends", descriptor(metadata()), tarfile.REGTYPE)],
                     [("alpha-1-1/files", descriptor(metadata() | {"FILES": []}), tarfile.REGTYPE)]]:
            with self.subTest(rows=rows):
                contract, _ = self.fixture(); contract["repositories"][0]["db"] = self.reference(archive(rows))
                with self.assertRaises(ValueError): audit.run(contract)

    def test_member_hash_provenance_matches_physical_file_list(self):
        contract, _ = self.fixture(); result = audit.run(contract)
        provenance = result["selected_packages"][0]["repository_member_provenance"]
        self.assertEqual(provenance["file_list_member"], "alpha-1-1/files")
        self.assertEqual(provenance["file_list_sha256"], hashlib.sha256(descriptor({"FILES": ["usr/", "usr/bin/", "usr/bin/new"]})).hexdigest())

    def test_installed_selection_uses_only_image_paths(self):
        contract, final = self.fixture(); final["packages"][0]["repo"] = "installed"
        contract["final_inventory"] = self.json(final); result = audit.run(contract)
        self.assertIn("usr/bin/old", result["selected_packages"][0]["declared_paths"])

    def test_version_arch_filename_and_hash_pair_mismatches_explicit(self):
        for field, value in [("VERSION", "2-1"), ("ARCH", "any"), ("FILENAME", "wrong.pkg.tar.xz"), ("SHA256SUM", "b" * 64)]:
            with self.subTest(field=field):
                contract, final = self.fixture(); meta = metadata(); meta[field] = [value]
                contract["repositories"][0]["files"] = self.reference(archive([("alpha-1-1/desc", descriptor(meta), tarfile.REGTYPE), ("alpha-1-1/files", descriptor({"FILES": []}), tarfile.REGTYPE)]))
                result = audit.run(contract); self.assertEqual(len(result["unavailable_packages"]), 1)
                self.assertFalse(result["ownership_findings_complete"])
                owner = result["removed_or_relinquished_owners"][0]
                self.assertTrue(owner["ownership_unavailable"]); self.assertFalse(owner["absent_from_proposed_inventory"])

    def test_missing_repository_or_package_is_reported(self):
        contract, _ = self.fixture(); contract["repositories"] = []
        self.assertEqual(audit.run(contract)["unavailable_packages"][0]["reason"], "unavailable repository snapshot")
        contract, _ = self.fixture(); contract["repositories"][0]["db"] = self.reference(archive([]))
        self.assertEqual(audit.run(contract)["unavailable_packages"][0]["reason"], "unavailable DB package")

    def test_failed_transaction_is_partial_even_with_all_filelists(self):
        contract, final = self.fixture(); final["transaction_status"] = "FAIL-incomplete-or-policy-rejected"
        contract["final_inventory"] = self.json(final); result = audit.run(contract)
        self.assertEqual(result["status"], "partial-transaction-inventory")
        self.assertFalse(result["ownership_findings_complete"])

    def test_transaction_acceptance_claim_refused(self):
        contract, final = self.fixture(); final["dependency_transaction_accepted"] = True
        contract["final_inventory"] = self.json(final)
        with self.assertRaises(ValueError): audit.run(contract)

    def test_shared_directories_tolerated_and_non_directory_overlap_detected(self):
        item = lambda values: {"metadata": metadata(), "paths": audit.paths(values)}
        final = {"a": item(["usr/", "usr/bin/same"]), "b": item(["usr/", "usr/bin/same"])}
        overlaps, _ = audit.analyze({}, final)
        self.assertEqual([x["path"] for x in overlaps], ["usr/bin/same"])

    def test_file_directory_overlap_candidate(self):
        final = {"a": {"paths": {"usr/bin": True}}, "b": {"paths": {"usr/bin": False}}}
        self.assertEqual(audit.analyze({}, final)[0][0]["path"], "usr/bin")

    def test_removed_owner_with_declared_transfer(self):
        initial = {"old": {"paths": {"usr/x": False}}}; final = {"new": {"paths": {"usr/x": False}}}
        row = audit.analyze(initial, final)[1][0]
        self.assertTrue(row["absent_from_proposed_inventory"])
        self.assertEqual(row["relinquished_paths"][0]["final_declared_owners"][0]["package"], "new")

    def test_hook_candidates_are_paths_not_execution_claims(self):
        contract, _ = self.fixture(["usr/share/libalpm/hooks/x.hook", "etc/pacman.d/hooks/y.hook"])
        result = audit.run(contract)
        self.assertEqual(len(result["selected_packages"][0]["hook_path_candidates"]), 2)
        self.assertFalse(result["hook_contents_verified"])

    def test_path_traversal_controls_and_duplicate_paths_refused(self):
        for values in [["/etc/x"], ["usr/../x"], ["usr//x"], ["usr/x\n"], ["usr/x", "usr/x/"], ["."]]:
            with self.subTest(values=values), self.assertRaises(ValueError): audit.paths(values)

    def test_tar_traversal_duplicate_links_and_checksum_refused(self):
        for rows in [[("../desc", b"", tarfile.REGTYPE)], [("a/desc", b"", tarfile.REGTYPE)] * 2,
                     [("a/desc", b"", tarfile.SYMTYPE)]]:
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                list(audit.tar_members(io.BytesIO(gzip.decompress(archive(rows))), {"decoded": 0, "members": 0}))
        body = bytearray(gzip.decompress(archive([("a/desc", b"", tarfile.REGTYPE)]))); body[0] ^= 1
        with self.assertRaisesRegex(ValueError, "checksum"):
            list(audit.tar_members(io.BytesIO(body), {"decoded": 0, "members": 0}))

    def test_truncated_archive_nonzero_trailer_and_decode_bounds(self):
        raw = gzip.decompress(archive([("a/desc", b"data", tarfile.REGTYPE)]))
        for body in [raw[:700], raw + b"unexpected"]:
            with self.subTest(length=len(body)), self.assertRaises(ValueError):
                list(audit.tar_members(io.BytesIO(body), {"decoded": 0, "members": 0}))
        with patch.object(audit, "DECODED_LIMIT", 511), self.assertRaisesRegex(ValueError, "decoded"):
            list(audit.tar_members(io.BytesIO(raw), {"decoded": 0, "members": 0}))

    def test_sparse_unselected_descriptor_is_explicitly_unavailable(self):
        def pax(key, value):
            record = (key + "=" + value + "\n").encode(); length = len(record) + 2
            while length != len(str(length)) + 1 + len(record): length = len(str(length)) + 1 + len(record)
            return str(length).encode() + b" " + record
        extension = b"".join(pax(k, v) for k, v in [("GNU.sparse.major", "1"), ("GNU.sparse.minor", "0"),
                              ("GNU.sparse.name", "alpha-1-1/desc"), ("GNU.sparse.realsize", "100")])
        spec = self.reference(archive([("alpha-1-1/PaxHeader/desc", extension, tarfile.XHDTYPE),
                                       ("alpha-1-1/GNUSparseFile/desc", b"unsupported mapping", tarfile.REGTYPE)]))
        records, diagnostics = audit.catalog(spec, {"alpha"}, {"decoded": 0, "members": 0, "metadata": 0})
        self.assertEqual(records, {}); self.assertIn("unselectable", diagnostics[0]["reason"])

    def test_sparse_blocked_folder_cannot_be_resurrected_by_depends(self):
        def pax(key, value):
            record = (key + "=" + value + "\n").encode(); length = len(record) + 2
            while length != len(str(length)) + 1 + len(record): length = len(str(length)) + 1 + len(record)
            return str(length).encode() + b" " + record
        extension = b"".join(pax(k, v) for k, v in [("GNU.sparse.major", "1"), ("GNU.sparse.minor", "0"),
                              ("GNU.sparse.name", "alpha-1-1/desc"), ("GNU.sparse.realsize", "100")])
        contract, _ = self.fixture()
        contract["repositories"][0]["db"] = self.reference(archive([
            ("alpha-1-1/PaxHeader/desc", extension, tarfile.XHDTYPE),
            ("alpha-1-1/GNUSparseFile/desc", b"mapping", tarfile.REGTYPE),
            ("alpha-1-1/depends", descriptor(metadata()), tarfile.REGTYPE)]))
        result = audit.run(contract)
        self.assertEqual(result["unavailable_packages"][0]["reason"], "unavailable DB package")
        self.assertEqual(result["available_package_count"], 0)
        self.assertFalse(result["ownership_findings_complete"])

    def test_later_sparse_member_invalidates_previously_read_identity(self):
        def pax(key, value):
            record = (key + "=" + value + "\n").encode(); length = len(record) + 2
            while length != len(str(length)) + 1 + len(record): length = len(str(length)) + 1 + len(record)
            return str(length).encode() + b" " + record
        extension = b"".join(pax(k, v) for k, v in [("GNU.sparse.major", "1"), ("GNU.sparse.minor", "0"),
                              ("GNU.sparse.name", "alpha-1-1/depends"), ("GNU.sparse.realsize", "100")])
        spec = self.reference(archive([("alpha-1-1/desc", descriptor(metadata()), tarfile.REGTYPE),
            ("alpha-1-1/PaxHeader/depends", extension, tarfile.XHDTYPE),
            ("alpha-1-1/GNUSparseFile/depends", b"mapping", tarfile.REGTYPE)]))
        records, diagnostics = audit.catalog(spec, {"alpha"}, {"decoded": 0, "members": 0, "metadata": 0})
        self.assertEqual(records, {}); self.assertEqual(len(diagnostics), 1)

    def test_unselected_uppercase_name_does_not_abort_selected_parse(self):
        spec = self.reference(archive([("FEX-Emu-1-1/desc", descriptor(metadata("FEX-Emu")), tarfile.REGTYPE),
                                       ("alpha-1-1/desc", descriptor(metadata()), tarfile.REGTYPE)]))
        records, _ = audit.catalog(spec, {"alpha"}, {"decoded": 0, "members": 0, "metadata": 0})
        self.assertEqual(set(records), {"alpha"})

    def test_upstream_uppercase_package_identity_is_data_not_a_policy_failure(self):
        self.assertEqual(audit.identity(metadata("FEX-Emu"), archive=True), ("FEX-Emu", "1-1"))

    def test_input_hash_symlink_and_duplicate_json_refused(self):
        ref = self.reference(b"data"); ref["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            with audit.reference(ref, 10): pass
        ref = self.reference(b"data"); link = self.root / "link"; link.symlink_to(ref["path"]); ref["path"] = str(link)
        with self.assertRaises(OSError):
            with audit.reference(ref, 10): pass
        with self.assertRaises(ValueError): audit.loads(b'{"x":1,"x":2}')

    def test_reference_snapshot_survives_same_size_overwrite_truncation_and_path_replace(self):
        original, replacement = b'{"v":1}', b'{"v":2}'
        for change in ("overwrite", "truncate", "replace"):
            with self.subTest(change=change):
                ref = self.reference(original)
                path = Path(ref["path"])
                with audit.reference(ref, 32) as snapshot:
                    if change == "replace":
                        alternate = path.with_name(path.name + "-replacement")
                        alternate.write_bytes(replacement)
                        alternate.replace(path)
                    else:
                        path.write_bytes(replacement if change == "overwrite" else b"")
                    self.assertEqual(snapshot.read(), original)
                    snapshot.seek(0)
                    self.assertEqual(snapshot.read(5) + snapshot.read(), original)
                    self.assertEqual(hashlib.sha256(snapshot.getvalue()).hexdigest(), ref["sha256"])
                self.assertTrue(snapshot.closed)

    def test_mutation_during_capture_is_refused_before_yield(self):
        ref = self.reference(b'{"v":1}')
        original_fdopen = audit.os.fdopen
        def changing_fdopen(fd, *args, **kwargs):
            Path(ref["path"]).write_bytes(b'{"v":2}')
            return original_fdopen(fd, *args, **kwargs)
        with patch.object(audit.os, "fdopen", side_effect=changing_fdopen):
            with self.assertRaisesRegex(ValueError, "input checksum mismatch"):
                with audit.reference(ref, 32):
                    self.fail("mutated source must not yield")

    def test_json_and_catalog_consume_the_verified_snapshot(self):
        reference = audit.reference
        @contextlib.contextmanager
        def mutate_after_capture(spec, maximum):
            with reference(spec, maximum) as stream:
                Path(spec["path"]).write_bytes(b"X" * spec["size"])
                yield stream
        document = self.json({"v": 1})
        database = self.reference(archive([("alpha-1-1/desc", descriptor(metadata()), tarfile.REGTYPE)]))
        with patch.object(audit, "reference", side_effect=mutate_after_capture):
            self.assertEqual(audit.json_reference(document), {"v": 1})
            records, _ = audit.catalog(database, {"alpha"}, {"decoded": 0, "members": 0, "metadata": 0})
        self.assertEqual(records["alpha"]["metadata"], metadata())

    def test_payload_inspection_consumes_snapshot_after_same_size_source_overwrite(self):
        spec = importlib.util.spec_from_file_location("snapshot_payload", Path(audit.__file__).with_name("payload_audit.py"))
        payload = importlib.util.module_from_spec(spec); spec.loader.exec_module(payload)
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w:") as stream:
            for name, data in ((".PKGINFO", b"pkgname = alpha\npkgver = 1-1\narch = aarch64\n"),
                               ("usr/share/alpha/data", b"verified payload")):
                member = tarfile.TarInfo(name); member.size = len(data)
                stream.addfile(member, io.BytesIO(data))
        ref = self.reference(lzma.compress(raw.getvalue()))
        reference = payload.ownership.reference
        @contextlib.contextmanager
        def mutate_after_capture(spec, maximum):
            with reference(spec, maximum) as stream:
                Path(spec["path"]).write_bytes(b"X" * spec["size"])
                yield stream
        with patch.object(payload.ownership, "reference", side_effect=mutate_after_capture):
            result = payload.inspect(ref, {"decoded": 0, "nodes": 0})
        self.assertEqual(result["nodes"][0]["sha256"], hashlib.sha256(b"verified payload").hexdigest())

    def test_snapshot_size_bounds_checked_before_consumption(self):
        for data, size, maximum in ((b"abcd", 3, 10), (b"abc", 4, 10), (b"abcd", 4, 3)):
            with self.subTest(data=data, size=size, maximum=maximum):
                ref = self.reference(data); ref["size"] = size
                with self.assertRaisesRegex(ValueError, "input (size mismatch|bound)"):
                    with audit.reference(ref, maximum):
                        self.fail("out-of-bound source must not yield")

    def test_private_output_new_file_and_public_parent_refusal(self):
        import os
        with patch.object(audit, "ARTIFACTS", self.root):
            output = self.root / "out.json"; audit.write_private(output, {"x": 1})
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError): audit.write_private(output, {})
            os.chmod(self.root, 0o755)
            with self.assertRaises(ValueError): audit.write_private(self.root / "other", {})


if __name__ == "__main__":
    unittest.main()
