import hashlib
import importlib.util
import io
import json
import lzma
from pathlib import Path
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("checksum_successor", HERE / "verify.py")
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)
FIX = importlib.util.spec_from_file_location("tar_fixtures", HERE.parent / "test_inventory.py")
TAR = importlib.util.module_from_spec(FIX)
FIX.loader.exec_module(TAR)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run_scan(entries, expected=None, corrupt_source=False):
    expected = expected if expected is not None else {"src/lib.rs": digest(b"source-data")}
    body = json.dumps({"files": expected, "package": "a" * 64}).encode()
    payload = b"".join(entries) + TAR.member("root/vendor/one/.cargo-checksum.json", body) + bytes(1024)
    compressed = lzma.compress(payload)
    spec = {"name": "rust", "root": "root", "filename": "fixture.xz", "bytes": len(compressed), "sha256": "0" * 64 if corrupt_source else digest(compressed)}
    reader = VERIFY.BASE.XZReader(io.BytesIO(compressed), spec)
    previous = {"one": {".cargo-checksum.json": {"bytes": len(body), "sha256": digest(body)}}}
    scan = VERIFY.Checksums(reader, spec, previous, ["one"])
    scan.scan()
    return scan, scan.results()["one"]


class IntegrityControls(unittest.TestCase):
    def test_manifest_last_actual_bytes_pass(self):
        scan, result = run_scan([TAR.member("root/vendor/one/src/lib.rs", b"source-data")])
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["matched_files"], 1)
        self.assertTrue(scan.reader.finished)

    def test_changed_missing_and_extra_are_distinct_failures(self):
        for entries, field in [([TAR.member("root/vendor/one/src/lib.rs", b"changed")], "changed"),
                               ([], "missing"),
                               ([TAR.member("root/vendor/one/src/lib.rs", b"source-data"), TAR.member("root/vendor/one/extra", b"x")], "extra")]:
            with self.subTest(field=field):
                _scan, result = run_scan(entries)
                self.assertEqual(result["status"], "FAIL_OR_REFUSED")
                self.assertEqual(result["issues"][field], 1)

    def test_duplicate_archive_canonical_alias_refused(self):
        _scan, result = run_scan([TAR.member("root/vendor/one/src/lib.rs", b"source-data"),
                                  TAR.member("./root/vendor/one/src/lib.rs", b"source-data")])
        self.assertEqual(result["issues"]["aliases"], 1)
        self.assertNotEqual(result["status"], "PASS")

    def test_file_directory_ancestor_collision_refused(self):
        for entries in ([TAR.member("root/vendor/one/src", b"x"), TAR.member("root/vendor/one/src/lib.rs", b"source-data")],
                        [TAR.member("root/vendor/one/src/lib.rs", b"source-data"), TAR.member("root/vendor/one/src", b"x")]):
            _scan, result = run_scan(entries)
            self.assertEqual(result["issues"]["aliases"], 1)

    def test_links_are_not_followed_or_counted_as_verified_bytes(self):
        _scan, result = run_scan([TAR.member("root/vendor/one/src/lib.rs", kind=b"2")])
        self.assertEqual(result["issues"]["refused_nonregular"], 1)
        self.assertEqual(result["matched_files"], 0)

    def test_json_duplicate_keys_and_path_aliases_refused(self):
        for body in [b'{"files":{},"files":{},"package":null}',
                     b'{"files":{"x":"a","x":"b"},"package":null}',
                     json.dumps({"files": {"a/../b": "a" * 64}, "package": None}).encode()]:
            with self.subTest(body=body), self.assertRaises(VERIFY.BASE.BoundError):
                VERIFY.checksum_map(body)

    def test_unsafe_checksum_paths_and_self_checksum_refused(self):
        for path in ("/x", "./x", "a//b", "a\\b", "x\0y", ".cargo-checksum.json"):
            with self.subTest(path=path), self.assertRaises(VERIFY.BASE.BoundError):
                VERIFY.checksum_map(json.dumps({"files": {path: "a" * 64}, "package": None}).encode())

    def test_nonregular_authoritative_marker_refused(self):
        with self.assertRaisesRegex(VERIFY.BASE.BoundError, "nonregular"):
            run_scan([TAR.member("root/vendor/one/.cargo-checksum.json", kind=b"2")])

    def test_nested_marker_is_an_ordinary_listed_file(self):
        content = b"not-json"
        _scan, result = run_scan([TAR.member("root/vendor/one/nested/.cargo-checksum.json", content)],
                                {"nested/.cargo-checksum.json": digest(content)})
        self.assertEqual(result["status"], "PASS")

    def test_bad_declared_digests_refused(self):
        for value in ("a" * 63, "G" * 64, 3, None):
            with self.subTest(value=value), self.assertRaises(VERIFY.BASE.BoundError):
                VERIFY.checksum_map(json.dumps({"files": {"file": value}, "package": None}).encode())

    def test_absent_package_checksum_still_checks_file_bytes(self):
        files, package = VERIFY.checksum_map(json.dumps({"files": {"file": "a" * 64}}).encode())
        self.assertIsNone(package)
        self.assertEqual(files, {"file": bytes.fromhex("a" * 64)})

    def test_vendor_root_alias_and_nonempty_directory_refused(self):
        for entries in ([TAR.member("root/vendor", kind=b"2")],
                        [TAR.member("root/vendor", kind=b"5"), TAR.member("./root/vendor", kind=b"5")],
                        [TAR.member("root/vendor/one", b"bad-directory-payload", kind=b"5")]):
            with self.subTest(count=len(entries)), self.assertRaises(VERIFY.BASE.BoundError):
                run_scan(entries)

    def test_unknown_map_schema_stays_unresolved(self):
        with self.assertRaisesRegex(VERIFY.BASE.BoundError, "schema"):
            VERIFY.checksum_map(b'{"files":{},"unknown":true}')

    def test_comment_is_only_bounded_annotation(self):
        files, package = VERIFY.checksum_map(json.dumps({"$comment": "signed source annotation", "files": {"file": "a" * 64}}).encode())
        self.assertEqual(files, {"file": bytes.fromhex("a" * 64)})
        self.assertIsNone(package)
        for comment in ({"files": {}}, "x" * 4097):
            with self.subTest(comment_type=type(comment).__name__), self.assertRaises(VERIFY.BASE.BoundError):
                VERIFY.checksum_map(json.dumps({"$comment": comment, "files": {}}).encode())

    def test_matching_files_do_not_override_bad_archive_source_pin(self):
        with self.assertRaisesRegex(VERIFY.BASE.BoundError, "source pin"):
            run_scan([TAR.member("root/vendor/one/src/lib.rs", b"source-data")], corrupt_source=True)

    def test_low_host_reserve_refuses_before_decompression(self):
        compressed = lzma.compress(bytes(1024))
        spec = {"bytes": len(compressed), "sha256": digest(compressed)}
        reader = VERIFY.ReserveReader(io.BytesIO(compressed), spec)
        with mock.patch.object(VERIFY, "memory_available", return_value=VERIFY.RESERVE - 1), \
                self.assertRaisesRegex(VERIFY.BASE.BoundError, "reserve"):
            reader.read(512)
        self.assertEqual(reader.logical, 0)


if __name__ == "__main__":
    unittest.main()
