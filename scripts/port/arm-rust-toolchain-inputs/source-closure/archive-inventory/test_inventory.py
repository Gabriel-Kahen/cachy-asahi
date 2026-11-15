"""Focused synthetic parser/bound controls, no real source archive needed."""
import hashlib
import importlib.util
import io
import lzma
import os
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("source_inventory", HERE / "inventory.py")
INV = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INV)


def header(name, size, kind=b"0"):
    data = bytearray(512)
    encoded = name.encode()
    if len(encoded) > 100:
        raise ValueError("fixture header name too long")
    data[:len(encoded)] = encoded
    data[100:108] = b"0000644\0"
    data[124:136] = f"{size:011o}\0".encode()
    data[148:156] = b" " * 8
    data[156:157] = kind
    data[257:263] = b"ustar\0"
    data[148:156] = f"{sum(data):06o}\0 ".encode()
    return bytes(data)


def member(name, body=b"", kind=b"0"):
    return header(name, len(body), kind) + body + bytes((-len(body)) % 512)


def pax(key, value):
    tail = b" " + key.encode() + b"=" + value.encode() + b"\n"
    size = len(tail) + 1
    while len(str(size)) + len(tail) != size:
        size = len(str(size)) + len(tail)
    return str(size).encode() + tail


def scanner(payload, changes=None, corrupt_sha=False):
    compressed = lzma.compress(payload)
    limits = {**INV.LIMITS, **(changes or {})}
    spec = {"name": "rust", "root": "root", "filename": "fixture.tar.xz",
            "bytes": len(compressed), "sha256": "0" * 64 if corrupt_sha else hashlib.sha256(compressed).hexdigest()}
    return INV.Inventory(INV.XZReader(io.BytesIO(compressed), spec, limits), spec, limits)


class ParserControls(unittest.TestCase):
    def test_real_stream_metadata_and_no_member_materialization(self):
        source = member("root/Cargo.lock", b'version = 4\n[[package]]\nname="one"\nversion="1"\n') + bytes(1024)
        scan = scanner(source)
        scan.scan()
        report = scan.report(None)
        self.assertTrue(report["authenticated_source_pin_verified"])
        self.assertEqual(report["archive_member_payload_bytes_written"], 0)
        self.assertEqual(report["selected_metadata"][0]["declarations"]["packages"][0]["name"], "one")

    def test_header_count_stops_at_literal_limit(self):
        scan = scanner(member("root/a") + member("root/b") + bytes(1024), {"headers": 1})
        with self.assertRaisesRegex(INV.BoundError, "header bound"):
            scan.scan()
        self.assertEqual(scan.headers, 1)

    def test_output_decompression_never_exceeds_logical_cap(self):
        scan = scanner(member("root/a", b"x" * 8192) + bytes(1024), {"logical": 1024})
        with self.assertRaises(INV.BoundError):
            scan.scan()
        self.assertLessEqual(scan.reader.logical, 1024)

    def test_individual_metadata_cap_before_body_read(self):
        scan = scanner(member("root/Cargo.lock", b"x" * 20) + bytes(1024), {"metadata": 10})
        with self.assertRaisesRegex(INV.BoundError, "individual selected metadata"):
            scan.scan()
        self.assertEqual(scan.reader.logical, 512)

    def test_checksum_corruption_rejected(self):
        source = bytearray(member("root/a") + bytes(1024))
        source[0] ^= 1
        with self.assertRaisesRegex(INV.BoundError, "header checksum"):
            scanner(bytes(source)).scan()

    def test_source_digest_must_match_before_complete(self):
        with self.assertRaisesRegex(INV.BoundError, "source pin"):
            scanner(member("root/a") + bytes(1024), corrupt_sha=True).scan()

    def test_pax_and_gnu_long_paths(self):
        for extension, body in ((b"x", pax("path", "root/Cargo.lock")),
                                (b"L", b"root/Cargo.lock\0")):
            source = member("PaxHeader", body, extension) + member("root/wrong", b"version=4\n") + bytes(1024)
            scan = scanner(source)
            scan.scan()
            self.assertEqual(scan.selected[0]["path"], "Cargo.lock")

    def test_sparse_and_unsafe_paths_refused(self):
        for source in (member("root/../bad"), member("/root/a"), member("root/a", kind=b"S")):
            with self.subTest(source=source[:30]), self.assertRaises(INV.BoundError):
                scanner(source + bytes(1024)).scan()

    def test_no_follow_for_selected_symlink(self):
        scan = scanner(member("root/Cargo.lock", kind=b"2") + bytes(1024))
        scan.scan()
        self.assertEqual(scan.selected[0]["metadata"], "NOT_REGULAR_NOT_FOLLOWED")

    def test_tar_trailing_payload_and_truncation_refused(self):
        for source in (member("root/a") + bytes(1024) + b"x", header("root/a", 2048)):
            with self.subTest(size=len(source)), self.assertRaises(INV.BoundError):
                scanner(source).scan()

    def test_bad_pax_lengths_and_oversized_fields(self):
        for value in (b"999 path=x\n", pax("GNU.sparse.map", "0,1"), pax("size", "9" * 30)):
            with self.subTest(value=value[:30]), self.assertRaises(INV.BoundError):
                INV.pax_fields(value)

    def test_nonregular_and_symlink_compressed_inputs_refused(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as folder:
            fifo, link = Path(folder) / "fifo", Path(folder) / "link"
            os.mkfifo(fifo)
            link.symlink_to("/dev/zero")
            for path in (fifo, link):
                with self.subTest(path=path.name), self.assertRaises((INV.BoundError, OSError)):
                    INV.regular_input(path)


if __name__ == "__main__":
    unittest.main()
