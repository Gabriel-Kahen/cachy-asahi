"""Portable temp-only C01 corpus tests; no subprocess or native acceptance."""
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("corpus", Path(__file__).with_name("corpus.py"))
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


class CorpusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cachy-asahi-corpus-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.heldout = b"/* caller-reviewed public source fixture */\nint main(void) { return 0; }\n"

    def test_repeated_creation_has_identical_bytes_and_manifest(self):
        first, second = self.root / "first", self.root / "second"
        manifest = c.create(first, self.heldout)
        self.assertEqual(c.create(second, self.heldout), manifest)
        self.assertEqual(set(p.name for p in first.iterdir()), {r["path"] for r in manifest["files"]} | {"manifest.json"})
        self.assertEqual(json.loads((first / "manifest.json").read_text()), manifest)
        for path in first.iterdir():
            self.assertEqual(path.read_bytes(), (second / path.name).read_bytes())
        for row in manifest["files"]:
            data = (first / row["path"]).read_bytes()
            self.assertEqual(row["bytes"], len(data))
            self.assertEqual(row["sha256"], hashlib.sha256(data).hexdigest())
        self.assertLessEqual(sum(p.stat().st_size for p in first.iterdir()), c.LIMIT)

    def test_edge_inputs_and_training_timing_separation(self):
        output = self.root / "corpus"
        manifest = c.create(output, self.heldout)
        self.assertEqual((output / "empty.bin").read_bytes(), b"")
        self.assertEqual((output / "onebyte.bin").read_bytes(), b"x")
        self.assertEqual(set((output / "allbytes.bin").read_bytes()), set(range(256)))
        noise = (output / "incompressible.bin").read_bytes()
        self.assertEqual(len(noise), 256 * 1024)
        self.assertGreater(len(gzip.compress(noise, mtime=0)), len(noise))
        train = {r["sha256"] for r in manifest["files"] if r["role"] == "train"}
        heldout = {r["sha256"] for r in manifest["files"] if r["role"] == "heldout"}
        self.assertTrue(train and heldout and train.isdisjoint(heldout))
        self.assertEqual((output / "heldout-source.bin").read_bytes(), self.heldout)

    def test_gzip_corruption_keeps_header_and_fails_stdlib_decoder(self):
        output = self.root / "corpus"
        manifest = c.create(output, self.heldout)
        reference = (output / "gzip-reference.gz").read_bytes()
        self.assertEqual(gzip.decompress(reference), c.GZIP_PAYLOAD)
        self.assertEqual(reference[:10], b"\x1f\x8b\x08\x00\0\0\0\0\x00\xff")
        size = len(c.GZIP_PAYLOAD)
        self.assertEqual(reference[10:15], b"\x01" + size.to_bytes(2, "little") + (size ^ 0xffff).to_bytes(2, "little"))
        self.assertEqual(reference[15:-8], c.GZIP_PAYLOAD)
        corrupt = [r for r in manifest["files"] if r["kind"] == "corrupt"]
        self.assertEqual({r["path"] for r in corrupt}, {"corrupt-crc.gz", "truncated-trailer.gz"})
        for row in corrupt:
            data = (output / row["path"]).read_bytes()
            self.assertEqual(data[:10], reference[:10])
            with self.subTest(path=row["path"]), self.assertRaises((gzip.BadGzipFile, EOFError)):
                gzip.decompress(data)
        crc = (output / "corrupt-crc.gz").read_bytes()
        self.assertEqual([i for i, (a, b) in enumerate(zip(reference, crc)) if a != b], [len(reference) - 8])
        self.assertEqual((output / "truncated-trailer.gz").read_bytes(), reference[:-8])

    def test_invalid_or_overlapping_heldout_refused_before_writes(self):
        for value, error in (("text", TypeError), (bytearray(b"x"), TypeError), (b"", ValueError),
                             (c.TRAIN, ValueError), (b"x" * c.LIMIT, ValueError)):
            output = self.root / "refused"
            with self.subTest(length=len(value)), self.assertRaises(error):
                c.create(output, value)
            self.assertFalse(output.exists())
        self.assertEqual(list(self.root.iterdir()), [])

    def test_existing_directory_file_and_symlink_are_not_modified(self):
        target = self.root / "existing"
        target.mkdir()
        sentinel = target / "sentinel"
        sentinel.write_bytes(b"retain caller bytes")
        regular = self.root / "regular"
        regular.write_bytes(b"retain caller file")
        link = self.root / "link"
        link.symlink_to(target, target_is_directory=True)
        for output in (target, regular, link):
            with self.subTest(output=output), self.assertRaises(FileExistsError):
                c.create(output, self.heldout)
        self.assertEqual(list(target.iterdir()), [sentinel])
        self.assertEqual(sentinel.read_bytes(), b"retain caller bytes")
        self.assertEqual(regular.read_bytes(), b"retain caller file")
        self.assertTrue(link.is_symlink())

    def test_missing_parent_is_not_created(self):
        with self.assertRaises(FileNotFoundError):
            c.create(self.root / "missing" / "corpus", self.heldout)
        self.assertFalse((self.root / "missing").exists())


if __name__ == "__main__":
    unittest.main()
