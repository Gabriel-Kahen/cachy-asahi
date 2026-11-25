# SPDX-License-Identifier: MIT
import gzip
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import baseline
import materialize
import prepare
import verify_packages


class SourceTests(unittest.TestCase):
    def test_stored_gzip_framing_at_block_boundaries(self):
        epoch = 1791585070
        for size in (0, 1, 65534, 65535, 65536, 131070, 131071):
            with self.subTest(size=size):
                payload = (b"project-libraries" * size)[:size]
                archive = materialize.canonical_gzip(payload, epoch, lambda label: None)
                self.assertEqual(gzip.decompress(archive), payload)
                self.assertEqual(archive[:10], b"\x1f\x8b\x08\x00" + epoch.to_bytes(4, "little") + b"\x00\xff")
                self.assertEqual(len(archive), size + 18 + 5 * max(1, (size + 65534) // 65535))

    def test_stored_gzip_propagates_deadline(self):
        failure = TimeoutError("stop")

        def checkpoint(label):
            if label == "after-filtered-gzip-block":
                raise failure

        with self.assertRaises(TimeoutError) as captured:
            materialize.canonical_gzip(b"x" * 65536, 1, checkpoint)
        self.assertIs(captured.exception, failure)

    def test_mismatched_upstream_refuses_before_creating_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "candidate"
            with self.assertRaisesRegex(ValueError, "upstream pin"):
                prepare.prepare(dict.fromkeys(prepare.UPSTREAM, b""), output, lambda label: None)
            self.assertFalse(output.exists())

    def test_review_requires_exact_regular_file_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "PKGBUILD"
            source.write_bytes(b"test")
            source.chmod(0o600)
            plan = {"outputs": [{"package": "jbigkit", "filename": "PKGBUILD", "bytes": 4,
                                 "mode": 0o644, "sha256": materialize.sha(b"test")}]}
            with self.assertRaisesRegex(ValueError, "recipe size/mode"):
                prepare.verify_recipe(source.parent, "jbigkit", plan)
            (source.parent / "extra").touch()
            with self.assertRaisesRegex(ValueError, "recipe file set"):
                prepare.verify_recipe(source.parent, "jbigkit", plan)


class BaselineTests(unittest.TestCase):
    def test_base_and_tiff_output_locks_are_both_pinned(self):
        before = b"glibc 1-1\n"
        after = b"cachy-asahi-jbigkit 2.2-1.1\nglibc 1-1\nlibwebp 1.6.0-2\n"
        contract = {"base_lock_sha256": materialize.sha(before), "base_package_count": 1,
                    "codec_versions": {"libwebp": "1.6.0-2"},
                    "tiff_lock_sha256": materialize.sha(after), "tiff_package_count": 3}
        self.assertEqual(baseline.derive(before, contract), after)
        with self.assertRaisesRegex(ValueError, "baseline lock pin"):
            baseline.derive(before.replace(b"1-1", b"2-1"), contract)
        with self.assertRaisesRegex(ValueError, "derived TIFF builder lock pin"):
            baseline.derive(before, {**contract, "codec_versions": {"libwebp": "3-1"}})
        with self.assertRaisesRegex(ValueError, "already has a codec or library provider"):
            older = before + b"jbigkit 2.1-8\n"
            baseline.derive(older, {**contract, "base_lock_sha256": materialize.sha(older), "base_package_count": 2})


class PackageTests(unittest.TestCase):
    def test_source_and_generated_inventory_are_bound_to_package_members(self):
        prefix = "usr/share/cachy-asahi-libtiff/corresponding-source/"
        source = {path: {"type": "0", "mode": 0o644, "sha256": "data", "size": 1}
                  for path in verify_packages.GENERATED | {"recipe/PKGBUILD", "inventory.json"}}
        inventory = {path: {"sha256": row["sha256"], "bytes": row["size"]}
                     for path, row in source.items() if path != "inventory.json"}
        members = {prefix + path: row for path, row in source.items()}
        with patch.object(verify_packages, "member_bytes", return_value=json.dumps(inventory).encode()):
            count = verify_packages.check_sources(Path("archive"), "libtiff", members, {"PKGBUILD": "data"})
            self.assertEqual(count, len(source))
            source["recipe/PKGBUILD"]["sha256"] = "swapped"
            with self.assertRaisesRegex(ValueError, "corresponding-source checksum"):
                verify_packages.check_sources(Path("archive"), "libtiff", members, {"PKGBUILD": "data"})
            source["recipe/PKGBUILD"]["sha256"] = "data"
            source["actual-build/CMakeCache.txt"]["sha256"] = "swapped"
            with self.assertRaisesRegex(ValueError, "generated-source inventory"):
                verify_packages.check_sources(Path("archive"), "libtiff", members, {"PKGBUILD": "data"})

    def test_library_requires_expected_provider_and_refuses_runpath(self):
        members = {
            "usr/lib/libtiff.so": {"type": "2", "link": "libtiff.so.6"},
            "usr/lib/libtiff.so.6": {"type": "2", "link": "libtiff.so.6.3.0"},
            "usr/lib/libtiff.so.6.3.0": {"type": "0", "sha256": "data"},
        }
        elf = {"classification": "aarch64-loadable-elf", "type": 3, "interpreter": None,
               "soname": "libtiff.so.6", "needed": ["libjbig.so.2.2"], "rpath": None, "runpath": None}
        with patch.object(verify_packages, "member_bytes"), patch.object(verify_packages, "parse_elf", return_value=elf):
            args = (Path("archive"), "libtiff.so.6", members, {"libjbig.so.2.2"})
            self.assertEqual(verify_packages.check_library(*args)["needed"], ["libjbig.so.2.2"])
            elf["needed"] = ["libjbig.so.2.1"]
            with self.assertRaisesRegex(ValueError, "dynamic dependencies"):
                verify_packages.check_library(*args)
            elf.update(needed=["libjbig.so.2.2"], runpath="/tmp/library")
            with self.assertRaisesRegex(ValueError, "dynamic dependencies or paths"):
                verify_packages.check_library(*args)
            members["usr/lib/libtiff.so.6"]["link"] = "../libtiff.so.6.3.0"
            with self.assertRaisesRegex(ValueError, "versioned symlink"):
                verify_packages.check_library(*args)


if __name__ == "__main__":
    unittest.main()
