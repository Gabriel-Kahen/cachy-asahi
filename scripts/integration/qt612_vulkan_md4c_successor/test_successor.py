#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline source projection and ELF-readback controls."""

import hashlib
import json
from pathlib import Path
import runpy
import shutil
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
P = runpy.run_path(str(HERE / "prepare.py"))
GUI = runpy.run_path(str(HERE / "check_gui.py"))


class PrepareTests(unittest.TestCase):
    def test_deterministic_recipe_with_bare_provision_and_exact_sources(self):
        with tempfile.TemporaryDirectory() as work:
            a, b = (Path(work) / name for name in ("one", "two"))
            receipt = P["prepare"](a)
            self.assertEqual(P["prepare"](b), receipt)
            self.assertEqual(receipt["status"], "UNISSUED_RECIPE_ONLY")
            self.assertIsNone(receipt["authority"])
            for file in a.iterdir():
                self.assertEqual(file.read_bytes(), (b / file.name).read_bytes())
            self.assertEqual(json.loads((a / "SUCCESSOR.UNISSUED.json").read_text()), receipt)

            srcinfo = (a / ".SRCINFO").read_text().splitlines()
            self.assertIn("\tpkgrel = 3", srcinfo)
            self.assertIn("\tdepends = md4c=0.6.0-2", srcinfo)
            self.assertIn("\tmakedepends = vulkan-headers=1:1.4.363.0-1", srcinfo)
            self.assertEqual([line for line in srcinfo if line.startswith("\tprovides = qt6-base")],
                             ["\tprovides = qt6-base"])
            sources = [line.split(" = ", 1)[1] for line in srcinfo if line.startswith("\tsource = ")][1:]
            self.assertEqual(sources[-1], P["PATCH"])
            hashes = [line.split(" = ", 1)[1] for line in srcinfo if line.startswith("\tsha256sums = ")][1:]
            self.assertEqual(hashes, [hashlib.sha256((a / name).read_bytes()).hexdigest() for name in sources])
            profile = (a / "configure.cmake").read_text()
            for option in ("FEATURE_vulkan ON", "FEATURE_vkkhrdisplay OFF", "FEATURE_system_textmarkdownreader ON"):
                self.assertIn(f'set({option} CACHE BOOL "" FORCE)', profile)
            self.assertIn(P["PATCH"], (a / "PKGBUILD").read_text())

    def test_changed_pinned_file_refuses_before_output(self):
        with tempfile.TemporaryDirectory() as work:
            reference, output = (Path(work) / name for name in ("reference", "output"))
            shutil.copytree(P["REFERENCE"], reference)
            source = reference / "source.py"
            source.write_bytes(source.read_bytes() + b"\n")
            with patch.dict(P["prepare"].__globals__, REFERENCE=reference):
                with self.assertRaisesRegex(ValueError, "recipe input: source.py"):
                    P["prepare"](output)
            self.assertFalse(output.exists())

    def test_existing_output_refused_and_preserved(self):
        with tempfile.TemporaryDirectory() as work:
            output = Path(work)
            marker = output / "marker"
            marker.write_text("untouched")
            with self.assertRaises(FileExistsError):
                P["prepare"](output)
            self.assertEqual(list(output.iterdir()), [marker])
            self.assertEqual(marker.read_text(), "untouched")


class ReadbackTests(unittest.TestCase):
    exports = sorted(GUI["VULKAN_EXPORTS"])

    def fixture(self, architecture="AARCH64"):
        rows = [f" {i}: 0000000000000100 32 FUNC GLOBAL DEFAULT 13 {name.replace('@', '@@')}"
                for i, name in enumerate(self.exports, start=1)]
        rows.extend([
            " 7: 0000000000000000 0 FUNC GLOBAL DEFAULT UND md_parse",
            " 0x0000000000000001 (NEEDED) Shared library: [libmd4c.so.0]",
            f" 0000000000000120 0000000a00000402 R_{architecture}_JUMP_SLOT 0000000000000000 md_parse + 0",
        ])
        return "\n".join(rows)

    def test_both_architecture_relocation_shapes(self):
        for architecture in ("AARCH64", "X86_64"):
            with self.subTest(architecture=architecture):
                row = GUI["check_readback"](self.fixture(architecture))
                self.assertEqual(row["vulkan_exports"], self.exports)
                self.assertEqual(row["external_md4c_import"], "md_parse")

    def test_missing_misversioned_or_undefined_vulkan_refused(self):
        for before, after in (("Qt_6_PRIVATE_API", "Qt_6"), ("DEFAULT 13", "DEFAULT UND"),
                              ("FUNC GLOBAL DEFAULT 13", "FUNC WEAK DEFAULT 13")):
            with self.subTest(after=after), self.assertRaisesRegex(ValueError, "Vulkan exports"):
                GUI["check_readback"](self.fixture().replace(before, after, 1))

    def test_missing_wrong_md4c_provider_or_relocation_refused(self):
        for before, after in (("libmd4c.so.0", "libmd4c-html.so.0"), ("UND md_parse", "UND another_function"),
                              ("R_AARCH64_JUMP_SLOT", "R_AARCH64_RELATIVE")):
            with self.subTest(after=after), self.assertRaisesRegex(ValueError, "relocate md_parse"):
                GUI["check_readback"](self.fixture().replace(before, after, 1))


if __name__ == "__main__":
    unittest.main()
