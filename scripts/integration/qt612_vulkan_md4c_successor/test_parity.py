#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline projection and staged parity controls."""

import hashlib
import json
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
P = runpy.run_path(str(HERE / "prepare_parity.py"))
S = runpy.run_path(str(HERE / "check_parity.py"))


class Projection(unittest.TestCase):
    def test_projection_keeps_the_held_recipe_and_changes_only_expected_inputs(self):
        with tempfile.TemporaryDirectory() as scratch:
            base, candidate, replay = (Path(scratch) / name for name in ("base", "candidate", "replay"))
            prior = P["BASE"]["prepare"](base)
            receipt = P["prepare_parity"](candidate)
            self.assertEqual(P["prepare_parity"](replay), receipt)
            self.assertEqual(json.loads((candidate / "PARITY.UNISSUED.json").read_text()), receipt)
            self.assertEqual(receipt["artifact_version"], "6.12.0-4")
            self.assertIsNone(receipt["authority"])
            self.assertEqual(receipt["build"], "NOT_RUN")
            self.assertEqual(receipt["installation"], "NOT_RUN")
            self.assertEqual(set(receipt["official_inputs"]) - set(prior["official_inputs"]), set(P["PARITY_INPUTS"]))
            self.assertEqual(set(receipt["files"]) - set(prior["files"]), {"check_parity.py"})
            self.assertEqual(
                {name for name in prior["files"] if prior["files"][name] != receipt["files"][name]},
                {"PKGBUILD", ".SRCINFO", "configure.cmake"},
            )
            self.assertEqual({path.name: path.read_bytes() for path in candidate.iterdir()},
                             {path.name: path.read_bytes() for path in replay.iterdir()})
            before = (base / "configure.cmake").read_text().splitlines()
            after = (candidate / "configure.cmake").read_text().splitlines()
            self.assertEqual(len(before), len(after))
            self.assertEqual(
                [(old, new) for old, new in zip(before, after) if old != new],
                [(f'set(FEATURE_{feature} OFF CACHE BOOL "" FORCE)',
                  f'set(FEATURE_{feature} ON CACHE BOOL "" FORCE)')
                 for feature in ("egl_x11", "xcb_egl_plugin", "accessibility_atspi_bridge", "cups")],
            )
            srcinfo = (candidate / ".SRCINFO").read_text().splitlines()
            for line in ("pkgrel = 4", "depends = libcups", "makedepends = at-spi2-core",
                         "optdepends = at-spi2-core: desktop accessibility bus and registry", "provides = qt6-base"):
                self.assertIn("\t" + line, srcinfo)
            self.assertEqual([line for line in srcinfo if line.startswith("\tprovides = qt6-base")],
                             ["\tprovides = qt6-base"])
            sources = [line.split(" = ", 1)[1] for line in srcinfo if line.startswith("\tsource = ")][1:]
            hashes = [line.split(" = ", 1)[1] for line in srcinfo if line.startswith("\tsha256sums = ")][1:]
            self.assertEqual(hashes, [hashlib.sha256((candidate / name).read_bytes()).hexdigest() for name in sources])
            recipe = (candidate / "PKGBUILD").read_text()
            self.assertIn('python "$srcdir/check_parity.py" "$srcdir/stage-contract.json" || return', recipe)

    def test_base_recipe_drift_prevents_projection(self):
        with tempfile.TemporaryDirectory() as scratch:
            output = Path(scratch) / "candidate"
            with patch.dict(P["prepare_parity"].__globals__, BASE_SHA256="0" * 64):
                with self.assertRaisesRegex(ValueError, "differs from the Asahi629 input"):
                    P["prepare_parity"](output)
            self.assertFalse(output.exists())


class Stage(unittest.TestCase):
    def setUp(self):
        self.stage = {
            "files": {name: {"mode": 0o755 if name in S["PLUGINS"] else 0o644} for name in S["ADDED_FILES"]},
            "elf": {name: {"type": 3, "needed": [library]} for name, library in S["PLUGINS"].items()},
        }

    def test_expected_files_and_links(self):
        S["check_parity"](self.stage)

    def test_each_required_file_must_be_a_regular_stage_leaf(self):
        for name in sorted(self.stage["files"]):
            with self.subTest(name=name):
                row = self.stage["files"].pop(name)
                with self.assertRaisesRegex(ValueError, "Qt parity files missing"):
                    S["check_parity"](self.stage | {"symlinks": {name: "elsewhere"}})
                self.stage["files"][name] = row

    def test_each_plugin_must_be_an_executable_linked_shared_object(self):
        for name in S["PLUGINS"]:
            with self.subTest(name=name):
                elf = self.stage["elf"][name]
                original_file = self.stage["files"][name]
                for change in ({"type": 2}, {"needed": []}):
                    self.stage["elf"][name] = elf | change
                    with self.assertRaisesRegex(ValueError, "linked to"):
                        S["check_parity"](self.stage)
                self.stage["elf"][name] = elf
                self.stage["files"][name] = {"mode": 0o644}
                with self.assertRaisesRegex(ValueError, "linked to"):
                    S["check_parity"](self.stage)
                self.stage["files"][name] = original_file


if __name__ == "__main__":
    unittest.main()
