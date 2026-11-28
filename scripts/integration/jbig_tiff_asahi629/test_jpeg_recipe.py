# SPDX-License-Identifier: MIT

import os
from pathlib import Path
from runpy import run_path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


R = run_path(str(Path(__file__).with_name("jpeg_recipe.py")))
I = run_path(str(Path(__file__).with_name("inputs.py")))
PARENT = Path(__file__).resolve().parents[3] / "scripts/build/project-libraries/recipes/libtiff/PKGBUILD"


class RecipeTest(unittest.TestCase):
    def test_source_pin_and_only_intended_recipe_delta(self):
        original = PARENT.read_bytes()
        self.assertEqual(R["pin"](original), R["PARENT_PIN"])
        result = R["recipe"](original)
        self.assertEqual(R["pin"](result), R["PKGBUILD_PIN"])
        self.assertEqual(set(result.splitlines()) - set(original.splitlines()), {
            b"pkgrel=1.2",
            b"depends=(glibc libstdc++ 'jbigkit=2.2' libdeflate libjpeg-turbo 'libjpeg.so=8-64' libwebp xz zlib zstd)",
        })
        self.assertEqual(result.replace(b"pkgrel=1.2\n", b"pkgrel=1.1\n").replace(b" 'libjpeg.so=8-64'", b""),
                         original)
        with self.assertRaisesRegex(ValueError, "Exact historical"):
            R["recipe"](original + b"# drift\n")
        self.assertEqual(set(R["source_specs"](I["read"])), R["FILES"])

    def test_copy_and_refusal_preserve_historical_inputs(self):
        fixture = {name: name.encode() for name in R["FILES"]} | {"PKGBUILD": PARENT.read_bytes()}
        specs = {name: R["pin"](body) for name, body in fixture.items()}
        action = R["place"]
        with TemporaryDirectory() as work, patch.dict(action.__globals__, dict(source_specs=lambda read: specs)):
            folder = Path(work)
            origin, output = folder / "original", folder / "output"
            origin.mkdir()
            for name, body in fixture.items():
                (origin / name).write_bytes(body)
            with self.assertRaisesRegex(ValueError, "outside the historical"):
                action(origin, origin / "wrong")
            result = action(origin, output)
            self.assertEqual(result["files"], specs | {"PKGBUILD": R["PKGBUILD_PIN"]})
            self.assertEqual((result["archive"], result["build"], result["archive_admission"]),
                             (None, "NOT RUN", "REBUILD_AND_PIN_REQUIRED"))
            self.assertEqual({path.name: path.read_bytes() for path in origin.iterdir()}, fixture)
            self.assertEqual({path.name: path.read_bytes() for path in output.iterdir()},
                             fixture | {"PKGBUILD": R["recipe"](fixture["PKGBUILD"])})
            with self.assertRaises(FileExistsError):
                action(origin, output)
            (origin / "stage-source.py").write_bytes(b"tampered")
            rejected = folder / "rejected"
            with self.assertRaises(ValueError):
                action(origin, rejected)
            self.assertFalse(rejected.exists())
            (origin / "extra").touch()
            with self.assertRaisesRegex(ValueError, "seven-file"):
                action(origin, rejected)
            self.assertFalse(rejected.exists())

    @unittest.skipUnless(shutil.which("makepkg") and os.geteuid() != 0, "requires a non-root Arch makepkg host")
    def test_makepkg_source_metadata(self):
        with TemporaryDirectory() as work:
            root = Path(work)
            (root / "PKGBUILD").write_bytes(R["recipe"](PARENT.read_bytes()))
            lines = subprocess.run(["makepkg", "--printsrcinfo"], cwd=root, check=True, capture_output=True,
                                   timeout=20, text=True).stdout.splitlines()
            self.assertEqual(lines.count("\tpkgrel = 1.2"), 1)
            self.assertEqual(lines.count("\tdepends = libjpeg-turbo"), 1)
            self.assertEqual(lines.count("\tdepends = libjpeg.so=8-64"), 1)
            self.assertEqual({child.name for child in root.iterdir()}, {"PKGBUILD"})


if __name__ == "__main__":
    unittest.main()
