#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Source pins and exact package-function staging; no install or desktop launch."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--recipe-root", type=Path, default=HERE)
args, test_args = parser.parse_known_args()
RECIPE = args.recipe_root.resolve()
NAME = "cachy-asahi-hyprland-settings"
SOURCES = ["hyprland.lua", "waybar.json", "waybar.css", "mako.conf", "README.md", "NOTICE", "LICENSE",
           "cachy-asahi-screenshot", "source-provenance.json", "test_settings.py", "test_package.py"]
EXPECTED = {"usr/bin/cachy-asahi-screenshot": ("cachy-asahi-screenshot", 0o755),
            **{f"usr/share/cachy-asahi/hyprland/{name}": (name, 0o644)
               for name in ("hyprland.lua", "waybar.json", "waybar.css", "mako.conf")},
            **{f"usr/share/doc/{NAME}/{name}": (name, 0o644) for name in ("README.md", "source-provenance.json")},
            **{f"usr/share/licenses/{NAME}/{name}": (name, 0o644) for name in ("NOTICE", "LICENSE")}}


class Package(unittest.TestCase):
    def test_source_checksums_metadata_and_helper_dependency_bounds(self):
        result = subprocess.run(["/usr/bin/makepkg", "--printsrcinfo"], cwd=RECIPE,
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, (RECIPE / ".SRCINFO").read_bytes())
        lines = result.stdout.decode().splitlines()
        sources = [line.split(" = ", 1)[1] for line in lines if line.startswith("\tsource = ")]
        hashes = [line.split(" = ", 1)[1] for line in lines if line.startswith("\tsha256sums = ")]
        self.assertEqual(sources, SOURCES)
        self.assertEqual(len(sources), len(hashes))
        for name, expected in zip(sources, hashes):
            self.assertEqual(hashlib.sha256((HERE / name).read_bytes()).hexdigest(), expected, name)
        self.assertIn("\tpkgver = 0.1.1", lines)
        self.assertIn("\tpkgrel = 1", lines)
        provenance = json.loads((HERE / "source-provenance.json").read_text())
        for dependency in provenance["session_lock_dependency"]:
            self.assertIn(f"\tdepends = {dependency}", lines)
        self.assertIn("\tdepends = hyprland>=0.56.2", lines)
        self.assertIn("\tdepends = hyprland<0.57.0", lines)
        self.assertFalse(any(line.startswith("\tinstall = ") for line in lines))
        for tool in ("grim", "slurp", "waybar", "mako"):
            self.assertTrue(any(line.startswith(f"\toptdepends = {tool}:") for line in lines))

    def test_actual_package_function_exact_payload_bytes_modes_and_safe_screenshot_help(self):
        with tempfile.TemporaryDirectory(prefix="settings011-package-") as temporary:
            work = Path(temporary)
            stage = work / "stage"
            result = subprocess.run(["/usr/bin/bash", "--noprofile", "--norc", "-c",
                                     'set -e; source "$1/PKGBUILD"; srcdir=$2; pkgdir=$3; umask 022; package',
                                     "stage", str(RECIPE), str(HERE), str(stage)],
                                    cwd=work, env={"PATH": "/usr/bin", "LC_ALL": "C"}, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            paths = {str(path.relative_to(stage)) for path in stage.rglob("*") if not path.is_dir()}
            self.assertEqual(paths, set(EXPECTED))
            self.assertEqual(len(paths), 9)
            for name, (source, mode) in EXPECTED.items():
                path = stage / name
                self.assertFalse(path.is_symlink())
                self.assertEqual(path.read_bytes(), (HERE / source).read_bytes())
                self.assertEqual(path.stat().st_mode & 0o7777, mode)
            result = subprocess.run(["/usr/bin/python3", "-I", "-B", str(stage / "usr/bin/cachy-asahi-screenshot"), "--help"],
                                    cwd=work, env={"PATH": "/absent"}, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(b"full", result.stdout)
            self.assertIn(b"region", result.stdout)
            self.assertFalse((stage / "usr/bin/cachy-asahi-session-lock").exists(),
                             "settings must depend on the helper, not duplicate its ownership")
            self.assertFalse(any(path.name == "__pycache__" for path in stage.rglob("*")))


if __name__ == "__main__":
    unittest.main(argv=[__file__, *test_args])
