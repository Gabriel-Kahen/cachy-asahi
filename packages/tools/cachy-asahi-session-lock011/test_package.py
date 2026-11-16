#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Stage the actual package function and inspect its exact payload; no install."""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--recipe-root", type=Path, default=HERE)
args, test_args = parser.parse_known_args()
RECIPE = args.recipe_root.resolve()
NAME = "cachy-asahi-session-lock"
EXPECTED = {f"usr/bin/{NAME}": (NAME, 0o755),
            f"usr/share/doc/{NAME}/README.md": ("README.md", 0o644),
            f"usr/share/doc/{NAME}/source-provenance.json": ("source-provenance.json", 0o644),
            f"usr/share/licenses/{NAME}/LICENSE": ("LICENSE", 0o644),
            f"usr/share/licenses/{NAME}/NOTICE": ("NOTICE", 0o644)}


class Package(unittest.TestCase):
    def test_source_checksums_and_srcinfo_match_actual_recipe(self):
        result = subprocess.run(["/usr/bin/makepkg", "--printsrcinfo"], cwd=RECIPE,
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, (RECIPE / ".SRCINFO").read_bytes())
        text = result.stdout.decode().splitlines()
        sources = [line.split(" = ", 1)[1] for line in text if line.startswith("\tsource = ")]
        hashes = [line.split(" = ", 1)[1] for line in text if line.startswith("\tsha256sums = ")]
        self.assertEqual(sources, [NAME, "test_session_lock.py", "test_idle.py", "test_package.py", "README.md", "source-provenance.json", "NOTICE", "LICENSE"])
        self.assertEqual(len(sources), len(hashes))
        for name, expected in zip(sources, hashes):
            self.assertEqual(hashlib.sha256((HERE / name).read_bytes()).hexdigest(), expected, name)
        self.assertNotIn("\tinstall = ", text)
        self.assertIn("\tdepends = swaylock>=1.8.6", text)
        self.assertIn("\tdepends = systemd>=248", text)
        self.assertIn("\tdepends = coreutils", text)
        self.assertIn("\toptdepends = swayidle>=1.8.0: explicit idle-timeout locking", text)

    def test_actual_package_function_exact_payload_bytes_modes_and_safe_help(self):
        with tempfile.TemporaryDirectory(prefix="session-lock-package-") as temporary:
            work = Path(temporary)
            stage = work / "stage"
            result = subprocess.run(["/usr/bin/bash", "--noprofile", "--norc", "-c",
                                     'set -e; source "$1/PKGBUILD"; srcdir=$2; pkgdir=$3; umask 022; package',
                                     "stage", str(RECIPE), str(HERE), str(stage)],
                                    cwd=work, env={"PATH": "/usr/bin", "LC_ALL": "C"}, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            paths = {str(path.relative_to(stage)) for path in stage.rglob("*") if not path.is_dir()}
            self.assertEqual(paths, set(EXPECTED))
            for name, (source, mode) in EXPECTED.items():
                path = stage / name
                self.assertFalse(path.is_symlink())
                self.assertEqual(path.read_bytes(), (HERE / source).read_bytes())
                self.assertEqual(path.stat().st_mode & 0o7777, mode)
            program = stage / "usr/bin" / NAME
            result = subprocess.run([str(program), "--help"], cwd=work,
                                    env={"PATH": "/absent", "PYTHONHOME": "/absent", "PYTHONPATH": "/absent"},
                                    capture_output=True, timeout=3)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(b"--ready-timeout", result.stdout)
            self.assertIn(b"{lock,suspend,idle}", result.stdout)
            result = subprocess.run([str(program), "suspend"], cwd=work, env={}, capture_output=True, timeout=3)
            self.assertEqual(result.returncode, 1)
            self.assertIn(b"XDG_RUNTIME_DIR", result.stderr)
            self.assertEqual({str(path.relative_to(stage)) for path in stage.rglob("*") if not path.is_dir()}, paths)


if __name__ == "__main__":
    unittest.main(argv=[__file__, *test_args])
