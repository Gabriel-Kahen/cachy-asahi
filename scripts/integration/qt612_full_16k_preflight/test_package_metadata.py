# SPDX-License-Identifier: MIT
"""Test the metadata projection and libalpm dependency resolution without a transaction."""

import json
from pathlib import Path
from runpy import run_path
import shutil
import subprocess
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest


HERE = Path(__file__).resolve().parent
M = SimpleNamespace(**run_path(str(HERE / "package_metadata.py")))
RECIPE = HERE.parents[2] / "packages/port" / M.PACKAGE.removeprefix("cachy-asahi-")
PACMAN = shutil.which("pacman")
MAKEPKG = shutil.which("makepkg")
ALPM_DB_VERSION = Path("/var/lib/pacman/local/ALPM_DB_VERSION")


def metadata_rows(body, field):
    prefix = "\t" + field + " = "
    return [line.removeprefix(prefix) for line in body.decode().splitlines() if line.startswith(prefix)]


class MetadataProjection(unittest.TestCase):
    def setUp(self):
        self.recipe = (RECIPE / "PKGBUILD").read_bytes()
        self.srcinfo = (RECIPE / ".SRCINFO").read_bytes()

    def test_both_pinned_profiles_change_only_the_advertised_version(self):
        q3 = self.recipe.replace(
            b'cmake -C "$srcdir/configure.cmake"',
            b'cmake -DCMAKE_AUTOGEN_PARALLEL:STRING=1 -C "$srcdir/configure.cmake"').replace(
            b'"$srcdir/smoke-build/qt612-smoke" || return\n',
            b'"$srcdir/smoke-build/qt612-smoke" || return\n'
            b"  printf '%s\\n' 'PASS_QT612_FAMILY_CHECK_GUI_SERVER'\n")
        for profile, recipe in (("canonical", self.recipe), ("q3", q3)):
            with self.subTest(profile=profile):
                changed = M.successor(recipe, self.srcinfo)
                reverted = changed["PKGBUILD"].replace(b"\npkgrel=2\n", b"\npkgrel=1\n").replace(
                    b'provides=("qt6-base=$pkgver-$pkgrel" ', b'provides=("qt6-base=$pkgver" ')
                self.assertEqual(reverted, recipe)
                old = metadata_rows(self.srcinfo, "provides")
                new = metadata_rows(changed[".SRCINFO"], "provides")
                self.assertEqual(new, ["qt6-base=6.12.0-2", *old[1:]])
                self.assertEqual(metadata_rows(changed[".SRCINFO"], "pkgrel"), ["2"])
                receipt = json.loads(changed["receipt"])
                self.assertEqual((receipt["profile"], receipt["version"], receipt["authority"]),
                                 (profile, M.VERSION, None))
                self.assertEqual(receipt["outputs"]["PKGBUILD"], M.describe(changed["PKGBUILD"]))

    def test_source_drift_refuses(self):
        for recipe, srcinfo in ((self.recipe + b"\n", self.srcinfo), (self.recipe, self.srcinfo + b"\n")):
            with self.assertRaisesRegex(ValueError, "exact canonical or Q3"):
                M.successor(recipe, srcinfo)

    @unittest.skipUnless(MAKEPKG, "requires makepkg metadata-only mode")
    def test_generated_srcinfo_matches_makepkg(self):
        changed = M.successor(self.recipe, self.srcinfo)
        with TemporaryDirectory() as temp:
            (Path(temp) / "PKGBUILD").write_bytes(changed["PKGBUILD"])
            result = subprocess.run([MAKEPKG, "--printsrcinfo"], cwd=temp, capture_output=True, check=True, timeout=10)
            self.assertEqual(result.stdout, changed[".SRCINFO"])

    @unittest.skipUnless(PACMAN and ALPM_DB_VERSION.is_file(), "requires libalpm and its local DB format")
    def test_alpm_exact_official_dependency_refuses_but_generic_resolves(self):
        evidence = M.successor(self.recipe, self.srcinfo)
        with TemporaryDirectory() as temp:
            base = Path(temp)
            (base / "root").mkdir()
            local = base / "db/local"
            local.mkdir(parents=True)
            (local / "ALPM_DB_VERSION").write_bytes(ALPM_DB_VERSION.read_bytes())

            def observe(srcinfo, dep):
                provides = "\n".join(metadata_rows(srcinfo, "provides"))
                version = metadata_rows(srcinfo, "pkgver")[0] + "-" + metadata_rows(srcinfo, "pkgrel")[0]
                desc = local / f"{M.PACKAGE}-{version}" / "desc"
                desc.parent.mkdir()
                desc.write_text(f"%NAME%\n{M.PACKAGE}\n\n%VERSION%\n{version}\n\n"
                                f"%ARCH%\naarch64\n\n%PROVIDES%\n{provides}\n\n")
                outcome = subprocess.run([PACMAN, "--config", "/dev/null", "--root", str(base / "root"),
                                          "--dbpath", str(local.parent), "-T", dep],
                                         capture_output=True, text=True, timeout=10)
                desc.unlink()
                desc.parent.rmdir()
                self.assertEqual(outcome.stderr, "")
                return outcome.returncode, outcome.stdout

            exact = "qt6-base=6.12.0-3"
            self.assertEqual(observe(self.srcinfo, exact), (0, ""))
            self.assertEqual(observe(evidence[".SRCINFO"], exact), (127, exact + "\n"))
            for generic in ("qt6-base", "qt6-base=6.12.0", "qt6-base>=6.12.0"):
                with self.subTest(generic=generic):
                    self.assertEqual(observe(evidence[".SRCINFO"], generic), (0, ""))


if __name__ == "__main__":
    unittest.main()
