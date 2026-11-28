# SPDX-License-Identifier: MIT
"""Test the projected recipe, private tool aliases and dependency metadata."""

import json
import os
from pathlib import Path
from runpy import run_path
import shutil
import stat
import subprocess
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest


HERE = Path(__file__).resolve().parent
M = SimpleNamespace(**run_path(str(HERE / "package_metadata.py")))
RECIPE = HERE.parents[2] / "packages/port" / M.PACKAGE.removeprefix("cachy-asahi-")
PACMAN = shutil.which("pacman")
MAKEPKG = shutil.which("makepkg")
BASH = shutil.which("bash")
ALPM_DB_VERSION = Path("/var/lib/pacman/local/ALPM_DB_VERSION")


def metadata_rows(body, field):
    prefix = "\t" + field + " = "
    return [line.removeprefix(prefix) for line in body.decode().splitlines() if line.startswith(prefix)]


class MetadataProjection(unittest.TestCase):
    def setUp(self):
        self.recipe = (RECIPE / "PKGBUILD").read_bytes()
        self.srcinfo = (RECIPE / ".SRCINFO").read_bytes()

    def test_both_pinned_profiles_change_only_the_package_stage_and_version(self):
        q3 = self.recipe.replace(
            b'cmake -C "$srcdir/configure.cmake"',
            b'cmake -DCMAKE_AUTOGEN_PARALLEL:STRING=1 -C "$srcdir/configure.cmake"').replace(
            b'"$srcdir/smoke-build/qt612-smoke" || return\n',
            b'"$srcdir/smoke-build/qt612-smoke" || return\n'
            b"  printf '%s\\n' 'PASS_QT612_FAMILY_CHECK_GUI_SERVER'\n")
        for profile, recipe in (("canonical", self.recipe), ("q3", q3)):
            with self.subTest(profile=profile):
                changed = M.successor(recipe, self.srcinfo)
                self.assertEqual(changed["PKGBUILD"].count(M.NORMALIZE_TOOL_ALIASES), 1)
                self.assertEqual(changed["PKGBUILD"].count(M.PROJECTED_STAGE_CHECK), 1)
                self.assertIn(b'--license-manifest "$pkgdir/usr/share/licenses/$pkgname/source-notices.json"',
                              M.PROJECTED_STAGE_CHECK)
                reverted = changed["PKGBUILD"].replace(b"\npkgrel=2\n", b"\npkgrel=1\n").replace(
                    b'provides=("qt6-base=$pkgver-$pkgrel" ', b'provides=("qt6-base=$pkgver" ')
                reverted = reverted.replace(M.NORMALIZE_TOOL_ALIASES, b"").replace(
                    M.PROJECTED_STAGE_CHECK, M.STAGE_CHECK)
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


@unittest.skipUnless(BASH, "requires Bash for projected recipe fixture")
class ToolAliases(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.destdir = self.root / "package"
        self.bin = self.destdir / "usr/lib/qt6/bin"
        self.bin.mkdir(parents=True)
        self.public = self.destdir / "usr/bin/qmake6"
        self.public.parent.mkdir()
        self.public.symlink_to("../lib/qt6/bin/qmake")
        self.pairs = [(self.bin / tool, self.bin / (tool + "6")) for tool in ("qmake", "qtpaths")]
        self.recipe = self.root / "PKGBUILD.package"
        self.recipe.write_bytes(M.successor((RECIPE / "PKGBUILD").read_bytes(),
                                            (RECIPE / ".SRCINFO").read_bytes())["PKGBUILD"])

    def put_pairs(self, *, linked):
        for original, alias in self.pairs:
            original.write_bytes(original.name.encode() * 48)
            original.chmod(0o755)
            os.utime(original, ns=(1_720_000_000_000_000_000, 1_720_000_000_000_000_001))
            if linked:
                os.link(original, alias)
            else:
                shutil.copy2(original, alias)

    def normalize(self):
        return subprocess.run([BASH, "--noprofile", "--norc", "-euo", "pipefail", "-c",
                               'source "$1"; pkgdir=$2; _qt_normalize_tool_aliases',
                               "fixture", str(self.recipe), str(self.destdir)],
                              env={"PATH": os.defpath, "LC_ALL": "C", "BASH_ENV": "/dev/null"},
                              capture_output=True, timeout=10)

    def test_replaces_only_versioned_hardlinks_and_preserves_executable_metadata(self):
        self.put_pairs(linked=True)
        before = [alias.lstat() for _, alias in self.pairs]
        public = self.public.lstat()
        outcome = self.normalize()
        self.assertEqual(outcome.returncode, 0, outcome.stderr)
        for (original, alias), previous in zip(self.pairs, before, strict=True):
            left, right = original.lstat(), alias.lstat()
            self.assertEqual(alias.read_bytes(), original.read_bytes())
            self.assertEqual((left.st_nlink, right.st_nlink), (1, 1))
            self.assertEqual(left.st_ino, previous.st_ino)
            self.assertNotEqual(right.st_ino, previous.st_ino)
            self.assertEqual((right.st_mode, right.st_uid, right.st_gid, right.st_mtime_ns),
                             (previous.st_mode, previous.st_uid, previous.st_gid, previous.st_mtime_ns))
        self.assertEqual(self.public.lstat(), public)
        self.assertEqual(self.public.readlink(), Path("../lib/qt6/bin/qmake"))
        self.assertEqual({path.name for path in self.bin.iterdir()}, {path.name for pair in self.pairs for path in pair})

    def test_preserves_existing_independent_copies(self):
        self.put_pairs(linked=False)
        before = [alias.lstat().st_ino for _, alias in self.pairs]
        self.assertEqual(self.normalize().returncode, 0)
        self.assertEqual([alias.lstat().st_ino for _, alias in self.pairs], before)

    def test_external_third_link_refuses_before_normalizing_either_pair(self):
        self.put_pairs(linked=True)
        original, alias = self.pairs[1]
        external = self.root / "external"
        os.link(original, external)
        self.assertNotEqual(self.normalize().returncode, 0)
        self.assertEqual([pair[1].lstat().st_nlink for pair in self.pairs], [2, 3])
        self.assertEqual(alias.lstat().st_ino, external.lstat().st_ino)

    def test_symlink_refuses_before_normalizing_either_pair(self):
        self.put_pairs(linked=True)
        original, alias = self.pairs[1]
        alias.unlink()
        alias.symlink_to(original.name)
        self.assertNotEqual(self.normalize().returncode, 0)
        self.assertEqual(self.pairs[0][1].lstat().st_nlink, 2)
        self.assertTrue(alias.is_symlink())

    def test_independent_copy_with_byte_or_mode_drift_refuses(self):
        self.put_pairs(linked=True)
        original, alias = self.pairs[1]
        alias.unlink()
        shutil.copy2(original, alias)
        previous = alias.lstat().st_ino
        alias.write_bytes(b"x" * original.stat().st_size)
        self.assertNotEqual(self.normalize().returncode, 0)
        self.assertEqual(alias.lstat().st_ino, previous)
        self.assertNotEqual(alias.read_bytes(), original.read_bytes())
        alias.write_bytes(original.read_bytes())
        alias.chmod(0o754)
        self.assertNotEqual(self.normalize().returncode, 0)
        self.assertEqual(alias.lstat().st_ino, previous)
        self.assertEqual(stat.S_IMODE(alias.lstat().st_mode), 0o754)
        self.assertEqual(self.pairs[0][1].lstat().st_nlink, 2)


if __name__ == "__main__":
    unittest.main()
