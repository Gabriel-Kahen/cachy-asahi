# SPDX-License-Identifier: MIT
"""Pure controls for the unissued installed Qtbase source plan."""

import os
from pathlib import Path
from runpy import run_path
import stat
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch


F = SimpleNamespace(**run_path(str(Path(__file__).with_name("preflight.py"))))
G = F.make_plan.__globals__


def inventory():
    packages = {f"fixture{i:03}": "1-1" for i in range(353)}
    packages |= {"md4c": "0.5.3-1", "wayland": "1.26.0-1", "libglvnd": "1.7.0-3"}
    return packages


def lock(packages):
    return "".join(f"{name} {version}\n" for name, version in sorted(packages.items())).encode()


class Preflight(unittest.TestCase):
    def setUp(self):
        self.files = F.recipe_inputs()
        self.raw = lock(inventory())
        self.nonce = "b" * 32

    def plan(self, raw=None):
        if raw is None:
            raw = self.raw
        with patch.dict(G, Q3_INVENTORY=F.T.pin(raw)):
            return F.make_plan(raw, self.nonce, {"fixture": True}, self.files)

    def test_only_selected_package_changes_the_clean_lifecycle(self):
        still_base = F.T.pin(self.raw)
        installed = F.T.pin(lock(inventory() | {F.M.PACKAGE: F.M.VERSION}))
        plan = self.plan()
        self.assertIsNone(plan["authority"])
        self.assertEqual([row["inventory"] for row in plan["stages"]],
                         [still_base, installed, installed, still_base, installed, still_base])
        self.assertEqual(plan["package_manager"]["prepare_expected"], f"{F.M.PACKAGE} 6.12.0-2")
        self.assertNotIn("-Rns", str(plan))
        self.assertNotIn("--nodeps", str(plan))
        config = plan["package_manager"]["configuration"]
        self.assertIn("\nSigLevel = Required TrustedOnly\n", config)
        self.assertIn("\nLocalFileSigLevel = Required TrustedOnly\n", config)
        self.assertTrue(plan["package"]["signature"].endswith(".pkg.tar.xz.sig"))

    def test_stage_matches_the_guest_input_names_and_refuses_overwrite(self):
        plan = self.plan()
        with TemporaryDirectory() as parent, patch.dict(G, Q3_INVENTORY=F.T.pin(self.raw)):
            output = Path(parent) / "staged"
            previous = os.umask(0o077)
            try:
                receipt = F.stage_plan(output, plan, self.raw, self.files)
            finally:
                os.umask(previous)
            actual = {path.relative_to(output).as_posix(): F.T.pin(path.read_bytes())
                      for path in output.rglob("*") if path.is_file()}
            self.assertEqual(actual, receipt["files"])
            self.assertEqual(receipt["status"], "PASS_UNISSUED_INSTALLED_INPUTS_ONLY")
            self.assertIsNone(receipt["authority"])
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            for name in ("inputs", "inputs/consumer", "work"):
                self.assertEqual(stat.S_IMODE((output / name).stat().st_mode), 0o755)
            self.assertEqual((output / "inputs/PLAN.json").read_bytes(), F.T.encoded(plan))
            self.assertEqual(set(actual), {"inputs/PLAN.json", "inputs/expected356.lock", "inputs/loader_probe.py",
                                          "inputs/consumer/CMakeLists.txt", "inputs/consumer/smoke.cpp", "work/pacman.conf"})
            with self.assertRaisesRegex(ValueError, "Fresh private staging"):
                F.stage_plan(output, plan, self.raw, self.files)

    def test_exact_provider_version_and_original_payload_interfaces(self):
        plan = self.plan()
        package = plan["package"]
        self.assertEqual(package["staged_recipe"], F.Q.file_record(F.M.RECIPE_PINS[F.Q.OPERANDS["PKGBUILD"]][1]))
        self.assertEqual(len(package["sonames"]), 18)
        self.assertEqual(len(package["plugins"]), 12)
        self.assertEqual(len(package["tools"]), 5)
        self.assertIn("libwayland-server.so=0-64", package["depends"])
        for stage in [row for row in plan["stages"] if row["state"] == "installed"]:
            self.assertIn("qt6-base=6.12.0-2", stage["dependency_check"])
            self.assertEqual(stage["version_refusal"][-1], "qt6-base=6.12.0-3")
        self.assertEqual(set(plan["negative_trials"]), {"tampered_signature", "unknown_key"})
        self.assertTrue(all(row["clone"] == "separate-fresh-Q3-child" for row in plan["negative_trials"].values()))

    def test_refuses_wrong_pin_duplicate_wrong_provider_and_conflict(self):
        with self.assertRaisesRegex(ValueError, "Exact Q3"):
            F.make_plan(self.raw, self.nonce, {}, self.files)
        bad = self.raw.splitlines(keepends=True)
        bad[1] = bad[0]
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.plan(b"".join(bad))
        wrong = inventory() | {"wayland": "1.26.0-2"}
        with self.assertRaisesRegex(ValueError, "Exact Q3"):
            self.plan(lock(wrong))
        conflicting = inventory() | {"qt6-base": "6.12.0-3"}
        conflicting.pop("fixture000")
        with self.assertRaisesRegex(ValueError, "no-Qtbase"):
            self.plan(lock(conflicting))

    def test_installed_consumer_uses_installed_private_headers_and_normal_loader(self):
        installed = F.consumer_cmake(self.files["SmokeCMakeLists.txt"])
        plan = self.plan()
        self.assertIn(b'set(QT612_BUILD_TREE "/usr")', installed)
        self.assertIn(b'/include/qt6/QtWaylandGlobal', installed)
        self.assertIn(b'6.12.0 EXACT REQUIRED', installed)
        self.assertIn(b'IMPORTED_LOCATION', installed)
        self.assertEqual(plan["consumer"]["files"]["CMakeLists.txt"], F.T.pin(installed))
        self.assertIn("-DCMAKE_SKIP_RPATH=ON", plan["consumer"]["configure"])
        self.assertNotIn("LD_LIBRARY_PATH", plan["consumer"]["environment"])
        with self.assertRaises(ValueError):
            F.consumer_cmake(self.files["SmokeCMakeLists.txt"].replace(b'/include/QtWaylandGlobal', b'/other'))


if __name__ == "__main__":
    unittest.main(verbosity=2)
