# SPDX-License-Identifier: MIT
"""Exercise the ordinary-user CLI with real Git, cc and scripted Vim."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

HERE = Path(__file__).resolve().parent


@unittest.skipUnless(all(shutil.which(tool) for tool in ("git", "cc", "vim")), "requires Git, cc and Vim")
class OnboardingTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.source = self.root / "source repository"
        self.workspace = self.root / "exercise workspace"
        self.source.mkdir()
        self.git("init", "-q")
        self.example = self.source / "examples/development/hello.c"
        self.example.parent.mkdir(parents=True)
        self.original = (HERE / "hello.c").read_bytes()
        self.example.write_bytes(self.original)
        self.git("add", ".")
        self.git("commit", "-qm", "pin the project example")
        self.revision = self.git("rev-parse", "HEAD").strip()
        self.git("commit", "--allow-empty", "-qm", "independent newer source tip")

    def git(self, *args):
        return subprocess.check_output([
            "git", "-C", str(self.source), "-c", "user.name=Onboarding Test",
            "-c", "user.email=onboarding@invalid.example", "-c", "commit.gpgsign=false",
            "-c", "core.hooksPath=/dev/null", *args,
        ], text=True)

    def cli(self, *args, code=0):
        result = subprocess.run([sys.executable, "-I", "-B", str(HERE / "onboarding.py"), *args],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return result

    def reports(self):
        return [json.loads(path.read_text()) for path in
                sorted((self.workspace / "evidence").glob("*/report.json"))]

    def test_edit_rebuild_and_failed_rebuild_preserve_both_sources(self):
        dirty = self.original + b"// Work in the original tree remains mine.\n"
        self.example.write_bytes(dirty)
        self.cli("prepare", self.workspace, "--source", self.source, "--revision", self.revision)
        baseline, = self.reports()
        self.assertEqual((baseline["source_revision"], baseline["checkout_head"]), (self.revision, self.revision))
        self.assertEqual(baseline["run"]["stdout"], "Hello from cachy-asahi\n")
        self.assertEqual(baseline["compile"]["argv"][1:6],
                         ["-Wall", "-Wextra", "-Werror", "-O2", "examples/development/hello.c"])
        result = self.cli("rebuild", self.workspace, "--expect", "Hello from cachy-asahi", code=2)
        self.assertIn("Save an edit", result.stderr)

        clone = self.workspace / "checkout/examples/development/hello.c"
        subprocess.run(["vim", "-Nu", "NONE", "-n", "-i", "NONE", "-es", str(clone),
                        "-c", "%s/Hello from cachy-asahi/Hello after editing/", "-c", "wq"], check=True)
        edited = clone.read_bytes()
        self.cli("rebuild", self.workspace, "--expect", "Hello after editing")
        clone.write_bytes(edited + b"unexpected syntax\n")
        broken = clone.read_bytes()
        self.cli("rebuild", self.workspace, "--expect", "Hello after editing", code=1)
        self.assertEqual(clone.read_bytes(), broken)
        self.assertEqual(self.example.read_bytes(), dirty)
        outcomes = {report["status"]: report for report in self.reports() if report["phase"] == "rebuild"}
        self.assertEqual(outcomes["PASS"]["run"]["stdout"], "Hello after editing\n")
        self.assertNotEqual(outcomes["PASS"]["source_sha256"], baseline["source_sha256"])
        self.assertNotEqual(outcomes["PASS"]["binary_sha256"], baseline["binary_sha256"])
        self.assertIsNone(outcomes["FAILED"]["run"])

    def test_unpinned_example_refuses_before_creating_workspace(self):
        self.example.write_bytes(self.original + b"// different committed source\n")
        self.git("add", ".")
        self.git("commit", "-qm", "change pinned example")
        result = self.cli("prepare", self.workspace, "--source", self.source, code=2)
        self.assertIn("pinned development example", result.stderr)
        self.assertFalse(self.workspace.exists())


if __name__ == "__main__":
    unittest.main()
