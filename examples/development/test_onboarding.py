# SPDX-License-Identifier: MIT
"""Exercise the ordinary-user CLI with real Git, cc and scripted Vim."""
import hashlib
import json
import os
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

    def cli(self, *args, code=0, env=None):
        result = subprocess.run([sys.executable, "-I", "-B", str(HERE / "onboarding.py"), *args],
                                capture_output=True, text=True, env=env)
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

        # A second operator can check copies without the producer's clone, tools or executable runs.
        copied = self.root / "operator copy"
        evidence = self.workspace / "evidence"
        shutil.copytree(evidence, copied)
        self.workspace.rename(self.root / "moved workspace")
        self.source.rename(self.root / "moved source repository")
        selected = {json.loads((path / "report.json").read_bytes())["status"]: path
                    for path in copied.glob("rebuild-*")}
        for directory in (copied / "baseline", selected["PASS"]):
            (directory / "hello").chmod(0o600)
        result = self.cli("verify", selected["PASS"], env=os.environ | {"PATH": ""})
        report = json.loads(result.stdout)
        self.assertEqual((report["status"], report["scope"], report["source_revision"]),
                         ("PASS", "retained-build-evidence", self.revision))
        self.assertEqual(report["baseline_report_sha256"],
                         hashlib.sha256((copied / "baseline/report.json").read_bytes()).hexdigest())
        self.assertEqual(report["rebuild_report_sha256"],
                         hashlib.sha256((selected["PASS"] / "report.json").read_bytes()).hexdigest())
        self.assertIn("successful rebuild report", self.cli("verify", selected["FAILED"], code=2).stderr)
        (selected["PASS"] / "hello.c").write_bytes(b"changed saved source")
        self.assertIn("Saved rebuild hello.c differs", self.cli("verify", selected["PASS"], code=2).stderr)

    def test_rebuild_requires_retained_baseline_artifacts(self):
        self.cli("prepare", self.workspace, "--source", self.source, "--revision", self.revision)
        clone = self.workspace / "checkout/examples/development/hello.c"
        clone.write_bytes(self.original.replace(b"Hello from cachy-asahi", b"Hello after editing"))
        evidence = self.workspace / "evidence"
        binary = evidence / "baseline/hello"
        saved = binary.read_bytes()
        binary.unlink()
        result = self.cli("rebuild", self.workspace, "--expect", "Hello after editing", code=2)
        self.assertIn("baseline/hello", result.stderr)
        binary.write_bytes(saved + b"changed saved executable")
        result = self.cli("rebuild", self.workspace, "--expect", "Hello after editing", code=2)
        self.assertIn("Saved baseline hello differs", result.stderr)
        binary.unlink()
        binary.symlink_to(clone)
        self.cli("rebuild", self.workspace, "--expect", "Hello after editing", code=2)
        self.assertEqual(list(evidence.iterdir()), [evidence / "baseline"])

    def test_unpinned_example_refuses_before_creating_workspace(self):
        self.example.write_bytes(self.original + b"// different committed source\n")
        self.git("add", ".")
        self.git("commit", "-qm", "change pinned example")
        result = self.cli("prepare", self.workspace, "--source", self.source, code=2)
        self.assertIn("pinned development example", result.stderr)
        self.assertFalse(self.workspace.exists())

    def test_prepare_fetches_requested_commit_with_unborn_source_head(self):
        tip = self.git("rev-parse", "HEAD").strip()
        self.git("symbolic-ref", "HEAD", "refs/heads/unborn")
        self.cli("prepare", self.workspace, "--source", self.source, "--revision", self.revision)

        baseline, = self.reports()
        self.assertEqual(baseline["checkout_head"], self.revision)
        checkout = self.workspace / "checkout"
        indexes = list((checkout / ".git/objects/pack").glob("*.idx"))
        self.assertTrue(indexes)
        packs = subprocess.check_output(["git", "verify-pack", "-v", *indexes], text=True)
        self.assertIn(self.revision, packs)
        self.assertNotIn(tip, packs)


if __name__ == "__main__":
    unittest.main()
