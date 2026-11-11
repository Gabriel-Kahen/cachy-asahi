#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors.
"""Temporary-fixture tests; never launch a helper or write caller configuration."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


CHECKER = Path(__file__).with_name("check-sync.py").resolve()


class SyncTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cachy-asahi-sync-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.canonical = self.root / "scripts/setup/helper.py"
        self.copy = self.root / "packages/settings/cachy-asahi-setup/cachy-asahi-setup"
        for path in (self.canonical, self.copy):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"raise RuntimeError('the checker must never execute this helper')\n")
        self.license = self.root / "LICENSE"
        self.license.write_bytes(b"fixture license\n")
        self.copy.with_name("LICENSE").write_bytes(self.license.read_bytes())
        self.record = {
            "canonical_path": "scripts/setup/helper.py",
            "packaged_source": "cachy-asahi-setup",
            "sha256": hashlib.sha256(self.canonical.read_bytes()).hexdigest(),
            "license_sha256": hashlib.sha256(self.license.read_bytes()).hexdigest(),
        }
        self.write_record()

    def write_record(self):
        self.copy.with_name("source-provenance.json").write_text(json.dumps(self.record))

    def run_check(self, success=True, default=False):
        checker = CHECKER
        arguments = ["--canonical", str(self.canonical), "--copy", str(self.copy), "--license", str(self.license)]
        if default:
            checker = self.copy.with_name("check-sync.py")
            checker.write_bytes(CHECKER.read_bytes())
            arguments = []
        env = dict(os.environ, HOME=str(self.root / "home"), XDG_CONFIG_HOME=str(self.root / "config"),
                   XDG_DATA_HOME=str(self.root / "data"), XDG_CACHE_HOME=str(self.root / "cache"),
                   PYTHONDONTWRITEBYTECODE="1")
        before = {path: path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
        result = subprocess.run([sys.executable, "-B", str(checker), *arguments],
                                cwd=self.root, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0 if success else 1, result.stdout + result.stderr)
        self.assertIn("PASS:" if success else "FAIL:", result.stdout + result.stderr)
        self.assertFalse(list(self.root.rglob("__pycache__")))
        self.assertFalse((self.root / "home").exists())
        self.assertEqual(before, {path: path.read_bytes() for path in self.root.rglob("*") if path.is_file()})
        return result.stderr

    def test_explicit_and_default_success(self):
        self.run_check()
        self.run_check(default=True)

    def test_canonical_drift(self):
        self.canonical.write_bytes(b"drift\n")
        self.assertIn("canonical helper", self.run_check(False))

    def test_packaged_drift(self):
        self.copy.write_bytes(b"drift\n")
        self.assertIn("packaged helper", self.run_check(False))

    def test_missing_inputs(self):
        for path in (self.canonical, self.copy, self.license, self.copy.with_name("LICENSE"),
                     self.copy.with_name("source-provenance.json")):
            original = path.read_bytes()
            path.unlink()
            self.run_check(False)
            path.write_bytes(original)

    def test_stale_hashes(self):
        for key in ("sha256", "license_sha256"):
            original = self.record[key]
            self.record[key] = "0" * 64
            self.write_record()
            self.run_check(False)
            self.record[key] = original
        self.write_record()

    def test_license_drift(self):
        for path in (self.license, self.copy.with_name("LICENSE")):
            original = path.read_bytes()
            path.write_bytes(b"different grant\n")
            self.run_check(False)
            path.write_bytes(original)

    def test_unsafe_paths(self):
        for name in ("/scripts/setup/helper.py", "../scripts/setup/helper.py", "scripts/setup/../helper.py",
                     "scripts/setup", "scripts//setup/helper.py", "scripts/setup/./helper.py", "scripts\\setup\\helper.py", "other/helper.py"):
            self.record["canonical_path"] = name
            self.write_record()
            self.assertIn("unsafe canonical_path", self.run_check(False))

    def test_default_symlink_escape(self):
        outside = self.root / "outside.py"
        outside.write_bytes(self.canonical.read_bytes())
        self.canonical.unlink()
        # The synthetic repository is a subdirectory of this fixture.
        repo = self.root / "repo"
        package = repo / "packages/settings/cachy-asahi-setup"
        package.mkdir(parents=True)
        for name in ("LICENSE", "source-provenance.json", "cachy-asahi-setup"):
            (package / name).write_bytes(self.copy.with_name(name).read_bytes())
        (repo / "LICENSE").write_bytes(self.license.read_bytes())
        target = repo / "scripts/setup/helper.py"
        target.parent.mkdir(parents=True)
        target.symlink_to(outside)
        self.copy = package / "cachy-asahi-setup"
        self.assertIn("outside the repository", self.run_check(False, default=True))

    def test_bad_provenance(self):
        for key, value in (("packaged_source", "other"), ("sha256", "bad"), ("license_sha256", None)):
            original = self.record[key]
            self.record[key] = value
            self.write_record()
            self.run_check(False)
            self.record[key] = original
        for text in ("{", "[]"):
            self.copy.with_name("source-provenance.json").write_text(text)
            self.run_check(False)


if __name__ == "__main__":
    unittest.main()
