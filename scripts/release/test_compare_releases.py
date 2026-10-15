#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Signed synthetic bundles, real ALPM ordering, no host installation or trust changes."""
import argparse
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


c = module("compare_releases", "compare_releases.py")
fixture = module("comparison_fixture", "test_release.py")
fixture.r = c.r


class ComparisonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.ReleaseTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        fixture.ReleaseTests.tearDownClass.__func__(cls)

    setUp = fixture.ReleaseTests.setUp
    put = fixture.ReleaseTests.put
    ref = fixture.ReleaseTests.ref
    save_spec = fixture.ReleaseTests.save_spec

    def snapshot(self):
        return {str(p.relative_to(self.root)): ("link", os.readlink(p)) if p.is_symlink() else
                ("file", p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns)
                for p in self.root.rglob("*") if p.is_file() or p.is_symlink()}

    def bundle(self, rid, packages=None, runtime="2", kernel="1", extra_base=None, models=None, dependency="virtual-runtime>=2"):
        packages = packages or [("fixture", "1.0-1", b"fixture\n")]
        base = c.r.load(self.inputs / "base.json")
        base["snapshot_id"] = rid + "-base"
        for row in base["packages"]:
            row["version"] = runtime if row["name"] == "runtime" else kernel
            if row["name"] == "runtime":row["provides"] = ["virtual-runtime=" + runtime]
        if extra_base:base["packages"].append(extra_base)
        self.put("base.json", base)
        self.release_spec.update(release_id=rid, base=dict(self.ref("base.json"), snapshot_id=base["snapshot_id"]), packages=[])
        self.release_spec["policy"].update(selected_packages=[p[0] for p in packages],
            supported_models=models or ["m2-air-13"], coordinated_sets=[
                {"name": "synthetic-runtime", "versions": {"runtime": runtime}},
                {"name": "synthetic-platform", "versions": {"linux-asahi": kernel}}])
        for name, version, payload in packages:
            filename = name + "-" + version.replace(":", "_") + "-any.pkg.tar.gz"
            archive = self.inputs / filename
            metadata = (f"pkgname = {name}\npkgver = {version}\narch = any\nlicense = MIT\n"
                        f"depend = {dependency}\n")
            with tarfile.open(archive, "w:gz") as tar:
                for path, data in {".PKGINFO": metadata.encode(), "usr/share/" + name + "/config": payload}.items():
                    entry = tarfile.TarInfo(path);entry.size = len(data);entry.mtime = 1700000000
                    tar.addfile(entry, io.BytesIO(data))
            provenance = c.r.load(self.inputs / "provenance.json")
            provenance.update(artifact_sha256=c.r.sha(archive), package={"name": name, "version": version, "arch": "any"})
            provenance["build"]["snapshot_id"] = base["snapshot_id"]
            self.put(name + "-provenance.json", provenance)
            self.release_spec["packages"].append({"artifact": self.ref(filename), "provenance": self.ref(name + "-provenance.json")})
        self.save_spec()
        return Path(c.r.stage(argparse.Namespace(spec=str(self.spec_path)), self.root, self.key, self.env)["path"])

    def compare(self, before, after):
        snapshot = self.snapshot()
        result = c.compare_releases(before, after, self.key, self.env)
        self.assertEqual(self.snapshot(), snapshot)
        return result

    def refused(self, before, after, **kwargs):
        snapshot = self.snapshot()
        with self.assertRaises((c.r.Error, OSError, ValueError)):
            c.compare_releases(before, after, kwargs.get("key", self.key), self.env)
        self.assertEqual(self.snapshot(), snapshot)

    def test_signed_package_add_remove_upgrade_and_natural_order(self):
        before = self.bundle("old", [("kept", "1.9-1", b"old"), ("removed", "1-1", b"removed")])
        after = self.bundle("new", [("kept", "1.10-1", b"new"), ("added", "1-1", b"added")])
        (self.root / "stable").mkdir();(self.root / "stable/current").symlink_to("untouched")
        result = self.compare(before, after)
        self.assertEqual([(p["name"], p["change"]) for p in result["packages"]],
                         [("added", "added"), ("kept", "upgraded"), ("removed", "removed")])
        self.assertFalse(result["stable_eligibility_checked"])
        self.assertTrue(result["before"]["synthetic"])
        self.assertEqual(result["before"]["release_sha256"], c.r.sha(before / "release.json"))

    def test_epoch_and_pkgrel_downgrades_use_vercmp(self):
        before = self.bundle("old", [("epoch", "2:1.0-1", b"old"), ("rel", "1.0-10", b"old")])
        after = self.bundle("new", [("epoch", "1:99.0-1", b"new"), ("rel", "1.0-2", b"new")])
        self.assertEqual([p["change"] for p in self.compare(before, after)["packages"]], ["downgraded", "downgraded"])

    def test_equivalent_version_labels_are_not_misreported_as_upgrades(self):
        before = self.bundle("old", [("fixture", "1.0-1", b"before")])
        after = self.bundle("new", [("fixture", "1.0-01", b"after")])
        change = self.compare(before, after)["packages"][0]
        self.assertEqual(change["change"], "equivalent-version")
        self.assertTrue(change["artifact_bytes_changed"])

    def test_version_tool_failure_has_no_lexical_fallback(self):
        before = self.bundle("old", [("fixture", "1.9-1", b"before")])
        after = self.bundle("new", [("fixture", "1.10-1", b"after")])
        original = c.r.run
        def unavailable(argv, **kwargs):
            if argv[0] == "vercmp":raise c.r.Error("version tool unavailable")
            return original(argv, **kwargs)
        with mock.patch.object(c.r, "run", side_effect=unavailable):
            with self.assertRaisesRegex(c.r.Error, "version tool unavailable"):
                self.compare(before, after)

    def test_same_version_changed_bytes_are_visible(self):
        before = self.bundle("old", [("fixture", "1.0-1", b"before")])
        after = self.bundle("new", [("fixture", "1.0-1", b"after")])
        change = self.compare(before, after)["packages"][0]
        self.assertEqual(change["change"], "same-version-byte-change")
        self.assertTrue(change["artifact_bytes_changed"])
        self.assertNotEqual(change["before"]["sha256"], change["after"]["sha256"])

    def test_same_bundle_has_no_changes(self):
        release = self.bundle("unchanged")
        result = self.compare(release, release)
        for key in ("packages", "files", "symlinks", "coordinated_sets", "policy"):
            self.assertEqual(result[key], [])
        self.assertEqual(result["dependency_inventory"]["packages"], [])

    def test_dependency_inventory_and_coordinated_platform_changes(self):
        before = self.bundle("old")
        extra = {"name": "added-runtime", "version": "1", "arch": "aarch64", "depend": [],
                 "provides": [], "conflict": [], "files": ["usr/lib/added-runtime"]}
        after = self.bundle("new", runtime="3", kernel="2", extra_base=extra, models=["m2-air-13", "m2-air-15"])
        result = self.compare(before, after)
        self.assertEqual([(p["name"], p["change"]) for p in result["dependency_inventory"]["packages"]],
                         [("added-runtime", "added"), ("linux-asahi", "upgraded"), ("runtime", "upgraded")])
        self.assertEqual(result["coordinated_sets"], [
            {"name": "synthetic-platform", "packages": [{"name": "linux-asahi", "before": "1", "after": "2"}]},
            {"name": "synthetic-runtime", "packages": [{"name": "runtime", "before": "2", "after": "3"}]}])
        self.assertEqual(result["policy"], [{"name": "supported_models", "before": ["m2-air-13"], "after": ["m2-air-13", "m2-air-15"]}])
        self.assertEqual(result["dependency_inventory"]["before_snapshot"], "old-base")

    def test_same_version_dependency_change_is_reported_with_artifact_change(self):
        before = self.bundle("old")
        after = self.bundle("new", dependency="virtual-runtime>=1")
        change = self.compare(before, after)["packages"][0]
        self.assertEqual(change["change"], "same-version-byte-change")
        self.assertIn({"name": "depend", "before": ["virtual-runtime>=2"],
                       "after": ["virtual-runtime>=1"]}, change["metadata_changes"])

    def test_tampered_payload_signature_and_unsigned_bundle_refuse(self):
        before = self.bundle("old");after = self.bundle("new")
        for relative in ("base.json", "release.json.sig", "repo/fixture-1.0-1-any.pkg.tar.gz"):
            path = after / relative;raw = path.read_bytes();path.write_bytes(raw + b"tampered")
            try:self.refused(before, after)
            finally:path.write_bytes(raw)
        signature = after / "release.json.sig";raw = signature.read_bytes();signature.unlink()
        try:self.refused(before, after)
        finally:signature.write_bytes(raw)
        self.refused(before, after, key="0" * 40)

    def test_extra_file_and_symlink_input_refuse(self):
        before = self.bundle("old");after = self.bundle("new")
        extra = after / "unrecorded";extra.write_bytes(b"not signed")
        self.refused(before, after);extra.unlink()
        link = self.base / "bundle-alias";link.symlink_to(after)
        self.refused(before, link)
        self.refused(before, "/" + str(after))

    def test_changed_source_during_comparison_refuses(self):
        before = self.bundle("old");after = self.bundle("new");original = c.r.verify_release
        calls = []
        def changed(path, key, env):
            value = original(path, key, env);calls.append(path)
            if len(calls) == 2:(after / "base.json").write_bytes(b"{}")
            return value
        snapshot = self.snapshot();raw = (after / "base.json").read_bytes()
        try:
            with mock.patch.object(c.r, "verify_release", side_effect=changed):
                with self.assertRaisesRegex(c.r.Error, "base changed during comparison"):
                    c.compare_releases(before, after, self.key, self.env)
        finally:(after / "base.json").write_bytes(raw)
        # Only the deliberately injected external write occurred.
        self.assertEqual({k:v[:2] for k,v in self.snapshot().items()}, {k:v[:2] for k,v in snapshot.items()})
        self.assertEqual(len(calls), 2)

    def test_resigned_equivalent_manifest_change_during_final_check_refuses(self):
        before = self.bundle("old");after = self.bundle("new");original = c.r.verify_release
        paths = [before / "release.json", before / "release.json.sig"]
        saved = [p.read_bytes() for p in paths];calls = []
        def changed(path, key, env):
            calls.append(path)
            if len(calls) == 3:
                paths[0].write_text(json.dumps(c.r.load(paths[0]), indent=4) + "\n")
                paths[1].unlink();c.r.sign(paths[0], key, env)
            return original(path, key, env)
        try:
            with mock.patch.object(c.r, "verify_release", side_effect=changed):
                with self.assertRaisesRegex(c.r.Error, "release changed during comparison"):
                    c.compare_releases(before, after, self.key, self.env)
        finally:
            for path, raw in zip(paths, saved):path.write_bytes(raw)
        self.assertEqual(len(calls), 3)

    def test_cli_prints_json_and_preserves_selection(self):
        before = self.bundle("old");after = self.bundle("new")
        snapshot = self.snapshot()
        result = subprocess.run([sys.executable, "-I", "-B", str(HERE / "compare_releases.py"),
            "--before", str(before), "--after", str(after), "--gpg-home", str(self.home), "--key", self.key],
            capture_output=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b'"purpose": "signed-release-comparison"', result.stdout)
        self.assertEqual(self.snapshot(), snapshot)


if __name__ == "__main__":
    unittest.main()
