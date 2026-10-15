#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Signed synthetic bundles, real ALPM ordering, no host installation or trust changes."""
import argparse
import copy
import gzip
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


class DependencyImpactTests(unittest.TestCase):
    def package(self, name, version="1", depend=(), provides=(), **extra):
        return dict(name=name, version=version, arch="any", depend=list(depend),
                    provides=list(provides), conflict=[], files=["usr/share/" + name], **extra)

    def impact(self, before, after, old_overlay=(), new_overlay=()):
        saved = copy.deepcopy((before, after, old_overlay, new_overlay))
        value = c.dependency_impact(old_overlay, new_overlay, before, after)
        self.assertEqual((before, after, old_overlay, new_overlay), saved)
        self.assertFalse(value["build_dependencies_checked"])
        self.assertEqual(value["rebuild_requirement"], "NOT_ESTABLISHED")
        return value

    def test_transitive_paths_and_cycles_terminate(self):
        before = [self.package("lib", depend=["app"]), self.package("middle", depend=["lib>=1"]),
                  self.package("app", depend=["middle"])]
        after = copy.deepcopy(before);after[0]["version"] = "2"
        value = self.impact(before, after)
        self.assertEqual([p["name"] for p in value["unchanged_dependents"]], ["app", "middle"])
        path = value["unchanged_dependents"][0]["impacts"][0]["paths"]["before"]
        self.assertEqual(path, [{"package":"app", "dependency":"middle", "provider":"middle"},
                                {"package":"middle", "dependency":"lib>=1", "provider":"lib"}])
        self.assertEqual(len(path), 2)

    def test_removed_provider_keeps_before_path_and_alternatives_are_not_selected(self):
        provider = self.package("removed", provides=["virtual=2"])
        kept = [self.package("alternative", provides=["virtual=2"]), self.package("app", depend=["virtual>=2"])]
        value = self.impact([provider, *kept], kept)
        self.assertEqual(value["changed_packages"][0]["change"], "removed")
        paths = value["unchanged_dependents"][0]["impacts"][0]["paths"]
        self.assertEqual(set(paths), {"before"})
        self.assertEqual(paths["before"][0]["provider"], "removed")
        self.assertEqual(value["provider_policy"], "all-matching-providers")

    def test_provided_version_not_provider_package_version_matches_requirement(self):
        before = [self.package("older-api", "99", provides=["api=1"]),
                  self.package("current-api", provides=["api=2"]), self.package("app", depend=["api>=2"])]
        after = copy.deepcopy(before);after[0]["version"] = "100"
        self.assertEqual(self.impact(before, after)["unchanged_dependents"], [])
        after[1]["provides"] = ["api=3"]
        impacts = self.impact(before, after)["unchanged_dependents"][0]["impacts"]
        self.assertEqual([p["name"] for p in impacts], ["current-api"])

    def test_unversioned_provide_cannot_satisfy_versioned_requirement(self):
        before = [self.package("plain", provides=["api"]), self.package("versioned", provides=["api=2"]),
                  self.package("needs-version", depend=["api>=2"]), self.package("unversioned", depend=["api"])]
        after = copy.deepcopy(before);after[0]["version"] = "2"
        self.assertEqual([p["name"] for p in self.impact(before, after)["unchanged_dependents"]], ["unversioned"])

    def test_alpm_epoch_pkgrel_and_relation_boundaries(self):
        before = [self.package("lib", "2:1.0-2"), self.package("exact", depend=["lib=2:1.0-2"]),
                  self.package("newer", depend=["lib>=2:1.0-3"]), self.package("fallback", provides=["lib=2:1.0-2", "lib=2:1.0-3"])]
        after = copy.deepcopy(before);after[0]["version"] = "2:1.0-3"
        value = self.impact(before, after)
        paths = {p["name"]:p["impacts"][0]["paths"] for p in value["unchanged_dependents"]}
        self.assertEqual(set(paths["exact"]), {"before"})
        self.assertEqual(set(paths["newer"]), {"after"})

    def test_overlay_shadows_changed_base_package(self):
        old = [self.package("lib"), self.package("app", depend=["lib"])]
        new = copy.deepcopy(old);new[0]["version"] = "2"
        overlay = [self.package("lib", filename="lib.pkg", sha256="a"*64)]
        self.assertEqual(self.impact(old, new, overlay, overlay)["changed_packages"], [])

    def test_changed_dependents_excluded_and_overlay_bytes_are_a_cause(self):
        base = [self.package("app", depend=["lib"])]
        old = [self.package("lib", filename="lib.pkg", sha256="a"*64)]
        new = [self.package("lib", filename="lib.pkg", sha256="b"*64)]
        self.assertEqual(self.impact(base, base, old, new)["unchanged_dependents"][0]["name"], "app")
        changed = copy.deepcopy(base);changed[0]["version"] = "2"
        self.assertEqual(self.impact(base, changed, old, new)["unchanged_dependents"], [])

    def test_irrelevant_changes_and_added_only_providers_do_not_seed_review(self):
        old = [self.package("lib"), self.package("app", depend=["lib"]), self.package("unrelated")]
        new = copy.deepcopy(old);new[2]["version"] = "2"
        self.assertEqual(self.impact(old, new)["unchanged_dependents"], [])
        new = [*old, self.package("added", provides=["lib"])]
        self.assertEqual(self.impact(old, new)["changed_packages"], [])

    def test_ordering_and_shortest_path_are_deterministic(self):
        old = [self.package("lib"), self.package("z", depend=["lib"]),
               self.package("a", depend=["lib"]), self.package("app", depend=["z", "a"])]
        new = copy.deepcopy(old);new[0]["version"] = "2"
        value = self.impact(old, new)
        self.assertEqual(value, self.impact(list(reversed(old)), list(reversed(new))))
        app = next(p for p in value["unchanged_dependents"] if p["name"] == "app")
        self.assertEqual(app["impacts"][0]["paths"]["before"][0]["provider"], "a")

    def test_version_tool_failure_propagates_without_fallback(self):
        old = [self.package("lib"), self.package("app", depend=["lib>=1"])]
        new = copy.deepcopy(old);new[0]["version"] = "2"
        failure = c.r.Error("version tool unavailable")
        with mock.patch.object(c.r, "run", side_effect=failure) as run:
            with self.assertRaises(c.r.Error) as caught:self.impact(old, new)
        self.assertIs(caught.exception, failure);self.assertEqual(run.call_count, 1)

    def test_provider_index_skips_unrelated_and_reuses_matching_version_probe(self):
        old = [self.package("lib"), self.package("app", depend=["lib>=1"]),
               *[self.package("unrelated-" + str(i)) for i in range(100)]]
        new = copy.deepcopy(old);new[0]["files"] = ["usr/share/changed-lib"]
        with mock.patch.object(c.r, "satisfies", wraps=c.r.satisfies) as matches, \
                mock.patch.object(c.r, "run", wraps=c.r.run) as commands:
            self.assertEqual(len(self.impact(old, new)["unchanged_dependents"]), 1)
        self.assertEqual(matches.call_count, 1)
        self.assertEqual(matches.call_args.args[1]["name"], "lib")
        self.assertEqual(commands.call_args_list, [mock.call(["vercmp", "1", "1"])])

    def test_graph_and_path_limits_refuse_instead_of_truncating(self):
        old = [self.package("lib"), self.package("a", depend=["lib"]), self.package("b", depend=["a"])]
        new = copy.deepcopy(old);new[0]["version"] = "2"
        for limit, reason in (("MAX_IMPACT_EDGES", "graph exceeds edge limit"), ("MAX_IMPACT_STEPS", "report exceeds path limit"),
                              ("MAX_IMPACT_CHECKS", "graph exceeds match limit")):
            with mock.patch.object(c, limit, 1):
                with self.assertRaisesRegex(c.r.Error, reason):self.impact(old, new)

    def test_global_traversal_limit_bounds_changed_cycle_with_zero_output_paths(self):
        old = [self.package("cycle-" + str(i), depend=["cycle-" + str((i + 1) % 4)]) for i in range(4)]
        old.append(self.package("isolated-unchanged"))
        new = copy.deepcopy(old)
        for package in new[:4]:package["version"] = "2"
        with mock.patch.object(c, "MAX_IMPACT_WORK", 64), mock.patch.object(c, "MAX_IMPACT_STEPS", 1):
            value = self.impact(old, new)
        self.assertEqual(len(value["changed_packages"]), 4)
        self.assertEqual(value["unchanged_dependents"], [])
        # All roots and both releases share one budget, even without emitted paths.
        with mock.patch.object(c, "MAX_IMPACT_WORK", 63), mock.patch.object(c, "MAX_IMPACT_STEPS", 1):
            with self.assertRaisesRegex(c.r.Error, "traversal exceeds work limit"):
                self.impact(old, new)


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
            with archive.open("wb") as stream, gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=1700000000) as packed, \
                    tarfile.open(fileobj=packed, mode="w") as tar:
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
        self.assertEqual(result["dependency_impact"]["unchanged_dependents"], [])
        self.assertEqual(result["dependency_impact"]["changed_packages"], [])

    def test_signed_transitive_unchanged_overlay_consumer(self):
        bridge = dict(name="bridge", version="1", arch="any", depend=["virtual-runtime>=2"],
                      provides=[], conflict=[], files=["usr/share/bridge"])
        before = self.bundle("old", extra_base=bridge, dependency="bridge>=1")
        after = self.bundle("new", runtime="3", dependency="bridge>=1")
        result = self.compare(before, after)
        self.assertEqual(result["packages"], [])
        affected = result["dependency_impact"]["unchanged_dependents"]
        self.assertEqual([p["name"] for p in affected], ["bridge", "fixture"])
        self.assertEqual(affected[1]["origin"], "release")
        path = affected[1]["impacts"][0]["paths"]["before"]
        self.assertEqual([p["provider"] for p in path], ["bridge", "runtime"])

    def test_signed_removed_matching_provider_with_remaining_alternative(self):
        provider = dict(name="removed-provider", version="1", arch="any", depend=[],
                        provides=["virtual-runtime=2"], conflict=[], files=["usr/share/provider"])
        before = self.bundle("old", extra_base=provider)
        base = c.r.load(self.inputs / "base.json")
        base["packages"] = [p for p in base["packages"] if p["name"] != "removed-provider"]
        self.put("base.json", base)
        after = self.bundle("new")
        impact = self.compare(before, after)["dependency_impact"]
        self.assertEqual([p["name"] for p in impact["unchanged_dependents"]], ["fixture"])
        self.assertEqual(set(impact["unchanged_dependents"][0]["impacts"][0]["paths"]), {"before"})

    def test_signed_same_version_byte_change_impacts_unchanged_base_consumer(self):
        consumer = dict(name="consumer", version="1", arch="any", depend=["fixture>=1"],
                        provides=[], conflict=[], files=["usr/share/consumer"])
        before = self.bundle("old", packages=[("fixture", "1-1", b"old")], extra_base=consumer)
        after = self.bundle("new", packages=[("fixture", "1-1", b"new")])
        result = self.compare(before, after)
        self.assertEqual(result["packages"][0]["change"], "same-version-byte-change")
        self.assertEqual(result["dependency_impact"]["unchanged_dependents"][0]["name"], "consumer")

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
