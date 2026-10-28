#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite host-only DATA joins; no builds, installs, network or real actors."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("import_release_graph.py")
spec = importlib.util.spec_from_file_location("graph_import", SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Fixture:
    def __init__(self, root):
        self.root = root
        self.recipe = root / "recipe"
        self.recipe.mkdir()
        self.write("recipe/PKGBUILD", b"# metadata reviewed separately\npkgname=local-lib\n")
        source = "pkgbase = source-local\npkgname = local-lib\npkgver = 2\npkgrel = 1\narch = aarch64\nlicense = MIT\ndepends = virtual-ext>=9-1\nprovides = virtual-local=2-1\nmakedepends_aarch64 = external-lib\ncheckdepends = consumer\nsource = https://example.invalid/FIXTURE.tar\nsha256sums = " + "a"*64 + "\n"
        self.write("recipe/.SRCINFO", source.encode())
        pkginfo = "pkgname = local-lib\npkgbase = source-local\npkgver = 2-1\narch = aarch64\nlicense = MIT\ndepend = virtual-ext>=9-1\nprovides = virtual-local=2-1\nmakedepend = external-lib\ncheckdepend = consumer\nurl = https://example.invalid/FIXTURE\n"
        buildinfo = "pkgbuild_sha256sum = " + m.a.pin((self.recipe / "PKGBUILD").read_bytes())["sha256"] + "\n"
        self.archive(pkginfo, buildinfo)
        checksum = m.a.pin((root / "project.tar").read_bytes())["sha256"]
        self.local = dict(name="local-lib", version="2-1", sha256=checksum)
        self.external = dict(name="external-lib", version="1:1-1", arch="aarch64", sha256="b"*64,
                             depends=[], provides=["virtual-ext=1:1-1"], conflicts=[], replaces=[], license=["GPL-2.0-only"],
                             source_url=["https://example.invalid/UPSTREAM"], pkgbase="upstream-source")
        self.consumer = dict(name="consumer", version="1-1", arch="any", sha256="c"*64,
                             depends=["virtual-local>=2-1"], provides=[], conflicts=[], replaces=[], license=["MIT"])
        self.write("inventory.lock", b"external-lib 1:1-1\nlocal-lib 2-1\nconsumer 1-1\n")
        self.json("manifest.json", dict(packages=[self.local, self.external, self.consumer], projects=[self.local]))
        self.json("lock.json", dict(packages=[self.external, self.consumer]))
        self.selection = dict(schema_version=1, release_id="HOST-FIXTURE", snapshot_id="HOST-FIXTURE-BASE",
                              inventory=self.desc("inventory.lock"), manifest=self.desc("manifest.json"), extension_profile=None,
                              metadata=[dict(file=self.desc("lock.json"), select=["packages"], format="lock")],
                              archives=[self.desc("project.tar")], recipes=[self.recipe_spec()],
                              changed=dict(sources=["source-local"], toolchains=[], advisories=[]))

    def write(self, name, raw):
        path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)

    def json(self, name, value): self.write(name, m.a.encoded(value))
    def desc(self, name): return dict(path=name, sha256=m.a.pin((self.root / name).read_bytes())["sha256"])
    def recipe_spec(self):
        return dict(package="local-lib", path="recipe/PKGBUILD",
                    files={p.name:m.a.pin(p.read_bytes())["sha256"] for p in self.recipe.iterdir() if p.is_file()})

    def archive(self, pkginfo, buildinfo):
        with tarfile.open(self.root / "project.tar", "w") as stream:
            for name, value in ((".PKGINFO", pkginfo), (".BUILDINFO", buildinfo)):
                raw = value.encode(); member = tarfile.TarInfo(name); member.size = len(raw); stream.addfile(member, io.BytesIO(raw))

    def run(self):
        before = copy.deepcopy(self.selection)
        with patch.object(socket, "create_connection", side_effect=AssertionError("offline only")):
            result = m.import_graph(self.selection, m.Reader(self.root))
        assert before == self.selection
        return result


class Controls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.f = Fixture(Path(self.temp.name))

    def review(self, result, name): return next(row for row in result["packages"] if row["name"] == name)

    def test_actual_metadata_recipe_binding_and_arch_effective_inputs(self):
        result = self.f.run()
        self.assertEqual(result["summary"]["packages"], 3)
        self.assertEqual(result["summary"]["external"], 2)
        self.assertTrue(self.review(result, "local-lib")["archive_recipe_metadata_bound"])
        record = result["graph"]["build_dependencies"][0]
        self.assertEqual(record["source_id"], "source-local")
        self.assertEqual(record["makedepend"], ["external-lib"])
        self.assertEqual(record["checkdepend"], ["consumer"])
        self.assertEqual(record["disposition"], "hold")
        self.assertIn("IMPLICIT_TOOLCHAIN_INPUTS_UNKNOWN", record["hold_reason"])
        self.assertIsNone(record["owner"])

    def test_binary_pkgbase_provider_distinctions_and_external_retention(self):
        result = self.f.run()
        self.assertEqual(self.review(result, "external-lib")["pkgbase"], "upstream-source")
        inv = {row["name"]:row for row in result["inventory"]}
        self.assertEqual(inv["external-lib"]["provides"], ["virtual-ext=1:1-1"])
        self.assertNotIn("virtual-ext", inv)
        self.assertNotIn("upstream-source", inv)
        self.assertEqual({r["package"] for r in result["graph"]["build_dependencies"]}, {"local-lib"})
        external = self.review(result, "external-lib")
        self.assertEqual(external["project_build_status"], "EXTERNAL_NOT_PROJECT_BUILT")
        self.assertIn("BUILD_DEPENDENCY_METADATA_UNKNOWN", external["holds"])
        self.assertEqual(external["license_declarations"], ["GPL-2.0-only"])
        plan = m.b.plan(result["graph"])
        self.assertIn("consumer", {p["name"] for p in plan["packages"]})
        self.assertTrue(any(edge["provider"] == "local-lib" and edge["package"] == "consumer" for edge in plan["build_inputs"]))
        self.assertTrue(all(g["held"] for g in plan["groups"]))

    def test_recipe_name_match_does_not_promote_external_package(self):
        self.f.selection["recipes"][0]["package"] = "external-lib"
        with self.assertRaisesRegex(ValueError, "project package membership"): self.f.run()

    def test_wrong_inventory_version_or_missing_authority_refuses(self):
        for raw in (b"local-lib 3-1\n", b"absent 1-1\n"):
            self.f.write("inventory.lock", raw); self.f.selection["inventory"] = self.f.desc("inventory.lock")
            with self.assertRaisesRegex(ValueError, "authority"): self.f.run()

    def test_same_version_archive_ambiguity_refuses(self):
        manifest = json.loads((self.f.root / "manifest.json").read_bytes())
        manifest["packages"].append(dict(self.f.local, sha256="d"*64))
        self.f.json("manifest.json", manifest); self.f.selection["manifest"] = self.f.desc("manifest.json")
        with self.assertRaisesRegex(ValueError, "ambiguous same-version"): self.f.run()

    def test_wrong_metadata_archive_hash_and_conflicting_relation_refuse(self):
        lock = json.loads((self.f.root / "lock.json").read_bytes())
        lock["packages"][0]["sha256"] = "e"*64
        self.f.json("lock.json", lock); self.f.selection["metadata"][0]["file"] = self.f.desc("lock.json")
        with self.assertRaisesRegex(ValueError, "archive hash mismatch"): self.f.run()
        lock["packages"][0] = self.f.external
        lock["packages"].append(dict(self.f.external, provides=["wrong"]))
        self.f.json("lock.json", lock); self.f.selection["metadata"][0]["file"] = self.f.desc("lock.json")
        with self.assertRaisesRegex(ValueError, "conflicting retained"): self.f.run()

    def test_unversioned_provider_never_satisfies_versioned_dependency(self):
        lock = json.loads((self.f.root / "lock.json").read_bytes()); lock["packages"][0]["provides"] = ["virtual-ext"]
        self.f.json("lock.json", lock); self.f.selection["metadata"][0]["file"] = self.f.desc("lock.json")
        plan = m.b.plan(self.f.run()["graph"])
        self.assertTrue(any(p["status"] == "UNAVAILABLE_DEPENDENCY" for p in plan["dependency_issues"]))

    def test_recipe_directory_hash_namespace_and_binary_identity_refuse(self):
        self.f.write("recipe/unknown", b"extra")
        with self.assertRaisesRegex(ValueError, "namespace/hash mismatch"): self.f.run()
        (self.f.recipe / "unknown").unlink()
        self.f.selection["recipes"][0]["files"]["PKGBUILD"] = "0"*64
        with self.assertRaisesRegex(ValueError, "checksum mismatch"): self.f.run()

    def test_missing_pkginfo_without_recipe_never_invents_architecture(self):
        self.f.selection["archives"] = []; self.f.selection["recipes"] = []
        with self.assertRaisesRegex(ValueError, "cannot fabricate inventory"): self.f.run()

    def test_missing_local_source_is_explicit_held_pin_availability(self):
        text = (self.f.recipe / ".SRCINFO").read_text().replace("https://example.invalid/FIXTURE.tar", "missing-source.tar")
        self.f.write("recipe/.SRCINFO", text.encode()); self.f.selection["recipes"] = [self.f.recipe_spec()]
        result = self.f.run()
        self.assertIn("DECLARED_LOCAL_SOURCE_NOT_AVAILABLE", self.review(result, "local-lib")["holds"])
        self.assertTrue(self.review(result, "local-lib")["recipe_static_errors"])
        self.assertTrue(all(g["held"] for g in m.b.plan(result["graph"])["groups"]))

    def test_archive_recipe_hash_mismatch_remains_unverified(self):
        self.f.write("recipe/PKGBUILD", b"# different recipe\npkgname=local-lib\n")
        self.f.selection["recipes"] = [self.f.recipe_spec()]
        result = self.f.run(); row = self.review(result, "local-lib")
        self.assertFalse(row["archive_recipe_metadata_bound"])
        self.assertIn("RECIPE_ARCHIVE_BINDING_UNVERIFIED", row["holds"])
        self.assertTrue(any("PKGBUILD hash" in error for error in row["archive_recipe_binding_errors"]))

    def test_source_only_manifest_bridge_is_held_and_explicit(self):
        manifest = json.loads((self.f.root / "manifest.json").read_bytes())
        manifest["projects"][0].update(depends=["virtual-ext>=9-1"], provides=["virtual-local=2-1"], conflicts=[])
        self.f.json("manifest.json", manifest); self.f.selection["manifest"] = self.f.desc("manifest.json")
        self.f.selection["archives"] = []
        result = self.f.run(); row = self.review(result, "local-lib")
        self.assertIn("ARCHIVE_METADATA_CORRESPONDENCE_UNVERIFIED", row["holds"])
        self.assertFalse(row["archive_recipe_metadata_bound"])
        self.assertIn("SOURCE_ONLY", row["metadata_inputs"][0]["format"])
        self.assertEqual(result["graph"]["build_dependencies"][0]["disposition"], "hold")

    def test_advisory_join_uses_binary_not_pkgbase_or_provides(self):
        result = self.f.run()
        group = dict(name="AVG-1", packages=["source-local", "virtual-local"], status="Unknown", severity="Unknown",
                     type="SYNTHETIC FIXTURE ONLY", affected=None, fixed=None, issues=[], advisories=[])
        report = m.a.report(result["inventory"], [group], {}, "2026-10-27T00:00:00Z")
        self.assertTrue(all(row["status"] == "UNKNOWN_NO_TRACKER_MATCH" for row in report["packages"]))
        group["packages"] = ["local-lib"]
        report = m.a.report(result["inventory"], [group], {}, "2026-10-27T00:00:00Z")
        self.assertEqual([row["name"] for row in report["packages"] if row["findings"]], ["local-lib"])
        self.assertEqual(report["arm_security_status"], "UNKNOWN")

    def test_unknown_metadata_and_capacity_facts_are_not_fabricated(self):
        result = self.f.run()
        self.assertEqual(result["graph"]["capacity"], dict(native_aarch64_slots=None, owner=None, reference=None))
        self.assertTrue(all(row["project_build_status"] != "PASS" for row in result["packages"]))
        self.assertIn("SOURCE_RECIPE_PINS_UNKNOWN", self.review(result, "consumer")["holds"])

    def test_archive_metadata_bounds_and_duplicates_refuse(self):
        raw = (self.f.root / "project.tar").read_bytes()
        with patch.object(m, "MAX_MEMBERS", 1), self.assertRaisesRegex(ValueError, "member count"):
            m.archive_metadata(raw)
        with tarfile.open(self.f.root / "duplicate.tar", "w") as stream:
            for _ in range(2):
                payload = b"pkgname = local-lib\n"; info = tarfile.TarInfo(".PKGINFO"); info.size = len(payload)
                stream.addfile(info, io.BytesIO(payload))
        with self.assertRaisesRegex(ValueError, "duplicate archive member"):
            m.archive_metadata((self.f.root / "duplicate.tar").read_bytes())

    def test_stale_project_names_cannot_promote_selected_external_binary(self):
        for field, value in (("version", "1-1"), ("sha256", "0"*64)):
            manifest = json.loads((self.f.root / "manifest.json").read_bytes())
            manifest["projects"] = [dict(self.f.local, **{field:value})]
            self.f.json("manifest.json", manifest); self.f.selection["manifest"] = self.f.desc("manifest.json")
            self.f.selection["recipes"] = []
            result = self.f.run()
            self.assertTrue(self.review(result, "local-lib")["external"])
            self.assertIn("PROJECT_RELEASE_MEMBERSHIP_UNBOUND", self.review(result, "local-lib")["holds"])
            self.f.selection["recipes"] = [self.f.recipe_spec()]
            with self.assertRaisesRegex(ValueError, "project package membership"): self.f.run()

    def test_undeclared_recipe_namespace_refuses_before_shared_auditor(self):
        self.f.write("recipe/large-undeclared", b"unselected")
        with patch.object(m.c, "recipe", side_effect=AssertionError("must refuse before hashing")), self.assertRaisesRegex(ValueError, "namespace/hash mismatch"):
            self.f.run()

    def test_symlink_traversal_and_changed_inputs_refuse(self):
        (self.f.root / "alias").symlink_to(self.f.root / "lock.json")
        reader = m.Reader(self.f.root)
        for descriptor in (dict(path="../outside", sha256="a"*64), dict(path="alias", sha256=self.f.desc("lock.json")["sha256"])):
            with self.assertRaises(ValueError): reader.read(descriptor)
        reader.read(self.f.desc("lock.json")); self.f.write("lock.json", b"changed")
        with self.assertRaisesRegex(ValueError, "changed during import"): reader.recheck()

    def test_extension_overlay_retains_exact_selected_inventory(self):
        manifest = json.loads((self.f.root / "manifest.json").read_bytes())
        manifest["packages"][0] = dict(self.f.local, version="1-1", sha256="9"*64)
        self.f.json("manifest.json", manifest); self.f.selection["manifest"] = self.f.desc("manifest.json")
        self.f.json("profile.json", dict(incoming={"local-lib":self.f.local}))
        self.f.selection["extension_profile"] = self.f.desc("profile.json")
        result = self.f.run()
        self.assertEqual(next(r for r in result["inventory"] if r["name"] == "local-lib")["version"], "2-1")

    def test_json_duplicates_and_all_cli_outputs_are_finite_deterministic(self):
        self.f.write("bad.json", b'{"packages":[],"packages":[]}')
        with self.assertRaises(ValueError): m.Reader(self.f.root).json(self.f.desc("bad.json"))
        self.f.json("selection.json", self.f.selection)
        args = [sys.executable, "-B", str(SCRIPT), "--root", str(self.f.root), "--selection", str(self.f.root / "selection.json"),
                "--selection-sha256", self.f.desc("selection.json")["sha256"]]
        for output in ("bundle", "graph", "inventory"):
            command = [*args, "--output", output]
            first = subprocess.run(command, capture_output=True, check=True)
            second = subprocess.run(command, capture_output=True, check=True)
            self.assertEqual(first.stdout, second.stdout)
            value = json.loads(first.stdout)
            if output == "inventory": m.a.inventory(value)
            if output == "graph": self.assertEqual(m.b.plan(value)["build_status"], "NOT_RUN")

    def test_invalid_archive_cli_has_no_partial_stdout(self):
        self.f.write("project.tar", b"invalid compressed package DATA")
        self.f.selection["archives"] = [self.f.desc("project.tar")]
        self.f.json("selection.json", self.f.selection)
        args = [sys.executable, "-B", str(SCRIPT), "--root", str(self.f.root), "--selection", str(self.f.root / "selection.json"),
                "--selection-sha256", self.f.desc("selection.json")["sha256"]]
        result = subprocess.run(args, capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"release graph import:", result.stderr)
        self.assertNotIn(b"Traceback", result.stderr)


if __name__ == "__main__": unittest.main()
