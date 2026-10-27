#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline maintenance integration controls; real Arch vercmp, synthetic data."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("update_plan.py")
spec = importlib.util.spec_from_file_location("update_plan", SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
NOW = "2026-10-26T20:00:00Z"


def fixture():
    names = ("lib", "lib-tools", "middle", "app", "other")
    inventory = [dict(name=name, version="1-1", arch="aarch64", provides=[], pkgbase=name)
                 for name in names]
    inventory[0]["pkgbase"] = "source-lib"
    inventory[0]["provides"] = ["virtual-lib=1:1-1"]
    inventory[1]["pkgbase"] = "source-lib"
    packages = [dict(row, depend=[]) for row in inventory]
    packages[2]["depend"] = ["virtual-lib>=99-1"]  # epoch wins via real vercmp
    packages[3]["depend"] = ["middle"]
    builds = [dict(package=row["name"], source_id=row["pkgbase"], makedepend=[], checkdepend=[], toolchain=[],
                   owner="FIXTURE-maintainer", disposition="build", hold_reason=None) for row in inventory]
    sources = [dict(id=name, recipe_sha256="a" * 64,
                    sources=[dict(url="https://example.invalid/FIXTURE/" + name, commit="b" * 40)])
               for name in sorted({row["source_id"] for row in builds})]
    graph = dict(schema_version=1, metadata_role="pre-change-release", release_id="FIXTURE-only",
                 snapshot_id="FIXTURE-base", packages=packages, build_dependencies=builds, sources=sources,
                 changed=dict(sources=[], toolchains=[], advisories=[]),
                 capacity=dict(native_aarch64_slots=1, owner="FIXTURE-builder", reference="unmeasured illustrative capacity"))
    advisory = dict(name="AVG-1", packages=["lib"], status="Fixed", severity="High", type="FIXTURE issue",
                    affected="1-1", fixed="1-2", issues=["CVE-2026-12345"], advisories=["ASA-202610-1"])
    return inventory, [advisory], graph


def originals(items=None, groups=None, graph=None, retrieved="2026-10-26T19:00:00Z", report_time=NOW):
    defaults = fixture()
    items, groups, graph = [default if value is None else value
                            for value, default in zip((items, groups, graph), defaults)]
    raws = {"inventory": m.a.encoded(items), "advisories": m.a.encoded(groups), "graph": m.a.encoded(graph)}
    provenance = dict(url=m.a.URL, retrieved_at=retrieved, **m.a.pin(raws["advisories"]))
    raws["provenance"] = m.a.encoded(provenance)
    cache = m.a.provenance(provenance, raws["advisories"], m.a.utc(report_time), 24)
    report = m.a.report(items, groups, cache, report_time)
    report["inputs"] = {key + ".json": m.a.pin(raws[key]) for key in ("inventory", "advisories", "provenance")}
    raws["advisory_report"] = m.a.encoded(report)
    return raws


def argv(root, raws, fmt="json"):
    result = ["--as-of", NOW, "--format", fmt]
    for key in m.INPUTS:
        path = root / (key + ".json")
        path.write_bytes(raws[key])
        result.extend(["--" + key.replace("_", "-"), str(path),
                       "--" + key.replace("_", "-") + "-sha256", m.a.pin(raws[key])["sha256"]])
    return result


class Controls(unittest.TestCase):
    def run_plan(self, raws=None, time=NOW):
        raws = originals() if raws is None else raws
        before = copy.deepcopy(raws)
        with patch.object(socket, "create_connection", side_effect=AssertionError("offline only")):
            result = m.plan(raws, time)
        self.assertEqual(before, raws)
        return result

    def review(self, value, name):
        return next(row for row in value["package_reviews"] if row["name"] == name)

    def test_changed_binary_split_source_and_transitive_prerequisite_order(self):
        value = self.run_plan()
        self.assertEqual([g["packages"] for g in value["maintenance_groups"]], [["lib", "lib-tools"], ["middle"], ["app"]])
        self.assertEqual(value["rebuild"]["unaffected_by_declared_graph"], ["other"])
        groups = value["maintenance_groups"]
        self.assertEqual(groups[1]["prerequisites"], [groups[0]["id"]])
        self.assertTrue(all(g["held"] for g in groups))
        self.assertEqual(groups[1]["held_prerequisites"], [groups[0]["id"]])
        self.assertEqual(value["derived_advisory_roots"], [dict(package="lib", reference="https://security.archlinux.org/AVG-1")])
        self.assertEqual(self.review(value, "lib")["source_id"], "source-lib")
        self.assertEqual(value["build_status"], "NOT_RUN")
        self.assertEqual(value["arm_security_status"], "UNKNOWN")
        self.assertEqual(value["release_acceptance"], "NOT_ESTABLISHED")

    def test_at_or_above_arch_reference_still_seeds_and_holds_arm(self):
        items, groups, graph = fixture()
        items[0]["version"] = graph["packages"][0]["version"] = "1:1-1"
        value = self.run_plan(originals(items, groups, graph))
        row = self.review(value, "lib")
        self.assertEqual(row["findings"][0]["version_relation"], "AT_OR_ABOVE_ARCH_FIXED_REFERENCE")
        self.assertEqual({h["code"] for h in row["holds"]}, {"ARM_AFFECTEDNESS_UNKNOWN", "ARM_FIX_EVIDENCE_MISSING"})
        self.assertTrue(value["derived_advisory_roots"])

    def test_pkgbase_and_virtual_names_never_advisory_aliases(self):
        items, groups, graph = fixture()
        groups[0]["packages"] = ["source-lib", "virtual-lib", "Lib"]
        value = self.run_plan(originals(items, groups, graph))
        self.assertEqual(value["derived_advisory_roots"], [])
        self.assertEqual(value["maintenance_groups"], [])
        self.assertTrue(all(row["advisory_status"] == "UNKNOWN_NO_TRACKER_MATCH" for row in value["package_reviews"]))
        self.assertTrue(value["maintenance_review_held"])

    def test_explicit_source_and_toolchain_changes_preserved(self):
        items, groups, graph = fixture()
        groups[0]["packages"] = ["absent"]
        graph["changed"]["sources"] = ["middle"]
        graph["changed"]["toolchains"] = ["other"]
        value = self.run_plan(originals(items, groups, graph))
        self.assertEqual({r["name"] for r in value["rebuild"]["packages"]}, {"middle", "app", "other"})

    def test_missing_owner_pin_and_build_metadata_have_actionable_holds(self):
        items, groups, graph = fixture()
        graph["build_dependencies"][0]["owner"] = None
        graph["sources"] = [row for row in graph["sources"] if row["id"] != "source-lib"]
        del graph["build_dependencies"][2]
        value = self.run_plan(originals(items, groups, graph))
        codes = {r["code"] for g in value["maintenance_groups"] for r in g["rebuild_actions"]}
        self.assertTrue({"UNKNOWN_PACKAGE_OWNER", "UNKNOWN_SOURCE_PINS", "UNKNOWN_BUILD_METADATA"} <= codes)
        self.assertTrue(all(r["action"] for g in value["maintenance_groups"] for r in g["rebuild_actions"]))

    def test_missing_provides_is_unknown_and_conflicting_provides_refuse(self):
        items, groups, graph = fixture()
        del items[0]["provides"]
        value = self.run_plan(originals(items, groups, graph))
        self.assertIn("INVENTORY_PROVIDES_UNKNOWN", {h["code"] for h in self.review(value, "lib")["holds"]})
        items[0]["provides"] = ["virtual-lib=2-1"]
        with self.assertRaisesRegex(ValueError, "provides mismatch"):
            self.run_plan(originals(items, groups, graph))

    def test_no_match_and_no_change_keep_owner_pin_holds_visible(self):
        items, groups, graph = fixture()
        groups[0]["packages"] = ["absent"]
        graph["build_dependencies"][0]["owner"] = None
        graph["sources"] = [row for row in graph["sources"] if row["id"] != "source-lib"]
        value = self.run_plan(originals(items, groups, graph))
        self.assertEqual(value["maintenance_groups"], [])
        self.assertTrue({"UNKNOWN_PACKAGE_OWNER", "UNKNOWN_SOURCE_PINS", "ADVISORY_COVERAGE_UNKNOWN"}
                        <= {h["code"] for h in self.review(value, "lib")["holds"]})

    def test_cycle_and_external_update_holds_survive_join(self):
        items, groups, graph = fixture()
        graph["packages"][0]["depend"] = ["app"]
        graph["build_dependencies"][3]["disposition"] = "external"
        value = self.run_plan(originals(items, groups, graph))
        self.assertEqual(len(value["maintenance_groups"]), 1)
        group = value["maintenance_groups"][0]
        self.assertTrue(group["cycle"] and group["held"])
        self.assertTrue({"CYCLE_BOOTSTRAP_REVIEW_REQUIRED", "EXTERNAL_UPDATE_REVIEW"} <= set(group["holds"]))

    def test_fresh_stale_cache_stale_report_and_future_refusal(self):
        fresh = self.run_plan()
        self.assertEqual(fresh["global_holds"], [])
        stale = self.run_plan(originals(retrieved="2026-10-20T00:00:00Z"))
        self.assertIn("STALE_ADVISORY_CACHE", {h["code"] for h in stale["global_holds"]})
        late = self.run_plan(time="2026-10-28T20:00:00Z")
        self.assertTrue({"STALE_ADVISORY_REPORT", "STALE_ADVISORY_CACHE"} <= {h["code"] for h in late["global_holds"]})
        with self.assertRaisesRegex(ValueError, "future"):
            self.run_plan(time="2026-10-25T20:00:00Z")

    def test_inventory_identity_and_graph_role_mismatch_refuse(self):
        for change in ("set", "version", "arch", "role"):
            items, groups, graph = fixture()
            if change == "set": graph["packages"].pop()
            if change == "version": graph["packages"][0]["version"] = "2-1"
            if change == "arch": graph["packages"][0]["arch"] = "any"
            if change == "role": graph["metadata_role"] = "post-change-release"
            with self.subTest(change=change), self.assertRaises((ValueError, m.b.r.Error)):
                self.run_plan(originals(items, groups, graph))

    def test_tampered_report_findings_status_pin_and_boolean_refuse(self):
        for field in ("status", "findings", "inputs", "count"):
            raws = originals()
            report = json.loads(raws["advisory_report"])
            if field == "status": report["arm_security_status"] = "SAFE"
            if field == "findings": report["packages"][1]["findings"] = []
            if field == "inputs": report["inputs"]["inventory.json"]["sha256"] = "0" * 64
            if field == "count": report["schema_version"] = True  # Python equality alone would miss this.
            raws["advisory_report"] = m.a.encoded(report)
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "does not replay"):
                self.run_plan(raws)

    def test_invalid_duplicate_nonfinite_unpinned_inputs_refuse(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1.2}', b'[]'):
            raws = originals(); raws["graph"] = raw
            with self.subTest(raw=raw), self.assertRaises((ValueError, TypeError, m.b.r.Error)):
                self.run_plan(raws)
        items, groups, graph = fixture()
        graph["sources"][0]["sources"][0]["commit"] = "main"
        with self.assertRaisesRegex(m.b.r.Error, "pinned"):
            self.run_plan(originals(items, groups, graph))

    def test_cli_five_digest_checks_fail_before_stdout(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); raws = originals()
            for key in m.INPUTS:
                args = argv(root, raws)
                args[args.index("--" + key.replace("_", "-") + "-sha256") + 1] = "0" * 64
                out, err = io.StringIO(), io.StringIO()
                with self.subTest(key=key), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    self.assertEqual(m.main(args), 2)
                self.assertEqual(out.getvalue(), "")
                self.assertIn("checksum mismatch", err.getvalue())

    def test_real_report_producer_to_cli_deterministic_json_text_and_inputs_held(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); raws = originals()
            args = argv(root, raws)
            produced = root / "produced"
            producer = [sys.executable, "-B", str(m.ADVISORY), "--inventory", str(root / "inventory.json"),
                        "--advisories", str(root / "advisories.json"), "--provenance", str(root / "provenance.json"),
                        "--as-of", NOW, "--output", str(produced)]
            subprocess.run(producer, check=True, capture_output=True)
            self.assertEqual((produced / "report.json").read_bytes(), raws["advisory_report"])
            result = subprocess.run([sys.executable, "-B", str(SCRIPT), *args], capture_output=True, check=True)
            again = subprocess.run([sys.executable, "-B", str(SCRIPT), *args], capture_output=True, check=True)
            self.assertEqual(result.stdout, again.stdout)
            report = json.loads(result.stdout)
            self.assertEqual(report["inputs"], {key: dict(**m.a.pin(raws[key]), authenticated=False) for key in m.INPUTS})
            text_args = args[:]; text_args[text_args.index("--format") + 1] = "text"
            text = subprocess.run([sys.executable, "-B", str(SCRIPT), *text_args], capture_output=True, check=True).stdout.decode()
            self.assertIn("ARM_FIX_EVIDENCE_MISSING", text)
            self.assertIn("source-lib", text)
            self.assertIn("lib, lib-tools", text)
            for key in m.INPUTS:
                self.assertEqual((root / (key + ".json")).read_bytes(), raws[key])

    def test_invalid_and_changed_paths_refused_without_partial_output(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); raws = originals(); args = argv(root, raws)
            (root / "graph.json").unlink(); (root / "graph.json").symlink_to(root / "inventory.json")
            with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(m.main(args), 2)
            self.assertEqual(out.getvalue(), "")
            (root / "graph.json").unlink()
            args = argv(root, raws); actual_read = m.a.read; reads = {}
            def changed(path):
                reads[path] = reads.get(path, 0) + 1
                if path == root / "inventory.json" and reads[path] == 2:
                    return b"changed"
                return actual_read(path)
            with patch.object(m.a, "read", side_effect=changed), contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(m.main(args), 2)
            self.assertEqual(out.getvalue(), "")
            self.assertIn("changed during planning", err.getvalue())

    def test_graph_cli_validation_error_is_clean_refusal(self):
        items, groups, graph = fixture(); graph["metadata_role"] = "post-change-release"
        with tempfile.TemporaryDirectory() as td:
            args = argv(Path(td), originals(items, groups, graph))
            value = subprocess.run([sys.executable, "-B", str(SCRIPT), *args], capture_output=True)
            self.assertEqual(value.returncode, 2)
            self.assertEqual(value.stdout, b"")
            self.assertIn(b"pre-change release", value.stderr)
            self.assertNotIn(b"Traceback", value.stderr)

    def test_integrated_sibling_layout_without_proposal_fallback(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            dependencies = {"scripts/maintenance/update_plan.py": SCRIPT,
                            "scripts/maintenance/rebuild_plan.py": m.REBUILD,
                            "scripts/maintenance/security_advisories.py": m.ADVISORY}
            for name in ("check_source_pins.py", "release.py", "source_delivery.py"):
                dependencies["scripts/release/" + name] = m.b.DEPENDENCY.with_name(name)
            for relative, original in dependencies.items():
                target = root / relative; target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(original.read_bytes())
            args = argv(root, originals())
            result = subprocess.run([sys.executable, "-B", str(root / "scripts/maintenance/update_plan.py"), *args], capture_output=True, check=True)
            report = json.loads(result.stdout)
            self.assertIn("scripts/maintenance/rebuild_plan.py", report["implementation_dependencies"])
            self.assertFalse(any("artifacts/" in path for path in report["implementation_dependencies"]))

    def test_inventory_and_root_bounds_precede_comparison_and_expansion(self):
        raws = originals()
        with patch.object(m.b, "MAX_PACKAGES", 4), patch.object(m.a, "report", side_effect=AssertionError("must refuse first")), self.assertRaisesRegex(ValueError, "inventory exceeds"):
            self.run_plan(raws)
        items, groups, graph = fixture()
        groups = [dict(groups[0], name="AVG-" + str(i)) for i in range(1, 7)]
        raws = originals(items, groups, graph)
        with patch.object(m.b, "MAX_PACKAGES", 5), patch.object(m.a, "report", side_effect=AssertionError("must refuse first")), self.assertRaisesRegex(ValueError, "root count"):
            self.run_plan(raws)

    def test_replay_expansion_bound_precedes_generated_report(self):
        raws = originals()
        with patch.object(m.b.pins, "MAX_OUTPUT", 8000), patch.object(m.a, "report", side_effect=AssertionError("must refuse first")), self.assertRaisesRegex(ValueError, "expansion bound"):
            self.run_plan(raws)


if __name__ == "__main__":
    unittest.main()
