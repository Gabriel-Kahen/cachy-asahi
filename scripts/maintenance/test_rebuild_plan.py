#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline host controls; real ALPM relation ordering, no builds or installs."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("rebuild_plan.py")
spec = importlib.util.spec_from_file_location("rebuild_plan", SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def fixture():
    packages = [dict(name=name, version="1-1", arch="aarch64", depend=[], provides=[])
                for name in ("compiler", "lib", "middle", "app", "unrelated")]
    packages[0]["provides"] = ["c-compiler=2-1"]
    packages[2]["depend"] = ["lib>=1-1"]
    packages[3]["depend"] = ["middle"]
    sources = [dict(id=row["name"], recipe_sha256="a" * 64,
                    sources=[dict(url="https://example.invalid/" + row["name"], commit="b" * 40)]) for row in packages]
    builds = [dict(package=row["name"], source_id=row["name"], makedepend=[], checkdepend=[], toolchain=[],
                   disposition="build", owner="fixture-maintainer", hold_reason=None) for row in packages]
    builds[1]["makedepend"] = ["c-compiler>=2-1"]
    return dict(schema_version=1, metadata_role="pre-change-release", release_id="fixture-release", snapshot_id="fixture-base", packages=packages,
                sources=sources, build_dependencies=builds, changed=dict(sources=["compiler"], toolchains=[], advisories=[]),
                capacity=dict(native_aarch64_slots=2, owner="fixture-builder-owner", reference="fixture-only; no capacity attestation"))


class PlannerTests(unittest.TestCase):
    def setUp(self):
        self.data = fixture()

    def run_plan(self):
        before = copy.deepcopy(self.data)
        result = m.plan(self.data)
        self.assertEqual(self.data, before, "planner mutated input")
        return result

    def package(self, result, name):
        return next(row for row in result["packages"] if row["name"] == name)

    def group(self, result, name):
        return next(row for row in result["groups"] if name in row["packages"])

    def test_transitive_compiler_library_consumer_order_and_reasons(self):
        value = self.run_plan()
        self.assertEqual([row["packages"] for row in value["groups"]], [["compiler"], ["lib"], ["middle"], ["app"]])
        self.assertEqual(value["unaffected_by_declared_graph"], ["unrelated"])
        self.assertFalse(any(row["held"] for row in value["groups"]))
        self.assertEqual(self.package(value, "app")["reasons"], [dict(kind="REVERSE_BUILD_INPUT", package="app", field="depend", dependency="middle", provider="middle", relation_satisfied=True)])
        self.assertEqual(value["build_status"], "NOT_RUN")
        self.assertEqual(value["dependency_solution"], "NOT_ESTABLISHED")
        self.assertEqual(value["advisory_fix_status"], "UNKNOWN")

    def test_real_version_order_epoch_pkgrel_and_unversioned_provides(self):
        self.data["packages"][0]["provides"] = ["c-compiler=1:1-1"]
        self.data["build_dependencies"][1]["makedepend"] = ["c-compiler>=99-9"]
        self.assertIn("lib", [row["name"] for row in self.run_plan()["packages"]])
        self.data["packages"][0]["provides"] = ["c-compiler"]
        value = self.run_plan()
        self.assertEqual(value["dependency_issues"][0]["status"], "UNAVAILABLE_DEPENDENCY")
        self.assertEqual(value["dependency_issues"][0]["matching_providers"], [])
        self.assertTrue(self.group(value, "lib")["held"])
        self.assertIn("lib", [row["name"] for row in value["packages"]])

    def test_all_virtual_providers_impact_and_ambiguity_hold(self):
        self.data["packages"][4]["provides"] = ["c-compiler=3-1"]
        self.data["changed"]["sources"] = ["unrelated"]
        value = self.run_plan()
        self.assertEqual(value["dependency_issues"][0]["matching_providers"], ["compiler", "unrelated"])
        self.assertTrue(self.group(value, "lib")["held"])
        self.assertTrue(self.group(value, "app")["held_prerequisites"])
        self.assertIn("unrelated", {edge["provider"] for edge in value["build_inputs"] if edge["package"] == "lib"})

    def test_available_name_with_wrong_version_is_visible_unavailable(self):
        self.data["build_dependencies"][1]["makedepend"] = ["c-compiler>2-1"]
        value = self.run_plan()
        self.assertEqual(value["dependency_issues"][0]["candidates"], ["compiler"])
        self.assertEqual(value["dependency_issues"][0]["matching_providers"], [])

    def test_unavailable_dependency_held_when_consumer_selected(self):
        self.data["changed"]["sources"].append("lib")
        self.data["build_dependencies"][1]["checkdepend"] = ["missing-test-runner"]
        value = self.run_plan()
        self.assertTrue(self.group(value, "lib")["held"])
        self.assertTrue(self.group(value, "app")["held"])
        self.assertIn("UNAVAILABLE_DEPENDENCY:checkdepend:missing-test-runner", self.package(value, "lib")["holds"])

    def test_checkdeps_and_implicit_toolchain_inputs_propagate(self):
        self.data["build_dependencies"][4]["checkdepend"] = ["compiler"]
        self.data["build_dependencies"][3]["toolchain"] = ["compiler"]
        value = self.run_plan()
        self.assertEqual(len(value["packages"]), 5)
        fields = {edge["field"] for edge in value["build_inputs"]}
        self.assertEqual(fields, {"depend", "makedepend", "checkdepend", "toolchain"})

    def test_split_source_outputs_selected_together(self):
        self.data["build_dependencies"][4]["source_id"] = "compiler"
        self.data["sources"].pop()
        value = self.run_plan()
        group = self.group(value, "compiler")
        self.assertEqual(group["packages"], ["compiler", "unrelated"])
        self.assertFalse(group["cycle"])
        self.assertEqual(len(value["groups"]), 4)

    def test_scc_cycle_and_downstream_held(self):
        self.data["packages"][1]["depend"] = ["middle"]
        value = self.run_plan()
        group = self.group(value, "lib")
        self.assertEqual(group["packages"], ["lib", "middle"])
        self.assertTrue(group["cycle"])
        self.assertIn("CYCLE_BOOTSTRAP_REVIEW_REQUIRED", group["holds"])
        self.assertEqual(self.group(value, "app")["held_prerequisites"], [group["id"]])

    def test_self_cycle_retained(self):
        self.data["build_dependencies"][0]["toolchain"] = ["compiler"]
        self.assertTrue(self.group(self.run_plan(), "compiler")["cycle"])

    def test_missing_build_metadata_is_conservatively_selected(self):
        self.data["build_dependencies"].pop()
        value = self.run_plan()
        self.assertIn("unrelated", value["unknown_dependency_coverage"])
        self.assertIn("UNKNOWN_BUILD_METADATA", self.package(value, "unrelated")["holds"])

    def test_missing_provides_cannot_hide_possible_consumers(self):
        del self.data["packages"][0]["provides"]
        value = self.run_plan()
        self.assertEqual(len(value["packages"]), 5)
        self.assertIn("UNKNOWN_PROVIDER_COVERAGE_FULL_SET_REVIEW", value["global_holds"])
        self.assertTrue(all(row["held"] for row in value["groups"]))

    def test_missing_runtime_deps_selects_unknown_consumer_and_holds(self):
        del self.data["packages"][4]["depend"]
        value = self.run_plan()
        self.assertIn("UNKNOWN_DEPEND", self.package(value, "unrelated")["holds"])

    def test_external_explicit_hold_and_owner_retained(self):
        self.data["build_dependencies"][0]["disposition"] = "external"
        self.data["build_dependencies"][1].update(disposition="hold", hold_reason="ABI transition needs review", owner=None)
        value = self.run_plan()
        self.assertIn("EXTERNAL_UPDATE_REVIEW", self.package(value, "compiler")["holds"])
        self.assertEqual(self.package(value, "lib")["hold_reason"], "ABI transition needs review")
        self.assertIn("UNKNOWN_PACKAGE_OWNER", self.package(value, "lib")["holds"])
        self.assertTrue(self.group(value, "app")["held"])

    def test_unknown_source_pins_and_capacity_hold(self):
        self.data["sources"].pop(0)
        self.data["capacity"] = dict(native_aarch64_slots=None, owner=None, reference=None)
        value = self.run_plan()
        self.assertIn("UNKNOWN_SOURCE_PINS", self.package(value, "compiler")["holds"])
        self.assertIn("CAPACITY_OR_CAPACITY_OWNER_UNAVAILABLE", value["global_holds"])

    def test_source_toolchain_and_advisory_roots_have_distinct_reasons(self):
        self.data["changed"]["toolchains"] = ["compiler"]
        self.data["changed"]["advisories"] = [dict(package="lib", reference="AVG-fixture-review")]
        value = self.run_plan()
        self.assertEqual({row["kind"] for row in self.package(value, "compiler")["reasons"]}, {"SOURCE_CHANGE", "TOOLCHAIN_CHANGE"})
        self.assertIn("ADVISORY_REVIEW", {row["kind"] for row in self.package(value, "lib")["reasons"]})

    def test_unknown_advisory_alias_or_toolchain_forces_full_review(self):
        for changed in (dict(sources=[], toolchains=[], advisories=[dict(package="c-compiler", reference="AVG-fixture")]),
                        dict(sources=[], toolchains=["unlisted-compiler"], advisories=[]),
                        dict(sources=["unlisted-source"], toolchains=[], advisories=[])):
            with self.subTest(changed=changed):
                self.data["changed"] = changed
                value = self.run_plan()
                self.assertEqual(len(value["packages"]), 5)
                self.assertEqual(len(value["unresolved_roots"]), 1)
                self.assertTrue(all(row["held"] for row in value["groups"]))

    def test_no_roots_does_not_invent_a_build(self):
        self.data["changed"]["sources"] = []
        value = self.run_plan()
        self.assertEqual(value["groups"], [])
        self.assertEqual(value["packages"], [])

    def test_determinism_under_input_permutations(self):
        expected = self.run_plan()
        for field in ("packages", "sources", "build_dependencies"):
            self.data[field].reverse()
        self.assertEqual(self.run_plan(), expected)

    def test_invalid_duplicate_unknown_fields_and_unpinned_sources_refused(self):
        variants = []
        value = fixture();value["packages"].append(value["packages"][0]);variants.append(value)
        value = fixture();value["build_dependencies"][0]["typo"] = [];variants.append(value)
        value = fixture();value["sources"][0]["sources"][0].pop("commit");variants.append(value)
        value = fixture();value["packages"][0]["provides"] = ["compiler>=1"];variants.append(value)
        value = fixture();value["build_dependencies"][0]["disposition"] = "hold";variants.append(value)
        value = fixture();value["packages"][0]["arch"] = "x86_64";variants.append(value)
        for value in variants:
            with self.subTest(value=value), self.assertRaises((m.r.Error, m.s.Error)):
                m.plan(value)

    def test_unmapped_sources_are_reported_and_held(self):
        self.data["sources"].append(dict(self.data["sources"][0], id="unmapped"))
        value = self.run_plan()
        self.assertEqual(value["unmapped_sources"], ["unmapped"])
        self.assertIn("UNMAPPED_SOURCE_RECORDS", value["global_holds"])

    def test_version_rejected_changed_provider_keeps_consumer_in_review(self):
        self.data["packages"][1]["version"] = "2-1"
        self.data["packages"][2]["depend"] = ["lib<2-1"]
        self.data["changed"]["sources"] = ["lib"]
        value = self.run_plan()
        self.assertTrue(self.group(value, "middle")["held"])
        self.assertTrue(self.group(value, "app")["held"])
        self.assertIn(False, [edge["relation_satisfied"] for edge in value["build_inputs"]])

    def test_unchanged_held_prerequisite_blocks_consumer(self):
        self.data["changed"]["sources"] = ["app"]
        self.data["build_dependencies"][1].update(disposition="hold", hold_reason="Unavailable baseline input")
        value = self.run_plan()
        self.assertEqual([row["name"] for row in value["packages"]], ["app"])
        self.assertIn("HELD_BASELINE_INPUT:middle", self.package(value, "app")["holds"])
        baseline = {row["name"]: row for row in value["baseline_inputs"]}
        self.assertTrue(baseline["middle"]["held"])
        self.assertEqual(baseline["lib"]["hold_reason"], "Unavailable baseline input")
        self.assertIn("lib", baseline["middle"]["prerequisites"])

    def test_post_change_metadata_cannot_claim_prior_provider_coverage(self):
        self.data["metadata_role"] = "post-change-release"
        with self.assertRaises(m.r.Error):
            self.run_plan()

    def test_unchanged_external_baseline_is_not_a_current_update_hold(self):
        self.data["changed"]["sources"] = ["lib"]
        self.data["build_dependencies"][0]["disposition"] = "external"
        value = self.run_plan()
        self.assertEqual(value["baseline_inputs"][0]["holds"], [])
        self.assertFalse(value["baseline_inputs"][0]["held"])
        self.assertFalse(self.group(value, "lib")["held"])

    def test_version_rejected_alternative_is_not_lost_when_another_matches(self):
        self.data["packages"][4]["provides"] = ["c-compiler=1-1"]
        self.data["changed"]["sources"] = ["unrelated"]
        value = self.run_plan()
        self.assertIn("UNSATISFIED_NAMED_PROVIDER_REVIEW:unrelated", self.package(value, "lib")["holds"])

    def test_graph_bounds_refuse_instead_of_truncating(self):
        for bound in ("MAX_CHECKS", "MAX_RELATIONS", "MAX_WORK"):
            with self.subTest(bound=bound), patch.object(m, bound, 1), self.assertRaises(m.r.Error):
                self.run_plan()

    def test_comparator_failure_has_no_alternate_order(self):
        with patch.object(m.r, "run", side_effect=m.r.Error("vercmp unavailable")), self.assertRaises(m.r.Error):
            self.run_plan()

    def test_iterative_scc_handles_long_chain(self):
        graph = {str(i): {str(i - 1)} if i else set() for i in range(3000)}
        self.assertEqual(len(m.components(graph)), 3000)


class CliTests(unittest.TestCase):
    def invoke(self, path, digest, format="json"):
        return subprocess.run([sys.executable, "-B", str(SCRIPT), "--input", str(path), "--input-sha256", digest,
                               "--format", format], capture_output=True, text=True, timeout=30)

    def test_json_text_pins_original_inputs_and_no_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input.json"
            raw = json.dumps(fixture()).encode();path.write_bytes(raw)
            digest = hashlib.sha256(raw).hexdigest()
            result = self.invoke(path, digest)
            self.assertEqual(result.returncode, 0, result.stderr)
            value = json.loads(result.stdout)
            self.assertEqual(value["input"], dict(bytes=len(raw), sha256=digest, authenticated=False))
            self.assertEqual(len(value["implementation_dependencies"]), 3)
            other = self.invoke(path, digest, "text")
            self.assertEqual(other.returncode, 0, other.stderr)
            self.assertIn("Builds NOT_RUN", other.stdout)
            self.assertIn("REVERSE_BUILD_INPUT", other.stdout)
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual(list(Path(temporary).iterdir()), [path])

    def test_bad_digest_duplicate_json_and_symlink_refused_without_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input.json"
            for raw, digest in ((b'{}', "0" * 64), (b'{"x":1,"x":2}', None), (b'{"x":NaN}', None)):
                path.write_bytes(raw)
                result = self.invoke(path, digest or hashlib.sha256(raw).hexdigest())
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
            link = path.with_name("link.json");link.symlink_to(path)
            result = self.invoke(link, hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
