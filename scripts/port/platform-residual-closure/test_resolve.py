#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Synthetic metadata-only dependency and policy counterexamples."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location(
    "residual_resolver_under_test", Path(__file__).with_name("resolve.py"))
resolver = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = resolver
SPEC.loader.exec_module(resolver)


def record(name, version="1.0-1", **changes):
    value = {
        "name": name, "version": version, "repo": "fixture", "arch": "aarch64",
        "depends": [], "provides": [], "conflicts": [], "replaces": [],
        "archive": {"filename": f"{name}-{version}-aarch64.pkg.tar.xz",
                    "bytes": 100, "sha256": "a" * 64,
                    "signature_sha256": "b" * 64, "signature_bytes": 80},
        "files": [f"usr/share/fixture/{name}"], "hooks": [],
        "review": {"source_revision": "c" * 40,
                   "license_review": "fixture-reviewed",
                   "grant_review": "fixture-reviewed", "maintainer": "fixture-owner"},
    }
    value.update(changes)
    return value


def pin(value):
    return {key: value[key] for key in ("name", "version", "repo")}


def catalog_tar(members):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
        for member, content in members:
            archive.addfile(member, io.BytesIO(content))
    return stream.getvalue()


def catalog_member(name, content=b"%NAME%\nfixture\n\n", **options):
    member = tarfile.TarInfo(name)
    member.size = len(content)
    for key, value in options.items():
        setattr(member, key, value)
    return member, content


class ResolveTests(unittest.TestCase):
    def solve(self, catalog, roots=None, anchors=None, protected=None, **kwargs):
        anchors = [] if anchors is None else anchors
        if roots is None:
            roots = [pin(catalog[0])]
        inputs = copy.deepcopy((anchors, catalog, roots, protected or {}))
        result = resolver.resolve(anchors, catalog, roots, protected or {}, **kwargs)
        self.assertEqual((anchors, catalog, roots, protected or {}), inputs,
                         "resolver changed caller metadata")
        self.assertIn(result["status"], ("PASS", "FAIL"))
        self.assertIn(result["metadata_graph_status"], ("PASS", "FAIL"))
        json.dumps(result, allow_nan=False)
        return result

    def failed(self, result, code, graph=True):
        self.assertEqual(result["status"], "FAIL")
        if graph:
            self.assertEqual(result["metadata_graph_status"], "FAIL")
        self.assertIn(code, {row["code"] for row in result["blockers"]})

    def names(self, result):
        return {(row["name"], row["version"], row["repo"])
                for row in result["selected"]}

    def failed_catalog_reason(self, result, reason):
        self.failed(result, "invalid-catalog-package")
        self.assertTrue(any(row["code"] == "invalid-catalog-package"
                            and row.get("reason") == reason
                            for row in result["blockers"]))

    def test_unique_exact_dependency_and_input_immutability(self):
        app = record("app", depends=["dependency>=1.0"])
        dependency = record("dependency", "1.10-2")
        result = self.solve([app, dependency])
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["metadata_graph_status"], "PASS")
        self.assertIs(result["transaction_accepted"], False)
        self.assertIs(result["system_mutation"], False)
        self.assertEqual(result["archive_signature_authentication"], "NOT RUN")
        self.assertEqual(self.names(result), {tuple(pin(v).values()) for v in (app, dependency)})
        edge, = result["edges"]
        self.assertEqual(edge["selected"]["name"], "dependency")

    def test_root_pin_disambiguates_versions_and_repositories(self):
        wanted = record("app", "2.0-1")
        alternatives = [record("app", "1.0-1"), record("app", "2.0-1", repo="other")]
        result = self.solve([*alternatives, wanted], roots=[pin(wanted)])
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(self.names(result), {("app", "2.0-1", "fixture")})

    def test_unique_versioned_virtual_provider(self):
        app = record("app", depends=["abi>=2.0"])
        provider = record("implementation", provides=["abi=2.3-1"])
        result = self.solve([app, provider])
        self.assertEqual(result["status"], "PASS")
        edge, = result["edges"]
        self.assertEqual(edge["selected"]["name"], "implementation")
        self.assertEqual(edge["alternatives"][0]["effective_version"], "2.3-1")

    def test_unversioned_provide_does_not_satisfy_version_constraint(self):
        self.failed(self.solve([record("app", depends=["abi>=2"]),
                                record("implementation", provides=["abi"])]),
                    "unsatisfied-dependency")

    def test_ambiguous_catalog_never_prefers_exact_name(self):
        result = self.solve([record("app", depends=["abi"]), record("abi"),
                             record("other", provides=["abi"])])
        self.failed(result, "ambiguous-provider")
        self.assertEqual({r["name"] for r in result["edges"][0]["alternatives"]},
                         {"abi", "other"})
        self.assertIsNone(result["edges"][0]["selected"])

    def test_ambiguous_already_selected_providers(self):
        app = record("app", depends=["abi"])
        result = self.solve([app], anchors=[record("one", provides=["abi"]),
                                            record("two", provides=["abi"])])
        self.failed(result, "ambiguous-provider")

    def test_selected_provider_precedes_unused_catalog_alternative(self):
        app = record("app", depends=["abi>=2"])
        selected = record("one", provides=["abi=2"])
        result = self.solve([app, record("two", provides=["abi=3"])], anchors=[selected])
        self.assertEqual(result["status"], "PASS")
        self.assertNotIn("two", {r[0] for r in self.names(result)})

    def test_version_constraints_numeric_epoch_and_release(self):
        for requirement, version, passes in [
            ("dep>1.9", "1.10-1", True), ("dep<1.10", "1.9-9", True),
            ("dep>=1:1.0", "1:1.0-1", True), ("dep>=1:1.0", "9.0-1", False),
            ("dep>1.0-1", "1.0-2", True), ("dep<=1.0-1", "1.0-2", False),
            ("dep=1.0-2", "1.0-2", True), ("dep=1.0-2", "1.0-3", False),
        ]:
            with self.subTest(requirement=requirement, version=version):
                result = self.solve([record("app", depends=[requirement]), record("dep", version)])
                if passes:
                    self.assertEqual(result["status"], "PASS")
                else:
                    self.failed(result, "unsatisfied-dependency")

    def test_missing_requirement_and_missing_root_refuse(self):
        self.failed(self.solve([record("app", depends=["missing"])]),
                    "unsatisfied-dependency")
        result = self.solve([record("app")], roots=[pin(record("missing"))])
        self.assertEqual(result["metadata_graph_status"], "FAIL")
        self.assertEqual(result["status"], "FAIL")

    def test_contradictory_versions_cannot_silently_replace_selected(self):
        app = record("app", depends=["dep=1.0-1", "dep=2.0-1"])
        result = self.solve([app, record("dep"), record("dep", "2.0-1")])
        self.failed(result, "selected-version-contradiction")
        self.assertLessEqual(sum(r[0] == "dep" for r in self.names(result)), 1)

    def test_protected_python_replacement_refused_with_or_without_anchor(self):
        new = record("python", "3.14.8-1")
        for anchors in ([], [record("python", "3.14.7-1")]):
            with self.subTest(anchored=bool(anchors)):
                self.failed(self.solve([new], anchors=anchors,
                                       protected={"python": "3.14.7-1"}),
                            "protected-replacement")

    def test_preserved_protected_python_accepts_separate_alternative_catalog(self):
        old, new = record("python", "3.14.7-1"), record("python", "3.14.8-1")
        app = record("app", depends=["python>=3.14"])
        result = self.solve([app, new], anchors=[old], protected={"python": "3.14.7-1"})
        self.assertEqual(result["status"], "PASS")
        self.assertIn(("python", "3.14.7-1", "fixture"), self.names(result))
        self.assertNotIn(("python", "3.14.8-1", "fixture"), self.names(result))

    def test_explicit_alternative_branch_is_not_protected_baseline_adoption(self):
        new = record("python", "3.14.8-1")
        app = record("app", depends=["python>=3.14"])
        result = self.solve([app], anchors=[new], protected={"python": "3.14.8-1"})
        self.assertEqual(result["status"], "PASS")
        self.assertIn(("python", "3.14.8-1", "fixture"), self.names(result))
        self.assertNotIn(("python", "3.14.7-1", "fixture"), self.names(result))
        self.failed(self.solve([new], protected={"python": "3.14.7-1"}),
                    "protected-replacement")

    def test_declared_conflict_and_replacement_do_not_remove_packages(self):
        for field, code in (("conflicts", "declared-conflict"),
                            ("replaces", "declared-replacement")):
            with self.subTest(field=field):
                app = record("app", **{field: ["abi>=2"]})
                provider = record("dep", provides=["abi=2"])
                result = self.solve([app], anchors=[provider])
                self.failed(result, code)
                self.assertIn(("dep", "1.0-1", "fixture"), self.names(result))

    def test_nonmatching_conflict_and_replacement_do_not_false_refuse(self):
        app = record("app", conflicts=["dep>2"], replaces=["absent"])
        result = self.solve([app], anchors=[record("dep", "1.0-1")])
        self.assertEqual(result["status"], "PASS")

    def test_cycle_terminates_and_retains_every_dependency(self):
        one, two = record("one", depends=["two"]), record("two", depends=["one"])
        result = self.solve([one, two])
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(len(result["selected"]), 2)
        self.assertEqual(len(result["edges"]), 2)
        self.assertTrue(result["cycles"], "cycle must be reported rather than dropped")

    def test_package_limit(self):
        app = record("app", depends=["one", "two"])
        self.failed(self.solve([app, record("one"), record("two")],
                               limits=resolver.Limits(max_packages=2)), "resource-package")

    def test_edge_limit(self):
        app = record("app", depends=["one", "two", "three"])
        self.failed(self.solve([app, *[record(n) for n in ("one", "two", "three")]],
                               limits=resolver.Limits(max_edges=2)), "resource-edge")

    def test_depth_limit(self):
        values = [record(f"node{i}", depends=[f"node{i+1}"] if i < 4 else [])
                  for i in range(5)]
        self.failed(self.solve(values, limits=resolver.Limits(max_depth=2)), "resource-depth")

    def test_elapsed_limit_without_sleep(self):
        ticks = iter([0.0, 121.0])
        result = self.solve([record("app")], clock=lambda: next(ticks, 121.0))
        self.failed(result, "resource-time")

    def test_report_limit_is_finite_even_when_reporting_failure(self):
        app = record("app", depends=["missing" + str(i) for i in range(20)])
        result = self.solve([app], limits=resolver.Limits(max_report_bytes=4096))
        self.failed(result, "resource-report")
        self.assertLessEqual(len(json.dumps(result, sort_keys=True).encode()), 4096)

    def test_production_bounds_cannot_be_relaxed_or_disabled(self):
        bounds = {"max_packages": 1024, "max_edges": 16384, "max_depth": 128,
                  "max_seconds": 120, "max_report_bytes": 16 * 1024 * 1024}
        for field, maximum in bounds.items():
            self.assertEqual(getattr(resolver.Limits(), field), maximum)
            for bad in (True, 0, -1, maximum + 1, float("inf"), float("nan")):
                with self.subTest(field=field, bad=bad):
                    with self.assertRaises(ValueError):
                        self.solve([record("app")], limits=resolver.Limits(**{field: bad}))

    def test_unknown_files_and_hooks_fail_overall_not_dependency_graph(self):
        for field, code in (("files", "unknown-file-ownership"), ("hooks", "unknown-hooks")):
            with self.subTest(field=field):
                result = self.solve([record("app", **{field: None})])
                self.failed(result, code, graph=False)
                self.assertEqual(result["metadata_graph_status"], "PASS")

    def test_unknown_source_license_grant_and_maintainer_fail_explicitly(self):
        for field, code in (("source_revision", "unknown-source-revision"),
                            ("license_review", "unknown-license-review"),
                            ("grant_review", "unknown-grant-review"),
                            ("maintainer", "unknown-maintainer")):
            with self.subTest(field=field):
                value = record("app"); value["review"][field] = None
                result = self.solve([value])
                self.failed(result, code, graph=False)
                self.assertEqual(result["metadata_graph_status"], "PASS")
        result = self.solve([record("app", review=None)])
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["metadata_graph_status"], "PASS")
        self.assertTrue({"unknown-source-revision", "unknown-license-review",
                         "unknown-grant-review", "unknown-maintainer"}.issubset(
                             {r["code"] for r in result["blockers"]}))

    def test_source_pin_requires_full_lowercase_commit_or_content_digest(self):
        for bad in ("not-a-source-pin", "c" * 39, "C" * 40, "c" * 63, "g" * 64):
            with self.subTest(source_revision=bad):
                value = record("app"); value["review"]["source_revision"] = bad
                result = self.solve([value])
                self.failed(result, "unknown-source-revision", graph=False)
                self.assertEqual(result["metadata_graph_status"], "PASS")
        value = record("app"); value["review"]["source_revision"] = "d" * 64
        self.assertEqual(self.solve([value])["status"], "PASS")

    def test_explicit_unreviewed_sentinels_cannot_be_recorded_as_success(self):
        for field in ("license_review", "grant_review", "maintainer"):
            for sentinel in ("unknown", "UNRESOLVED", "UNASSIGNED", "NOT RUN",
                             "FAIL", "UNREVIEWED", "  Unknown  "):
                with self.subTest(field=field, sentinel=sentinel):
                    value = record("app"); value["review"][field] = sentinel
                    result = self.solve([value])
                    self.failed(result, "unknown-" + field.replace("_", "-"), graph=False)
                    self.assertEqual(result["metadata_graph_status"], "PASS")

    def test_unsupported_versions_fail_without_guessing_order(self):
        for version in ("1.0;true", "1.0/1", "1.0\n", "１.0"):
            with self.subTest(version=version):
                result = self.solve([record("app", version)])
                self.failed(result, "invalid-catalog-package")
                self.assertTrue(any(r.get("reason") == "unsupported-version"
                                    for r in result["blockers"]))
        result = self.solve([record("app", "1.0" * 100)])
        self.failed(result, "invalid-catalog-package")
        self.assertTrue(any(r.get("reason") == "invalid-package-identity"
                            for r in result["blockers"]))

    def test_duplicate_file_ownership_not_resolved_by_catalog_selection(self):
        app, dependency = record("app", depends=["dep"]), record("dep")
        app["files"] = dependency["files"] = ["usr/bin/collision"]
        result = self.solve([app, dependency])
        self.failed(result, "file-ownership-collision", graph=False)
        self.assertEqual(result["metadata_graph_status"], "PASS")

    def test_literal_multihyphen_SONAME_version_constraints(self):
        for version in ("0.20.so-64", "libwlroots-0.20.so-64"):
            for requirement, passes in (("libwlroots=" + version, True),
                                        ("libwlroots>=" + version, True),
                                        ("libwlroots<" + version, False),
                                        ("libwlroots=" + version.replace("0.20", "0.21"), False)):
                with self.subTest(requirement=requirement):
                    result = self.solve([record("app", depends=[requirement]),
                                         record("wlroots", provides=["libwlroots=" + version])])
                    if passes:
                        self.assertEqual(result["status"], "PASS")
                    else:
                        self.failed(result, "unsatisfied-dependency")

    def test_duplicate_dependency_occurrences_are_preserved_not_ambiguous(self):
        app = record("app", depends=["dep>=1", "dep>=1"])
        result = self.solve([app, record("dep")])
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(len(result["edges"]), 2)
        self.assertEqual([edge["status"] for edge in result["edges"]], ["SATISFIED"] * 2)
        self.assertEqual(len(result["selected"]), 2)
        self.assertIn({"package": "app", "field": "depends", "directive": "dep>=1",
                       "occurrences": 2}, result["duplicate_declarations"])

    def test_missing_signature_pin_is_custody_failure_not_graph_abort(self):
        app = record("app", depends=["dep"])
        app["archive"]["signature_bytes"] = app["archive"]["signature_sha256"] = None
        result = self.solve([app, record("dep")])
        self.failed(result, "unknown-signature-pin", graph=False)
        self.assertEqual(result["metadata_graph_status"], "PASS")
        self.assertEqual(result["edges"][0]["status"], "SATISFIED")
        self.assertEqual(len(result["selected"]), 2)
        self.assertIs(result["archive_budget"]["complete"], False)

    def test_late_provider_rechecks_an_earlier_satisfied_edge(self):
        # A selected ABI provider initially wins; a later independent dependency
        # introduces another ABI provider and invalidates that earlier decision.
        app = record("app", depends=["abi", "second-provider"])
        second = record("second-provider", provides=["abi"])
        result = self.solve([app, second], anchors=[record("first-provider", provides=["abi"])])
        self.failed(result, "ambiguous-provider")
        edge = next(e for e in result["edges"] if e["requirement"] == "abi")
        self.assertEqual(edge["status"], "AMBIGUOUS")
        self.assertEqual({candidate["name"] for candidate in edge["alternatives"]},
                         {"first-provider", "second-provider"})
        self.assertTrue(any(e["requirement"] == "second-provider" and e["status"] == "SATISFIED"
                            for e in result["edges"]))

    def test_inert_catalog_reads_regular_fields_without_filesystem_extraction(self):
        raw = catalog_tar([catalog_member("fixture-1/desc"),
                           catalog_member("fixture-1/depends", b"%DEPENDS%\ndep\ndep\n\n")])
        with mock.patch.object(tarfile.TarFile, "extract", side_effect=AssertionError("extraction")), \
             mock.patch.object(tarfile.TarFile, "extractall", side_effect=AssertionError("extraction")):
            grouped, unavailable = resolver.read_catalog(raw, "fixture", time.monotonic() + 5)
        self.assertEqual(unavailable, [])
        self.assertEqual(grouped["fixture-1"]["depends"]["fields"]["DEPENDS"], ["dep", "dep"])

    def test_sparse_catalog_entry_cannot_remain_selectable(self):
        sparse = catalog_member("sparse-1/depends", b"X", pax_headers={
            "GNU.sparse.map": "0,1", "GNU.sparse.size": "1"})
        raw = catalog_tar([catalog_member("sparse-1/desc"), sparse,
                           catalog_member("sparse-1/files", b"%FILES%\nusr/bin/sparse\n\n"),
                           catalog_member("ordinary-1/desc")])
        grouped, unavailable = resolver.read_catalog(raw, "fixture", time.monotonic() + 5)
        self.assertEqual(unavailable, ["sparse-1"])
        self.assertNotIn("sparse-1", grouped)
        self.assertIn("ordinary-1", grouped)

    def test_catalog_traversal_links_specials_and_duplicates_refuse(self):
        negatives = [
            [catalog_member("../desc")], [catalog_member("./desc")],
            [catalog_member("fixture-1/../../desc")], [catalog_member("/fixture-1/desc")],
            [catalog_member("fixture-1/desc", b"", type=tarfile.SYMTYPE, linkname="outside")],
            [catalog_member("fixture-1/desc", b"", type=tarfile.FIFOTYPE)],
            [catalog_member("fixture-1/desc"), catalog_member("fixture-1/desc")],
        ]
        for members in negatives:
            with self.subTest(names=[m.name for m, _ in members]):
                with self.assertRaises(resolver.Refused):
                    resolver.read_catalog(catalog_tar(members), "fixture", time.monotonic() + 5)

    def test_bound_references_refuse_hash_size_links_and_special_files(self):
        with tempfile.TemporaryDirectory(prefix="residual-reference-test-") as directory:
            root = Path(directory); source = root / "source"; source.write_bytes(b"fixture")
            source.chmod(0o644)
            reference = {"path": str(source), "size": 7,
                         "sha256": hashlib.sha256(b"fixture").hexdigest(), "mode": 0o644}
            self.assertEqual(resolver.bound(reference), b"fixture")
            source.chmod(0o600)
            with self.assertRaises(resolver.Refused):
                resolver.bound(reference)
            source.chmod(0o644)
            for changed in (dict(reference, sha256="0" * 64), dict(reference, size=8)):
                with self.subTest(reference=changed):
                    with self.assertRaises(resolver.Refused):
                        resolver.bound(changed)
            source.write_bytes(b"changed")
            with self.assertRaises(resolver.Refused):
                resolver.bound(reference)
            source.write_bytes(b"fixture")
            symlink = root / "link"; symlink.symlink_to(source)
            with self.assertRaises(resolver.Refused):
                resolver.bound(dict(reference, path=str(symlink)))
            parent_link = root / "parent"; parent_link.symlink_to(root, target_is_directory=True)
            with self.assertRaises(resolver.Refused):
                resolver.bound(dict(reference, path=str(parent_link / "source")))
            hardlink = root / "hard"; os.link(source, hardlink)
            with self.assertRaises(resolver.Refused):
                resolver.bound(reference)
            hardlink.unlink()
            fifo = root / "fifo"; os.mkfifo(fifo)
            with self.assertRaises(resolver.Refused):
                resolver.bound(dict(reference, path=str(fifo)))
            # A rejected directory must not strand the descriptor opened before
            # the regular-file guard, even though fdopen cannot own that fd.
            with mock.patch.object(resolver.os, "close", wraps=os.close) as close:
                with self.assertRaises(resolver.Refused):
                    resolver.bound(dict(reference, path=str(root)))
                self.assertEqual(close.call_count, 1)

    def test_noncanonical_file_spellings_cannot_hide_shared_ownership(self):
        for spelling in ("usr//bin/shared", "usr/./bin/shared", "usr/bin//shared",
                         "usr/bin/../bin/shared"):
            with self.subTest(spelling=spelling):
                app = record("app", depends=["dep"], files=[spelling])
                dependency = record("dep", files=["usr/bin/shared"])
                self.failed_catalog_reason(self.solve([app, dependency]), "invalid-file-path")
        self.failed(self.solve([record("app", depends=["dep"], files=["usr/bin/shared"]),
                                record("dep", files=["usr/bin/shared"])]),
                    "file-ownership-collision", graph=False)

    def test_one_terminal_directory_slash_is_canonical(self):
        app = record("app", depends=["dep"], files=["usr/", "usr/bin/", "usr/bin/app"])
        dependency = record("dep", files=["usr/", "usr/bin/", "usr/bin/dep"])
        result = self.solve([app, dependency])
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["metadata_graph_status"], "PASS")
        self.assertEqual(self.names(result), {("app", "1.0-1", "fixture"),
                                             ("dep", "1.0-1", "fixture")})

    def test_repeated_directory_slashes_and_dot_components_are_refused(self):
        for spelling in ("usr//", "usr///", "usr/bin//", "usr/bin///",
                         "usr//bin/", "usr///bin/", "usr/./bin/", "usr/../bin/",
                         "usr/bin/./", "usr/bin/../", "./usr/", "../usr/",
                         "/usr/", "//usr/", "///usr/"):
            with self.subTest(spelling=spelling):
                self.failed_catalog_reason(self.solve([record("app", files=[spelling])]),
                                           "invalid-file-path")

    def test_unused_supplied_noncanonical_file_paths_fail_at_ingestion(self):
        for spelling in ("usr//", "usr///", "usr/bin//", "usr/bin///",
                         "usr//bin/", "usr///bin/", "usr/./", "usr/../",
                         "usr/./bin/", "usr/../bin/", "./usr/", "../usr/",
                         "/usr/", "", "usr/\x00", "usr/\n"):
            with self.subTest(spelling=repr(spelling)):
                unused = record("unused", files=[spelling])
                with self.assertRaisesRegex(resolver.Refused, "invalid-file-path"):
                    resolver.record(unused)
                result = self.solve([record("app"), unused])
                self.failed_catalog_reason(result, "invalid-file-path")
                self.assertEqual(self.names(result), {("app", "1.0-1", "fixture")})

    def test_unused_canonical_single_slash_and_paths_do_not_claim_ownership(self):
        unused = record("unused", files=["usr/", "usr/bin/", "usr/share/fixture/app"])
        result = self.solve([record("app"), unused])
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(self.names(result), {("app", "1.0-1", "fixture")})
        self.assertNotIn("file-ownership-collision", {row["code"] for row in result["blockers"]})

    def test_unknown_unused_file_and_policy_facts_do_not_block_transaction(self):
        for files in (None, []):
            with self.subTest(files=files):
                unused = record("unused", files=files, archive=None, hooks=None, review=None,
                                source_grant="UNRESOLVED", maintainer="UNASSIGNED")
                result = self.solve([record("app"), unused])
                self.assertEqual(result["status"], "PASS")
                self.assertEqual(self.names(result), {("app", "1.0-1", "fixture")})
        unused = record("unused", archive=None, hooks=None, review=None)
        del unused["files"]
        self.assertEqual(self.solve([record("app"), unused])["status"], "PASS")
        result = self.solve([record("app", files=None)])
        self.failed(result, "unknown-file-ownership", graph=False)
        self.assertEqual(result["metadata_graph_status"], "PASS")

    def test_unused_file_declaration_container_and_entry_types_refuse(self):
        for files in ("UNKNOWN", True, 1, {}, [None], [True], [1], [{}], [[]]):
            with self.subTest(files=files):
                unused = record("unused", files=files)
                with self.assertRaisesRegex(resolver.Refused, "invalid-file-list"):
                    resolver.record(unused)
                self.failed_catalog_reason(self.solve([record("app"), unused]),
                                           "invalid-file-list")

    def test_unused_duplicate_directories_and_regular_paths_refuse(self):
        for files in (["usr/", "usr/"], ["usr/bin/fixture", "usr/bin/fixture"]):
            with self.subTest(files=files):
                self.failed_catalog_reason(self.solve([record("app"), record("unused", files=files)]),
                                           "duplicate-file-list")

    def test_unused_file_count_and_path_length_caps_have_small_controls(self):
        self.assertEqual(resolver.MAX_FILE_PATHS, 200000)
        with mock.patch.object(resolver, "MAX_FILE_PATHS", 2):
            self.assertEqual(self.solve([record("app"), record("unused", files=["usr/", "usr/a"])])["status"], "PASS")
            self.failed_catalog_reason(self.solve([record("app"), record("unused", files=["usr/", "usr/a", "usr/b"])]),
                                       "invalid-file-list")
        self.assertEqual(self.solve([record("app"), record("unused", files=["a" * 4096])])["status"], "PASS")
        self.failed_catalog_reason(self.solve([record("app"), record("unused", files=["a" * 4097])]),
                                   "invalid-file-path")

    def test_malformed_anchor_supplied_paths_fail_at_ingestion_too(self):
        for spelling in ("usr//", "usr///", "usr/./"):
            with self.subTest(spelling=spelling):
                self.failed(self.solve([record("app")], anchors=[record("anchor", files=[spelling])]),
                            "invalid-file-path")

    def test_nonfinite_values_anywhere_in_selected_or_unused_metadata_refuse(self):
        for number in (float("nan"), float("inf"), float("-inf")):
            for location in ("top", "nested", "review-extra", "archive-extra"):
                for selected in (True, False):
                    with self.subTest(number=repr(number), location=location,
                                      selected=selected):
                        poisoned = record("app" if selected else "unused")
                        if location == "top":
                            poisoned["unused_metadata"] = number
                        elif location == "nested":
                            poisoned["unused_metadata"] = {"rows": [0, {"deep": [number]}]}
                        else:
                            container = poisoned[location.split("-", 1)[0]]
                            container["unused_metadata"] = {"deep": [number]}
                        values = [poisoned] if selected else [record("app"), poisoned]
                        self.failed(self.solve(values), "nonfinite-metadata")

    def test_nonfinite_anchor_and_policy_metadata_cannot_be_ignored(self):
        for number in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(number=repr(number), location="anchor"):
                anchor = record("anchor", unused_metadata={"deep": [number]})
                self.failed(self.solve([record("app")], anchors=[anchor]),
                            "nonfinite-metadata")
            with self.subTest(number=repr(number), location="root-extra"):
                root = dict(pin(record("app")), unused_metadata={"deep": [number]})
                self.failed(self.solve([record("app")], roots=[root]),
                            "nonfinite-metadata")

    def test_finite_unused_metadata_and_empty_hook_policy_pass(self):
        values = {"deep": [0, -1, 1.25, -0.0, None, True, "finite"]}
        result = self.solve([record("app", unused_metadata=values, hooks=[]),
                             record("unused", unused_metadata=values, hooks=[])])
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["metadata_graph_status"], "PASS")

    def test_nonempty_string_hook_labels_cannot_claim_review(self):
        for hooks in (["unknown"], ["PASS"], ["reviewed"],
                      ["safe-install-hook"], ["usr/share/libalpm/hooks/fixture.hook"],
                      ["PASS", "unknown"]):
            with self.subTest(hooks=hooks):
                result = self.solve([record("app", hooks=hooks)])
                self.failed(result, "unreviewed-hooks", graph=False)
                self.assertEqual(result["metadata_graph_status"], "PASS")

    def test_structured_unknown_hook_policy_is_not_accepted(self):
        for hooks in ([{"status": "UNKNOWN"}],
                      [{"status": "PASS", "sha256": "a" * 64}],
                      [{"policy": {"reviewed": True}, "path": "fixture.hook"}],
                      [None], [True], ["reviewed", {"status": "UNKNOWN"}]):
            with self.subTest(hooks=hooks):
                self.failed(self.solve([record("app", hooks=hooks)]),
                            "invalid-hook-decisions")

    def test_raw_json_nonfinite_constants_and_exponent_overflow_refuse(self):
        for literal in ("NaN", "Infinity", "-Infinity", "1e999", "-1e999"):
            for location in ("selected", "unused"):
                raw = ('{"' + location + '": {"ignored": [0, {"deep": '
                       + literal + '}]}}').encode()
                with self.subTest(literal=literal, location=location):
                    with self.assertRaisesRegex(resolver.Refused, "nonfinite-metadata"):
                        resolver.json_document(raw)
        with self.assertRaises(json.JSONDecodeError):
            resolver.json_document(b'{"unused": +Infinity}')
        finite = {"unused": {"numbers": [0, 1.25, -1000.0],
                              "labels": ["NaN", "Infinity", "-Infinity"]}}
        self.assertEqual(resolver.json_document(json.dumps(finite).encode()), finite)

    def test_canonical_encoding_never_emits_nonfinite_json(self):
        for number in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(number=repr(number)):
                with self.assertRaises(ValueError):
                    resolver.encoded({"unused": {"deep": [number]}})
        value = {"unused": [0, 1.25, None, "NaN"]}
        self.assertEqual(json.loads(resolver.encoded(value)), value)

    def test_unused_cyclic_metadata_returns_finite_failure(self):
        cycle = []
        cycle.append(cycle)
        unused = record("unused", unused_metadata={"deep": cycle})
        result = resolver.resolve([], [record("app"), unused],
                                  [pin(record("app"))], {})
        self.failed(result, "invalid-metadata-cycle")
        json.dumps(result, allow_nan=False)
        self.assertIs(unused["unused_metadata"]["deep"][0], cycle)

    def test_metadata_depth_and_node_bounds_have_small_causal_fixtures(self):
        value = 0
        for _ in range(128):
            value = [value]
        resolver.finite_metadata(value, lambda: None)
        with self.assertRaisesRegex(resolver.Refused, "resource-metadata-depth"):
            resolver.finite_metadata([value], lambda: None)
        with mock.patch.object(resolver, "MAX_METADATA_NODES", 3):
            resolver.finite_metadata([0, 1], lambda: None)
        with mock.patch.object(resolver, "MAX_METADATA_NODES", 2):
            with self.assertRaisesRegex(resolver.Refused, "resource-metadata-nodes"):
                resolver.finite_metadata([0, 1], lambda: None)

    def test_metadata_scalar_byte_bound_checks_utf8_and_ascii(self):
        with mock.patch.object(resolver, "MAX_DECODED", 8):
            for value in ("12345678", "é" * 4):
                resolver.finite_metadata(value, lambda: None)
            for value in ("123456789", "é" * 5):
                with self.subTest(value=value):
                    with self.assertRaisesRegex(resolver.Refused, "resource-metadata-bytes"):
                        resolver.finite_metadata(value, lambda: None)

    def test_empty_release_is_refused_in_versions_and_dependency_constraints(self):
        for version in ("1-", "-1", "1:-1"):
            with self.subTest(version=version):
                with self.assertRaises(resolver.Refused):
                    resolver.vercmp(version, "1")
                with self.assertRaises(resolver.Refused):
                    resolver.vercmp("1", version)
            for item in (record("unused", version), record("unused", depends=["dep=" + version])):
                with self.subTest(item=item):
                    result = self.solve([record("app"), item])
                    self.failed(result, "invalid-catalog-package")
                    self.assertTrue(any(r.get("reason") == "unsupported-version"
                                        for r in result["blockers"]))

    def test_malformed_unused_catalog_archive_fails_with_finite_diagnostic(self):
        self.assertEqual(self.solve([record("app"), record("unused")])["status"], "PASS")
        for change, expected in (({"sha256": None}, "invalid-archive-pin"),
                                 ({"bytes": True}, "invalid-archive-pin"),
                                 ({"filename": "../outside.pkg.tar.xz"}, "invalid-archive-pin"),
                                 ({"signature_sha256": None}, "invalid-signature-pin")):
            with self.subTest(change=change):
                unused = record("unused"); unused["archive"].update(change)
                result = self.solve([record("app"), unused])
                self.failed(result, "invalid-catalog-package")
                self.assertTrue(any(r.get("reason") == expected for r in result["blockers"]))
                self.assertEqual({r[0] for r in self.names(result)}, {"app"})

    def test_nondictionary_unused_catalog_entries_are_finite_failures(self):
        for unused in (None, True, "untrusted-unused-entry", ["not", "a", "record"]):
            with self.subTest(unused=unused):
                result = self.solve([record("app"), unused])
                self.failed(result, "invalid-catalog-package")
                self.assertTrue(any(r.get("reason") == "invalid-package-record"
                                    for r in result["blockers"]))
                self.assertEqual({r[0] for r in self.names(result)}, {"app"})

    def test_whitespace_reviews_and_malformed_review_container_cannot_pass(self):
        for field in ("source_revision", "license_review", "grant_review", "maintainer"):
            with self.subTest(field=field):
                value = record("app"); value["review"][field] = " \t "
                self.failed(self.solve([value]), "unknown-" + field.replace("_", "-"), graph=False)
        self.failed(self.solve([record("app", review=["not", "a", "mapping"])]),
                    "invalid-review-record")

    def test_decoded_catalog_bound_counts_directory_and_PAX_bytes(self):
        # These tiny compressed fixtures contain no large regular-file payload.
        # Counting declared regular-file sizes alone misses their tar overhead.
        directories = [catalog_member(f"directory{i}/", b"", type=tarfile.DIRTYPE)
                       for i in range(24)]
        pax = [catalog_member("fixture-1/desc", pax_headers={"comment": "x" * 12000})]
        for members in (directories, pax):
            raw = catalog_tar(members)
            self.assertLess(len(raw), 2048)
            with self.subTest(kind="directories" if members is directories else "PAX"):
                with mock.patch.object(resolver, "MAX_DECODED", 32768):
                    resolver.read_catalog(raw, "fixture", time.monotonic() + 5)
                with mock.patch.object(resolver, "MAX_DECODED", 4096):
                    with self.assertRaisesRegex(resolver.Refused, "catalog-decoded-bound"):
                        resolver.read_catalog(raw, "fixture", time.monotonic() + 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
