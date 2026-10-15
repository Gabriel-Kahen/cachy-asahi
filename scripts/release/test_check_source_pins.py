#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline previews: pure snapshots and real signed, synthetic release fixtures."""
import copy
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


p = module("check_source_pins", "check_source_pins.py")
fixture = module("pin_test_fixture", "test_release.py")
fixture.r = p.r


def row(name="fixture", **changes):
    return {"package": {"name": name, "version": "1.0-1", "arch": "any"},
            "recipe_sha256": "b" * 64, "sources": [{"url": "https://invalid.example/source", "sha256": "c" * 64}],
            **changes}


def snapshot(rows):
    return p.encoded({"schema_version": 1, "packages": rows})


class SnapshotTests(unittest.TestCase):
    def parse(self, raw):
        return p.candidate(raw, p.digest(raw))

    def test_coverage_missing_extra_and_identity_are_separate(self):
        before = p.indexed([row("kept"), row("missing")])
        changed = row("kept");changed["package"]["arch"] = "aarch64"
        result = p.comparison(before, self.parse(snapshot([row("extra"), changed])))
        self.assertEqual(result["coverage"], {"scope": "project-built-release-provenance", "missing": ["missing"],
                                           "extra": ["extra"], "exact_package_set": False})
        self.assertEqual(result["changes"][0]["fields"], ["package"])
        self.assertEqual(p.comparison(before, self.parse(snapshot([])))["coverage"]["missing"], ["kept", "missing"])

    def test_pin_recipe_drift_and_unchanged_are_reported_without_mutation(self):
        rows = [row("kept"), row("changed")];saved = copy.deepcopy(rows)
        after = copy.deepcopy(rows);after[1]["recipe_sha256"] = "d" * 64
        after[1]["sources"][0]["sha256"] = "e" * 64
        result = p.comparison(p.indexed(rows), p.indexed(after))
        self.assertEqual(result["unchanged"], ["kept"])
        self.assertEqual(result["changes"][0]["fields"], ["recipe_sha256", "sources"])
        self.assertTrue(result["coverage"]["exact_package_set"])
        self.assertEqual(rows, saved)

    def test_both_existing_pin_kinds_extras_duplicates_and_order_are_preserved(self):
        sources = [{"url": "fixture:git", "commit": "a" * 40, "note": {"value": 1.25}},
                   {"url": "fixture:archive", "sha256": "c" * 64, "commit": "also-recorded"}]
        source = row(sources=[*sources, sources[0]])
        # The existing inclusive OR accepts a valid archive hash alongside an
        # uninterpreted commit label; this tool must not silently drop it.
        projected = self.parse(snapshot([source]))["fixture"]
        self.assertEqual(projected, source)
        changed = copy.deepcopy(source);changed["sources"].reverse()
        # A palindrome has the same ordered descriptors.
        self.assertEqual(p.comparison(p.indexed([source]), p.indexed([changed]))["changes"], [])
        changed["sources"] = [sources[1], sources[0], sources[0]]
        self.assertEqual(p.comparison(p.indexed([source]), p.indexed([changed]))["changes"][0]["fields"], ["sources"])

    def test_duplicate_packages_keys_and_nonfinite_numbers_refuse(self):
        for raw in (snapshot([row(), row()]), b'{"schema_version":1,"schema_version":1,"packages":[]}',
                    snapshot([row()]).replace(b'"sha256":', b'"sha256":"c","sha256":', 1),
                    b'{"schema_version":1,"packages":[],"extra":NaN}',
                    b'{"schema_version":1,"packages":[],"extra":1e999}'):
            with self.subTest(raw=raw[:70]), self.assertRaises((p.r.Error, ValueError)):
                self.parse(raw)

    def test_bad_schema_pin_and_identity_refuse(self):
        variants = []
        for field, value in (("recipe_sha256", "latest"), ("sources", []),
                             ("sources", [{"url": "fixture:unpinned", "commit": "main"}]),
                             ("sources", [{"url": " ", "sha256": "c" * 64}]),
                             ("sources", [{"url": "fixture:bad", "sha256": 12}]), ("extra", 1)):
            variants.append(snapshot([row(**{field: value})]))
        for key, value in (("name", "../escape"), ("version", "two words"), ("arch", "x86_64")):
            item = row();item["package"][key] = value;variants.append(snapshot([item]))
        variants.extend([b'{"schema_version":true,"packages":[]}', b'{"schema_version":1,"packages":{}}'])
        for raw in variants:
            with self.subTest(raw=raw[:70]), self.assertRaises((p.r.Error, ValueError)):
                self.parse(raw)

    def test_hash_count_byte_and_total_source_bounds_refuse(self):
        raw = snapshot([row()])
        with self.assertRaisesRegex(p.r.Error, "checksum"):
            p.candidate(raw, "0" * 64)
        for constant, value, raw in (("MAX_JSON", 10, raw), ("MAX_PACKAGES", 1, snapshot([row(), row("other")])),
                                     ("MAX_SOURCES", 1, snapshot([row(sources=row()["sources"] * 2)])),
                                     ("MAX_ALL_SOURCES", 1, snapshot([row(), row("other")]))):
            with self.subTest(bound=constant), mock.patch.object(p, constant, value), self.assertRaises(p.r.Error):
                self.parse(raw)

    def test_package_order_gives_identical_deterministic_report(self):
        before = [row("a"), row("b"), row("c")]
        after = [row("b"), row("a", recipe_sha256="e" * 64)]
        self.assertEqual(p.encoded(p.comparison(p.indexed(before), p.indexed(after))),
                         p.encoded(p.comparison(p.indexed(list(reversed(before))), p.indexed(list(reversed(after))))))

    def test_nested_source_metadata_preserves_json_types_but_ignores_object_key_order(self):
        for left, right in ((True, 1), (1, 1.0), (False, 0), (0, 0.0)):
            with self.subTest(before_type=type(left).__name__, after_type=type(right).__name__):
                before = row();before["sources"][0]["metadata"] = {"nested": [{"value": left}]}
                after = copy.deepcopy(before);after["sources"][0]["metadata"]["nested"][0]["value"] = right
                # Parse actual JSON so only supported decoded JSON values enter.
                result = p.comparison(self.parse(snapshot([before])), self.parse(snapshot([after])))
                self.assertEqual(result["changes"][0]["fields"], ["sources"])
                self.assertEqual(result["unchanged"], [])
        before = row();before["sources"][0]["metadata"] = {"b": [True, 1, 1.0], "a": {"y": 2, "x": 3}}
        after = copy.deepcopy(before)
        after["sources"][0] = {"metadata": {"a": {"x": 3, "y": 2}, "b": [True, 1, 1.0]},
                               "sha256": "c" * 64, "url": "https://invalid.example/source"}
        self.assertEqual(p.comparison(p.indexed([before]), p.indexed([after]))["unchanged"], ["fixture"])
        # Lexically different encodings of the same decoded float are equal.
        left = snapshot([row(sources=[{"url": "fixture:source", "sha256": "c" * 64, "value": 1.0}])])
        right = left.replace(b'"value": 1.0', b'"value": 1e0')
        self.assertNotEqual(left, right)
        self.assertEqual(p.comparison(self.parse(left), self.parse(right))["unchanged"], ["fixture"])

    def test_encoder_budget_counts_utf8_and_newline_and_stops_before_later_chunks(self):
        value = {"note": "é" * 12}
        expected = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
        with mock.patch.object(p, "MAX_OUTPUT", len(expected)):
            self.assertEqual(p.encoded(value), expected)
        with mock.patch.object(p, "MAX_OUTPUT", len(expected) - 1), self.assertRaisesRegex(p.r.Error, "report byte bound"):
            p.encoded(value)
        seen = []
        def chunks(*args, **kwargs):
            for chunk in ('"', 'éé', '"'):
                seen.append(chunk)
                yield chunk
            self.fail("encoder consumed beyond the refusing UTF-8 chunk")
        with mock.patch.object(p, "MAX_OUTPUT", 4), mock.patch.object(p.json.JSONEncoder, "iterencode", chunks), \
                self.assertRaisesRegex(p.r.Error, "report byte bound"):
            p.encoded("fixture")
        self.assertEqual(seen, ['"', 'éé'])

    def test_deep_metadata_comparison_is_compact_and_report_stops_early(self):
        nested = "leaf"
        for _ in range(80):nested = [nested]
        before = row();before["sources"][0]["metadata"] = nested
        compact = json.dumps({"schema_version": 1, "packages": [before]}, separators=(",", ":")).encode()
        self.assertLess(len(compact), 1024)
        with mock.patch.object(p, "MAX_OUTPUT", 4096):
            self.assertLess(len(p.encoded(before["sources"], compact=True)), 4096)
            result = p.comparison(self.parse(compact), self.parse(compact))
            self.assertEqual(result["unchanged"], ["fixture"])
            original = p.json.JSONEncoder.iterencode;seen = []
            def counted(encoder, value):
                for chunk in original(encoder, value):
                    seen.append(chunk);yield chunk
            with mock.patch.object(p.json.JSONEncoder, "iterencode", counted), self.assertRaisesRegex(p.r.Error, "report byte bound"):
                p.encoded({"report": before})
            consumed = len(seen)
            complete = list(original(p.json.JSONEncoder(sort_keys=True, indent=2), {"report": before}))
            self.assertLess(consumed, len(complete))
            self.assertLess(sum(len(chunk) for chunk in seen[:-1]), 4096)


class SignedPreviewTests(unittest.TestCase):
    setUpClass = classmethod(fixture.ReleaseTests.setUpClass.__func__)
    tearDownClass = classmethod(fixture.ReleaseTests.tearDownClass.__func__)
    setUp = fixture.ReleaseTests.setUp
    put = fixture.ReleaseTests.put
    ref = fixture.ReleaseTests.ref
    save_spec = fixture.ReleaseTests.save_spec
    stage = fixture.ReleaseTests.stage

    def prepare(self, rows=None):
        self.stage()
        self.snapshot_path = self.base / "candidate.json"
        raw = snapshot([row()] if rows is None else rows)
        self.snapshot_path.write_bytes(raw)
        self.checksum = p.digest(raw)

    def files(self):
        return {str(path.relative_to(self.base)): (os.readlink(path) if path.is_symlink() else path.read_bytes())
                for path in self.base.rglob("*") if path.is_symlink() or path.is_file()}

    def preview(self, **changes):
        args = dict(release=self.directory, snapshot=self.snapshot_path, checksum=self.checksum, key=self.key, env=self.env)
        args.update(changes)
        return p.check_source_pins(**args)

    def test_real_signed_bundle_binds_provenance_and_unsigned_candidate_without_writes(self):
        self.prepare();before = self.files()
        result = self.preview()
        self.assertEqual(result["unchanged"], ["fixture"])
        self.assertEqual(result["changes"], [])
        self.assertEqual(result["release"]["release_sha256"], p.r.sha(self.directory / "release.json"))
        manifest = p.r.load(self.directory / "release.json")
        self.assertEqual(result["release"]["provenance_sha256"],
                         {record["provenance"]: manifest["files"][record["provenance"]] for record in manifest["packages"]})
        self.assertEqual(result["candidate"], {"sha256": self.checksum, "authenticated": False})
        for field in ("base_source_pins_checked", "freshness_established", "build_dependencies_checked",
                      "stable_eligibility_checked", "installation_authorized"):
            self.assertIs(result[field], False)
        self.assertEqual(self.files(), before)

    def test_real_signed_bundle_reports_drift_missing_extra_and_cli(self):
        self.prepare([row(recipe_sha256="d" * 64), row("new")])
        result = self.preview()
        self.assertEqual(result["changes"][0]["fields"], ["recipe_sha256"])
        self.assertEqual(result["coverage"]["extra"], ["new"])
        process = subprocess.run([sys.executable, "-B", str(HERE / "check_source_pins.py"), "--release", str(self.directory),
                                  "--candidate", str(self.snapshot_path), "--candidate-sha256", self.checksum,
                                  "--key", self.key, "--gpg-home", str(self.home)], capture_output=True)
        self.assertEqual(process.returncode, 0, process.stderr.decode())
        self.assertEqual(json.loads(process.stdout), result)
        self.snapshot_path.write_bytes(snapshot([]));self.checksum = p.r.sha(self.snapshot_path)
        self.assertEqual(self.preview()["coverage"]["missing"], ["fixture"])

    def test_real_signed_nested_source_type_drift_is_not_unchanged(self):
        provenance = p.r.load(self.inputs / "provenance.json")
        provenance["sources"][0]["metadata"] = {"nested": [{"enabled": True, "count": 1}]}
        self.put("provenance.json", provenance)
        self.release_spec["packages"][0]["provenance"] = self.ref("provenance.json")
        candidate_row = row()
        candidate_row["sources"][0]["metadata"] = {"nested": [{"enabled": 1, "count": 1.0}]}
        self.prepare([candidate_row])
        result = self.preview()
        self.assertEqual(result["unchanged"], [])
        self.assertEqual(result["changes"][0]["fields"], ["sources"])
        self.assertIs(result["changes"][0]["before"]["sources"][0]["metadata"]["nested"][0]["enabled"], True)
        self.assertIs(type(result["changes"][0]["after"]["sources"][0]["metadata"]["nested"][0]["enabled"]), int)

    def test_cli_entry_budget_refusal_emits_no_partial_report(self):
        nested = "leaf"
        for _ in range(80):nested = [nested]
        changed = row();changed["sources"][0]["metadata"] = nested
        self.prepare([changed])
        raw = json.dumps({"schema_version": 1, "packages": [changed]}, separators=(",", ":")).encode()
        self.assertLess(len(raw), 1024)
        self.snapshot_path.write_bytes(raw);self.checksum = p.digest(raw)
        arguments = ["--release", str(self.directory), "--candidate", str(self.snapshot_path),
                     "--candidate-sha256", self.checksum, "--key", self.key, "--gpg-home", str(self.home)]
        captured = io.StringIO()
        with mock.patch.object(p, "MAX_OUTPUT", 4096), contextlib.redirect_stdout(captured), \
                self.assertRaisesRegex(p.r.Error, "report byte bound"):
            p.main(arguments)
        self.assertEqual(captured.getvalue(), "")

    def test_wrong_signer_signature_and_provenance_tamper_refuse(self):
        self.prepare()
        with self.assertRaises(p.r.Error):self.preview(key="0" * 40)
        path = self.directory / p.r.load(self.directory / "release.json")["packages"][0]["provenance"]
        saved = path.read_bytes();path.write_bytes(saved + b" ")
        with self.assertRaises(p.r.Error):self.preview()
        path.write_bytes(saved)
        signature = self.directory / "release.json.sig";signature.write_bytes(b"not a signature")
        with self.assertRaises(p.r.Error):self.preview()

    def test_symlink_hardlink_and_alias_inputs_refuse_without_following(self):
        self.prepare()
        link = self.base / "linked";link.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaises((p.s.Error, OSError)):self.preview(release=link)
        linked = self.base / "candidate-link";linked.symlink_to(self.snapshot_path)
        with self.assertRaises((p.s.Error, OSError)):self.preview(snapshot=linked)
        linked.unlink();os.link(self.snapshot_path, linked)
        with self.assertRaises(p.s.Error):self.preview()
        linked.unlink()
        for field, value in (("release", "//" + str(self.directory).lstrip("/")),
                             ("snapshot", self.base / ".." / self.base.name / "candidate.json")):
            with self.subTest(field=field), self.assertRaises(p.r.Error):self.preview(**{field: value})

    def test_candidate_replacement_during_final_verification_refuses(self):
        self.prepare();original = p.r.verify_release;calls = 0
        def replace(*args):
            nonlocal calls
            calls += 1
            result = original(*args)
            if calls == 2:self.snapshot_path.write_bytes(snapshot([]))
            return result
        with mock.patch.object(p.r, "verify_release", side_effect=replace), self.assertRaisesRegex(p.r.Error, "candidate changed"):
            self.preview()
        self.assertEqual(calls, 2)

    def test_provenance_replacement_after_final_verification_refuses(self):
        self.prepare();original = p.r.verify_release;calls = 0
        path = self.directory / p.r.load(self.directory / "release.json")["packages"][0]["provenance"]
        def replace(*args):
            nonlocal calls
            calls += 1
            result = original(*args)
            if calls == 2:path.write_bytes(path.read_bytes() + b" ")
            return result
        with mock.patch.object(p.r, "verify_release", side_effect=replace), self.assertRaisesRegex(p.r.Error, "provenance changed"):
            self.preview()

    def test_changed_release_verification_or_report_bounds_never_return_partial_report(self):
        self.prepare([row(recipe_sha256="d" * 64)])
        with mock.patch.object(p, "MAX_TOTAL", 1), self.assertRaises((p.r.Error, p.s.Error)):
            self.preview()
        with mock.patch.object(p, "MAX_OUTPUT", 1), self.assertRaisesRegex(p.r.Error, "report byte bound"):
            self.preview()
        original = p.r.verify_release;calls = 0
        def replace(*args):
            nonlocal calls
            calls += 1
            result = original(*args)
            if calls == 2:(self.directory / "release.json").write_bytes(b"{}")
            return result
        with mock.patch.object(p.r, "verify_release", side_effect=replace), self.assertRaisesRegex(p.r.Error, "release changed"):
            self.preview()


if __name__ == "__main__":
    unittest.main()
