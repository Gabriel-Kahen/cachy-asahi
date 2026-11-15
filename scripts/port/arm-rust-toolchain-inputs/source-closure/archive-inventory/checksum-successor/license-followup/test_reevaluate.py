import importlib.util
import json
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("license_followup", Path(__file__).with_name("reevaluate.py"))
REVIEW = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REVIEW)


def fixture(notice="Copyright Example Holder"):
    body = b'[package]\nname="one"\nversion="1.0.0"\n'
    grant = ((notice + "\n" if notice else "") +
             "Permission is hereby granted; copyright notice; THE SOFTWARE IS PROVIDED\n").encode()
    case = {"component": "one-1.0.0", "commit": "a" * 40, "repository": "example/repo",
            "manifest_path": "Cargo.toml", "grant_upstream_path": "LICENSE-MIT", "grant_file": "one.txt",
            "manual_grant_kind": "MIT complete actual grant/conditions/disclaimer",
            "manual_named_notice": notice, "named_notice_ownership_inferred_from_authors_or_identical_bytes": False}
    captures = [{"path": "vendor/one/Cargo.toml.orig", "text": body.decode(), "complete_text": True, **REVIEW.pin(body)},
                {"path": "vendor/one/.cargo_vcs_info.json", "text": json.dumps({"git": {"sha1": "a" * 40}, "path_in_vcs": ""}), "complete_text": True}]
    tree = {"truncated": False, "tree": [{"path": "Cargo.toml", "type": "blob", "sha": REVIEW.blob(body)},
                                           {"path": "LICENSE-MIT", "type": "blob", "sha": REVIEW.blob(grant)}]}
    return case, captures, tree, grant


class EvidenceControls(unittest.TestCase):
    def test_exact_binding_and_notice_required_for_scoped_closure(self):
        self.assertEqual(REVIEW.evaluate_binding(*fixture())["status"], "UPSTREAM_ROOT_GRANT_AND_NOTICE_EVIDENCE_COMPLETE")
        self.assertEqual(REVIEW.evaluate_binding(*fixture(None))["status"], "UNRESOLVED_ATTRIBUTION")

    def test_changed_license_or_manifest_rejected(self):
        case, captures, tree, grant = fixture()
        with self.assertRaisesRegex(ValueError, "license Git blob"):
            REVIEW.evaluate_binding(case, captures, tree, grant + b"changed")
        captures[0]["text"] += "#changed\n"
        with self.assertRaisesRegex(ValueError, "pin"):
            REVIEW.evaluate_binding(case, captures, tree, grant)

    def test_wrong_version_commit_dirty_or_truncated_rejected(self):
        for field, value in (("component", "one-2.0.0"), ("commit", "b" * 40)):
            case, captures, tree, grant = fixture(); case[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                REVIEW.evaluate_binding(case, captures, tree, grant)
        case, captures, tree, grant = fixture()
        captures[1]["text"] = json.dumps({"git": {"sha1": "a" * 40, "dirty": True}})
        with self.assertRaisesRegex(ValueError, "dirty"):
            REVIEW.evaluate_binding(case, captures, tree, grant)
        case, captures, tree, grant = fixture(); tree["truncated"] = True
        with self.assertRaisesRegex(ValueError, "complete"):
            REVIEW.evaluate_binding(case, captures, tree, grant)

    def test_template_copyright_and_inferred_ownership_rejected(self):
        with self.assertRaisesRegex(ValueError, "template"):
            REVIEW.evaluate_binding(*fixture("Copyright [yyyy] [name of copyright owner]"))
        case, captures, tree, grant = fixture(); case["named_notice_ownership_inferred_from_authors_or_identical_bytes"] = True
        with self.assertRaisesRegex(ValueError, "inferred"):
            REVIEW.evaluate_binding(case, captures, tree, grant)

    def test_sibling_package_license_does_not_cover_manifest(self):
        case, captures, tree, grant = fixture(); case["grant_upstream_path"] = "sibling/LICENSE-MIT"; tree["tree"][1]["path"] = case["grant_upstream_path"]
        with self.assertRaisesRegex(ValueError, "scope"):
            REVIEW.evaluate_binding(case, captures, tree, grant)

    def test_qualified_lock_edges_and_ambiguous_unqualified_refusal(self):
        packages = [{"name": "root", "version": "1", "dependencies": ["leaf 1 (registry+one)"]},
                    {"name": "leaf", "version": "1", "source": "registry+one"},
                    {"name": "leaf", "version": "1", "source": "git+two"}]
        paths = REVIEW.dependency_paths(packages, [["root", "1"]])
        self.assertIn(("leaf", "1", "registry+one"), paths)
        self.assertNotIn(("leaf", "1", "git+two"), paths)
        packages[0]["dependencies"] = ["leaf 1"]
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            REVIEW.dependency_paths(packages, [["root", "1"]])

    def test_network_budget_counts_errors_and_redirects(self):
        receipts = [{"bytes": 1, "status": 301}] * 9 + [{"bytes": 1, "HTTP": 422}] * 11
        self.assertEqual(REVIEW.network_summary(receipts)["HTTP_requests"], 20)
        with self.assertRaisesRegex(ValueError, "budget"):
            REVIEW.network_summary(receipts + [{"bytes": 0}])
        with self.assertRaisesRegex(ValueError, "budget"):
            REVIEW.network_summary([{"bytes": 8 * 1024**2 + 1}])

    def test_priority_does_not_promote_optional_or_target_only_edges(self):
        self.assertEqual(REVIEW.direct_dependency_evidence({"dependencies": {"one": "1"}}, ["one"]), {"one": "1"})
        for document in ({"dependencies": {"one": {"optional": True}}},
                         {"target": {"cfg(windows)": {"dependencies": {"one": "1"}}}}):
            with self.assertRaisesRegex(ValueError, "priority"):
                REVIEW.direct_dependency_evidence(document, ["one"])


if __name__ == "__main__":
    unittest.main()
