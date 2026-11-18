#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""No-network controls for the manual dispatch and selected Source join."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("qt_workflow_entry", Path(__file__).with_name("workflow_entry.py"))
W = importlib.util.module_from_spec(spec)
spec.loader.exec_module(W)


def encoded(value):
    return json.dumps(value, sort_keys=True).encode()


def reference(name, raw):
    return dict(path=name, bytes=len(raw), sha256=W.digest(raw))


class WorkflowControls(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory(prefix="qt-workflow-control-")
        self.addCleanup(work.cleanup)
        self.root = Path(work.name)
        self.record = dict(
            kind=W.KIND, issuer="Root", approved=True, mode="pair-only",
            repository=W.REPOSITORY, live_ref="refs/heads/codex/qt-live-dispatch",
            workflow_sha="a" * 40, issued_utc=90, expires_utc=120,
            runtime_source=dict(ref="refs/heads/codex/qt-immutable-runtime",
                                commit="b" * 40, tree="c" * 40),
            inputs={},
        )
        self.entries = {}
        entry = self.put(W.ENTRY, b"ordinary fixture code")
        self.record["runtime_source"]["entry"] = entry
        for role, name, data in (
                ("portable_selection", "portable/selection.DATA.json", b"selector"),
                ("route_plan", "inputs/routes.json", b"route plan"),
                ("md4c_signature", "inputs/md4c/package.sig", b"p" * 119),
                ("md4c_certificate", "inputs/md4c/public.gpg", b"c" * 265),
                ("md4c_authority", "inputs/md4c/authority.json", b"public authority")):
            self.record["inputs"][role] = self.put(name, data)
        self.reseal_map()
        self.env = {
            "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REPOSITORY": W.REPOSITORY,
            "GITHUB_ACTOR": W.OWNER, "GITHUB_TRIGGERING_ACTOR": W.OWNER, "GITHUB_REF": self.record["live_ref"],
            "GITHUB_SHA": self.record["workflow_sha"], "GITHUB_WORKFLOW_SHA": self.record["workflow_sha"],
            "GITHUB_WORKFLOW_REF": f"{W.REPOSITORY}/{W.WORKFLOW}@{self.record['live_ref']}",
            "GITHUB_RUN_ATTEMPT": "1", "GITHUB_JOB": "pair", "RUNNER_OS": "Linux", "RUNNER_ARCH": "ARM64",
            "GITHUB_RUN_ID": "1234",
        }

    def put(self, leaf, raw):
        path = self.root / leaf
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o644)
        ref = reference(leaf, raw)
        self.entries[leaf] = dict(bytes=ref["bytes"], sha256=ref["sha256"], mode=0o644)
        return ref

    def reseal_map(self, **fields):
        mapping = dict(kind=W.MAP_KIND, schema=1, files=self.entries)
        raw = encoded(dict(mapping, **fields))
        (self.root / "source-map.json").write_bytes(raw)
        self.record["runtime_source"]["map"] = reference("source-map.json", raw)

    def approved(self, record=None, env=None, *, now=100, sha=None):
        value = encoded(self.record if record is None else record)
        trust = {name: {key: self.record["inputs"][name][key] for key in ("bytes", "sha256")}
                 for name in W.PUBLIC_TRUST}
        with patch.object(W, "PUBLIC_TRUST", trust):
            return W.approval(value, W.digest(value) if sha is None else sha, self.env if env is None else env, now)

    def verified_checkout(self):
        selected = self.record["runtime_source"]
        with patch.object(W, "git_identity", return_value=(selected["commit"], selected["tree"])):
            return W.verify_source(self.root, selected, self.record["inputs"])

    def test_live_ref_workflow_sha_and_runtime_source_commit_are_separate(self):
        actual = self.approved()
        self.assertNotEqual(actual["runtime_source"]["commit"], self.env["GITHUB_SHA"])
        for key, value in (("GITHUB_ACTOR", "other"), ("GITHUB_TRIGGERING_ACTOR", "other"),
                           ("GITHUB_RUN_ATTEMPT", "2"), ("GITHUB_WORKFLOW_SHA", "b" * 40),
                           ("GITHUB_REF", actual["runtime_source"]["ref"]), ("RUNNER_ARCH", "X64")):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "EXACT_HOSTED_OWNER"):
                self.approved(env=dict(self.env, **{key: value}))

    def test_expiry_unissued_approval_mode_mismatch_and_spoofed_ref(self):
        with self.assertRaisesRegex(ValueError, "CURRENT_ROOT_DISPATCH"):
            self.approved(now=120)
        with self.assertRaisesRegex(ValueError, "EXACT_ROOT_APPROVAL"):
            self.approved(sha="0" * 64)
        with self.assertRaisesRegex(ValueError, "ROOT_PAIR_ONLY"):
            self.approved(record=dict(self.record, mode="signed-lifecycle"))
        for branch in ("refs/heads/a\nREPLACED=1", "refs/heads/../unsafe", self.record["live_ref"]):
            candidate = copy.deepcopy(self.record)
            candidate["runtime_source"]["ref"] = branch
            with self.assertRaisesRegex(ValueError, "(BRANCH_REF|SEPARATE_IMMUTABLE)"):
                self.approved(record=candidate)

    def test_checkout_joins_actual_members_and_refuses_mutation_or_extra_leaves(self):
        self.verified_checkout()
        path = self.root / self.record["inputs"]["route_plan"]["path"]
        original = path.read_bytes()
        path.write_bytes(b"other")
        with self.assertRaisesRegex(ValueError, "SOURCE_FILE|FILE_BYTES"):
            self.verified_checkout()
        path.write_bytes(original)
        extra = self.root / "foreign.py"
        extra.write_text("unknown source")
        with self.assertRaisesRegex(ValueError, "EXACT_CLOSED"):
            self.verified_checkout()
        extra.unlink()
        unused = self.root / "untracked-empty"
        unused.mkdir()
        with self.assertRaisesRegex(ValueError, "EXACT_CLOSED"):
            self.verified_checkout()
        unused.rmdir()
        self.reseal_map(entry=None)
        with self.assertRaisesRegex(ValueError, "EXACT_RECORD_FIELDS"):
            self.verified_checkout()

    def test_cli_preflight_keeps_exact_json_and_only_emits_selected_ref(self):
        selected, output = self.root / "approval.json", self.root / "github-output"
        output.touch()
        raw = encoded(self.record)
        env = dict(self.env, QT612_ROOT_APPROVAL_JSON=raw.decode(), QT612_ROOT_APPROVAL_SHA256=W.digest(raw))
        trust = {name: {key: self.record["inputs"][name][key] for key in ("bytes", "sha256")}
                 for name in W.PUBLIC_TRUST}
        with patch.dict(W.os.environ, env, clear=True), patch.object(W.time, "time", return_value=100), \
             patch.object(W, "PUBLIC_TRUST", trust):
            argv = ["preflight", "--approval", str(selected), "--github-output", str(output)]
            self.assertEqual(W.main(argv), 0)
            with self.assertRaises(FileExistsError):
                W.main(argv)
        self.assertEqual(selected.read_bytes(), raw)
        self.assertEqual(selected.stat().st_mode & 0o777, 0o600)
        self.assertEqual(output.read_text(), "runtime_ref=" + self.record["runtime_source"]["ref"] + "\n")

    def test_closed_source_with_real_git_commit_and_tree(self):
        git = ["/usr/bin/git", "-C", str(self.root), "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false",
               "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid"]
        for args in (["init", "-q"], ["add", "--all"], ["commit", "-q", "-m", "Fixture"]):
            subprocess.run([*git, *args], check=True, capture_output=True, timeout=10)
        selected = self.record["runtime_source"]
        selected["commit"], selected["tree"] = W.git_identity(self.root)
        W.verify_source(self.root, selected, self.record["inputs"])
        with self.assertRaisesRegex(ValueError, "COMMIT_TREE"):
            W.verify_source(self.root, dict(selected, commit="a" * 40), self.record["inputs"])

    def test_exact_public_export_requires_promotion_closure_and_closed_bytes(self):
        root = self.root / "owned"
        root.mkdir()
        root.chmod(0o711)
        evidence = root / "evidence"
        recipe = evidence / "build-1/inputs/.SRCINFO"
        recipe.parent.mkdir(parents=True)
        recipe.write_bytes(b"recipe")
        recipe.chmod(0o644)
        rel = recipe.relative_to(evidence).as_posix()
        row = reference(rel, recipe.read_bytes())
        row.pop("path")
        dispatch = dict(source=self.env["GITHUB_SHA"], ref=self.env["GITHUB_REF"], run=self.env["GITHUB_RUN_ID"],
                        job="312", attempt="1")
        manifest = dict(kind="QT612_HOSTED_PAIR_EXACT_EXPORT_V1", selected=dict(dispatch=dispatch),
                        files={rel: row}, lifecycle_status="NOT_RUN", native_acceptance=None, Root_acceptance=None)
        description = evidence / W.MANIFEST
        description.write_bytes(encoded(manifest))
        description.chmod(0o644)
        manifest_pin = reference(W.MANIFEST, description.read_bytes())
        manifest_pin.pop("path")
        owner = root / W.OWNER_REPORT
        approval_sha = "e" * 64
        status = dict(status="PASS_QT612_GUI_SERVER_PAIR_EXTERNAL_CLEANUP_ONLY", approval=dict(sha256=approval_sha),
                      lifecycle_status="NOT_RUN", native_acceptance=None, Root_acceptance=None, dispatch=dispatch,
                      cleanup=dict(owned_storage_absent=True, errors=[]), evidence=dict(manifest_pin=manifest_pin,
                      selected=manifest["selected"], qualification=dict(status="PASS_QT612_HOSTED_PAIR_EXACT_READBACK_ONLY",
                      files=1, bytes=row["bytes"], lifecycle_status="NOT_RUN", Root_acceptance=None)))
        owner.write_bytes(encoded(status))
        owner.chmod(0o444)
        env = dict(self.env, QT612_ROOT_APPROVAL_SHA256=approval_sha)
        with patch.object(W, "ROOT_UID", root.stat().st_uid):
            W.verify_export(root, env)
            with self.assertRaisesRegex(ValueError, "SAME_PAIR_WORKFLOW_RUN"):
                W.verify_export(root, dict(env, GITHUB_RUN_ID="123"))
            private = evidence / ".credential"
            private.write_text("out of scope")
            with self.assertRaisesRegex(ValueError, "EXACT_CLOSED"):
                W.verify_export(root, env)
            private.unlink()
            recipe.write_bytes(b"betray")
            with self.assertRaisesRegex(ValueError, "FILE_BYTES"):
                W.verify_export(root, env)
            owner.chmod(0o644)
            status["status"] = "HOLD"
            owner.write_bytes(encoded(status))
            owner.chmod(0o444)
            with self.assertRaisesRegex(ValueError, "QUALIFIED_PAIR_CLOSURE"):
                W.verify_export(root, env)

    def test_checkout_rejects_stale_tree_and_symlinked_role(self):
        selected = self.record["runtime_source"]
        with patch.object(W, "git_identity", return_value=(selected["commit"], "f" * 40)):
            with self.assertRaisesRegex(ValueError, "COMMIT_TREE"):
                W.verify_source(self.root, selected, self.record["inputs"])
        path = self.root / self.record["inputs"]["route_plan"]["path"]
        path.unlink()
        path.symlink_to("/etc/passwd")
        with self.assertRaisesRegex(ValueError, "SOURCE_NAMESPACE"):
            self.verified_checkout()


if __name__ == "__main__":
    unittest.main()
