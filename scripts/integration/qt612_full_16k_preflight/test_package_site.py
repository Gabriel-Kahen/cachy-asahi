# SPDX-License-Identifier: MIT
"""Exercise the package role without invoking a live actor or Docker daemon."""

import os
from pathlib import Path
from runpy import run_path
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


HERE = Path(__file__).resolve().parent
with patch.object(sys, "path", [str(HERE), *sys.path]):
    S = SimpleNamespace(**run_path(str(HERE / "package_site.py"), run_name="_qtbase_package_site_fixture"))
E, C, W = S.E, S.C, S.W
PLAN, SELECTION, MEDIA = "a" * 64, "b" * 64, "c" * 64
CID, NONCE = "e" * 64, "f" * 32
GROUP = "/user.slice/app.slice/" + W.SCOPE


class PackageSiteTests(unittest.TestCase):
    def setUp(self):
        # The historical actor imports a sibling helper by its local name.
        # Keep that search path private to each fixture.
        self.enterContext(patch.object(sys, "path", [str(HERE), *sys.path]))
        self.scratch = Path(self.enterContext(TemporaryDirectory())).resolve()
        self.root = self.scratch / "capsule"
        self.stage = self.scratch / "staged"
        for path in (self.root, self.stage):
            path.mkdir(mode=0o700)
        self.attempt = self.root / S.CLAIM
        self.owner = S.package_owner(self.stage, PLAN)
        self.role = dict(nonce=NONCE, plan=C.file_pin(1, PLAN), selection=C.file_pin(1, SELECTION),
                         runtime=dict(actor_memory_bytes=8 << 30, cpus=4),
                         times=dict(attach=3900, scope_stop_grace=360))
        self.selected = SimpleNamespace(owner=self.owner, role=self.role, root=self.root, stage=self.stage,
                                        media_sha=MEDIA, site_sha="8" * 64, raw_selection=b"fixture",
                                        media=dict(runner={"actor_image": "sha256:" + "9" * 64}))
        self.meta = S.attempt_meta(self.selected, GROUP)

    def test_role_uses_exact_package_actor_and_source_mounts(self):
        args = self.owner.create_args(self.attempt, self.meta)
        mounts = [value for flag, value in zip(args, args[1:]) if flag == "--mount"]
        self.assertEqual(len(mounts), 6)
        self.assertIn(f"type=bind,source={self.stage},target=/stage,readonly", mounts)
        self.assertIn(f"type=bind,source={self.root / S.MEDIA},target=/media.json,readonly", mounts)
        self.assertEqual([entry for entry in mounts if not entry.endswith(",readonly")],
                         [f"type=bind,source={self.attempt / 'output'},target=/out"])
        self.assertEqual(args[-10:], S.actor_args(PLAN, MEDIA, SELECTION))
        self.assertIn("--pull=never", args)
        self.assertIn("--network=none", args)
        self.assertIn("--memory-swap=8589934592", args)
        self.assertEqual({value for flag, value in zip(args, args[1:]) if flag == "--env"}, set(S.ROLE_FLAGS))

    def test_borrowed_owner_has_separate_scope_and_namespace(self):
        historical = run_path(str(HERE / "full_site.py"), run_name="_qtbase_full_site_fixture")
        other = S.package_owner(self.stage, "7" * 64)
        self.assertNotEqual(self.owner.SCOPE, historical["SCOPE"])
        self.assertNotEqual(self.owner.NONCE_LABEL, historical["NONCE_LABEL"])
        self.assertNotEqual(self.owner.CLAIM, historical["CLAIM"])
        self.assertEqual(self.owner.execute_owned.__code__.co_code, historical["execute_owned"].__code__.co_code)
        self.assertEqual(self.owner.owning_group.__code__.co_code, historical["owning_group"].__code__.co_code)
        self.assertEqual(self.owner.actor_args(MEDIA, SELECTION), S.actor_args(PLAN, MEDIA, SELECTION))
        self.assertEqual(other.actor_args(MEDIA, SELECTION), S.actor_args("7" * 64, MEDIA, SELECTION))

    def test_role_rejects_a_container_claimed_by_the_full_build(self):
        row = dict(Id=CID, Image=self.meta["image"], Name="/" + self.meta["name"], Path="/usr/bin/python3",
                   Args=S.actor_args(PLAN, MEDIA, SELECTION), Config={"Labels": {S.NONCE_LABEL: NONCE}})
        self.assertEqual(self.owner.owned_row(C.wire([row]), self.meta, CID), row)
        row["Config"]["Labels"] = {"org.cachy-asahi.qtbase16k-full.nonce": NONCE}
        with self.assertRaises(ValueError):
            self.owner.owned_row(C.wire([row]), self.meta, CID)

    def test_lost_create_recovery_uses_the_package_name_and_label(self):
        self.attempt.mkdir(mode=0o700)
        client = Mock()
        phase = iter((subprocess.TimeoutExpired("create", 45), (CID + "\n").encode(),
                      C.wire([dict(Id=CID, Image=self.meta["image"], Name="/" + self.meta["name"],
                                   Path="/usr/bin/python3", Args=S.actor_args(PLAN, MEDIA, SELECTION),
                                   Config={"Labels": {S.NONCE_LABEL: NONCE}},
                                   State=dict(Running=False, OOMKilled=False, Pid=0, Error="", Status="created"))]),
                      (CID + "\n").encode(), b"", b""))

        def docker(*_args, **_kwargs):
            item = next(phase)
            if isinstance(item, Exception):
                raise item
            return item

        client.docker.side_effect = docker
        with self.assertRaises(subprocess.TimeoutExpired):
            self.owner.execute_owned(client, self.attempt, self.meta, lambda: None)
        recovery = client.docker.call_args_list[1].args
        self.assertIn("label=" + S.NONCE_LABEL + "=" + NONCE, recovery)
        self.assertIn("name=^/" + self.meta["name"] + "$", recovery)
        self.assertFalse(client.attach.called)
        report = C.json_body((self.attempt / "host-HOLD.json").read_bytes(), canonical=True)
        self.assertEqual((report["kind"], report["cid"], report["disposition"]), (S.RETIREMENT_KIND, CID, "REMOVED"))

    def test_scope_refusal_leaves_the_claim_uncreated(self):
        with patch.dict(S.run.__globals__, confirm_identity=lambda _: None,
                        verify_current_selection=lambda _: None):
            with patch.object(self.owner, "owning_group", side_effect=ValueError("scope mismatch")):
                with self.assertRaisesRegex(ValueError, "scope mismatch"):
                    S.run(self.selected)
        self.assertFalse(os.path.lexists(self.attempt))

    def test_readonly_preflight_rejects_claim_and_low_capacity(self):
        self.selected.identity = self.owner.capsule_identity(self.root)
        self.selected.stage_identity = self.owner.capsule_identity(self.stage)
        self.selected.client = Mock()
        with patch.dict(S.preflight.__globals__, capacity=lambda _: {"fits": True}):
            report, passed = S.preflight(self.selected)
            self.assertTrue(passed)
            self.assertEqual(report["status"], "PASS_PACKAGE_HOST_PREFLIGHT_ONLY")
            self.assertFalse(report["actor_entered"])
            self.assertFalse(os.path.lexists(self.attempt))
            self.attempt.symlink_to(self.root / "absent")
            report, passed = S.preflight(self.selected)
            self.assertFalse(passed)
            self.assertTrue(report["claim_exists"])
            self.attempt.unlink()
        with patch.dict(S.preflight.__globals__, capacity=lambda _: {"fits": False}):
            report, passed = S.preflight(self.selected)
            self.assertFalse(passed)
            self.assertFalse(report["claim_exists"])
        self.selected.client.check.assert_called()
        self.assertFalse(self.selected.client.docker.called)

    def test_run_claims_once_after_scope_and_predecessor_checks(self):
        self.selected.identity = self.owner.capsule_identity(self.root)
        self.selected.stage_identity = self.owner.capsule_identity(self.stage)
        self.selected.client = Mock()
        self.selected.client.docker.return_value = b""
        self.selected.predecessor = ("full.scope", CID, b"predecessor receipt")
        self.selected.packaging = Mock()
        self.role["result_carrier"] = {"uuid": "fixture-uuid"}
        self.selected.media["result"] = C.pin(b"template")
        (self.root / "templates").mkdir()
        (self.root / "templates/result.raw").write_bytes(b"template")
        owner = self.owner

        def clone(_original, target, expected):
            self.assertEqual(expected, self.selected.media["result"])
            target.write_bytes(b"template")
            target.chmod(0o444)

        with (patch.dict(S.run.__globals__, verify_current_selection=Mock(), capacity=lambda _: {"fits": True}),
              patch.object(owner, "owning_group", return_value=GROUP),
              patch.object(owner, "predecessors_absent") as predecessors,
              patch.object(S.F.K, "clone", clone),
              patch.object(owner, "execute_owned", return_value=2) as execute):
            self.assertEqual(S.run(self.selected), 2)
            predecessors.assert_called_once_with(self.selected.client, {"full": self.selected.predecessor})
            execute.assert_called_once()
            self.assertEqual(execute.call_args.args[:3], (self.selected.client, self.attempt, self.meta))
            with self.assertRaisesRegex(ValueError, "already claimed"):
                S.run(self.selected)
        target = self.attempt / "output/result.raw"
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.attempt / "prior-full-closure.json").read_bytes(), b"predecessor receipt")
        self.selected.packaging.verify_result.assert_called_once_with(target, "fixture-uuid", empty=True)

    def test_load_rejects_unbound_media_or_result_template_before_claim(self):
        authority = self.scratch / "selection"
        authority.write_bytes(b"fixture selection")
        self.role.update(claim=S.CLAIM, scope=W.SCOPE, selection=C.pin(authority.read_bytes()),
                         result_carrier=dict(uuid="fixture-uuid"))
        templates = self.root / "templates"
        templates.mkdir()
        template = templates / "result.raw"
        template.write_bytes(b"fixture result")
        template.chmod(0o444)
        templates.chmod(0o555)
        plan = {"fixture": True}
        media = self.selected.media | {"result": C.pin(template.read_bytes())}
        args = SimpleNamespace(media=self.root, stage=self.stage, selection=authority, plan_sha256=PLAN,
                               selection_sha256=self.role["selection"]["sha256"], media_sha256=MEDIA)
        packaging = Mock()
        packaging.selected_role.return_value = (plan, {}, self.role, {})
        packaging.load_media.return_value = media
        orig_owner = S.package_owner

        def inert_owner(stage, plan_sha):
            owner = orig_owner(stage, plan_sha)
            owner.client_for = Mock()
            return owner

        with patch.dict(S.load.__globals__, package_owner=inert_owner, verify_source=Mock(),
                        predecessor=lambda _: ("source.scope", CID, b"retired")):
            selected = S.load(args, packaging, live=True)
            self.assertEqual(selected.role, self.role)
            packaging.load_media.assert_called_once_with(self.root / S.MEDIA, MEDIA, self.role)
            packaging.verify_inputs.assert_called_once_with(self.root / "inputs", self.role, media)
            packaging.verify_result.assert_called_once_with(template, "fixture-uuid", empty=True)
            template.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "readonly package result"):
                S.load(args, packaging, live=True)
            packaging.load_media.side_effect = ValueError("unbound media")
            with self.assertRaisesRegex(ValueError, "unbound media"):
                S.load(args, packaging, live=True)
        self.assertFalse(os.path.lexists(self.attempt))


if __name__ == "__main__":
    unittest.main()
