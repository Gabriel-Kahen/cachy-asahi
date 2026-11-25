# SPDX-License-Identifier: MIT
"""Bounded passive tests for the Qtbase packaging plan and staging boundary."""

from pathlib import Path
from runpy import run_path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

P = SimpleNamespace(**run_path(str(Path(__file__).with_name("package_preflight.py"))))
C, S = P.C, P.S
PIN = C.pin(b"fixture")
OLD_NONCE = "a" * 32
NEW_NONCE = "b" * 32
AUTHORITY = "c" * 64
HANDOFF = "d" * 64
SITE = "e" * 64


class PackagingPreflight(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.capsule = self.root / "capsule"
        self.site_path = self.root / "site.json"
        self.retirement = self.root / "retirement.json"
        self.independent = self.root / "independent.json"
        self.meta = dict(nonce=OLD_NONCE, scope=S.SCOPE, scope_group="/fixture/" + S.SCOPE,
                         authority_sha256=AUTHORITY, handoff_sha256=HANDOFF, plan_sha256=PIN["sha256"],
                         site_sha256=SITE, scope_stop_grace_seconds=S.SCOPE_STOP_GRACE_SECONDS)
        self.host = dict(cid="0" * 64, exit_code=0, actor_result=PIN)
        self.post = self.meta | dict(kind=S.OBSERVATION_KIND, host_result=PIN, cid=self.host["cid"],
                                     exit_code=0, actor_result=PIN, authority=None,
                                     observations=[dict(scope_absent=True, container_absent=True)] * 2)
        self.full = dict(kind=P.INDEPENDENT_KIND, status=P.INDEPENDENT_PASS, nonce=OLD_NONCE,
                         handoff_sha256=HANDOFF, plan_sha256=PIN["sha256"], authority={"sha256": AUTHORITY},
                         actor=dict(actor_result=PIN, overlay=PIN, result_disk=PIN),
                         guest=dict(status="VERIFIED_QTBASE_BUILD_ONLY"))

    def record(self, path, data):
        raw = C.wire(data)
        path.write_bytes(raw)
        return C.pin(raw)["sha256"]

    def complete(self, post=None, full=None):
        retirement_sha = self.record(self.retirement, self.post if post is None else post)
        independent_sha = self.record(self.independent, self.full if full is None else full)
        return P.completed_build(self.capsule, self.site_path, SITE, self.retirement, retirement_sha,
                                 self.independent, independent_sha)

    def test_hold_or_missing_proof_refuses_before_opening_original_claim(self):
        with patch.object(S, "load_site") as load:
            for post, full in ((self.post | {"exit_code": 2}, self.full),
                               (self.post | {"observations": [dict(scope_absent=True, container_absent=True)]},
                                self.full),
                               (self.post, self.full | {"status": "HOLD"})):
                with self.subTest(post=post["exit_code"], readback=full["status"]), self.assertRaises(ValueError):
                    self.complete(post, full)
            with self.assertRaises(FileNotFoundError):
                P.completed_build(self.capsule, self.site_path, SITE, self.root / "missing.json", SITE,
                                  self.independent, SITE)
            load.assert_not_called()
        self.assertFalse(self.capsule.exists())

    def test_original_readback_and_scope_must_join(self):
        plan = {"inputs": {name: PIN for name in ("Image", "scratch.raw", "core.qcow2", "gui.qcow2", "boot.raw")}}
        with patch.object(S, "load_site", return_value=({}, {"plan": PIN}, plan)), \
             patch.object(S, "read_attempt", return_value=(self.meta, self.host, PIN)), \
             patch.object(P.R, "readback", return_value=self.full) as replay:
            for key, value in (("authority_sha256", SITE), ("cid", "1" * 64), ("host_result", C.pin(b"wrong"))):
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, "same exact original"):
                    self.complete(self.post | {key: value})
            replay.assert_not_called()
            with self.assertRaisesRegex(ValueError, "differs from original"):
                self.complete(full=self.full | {"actor": self.full["actor"] | {"overlay": C.pin(b"other")}})
            nonce, media, evidence = self.complete()
            self.assertEqual(nonce, OLD_NONCE)
            self.assertEqual(media["complete.qcow2"]["path"],
                             str(self.capsule / S.CLAIM / "output" / "overlay.qcow2"))
            self.assertEqual(evidence["result"]["sha256"], PIN["sha256"])
            replay.assert_called_with(self.capsule, HANDOFF, self.capsule / S.CLAIM / "selection.json",
                                      AUTHORITY, self.capsule / S.CLAIM / "output", PIN["sha256"])

    def test_unissued_plan_preserves_normal_sequence_and_selected_recipe(self):
        args = SimpleNamespace(nonce=NEW_NONCE, q3_media=self.root / "q3", capsule=self.capsule,
                               site=self.site_path, site_sha256=SITE, retirement=self.retirement,
                               retirement_sha256=SITE, readback=self.independent, readback_sha256=SITE)
        sidecar = P.guest_sidecar()
        files = {"recipe/PKGBUILD": b"successor", "recipe/.SRCINFO": b"metadata", "recipe/source.py": b"helper"}
        original = P.F.K.F.file_record(sidecar.Q3_PINS["PKGBUILD"])
        with patch.dict(P.prepare.__globals__, q3_inputs=lambda _: ({}, original, ["md4c<0.6"], files),
                        completed_build=lambda *_: (OLD_NONCE, {"complete.qcow2": PIN}, {})):
            plan, staged = P.prepare(args)
            with self.assertRaisesRegex(ValueError, "distinct boot identity"):
                P.prepare(SimpleNamespace(**(vars(args) | {"nonce": OLD_NONCE})))
        self.assertEqual(staged, files)
        self.assertEqual(plan["authority"], None)
        self.assertEqual(plan["packaging"], "NOT_RUN")
        self.assertEqual(plan["readonly_media"], {"complete.qcow2": PIN})
        self.assertEqual(plan["fresh_child"]["backing"], "/inputs/complete.qcow2")
        self.assertEqual(plan["expected_archive"]["buildinfo_recipe"], C.pin(files["recipe/PKGBUILD"]))
        worker = plan["worker"]
        self.assertEqual(worker["exact_build_inputs"]["PKGBUILD"], original)
        self.assertEqual(worker["environment"]["BUILDDIR"], "/qt-recipe")
        self.assertTrue(worker["makepkg_configuration"]["require_no_user_override"])
        self.assertTrue(worker["stage_recipe"]["must_be_absent"])
        roles = [row["role"] for row in worker["actions"]]
        self.assertLess(roles.index("patched-source"), roles.index("recipe-check"))
        self.assertLess(roles.index("recipe-check"), roles.index("repackage"))
        steps = {step["role"]: step for step in worker["actions"]}
        self.assertEqual(steps["recipe-check"]["expected"], {"stdout_line": P.SMOKE})
        self.assertIn("--repackage", steps["repackage"]["argv"])
        self.assertNotIn("--nodeps", steps["repackage"]["argv"])
        self.assertNotIn("--install", steps["repackage"]["argv"])

    def test_stage_cannot_overwrite_or_land_in_a_selected_root(self):
        self.capsule.mkdir()
        output = self.root / "stage"
        files = {"recipe/PKGBUILD": b"fixture", "metadata-projection.json": b"fixture"}
        plan = dict(kind="model", authority=None, staging_files={name: C.pin(body) for name, body in files.items()})
        with self.assertRaisesRegex(ValueError, "staging leaves"):
            P.stage(output, plan, files | {"recipe/../foreign": b"fixture"}, (self.capsule,))
        self.assertFalse(output.exists())
        with self.assertRaisesRegex(ValueError, "outside every selected"):
            P.stage(self.capsule / "stage", plan, files, (self.capsule,))
        self.assertEqual(list(self.capsule.iterdir()), [])
        P.stage(output, plan, files, (self.capsule,))
        expected = set(files) | {P.PLAN_NAME}
        self.assertEqual(set(str(p.relative_to(output)) for p in output.rglob("*") if p.is_file()), expected)
        self.assertEqual((output / P.PLAN_NAME).read_bytes(), C.wire(plan))
        with self.assertRaisesRegex(ValueError, "Fresh staging path"):
            P.stage(output, plan | {"kind": "replacement"}, files, (self.capsule,))
        self.assertEqual((output / P.PLAN_NAME).read_bytes(), C.wire(plan))


if __name__ == "__main__":
    unittest.main()
