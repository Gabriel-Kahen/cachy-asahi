# SPDX-License-Identifier: MIT
"""Actor-fenced controls for Source206 selection and the exact C908 Reader."""

from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import checkpoint as P
import terminal as T
import test_contract as model
import test_terminal as terminal_model

C = P.C
S = C.S


class Source206(unittest.TestCase):

    def setUp(self):
        profile = model.G.model_inputs()[3]
        profile["materials"] = {name.lower(): row for name, row in profile["materials"].items()}
        material = next(iter(profile["materials"]))
        del profile["materials"][material]
        profile["materials"]["setup8_current_public_key"] = dict(S.TEST_PUBLIC_KEY)
        self.profile = C.encoded(profile)
        for roles in (S, T.C.S):
            binding = patch.object(roles, "PROFILE", C.pin(self.profile))
            binding.start()
            self.addCleanup(binding.stop)

        values = model.model_case(profile)
        case = values["case"]
        self.now = S.TEST_ROLE_EXPIRES - 690
        case.update(kind=S.CASE_KIND, workflow_id=S.WORKFLOW_ID,
                    source=dict(cid=S.CID, ref=S.REF, **S.SOURCE, program=S.PROGRAM, profile=S.PROFILE),
                    issued_epoch=self.now - 10, expires_epoch=S.TEST_ROLE_EXPIRES,
                    resources=dict(C.RESOURCES, policy=S.POLICY))
        case["main"].update(reader=S.READER, reader_contract=S.READER_CONTRACT)
        for name in ("admission", "runtime", "registration", "readback", "once"):
            values[name]["binding"] = C.binding(case)
        for name in ("admission", "runtime"):
            values[name].update(issued_epoch=self.now - 8, expires_epoch=case["expires_epoch"])
        values["admission"]["resources"] = case["resources"]
        for name in ("registration", "readback", "once"):
            values[name]["observed_epoch"] = self.now - 2
        for index, sweep in enumerate(values["runtime"]["sweeps"]):
            sweep["observed_epoch"] = self.now - 5 + index
        values["registration"]["workflow_id"] = S.WORKFLOW_ID
        values["readback"].update(source=case["source"], main=case["main"], profile_pin=S.PROFILE)

        self.key = dict(path="/MODEL/source/" + S.TEST_PUBLIC_KEY["member"],
                        **{key: S.TEST_PUBLIC_KEY[key] for key in ("bytes", "sha256")})
        self.approval = dict(issuer="Root", approved=True, scope="CURRENT_ONBOARDING_IMAGE_INPUT_TRUST_ONLY",
                             public_key=self.key, fingerprint=S.TEST_FINGERPRINT,
                             issued_epoch=case["issued_epoch"], expires_epoch=case["expires_epoch"])

        def delegation(row):
            row.update(policy=S.POLICY, issued_epoch=case["issued_epoch"], expires_epoch=case["expires_epoch"])
            row["binding"].update(source=S.CID, ref=S.REF, source_lock=S.SOURCE["source_map"])
            row["hosted"].update(workflow_ref=C.REPOSITORY + "/" + C.WORKFLOW + "@" + S.REF,
                                 workflow_sha=S.CID)

        model.change_request(values, "delegation", delegation)
        model.change_request(values, "grant", lambda row: row.update(
            source=S.CID, ref=S.REF, source_lock=S.SOURCE["source_map"], issued_epoch=case["issued_epoch"],
            expires_epoch=case["expires_epoch"], policy={key: S.POLICY[key] for key in ("bytes", "sha256")}))
        self.values = values
        self.use_approval(self.approval)
        self.reader = (HERE.parents[4] / S.READER["member"]).read_bytes()

    def use_approval(self, approval):
        raw = C.encoded(approval)
        model.change_request(self.values, "assembler", lambda row: row.update(test_trust=dict(
            fingerprint=S.TEST_FINGERPRINT, public_key=dict(S.TEST_PUBLIC_KEY),
            Root_admission=dict(json=raw.decode(), pin=C.pin(raw)))))

    def qualify(self, now=None):
        operands, pins = model.pack(self.values)
        return C.qualify(operands, pins, now=self.now if now is None else now,
                         core_raw=model.CORE_RAW, profile_raw=self.profile)

    def test_exact_reader_and_historical_predecessor(self):
        self.assertEqual(C.pin(self.reader), {key: S.READER[key] for key in ("bytes", "sha256")})
        old = (HERE.parents[4] / C.READER).read_bytes()
        self.assertEqual(C.pin(old), T.READER)
        successor = P.load("source206_exact_reader_control", HERE / "reader_current_v3_source206.py")
        historical = P.load("source205_exact_reader_control", HERE.parents[4] / C.READER)
        self.assertEqual(successor.MATERIAL_FULL_POLICY_PIN, {key: S.POLICY[key] for key in ("bytes", "sha256")})
        self.assertEqual(historical.MATERIAL_FULL_POLICY_PIN, {key: C.POLICY[key] for key in ("bytes", "sha256")})
        self.assertEqual(successor.SELECTED_TEST_FINGERPRINT, S.TEST_FINGERPRINT)
        self.assertNotEqual(historical.SELECTED_TEST_FINGERPRINT, S.TEST_FINGERPRINT)
        successor.helper_inverse()
        historical.helper_inverse()

    def test_live_selector_refuses_wrong_version_and_expiry(self):
        result = self.qualify()
        self.assertEqual(result["POSTs"], 0)
        self.assertEqual(result["binding"]["source"], S.CID)
        self.assertEqual(result["request_raw"], C.encoded(self.values["request"]))
        with self.assertRaisesRegex(ValueError, "HOLD_AUTHORITY_TIME"):
            self.qualify(S.TEST_ROLE_EXPIRES)
        case = self.values["case"]
        case["expires_epoch"] += 1
        with self.assertRaisesRegex(ValueError, "HOLD_SOURCE206_TEST_ROLE_EXPIRY"):
            self.qualify()
        case["expires_epoch"] -= 1
        case["kind"] = "ROOT_SOURCE205_ONCE_CASE_V1"
        with self.assertRaisesRegex(ValueError, "HOLD_SOURCE205_IDENTITY"):
            self.qualify()

    def test_inline_test_role_requires_exact_anchor_and_whole_time(self):
        with self.assertRaisesRegex(ValueError, "HOLD_SOURCE206_TEST_APPROVAL_EXPIRY"):
            self.use_approval(dict(self.approval, expires_epoch=S.TEST_ROLE_EXPIRES - 1))
            self.qualify()
        with self.assertRaisesRegex(ValueError, "HOLD_SOURCE206_TEST_APPROVAL_CERTIFICATE"):
            self.use_approval(dict(self.approval, public_key=dict(self.key, sha256="1" * 64)))
            self.qualify()
        self.use_approval(self.approval)
        model.change_request(self.values, "assembler", lambda row: row["test_trust"].update(
            fingerprint="D9D7A9FC25B9914CF6F2CE55952AEDD8A209B4C0"))
        with self.assertRaisesRegex(ValueError, "HOLD_SOURCE206_TEST_CERTIFICATE"):
            self.qualify()
        self.use_approval(self.approval)
        model.change_request(self.values, "assembler", lambda row: row["test_trust"]["Root_admission"].update(
            pin=C.pin(b"another body")))
        with self.assertRaisesRegex(ValueError, "HOLD_SOURCE206_TEST_APPROVAL_PIN"):
            self.qualify()

    def test_local_qualification_cli_selection_with_no_actor(self):
        operands, _ = model.pack(self.values)
        case = C.decode(operands["case"])
        checkpoint = dict(kind=P.SUCCESSOR_KIND, authority=None, stage="backend", dispatch_ready=False, root_case=case)
        files = operands | dict(checkpoint=C.encoded(checkpoint), core=model.CORE_RAW, profile=self.profile)
        with TemporaryDirectory() as workspace:
            references = {}
            for role, raw in files.items():
                path = Path(workspace) / role
                path.write_bytes(raw)
                references[role] = dict(path=str(path), **C.pin(raw))
            selected = dict(schema=1, kind=P.QUALIFICATION_SELECTION, files=references)
            result = P.qualify_selection(selected, self.now)
            self.assertEqual(result["POSTs"], 0)
            self.assertEqual(C.decode(result["dispatch_body"].encode())["inputs"]["root_request_json"],
                             operands["request"].decode())
            with self.assertRaisesRegex(ValueError, "HOLD_EXPLICIT_NOW"):
                P.qualify_selection(selected, None)

    def test_historical_terminal_mode_selects_only_the_source206_reader(self):
        fixture = terminal_model.Terminal()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        operands, pins = model.pack(self.values)
        case = self.values["case"]
        fixture.run.update(head_sha=S.CID, head_branch=S.REF.removeprefix("refs/heads/"), workflow_id=S.WORKFLOW_ID)
        fixture.job.update(head_sha=S.CID)
        fixture.artifact["workflow_run"].update(head_sha=S.CID, head_branch=fixture.run["head_branch"])
        fixture.entries = {"launcher-report.json": dict(status="HOLD", request_pin=pins["request"],
                   failure=dict(phase="git_source", reason="VALIDATION_REFUSED"), **C.FINAL)}
        archive = fixture.archive()
        fixture.artifact["size_in_bytes"] = len(archive)
        fixture.artifact["digest"] = "sha256:" + C.pin(archive)["sha256"]
        files = dict(case=operands["case"], request=operands["request"], run=C.encoded(fixture.run),
                     jobs=C.encoded(fixture.jobs), artifacts=C.encoded(fixture.artifacts), archive=archive)
        pins = {name: C.pin(raw) for name, raw in files.items()}
        kwargs = dict(ids=terminal_model.IDS, core_raw=model.CORE_RAW, profile_raw=self.profile)
        result = T.verify(files, pins, reader_raw=self.reader, successor=True, **kwargs)
        self.assertEqual(result["status"], T.UNRETAINED)
        self.assertEqual(result["source"], case["source"]["cid"])
        with self.assertRaisesRegex(ValueError, "HOLD_TERMINAL_CASE"):
            T.verify(files, pins, reader_raw=self.reader, **kwargs)
        with self.assertRaisesRegex(ValueError, "HOLD_TERMINAL_READER"):
            T.verify(files, pins, reader_raw=terminal_model.READER, successor=True, **kwargs)

    def tearDown(self):
        self.assertEqual(model.ACTORS, [])


if __name__ == "__main__":
    unittest.main()
