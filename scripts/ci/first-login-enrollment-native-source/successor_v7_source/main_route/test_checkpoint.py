# SPDX-License-Identifier: MIT
"""Actor-fenced caller controls over maintained, explicitly synthetic DATA."""

from contextlib import ExitStack
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import checkpoint as P

C = P.C
M = P.load("source205_backend_case_MODEL", HERE / "test_contract.py")


class CheckpointControls(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        profile = M.G.model_inputs()[3]
        profile["materials"] = {name.lower(): row for name, row in profile["materials"].items()}
        self.values = M.model_case(profile)
        self.profile = C.encoded(profile)
        model_pin = C.pin(self.profile)
        for module, field in ((C, "PROFILE"), (M.C, "PROFILE"), (P.R, "PROFILE_PIN")):
            stack.enter_context(patch.object(module, field, model_pin))
        case = self.values["case"]
        self.selection = {key: {name: case[key][name] for name in fields} for key, fields in
                          (("source", ("cid", "ref")), ("main", ("cid", "tree")))}
        self.selection["workflow_id"] = case["workflow_id"]
        self.inputs = {
            "publication": C.encoded(dict(status="PASS_COMPLETE_PUBLIC_GIT_READBACK_DATA_ONLY", issuer="Root",
                source=case["source"]["cid"], ref=case["source"]["ref"], public_clone_complete=True,
                public_blob_tree_join=True, Root_independent_fresh_ref_commit_recheck=True,
                Root_independent_whole_file_mode_recheck=True, native="NOT RUN",
                source_map_sha256=C.SOURCE205["source_map"]["sha256"],
                **{key: C.SOURCE205[key] for key in ("tree", "files", "bytes")})),
            "source196_close": C.encoded(dict(status=P.SOURCE196_HOLD, Source=P.R.SOURCE196, issuer="Root",
                run=1, job=2, attempt=1, retry=False, native_acceptance=False,
                underlying_child_cause="UNKNOWN_NOT_RETAINED")),
            "registration": C.encoded(dict(id=case["workflow_id"], path=C.WORKFLOW, state="active",
                                            name="Current onboarding delegated private v3")),
            "profile": self.profile,
            "launcher": M.CORE_RAW,
            "provenance_operand": M.CORE_RAW,
            "reader": b"\n".join(f"def {name}(): pass".encode() for name in (
                "transport_packet", "diagnostic_failure_record", "transport_source_data", "read_delegated_stage")),
            "workflow": (HERE.parents[4] / C.WORKFLOW).read_bytes(),
        }
        self.result = self.checkpoint()
        for key in ("source", "main"):
            case[key] = self.result["root_case"][key]
            self.values["readback"][key] = case[key]
        self.values["readback"]["profile_pin"] = model_pin

    def checkpoint(self, inputs=None):
        values = self.inputs if inputs is None else inputs
        return P.prepare(self.selection, values, {role: C.pin(raw) for role, raw in values.items()})

    def qualify(self, values=None):
        operands, pins = M.pack(self.values if values is None else values)
        raw = C.encoded(self.result)
        return P.qualify_backend(raw, C.pin(raw), operands, pins, now=M.NOW, core_raw=M.CORE_RAW,
                                 profile_raw=self.profile)

    def test_unissued_keeps_live_fields_absent(self):
        self.assertFalse(self.result["dispatch_ready"])
        self.assertFalse(self.result["standalone_transport_stage"])
        self.assertIsNone(self.result["live_registration_proof"])
        self.assertIsNone(self.result["root_case"]["nonce"])
        self.assertIsNone(self.result["root_case"]["approved"])
        self.assertIsNone(self.result["scaffold"]["runtime.TEMPLATE.json"]["sweeps"])
        self.assertEqual(self.result["root_case"]["stage"], "backend")
        self.assertEqual(self.result["native248_command_ordinal"], 2)
        self.assertEqual(self.result["assembler"]["products"], {})

    def test_independent_data_and_active_workflow_checks(self):
        wrong = {role: C.pin(raw) for role, raw in self.inputs.items()}
        wrong["publication"] = wrong["source196_close"]
        with self.assertRaisesRegex(ValueError, "HOLD_STATIC_PUBLICATION_PIN"):
            P.prepare(self.selection, self.inputs, wrong)
        inactive = C.encoded(P.observation(self.inputs["registration"]) | {"state": "disabled_manually"})
        with self.assertRaisesRegex(ValueError, "HOLD_ACTIVE_WORKFLOW_METADATA"):
            self.checkpoint(self.inputs | {"registration": inactive})

    def test_unadopted_or_incompatible_main_readers_refuse(self):
        with self.assertRaisesRegex(ValueError, "HOLD_EXACT_CANONICAL_MAIN_ADOPTION"):
            self.checkpoint(self.inputs | {"launcher": b"def old_v6(): pass\n"})
        with self.assertRaisesRegex(ValueError, "HOLD_MAIN_READER_TRANSPORT_ENTRY_POINTS"):
            self.checkpoint(self.inputs | {"reader": b"def diagnostic_failure_record(): pass\n"})

    def test_uses_maintained_positive_backend_qualifier(self):
        qualified = self.qualify()
        self.assertTrue(qualified["ready_for_external_root_operator"])
        self.assertFalse(qualified["Root_authentication"])
        self.assertEqual(qualified["POSTs"], 0)
        self.assertFalse(qualified["native_entered"])
        self.assertEqual(set(qualified["dispatch_inputs"]), {"root_request_json", "root_request_sha256"})

    def test_other_stage_or_backend_products_refuse(self):
        case = self.values["case"]
        case["stage"] = "ui"
        with self.assertRaisesRegex(ValueError, "HOLD_CHECKPOINT_CASE_STAGE"):
            self.qualify()
        case["stage"] = "backend"
        M.change_request(self.values, "assembler", lambda row: row.update(products={"extra": {}}))
        with self.assertRaisesRegex(ValueError, "HOLD_EXACT_FIRST_BACKEND_PRODUCTS_AND_RETENTION"):
            self.qualify()


if __name__ == "__main__":
    unittest.main()
