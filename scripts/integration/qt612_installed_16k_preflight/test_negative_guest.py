# SPDX-License-Identifier: MIT
"""Exercise the two installed Qtbase refusal clones with inert ALPM commands."""

from pathlib import Path
from runpy import run_path
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


G = SimpleNamespace(**run_path(str(Path(__file__).with_name("guest.py"))))
W, P, T = G.W, G.P, G.T
NONCE, CLONE, FPR = "a" * 32, "b" * 32, "C" * 40
ORIGINAL, TAMPERED = bytes((194, 1, 1)), bytes((194, 1, 2))
CERTIFICATE = bytes((198, 1, 1, 205, 1, 1, 194, 1, 1))
LOCK = b"model 1-1\n"
DATABASE = b'{"unchanged":"model"}\n'
DIAGNOSTICS = {
    "tampered_signature": b"error: invalid or corrupted package (PGP signature)\n",
    "unknown_key": b"error: required key missing from keyring\n",
}


class NegativeGuest(unittest.TestCase):
    def setUp(self):
        self.output = Path(self.enterContext(TemporaryDirectory()))
        self.commands = self.output / "commands"
        self.commands.mkdir()
        self.argv = P.PACMAN + ["--noconfirm", "-U", "--", P.ARCHIVE]
        self.plan = dict(nonce=NONCE, guest={"model": True}, consumer={},
                         stages=[dict(inventory_query=P.PACMAN + ["-Q"], inventory=T.pin(LOCK))],
                         negative_trials={case: {"command": self.argv} for case in W.NEGATIVE_CASES})
        self.selection = {
            "key": dict(fingerprint=FPR, created=100, expires=300, test_only=True),
            "inputs": {"archive": T.pin(b"archive"), "certificate": T.pin(CERTIFICATE),
                       "signature": T.pin(ORIGINAL)},
        }
        self.boundary = Mock(return_value=True)
        self.prepare = Mock(return_value=self.commands)
        self.database = Mock(side_effect=[DATABASE, DATABASE])
        self.call = Mock(side_effect=self.response)
        self.overrides = {}

    def response(self, role, argv, *, timeout, stdin, env):
        result = dict(exit_code=0, stdout=b"", stderr=b"", natural=True, group_empty=True, overflow=False)
        if role.startswith("inventory-"):
            result["stdout"] = LOCK
        if role == "test-certificate":
            result["stdout"] = f"pub:::::100:300:\nuid:::::::::Qt TEST:\nfpr:::::::::{FPR}:\n".encode()
        if role == "signature-refusal":
            result.update(exit_code=1, stderr=DIAGNOSTICS[self.case])
        result |= self.overrides.get(role, {})
        (self.commands / (role + ".stderr")).write_bytes(result["stderr"])
        return result

    def execute(self, case, signature=None, selected_sha=None, clone=CLONE):
        self.case = case
        if signature is None:
            signature = TAMPERED if case == "tampered_signature" else ORIGINAL
        inputs = self.selection["inputs"] | {"signature": T.pin(signature)}
        observed = dict(input_pins=inputs, config_raw=P.CONFIG.encode(),
                        certificate_raw=CERTIFICATE, signature_raw=signature)
        globals_ = G.execute_negative.__globals__
        with (patch.dict(globals_, verify_boundary=self.boundary, prepare_work=self.prepare,
                         runtime_module=Mock(), Runner=Mock(return_value=self.call)),
              patch.object(W, "read_plan", return_value=self.plan),
              patch.object(W, "read_selection", return_value=self.selection),
              patch.object(W, "stopped_database", self.database),
              patch.object(G.O, "input_evidence", return_value=observed)):
            G.execute_negative(b"model plan", "1" * 64, LOCK, b"model selection", "2" * 64,
                               now=200, deadline=time.monotonic() + 120, case=case, clone=clone,
                               signature_sha=inputs["signature"]["sha256"] if selected_sha is None else selected_sha)
        return T.decode((self.output / "result.json").read_bytes())

    def roles(self):
        return [call.args[0] for call in self.call.call_args_list]

    def verify_refusal(self, case):
        result = self.execute(case)
        self.assertEqual(result["status"], "SIGNATURE_REFUSAL_VERIFIED_ONLY")
        self.assertEqual(result["kind"], "QTBASE16K_INSTALLED_NEGATIVE_RESULT_V1")
        self.assertEqual(result["nonce"], NONCE)
        self.assertEqual(result["clone"], CLONE)
        self.assertEqual(result["case"], case)
        self.assertEqual(result["argv"], self.argv)
        self.assertEqual(result["inventory_before"], result["inventory_after"])
        self.assertEqual(result["database_before"], result["database_after"])
        for point in ("before", "after"):
            raw = (self.output / f"database-{point}.json").read_bytes()
            self.assertEqual(result[f"database_{point}"], T.pin(raw))
        stderr = (self.commands / "signature-refusal.stderr").read_bytes()
        self.assertEqual(result["stderr"], T.pin(stderr))
        self.boundary.assert_called_once_with(NONCE, self.plan["guest"], case=case, clone=CLONE)
        self.assertEqual(self.roles().count("signature-refusal"), 1)
        replay = {name: result[name] for name in
                  ("clone", "scratch", "configuration", "archive", "signature", "argv",
                   "exit_code", "natural", "group_empty")}
        W.review_negative(self.plan, self.selection, DATABASE, {NONCE}, case,
                          replay | dict(stderr=stderr, database_before=DATABASE, database_after=DATABASE))

    def test_tampered_signature_uses_exact_current_test_trust(self):
        self.verify_refusal("tampered_signature")
        self.assertEqual(self.roles(), ["inventory-before", "test-certificate", "key-import", "key-trust",
                                       "signature-refusal", "inventory-after", "trust-retirement"])

    def test_unknown_key_reuses_original_signature_and_proves_empty_trust(self):
        self.verify_refusal("unknown_key")
        self.assertEqual(self.roles(), ["inventory-before", "keyring-before", "signature-refusal",
                                       "inventory-after", "keyring-after", "trust-retirement"])

    def test_wrong_operands_refuse_before_preparation(self):
        with self.assertRaisesRegex(ValueError, "case operand"):
            self.execute("tampered_signature", signature=ORIGINAL)
        with self.assertRaisesRegex(ValueError, "signed staged inputs"):
            self.execute("tampered_signature", selected_sha="f" * 64)
        with self.assertRaisesRegex(ValueError, "selected signature-refusal clone"):
            self.execute("unknown_key", clone=NONCE)
        self.prepare.assert_not_called()
        self.call.assert_not_called()

    def test_unknown_key_refuses_any_existing_public_key(self):
        self.overrides["keyring-before"] = {"stdout": b"pub:existing key\n"}
        with self.assertRaisesRegex(ValueError, "empty disposable keyring"):
            self.execute("unknown_key")
        self.assertNotIn("signature-refusal", self.roles())
        self.assertEqual(self.roles()[-1], "trust-retirement")
        self.assertFalse((self.output / "result.json").exists())

    def test_modified_database_keeps_originals_without_success_receipt(self):
        self.database.side_effect = [DATABASE, b"changed database"]
        with self.assertRaisesRegex(ValueError, "clean database"):
            self.execute("unknown_key")
        self.assertTrue((self.output / "database-after.json").exists())
        self.assertEqual(self.roles()[-1], "trust-retirement")
        self.assertFalse((self.output / "result.json").exists())

    def test_boot_binding_preserves_main_and_refuses_cross_case_or_duplicate_tokens(self):
        main = [G.BOOT_NONCE + NONCE]
        G.verify_boot_case(main, NONCE)
        G.verify_boot_case(main + [G.BOOT_CASE + "main", G.BOOT_CLONE + NONCE], NONCE)
        sibling = main + [G.BOOT_CASE + "unknown_key", G.BOOT_CLONE + CLONE]
        G.verify_boot_case(sibling, NONCE, case="unknown_key", clone=CLONE)
        for args, case in ((sibling, "tampered_signature"), (sibling + sibling[-1:], "unknown_key"),
                           (sibling + main, "unknown_key"), (main, "unknown_key")):
            with self.assertRaisesRegex(ValueError, "boot case and clone"):
                G.verify_boot_case(args, NONCE, case=case, clone=CLONE)
        with self.assertRaisesRegex(ValueError, "boot case and clone"):
            G.verify_boot_case(sibling, NONCE)


if __name__ == "__main__":
    unittest.main()
