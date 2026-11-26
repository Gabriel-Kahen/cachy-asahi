# SPDX-License-Identifier: MIT
"""Offline pinned-case controls for the emulated installed lifecycle join."""

from pathlib import Path
from runpy import run_path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest


Q = SimpleNamespace(**run_path(str(Path(__file__).with_name("qualify.py"))))
C = Q.C


class Qualification(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory())).resolve()
        self.protection = dict(selected=["/home/builder/.config", "/etc/example.conf"],
                               baseline={"/home/builder/.config": {"present": True, "type": "directory"},
                                         "/etc/example.conf": {"present": False}})
        self.rows = {}
        for i, case in enumerate(Q.H.CASES, 1):
            self.rows[case] = dict(kind=Q.CASE_KIND, status="PASS_INSTALLED_CASE_READBACK_ONLY", case=case,
                                   clone=f"{i:032x}"[::-1], plan=C.pin(b"plan"), selection=C.pin(b"signed"),
                                   scratch=Q.H.P.Q3_SCRATCH, retirement=C.pin(f"retirement {i}".encode()),
                                   baseline_database=C.pin(b"original database"), physical_M2="NOT_RUN",
                                   original_files={"evidence/result.json": C.pin(b"result")},
                                   protection=self.protection if case == "main" else None,
                                   media_sha256=C.pin(f"media {i}".encode())["sha256"],
                                   site_sha256=C.pin(f"site {i}".encode())["sha256"],
                                   authority_sha256=C.pin(f"authority {i}".encode())["sha256"])

    def refs(self):
        result = {}
        for case, row in self.rows.items():
            path = self.root / f"{case}.json"
            body = C.wire(row)
            path.write_bytes(body)
            result[case] = path, C.pin(body)["sha256"]
        return result

    def test_join_keeps_exact_selected_path_and_three_receipt_pins(self):
        refs = self.refs()
        result = Q.qualify(refs)
        self.assertEqual(result["status"], "PASS_EXACT_EMULATED_INSTALLED_LIFECYCLE")
        self.assertEqual(result["selected_path_protection"], self.protection)
        for case, (_, digest) in refs.items():
            self.assertEqual(result["cases"][case]["receipt"]["sha256"], digest)

    def test_refuses_original_digest_mutation_or_missing_case(self):
        refs = self.refs()
        with self.assertRaises(ValueError):
            Q.qualify({case: ref for case, ref in refs.items() if case != "unknown_key"})
        refs["main"][0].write_bytes(b"changed")
        with self.assertRaises(ValueError):
            Q.qualify(refs)

    def test_refuses_baseline_and_plan_drift_or_reused_site(self):
        unknown = self.rows["unknown_key"]
        for key, mutated in (("baseline_database", C.pin(b"other database")), ("selection", C.pin(b"other archive")),
                             ("plan", C.pin(b"other plan")), ("site_sha256", self.rows["main"]["site_sha256"])):
            with self.subTest(key=key):
                original = unknown[key]
                unknown[key] = mutated
                try:
                    with self.assertRaises(ValueError):
                        Q.qualify(self.refs())
                finally:
                    unknown[key] = original

    def test_refuses_clone_prefix_or_old_case_readback(self):
        original = self.rows["main"]["clone"]
        self.rows["unknown_key"]["clone"] = original[:8] + "e" * 24
        with self.assertRaises(ValueError):
            Q.qualify(self.refs())
        self.rows["unknown_key"]["clone"] = "f" * 32
        self.rows["main"]["kind"] = "QTBASE16K_INSTALLED_CASE_READBACK_V1"
        with self.assertRaises(ValueError):
            Q.qualify(self.refs())


if __name__ == "__main__":
    unittest.main()
