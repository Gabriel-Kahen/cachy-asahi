#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded fixture checks for draft handoff and refusal paths."""
import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest

here = Path(__file__).resolve().parent
loader = importlib.util.spec_from_file_location("hardware_drafts", here / "prepare_release_evidence.py")
draft = importlib.util.module_from_spec(loader)
loader.loader.exec_module(draft)
release = draft.module(here.parent / "release" / "release.py")
client = draft.client


class DraftTests(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.root = Path(work.name)
        self.output = self.root / "hardware"
        self.kernel = "6.18.9-asahi"
        self.source = "a" * 40
        self.roles = {role: role.replace("_", "-") for role in draft.ROLES}
        packages = [dict(name=name, version="1.0-1", arch="aarch64", files=[]) for name in sorted(self.roles.values())]
        self.base = self.put("base.json", dict(schema_version=1, kind="complete-target-transaction",
                            target_arch="aarch64", snapshot_id="fixture-base", packages=packages))
        self.artifact = self.put("fixture.pkg.tar.xz", b"fixture package bytes")
        self.prov = self.put("provenance.json", dict(schema_version=1, source_commit=self.source,
            package=dict(name="fixture", version="1.0-1", arch="any"), artifact_sha256=self.artifact["sha256"]))
        self.spec = self.put("spec.json", dict(schema_version=1, target_arch="aarch64", synthetic=False,
            source_commit=self.source, release_id="fixture-release", base=dict(self.base, snapshot_id="fixture-base"),
            policy=dict(supported_models=["m2-air-13", "m2-air-15"], protected_packages=list(self.roles.values()),
                        selected_packages=["fixture"]),
            packages=[dict(artifact=self.artifact, provenance=self.prov)]))
        self.contract = self.put("contract.raw.json", dict(sleep_wake_repetitions=20, private_case="PRIVATE-TAG"))
        self.baseline = dict(schema_version=1, record_type="environment-baseline", validation_result="NOT RUN",
            execution_context="physical", architecture="aarch64", page_size_bytes=16_384, kernel=self.kernel,
            collected_at="2026-10-11T12:00:01.100000+00:00", operator="PRIVATE-TAG-capturer",
            machine_model="PRIVATE-TAG serial", graphics=dict(stdout="PRIVATE-TAG app"), audio=dict(stdout="PRIVATE-TAG audio"),
            packages=dict(command=["pacman", "-Q"], returncode=0,
                          stdout="\n".join(f"{p['name']} {p['version']}" for p in packages)))
        self.review = dict(kind=draft.REVIEW_KIND, decision="REVIEWED_PHYSICAL_BASELINE", model_id="apple,j413",
            machine_id="m2-" + "9" * 32, reviewer="PRIVATE-TAG-reviewer", reviewed_utc="2026-10-11T12:05:00Z",
            platform_packages=self.roles, boot_firmware_version="iBoot-42.1",
            spec_sha256=self.spec["sha256"], base_sha256=self.base["sha256"], contract_sha256=self.contract["sha256"])

    def put(self, leaf, value):
        content = value if isinstance(value, bytes) else client.encoded(value)
        (self.root / leaf).write_bytes(content)
        return dict(path=leaf, sha256=client.digest(content))

    def cli(self, board="apple,j413", size="13-inch", session=False, review_pin=None, session_identity=None):
        self.baseline.update(device_tree_compatible=f"{board}\napple,t8112", m2_air_size=size)
        before = self.put("baseline.raw.json", self.baseline)
        self.review.update(baseline_sha256=before["sha256"], session_sha256=None)
        options = []
        if session:
            identities = dict(architecture="aarch64", observed_model_id=board, declared_model_id=board,
                declared_model_matches_observation=True, execution_context="physical", page_size_bytes=16_384,
                kernel=self.kernel, baseline_sha256=before["sha256"], source_revision=self.source)
            identities.update(session_identity or {})
            raw = self.put("session.raw.json", dict(schema_version=1, record_type="session-observations",
                collected_at="2026-10-11T12:00:02Z", identity=identities, checks=[dict(value="PRIVATE-TAG session")],
                physical_checks=dict(sleep_wake="NOT RUN")))
            self.review["session_sha256"] = raw["sha256"]
            options = ["--session", str(self.root / raw["path"])]
        review = self.put("review.raw.json", self.review)
        paths = dict(baseline=before["path"], contract=self.contract["path"], review=review["path"],
                     spec=self.spec["path"], output=self.output.name)
        for name, path in paths.items():
            options.extend(("--" + name, str(self.root / path)))
        options.extend(("--review-sha256", review["sha256"] if review_pin is None else review_pin))
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            status = draft.main(options)
        return status, out.getvalue(), err.getvalue()

    def test_both_model_evidence_refs_resolve_and_raw_private_data_stays_local(self):
        for board, size, session in (("apple,j413", "13-inch", False), ("apple,j415", "15-inch", True)):
            with self.subTest(board=board):
                self.output = self.root / size
                self.review["model_id"] = board
                status, out, err = self.cli(board, size, session)
                self.assertEqual((status, err), (0, ""))
                output = client.decode(out.encode())
                self.assertEqual(output["hardware_validation"], "NOT RUN")
                self.assertEqual(len(output["evidence"]), 4 if session else 3)
                evidence = {row["id"]: release.file_ref(self.root, row) for row in output["evidence"]}
                machine = release.load(evidence[output["machine_record"]])
                self.assertEqual(machine["model"], "m2-air-" + size.split("-")[0])
                self.assertEqual(machine["base_sha256"], self.base["sha256"])
                self.assertEqual(machine["package_sha256"], {"fixture": self.artifact["sha256"]})
                self.assertEqual(machine["platform_versions"]["kernel"]["baseline_version"], "1.0-1")
                self.assertEqual(release.load(evidence[machine["acceptance_contract"]])["sleep_wake_repetitions"], 20)
                self.assertEqual("session" in machine, session)
                self.assertTrue(all("PRIVATE-TAG" not in path.read_text() for path in self.output.iterdir()))
                self.assertNotIn("result", machine)

    def test_off_target_ambiguous_and_private_id_refuse_without_output(self):
        self.baseline["architecture"] = "x86_64"
        self.assertIn("unambiguous", self.cli()[2])
        self.baseline["architecture"] = "aarch64"
        self.assertIn("unambiguous", self.cli("apple,j413\napple,j415")[2])
        self.review["machine_id"] = "PRIVATE-TAG-serial"
        self.assertIn("independently pinned", self.cli()[2])
        self.assertFalse(self.output.exists())

    def test_independent_review_pin_package_bytes_and_protected_version_refusal(self):
        self.assertIn("independently supplied SHA-256", self.cli(review_pin="0" * 64)[2])
        old = self.review["reviewer"]
        self.review["reviewer"] = self.baseline["operator"]
        self.assertIn("independently pinned", self.cli()[2])
        self.review["reviewer"] = old
        original = (self.root / self.artifact["path"]).read_bytes()
        self.put(self.artifact["path"], b"drift")
        self.assertIn("identity, provenance, or bytes differ", self.cli()[2])
        self.put(self.artifact["path"], original)
        self.baseline["packages"]["stdout"] = self.baseline["packages"]["stdout"].replace("kernel 1.0-1", "kernel 2.0-1")
        self.assertIn("protected package versions differ", self.cli()[2])
        self.assertFalse(self.output.exists())

    def test_session_and_base_pin_refusal(self):
        self.assertIn("session observation differs", self.cli(
            session=True, session_identity={"observed_model_id": "apple,j415"})[2])
        self.assertIn("session observation differs", self.cli(
            session=True, session_identity={"source_revision": "b" * 40})[2])
        self.review["base_sha256"] = "0" * 64
        self.assertIn("release base checksum differs", self.cli()[2])
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
