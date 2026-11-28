#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise the scoped provider transaction with inert fake state and evidence."""

from contextlib import contextmanager
import io
import json
from pathlib import Path
from runpy import run_path
from subprocess import CompletedProcess
import tarfile
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch


T = run_path(str(Path(__file__).with_name("transaction.py")))
OFFICIAL, PROJECT, VERSION = (T[name] for name in ("OFFICIAL", "PROJECT", "VERSION"))
PIN = T["pin"]
PLATFORM = b'{"fixture":"protected"}\n'
NONCE = "e" * 32
TEST_FINGERPRINT = "C" * 40
CERTIFICATE = b"inert public certificate body"
REVIEW = dict(fingerprint=TEST_FINGERPRINT, certificate=PIN(CERTIFICATE), signature=PIN(b"inert signature"),
              not_before=100, not_after=200)


def inventory(owner, version=VERSION):
    rows = [f"fixture-{i:04d} 1:2-1\n" for i in range(628)] + [f"{owner} {version}\n"]
    return "".join(sorted(rows)).encode("ascii")


def accepted(incoming, outgoing, versions=None):
    if versions is None:
        versions = {OFFICIAL: VERSION, PROJECT: VERSION}
    return dict(type=T["CONFLICT_PKG"], pair=((incoming, versions[incoming]), (outgoing, versions[outgoing])),
                accepted=True)


class FakeBackend:
    def __init__(self, journal, fault=None, *, project_version=VERSION):
        self.journal = journal
        self.fault = fault
        self.raw = inventory(OFFICIAL)
        self.versions = {OFFICIAL: VERSION, PROJECT: project_version}
        self.reason = 1
        self.commits = []
        self.locked = False

    def inventory(self, _owner):
        assert not self.locked
        return self.raw, self.reason

    def authenticate(self):
        if self.fault == "trust":
            raise ValueError("Official signature unavailable")
        signers = {owner: (dict(status=PIN(owner.encode()), fingerprint=fingerprint), owner.encode()) for owner, fingerprint
                   in ((OFFICIAL, T["A"]["FINGERPRINT"]), (PROJECT, TEST_FINGERPRINT))}
        observed = dict(pin=PIN(CERTIFICATE), fingerprint=TEST_FINGERPRINT, not_before=100, not_after=200)
        if self.fault == "certificate-signer":
            observed["fingerprint"] = "D" * 40
        return signers, (observed, CERTIFICATE)

    @contextmanager
    def prepare(self, incoming, outgoing, before, reason):
        assert not self.locked
        self.locked = True
        try:
            if self.raw != before or self.reason != reason:
                raise ValueError("Locked state differs")
            if incoming == OFFICIAL and self.fault == "restore-prepare":
                raise ValueError("Official reverse prepare refused")
            add, remove = {incoming: self.versions[incoming]}, {outgoing: self.versions[outgoing]}
            questions = [accepted(incoming, outgoing, self.versions)]
            if self.fault == "foreign-removal":
                remove["fixture-0001"] = "1:2-1"
            if self.fault == "extra-question":
                questions.append(dict(type=1, pair=None, accepted=False))
            yield dict(add=add, remove=remove, questions=questions, install_reason=self.reason), self.commit
        finally:
            self.locked = False

    def commit(self, owner, reason):
        assert self.locked
        stage = "replacement" if owner == PROJECT else "restoration"
        row = json.loads(self.journal.path.read_text().splitlines()[-1])
        assert row["phase"] == stage + "-commit-start"
        self.commits.append(owner)
        self.raw = inventory(owner, self.versions[owner])
        if self.fault == stage + "-commit":
            raise ValueError("Commit failed after reporting the new inventory")
        if self.fault == stage + "-interrupt":
            raise KeyboardInterrupt
        if self.fault == stage + "-reason":
            self.reason = 1 - reason
        if self.fault == stage + "-readback":
            self.raw = self.raw.replace(b"fixture-0001 1:2-1", b"fixture-0001 1:3-1")


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.journal = T["Journal"](self.root)
        self.backend = FakeBackend(self.journal)

    def rows(self):
        return [json.loads(line) for line in self.journal.path.read_bytes().splitlines()]

    def execute(self, probe=lambda: None, platform=lambda: PLATFORM):
        return T["_run"](self.backend, self.journal, inventory(OFFICIAL), probe, platform, PIN(PLATFORM), NONCE)

    def test_exact_round_trip_retains_other_628_rows_and_install_reason(self):
        def probe():
            self.assertEqual(self.backend.raw, inventory(PROJECT))
            self.assertFalse(self.backend.locked)

        self.assertEqual(self.execute(probe)["status"], T["PASS"])
        self.assertEqual(self.backend.commits, [PROJECT, OFFICIAL])
        rows = self.rows()
        self.assertEqual([row["phase"] for row in rows], [
            "entry", "baseline", "trust", "replacement-prepare", "replacement-commit-start",
            "replacement-commit-done", "replacement", "probe", "restoration-prepare",
            "restoration-commit-start", "restoration-commit-done", "restoration", "terminal",
        ])
        self.assertEqual(rows[2]["policy"], "Required TrustedOnly")
        self.assertEqual(rows[0]["nonce"], NONCE)
        self.assertEqual(rows[2]["test_certificate"], dict(pin=PIN(CERTIFICATE), fingerprint=TEST_FINGERPRINT,
                                                           not_before=100, not_after=200))
        self.assertEqual((self.root / "test-certificate.gpg").read_bytes(), CERTIFICATE)
        self.assertEqual(rows[3]["add"], {PROJECT: VERSION})
        self.assertEqual(rows[8]["remove"], {PROJECT: VERSION})
        for stage, owner in (("baseline", OFFICIAL), ("replacement", PROJECT), ("restoration", OFFICIAL)):
            body = (self.root / (stage + ".lock")).read_bytes()
            phase = next(row for row in rows if row["phase"] == stage)
            self.assertEqual(body, inventory(owner))
            self.assertEqual(phase["inventory"], PIN(body))
            self.assertEqual(phase["install_reason"], 1)
            self.assertEqual((self.root / (stage + "-platform.json")).read_bytes(), PLATFORM)
        for stage, owner in (("replacement", PROJECT), ("restoration", OFFICIAL)):
            self.assertEqual((self.root / (stage + "-signature.status")).read_bytes(), owner.encode())

    def test_parity_probe_runs_only_after_exact_official_restoration(self):
        parity = T["P"]["PARITY_PROJECT_VERSION"]
        report = PIN(b"restored runtime report")
        for fault in (None, "completed-probe-failure", "missing-probe-report", "restoration-readback"):
            with self.subTest(fault=fault), TemporaryDirectory() as folder:
                journal = T["Journal"](Path(folder))
                backend = FakeBackend(journal, project_version=parity)
                backend.fault = fault

                def restored_probe():
                    self.assertEqual(backend.raw, inventory(OFFICIAL))
                    self.assertFalse(backend.locked)
                    self.assertTrue((journal.directory / "restoration.lock").is_file())
                    if fault == "missing-probe-report":
                        raise OSError("No completed report")
                    failure = RuntimeError("Restored runtime failed") if fault == "completed-probe-failure" else None
                    return report, failure

                callback = Mock(side_effect=restored_probe)
                result = T["_run"](backend, journal, inventory(OFFICIAL), lambda: None, lambda: PLATFORM,
                                   PIN(PLATFORM), NONCE, project_version=parity, profile_pin=PIN(b"profile"),
                                   restored_probe=callback)
                rows = [json.loads(line) for line in journal.path.read_bytes().splitlines()]
                if fault == "restoration-readback":
                    callback.assert_not_called()
                    self.assertEqual(result["status"], T["HOLD_DISCARD"])
                    self.assertEqual(result["failure_phase"], "restoration")
                else:
                    callback.assert_called_once_with()
                    self.assertEqual([row["phase"] for row in rows[-3:]],
                                     ["restoration", "restoration-probe", "terminal"])
                    self.assertEqual(result["last_verified"], "restoration")
                    if fault is None:
                        self.assertEqual(result["status"], T["PASS"])
                        self.assertEqual(result["restored_runtime_probe"], report)
                    else:
                        self.assertEqual(result["status"], T["HOLD_RESTORED"])
                        self.assertEqual(result["failure_phase"], "restoration-probe")
                        self.assertEqual(rows[-2]["status"], "HOLD")
                        self.assertEqual(result["error"], rows[-2]["error"])
                        expected = (report, "RuntimeError", "Restored runtime failed") if fault == "completed-probe-failure" else (
                            None, "OSError", "No completed report")
                        pin, error_type, message = expected
                        self.assertEqual(result["restored_runtime_probe"], pin)
                        self.assertEqual(result["error"], {"error_type": error_type, "error": message})
                        self.assertEqual(rows[-1]["restored_runtime_probe"], pin)

    def test_mixed_version_round_trip_and_legacy_project_rejection(self):
        parity = T["P"]["PARITY_PROJECT_VERSION"]
        backend = FakeBackend(self.journal, project_version=parity)
        result = T["_run"](backend, self.journal, inventory(OFFICIAL), lambda: None,
                           lambda: PLATFORM, PIN(PLATFORM), NONCE, project_version=parity)
        self.assertEqual(result["status"], T["PASS"])
        self.assertEqual(backend.commits, [PROJECT, OFFICIAL])
        rows = {row["phase"]: row for row in self.rows()}
        self.assertEqual(rows["replacement-prepare"]["questions"][0]["pair"],
                         [[PROJECT, parity], [OFFICIAL, VERSION]])
        self.assertEqual(rows["restoration-prepare"]["questions"][0]["pair"],
                         [[OFFICIAL, VERSION], [PROJECT, parity]])
        self.assertEqual((self.root / "replacement.lock").read_bytes(), inventory(PROJECT, parity))
        self.assertEqual((self.root / "restoration.lock").read_bytes(), inventory(OFFICIAL))
        with self.assertRaisesRegex(ValueError, "one approved Qt provider conflict"):
            T["check_prepared"]({PROJECT: VERSION}, {OFFICIAL: VERSION}, [accepted(PROJECT, OFFICIAL)],
                                PROJECT, OFFICIAL, project_version=parity)

    def test_both_signatures_are_required_before_the_first_prepare(self):
        self.backend.fault = "trust"
        result = self.execute()
        self.assertEqual(result["status"], T["HOLD_BASELINE"])
        self.assertEqual(result["failure_phase"], "trust")
        self.assertEqual(self.backend.commits, [])

    def test_signature_must_match_authenticated_test_certificate(self):
        self.backend.fault = "certificate-signer"
        result = self.execute()
        self.assertEqual(result["status"], T["HOLD_BASELINE"])
        self.assertEqual(result["failure_phase"], "trust")
        self.assertEqual(self.backend.commits, [])
        self.assertEqual([row["phase"] for row in self.rows()], ["entry", "baseline", "terminal"])

    def test_refuses_foreign_removal_and_extra_question_before_commit(self):
        for fault in ("foreign-removal", "extra-question"):
            with self.subTest(fault=fault):
                self.backend.fault = fault
                result = self.execute()
                self.assertEqual(result["status"], T["HOLD_BASELINE"])
                self.assertEqual(result["failure_phase"], "replacement-prepare")
                self.assertEqual(self.backend.commits, [])
                for child in self.root.iterdir():
                    child.unlink()

    def test_reversal_occurs_after_failed_probe_but_trial_is_held(self):
        def probe():
            raise RuntimeError("Qt Quick failed")

        result = self.execute(probe)
        self.assertEqual(result["status"], T["HOLD_RESTORED"])
        self.assertEqual(result["failure_phase"], "probe")
        self.assertEqual(result["last_verified"], "restoration")
        self.assertEqual(self.backend.commits, [PROJECT, OFFICIAL])

    def test_ambiguous_candidate_failure_never_starts_restoration(self):
        self.backend.fault = "replacement-commit"
        result = self.execute()
        self.assertEqual(result["status"], T["HOLD_DISCARD"])
        self.assertIsNone(result["last_verified"])
        self.assertEqual(self.backend.raw, inventory(PROJECT))
        self.assertEqual(self.backend.commits, [PROJECT])

    def test_wrong_candidate_inventory_or_reason_stops_even_after_commit_success(self):
        for fault in ("replacement-readback", "replacement-reason"):
            with self.subTest(fault=fault), TemporaryDirectory() as folder:
                journal = T["Journal"](Path(folder))
                backend = FakeBackend(journal, fault)
                result = T["_run"](backend, journal, inventory(OFFICIAL), lambda: None, lambda: PLATFORM,
                                   PIN(PLATFORM), NONCE)
                self.assertEqual(result["status"], T["HOLD_DISCARD"])
                self.assertEqual(result["failure_phase"], "replacement")
                self.assertEqual(backend.commits, [PROJECT])

    def test_changed_protected_state_stops_after_candidate_commit(self):
        result = self.execute(platform=lambda: b"changed" if self.backend.commits else PLATFORM)
        self.assertEqual(result["status"], T["HOLD_DISCARD"])
        self.assertEqual(self.backend.commits, [PROJECT])

    def test_restore_prepare_commit_and_readback_failures_require_discard(self):
        for stage in ("prepare", "commit", "readback"):
            with self.subTest(stage=stage), TemporaryDirectory() as folder:
                journal = T["Journal"](Path(folder))
                backend = FakeBackend(journal, "restore-prepare" if stage == "prepare" else "restoration-" + stage)
                result = T["_run"](backend, journal, inventory(OFFICIAL), lambda: None, lambda: PLATFORM,
                                   PIN(PLATFORM), NONCE)
                self.assertEqual(result["status"], T["HOLD_DISCARD"])
                self.assertEqual(backend.commits, [PROJECT] if stage == "prepare" else [PROJECT, OFFICIAL])

    def test_interrupt_during_commit_leaves_pending_marker_and_no_retry(self):
        self.backend.fault = "replacement-interrupt"
        with self.assertRaises(KeyboardInterrupt):
            self.execute()
        self.assertEqual(self.rows()[-1]["phase"], "replacement-commit-start")
        self.assertEqual(self.backend.commits, [PROJECT])
        self.assertFalse(self.backend.locked)

    def test_unavailable_commit_journal_stops_before_mutation(self):
        real_record = self.journal.record

        def record(phase, **data):
            if phase == "replacement-commit-start":
                raise OSError("journal write failed")
            return real_record(phase, **data)

        with patch.object(self.journal, "record", record):
            result = self.execute()
        self.assertEqual(result["status"], T["HOLD_BASELINE"])
        self.assertEqual(self.backend.commits, [])

    def test_wrong_initial_inventory_declines_before_trust(self):
        self.backend.raw = inventory(PROJECT)
        result = self.execute()
        self.assertEqual(result["status"], T["HOLD_DISCARD"])
        self.assertEqual([row["phase"] for row in self.rows()], ["entry", "terminal"])


class ConflictTests(unittest.TestCase):
    def test_callback_consent_is_ordered_exact_single_and_versioned(self):
        ct = T["ct"]
        owners = {1: (PROJECT, VERSION), 2: (OFFICIAL, VERSION), 3: (OFFICIAL, "6.12.0-4"),
                  4: ("foreign-qt", VERSION)}
        expected = owners[1], owners[2]
        for incoming, outgoing in ((2, 1), (1, 3), (1, 4), (1, 2)):
            with self.subTest(pair=(incoming, outgoing)):
                conflict = T["Conflict"](incoming, outgoing, None)
                body = T["ConflictQuestion"](T["Question"](T["CONFLICT_PKG"], 1), ct.pointer(conflict))
                ptr = ct.cast(ct.pointer(body), ct.POINTER(T["Question"]))
                seen = []
                T["resolve_conflict"](expected, owners.__getitem__, seen, ptr)
                self.assertEqual(body.base.answer, int((incoming, outgoing) == (1, 2)))
                T["resolve_conflict"](expected, owners.__getitem__, seen, ptr)
                self.assertEqual(body.base.answer, 0)
        body = T["Question"](1, 1)
        seen = []
        T["resolve_conflict"](expected, owners.__getitem__, seen, ct.pointer(body))
        self.assertEqual(seen, [dict(type=1, pair=None, accepted=False)])
        self.assertEqual(body.answer, 0)


class ReviewTests(unittest.TestCase):
    def test_nonce_must_be_exact_and_distinct_from_predecessor(self):
        self.assertIsNone(T["checked_nonce"](NONCE, "a" * 32))
        for invalid in (None, NONCE.upper(), "a" * 32, NONCE[:-1]):
            with self.subTest(nonce=invalid), self.assertRaisesRegex(ValueError, "Fresh selected"):
                T["checked_nonce"](invalid, "a" * 32)

    def test_read_test_certificate_binds_body_gpg_primary_and_validity(self):
        root = Path(self.enterContext(TemporaryDirectory()))
        path = root / "test-certificate.gpg"
        path.write_bytes(CERTIFICATE)
        listing = (
            f"pub:-:255:22:{TEST_FINGERPRINT[-16:]}:100:200:::::scESC:\n"
            f"fpr:::::::::{TEST_FINGERPRINT}:\n"
        ).encode()
        expected = dict(pin=PIN(CERTIFICATE), fingerprint=TEST_FINGERPRINT, not_before=100, not_after=200)
        with patch.object(T["time"], "time", return_value=150), patch.object(T["subprocess"], "run") as command:
            command.return_value = CompletedProcess([], 0, stdout=listing, stderr=b"")
            observed, body = T["certificate"](path, T["checked_review"](REVIEW), root)
            self.assertEqual((observed, body), (expected, CERTIFICATE))
            self.assertIn("--show-keys", command.call_args.args[0])
            for changes in (dict(fingerprint="D" * 40), dict(not_after=201)):
                with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, "identity or current validity"):
                    T["certificate"](path, REVIEW | changes, root)
            command.return_value = CompletedProcess([], 0, stdout=listing.replace(b"pub:", b"sec:"), stderr=b"")
            with self.assertRaisesRegex(ValueError, "one public Qt TEST primary"):
                T["certificate"](path, REVIEW, root)
        path.write_bytes(CERTIFICATE[:-1] + b"!")
        with self.assertRaisesRegex(ValueError, "Input pin differs"):
            T["certificate"](path, REVIEW, root)


class AlpmReadOnlyTests(unittest.TestCase):
    def test_real_binding_requires_signature_and_releases_temporary_db_lock(self):
        library = Path("/usr/lib/libalpm.so.16")
        if not library.is_file():
            self.skipTest("libalpm 16 unavailable")
        version = T["ct"].CDLL(str(library)).alpm_version
        version.restype = T["ct"].c_char_p
        if version() != b"16.0.1":
            self.skipTest("libalpm 16.0.1 unavailable")
        root = Path(self.enterContext(TemporaryDirectory()))
        target = root / "synthetic-target"
        db = target / "var/lib/pacman"
        package = db / "local" / f"{OFFICIAL}-{VERSION}"
        package.mkdir(parents=True)
        (db / "local/ALPM_DB_VERSION").write_text("9\n")
        desc = f"%NAME%\n{OFFICIAL}\n\n%VERSION%\n{VERSION}\n\n%REASON%\n1\n".encode()
        (package / "desc").write_bytes(desc)
        keyring = root / "public"
        keyring.mkdir(mode=0o700)
        unsigned = root / T["P"]["PROJECT_NAME"]
        metadata = f"pkgname = {PROJECT}\npkgver = {VERSION}\narch = aarch64\n".encode()
        with tarfile.open(unsigned, "w:xz") as archive:
            entry = tarfile.TarInfo(".PKGINFO")
            entry.size = len(metadata)
            archive.addfile(entry, io.BytesIO(metadata))
        with patch.dict(T["run"].__globals__, TARGET=target):
            alpm = T["Alpm"](keyring, root / "alpm.log")
            self.addCleanup(alpm.close)
            expected = f"{OFFICIAL} {VERSION}\n".encode()
            self.assertEqual(alpm.inventory(), expected)
            with self.assertRaisesRegex(ValueError, "signature"):
                with alpm.prepare(unsigned, PROJECT, OFFICIAL, expected, 1):
                    self.fail("Unsigned fixture unexpectedly prepared")
            self.assertFalse((db / "db.lck").exists())
            self.assertEqual((package / "desc").read_bytes(), desc)


if __name__ == "__main__":
    unittest.main()
