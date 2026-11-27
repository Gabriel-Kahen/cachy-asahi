#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert controls for the live Asahi629 checkpoint adapter."""

from pathlib import Path
from contextlib import contextmanager
import os
from runpy import run_path
from shutil import copyfile
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
E = run_path(str(HERE / "guest_entry.py"))
T = SimpleNamespace(**run_path(str(REPO / "scripts/install/overlay583_trial/trial.py")))
G = SimpleNamespace(**run_path(str(REPO / "scripts/install/asahi629_trial/guest.py")))
R = SimpleNamespace(**run_path(str(HERE / "runtime_probes.py")))
X = SimpleNamespace(**run_path(str(HERE / "transaction.py")))
W = SimpleNamespace(**run_path(str(HERE / "weston_run.py")))
NONCE = "a" * 32
EXPIRED = "E" * 40
ALARM, COMMUNITY, PREVIEW, CANDIDATE = (label * 40 for label in "ABCD")
KEYS = {
    "alarm": dict(fingerprint=ALARM, scope="vendor", file="keys/alarm.gpg"),
    "community": dict(fingerprint=COMMUNITY, scope="vendor", file="keys/community.gpg"),
    "preview-test": dict(fingerprint=PREVIEW, scope="project-test", not_before=100, not_after=900),
}
REVIEW = dict(fingerprint=CANDIDATE, not_before=120, not_after=800,
              signature=T.pin(b"candidate signature"), certificate=T.pin(b"candidate certificate"))
PLATFORM = {"boot": {"type": "directory"}}
BASE_ALARM = b"armored ALARM fixture"
QT_ALARM = b"binary Qt key fixture"


def passing_checks():
    checks = {name: R.result("PASS", "test") for name in R.PHASES}
    checks["wayland"]["process"] = dict(pid=101, start_ticks=901)
    checks["vulkan_qrhi"]["process"] = dict(pid=102, start_ticks=902)
    return checks


def signature(fingerprint):
    return (f"[GNUPG:] GOODSIG {fingerprint[-16:]} fixture\n"
            f"[GNUPG:] VALIDSIG {fingerprint} 1970-01-01 130 0 4 0 22 8 00 {fingerprint}\n").encode()


class Keyrings:
    def __init__(self, homes):
        self.names = {path: name for name, path in homes.items()}
        self.primary = dict(vendor={ALARM, COMMUNITY}, **{"project-test": {PREVIEW}},
                            pacman={ALARM, COMMUNITY, PREVIEW})
        self.ownertrust = {ALARM, COMMUNITY, PREVIEW}
        self.secret_scope = None
        self.calls = []

    def __call__(self, _trial, home, *args, data=None):
        scope, action = self.names[home], args[-1]
        self.calls.append((scope, action, data))
        if action == "--list-keys":
            times = {PREVIEW: (100, 900), CANDIDATE: (120, 800)}
            listed = []
            for fpr in sorted(self.primary[scope]):
                before, after = times.get(fpr, (100, ""))
                listed.extend((f"pub:-:255:22:{fpr[-16:]}:{before}:{after}:::::scESC:", f"fpr:::::::::{fpr}:"))
            return ("\n".join(listed) + "\n").encode()
        if action == "--list-secret-keys":
            return b"sec:secret\n" if self.secret_scope == scope else b"tru::1\n"
        if action == "--export-ownertrust":
            values = self.ownertrust if scope == "pacman" else set()
            return b"# public fixture\n" + b"".join(f"{fpr}:6:\n".encode() for fpr in values)
        if action == "--import":
            assert data == b"candidate certificate"
            self.primary[scope].add(CANDIDATE)
            return b""
        if action == "--import-ownertrust":
            assert data == f"{CANDIDATE}:6:\n".encode() and scope == "pacman"
            self.ownertrust.add(CANDIDATE)
            return b""
        raise AssertionError(action)


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.O = SimpleNamespace(IN=self.root / "media", WORK=self.root / "work", TARGET=self.root / "target",
                                 HISTORICAL_TEST={EXPIRED}, relative=lambda _trial, name: Path(name))
        self.folder = self.O.IN / "qt-replacement"
        self.folder.mkdir(parents=True)
        self.homes = G.trust_homes(self.O)
        self.O.WORK.mkdir()
        (self.O.WORK / "pacman.conf").write_bytes(E["PACKAGE_POLICY"])
        files = {
            "rollback.lock": b"historical lock",
            "result.json": T.encoded(dict(nonce="f" * 32, platform={"rollback": T.pin(T.encoded(PLATFORM))})),
            "official.pkg": b"official body", "official.pkg.sig": b"original detached signature",
            "project.pkg": b"project body", "project.pkg.sig": b"candidate signature",
            "test-certificate.gpg": b"candidate certificate",
            E["QT_ALARM_NAME"]: QT_ALARM,
        }
        for leaf, body in files.items():
            (self.folder / leaf).write_bytes(body)
        alarm_cert = self.O.IN / "keys/alarm.gpg"
        alarm_cert.parent.mkdir()
        alarm_cert.write_bytes(BASE_ALARM)
        fixed = {
            role: T.pin(files[name]) for role, name in (
                ("rollback_lock", "rollback.lock"), ("rollback_result", "result.json"),
                ("official_archive", "official.pkg"), ("official_signature", "official.pkg.sig"),
                ("project_archive", "project.pkg"),
            )
        }
        fixed["alarm_public_key"] = T.pin(QT_ALARM)
        self.enterContext(patch.dict(E["media"].__globals__, ASAHI629_ALARM=T.pin(BASE_ALARM)))
        self.tx = SimpleNamespace(
            P=dict(OFFICIAL_NAME="official.pkg", PROJECT_NAME="project.pkg", PINS=fixed, verify_official=Mock(),
                   plan_profile=X.P["plan_profile"],
                   profile_pins=lambda profile: fixed if profile is None else fixed | {
                       "project_archive": profile["project_archive"]},
                   project_name=lambda profile: "project.pkg" if profile is None else X.P["project_name"](profile)),
            A=dict(FINGERPRINT=ALARM), PROJECT="project-qt", PASS="test actor pass",
            checked_review=X.checked_review, checked_nonce=X.checked_nonce,
            certificate=Mock(return_value=(REVIEW, files["test-certificate.gpg"])),
            signature=Mock(return_value=({}, signature(CANDIDATE))),
        )
        self.fixture = SimpleNamespace(ARCHIVE="weston.pkg", PINS=dict(archive=T.pin(b"weston"), signature=T.pin(b"sig")),
                                       stage=Mock(return_value={"verified": True}))
        self.plan = dict(
            kind=G.BOOT, nonce=NONCE, qt_replacement=dict(project_review=REVIEW, wayland_socket=None),
            media=dict(keys=KEYS, files={KEYS["alarm"]["file"]: T.pin(BASE_ALARM)}),
        )

    def media(self, selected, seen):
        return E["media"](T, self.O, self.tx, self.fixture, W, selected, seen)

    def test_boot_nonce_requires_one_exact_selected_token(self):
        token = E["NONCE_ARG"] + "=" + NONCE
        self.assertEqual(E["boot_nonce"](T, f"ro {token} console=ttyAMA0\n", NONCE), NONCE)
        for cmdline in ("ro", token + " " + token, token + " " + E["NONCE_ARG"], token + "0",
                        token + " " + E["NONCE_ARG"] + "=" + "b" * 32):
            with self.subTest(cmdline=cmdline), self.assertRaisesRegex(ValueError, "boot nonce differs"):
                E["boot_nonce"](T, cmdline, NONCE)

    def test_media_checks_all_finite_members_and_retained_alarm_certificate(self):
        seen = {}
        self.assertEqual(self.media(self.plan, seen), (self.folder, REVIEW, None))
        self.assertEqual(len(seen), 9)
        self.tx.P["verify_official"].assert_called_once_with(
            {"official_archive": self.folder / "official.pkg", "official_signature": self.folder / "official.pkg.sig"}, QT_ALARM)
        extra = self.folder / "extra"
        extra.touch()
        with self.assertRaisesRegex(ValueError, "Exact Qt read-only media members"):
            self.media(self.plan, {})
        extra.unlink()
        archive = self.folder / "official.pkg"
        archive.write_bytes(b"officiaL body")
        with self.assertRaisesRegex(ValueError, "Changed pinned bytes"):
            self.media(self.plan, {})

    def test_parity_media_requires_new_archive_identity_and_matching_test_review(self):
        P = X.P
        profile = dict(kind=P["PARITY_KIND"], official_version=P["VERSION"], project_version=P["PARITY_PROJECT_VERSION"],
                       recipe=P["PARITY_RECIPE"], test_review=REVIEW,
                       **{name: T.pin(name.encode()) for name in P["PARITY_INPUT_CAPS"]})
        profile["project_archive"] = T.pin((self.folder / "project.pkg").read_bytes())
        addon = self.plan["qt_replacement"] | {"parity_profile": profile}
        plan = self.plan | {"qt_replacement": addon}
        with self.assertRaisesRegex(ValueError, "Exact Qt read-only media members"):
            self.media(plan, {})
        name = P["project_name"](profile)
        (self.folder / "project.pkg").rename(self.folder / name)
        (self.folder / "project.pkg.sig").rename(self.folder / (name + ".sig"))
        self.assertEqual(self.media(plan, {}), (self.folder, REVIEW, None))
        changed = addon | {"project_review": REVIEW | {"signature": T.pin(b"wrong signature")}}
        with self.assertRaisesRegex(ValueError, "Qt TEST review differs"):
            self.media(self.plan | {"qt_replacement": changed}, {})

    def test_base_armored_and_qt_binary_certificate_pins_cannot_substitute_for_each_other(self):
        self.media(self.plan, {})
        qt_key = self.folder / E["QT_ALARM_NAME"]
        qt_key.write_bytes(BASE_ALARM)
        with self.assertRaises(ValueError):
            self.media(self.plan, {})
        qt_key.write_bytes(QT_ALARM)
        self.plan["media"]["files"][KEYS["alarm"]["file"]] = T.pin(QT_ALARM)
        with self.assertRaisesRegex(ValueError, "distinct original ALARM"):
            self.media(self.plan, {})

    def test_media_rejects_wrong_alarm_role_and_unapproved_socket_syntax(self):
        selected = self.plan["qt_replacement"]
        for invalid in ("/tmp/wayland-0", "/run/../run/wayland-0", "/run/wayland-0\n", 123):
            with self.subTest(socket=invalid), self.assertRaisesRegex(ValueError, "exact selected guest Weston socket"):
                self.media(self.plan | {"qt_replacement": selected | {"wayland_socket": invalid}}, {})
        previous = self.plan["media"]
        vendor = KEYS["alarm"] | {"fingerprint": COMMUNITY}
        with self.assertRaisesRegex(ValueError, "original ALARM public certificate"):
            self.media(self.plan | {"media": previous | {"keys": KEYS | {"alarm": vendor}}}, {})

    def select(self, ring, review=REVIEW):
        function = E["select_trust"]
        with patch.dict(function.__globals__, private_homes=lambda *_args: self.homes, call_gpg=ring), \
                patch.object(E["time"], "time", return_value=150):
            return function(T, self.O, G, self.tx, self.plan["media"], self.folder, review)

    def test_import_extends_only_test_verification_and_pacman_keyrings(self):
        ring = Keyrings(self.homes)
        self.select(ring)
        changes = [(scope, action) for scope, action, _ in ring.calls if action.startswith("--import")]
        self.assertEqual(changes, [("project-test", "--import"), ("pacman", "--import"), ("pacman", "--import-ownertrust")])
        self.assertEqual(ring.primary["vendor"], {ALARM, COMMUNITY})
        self.assertEqual(ring.ownertrust, {ALARM, COMMUNITY, PREVIEW, CANDIDATE})
        self.tx.certificate.assert_called_once_with(self.folder / "test-certificate.gpg", REVIEW, self.homes["project-test"])

    def test_wrong_ownertrust_secret_keys_or_relaxed_pacman_prevent_import(self):
        ring = Keyrings(self.homes)
        ring.ownertrust.add(EXPIRED)
        with self.assertRaisesRegex(ValueError, "Unexpected ownertrust"):
            self.select(ring)
        self.assertFalse(any(action.startswith("--import") for _, action, _ in ring.calls))
        ring = Keyrings(self.homes)
        ring.secret_scope = "project-test"
        with self.assertRaisesRegex(ValueError, "only public certificates"):
            self.select(ring)
        (self.O.WORK / "pacman.conf").write_bytes(E["PACKAGE_POLICY"].replace(b"Required", b"Optional"))
        with self.assertRaisesRegex(ValueError, "Required TrustedOnly"):
            self.select(ring)
        self.assertFalse(any(action.startswith("--import") for _, action, _ in ring.calls))

    def test_signature_failure_or_key_reuse_cannot_grant_ownertrust(self):
        ring = Keyrings(self.homes)
        for reuse in (ALARM, PREVIEW, EXPIRED):
            with self.subTest(fingerprint=reuse), self.assertRaisesRegex(ValueError, "separate from previous"):
                self.select(ring, REVIEW | {"fingerprint": reuse})
        self.assertFalse(ring.calls)
        self.tx.signature.return_value = ({}, signature(COMMUNITY))
        with self.assertRaisesRegex(ValueError, "current selected detached signature"):
            self.select(ring)
        self.assertFalse(any(scope == "pacman" and action.startswith("--import") for scope, action, _ in ring.calls))

    def test_live_checkpoint_calls_probe_and_returns_readback_pin(self):
        report_path = self.O.WORK / "qt-replacement-evidence/runtime-probes.json"
        socket = W.SOCKET
        self.plan["qt_replacement"]["wayland_socket"] = socket
        (self.folder / self.fixture.ARCHIVE).write_bytes(b"weston")
        (self.folder / (self.fixture.ARCHIVE + ".sig")).write_bytes(b"sig")
        checkpoint = self.O.WORK / "evidence/rollback.lock"
        checkpoint.parent.mkdir()
        checkpoint.write_bytes((self.folder / "rollback.lock").read_bytes())
        actor = SimpleNamespace(**vars(R))
        calls = []
        compositor = SimpleNamespace(socket=socket)
        weston = SimpleNamespace(**vars(W))

        @contextmanager
        def supervise(*, nonce, stage_fixture):
            self.assertEqual(nonce, NONCE)
            self.fixture.stage.assert_not_called()
            destination = self.O.TARGET / W.FIXTURE.lstrip("/")
            self.assertEqual(stage_fixture(destination), {"verified": True})
            self.fixture.stage.assert_called_once_with(
                archive=self.folder / self.fixture.ARCHIVE, signature=self.folder / (self.fixture.ARCHIVE + ".sig"),
                public_key=self.folder / E["QT_ALARM_NAME"], destination=destination)
            calls.append("ready")
            try:
                yield compositor
            finally:
                calls.append("retired")

        weston.supervise = supervise

        def run_probe(*, nonce, wayland_socket, weston, phase="replacement"):
            self.assertIs(weston, compositor)
            calls.append(phase)
            directory, name = ((self.O.WORK, R.VENDOR_REPORT) if phase == "vendor"
                               else (report_path.parent, "runtime-probes.json"))
            return R.write_result(directory, passing_checks(), wayland_socket, nonce=nonce, name=name)

        actor.run = Mock(side_effect=run_probe)
        context = SimpleNamespace(**vars(G))
        context.base = SimpleNamespace(platform=Mock(return_value=PLATFORM))

        def transact(*, project_review, probe, platform, nonce):
            self.assertEqual(project_review, REVIEW)
            self.assertEqual(nonce, NONCE)
            self.assertEqual(platform(), T.encoded(PLATFORM))
            report_path.parent.mkdir()
            self.assertIsNone(probe())
            return dict(status=self.tx.PASS)

        self.tx.run = Mock(side_effect=transact)
        hook = E["run_checkpoint"]
        with patch.dict(hook.__globals__, environment=Mock(return_value=NONCE),
                        modules=Mock(return_value=(self.tx, actor, self.fixture, weston)), select_trust=Mock()):
            output = hook(T, self.O, context, self.plan)
            self.assertEqual(output, dict(nonce=NONCE, transaction={"status": self.tx.PASS},
                                          runtime_probe=T.pin(report_path.read_bytes())))
            self.assertEqual(calls, ["ready", "vendor", "replacement", "retired"])
            self.assertTrue((report_path.parent / R.VENDOR_REPORT).is_file())
            checkpoint.write_bytes(b"foreign data")
            with self.assertRaises(ValueError):
                hook(T, self.O, context, self.plan)
            self.tx.run.assert_called_once()

    def test_partial_runtime_report_is_preserved_but_cannot_back_a_pass(self):
        checks = {name: R.result("PASS", "test") for name in R.PHASES}
        for name in ("wayland", "vulkan_qrhi"):
            checks[name] = R.result("SKIP", "test")
        with self.assertRaisesRegex(RuntimeError, "coverage PARTIAL"):
            R.write_result(self.root, checks, None, nonce=NONCE)
        name = self.root / E["PROBE_FILE"]
        self.assertEqual(E["probe_evidence"](T, R, name, None, nonce=NONCE, passed=False), T.pin(name.read_bytes()))
        with self.assertRaisesRegex(ValueError, "evidence differs"):
            E["probe_evidence"](T, R, name, None, nonce="f" * 32, passed=False)
        with self.assertRaisesRegex(ValueError, "coverage differs"):
            E["probe_evidence"](T, R, name, None, nonce=NONCE, passed=True)
        name.unlink()
        with self.assertRaisesRegex(ValueError, "lacks its runtime probe report"):
            E["probe_evidence"](T, R, name, None, nonce=NONCE, passed=True)
        R.write_result(self.root, passing_checks(), None, nonce=NONCE)
        with self.assertRaisesRegex(ValueError, "Unselected Wayland compositor"):
            E["probe_evidence"](T, R, name, None, nonce=NONCE, passed=True)

    def test_runtime_report_inspection_error_is_not_treated_as_absence(self):
        report = self.root / E["PROBE_FILE"]
        failed = Mock(side_effect=PermissionError("cannot inspect runtime report"))
        with patch.object(os, "lstat", failed), patch.object(Path, "lstat", failed):
            with self.assertRaisesRegex(PermissionError, "cannot inspect runtime report"):
                E["probe_evidence"](T, R, report, None, nonce=NONCE, passed=False)


class SourceSelectionTests(unittest.TestCase):
    def test_exact_staged_source_only_tree_loads_both_pin_checked_helpers(self):
        root = Path(self.enterContext(TemporaryDirectory()))
        pins = {}
        for leaf in E["SOURCES"]:
            target = root / leaf
            target.parent.mkdir(parents=True, exist_ok=True)
            copyfile(REPO / leaf, target)
            pins[leaf] = T.pin(target.read_bytes())
        loader = E["modules"]
        with patch.dict(loader.__globals__, CODE=root):
            seen = {}
            tx, probes, fixture, weston = loader(T, G, {"code": pins}, seen)
            self.assertEqual(tx.VERSION, X.VERSION)
            self.assertEqual(probes.PHASES, R.PHASES)
            self.assertEqual(weston.SOCKET, W.SOCKET)
            self.assertEqual(fixture.ARCHIVE, W.F["ARCHIVE"])
            self.assertEqual(len(seen), len(pins))
            path = root / (E["LANE"] + "prepare.py")
            path.write_bytes(path.read_bytes() + b"\n")
            with self.assertRaises(ValueError):
                loader(T, G, {"code": pins}, {})


if __name__ == "__main__":
    unittest.main()
