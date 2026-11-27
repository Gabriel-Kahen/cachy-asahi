#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert controls for staging and stopped-disk evidence collection."""

import json
from pathlib import Path
from runpy import run_path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
S = run_path(str(Path(__file__).with_name("host_stage.py")))
C, E = S["C"], S["E"]
INIT = b'''#!/bin/bash
set -Eeuo pipefail
umask 077

[[ $$ == 1 && $# == 0 && $EUID == 0 ]]
export_evidence /trial-work/evidence /trial-export/evidence
'''


class StageTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.init = self.root / "retained-init.sh"
        self.init.write_bytes(INIT)
        self.enterContext(patch.dict(S["PID1"], C.pin(INIT)))
        self.addon = {name: C.pin((ROOT / name).read_bytes()) for name in S["GUEST_ENTRY"]["SOURCES"]}
        self.plan = dict(kind=S["KIND"], nonce="b" * 32,
                         code={name: C.file_pin(size, sha) for name, (_, size, sha) in S["BASE"].items()},
                         media={"files": {"rollback.lock": C.pin(b"retained manifest lock")}})
        self.plan["manifest"] = C.pin(C.wire(self.plan["media"]))
        self.review = dict(fingerprint="A" * 40, not_before=100, not_after=200,
                           certificate=C.pin(b"test cert"), signature=C.pin(b"test signing evidence"))
        official, project = S["P"]["OFFICIAL_NAME"], S["P"]["PROJECT_NAME"]
        media = {"rollback.lock": b"retained lock", "result.json": C.wire({"nonce": "a" * 32}),
                 official: b"official archive", official + ".sig": b"official signature",
                 project: b"project archive", project + ".sig": b"test signing evidence",
                 "test-certificate.gpg": b"test cert", S["QT_ALARM_NAME"]: b"reviewed ALARM public key"}
        self.paths = {}
        for name, body in media.items():
            path = self.root / name
            path.write_bytes(body)
            self.paths[name] = path
        self.enterContext(patch.dict(S["P"]["PINS"], {
            "rollback_lock": C.pin(media["rollback.lock"]), "rollback_result": C.pin(media["result.json"]),
            "official_archive": C.pin(media[official]), "official_signature": C.pin(media[official + ".sig"]),
            "project_archive": C.pin(media[project]),
            "alarm_public_key": C.pin(media[S["QT_ALARM_NAME"]]),
        }))

    def stage(self, **changes):
        args = dict(retained_source=ROOT, retained_init=self.init, qt_source=ROOT, qt_source_pins=self.addon,
                    baseline_plan=self.plan, project_review=self.review, media_paths=self.paths,
                    wayland_socket="/run/qt629/wayland-0", output=self.root / "stage")
        return S["stage"](**(args | changes))

    def test_stages_exact_fresh_worker_set_and_transport_pins(self):
        report = self.stage()
        root = Path(report["path"])
        self.assertIsNone(report["authority"])
        self.assertEqual({str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()},
                         {"guest-init.sh", *report["files"]})
        for name, pin in (report["files"] | {"guest-init.sh": report["init"]}).items():
            self.assertEqual(C.pin((root / name).read_bytes()), pin, name)
        raw = (root / "code/plan.json").read_bytes()
        plan = C.json_body(raw, canonical=True)
        self.assertEqual(C.pin(raw), report["plan"])
        self.assertEqual(plan["manifest"], self.plan["manifest"])
        self.assertEqual(plan["media"], self.plan["media"])
        self.assertEqual(plan["code"]["asahi-guest.py"], report["worker"])
        self.assertEqual(plan["code"]["trial.py"], self.plan["code"]["trial.py"])
        self.assertEqual(set(plan["qt_media"]), {"qt-replacement/" + name for name in self.paths})
        worker = (root / "code/asahi-guest.py").read_bytes()
        self.assertLess(worker.index(b"query(stage)"), worker.index(b".run_checkpoint("))
        self.assertLess(worker.index(b".run_checkpoint("), worker.index(b'phase = "seal"'))
        result = subprocess.run(["/usr/bin/bash", "-n", str(root / "guest-init.sh")], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"export_qt_evidence /trial-work/qt-replacement-evidence", (root / "guest-init.sh").read_bytes())

    def test_stages_parity_archive_and_detached_signature_only_at_the_selected_names(self):
        P = S["P"]
        old = P["PROJECT_NAME"]
        body = b"new parity archive"
        profile = dict(kind=P["PARITY_KIND"], official_version=P["VERSION"], project_version=P["PARITY_PROJECT_VERSION"],
                       recipe=P["PARITY_RECIPE"], test_review=self.review,
                       **{name: C.pin(name.encode()) for name in P["PARITY_INPUT_CAPS"]})
        profile["project_archive"] = C.pin(body)
        name = P["project_name"](profile)
        paths = {key: path for key, path in self.paths.items() if key not in {old, old + ".sig"}}
        paths[name] = self.root / name
        paths[name].write_bytes(body)
        paths[name + ".sig"] = self.paths[old + ".sig"]
        with self.assertRaisesRegex(ValueError, "Exact pinned Qt media input set"):
            self.stage(profile=profile)
        with self.assertRaisesRegex(ValueError, "Qt TEST review differs"):
            self.stage(profile=profile, media_paths=paths,
                       project_review=self.review | {"certificate": C.pin(b"substitute")})
        paths[name].write_bytes(body[::-1])
        with self.assertRaisesRegex(ValueError, "Exact original file pin"):
            self.stage(profile=profile, media_paths=paths)
        paths[name].write_bytes(body)
        report = self.stage(profile=profile, media_paths=paths)
        root = Path(report["path"])
        plan = C.json_body((root / "code/plan.json").read_bytes(), canonical=True)
        self.assertEqual(P["plan_profile"](plan["qt_replacement"]), profile)
        self.assertEqual(plan["qt_media"]["qt-replacement/" + name], profile["project_archive"])
        self.assertEqual(plan["qt_media"]["qt-replacement/" + name + ".sig"], self.review["signature"])
        self.assertNotIn("qt-replacement/" + old, plan["qt_media"])

    def test_refuses_unexpected_or_rebound_selection_before_publishing(self):
        wrong_code = self.addon | {"unexpected.py": C.pin(b"unreviewed")}
        first = next(iter(self.addon))
        wrong_pin = self.addon | {first: C.pin(b"wrong reviewed bytes")}
        for changes in ({"qt_source_pins": wrong_code}, {"qt_source_pins": wrong_pin},
                        {"media_paths": self.paths | {"unexpected": self.init}},
                        {"baseline_plan": self.plan | {"nonce": "a" * 32}},
                        {"wayland_socket": "/run/../run/wayland-0"}):
            with self.subTest(fields=changes.keys()), self.assertRaises(ValueError):
                self.stage(**changes)
            self.assertFalse((self.root / "stage").exists())

    def test_refuses_existing_stage_and_keeps_original_files(self):
        self.stage()
        snapshot = {path: C.pin(path.read_bytes()) for path in (self.root / "stage").rglob("*") if path.is_file()}
        with self.assertRaises(FileExistsError):
            self.stage()
        self.assertEqual({path: C.pin(path.read_bytes()) for path in snapshot}, snapshot)
        self.assertEqual(list(self.root.glob(".qt629-stage.*")), [])

    def test_weston_media_needs_pinned_sources_and_keeps_exact_bytes(self):
        weston = {}
        archive = S["WESTON_ARCHIVE"]
        for name, body in {archive: b"fixture archive", archive + ".sig": b"detached fixture signature"}.items():
            path = self.root / name
            path.write_bytes(body)
            weston[name] = dict(path=str(path), **C.pin(body))
        socket = "/run/qt629-wl/wayland-0"
        without_weston = self.addon.keys() - S["WESTON_SOURCES"]
        with patch.dict(S["GUEST_ENTRY"], SOURCES=without_weston):
            with self.assertRaisesRegex(ValueError, "pinned guest supervisor"):
                self.stage(qt_source_pins={name: self.addon[name] for name in without_weston},
                           weston=weston, wayland_socket=socket)
        names = self.addon.keys() | S["WESTON_SOURCES"]
        pins = {name: C.pin((ROOT / name).read_bytes()) for name in names}
        with patch.dict(S["GUEST_ENTRY"], SOURCES=names):
            report = self.stage(qt_source_pins=pins, weston=weston, wayland_socket=socket)
        tree = Path(report["path"])
        plan = C.json_body((tree / "code/plan.json").read_bytes())
        for name, op in weston.items():
            pin = C.file_pin(op["bytes"], op["sha256"])
            self.assertEqual(plan["qt_media"]["qt-replacement/" + name], pin)
            self.assertEqual(C.pin((tree / "inputs/qt-replacement" / name).read_bytes()), pin)

    def test_refuses_changed_pid1_and_missing_source_seam(self):
        self.init.write_bytes(INIT.replace(b"umask 077", b"umask 022"))
        with self.assertRaisesRegex(ValueError, "Exact original file pin"):
            self.stage()
        with self.assertRaisesRegex(ValueError, "Exact retained source seam"):
            S["guest_init"](b"#!/bin/bash\n")

    def test_pid1_copies_partial_qt_evidence_and_refuses_unexpected_member(self):
        function, _ = S["guest_init"](INIT).split(b"[[ $$ == 1", 1)
        # Simulate UID/GID zero for ordinary files owned by the test runner.
        command = br'''
stat() {
    local actual dev ino links bytes uid gid mode tail
    actual=$(/usr/bin/stat "$@") || return
    case "$2" in
        '%u:%g:%a') printf '0:0:%s\n' "${actual##*:}" ;;
        '%d %i %h %s %u %g %a %y %z')
            read -r dev ino links bytes uid gid mode tail <<< "$actual"
            printf '%s %s %s %s 0 0 %s %s\n' "$dev" "$ino" "$links" "$bytes" "$mode" "$tail" ;;
        *) printf '%s\n' "$actual" ;;
    esac
}
export_qt_evidence "$1" "$2"
'''
        incoming, retained = self.root / "incoming", self.root / "retained"
        incoming.mkdir(mode=0o700)
        journal = incoming / "transaction.jsonl"
        journal.write_bytes(b"partial HOLD journal\n")
        journal.chmod(0o600)
        for name, body in {"weston-server.log": b"partial server trace\n",
                           "weston-lifecycle.json": b'{"status":"HOLD"}\n',
                           "vendor-runtime-probes.json": b'{"status":"PARTIAL"}\n'}.items():
            leaf = incoming / name
            leaf.write_bytes(body)
            leaf.chmod(0o600)
        result = subprocess.run(["/usr/bin/bash", "-s", "--", str(incoming), str(retained)],
                                input=function + command, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((retained / journal.name).read_bytes(), journal.read_bytes())
        self.assertEqual((retained / journal.name).stat().st_mode & 0o777, 0o600)
        for name in ("weston-server.log", "weston-lifecycle.json", "vendor-runtime-probes.json"):
            self.assertEqual((retained / name).read_bytes(), (incoming / name).read_bytes())
        (incoming / "unexpected").symlink_to(journal)
        refused = self.root / "refused"
        result = subprocess.run(["/usr/bin/bash", "-s", "--", str(incoming), str(refused)],
                                input=function + command, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(refused.exists())


class CheckpointTests(unittest.TestCase):
    def test_generated_guest_keeps_pass_and_hold_before_recording_cleanup_time(self):
        lane = ROOT / "scripts/install/asahi629_trial"
        original = run_path(str(lane / "test_guest.py"))
        T, _, O = original["modules"]()
        worker, _ = S["guest_checkpoint"]((lane / "guest.py").read_bytes(),
                                            (lane / "operands.py").read_bytes(), {})
        guest = ModuleType("qt629_mocked_guest")
        guest.__file__ = str(lane / "guest.py")
        exec(compile(worker, guest.__file__, "exec"), guest.__dict__)
        execute = guest.execute
        key = S["LANE"] + "guest_entry.py"
        guest.execute = lambda T, O, plan: execute(T, O, plan | {"code": {key: {}}, "qt_media": {}})
        for status, code, failed in (("PASS_QT629_PROVIDER_ROUND_TRIP", 0, False),
                                     ("HOLD_QT629_OFFICIAL_RESTORATION_VERIFIED", 75, False),
                                     ("PASS_QT629_PROVIDER_ROUND_TRIP", 75, True)):
            with self.subTest(status=status, failed=failed), TemporaryDirectory() as tmp:
                root = Path(tmp)
                expected = dict(nonce="0" * 32, transaction={"status": status}, runtime_probe=C.pin(b"observed probe"))

                def checkpoint(*_args):
                    self.assertTrue((root / "work/verify-project-test").is_dir())
                    if failed:
                        retained = root / "work/qt-replacement-evidence"
                        retained.mkdir()
                        rows = (dict(phase="entry", nonce=expected["nonce"]),
                                dict(phase="terminal", at_ns=100, **expected["transaction"]))
                        (retained / "transaction.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
                        (retained / "runtime-probes.json").write_bytes(b"observed probe")
                        expected["failure"] = dict(error_type="ValueError", error="Weston retirement failed")
                        raise ValueError("Weston retirement failed")
                    return expected

                def clock():
                    self.assertFalse(any((root / "work" / name).exists()
                                         for name in ("verify-vendor", "verify-project-test", "trust")))
                    return 101

                with (patch.dict(sys.modules, {guest.__name__: guest}),
                      patch.object(guest, "pinned_module", return_value=SimpleNamespace(run_checkpoint=checkpoint)),
                      patch.object(guest, "review_extra"), patch.object(guest.time, "time_ns", side_effect=clock)):
                    _, _, _, result, _, returned, _ = original["exercise"](T, guest, O, root, expired=False)
                self.assertEqual(returned, code)
                self.assertEqual(result["qt_checkpoint"], expected)
                self.assertEqual(result["trust_retired_at_ns"], 101)

    def test_host_joins_returned_disposition_runtime_pin_and_real_cleanup(self):
        nonce, probe = "a" * 32, b"runtime evidence"
        transaction = {"status": "PASS_QT629_PROVIDER_ROUND_TRIP"}
        checkpoint = dict(nonce=nonce, transaction=transaction, runtime_probe=C.pin(probe))
        cleanup = C.wire(dict(completed=True, target_submounts=[],
                              keyrings=dict.fromkeys(E["R"]["TRUST_HOMES"], "removed")))
        owner = dict(nonce=nonce, qt_checkpoint=checkpoint, trust_retired_at_ns=101, cleanup=C.pin(cleanup))
        asahi = {"result.json": C.wire(owner), "cleanup.json": cleanup}
        journal = (json.dumps(dict(phase="terminal", at_ns=100, **transaction)) + "\n").encode()
        qt = {"runtime-probes.json": probe, "transaction.jsonl": journal}
        self.assertEqual(S["checkpoint_observations"](asahi, qt, held=False), (checkpoint, 101))
        with self.assertRaisesRegex(ValueError, "runtime evidence pin"):
            S["checkpoint_observations"](asahi, qt | {"runtime-probes.json": b"rebound"}, held=True)
        with self.assertRaisesRegex(ValueError, "terminal journal"):
            S["checkpoint_observations"](asahi | {"result.json": C.wire(owner | {"trust_retired_at_ns": 99})},
                                         qt, held=False)
        self.assertEqual(S["checkpoint_observations"](asahi, {}, held=True), (checkpoint, 101))


class TestAdmissionSignature(unittest.TestCase):
    def test_checks_detached_signature_even_when_all_operand_pins_match(self):
        root = Path(self.enterContext(TemporaryDirectory()))
        archive = root / S["P"]["PROJECT_NAME"]
        certificate, signature, archive_body = b"public test certificate", b"detached signature", b"pinned project archive"
        (root / "test-certificate.gpg").write_bytes(certificate)
        Path(str(archive) + ".sig").write_bytes(signature)
        archive.write_bytes(archive_body)
        signer = "C" * 40
        review = dict(fingerprint=signer, not_before=100, not_after=200,
                      certificate=C.pin(certificate), signature=C.pin(signature))
        listing = (f"pub:-:255:22:{signer[-16:]}:100:200:::::scESC:\n"
                   f"fpr:::::::::{signer}:\n").encode()
        valid = (f"[GNUPG:] GOODSIG {signer[-16:]} TEST\n"
                 f"[GNUPG:] VALIDSIG {signer} 1970-01-01 120 0 4 0 22 8 00 {signer}\n").encode()
        homes = set()

        def verify(output, exit_code):
            def gpg(argv, **kwargs):
                homes.add(Path(argv[argv.index("--homedir") + 1]))
                if "--show-keys" in argv:
                    return subprocess.CompletedProcess(argv, 0, listing, b"")
                if "--import" in argv:
                    self.assertEqual(kwargs["input"], certificate)
                    self.assertIn("--no-autostart", argv)
                    return subprocess.CompletedProcess(argv, 0, b"", b"")
                self.assertIn("--verify", argv)
                self.assertEqual([Path(path).read_bytes() for path in argv[-2:]], [signature, archive_body])
                return subprocess.CompletedProcess(argv, exit_code, output, b"")

            with (patch.dict(S["P"]["PINS"], project_archive=C.pin(archive_body)),
                  patch.object(S["time"], "time", return_value=150), patch.object(subprocess, "run", side_effect=gpg)):
                return S["verify_qt_test"](root, review)

        self.assertEqual(verify(valid, 0)["signature"]["status"], C.pin(valid))
        with self.assertRaisesRegex(ValueError, "Exact detached signature refused"):
            verify(f"[GNUPG:] BADSIG {signer[-16:]} TEST\n".encode(), 1)
        with self.assertRaisesRegex(ValueError, "outside its reviewed certificate window"):
            verify(valid.replace(b" 120 0 ", b" 151 0 "), 0)
        self.assertTrue(homes)
        self.assertFalse(any(path.exists() for path in homes))


@unittest.skipUnless(shutil.which("mke2fs") and shutil.which("debugfs"), "e2fsprogs unavailable")
class ExportTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.tree = self.root / "tree"
        self.tree.mkdir()
        self.result = C.wire({"status": "Asahi HOLD"})
        self.put("evidence/result.json", self.result)
        self.put(E["ACTOR_DIR"] + "/transaction.jsonl", b"Qt HOLD\n")
        self.put(E["ACTOR_DIR"] + "/weston-server.log", b"")
        self.put(E["ACTOR_DIR"] + "/weston-lifecycle.json", b'{"status":"HOLD"}\n')

    def put(self, name, body):
        path = self.tree / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(body)
        path.chmod(0o600)

    def image(self):
        path = self.root / "result.raw"
        with path.open("xb") as stream:
            stream.truncate(E["RESULT_BYTES"])
        subprocess.run(["mke2fs", "-q", "-t", "ext4", "-b", "4096", "-O", "^orphan_file", "-d", str(self.tree),
                        str(path)], check=True, capture_output=True)
        for entry in self.tree.rglob("*"):
            name = "/" + str(entry.relative_to(self.tree))
            for field in ("uid", "gid"):
                subprocess.run(["debugfs", "-w", "-R", f"set_inode_field {name} {field} 0", str(path)],
                               check=True, capture_output=True)
        return path, C.read(path, E["RESULT_BYTES"], collect=False)[1]

    def test_exports_partial_hold_from_both_namespaces_without_touching_disk(self):
        disk, pin = self.image()
        before = C.identity(disk.lstat())
        qt, asahi = self.root / "qt", self.root / "asahi"
        report = S["export_result"](disk, pin, qt, held=True, asahi_bundle=asahi)
        self.assertEqual(report["evidence"], {"transaction.jsonl": C.pin(b"Qt HOLD\n"),
                                             "weston-server.log": C.pin(b""),
                                             "weston-lifecycle.json": C.pin(b'{"status":"HOLD"}\n')})
        self.assertEqual(report["asahi"], {"result.json": C.pin(self.result)})
        self.assertIn("runtime-probes.json", report["missing_actor_files"])
        self.assertEqual((qt / "transaction.jsonl").read_bytes(), b"Qt HOLD\n")
        self.assertEqual((qt / "weston-lifecycle.json").read_bytes(), b'{"status":"HOLD"}\n')
        self.assertEqual((asahi / "result.json").read_bytes(), self.result)
        self.assertEqual(C.identity(disk.lstat()), before)

    def test_refuses_partial_disk_when_outer_reports_completion(self):
        disk, pin = self.image()
        with self.assertRaisesRegex(ValueError, "incomplete"):
            S["export_result"](disk, pin, self.root / "qt", held=False)
        self.assertFalse((self.root / "qt").exists())

    def test_held_export_refuses_guest_evidence_from_a_different_nonce(self):
        nonce = "a" * 32
        self.put("evidence/result.json", C.wire({"status": "Asahi HOLD", "nonce": nonce}))
        self.put(E["ACTOR_DIR"] + "/weston-lifecycle.json", C.wire({"status": "HOLD", "nonce": "d" * 32}))
        disk, pin = self.image()
        qt, asahi = self.root / "qt", self.root / "asahi"
        with self.assertRaisesRegex(ValueError, "nonce.*weston-lifecycle"):
            S["export_result"](disk, pin, qt, held=True, asahi_bundle=asahi, expected_nonce=nonce)
        self.assertFalse(qt.exists())
        self.assertFalse(asahi.exists())

    def test_rejects_unexpected_legacy_result_file(self):
        self.put("evidence/unexpected.json", b"unexpected")
        disk, pin = self.image()
        with self.assertRaisesRegex(ValueError, "result namespace"):
            S["export_result"](disk, pin, self.root / "qt", held=True)
        self.assertFalse((self.root / "qt").exists())

    def test_rejects_unexpected_qt_result_file(self):
        self.put(E["ACTOR_DIR"] + "/unexpected.json", b"unexpected")
        disk, pin = self.image()
        with self.assertRaisesRegex(ValueError, "Unexpected result member"):
            S["export_result"](disk, pin, self.root / "qt", held=True)
        self.assertFalse((self.root / "qt").exists())

    def test_rejects_weston_log_larger_than_the_producer_limit(self):
        self.put(E["ACTOR_DIR"] + "/weston-server.log", b"a" * ((1 << 20) + 1))
        disk, pin = self.image()
        with self.assertRaisesRegex(ValueError, "size: weston-server.log"):
            S["export_result"](disk, pin, self.root / "qt", held=True)
        self.assertFalse((self.root / "qt").exists())


if __name__ == "__main__":
    unittest.main()
