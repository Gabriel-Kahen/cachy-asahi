#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Synthetic evidence and tampering controls for the Qt629 receipt reader."""

import copy
import hashlib
from itertools import count
import json
from pathlib import Path
from runpy import run_path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch


R = run_path(str(Path(__file__).with_name("readback.py")))
RUNTIME = run_path(str(Path(__file__).with_name("runtime_probes.py")))
C, P, W = R["C"], R["P"], R["W"]
OFFICIAL, PROJECT, VERSION, PHASES, EVENTS = (R[name] for name in (
    "OFFICIAL", "PROJECT", "VERSION", "PHASES", "EVENTS"))
VENDOR = P["A"]["FINGERPRINT"]
TEST = "D" * 40
NONCE, PRIOR = "b" * 32, "a" * 32
NOW = 1795804000


def signature(signer):
    return (f"[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG {signer[-16:]} Fixture\n"
            f"[GNUPG:] VALIDSIG {signer} 2026-11-27 {NOW} 0 4 0 1 10 00 {signer}\n").encode()


def jsonl(rows):
    return b"".join((json.dumps(row, sort_keys=True) + "\n").encode("ascii") for row in rows)


def runtime_fixture(phase):
    """Use the current producer, with inert command results and socket state."""
    guest = RUNTIME["Guest"].__new__(RUNTIME["Guest"])
    guest.inner = "/tmp/qt629-probe-" + {"vendor": "vendor", "replacement": "fixture", "restoration": "restored"}[phase]
    guest.path = lambda _: SimpleNamespace(is_file=lambda: True)
    socket = W["SOCKET"]
    pids = count({"vendor": 100, "replacement": 200, "restoration": 300}[phase])
    marks = {
        "offscreen": "QT629_GUI_OK 6.12.0 offscreen",
        "software": "QT629_QUICK_OK software pixels=verified",
        "wayland": "QT629_GUI_OK 6.12.0 wayland",
        "vulkan": "QT629_QRHI_OK wayland vulkan frame=swapped",
    }

    def execute(argv, _timeout):
        command = next(i for i, arg in enumerate(argv[len(R["PROBE_PREFIX"]):], len(R["PROBE_PREFIX"]))
                       if arg.startswith("/"))
        program, *args = argv[command:]
        output = {"pkg-config": "-I/usr/include/qt6 -l" + args[-1],
                  "g++": "", "python3": "QT629_VULKAN_OK devices=1"}.get(Path(program).name)
        if output is None:
            output = marks[args[0]]
        pid = next(pids)
        return dict(argv=argv, pid=pid, start_ticks=pid * 2, exit=0, problem=None, output=output + "\n")

    weston = SimpleNamespace(socket=socket, begin=lambda *_: None, attest=lambda *_: {"status": "PASS"})
    with patch.dict(guest.command.__globals__, execute=execute, socket_state=lambda *_: None):
        checks = RUNTIME["collect"](guest, socket, weston, phase=phase)
    with TemporaryDirectory() as folder:
        path = Path(folder)
        name = RUNTIME["REPORTS"][phase]
        RUNTIME["write_result"](path, checks, socket, nonce=NONCE, name=name)
        return (path / name).read_bytes()


def protocol_trace(pid, frames):
    events = [
        "rq wl_compositor@4.create_surface(new id wl_surface@44)",
        "rq xdg_wm_base@5.get_xdg_surface(new id xdg_surface@45, wl_surface@44)",
        "rq xdg_surface@45.get_toplevel(new id xdg_toplevel@46)",
        "ev xdg_toplevel@46.configure(64, 64, array)",
        "ev xdg_surface@45.configure(7)",
        "rq xdg_surface@45.ack_configure(7)",
        "rq wl_shm@6.create_pool(new id wl_shm_pool@47, fd 7, 65536)",
    ]
    for offset in range(frames):
        buffer, callback = 50 + offset, 60 + offset
        events.extend((f"rq wl_shm_pool@47.create_buffer(new id wl_buffer@{buffer}, 0, 64, 64, 256, 0)",
                       f"rq wl_surface@44.attach(wl_buffer@{buffer}, 0, 0)",
                       f"rq wl_surface@44.frame(new id wl_callback@{callback})",
                       "rq wl_surface@44.commit()", f"ev wl_callback@{callback}.done(1234)"))
    return "".join(f"[2026-11-27 21:10:00.123][proto] client 0xab (PID {pid}) {event}\n"
                   for event in events).encode()


def weston_fixture(raw):
    trace = b"[21:10:00.123] weston 15.0.1\n"
    presentations = {}
    roles = W["PARITY_PROBES"] if R["RESTORED_REPORT"] in raw else W["PROBES"]
    for role, minimum in roles.items():
        phase, kind = role.split("-")
        name = RUNTIME["REPORTS"][phase]
        check = "wayland" if kind == "raster" else "vulkan_qrhi"
        process = C.json_body(raw[name])["checks"][check]["process"]
        pid = process["pid"]
        segment = protocol_trace(pid, minimum)
        presentations[role] = dict(status="PASS", **process, socket=W["SOCKET"], start=len(trace),
                                   end=len(trace) + len(segment), trace=C.pin(segment),
                                   presentation=W["presentation"](segment, pid, minimum))
        trace += segment
    report = dict(
        kind=W["KIND"], status="PASS", nonce=NONCE, socket=W["SOCKET"], argv=W["command"](),
        dependencies={name: dict(exit=0, output="fixture loader result", truncated=False) for name in W["F"]["FILES"]},
        startup=dict(peer=dict(pid=9, uid=65534, gid=65534), socket_inode=[1, 2],
                     output=dict(name="headless", width=256, height=256, refresh_millihz=60000)),
        retirement=dict(signals=["SIGTERM"], forced=False, exit=0, reaped=True, group_absent=True,
                        socket_removed_by_weston=True, runtime_removed=True, fixture_removed=True),
        presentations=presentations, error=None, log=C.pin(trace), log_limit_reached=False, missing_presentations=[],
    )
    return {W["LOG_NAME"]: trace, W["REPORT_NAME"]: C.wire(report)}


def fixture(*, project_version=VERSION, restored_runtime=False):
    """Return canonical receipt data and the original and observed file bodies."""
    lock = (f"{OFFICIAL} {VERSION}\n" + "".join(f"unchanged-{i:04d} 1:2.3-4\n" for i in range(628))).encode()
    changed, restored = P["project"](lock, project_version=project_version)
    versions = {OFFICIAL: VERSION, PROJECT: project_version}
    fixed = dict(type="file", pin=C.pin(b"fixture"), uid=0, gid=0, mode=0o644, links=1)
    state = {name: fixed for name in ("boot/vmlinuz-linux-asahi", "boot/initramfs-linux-asahi.img",
                                      "etc/fstab", "etc/crypttab")}
    state["boot"] = dict(type="directory", uid=0, gid=0, mode=0o755, links=2)
    state.update({f"boot/fixture-{i:03d}": fixed for i in range(357)})
    platform = C.wire(state)
    inputs = {role: ("fixture " + role).encode() for role in R["ORIGINALS"]}
    inputs["project_archive"] += f" {project_version}".encode()
    inputs["r132_config"] = b"CONFIG_ARM64_16K_PAGES=y\nCONFIG_RTC_DRV_PL031=y\n"
    inputs["rollback_lock"] = lock
    inputs["rollback_result"] = C.wire(dict(
        status=P["PASS629"], nonce=PRIOR, inventory=dict(rollback=C.pin(lock)),
        platform=dict.fromkeys(("baseline", "forward", "rollback"), C.pin(platform))))
    inputs["owned_terminal"] = C.wire(dict(
        status=P["OWNED_SUCCESS"], nonce=PRIOR, outer_container_absent_twice=True,
        inputs_reverified_after=True, controller_result=dict(status=P["PASS629"]),
        retained_result_files={"evidence/result.json": C.pin(inputs["rollback_result"])}))
    pins = {name: C.pin(body) for name, body in inputs.items()}
    raw = {f"{phase}.lock": body for phase, body in zip(PHASES, (lock, changed, restored), strict=True)}
    raw.update({f"{phase}-platform.json": platform for phase in PHASES})
    raw.update({"test-certificate.gpg": b"synthetic public certificate",
                "test-signature.sig": b"synthetic detached signature",
                "replacement-signature.status": signature(TEST),
                "restoration-signature.status": signature(VENDOR),
                "runtime-probes.json": runtime_fixture("replacement"),
                "vendor-runtime-probes.json": runtime_fixture("vendor")})
    if restored_runtime:
        raw[R["RESTORED_REPORT"]] = runtime_fixture("restoration")
    raw.update(weston_fixture(raw))
    actions = [("removed", OFFICIAL), ("installed", PROJECT), ("removed", PROJECT), ("installed", OFFICIAL)]
    raw["pacman.log"] = "".join(f"[2026-11-27T13:30:00+0000] [ALPM] {action} {name} ({versions[name]})\n"
                                for action, name in actions).encode()
    start = NOW * 10**9
    journal_phases = R["PARITY_JOURNAL_PHASES"] if restored_runtime else R["JOURNAL_PHASES"]
    rows = {name: dict(phase=name, at_ns=start + i) for i, name in enumerate(journal_phases, 1)}
    rows["entry"].update(kind=R["JOURNAL_KIND"], nonce=NONCE)
    rows["trust"]["signers"] = {
        PROJECT: dict(archive=pins["project_archive"], signature=C.pin(raw["test-signature.sig"]),
                      fingerprint=TEST, status=C.pin(raw["replacement-signature.status"])),
        OFFICIAL: dict(archive=pins["official_archive"], signature=pins["official_signature"],
                       fingerprint=VENDOR, status=C.pin(raw["restoration-signature.status"])),
    }
    rows["trust"]["policy"] = "Required TrustedOnly"
    rows["trust"]["test_certificate"] = dict(pin=C.pin(raw["test-certificate.gpg"]), fingerprint=TEST,
                                            not_before=NOW - 60, not_after=NOW + 600)
    for phase in PHASES:
        rows[phase].update(inventory=C.pin(raw[f"{phase}.lock"]), install_reason=1, platform=C.pin(platform))
    for phase, add, remove in (("replacement", PROJECT, OFFICIAL), ("restoration", OFFICIAL, PROJECT)):
        added, removed = versions[add], versions[remove]
        question = dict(type=4, pair=[[add, added], [remove, removed]], accepted=True)
        rows[f"{phase}-prepare"].update(add={add: added}, remove={remove: removed}, questions=[question],
                                        install_reason=1)
    rows["probe"].update(status="PASS", error=None)
    rows["terminal"].update(kind=R["JOURNAL_KIND"], status="PASS_QT629_PROVIDER_ROUND_TRIP",
                            last_verified="restoration", failure_phase=None, error=None)
    if restored_runtime:
        rows["restoration-probe"].update(status="PASS", error=None)
        rows["terminal"]["restored_runtime_probe"] = C.pin(raw[R["RESTORED_REPORT"]])
    raw["transaction.jsonl"] = jsonl(rows.values())
    outer = dict(zip(("trust-retired", "vm-exited", "absence-first", "absence-second"), range(20, 24), strict=True))
    times = {"inputs-verified": start} | {name: start + offset for name, offset in outer.items()}
    times.update({event: rows[phase]["at_ns"] for phase, event in R["JOURNAL_EVENTS"].items()})
    receipt = dict(
        kind=R["KIND"], nonce=NONCE, original_inputs=pins,
        evidence={name: C.pin(body) for name, body in raw.items()},
        phases={phase: dict(lock=C.pin(raw[f"{phase}.lock"]), platform=C.pin(platform)) for phase in PHASES},
        chronology=[dict(event=event, at_ns=times[event]) for event in EVENTS],
        trust=dict(policy="Required TrustedOnly", test_fingerprint=TEST,
                   test_certificate=C.pin(raw["test-certificate.gpg"]),
                   test_not_before=NOW - 60, test_not_after=NOW + 600),
        retirement=dict(nonce=NONCE, target_submounts=[], keyrings=dict.fromkeys(R["TRUST_HOMES"], "removed"),
                        qemu=dict(exit=0, reaped=True, output_complete=True, timeout=False, signals=[]),
                        outer_container=dict(id="c" * 64, exit=0, removed=True),
                        observations=[dict(event=event, qemu=[], outer_containers=[]) for event in EVENTS[-2:]]),
    )
    return receipt, inputs, raw


class ReadbackTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.bundle = Path(temp.name)
        self.receipt, self.inputs, self.raw = fixture()
        pins = self.receipt["original_inputs"]
        for target in (R["ORIGINALS"], P["PINS"]):
            update = patch.dict(target, {name: pins[name] for name in target})
            update.start()
            self.addCleanup(update.stop)
        (self.bundle / "inputs").mkdir()
        for role, body in self.inputs.items():
            (self.bundle / "inputs" / role).write_bytes(body)
        for name, body in self.raw.items():
            (self.bundle / name).write_bytes(body)

    def readback(self, *, digest=None):
        body = C.wire(self.receipt)
        (self.bundle / "receipt.json").write_bytes(body)
        return R["readback"](self.bundle, digest or C.pin(body)["sha256"])

    def test_mixed_version_independent_checks_reject_legacy_and_rewritten_actions(self):
        parity = P["PARITY_PROJECT_VERSION"]
        receipt, inputs, raw = fixture(project_version=parity)
        times = R["chronology"](receipt["chronology"])
        inventory = (receipt["phases"], raw, inputs["rollback_lock"])
        transaction = (receipt["trust"], raw, times, NONCE)
        project_archive = C.pin(inputs["project_archive"])
        self.assertEqual(R["inventories"](*inventory, project_version=parity),
                         R["inventories"](self.receipt["phases"], self.raw, self.inputs["rollback_lock"]))
        R["transactions"](*transaction, project_version=parity, project_archive=project_archive)
        for wrong in (None, C.pin(b""), R["ORIGINALS"]["project_archive"], R["ORIGINALS"]["official_archive"]):
            with self.subTest(wrong=wrong), self.assertRaisesRegex(ValueError, "distinct independently selected"):
                R["transactions"](*transaction, project_version=parity, project_archive=wrong)
        with self.assertRaisesRegex(ValueError, "verified replacement operand"):
            R["transactions"](*transaction, project_version=parity, project_archive=C.pin(b"wrong archive"))
        with self.assertRaisesRegex(ValueError, "replacement package lock"):
            R["inventories"](*inventory)
        with self.assertRaisesRegex(ValueError, "replacement ALPM prepare"):
            R["transactions"](*transaction)
        raw["pacman.log"] = raw["pacman.log"].replace(parity.encode(), VERSION.encode())
        with self.assertRaisesRegex(ValueError, "ALPM log differs"):
            R["transactions"](*transaction, project_version=parity, project_archive=project_archive)

    def test_public_parity_readback_requires_same_profile_archive_and_test_operands(self):
        parity = P["PARITY_PROJECT_VERSION"]
        receipt, inputs, raw = fixture(project_version=parity, restored_runtime=True)
        del inputs["recovery_seal"]
        inputs["parity_recipe"] = b"inert parity recipe\n"
        recipe = C.pin(inputs["parity_recipe"])
        archive = C.pin(inputs["project_archive"])
        profile_globals = P["checked_profile"].__globals__
        self.enterContext(patch.dict(profile_globals, PARITY_RECIPE=recipe))
        source_fields = dict(profile="parity", payload={"recipe/PARITY.UNISSUED.json": recipe},
                             launcher=C.pin(b"launcher"), actor=C.pin(b"actor"))
        source = hashlib.sha256(json.dumps(source_fields, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
        inputs["build_plan"] = C.wire(dict(kind="QTBASE_SUCCESSOR16K_PLAN_V1", mode="full", nonce=PRIOR,
            inputs={"recipe": recipe}, source_sha256=source, **source_fields))
        artifact = f"{PROJECT}-{parity}-aarch64.pkg.tar.xz"
        exports = {name: {"new_exports": []} for name in P["PARITY_LIBRARIES"]}
        exports[P["PARITY_QTGUI"]]["new_exports"] = [P["PARITY_ATSPI_EXPORT"]]
        delta = dict(added_files=sorted(P["PARITY_ADDED_FILES"]), added_directories=[P["PARITY_PRINT_DIRECTORY"]],
                     removed=[], metadata_changed=[], baseline_nodes=100, candidate_nodes=132, qt_dynamic_exports=exports)
        bridge = dict(qtgui_export=P["PARITY_ATSPI_EXPORT"], consumers=list(P["PARITY_ATSPI_CONSUMERS"]))
        guest = dict(evidence={artifact: archive}, archive=dict(
            path_delta=delta, atspi_bridge_abi=bridge, libraries={name: C.pin(name.encode()) for name in exports},
            mtree=dict(entries=134, inventory=C.pin(b"inert MTREE inventory")),
            controls={".MTREE": C.pin(b"inert MTREE control")}),
                     worker=dict(architecture="aarch64", page_size=16384, nonce=PRIOR, phase="complete",
                                 status="PASS", mode="full"))
        inputs["build_receipt"] = C.wire(dict(kind="QTBASE_SUCCESSOR16K_INDEPENDENT_READBACK_V1",
            status="PASS_UNSIGNED_EMULATED_AARCH64_16K_PACKAGE", mode="full", nonce=PRIOR,
            plan=C.pin(inputs["build_plan"]), originals_unchanged=True, container_retired=[True, True],
            container_exit=0, qemu_exit=0, guest=guest, profile="parity", source_sha256=source))
        metadata = {"project": {"PROVIDES": [OFFICIAL], "CONFLICTS": [OFFICIAL]},
                    "official": {"PROVIDES": [], "CONFLICTS": []}}
        solves = {name: {"tests": {"whole": [0, [], []]}} for name in metadata}
        objects = {str(i): dict(strong_qt_symbols=1, missing_project=[], missing_project_versions=[],
                               missing_project_unversioned=[]) for i in range(145)}
        objects["0"]["strong_qt_symbols"] = 18661 - 144
        inputs["abi_comparison"] = C.wire(dict(
            inputs=dict(project=archive, official=C.pin(inputs["official_archive"]),
                        rollback629=C.pin(inputs["rollback_lock"])),
            locks={"exact629": 629}, metadata=metadata | {"solves": {"629": solves}},
            abi={"consumers": {"inert": {"objects": objects}}}))
        inputs["alpm_prepare"] = (
            f"629 official to project, accept\nconflict: add {PROJECT}, remove {OFFICIAL}, initial answer 0\n"
            f"prepare: 0 ok\n{PROJECT} {parity}\n{OFFICIAL} {VERSION}\n"
            f"629 project to official, accept\nconflict: add {OFFICIAL}, remove {PROJECT}, initial answer 0\n"
            f"prepare: 0 ok\n{OFFICIAL} {VERSION}\n{PROJECT} {parity}\n").encode()
        profile = dict(kind=P["PARITY_KIND"], official_version=VERSION, project_version=parity, recipe=recipe,
                       **{name: C.pin(inputs[name]) for name in P["PARITY_INPUT_CAPS"]})
        profile["test_review"] = dict(fingerprint=TEST, certificate=C.pin(raw["test-certificate.gpg"]),
                                      signature=C.pin(raw["test-signature.sig"]),
                                      not_before=NOW - 60, not_after=NOW + 600)
        profile_pin = C.pin(C.wire(profile))
        rows = [C.json_body(line) for line in raw["transaction.jsonl"].splitlines()]
        rows[0]["parity_profile"] = profile_pin
        raw["transaction.jsonl"] = jsonl(rows)
        originals = {name: C.pin(body) for name, body in inputs.items()}
        W_fixture = W["F"]
        media = {
            P["OFFICIAL_NAME"]: originals["official_archive"],
            P["OFFICIAL_NAME"] + ".sig": originals["official_signature"],
            artifact: archive,
            artifact + ".sig": profile["test_review"]["signature"],
            "test-certificate.gpg": profile["test_review"]["certificate"],
            "alarm-public-key.gpg": originals["alarm_public_key"],
            "rollback.lock": originals["rollback_lock"],
            "result.json": originals["rollback_result"],
            W_fixture["ARCHIVE"]: W_fixture["PINS"]["archive"],
            W_fixture["ARCHIVE"] + ".sig": W_fixture["PINS"]["signature"],
        }
        base_media = {"files": {}}
        plan = dict(kind="ASAHI629_EXACT_GUEST_PLAN_V1", nonce=NONCE, code={}, media=base_media,
                    manifest=C.pin(C.wire(base_media)), qt_media={"qt-replacement/" + name: pin for name, pin in media.items()},
                    qt_replacement=dict(parity_profile=profile, project_review=profile["test_review"], wayland_socket=W["SOCKET"]))
        plan_pin = C.pin(C.wire(plan))
        times = R["chronology"](receipt["chronology"])
        terminal = {name: value for name, value in rows[-1].items() if name not in ("phase", "at_ns")}
        retirement = receipt["retirement"]
        cleanup = dict(completed=True, target_submounts=retirement["target_submounts"], keyrings=retirement["keyrings"])
        owner = dict(status=P["PASS629"], nonce=NONCE, plan=plan_pin,
                     inventory={"rollback": originals["rollback_lock"]},
                     platform={"rollback": receipt["phases"]["baseline"]["platform"]},
                     trust_retired_at_ns=times["trust-retired"], cleanup=C.pin(C.wire(cleanup)),
                     qt_checkpoint=dict(nonce=NONCE, transaction=terminal, runtime_probe=C.pin(raw["runtime-probes.json"])))
        disk = C.file_pin(R["RESULT_BYTES"], "d" * 64)
        stopped = dict(kind=R["STOPPED_KIND"], nonce=NONCE, disk=disk, held=False, retirement=receipt["retirement"],
                       host_times={name: times[name] for name in R["HOST_TIMES"]})
        provenance = {"guest_plan": plan, "stopped_observation": stopped, "asahi_owner": owner}
        for role, value in provenance.items():
            body = C.wire(value)
            (self.bundle / R["PARITY_EVIDENCE"][role][0]).write_bytes(body)
            receipt[role] = C.pin(body)
        receipt.update(kind=R["PARITY_KIND"], parity_profile=profile_pin,
                       stopped_disk=disk, original_inputs=originals,
                       evidence={name: C.pin(body) for name, body in raw.items()})
        (self.bundle / "inputs/recovery_seal").unlink()
        for name, body in inputs.items():
            (self.bundle / "inputs" / name).write_bytes(body)
        for name, body in raw.items():
            (self.bundle / name).write_bytes(body)
        self.receipt = receipt
        self.enterContext(patch.dict(P, archive_metadata=lambda role, *_a, **_k: (metadata[role.removesuffix("_archive")], None)))

        def check(selected=profile):
            body = C.wire(self.receipt)
            (self.bundle / "receipt.json").write_bytes(body)
            return R["readback"](self.bundle, C.pin(body)["sha256"], profile=selected)

        checked = check()
        self.assertEqual(checked["status"], "CONSISTENT_EXPORTED_QT612_ASAHI629_PARITY_SCOPED_RECEIPT")
        self.assertEqual(checked["guest_plan"], plan_pin)
        self.assertEqual(checked["stopped_disk"], disk)

        restored_name = R["RESTORED_REPORT"]
        removed_pin = receipt["evidence"].pop(restored_name)
        with self.assertRaisesRegex(ValueError, "Unexpected evidence fields"):
            check()
        receipt["evidence"][restored_name] = removed_pin
        self.change_evidence(restored_name, raw["vendor-runtime-probes.json"])
        with self.assertRaisesRegex(ValueError, "Complete successful guest transaction"):
            check()
        self.change_evidence(restored_name, raw[restored_name])

        # Even a correctly repinned PASS must contain fresh restoration-phase client evidence.
        restored = C.json_body(raw[restored_name])
        for change, message in (
            ({"phase": "vendor"}, "Expected the restored runtime phase"),
            ({"status": "PARTIAL"}, "Complete ordinary-user runtime probe PASS"),
            ({"checks": C.json_body(raw["runtime-probes.json"])["checks"]}, "Weston presentation client identity"),
        ):
            body = C.wire(restored | change)
            terminal_pin = {"restored_runtime_probe": C.pin(body)}
            self.change_evidence(restored_name, body)
            self.change_evidence("transaction.jsonl", jsonl([*rows[:-1], rows[-1] | terminal_pin]))
            altered_owner = owner | {"qt_checkpoint": owner["qt_checkpoint"] | {"transaction": terminal | terminal_pin}}
            owner_path = self.bundle / R["PARITY_EVIDENCE"]["asahi_owner"][0]
            owner_path.write_bytes(C.wire(altered_owner))
            receipt["asahi_owner"] = C.pin(C.wire(altered_owner))
            with self.subTest(restored=change.keys()), self.assertRaisesRegex(ValueError, message):
                check()
        self.change_evidence(restored_name, raw[restored_name])
        self.change_evidence("transaction.jsonl", raw["transaction.jsonl"])
        owner_path.write_bytes(C.wire(owner))
        receipt["asahi_owner"] = C.pin(C.wire(owner))

        without_probe = [row for row in rows if row["phase"] != "restoration-probe"]
        self.change_evidence("transaction.jsonl", jsonl(without_probe))
        with self.assertRaisesRegex(ValueError, "Complete Qt transaction journal"):
            check()
        misordered = [*rows[:-3], rows[-2], rows[-3], rows[-1]]
        self.change_evidence("transaction.jsonl", jsonl(misordered))
        with self.assertRaisesRegex(ValueError, "Misordered Qt transaction journal"):
            check()
        self.change_evidence("transaction.jsonl", raw["transaction.jsonl"])
        lifecycle = C.json_body(raw[W["REPORT_NAME"]])
        del lifecycle["presentations"]["restoration-qrhi"]
        self.change_evidence(W["REPORT_NAME"], C.wire(lifecycle))
        with self.assertRaisesRegex(ValueError, "Unexpected Weston presentation roles fields"):
            check()
        self.change_evidence(W["REPORT_NAME"], raw[W["REPORT_NAME"]])
        self.assertEqual(check(), checked)

        with self.assertRaisesRegex(ValueError, "Unexpected receipt fields"):
            check(None)
        with self.assertRaisesRegex(ValueError, "Prior Qt evidence"):
            check(profile | {"project_archive": R["ORIGINALS"]["project_archive"]})
        with self.assertRaisesRegex(ValueError, "parity pin required for project_archive"):
            check(profile | {"project_archive": C.pin(b"")})
        self.receipt["stopped_disk"] = C.file_pin(R["RESULT_BYTES"], "f" * 64)
        with self.assertRaisesRegex(ValueError, "Stopped disk, chronology or retirement differs"):
            check()
        self.receipt["stopped_disk"] = disk
        plan_path = self.bundle / R["PARITY_EVIDENCE"]["guest_plan"][0]
        forged = C.wire(plan | {"code": {"asahi-guest.py": C.pin(b"different guest worker")}})
        plan_path.write_bytes(forged)
        self.receipt["guest_plan"] = C.pin(forged)
        with self.assertRaisesRegex(ValueError, "Stopped Asahi owner result does not bind"):
            check()
        self.receipt["guest_plan"] = None
        with self.assertRaisesRegex(ValueError, "Exact bundled parity pin required for guest_plan"):
            check()
        plan_path.write_bytes(C.wire(plan))
        self.receipt["guest_plan"] = plan_pin
        owner_path = self.bundle / R["PARITY_EVIDENCE"]["asahi_owner"][0]
        for wrong in (None, C.pin(C.wire(cleanup | {"keyrings": cleanup["keyrings"] | {"pacman": "left-open"}}))):
            body = C.wire(owner | {"cleanup": wrong})
            owner_path.write_bytes(body)
            self.receipt["asahi_owner"] = C.pin(body)
            with self.subTest(cleanup=wrong), self.assertRaisesRegex(ValueError, "cleanup digest differs"):
                check()
        owner_path.write_bytes(C.wire(owner))
        self.receipt["asahi_owner"] = C.pin(C.wire(owner))
        self.change_evidence("test-signature.sig", b"foreign detached signature")
        with self.assertRaisesRegex(ValueError, "Qt TEST review differs"):
            check()

        build_plan = C.json_body(inputs["build_plan"])
        build_receipt = C.json_body(inputs["build_receipt"])

        def verify(report, sealed=build_plan):
            plan_body = C.wire(sealed)
            body = C.wire(report | {"plan": C.pin(plan_body)})
            pins = profile | {"build_receipt": C.pin(body), "build_plan": C.pin(plan_body)}
            P["verify_parity_build"](pins, plan_body, body, inputs["parity_recipe"])

        for field, wrong, error in (
            ("added_files", sorted((P["PARITY_ADDED_FILES"] - {min(P["PARITY_ADDED_FILES"])}) | {"wrong path"}),
             "path delta differs"),
            ("qt_dynamic_exports", {str(i): {} for i in range(18)}, "library identities differ"),
            ("added_directories", ["wrong directory"], "path delta differs"),
        ):
            report = copy.deepcopy(build_receipt)
            report["guest"]["archive"]["path_delta"][field] = wrong
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, error):
                verify(report)
        for wrong in (bridge | {"qtgui_export": "wrong@Qt_6_PRIVATE_API"},
                      bridge | {"consumers": ["libQt6WaylandClient.so.6.12.0", "wrong.so"]}):
            report = copy.deepcopy(build_receipt)
            report["guest"]["archive"]["atspi_bridge_abi"] = wrong
            with self.subTest(bridge=wrong), self.assertRaisesRegex(ValueError, "AT-SPI symbol or consumer"):
                verify(report)
        verify(build_receipt)
        for fields in ({"profile"}, {"source_sha256"}, {"profile", "source_sha256"}):
            plan_without = {key: value for key, value in build_plan.items() if key not in fields}
            receipt_without = {key: value for key, value in build_receipt.items() if key not in fields}
            for plan, report in ((plan_without, build_receipt), (build_plan, receipt_without),
                                 (plan_without, receipt_without)):
                with self.subTest(missing=fields), self.assertRaisesRegex(ValueError, "Explicit parity build binder"):
                    verify(report, plan)
        with self.assertRaisesRegex(ValueError, "binder source or profile differs"):
            verify(build_receipt | {"source_sha256": "0" * 64})
        for mtree in (None, {"entries": 133, "inventory": C.pin(b"wrong census")},
                      {"entries": 134, "inventory": C.pin(b"")}):
            report = copy.deepcopy(build_receipt)
            report["guest"]["archive"]["mtree"] = mtree
            with self.subTest(mtree=mtree), self.assertRaisesRegex(ValueError, "Parity MTREE inventory"):
                verify(report)

    def change_evidence(self, name, body):
        (self.bundle / name).write_bytes(body)
        self.receipt["evidence"][name] = C.pin(body)

    def journal_rows(self):
        return [C.json_body(line) for line in self.raw["transaction.jsonl"].splitlines()]

    def test_exact_reversal_and_pinned_predecessor(self):
        output = self.readback()
        self.assertEqual(output["status"], "CONSISTENT_EXPORTED_QT612_ASAHI629_RECEIPT")
        self.assertEqual(output["predecessor_nonce"], PRIOR)
        self.assertEqual(output["untouched_rows"], 628)
        self.assertEqual(output["restored_lock"], C.pin(self.inputs["rollback_lock"]))
        unchanged = self.inputs["rollback_lock"].split(b"\n", 1)[1]
        self.assertEqual(output["untouched_lock"], C.pin(unchanged))

    def test_requires_the_separately_selected_receipt_digest(self):
        with self.assertRaisesRegex(ValueError, "External digest differs"):
            self.readback(digest="0" * 64)

    def test_rejects_rewrapped_guest_journal_under_new_nonce(self):
        self.receipt["nonce"] = self.receipt["retirement"]["nonce"] = "e" * 32
        with self.assertRaisesRegex(ValueError, "Guest journal nonce differs"):
            self.readback()

    def test_rejects_substituted_test_certificate_with_rebound_outer_pins(self):
        body = b"unrelated public certificate"
        self.change_evidence("test-certificate.gpg", body)
        self.receipt["trust"]["test_certificate"] = C.pin(body)
        with self.assertRaisesRegex(ValueError, "Verified guest TEST certificate differs"):
            self.readback()

    def test_rejects_verified_certificate_fingerprint_different_from_signer(self):
        rows = self.journal_rows()
        rows[2]["test_certificate"]["fingerprint"] = "E" * 40
        self.change_evidence("transaction.jsonl", jsonl(rows))
        with self.assertRaisesRegex(ValueError, "Verified guest TEST certificate differs"):
            self.readback()

    def test_rejects_rebound_skipped_or_failed_runtime_check_despite_pass_journal(self):
        for status in ("SKIP", "FAIL"):
            with self.subTest(status=status):
                report = C.json_body(self.raw["runtime-probes.json"])
                report["checks"]["wayland"]["status"] = status
                self.change_evidence("runtime-probes.json", C.wire(report))
                with self.assertRaisesRegex(ValueError, "Complete runtime probe PASS required: wayland"):
                    self.readback()

    def test_requires_runtime_report_pin_in_receipt_evidence(self):
        del self.receipt["evidence"]["runtime-probes.json"]
        with self.assertRaisesRegex(ValueError, "Unexpected evidence fields"):
            self.readback()

    def test_rejects_runtime_marker_without_device_or_ordinary_user(self):
        report = C.json_body(self.raw["runtime-probes.json"])
        loader = report["checks"]["vulkan_loader"]["steps"][0]
        output = loader["output"]
        loader["output"] = "QT629_VULKAN_OK devices=0\n"
        self.change_evidence("runtime-probes.json", C.wire(report))
        with self.assertRaisesRegex(ValueError, "Runtime probe success marker differs: vulkan_loader"):
            self.readback()
        loader["output"] = output
        loader["argv"][3] = "--reuid=0"
        self.change_evidence("runtime-probes.json", C.wire(report))
        with self.assertRaisesRegex(ValueError, "Expected successful ordinary-user runtime command"):
            self.readback()

    def test_rejects_rebound_nonbuild_commands(self):
        for index, executable, role in ((0, "/usr/bin/pkg-config", "pkg-config"), (1, "/usr/bin/g++", "compiler")):
            with self.subTest(executable=executable):
                report = C.json_body(self.raw["runtime-probes.json"])
                step = report["checks"]["core_gui_offscreen"]["steps"][index]
                start = step["argv"].index(executable)
                step["argv"][start:] = ["/usr/bin/true"]
                self.change_evidence("runtime-probes.json", C.wire(report))
                with self.assertRaisesRegex(ValueError, f"Runtime probe {role} command differs: core_gui_offscreen"):
                    self.readback()

    def test_rejects_compiler_flags_or_output_different_from_build_and_launch(self):
        for change in ("flags", "output"):
            with self.subTest(change=change):
                report = C.json_body(self.raw["runtime-probes.json"])
                query, compile, _ = report["checks"]["quick_offscreen"]["steps"]
                if change == "flags":
                    query["output"] += "-DNOT_BUILT_WITH_THIS=1\n"
                else:
                    compile["argv"][compile["argv"].index("-o") + 1] += "-different"
                self.change_evidence("runtime-probes.json", C.wire(report))
                with self.assertRaisesRegex(ValueError, "Runtime probe compiler command differs: quick_offscreen"):
                    self.readback()

    def test_rejects_runtime_command_from_a_different_fixture(self):
        report = C.json_body(self.raw["runtime-probes.json"])
        step = report["checks"]["wayland"]["steps"][0]
        step["argv"] = [arg.replace("/tmp/qt629-probe-fixture", "/tmp/qt629-probe-unrelated") for arg in step["argv"]]
        self.change_evidence("runtime-probes.json", C.wire(report))
        with self.assertRaisesRegex(ValueError, "Runtime probe fixture path differs: wayland"):
            self.readback()

    def test_rejects_repinned_unreviewed_probe_environment(self):
        for check, step, setting, role in (
            ("vulkan_qrhi", 0, "LD_PRELOAD=/tmp/foreign.so", "launch"),
            ("vulkan_qrhi", 0, "QT_PLUGIN_PATH=/tmp/foreign-plugins", "launch"),
            ("core_gui_offscreen", 0, "PKG_CONFIG_PATH=/tmp/foreign", "build"),
            ("quick_offscreen", 1, "CPATH=/tmp/foreign", "build"),
        ):
            with self.subTest(setting=setting):
                report = C.json_body(self.raw["runtime-probes.json"])
                report["checks"][check]["steps"][step]["argv"].insert(len(R["PROBE_PREFIX"]), setting)
                self.change_evidence("runtime-probes.json", C.wire(report))
                with self.assertRaisesRegex(ValueError, f"Runtime probe {role} environment differs: {check}"):
                    self.readback()

    def test_rejects_rebound_lifecycle_for_unrelated_nonce_socket_or_start_ticks(self):
        for changed in ("nonce", "socket", "start_ticks"):
            with self.subTest(changed=changed):
                report = C.json_body(self.raw[W["REPORT_NAME"]])
                if changed == "start_ticks":
                    report["presentations"]["replacement-raster"][changed] += 1
                    reason = "Weston presentation client identity differs"
                else:
                    report[changed] = "f" * 32 if changed == "nonce" else "/run/foreign/wayland-0"
                    reason = "Exact complete Weston lifecycle"
                self.change_evidence(W["REPORT_NAME"], C.wire(report))
                with self.assertRaisesRegex(ValueError, reason):
                    self.readback()

    def test_rejects_repinned_vendor_runtime_report_from_another_boot(self):
        name = "vendor-runtime-probes.json"
        report = C.json_body(self.raw[name])
        report["nonce"] = "f" * 32
        self.change_evidence(name, C.wire(report))
        with self.assertRaisesRegex(ValueError, "selected nonce and socket required: vendor"):
            self.readback()

    def test_rejects_repinned_trace_without_selected_client_ack_shm_or_callback(self):
        role = "replacement-raster"
        pid = C.json_body(self.raw[W["REPORT_NAME"]])["presentations"][role]["pid"]
        for old, altered in (
            (b"ack_configure(7)", b"ack_configure(8)"),
            (b"attach(wl_buffer@50", b"attach(wl_buffer@99"),
            (b"wl_callback@60.done", b"wl_callback@99.done"),
            (f"(PID {pid})".encode(), b"(PID 999)"),
        ):
            with self.subTest(old=old):
                report = C.json_body(self.raw[W["REPORT_NAME"]])
                entry = report["presentations"][role]
                trace = self.raw[W["LOG_NAME"]]
                start, end = entry["start"], entry["end"]
                segment = trace[start:end]
                self.assertIn(old, segment)
                edited = segment.replace(old, altered)
                self.assertEqual(len(edited), len(segment))
                trace = trace[:start] + edited + trace[end:]
                report["log"] = C.pin(trace)
                entry["trace"] = C.pin(edited)
                self.change_evidence(W["LOG_NAME"], trace)
                self.change_evidence(W["REPORT_NAME"], C.wire(report))
                with self.assertRaisesRegex(ValueError, "PID-bound Weston connection"):
                    self.readback()

    def test_rejects_same_length_archive_substitution(self):
        path = self.bundle / "inputs" / "official_archive"
        path.write_bytes(b"X" * len(self.inputs["official_archive"]))
        with self.assertRaisesRegex(ValueError, "Exact original file pin"):
            self.readback()

    def test_rejects_symlink_even_when_bytes_match(self):
        path = self.bundle / "inputs" / "project_archive"
        moved = self.bundle / "unrelated"
        path.rename(moved)
        path.symlink_to(moved)
        with self.assertRaisesRegex(ValueError, "Canonical read-only path"):
            self.readback()

    def test_rejects_reordered_or_repeated_events(self):
        rows = self.receipt["chronology"]
        rows[3]["event"], rows[5]["event"] = rows[5]["event"], rows[3]["event"]
        with self.assertRaisesRegex(ValueError, "Misordered chronology"):
            self.readback()
        rows[3]["event"], rows[5]["event"] = rows[5]["event"], rows[3]["event"]
        rows[5]["at_ns"] = rows[4]["at_ns"]
        with self.assertRaisesRegex(ValueError, "Misordered chronology"):
            self.readback()

    def test_rejects_extra_package_change_even_with_rebound_pins(self):
        altered = self.raw["replacement.lock"].replace(b"unchanged-0429 1:2.3-4", b"unchanged-0429 1:2.3-5")
        self.change_evidence("replacement.lock", altered)
        self.receipt["phases"]["replacement"]["lock"] = C.pin(altered)
        with self.assertRaisesRegex(ValueError, "replacement package lock differs"):
            self.readback()

    def test_rejects_wrong_restored_provider(self):
        body = self.raw["replacement.lock"]
        self.change_evidence("restoration.lock", body)
        self.receipt["phases"]["restoration"]["lock"] = C.pin(body)
        with self.assertRaisesRegex(ValueError, "restoration package lock differs"):
            self.readback()

    def test_rejects_protected_drift_even_with_rebound_pins(self):
        body = self.raw["restoration-platform.json"]
        state = C.json_body(body, canonical=True)
        state["etc/fstab"]["pin"] = C.pin(b"changed")
        body = C.wire(state)
        self.change_evidence("restoration-platform.json", body)
        self.receipt["phases"]["restoration"]["platform"] = C.pin(body)
        with self.assertRaisesRegex(ValueError, "Protected boot and mount identity differs at restoration"):
            self.readback()

    def test_rejects_rebound_restoration_operand(self):
        rows = self.journal_rows()
        rows[2]["signers"][OFFICIAL]["signature"] = C.pin(b"other")
        self.change_evidence("transaction.jsonl", jsonl(rows))
        with self.assertRaisesRegex(ValueError, "Exact verified restoration operand"):
            self.readback()

    def test_rejects_journal_commit_reordered(self):
        rows = self.journal_rows()
        rows[4], rows[5] = rows[5], rows[4]
        self.change_evidence("transaction.jsonl", jsonl(rows))
        with self.assertRaisesRegex(ValueError, "Misordered Qt transaction journal"):
            self.readback()

    def test_rejects_guest_timeline_disagreement(self):
        self.receipt["chronology"][3]["at_ns"] -= 1
        with self.assertRaisesRegex(ValueError, "Guest transaction timestamps differ"):
            self.readback()

    def test_rejects_changed_install_reason(self):
        rows = self.journal_rows()
        rows[-2]["install_reason"] = 0
        self.change_evidence("transaction.jsonl", jsonl(rows))
        with self.assertRaisesRegex(ValueError, "restoration inventory or install reason differs"):
            self.readback()

    def test_rejects_wrong_conflict_decision(self):
        rows = self.journal_rows()
        rows[3]["questions"][0]["accepted"] = False
        self.change_evidence("transaction.jsonl", jsonl(rows))
        with self.assertRaisesRegex(ValueError, "Exact replacement ALPM prepare"):
            self.readback()

    def test_rejects_extra_alpm_action_even_if_final_inventory_matches(self):
        extra = b"[2026-11-27T13:30:00+0000] [ALPM] reinstalled unchanged-0000 (1:2.3-4)\n"
        self.change_evidence("pacman.log", self.raw["pacman.log"] + extra)
        with self.assertRaisesRegex(ValueError, "ALPM log differs"):
            self.readback()

    def test_rejects_refused_verification_despite_validsig_row(self):
        body = self.raw["replacement-signature.status"] + b"[GNUPG:] EXPKEYSIG fixture\n"
        self.change_evidence("replacement-signature.status", body)
        rows = self.journal_rows()
        rows[2]["signers"][PROJECT]["status"] = C.pin(body)
        self.change_evidence("transaction.jsonl", jsonl(rows))
        with self.assertRaisesRegex(ValueError, "Missing successful detached signature"):
            self.readback()

    def test_rejects_expired_test_trust(self):
        self.receipt["trust"]["test_not_after"] = NOW
        with self.assertRaisesRegex(ValueError, "Separate current TEST trust"):
            self.readback()

    def test_rejects_unretired_trust_or_guest(self):
        row = self.receipt["retirement"]
        row["keyrings"]["project-test"] = "present"
        with self.assertRaisesRegex(ValueError, "Guest trust homes and target submounts must retire"):
            self.readback()
        row["keyrings"]["project-test"] = "removed"
        row["qemu"]["timeout"] = True
        with self.assertRaisesRegex(ValueError, "Natural owned QEMU retirement"):
            self.readback()
        row["qemu"]["timeout"] = False
        row["outer_container"]["removed"] = False
        with self.assertRaisesRegex(ValueError, "Owned outer container retirement"):
            self.readback()
        row["outer_container"]["removed"] = True
        row["observations"][1]["qemu"] = [2718]
        with self.assertRaisesRegex(ValueError, "observed absent twice"):
            self.readback()


if __name__ == "__main__":
    unittest.main()
