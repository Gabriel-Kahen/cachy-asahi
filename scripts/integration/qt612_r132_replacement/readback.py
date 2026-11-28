#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate exported evidence of an offline Asahi629 Qt replacement and restoration.

The absolute bundle directory holds receipt.json, original bodies in inputs/<role>, and the files
listed by EVIDENCE below. Pins are {"bytes": int, "sha256": lowercase hex}.
The canonical receipt binds the original_inputs and evidence maps, a fresh
nonce, chronology (ordered UTC nanosecond observations), phases (inventory
and boot/mount observations), trust policy and retirement. The guest's
transaction.jsonl and pacman.log supply the transaction observations. The
guest journal entry repeats the guest's selected boot nonce. Its trust row
records the exact certificate pin, verified primary fingerprint and validity
window under test_certificate. A complete receipt also binds both runtime
reports to PID-scoped presentations in the stopped Weston server trace. The
two absence observations follow clean VM exit. See test_readback.py for a
complete synthetic bundle.

The separately selected receipt digest binds the export. The reader checks
exported observations without executing a guest, ALPM or GPG.
"""

import argparse
from pathlib import Path
import re
from runpy import run_path
import shlex
import sys


P = run_path(str(Path(__file__).with_name("prepare.py")))
W = run_path(str(Path(__file__).with_name("weston_run.py")))
C, A, need = P["C"], P["A"], P["need"]
OFFICIAL, PROJECT, VERSION = (P[name] for name in ("OFFICIAL", "PROJECT", "VERSION"))
KIND = "QT612_ASAHI629_REPLACEMENT_RECEIPT_V1"
PARITY_KIND = "QT612_ASAHI629_PARITY_SCOPED_RECEIPT_V1"
STOPPED_KIND = "QT629_STOPPED_RESULT_OBSERVATION_V1"
HOST_TIMES = ("inputs-verified", "vm-exited", "absence-first", "absence-second")
RESULT_BYTES = 64 << 20
PARITY_EVIDENCE = {
    "guest_plan": ("guest-plan.json", 512 << 10),
    "stopped_observation": ("stopped-observation.json", 128 << 10),
    "asahi_owner": ("asahi-owner-result.json", 128 << 10),
}
PHASES = ("baseline", "replacement", "restoration")
EVENTS = (
    "inputs-verified", "baseline", "trust-verified", "replacement-applied", "replacement",
    "restoration-applied", "restoration", "trust-retired", "vm-exited", "absence-first", "absence-second",
)
ORIGINALS = P["PINS"] | {
    "r132_kernel": A["KERNEL"],
    "r132_config": A["CONFIG"],
    "r132_transport": C.file_pin(197340, "08a1f949794b085158608c9577476574514fa963a8168554ca523c2242f35178"),
}


def originals(profile):
    if profile is None:
        return ORIGINALS
    return {role: ORIGINALS[role] for role in ("r132_kernel", "r132_config", "r132_transport")} | P["profile_pins"](profile)


EVIDENCE = {
    **{f"{phase}.lock": 64 << 10 for phase in PHASES},
    **{f"{phase}-platform.json": 2 << 20 for phase in PHASES},
    "transaction.jsonl": 128 << 10,
    "pacman.log": 2 << 20,
    "test-certificate.gpg": 128 << 10,
    "test-signature.sig": 64 << 10,
    "replacement-signature.status": 16 << 10,
    "restoration-signature.status": 16 << 10,
    "runtime-probes.json": 2 << 20,
    "vendor-runtime-probes.json": 2 << 20,
    W["LOG_NAME"]: W["LOG_CAP"],
    W["REPORT_NAME"]: 128 << 10,
}
RESTORED_REPORT = "restored-runtime-probes.json"


def evidence_files(profile):
    return EVIDENCE if profile is None else EVIDENCE | {RESTORED_REPORT: 2 << 20}


JOURNAL_KIND = "QT629_PROVIDER_TRANSACTION_V1"
JOURNAL_PHASES = (
    "entry", "baseline", "trust", "replacement-prepare", "replacement-commit-start", "replacement-commit-done",
    "replacement", "probe", "restoration-prepare", "restoration-commit-start", "restoration-commit-done",
    "restoration", "terminal",
)
PARITY_JOURNAL_PHASES = (*JOURNAL_PHASES[:-1], "restoration-probe", JOURNAL_PHASES[-1])
JOURNAL_EVENTS = {
    "baseline": "baseline",
    "trust": "trust-verified",
    "replacement-commit-done": "replacement-applied",
    "replacement": "replacement",
    "restoration-commit-done": "restoration-applied",
    "restoration": "restoration",
}
TRUST_HOMES = ("vendor", "project-test", "pacman")
ALPM_ACTION = re.compile(
    rb"\[ALPM\] ((?:re)?installed|removed|upgraded|downgraded) ([A-Za-z0-9_.+@-]+) \(([^()]+)\)$"
)
FINGERPRINT = re.compile(r"[0-9A-F]{40}")
NONCE = re.compile(r"[0-9a-f]{32}")
PROBE_KIND = "QT629_INSTALLED_RUNTIME_PROBES_V1"
LAVAPIPE = "/usr/share/vulkan/icd.d/lvp_icd.json"
PROBE_PREFIX = [
    "/usr/bin/chroot", "/trial-scratch", "/usr/bin/setpriv", "--reuid=65534", "--regid=65534",
    "--clear-groups", "--no-new-privs", "--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all",
    "/usr/bin/env", "-i",
]
PROBE_CHECKS = {
    "core_gui_offscreen": ("OFFSCREEN_PAINTER_AND_BACKING_STORE", 3, r"QT629_GUI_OK 6\.12\.0 offscreen"),
    "quick_offscreen": ("QTQUICK_SOFTWARE_QML_PIXEL_VERIFIED", 3, "QT629_QUICK_OK software pixels=verified"),
    "wayland": ("WAYLAND_RASTER_PRESENTATION_OBSERVED", 1, r"QT629_GUI_OK 6\.12\.0 wayland"),
    "vulkan_loader": ("LAVAPIPE_INSTANCE_AND_DEVICE_ENUMERATION", 1, r"QT629_VULKAN_OK devices=([0-9]{1,10})"),
    "vulkan_qrhi": ("QTQUICK_VULKAN_QRHI_PRESENTATION_OBSERVED", 1, "QT629_QRHI_OK wayland vulkan frame=swapped"),
}
PRESENTED_CHECKS = {"wayland": "raster", "vulkan_qrhi": "qrhi"}
PROBE_BUILDS = {
    "core_gui_offscreen": ("gui", "Qt6Gui"),
    "quick_offscreen": ("quick", "Qt6Quick"),
}


def fields(value, names, role):
    need(type(value) is dict and value.keys() == set(names.split()), f"Unexpected {role} fields")
    return value


def chronology(rows):
    need(type(rows) is list and len(rows) == len(EVENTS), "Complete receipt chronology required")
    times = {}
    previous = 0
    for name, row in zip(EVENTS, rows, strict=True):
        fields(row, "event at_ns", "chronology event")
        stamp = row["at_ns"]
        need(row["event"] == name and type(stamp) is int and previous < stamp < 2**63,
             f"Misordered chronology at {name}")
        times[name] = stamp
        previous = stamp
    return times


def inventories(phases, raw, original, *, project_version=VERSION):
    expected, restored = P["project"](original, project_version=project_version)
    for phase, lock in zip(PHASES, (original, expected, restored), strict=True):
        row = fields(phases[phase], "lock platform", phase)
        observed = raw[f"{phase}.lock"]
        need(observed == lock and row["lock"] == C.pin(observed), f"Exact {phase} package lock differs")
    common = P["A"]["package_inventory"](original, P["COUNT"])
    del common[OFFICIAL.encode("ascii")]
    need(len(common) == P["COUNT"] - 1, "Expected 628 untouched package rows")
    return C.pin(b"".join(name + b" " + version + b"\n" for name, version in common.items()))


def protected(phases, raw, predecessor):
    historic = predecessor["platform"]
    reference = historic["rollback"]
    need(all(historic[phase] == reference for phase in ("baseline", "forward")),
         "Original Asahi629 boot and mount identity differs")
    baseline = raw["baseline-platform.json"]
    state = C.json_body(baseline, canonical=True)
    need(len(state) == 362 and state["boot"]["type"] == "directory"
         and all(state[name]["type"] == "file" for name in (
             "boot/vmlinuz-linux-asahi", "boot/initramfs-linux-asahi.img", "etc/fstab", "etc/crypttab")),
         "Incomplete protected boot and mount snapshot")
    need(C.pin(baseline) == reference, "Original Asahi629 boot and mount snapshot differs")
    for phase in PHASES:
        need(raw[f"{phase}-platform.json"] == baseline and phases[phase]["platform"] == reference,
             f"Protected boot and mount identity differs at {phase}")
    return reference


def signature_status(raw, signer):
    lines = raw.decode("utf-8").splitlines()
    need(all(line.startswith("[GNUPG:] ") and len(line.split()) >= 2 for line in lines),
         "Expected machine-readable signature observations")
    rows = [line.split()[1:] for line in lines]
    tags = {row[0] for row in rows}
    good = [row for row in rows if row[0] == "GOODSIG"]
    valid = [row for row in rows if row[0] == "VALIDSIG"]
    need(not any(A["REFUSAL"].fullmatch(tag.encode()) for tag in tags)
         and not tags.intersection({"FAILURE", "ERROR", "NODATA", "UNEXPECTED"})
         and len(good) == len(valid) == 1 and len(good[0]) >= 2 and len(valid[0]) == 11,
         "Missing successful detached signature observation")
    record = valid[0]
    need(FINGERPRINT.fullmatch(record[1]) and record[-1] == signer and good[0][1] == record[1][-16:]
         and all(re.fullmatch(r"[0-9]{1,12}", record[index]) for index in (3, 4)),
         "Detached signature signer or timestamp differs")
    return int(record[3]), int(record[4])


def journal_rows(raw, *, parity=False):
    phases = PARITY_JOURNAL_PHASES if parity else JOURNAL_PHASES
    lines = raw.splitlines(keepends=True)
    need(len(lines) == len(phases) and all(line.endswith(b"\n") for line in lines),
         "Complete Qt transaction journal required")
    rows = [C.json_body(line) for line in lines]
    need(tuple(row["phase"] for row in rows) == phases, "Misordered Qt transaction journal")
    return rows


def journal(raw, times, nonce, *, profile_pin=None):
    rows = journal_rows(raw, parity=profile_pin is not None)
    phases = [row.pop("phase") for row in rows]
    stamps = [row.pop("at_ns") for row in rows]
    need(all(type(stamp) is int for stamp in stamps)
         and times["inputs-verified"] <= stamps[0] < stamps[-1] < times["trust-retired"]
         and all(before < after for before, after in zip(stamps, stamps[1:])),
         "Misordered Qt transaction journal timestamps")
    observed_times = dict(zip(phases, stamps, strict=True))
    need(all(observed_times[phase] == times[event] for phase, event in JOURNAL_EVENTS.items()),
         "Guest transaction timestamps differ from outer chronology")
    observed = dict(zip(phases, rows, strict=True))
    entry = dict(kind=JOURNAL_KIND, nonce=nonce)
    if profile_pin is not None:
        entry["parity_profile"] = profile_pin
    need(observed["entry"] == entry, "Guest journal nonce differs from receipt or the parity profile differs")
    need(observed["probe"] == dict(status="PASS", error=None),
         "Complete successful guest transaction and probe required")
    if profile_pin is not None:
        need(observed["restoration-probe"] == dict(status="PASS", error=None),
             "Complete successful restored runtime probe required")
    return observed


def transactions(trust, raw, times, nonce, *, project_version=VERSION, project_archive=None, profile_pin=None):
    versions = P["provider_versions"](project_version)
    legacy_archive = ORIGINALS["project_archive"]
    if project_version == VERSION:
        need(project_archive is None or project_archive == legacy_archive, "Expected the original V1 project archive")
        project_archive = legacy_archive
    else:
        need(C.check_pin(project_archive, P["ARCHIVE_CAP"]) and project_archive["bytes"] > 0
             and project_archive not in (legacy_archive, ORIGINALS["official_archive"]),
             "Expected a distinct independently selected parity project archive")
    fields(trust, "policy test_certificate test_fingerprint test_not_before test_not_after", "trust")
    candidate = trust["test_fingerprint"]
    before, after = trust["test_not_before"], trust["test_not_after"]
    vendor = A["FINGERPRINT"]
    verified = times["trust-verified"] // 10**9
    restored = times["restoration-applied"] // 10**9
    need(trust["policy"] == "Required TrustedOnly" and type(candidate) is str
         and FINGERPRINT.fullmatch(candidate) and candidate != vendor
         and trust["test_certificate"] == C.pin(raw["test-certificate.gpg"])
         and trust["test_certificate"] != ORIGINALS["alarm_public_key"]
         and type(before) is type(after) is int and 0 < before <= verified <= restored < after,
         "Separate current TEST trust required")
    rows = journal(raw["transaction.jsonl"], times, nonce, profile_pin=profile_pin)
    terminal = dict(kind=JOURNAL_KIND, status="PASS_QT629_PROVIDER_ROUND_TRIP", last_verified="restoration",
                    failure_phase=None, error=None)
    if profile_pin is not None:
        terminal["restored_runtime_probe"] = C.pin(raw[RESTORED_REPORT])
    need(rows["terminal"] == terminal, "Complete successful guest transaction and probe required")
    reason = rows["baseline"]["install_reason"]
    need(type(reason) is int and reason in (0, 1), "Expected supported original provider install reason")
    for phase in PHASES:
        row = rows[phase]
        need(row == dict(inventory=C.pin(raw[f"{phase}.lock"]), install_reason=reason,
                         platform=C.pin(raw[f"{phase}-platform.json"]))
             and type(row["install_reason"]) is int, f"Journal {phase} inventory or install reason differs")
    reported = fields(rows["trust"], "policy signers test_certificate", "journal trust")
    need(reported["policy"] == trust["policy"], "Guest trust policy differs")
    certificate = fields(reported["test_certificate"], "pin fingerprint not_before not_after", "TEST certificate")
    need(certificate == dict(pin=trust["test_certificate"], fingerprint=candidate, not_before=before, not_after=after)
         and type(certificate["not_before"]) is type(certificate["not_after"]) is int,
         "Verified guest TEST certificate differs from selected certificate")
    signers = reported["signers"]
    fields(signers, f"{OFFICIAL} {PROJECT}", "journal signer")
    operations = (
        ("replacement", OFFICIAL, PROJECT, project_archive, C.pin(raw["test-signature.sig"]), candidate),
        ("restoration", PROJECT, OFFICIAL, ORIGINALS["official_archive"], ORIGINALS["official_signature"], vendor),
    )
    expected_actions = []
    for phase, remove, add, archive, sig, signer in operations:
        prepared = rows[f"{phase}-prepare"]
        added, removed = versions[add], versions[remove]
        question = dict(type=4, pair=[[add, added], [remove, removed]], accepted=True)
        need(prepared == dict(add={add: added}, remove={remove: removed}, questions=[question],
                              install_reason=reason) and type(prepared["install_reason"]) is int
             and type(prepared["questions"][0]["type"]) is int
             and prepared["questions"][0]["accepted"] is True
             and rows[f"{phase}-commit-start"] == rows[f"{phase}-commit-done"] == {},
             f"Exact {phase} ALPM prepare and commit boundary required")
        status = raw[f"{phase}-signature.status"]
        need(signers[add] == dict(archive=archive, signature=sig,
                                  fingerprint=signer, status=C.pin(status)),
             f"Exact verified {phase} operand required")
        created, expires = signature_status(status, signer)
        need(created <= verified and (expires == 0 or restored < expires),
             f"{phase} signature is outside the reported validation window")
        if phase == "replacement":
            need(before <= created, "TEST signature predates the reported certificate")
        expected_actions.extend(((b"removed", remove.encode(), removed.encode()),
                                 (b"installed", add.encode(), added.encode())))
    actions = []
    for line in raw["pacman.log"].splitlines():
        if any(b"[ALPM] " + action + b" " in line
               for action in (b"installed", b"reinstalled", b"removed", b"upgraded", b"downgraded")):
            match = ALPM_ACTION.search(line)
            need(match, "Malformed ALPM package action")
            actions.append(match.groups())
    need(actions == expected_actions, "ALPM log differs from the two one-package swaps")
    return rows


def probe_arguments(step):
    fields(step, "argv pid start_ticks exit problem output", "runtime probe command")
    argv = step["argv"]
    need(type(step["exit"]) is int and step["exit"] == 0 and step["problem"] is None
         and all(type(step[key]) is int and step[key] > 0 for key in ("pid", "start_ticks"))
         and type(step["output"]) is str and len(step["output"]) <= 32 << 10
         and type(argv) is list and argv[:len(PROBE_PREFIX)] == PROBE_PREFIX
         and all(type(arg) is str and "\0" not in arg for arg in argv),
         "Expected successful ordinary-user runtime command")
    words = argv[len(PROBE_PREFIX):]
    split = next((i for i, word in enumerate(words) if word.startswith("/")), len(words))
    settings = words[:split]
    need(split < len(words) and all(re.fullmatch(r"[A-Z_][A-Z0-9_]*=.*", word) for word in settings),
         "Missing runtime probe command or environment")
    env = dict(word.split("=", 1) for word in settings)
    inner = env.get("XDG_RUNTIME_DIR", "").removesuffix("/run")
    need(len(env) == len(settings) and re.fullmatch(r"/tmp/qt629-probe-[a-z0-9_]+", inner)
         and env["XDG_RUNTIME_DIR"] == inner + "/run",
         "Unexpected runtime probe fixture directory")
    return inner, words[split:], env


def runtime_probes(raw, nonce, phase):
    names = "kind status nonce uid gid wayland_socket vulkan_icd checks"
    if phase == "restoration":
        names += " phase"
    report = fields(C.json_body(raw, canonical=True), names, "runtime probe report")
    if phase == "restoration":
        need(report["phase"] == phase, "Expected the restored runtime phase")
    socket = report["wayland_socket"]
    need(report["kind"] == PROBE_KIND and report["status"] == "PASS" and report["nonce"] == nonce
         and type(report["uid"]) is type(report["gid"]) is int and report["uid"] == report["gid"] == 65534
         and report["vulkan_icd"] == LAVAPIPE and socket == W["SOCKET"],
         f"Complete ordinary-user runtime probe PASS for the selected nonce and socket required: {phase}")
    checks = fields(report["checks"], " ".join(PROBE_CHECKS), "runtime probe checks")
    fixture, clients = None, {}
    for name, (reason, count, marker) in PROBE_CHECKS.items():
        reported = "status reason steps process" if name in PRESENTED_CHECKS else "status reason steps"
        row = fields(checks[name], reported, f"{name} runtime check")
        steps = row["steps"]
        need(row["status"] == "PASS" and row["reason"] == reason and type(steps) is list and len(steps) == count,
             f"Complete runtime probe PASS required: {name}")
        commands = [probe_arguments(step) for step in steps]
        inner, actual, env = commands[-1]
        base_env = dict(PATH="/usr/bin:/bin", LC_ALL="C", TZ="UTC", HOME=f"{inner}/work", TMPDIR=f"{inner}/work",
                        XDG_RUNTIME_DIR=f"{inner}/run", XDG_CACHE_HOME=f"{inner}/work", QML_DISABLE_DISK_CACHE="1")
        fixture = fixture or inner
        need(all(directory == fixture for directory, _, _ in commands),
             f"Runtime probe fixture path differs: {name}")
        if name in PROBE_BUILDS:
            binary, module = PROBE_BUILDS[name]
            need(commands[0][1] == ["/usr/bin/pkg-config", "--cflags", "--libs", module],
                 f"Runtime probe pkg-config command differs: {name}")
            flags = shlex.split(steps[0]["output"])
            compiler = ["/usr/bin/g++", "-std=c++17", "-O0", "-fPIC", f"{inner}/{binary}.cpp",
                        "-o", f"{inner}/work/{binary}", *flags]
            need(commands[1][1] == compiler, f"Runtime probe compiler command differs: {name}")
            need(all(settings == base_env for _, _, settings in commands[:-1]),
                 f"Runtime probe build environment differs: {name}")
        gui, quick, qml = f"{inner}/work/gui", f"{inner}/work/quick", f"{inner}/fixture.qml"
        expected_args, expected_env = {
            "core_gui_offscreen": ([gui, "offscreen"], {"QT_QPA_PLATFORM": "offscreen"}),
            "quick_offscreen": ([quick, "software", qml], {"QT_QPA_PLATFORM": "offscreen"}),
            "wayland": ([gui, "wayland"], {"QT_QPA_PLATFORM": "wayland", "WAYLAND_DISPLAY": socket}),
            "vulkan_loader": (["/usr/bin/python3", "-I", "-B", f"{inner}/vulkan.py"],
                              {"VK_DRIVER_FILES": LAVAPIPE, "LP_NUM_THREADS": "2"}),
            "vulkan_qrhi": ([quick, "vulkan", qml],
                            {"QT_QPA_PLATFORM": "wayland", "WAYLAND_DISPLAY": socket, "QSG_RENDER_LOOP": "basic",
                             "VK_DRIVER_FILES": LAVAPIPE, "LP_NUM_THREADS": "2"}),
        }[name]
        need(actual == expected_args, f"Runtime probe command differs: {name}")
        need(env == base_env | expected_env, f"Runtime probe launch environment differs: {name}")
        matched = [match for line in steps[-1]["output"].splitlines() if (match := re.fullmatch(marker, line))]
        need(len(matched) == 1 and (name != "vulkan_loader" or int(matched[0][1]) > 0),
             f"Runtime probe success marker differs: {name}")
        if name in PRESENTED_CHECKS:
            process = fields(row["process"], "pid start_ticks", f"{name} runtime process")
            need(all(type(process[key]) is int and process[key] == steps[-1][key] for key in process),
                 f"Runtime probe process identity differs: {name}")
            clients[f"{phase}-{PRESENTED_CHECKS[name]}"] = process
    return clients


def weston_presentations(raw, trace, nonce, clients, *, parity=False):
    report = fields(C.json_body(raw, canonical=True),
                    "kind status nonce socket dependencies startup retirement presentations error argv log"
                    " log_limit_reached missing_presentations", "Weston lifecycle evidence")
    socket = W["SOCKET"]
    need(report["kind"] == W["KIND"] and report["status"] == "PASS" and report["nonce"] == nonce
         and report["socket"] == socket and report["error"] is None and report["missing_presentations"] == []
         and report["argv"] == W["command"]() and report["log_limit_reached"] is False
         and 0 < len(trace) < W["LOG_CAP"] and trace.endswith(b"\n") and report["log"] == C.pin(trace),
         "Exact complete Weston lifecycle and server log required")
    startup = fields(report["startup"], "peer socket_inode output", "Weston readiness")
    peer = fields(startup["peer"], "pid uid gid", "Weston socket peer")
    inode = startup["socket_inode"]
    need(type(peer["pid"]) is int and peer["pid"] > 0 and peer["uid"] == peer["gid"] == W["USER"]
         and type(inode) is list and len(inode) == 2 and all(type(value) is int and value > 0 for value in inode)
         and startup["output"] == dict(name="headless", width=256, height=256, refresh_millihz=60000),
         "Expected owned Weston peer and headless output")
    retired = fields(report["retirement"], "signals forced exit reaped group_absent socket_removed_by_weston"
                     " runtime_removed fixture_removed", "Weston retirement")
    need(retired["signals"] == ["SIGTERM"] and retired["forced"] is False
         and type(retired["exit"]) is int and retired["exit"] == 0
         and all(retired[key] is True for key in (
             "reaped", "group_absent", "socket_removed_by_weston", "runtime_removed", "fixture_removed")),
         "Expected clean scoped Weston retirement")
    dependencies = fields(report["dependencies"], " ".join(W["F"]["FILES"]), "Weston dependency results")
    for row in dependencies.values():
        fields(row, "exit output truncated", "Weston dependency result")
        need(type(row["exit"]) is int and row["exit"] == 0 and row["truncated"] is False
             and type(row["output"]) is str and 0 < len(row["output"]) <= 32 << 10 and "not found" not in row["output"],
             "Expected complete Weston dependency result")
    roles = W["PARITY_PROBES"] if parity else W["PROBES"]
    presentations = fields(report["presentations"], " ".join(roles), "Weston presentation roles")
    pids, previous_end = {peer["pid"]}, 0
    for role, minimum in roles.items():
        entry = fields(presentations[role], "status pid start_ticks socket start end trace presentation",
                       f"{role} Weston presentation")
        pid, ticks, start, end = (entry[key] for key in ("pid", "start_ticks", "start", "end"))
        need(entry["status"] == "PASS" and entry["socket"] == socket
             and type(pid) is type(ticks) is int and pid not in pids
             and clients[role] == dict(pid=pid, start_ticks=ticks),
             f"Weston presentation client identity differs: {role}")
        need(type(start) is type(end) is int and previous_end <= start < end <= len(trace)
             and (start == 0 or trace[start - 1] == 10) and trace[end - 1] == 10,
             f"Weston presentation trace range differs: {role}")
        segment = trace[start:end]
        need(entry["trace"] == C.pin(segment), f"Weston presentation trace pin differs: {role}")
        observed = W["presentation"](segment, pid, minimum)
        need(entry["presentation"] == observed, f"Weston presentation proof differs: {role}")
        pids.add(pid)
        previous_end = end


def retirement(row, nonce):
    fields(row, "nonce target_submounts keyrings qemu outer_container observations", "retirement")
    need(row["nonce"] == nonce and row["target_submounts"] == []
         and row["keyrings"] == dict.fromkeys(TRUST_HOMES, "removed"),
         "Guest trust homes and target submounts must retire")
    qemu = fields(row["qemu"], "exit reaped output_complete timeout signals", "QEMU retirement")
    outer = fields(row["outer_container"], "id exit removed", "outer container retirement")
    need(type(qemu["exit"]) is int and qemu["exit"] == 0 and qemu["reaped"] is True
         and qemu["output_complete"] is True and qemu["timeout"] is False and qemu["signals"] == [],
         "Natural owned QEMU retirement required")
    need(type(outer["id"]) is str and re.fullmatch(r"[0-9a-f]{64}", outer["id"])
         and type(outer["exit"]) is int and outer["exit"] == 0 and outer["removed"] is True,
         "Owned outer container retirement required")
    need(row["observations"] == [
        dict(event=event, qemu=[], outer_containers=[]) for event in EVENTS[-2:]
    ], "QEMU and outer container must be observed absent twice")


def stopped_observation(row, nonce):
    row = fields(row, "kind nonce disk held retirement host_times", "stopped result observation")
    need(row["kind"] == STOPPED_KIND and type(nonce) is str and NONCE.fullmatch(nonce) and row["nonce"] == nonce,
         "Stopped result observation differs from the selected run nonce")
    need(row["held"] is False, "Held result cannot supply a completed receipt")
    disk = row["disk"]
    need(C.check_pin(disk, RESULT_BYTES) and disk["bytes"] == RESULT_BYTES,
         "Expected the independently pinned stopped result disk")
    retirement(row["retirement"], nonce)
    times = fields(row["host_times"], " ".join(HOST_TIMES), "host chronology")
    need(all(type(stamp) is int and 0 < stamp < 2**63 for stamp in times.values()),
         "Exact independently observed host nanoseconds required")
    return row


def parity_provenance(bundle, receipt, profile, phases, raw, times, transaction):
    bodies = {}
    for role, (file, cap) in PARITY_EVIDENCE.items():
        pin = receipt[role]
        need(C.check_pin(pin, cap) and pin["bytes"] > 0, f"Exact bundled parity pin required for {role}")
        bodies[role] = C.json_body(C.read(bundle / file, cap, pin)[0], canonical=True)
    nonce = receipt["nonce"]
    stopped = stopped_observation(bodies["stopped_observation"], nonce)
    need(receipt["stopped_disk"] == stopped["disk"] and receipt["retirement"] == stopped["retirement"]
         and stopped["host_times"] == {name: times[name] for name in HOST_TIMES},
         "Stopped disk, chronology or retirement differs from the published parity receipt")
    plan = fields(bodies["guest_plan"], "kind nonce code manifest media qt_media qt_replacement", "staged guest plan")
    need(plan["kind"] == "ASAHI629_EXACT_GUEST_PLAN_V1" and plan["nonce"] == nonce
         and plan["manifest"] == C.pin(C.wire(plan["media"]))
         and P["plan_profile"](plan["qt_replacement"]) == profile
         and plan["qt_replacement"]["wayland_socket"] == W["SOCKET"],
         "Staged guest plan differs from the selected parity profile or nonce")
    prefix = "qt-replacement/"
    project = P["project_name"](profile)
    pins = receipt["original_inputs"]
    review = profile["test_review"]
    expected = {
        P["OFFICIAL_NAME"]: pins["official_archive"], P["OFFICIAL_NAME"] + ".sig": pins["official_signature"],
        project: pins["project_archive"], project + ".sig": review["signature"],
        "test-certificate.gpg": review["certificate"], "alarm-public-key.gpg": pins["alarm_public_key"],
        "rollback.lock": pins["rollback_lock"], "result.json": pins["rollback_result"],
        W["F"]["ARCHIVE"]: W["F"]["PINS"]["archive"], W["F"]["ARCHIVE"] + ".sig": W["F"]["PINS"]["signature"],
    }
    need(plan["qt_media"] == {prefix + name: pin for name, pin in expected.items()},
         "Staged guest plan media differs from the reviewed parity inputs")
    owner = bodies["asahi_owner"]
    cleanup = dict(completed=True, target_submounts=stopped["retirement"]["target_submounts"],
                   keyrings=stopped["retirement"]["keyrings"])
    need(owner.get("cleanup") == C.pin(C.wire(cleanup)),
         "Stopped Asahi owner cleanup digest differs from the witnessed trust retirement")
    need(owner["nonce"] == nonce and owner["status"] == P["PASS629"] and owner["plan"] == receipt["guest_plan"]
         and owner["inventory"]["rollback"] == phases["baseline"]["lock"]
         and owner["platform"]["rollback"] == phases["baseline"]["platform"]
         and owner["trust_retired_at_ns"] == times["trust-retired"]
         and owner["qt_checkpoint"] == dict(nonce=nonce, transaction=transaction["terminal"],
                                             runtime_probe=C.pin(raw["runtime-probes.json"])),
         "Stopped Asahi owner result does not bind the staged guest plan and Qt checkpoint")


def readback(bundle, receipt_sha256, *, profile=None):
    selected_pins = originals(profile)
    profile_pin = None if profile is None else C.pin(C.wire(profile))
    version = VERSION if profile is None else profile["project_version"]
    kind = KIND if profile is None else PARITY_KIND
    receipt_raw, receipt_pin = C.external(bundle / "receipt.json", 128 << 10, receipt_sha256)
    names = "kind nonce original_inputs evidence chronology phases trust retirement"
    if profile is not None:
        names += " parity_profile stopped_disk " + " ".join(PARITY_EVIDENCE)
    receipt = fields(C.json_body(receipt_raw, canonical=True),
                     names, "receipt")
    need(receipt["kind"] == kind and type(receipt["nonce"]) is str and NONCE.fullmatch(receipt["nonce"])
         and receipt.get("parity_profile") == profile_pin,
         "Expected scoped Qt replacement receipt and run nonce")
    need(receipt["original_inputs"] == selected_pins, "Original R132, Asahi629 or Qt input pins differ")
    collect = {"rollback_lock", "rollback_result", "owned_terminal", "r132_config"}
    if profile is not None:
        collect |= {"build_plan", "build_receipt", "parity_recipe", "abi_comparison", "alpm_prepare"}
    inputs = bundle / "inputs"
    bodies = {role: C.read(inputs / role, pin["bytes"], pin, collect=role in collect)[0]
              for role, pin in selected_pins.items()}
    if profile is not None:
        P["verify_parity_build"](profile, *(bodies[name] for name in ("build_plan", "build_receipt", "parity_recipe")))
        metadata = {role: P["archive_metadata"](role + "_archive", inputs / (role + "_archive"), owner,
                                               profile=profile)[0]
                    for role, owner in (("project", PROJECT), ("official", OFFICIAL))}
        P["verify_audit"](C.json_body(bodies["abi_comparison"]), bodies["alpm_prepare"], metadata, profile=profile)
    need(b"CONFIG_ARM64_16K_PAGES=y" in bodies["r132_config"].splitlines()
         and b"CONFIG_RTC_DRV_PL031=y" in bodies["r132_config"].splitlines(),
         "Expected R132 ARM16K kernel with the built-in PL031 clock")
    predecessor = C.json_body(bodies["rollback_result"])
    terminal = C.json_body(bodies["owned_terminal"])
    P["verify_predecessor"](predecessor, terminal)
    need(receipt["nonce"] != predecessor["nonce"], "Qt replacement must use a fresh run nonce")
    expected_evidence = evidence_files(profile)
    evidence = fields(receipt["evidence"], " ".join(expected_evidence), "evidence")
    raw = {name: C.read(bundle / name, cap, evidence[name])[0] for name, cap in expected_evidence.items()}
    need(all(raw.values()), "Empty Qt replacement evidence")
    times = chronology(receipt["chronology"])
    phases = fields(receipt["phases"], " ".join(PHASES), "phase")
    untouched = inventories(phases, raw, bodies["rollback_lock"], project_version=version)
    platform = protected(phases, raw, predecessor)
    if profile is not None:
        reviewed = receipt["trust"]
        P["choose_review"](profile, dict(
            fingerprint=reviewed["test_fingerprint"], certificate=C.pin(raw["test-certificate.gpg"]),
            signature=C.pin(raw["test-signature.sig"]), not_before=reviewed["test_not_before"],
            not_after=reviewed["test_not_after"]))
    transaction = transactions(receipt["trust"], raw, times, receipt["nonce"], project_version=version,
                               project_archive=selected_pins["project_archive"], profile_pin=profile_pin)
    if profile is not None:
        parity_provenance(bundle, receipt, profile, phases, raw, times, transaction)
    nonce = receipt["nonce"]
    clients = runtime_probes(raw["vendor-runtime-probes.json"], nonce, "vendor") | runtime_probes(
        raw["runtime-probes.json"], nonce, "replacement")
    if profile is not None:
        clients |= runtime_probes(raw[RESTORED_REPORT], nonce, "restoration")
    weston_presentations(raw[W["REPORT_NAME"]], raw[W["LOG_NAME"]], nonce, clients, parity=profile is not None)
    retirement(receipt["retirement"], receipt["nonce"])
    result = dict(status="CONSISTENT_EXPORTED_QT612_ASAHI629_RECEIPT", receipt=receipt_pin,
                nonce=receipt["nonce"], predecessor_nonce=predecessor["nonce"], untouched_rows=628,
                untouched_lock=untouched, restored_lock=phases["restoration"]["lock"], platform=platform)
    if profile_pin is not None:
        result.update(status="CONSISTENT_EXPORTED_QT612_ASAHI629_PARITY_SCOPED_RECEIPT", parity_profile=profile_pin,
                      guest_plan=receipt["guest_plan"], stopped_disk=receipt["stopped_disk"])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--receipt-sha256", required=True)
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--profile-sha256")
    args = parser.parse_args()
    try:
        sys.addaudithook(C.audit_fence)
        profile = P["load_profile"](args.profile, args.profile_sha256)
        sys.stdout.buffer.write(C.wire(readback(args.bundle, args.receipt_sha256, profile=profile)))
    except (KeyError, OSError, RecursionError, TypeError, ValueError) as error:
        sys.exit(f"Qt629 readback refused: {error}")


if __name__ == "__main__":
    main()
