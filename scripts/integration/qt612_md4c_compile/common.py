# SPDX-License-Identifier: MIT
"""Portable, externally pinned input and authority checks for the bounded actor."""

import importlib.util
from itertools import islice
from pathlib import Path
import os
import re
import shutil
import stat
import time

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parents[2]
LANE = HERE.relative_to(SOURCE).as_posix()
ACTOR = "/src/" + LANE + "/actor.py"
ATTACH_SECONDS = 2400
DISK_GATE, RAM_GATE, CPUS = 4395630592, 6 << 30, 4
HANDOFF_KIND = "QT_MD4C_PORTABLE_HANDOFF_UNISSUED_V1"
SELECTION_KIND = "ROOT_QT_MD4C_PORTABLE_COMPILE_SELECTION_V1"
MAX_FILE = 16 << 30
HEX = re.compile("[a-f0-9]{64}")
NONCE = re.compile("[a-f0-9]{32}")
UUID = re.compile("[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}")
ROLE = re.compile("[a-z][a-z0-9_-]{0,31}")
SCOPE = re.compile("[A-Za-z0-9_.-]{1,150}\\.scope")

REQUIRED = {f"{LANE}/{leaf}" for leaf in ("actor.py", "common.py", "guest.sh", "prepare.py")} | {
    "scripts/install/overlay583_trial/controller.py",
    "scripts/install/overlay583_trial/trial.py",
    "scripts/integration/arm16k_perl5423_vm/runtime.py",
    "scripts/integration/arm16k_perl5423_vm/contracts.py",
    "scripts/integration/arm16k_perl5423_vm/helper-origin.json",
    "scripts/integration/arm16k_perl5423_vm/frozen/owned_process.py",
}


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


O = module("qt_md4c_overlay", SOURCE / "scripts/install/overlay583_trial/controller.py")
T = O.T
IMAGE = O.ACTOR_IMAGE
P = module("qt_md4c_prepare", HERE / "prepare.py")


def pin_shape(value):
    return (type(value) is dict and set(value) == {"bytes", "sha256"}
            and type(value["bytes"]) is int and 0 < value["bytes"] <= MAX_FILE
            and type(value["sha256"]) is str and HEX.fullmatch(value["sha256"]) is not None)


def ordinary_spelling(value):
    return (type(value) is str and Path(value).is_absolute() and ".." not in Path(value).parts
            and str(Path(value)) == value and not any(char in value for char in "\0\r\n"))


def closure_refs(value):
    T.need(type(value) is dict and 0 < len(value) <= 16, "Explicit bounded predecessor metadata required")
    result = {}
    for role, ref in value.items():
        T.need(ROLE.fullmatch(role) and type(ref) is dict and set(ref) == {"path", "bytes", "sha256"}
               and ordinary_spelling(ref["path"]), "Ordinary explicitly selected close reference required")
        pin = {key: ref[key] for key in ("bytes", "sha256")}
        T.need(pin_shape(pin) and pin["bytes"] <= 128 << 10, "Finite predecessor metadata pin required")
        result[role] = pin
    return result


def check_pinned_file(path, expected):
    return T.read(path, expected, cap=MAX_FILE, collect=False)


def load_envelope(path, digest):
    raw = T.read(path, cap=128 << 10)
    data = T.decode(raw)
    keys = {"kind", "authority", "scope", "actor_image", "plan", "attach_seconds", "required_disk_bytes",
            "result_uuid", "prior_closures", "operand_root", "source", "source_tree_sha256"}
    T.need(type(digest) is str and HEX.fullmatch(digest) and T.pin(raw)["sha256"] == digest
           and type(data) is dict and set(data) == keys and raw == T.encoded(data)
           and data["kind"] == HANDOFF_KIND and data["authority"] is None and data["actor_image"] == IMAGE
           and type(data["scope"]) is str and SCOPE.fullmatch(data["scope"]) and pin_shape(data["plan"])
           and data["attach_seconds"] == ATTACH_SECONDS and data["required_disk_bytes"] == DISK_GATE
           and type(data["result_uuid"]) is str and UUID.fullmatch(data["result_uuid"])
           and ordinary_spelling(data["operand_root"]), "Exact sealed compile handoff required")
    closure_refs(data["prior_closures"])
    return data


def verify_source(data, base=SOURCE):
    base = T.ordinary(base)
    files = data["source"]
    T.need(type(files) is dict and REQUIRED <= files.keys() and
           stat.S_IMODE(base.stat().st_mode) == 0o555 and
           T.pin(T.encoded(files))["sha256"] == data["source_tree_sha256"], "Exact source seal required")
    paths = list(islice(base.rglob("*"), 101))
    T.need(len(paths) <= 100 and not any(p.is_symlink() for p in paths) and
           {p.relative_to(base).as_posix() for p in paths if not p.is_dir()} == set(files),
           "Exact ordinary source leaf set required")
    for path in paths:
        mode = stat.S_IMODE(path.lstat().st_mode)
        if path.is_dir():
            T.need(mode == 0o555, "Sealed source directory mode differs")
        else:
            ref = files[path.relative_to(base).as_posix()]
            T.need(mode == ref["mode"] in (0o444, 0o555), "Sealed source file mode differs")
            T.read(path, {key: ref[key] for key in ("bytes", "sha256")}, cap=2 << 20, collect=False)


def read_plan(path, expected):
    raw = T.read(path, expected, cap=128 << 10)
    plan = T.decode(raw)
    keys = {"kind", "authority", "guest_invoked", "original_reflink_fallback", "q3_closure_sha256",
            "q3_postclose_operands", "inputs", "nonce", "guest_payload", "actor", "command_slots",
            "requested_outputs", "qemu_seconds", "qemu_argv", "retained_native_disk_gate", "build_scope"}
    T.need(type(plan) is dict and set(plan) == keys and raw == P.canonical(plan) and
           plan["kind"] == "QT612_MD4C_COMPILE_CONTINUATION_UNISSUED_V1"
           and plan["authority"] is None and plan["guest_invoked"] is False
           and plan["original_reflink_fallback"] is False and plan["qemu_seconds"] == 2100
           and plan["retained_native_disk_gate"] == 14 << 30 and plan["build_scope"] == "QT_MD4C_IMPORTER_OBJECT_ONLY"
           and plan["requested_outputs"] == [P.PCH, P.IMPORTER] and plan["command_slots"] == {
               "headers": 6, "pch": 1, "importer": 1}
           and type(plan["nonce"]) is str and NONCE.fullmatch(plan["nonce"])
           and type(plan["q3_closure_sha256"]) is str and HEX.fullmatch(plan["q3_closure_sha256"]),
           "Exact bounded compile plan required")
    originals, selected = plan["q3_postclose_operands"], plan["inputs"]
    T.need(set(originals) == {"Image", "boot.raw", "scratch.raw"} and
           set(selected) == set(originals) | {"result.raw"} and
           all(pin_shape(pin) for pin in (*originals.values(), *selected.values())) and
           all(pin["bytes"] <= P.SOURCE_LIMITS[name] for name, pin in originals.items()) and
           all(selected[name] == originals[name] for name in ("Image", "scratch.raw")) and
           selected["boot.raw"]["bytes"] == originals["boot.raw"]["bytes"] and
           P.OFFSET < selected["boot.raw"]["bytes"] and selected["boot.raw"]["bytes"] % 4096 == 0 and
           selected["scratch.raw"]["bytes"] == P.WORK and selected["result.raw"]["bytes"] == P.RESULT,
           "Exact immutable carrier identities and geometry required")
    policy = P.actor_policy(plan["actor"]["profile"], sum(value["bytes"] for value in originals.values()))
    T.need(T.encoded(plan["actor"]) == T.encoded(policy) and policy["profile"]["actor_image"] == IMAGE
           and policy["admission_disk_bytes"] == DISK_GATE, "Exact selected tool and bounded actor policy required")
    guest = plan["guest_payload"]
    T.need(set(guest) == {"MANIFEST.sha256", "guest.sh", "headers.commands", "pch.commands", "importer.commands",
                          "operands.sha256"} and
           all(type(sha) is str and HEX.fullmatch(sha) for sha in guest.values()) and
           T.read(HERE / "guest.sh", cap=128 << 10, collect=False)["sha256"] == guest["guest.sh"] and
           T.pin(P.checksums({name: sha for name, sha in guest.items() if name != "MANIFEST.sha256"}))["sha256"] ==
           guest["MANIFEST.sha256"], "Exact guest payload manifest required")
    argv = plan["qemu_argv"]
    T.need(type(argv) is list and all(type(arg) is str for arg in argv) and argv.count("-append") == 1
           and argv[-1] != "-append", "Exact literal guest arguments required")
    append = argv[argv.index("-append") + 1]
    match = re.search(r" cachy_qt_compile_scratch_uuid=([a-f0-9-]+) cachy_qt_compile_result_uuid=", append)
    T.need(match and UUID.fullmatch(match[1]) and match[1] != P.result_uuid(plan["nonce"])
           and argv == P.continuation_argv(plan["nonce"], guest["MANIFEST.sha256"], match[1]),
           "Exact offline QEMU disks, storage UUIDs and invocation required")
    return plan


def binding(data, plan, handoff_sha):
    closures = closure_refs(data["prior_closures"])
    T.need(any(ref["sha256"] == plan["q3_closure_sha256"] for ref in closures.values()) and
           data["result_uuid"] == P.result_uuid(plan["nonce"]), "Exact configure closure and result UUID required")
    return dict(kind=SELECTION_KIND, issuer=None, approved=None, created_utc=None, expires_utc=None,
                actor_image=IMAGE, scope=data["scope"], nonce=plan["nonce"], handoff_sha256=handoff_sha,
                prior_closures=closures, plan_sha256=data["plan"]["sha256"])


def verify_selection(raw, digest, data, plan, handoff_sha, *, live=True):
    T.need(type(digest) is str and HEX.fullmatch(digest) and T.pin(raw)["sha256"] == digest,
           "Independent Root authority digest differs")
    issued = T.decode(raw)
    created, expires = issued["created_utc"], issued["expires_utc"]
    T.need(type(created) is type(expires) is int and 0 < expires - created <= 3600,
           "Exact finite Root entry window required")
    if live:
        T.need(created <= int(time.time()) < expires, "Root entry window closed")
    expected = binding(data, plan, handoff_sha) | dict(issuer="Root", approved=True,
                                                      created_utc=created, expires_utc=expires)
    T.need(raw == T.encoded(expected), "Issued authority differs from the sealed unissued binding")
    return issued


def capacity(path):
    free = shutil.disk_usage(T.ordinary(path)).free
    memory = int(re.search(r"^MemAvailable:\s+(\d+) kB$", Path("/proc/meminfo").read_text(), re.M)[1]) * 1024
    cpus = len(os.sched_getaffinity(0))
    return dict(free_bytes=free, memory_available_bytes=memory, allowed_cpus=cpus, required_bytes=DISK_GATE,
                minimum_memory_bytes=RAM_GATE, minimum_cpus=CPUS,
                fits=free >= DISK_GATE and memory >= RAM_GATE and cpus >= CPUS)
