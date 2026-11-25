# SPDX-License-Identifier: MIT
"""Run and verify the exact full Qtbase target in the selected 16 KiB guest."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import struct
import subprocess
import sys
from types import SimpleNamespace


MIB = 1 << 20
GIB = 1 << 30
EVIDENCE = Path("/qtbase-full-evidence")
SIDECAR = Path("/qtmedia/guest_link.py")
SIDECAR_PIN = (15956, "4e463ecf3db06fc483d529340ffc1df98497651a372ff40fbf363201e7d63725")
PLAN_KIND = "QTBASE_FULL16K_GUEST_PLAN_V1"
RESULT_KIND = "QTBASE_FULL16K_GUEST_RESULT_V1"
TARGET = "all"
BUILD_ARGV = ["/usr/bin/cmake", "--build", "/qt-recipe/src/build", "--parallel", "1", "--target", TARGET]
VERSION = ".so.6.12.0"
LIBRARIES = tuple("libQt6" + module + VERSION for module in (
    "Concurrent", "Core", "DBus", "EglFSDeviceIntegration", "EglFsKmsGbmSupport",
    "EglFsKmsSupport", "Gui", "Network", "OpenGL", "OpenGLWidgets", "PrintSupport",
    "Sql", "Test", "WaylandClient", "Widgets", "WlShellIntegration", "XcbQpa", "Xml",
))
ROLE_NAMES = {role.lower(): "libQt6" + role + VERSION for role in ("Core", "DBus", "Gui")}
NINJA_IDLE = b"ninja: no work to do.\n"
REMAINDER_COUNT = 1216
MAX_LIBRARY = 128 * MIB
SHA = re.compile("[0-9a-f]{64}")
NONCE = re.compile("[0-9a-f]{32}")
PHDR = struct.Struct("<II6Q")
FAILURE_CODES = {
    "inputs": "INPUT_CHECK_FAILED",
    "graph": "GRAPH_CHECK_FAILED",
    "build": "BUILD_FAILED",
    "verify": "OUTPUT_VERIFY_FAILED",
}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def pin(body):
    return dict(bytes=len(body), sha256=hashlib.sha256(body).hexdigest())


def pin_tuple(record):
    return record["bytes"], record["sha256"]


INVENTORY = dict(bytes=6925, sha256="e2a4da7903e6de26b0ee37758ad424439f83196fa6a3b0bdffa501f35a02d0b9")
INHERITED = {
    "core": dict(bytes=8819928, sha256="50f2365b3238ccbc4f70b19d4fb0ec9a24462e0cd752a862030e3ed002877558"),
    "dbus": dict(bytes=1280088, sha256="c64174251bacb101fe466b3f07a00a9b82c628e054a3a6447ab8af735852ebe6"),
    "gui": dict(bytes=10831952, sha256="bc73b419fcc9f2e8d07d8454d867e5e2dad34beae4e3d32f29c601dfec767ad8"),
    "md4c": dict(bytes=133128, sha256="d7754699fec7db8e53a7813547b4c1c0cfdde079ae09128401c379ec034bdef2"),
}
DRY_RUN = {
    "gui": pin(NINJA_IDLE),
    "all": dict(bytes=2092143, sha256="48732e61acb20d36c37d253e3e42a63bcd1986ede207d0f843f7a8d9d1f39ec7"),
}
ALL_COMMANDS = dict(bytes=3451659, sha256="e9bdd7b241d2c28d035e3a084ca7fbeefd7d90f64748e0c0c356e1ea9baff628")
INITIAL_NINJA_LOG = (78876, "8ff1dbfd5b753b464f64e240eeb13206f0f231ea1e7acb3fd0f446f8b0c73e58")


def wire_plan(plan):
    return (json.dumps(plan, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def wire_evidence(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def validate_plan(plan):
    fields = {"kind", "nonce", "target", "limits", "inventory", "inherited", "dry_run", "all_commands"}
    need(type(plan) is dict and plan.keys() == fields, "Exact full Qtbase guest plan required")
    need(plan["kind"] == PLAN_KIND and plan["target"] == TARGET and type(plan["nonce"]) is str
         and NONCE.fullmatch(plan["nonce"]), "Wrong Qtbase guest plan identity")
    need(plan["inventory"] == INVENTORY and plan["inherited"] == INHERITED
         and plan["dry_run"] == DRY_RUN and plan["all_commands"] == ALL_COMMANDS,
         "Exact original Q3 inventory, checkpoint and graph pins required")
    limits = plan["limits"]
    maximum = dict(guest_build_seconds=86400, build_log_bytes=64 * MIB,
                   artifact_bytes=GIB, guest_min_free_bytes=16 * GIB)
    need(type(limits) is dict and limits.keys() == maximum.keys()
         and all(type(limits[k]) is int and 0 < limits[k] <= limit for k, limit in maximum.items())
         and limits["artifact_bytes"] > sum(INHERITED[role]["bytes"] for role in ROLE_NAMES),
         "Finite structural Qtbase guest limits required")
    return plan


def identity(row):
    return (row.st_dev, row.st_ino, row.st_mode, row.st_nlink, row.st_uid, row.st_gid,
            row.st_size, row.st_mtime_ns, row.st_ctime_ns)


def read_leaf(path, limit):
    """Read one exact-size ordinary plan or helper without following a leaf alias."""
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= limit,
             "Expected bounded ordinary input")
        body = stream.read(before.st_size + 1)
        need(len(body) == before.st_size
             and identity(os.fstat(stream.fileno())) == identity(before) == identity(path.lstat()),
             "Input changed while reading")
    return body


def read_plan(path, sha):
    need(path.is_absolute() and path == path.resolve(strict=True) and SHA.fullmatch(sha),
         "Canonical independently pinned full Qtbase plan required")
    body = read_leaf(path, 4096)
    need(pin(body)["sha256"] == sha, "Full Qtbase guest plan pin differs")
    plan = validate_plan(json.loads(body))
    need(wire_plan(plan) == body, "Expected canonical full Qtbase plan")
    return plan


def evidence_caps(plan):
    validate_plan(plan)
    sizes = plan["limits"]
    return {
        "inventory.before": INVENTORY["bytes"], "inventory.after": INVENTORY["bytes"],
        "gui-dry-run.log": DRY_RUN["gui"]["bytes"], "all-dry-run.log": DRY_RUN["all"]["bytes"],
        "all-dry-run.after.log": len(NINJA_IDLE), "all.commands": ALL_COMMANDS["bytes"],
        "build.log": sizes["build_log_bytes"], "metrics.json": 4096, "outputs.json": 16384,
        "result.json": 4096,
    } | {name: min(MAX_LIBRARY, sizes["artifact_bytes"]) for name in LIBRARIES}


def alias_metadata(name):
    stem = name.removesuffix(VERSION)
    return {stem + ".so": stem + ".so.6", stem + ".so.6": name}


def verify_library(body):
    """Check AArch64 shared ELF load geometry without loading the object."""
    need(len(body) >= 64 and body[:7] == b"\x7fELF\x02\x01\x01"
         and struct.unpack_from("<HHI", body, 16) == (3, 183, 1),
         "Expected AArch64 ELF shared object")
    start = struct.unpack_from("<Q", body, 32)[0]
    header, entry, count = struct.unpack_from("<HHH", body, 52)
    need(header == 64 and entry == PHDR.size and 0 < count <= 1024
         and 64 <= start <= len(body) - count * entry, "Unbounded ELF program header table")
    load = executable = False
    for kind, flags, offset, address, _, file_size, mem_size, align in PHDR.iter_unpack(
            memoryview(body)[start:start + count * entry]):
        if kind != 1:
            continue
        load = True
        executable |= bool(flags & 1 and file_size)
        need(file_size <= mem_size and offset + file_size <= len(body) and address + mem_size < 2**64
             and align >= 16384 and align & (align - 1) == 0 and offset % align == address % align,
             "Expected 16 KiB ELF load geometry")
    need(load and executable, "Expected executable ELF load segment")


def evidence_json(body):
    data = json.loads(body)
    need(type(data) is dict and wire_evidence(data) == body, "Expected canonical Qtbase guest evidence JSON")
    return data


def verify_evidence(files, plan, sha):
    """Verify the complete PASS evidence, without guest tools or filesystem access."""
    caps = evidence_caps(plan)
    need(SHA.fullmatch(sha) and pin(wire_plan(plan))["sha256"] == sha
         and files.keys() == caps.keys() and all(type(body) is bytes and 0 < len(body) <= caps[name]
                                                 for name, body in files.items()),
         "Exact independently pinned full Qtbase evidence required")
    result = evidence_json(files["result.json"])
    need(result == dict(kind=RESULT_KIND, status="PASS", phase="complete", nonce=plan["nonce"],
                        plan_sha256=sha, target=TARGET), "Expected completed Qtbase guest result")
    need(all(pin(files[name]) == expected for name, expected in (
        ("inventory.before", INVENTORY), ("inventory.after", INVENTORY),
        ("gui-dry-run.log", DRY_RUN["gui"]), ("all-dry-run.log", DRY_RUN["all"]),
        ("all.commands", ALL_COMMANDS))) and files["all-dry-run.after.log"] == NINJA_IDLE,
        "Original inventory or full Qtbase graph observation differs")
    metrics = evidence_json(files["metrics.json"])
    need(metrics.keys() == {"exit_code", "elapsed_ms", "peak_child_rss_kib", "log_complete", "natural",
                            "group_empty", "timeout", "overflow", "dry_run_steps"}
         and type(metrics["exit_code"]) is int and metrics["exit_code"] == 0
         and type(metrics["dry_run_steps"]) is int and metrics["dry_run_steps"] == REMAINDER_COUNT
         and type(metrics["elapsed_ms"]) is int
         and 0 < metrics["elapsed_ms"] <= plan["limits"]["guest_build_seconds"] * 1000
         and type(metrics["peak_child_rss_kib"]) is int and metrics["peak_child_rss_kib"] > 0
         and metrics["log_complete"] is metrics["natural"] is metrics["group_empty"] is True
         and metrics["timeout"] is metrics["overflow"] is False, "Expected bounded natural Qtbase build")
    outputs = evidence_json(files["outputs.json"])
    need(outputs.keys() == {"libraries", "guest_free_bytes"}, "Exact Qtbase output record required")
    free = outputs["guest_free_bytes"]
    need(type(free) is dict and free.keys() == {"before", "after"}
         and all(type(value) is int and plan["limits"]["guest_min_free_bytes"] <= value <= 16 * GIB
                 for value in free.values()), "Guest disk floor failed at an observed boundary")
    need(sum(len(files[name]) for name in LIBRARIES) <= plan["limits"]["artifact_bytes"],
         "Qtbase shared-library evidence exceeds the total budget")
    library_pins = {name: pin(files[name]) for name in LIBRARIES}
    need(all(library_pins[name] == INHERITED[role] for role, name in ROLE_NAMES.items())
         and outputs["libraries"] == {name: dict(library_pins[name], aliases=alias_metadata(name)) for name in LIBRARIES},
         "Qtbase library bodies or alias record differ")
    for name in LIBRARIES:
        verify_library(files[name])
    return dict(status="VERIFIED_QTBASE_BUILD_ONLY", result=pin(files["result.json"]), metrics=metrics,
                outputs=outputs, evidence={name: pin(body) for name, body in files.items()})


def guest_runtime():
    body = read_leaf(SIDECAR, SIDECAR_PIN[0])
    need(pin_tuple(pin(body)) == SIDECAR_PIN, "Exact frozen QtGui guest helper required")
    namespace = {"__name__": "qtbase_pinned_guest_sidecar", "__file__": str(SIDECAR)}
    exec(compile(body, str(SIDECAR), "exec"), namespace)
    return SimpleNamespace(**namespace)


def inherited_state(g):
    state = {}
    for role, name in ROLE_NAMES.items():
        expected = pin_tuple(INHERITED[role])
        _, stable, _ = g.file_data(g.BUILD / "lib" / name, expected[0], expected=expected)
        state[role] = (stable, g.alias_chain(name.removesuffix(VERSION)))
    expected = pin_tuple(INHERITED["md4c"])
    _, stable, _ = g.file_data(g.MD4C, expected[0], expected=expected)
    alias = g.MD4C.with_name("libmd4c.so.0")
    state["md4c"] = stable, g.identity(alias.lstat())
    return state


def inventory(g, evidence, name):
    try:
        g.inventory(evidence, name)
    finally:
        (evidence / (name + ".raw")).unlink(missing_ok=True)


def dry_run(g, evidence, name, target, expected):
    path = evidence / name
    g.require_success(g.capture([g.NINJA, "-n", "-v", target], path, 90, expected["bytes"], cwd=g.BUILD), name)
    g.file_data(path, expected["bytes"], expected=pin_tuple(expected))


def free_space(build, floor):
    volume = os.statvfs(build)
    free = volume.f_bavail * volume.f_frsize
    need(floor <= free <= 16 * GIB, "Qtbase guest scratch free space outside selected bounds")
    return free


def retain_outputs(g, evidence, limit):
    lib = g.BUILD / "lib"
    actual = {p.name for p in lib.glob("libQt6*" + VERSION)}
    need(actual == set(LIBRARIES), "Expected exact 18 full-version Qtbase libraries")
    rows = {}
    for name in LIBRARIES:
        aliases = g.alias_chain(name.removesuffix(VERSION))
        cap = min(limit, MAX_LIBRARY)
        body = g.file_data(lib / name, cap, collect=True)[2]
        verify_library(body)
        metadata = {alias: target for alias, target, _identity in aliases}
        need(metadata == alias_metadata(name), "Wrong Qtbase output alias chain")
        g.put(evidence / name, body)
        rows[name] = dict(pin(body), aliases=metadata)
        limit -= len(body)
    return rows


def build(g, plan, sha, evidence):
    result = dict(kind=RESULT_KIND, nonce=plan["nonce"], plan_sha256=sha, target=TARGET)
    phase = "inputs"
    limits = plan["limits"]
    try:
        g.check_inputs()
        inherited = inherited_state(g)
        for name in set(LIBRARIES) - set(ROLE_NAMES.values()):
            for leaf in (name, *alias_metadata(name)):
                need(not os.path.lexists(g.BUILD / "lib" / leaf), "Preexisting full Qtbase output")
        inventory(g, evidence, "inventory.before")
        free_space(g.BUILD, limits["guest_min_free_bytes"])
        phase = "graph"
        log = g.BUILD / ".ninja_log"
        g.file_data(log, INITIAL_NINJA_LOG[0], expected=INITIAL_NINJA_LOG)
        g.command_body(evidence, "all.commands", TARGET, pin_tuple(ALL_COMMANDS), 1855)
        dry_run(g, evidence, "gui-dry-run.log", g.TARGET, DRY_RUN["gui"])
        dry_run(g, evidence, "all-dry-run.log", TARGET, DRY_RUN["all"])
        g.file_data(log, INITIAL_NINJA_LOG[0], expected=INITIAL_NINJA_LOG)
        before = free_space(g.BUILD, limits["guest_min_free_bytes"])

        phase = "build"
        metrics = g.capture(BUILD_ARGV, evidence / "build.log", limits["guest_build_seconds"],
                            limits["build_log_bytes"], cwd=g.RECIPE)
        g.put_json(evidence / "metrics.json", metrics | {"dry_run_steps": REMAINDER_COUNT})
        g.require_success(metrics, "full Qtbase build")

        phase = "verify"
        dry_run(g, evidence, "all-dry-run.after.log", TARGET, pin(NINJA_IDLE))
        g.check_inputs()
        need(inherited_state(g) == inherited, "Accepted Qtbase checkpoint objects or aliases changed")
        inventory(g, evidence, "inventory.after")
        rows = retain_outputs(g, evidence, limits["artifact_bytes"])
        after = free_space(g.BUILD, limits["guest_min_free_bytes"])
        g.put_json(evidence / "outputs.json", dict(libraries=rows, guest_free_bytes=dict(before=before, after=after)))
    except (OSError, ValueError, subprocess.SubprocessError):
        result.update(status="HOLD", phase=phase, failure_code=FAILURE_CODES[phase])
    else:
        result.update(status="PASS", phase="complete")
    g.put_json(evidence / "result.json", result)
    return result["status"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    need(sys.flags.isolated and sys.dont_write_bytecode and __debug__, "Expected isolated Python")
    need(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 1000
         and os.uname().machine == "aarch64" and os.sysconf("SC_PAGE_SIZE") == 16384,
         "Expected ordinary AArch64 guest on 16 KiB pages")
    need(args.evidence == EVIDENCE == EVIDENCE.resolve(strict=True), "Exact guest evidence directory required")
    info = EVIDENCE.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 1000
         and stat.S_IMODE(info.st_mode) == 0o700 and not any(EVIDENCE.iterdir()),
         "Expected empty ordinary-user evidence directory")
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    plan = read_plan(args.plan, args.plan_sha256)
    g = guest_runtime()
    for signum in g.INTERRUPTS:
        signal.signal(signum, g.interrupt)
    return 0 if build(g, plan, args.plan_sha256, EVIDENCE) == "PASS" else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError):
        raise SystemExit("Full Qtbase guest refused") from None
