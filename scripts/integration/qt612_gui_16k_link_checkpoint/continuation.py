# SPDX-License-Identifier: MIT
"""Prepare read-only QtGui backing operands from an externally accepted QtCore run."""

import argparse
import fcntl
import json
import os
from pathlib import Path
from runpy import run_path
import secrets
import stat
import struct
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
CORE = HERE.parent / "qt612_base_16k_link_preflight"
C = SimpleNamespace(**run_path(str(CORE / "readback.py")))
F = SimpleNamespace(**run_path(str(CORE / "preflight.py")))
GIB, MIB = 1 << 30, 1 << 20
TARGET = "lib/libQt6Gui.so"
ARGV = ["/usr/bin/cmake", "--build", F.BUILD, "--parallel", "1", "--target", TARGET]
CORE_ELF = "libQt6Core.so.6.12.0"
CORE_OVERLAY, RAW_BACKING, TOP_OVERLAY = "/inputs/core.qcow2", "/inputs/scratch.raw", "/out/overlay.qcow2"
TOOL = "scripts/integration/qt612_md4c_compile/prepare.py"
TOOL_SHA = "e0212da30780cdf3507c796f6f523d4c5e0e37716395b3477fc66b8daa0e2740"
SELECTION_KIND = "ROOT_QTGUI_LINK_SUCCESSOR_SELECTION_V1"
GUEST_KEYS = ("guest_build_seconds", "build_log_bytes", "artifact_bytes")
CORE_SCRATCH = F.file_record(F.Q3_SCRATCH)
LIMITS = {
    "guest_build_seconds": (1, 86400),
    "build_log_bytes": (1, 64 * MIB),
    "artifact_bytes": (1, GIB),
    "qemu_seconds": (1, 90000),
    "overlay_file_bytes": (MIB, 4 * GIB),
    "result_disk_bytes": (64 * MIB, 4 * GIB),
    "report_allocation_bytes": (MIB, 128 * MIB),
    "host_disk_reserve_bytes": (2 * GIB, 32 * GIB),
    "guest_memory_bytes": (GIB, 16 * GIB),
    "actor_memory_bytes": (GIB, 24 * GIB),
}


def wire_guest(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def reference(ref):
    C.need(type(ref) is dict and set(ref) == {"path", "sha256"}
           and type(ref["path"]) is str and type(ref["sha256"]) is str and C.SHA.fullmatch(ref["sha256"]),
           "Exact independently selected predecessor reference required")
    return Path(ref["path"]), ref["sha256"]


def closed_core(refs):
    C.need(type(refs) is dict and set(refs) == {"handoff", "independent", "post_scope", "output"},
           "Explicit completed QtCore attempt references required")
    handoff_path, handoff_sha = reference(refs["handoff"])
    independent_path, independent_sha = reference(refs["independent"])
    post_path, post_sha = reference(refs["post_scope"])
    C.need(type(refs["output"]) is str, "Canonical original QtCore output required")
    output = Path(refs["output"])
    root = handoff_path.parent
    C.need(handoff_path == root / "HANDOFF.UNISSUED.json" and output.is_absolute()
           and output.parent.parent == root and output.name == "output",
           "Original closed QtCore capsule and once-claimed output must agree")
    original, independent_pin = C.external(independent_path, 128 << 10, independent_sha)
    accepted = C.json_body(original, canonical=True)
    C.need(accepted["kind"] == "QTCORE_LINK_INDEPENDENT_READBACK_V1"
           and accepted["status"] == "PASS_EXACT_QTCORE_LINK_ONLY" and accepted["phase"] == "complete"
           and accepted["post_scope"]["exit_code"] == 0 and accepted["handoff_sha256"] == handoff_sha
           and accepted["post_scope"]["closure"]["sha256"] == post_sha
           and type(accepted["metrics"]["elapsed_ms"]) is int and accepted["metrics"]["elapsed_ms"] > 0,
           "A completed and independently verified QtCore link with measured resources is required")
    handoff = C.json_body(C.external(handoff_path, 64 << 10, handoff_sha)[0], canonical=True)
    C.need(handoff["kind"] == "QTCORE_LINK_HANDOFF_UNISSUED_V1" and handoff["authority"] is None
           and handoff["plan"]["sha256"] == accepted["plan_sha256"],
           "Exact original QtCore handoff and plan must agree")
    plan_raw, _ = C.read(root / "PLAN.UNISSUED.json", 32 << 10, handoff["plan"])
    plan = C.json_body(plan_raw, canonical=True)
    C.need(plan["kind"] == "QTCORE_LINK_PLAN_UNISSUED_V1" and plan["authority"] is None
           and plan["nonce"] == accepted["nonce"] and plan["inputs"]["scratch.raw"] == CORE_SCRATCH
           and plan["q3_terminal"] == F.file_record(F.Q3_TERMINAL),
           "Exact Q3 backing and observed QtCore plan required")
    authority_raw, _ = C.external(output.parent / "selection.json", 128 << 10, accepted["authority_sha256"])
    authority = C.json_body(authority_raw, canonical=True)
    C.need(authority["issuer"] == "Root" and authority["approved"] is True
           and authority["kind"] == "ROOT_QTCORE_LINK_SELECTION_V1"
           and authority["nonce"] == plan["nonce"] and authority["plan_sha256"] == handoff["plan"]["sha256"]
           and authority["handoff_sha256"] == handoff_sha, "Original issued QtCore selection required")
    tool = handoff["source"][TOOL]
    C.need(tool["sha256"] == TOOL_SHA and tool["mode"] == 0o444, "Exact retained App B chain reader required")
    module = C.pinned_module("qtgui_qcow2_readback", root / "source" / TOOL, (tool["bytes"], TOOL_SHA))
    # Replay the original streams, watched resources, owned closure and ELF.
    checks = C.verify_actor(output, plan, handoff["plan"]["sha256"], accepted["actor_result"]["sha256"],
                            module.validate_empty_overlay, handoff_sha=handoff_sha,
                            authority_sha=accepted["authority_sha256"])
    post = C.verify_host_scope(output, post_path, post_sha, handoff["plan"]["sha256"], checks)
    replay = dict(kind="QTCORE_LINK_INDEPENDENT_READBACK_V1", plan_sha256=handoff["plan"]["sha256"],
                  post_scope=post, **checks)
    C.need(C.wire(replay) == original, "Exact prior independent result must replay from original bytes")
    files = C.result_files(output / "result.raw", checks["result_disk"], plan["result_uuid"], True)
    raw = root / "inputs/scratch.raw"
    C.read(raw, CORE_SCRATCH["bytes"], CORE_SCRATCH, collect=False)
    return root, output / "overlay.qcow2", raw, files[CORE_ELF], independent_pin, replay


def qcow_backing(header, image_bytes, backing, form):
    """Inspect a fixed QCOW2 v3 header without opening its parent."""
    C.need(len(header) == 65536 and image_bytes >= 3 * 65536, "Bounded QCOW2 header cluster required")
    fields = struct.unpack_from(">4sIQIIQIIQQIIQ", header)
    magic, ver, offset, length, bits, size, crypt, l1, l1_off, refs, refcount, snaps, snap_off = fields
    C.need((magic, ver, bits, size, crypt, l1, snaps, snap_off) == (b"QFI\xfb", 3, 16, 16 * GIB, 0, 32, 0, 0)
           and refcount > 0 and l1_off >= 65536 and refs >= 65536 and l1_off % 65536 == refs % 65536 == 0
           and l1_off + l1 * 8 <= image_bytes and refs + refcount * 65536 <= image_bytes
           and not refs <= l1_off < refs + refcount * 65536,
           "Expected nonencrypted 16 GiB owned QCOW2 geometry")
    features = struct.unpack_from(">QQQII", header, 72)
    header_bytes = features[-1]
    C.need(features == (0, 0, 0, 4, 112)
           and offset >= header_bytes + 8 and 0 < length <= 1023 and offset + length <= len(header)
           and header[offset:offset + length] == backing.encode("ascii"),
           "Expected clean standard QCOW2 and exact immutable backing path")
    pos, extensions = header_bytes, {}
    while pos + 8 <= offset:
        kind, count = struct.unpack_from(">II", header, pos)
        pos += 8
        if kind == 0:
            C.need(count == 0 and pos == offset, "Exact end of QCOW2 extensions required")
            break
        padded = ((count + 7) // 8) * 8
        C.need(kind in (0xE2792ACA, 0x6803F857) and kind not in extensions
               and 0 < count <= 4096 and pos + padded <= offset,
               "Unexpected QCOW2 extension or additional external data")
        extensions[kind] = header[pos:pos + count]
        pos += padded
    else:
        raise ValueError("Missing QCOW2 extension terminator")
    C.need(extensions.get(0xE2792ACA) == form.encode("ascii"), "Exact declared QCOW2 backing format required")


def inspect_overlay(path, expected, backing, form):
    with F.open_original(path) as stream:
        original = F.verify_original(stream, path, expected["bytes"])
        qcow_backing(stream.read(65536), expected["bytes"], backing, form)
        C.need(F.identity(os.fstat(stream.fileno())) == original == F.identity(path.lstat()),
               "Accepted overlay changed while inspecting the backing header")


def limit_profile(selected, basis_sha, verified):
    C.need(selected["budget_basis_sha256"] == basis_sha and verified["status"] == "PASS_EXACT_QTCORE_LINK_ONLY"
           and verified["post_scope"]["exit_code"] == 0 and verified["metrics"]["elapsed_ms"] > 0,
           "Select budgets only against the exact measured completed Core result")
    caps = selected["limits"]
    C.need(type(caps) is dict and set(caps) == set(LIMITS)
           and all(type(caps[key]) is int and low <= caps[key] <= high for key, (low, high) in LIMITS.items()),
           "Complete separately selected finite QtGui limits required")
    C.need(caps["qemu_seconds"] >= caps["guest_build_seconds"] + 60
           and caps["guest_memory_bytes"] % MIB == 0 and caps["actor_memory_bytes"] > caps["guest_memory_bytes"]
           and caps["result_disk_bytes"] % 4096 == 0 and caps["artifact_bytes"] > 133128
           and caps["result_disk_bytes"] >= caps["artifact_bytes"] + caps["build_log_bytes"] + 8 * MIB,
           "Keep guest/host retirement, memory and result-filesystem headroom")
    return caps


def clone(source, destination, expected):
    with F.open_original(source) as direction, destination.open("xb") as target:
        before = F.verify_original(direction, source, expected["bytes"])
        C.need(os.fstat(target.fileno()).st_dev == before[0], "Same-filesystem backing required")
        fcntl.ioctl(target.fileno(), 0x40049409, direction.fileno())
        C.need(F.identity(os.fstat(direction.fileno())) == before == F.identity(source.lstat()),
               "Original changed during backing reflink")
    C.read(destination, expected["bytes"], expected, collect=False)
    destination.chmod(0o444)


def save(path, body):
    with path.open("xb") as stream:
        stream.write(body)
    path.chmod(0o444)


def stage(where, root, overlay, scratch, core, plan, guest):
    C.need(where.is_absolute() and where == where.resolve() and not where.exists()
           and not where.is_relative_to(root) and where.parent.is_dir()
           and not where.parent.stat().st_mode & 0o022,
           "Fresh private staging outside the original QtCore capsule required")
    volume = os.statvfs(where.parent)
    C.need(volume.f_bavail * volume.f_frsize >= plan["required_host_disk_bytes"],
           "Current staging filesystem is below selected QtGui storage and reserve")
    with TemporaryDirectory(prefix="qtgui-backing-", dir=where.parent) as tmp:
        packet = Path(tmp) / "packet"
        packet.mkdir(mode=0o700)
        inputs = packet / "inputs"
        inputs.mkdir(mode=0o700)
        clone(overlay, inputs / "core.qcow2", plan["inputs"]["core.qcow2"])
        clone(scratch, inputs / "scratch.raw", CORE_SCRATCH)
        inspect_overlay(inputs / "core.qcow2", plan["inputs"]["core.qcow2"], RAW_BACKING, "raw")
        inputs.chmod(0o555)
        save(packet / CORE_ELF, core)
        save(packet / "GUI-GUEST-PLAN.json", guest)
        save(packet / "BACKING.UNISSUED.json", C.wire(plan))
        packet.rename(where)


def reviewed_backing(selection, digest):
    original, pin = C.external(selection, 32 << 10, digest)
    chosen = C.json_body(original, canonical=True)
    C.need(set(chosen) == {"kind", "issuer", "approved", "core", "limits", "budget_basis_sha256"}
           and chosen["kind"] == SELECTION_KIND and chosen["issuer"] == "Root" and chosen["approved"] is True,
           "Exact separately selected accepted Core inputs and limits required")
    root, overlay, scratch, core, independent, actual = closed_core(chosen["core"])
    limits = limit_profile(chosen, independent["sha256"], actual)
    inspect_overlay(overlay, actual["overlay"], RAW_BACKING, "raw")
    nonce = secrets.token_hex(16)
    C.need(nonce != actual["nonce"], "Fresh continuation nonce required")
    guest = wire_guest(dict(kind="QTGUI_LINK_GUEST_PLAN_V1", authority=None, nonce=nonce, core=C.pin(core),
                            limits={key: limits[key] for key in GUEST_KEYS}, target=TARGET))
    plan = dict(kind="QTGUI_LINK_BACKING_UNISSUED_V1", authority=None, actor_started=False, nonce=nonce,
                issuer_selection=pin, core_readback=independent, core_elf=C.pin(core),
                core_measurements=dict(metrics=actual["metrics"], allocation=actual["allocation"],
                                       actor_memory_peak_bytes=actual["host_cgroup_memory_peak_bytes"]),
                inputs={"core.qcow2": actual["overlay"], "scratch.raw": CORE_SCRATCH},
                guest_plan=C.pin(guest), guest_command=ARGV, limits=limits,
                required_host_disk_bytes=sum(limits[key] for key in
                                             ("overlay_file_bytes", "result_disk_bytes", "report_allocation_bytes",
                                              "host_disk_reserve_bytes")),
                overlay_create=["/usr/bin/qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b",
                                CORE_OVERLAY, TOP_OVERLAY],
                expected_backing_chain=[TOP_OVERLAY, CORE_OVERLAY, RAW_BACKING],
                root_acceptance=None, qtgui_link="NOT_RUN", full_package="NOT_RUN")
    return chosen, root, overlay, scratch, core, plan, guest, actual


def prepare(selection, digest, output=None):
    _, root, overlay, scratch, core, plan, guest, _ = reviewed_backing(selection, digest)
    if output is not None:
        stage(output, root, overlay, scratch, core, plan, guest)
    return plan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--selection-sha256", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        sys.stdout.buffer.write(C.wire(prepare(args.selection, args.selection_sha256, args.output)))
    except (OSError, ValueError, KeyError, TypeError) as error:
        sys.exit("QtGui continuation refused: " + str(error))


if __name__ == "__main__":
    main()
