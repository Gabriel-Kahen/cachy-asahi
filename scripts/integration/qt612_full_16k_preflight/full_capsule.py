# SPDX-License-Identifier: MIT
"""Sealed full-target Qtbase capsule and passive admission checks."""

import argparse
import json
import os
from pathlib import Path
import re
from runpy import run_path
import stat
import struct
import sys
import time
from types import SimpleNamespace
from uuid import UUID


HERE = Path(__file__).resolve().parent
GUI = HERE.parent / "qt612_gui_16k_link_checkpoint"
Q = SimpleNamespace(**run_path(str(GUI / "gui_capsule.py")))
C, B, T, P, K = Q.C, Q.B, Q.T, Q.P, Q.K
GIB, MIB = K.GIB, K.MIB
SCOPE = "cachy-asahi-qtbase16k-full-build.scope"
HANDOFF = "HANDOFF.UNISSUED.json"
PLAN = "PLAN.UNISSUED.json"
GUEST = "FULL-GUEST-PLAN.json"
SELECTION_KIND = "ROOT_QTBASE_FULL16K_SELECTION_V1"
PAYLOAD = "/qtbase-full"
INPUTS = {"boot.raw", "result.raw", "Image", "scratch.raw", "core.qcow2", "gui.qcow2"}
GUEST_SOURCE = "scripts/integration/qt612_full_16k_preflight"
DRY_RUN_SOURCE = GUEST_SOURCE + "/evidence/dry-run.ACTUAL.json"
SOURCE_FILES = Q.SOURCE_FILES | {GUEST_SOURCE + "/" + name for name in (
    "full_capsule.py", "full_actor.py", "full_readback.py", "full_guest.py", "full-guest-init.sh")} | {DRY_RUN_SOURCE}
HISTORICAL_HANDOFF = "635695d627d3181583830c44969ca1b0cef679755554e54f92be32267c0cbfc4"
HISTORICAL_SOURCE = "0885cbd2ce252cfcbb335bc7422213b81b613d06a03765c03c6aee5bdaa5531a"
RUNNER_PIN = C.file_pin(1229, "1394cc868adef10a7d673d491c22c8827fb5463303577370683b1e71b2c800fb")
DRY_RUN_RECEIPT = C.file_pin(2137, "9634688898152d17063d94bcfd2421e8048e07ceea5d969e6eec30aaec934f7d")
DRY_GUI = C.file_pin(22, "8c35b1682f73592d30612d7b0fabdb384fcfff35cb5a076cb48b85b1368aa794")
DRY_ALL = C.file_pin(2092143, "48732e61acb20d36c37d253e3e42a63bcd1986ede207d0f843f7a8d9d1f39ec7")
ALL_COMMANDS = K.F.file_record(K.F.TARGETS["all"][-1])
INVENTORY = C.file_pin(6925, "e2a4da7903e6de26b0ee37758ad424439f83196fa6a3b0bdffa501f35a02d0b9")
INHERITED = {
    "core": C.file_pin(8819928, "50f2365b3238ccbc4f70b19d4fb0ec9a24462e0cd752a862030e3ed002877558"),
    "dbus": C.file_pin(1280088, "c64174251bacb101fe466b3f07a00a9b82c628e054a3a6447ab8af735852ebe6"),
    "gui": C.file_pin(10831952, "bc73b419fcc9f2e8d07d8454d867e5e2dad34beae4e3d32f29c601dfec767ad8"),
    "md4c": C.file_pin(133128, "d7754699fec7db8e53a7813547b4c1c0cfdde079ae09128401c379ec034bdef2"),
}
LOWER = {
    "Image": Q.CORE_KERNEL,
    "scratch.raw": K.CORE_SCRATCH,
    "core.qcow2": C.file_pin(267386880, "65b812f17dfd8bd24e7f1e8e4554f719749ae96c547e4719eb13c307b81188d7"),
    "gui.qcow2": C.file_pin(750845952, "26afc11e8581afe2556be6ae0171c88cd64e755dcff6f9253cdd3cbb26d25ef4"),
}
GUEST_LIMITS = ("guest_build_seconds", "build_log_bytes", "artifact_bytes", "guest_min_free_bytes")
GUEST_RETIRE_SECONDS = 180
MIN_QEMU_SLACK_SECONDS = 800
# The unchanged owned runtime enforces a 4 GiB RLIMIT_FSIZE ceiling.
LIMITS = K.LIMITS | {"guest_min_free_bytes": (2 * GIB, 8 * GIB)}
DEFAULT_LIMITS = dict(guest_build_seconds=50400, qemu_seconds=51300, build_log_bytes=64 * MIB,
                      artifact_bytes=GIB, overlay_file_bytes=4 * GIB, result_disk_bytes=2 * GIB,
                      report_allocation_bytes=128 * MIB, host_disk_reserve_bytes=2 * GIB,
                      guest_min_free_bytes=2 * GIB, guest_memory_bytes=6 * GIB, actor_memory_bytes=8 * GIB)


def pinned_file(path, pin):
    return C.read(path, pin["bytes"], pin, collect=False)[1]


def limit_shape(limits):
    C.need(type(limits) is dict and limits.keys() == LIMITS.keys()
           and all(type(limits[name]) is int and low <= limits[name] <= high
                   for name, (low, high) in LIMITS.items()), "Unreviewed full-build resource limit")
    inherited_bytes = sum(INHERITED[role]["bytes"] for role in ("core", "dbus", "gui"))
    C.need(limits["qemu_seconds"] >= limits["guest_build_seconds"] + MIN_QEMU_SLACK_SECONDS
           and limits["artifact_bytes"] > inherited_bytes
           and limits["actor_memory_bytes"] >= limits["guest_memory_bytes"] + 2 * GIB
           and limits["guest_memory_bytes"] % MIB == 0
           and limits["result_disk_bytes"] % 4096 == 0
           and limits["result_disk_bytes"] >= limits["artifact_bytes"] + limits["build_log_bytes"] + 16 * MIB,
           "Full-build reserve or retirement budget is insufficient")
    return limits


def guest_plan(nonce, limits):
    C.need(type(nonce) is str and Q.NONCE.fullmatch(nonce), "Exact fresh guest nonce required")
    return dict(kind="QTBASE_FULL16K_GUEST_PLAN_V1", nonce=nonce, target="all",
                limits={name: limits[name] for name in GUEST_LIMITS}, inventory=INVENTORY,
                inherited=INHERITED, dry_run={"gui": DRY_GUI, "all": DRY_ALL}, all_commands=ALL_COMMANDS)


def payload(nonce, limits, source, files):
    guest = K.wire_guest(guest_plan(nonce, limits))
    pieces = {GUEST: guest}
    for name, relative in {
        "guest-init.sh": GUEST_SOURCE + "/full-guest-init.sh",
        "full_guest.py": GUEST_SOURCE + "/full_guest.py",
        "guest_link.py": Q.LANE + "/guest_link.py",
    }.items():
        pieces[name] = C.read(source / relative, 128 * 1024, Q.pin_ref(files[relative]))[0]
    pieces["MANIFEST.sha256"] = P.checksums({name: C.pin(body)["sha256"] for name, body in pieces.items()})
    return pieces


def canonical_plan(nonce, inputs, limits, runner, guest_payload):
    limit_shape(limits)
    Q.runner_shape(runner)
    C.need(C.pin(C.wire(runner)) == RUNNER_PIN, "Exact retained local runner profile required")
    C.need(type(nonce) is str and Q.NONCE.fullmatch(nonce)
           and inputs.keys() == INPUTS and all(C.check_pin(pin, 16 * GIB) and pin["bytes"] > 0
                                                for pin in inputs.values())
           and all(inputs[name] == expected for name, expected in LOWER.items())
           and inputs["boot.raw"]["bytes"] == Q.BOOT_BYTES
           and inputs["result.raw"]["bytes"] == limits["result_disk_bytes"],
           "Exact full-build backing and derivative media shapes required")
    result_uuid = P.result_uuid(nonce)
    seconds = limits["qemu_seconds"]
    pins = {name: C.pin(body) for name, body in guest_payload.items()}
    extra = dict(nonce=nonce, manifest=pins["MANIFEST.sha256"]["sha256"], guest_plan=pins[GUEST]["sha256"],
                 scratch_uuid=K.F.SCRATCH_UUID, result_uuid=result_uuid,
                 result_bytes=limits["result_disk_bytes"], guest_deadline=seconds - GUEST_RETIRE_SECONDS)
    argv = P.vm_argv("/inputs/Image", P.boot_cmdline(nonce, PAYLOAD + "/guest-init.sh") +
                    "".join(f" cachy_qt_full_{key}={value}" for key, value in extra.items()),
                    "qtbase-full-" + nonce, (
                        ("boot", "file=/inputs/boot.raw,format=raw,readonly=on"),
                        ("scratch", "file=/out/overlay.qcow2,format=qcow2,readonly=off,discard=ignore"),
                        ("result", "file=/out/result.raw,format=raw,readonly=off"),
                    ))
    argv[argv.index("-m") + 1] = str(limits["guest_memory_bytes"] // MIB)
    profile = dict(kind=P.TOOL_PROFILE_KIND, actor_image=runner["actor_image"], tools=runner["tools"])
    policy = P.actor_policy(profile, sum(inputs[name]["bytes"] for name in ("Image", "boot.raw", "scratch.raw")))
    out_max = sum(limits[name] for name in ("overlay_file_bytes", "result_disk_bytes", "report_allocation_bytes"))
    policy.update(overlay_create=["/usr/bin/qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
                                  "-b", "/inputs/gui.qcow2", "/out/overlay.qcow2"],
                  result_disk_bytes=limits["result_disk_bytes"],
                  preparation_readonly_logical_bytes=sum(inputs[name]["bytes"] for name in INPUTS - {"result.raw"}),
                  report_allocation_bytes=limits["report_allocation_bytes"],
                  admission_disk_bytes=out_max + limits["host_disk_reserve_bytes"],
                  child_file_size_cap=limits["overlay_file_bytes"],
                  watched_tree=["/out", out_max, limits["host_disk_reserve_bytes"]],
                  watched_paths=[["/out/overlay.qcow2", limits["overlay_file_bytes"]],
                                 ["/out/result.raw", limits["result_disk_bytes"]]])
    return dict(kind="QTBASE_FULL16K_PLAN_UNISSUED_V1", authority=None, nonce=nonce, inputs=inputs,
                qemu_argv=argv, qemu_seconds=seconds, attach_seconds=seconds + 300, limits=limits, actor=policy,
                result_uuid=result_uuid, guest_plan=pins[GUEST], guest_payload=pins, dry_run_receipt=DRY_RUN_RECEIPT)


def source_manifest(root):
    root = T.ordinary(root)
    wanted_dirs = {parent.as_posix() for name in SOURCE_FILES for parent in Path(name).parents}
    C.need(stat.S_IMODE(root.lstat().st_mode) == 0o555, "Private source directory must be readonly")
    observed = {}
    stack = [root]
    while stack:
        directory = stack.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                relative = path.relative_to(root).as_posix()
                mode = stat.S_IMODE(entry.stat(follow_symlinks=False).st_mode)
                if entry.is_dir(follow_symlinks=False):
                    C.need(relative in wanted_dirs and mode == 0o555, "Unexpected source directory")
                    stack.append(path)
                else:
                    C.need(relative in SOURCE_FILES and entry.is_file(follow_symlinks=False) and mode == 0o444,
                           "Unexpected or writable source leaf")
                    observed[relative] = dict(C.read(path, 128 * 1024, collect=False)[1], mode=mode)
    C.need(observed.keys() == SOURCE_FILES, "Incomplete full-build source tree")
    return observed


def verify_source(root, handoff):
    observed = source_manifest(root)
    inherited = {name: observed[name] for name in Q.SOURCE_FILES}
    C.need(observed == handoff["source"], "Exact sealed full-build source tree differs")
    C.need(C.pin(C.wire(inherited))["sha256"] == HISTORICAL_SOURCE,
           "Exact historical runtime sources required")
    C.need(Q.pin_ref(observed[DRY_RUN_SOURCE]) == DRY_RUN_RECEIPT, "Exact observed dry run required")


def verify_inputs(root, plan):
    root = T.ordinary(root)
    C.need(stat.S_IMODE(root.stat().st_mode) == 0o555
           and {item.name for item in root.iterdir()} == INPUTS - {"result.raw"},
           "Expected only exact readonly full-build inputs")
    for name in sorted(INPUTS - {"result.raw"}):
        path = root / name
        C.need(stat.S_IMODE(path.lstat().st_mode) == 0o444, "Readonly input mode differs")
        pinned_file(path, plan["inputs"][name])
    boot_identity(root / "boot.raw", plan["nonce"])
    verify_boot_payload(root / "boot.raw", plan["guest_payload"])
    K.inspect_overlay(root / "gui.qcow2", LOWER["gui.qcow2"], "/inputs/core.qcow2", "qcow2")
    K.inspect_overlay(root / "core.qcow2", LOWER["core.qcow2"], "/inputs/scratch.raw", "raw")


def media_header(path, offset, size):
    before = B.clean_file(path)
    with K.F.open_original(path) as stream:
        header = os.pread(stream.fileno(), size, offset)
        C.need(len(header) == size and C.identity(before) == C.identity(os.fstat(stream.fileno()))
               == C.identity(path.lstat()), "Stable media header required")
    return header


def boot_identity(path, nonce):
    mbr = media_header(path, 0, 512)
    C.need(mbr[440:444] == struct.pack("<I", int(nonce[:8], 16)) and mbr[510:] == b"\x55\xaa"
           and mbr[450] == 0x83 and mbr[462:510] == bytes(48) and
           struct.unpack_from("<II", mbr, 454) == (P.OFFSET // 512, (Q.BOOT_BYTES - P.OFFSET) // 512),
           "Exact fresh boot partition identity required")


def boot_directory(fs, number):
    inode, raw = fs.inode(number)
    C.need(inode["type"] == "directory" and 0 < inode["size"] <= 128 * 1024, "Finite boot directory required")
    data = b"".join(fs.chunks(inode, raw))
    entries, pos = {}, 0
    while pos + 8 <= len(data):
        child, length, count, kind = struct.unpack_from("<IHBB", data, pos)
        C.need(length >= 8 and length % 4 == 0 and length <= len(data) - pos
               and pos % 4096 + length <= 4096 and count <= length - 8, "Bounded boot directory entries required")
        if child:
            name = data[pos + 8:pos + 8 + count]
            C.need(name and b"\0" not in name and b"/" not in name and name not in entries,
                   "Unique ordinary boot entry required")
            entries[name] = (child, kind)
        pos += length
    C.need(pos == len(data), "Incomplete boot directory")
    return inode, entries


def verify_boot_payload(path, pins):
    # Scope the existing ext4 reader to the partition already selected by the MBR.
    frozen = C.pinned_module("qtbase_full_boot_ext4", C.FROZEN, C.FROZEN_PIN)
    original = B.clean_file(path)

    class PartitionOS:
        def __getattr__(self, name):
            return getattr(os, name)

        @staticmethod
        def open(path, flags):
            return os.open(path, flags | os.O_NOATIME | os.O_CLOEXEC)

        @staticmethod
        def fstat(fd):
            info = os.fstat(fd)
            C.need(C.identity(info) == C.identity(original) and info.st_size == Q.BOOT_BYTES,
                   "Exact original boot partition required")
            return SimpleNamespace(st_mode=info.st_mode, st_size=info.st_size - P.OFFSET)

        @staticmethod
        def pread(fd, size, offset):
            return os.pread(fd, size, P.OFFSET + offset)

    frozen.os = PartitionOS()
    with frozen.Ext4Reader(path, max_nodes=16, max_file_bytes=128 * 1024) as fs:
        _, root = boot_directory(fs, 2)
        number, kind = root[PAYLOAD.lstrip("/").encode()]
        node, payload = boot_directory(fs, number)
        C.need(kind == 2 and node["mode"] == 0o755 and node["uid"] == node["gid"] == 0
               and payload.pop(b".") == (number, 2) and payload.pop(b"..") == (2, 2)
               and payload.keys() == {name.encode() for name in pins}, "Exact boot payload namespace required")
        for name, pin in pins.items():
            child, kind = payload[name.encode()]
            node, data = fs.inode(child)
            mode = 0o555 if name == "guest-init.sh" else 0o444
            C.need(kind == 1 and node["type"] == "file" and node["uid"] == node["gid"] == 0
                   and node["mode"] == mode and node["links"] == 1 and node["size"] == pin["bytes"]
                   and C.pin(b"".join(fs.chunks(node, data))) == pin, "Exact original boot payload file required")
        C.need(C.identity(os.fstat(fs.fd)) == C.identity(path.lstat()) == C.identity(original),
               "Boot payload carrier changed during readback")


def unsupplied_selection(handoff, plan, handoff_sha):
    return dict(kind=SELECTION_KIND, issuer=None, approved=None, created_utc=None, expires_utc=None,
                scope=SCOPE, nonce=plan["nonce"], handoff_sha256=handoff_sha,
                plan_sha256=handoff["plan"]["sha256"], actor_image=handoff["runner"]["actor_image"],
                dry_run_receipt=DRY_RUN_RECEIPT)


def verify_selection(raw, digest, handoff, plan, handoff_sha, *, live=True):
    C.need(C.pin(raw)["sha256"] == digest, "Exact independent full-target selection pin required")
    issued = C.json_body(raw, canonical=True)
    start, end = issued["created_utc"], issued["expires_utc"]
    C.need(type(start) is type(end) is int and 0 < end - start <= 3600
           and (not live or start <= int(time.time()) < end), "Fresh full-target Root entry window required")
    expected = unsupplied_selection(handoff, plan, handoff_sha) | dict(
        issuer="Root", approved=True, created_utc=start, expires_utc=end)
    C.need(raw == C.wire(expected), "Selection is outside the full-target scope or plan")
    return issued


def verify_documents(handoff, plan, source):
    C.need(handoff.keys() == {"kind", "authority", "scope", "source", "source_tree_sha256", "runner", "plan"}
           and handoff["kind"] == "QTBASE_FULL16K_HANDOFF_UNISSUED_V1"
           and handoff["authority"] is None and handoff["scope"] == SCOPE
           and handoff["source_tree_sha256"] == C.pin(C.wire(handoff["source"]))["sha256"],
           "Exact unissued full-build handoff required")
    verify_source(source, handoff)
    pieces = payload(plan["nonce"], plan["limits"], source, handoff["source"])
    C.need(C.wire(plan) == C.wire(canonical_plan(plan["nonce"], plan["inputs"], plan["limits"], handoff["runner"], pieces))
           and handoff["plan"] == C.pin(C.wire(plan)), "Full-target plan changed")
    return pieces


def load_capsule(root, handoff_sha):
    root = T.ordinary(root)
    C.need(stat.S_IMODE(root.stat().st_mode) == 0o700, "Private capsule root required")
    handoff = C.json_body(C.external(root / HANDOFF, 64 * 1024, handoff_sha)[0], canonical=True)
    plan = C.json_body(C.read(root / PLAN, 64 * 1024, handoff["plan"])[0], canonical=True)
    pieces = verify_documents(handoff, plan, root / "source")
    C.need(C.read(root / GUEST, 4096, plan["guest_plan"])[0] == pieces[GUEST], "Exact staged guest plan required")
    return handoff, plan


def capacity(path, plan):
    # The existing capacity probe binds statvfs, available RAM, and CPU affinity.
    return Q.capacity(path, plan)


def result_uuid(path, size):
    data = media_header(path, 1024, 1024)
    C.need(path.lstat().st_size == size and data[56:58] == b"\x53\xef"
           and data[120:136].rstrip(b"\0") == b"QT16K_FULL"
           and struct.unpack_from("<I", data, 24)[0] == 2 and struct.unpack_from("<I", data, 336)[0] == 0
           and not struct.unpack_from("<I", data, 92)[0] & 0x1000
           and struct.unpack_from("<I", data, 4)[0] * 4096 == size, "Exact full-build result ext4 required")
    return str(UUID(bytes=data[104:120]))


def verify_result_template(path, plan):
    pin = plan["inputs"]["result.raw"]
    original = B.clean_file(path)
    pinned_file(path, pin)
    C.need(result_uuid(path, pin["bytes"]) == plan["result_uuid"], "Result template UUID differs")
    with C.ext4_reader()(path, max_nodes=2, max_file_bytes=64 * 1024) as fs:
        sb = fs.read(1024, 1024)
        C.need(struct.unpack_from("<H", sb, 58)[0] == 1 and not fs.incompat & 4
               and fs.uuid == plan["result_uuid"], "Clean result template required")
        nodes = fs.inventory()["nodes"]
    C.need(nodes.keys() == {".", "lost+found"} and all(
        node["type"] == "directory" and node["uid"] == node["gid"] == 0 and not node["xattrs"]
        and node["mode"] == (0o755 if name == "." else 0o700) for name, node in nodes.items())
        and C.identity(path.lstat()) == C.identity(original), "Fresh stable result template required")


def terminal(serial, nonce):
    C.need(type(nonce) is str and Q.NONCE.fullmatch(nonce), "Exact full-target guest nonce required")
    prefix = b"QTBASE_FULL16K_TERMINAL "
    rows = [row for row in serial.splitlines() if row.startswith(prefix)]
    C.need(len(rows) == 1, "Expected one full-target terminal")
    found = re.fullmatch(prefix + nonce.encode() + rb" (PASS|HOLD) ([a-z][a-z0-9_-]{0,31})", rows[0])
    C.need(found is not None and
           (found[2] == b"complete" if found[1] == b"PASS"
            else found[2] in {b"boot", b"storage", b"build", b"retain", b"cleanup"}),
           "Full-target guest terminal differs")
    return found[1] == b"PASS", found[2].decode()


def validate_chain(raw, sizes):
    def distinct(items):
        obj = dict(items)
        C.need(len(obj) == len(items), "Duplicate image-chain key")
        return obj

    C.need(0 < len(raw) <= 16 * 1024, "Finite QEMU chain metadata required")
    def reject_constant(_):
        raise ValueError("Nonfinite image-chain value")

    nodes = json.loads(raw, object_pairs_hook=distinct, parse_constant=reject_constant)
    paths = ("/out/overlay.qcow2", "/inputs/gui.qcow2", "/inputs/core.qcow2", "/inputs/scratch.raw")
    C.need(type(nodes) is list and len(nodes) == len(paths), "Expected exact four-node full-build chain")
    for index, (row, path) in enumerate(zip(nodes, paths, strict=True)):
        eof = sizes[Path(path).name]
        cap = (MIB, 4 * GIB, 4 * GIB, 16 * GIB)[index]
        C.need(type(row) is dict and type(eof) is int and 0 < eof <= cap, "Finite chain node required")
        allocated = row.get("actual-size")
        C.need(type(allocated) is int and 0 < allocated <= cap and allocated % 512 == 0,
               "Bounded sector-aligned chain node required")
        leaf = {"filename": path, "format": "file", "actual-size": allocated,
                "virtual-size": (eof + 511) // 512 * 512, "children": [], "dirty-flag": False,
                "format-specific": {"type": "file", "data": {}}}
        expected = {"filename": path, "format": "qcow2" if index < 3 else "raw",
                    "actual-size": allocated, "virtual-size": 16 * GIB,
                    "children": [{"name": "file", "info": leaf}], "dirty-flag": False}
        if index < 3:
            expected.update({"backing-filename": paths[index + 1], "full-backing-filename": paths[index + 1],
                             "backing-filename-format": "qcow2" if index < 2 else "raw", "cluster-size": 65536,
                             "format-specific": {"type": "qcow2", "data": {"compat": "1.1", "compression-type": "zlib",
                                 "lazy-refcounts": False, "refcount-bits": 16, "corrupt": False, "extended-l2": False}}})
        C.need(C.wire(row) == C.wire(expected), "Full-build chain role or geometry differs")


def preflight(root, handoff_sha):
    handoff, plan = load_capsule(root, handoff_sha)
    C.need(C.read(root / "binding.UNISSUED.json", 16 * 1024)[0] ==
           C.wire(unsupplied_selection(handoff, plan, handoff_sha)), "Exact unissued admission binding required")
    live = capacity(root, plan)
    C.need(live["fits"], "Full-build host admission limits are unmet")
    verify_inputs(root / "inputs", plan)
    template = root / "templates" / "result.raw"
    C.need({node.name for node in T.ordinary(template.parent).iterdir()} == {"result.raw"}
           and stat.S_IMODE(template.parent.stat().st_mode) == 0o555
           and stat.S_IMODE(template.lstat().st_mode) == 0o444, "Exact readonly result template required")
    verify_result_template(template, plan)
    return dict(status="PASS_PASSIVE_FULL_BUILD_PREFLIGHT_ONLY", authority=None, capacity=live,
                handoff_sha256=handoff_sha, plan=handoff["plan"], full_build="NOT RUN")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capsule", required=True, type=Path)
    parser.add_argument("--handoff-sha256", required=True)
    args = parser.parse_args()
    sys.addaudithook(C.audit_fence)
    try:
        sys.stdout.buffer.write(C.wire(preflight(args.capsule, args.handoff_sha256)))
    except (ValueError, OSError, KeyError, TypeError):
        sys.exit("Full Qtbase passive admission refused")


if __name__ == "__main__":
    main()
