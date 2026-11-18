# SPDX-License-Identifier: MIT
"""Independently read a retired QtCore link attempt's original result bytes."""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
from runpy import run_path
import stat
import struct
import sys
import types


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
FROZEN = HERE.parent / "arm16k_perl5423_vm/frozen/independent_readback.py"
FROZEN_PIN = (13913, "8fb8c2c32dc5a40998bf31cc5727768f88ce51e423b7090cfb702116bdc9b5d3")
CHECKER = REPO / "packages/port/qt612-gui-server-source-reference/check_stage.py"
CHECKER_PIN = (22362, "35f410bf60af41f677f7a36d58cc5079ecf57dfde2b84f29dc1b006a4bf7f0da")
KIB, MIB, GIB = 1 << 10, 1 << 20, 1 << 30
RESULT_BYTES = 64 * MIB
ELF_NAME = "libQt6Core.so.6.12.0"
SONAME = "libQt6Core.so.6"
CORE_INTERPRETER = "/lib/ld-linux-aarch64.so.1"
CORE_ENTRY_SYMBOL = b"qt_core_boilerplate\0"
PROGRAM_HEADER = struct.Struct("<II6Q")
SECTION_HEADER = struct.Struct("<II4QII2Q")
SYMBOL = struct.Struct("<IBBHQQ")
GUEST_BUILD_SECONDS = 6900
CORE_COMMANDS = (671480, "1836d53ff5aa42d6d115b8c5301938ccccdd8e3d1fffc29e52d524e44a701769")
INVENTORY = (6925, "e2a4da7903e6de26b0ee37758ad424439f83196fa6a3b0bdffa501f35a02d0b9")
ALIASES = b"libQt6Core.so -> libQt6Core.so.6\nlibQt6Core.so.6 -> libQt6Core.so.6.12.0\n"
EVIDENCE_CAPS = {"result.json": 4096, "metrics.json": 4096, "build.log": 8 * MIB,
                 "core.commands": CORE_COMMANDS[0], ELF_NAME: 48 * MIB, "aliases.txt": 256,
                 "inventory.before": 32 * KIB, "inventory.after": 32 * KIB}
SHA = re.compile("[a-f0-9]{64}")
NONCE = re.compile("[a-f0-9]{32}")
ACTOR_PASS = "PASS_QTCORE_LINK_FOR_ROOT_REVIEW"
SITE_SCOPE = "cachy-asahi-qtbase16k-qtcore-link.scope"
ACTOR_KEYS = set((
    "kind status phase nonce authority_sha256 handoff_sha256 plan_sha256 tools watched_tree watched_paths "
    "capacity_before capacity_after allocation qemu serial fsck_result overlay_create overlay_inspect "
    "overlay_inspect_stdout overlay_initial_eof result_disk overlay result_uuid native_Qt_full_build physical_M2 "
    "Root_acceptance host_cgroup_memory_peak_bytes"
).split())


def need(condition, message):
    if not condition:
        raise ValueError(message)


def pin(body):
    return file_pin(len(body), hashlib.sha256(body).hexdigest())


def file_pin(size, digest):
    return dict(bytes=size, sha256=digest)


def check_pin(value, cap):
    return (type(value) is dict and set(value) == {"bytes", "sha256"} and type(value["bytes"]) is int
            and 0 <= value["bytes"] <= cap and type(value["sha256"]) is str and SHA.fullmatch(value["sha256"]))


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
            info.st_size, info.st_atime_ns, info.st_mtime_ns, info.st_ctime_ns)


def read(path, cap, expected=None, *, collect=True):
    need(path.is_absolute() and path.resolve(strict=True) == path, f"Canonical read-only path required: {path}")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOATIME
    with os.fdopen(os.open(path, flags), "rb") as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= cap,
             f"Finite ordinary single-link file required: {path.name}")
        body = stream.read(before.st_size + 1) if collect else None
        observed = (pin(body) if collect else file_pin(before.st_size, hashlib.file_digest(stream, "sha256").hexdigest()))
        need(observed["bytes"] == before.st_size
             and identity(before) == identity(os.fstat(stream.fileno())) == identity(path.lstat()),
             f"Original bytes or metadata changed while reading: {path.name}")
    if expected is not None:
        need(check_pin(expected, cap) and observed == expected, f"Exact original file pin required: {path.name}")
    return body, observed


def external(path, cap, digest):
    need(type(digest) is str and SHA.fullmatch(digest), "External exact SHA-256 required")
    raw, observed = read(path, cap)
    need(observed["sha256"] == digest, f"External digest differs: {path.name}")
    return raw, observed


def json_body(body, *, canonical=False):
    def unique(items):
        obj = dict(items)
        need(len(obj) == len(items), "Duplicate JSON evidence field")
        return obj

    def constant(_):
        raise ValueError("Nonfinite JSON evidence number")

    value = json.loads(body, object_pairs_hook=unique, parse_constant=constant)
    need(type(value) is dict and (not canonical or body == wire(value)), "Expected exact JSON evidence object")
    return value


def wire(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def audit_fence(event, args):
    need(not event.startswith(("subprocess.", "socket.", "ctypes.", "shutil."))
         and event not in {"os.system", "os.exec", "os.fork", "os.forkpty", "os.posix_spawn", "os.kill", "os.killpg",
                           "os.mkdir", "os.rmdir", "os.remove", "os.rename", "os.link", "os.symlink", "os.chmod",
                           "os.chown", "os.truncate", "os.setxattr", "os.removexattr", "fcntl.flock", "fcntl.ioctl"},
         "Independent reader cannot invoke an actor, use the network or mutate files")
    if event == "open":
        _, mode, flags = args
        write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
        need((mode is None or not any(char in mode for char in "wax+")) and
             (flags is None or not flags & write_flags), "Independent reader can only open read-only files")


def pinned_module(name, path, pair):
    raw, _ = read(path, pair[0], file_pin(*pair))
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def ext4_reader():
    frozen = pinned_module("qtcore_frozen_ext4", FROZEN, FROZEN_PIN)

    class ReadOnlyOS:
        def __getattr__(self, name):
            return getattr(os, name)

        @staticmethod
        def open(path, flags):
            return os.open(path, flags | os.O_NOATIME | os.O_CLOEXEC)

    frozen.os = ReadOnlyOS()
    return frozen.Ext4Reader


def result_files(disk, disk_pin, uuid, passed):
    _, original = read(disk, RESULT_BYTES, disk_pin, collect=False)
    need(original["bytes"] == RESULT_BYTES, "Exact 64 MiB QtCore result disk required")
    identity_before = identity(disk.lstat())
    with ext4_reader()(disk, max_nodes=len(EVIDENCE_CAPS) + 3, max_file_bytes=max(EVIDENCE_CAPS.values())) as fs:
        sb = fs.read(1024, 1024)
        need(struct.unpack_from("<HH", sb, 56) == (0xEF53, 1) and not fs.incompat & 4
             and sb[120:136] == b"QT16K_CORE".ljust(16, b"\0") and fs.uuid == uuid,
             "Exact clean QtCore ext4 result with sealed UUID and label required")
        nodes = fs.inventory()["nodes"]
        fixed = {".", "lost+found"}
        folders = fixed | {"evidence"}
        leaves = set(nodes) - folders
        names = {leaf.removeprefix("evidence/") for leaf in leaves}
        need(fixed <= nodes.keys() and (not leaves or "evidence" in nodes)
             and names <= EVIDENCE_CAPS.keys() and leaves == {"evidence/" + name for name in names}
             and (not passed or names == EVIDENCE_CAPS.keys()), "Exact bounded QtCore result namespace required")
        for name in folders & nodes.keys():
            row = nodes[name]
            need(row["type"] == "directory" and row["uid"] == row["gid"] == 0
                 and row["mode"] == (0o755 if name == "." else 0o700) and not row["xattrs"],
                 f"Unexpected QtCore result directory metadata: {name}")
        files = {}
        for name in sorted(names):
            row = nodes["evidence/" + name]
            need(row["type"] == "file" and row["links"] == 1 and row["mode"] == 0o600
                 and row["uid"] == row["gid"] == 0 and not row["xattrs"]
                 and (1 if passed else 0) <= row["size"] <= EVIDENCE_CAPS[name],
                 f"Unexpected QtCore result file metadata: {name}")
            inode, raw = fs.inode(row["inode"])
            body = b"".join(fs.chunks(inode, raw))
            need(pin(body) == file_pin(row["size"], row["sha256"]), f"QtCore ext4 leaf changed: {name}")
            files[name] = body
    read(disk, RESULT_BYTES, original, collect=False)
    need(identity(disk.lstat()) == identity_before, "QtCore result identity changed across ext4 readback")
    return files


def serial_state(body, nonce):
    need(type(nonce) is str and NONCE.fullmatch(nonce), "Exact attempt nonce required")
    markers = [line for line in body.splitlines() if line.startswith(b"QTCORE_LINK_TERMINAL")]
    need(len(markers) == 1, "Exactly one QtCore terminal marker required")
    match = re.fullmatch(rb"QTCORE_LINK_TERMINAL " + nonce.encode() +
                         rb" (PASS complete|HOLD [a-z][a-z0-9_-]{0,31})", markers[0])
    need(match is not None, "QtCore terminal marker must select the original attempt")
    status, phase = match[1].decode().split()
    return status, phase


def verify_core_entry(body, interpreter, segments):
    """Verify the entry point of QtCore's intentionally executable shared library."""
    if interpreter is None:
        return
    need(interpreter == CORE_INTERPRETER, "Unexpected QtCore ELF interpreter")
    entry = struct.unpack_from("<Q", body, 24)[0]
    need(entry > 0 and entry % 4 == 0, "Expected aligned AArch64 QtCore entry point")
    (_, interp_flags, interp_offset, interp_address, _, interp_size, interp_mem, _), = (
        segment for segment in segments if segment[0] == 3)
    loads = [segment for segment in segments if segment[0] == 1]

    def mapped_offset(address, size, flags):
        matches = [(actual, offset + address - virtual) for _, actual, offset, virtual, _, extent, _, _ in loads
                   if size > 0 and virtual <= address and address + size <= virtual + extent]
        need(len(matches) == 1 and matches[0][0] & flags == flags,
             "QtCore entry metadata outside one file-backed segment with the required permissions")
        return matches[0][1]

    need(interp_flags == 4 and interp_size == interp_mem
         and mapped_offset(interp_address, interp_size, 4) == interp_offset,
         "QtCore interpreter must be read-only and file-backed")

    start = struct.unpack_from("<Q", body, 40)[0]
    entry_size, count = struct.unpack_from("<HH", body, 58)
    need(entry_size == SECTION_HEADER.size and 1 <= count <= 4096 and start >= 64
         and start + entry_size * count <= len(body), "Bounded QtCore ELF section headers required")
    sections = [SECTION_HEADER.unpack_from(body, start + i * entry_size) for i in range(count)]
    tables = [row for row in sections if row[1] == 2]
    need(len(tables) == 1, "Exactly one QtCore static symbol table required")
    _, _, _, _, offset, size, str_index, local_count, _, symbol_size = tables[0]
    need(symbol_size == SYMBOL.size and size % SYMBOL.size == 0
         and 1 < local_count <= size // SYMBOL.size <= 1 << 20 and 0 < str_index < count
         and offset >= 64 and offset + size <= len(body),
         "Bounded QtCore static symbol table required")
    _, kind, _, _, str_offset, str_size, *_ = sections[str_index]
    need(kind == 3 and str_offset >= 64 and 0 < str_size <= len(body) - str_offset
         and (offset + size <= str_offset or str_offset + str_size <= offset)
         and body[str_offset] == 0, "Bounded QtCore static string table required")
    matches = []
    for index, (name, info, other, section, address, length) in enumerate(
            SYMBOL.iter_unpack(memoryview(body)[offset:offset + size])):
        need(name < str_size, "QtCore symbol name outside string table")
        name_end = name + len(CORE_ENTRY_SYMBOL)
        if name_end <= str_size and body[str_offset + name:str_offset + name_end] == CORE_ENTRY_SYMBOL:
            matches.append((index, info, other, section, address, length))
    need(len(matches) == 1, "Exactly one QtCore qt_core_boilerplate symbol required")
    index, info, other, section, address, length = matches[0]
    need(0 < index < local_count and info == 2 and other == 0 and 0 < section < count
         and address == entry and length > 0, "QtCore entry must select its local qt_core_boilerplate function")
    _, kind, flags, virtual, file_at, extent, *_ = sections[section]
    need(kind == 1 and flags & 7 == 6 and virtual <= entry and entry + length <= virtual + extent
         and mapped_offset(entry, length, 1) == file_at + entry - virtual,
         "QtCore entry function must reside in an executable file-backed section")


def linked_core(body):
    checker = pinned_module("qtcore_family_elf_parser", CHECKER, CHECKER_PIN)
    dynamic = checker.elf_info(body)
    need(dynamic["type"] == 3 and dynamic["machine"] == 183 and dynamic["soname"] == SONAME
         and dynamic["geometry_16k"] is True,
         "Expected an AArch64 QtCore shared ELF with the exact SONAME and 16 KiB load geometry")
    phoff = struct.unpack_from("<Q", body, 32)[0]
    phnum = struct.unpack_from("<H", body, 56)[0]
    segments = [PROGRAM_HEADER.unpack_from(body, phoff + PROGRAM_HEADER.size * n) for n in range(phnum)]
    need(any(kind == 1 and flags & 1 and size != 0
             for kind, flags, _, _, _, size, _, _ in segments),
         "QtCore shared ELF must contain an executable file-backed load segment")
    verify_core_entry(body, dynamic["interpreter"], segments)
    return dict(bytes=pin(body), soname=dynamic["soname"], architecture="aarch64", type="ET_DYN",
                geometry_16k=dynamic["geometry_16k"], load_segments=dynamic["load_segments"],
                needed=dynamic["needed"])


def guest_facts(files, nonce, status, phase, manifest_sha):
    outcome = files.get("result.json")
    if outcome is not None:
        expected = dict(kind="QTCORE_LINK_RESULT_V1", status=status, phase=phase, nonce=nonce,
                        plan_sha256=manifest_sha, architecture="aarch64", page_size=16384, uid=1000, gid=1000)
        need(wire(json_body(outcome)) == wire(expected) and outcome.endswith(b"\n"),
             "Raw QtCore guest outcome differs from the original guest payload and serial")
    metrics = None
    if "metrics.json" in files:
        metrics = json_body(files["metrics.json"])
        need(set(metrics) == {"compile_exit", "elapsed_ms", "peak_child_rss_kib", "log_complete"}
             and all(type(metrics[key]) is int for key in ("compile_exit", "elapsed_ms", "peak_child_rss_kib"))
             and -255 <= metrics["compile_exit"] <= 255 and 0 <= metrics["elapsed_ms"] <= 7_200_000
             and 0 <= metrics["peak_child_rss_kib"] <= 4 * GIB // KIB
             and type(metrics["log_complete"]) is bool and files["metrics.json"].endswith(b"\n"),
             "Invalid bounded QtCore compile metrics")
    if status == "HOLD":
        return None, metrics
    need(files.keys() == EVIDENCE_CAPS.keys() and bool(outcome), "Missing exact original QtCore PASS evidence")
    need(bool(metrics) and metrics["compile_exit"] == 0 and metrics["log_complete"] is True
         and 0 < metrics["elapsed_ms"] <= GUEST_BUILD_SECONDS * 1000 and metrics["peak_child_rss_kib"] > 0,
         "QtCore PASS requires a successful bounded compile and complete log")
    need(pin(files["core.commands"]) == file_pin(*CORE_COMMANDS), "Exact Q3 QtCore command closure required")
    for name in ("inventory.before", "inventory.after"):
        need(pin(files[name]) == file_pin(*INVENTORY) and files[name].count(b"\n") == 356,
             "Exact 356-package Q3 inventory required before and after the QtCore link")
    need(files["aliases.txt"] == ALIASES, "Expected the exact QtCore SONAME/development symlink chain")
    log_lines = files["build.log"].splitlines()
    link = re.compile(rb"\[[0-9]+/[0-9]+\] Linking CXX shared library lib/libQt6Core\.so\.6\.12\.0")
    symlink = re.compile(rb"\[[0-9]+/[0-9]+\] Creating library symlink lib/libQt6Core\.so\.6 lib/libQt6Core\.so")
    linked = [index for index, line in enumerate(log_lines) if link.fullmatch(line)]
    aliased = [index for index, line in enumerate(log_lines) if symlink.fullmatch(line)]
    need(len(linked) == len(aliased) == 1 and linked[0] < aliased[0],
         "Whole build log must contain the real QtCore link and symlink steps in order")
    return linked_core(files[ELF_NAME]), metrics


def command_receipt(output, label, expected, argv, seconds, size_cap, stream_cap):
    need(check_pin(expected, 128 * KIB), f"Missing exact owned-command pin: {label}")
    raw, receipt_pin = read(output / (label + ".json"), 128 * KIB, expected)
    row = json_body(raw, canonical=True)
    need(row["argv"] == argv and type(row["exit"]) is int and row["exit"] == 0 and
         row["ownership"] == "REAPED" and row["group_census"] == "EMPTY_TWICE" and
         row["passed"] is row["reaped"] is row["output_complete"] is True and
         row["timeout"] is row["command_timed_out"] is row["original_budget_overrun"] is
         row["emergency_retirement"] is False and row["emergency_retirement_cap_seconds"] is None and
         row["signals"] == row["command_cancelled"] == [] and row["error"] is None and
         all(type(row[key]) in (float, int) and math.isfinite(row[key])
             for key in ("operation_seconds", "operation_cap_seconds")) and
         0 < row["operation_seconds"] <= row["operation_cap_seconds"] <= seconds and
         type(row["child_file_size_cap"]) is type(size_cap) and row["child_file_size_cap"] == size_cap,
         f"Exact natural owned command retirement required: {label}")
    stdout, stdout_pin = read(output / (label + ".stdout"), stream_cap)
    stderr, stderr_pin = read(output / (label + ".stderr"), stream_cap)
    need(len(stdout) + len(stderr) <= stream_cap, f"Combined command streams exceeded their cap: {label}")
    _, log_pin = read(output / (label + ".log"), stream_cap, pin(stdout + stderr))
    return dict(receipt=receipt_pin, stdout=stdout_pin, stderr=stderr_pin, log=log_pin,
                elapsed_seconds=row["operation_seconds"]), stdout


def capacity(row, policy, *, admission):
    measurements = ("free_bytes", "memory_available_bytes", "allowed_cpus")
    minima = ("required_bytes", "minimum_memory_bytes", "minimum_cpus")
    need(set(row) == set(measurements + minima) | {"fits"} and
         all(type(row[key]) is int and row[key] >= 0 for key in measurements + minima) and
         tuple(row[key] for key in minima) == (policy["admission_disk_bytes"], 8 * GIB, 4) and
         row["fits"] is all(row[key] >= row[minimum] for key, minimum in zip(measurements, minima, strict=True)) and
         (row["fits"] if admission else row["free_bytes"] >= policy["watched_tree"][2]),
         "Exact live QtCore capacity record required")


def check_watch(rows, policy, overlay_bytes):
    caps = {"tree_allocated": policy["watched_tree"][1],
            "overlay_allocated": policy["watched_paths"][0][1], "overlay_eof": policy["child_file_size_cap"],
            "result_allocated": policy["result_disk_bytes"]}
    need(set(rows) == {"before", "after", "peak", "samples"} and
         type(rows["samples"]) is int and 2 <= rows["samples"] <= 100000,
         "Finite owned allocation samples required")
    for phase in ("before", "after", "peak"):
        row = rows[phase]
        need(row.keys() == caps.keys() | {"free"} and
             all(type(row[key]) is int and 0 <= row[key] <= limit for key, limit in caps.items()) and
             type(row["free"]) is int and row["free"] >= policy["watched_tree"][2] and
             row["tree_allocated"] >= max(row["overlay_allocated"], row["result_allocated"]),
             f"Owned allocation or reserve sample exceeds the reviewed bound: {phase}")
    start, end, peak = (rows[phase] for phase in ("before", "after", "peak"))
    need(start["overlay_allocated"] == start["overlay_eof"] == 0 and
         all(peak[key] >= max(start[key], end[key]) for key in caps) and
         peak["free"] <= min(start["free"], end["free"]) and end["overlay_eof"] == overlay_bytes and
         end["overlay_allocated"] > 0 and start["result_allocated"] > 0 and end["result_allocated"] > 0,
         "Owned allocation extrema differ from the initial and final carriers")


def verify_actor(output, plan, plan_sha, report_sha, validate_overlay, *, handoff_sha=None, authority_sha=None):
    need(output.is_absolute() and output == output.resolve(strict=True) and output.is_dir(),
         "Ordinary original output directory required")
    policy = plan["actor"]
    stream_cap = policy["serial_combined_cap"]
    phases = (
        ("overlay-create", "overlay_create", policy["overlay_create"], 10, None),
        ("overlay-inspect", "overlay_inspect", policy["overlay_inspect"], 10, None),
        ("qemu", "qemu", plan["qemu_argv"], plan["qemu_seconds"], policy["child_file_size_cap"]),
        ("fsck-result", "fsck_result", ["/usr/bin/e2fsck", "-fn", "/out/result.raw"], 60, None),
    )
    expected_files = {"actor-result.json", "result.raw", "overlay.qcow2"} | {
        label + suffix for label, *_ in phases for suffix in (".json", ".stdout", ".stderr", ".log")}
    need({path.name for path in output.iterdir()} == expected_files,
         "Complete actor receipt requires the exact original output namespace")
    report_raw, report_pin = external(output / "actor-result.json", 16 * KIB, report_sha)
    report = json_body(report_raw, canonical=True)
    need(report.keys() == ACTOR_KEYS and report["kind"] == "QTCORE_LINK_ACTOR_RESULT_V1" and
         report["nonce"] == plan["nonce"] and report["plan_sha256"] == plan_sha and
         all(type(report[key]) is str and SHA.fullmatch(report[key]) for key in
             ("authority_sha256", "handoff_sha256", "plan_sha256")) and
         (handoff_sha is None or report["handoff_sha256"] == handoff_sha) and
         (authority_sha is None or report["authority_sha256"] == authority_sha) and
         report["result_uuid"] == plan["result_uuid"] and report["tools"] == policy["profile"]["tools"] and
         report["watched_tree"] == policy["watched_tree"] and report["watched_paths"] == policy["watched_paths"] and
         report["native_Qt_full_build"] == report["physical_M2"] == "NOT_RUN" and report["Root_acceptance"] is None,
         "Actor record does not match the exact sealed attempt and owned limits")
    peak = report["host_cgroup_memory_peak_bytes"]
    need(peak is None or (type(peak) is int and 0 < peak <= 6 * GIB), "Finite actor cgroup memory peak required")
    capacity(report["capacity_before"], policy, admission=True)
    capacity(report["capacity_after"], policy, admission=False)
    _, overlay_pin = read(output / "overlay.qcow2", policy["child_file_size_cap"], report["overlay"], collect=False)
    check_watch(report["allocation"], policy, overlay_pin["bytes"])
    commands = {}
    output_streams = {}
    for label, field, argv, seconds, size_cap in phases:
        commands[label], output_streams[label] = command_receipt(
            output, label, report[field], argv, seconds, size_cap, stream_cap)
    need(commands["overlay-inspect"]["stdout"] == report["overlay_inspect_stdout"],
         "Initial overlay inspection stdout differs from the actor receipt")
    validate_overlay(output_streams["overlay-inspect"], report["overlay_initial_eof"])
    need(commands["qemu"]["stdout"] == report["serial"], "Original serial bytes differ from the actor receipt")
    guest_status, phase = serial_state(output_streams["qemu"], plan["nonce"])
    passed = guest_status == "PASS"
    need(report["status"] == (ACTOR_PASS if passed else "HOLD") and report["phase"] == phase,
         "Actor outcome differs from the original guest terminal marker")
    need(not passed or report["result_disk"] != plan["inputs"]["result.raw"],
         "QtCore PASS cannot use the unchanged result template")
    files = result_files(output / "result.raw", report["result_disk"], plan["result_uuid"], passed)
    elf, metrics = guest_facts(files, plan["nonce"], guest_status, phase, plan["guest_payload"]["MANIFEST.sha256"])
    return dict(status="PASS_EXACT_QTCORE_LINK_ONLY" if passed else "HOLD", phase=phase, nonce=plan["nonce"],
                actor_result=report_pin, commands=commands, elf=elf, metrics=metrics, overlay=overlay_pin,
                result_disk=report["result_disk"], result_uuid=report["result_uuid"],
                allocation=report["allocation"], host_cgroup_memory_peak_bytes=peak,
                evidence={key: pin(body) for key, body in files.items()},
                handoff_sha256=report["handoff_sha256"], authority_sha256=report["authority_sha256"],
                native_Qt_full_build="NOT_RUN", physical_M2="NOT_RUN", Root_acceptance=None)


def verify_host_scope(output, closure_path, closure_sha, plan_sha, checks, *, incomplete=False):
    attempt = output.parent
    need(output.name == "output" and re.fullmatch(r"issued\.[A-Za-z0-9_]+", attempt.name)
         and stat.S_IMODE(attempt.stat().st_mode) == 0o700, "Exact once-claimed site attempt required")
    raw, closure_pin = external(closure_path, 32 * KIB, closure_sha)
    closure = json_body(raw, canonical=True)
    cid, group = closure["cid"], closure["scope_group"]
    need(type(cid) is str and SHA.fullmatch(cid) and type(group) is str
         and 0 < len(group) <= 1023 and re.fullmatch(r"(?:/[A-Za-z0-9_.@-]+)+", group)
         and group.endswith("/" + SITE_SCOPE), "Exact retired site container and scope required")
    identity_fields = dict(nonce=checks["nonce"], scope=SITE_SCOPE, scope_group=group, cid=cid,
                           authority_sha256=checks["authority_sha256"], handoff_sha256=checks["handoff_sha256"],
                           plan_sha256=plan_sha)
    need(raw == wire(dict(kind="QTCORE_LINK_POST_SCOPE_V1", **identity_fields, host_result=closure["host_result"],
                          observations=[dict(scope_absent=True, container_absent=True)] * 2)),
         "Post-scope closure differs from the retired original actor attempt")
    body, host_pin = read(attempt / "host-result.json", 32 * KIB, closure["host_result"])
    if incomplete:
        exit_code = json_body(body)["exit_code"]
        need(type(exit_code) is int and 0 < exit_code < 124,
             "An incomplete actor requires an original natural nonzero site exit")
    else:
        exit_code = 0 if checks["status"] == "PASS_EXACT_QTCORE_LINK_ONLY" else 2
    need(body == wire(dict(kind="QTCORE_LINK_HOST_RETIREMENT_V1", **identity_fields, natural=True,
                           exit_code=exit_code, container_removed=True, absent_twice=True)),
         "Site retirement differs from independently observed actor/guest status")
    for path, expected in (
        (attempt.parent / "root-run.claim/attempt.path", (str(attempt) + "\n").encode()),
        (attempt / "run.cid", cid.encode()),
        (attempt / "scope.path", (group + "\n").encode()),
        (attempt / "run.attach-exit", f"{exit_code}\n".encode()),
        (attempt / "run.absence-1", b""),
        (attempt / "run.absence-2", b""),
    ):
        raw, _ = read(path, 4096)
        need(raw in ((expected, expected + b"\n") if path.name == "run.cid" else (expected,)),
             f"Exact original site retirement leaf required: {path.name}")
    return dict(closure=closure_pin, host_result=host_pin, scope=SITE_SCOPE, scope_group=group, cid=cid,
                exit_code=exit_code)


def incomplete_actor(output, plan_path, plan, plan_sha, capsule, handoff_sha, authority_sha, post_scope, post_sha):
    need(output.is_absolute() and output == output.resolve(strict=True) and output.is_dir(),
         "Ordinary original output directory required")
    root = output.parent.parent
    need(plan_path == root / capsule["PLAN_LEAF"], "Incomplete readback requires the original staged plan path")
    checks = dict(status="HOLD_NO_COMPLETE_ACTOR_REPORT", nonce=plan["nonce"],
                  handoff_sha256=handoff_sha, authority_sha256=authority_sha)
    host = verify_host_scope(output, post_scope, post_sha, plan_sha, checks, incomplete=True)
    _, plan_pin = external(plan_path, 32 * KIB, plan_sha)
    handoff = capsule["load_handoff"](root / capsule["HANDOFF_LEAF"], handoff_sha)
    need(handoff["plan"] == plan_pin, "Exact site handoff must bind the original staged plan")
    selection, _ = external(output.parent / "selection.json", 128 * KIB, authority_sha)
    capsule["verify_selection"](selection, authority_sha, handoff, plan, handoff_sha, live=False)
    policy = plan["actor"]
    cap = {"result.raw": RESULT_BYTES, "overlay.qcow2": policy["child_file_size_cap"]}
    for label in ("overlay-create", "overlay-inspect", "qemu", "fsck-result"):
        for suffix in ("json", "stdout", "stderr", "log"):
            cap[label + "." + suffix] = 128 * KIB if suffix == "json" else policy["serial_combined_cap"]
    names = {path.name for path in output.iterdir()}
    need(names <= cap.keys(), "Incomplete actor output must contain only bounded original diagnostics")
    diagnostics = {name: read(output / name, cap[name], collect=False)[1] for name in sorted(names)}
    need({path.name for path in output.iterdir()} == names, "Incomplete actor output changed during readback")
    capsule["verify_source"](handoff, root / "source")
    read(plan_path, 32 * KIB, plan_pin, collect=False)
    return dict(kind="QTCORE_LINK_INDEPENDENT_READBACK_V1", plan_sha256=plan_sha, post_scope=host,
                evidence=diagnostics, native_Qt_full_build="NOT_RUN", physical_M2="NOT_RUN", Root_acceptance=None,
                **checks)


def result(output, plan_path, plan_sha, report_sha, *, handoff_sha=None, authority_sha=None,
           post_scope=None, post_scope_sha=None):
    need(sys.flags.isolated and sys.dont_write_bytecode and __debug__, "Isolated nonoptimized readback required")
    need((handoff_sha is None) == (authority_sha is None) and
         (post_scope is None) == (post_scope_sha is None) and (post_scope is None or handoff_sha is not None),
         "Submit paired handoff/authority and post-scope selections")
    if handoff_sha is not None:
        need(SHA.fullmatch(handoff_sha) and SHA.fullmatch(authority_sha), "Exact handoff and authority digests required")
    sys.addaudithook(audit_fence)
    capsule = run_path(str(HERE / "capsule.py"))
    plan = capsule["load_plan"](plan_path, plan_sha)
    if report_sha is None:
        need(post_scope is not None, "Omitting the actor-result digest requires exact post-scope, handoff and authority")
        return incomplete_actor(output, plan_path, plan, plan_sha, capsule, handoff_sha, authority_sha,
                                post_scope, post_scope_sha)
    checks = verify_actor(output, plan, plan_sha, report_sha, capsule["B"].P.validate_empty_overlay,
                          handoff_sha=handoff_sha, authority_sha=authority_sha)
    host = verify_host_scope(output, post_scope, post_scope_sha, plan_sha, checks) if post_scope else None
    return dict(kind="QTCORE_LINK_INDEPENDENT_READBACK_V1", plan_sha256=plan_sha, post_scope=host, **checks)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("output", "plan"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--actor-result-sha256")
    parser.add_argument("--handoff-sha256")
    parser.add_argument("--authority-sha256")
    parser.add_argument("--post-scope", type=Path)
    parser.add_argument("--post-scope-sha256")
    args = parser.parse_args()
    try:
        record = result(args.output, args.plan, args.plan_sha256, args.actor_result_sha256,
                        handoff_sha=args.handoff_sha256, authority_sha=args.authority_sha256,
                        post_scope=args.post_scope, post_scope_sha=args.post_scope_sha256)
    except (OSError, ValueError, KeyError, TypeError) as error:
        sys.exit(str(error))
    sys.stdout.buffer.write(wire(record))


if __name__ == "__main__":
    main()
