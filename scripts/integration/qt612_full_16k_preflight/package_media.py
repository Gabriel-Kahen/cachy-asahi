# SPDX-License-Identifier: MIT
"""Seal and check the private media for one package-only Qtbase continuation."""

import argparse
import os
from pathlib import Path
import re
from runpy import run_path
import stat
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace


HERE = Path(__file__).resolve().parent
E = SimpleNamespace(**run_path(str(HERE / "package_execution.py")))
F, C, P, W = E.F, E.C, E.P, E.W
MEDIA_NAME = "MEDIA.UNISSUED.json"
MEDIA_KIND = "QTBASE16K_PACKAGE_MEDIA_UNISSUED_V1"
SOURCE_FILES = F.SOURCE_FILES | {F.GUEST_SOURCE + "/" + name for name in (
    "package_actor.py", "package_execution.py", "package_media.py", "package-guest-init.sh",
    "package_guest.py",
)}
CONTROL_CAP = 128 << 10
INPUTS = {"boot.raw", "Image", "complete.qcow2", "gui.qcow2", "core.qcow2", "scratch.raw"}


def selected_role(stage, plan_sha, selection, selection_sha, now):
    plan_raw, _ = C.external(stage / W.PLAN_NAME, CONTROL_CAP, plan_sha)
    selection_raw, _ = C.external(selection, 16 << 10, selection_sha)
    files = E.staged_inputs(stage, C.json_body(plan_raw, canonical=True))
    plan, issued, bundle = E.boot_bundle(plan_raw, files, selection_raw, selection_sha, now)
    return plan, issued, E.role_descriptor(plan, bundle), bundle


def source_records(root):
    allowed = {parent.as_posix() for name in SOURCE_FILES for parent in Path(name).parents}
    C.need(F.T.ordinary(root) == root and stat.S_IMODE(root.lstat().st_mode) == 0o555,
           "Read-only package source root required")
    records, queue = {}, [root]
    while queue:
        for path in queue.pop().iterdir():
            name = path.relative_to(root).as_posix()
            attr = path.lstat()
            mode = stat.S_IMODE(attr.st_mode)
            if stat.S_ISDIR(attr.st_mode):
                C.need(name in allowed and mode == 0o555, "Unexpected package source directory")
                queue.append(path)
                continue
            C.need(name in SOURCE_FILES and mode == 0o444, "Unexpected package source leaf")
            records[name] = C.read(path, CONTROL_CAP, collect=False)[1] | {"mode": mode}
    C.need(records.keys() == SOURCE_FILES, "Incomplete package source snapshot")
    return records


def boot_filesystem(path):
    frozen = C.pinned_module("qtbase_package_boot_ext4", C.FROZEN, C.FROZEN_PIN)
    original = F.B.clean_file(path)

    class PartitionOS:
        def __getattr__(self, name):
            return getattr(os, name)

        @staticmethod
        def open(name, flags):
            return os.open(name, flags | os.O_NOATIME | os.O_CLOEXEC)

        @staticmethod
        def fstat(fd):
            current = os.fstat(fd)
            C.need(C.identity(current) == C.identity(original) and current.st_size == F.Q.BOOT_BYTES,
                   "Exact package boot partition required")
            return SimpleNamespace(st_mode=current.st_mode, st_size=current.st_size - P.OFFSET)

        @staticmethod
        def pread(fd, size, offset):
            return os.pread(fd, size, P.OFFSET + offset)

    frozen.os = PartitionOS()
    return frozen.Ext4Reader(path, max_nodes=64, max_file_bytes=CONTROL_CAP)


def verify_boot(path, role):
    before = C.identity(path.lstat())
    F.boot_identity(path, role["nonce"])
    pins = role["boot_payload"]
    folders = set(role["boot_subdirectories"])
    names = {Path(name) for name in pins.keys() | folders}
    with boot_filesystem(path) as fs:
        _, root = F.boot_directory(fs, 2)
        start, kind = root[role["boot_directory"].lstrip("/").encode()]
        C.need(kind == 2, "Exact package boot directory required")
        queue = [(Path("."), start, 2)]
        for parent, number, ancestor in queue:
            directory, entries = F.boot_directory(fs, number)
            expected = {name.name.encode(): name for name in names if name.parent == parent}
            C.need(directory["mode"] == 0o755 and directory["uid"] == directory["gid"] == 0
                   and not directory["xattrs"] and entries.pop(b".") == (number, 2)
                   and entries.pop(b"..") == (ancestor, 2) and entries.keys() == expected.keys(),
                   "Exact package boot namespace required")
            for basename, (child, kind) in entries.items():
                name = expected[basename].as_posix()
                if name in folders:
                    C.need(kind == 2, "Expected an ordinary package boot subdirectory")
                    queue.append((Path(name), child, number))
                    continue
                pin = pins[name]
                inode, raw = fs.inode(child)
                C.need(kind == 1 and inode["type"] == "file" and inode["links"] == 1 and not inode["xattrs"]
                       and inode["uid"] == inode["gid"] == 0 and inode["mode"] == pin["mode"]
                       and inode["size"] == pin["bytes"] and
                       C.pin(b"".join(fs.chunks(inode, raw))) == F.Q.pin_ref(pin),
                       "Exact package boot file required")
        C.need(C.identity(os.fstat(fs.fd)) == C.identity(path.lstat()) == before,
               "Package boot carrier changed during readback")


def verify_result(path, uuid, *, empty=False):
    before = C.identity(path.lstat())
    C.need(path.lstat().st_size == E.RESULT_BYTES, "Exact package result geometry required")
    with C.ext4_reader()(path, max_nodes=2, max_file_bytes=64 << 10) as fs:
        sb = fs.read(1024, 1024)
        C.need(struct.unpack_from("<HH", sb, 56) == (0xEF53, 1) and not fs.incompat & 4
               and not struct.unpack_from("<I", sb, 92)[0] & 0x1000
               and sb[120:136].rstrip(b"\0") == E.RESULT_LABEL.encode() and fs.uuid == uuid,
               "Exact clean package result volume required")
        if empty:
            nodes = fs.inventory()["nodes"]
            C.need(nodes.keys() == {".", "lost+found"} and all(
                node["type"] == "directory" and node["uid"] == node["gid"] == 0 and not node["xattrs"]
                and node["mode"] == (0o755 if name == "." else 0o700) for name, node in nodes.items()),
                "Exact fresh empty package result required")
        C.need(C.identity(os.fstat(fs.fd)) == C.identity(path.lstat()) == before,
               "Package result carrier changed during header inspection")


def media_shape(media, role=None):
    C.need(media.keys() == {"kind", "authority", "scope", "nonce", "plan", "selection", "role", "result", "boot",
                            "runner", "source"} and media["kind"] == MEDIA_KIND and media["authority"] is None
           and media["scope"] == W.SCOPE and W.NONCE.fullmatch(media["nonce"]) and media["nonce"][:8] != "00000000"
           and all(C.check_pin(media[key], cap) and 0 < media[key]["bytes"] <= cap for key, cap in (
                ("plan", CONTROL_CAP), ("selection", 16 << 10), ("role", CONTROL_CAP),
                ("boot", F.Q.BOOT_BYTES), ("result", E.RESULT_BYTES)))
           and media["boot"]["bytes"] == F.Q.BOOT_BYTES and media["result"]["bytes"] == E.RESULT_BYTES,
           "Exact unissued package media descriptor required")
    F.Q.runner_shape(media["runner"])
    C.need(C.pin(C.wire(media["runner"])) == F.RUNNER_PIN and media["source"].keys() == SOURCE_FILES
           and all(row.keys() == {"bytes", "sha256", "mode"} and row["mode"] == 0o444
                   and C.check_pin(F.Q.pin_ref(row), CONTROL_CAP) and row["bytes"] > 0
                   for row in media["source"].values())
           and C.pin(C.wire({name: media["source"][name] for name in F.Q.SOURCE_FILES}))["sha256"] == F.HISTORICAL_SOURCE
           and F.Q.pin_ref(media["source"][F.DRY_RUN_SOURCE]) == F.DRY_RUN_RECEIPT,
           "Exact inherited runtime profile and source map required")
    if role is not None:
        C.need(media["role"] == C.pin(C.wire(role)) and all(media[key] == role[key] for key in ("nonce", "plan", "selection")),
               "Media descriptor differs from independently selected package role")
    return media


def load_media(path, sha, role=None):
    raw, _ = C.external(path, CONTROL_CAP, sha)
    return media_shape(C.json_body(raw, canonical=True), role)


def input_pins(role, media):
    return {name: P.ref_pin(row) for name, row in role["readonly_media"].items()} | {"boot.raw": media["boot"]}


def verify_inputs(inputs, role, media):
    C.need(F.T.ordinary(inputs) == inputs and stat.S_IMODE(inputs.lstat().st_mode) == 0o555
           and {path.name for path in inputs.iterdir()} == INPUTS, "Exact readonly package input namespace required")
    for name, pin in input_pins(role, media).items():
        path = inputs / name
        C.need(stat.S_IMODE(path.lstat().st_mode) == 0o444, "Package input must be readonly")
        C.read(path, pin["bytes"], pin, collect=False)
    for index, ref in enumerate(E.CHAIN[1:-1], 1):
        name, backing = Path(ref).name, E.CHAIN[index + 1]
        F.K.inspect_overlay(inputs / name, P.ref_pin(role["readonly_media"][name]), backing,
                            "raw" if backing.endswith(".raw") else "qcow2")
    verify_boot(inputs / "boot.raw", role)


def patch_boot(path, tools, role, bundle):
    size, offset = F.Q.BOOT_BYTES, P.OFFSET
    extent = size - offset
    with TemporaryDirectory(prefix="qtbase-package-boot-", dir=path.parent) as temp:
        root = Path(temp)
        partition = root / "root.ext4"
        P.clone(path, partition, start=offset, count=extent)
        target = role["boot_directory"]
        commands = []
        for directory in [target] + [target + "/" + name for name in role["boot_subdirectories"]]:
            commands += ["mkdir " + directory, "set_inode_field " + directory + " mode 040755"]
        for index, (name, body) in enumerate(sorted(bundle.items())):
            leaf = root / f"payload-{index}"
            F.K.save(leaf, body)
            path_in_boot = target + "/" + name
            mode = role["boot_payload"][name]["mode"]
            commands += [f"write {leaf} {path_in_boot}", f"set_inode_field {path_in_boot} mode {0o100000 | mode:07o}"]
        edits = root / "patch.debugfs"
        F.K.save(edits, ("\n".join(commands) + "\n").encode())
        tools.run("debugfs", ["-w", "-f", edits, partition], root)
        tools.run("e2fsck", ["-fn", partition], root)
        P.clone(partition, path, count=extent, destination=offset, existing=True)
    with path.open("r+b") as writable:
        signature = struct.pack("<I", int(role["nonce"][:8], 16))
        writable.seek(440)
        C.need(writable.read(4) != signature, "Fresh package PARTUUID required")
        writable.seek(440)
        writable.write(signature)
    path.chmod(0o444)
    verify_boot(path, role)


def format_result(path, tools, role):
    with path.open("xb") as stream:
        stream.truncate(E.RESULT_BYTES)
    tools.run("mke2fs", ["-q", "-F", "-t", "ext4", "-b", "4096", "-L", E.RESULT_LABEL,
                         "-U", role["result_carrier"]["uuid"], "-O", "^orphan_file",
                         "-E", "lazy_itable_init=0,lazy_journal_init=0", path], path.parent)
    tools.run("e2fsck", ["-fn", path], path.parent)
    path.chmod(0o444)
    verify_result(path, role["result_carrier"]["uuid"], empty=True)


def prepare(output, stage, plan_sha, selection, selection_sha, tool_pins):
    plan, _, role, bundle = selected_role(stage, plan_sha, selection, selection_sha, int(time.time()))
    evidence = plan["source_evidence"]
    original = Path(evidence["handoff"]["path"])
    raw, _ = C.read(original, 64 << 10, P.ref_pin(evidence["handoff"]))
    build = C.json_body(raw, canonical=True)
    archived = original.parent / "source"
    F.verify_source(archived, build)
    F.Q.runner_shape(build["runner"])
    C.need(C.pin(C.wire(build["runner"])) == F.RUNNER_PIN, "Original exact runner profile required")
    protected = {stage, original.parent, F.Q.ROOT} | {Path(ref["path"]).parent for ref in role["readonly_media"].values()}
    C.need(output.is_absolute() and output == output.resolve() and re.fullmatch(r"/[A-Za-z0-9_./-]+", str(output))
           and not any(output.is_relative_to(path) for path in protected) and not os.path.lexists(output)
           and output.parent.stat().st_uid == os.getuid() and not output.parent.stat().st_mode & 0o022,
           "Fresh private media directory outside input trees required")
    source_inputs = role["readonly_media"] | {"boot.raw": role["boot_template"]}
    for ref in source_inputs.values():
        C.read(Path(ref["path"]), ref["bytes"], P.ref_pin(ref), collect=False)
    F.boot_identity(Path(role["boot_template"]["path"]), plan["source_build_nonce"])
    formatting = run_path(str(F.GUI / "prepare.py"))["Formatting"](F.Q, tool_pins)
    os.umask(0o077)
    output.mkdir(mode=0o700)
    source, inputs, templates = (output / name for name in ("source", "inputs", "templates"))
    for directory in (source, inputs, templates):
        directory.mkdir(mode=0o700)
    for name in sorted(SOURCE_FILES):
        record = build["source"].get(name)
        parent = archived if record is not None else F.Q.ROOT
        body, _ = C.read(parent / name, CONTROL_CAP, F.Q.pin_ref(record) if record is not None else None)
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        F.K.save(path, body)
    for folder in sorted((leaf for leaf in source.rglob("*") if leaf.is_dir()), key=lambda leaf: -len(leaf.parts)):
        folder.chmod(0o555)
    source.chmod(0o555)
    for name, ref in source_inputs.items():
        F.K.clone(Path(ref["path"]), inputs / name, P.ref_pin(ref))
    boot = inputs / "boot.raw"
    boot.chmod(0o600)
    patch_boot(boot, formatting, role, bundle)
    result = templates / "result.raw"
    format_result(result, formatting, role)
    for directory in (inputs, templates):
        directory.chmod(0o555)
    media = dict(kind=MEDIA_KIND, authority=None, scope=W.SCOPE, nonce=plan["nonce"],
                 plan=role["plan"], selection=role["selection"], role=C.pin(C.wire(role)),
                 runner=build["runner"], source=source_records(source),
                 boot=C.read(boot, F.Q.BOOT_BYTES, collect=False)[1],
                 result=C.read(result, E.RESULT_BYTES, collect=False)[1])
    media_shape(media, role)
    F.K.save(output / MEDIA_NAME, C.wire(media))
    return media


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--selection-sha256", required=True)
    parser.add_argument("--format-tools", type=Path, required=True)
    parser.add_argument("--format-tools-sha256", required=True)
    args = parser.parse_args()
    try:
        raw, _ = C.external(args.format_tools, 16 << 10, args.format_tools_sha256)
        media = prepare(args.output, args.stage, args.plan_sha256, args.selection, args.selection_sha256,
                        C.json_body(raw, canonical=True))
        sys.stdout.buffer.write(C.wire(dict(media=C.pin(C.wire(media)), authority=None, packaging="NOT_RUN")))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        sys.exit("Qtbase packaging media preparation refused")


if __name__ == "__main__":
    main()
