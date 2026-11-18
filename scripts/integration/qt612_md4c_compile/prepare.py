# SPDX-License-Identifier: MIT
"""Prepare a reflink-only continuation from a pinned closed Qtbase rehearsal."""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import struct
import subprocess
import tempfile
from uuid import UUID

HERE = Path(__file__).resolve().parent
GIB = 1 << 30
WORK, RESULT, OFFSET = 16 * GIB, 64 << 20, 1 << 20
SOURCE_LIMITS = {"Image": 64 << 20, "boot.raw": 2 * GIB, "scratch.raw": WORK}
QEMU_ACTOR_IMAGE = "sha256:52958d534193d739aeb6d3c9239ed31b97f8fb357a618e14391293068b28cd2a"
TOOL_PROFILE_KIND = "QTBASE_16K_QEMU_TOOL_PROFILE_V1"
PROFILE_KIND = "QT_MD4C_CONTINUATION_INPUT_PROFILE_V1"
TOOL_NAMES = frozenset("/usr/bin/" + name for name in (
    "cp", "debugfs", "e2fsck", "mke2fs", "qemu-system-aarch64"))
CONFIGURE_FILES = {
    "corrected_independent_readback": (128 << 10, None),
    "guest_serial": (1 << 20, "output/qtbase16k/qemu.stdout"),
    "original_qemu": (128 << 10, "output/qtbase16k/qemu.json"),
    "guest_result_disk": (RESULT, "output/qtbase16k/result.raw"),
    "host_result": (128 << 10, "host-result.json"),
    "absent_observation": (128 << 10, "scope-closure.DATA.json"),
}
BUILD = "/qt-recipe/src/build/"
GUI = BUILD + "src/gui/CMakeFiles/Gui.dir/"
IMPORTER = GUI + "text/qtextmarkdownimporter.cpp.o"
PCH = GUI + "cmake_pch.hxx.gch"
IMPORTER_SOURCE = "/qt-recipe/src/qtbase-everywhere-src-6.12.0/src/gui/text/qtextmarkdownimporter.cpp"
OPERAND_PATHS = frozenset((
    BUILD + "build.ninja",
    BUILD + "CMakeFiles/rules.ninja",
    BUILD + "CMakeCache.txt",
    BUILD + "src/gui/qtgui-config.h",
    GUI + "cmake_pch.hxx",
    GUI + "cmake_pch.hxx.cxx",
    IMPORTER_SOURCE,
    "/usr/include/md4c.h",
    "/usr/lib/libmd4c.so.0.5.3",
    "/var/lib/pacman/local/md4c-0.5.3-1/desc",
))
COMMANDS = {
    "headers": ([], "src/gui/Gui_sync_headers", 6),
    "pch": (["-s"], PCH.removeprefix(BUILD), 1),
    "importer": (["-s"], IMPORTER.removeprefix(BUILD), 1),
}
PAYLOAD = "/qt-md4c-compile"
VM_SECONDS = 2100
OVERLAY, REPORTS, RESERVE = 2 * GIB, 32 << 20, 2 * GIB
WRITE_LIMIT = OVERLAY + RESULT + REPORTS
DISK_GATE = WRITE_LIMIT + RESERVE
OUTPUT = Path("/out")


def need(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def sha(body):
    return hashlib.sha256(body).hexdigest()


def strict_json(raw):
    def unique(items):
        value = dict(items)
        need(len(value) == len(items), "Duplicate JSON key")
        return value

    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: need(False, "Non-finite JSON value"))


def hex_sha256(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value)


def absolute(value):
    need(type(value) is str and "\0" not in value and "\n" not in value and "\r" not in value,
         "Expected a literal absolute path")
    path = Path(value)
    need(path.is_absolute() and str(path) == value and ".." not in path.parts, "Expected a normalized absolute path")
    return path


def pin_shape(pin, cap):
    need(type(pin) is dict and set(pin) == {"bytes", "sha256"} and type(pin["bytes"]) is int
         and 0 < pin["bytes"] <= cap and hex_sha256(pin["sha256"]), "Expected a complete bounded pin")
    return pin


def ref_shape(ref, cap):
    need(type(ref) is dict and set(ref) == {"path", "bytes", "sha256"}, "Expected an ordinary pinned file reference")
    absolute(ref["path"])
    pin_shape(ref_pin(ref), cap)


def ref_pin(ref):
    return {"bytes": ref["bytes"], "sha256": ref["sha256"]}


def load_profile(path, digest):
    raw = read(path, digest)
    profile = strict_json(raw)
    need(type(profile) is dict and set(profile) == {"kind", "configure", "original_inputs", "scratch_uuid", "tools",
                                                     "operand_sha256", "command_sha256"}
         and profile["kind"] == PROFILE_KIND, "Expected the exact importer input profile")
    configure, inputs, tools = (profile[key] for key in ("configure", "original_inputs", "tools"))
    need(type(configure) is dict and set(configure) == {"attempt", "claim", "closure"} | CONFIGURE_FILES.keys()
         and type(inputs) is dict and set(inputs) == SOURCE_LIMITS.keys()
         and type(tools) is dict and set(tools) == {"profile", "qemu_img"}, "Exact original operand/profile roles required")
    attempt = absolute(configure["attempt"])
    need(re.fullmatch(r"issued\.[A-Za-z0-9_]+", attempt.name), "Exact originally issued attempt name required")
    ref_shape(configure["claim"], 4096)
    ref_shape(configure["closure"], 128 << 10)
    need(absolute(configure["claim"]["path"]) == attempt.parent / "root-run.claim/attempt.path",
         "Exact original claim leaf required")
    for name, (cap, relative) in CONFIGURE_FILES.items():
        ref_shape(configure[name], cap)
        if relative is not None:
            need(absolute(configure[name]["path"]) == attempt / relative, f"Original attempt leaf differs: {name}")
    for name, cap in SOURCE_LIMITS.items():
        ref_shape(inputs[name], cap)
        need(absolute(inputs[name]["path"]) == attempt / "output/qtbase16k" / name,
             f"Original attempt operand differs: {name}")
    need(inputs["scratch.raw"]["bytes"] == WORK and configure["guest_result_disk"]["bytes"] == RESULT and
         OFFSET < inputs["boot.raw"]["bytes"] and inputs["boot.raw"]["bytes"] % 4096 == 0,
         "Exact bounded configure disk geometry required")
    ref_shape(tools["profile"], 16 << 10)
    pin_shape(tools["qemu_img"], 64 << 20)
    uuid = profile["scratch_uuid"]
    need(type(uuid) is str and str(UUID(uuid)) == uuid, "Exact canonical scratch UUID required")
    for key, names in (("operand_sha256", OPERAND_PATHS), ("command_sha256", COMMANDS.keys())):
        value = profile[key]
        need(type(value) is dict and set(value) == names and all(hex_sha256(pin) for pin in value.values()),
             f"Exact guest path or generated command digest pins required: {key}")
    return profile


def identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def ordinary(path):
    need(path.is_absolute() and path.resolve() == path, f"Expected an ordinary absolute path: {path}")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    stream = os.fdopen(fd, "rb")
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        stream.close()
        raise ValueError(f"Expected regular file: {path}")
    return stream


def observe(path, limit, *, collect=False):
    with ordinary(path) as stream:
        before = os.fstat(stream.fileno())
        size = before.st_size
        need(0 < size <= limit, f"File exceeds its bound: {path}")
        body = stream.read(size + 1) if collect else None
        digest = sha(body) if collect else hashlib.file_digest(stream, "sha256").hexdigest()
        need(identity(os.fstat(stream.fileno())) == identity(before) == identity(path.stat()),
             f"File changed while hashing: {path}")
        return body, dict(bytes=size, sha256=digest)


def read(path, pin):
    body, observed = observe(path, 128 << 10, collect=True)
    need(observed["sha256"] == pin, f"File pin differs: {path}")
    return body


def match(path, expected):
    need(observe(path, expected["bytes"])[1] == expected, f"File pin differs: {path}")


def tool(name, args, *, stdin=None, seconds=45):
    proc = subprocess.run(["/usr/bin/" + name, *map(str, args)], input=stdin, capture_output=True,
                          env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"},
                          check=True, timeout=seconds)
    need(len(proc.stdout) <= 8 << 20 and len(proc.stderr) <= 64 << 10, f"{name} output bound")
    return proc.stdout


def new(path, body):
    with path.open("xb") as stream:
        stream.write(body)
    path.chmod(0o444)


def clone(source, target, *, start=0, count=0, destination=0, existing=False):
    with ordinary(source) as src, target.open("r+b" if existing else "xb") as dst:
        before = os.fstat(src.fileno())
        other = os.fstat(dst.fileno())
        need(before.st_dev == other.st_dev and before.st_ino != other.st_ino, "Same-volume distinct clone required")
        if count:
            args = struct.pack("=qQQQ", src.fileno(), start, count, destination)
            fcntl.ioctl(dst.fileno(), 0x4020940D, args)  # FICLONERANGE
        else:
            fcntl.ioctl(dst.fileno(), 0x40049409, src.fileno())  # FICLONE
        need(identity(os.fstat(src.fileno())) == identity(before), "Reflink source mutated")
        need(os.fstat(dst.fileno()).st_size == (other.st_size if existing else count or before.st_size),
             "Reflink size differs")


def predecessor(profile):
    configure = profile["configure"]
    claim, claim_pin = observe(Path(configure["claim"]["path"]), 4096, collect=True)
    need(claim_pin == ref_pin(configure["claim"]) and claim == (configure["attempt"] + "\n").encode(),
         "Exact original configure claim required")
    close = configure["closure"]
    close_bytes = read(Path(close["path"]), close["sha256"])
    need(len(close_bytes) == close["bytes"], "Exact configure closure size required")
    terminal = strict_json(close_bytes)
    need(terminal["status"] == "CLOSED_QTBASE16K_Q3_PASS" and terminal["original_custody_pass"] is True
         and terminal["issuer"] == "Root" and terminal["configure"] == "PASS_EXACT_QTBASE16K_CONFIGURE_ONLY"
         and type(terminal["page_size"]) is int and terminal["page_size"] == 16384
         and terminal["md4c"] == "0.5.3-1" and terminal["scoped_TEST_only"] is True
         and terminal["attempt"] == configure["attempt"] and terminal["release"] == "CLOSE_ONLY"
         and terminal["full_Qt_build"] == "NOT RUN" and terminal["scope_exit"] == terminal["container_exit"] == 0
         and canonical(terminal["observations"]) == canonical([dict(container_absent=True, scope_absent=True)] * 2),
         "Q3 closed configure-only custody required")
    for name in CONFIGURE_FILES:
        ref = configure[name]
        need(canonical(ref_pin(ref)) == canonical(terminal[name]), f"Configure closure operand differs: {name}")
        match(Path(ref["path"]), ref_pin(ref))
    qemu = configure["original_qemu"]
    original = strict_json(read(Path(qemu["path"]), qemu["sha256"]))
    validate_predecessor_argv(original["argv"])
    return original["argv"]


def checksums(pins):
    return "".join(f"{pin}  {name}\n" for name, pin in sorted(pins.items())).encode()


def commands(scratch, profile):
    operands, command_pins = profile["operand_sha256"], profile["command_sha256"]
    inputs = {}
    for path, expected in operands.items():
        body = tool("debugfs", ["-R", f"cat /root{path}", scratch])
        need(sha(body) == expected, f"Q3 selected guest file changed: {path}")
        inputs[path] = body
    graph = inputs[BUILD + "build.ninja"]
    include = b"include CMakeFiles/rules.ninja\n"
    need(graph.count(include) == 1, "Expected one exact Ninja rule manifest")
    graph = graph.replace(include, inputs[BUILD + "CMakeFiles/rules.ninja"])
    result = {}
    for name, (flags, target, count) in COMMANDS.items():
        output = tool("ninja", ["-f", "/dev/stdin", "-t", "commands", *flags, target], stdin=graph)
        need(sha(output) == command_pins[name] and output.count(b"\n") == count and output.endswith(b"\n"),
             f"Exact Q3 Ninja commands differ: {name}")
        result[name + ".commands"] = output
    need(b"md_parse(" in inputs[IMPORTER_SOURCE] and
         b"QT_FEATURE_system_textmarkdownreader:INTERNAL=ON\n" in inputs[BUILD + "CMakeCache.txt"],
         "Qt importer must select and call the signed system md4c provider")
    result["operands.sha256"] = checksums(operands)
    result["guest.sh"] = (HERE / "guest.sh").read_bytes()
    result["MANIFEST.sha256"] = checksums({name: sha(body) for name, body in result.items()})
    return result


def boot_image(where, payload, nonce, boot_bytes):
    image = where / "boot.raw"
    extent = boot_bytes - OFFSET
    with tempfile.TemporaryDirectory(prefix="patch-", dir=where) as temporary:
        staging = Path(temporary)
        root = staging / "root.ext4"
        clone(image, root, start=OFFSET, count=extent)
        edits = [f"mkdir {PAYLOAD}", f"set_inode_field {PAYLOAD} mode 040755"]
        for name, body in payload.items():
            new(staging / name, body)
            target = f"{PAYLOAD}/{name}"
            mode = "0100555" if name == "guest.sh" else "0100444"
            edits += [f"write {staging / name} {target}", f"set_inode_field {target} mode {mode}"]
        new(staging / "edits", ("\n".join(edits) + "\n").encode())
        tool("debugfs", ["-w", "-f", staging / "edits", root])
        tool("e2fsck", ["-fn", root], seconds=120)
        for name, body in payload.items():
            observed = tool("debugfs", ["-R", f"cat {PAYLOAD}/{name}", root])
            need(observed == body, f"Boot readback differs: {name}")
        clone(root, image, count=extent, destination=OFFSET, existing=True)
    with image.open("r+b") as stream:
        mbr = stream.read(512)
        sectors = struct.unpack_from("<II", mbr, 454)
        need(mbr[510:] == b"\x55\xaa" and mbr[450] == 0x83 and mbr[462:510] == bytes(48)
             and sectors == (OFFSET // 512, extent // 512),
             "Original Q3 partition geometry required")
        stream.seek(440)
        stream.write(struct.pack("<I", int(nonce[:8], 16)))
    image.chmod(0o444)


def vm_argv(kernel, append, name, drives):
    argv = ["/usr/bin/qemu-system-aarch64", "-machine", "virt", "-accel", "tcg,thread=multi",
            "-rtc", "base=utc,clock=host", "-cpu", "max", "-smp", "4", "-m", "4096",
            "-nodefaults", "-no-user-config", "-display", "none", "-monitor", "none", "-nic", "none",
            "-no-reboot", "-kernel", kernel, "-append", append, "-serial", "stdio", "-name", name,
            "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"]
    for disk, options in drives:
        argv += ["-drive", f"if=none,id={disk},{options}", "-device", f"virtio-blk-device,drive={disk}"]
    return argv


def boot_cmdline(nonce, entry):
    return (f"root=PARTUUID={nonce[:8]}-01 rootfstype=ext4 rootflags=noload ro rootwait "
            f"console=ttyAMA0,115200n8 init={entry}")


def validate_predecessor_argv(previous):
    need(type(previous) is list and all(type(arg) is str for arg in previous) and previous.count("-append") == 1
         and previous[-1] != "-append", "Exact original configure QEMU arguments required")
    append = previous[previous.index("-append") + 1]
    selection = re.search(r" cachy_qtbase_nonce=([0-9a-f]{32}) cachy_qtbase_plan=([0-9a-f]{64})$", append)
    need(selection is not None, "Exact original configure QEMU nonce and plan required")
    nonce, digest = selection.groups()
    expected = vm_argv("/out/qtbase16k/Image", boot_cmdline(nonce, "/qtbase16k-init") +
                       f" cachy_qtbase_nonce={nonce} cachy_qtbase_plan={digest}", "overlay583-" + nonce,
                       [(disk, f"file=/out/qtbase16k/{disk}.raw,format=raw,readonly={mode}")
                        for disk, mode in (("boot", "on"), ("inputs", "on"), ("scratch", "off"), ("result", "off"))])
    need(previous == expected, "Exact original configure QEMU controls required")
    return nonce


def continuation_argv(nonce, manifest, scratch_uuid):
    need(type(nonce) is str and re.fullmatch(r"[0-9a-f]{32}", nonce) and hex_sha256(manifest),
         "Exact fresh nonce and manifest digest required")
    return vm_argv("/inputs/Image", boot_cmdline(nonce, PAYLOAD + "/guest.sh") +
                   f" cachy_qt_compile_nonce={nonce} cachy_qt_compile_plan={manifest}" + storage_args(nonce, scratch_uuid),
                   f"qtmd4c-{nonce}", (
                       ("boot", "file=/inputs/boot.raw,format=raw,readonly=on"),
                       ("scratch", "file=/out/overlay.qcow2,format=qcow2,readonly=off,discard=ignore"),
                       ("result", "file=/out/result.raw,format=raw,readonly=off"),
                   ))


def qemu_argv(previous, nonce, manifest, scratch_uuid):
    old_nonce = validate_predecessor_argv(previous)
    argv = continuation_argv(nonce, manifest, scratch_uuid)
    need(nonce[:8] != old_nonce[:8], "Fresh boot identity required")
    return argv


def result_uuid(nonce):
    return str(UUID(hex=nonce, version=4))


def storage_args(nonce, scratch_uuid):
    need(type(scratch_uuid) is str and str(UUID(scratch_uuid)) == scratch_uuid and scratch_uuid != result_uuid(nonce),
         "Distinct canonical scratch and result UUIDs required")
    return f" cachy_qt_compile_scratch_uuid={scratch_uuid} cachy_qt_compile_result_uuid={result_uuid(nonce)}"


def ext4_uuid(path, label):
    with ordinary(path) as stream:
        raw = os.pread(stream.fileno(), 1024, 1024)
    need(len(raw) == 1024 and raw[56:58] == b"\x53\xef" and
         raw[120:136] == label.encode().ljust(16, b"\0"), "Exact ext4 storage identity required")
    return str(UUID(bytes=raw[104:120]))


def actor_plan(profile):
    ref = profile["tools"]["profile"]
    raw, observed = observe(Path(ref["path"]), 16 << 10, collect=True)
    need(observed == ref_pin(ref), "Exact configure tool profile required")
    five = strict_json(raw)
    need(type(five) is dict and set(five) == {"kind", "actor_image", "tools"}
         and type(five["tools"]) is dict and set(five["tools"]) == TOOL_NAMES,
         "Exact original five tool names required")
    tool_profile = dict(five, tools=five["tools"] | {"/usr/bin/qemu-img": profile["tools"]["qemu_img"]})
    return actor_policy(tool_profile, sum(ref["bytes"] for ref in profile["original_inputs"].values()))


def actor_policy(tool_profile, readonly_bytes):
    need(type(tool_profile) is dict and set(tool_profile) == {"kind", "actor_image", "tools"}
         and tool_profile["kind"] == TOOL_PROFILE_KIND and tool_profile["actor_image"] == QEMU_ACTOR_IMAGE
         and type(tool_profile["tools"]) is dict and set(tool_profile["tools"]) == TOOL_NAMES | {"/usr/bin/qemu-img"},
         "Exact pinned six-tool actor profile required")
    for pin in tool_profile["tools"].values():
        pin_shape(pin, 64 << 20)
    need(type(readonly_bytes) is int and WORK + OFFSET < readonly_bytes <= sum(SOURCE_LIMITS.values()),
         "Exact bounded read-only operand extent required")
    return dict(profile=tool_profile, bind_modes={"/inputs": "ro", "/out": "rw"},
                overlay_create=["/usr/bin/qemu-img", "create", "-f", "qcow2", "-F", "raw",
                                "-b", "/inputs/scratch.raw", "/out/overlay.qcow2"],
                overlay_inspect=["/usr/bin/qemu-img", "info", "-f", "qcow2", "--output=json",
                                 "--backing-chain", "/out/overlay.qcow2"],
                overlay_logical_bytes=WORK, preparation_readonly_logical_bytes=readonly_bytes,
                result_disk_bytes=RESULT, report_allocation_bytes=REPORTS, admission_disk_bytes=DISK_GATE,
                child_file_size_cap=OVERLAY, watched_tree=[str(OUTPUT), WRITE_LIMIT, RESERVE],
                watched_paths=[[str(OUTPUT / "overlay.qcow2"), OVERLAY], [str(OUTPUT / "result.raw"), RESULT]],
                serial_combined_cap=1 << 20)


def validate_empty_overlay(raw, eof):
    """Check the fixed QEMU chain and the 512-byte block-node size projection."""
    need(type(eof) is int and 0 < eof <= 1 << 20 and 0 < len(raw) <= 16 << 10, "Initial overlay bound")

    def unique(items):
        result = dict(items)
        need(len(result) == len(items), "Duplicate QEMU metadata key")
        return result

    chain = json.loads(raw, object_pairs_hook=unique,
                       parse_constant=lambda _: need(False, "Non-finite QEMU metadata"))
    need(type(chain) is list and len(chain) == 2, "One QCOW2 node and one raw backing required")
    overlay, backing = chain
    filename = "/inputs/scratch.raw"
    qcow2 = {"backing-filename": filename, "full-backing-filename": filename,
             "backing-filename-format": "raw", "cluster-size": 65536,
             "format-specific": {"type": "qcow2", "data": {
                 "compat": "1.1", "compression-type": "zlib", "lazy-refcounts": False,
                 "refcount-bits": 16, "corrupt": False, "extended-l2": False}}}
    for node, kind, path, length, ceiling, extras in (
        (overlay, "qcow2", "/out/overlay.qcow2", eof, 1 << 20, qcow2),
        (backing, "raw", filename, WORK, WORK, {}),
    ):
        need(type(node) is dict, "Exact local overlay node required")
        allocated = node.get("actual-size")
        need(type(allocated) is int and 0 < allocated <= ceiling and allocated % 512 == 0,
             "Bounded allocated bytes required")
        # QEMU's file block backend reports sector-rounded length, not stat(2) EOF.
        block_bytes = (length + 511) // 512 * 512
        file = {"filename": path, "format": "file", "actual-size": allocated,
                "virtual-size": block_bytes, "children": [], "dirty-flag": False,
                "format-specific": {"type": "file", "data": {}}}
        expected = {"filename": path, "format": kind, "actual-size": allocated, "virtual-size": WORK,
                    "children": [{"name": "file", "info": file}], "dirty-flag": False} | extras
        need(canonical(node) == canonical(expected), "Exact ordinary local file backend and chain required")


def capacity(directory):
    filesystem = os.statvfs(directory)
    free = filesystem.f_bavail * filesystem.f_frsize
    memory = int(re.search(r"^MemAvailable:\s+(\d+) kB$", Path("/proc/meminfo").read_text(), re.M)[1]) * 1024
    cpus = len(os.sched_getaffinity(0))
    return dict(free_bytes=free, memory_available_bytes=memory, cpus=cpus, disk_gate=DISK_GATE,
                memory_gate=6 * GIB, cpu_gate=4, fits=free >= DISK_GATE and memory >= 6 * GIB and cpus >= 4)


def view_sources(profile):
    return {name: ref_pin(ref) for name, ref in profile["original_inputs"].items()}


def expected_payload(profile):
    pins = {name + ".commands": digest for name, digest in profile["command_sha256"].items()}
    pins["guest.sh"] = sha((HERE / "guest.sh").read_bytes())
    pins["operands.sha256"] = sha(checksums(profile["operand_sha256"]))
    pins["MANIFEST.sha256"] = sha(checksums(pins))
    return pins


def plan_data(profile, previous, nonce, files):
    payload = expected_payload(profile)
    return dict(kind="QT612_MD4C_COMPILE_CONTINUATION_UNISSUED_V1", authority=None, guest_invoked=False,
                q3_closure_sha256=profile["configure"]["closure"]["sha256"],
                q3_postclose_operands=view_sources(profile), inputs=files, nonce=nonce,
                guest_payload=payload, actor=actor_plan(profile),
                command_slots={name: row[2] for name, row in COMMANDS.items()}, requested_outputs=[PCH, IMPORTER],
                qemu_seconds=VM_SECONDS, qemu_argv=qemu_argv(previous, nonce, payload["MANIFEST.sha256"],
                                                          profile["scratch_uuid"]),
                retained_native_disk_gate=14 * GIB, build_scope="QT_MD4C_IMPORTER_OBJECT_ONLY",
                original_reflink_fallback=False)


def validate_plan(plan, profile, previous):
    files, nonce = plan["inputs"], plan["nonce"]
    originals = view_sources(profile)
    sizes = {name: row["bytes"] for name, row in originals.items()} | {"result.raw": RESULT}
    need(type(files) is dict and set(files) == sizes.keys(), "Exact continuation image set required")
    for name, size in sizes.items():
        pin_shape(files[name], size)
        need(files[name]["bytes"] == size, f"Exact continuation image size required: {name}")
    need(all(files[name] == originals[name] for name in ("scratch.raw", "Image")), "Exact reflink operands required")
    need(canonical(plan) == canonical(plan_data(profile, previous, nonce, files)), "Exact unissued continuation required")
    return plan


def prepare(where, profile):
    old_argv = predecessor(profile)
    need(absolute(str(where)) == where.resolve() and re.fullmatch(r"/[A-Za-z0-9_./-]+", str(where))
         and where.parent.is_dir() and not os.stat(where.parent).st_mode & 0o022
         and not where.exists() and not where.is_symlink(),
         "Select a fresh private output under an ordinary protected directory")
    inputs_refs = profile["original_inputs"]
    views = view_sources(profile)
    for name, ref in inputs_refs.items():
        match(Path(ref["path"]), views[name])
    with tempfile.TemporaryDirectory(prefix="qtmd4c-", dir=where.parent) as temporary:
        owned = Path(temporary) / "packet"
        owned.mkdir(mode=0o700)
        inputs, output = owned / "inputs", owned / "output"
        inputs.mkdir(mode=0o700)
        output.mkdir(mode=0o700)
        for name, ref in inputs_refs.items():
            clone(Path(ref["path"]), inputs / name)
        tool("e2fsck", ["-fn", inputs / "scratch.raw"], seconds=150)
        need(ext4_uuid(inputs / "scratch.raw", "QT16K_WORK") == profile["scratch_uuid"],
             "Pinned Q3 scratch UUID differs")
        payload = commands(inputs / "scratch.raw", profile)
        nonce = secrets.token_hex(16)
        need(not any(nonce[:8] in arg for arg in old_argv), "Fresh boot identity required")
        boot_image(inputs, payload, nonce, views["boot.raw"]["bytes"])
        result = output / "result.raw"
        with result.open("xb") as stream:
            stream.truncate(RESULT)
        tool("mke2fs", ["-q", "-F", "-t", "ext4", "-b", "4096", "-L", "QT16K_MD4C", "-U", result_uuid(nonce),
                        "-O", "^orphan_file",
                        "-E", "lazy_itable_init=0,lazy_journal_init=0", result])
        tool("e2fsck", ["-fn", result], seconds=120)
        for name in inputs_refs:
            (inputs / name).chmod(0o444)
        inputs.chmod(0o555)
        files = {name: observe(inputs / name, WORK)[1] for name in inputs_refs}
        files["result.raw"] = observe(result, RESULT)[1]
        need({name: sha(body) for name, body in payload.items()} == expected_payload(profile),
             "Guest manifest differs from the pinned compiler inputs")
        plan = validate_plan(plan_data(profile, old_argv, nonce, files), profile, old_argv)
        raw = canonical(plan)
        new(owned / "PLAN.UNISSUED.json", raw)
        owned.rename(where)
    return preflight(where, sha(raw), profile)


def preflight(where, supplied, profile):
    raw = read(where / "PLAN.UNISSUED.json", supplied)
    plan = strict_json(raw)
    need(raw == canonical(plan), "Canonical unissued continuation plan required")
    validate_plan(plan, profile, predecessor(profile))
    inputs, output = where / "inputs", where / "output"
    need(inputs.resolve() == inputs and output.resolve() == output and
         set(p.name for p in inputs.iterdir()) == SOURCE_LIMITS.keys() and
         set(p.name for p in output.iterdir()) == {"result.raw"} and
         inputs.stat().st_dev == output.stat().st_dev,
         "Exact separate read-only inputs and unused mutable output on the same volume required")
    originals = profile["original_inputs"] | {"result.raw": profile["configure"]["guest_result_disk"]}
    for name, expected in plan["inputs"].items():
        path, mode = (output / name, 0o600) if name == "result.raw" else (inputs / name, 0o444)
        match(path, expected)
        need(stat.S_IMODE(path.stat().st_mode) == mode and not path.samefile(Path(originals[name]["path"])),
             "Private continuation image mode or original inode differs")
    need(ext4_uuid(inputs / "scratch.raw", "QT16K_WORK") == profile["scratch_uuid"] and
         ext4_uuid(output / "result.raw", "QT16K_MD4C") == result_uuid(plan["nonce"]),
         "Exact pinned scratch and result UUIDs required")
    measured = capacity(where)
    return dict(status="PASS_PREPARED_UNISSUED" if measured["fits"] else "PASS_INPUTS_HOLD_LIVE_CAPACITY",
                guest_invoked=False, custody="PASS", plan_sha256=supplied, capacity=measured)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--profile-sha256", required=True, metavar="SHA256")
    parser.add_argument("--preflight-sha256", metavar="SHA256")
    arguments = parser.parse_args()
    os.umask(0o077)
    profile = load_profile(arguments.profile, arguments.profile_sha256)
    report = (preflight(arguments.path, arguments.preflight_sha256, profile) if arguments.preflight_sha256
              else prepare(arguments.path, profile))
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError) as error:
        raise SystemExit(f"Continuation preparation refused: {error}") from None
