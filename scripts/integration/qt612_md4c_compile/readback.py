# SPDX-License-Identifier: MIT
"""Read the retired Qt importer attempt through a trusted site adapter."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import types

HERE = Path(__file__).resolve().parent
FROZEN = HERE.parent / "arm16k_perl5423_vm/frozen/independent_readback.py"
FROZEN_PIN = {"bytes": 13913, "sha256": "8fb8c2c32dc5a40998bf31cc5727768f88ce51e423b7090cfb702116bdc9b5d3"}
RESULT_BYTES = 64 << 20
SERIAL_CAP = 1 << 20
EVIDENCE = {"result.json": 4096, "compile.log": 4 << 20, "importer.elf": 64 << 10,
            "importer.symbols": 8 << 20, "importer.o": 8 << 20}
ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
ELF_SECTION = struct.Struct("<IIQQQQIIQQ")
ELF_SYMBOL = struct.Struct("<IBBHQQ")
ELF_RELA = struct.Struct("<QQq")
IMPORTER = b"_ZN21QTextMarkdownImporter6importERK7QString"
CALL_OPCODES = {282: 0x14000000, 283: 0x94000000}
SHA = re.compile("[0-9a-f]{64}")
NONCE = re.compile("[0-9a-f]{32}")
EMPTY = {"scope_absent": True, "container_absent": True}
STORAGE_REASONS = {b"UUID_LOOKUP", b"UUID_SELECTION", b"WHOLE_VIRTIO", b"FLAT_DISK",
                   b"DISK_ALIAS", b"FILESYSTEM_ID", b"GEOMETRY", b"WRITE_STATE"}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode()


def wire(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def pin(body):
    return {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}


def identity(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def read(path, cap, expected=None, *, collect=True):
    need(path.is_absolute() and path.resolve() == path, f"Ordinary absolute evidence path required: {path}")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= cap,
             f"Finite single-link evidence file required: {path}")
        body = stream.read(before.st_size + 1) if collect else None
        observed = (pin(body) if collect else
                    {"bytes": before.st_size, "sha256": hashlib.file_digest(stream, "sha256").hexdigest()})
        need(observed["bytes"] == before.st_size and
             identity(before) == identity(os.fstat(fd)) == identity(path.lstat()),
             f"Evidence changed during readback: {path}")
    if expected is not None:
        need(canonical(observed) == canonical(expected), f"Evidence pin differs: {path}")
    return (body, observed) if collect else observed


def decode(body):
    def unique(items):
        obj = dict(items)
        need(len(obj) == len(items), "Duplicate evidence field")
        return obj

    return json.loads(body, object_pairs_hook=unique, parse_constant=lambda _: need(False, "Nonfinite JSON number"))


def json_object(body, *, encoded=True):
    value = decode(body)
    need(type(value) is dict and (not encoded or wire(value) == body), "Expected a canonical JSON object")
    return value


def evidence_object(path, expected=None, *, cap=128 << 10, encoded=True):
    body, observed = read(path, cap, expected)
    return json_object(body, encoded=encoded), observed


def external(path, sha256):
    need(type(sha256) is str and SHA.fullmatch(sha256), "External exact SHA-256 required")
    body, observed = read(path, 128 << 10)
    need(observed["sha256"] == sha256, f"External evidence SHA-256 differs: {path}")
    return body, observed


def audit_fence(event, args):
    need(not event.startswith(("subprocess.", "socket.", "ctypes.", "shutil."))
         and event not in {"os.system", "os.exec", "os.fork", "os.forkpty", "os.posix_spawn", "os.kill", "os.killpg",
                           "os.mkdir", "os.rmdir", "os.remove", "os.rename", "os.link", "os.symlink", "os.chmod",
                           "os.chown", "os.truncate", "os.setxattr", "os.removexattr", "fcntl.flock", "fcntl.ioctl"},
         "Independent readback cannot use an actor, network or mutation")
    if event == "open":
        _, mode, flags = args
        need((mode is None or not any(char in mode for char in "wax+")) and
             (flags is None or not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)),
             "Independent readback can only open read-only files")


def raw_ext4_reader():
    code, _ = read(FROZEN, FROZEN_PIN["bytes"], FROZEN_PIN)
    module = types.ModuleType("qt_md4c_frozen_ext4")
    exec(compile(code, str(FROZEN), "exec"), module.__dict__)
    return module.Ext4Reader


def result_files(disk, disk_pin, expected_uuid, passed):
    original = read(disk, RESULT_BYTES, disk_pin, collect=False)
    need(original["bytes"] == RESULT_BYTES, "Exact 64 MiB result geometry required")
    with raw_ext4_reader()(disk, max_nodes=10, max_file_bytes=max(EVIDENCE.values())) as fs:
        sb = fs.read(1024, 1024)
        need(struct.unpack_from("<HH", sb, 56) == (0xEF53, 1) and not fs.incompat & 4
             and sb[120:136] == b"QT16K_MD4C".ljust(16, b"\0") and fs.uuid == expected_uuid,
             "Clean Qt result extent filesystem with original label and UUID required")
        nodes = fs.inventory()["nodes"]
        fixed = {".", "lost+found"}
        folders = fixed | {"evidence"}
        leaves = set(nodes) - folders
        names = {n.removeprefix("evidence/") for n in leaves}
        need(fixed <= nodes.keys() and (not leaves or "evidence" in nodes)
             and names <= EVIDENCE.keys() and leaves == {"evidence/" + name for name in names}
             and (not passed or names == EVIDENCE.keys()), "Exact bounded raw result namespace required")
        for name in folders & nodes.keys():
            row = nodes[name]
            need(row["type"] == "directory" and row["uid"] == row["gid"] == 0 and
                 row["mode"] == (0o755 if name == "." else 0o700) and not row["xattrs"],
                 f"Unexpected result directory metadata: {name}")
        files = {}
        for name in sorted(names):
            row = nodes["evidence/" + name]
            need(row["type"] == "file" and row["links"] == 1 and row["mode"] == 0o600 and
                 row["uid"] == row["gid"] == 0 and not row["xattrs"] and 0 <= row["size"] <= EVIDENCE[name] and
                 (not passed or row["size"] > 0), f"Unexpected result file metadata: {name}")
            inode, raw = fs.inode(row["inode"])
            body = b"".join(fs.chunks(inode, raw))
            need(pin(body) == {"bytes": row["size"], "sha256": row["sha256"]}, f"Raw ext4 leaf changed: {name}")
            files[name] = body
    read(disk, RESULT_BYTES, original, collect=False)
    return files


def verify_object(raw):
    """Verify the produced object directly, with no compiler or readelf child."""
    need(ELF_HEADER.size <= len(raw) <= EVIDENCE["importer.o"], "Bounded importer ELF required")
    (ident, kind, arch, version, entry, phoff, shoff, flags, ehsize, phsize, phnum,
     shsize, shnum, shstr) = ELF_HEADER.unpack_from(raw)
    need(ident[:7] == b"\x7fELF\x02\x01\x01" and kind == 1 and arch == 183 and version == 1 and
         entry == phoff == flags == phnum == phsize == 0 and ehsize == ELF_HEADER.size and
         shsize == ELF_SECTION.size and 1 < shnum <= 2048 and 0 < shstr < shnum and
         ELF_HEADER.size <= shoff <= len(raw) - shsize * shnum,
         "Expected little-endian ELF64 AArch64 ET_REL with a bounded section table")
    sections = [ELF_SECTION.unpack_from(raw, shoff + i * shsize) for i in range(shnum)]
    need(not any(sections[0]) and sections[shstr][1] == 3, "Ordinary ELF section index required")
    for sec in sections:
        if sec[1] != 8:  # SHT_NOBITS has no on-disk contents.
            need(sec[4] <= len(raw) and sec[5] <= len(raw) - sec[4], "ELF section exceeds object")
    tables = [i for i, sec in enumerate(sections) if sec[1] == 2]  # SHT_SYMTAB
    need(len(tables) == 1, "One static symbol table required")
    sym_id = tables[0]
    sym = sections[sym_id]
    strings_idx = sym[6]
    need(0 < strings_idx < shnum and sections[strings_idx][1] == 3 and
         sym[9] == ELF_SYMBOL.size and sym[5] % ELF_SYMBOL.size == 0 and
         0 < sym[5] // ELF_SYMBOL.size <= 65536, "Bounded symbol and linked string tables required")
    strings = sections[strings_idx]
    names = raw[strings[4]:strings[4] + strings[5]]
    need(names[:1] == names[-1:] == b"\0", "ELF string table is not NUL terminated")
    md_indices, importer_defined = [], False
    for index, row in enumerate(ELF_SYMBOL.iter_unpack(raw[sym[4]:sym[4] + sym[5]])):
        name_offset, info, _, section, value, size = row
        need(name_offset < len(names), "ELF symbol name offset exceeds table")
        if names.startswith(b"md_parse\0", name_offset):
            need(section == value == size == 0 and info >> 4 in (1, 2) and info & 15 in (0, 2),
                 "Expected external undefined md_parse, with no local definition")
            md_indices.append(index)
        if names.startswith(IMPORTER + b"\0", name_offset):
            need(info & 15 == 2 and 0 < section < shnum and sections[section][1] == 1
                 and sections[section][2] & 4 and 0 < size <= sections[section][5] - value,
                 "Expected defined Qt Markdown importer function in executable code")
            importer_defined = True
    need(len(md_indices) == 1 and importer_defined, "Expected real Qt importer and exactly one undefined md_parse")
    calls = set()
    for reloc in sections:
        if reloc[1] != 4:  # SHT_RELA
            continue
        need(reloc[6] == sym_id and 0 < reloc[7] < shnum and reloc[9] == ELF_RELA.size
             and reloc[5] % ELF_RELA.size == 0, "Invalid ELF relocation table")
        target = sections[reloc[7]]
        if target[1] != 1 or not target[2] & 4:
            continue
        for offset, kind, addend in ELF_RELA.iter_unpack(raw[reloc[4]:reloc[4] + reloc[5]]):
            if kind >> 32 == md_indices[0] and kind & 0xFFFFFFFF in CALL_OPCODES:
                opcode = kind & 0xFFFFFFFF
                need(addend == 0 and offset % 4 == 0 and offset <= target[5] - 4 and
                     struct.unpack_from("<I", raw, target[4] + offset)[0] & 0xFC000000 == CALL_OPCODES[opcode],
                     "Expected a valid AArch64 direct branch relocation to md_parse")
                calls.add((reloc[7], offset))
    need(calls, "No executable relocation calls the external md_parse symbol")
    return {"class": "ELF64", "machine": "AArch64", "type": "ET_REL", "defined_importer": IMPORTER.decode(),
            "undefined_symbol": "md_parse", "executable_reference_count": len(calls)}


def serial_state(body, nonce):
    need(type(nonce) is str and NONCE.fullmatch(nonce), "Exact compile nonce required")
    markers = [line for line in body.splitlines() if line.startswith(b"QTMD4C16K ")]
    need(len(markers) == 1, "Exactly one compile terminal marker required")
    match = re.fullmatch(b"QTMD4C16K " + nonce.encode() +
                         rb" (PASS complete|HOLD (?:boot|storage|compile|complete))", markers[0])
    need(match is not None, "Expected the original nonce-bound compile terminal marker")
    state, phase = match[1].decode().split()
    return state == "PASS", phase


def serial_storage_reason(body, nonce, phase):
    markers = [line for line in body.splitlines() if line.startswith(b"QTMD4C16K_STORAGE")]
    if not markers:
        return None
    need(len(markers) == 1 and phase == "storage" and NONCE.fullmatch(nonce),
         "Expected one diagnostic on the original storage HOLD")
    prefix = b"QTMD4C16K_STORAGE " + nonce.encode() + b" "
    need(markers[0].startswith(prefix) and markers[0][len(prefix):] in STORAGE_REASONS,
         "Storage diagnostic has an unknown reason or nonce")
    return markers[0][len(prefix):].decode()


def verify_guest(files, nonce, passed, phase):
    status = "PASS" if passed else "HOLD"
    if "result.json" in files:
        body = json_object(files["result.json"], encoded=False)
        need(canonical(body) == canonical(dict(status=status, nonce=nonce, phase=phase, page_size=16384)),
             "Raw guest outcome differs from its nonce-bound serial marker")
    if not passed:
        return None
    need(files.keys() == EVIDENCE.keys(), "Missing original compile evidence")
    log = files["compile.log"]
    logged = set(log.splitlines())
    need({b"/usr/include/md4c.h: OK", b"/usr/lib/libmd4c.so.0.5.3: OK",
          b"/qt-recipe/src/build/build.ninja: OK"} <= logged,
         "Compile log must record checks of the selected md4c and Ninja bytes")
    header = files["importer.elf"]
    symbols = files["importer.symbols"]
    need(all(re.search(pattern, header, re.M) for pattern in (
        rb"^[ \t]*Class:[ \t]+ELF64[ \t]*$", rb"^[ \t]*Type:[ \t]+REL(?:[ \t][^\r\n]*)?$",
        rb"^[ \t]*Machine:[ \t]+AArch64[ \t]*$")) and
        any(len(row.split()) >= 8 and row.split()[6:8] == [b"UND", b"md_parse"] for row in symbols.splitlines()),
        "Guest object diagnostics differ from the expected AArch64 importer record")
    return verify_object(files["importer.o"])


def runtime_receipt(output, label, expected, argv, seconds, size_cap=None):
    receipt, receipt_pin = evidence_object(output / (label + ".json"), expected)
    elapsed, cap = receipt["operation_seconds"], receipt["operation_cap_seconds"]
    need(receipt["argv"] == argv and type(receipt["exit"]) is int and receipt["exit"] == 0 and
         receipt["ownership"] == "REAPED" and receipt["group_census"] == "EMPTY_TWICE" and
         receipt["passed"] is receipt["reaped"] is receipt["output_complete"] is True and
         receipt["timeout"] is receipt["command_timed_out"] is receipt["original_budget_overrun"] is
         receipt["emergency_retirement"] is False and receipt["emergency_retirement_cap_seconds"] is None and
         receipt["command_cancelled"] == receipt["signals"] == [] and receipt["error"] is None and
         type(elapsed) in (float, int) and type(cap) in (float, int) and 0 < elapsed <= cap <= seconds and
         type(receipt["child_file_size_cap"]) is type(size_cap) and receipt["child_file_size_cap"] == size_cap,
         f"Exact natural owned command retirement required: {label}")
    stdout, stdout_pin = read(output / (label + ".stdout"), SERIAL_CAP)
    stderr, stderr_pin = read(output / (label + ".stderr"), SERIAL_CAP)
    need(len(stdout) + len(stderr) <= SERIAL_CAP, f"Combined command streams exceed their cap: {label}")
    _, all_pin = read(output / (label + ".log"), SERIAL_CAP, pin(stdout + stderr))
    return dict(receipt=receipt_pin, stdout=stdout_pin, stderr=stderr_pin, log=all_pin), stdout


def require_capacity(row, policy, *, admission):
    gate = policy["admission_disk_bytes"]
    reserve = policy["watched_tree"][2]
    measurements = ("free_bytes", "memory_available_bytes", "allowed_cpus")
    minima = ("required_bytes", "minimum_memory_bytes", "minimum_cpus")
    need(set(row) == set(measurements + minima) | {"fits"} and
         all(type(row[key]) is int and row[key] >= 0 for key in measurements + minima) and
         tuple(row[key] for key in minima) == (gate, 6 << 30, 4) and
         row["fits"] is all(row[key] >= row[minimum] for key, minimum in zip(measurements, minima)) and
         (row["fits"] if admission else row["free_bytes"] >= reserve), "Exact live compile capacity record required")


def require_watch(rows, policy, overlay_bytes):
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
    start, end, peak = rows["before"], rows["after"], rows["peak"]
    need(all(peak[key] >= max(start[key], end[key]) for key in caps) and
         peak["free"] <= min(start["free"], end["free"]) and end["overlay_eof"] == overlay_bytes and
         end["result_allocated"] > 0, "Owned allocation extrema differ from actual final overlay and result")


def require_initial_overlay(body, eof, policy):
    spec = importlib.util.spec_from_file_location("md4c_readback_prepare", HERE / "prepare.py")
    prepare = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(prepare)
    need(type(policy["overlay_logical_bytes"]) is int and policy["overlay_logical_bytes"] == prepare.WORK,
         "Exact sealed raw backing size required")
    prepare.validate_empty_overlay(body, eof)


def actor_result(output, data, plan, meta, host_exit):
    labels = ("overlay-create", "overlay-inspect", "qemu", "fsck-result")
    names = {"actor-result.json", "result.raw", "overlay.qcow2"} | {
        label + "." + ext for label in labels for ext in ("json", "stdout", "stderr", "log")}
    actual = {path.name for path in output.iterdir()}
    need(output.resolve() == output and "result.raw" in actual and actual <= names,
         "Exact bounded actor output namespace required")
    if "actor-result.json" not in actual:
        need(0 < host_exit < 124, "Successful actor exit requires complete original result")
        caps = {"result.raw": RESULT_BYTES, "overlay.qcow2": plan["actor"]["child_file_size_cap"]}
        for label in labels:
            for ext in ("stdout", "stderr", "log", "json"):
                caps[label + "." + ext] = (128 << 10) if ext == "json" else SERIAL_CAP
        available = {name: read(output / name, caps[name], collect=False) for name in sorted(actual)}
        return dict(status="HOLD_NO_COMPLETE_ACTOR_REPORT", evidence=available,
                    full_Qt_build="NOT_RUN", physical_M2="NOT_RUN", Root_acceptance=None)
    need(actual == names, "Complete actor report requires all original evidence")
    report, report_pin = evidence_object(output / "actor-result.json")
    keys = {"kind", "status", "phase", "nonce", "authority_sha256", "handoff_sha256", "plan_sha256", "tools",
            "watched_tree", "watched_paths", "capacity_before", "capacity_after", "allocation", "qemu", "serial",
            "fsck_result", "overlay_create", "overlay_inspect", "overlay_inspect_stdout", "overlay_initial_eof",
            "result_disk", "overlay", "result_uuid", "native_Qt_full_build", "physical_M2", "Root_acceptance"}
    policy = plan["actor"]
    need(report.keys() == keys and report["kind"] == "QT_MD4C_ACTOR_RESULT_V1" and
         all(report[key] == meta[key] for key in ("nonce", "authority_sha256", "handoff_sha256", "plan_sha256")) and
         report["result_uuid"] == data["result_uuid"] and report["tools"] == policy["profile"]["tools"] and
         report["watched_tree"] == policy["watched_tree"] and report["watched_paths"] == policy["watched_paths"] and
         report["native_Qt_full_build"] == report["physical_M2"] == "NOT_RUN" and report["Root_acceptance"] is None,
         "Exact sealed actor and bounded tool report required")
    require_capacity(report["capacity_before"], policy, admission=True)
    require_capacity(report["capacity_after"], policy, admission=False)
    overlay = read(output / "overlay.qcow2", policy["child_file_size_cap"], report["overlay"], collect=False)
    require_watch(report["allocation"], policy, overlay["bytes"])
    streams = {}
    for label, key, argv, seconds, size_cap in (
        ("overlay-create", "overlay_create", policy["overlay_create"], 10, None),
        ("overlay-inspect", "overlay_inspect", policy["overlay_inspect"], 10, None),
        ("qemu", "qemu", plan["qemu_argv"], plan["qemu_seconds"], policy["child_file_size_cap"]),
        ("fsck-result", "fsck_result", ["/usr/bin/e2fsck", "-fn", "/out/result.raw"], 60, None),
    ):
        observed, stdout = runtime_receipt(output, label, report[key], argv, seconds, size_cap)
        streams[label] = observed
        if label == "overlay-inspect":
            need(observed["stdout"] == report["overlay_inspect_stdout"], "Initial overlay stdout pin differs")
            require_initial_overlay(stdout, report["overlay_initial_eof"], policy)
        if label == "qemu":
            need(observed["stdout"] == report["serial"], "Original compile serial pin differs")
            passed, phase = serial_state(stdout, report["nonce"])
            storage_reason = serial_storage_reason(stdout, report["nonce"], phase)
    status = "PASS_QT_MD4C_IMPORTER_OBJECT_FOR_ROOT_REVIEW" if passed else "HOLD"
    need(report["status"] == status and report["phase"] == phase and host_exit == (0 if passed else 2),
         "Actor status, serial and naturally retired Docker exit differ")
    files = result_files(output / "result.raw", report["result_disk"], data["result_uuid"], passed)
    facts = verify_guest(files, report["nonce"], passed, phase)
    return dict(status="PASS_EXACT_QT_MD4C_IMPORTER_OBJECT_ONLY" if passed else "HOLD", phase=phase,
                actor_report=report_pin, commands=streams, object=facts, overlay=overlay,
                result_disk=report["result_disk"], result_uuid=report["result_uuid"],
                allocation=report["allocation"], evidence={name: pin(body) for name, body in files.items()},
                full_Qt_build="NOT_RUN", physical_M2="NOT_RUN", Root_acceptance=None,
                **({"storage_reason": storage_reason} if storage_reason is not None else {}))


def host_result(entry, attempt, data, plan, handoff_sha, authority_sha, closure):
    selection, authority_pin = external(attempt / "selection.json", authority_sha)
    issued = entry.verify_selection(selection, authority_sha, data, plan, handoff_sha, live=False)
    need(issued["nonce"] == plan["nonce"], "Selection must use the sealed plan nonce")
    cid_body, _ = read(attempt / "run.cid", 65)
    need(re.fullmatch(rb"[a-f0-9]{64}\n?", cid_body), "Exact original Docker CID required")
    cid = cid_body.strip().decode()
    scope_raw, _ = read(attempt / "scope.path", 1024)
    scope = data["scope"]
    need(re.fullmatch(rb"(?:/[A-Za-z0-9_.@-]+)+\n", scope_raw) and
         scope_raw.endswith(("/" + scope + "\n").encode()), "Exact original systemd scope group required")
    group = scope_raw[:-1].decode()
    record = dict(authority_sha256=authority_sha, scope=scope, scope_group=group, cid=cid)
    expected_closure = dict(kind="QT_MD4C_POST_SCOPE_READBACK_V1", observations=[EMPTY, EMPTY], **record)
    need(canonical(closure) == canonical(expected_closure), "Independent twice-absent original CID and scope required")
    meta, meta_pin = evidence_object(attempt / "attempt.json")
    need(canonical(meta) == canonical(entry.attempt_meta(data, plan, handoff_sha, authority_sha, group, attempt)) and
         meta["nonce"] == issued["nonce"] and meta["plan_sha256"] == data["plan"]["sha256"],
         "Original once-claimed attempt identity differs")
    claim, _ = read(attempt.parent / "root-run.claim/attempt.path", 4096)
    need(claim == (str(attempt) + "\n").encode(), "Exact original attempt claim required")
    prior_closures = data["prior_closures"]
    need(type(prior_closures) is dict and prior_closures and
         all(re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,31}", stage) for stage in prior_closures) and
         any(ref["sha256"] == plan["q3_closure_sha256"] for ref in prior_closures.values()),
         "Exact closure roles including the pinned configure predecessor required")
    prior_pins = {}
    for stage, ref in prior_closures.items():
        expected = {name: ref[name] for name in ("bytes", "sha256")}
        prior_pins[stage] = read(attempt / f"prior-{stage}-closure.json", 128 << 10, expected, collect=False)
    cap, cap_pin = evidence_object(attempt / "capacity.json", cap=4096)
    require_capacity(cap, plan["actor"], admission=True)
    report, report_pin = evidence_object(attempt / "host-result.json")
    exit_code = report["exit_code"]
    need(type(exit_code) is int and 0 <= exit_code < 124, "Original compile actor did not retire naturally")
    expected_host = dict(kind="QT_MD4C_HOST_RETIREMENT_V1", nonce=issued["nonce"], natural=True,
                         exit_code=exit_code, container_removed=True, absent_twice=True, **record)
    need(canonical(report) == canonical(expected_host) and
         read(attempt / "run.state", 64)[0] == f"exited {exit_code} false\n".encode() and
         read(attempt / "run.attach-exit", 8)[0] == f"{exit_code}\n".encode() and
         all(read(attempt / f"run.absence-{i}", 128)[0] == b"" for i in (1, 2)),
         "Original natural Docker exit, exact CID and two removal observations required")
    inspects = []
    inspect_pins = {}
    for phase in ("created", "exited"):
        raw, inspect_pins[phase] = read(attempt / f"run.{phase}.inspect.json", 512 << 10)
        rows = decode(raw)
        need(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict, "Exact one Docker inspect object required")
        inspects.append(rows[0])
    entry.matching_inspects(*inspects, attempt, meta, cid, exit_code, data)
    streams = {name: read(attempt / f"run.{name}", 2 << 20, collect=False) for name in ("stdout", "stderr")}
    return (meta, exit_code, dict(attempt=meta_pin, authority=authority_pin, capacity=cap_pin,
                                  predecessor_closures=prior_pins, retirement=report_pin,
                                  inspect=inspect_pins, streams=streams, exit_code=exit_code,
                                  nonce=issued["nonce"], **record))


def result(attempt, handoff_sha, authority_sha, closure_path, closure_sha, *, entry):
    """Verify a site-authenticated attempt in a dedicated read-only Python process.

    The caller supplies its trusted site adapter, which authenticates the handoff and
    plan, verifies the selection, reconstructs the attempt metadata, and compares the
    pinned actor inspections. The authenticated handoff supplies the scope, operand
    root, result UUID, plan pin, and all mandatory prior closure pins by role.
    """
    need(sys.flags.isolated and sys.dont_write_bytecode and __debug__, "Readback requires isolated unoptimized Python")
    sys.addaudithook(audit_fence)
    need(attempt.is_absolute() and attempt.resolve() == attempt and
         re.fullmatch(r"issued\.[a-z0-9_]+", attempt.name), "Exact ordinary claimed attempt path required")
    handoff_path = attempt.parent / "HANDOFF.DATA.json"
    handoff_raw, _ = external(handoff_path, handoff_sha)
    root, data, plan = entry.load_handoff(handoff_path, handoff_sha)
    need(root == attempt.parent and canonical(data) == canonical(json_object(handoff_raw, encoded=False)),
         "Attempt must use the exact sealed compile packet")
    template_root = Path(data["operand_root"])
    plan_raw, plan_pin = read(template_root / "PLAN.UNISSUED.json", 128 << 10, data["plan"])
    need(canonical(plan) == plan_raw and set(plan["inputs"]) == {"Image", "boot.raw", "scratch.raw", "result.raw"},
         "Adapter must select the exact sealed operand plan")
    raw, post_scope = external(closure_path, closure_sha)
    closure = json_object(raw)
    meta, host_exit, host = host_result(entry, attempt, data, plan, handoff_sha, authority_sha, closure)
    guest = actor_result(attempt / "output", data, plan, meta, host_exit)
    template = template_root / "output/result.raw"
    need(not template.samefile(attempt / "output/result.raw"), "Retired result must be a fresh independent inode")
    input_pins = {name: read(template if name == "result.raw" else template_root / "inputs" / name,
                             expected["bytes"], expected, collect=False)
                  for name, expected in plan["inputs"].items()}
    return dict(kind="QT_MD4C_INDEPENDENT_READBACK_V1", handoff_sha256=handoff_sha,
                plan=plan_pin, original_inputs=input_pins, host=host, post_scope=post_scope, **guest)
