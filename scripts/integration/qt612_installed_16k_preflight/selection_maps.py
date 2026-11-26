#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Derive unissued installed Qtbase payload and mandatory provider selection data."""

import argparse
from collections import defaultdict
from contextlib import contextmanager
from functools import cached_property
import io
import lzma
import math
import os
from pathlib import Path, PurePosixPath
import re
from runpy import run_path
import stat
import sys
import tarfile
import time
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
W = SimpleNamespace(**run_path(str(HERE / "worker.py")))
P, T = W.P, W.T
H = SimpleNamespace(**run_path(str(HERE / "package_handoff.py")))
PKG = SimpleNamespace(**run_path(str(P.ROOT / "scripts/checks/package_checks.py")))
pax_fields = run_path(str(P.ROOT / "scripts/port/qt612-gui-native-v1/archive.py"))["pax_fields"]
ELF = SimpleNamespace(**run_path(str(P.ROOT / "scripts/ci/platform-namespace-rootfs-v1/elf64le_aarch64.py")))
bounded_process = run_path(str(P.PROJECT / "lifecycle.py"))["bounded_process"]

MIB = 1 << 20
ARCHIVE_STREAM = PKG.MAX_TOTAL + 16 * MIB
ALPM = "/var/lib/pacman/local"
CONTROLS = {".PKGINFO", ".BUILDINFO", ".MTREE"}
INTERPRETER = "/lib/ld-linux-aarch64.so.1"
WAYLAND = "libwayland-server.so.0"
RESULT = "QTBASE16K_INSTALLED_SELECTION_MAPS_UNISSUED_V1"
SUPPLEMENT = "QTBASE16K_INSTALLED_SUPPLEMENTARY_SONAMES_V1"
PATH_PART = re.compile(r"[A-Za-z0-9_.+@:-]{1,255}")
COMMAND_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"}


@contextmanager
def hold(path, pin, cap):
    path = T.ordinary(path)
    identity = T.identity(path.lstat())
    H.C.read(path, cap, pin, collect=False)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOATIME
    with os.fdopen(os.open(path, flags), "rb") as stream:
        T.need(T.identity(os.fstat(stream.fileno())) == identity, "Original operand changed after pin verification")
        yield stream
        T.need(T.identity(os.fstat(stream.fileno())) == T.identity(path.lstat()) == identity,
               "Original operand changed during selection preparation")


def command(argv, limit, seconds=10):
    row = bounded_process(argv, timeout=seconds, stdout_limit=limit, stderr_limit=8192, env=COMMAND_ENV)
    T.need(row["returncode"] == 0 and row["reason"] == "exit" and row["cleanup"]["reaped"],
           "Bounded read-only command failed: " + argv[0] + " (" + row["reason"] + ")")
    return row["stdout"], row["stderr"]


def guest_path(path):
    pieces = path.split("/")[1:]
    T.need(path.startswith("/") and len(path) <= 1024
           and all(PATH_PART.fullmatch(part) and part not in (".", "..") for part in pieces),
           "Unsupported guest lookup path: " + path)
    return pieces


def expand_archive(stream):
    """Apply the existing Qt archive reader's single-stream XZ bounds in memory."""
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=256 * MIB)
    deadline = time.monotonic() + 120
    with io.BytesIO() as expanded:
        while not decoder.eof:
            T.need(time.monotonic() < deadline, "Qt package decompression exceeded time limit")
            compressed = stream.read(MIB) if decoder.needs_input else b""
            T.need(compressed or not decoder.needs_input, "Truncated Qt package XZ stream")
            block = decoder.decompress(compressed, max_length=MIB)
            T.need(expanded.tell() + len(block) <= ARCHIVE_STREAM, "Expanded Qt package exceeds bounds")
            expanded.write(block)
        T.need(not decoder.unused_data and not stream.read(1), "Trailing data after Qt package XZ stream")
        return expanded.getvalue()


def archive_headers(raw):
    """Check the physical limits before tarfile interprets PAX extensions."""
    offset = headers = extended = consecutive_extensions = 0
    while offset + 512 <= len(raw):
        block = raw[offset:offset + 512]
        if block == bytes(512):
            T.need(not consecutive_extensions and offset + 1024 <= len(raw)
                   and len(raw) % 512 == 0 and not any(raw[offset:]),
                   "Expected complete zero tar end markers and padding")
            return
        T.need(block[257:263] in (b"ustar\0", b"ustar "), "Expected USTAR or PAX archive header")
        info = tarfile.TarInfo.frombuf(block, "utf-8", "strict")
        headers += 1
        T.need(headers <= 32768 and 0 <= info.size <= PKG.MAX_MEMBER and
               info.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE, tarfile.SYMTYPE,
                             tarfile.XHDTYPE, tarfile.XGLTYPE),
               "Unsupported or excessive physical tar members")
        if info.type in (tarfile.XHDTYPE, tarfile.XGLTYPE):
            extended += info.size
            consecutive_extensions += 1
            T.need(consecutive_extensions <= 2 and 0 < info.size <= 65536
                   and extended <= MIB and offset + 512 + info.size <= len(raw),
                   "Tar extension metadata exceeds bounds")
            fields = pax_fields(raw[offset + 512:offset + 512 + info.size])
            T.need("size" not in fields and (info.type != tarfile.XGLTYPE or
                   not {"path", "linkpath", "uid", "gid"} & fields.keys()), "Unsupported PAX archive overrides")
        else:
            consecutive_extensions = 0
        offset += 512 + ((info.size + 511) // 512) * 512
    raise ValueError("Truncated tar member or missing end markers")


def elf_object(body):
    facts = ELF.parse_elf(body)
    T.need(facts is not None and facts["type"] in (2, 3) and facts["dynamic"]
           and len(facts["needed"]) <= 128 and all(row["alignment"] >= 16384 for row in facts["loads"]),
           "Expected a dynamic AArch64 object with 16 KiB load alignment")
    return facts


def archive_maps(raw, plan):
    archive_headers(raw)
    seen, nodes, payload, elf, controls = set(), {}, {}, {}, {}
    owner = plan["package"]["package"]
    total = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:", encoding="utf-8", errors="strict") as archive:
        for member in archive:
            name = PKG.clean_name(member.name)
            T.need(name not in seen and len(seen) < 32768 and
                   member.name in (name, "./" + name), "Duplicate or noncanonical archive member: " + name)
            seen.add(name)
            T.need(member.uid == member.gid == 0 and not member.mode & 0o6000
                   and not member.sparse and 0 <= member.size <= PKG.MAX_MEMBER,
                   "Unsupported Qt package ownership, mode or size: " + name)
            total += member.size
            T.need(total <= PKG.MAX_TOTAL, "Archive member data exceeds package checker bound")
            kind = "directory" if member.isdir() else "symlink" if member.issym() else "file"
            T.need(member.isdir() or member.isfile() or member.issym(), "Unexpected type in Qt archive: " + name)
            T.need(kind == "file" or member.size == 0, "Non-file archive member has data")
            if name in CONTROLS:
                T.need(kind == "file" and 0 < member.size <= 4 * MIB, "Invalid Qt package control file")
                controls[name] = archive.extractfile(member).read()
                continue
            path = "/" + name
            if name == ".":
                T.need(kind == "directory", "Archive root must be a directory")
                continue
            T.need(path.startswith("/usr/") or (path == "/usr" and kind == "directory"),
                   "Non-/usr member in selected Qt archive: " + path)
            T.need(str(PurePosixPath(path)) == path and len(path) <= 1024
                   and all(32 < ord(ch) < 127 for ch in path), "Expected bounded ASCII Qt package member")
            nodes[path] = (kind, member.linkname if kind == "symlink" else None)
            if kind == "directory":
                continue
            if kind == "symlink":
                T.need(0 < len(member.linkname) <= 1024 and
                       all(32 < ord(ch) < 127 for ch in member.linkname) and "\\" not in member.linkname,
                       "Unexpected Qt package link target")
                payload[path] = dict(type=kind, owner=owner, target=member.linkname)
                continue
            body = archive.extractfile(member).read()
            T.need(len(body) == member.size, "Truncated Qt archive file")
            payload[path] = dict(type=kind, owner=owner, pin=T.pin(body))
            if path.startswith("/usr/lib/") and body.startswith(b"\x7fELF"):
                elf[path] = elf_object(body)
    T.need(controls.keys() == CONTROLS, "Complete original Qt package controls required")
    for path in nodes:
        T.need(all(str(parent) not in nodes or nodes[str(parent)][0] == "directory"
                   for parent in PurePosixPath(path).parents), "Non-directory Qt archive ancestor")
    package = PKG.metadata(controls[".PKGINFO"].decode("utf-8"))
    build = PKG.metadata(controls[".BUILDINFO"].decode("utf-8"))
    version = plan["package"]["version"]
    T.need(package["pkgname"] == build["pkgname"] == [owner] and
           package["pkgver"] == build["pkgver"] == [version] and
           package["arch"] == build["pkgarch"] == ["aarch64"], "Wrong Qt package identity")
    W.check_payload_selection(plan, payload)
    return payload, nodes, elf


class Q3:
    """Read the original Q3 filesystem through a held read-only descriptor."""

    def __init__(self, held_path, packages):
        self.held_path, self.packages = held_path, packages
        self.nodes = {}
        self.deadline = time.monotonic() + 120

    def debugfs(self, operation, path, cap, *, absent=False):
        guest_path(path)
        operand = "/root" + path
        remaining = self.deadline - time.monotonic()
        T.need(remaining > 0, "Read-only Q3 lookup exceeded its total time limit")
        stdout, stderr = command(["/usr/bin/debugfs", "-R", operation + " " + operand, self.held_path], cap,
                                 seconds=min(10, remaining))
        lines = stderr.splitlines()
        T.need(lines and lines[0].startswith(b"debugfs "), "Expected original debugfs diagnostic header")
        if absent and not stdout and lines[1:] == [os.fsencode(operand) + b": File not found by ext2_lookup "]:
            return None
        T.need(len(lines) == 1, "Read-only Q3 lookup failed: " + path)
        return stdout

    def node(self, path):
        if path not in self.nodes:
            raw = self.debugfs("stat", path, 16384, absent=True)
            if raw is None:
                self.nodes[path] = None
            else:
                header = re.search(rb"^Inode: \d+ +Type: (regular|directory|symlink) ", raw)
                T.need(header, "Expected ordinary Q3 filesystem node: " + path)
                kind = header[1].decode()
                target = None
                if kind == "symlink":
                    link = re.search(rb'^Fast link dest: "([^"\r\n]+)"$', raw, re.M)
                    T.need(link, "Unsupported non-inline Q3 symlink: " + path)
                    target = link[1].decode("ascii")
                self.nodes[path] = ("file" if kind == "regular" else kind, target)
        return self.nodes[path]

    def file(self, path, cap):
        T.need(self.node(path) == ("file", None), "Expected original Q3 regular file: " + path)
        return self.debugfs("cat", path, cap)

    @cached_property
    def cache(self):
        T.need(self.node("/etc/ld.so.preload") is None, "Q3 loader preload policy needs independent review")
        raw = self.file("/etc/ld.so.cache", MIB)
        fd = os.memfd_create("qtbase16k-q3-ld-cache", os.MFD_CLOEXEC)
        with os.fdopen(fd, "wb", buffering=0) as stream:
            T.need(stream.write(raw) == len(raw), "Short original Q3 cache staging")
            stdout, stderr = command(["/usr/bin/ldconfig", "-p", "-C", f"/proc/{os.getpid()}/fd/{fd}"], 2 * MIB)
        T.need(not stderr, "Original Q3 loader cache parser diagnostic")
        first, *lines = stdout.decode("ascii").splitlines()
        count = re.match(r"^([0-9]+) libs? found in cache ", first)
        if lines and lines[-1].startswith("Cache generated by: "):
            lines.pop()
        T.need(count and 0 < len(lines) == int(count[1]) <= 8192, "Unexpected original Q3 loader cache census")
        result = defaultdict(list)
        for line in lines:
            row = re.fullmatch(r"\t(\S+) \(libc6,AArch64\) => (\S+)", line)
            T.need(row, "Unsupported Q3 cache ABI or hardware-capability row")
            ELF.library_name(row[1])
            guest_path(row[2])
            T.need(len(result[row[1]]) < 32 and row[2] not in result[row[1]], "Repeated or excessive Q3 cache alias")
            result[row[1]].append(row[2])
        return dict(result)

    def owners(self, pins):
        wanted = {name[1:].encode(): name for name in pins}
        result, total = {}, 0
        for owner, version in self.packages.items():
            entry = f"{ALPM}/{owner}-{version}"
            raw = self.debugfs("cat", entry + "/files", 4 * MIB)
            total += len(raw)
            T.need(total <= 64 * MIB, "Total ALPM file ownership exceeds bounds")
            if not raw:
                # Meta-packages have an ordinary empty files record.
                continue
            T.need(raw.startswith(b"%FILES%\n") and b"\n\n" in raw,
                   "Invalid original ALPM file ownership: " + owner)
            files = raw.split(b"\n\n", 1)[0].split(b"\n")[1:]
            matched = [wanted[name] for name in files if name in wanted]
            if not matched:
                continue
            desc = self.debugfs("cat", entry + "/desc", 128 << 10)
            fields = desc.split(b"\n\n")
            for key, value in (("NAME", owner), ("VERSION", version)):
                expected = f"%{key}%\n{value}".encode("ascii")
                T.need([field for field in fields if field.startswith(f"%{key}%\n".encode())] == [expected],
                       "Q3 ALPM package identity differs from the independently pinned inventory")
            for path in matched:
                T.need(path not in result, "Ambiguous Q3 ALPM file owner: " + path)
                result[path] = dict(owner=owner, version=version, pin=pins[path])
        T.need(result.keys() == pins.keys(), "Missing original ALPM file owner: " + ", ".join(sorted(pins.keys() - result)))
        return result


def resolve(path, node):
    visited = set()
    for _ in range(40):
        T.need(path not in visited, "Cyclic guest symlink")
        visited.add(path)
        parts = guest_path(path)
        for i in range(1, len(parts) + 1):
            name = "/" + "/".join(parts[:i])
            row = node(name)
            if row is None:
                return None
            kind, target = row
            if kind == "symlink":
                base = target if target.startswith("/") else str(PurePosixPath(name).parent / target)
                components = []
                for part in base.split("/") + parts[i:]:
                    if part == "..":
                        T.need(components, "Guest symlink escapes its root")
                        components.pop()
                    elif part not in ("", "."):
                        components.append(part)
                path = "/" + "/".join(components)
                break
            T.need(i == len(parts) or kind == "directory", "Guest search has a non-directory ancestor")
        else:
            return path if kind == "file" else None
    raise ValueError("Guest symlink depth exceeds bound")


def provider_map(plan, nodes, packaged, q3, supplementary):
    libraries, _, _ = W.payload_requirements(plan)
    pins, metadata, closed = {}, dict(packaged), set()
    total_provider_bytes = 0

    def node(path):
        return nodes[path] if path in nodes else q3.node(path)

    def facts(path):
        nonlocal total_provider_bytes
        T.need(path.startswith("/usr/lib/"), "Provider resolves outside canonical /usr/lib: " + path)
        if path not in metadata:
            T.need(path not in nodes, "Archive dependency is not a dynamic ELF object: " + path)
            body = q3.file(path, PKG.MAX_MEMBER)
            total_provider_bytes += len(body)
            T.need(total_provider_bytes <= 512 * MIB, "Original Q3 provider byte total exceeds bound")
            metadata[path] = elf_object(body)
            pins[path] = T.pin(body)
        return metadata[path]

    def lookup(name, directories):
        ELF.library_name(name)
        for directory in directories:
            T.need(node("/" + directory + "/glibc-hwcaps") is None,
                   "A guest hardware-capability search directory requires independent review")
        aliases = ["/" + directory + "/" + name for directory in directories] + q3.cache.get(name, [])
        paths = {resolve(alias, node) for alias in aliases} - {None}
        T.need(len(paths) == 1, "Missing or ambiguous static provider for " + name)
        path, = paths
        T.need(facts(path)["soname"] == name, "Provider ELF SONAME differs for " + name)
        return path

    canonical_interpreter = resolve(INTERPRETER, node)
    T.need(canonical_interpreter == "/usr/lib/ld-linux-aarch64.so.1" and
           facts(canonical_interpreter)["soname"] == PurePosixPath(INTERPRETER).name,
           "Expected exact Q3 AArch64 interpreter")
    roots = [canonical_interpreter, W.OFFSCREEN]
    for soname, path in libraries.items():
        T.need(lookup(soname, ELF.DEFAULT_DIRS) == path, "The selected Qt SONAME alias resolves elsewhere")
        roots.append(path)
    roots.extend(lookup(name, ELF.DEFAULT_DIRS) for name in [WAYLAND, *(row["soname"] for row in supplementary)])
    while roots:
        path = roots.pop()
        if path in closed:
            continue
        T.need(len(closed) < 512, "Static provider closure exceeds bound")
        closed.add(path)
        row = facts(path)
        if row["interpreter"] is not None:
            T.need(resolve(row["interpreter"], node) == canonical_interpreter,
                   "Unexpected ELF interpreter for " + path)
        directories = ELF.search_directories(path[1:], row)
        roots.extend(lookup(name, directories) for name in row["needed"])
    return q3.owners(pins)


def load_supplement(path, sha):
    if path is None:
        T.need(sha is None, "A supplementary SONAME pin requires its input file")
        return [], None
    raw, pin = H.C.external(path, 32 << 10, sha)
    value = H.C.json_body(raw, canonical=True)
    T.need(value.keys() == {"kind", "roots"} and value["kind"] == SUPPLEMENT
           and type(value["roots"]) is list and len(value["roots"]) <= 64,
           "Closed bounded supplementary SONAME inputs required")
    names = []
    for row in value["roots"]:
        T.need(row.keys() == {"soname", "reason"} and type(row["reason"]) is str and
               0 < len(row["reason"]) <= 512 and all(32 <= ord(ch) < 127 for ch in row["reason"]),
               "Supplementary SONAME requires a reviewed nonempty reason")
        names.append(ELF.library_name(row["soname"]))
    T.need(names == sorted(set(names)), "Supplementary SONAME roots must be unique and sorted")
    return value["roots"], pin


def prepare(stage, plan_sha, archive, handoff_path, handoff_sha, supplement=None, supplement_sha=None):
    inventory = T.read(stage / "inputs/expected356.lock", P.Q3_INVENTORY, cap=16 << 10)
    raw, plan_pin = H.C.external(stage / "inputs/PLAN.json", 64 << 10, plan_sha)
    plan = W.read_plan(raw, plan_sha, inventory)
    handoff, handoff_pin = H.receipt(handoff_path, handoff_sha, 16 << 10)
    T.need(archive.name == H.ARCHIVE_NAME and handoff.keys() == {
               "kind", "status", "authority", "package_nonce", "archive", "packaging_receipt",
               "package_actor", "package_retirement", "result_fsck", "signing", "installation"}
           and handoff["kind"] == "QTBASE16K_UNSIGNED_ARCHIVE_HANDOFF_V1"
           and handoff["status"] == "PASS_UNSIGNED_ARCHIVE_FOR_TEST_REVIEW" and handoff["authority"] is None
           and handoff["signing"] == handoff["installation"] == "NOT_RUN"
           and H.W.NONCE.fullmatch(handoff["package_nonce"]), "Exact retired unsigned Qt package handoff required")
    W.pin_shape(handoff["archive"], W.INPUT_LIMITS["archive"])
    W.pin_shape(handoff["packaging_receipt"], 256 << 10)
    W.pin_shape(handoff["package_actor"], 16 << 10)
    W.pin_shape(handoff["package_retirement"], 16 << 10)
    fsck = handoff["result_fsck"]
    T.need(fsck.keys() == {"receipt", "stdout", "stderr", "log", "elapsed_seconds"}
           and type(fsck["elapsed_seconds"]) in (int, float) and math.isfinite(fsck["elapsed_seconds"])
           and 0 < fsck["elapsed_seconds"] <= 60, "Original package result filesystem receipt required")
    W.pin_shape(fsck["receipt"], 128 << 10)
    for name in ("stdout", "stderr", "log"):
        W.pin_shape(fsck[name], H.E.SERIAL_CAP, minimum=0)
    T.need(fsck["stdout"]["bytes"] + fsck["stderr"]["bytes"] == fsck["log"]["bytes"] <= H.E.SERIAL_CAP,
           "Original result filesystem receipt streams differ")
    supplementary, supplementary_pin = load_supplement(supplement, supplement_sha)
    with hold(archive, handoff["archive"], W.INPUT_LIMITS["archive"]) as held:
        payload, nodes, elf = archive_maps(expand_archive(held), plan)
    scratch = Path(plan["baseline"]["scratch"]["path"])
    with hold(scratch, P.Q3_SCRATCH, P.Q3_SCRATCH["bytes"]) as held:
        fd_path = f"/proc/{os.getpid()}/fd/{held.fileno()}"
        q3 = Q3(fd_path, T.canonical_lock(inventory, 356))
        providers = provider_map(plan, nodes, elf, q3, supplementary)
    W.check_provider_selection(inventory, providers)
    return dict(kind=RESULT, authority=None, plan=plan_pin, handoff=handoff_pin,
                archive=handoff["archive"], packaging_receipt=handoff["packaging_receipt"],
                baseline={"scratch": P.Q3_SCRATCH, "inventory": P.Q3_INVENTORY, "terminal": P.Q3_TERMINAL},
                supplementary_roots=supplementary, supplementary_pin=supplementary_pin, payload=payload,
                mandatory_providers=providers, loader="STATIC_MANDATORY_CLOSURE_ONLY",
                signing="NOT_RUN", installation="NOT_RUN")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("stage", "archive", "handoff"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("plan-sha256", "handoff-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--supplementary-roots", type=Path,
                        help="canonical " + SUPPLEMENT + " JSON with sorted soname/reason rows")
    parser.add_argument("--supplementary-roots-sha256", help="externally selected digest of the optional roots file")
    args = parser.parse_args()
    try:
        result = prepare(args.stage, args.plan_sha256, args.archive, args.handoff, args.handoff_sha256,
                         args.supplementary_roots, args.supplementary_roots_sha256)
        sys.stdout.buffer.write(T.encoded(result))
    except (OSError, ValueError, TypeError, KeyError, AttributeError, lzma.LZMAError, tarfile.TarError) as error:
        sys.exit(f"Qtbase installed selection maps refused: {error}")


if __name__ == "__main__":
    main()
