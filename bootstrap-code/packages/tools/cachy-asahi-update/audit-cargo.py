#!/usr/bin/env python3
"""Data-only Cargo source collection. Never runs Cargo or crate code.

The report is evidence, not license, build-script, or distribution approval.
Archives and inert unpacked sources are retained in a private /tmp directory.
"""
import argparse
import concurrent.futures
import hashlib
import gzip
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import tempfile
import time
import tomllib
import urllib.request

COMMIT = "e2b1b7144be71cf392809f48d1440f8da1d9c81a"
LOCK_SHA256 = "0f12cdc2bd6e3838d67b08f0566f75f477bc83121196cf14d0ea5ce07faa3753"
LOCAL_MANIFEST_SHA256 = "fcae83c668f4aa18800450ca165d87cd929cbf1141f33177628c32e451a2582a"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
MAX_ARCHIVE = 32 * 1024 * 1024
MAX_FILE = 64 * 1024 * 1024
MAX_EXPANDED = 256 * 1024 * 1024
MAX_MEMBERS = 20000
NOTICE = re.compile(r"^(licen[sc]e|copying|notice|copyright|unlicense)(?:[._-].*)?$", re.I)
GRANT = re.compile(r"SPDX-License-Identifier:|[Ll]icensed under|[Pp]ermission is hereby granted|[Dd]ual.?licensed")


class AuditError(ValueError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_regular(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            raise AuditError(f"not a bounded, singly linked regular file: {path}")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        if len(data) > limit or len(data) != info.st_size:
            raise AuditError(f"file size changed or exceeded limit: {path}")
        return data
    finally:
        os.close(fd)


def lock_entries(data, expected=LOCK_SHA256):
    if digest(data) != expected:
        raise AuditError("Cargo.lock pin mismatch")
    lock = tomllib.loads(data.decode("utf-8"))
    if lock.get("version") != 4:
        raise AuditError("unsupported Cargo.lock schema")
    entries = lock["package"]
    identities = set()
    for entry in entries:
        name, version = entry["name"], entry["version"]
        if not re.fullmatch(r"[A-Za-z0-9_-]+", name) or not re.fullmatch(r"[A-Za-z0-9_.+-]+", version):
            raise AuditError("unsafe package identity")
        key = (name, version)
        if key in identities:
            raise AuditError("duplicate package identity")
        identities.add(key)
        if "source" in entry:
            if entry["source"] != REGISTRY or not re.fullmatch(r"[a-f0-9]{64}", entry.get("checksum", "")):
                raise AuditError("unrecognized source or missing registry checksum")
    return entries


class StaticCratesOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        from urllib.parse import urlsplit
        url = urlsplit(newurl)
        if url.scheme != "https" or url.netloc != "static.crates.io":
            raise AuditError("crate download redirected outside static.crates.io")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def archive_input(entry, cache, offline=False):
    name, version = entry["name"], entry["version"]
    url = f"https://static.crates.io/crates/{name}/{name}-{version}.crate"
    path = cache / "archives" / f"{name}-{version}.crate"
    if path.exists() or path.is_symlink():
        data = read_regular(path, MAX_ARCHIVE)
    else:
        if offline:
            raise AuditError(f"missing offline archive: {path.name}")
        opener = urllib.request.build_opener(StaticCratesOnly())
        request = urllib.request.Request(url, headers={"User-Agent": "cachy-asahi-data-audit/1"})
        deadline = time.monotonic() + 60
        with opener.open(request, timeout=20) as response:
            chunks, size = [], 0
            while True:
                if time.monotonic() > deadline:
                    raise AuditError("download deadline exceeded")
                chunk = response.read(65536)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_ARCHIVE:
                    raise AuditError("archive compressed size limit exceeded")
                chunks.append(chunk)
        data = b"".join(chunks)
        if digest(data) != entry["checksum"]:
            raise AuditError(f"registry checksum mismatch: {name}-{version}")
        with path.open("xb") as stream:
            stream.write(data)
        path.chmod(0o600)
    if digest(data) != entry["checksum"]:
        raise AuditError(f"registry checksum mismatch: {name}-{version}")
    return path, url, len(data)


def inspect_archive(path, entry):
    """Inspect all members before creating any unpacked file; no extractall."""
    archive = read_regular(path, MAX_ARCHIVE)
    if digest(archive) != entry["checksum"]:
        raise AuditError("registry checksum mismatch before archive inspection")
    root = f'{entry["name"]}-{entry["version"]}'
    files, directories, seen, total = {}, set(), set(), 0
    deadline = time.monotonic() + 30
    # Bound the complete tar stream, including hidden PAX/GNU metadata, before
    # tarfile parses headers. A payload-only limit misses metadata gzip bombs.
    expanded, expanded_size = [], 0
    with gzip.GzipFile(fileobj=io.BytesIO(archive), mode="rb") as compressed:
        while True:
            if time.monotonic() > deadline:
                raise AuditError("archive decompression deadline exceeded")
            chunk = compressed.read(65536)
            if not chunk:
                break
            expanded_size += len(chunk)
            if expanded_size > MAX_EXPANDED:
                raise AuditError("archive complete tar stream size limit exceeded")
            expanded.append(chunk)
    with tarfile.open(fileobj=io.BytesIO(b"".join(expanded)), mode="r|") as tar:
        for number, member in enumerate(tar, 1):
            if number > MAX_MEMBERS or time.monotonic() > deadline:
                raise AuditError("archive member/deadline limit exceeded")
            raw = member.name.rstrip("/") if member.isdir() else member.name
            parts = PurePosixPath(raw).parts
            if (not parts or parts[0] != root or raw.startswith("/") or "\\" in raw
                    or any(p in ("", ".", "..") for p in raw.split("/"))
                    or any(ord(c) < 32 or ord(c) == 127 for c in raw)
                    or member.name in seen or len(raw) > 4096):
                raise AuditError(f"unsafe or duplicate archive path: {member.name!r}")
            relative = "/".join(parts[1:])
            if relative in files or relative in directories:
                raise AuditError("duplicate normalized archive path")
            seen.add(member.name)
            if not member.isfile() and not member.isdir():
                raise AuditError("archive links/special files forbidden")
            if member.mode & 0o7000 or getattr(member, "sparse", None):
                raise AuditError("archive special mode or sparse member forbidden")
            if member.isdir():
                directories.add(relative)
                continue
            if not relative or member.size < 0 or member.size > MAX_FILE:
                raise AuditError("archive file size/path limit exceeded")
            total += member.size
            if total > MAX_EXPANDED:
                raise AuditError("archive expanded size limit exceeded")
            stream = tar.extractfile(member)
            data = stream.read(member.size + 1)
            if len(data) != member.size:
                raise AuditError("truncated archive member")
            files[relative] = data
    for path in set(files) | directories:
        if any(str(parent) in files for parent in PurePosixPath(path).parents if str(parent) != "."):
            raise AuditError("archive file used as directory")
    if "Cargo.toml" not in files:
        raise AuditError("normalized Cargo.toml absent")
    return files


def crate_metadata(files, entry):
    manifest = tomllib.loads(files["Cargo.toml"].decode("utf-8"))
    package = manifest.get("package", {})
    if (package.get("name"), package.get("version")) != (entry["name"], entry["version"]):
        raise AuditError("Cargo.toml package identity mismatch")
    license_file = package.get("license-file")
    if license_file is not None:
        if not isinstance(license_file, str) or license_file not in files:
            raise AuditError("declared license-file absent or unsafe")
    notices = [{"path": path, "sha256": digest(data), "size": len(data)}
               for path, data in sorted(files.items())
               if NOTICE.match(PurePosixPath(path).name) or path == license_file]
    declarations = [{"path": "Cargo.toml", "sha256": digest(files["Cargo.toml"]),
                     "kind": "upstream package license declaration", "expression": package.get("license")}]
    for path, data in sorted(files.items()):
        if PurePosixPath(path).suffix not in (".rs", ".md", ".txt", ".toml", ".c", ".h"):
            continue
        header = data[:8192].decode("utf-8", errors="replace")
        matches = [{"line": number, "text": line.strip()} for number, line in enumerate(header.splitlines(), 1)
                   if GRANT.search(line)]
        if matches:
            declarations.append({"path": path, "sha256": digest(data),
                                 "kind": "explicit source text (not a compatibility ruling)", "matched_lines": matches})
    embedded, binaries = [], []
    for path, data in sorted(files.items()):
        row = {"path": path, "sha256": digest(data), "size": len(data), "review": "NOT REVIEWED"}
        if data.startswith((b"\xfd7zXZ\x00", b"\x1f\x8b", b"PK\x03\x04")) or path.endswith(".tar"):
            embedded.append(row)
        if data.startswith((b"!<arch>\n", b"\x7fELF", b"MZ", b"\x00asm")) or PurePosixPath(path).suffix in (".a", ".lib", ".so", ".dll", ".exe"):
            binaries.append(row)
    build = package.get("build", "build.rs" if "build.rs" in files else False)
    if build is not False and (not isinstance(build, str) or build not in files):
        raise AuditError("declared build script absent or unsafe")
    scripts = [] if build is False else [{"path": build, "sha256": digest(files[build]),
                                         "review": "NOT REVIEWED", "execution": "NOT RUN"}]
    declared = package.get("license")
    if declared is not None and not isinstance(declared, str):
        raise AuditError("license declaration must be text")
    blockers = []
    if not declared and not license_file:
        blockers.append("No declared license expression or license-file")
    if not notices:
        blockers.append("No retained license/notice text in registry archive")
    empty = [row["path"] for row in notices if not row["size"]]
    if empty:
        blockers.append("Empty license/notice files: " + ", ".join(empty))
    return {"normalized_manifest_sha256": digest(files["Cargo.toml"]),
            "declared_spdx": declared, "declared_license_file": license_file,
            "repository": package.get("repository"), "rust_version": package.get("rust-version"),
            "license_notices": notices, "license_evidence_blockers": blockers,
            "license_declarations": declarations,
            "embedded_archives": embedded, "prebuilt_binary_inputs": binaries,
            "license_acceptance": "NOT REVIEWED",
            "build_scripts": scripts,
            "build_dependencies": manifest.get("build-dependencies", {}),
            "target_build_dependencies": {target: value["build-dependencies"]
                                          for target, value in manifest.get("target", {}).items()
                                          if "build-dependencies" in value},
            "links": package.get("links"), "file_count": len(files),
            "source_files_sha256": digest(json.dumps({p: digest(d) for p, d in sorted(files.items())},
                                                     sort_keys=True, separators=(",", ":")).encode())}


def retain_sources(files, entry, cache):
    if ".cargo-checksum.json" in files:
        raise AuditError("registry archive supplied reserved vendor checksum file")
    destination = cache / "vendor" / f'{entry["name"]}-{entry["version"]}'
    destination.mkdir(mode=0o700)
    for path, data in sorted(files.items()):
        output = destination / path
        output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with output.open("xb") as stream:
            stream.write(data)
        output.chmod(0o600)  # inert data; executable source permissions intentionally removed
    checksums = {"files": {p: digest(d) for p, d in sorted(files.items())},
                 "package": entry["checksum"]}
    (destination / ".cargo-checksum.json").write_text(json.dumps(checksums, sort_keys=True) + "\n")
    return str(destination)


def audit_entry(entry, cache, offline=False):
    archive, url, size = archive_input(entry, cache, offline)
    files = inspect_archive(archive, entry)
    if ".cargo-checksum.json" in files:
        raise AuditError("registry archive supplied reserved vendor checksum file")
    metadata = crate_metadata(files, entry)
    source = retain_sources(files, entry, cache)
    if entry["name"] == "gettext-sys":
        metadata["embedded_gettext"] = inspect_gettext(files["gettext-1.0.tar.xz"], cache, entry)
    if metadata["prebuilt_binary_inputs"]:
        metadata["binary_provenance_note"] = (
            "Locked registry archive retains prebuilt conditional import libraries or test fixtures. "
            "No source rebuild or library generation was performed; generation provenance is NOT REVIEWED. "
            "Declared upstream licenses and actual retained notices are recorded separately.")
    return {"name": entry["name"], "version": entry["version"], "registry": entry["source"],
            "url": url, "archive_sha256": entry["checksum"], "checksum": "PASS",
            "archive_size": size, "retained_archive": str(archive), "retained_source": source,
            **metadata}


class BoundedDecompressed:
    def __init__(self, stream):
        self.stream, self.total = stream, 0
        self.deadline = time.monotonic() + 30

    def read(self, size):
        if time.monotonic() > self.deadline:
            raise AuditError("embedded archive deadline exceeded")
        data = self.stream.read(min(size, 65536))
        self.total += len(data)
        if self.total > MAX_EXPANDED:
            raise AuditError("embedded complete tar stream size limit exceeded")
        return data


def inspect_gettext(data, cache, entry):
    """Bounded data-only scan of the bundled GNU gettext source, no extraction."""
    notices, notice_data, hashes, seen, files, total = [], {}, {}, set(), set(), 0
    key = f'{entry["name"]}-{entry["version"]}'
    root = "gettext-1.0"
    with lzma.LZMAFile(io.BytesIO(data)) as compressed:
        bounded = BoundedDecompressed(compressed)
        with tarfile.open(fileobj=bounded, mode="r|") as tar:
            for number, member in enumerate(tar, 1):
                raw = member.name.rstrip("/") if member.isdir() else member.name
                parts = raw.split("/")
                if (number > MAX_MEMBERS or not parts or parts[0] != root or raw in seen
                        or any(p in ("", ".", "..") for p in parts) or "\\" in raw
                        or any(ord(c) < 32 or ord(c) == 127 for c in raw) or len(raw) > 4096):
                    raise AuditError("unsafe embedded gettext member or member count limit")
                seen.add(raw)
                if not member.isfile() and not member.isdir() or member.mode & 0o7000 or getattr(member, "sparse", None):
                    raise AuditError("embedded gettext link/special member forbidden")
                if member.isdir():
                    continue
                if member.size < 0 or member.size > MAX_FILE:
                    raise AuditError("embedded gettext member size limit exceeded")
                total += member.size
                if total > MAX_EXPANDED:
                    raise AuditError("embedded gettext payload limit exceeded")
                files.add(raw)
                content = tar.extractfile(member)
                sha, size, notice_parts = hashlib.sha256(), 0, []
                is_notice = bool(NOTICE.match(parts[-1]))
                while True:
                    chunk = content.read(65536)
                    if not chunk:
                        break
                    sha.update(chunk)
                    size += len(chunk)
                    if is_notice:
                        notice_parts.append(chunk)
                if size != member.size:
                    raise AuditError("truncated embedded gettext member")
                hashes[raw] = sha.hexdigest()
                if is_notice:
                    notice_data[raw] = b"".join(notice_parts)
                    notices.append({"path": raw, "sha256": sha.hexdigest(), "size": size,
                                    "bundle_path": f"LICENSES/{key}/_embedded/{raw}"})
        expanded_bytes = bounded.total
    if any(str(parent) in files for path in seen for parent in PurePosixPath(path).parents if str(parent) != "."):
        raise AuditError("embedded gettext file used as directory")
    if f"{root}/COPYING" not in hashes or f"{root}/gettext-runtime/intl/COPYING.LIB" not in hashes:
        raise AuditError("GNU gettext GPL/LGPL notices absent")
    for path, text in sorted(notice_data.items()):
        output = cache / "embedded" / key / path
        output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with output.open("xb") as stream:
            stream.write(text)
        output.chmod(0o600)
    return {"archive_path": "gettext-1.0.tar.xz", "archive_sha256": digest(data),
            "data_inspection": "PASS", "members": len(seen), "files": len(files),
            "expanded_bytes_read": expanded_bytes, "payload_bytes": total,
            "source_files_sha256": digest(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()),
            "license_notices": sorted(notices, key=lambda row: row["path"]),
            "license_review": "INCOMPLETE",
            "notes": ["Root COPYING contains GPL version 3 text; intl/COPYING.LIB contains LGPL version 2.1 text.",
                      "Includes GNU runtime/tools, gnulib/libxml and tree-sitter sources; all collected notice files are retained.",
                      "License terms, headers, component scope and distribution obligations need independent review.",
                      "No configure, build script, make or native source code was executed."]}


def gettext_feature_evidence(local_manifest, rows, cache):
    data = read_regular(local_manifest, 1024 * 1024)
    if digest(data) != LOCAL_MANIFEST_SHA256:
        raise AuditError("local Cargo.toml pin mismatch")
    local = tomllib.loads(data.decode())
    rs = next(row for row in rows if row["name"] == "gettext-rs")
    sys = next(row for row in rows if row["name"] == "gettext-sys")
    rs_data = read_regular(cache / "vendor" / f'gettext-rs-{rs["version"]}' / "Cargo.toml", 1024 * 1024)
    sys_data = read_regular(cache / "vendor" / f'gettext-sys-{sys["version"]}' / "build.rs", 1024 * 1024)
    rs_manifest = tomllib.loads(rs_data.decode())
    if "gettext-system" not in local["dependencies"]["gettext-rs"]["features"] or rs_manifest["features"]["gettext-system"] != ["gettext-sys/gettext-system"]:
        raise AuditError("pinned gettext-system feature forwarding absent")
    text = sys_data.decode()
    required = ['if try_gettext_system() {\n        return;', 'cfg!(feature = "gettext-system")',
                'target.contains("linux")', 'target.contains("-gnu")', '// intl is part of glibc and musl\n            return true;']
    if not all(part in text for part in required):
        raise AuditError("gettext-system source-reviewed control flow changed")
    return {"status": "SOURCE AUDITED; NOT EXECUTED", "local_manifest_sha256": digest(data),
            "gettext_rs_manifest_sha256": digest(rs_data), "gettext_sys_build_rs_sha256": digest(sys_data),
            "conclusion": "Pinned local feature forwards to gettext-sys; try_gettext_system returns before fallback for Linux GNU/musl targets.",
            "intended_target": "aarch64-unknown-linux-gnu", "native_feature_activation": "NOT RUN",
            "build_script_approval": "NOT REVIEWED",
            "fallback_risk": "Other targets or changed feature inputs may execute bundled configure/make/install. Clean container build approval remains required."}


def historical_notice_paths(entries, rows, cache):
    """Lock graph plus normalized target predicates, not Cargo target resolution."""
    from collections import defaultdict, deque
    packages = {f'{p["name"]} {p["version"]}': p for p in entries}
    names = defaultdict(list)
    for key, entry in packages.items():
        names[entry["name"]].append(key)
    def identity(value):
        if value in packages:
            return value
        if len(names[value]) != 1:
            raise AuditError("ambiguous lock dependency identity")
        return names[value][0]
    graph = {key: [identity(value) for value in entry.get("dependencies", [])]
             for key, entry in packages.items()}
    start = "arch-update-tray 4.4.2"
    target_names = {"block", "malloc_buf", "objc-foundation", "objc_id"}
    paths, seen, queue = {}, {start}, deque([(start, [start])])
    while queue:
        node, path = queue.popleft()
        if packages[node]["name"] in target_names:
            paths[node] = path
        for child in graph[node]:
            if child not in seen:
                seen.add(child)
                queue.append((child, path + [child]))
    locale = next(row for row in rows if row["name"] == "locale_config")
    manifest_path = cache / "vendor" / f'locale_config-{locale["version"]}' / "Cargo.toml"
    data = read_regular(manifest_path, 1024 * 1024)
    manifest = tomllib.loads(data.decode())
    predicate = 'cfg(target_os = "macos")'
    deps = manifest["target"][predicate]["dependencies"]
    if not all(name in deps for name in ("objc", "objc-foundation")):
        raise AuditError("historical notice platform boundary changed")
    locale_key = f'locale_config {locale["version"]}'
    cut = {(locale_key, names[name][0]) for name in ("objc", "objc-foundation")}
    seen, queue = {start}, deque([start])
    while queue:
        node = queue.popleft()
        for child in graph[node]:
            if (node, child) not in cut and child not in seen:
                seen.add(child)
                queue.append(child)
    if any(node in seen for node in paths):
        raise AuditError("historical notice packages have another non-macOS graph path")
    return {"status": "SOURCE AUDITED; NO CARGO RESOLUTION EXECUTED", "lock_paths": paths,
            "boundary": {"crate": locale_key, "manifest_sha256": digest(data),
                         "predicate": predicate, "dependencies": deps},
            "conclusion": "All four historical notice blockers cross locale_config macOS-only dependency edges in the pinned graph.",
            "distribution_caveat": "All remain included in the full retained vendor bundle; this source analysis does not clear their missing notices or remove them."}


def portable_report(report):
    """Remove machine-dependent paths and the bundle's own hash from its contents."""
    portable = json.loads(json.dumps(report))
    portable.pop("cache", None)
    portable.pop("vendor_bundle", None)
    for row in portable["registry_sources"]:
        row.pop("retained_archive", None)
        row["retained_source"] = f'vendor/{row["name"]}-{row["version"]}'
    portable["archive_retention"] = "Checksum-bound original archives retained separately in the reported /tmp cache."
    return portable


def vendor_bundle(report, lock_data, cache):
    """Deterministic gzip/tar with full inert vendor inputs and license evidence."""
    if report["source_checksum_closure"] != "PASS":
        raise AuditError("cannot bundle an incomplete source closure")
    payloads = {"Cargo.lock": lock_data,
                "cargo-audit.json": (json.dumps(portable_report(report), indent=2, sort_keys=True) + "\n").encode()}
    for row in report["registry_sources"]:
        key = f'{row["name"]}-{row["version"]}'
        source = cache / "vendor" / key
        checksums = json.loads(read_regular(source / ".cargo-checksum.json", 8 * 1024 * 1024))
        if checksums["package"] != row["archive_sha256"]:
            raise AuditError("vendor package checksum changed")
        for path, expected in sorted(checksums["files"].items()):
            data = read_regular(source / path, MAX_FILE)
            if digest(data) != expected:
                raise AuditError("vendor source changed before bundle")
            payloads[f"vendor/{key}/{path}"] = data
        payloads[f"vendor/{key}/.cargo-checksum.json"] = read_regular(source / ".cargo-checksum.json", 8 * 1024 * 1024)
        for item in row["license_notices"] + row["license_declarations"]:
            path = item["path"]
            data = payloads[f"vendor/{key}/{path}"]
            if digest(data) != item["sha256"]:
                raise AuditError("license evidence changed before bundle")
            payloads[f"LICENSES/{key}/{path}"] = data
        for item in row.get("embedded_gettext", {}).get("license_notices", []):
            data = read_regular(cache / "embedded" / key / item["path"], MAX_FILE)
            if digest(data) != item["sha256"]:
                raise AuditError("embedded license evidence changed before bundle")
            payloads[item["bundle_path"]] = data
    destination = cache / "cachy-update-vendor.tar.gz"
    with destination.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
        with tarfile.open(mode="w|", fileobj=compressed, format=tarfile.PAX_FORMAT) as tar:
            for path, data in sorted(payloads.items()):
                member = tarfile.TarInfo(path)
                member.size, member.mode, member.mtime = len(data), 0o644, 0
                member.uid = member.gid = 0
                member.uname = member.gname = ""
                tar.addfile(member, io.BytesIO(data))
    return {"path": str(destination), "sha256": digest(read_regular(destination, 1024 * 1024 * 1024)),
            "size": destination.stat().st_size, "members": len(payloads),
            "format": "sorted PAX tar, uid/gid/mtime zero, files 0644, gzip mtime zero",
            "contains": ["all 167 inert registry source trees and Cargo per-file checksums", "Cargo.lock", "portable cargo-audit.json", "LICENSES/<crate-version>/exact notice and declaration source files"],
            "build_accepted": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--local-manifest", type=Path, help="pinned local Cargo.toml; defaults to Cargo.lock sibling")
    parser.add_argument("--archive-cache", type=Path, help="read-only /tmp cache for an offline rerun")
    args = parser.parse_args()
    lock_data = read_regular(args.lock, 1024 * 1024)
    entries = lock_entries(lock_data)
    local = [p for p in entries if "source" not in p]
    if [(p["name"], p["version"]) for p in local] != [("arch-update-tray", "4.4.2")]:
        raise AuditError("unexpected local package set")
    cache = Path(tempfile.mkdtemp(prefix="cachy-update-cargo-audit-", dir="/tmp"))
    (cache / "archives").mkdir(mode=0o700)
    (cache / "vendor").mkdir(mode=0o700)
    if args.archive_cache:
        source = args.archive_cache.resolve(strict=True)
        if source.parent != Path("/tmp") or not source.name.startswith("cachy-update-cargo-audit-"):
            raise AuditError("offline archive cache must be a prior private /tmp audit directory")
        for entry in entries:
            if "source" in entry:
                filename = f'{entry["name"]}-{entry["version"]}.crate'
                data = read_regular(source / "archives" / filename, MAX_ARCHIVE)
                if digest(data) != entry["checksum"]:
                    raise AuditError("offline cache checksum mismatch")
                (cache / "archives" / filename).write_bytes(data)
    report = {"schema_version": 1, "kind": "data-only Cargo source evidence",
              "upstream_commit": COMMIT, "cargo_lock_sha256": LOCK_SHA256,
              "cache": str(cache), "locked_packages": len(entries), "local_packages": local,
              "registry_packages": len(entries) - len(local), "registry_sources": [], "failures": [],
              "cargo_execution": "NOT RUN", "build_script_execution": "NOT RUN",
              "native_build": "NOT RUN", "distribution_accepted": False,
              "limits": {"compressed_bytes_per_archive": MAX_ARCHIVE, "expanded_bytes_per_archive": MAX_EXPANDED,
                         "bytes_per_member": MAX_FILE, "members_per_archive": MAX_MEMBERS,
                         "archive_inspection_seconds": 30, "download_seconds": 60},
              "notes": ["Includes all locked target-specific crates, not a Linux-only dependency subset.",
                        "Retained vendor files are non-executable data; no Cargo config or user Cargo directory changed.",
                        "Notice collection and declared SPDX text do not establish license compatibility or completeness.",
                        "The local package, artwork, patches, and upstream grant require a separate source audit.",
                        "Embedded archives and prebuilt binary inputs are retained but their inner source/license provenance is NOT REVIEWED.",
                        "Every build script and referenced native/source code remains unreviewed and unexecuted."]}
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        jobs = {pool.submit(audit_entry, entry, cache, bool(args.archive_cache)): entry
                for entry in entries if "source" in entry}
        for job in concurrent.futures.as_completed(jobs):
            entry = jobs[job]
            try:
                report["registry_sources"].append(job.result())
            except Exception as error:
                report["failures"].append({"name": entry["name"], "version": entry["version"],
                                           "error": f"{type(error).__name__}: {error}"})
    report["registry_sources"].sort(key=lambda row: (row["name"], row["version"]))
    report["failures"].sort(key=lambda row: (row["name"], row["version"]))
    report["source_checksum_closure"] = "PASS" if not report["failures"] and len(report["registry_sources"]) == report["registry_packages"] else "FAIL"
    report["license_evidence_blockers"] = [{"name": row["name"], "version": row["version"], "blockers": row["license_evidence_blockers"]}
                                           for row in report["registry_sources"] if row["license_evidence_blockers"]]
    report["license_notice_collection"] = "PASS" if report["source_checksum_closure"] == "PASS" and not report["license_evidence_blockers"] else "INCOMPLETE"
    report["license_compatibility_review"] = "NOT REVIEWED"
    report["build_script_review"] = "NOT REVIEWED"
    report["embedded_archive_review"] = "NOT REVIEWED"
    report["prebuilt_binary_provenance_review"] = "NOT REVIEWED"
    report["build_script_packages"] = sum(bool(row["build_scripts"]) for row in report["registry_sources"])
    report["audit_script_sha256"] = digest(read_regular(Path(__file__), 1024 * 1024))
    if report["source_checksum_closure"] == "PASS":
        report["gettext_system_feature"] = gettext_feature_evidence(args.local_manifest or args.lock.with_name("Cargo.toml"), report["registry_sources"], cache)
        report["historical_notice_source_paths"] = historical_notice_paths(entries, report["registry_sources"], cache)
        report["vendor_bundle"] = vendor_bundle(report, lock_data, cache)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: report[key] for key in ("cache", "locked_packages", "registry_packages", "source_checksum_closure", "license_notice_collection", "failures", "license_evidence_blockers", "vendor_bundle") if key in report}, indent=2))
    return 0 if report["source_checksum_closure"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
