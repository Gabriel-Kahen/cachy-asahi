#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Curated DEVELOPMENT TEST export; no recursive copying or release acceptance.

export(acceptance_ref, archive_refs, output, expected_binding, cancelled=callable)
captures pinned bytes before creating output. Only two package files and newly
constructed evidence JSON may leave the private native-job workspace.
"""
import gzip
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile

MIB = 1024**2
PACKAGE_LIMIT = 16 * MIB
TOTAL_PACKAGE_LIMIT = 32 * MIB
EVIDENCE_LIMIT = 65536
DECODED_LIMIT = 32 * MIB
NAME, VERSION, LICENSE = "cachy-asahi-ksmctl", "0.1.0-1", "GPL-2.0-or-later"
SCOPE = "DEVELOPMENT TEST ONLY"
INPUTS_SHA256 = "beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f"
PACKAGES_SHA256 = "fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25"
RECIPE_MAP_SHA256 = "f933ccfcfb52ca97ea809d904344f6ec72eb5907ef458b5c2e7f7f1797dc1d44"
BINDING_FIELDS = {"source_commit", "run_id", "image_id", "packet_sha256", "inputs_sha256", "packages_sha256", "recipe_map_sha256"}
PAYLOAD = {
    "usr/bin/" + NAME: (0o755, "f9fd76eaa6a205d56fa4bb9123b8c721ea1277249c4cab58d1b57eaf8edc7558"),
    "usr/share/doc/" + NAME + "/README.md": (0o644, "e7f806f7c81d5ddb2388faa4f7ddc53e04c004596a4f346bb270b47f8aad023d"),
    "usr/share/doc/" + NAME + "/source-provenance.json": (0o644, "d46e93a9893225d205a01fdcd3429782ba51d44c86b78e77fce458b53448b849"),
    "usr/share/licenses/" + NAME + "/NOTICE": (0o644, "939ad92c65a6c2f9da2c723a4c6e136add87ccb4a7a6e8ba0dd89692a77f3f10"),
    "usr/share/licenses/" + NAME + "/LICENSE": (0o644, "edaef632cbb643e4e7a221717a6c441a4c1a7c918e6e4d56debc3d8739b233f6"),
}


class Cancelled(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def check_cancelled(cancelled):
    value = cancelled()
    need(type(value) is bool, "boolean cancellation observation required")
    if value:
        raise Cancelled("public export cancelled")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pin(value):
    need(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value), "invalid SHA256 pin")


def identity(info):
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)


def metadata(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def walk_directory(path):
    """Hold each parent component without following symlinks, including ancestors."""
    path = Path(path)
    need(path.is_absolute() and ".." not in path.parts, "unsafe directory path")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for component in path.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def named_identity(directory, name, expected):
    need(identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) == expected,
         "public namespace identity changed; cleanup refused")


def capture(reference, maximum, cancelled):
    need(isinstance(reference, dict) and set(reference) == {"path", "size", "sha256"}, "exact input reference required")
    path = Path(reference["path"])
    need(path.is_absolute() and ".." not in path.parts, "unsafe input path")
    need(type(reference["size"]) is int and 0 < reference["size"] <= maximum, "input byte bound")
    pin(reference["sha256"])
    parent, fd = None, None
    try:
        parent = walk_directory(path.parent)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == reference["size"], "regular single-link bounded input required")
        data = bytearray()
        while True:
            check_cancelled(cancelled)
            block = os.read(fd, min(65536, reference["size"] + 1 - len(data)))
            if not block:
                break
            data.extend(block)
            need(len(data) <= reference["size"], "input size drift")
        need(metadata(before) == metadata(os.fstat(fd)), "input metadata drift")
        need(len(data) == reference["size"] and sha(data) == reference["sha256"], "input byte/hash mismatch")
        return bytes(data)
    except OSError as error:
        raise ValueError("unsafe or unavailable input path") from error
    finally:
        for descriptor in (fd, parent):
            if descriptor is not None:
                os.close(descriptor)


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def binding(value):
    need(isinstance(value, dict) and set(value) == BINDING_FIELDS, "exact frozen binding required")
    need(isinstance(value["source_commit"], str) and re.fullmatch(r"[a-f0-9]{40}", value["source_commit"]), "source commit binding")
    need(isinstance(value["run_id"], str) and re.fullmatch(r"[1-9][0-9]{0,19}", value["run_id"]), "run identity binding")
    need(isinstance(value["image_id"], str) and re.fullmatch(r"sha256:[a-f0-9]{64}", value["image_id"]), "immutable image binding")
    for key in BINDING_FIELDS - {"source_commit", "run_id", "image_id"}:
        pin(value[key])
    need(value["recipe_map_sha256"] == RECIPE_MAP_SHA256, "reviewed GPL15 recipe map required")
    need(value["inputs_sha256"] == INPUTS_SHA256 and value["packages_sha256"] == PACKAGES_SHA256,
         "reviewed inputs and package inventory required")


def validate(data, expected_binding, refs):
    value = json.loads(data, object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite JSON")))
    need(isinstance(value, dict) and set(value) == {"schema_version", "status", "scope", "binding", "producer", "builds",
                                                   "comparison", "lifecycle", "source_notices", "cleanup"}, "consumer acceptance allowlist")
    need(type(value["schema_version"]) is int and value["schema_version"] == 1 and value["status"] == "PASS"
         and value["scope"] == SCOPE, "complete development acceptance required")
    binding(expected_binding); binding(value["binding"])
    need(value["binding"] == expected_binding, "frozen same-job binding mismatch")
    for phase in ("producer", "lifecycle"):
        need(value[phase] == {"status": "PASS", "cleanup": "PASS"}, "complete producer/lifecycle cleanup required")
    need(isinstance(value["cleanup"], dict) and set(value["cleanup"]) == {"status", "absence_verified"}
         and value["cleanup"]["status"] == "PASS" and value["cleanup"]["absence_verified"] is True, "global cleanup/absence acceptance required")
    comparison = value["comparison"]
    need(isinstance(comparison, dict) and set(comparison) == {"status", "archives_equal", "metadata_equal", "payload_equal", "buildinfo_equal"}
         and comparison["status"] == "PASS" and all(comparison[key] is True for key in comparison if key != "status"), "complete build comparison required")
    notices = value["source_notices"]
    need(isinstance(notices, dict) and set(notices) == {"gpl15_recipe_snapshot", "notice_preserved", "license_preserved"}
         and all(v is True for v in notices.values()), "GPL recipe/snapshot and preserved notices required")
    builds = value["builds"]
    need(isinstance(builds, list) and len(builds) == 2, "two accepted builds required")
    for build, ref in zip(builds, refs):
        need(isinstance(build, dict) and set(build) == {"status", "filename", "sha256", "provenance_sha256", "container_cleanup"}
             and build["status"] == build["container_cleanup"] == "PASS", "accepted clean build required")
        pin(build["provenance_sha256"]); pin(build["sha256"])
        need(build["filename"] in {NAME + "-" + VERSION + "-any.pkg.tar.xz", NAME + "-" + VERSION + "-any.pkg.tar.gz"}
             and Path(ref["path"]).name == build["filename"] and ref["sha256"] == build["sha256"], "exact KSM archive binding required")
    need(builds[0]["filename"] == builds[1]["filename"] and builds[0]["sha256"] == builds[1]["sha256"]
         and builds[0]["provenance_sha256"] != builds[1]["provenance_sha256"], "distinct clean build/pair identity required")
    return value


def inspect(data, filename):
    decoder = lzma.LZMAFile(io.BytesIO(data)) if filename.endswith(".xz") else gzip.GzipFile(fileobj=io.BytesIO(data))
    with decoder as stream:
        decoded = stream.read(DECODED_LIMIT + 1)
    need(len(decoded) <= DECODED_LIMIT, "decoded public archive bound")
    found, metadata, seen = {}, None, set()
    directories = {str(parent) for path in PAYLOAD for parent in PurePosixPath(path).parents if str(parent) != "."}
    with tarfile.open(fileobj=io.BytesIO(decoded), mode="r:") as archive:
        for count, member in enumerate(archive, 1):
            name = member.name.removeprefix("./").rstrip("/")
            need(count <= 64 and name not in seen and 0 < len(name) <= 4096 and not name.startswith("/")
                 and all(part not in {"", ".", ".."} for part in name.split("/")), "unsafe public archive member")
            seen.add(name)
            need(member.uid == member.gid == 0 and (member.isdir() or member.isfile()), "public archive ownership/type")
            if member.isdir():
                need(name in directories and member.size == 0, "unexpected public archive directory")
                continue
            need(0 <= member.size <= PACKAGE_LIMIT and name in set(PAYLOAD) | {".PKGINFO", ".BUILDINFO", ".MTREE"}, "unknown public archive payload")
            need(name in PAYLOAD or member.size <= MIB, "public package control bound")
            content = archive.extractfile(member).read(PACKAGE_LIMIT + 1)
            need(len(content) == member.size, "public archive member size mismatch")
            if name in PAYLOAD:
                mode, digest = PAYLOAD[name]
                need(member.mode == mode and sha(content) == digest, "reviewed GPL payload/notice mismatch")
                found[name] = digest
            elif name == ".PKGINFO":
                metadata = {}
                for line in content.decode("utf-8").splitlines():
                    if not line or line.startswith("#"):
                        continue
                    key, separator, value = line.partition(" = ")
                    need(separator, "invalid PKGINFO")
                    metadata.setdefault(key, []).append(value)
    need(set(found) == set(PAYLOAD) and {".PKGINFO", ".BUILDINFO", ".MTREE"} <= seen, "complete reviewed GPL package required")
    for key, wanted in (("pkgname", [NAME]), ("pkgver", [VERSION]), ("arch", ["any"]),
                        ("license", [LICENSE]), ("depend", ["python>=3.11"]), ("provides", []), ("conflict", []), ("replaces", [])):
        need(metadata.get(key, []) == wanted, "exact public package identity/relations required")


def export(acceptance_ref, archive_refs, output, expected_binding, *, cancelled=lambda: False, on_owned=None):
    """Export exclusively; optional on_owned(root_fd, evidence_fd, encoded) may dup
    the created descriptors after validation. They remain borrowed until return.
    Failure cleans only owned nodes; detected replacements refuse cleanup.
    """
    need(on_owned is None or callable(on_owned), "owned export callback required")
    need(isinstance(archive_refs, list) and len(archive_refs) == 2, "two exact archive references required")
    binding(expected_binding)
    expected_binding = dict(expected_binding)
    need(isinstance(acceptance_ref, dict) and all(isinstance(ref, dict) for ref in archive_refs), "input reference objects required")
    acceptance_ref, archive_refs = dict(acceptance_ref), [dict(ref) for ref in archive_refs]
    check_cancelled(cancelled)
    acceptance_bytes = capture(acceptance_ref, EVIDENCE_LIMIT, cancelled)
    acceptance = validate(acceptance_bytes, expected_binding, archive_refs)
    packages = [capture(ref, PACKAGE_LIMIT, cancelled) for ref in archive_refs]
    need(sum(map(len, packages)) <= TOTAL_PACKAGE_LIMIT and packages[0] == packages[1], "bounded equal package bytes required")
    inspect(packages[0], acceptance["builds"][0]["filename"])
    evidence = {"schema_version": 1, "status": "PASS-curated-development-export", "scope": SCOPE,
                "binding": dict(expected_binding), "consumer_acceptance_sha256": sha(acceptance_bytes),
                "producer": acceptance["producer"], "comparison": acceptance["comparison"], "lifecycle": acceptance["lifecycle"],
                "cleanup": acceptance["cleanup"], "source_notices": acceptance["source_notices"],
                "packages": [{"file": f"build-{index}/{build['filename']}", "sha256": sha(data), "size": len(data),
                              "provenance_sha256": build["provenance_sha256"]}
                             for index, (build, data) in enumerate(zip(acceptance["builds"], packages), 1)],
                "package": {"name": NAME, "version": VERSION, "arch": "any", "license": LICENSE},
                "source_notice_scope": "caller-verified recipe/snapshot and preserved package notices; broader grants not established",
                "hardware": "NOT RUN", "management": "NOT RUN", "performance": "NOT RUN", "published": False, "source_grants_complete": False}
    encoded = (json.dumps(evidence, sort_keys=True, indent=2) + "\n").encode()
    need(len(encoded) <= EVIDENCE_LIMIT, "public evidence bound")
    output = Path(output)
    need(output.is_absolute() and ".." not in output.parts, "canonical nonsymlink public output required")
    parent = walk_directory(output.parent)
    root, children, files, root_identity, directories = None, {}, [], None, []
    parent_info = os.fstat(parent)

    def private_directory(info):
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
             and stat.S_IMODE(info.st_mode) == 0o700, "private owned output parent/directory required")

    def directory(directory, name):
        os.mkdir(name, mode=0o700, dir_fd=directory)
        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
        # Record even restrictive-umask directories before checking their mode.
        directories.append((directory, name, identity(info), info.st_uid, info.st_gid))
        return identity(info), info

    def write(directory, name, data):
        check_cancelled(cancelled)
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        info = os.fstat(fd)
        files.append((directory, name, identity(info), data, info.st_uid, info.st_gid, fd))
        view = memoryview(data)
        while view:
            check_cancelled(cancelled)
            count = os.write(fd, view[:65536])
            need(count > 0, "public output write failed")
            view = view[count:]
        os.fchmod(fd, 0o644); os.fsync(fd)

    def namespaces():
        fresh = walk_directory(output.parent)
        try:
            need(identity(os.fstat(fresh)) == identity(parent_info), "public parent identity changed; cleanup refused")
        finally:
            os.close(fresh)
        named_identity(parent, output.name, root_identity)
        if root is not None:
            need(set(os.listdir(root)) == set(children) | {name for fd, name, *_ in files if fd == root},
                 "unexpected public root contents; cleanup refused")
        for name, (fd, expected) in children.items():
            named_identity(root, name, expected)
            if fd is not None:
                need(set(os.listdir(fd)) == {name for directory, name, *_ in files if directory == fd},
                     "unexpected public child contents; cleanup refused")
        for directory_fd, name, expected, *_ in files:
            named_identity(directory_fd, name, expected)

    def verify_file(record):
        directory_fd, name, expected, data, uid, gid = record[:6]
        named_identity(directory_fd, name, expected)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory_fd)
        try:
            before = os.fstat(fd)
            need(identity(before) == expected and before.st_nlink == 1 and before.st_uid == uid == os.geteuid()
                 and before.st_gid == gid and stat.S_IMODE(before.st_mode) == 0o644
                 and before.st_size == len(data), "public output file identity/mode drift")
            offset = 0
            while offset < len(data):
                check_cancelled(cancelled)
                block = os.read(fd, min(65536, len(data) - offset))
                need(block and block == data[offset:offset + len(block)], "public output bytes changed")
                offset += len(block)
            need(not os.read(fd, 1) and metadata(before) == metadata(os.fstat(fd)), "public output metadata drift")
            named_identity(directory_fd, name, expected)
        finally:
            os.close(fd)

    def invalidate_evidence():
        for directory_fd, name, expected, _, uid, gid, owned_fd in files:
            if name != "evidence.json":
                continue
            fd = None
            try:
                fd = os.dup(owned_fd)
                info = os.fstat(fd)
                need(identity(info) == expected and info.st_nlink == 1 and info.st_uid == uid and info.st_gid == gid,
                     "cannot invalidate replaced evidence")
                failure = b'{"schema_version":1,"status":"FAIL-curated-development-export","scope":"DEVELOPMENT TEST ONLY"}\n'
                os.ftruncate(fd, 0)
                os.lseek(fd, 0, os.SEEK_SET)
                view = memoryview(failure)
                while view:
                    count = os.write(fd, view)
                    need(count > 0, "failure evidence write failed")
                    view = view[count:]
                os.fsync(fd)
            except (OSError, ValueError):
                # A foreign evidence replacement must remain untouched. An I/O
                # failure prevents a durability claim and the export still raises.
                pass
            finally:
                if fd is not None:
                    os.close(fd)

    try:
        private_directory(parent_info)
        check_cancelled(cancelled)
        need(output.name not in os.listdir(parent), "public output must be absent")
        root_identity, info = directory(parent, output.name)
        private_directory(info)
        root = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        need(identity(os.fstat(root)) == root_identity, "public output identity changed")
        for index, (build, data) in enumerate(zip(acceptance["builds"], packages), 1):
            name = f"build-{index}"
            expected, info = directory(root, name)
            children[name] = (None, expected)
            private_directory(info)
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
            children[name] = (child, expected)
            need(identity(os.fstat(child)) == expected, "public child identity changed")
            write(child, build["filename"], data)
        write(root, "evidence.json", encoded)
        for fd in [*(fd for fd, _ in children.values()), root, parent]:
            os.fsync(fd)
        check_cancelled(cancelled)
        namespaces()
        for fd in [parent, root, *(fd for fd, _ in children.values())]:
            private_directory(os.fstat(fd))
        for directory_fd, name, expected, uid, gid in directories:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            need(identity(info) == expected and info.st_uid == uid and info.st_gid == gid
                 and stat.S_IMODE(info.st_mode) == 0o700, "public directory mode/ownership drift")
        need(os.fstat(parent).st_gid == parent_info.st_gid, "public parent group drift")
        for record in files:
            verify_file(record)
        namespaces()
        if on_owned is not None:
            evidence_fd = next(record[6] for record in files if record[0] == root and record[1] == "evidence.json")
            on_owned(root, evidence_fd, encoded)
        check_cancelled(cancelled)
        return evidence
    except BaseException:
        if root_identity is not None:
            # Preflight the entire namespace before deleting any owned node.
            # Recheck each target and refuse detected replacement. POSIX has no
            # atomic identity-conditional unlink; the private owner must cooperate.
            try:
                namespaces()
            except BaseException:
                invalidate_evidence()
                raise
            for directory_fd, name, expected, *_ in reversed(files):
                named_identity(directory_fd, name, expected)
                os.unlink(name, dir_fd=directory_fd)
            for name, (_, expected) in children.items():
                named_identity(root, name, expected)
                os.rmdir(name, dir_fd=root)
            named_identity(parent, output.name, root_identity)
            os.rmdir(output.name, dir_fd=parent)
            os.fsync(parent)
        raise
    finally:
        for fd in [*(record[6] for record in files), *(fd for fd, _ in children.values()), root, parent]:
            if fd is not None:
                os.close(fd)
