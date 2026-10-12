#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Checksum-bound declared ownership audit; never inspect or change a target."""
import argparse
import contextlib
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import time

MIB = 1024**2
ARTIFACTS = Path(__file__).resolve().parents[2] / "artifacts"
JSON_LIMIT, COMPRESSED_LIMIT = 16 * MIB, 64 * MIB
DECODED_LIMIT, TOTAL_DECODED_LIMIT = 768 * MIB, 1024 * MIB
MEMBER_LIMIT, METADATA_LIMIT, PATH_LIMIT = 16 * MIB, 64 * MIB, 500000
IDENTITY = ("NAME", "VERSION", "ARCH", "FILENAME", "SHA256SUM")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9+_.-]*\Z")
HEX = re.compile(r"[a-f0-9]{64}\Z")


def need(condition, message):
    if not condition:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def loads(data):
    return json.loads(data.decode("utf-8"), object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


@contextlib.contextmanager
def reference(spec, maximum):
    """Yield a bounded snapshot of the exact bytes hashed, independent of its path.

    The source fd closes before consumption. RAM use is bounded by the caller's
    maximum plus BytesIO snapshot overhead; gzip/lzma consumers remain streaming.
    """
    need(isinstance(spec, dict) and set(spec) == {"path", "size", "sha256"}, "invalid reference")
    need(isinstance(spec["path"], str) and Path(spec["path"]).is_absolute(), "absolute input required")
    need(isinstance(spec["sha256"], str) and HEX.fullmatch(spec["sha256"]), "invalid input hash")
    need(type(spec["size"]) is int and 0 < spec["size"] <= maximum, "input bound")
    fd = os.open(spec["path"], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode), "regular input required")
        need(info.st_size == spec["size"], "input size mismatch")
        data = stream.read(spec["size"] + 1)
        need(len(data) == spec["size"], "input size mismatch")
        need(hashlib.sha256(data).hexdigest() == spec["sha256"], "input checksum mismatch")
    with io.BytesIO(data) as snapshot:
        yield snapshot


def json_reference(spec):
    with reference(spec, JSON_LIMIT) as stream:
        return loads(stream.read(JSON_LIMIT + 1))


def fields(data):
    result, key = {}, None
    for line in data.decode("utf-8").splitlines():
        need(len(line) <= 16384 and not any(ord(c) < 32 and c != "\t" for c in line), "unsafe metadata value")
        if line.startswith("%") and line.endswith("%"):
            key = line[1:-1]
            need(re.fullmatch(r"[A-Z][A-Z0-9_]*", key) and key not in result, "duplicate/invalid metadata field")
            result[key] = []
        elif line:
            need(key is not None, "metadata value without field")
            result[key].append(line)
    return result


def identity(data, archive=False):
    need(isinstance(data, dict), "invalid package metadata")
    keys = IDENTITY if archive else IDENTITY[:3]
    for key in keys:
        need(isinstance(data.get(key), list) and len(data[key]) == 1
             and isinstance(data[key][0], str), "invalid identity: " + key)
    need(len(data["NAME"][0]) <= 256 and NAME.fullmatch(data["NAME"][0]), "invalid package name")
    need(0 < len(data["VERSION"][0]) <= 512 and not re.search(r"[\s/\x00]", data["VERSION"][0]), "invalid package version")
    need(data["ARCH"][0] in {"aarch64", "any"}, "invalid architecture")
    if archive:
        need(HEX.fullmatch(data["SHA256SUM"][0]), "invalid archive checksum")
        need(re.fullmatch(r"[A-Za-z0-9._+:-]+", data["FILENAME"][0])
             and data["FILENAME"][0] not in {".", ".."}, "invalid archive filename")
    return data["NAME"][0], data["VERSION"][0]


def paths(values):
    need(isinstance(values, list) and len(values) <= PATH_LIMIT, "file-list count bound")
    result = {}
    for value in values:
        need(isinstance(value, str) and 0 < len(value) <= 4096
             and not any(ord(c) < 32 or ord(c) == 127 for c in value), "unsafe declared path")
        directory = value.endswith("/")
        path = value[:-1] if directory else value
        need(not path.startswith("/") and all(p not in {"", ".", ".."} for p in path.split("/")), "path traversal")
        need(path not in result, "duplicate declared path")
        result[path] = directory
    return result


def tar_members(stream, budget):
    """Strict physical ustar stream for these metadata snapshots; no extraction."""
    used, count, started = 0, 0, time.monotonic()
    def read(size):
        nonlocal used
        need(size <= MEMBER_LIMIT + 511, "tar read bound")
        block = stream.read(size)
        used += len(block); budget["decoded"] += len(block)
        need(used <= DECODED_LIMIT and budget["decoded"] <= TOTAL_DECODED_LIMIT, "decoded archive bound")
        need(time.monotonic() - started <= 300, "archive deadline")
        need(len(block) == size, "truncated tar")
        return block
    seen, sparse = set(), None
    while True:
        header = read(512)
        if not any(header):
            need(sparse is None, "dangling sparse PAX header")
            need(not any(read(512)), "missing second tar terminator")
            while block := stream.read(MIB):
                used += len(block); budget["decoded"] += len(block)
                need(used <= DECODED_LIMIT and budget["decoded"] <= TOTAL_DECODED_LIMIT
                     and time.monotonic() - started <= 300, "decoded archive bound")
                need(not any(block), "nonzero tar trailer")
            return
        count += 1; budget["members"] += 1
        need(count <= 200000 and budget["members"] <= 600000, "archive member bound")
        def octal(raw):
            value = raw.rstrip(b"\0 ").lstrip(b" ")
            need(value and re.fullmatch(b"[0-7]+", value), "invalid tar numeric field")
            return int(value, 8)
        need(octal(header[148:156]) == sum(header[:148]) + 256 + sum(header[156:]), "tar checksum")
        kind, size = header[156:157], octal(header[124:136])
        need(kind in {b"0", b"\0", b"5", b"x"} and size <= MEMBER_LIMIT, "unsupported/special tar member")
        name = header[:100].split(b"\0", 1)[0].decode("utf-8")
        prefix = header[345:500].split(b"\0", 1)[0].decode("utf-8")
        name = prefix + "/" + name if prefix else name
        name = name.rstrip("/") if kind == b"5" else name
        need(name and not name.startswith("/") and all(p not in {"", ".", ".."} for p in name.split("/")), "tar path traversal")
        need(name not in seen, "duplicate tar member"); seen.add(name)
        need(kind != b"5" or size == 0, "nonempty metadata directory")
        body = read(size) if size else b""
        padding = read((-size) % 512) if size % 512 else b""
        need(not any(padding), "nonzero tar padding")
        if kind == b"x":
            need(sparse is None and size <= 65536, "PAX extension bound")
            values, offset = {}, 0
            while offset < len(body):
                space = body.find(b" ", offset)
                need(space > offset and re.fullmatch(b"[0-9]{1,6}", body[offset:space]), "invalid PAX length")
                end = offset + int(body[offset:space])
                need(space + 1 < end <= len(body) and body[end - 1:end] == b"\n", "invalid PAX record")
                key, sep, value = body[space + 1:end - 1].decode("utf-8").partition("=")
                need(sep and key not in values, "duplicate/invalid PAX field")
                values[key] = value; offset = end
            need(set(values) == {"GNU.sparse.major", "GNU.sparse.minor", "GNU.sparse.name", "GNU.sparse.realsize"}
                 and values["GNU.sparse.major"] == "1" and values["GNU.sparse.minor"] == "0"
                 and values["GNU.sparse.realsize"].isdigit()
                 and int(values["GNU.sparse.realsize"]) <= 256 * 1024, "unsupported PAX metadata")
            sparse = values["GNU.sparse.name"]
            need(not sparse.startswith("/") and len(sparse.split("/")) == 2
                 and all(p not in {"", ".", ".."} for p in sparse.split("/")), "sparse path traversal")
            continue
        if sparse is not None:
            need(kind in {b"0", b"\0"} and sparse not in seen, "invalid sparse descriptor member")
            seen.add(sparse); name, sparse = sparse, None
            yield name, False, None
            continue
        yield name, kind == b"5", body


def catalog(spec, selected, budget, file_lists=False, directories=None):
    grouped, descriptors, file_members, blocked, diagnostics = {}, {}, {}, set(), []
    with reference(spec, COMPRESSED_LIMIT) as source, gzip.GzipFile(fileobj=source) as stream:
        for name, directory, body in tar_members(stream, budget):
            if body is None:
                folder = name.rsplit("/", 1)[0]
                blocked.add(folder)
                grouped.pop(folder, None); descriptors.pop(folder, None); file_members.pop(folder, None)
                diagnostics.append({"entry": name, "reason": "GNU sparse metadata unsupported; unselectable"})
                continue
            if directory:
                need("/" not in name, "nested metadata directory")
                continue
            pieces = name.split("/")
            allowed = {"desc", "depends", "files"} if file_lists else {"desc", "depends"}
            need(len(pieces) == 2 and pieces[1] in allowed, "unexpected metadata member")
            folder, member = pieces
            if folder in blocked:
                continue
            if file_lists and folder not in directories:
                continue
            if member != "files":
                need(len(body) <= 256 * 1024, "descriptor bound")
            budget["metadata"] += len(body)
            need(budget["metadata"] <= METADATA_LIMIT, "selected metadata bound")
            parsed = fields(body)
            if member == "files":
                if not body:
                    parsed = {"FILES": []}
                need("FILES" in parsed and set(parsed) <= {"FILES", "BACKUP"}, "invalid physical files fields")
                file_members[folder] = {"member": name, "sha256": hashlib.sha256(body).hexdigest()}
            else:
                need("FILES" not in parsed, "FILES outside physical files member")
                if member == "depends":
                    need(not set(parsed) & set(IDENTITY), "identity outside physical desc member")
                else:
                    descriptors[folder] = {"member": name, "sha256": hashlib.sha256(body).hexdigest(), "fields": parsed}
            entry = grouped.setdefault(folder, {})
            need(not set(entry) & set(parsed), "duplicate package metadata field")
            entry.update(parsed)
    result = {}
    for folder, data in grouped.items():
        names = data.get("NAME", [])
        if len(names) != 1 or names[0] not in selected:
            if len(names) != 1:
                diagnostics.append({"entry": folder, "reason": "unselectable NAME"})
            continue
        need(folder in descriptors, "missing physical desc member")
        name, _ = identity(descriptors[folder]["fields"], archive=True)
        need(all(data.get(k) == descriptors[folder]["fields"].get(k) for k in IDENTITY), "physical desc identity mismatch")
        need(name not in result, "duplicate repository package")
        result[name] = {"directory": folder, "metadata": data,
                        "descriptor_member": descriptors[folder]["member"],
                        "descriptor_sha256": descriptors[folder]["sha256"]}
        if file_lists:
            provenance = file_members.get(folder)
            result[name].update({"file_list_member": provenance["member"] if provenance else None,
                                 "file_list_sha256": provenance["sha256"] if provenance else None,
                                 "paths": paths(data["FILES"]) if provenance else None})
    return result, diagnostics


def baseline(files_doc, inventory):
    need(files_doc.get("inventory_sha256") == inventory["sha256"], "image inventory pairing mismatch")
    installed = json_reference(inventory)
    identities = {}
    for entry in installed["packages"]:
        name, version = identity(entry["metadata"])
        need(name not in identities, "duplicate image identity")
        identities[name] = entry["metadata"]
    result = {}
    need(isinstance(files_doc.get("packages"), list) and len(files_doc["packages"]) <= 4096, "image package bound")
    for entry in files_doc["packages"]:
        name, version = entry["name"], entry["version"]
        need(name in identities and identities[name]["VERSION"] == [version] and name not in result, "image files identity mismatch")
        text = entry["text"].encode("utf-8")
        need(len(text) <= MEMBER_LIMIT and len(text) == entry["bytes"]
             and hashlib.sha256(text).hexdigest() == entry["sha256"], "image file descriptor mismatch")
        parsed = fields(text)
        need(parsed == entry["fields"] and ("FILES" in parsed or not text), "image FILES descriptor mismatch")
        values = parsed.get("FILES", [])
        need(entry["empty_filelist"] is (not values), "empty image file-list mismatch")
        result[name] = {"metadata": identities[name], "paths": paths(values), "source": "image"}
    need(set(result) == set(identities), "incomplete image ownership inventory")
    return result


def analyze(initial, final, selected_names=None):
    selected_names = set(final) if selected_names is None else set(selected_names)
    owners = {}
    for name, item in final.items():
        for path, directory in item["paths"].items():
            owners.setdefault(path, []).append({"package": name, "directory_declared": directory})
    overlaps = [{"path": p, "owners": o} for p, o in sorted(owners.items())
                if len(o) > 1 and not all(x["directory_declared"] for x in o)]
    removed = []
    for name, item in sorted(initial.items()):
        old = {p for p, directory in item["paths"].items() if not directory}
        if name in selected_names and name not in final:
            removed.append({"package": name, "absent_from_proposed_inventory": False,
                            "ownership_unavailable": True, "unknown_previous_path_count": len(old),
                            "relinquished_paths": []})
            continue
        new = final.get(name, {}).get("paths", {})
        lost = sorted(p for p in old if p not in new or new[p])
        if name not in final or lost:
            removed.append({"package": name, "absent_from_proposed_inventory": name not in selected_names,
                            "ownership_unavailable": False,
                            "relinquished_paths": [{"path": p, "final_declared_owners": owners.get(p, [])} for p in lost]})
    return overlaps, removed


def run(contract):
    need(set(contract) == {"schema_version", "image_files", "image_inventory", "repositories", "final_inventory"}
         and contract["schema_version"] == 1, "invalid ownership contract")
    initial = baseline(json_reference(contract["image_files"]), contract["image_inventory"])
    selected_doc = json_reference(contract["final_inventory"])
    need(set(selected_doc) == {"packages", "transaction_status", "dependency_transaction_accepted"}
         and selected_doc["dependency_transaction_accepted"] is False
         and selected_doc["transaction_status"] in {"PASS-private-metadata-prepare", "FAIL-incomplete-or-policy-rejected"},
         "invalid proposed transaction inventory classification")
    partial = selected_doc["transaction_status"].startswith("FAIL")
    selected = selected_doc["packages"]
    need(isinstance(selected, list) and len(selected) <= 4096, "selected package bound")
    requested, final, unavailable, reports = {}, {}, [], []
    for item in selected:
        need(set(item) == {"name", "version", "repo", "metadata"}, "invalid selected record")
        name, version = identity(item["metadata"], archive=item["repo"] != "installed")
        need(name == item["name"] and version == item["version"] and name not in requested, "selected identity mismatch")
        need(isinstance(item["repo"], str) and NAME.fullmatch(item["repo"]), "invalid selected repository")
        requested[name] = item
        if item["repo"] == "installed":
            if name not in initial or any(item["metadata"].get(k) != initial[name]["metadata"].get(k) for k in IDENTITY[:3]):
                unavailable.append({"package": name, "reason": "installed identity mismatch"})
            else:
                final[name] = initial[name]
    need(isinstance(contract["repositories"], list) and len(contract["repositories"]) <= 8, "repository bound")
    repositories, budget = set(), {"decoded": 0, "members": 0, "metadata": 0}
    for repo in contract["repositories"]:
        need(set(repo) == {"name", "db", "files"} and NAME.fullmatch(repo["name"])
             and repo["name"] not in repositories and repo["name"] != "installed", "invalid repository contract")
        repositories.add(repo["name"])
        wanted = {n for n, p in requested.items() if p["repo"] == repo["name"]}
        db, diagnostics = catalog(repo["db"], wanted, budget)
        file_records, more = catalog(repo["files"], wanted, budget, True, {x["directory"] for x in db.values()})
        reports.append({"name": repo["name"], "db_sha256": repo["db"]["sha256"],
                        "files_sha256": repo["files"]["sha256"], "unselectable_entries": diagnostics + more})
        for name in sorted(wanted):
            wanted_meta = requested[name]["metadata"]
            reason = "unavailable DB package" if name not in db else "unavailable FILES package" if name not in file_records else None
            if not reason and file_records[name]["paths"] is None:
                reason = "unavailable physical files member"
            if not reason and any(wanted_meta.get(k) != db[name]["metadata"].get(k)
                                  or wanted_meta.get(k) != file_records[name]["metadata"].get(k) for k in IDENTITY):
                reason = "selected/DB/FILES identity mismatch"
            if reason:
                unavailable.append({"package": name, "repo": repo["name"], "reason": reason})
            else:
                final[name] = {"metadata": wanted_meta, "paths": file_records[name]["paths"], "source": repo["name"],
                               "file_list_member": file_records[name]["file_list_member"],
                               "file_list_sha256": file_records[name]["file_list_sha256"],
                               "descriptor_member": file_records[name]["descriptor_member"],
                               "descriptor_sha256": file_records[name]["descriptor_sha256"]}
    for name, item in requested.items():
        if item["repo"] != "installed" and item["repo"] not in repositories:
            unavailable.append({"package": name, "repo": item["repo"], "reason": "unavailable repository snapshot"})
    count = sum(len(p["paths"]) for p in final.values())
    need(count <= PATH_LIMIT, "aggregate selected path bound")
    overlaps, removed = analyze(initial, final, requested)
    return {"schema_version": 1, "kind": "metadata-only-declared-ownership-audit",
            "source_sha256": {"ownership.py": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
            "status": "incomplete-metadata" if unavailable else "partial-transaction-inventory" if partial else "declared-ownership-audited",
            "transaction_status": selected_doc["transaction_status"],
            "proposed_inventory_complete": not partial,
            "input_references": contract, "repositories": reports, "read_bounds": budget,
            "initial_package_count": len(initial), "selected_package_count": len(requested),
            "available_package_count": len(final), "unavailable_packages": unavailable,
            "ownership_findings_complete": not unavailable and not partial,
            "declared_non_directory_overlap_candidates": overlaps,
            "removed_or_relinquished_owners": removed,
            "selected_packages": [{"name": n, "version": p["metadata"]["VERSION"][0], "source": p["source"],
                                   "repository_member_provenance": {k: p[k] for k in ("file_list_member", "file_list_sha256", "descriptor_member", "descriptor_sha256") if k in p},
                                   "declared_paths": [path + ("/" if directory else "") for path, directory in sorted(p["paths"].items())],
                                   "hook_path_candidates": [path for path, directory in sorted(p["paths"].items()) if not directory and path.startswith(("usr/share/libalpm/hooks/", "etc/pacman.d/hooks/"))],
                                   "non_directory_file_types_unknown": True} for n, p in sorted(final.items())],
            "filesystem_collisions_verified": False, "symlink_resolution_verified": False,
            "installed_payload_verified": False, "hook_contents_verified": False,
            "transaction_committed": False, "installation_accepted": False,
            "hardware_accepted": False, "system_mutation": False,
            "limitations": ["Trailing slash is a metadata directory declaration; other file types and link targets are unknown.",
                            "Shared declared directories are tolerated; overlaps are candidates, not verified filesystem conflicts.",
                            "Unavailable selected ownership makes removal and overlap findings incomplete.",
                            "No archive payload, target filesystem, scriptlet or hook content is read or executed.",
                            "Checksums bind snapshots; this audit does not authenticate their owners or signatures."]}


def write_private(path, report):
    path = Path(os.path.abspath(path)); path.relative_to(ARTIFACTS)
    need(not any(p.is_symlink() for p in [path.parent, *path.parent.parents]), "symlink output ancestor")
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory)
        need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, "private owned output directory required")
        data = (json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
        need(len(data) <= 64 * MIB, "output bound")
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
        except BaseException:
            os.unlink(path.name, dir_fd=directory)
            raise
    finally:
        os.close(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--contract-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        spec = {"path": str(args.contract.absolute()), "size": args.contract.stat().st_size, "sha256": args.contract_sha256}
        report = run(json_reference(spec)); write_private(args.output, report)
        print(json.dumps({"status": report["status"], "report": str(args.output.absolute()), "system_mutation": False}))
        return 1 if not report["ownership_findings_complete"] or report["declared_non_directory_overlap_candidates"] else 0
    except (ValueError, OSError, KeyError, TypeError, EOFError) as error:
        parser.exit(2, "ownership audit refused: " + str(error) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
