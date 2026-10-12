#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Hash inert package payloads and inspect links/hooks; never extract or execute."""
import argparse
from collections import deque
import hashlib
import importlib.util
import json
import lzma
import posixpath
from pathlib import Path
import re
import struct
import tarfile
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("payload_ownership", HERE / "ownership.py")
ownership = importlib.util.module_from_spec(spec); spec.loader.exec_module(ownership)
MIB = 1024**2
ARCHIVE_LIMIT, DECODED_LIMIT, TOTAL_DECODED_LIMIT = 300_000_000, 1024**3, 8 * 1024**3
FILE_LIMIT, NODE_LIMIT, TOTAL_NODE_LIMIT = 512 * MIB, 100000, 500000
CONTROL = {".PKGINFO", ".BUILDINFO", ".MTREE", ".INSTALL"}


def need(value, message):
    if not value:
        raise ValueError(message)


def normalized(value):
    need(isinstance(value, str) and 0 < len(value) <= 4096
         and not re.search(r"[\x00-\x1f\x7f]", value), "unsafe node path")
    value = value.removeprefix("./").removesuffix("/")
    need(value and not value.startswith("/") and all(p not in {"", ".", ".."} for p in value.split("/")), "node traversal")
    return value


class Counted:
    def __init__(self, stream, budget):
        self.stream, self.budget, self.decoded = stream, budget, 0
        self.started = time.monotonic()

    def read(self, size):
        need(0 <= size <= MIB, "decoded read bound")
        need(self.decoded <= DECODED_LIMIT and self.budget["decoded"] <= TOTAL_DECODED_LIMIT, "decoded work exhausted")
        need(time.monotonic() - self.started <= 300, "archive inspection deadline")
        size = min(size, DECODED_LIMIT - self.decoded + 1, TOTAL_DECODED_LIMIT - self.budget["decoded"] + 1)
        data = self.stream.read(size)
        self.decoded += len(data); self.budget["decoded"] += len(data)
        need(self.decoded <= DECODED_LIMIT and self.budget["decoded"] <= TOTAL_DECODED_LIMIT, "decoded work bound")
        need(time.monotonic() - self.started <= 300, "archive inspection deadline")
        return data


def elf(header):
    if not header.startswith(b"\x7fELF"):
        return None
    need(len(header) >= 20 and header[4] in {1, 2} and header[5] in {1, 2}, "invalid ELF header")
    endian = "<" if header[5] == 1 else ">"
    result = {"class": 32 if header[4] == 1 else 64,
              "machine": struct.unpack_from(endian + "H", header, 18)[0], "executed": False,
              "16K_runtime_load_verified": False}
    if header[4] == 2 and len(header) >= 64:
        offset = struct.unpack_from(endian + "Q", header, 32)[0]
        entry_size, count = struct.unpack_from(endian + "HH", header, 54)
        if entry_size == 56 and count <= 256 and offset + count * entry_size <= len(header):
            loads = []
            for index in range(count):
                fields = struct.unpack_from(endian + "IIQQQQQQ", header, offset + index * entry_size)
                if fields[0] == 1:
                    loads.append({"offset": fields[2], "virtual_address": fields[3], "alignment": fields[7],
                                  "offset_vaddr_congruent_mod_16384": fields[2] % 16384 == fields[3] % 16384})
            result["PT_LOAD"] = loads
    return result


def hook_fields(text):
    sections, current = [], None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = {"section": line[1:-1], "fields": {}}; sections.append(current)
        elif current is not None and "=" in line:
            key, value = [p.strip() for p in line.split("=", 1)]
            current["fields"].setdefault(key, []).append(value)
        elif current is not None and current["section"] == "Action" and line in {"NeedsTargets", "AbortOnFail"}:
            current["fields"].setdefault(line, []).append(True)
        else:
            return {"parsed": False, "reason": "unsupported hook syntax", "executed": False}
    return {"parsed": True, "sections": sections, "executed": False,
            "trigger_execution_order_or_behavior_verified": False}


def inspect(reference, budget):
    nodes, controls, seen = [], {}, set()
    with ownership.reference(reference, ARCHIVE_LIMIT) as raw:
        with lzma.LZMAFile(raw) as decoded:
            counted = Counted(decoded, budget)
            with tarfile.open(fileobj=counted, mode="r|") as archive:
                for member in archive:
                    if member.name in {".", "./"} and member.isdir():
                        continue
                    name = normalized(member.name)
                    need(name not in seen and len(seen) < NODE_LIMIT, "duplicate/node count")
                    need(budget["nodes"] < TOTAL_NODE_LIMIT, "aggregate node count")
                    seen.add(name); budget["nodes"] += 1
                    need(member.sparse is None and not any(k.startswith("GNU.sparse.") for k in member.pax_headers), "sparse payload unsupported")
                    need(member.isdir() or member.isfile() or member.issym() or member.islnk(), "special payload node")
                    need(0 <= member.size <= FILE_LIMIT, "member size bound")
                    node = {"path": name, "mode": member.mode, "bytes": member.size}
                    if member.isdir():
                        node["type"] = "directory"
                    elif member.issym() or member.islnk():
                        need(0 < len(member.linkname) <= 4096 and not re.search(r"[\x00-\x1f\x7f]", member.linkname), "unsafe link value")
                        node.update({"type": "symlink" if member.issym() else "hardlink", "target": member.linkname})
                    else:
                        node["type"] = "file"
                        h, head, text, size = hashlib.sha256(), b"", bytearray(), 0
                        capture = name in {".PKGINFO", ".BUILDINFO", ".INSTALL"} or name.startswith(("usr/share/libalpm/hooks/", "etc/pacman.d/hooks/"))
                        need(not capture or member.size <= MIB, "scriptlet/hook/metadata bound")
                        stream = archive.extractfile(member)
                        while block := stream.read(MIB):
                            size += len(block); need(size <= member.size, "member read overrun")
                            h.update(block)
                            if len(head) < 65536:
                                head += block[:65536 - len(head)]
                            if capture:
                                text.extend(block)
                        need(size == member.size, "short payload member")
                        node["sha256"] = h.hexdigest()
                        info = elf(head)
                        if info:
                            node["ELF"] = info
                        if capture:
                            node["text"] = bytes(text).decode("utf-8")
                            if name.endswith(".hook"):
                                node["hook"] = hook_fields(node["text"])
                    if name in CONTROL:
                        need(node["type"] == "file", "non-file package control")
                        controls[name] = node
                    else:
                        nodes.append(node)
            # Check trailing decoded bytes too; tar terminators do not hide a bomb.
            while counted.read(MIB):
                pass
    need(".PKGINFO" in controls, "missing package identity")
    return {"nodes": nodes, "controls": controls, "decoded_bytes": counted.decoded}


def pkginfo(text):
    fields = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        need(" = " in line, "invalid PKGINFO field")
        key, value = line.split(" = ", 1); fields.setdefault(key, []).append(value)
    return fields


def resolved_link(node, namespace, maximum=40):
    """Resolve observed symlink prefixes through a declared, partly unknown tree."""
    need(type(maximum) is int and 1 <= maximum <= 40, "link expansion bound")
    target = node["target"]
    normalized(node["path"])
    need(isinstance(target, str) and 0 < len(target) <= 4096
         and not re.search(r"[\x00-\x1f\x7f]", target), "unsafe link value")
    path = target.lstrip("/") if target.startswith("/") else posixpath.join(posixpath.dirname(node["path"]), target)
    pending, resolved, visited, expansions = deque(path.split("/")), [], set(), 0

    def result(status, **fields):
        return {"status": status, "path": "/".join([*resolved, *pending]) or ".",
                "filesystem_resolution_verified": False, **fields}

    while pending:
        component = pending.popleft()
        if component in {"", "."}:
            continue
        if component == "..":
            if not resolved:
                pending.appendleft(component)
                return result("escapes-proposed-root")
            resolved.pop()
            continue
        prefix = "/".join([*resolved, component]); entry = namespace.get(prefix)
        if entry and entry.get("type") == "symlink" and not entry.get("declared_only"):
            state = (prefix, tuple(pending))
            if state in visited:
                pending.appendleft(component)
                return result("observed-link-cycle")
            if expansions == maximum:
                pending.appendleft(component)
                return result("link-depth-bound")
            visited.add(state); expansions += 1
            value = entry["target"]
            need(isinstance(value, str) and 0 < len(value) <= 4096
                 and not re.search(r"[\x00-\x1f\x7f]", value), "unsafe link value")
            if value.startswith("/"):
                resolved.clear()
            pending.extendleft(reversed(value.split("/")))
            if sum(len(p) + 1 for p in [*resolved, *pending]) > 8192:
                return result("link-path-bound")
            continue
        resolved.append(component)
        if pending and entry:
            if entry.get("type") == "unknown" or entry.get("declared_only"):
                return result("unknown-ancestor-type", ancestor=prefix)
            if entry.get("type") != "directory":
                return result("observed-nondirectory-ancestor", ancestor=prefix, errno="ENOTDIR")
    entry = namespace.get("/".join(resolved))
    return result("observed-target" if entry and entry.get("type") != "unknown" and not entry.get("declared_only") else "declared-target-payload-unknown" if entry else "target-not-declared")


def run(contract):
    need(set(contract) == {"schema_version", "transaction", "ownership", "archives"}
         and type(contract["schema_version"]) is int and contract["schema_version"] == 1, "payload contract")
    transaction, owners = [ownership.json_reference(contract[key]) for key in ("transaction", "ownership")]
    need(transaction["kind"] == "private-Asahi-metadata-transaction-prepare"
         and owners["kind"] == "metadata-only-declared-ownership-audit", "source report kind")
    source_final = ownership.json_reference(owners["input_references"]["final_inventory"])
    need(source_final["packages"] == transaction["proposed_final_inventory"]
         and source_final["transaction_status"] == owners["transaction_status"] == transaction["status"]
         and source_final["dependency_transaction_accepted"] is False, "ownership/full final metadata binding")
    final = {p["name"]: p for p in transaction["proposed_final_inventory"]}
    need(len(final) == len(transaction["proposed_final_inventory"]), "duplicate final identity")
    declarations = {p["name"]: p for p in owners["selected_packages"]}
    need(set(final) == set(declarations) and all(final[n]["version"] == declarations[n]["version"] for n in final), "ownership/final identity binding")
    rows = contract["archives"]
    need(isinstance(rows, list) and 1 <= len(rows) <= 4096, "finite archive input")
    need(sum(r["archive"]["size"] for r in rows) <= 1024**3, "compressed aggregate input bound")
    seen, results, budget = set(), [], {"decoded": 0, "nodes": 0}
    namespace, overlaps = {}, []
    for name, declaration in declarations.items():
        for value in declaration["declared_paths"]:
            path = normalized(value)
            namespace.setdefault(path, {"type": "directory" if value.endswith("/") else "unknown", "declared_only": True})
    for row in rows:
        need(set(row) == {"name", "archive"}, "archive input fields")
        name = row["name"]; need(name in final and name not in seen, "unselected/duplicate archive"); seen.add(name)
        metadata = final[name]["metadata"]
        pinned = final[name]["repo"] != "installed"
        if pinned:
            need(row["archive"]["sha256"] == metadata["SHA256SUM"][0] and row["archive"]["size"] == int(metadata["CSIZE"][0]), "final archive pin mismatch")
        result = {"name": name, "version": final[name]["version"], "archive": row["archive"],
                  "identity_scope": "exact-final-metadata-pins" if pinned else "same-identity-image-payload-unverified",
                  "image_payload_correspondence_verified": False}
        try:
            data = inspect(row["archive"], budget)
            fields = pkginfo(data["controls"][".PKGINFO"]["text"])
            for field, key in (("pkgname", "NAME"), ("pkgver", "VERSION"), ("arch", "ARCH"),
                               ("depend", "DEPENDS"), ("provides", "PROVIDES"), ("conflict", "CONFLICTS"),
                               ("replaces", "REPLACES"), ("license", "LICENSE")):
                need(sorted(fields.get(field, [])) == sorted(metadata.get(key, [])), "PKGINFO mismatch: " + field)
            actual = {n["path"] + ("/" if n["type"] == "directory" else "") for n in data["nodes"]}
            declared = set(declarations[name]["declared_paths"])
            result.update(data, status="payload-inspected-as-data", missing_declared_paths=sorted(declared - actual),
                          undeclared_archive_paths=sorted(actual - declared))
            for node in data["nodes"]:
                old = namespace.get(node["path"])
                if old and "observed_owner" in old and not (old["type"] == node["type"] == "directory"):
                    overlaps.append({"path": node["path"], "owners": [old["observed_owner"], name]})
                namespace[node["path"]] = node | {"observed_owner": name}
        except (ValueError, OSError, EOFError, tarfile.TarError, lzma.LZMAError, UnicodeError) as error:
            result.update(status="payload-inspection-failed", error=type(error).__name__ + ": " + str(error))
        results.append(result)
    links = []
    for package in results:
        for node in package.get("nodes", []):
            if node["type"] == "symlink":
                links.append({"name": package["name"], "path": node["path"], "target": node["target"],
                              "resolution": resolved_link(node, namespace)})
            elif node["type"] == "hardlink":
                try:
                    target = normalized(node["target"])
                except ValueError:
                    links.append({"name": package["name"], "path": node["path"], "target": node["target"],
                                  "resolution": {"status": "unsafe-hardlink-target", "filesystem_resolution_verified": False}})
                    continue
                peer = next((p for p in package["nodes"] if p["path"] == target), None)
                links.append({"name": package["name"], "path": node["path"], "target": node["target"],
                              "resolution": {"status": "same-archive-file" if peer and peer["type"] == "file" else "hardlink-target-not-regular-in-same-archive",
                                             "payload_sha256": peer.get("sha256") if peer else None, "filesystem_resolution_verified": False}})
    return {"schema_version": 1, "kind": "inert-exact-package-payload-link-hook-observation",
            "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "inputs": contract, "transaction_status": transaction["status"], "selected_final_count": len(final),
            "inspected_package_count": sum(p["status"] == "payload-inspected-as-data" for p in results),
            "archive_unavailable_packages": sorted(set(final) - seen), "packages": results,
            "links": links, "observed_non_directory_overlaps": overlaps, "read_bounds": budget,
            "archive_signatures_verified_by_this_helper": False, "complete_installed_payload_verified": False,
            "symlink_resolution_on_target_verified": False, "hook_execution_verified": False,
            "package_payloads_executed": False, "image_authentication_accepted": False,
            "installation_accepted": False, "hardware_accepted": False, "system_mutation": False,
            "limitations": ["Artifact checksums are exact; signature evidence is a separate hash-bound audit.",
                            "Observed archive file types/hashes do not establish identity of existing image payloads.",
                            "Link resolution uses declared ownership and available archive nodes; unknown baseline nodes remain unknown.",
                            "Hooks and scriptlets are retained as inert text; execution order and behavior are not tested."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--contract-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        report = run(ownership.json_reference({"path": str(args.contract.absolute()), "size": args.contract.stat().st_size, "sha256": args.contract_sha256}))
        ownership.write_private(args.output, report)
        print(json.dumps({"inspected_packages": report["inspected_package_count"], "output": str(args.output.absolute()), "system_mutation": False}))
        return 1 if report["archive_unavailable_packages"] or any(p["status"] != "payload-inspected-as-data" or p.get("missing_declared_paths") or p.get("undeclared_archive_paths") for p in report["packages"]) else 0
    except (ValueError, OSError, KeyError, TypeError) as error:
        parser.exit(2, "payload audit refused: " + str(error) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
