#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture explicit Asahi inputs into a private, independently retained bundle.

No target discovery, package operations, ownership inference, or recovery test.
Only the explicitly requested new evidence directory is written. Partial output
retains INCOMPLETE and is refused by the offline comparator.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def module(name, path):
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


s = module("retained_snapshot_collector", HERE / "target_snapshot.py")
need, MIB = s.need, s.MIB
REF = {"path", "size", "sha256"}
CONFIG = {"system-configuration", "user-configuration"}


def fields(value, keys, message):
    need(isinstance(value, dict) and set(value) == set(keys), message)


def rows(value, maximum):
    need(isinstance(value, list) and len(value) <= maximum, "bounded explicit rows required")
    return value


def plain(ref):
    need(isinstance(ref, dict) and set(ref) in (REF, REF | {"url"}), "supplement reference fields refused")
    return {key: ref[key] for key in REF}


def document(reader, ref):
    value = s.audit.load_json(reader.bound(ref, 8 * MIB))
    need(isinstance(value, dict), "JSON object required")
    return value


def recovery_sources(reader, references):
    """Read exact existing receipt dependencies; never replay or improve claims."""
    receipts = []
    total = 0
    for ref in rows(references, 32):
        receipt = document(reader, ref)
        need(type(receipt.get("schema_version")) is int and receipt["schema_version"] == 1
             and receipt.get("kind") == "exact-superseded-recovery-archive-data"
             and receipt.get("status") in {"PASS-all-exact-old-recovery-archive-data", "FAIL-incomplete-recovery-archive-data"}
             and all(receipt.get(key) is False for key in ("system_mutation", "installation_accepted", "hardware_accepted",
                                                          "image_payload_correspondence_accepted", "independent_owner_trust_accepted")),
             "existing recovery receipt kind/scope refused")
        inputs = receipt["inputs"]
        need(isinstance(inputs, dict) and {"image_inventory", "certificate"} <= set(inputs)
             and set(inputs) <= {"schema_version", "image_inventory", "certificate", "old_availability", "previous_receipt"},
             "existing recovery input map refused")
        for key in ("image_inventory", "certificate", "old_availability", "previous_receipt"):
            if key in inputs:
                reader.bound(inputs[key], 8 * MIB)
        entries = rows(receipt["packages"], 4096)
        total += len(entries)
        need(total <= 4096, "aggregate recovery row bound exceeded")
        seen = set()
        for row in entries:
            need(row["name"] not in seen, "duplicate recovery package refused")
            seen.add(row["name"])
            if row["status"] == "FAIL":
                continue
            need(row["status"] == "PASS-signed-old-archive-data-matches-image-metadata", "recovery row scope refused")
            for key, limit in (("archive", 32 * MIB), ("signature", 65536), ("operator_index", MIB), ("inspection", 8 * MIB)):
                reader.bound(plain(row[key]), limit)
        passed = sum(row["status"] != "FAIL" for row in entries)
        need(type(receipt.get("planned_count")) is int and receipt["planned_count"] == len(entries)
             and type(receipt.get("verified_count")) is int and receipt["verified_count"] == passed
             and (receipt["status"] == "PASS-all-exact-old-recovery-archive-data") == (passed == len(entries)),
             "existing recovery count/status refused")
        receipts.append((ref, receipt))
    return receipts


def rewrite_recovery(receipt, retained):
    # Only known directly consumed references are relocated. Historical JSON
    # documents remain verbatim retained bytes, with original paths as labels.
    def ref(value):
        return value | retained[value["path"]]
    result = dict(receipt)
    result["inputs"] = {key: ref(value) if key != "schema_version" else value for key, value in receipt["inputs"].items()}
    result["packages"] = []
    for row in receipt["packages"]:
        updated = dict(row)
        if row["status"] != "FAIL":
            for key in ("archive", "signature", "operator_index", "inspection"):
                updated[key] = ref(row[key])
        result["packages"].append(updated)
    return result


def run(request_ref, output):
    reader = s.Reader(retain=True)
    request = document(reader, request_ref)
    fields(request, {"schema_version", "kind", "capture_contract", "machine_id", "configuration_ownership",
                     "recovery_receipts", "recovery_assets"}, "bundle request fields refused")
    need(type(request["schema_version"]) is int and request["schema_version"] == 1
         and request["kind"] == "retained-Asahi-snapshot-bundle-capture", "bundle request version/kind refused")
    need(isinstance(request["machine_id"], str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", request["machine_id"]),
         "explicit stable machine pseudonym required")
    capture = document(reader, request["capture_contract"])
    need(capture.get("mode") in {"fixture", "live"}, "explicit collector mode required")
    root = s.absolute(capture["fixture_root"]) if capture["mode"] == "fixture" else Path("/")
    owners, paths = set(), set()
    for row in rows(request["configuration_ownership"], 2):
        fields(row, {"path", "role", "owner"}, "ownership assertion fields refused")
        path = str(s.absolute(row["path"]))
        need(row["role"] in CONFIG and row["role"] not in owners and path not in paths, "duplicate/unknown ownership assertion")
        fields(row["owner"], {"kind", "id"}, "owner assertion fields refused")
        need(row["owner"]["kind"] in {"package", "user"} and isinstance(row["owner"]["id"], str)
             and re.fullmatch(r"[A-Za-z0-9@._+:-]{1,128}", row["owner"]["id"]), "explicit owner assertion required")
        owners.add(row["role"])
        paths.add(path)
    recovery_roles = rows(request["recovery_assets"], len(s.ROLES))
    need(all(isinstance(role, str) and role in s.ROLES for role in recovery_roles)
         and len(set(recovery_roles)) == len(recovery_roles), "explicit unique recovery asset roles required")
    recovery = recovery_sources(reader, request["recovery_receipts"])
    output = s.absolute(str(output))
    need(not output.is_relative_to(root / "var/lib/pacman/local"), "bundle output cannot reside in source inventory")
    parent_fd = s.opened(output.parent, directory=True)
    output_fd = None
    try:
        parent = os.fstat(parent_fd)
        need(parent.st_uid == os.geteuid() and stat.S_IMODE(parent.st_mode) == 0o700,
             "bundle parent must be caller-owned mode 0700")
        reader.recheck()
        os.mkdir(output.name, mode=0o700, dir_fd=parent_fd)
        output_fd = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        s.output_identity(output, parent_fd, output_fd)
        s.save_at(output_fd, "INCOMPLETE", b"Only a completed bundle.json without INCOMPLETE may be compared.\n")
        collection = s.run(request["capture_contract"], output / "capture", retain_inputs=True)
        s.output_identity(output, parent_fd, output_fd)
        evidence = s.Reader(maximum=256 * MIB)
        target = document(evidence, collection["snapshot"])
        collection_data, _ = evidence.read(output / "capture/collection.json", 8 * MIB)
        need(s.audit.load_json(collection_data) == collection, "collector publication changed")
        collection_ref = s.reference(output / "capture/collection.json", collection_data)
        map_data, _ = evidence.read(output / "capture/retained-inputs.json", 8 * MIB)
        input_map = s.audit.load_json(map_data)
        need(input_map["collection"] == collection_ref and len(input_map["files"]) == len(collection["sources"]),
             "collector retained map incomplete")
        source_map = {row["path"]: row for row in collection["sources"]}
        seen = set()
        for row in input_map["files"]:
            need(row["source_path"] in source_map and row["source_path"] not in seen, "collector retention source map refused")
            source = source_map[row["source_path"]]
            need(all(row["retained"][key] == source[key] for key in ("size", "sha256")), "retained source pairing refused")
            evidence.bound(row["retained"], 32 * MIB)
            seen.add(row["source_path"])
        artifacts = {row["role"]: row["artifact"] for field in ("boot_assets", "configuration_backups") for row in target[field]}
        packages = {row["metadata"]["NAME"][0] for row in target["packages"]}
        for row in request["configuration_ownership"]:
            need(row["role"] in artifacts and (row["owner"]["kind"] != "package" or row["owner"]["id"] in packages),
                 "ownership assertion must name a selected artifact and installed package")
        need(set(recovery_roles) <= set(artifacts), "recovery assertion must name a selected artifact")
        for artifact in artifacts.values():
            evidence.bound(artifact, 32 * MIB)
        os.mkdir("supplements", mode=0o700, dir_fd=output_fd)
        supplement_fd = os.open("supplements", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=output_fd)
        retained, producer_inputs = {}, []
        try:
            for index, (path, data) in enumerate(reader.retained.items()):
                name = str(index) + ".bin"
                s.save_at(supplement_fd, name, data)
                retained[path] = s.reference(output / "supplements" / name, data)
                producer_inputs.append({"source": reader.files[path], "retained": retained[path]})
            os.fsync(supplement_fd)
        finally:
            os.close(supplement_fd)
        for ref in retained.values():
            evidence.bound(ref, 32 * MIB)
        receipt_refs, derivatives = [], []
        for index, (source, receipt) in enumerate(recovery):
            name = "recovery-" + str(index) + ".json"
            data = s.encoded(rewrite_recovery(receipt, retained))
            s.save_at(output_fd, name, data)
            ref = s.reference(output / name, data)
            receipt_refs.append(ref)
            evidence.bound(ref, 8 * MIB)
            derivatives.append({"source": source, "retained_original": retained[source["path"]], "relocated_reference_copy": ref})
        context = {"schema_version": 1, "kind": "snapshot-comparison-context", "snapshot": collection["snapshot"],
                   "machine_id": request["machine_id"], "model": target["model"],
                   "configuration_ownership": [row | {"artifact": artifacts[row["role"]]} for row in request["configuration_ownership"]],
                   "recovery": {"receipts": receipt_refs, "assets": [{"role": role, "artifact": artifacts[role]} for role in recovery_roles]}}
        context_data = s.encoded(context)
        s.save_at(output_fd, "context.json", context_data)
        evidence.bound(s.reference(output / "context.json", context_data), 8 * MIB)
        bundle = {"snapshot": collection["snapshot"], "collection": collection_ref,
                  "inputs": s.reference(output / "capture/retained-inputs.json", map_data),
                  "context": s.reference(output / "context.json", context_data)}
        bundle_data = s.encoded(bundle)
        input_data = s.encoded({"schema_version": 1, "kind": "retained-bundle-producer-input-map", "files": producer_inputs})
        s.save_at(output_fd, "producer-inputs.json", input_data)
        evidence.bound(s.reference(output / "producer-inputs.json", input_data), 8 * MIB)
        report = {"schema_version": 1, "kind": "retained-Asahi-snapshot-bundle-production", "status": "RETAINED_METADATA_ONLY",
                  "scope": collection["scope"], "request_reference": request_ref, "request_retained": retained[request_ref["path"]],
                  "producer_inputs": s.reference(output / "producer-inputs.json", input_data),
                  "source_code_sha256": collection["source_code_sha256"], "bundle": bundle,
                  "bundle_reference": s.reference(output / "bundle.json", bundle_data), "recovery_reference_derivatives": derivatives,
                  "missing_evidence": ["configuration-ownership:" + role for role in sorted(CONFIG - owners)]
                                      + (["recovery-package-references"] if not recovery else [])
                                      + ["recovery-asset:" + role for role in sorted(s.ROLES - set(recovery_roles))],
                  "hardware_accepted": False, "boot_accepted": False, "recovery_accepted": False,
                  "configuration_ownership_verified": False, "fresh_signature_verification": False,
                  "limitations": ["All copied bytes are observations, not hardware or recovery acceptance.",
                                  "Machine pseudonym, selected configuration ownership and recovery roles are explicit operator assertions.",
                                  "Recovery receipts retain prior claims and receive only path relocation; no signatures or archive contents are replayed.",
                                  "Original inputs were rechecked at capture time, not frozen against future machine changes."]}
        report_data = s.encoded(report)
        s.save_at(output_fd, "producer-receipt.json", report_data)
        evidence.bound(s.reference(output / "producer-receipt.json", report_data), 8 * MIB)
        reader.recheck()
        evidence.recheck()
        s.output_identity(output, parent_fd, output_fd)
        s.save_at(output_fd, "bundle.json", bundle_data)
        evidence.bound(report["bundle_reference"], 8 * MIB)
        s.output_identity(output, parent_fd, output_fd)
        os.unlink("INCOMPLETE", dir_fd=output_fd)
        os.fsync(output_fd)
        os.fsync(parent_fd)
        s.output_identity(output, parent_fd, output_fd)
        return report
    finally:
        if output_fd is not None:
            os.close(output_fd)
        os.close(parent_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--request-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        path = s.absolute(str(args.request))
        raw, _ = s.Reader().read(path, 8 * MIB)
        report = run({"path": str(path), "size": len(raw), "sha256": args.request_sha256}, args.output)
    except (ValueError, OSError, KeyError, TypeError, AttributeError, UnicodeError) as error:
        parser.exit(1, "retained bundle refused: " + str(error) + "\n")
    print(json.dumps({"bundle": report["bundle"], "bundle_reference": report["bundle_reference"], "scope": report["scope"],
                      "missing_evidence": report["missing_evidence"], "hardware_accepted": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
