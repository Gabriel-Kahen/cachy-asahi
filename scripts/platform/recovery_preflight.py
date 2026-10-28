#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Join offline exact-target metadata to a prepared update and retained recovery data.

Never probes the host, downloads, prepares/commits a transaction, or boots hardware.
Retained signature evidence is replayed, not freshly verified or owner trusted.
Exit 2 is a valid blocked assessment; exit 1 refuses malformed/broken inputs.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import time

sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


audit = module("preflight_tuple", HERE / "tuple_audit.py")
recovery = module("preflight_recovery", HERE / "recovery_inputs.py")
need = recovery.need
MODELS = {"apple,j413": 13, "apple,j415": 15}
PLATFORM = set(audit.BOOT + audit.AUDIO + ("mesa", "vulkan-asahi", "linux-firmware", "alsa-ucm-conf-asahi",
                                         "pipewire", "wireplumber", "bankstown", "triforce-lv2"))
BOOT_ROLES = {"boot-chain", "kernel", "kernel-release", "firmware"}
CONFIG_ROLES = {"user-configuration", "system-configuration"}
MAX_ROWS = 4096
MAX_RECOVERY = 32
MAX_SECONDS = 120
SEMANTIC = ("NAME", "VERSION", "ARCH", "DEPENDS", "PROVIDES", "CONFLICTS", "REPLACES", "LICENSE")


def document(reference):
    return audit.load_json(recovery.auth.bound_bytes(reference, 8 * recovery.MIB))


def metadata(rows):
    need(isinstance(rows, list) and 0 < len(rows) <= MAX_ROWS, "finite package rows required")
    cleaned = []
    for row in rows:
        fields = dict(row["metadata"])
        if "name" in row:
            need(fields.get("NAME") == [row["name"]] and fields.get("VERSION") == [row["version"]],
                 "inventory envelope/metadata identity mismatch")
        if "repo" in fields:
            need(fields["repo"] == row.get("repo") and fields["repo"] in {"installed", "asahi-alarm", "core", "extra"},
                 "final inventory repository annotation refused")
            del fields["repo"]
        cleaned.append(fields)
    return audit.packages(cleaned)


def versions(rows):
    return {name: data["VERSION"][0] for name, data in rows.items()}


def semantic(row):
    return None if row is None else {key: row.get(key, []) for key in SEMANTIC}


def reinspect(row, package, cache, reference, remaining):
    """Bound the maintained archive inspector in a private read-only child."""
    need(remaining > 0, "preflight deadline exceeded")
    request = json.dumps({"row": row, "package": package, "cache": cache, "reference": reference}).encode()
    need(len(request) <= 8 * recovery.MIB, "reinspection request bound exceeded")
    try:
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--reinspect-row"],
                                input=request, capture_output=True, timeout=min(30, remaining), check=False)
    except subprocess.TimeoutExpired:
        raise ValueError("recovery archive reinspection deadline exceeded") from None
    need(result.returncode == 0 and len(result.stdout) <= 1024 and not result.stderr,
         "bounded recovery archive reinspection refused")
    updated = audit.load_json(result.stdout)
    need(set(updated) == set(cache) and all(type(value) is int and value >= cache[key] for key, value in updated.items()),
         "reinspection byte accounting refused")
    cache.update(updated)


def run(contract):
    need(set(contract) == {"schema_version", "target_snapshot", "prepared_update", "recovery_receipts"}
         and type(contract["schema_version"]) is int and contract["schema_version"] == 1,
         "preflight contract fields/version refused")
    refs = contract["recovery_receipts"]
    need(isinstance(refs, list) and len(refs) <= MAX_RECOVERY, "finite recovery receipts required")
    started = time.monotonic()
    target, update = (document(contract[key]) for key in ("target_snapshot", "prepared_update"))
    need(set(target) == {"schema_version", "kind", "model", "device_tree_compatible", "packages",
                         "boot_assets", "configuration_backups", "captured_at", "runtime"}
         and type(target["schema_version"]) is int and target["schema_version"] == 1
         and target["kind"] == "operator-supplied-offline-Asahi-target-snapshot",
         "offline target snapshot schema refused")
    model = target["model"]
    need(set(model) == {"compatible", "air_size_inches"}
         and isinstance(model["compatible"], str)
         and type(model["air_size_inches"]) is int, "exact model fields required")
    need(isinstance(target["captured_at"], str) and 0 < len(target["captured_at"]) <= 128,
         "snapshot observation label required")
    runtime = target["runtime"]
    need(set(runtime) == {"architecture", "kernel_release", "page_size", "kernel_package_version"}
         and type(runtime["page_size"]) is int
         and isinstance(runtime["kernel_package_version"], str)
         and isinstance(runtime["kernel_release"], str) and 0 < len(runtime["kernel_release"]) <= 256,
         "runtime observation fields refused")
    compatible = recovery.auth.bound_bytes(target["device_tree_compatible"], 65536)
    need(compatible.endswith(b"\0"), "device-tree compatible must be a NUL-terminated raw property")
    compatible = compatible[:-1].decode("ascii").split("\0")
    installed = metadata(target["packages"])
    need(type(update.get("schema_version")) is int and update["schema_version"] == 1
         and update.get("kind") == "private-Asahi-metadata-transaction-prepare"
         and update.get("proposal_kind") == "unadopted-coordinated-python-change"
         and update.get("adopted") is False
         and all(update.get(key) is False for key in ("commit_called", "host_database_used", "hardware_accepted",
                                                     "installation_accepted", "dependency_transaction_accepted")),
         "unadopted data-only prepared-update scope refused")
    coordinated = document(update["input_references"]["strict_contract"])
    baseline_ref = coordinated["image_inventory"]
    baseline = metadata(document(baseline_ref)["packages"])
    tuple_report = document(coordinated["tuple_report"])
    need(tuple_report.get("input_sha256", {}).get("image") == baseline_ref["sha256"], "strict tuple/baseline pairing refused")
    graph = tuple_report["proposed_installed_dependency_graph"]
    need(isinstance(graph, list) and 0 < len(graph) <= MAX_ROWS, "finite strict protected graph required")
    authority = {row["name"]: row["version"] for row in graph}
    need(len(authority) == len(graph) and all(baseline.get(name, {}).get("VERSION") == [version]
                                            for name, version in authority.items()), "strict protected graph identity refused")
    final = metadata(update["proposed_final_inventory"])
    preserve = update["protected_preservation"]
    need(isinstance(preserve, list) and 0 < len(preserve) <= MAX_ROWS, "finite protected tuple required")
    protected = {}
    change = update["input_references"]["change"]
    need(change == {"name": "python", "from": "3.14.7-1", "to": "3.14.8-1"}
         and authority.get("python") == change["from"], "coordinated proposal change scope refused")
    for row in preserve:
        name = row["name"]
        need(name in baseline and name not in protected and row["original"] == baseline[name]["VERSION"][0],
             "protected original/baseline binding refused")
        need(isinstance(row["expected"], str) and row["final"] == final.get(name, {}).get("VERSION", [None])[0]
             and type(row["preserved"]) is bool and row["preserved"] == (row["final"] == row["expected"]),
             "protected final/preservation binding refused")
        need(row["expected"] == (change["to"] if name == change["name"] else row["original"]),
             "unexpected protected package version exemption")
        protected[name] = row
    need(set(protected) == set(authority), "whole strict protected graph required")
    conditions = []

    def blocked(code, action, **details):
        conditions.append({"code": code, "next_action": action, **details})

    if (MODELS.get(model["compatible"]) != model["air_size_inches"] or compatible.count(model["compatible"]) != 1
            or set(compatible) & set(MODELS) != {model["compatible"]}):
        blocked("target-model-mismatch", "Capture the exact M2 Air size and matching raw device-tree compatible property.")
    if runtime["architecture"] != "aarch64" or runtime["page_size"] != 16384:
        blocked("target-runtime-mismatch", "Capture the running target architecture and page size; generic ARM evidence cannot stand in for M2.")
    if installed.get("linux-asahi", {}).get("VERSION") != [runtime["kernel_package_version"]]:
        blocked("running-kernel-package-mismatch", "Bind the running kernel observation to the exact installed linux-asahi package version.")
    if update.get("status") != "PASS-private-metadata-prepare" or not all(
            update.get(key) is True for key in ("all_protected_versions_preserved", "all_targets_satisfied")):
        blocked("update-not-prepared", "Resolve the coordinated proposal's metadata preparation failures.")
    for name in sorted(set(baseline) | set(installed)):
        if semantic(installed.get(name)) != semantic(baseline.get(name)):
            blocked("target-baseline-metadata-mismatch", "Reprepare the coordinated proposal against this exact target inventory.",
                    package=name, baseline_version=versions(baseline).get(name), installed_version=versions(installed).get(name),
                    mismatched_fields=[key for key in SEMANTIC if baseline.get(name, {}).get(key, []) != installed.get(name, {}).get(key, [])])
    for name in sorted(PLATFORM):
        if name not in installed or name not in final:
            blocked("required-platform-package-missing", "Capture and retain the complete working Asahi platform tuple before proposing updates.",
                    package=name, installed=name in installed, proposed=name in final)
        elif semantic(installed[name]) != semantic(final[name]):
            blocked("platform-package-change", "Keep the working platform unchanged; separately review and test an exact coordinated platform change.",
                    package=name, installed_version=installed[name]["VERSION"][0], proposed_version=final[name]["VERSION"][0])
        if name not in protected:
            blocked("platform-package-not-protected", "Include this platform package in the coordinated protected tuple.", package=name)
    for name, row in sorted(protected.items()):
        if not row["preserved"]:
            blocked("protected-package-not-preserved", "Resolve the exact protected tuple mismatch in the prepared proposal.", package=name)
        if name != change["name"] and semantic(installed.get(name)) != semantic(final.get(name)):
            blocked("protected-package-metadata-change", "Preserve the protected package's exact dependency and identity metadata, or separately review its coordinated change.", package=name)
    retained = {}
    for field, required in (("boot_assets", BOOT_ROLES), ("configuration_backups", CONFIG_ROLES)):
        rows = target[field]
        need(isinstance(rows, list) and len(rows) <= 64, "finite retained asset set required")
        roles = set()
        for row in rows:
            need(set(row) == {"role", "artifact"} and row["role"] in required and row["role"] not in roles,
                 "duplicate/unknown retained asset role")
            roles.add(row["role"])
            data = recovery.auth.bound_bytes(row["artifact"], 32 * recovery.MIB)
            if row["role"] == "kernel-release" and data.decode("ascii").strip() != runtime["kernel_release"]:
                blocked("running-kernel-release-mismatch", "Capture the running kernel release and matching retained kernel release artifact together.")
        retained[field] = rows
        for role in sorted(required - roles):
            blocked("retained-asset-missing", "Retain a retrievable checksum-bound artifact for this exact target; document and exercise restoration.", role=role)
    cache = {"cache_bytes": 0, "metadata_bytes": 0, "external_retained_cache_bytes": 0, "external_retained_metadata_bytes": 0}
    recovered, seen = {}, set()
    total_rows = 0
    for reference in refs:
        need(time.monotonic() - started <= MAX_SECONDS, "preflight deadline exceeded")
        receipt = document(reference)
        need(receipt.get("kind") == "exact-superseded-recovery-archive-data"
             and type(receipt.get("schema_version")) is int and receipt["schema_version"] == 1
             and receipt.get("inputs", {}).get("image_inventory") == baseline_ref
             and receipt.get("status") in {"PASS-all-exact-old-recovery-archive-data", "FAIL-incomplete-recovery-archive-data"}
             and all(receipt.get(key) is False for key in ("system_mutation", "installation_accepted", "hardware_accepted",
                                                          "image_payload_correspondence_accepted", "independent_owner_trust_accepted")),
             "recovery receipt/baseline/scope binding refused")
        certificate = receipt["inputs"]["certificate"]
        need(certificate["sha256"] == recovery.auth.KEYS["alarm"][1], "recovery certificate pin refused")
        recovery.auth.bound_bytes(certificate, recovery.MIB)
        rows = receipt["packages"]
        need(isinstance(rows, list) and 0 < len(rows) <= MAX_ROWS, "finite recovery package rows required")
        count = sum(row.get("status") == "PASS-signed-old-archive-data-matches-image-metadata" for row in rows)
        need(type(receipt.get("planned_count")) is int and receipt["planned_count"] == len(rows)
             and type(receipt.get("verified_count")) is int and receipt["verified_count"] == count
             and (receipt["status"] == "PASS-all-exact-old-recovery-archive-data") == (count == len(rows)),
             "recovery receipt completion counts/status refused")
        total_rows += len(rows)
        need(total_rows <= MAX_ROWS, "aggregate recovery row bound exceeded")
        for row in rows:
            need(time.monotonic() - started <= MAX_SECONDS, "preflight deadline exceeded")
            name = row["name"]
            need(name in baseline and name not in seen and row["observed_image_metadata"] == baseline[name]
                 and (row["version"], row["arch"]) == tuple(baseline[name][key][0] for key in ("VERSION", "ARCH")),
                 "recovery package identity/duplicate refused")
            seen.add(name)
            if row["status"] == "FAIL":
                continue
            need(row["status"] == "PASS-signed-old-archive-data-matches-image-metadata", "recovery row status refused")
            package = {"name": name, "version": row["version"], "arch": row["arch"], "metadata": baseline[name],
                       "filename": f"{name}-{row['version']}-{row['arch']}.pkg.tar.xz",
                       "index_url": f"https://{recovery.HOST}/aarch64/packages/{name[0]}/{name}/"}
            # Reuse the maintained exact-link, signature-status and actual archive inspector.
            try:
                reinspect(row, package, cache, reference, MAX_SECONDS - (time.monotonic() - started))
            except ValueError as error:
                raise ValueError(f"recovery package {name}: {error}") from error
            recovered[name] = {"archive": recovery.ref_only(row["archive"]), "receipt": reference,
                               "fresh_signature_verification": False}
    recovery_needed = set(protected) | (PLATFORM & set(installed))
    for name in sorted(recovery_needed - set(recovered)):
        blocked("exact-recovery-archive-missing", "Retain and authenticate this installed package's exact recovery archive and detached signature; current catalog availability is insufficient.",
                package=name, installed_version=versions(installed).get(name))
    need(time.monotonic() - started <= MAX_SECONDS, "preflight deadline exceeded")
    return {"schema_version": 1, "kind": "offline-exact-target-platform-recovery-preflight",
            "status": "BLOCKED-unaccepted-target-update", "input_references": contract,
            "source_sha256": {"recovery_preflight.py": recovery.auth.hash_file(Path(__file__)),
                              "recovery_inputs.py": recovery.auth.hash_file(Path(recovery.__file__)),
                              "tuple_audit.py": recovery.auth.hash_file(Path(audit.__file__))},
            "model": model, "captured_at": target["captured_at"], "runtime": runtime,
            "target_snapshot_live_verified": False, "installed_package_count": len(installed),
            "protected_package_count": len(protected), "software_data_bound": not conditions,
            "conditions": conditions, "recovery_archives_rehashed_and_reinspected": recovered,
            "retained_assets_rehashed": retained, "recovery_byte_accounting": cache,
            "physical_checks": [{"check": check, "result": "NOT RUN", "model": model}
                                for check in ("exact-target-boot", "graphics-input-network", "audio-speaker-protection",
                                              "lock-and-session-preserving-suspend", "interrupted-update-recovery",
                                              "boot-and-session-restoration")],
            "next_action": "Resolve listed data conditions, independently authenticate owners and freshly verify signatures, then exercise the exact model/tuple under an owned hardware validation plan.",
            "system_mutation": False, "downloads_or_repository_updates": False,
            "fresh_signature_verification": False, "independent_owner_trust_accepted": False,
            "installation_accepted": False, "hardware_accepted": False, "recovery_accepted": False,
            "limitations": ["Snapshot metadata and retained bytes are supplied observations; no live machine was probed.",
                            "Package metadata equality does not establish installed payload, boot asset or configuration completeness.",
                            "Recovery archive checks replay retained signature evidence and reinspect archives without network or fresh crypto.",
                            "A clean data assessment grants no permission to install and no boot, recovery or M2 acceptance."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--contract-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        reference = {"path": str(args.contract.absolute()), "size": args.contract.stat().st_size,
                     "sha256": args.contract_sha256}
        report = run(document(reference))
        report["contract_reference"] = reference
        audit.write_private(args.output, report)
    except (ValueError, OSError, KeyError, TypeError, AttributeError, UnicodeError, EOFError, tarfile.TarError) as error:
        parser.exit(1, "recovery preflight refused: " + str(error) + "\n")
    print(json.dumps({"report": str(args.output.absolute()), "status": report["status"],
                      "software_data_bound": report["software_data_bound"], "hardware_accepted": False}, sort_keys=True))
    return 2


if __name__ == "__main__":
    if sys.argv[1:] == ["--reinspect-row"]:
        # Limits apply only to this disposable child, never its caller.
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (512 * recovery.MIB, 512 * recovery.MIB))
        resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
        try:
            raw = sys.stdin.buffer.read(8 * recovery.MIB + 1)
            need(len(raw) <= 8 * recovery.MIB, "worker input bound")
            request = audit.load_json(raw)
            recovery.reuse(request["row"], request["package"], request["cache"], request["reference"])
            print(json.dumps(request["cache"]))
        except Exception:
            raise SystemExit(1)
        raise SystemExit(0)
    raise SystemExit(main())
