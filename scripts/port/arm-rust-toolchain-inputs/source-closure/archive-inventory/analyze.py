#!/usr/bin/env python3
"""Compare scanned Cargo/vendor/license declarations, without accepting builds."""
import argparse
import hashlib
import json
from pathlib import Path
import resource
import signal

HERE = Path(__file__).resolve().parent
CAP = 16 * 1024**2
LICENSES = {("rust", "LICENSE-MIT"): "licenses/rust-LICENSE-MIT",
            ("rust", "LICENSE-APACHE"): "licenses/rust-LICENSE-APACHE",
            ("llvm", "llvm/LICENSE.TXT"): "licenses/llvm-llvm-LICENSE.TXT",
            ("llvm", "compiler-rt/LICENSE.TXT"): "licenses/llvm-compiler-rt-LICENSE.TXT",
            ("llvm", "lld/LICENSE.TXT"): "licenses/llvm-lld-LICENSE.TXT"}


def analyze(reports, parent):
    licenses, locks = [], []
    rust = reports["rust"]
    vendors = rust.get("vendor_components", {})
    packages = []
    for directory, vendor in vendors.items():
        package = vendor.get("Cargo.toml", {}).get("declarations", {})
        package = (package or {}).get("package", {})
        checksum = vendor.get(".cargo-checksum.json", {}).get("declarations", {}) or {}
        packages.append({"directory": directory, "name": package.get("name"),
                         "version": package.get("version"), "license": package.get("license"),
                         "license_file": package.get("license-file"),
                         "package_checksum": checksum.get("package_checksum"),
                         "license_files_seen": len(vendor["licenses"]),
                         "declared_file_checksums": checksum.get("declared_file_checksums")})
    for name, report in reports.items():
        records = {item["path"]: item for item in report.get("selected_metadata", [])}
        for (archive, path), retained in LICENSES.items():
            if archive != name:
                continue
            record, expected = records.get(path), parent["materials"][retained]
            licenses.append({"archive": name, "member": path, "original_notice": retained,
                             "metadata_pin_matches_retained_notice": bool(record and
                                 record.get("sha256") == expected["sha256"] and record.get("bytes") == expected["bytes"]),
                             "archive_member_pin": {key: record[key] for key in ("bytes", "sha256")} if record and "sha256" in record else None})
        for path, record in records.items():
            if not path.endswith("Cargo.lock"):
                continue
            entries = (record.get("declarations") or {}).get("packages", [])
            registry = [item for item in entries if item.get("source", "").startswith("registry+")]
            git = [item for item in entries if item.get("source", "").startswith("git+")]
            missing = []
            for item in registry:
                checksum = item.get("checksum")
                valid_checksum = isinstance(checksum, str) and len(checksum) == 64 and all(c in "0123456789abcdef" for c in checksum)
                if not valid_checksum or not any(p["name"] == item.get("name") and p["version"] == item.get("version")
                           and p["package_checksum"] == item.get("checksum") for p in packages):
                    missing.append(item)
            locks.append({"archive": name, "member": path, "packages": len(entries),
                          "registry_packages": len(registry), "registry_metadata_matches": len(registry) - len(missing),
                          "registry_metadata_mismatches_or_missing": missing,
                          "git_source_entries": git,
                          "match_does_not_verify_vendor_file_contents_or_build_consumption": True})
    return {"scope": "scanned declaration comparisons only", "source_reports_complete":
            all(r.get("status") == "COMPLETE_BOUNDED_SCAN" and r.get("authenticated_source_pin_verified") for r in reports.values()),
            "original_notice_comparisons": licenses, "cargo_lock_comparisons": locks,
            "vendor_components_seen": len(vendors),
            "vendor_components_without_license_named_files": [p for p in packages if not p["license_files_seen"]],
            "vendor_components_without_manifest_or_checksum_declaration": [p for p in packages
                if not p["name"] or not p["version"] or p["declared_file_checksums"] is None],
            "submodule_declarations": {name: report.get("submodule_declarations", []) for name, report in reports.items()},
            "selected_source_declarations_and_notices": {name: [{key: r[key] for key in ("path", "bytes", "sha256") if key in r}
                for r in report.get("selected_metadata", []) if not r["path"].startswith("vendor/")] for name, report in reports.items()},
            "license_named_file_predicate": "regular vendor file basename uppercased starts with LICENSE, COPYING, NOTICE, UNLICENSE or COPYRIGHT; no grant inferred",
            "remaining_evidence_gaps": [
                "Per-file vendor checksum maps were counted and pinned, not checked against every source file.",
                "Lock/vendor manifest/checksum declaration matches do not prove original registry archive availability or source identity for Git entries.",
                "Submodule path occupancy is not a checked-out commit or recursive-source-completeness proof.",
                "License-named file presence or absence does not establish the grant/notice requirements of every third-party source.",
                "Bootstrap artifacts, system toolchain providers and actual offline build consumption were not executed or accepted.",
                "Four original PKGBUILD/BUILDINFO hash mismatches remain unresolved; binary/source and release acceptance remain held."],
            "offline_build_acceptance": "HELD", "license_completeness_or_legal_acceptance": "HELD",
            "network_requests": 0, "payload_or_native_execution": "NOT_RUN"}


def timeout(_signum, _frame):
    raise TimeoutError("metadata comparison deadline")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.output.resolve().is_relative_to(Path("/tmp")):
        parser.error("new output must be below /tmp")
    resource.setrlimit(resource.RLIMIT_AS, (128 * 1024**2, 128 * 1024**2))
    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(30)
    paths = [args.reports / (name + ".json") for name in ("rust", "llvm")]
    if any(p.is_symlink() or not p.is_file() for p in paths) or sum(p.stat().st_size for p in paths) > CAP:
        raise ValueError("reports must be regular bounded metadata files")
    reports = {name: json.loads(path.read_text()) for name, path in zip(("rust", "llvm"), paths)}
    parent = json.loads((HERE.parent / "source-inputs.json").read_text())
    result = analyze(reports, parent)
    result["source_report_pins"] = {p.name: {"bytes": p.stat().st_size,
        "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in paths}
    data = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode()
    if len(data) + sum(p.stat().st_size for p in args.reports.iterdir() if p.is_file()) > CAP:
        raise ValueError("combined retained metadata cap")
    with args.output.open("xb") as target:
        target.write(data)
    print(json.dumps({"output": str(args.output), "bytes": len(data),
                      "source_reports_complete": result["source_reports_complete"]}))


if __name__ == "__main__":
    main()
