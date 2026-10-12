#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline candidate/archive correspondence; never download, install or execute payloads.

Contract v1: transaction_report={path,size,sha256}; sources=[{kind:'generic',
lock:{path,size,sha256},receipt:{path,size,sha256},cache:absolute_directory},
{kind:'community',receipt:{path,size,sha256},cache:absolute_directory}].
Receipt signature observations are retained evidence, not fresh verification or
independent key-owner authentication. A failed transaction remains tentative.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
JSON_LIMIT = 32 * 1024**2
ARCHIVE_LIMIT = 300_000_000
TOTAL_LIMIT = 1024**3
COMMUNITY_SIGNER = "12CE6799A94A3F1B5DDFFE88F576553597FB8FEB"


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


sys.path.insert(0, str(HERE.parent / "port"))
authenticate = module("coverage_authenticate", HERE.parent / "port/authenticate.py")


def need(condition, message):
    if not condition:
        raise ValueError(message)


def pairs(items):
    result = {}
    for name, value in items:
        need(name not in result, "duplicate JSON key")
        result[name] = value
    return result


def load(data):
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite JSON")))


def regular(path):
    need(path.is_absolute(), "absolute path required")
    need(not any(p.is_symlink() for p in [path, *path.parents]), "symlink path refused")
    info = path.stat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "single-link regular file required")
    return info


def hash_file(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024**2), b""):
            h.update(block)
    return h.hexdigest()


def reference(row):
    need(set(row) == {"path", "size", "sha256"}, "reference fields refused")
    path = Path(row["path"])
    need(type(row["size"]) is int and 0 < row["size"] <= JSON_LIMIT,
         "reference size bound refused")
    need(isinstance(row["sha256"], str) and re.fullmatch(r"[a-f0-9]{64}", row["sha256"]), "reference digest refused")
    need(regular(path).st_size == row["size"], "reference size mismatch")
    with path.open("rb") as stream:
        data = stream.read(row["size"] + 1)
    need(len(data) == row["size"] and hashlib.sha256(data).hexdigest() == row["sha256"], "reference hash mismatch")
    return load(data)


def identity(metadata):
    for key in ("NAME", "VERSION", "ARCH"):
        need(isinstance(metadata.get(key), list) and len(metadata[key]) == 1
             and isinstance(metadata[key][0], str), "metadata identity refused")
    name, version, arch = (metadata[key][0] for key in ("NAME", "VERSION", "ARCH"))
    need(re.fullmatch(r"[A-Za-z0-9@._+:-]+", name) and re.fullmatch(r"[A-Za-z0-9@._+:-]+", version)
         and arch in {"aarch64", "any"}, "unsafe package identity")
    return name, version, arch


def expected(metadata):
    name, version, arch = identity(metadata)
    row = {"name": name, "version": version, "arch": arch}
    for key, field in (("depends", "DEPENDS"), ("provides", "PROVIDES"),
                       ("conflicts", "CONFLICTS"), ("replaces", "REPLACES"), ("license", "LICENSE")):
        value = metadata.get(field, [])
        need(isinstance(value, list) and len(value) <= 256 and all(isinstance(x, str) for x in value), "metadata values refused")
        row[key] = value
    return row


def archive_record(metadata, archive, signature, source, cache):
    name, version, arch = identity(metadata)
    filename = metadata["FILENAME"][0]
    need(filename in {f"{name}-{version}-{arch}.pkg.tar.xz", f"{name}-{version}-{arch}.pkg.tar.zst"}, "archive filename identity mismatch")
    for record in (archive, signature):
        need(type(record["bytes"]) is int and 0 < record["bytes"] <= ARCHIVE_LIMIT
             and isinstance(record["sha256"], str) and re.fullmatch(r"[a-f0-9]{64}", record["sha256"]), "archive pin/size refused")
    need(signature["bytes"] <= 65536 and archive["sha256"] == metadata["SHA256SUM"][0]
         and archive["bytes"] == int(metadata["CSIZE"][0]), "archive metadata binding mismatch")
    return {"metadata": metadata, "filename": filename, "archive": archive, "signature": signature,
            "source": source, "cache": cache}


def source_records(source, index):
    kind = source.get("kind")
    need(kind in {"generic", "community"} and set(source) == ({"kind", "lock", "receipt", "cache"} if kind == "generic"
                                                               else {"kind", "receipt", "cache"}), "source contract refused")
    cache = Path(source["cache"])
    need(cache.is_absolute() and not any(p.is_symlink() for p in [cache, *cache.parents]), "unsafe cache path")
    receipt = reference(source["receipt"])
    packages = receipt.get("packages")
    need(isinstance(packages, list) and len(packages) <= 4096, "finite receipt package set required")
    records = []
    if kind == "generic":
        lock = reference(source["lock"])
        need(receipt.get("status") == "PASS-233-authenticated-generic-archives"
             and receipt.get("archive_lock_sha256") == source["lock"]["sha256"]
             and receipt.get("signer_fingerprint") == lock.get("signer_fingerprint") == authenticate.SIGNER,
             "generic receipt/lock authentication binding refused")
        need(lock.get("scope") == receipt.get("scope") == "GENERIC-desktop-data-authentication", "generic evidence scope refused")
        by_name = {p["name"]: p for p in packages}
        need(len(by_name) == len(packages), "duplicate receipt package")
        need(isinstance(lock.get("packages"), list) and len(lock["packages"]) <= 4096, "finite lock required")
        for item in lock["packages"]:
            match = by_name.get(item["name"])
            if not match or match.get("status") != "PASS-authenticated-data":
                continue
            need(match["version"] == item["version"] and match["archive_sha256"] == item["sha256"]
                 and match["signature_sha256"] == item["signature_sha256"], "generic individual receipt binding mismatch")
            authenticate.status(SimpleNamespace(returncode=match["gpg"]["exit"], stdout=match["gpg"]["status"]))
            metadata = {"NAME": [item["name"]], "VERSION": [item["version"]], "ARCH": [item["arch"]],
                        "FILENAME": [item["filename"]], "SHA256SUM": [item["sha256"]], "CSIZE": [str(item["size"])]}
            for key, field in (("depends", "DEPENDS"), ("provides", "PROVIDES"), ("conflicts", "CONFLICTS"),
                               ("replaces", "REPLACES"), ("license", "LICENSE")):
                metadata[field] = item[key]
            records.append((metadata, {"bytes": item["size"], "sha256": item["sha256"]},
                            {"bytes": item["signature_size"], "sha256": item["signature_sha256"]}))
    else:
        need(receipt.get("status") in {"signed-platform-archives-retained-not-installation-accepted",
                                        "signed-audio-extension-data-captured-not-installed"}, "community capture incomplete")
        need(all(receipt.get(k) is False for k in ("installation_accepted", "hardware_accepted"))
             and ("system_mutation" not in receipt or receipt["system_mutation"] is False), "community acceptance claim refused")
        for item in packages:
            verification = item.get("verification", item.get("signature_verification", {}))
            if verification.get("status") != "cryptographic-signature-valid":
                continue
            need(verification.get("primary_fingerprint") == COMMUNITY_SIGNER
                 and verification.get("independent_owner_trust_accepted") is False, "community signer/trust refused")
            records.append((item["metadata"], item["archive"], item["signature"]))
    seen = set()
    for metadata, archive, signature in records:
        key = identity(metadata)
        need(key not in seen, "duplicate source archive identity")
        seen.add(key)
        index.setdefault(key, []).append(archive_record(metadata, archive, signature,
                                                        {"kind": kind, "receipt_sha256": source["receipt"]["sha256"]}, cache))


def inspect_candidate(item, records):
    metadata = item["metadata"]
    key = identity(metadata)
    need(item["name"] == key[0] and item["version"] == key[1], "transaction identity mismatch")
    result = {"name": key[0], "version": key[1], "arch": key[2], "repo": item["repo"],
              "installation_accepted": False, "hardware_accepted": False, "source_grants_complete": False,
              "image_payload_correspondence_accepted": False,
              "candidate_metadata": expected(metadata)}
    pinned = all(len(metadata.get(field, [])) == 1 for field in ("FILENAME", "SHA256SUM", "CSIZE"))
    if pinned:
        filename = metadata["FILENAME"][0]
        need(filename in {f"{key[0]}-{key[1]}-{key[2]}.pkg.tar.xz", f"{key[0]}-{key[1]}-{key[2]}.pkg.tar.zst"}
             and re.fullmatch(r"[a-f0-9]{64}", metadata["SHA256SUM"][0])
             and metadata["CSIZE"][0].isdigit() and 0 < int(metadata["CSIZE"][0]) <= ARCHIVE_LIMIT,
             "candidate archive identity/pins refused")
        repo = item["repo"]
        url = (f"https://ca.us.mirror.archlinuxarm.org/aarch64/{repo}/{filename}" if repo in {"core", "extra"}
               else f"https://github.com/asahi-alarm/asahi-alarm/releases/download/aarch64/{filename}" if repo == "asahi-alarm" else None)
        result["candidate_archive"] = {"filename": filename, "sha256": metadata["SHA256SUM"][0],
                                       "bytes": int(metadata["CSIZE"][0]), "url": url,
                                       "signature_url": url + ".sig" if url else None,
                                       "network_availability": "NOT CHECKED"}
    matches = records.get(key, [])
    if pinned:
        matches = [r for r in matches if r["filename"] == metadata["FILENAME"][0]
                   and r["archive"]["sha256"] == metadata["SHA256SUM"][0]
                   and str(r["archive"]["bytes"]) == metadata["CSIZE"][0]]
    result["archive_identity_scope"] = "candidate-metadata-exact-pins" if pinned else "same-name-version-arch-only-image-payload-unverified"
    if not matches:
        result["status"] = "missing-exact-retained-authentication" if pinned else "baseline-archive-identity-unavailable"
        result["candidate_filename"] = metadata.get("FILENAME", [None])[0]
        result["other_retained_identities"] = [{"version": candidate[1], "arch": candidate[2],
                                                 "filename": row["filename"], "sha256": row["archive"]["sha256"]}
                                                for candidate, rows in records.items() if candidate[0] == key[0]
                                                for row in rows]
        return result
    failures = []
    for record in matches:
        filename = record["filename"]
        archive, signature = record["cache"] / filename, record["cache"] / (filename + ".sig")
        try:
            for path, pin in ((archive, record["archive"]), (signature, record["signature"])):
                need(regular(path).st_size == pin["bytes"] and hash_file(path) == pin["sha256"], "cache archive/signature byte mismatch")
            result.update({"filename": filename, "archive_sha256": record["archive"]["sha256"],
                           "archive_bytes": record["archive"]["bytes"], "signature_sha256": record["signature"]["sha256"],
                           "retained_authentication": record["source"], "cache_bytes_rehashed": True,
                           "fresh_signature_verification": False, "independent_owner_trust_accepted": False})
            need(filename.endswith(".xz"), "retained codec inspection unsupported; no payload execution")
            result["inspection"] = authenticate.observe(archive, expected(metadata))
            result["status"] = "retained-authenticated-exact-archive-inspected" if pinned else "retained-authenticated-same-identity-image-payload-unverified"
            return result
        except (ValueError, OSError, KeyError) as error:
            failures.append({"receipt_sha256": record["source"]["receipt_sha256"], "error": type(error).__name__ + ": " + str(error)})
    result["status"] = "retained-authentication-cache-or-inspection-failed"
    result["failures"] = failures
    return result


def finite_matches(records):
    """Each cache/archive/signature binding is attempted at most once per identity."""
    result = {}
    for identity_, matches in records.items():
        distinct = {}
        for row in matches:
            key = (str(row["cache"]), row["filename"], row["archive"]["sha256"], row["archive"]["bytes"],
                   row["signature"]["sha256"], row["signature"]["bytes"])
            distinct.setdefault(key, row)
        result[identity_] = list(distinct.values())
    return result


def run(contract):
    need(set(contract) == {"schema_version", "transaction_report", "sources"}
         and type(contract["schema_version"]) is int and contract["schema_version"] == 1, "coverage contract refused")
    sources = contract["sources"]
    need(isinstance(sources, list) and 1 <= len(sources) <= 8, "finite cache source set required")
    transaction = reference(contract["transaction_report"])
    need(type(transaction.get("schema_version")) is int and transaction["schema_version"] == 1
         and transaction.get("kind") == "private-Asahi-metadata-transaction-prepare"
         and transaction.get("status") in {"PASS-private-metadata-prepare", "FAIL-incomplete-or-policy-rejected"}, "actual transaction report required")
    candidates = transaction["proposed_final_inventory"]
    need(isinstance(candidates, list) and 1 <= len(candidates) <= 4096, "finite candidate inventory required")
    records = {}
    for source in sources:
        source_records(source, records)
    records = finite_matches(records)
    # Bound rehash/inspection work independently of generic receipt population.
    identities = [identity(item["metadata"]) for item in candidates]
    need(len(set(identities)) == len(identities) and len({key[0] for key in identities}) == len(identities), "duplicate candidate package")
    # Every remaining fallback can be rehashed after earlier failures. Bound the
    # sum, not the largest match, before any archive/signature bytes are read.
    total = sum(r["archive"]["bytes"] + r["signature"]["bytes"]
                for key in identities for r in records.get(key, []))
    need(total <= TOTAL_LIMIT, "candidate retained-byte work budget exceeded")
    rows = [inspect_candidate(item, records) for item in candidates]
    counts = {status: sum(row["status"] == status for row in rows) for status in sorted({r["status"] for r in rows})}
    return {"schema_version": 1, "kind": "offline-candidate-retained-archive-coverage", "transaction_report": contract["transaction_report"],
            "sources": sources, "source_sha256": {"archive_coverage.py": hash_file(Path(__file__)),
                                                    "authenticate.py": hash_file(Path(authenticate.__file__)),
                                                    "native_arm.py": hash_file(Path(authenticate.native.__file__)),
                                                    "preview.py": hash_file(Path(authenticate.preview.__file__))},
            "transaction_status": transaction["status"],
            "candidate_inventory_tentative": transaction["status"].startswith("FAIL"), "candidate_count": len(rows),
            "retained_rehash_upper_bound_bytes": total, "retained_rehash_byte_limit": TOTAL_LIMIT,
            "counts": counts, "packages": rows, "system_mutation": False, "installation_accepted": False,
            "hardware_accepted": False, "source_grants_complete": False, "complete_baseline_archive_authentication": False,
            "fresh_signature_verification": False,
            "limits": ["Receipt hash pins preserve prior signature observations; no fresh cryptographic verification.",
                       "Generic receipt contributes only individually matched archives, never acceptance of this transaction.",
                       "Same image metadata identity cannot prove installed payload or complete corresponding source."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--contract-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    contract = reference({"path": str(args.contract.absolute()), "size": regular(args.contract.absolute()).st_size,
                          "sha256": args.contract_sha256})
    report = run(contract)
    encoded = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode()
    need(len(encoded) <= JSON_LIMIT, "coverage output budget exceeded")
    output = args.output.absolute()
    need(not any(path.is_symlink() for path in [output, *output.parents]), "output symlink refused")
    with output.open("xb") as target:
        os.chmod(output, 0o600)
        target.write(encoded)
    print(json.dumps({"output": str(output), "counts": report["counts"], "transaction_status": report["transaction_status"]}))
    return 1 if report["candidate_inventory_tentative"] or any(not p["status"].startswith("retained-authenticated") for p in report["packages"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
