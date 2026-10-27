#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Authenticate a finite tentative candidate archive set as data; never install.

v1 contract: coverage_report/transaction_report are {path,size,sha256} refs;
keys={alarm:ref,community:ref}; additional_python={database:ref,name,version}.
Exactly 150 missing coverage rows plus the explicit coordinated Python target.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


coverage = module("missing_coverage", HERE / "archive_coverage.py")
need, reference, regular = coverage.need, coverage.reference, coverage.regular
hash_file, identity, expected = coverage.hash_file, coverage.identity, coverage.expected
capture = module("missing_capture", HERE / "capture.py")
transaction = module("missing_transaction", HERE / "transaction.py")
process = module("missing_bounded_process", HERE.parent / "integration/lifecycle.py")
ROOT = HERE.parents[1]
MIB = 1024**2
EXPECTED_MISSING = 150
BYTE_LIMIT = 500 * MIB
JSON_LIMIT = 64 * MIB
EVIDENCE_LIMIT = 64 * MIB
SIGNATURE_LIMIT = 65536
RUN_SECONDS = 4 * 60 * 60
KEYS = {
    "alarm": (coverage.authenticate.SIGNER, "6ce771e853f04a38a5b533cb33e61f877b9b06b58b6db051eb8a15d737a2332f"),
    "community": (coverage.COMMUNITY_SIGNER, "bd5a05085bc9ec99bc17156e60f5c7f1cd29f2b550bb80f652e0ba4a4820d5b2"),
}


def bound_bytes(ref, maximum=32 * MIB):
    need(set(ref) == {"path", "size", "sha256"} and type(ref["size"]) is int
         and 0 < ref["size"] <= maximum and re.fullmatch(r"[a-f0-9]{64}", ref["sha256"]), "binary input reference refused")
    path = Path(ref["path"])
    need(regular(path).st_size == ref["size"], "binary input size mismatch")
    with path.open("rb") as source:
        data = source.read(ref["size"] + 1)
    need(len(data) == ref["size"] and hashlib.sha256(data).hexdigest() == ref["sha256"], "binary input hash mismatch")
    return data


def archive_spec(metadata, repo, scope):
    name, version, arch = identity(metadata)
    need(repo in {"core", "extra", "asahi-alarm"}, "candidate repository refused")
    for field in ("FILENAME", "SHA256SUM", "CSIZE"):
        need(type(metadata.get(field)) is list and len(metadata[field]) == 1
             and type(metadata[field][0]) is str, "complete exact archive pins required")
    filename = metadata["FILENAME"][0]
    versions = {version}
    if ":" in version:
        epoch = re.fullmatch(r"([0-9]+):([^:]+)", version)
        need(epoch is not None, "single decimal package epoch required")
        versions.add(epoch[2])
        if repo == "asahi-alarm":
            versions.add(epoch[1] + "." + epoch[2])
    need(filename in {f"{name}-{value}-{arch}.pkg.tar.xz" for value in versions},
         "exact xz archive filename required")
    need(re.fullmatch(r"[a-f0-9]{64}", metadata["SHA256SUM"][0]) and metadata["CSIZE"][0].isdigit(), "archive digest/size refused")
    size = int(metadata["CSIZE"][0])
    need(0 < size <= coverage.ARCHIVE_LIMIT, "archive size bound refused")
    url = (f"https://github.com/asahi-alarm/asahi-alarm/releases/download/aarch64/{filename}" if repo == "asahi-alarm"
           else f"https://ca.us.mirror.archlinuxarm.org/aarch64/{repo}/{filename}")
    signature_pin = None
    if metadata.get("PGPSIG"):
        need(len(metadata["PGPSIG"]) == 1, "duplicate embedded signature")
        signature = base64.b64decode(metadata["PGPSIG"][0], validate=True)
        need(0 < len(signature) <= SIGNATURE_LIMIT, "embedded signature bound refused")
        signature_pin = {"size": len(signature), "sha256": hashlib.sha256(signature).hexdigest()}
    return {"name": name, "version": version, "arch": arch, "repo": repo, "filename": filename,
            "size": size, "sha256": metadata["SHA256SUM"][0], "url": url,
            "metadata": metadata, "scope": scope, "key": "community" if repo == "asahi-alarm" else "alarm",
            "signature_pin": signature_pin}


def plan(contract):
    need(set(contract) == {"schema_version", "coverage_report", "transaction_report", "keys", "additional_python"}
         and type(contract["schema_version"]) is int and contract["schema_version"] == 1, "authentication contract refused")
    report, prepared = reference(contract["coverage_report"]), reference(contract["transaction_report"])
    need(report.get("kind") == "offline-candidate-retained-archive-coverage"
         and report.get("transaction_report") == contract["transaction_report"]
         and prepared.get("kind") == "private-Asahi-metadata-transaction-prepare"
         and report.get("transaction_status") == prepared.get("status")
         and all(report.get(field) is False for field in ("installation_accepted", "hardware_accepted", "source_grants_complete")),
         "coverage/actual transaction binding refused")
    candidates = prepared["proposed_final_inventory"]
    need(isinstance(candidates, list) and 0 < len(candidates) <= 4096, "finite actual inventory required")
    by_name = {item["name"]: item for item in candidates}
    need(len(by_name) == len(candidates), "duplicate actual package")
    rows = report["packages"]
    need(isinstance(rows, list) and len(rows) == len(candidates) and len({r["name"] for r in rows}) == len(rows), "complete unique coverage inventory required")
    missing = []
    for row in rows:
        item = by_name.get(row["name"])
        need(item and item["version"] == row["version"] and item["repo"] == row["repo"]
             and identity(item["metadata"]) == (row["name"], row["version"], row["arch"]), "coverage candidate identity mismatch")
        if row["status"] != "missing-exact-retained-authentication":
            continue
        spec = archive_spec(item["metadata"], item["repo"], "missing-exact-tentative-candidate")
        candidate = row["candidate_archive"]
        need(candidate == {"filename": spec["filename"], "sha256": spec["sha256"], "bytes": spec["size"],
                           "url": spec["url"], "signature_url": spec["url"] + ".sig", "network_availability": "NOT CHECKED"},
             "coverage exact archive binding mismatch")
        missing.append(spec)
    need(len(missing) == EXPECTED_MISSING, "exact missing archive count refused")
    additional = contract["additional_python"]
    need(set(additional) == {"database", "name", "version"} and additional["name"] == "python"
         and additional["version"] == "3.14.8-1", "explicit coordinated Python target required")
    records = transaction.repository_records(bound_bytes(additional["database"]))
    python = [record for record in records.values() if record.get("NAME") == [additional["name"]]
              and record.get("VERSION") == [additional["version"]]]
    need(len(python) == 1, "one exact Python record in source database required")
    python = archive_spec(python[0], "core", "additional-coordinated-python-target")
    need(python["arch"] == "aarch64", "coordinated Python architecture refused")
    need(python["filename"] not in {p["filename"] for p in missing}, "additional target duplicates missing scope")
    need(set(contract["keys"]) == set(KEYS), "exact public key set required")
    for label, (_, pin) in KEYS.items():
        need(contract["keys"][label]["sha256"] == pin, "public certificate source pin refused")
        bound_bytes(contract["keys"][label], MIB)
    packages = [python, *missing]
    need(len({p["filename"] for p in packages}) == len(packages), "duplicate planned archive")
    upper_bound = sum(p["size"] + SIGNATURE_LIMIT for p in packages)
    need(upper_bound <= BYTE_LIMIT, "aggregate archive/signature bound exceeded")
    return packages, upper_bound


def destination(path, budget):
    need(path.is_absolute() and ".." not in path.parts, "absolute canonical private output required")
    path = Path(os.path.abspath(path))
    path.relative_to(Path(os.path.abspath(ROOT / "artifacts/platform")))
    need(not any(p.is_symlink() for p in [path, *path.parents]) and not path.exists(), "output must be absent with no symlinks")
    # Aggregate immutable evidence, live+replacement receipts, and key scratch
    # have separate space allowances from the finite archive/signature budget.
    reserve = EVIDENCE_LIMIT + 2 * JSON_LIMIT + 256 * MIB
    parent_info = path.parent.lstat()
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(parent)
        need((info.st_dev, info.st_ino) == (parent_info.st_dev, parent_info.st_ino)
             and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
             "private owned output parent identity required")
        need(shutil.disk_usage(path.parent).free >= budget + reserve, "output parent/space reserve refused")
        current = path.parent.lstat()
        need((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino)
             and not any(p.is_symlink() for p in [path.parent, *path.parent.parents]), "output parent identity changed")
        os.mkdir(path.name, mode=0o700, dir_fd=parent)
        created = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            for name in ("cache", "keys", "observations"):
                os.mkdir(name, mode=0o700, dir_fd=created)
            info = os.fstat(created)
            current = path.lstat()
            need((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino), "created output identity changed")
        finally:
            os.close(created)
    finally:
        os.close(parent)
    return path


def download(url, target, maximum, expected=None, exact_size=None):
    parsed = urllib.parse.urlsplit(url)
    need(parsed.scheme == "https" and parsed.hostname in {"ca.us.mirror.archlinuxarm.org", "github.com"}
         and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment, "download source refused")
    temporary = target.with_name(target.name + ".partial")
    started, size, h = time.monotonic(), 0, hashlib.sha256()
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            final = urllib.parse.urlsplit(response.url)
            allowed = {"ca.us.mirror.archlinuxarm.org"} if parsed.hostname != "github.com" else {"github.com", "release-assets.githubusercontent.com"}
            need(response.status == 200 and final.scheme == "https" and final.hostname in allowed
                 and not final.username and not final.password, "download response/redirect refused")
            advertised = response.headers.get("Content-Length")
            need(not advertised or advertised.isdigit() and int(advertised) <= maximum, "advertised byte limit refused")
            with temporary.open("xb") as out:
                os.chmod(temporary, 0o600)
                while True:
                    need(time.monotonic() - started <= 600, "download deadline exceeded")
                    block = response.read1(min(MIB, maximum - size + 1))
                    if not block:
                        break
                    size += len(block)
                    need(size <= maximum, "download byte limit exceeded")
                    out.write(block); h.update(block)
            need(not advertised or size == int(advertised), "download advertised size mismatch")
        need(size > 0 and (exact_size is None or size == exact_size), "download exact size mismatch")
        need(expected is None or h.hexdigest() == expected, "download digest mismatch")
        temporary.rename(target)
        return {"path": str(target), "size": size, "sha256": h.hexdigest()}
    finally:
        temporary.unlink(missing_ok=True)


def save(path, document, *, replace=False, remaining=None):
    encoded = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    need(len(encoded) <= JSON_LIMIT, "serialized evidence bound exceeded")
    need(remaining is None or len(encoded) <= remaining, "aggregate evidence bound exceeded")
    target = path.with_name(path.name + ".new") if replace else path
    with target.open("xb") as out:
        os.chmod(target, 0o600); out.write(encoded)
    if replace:
        os.replace(target, path)
    return len(encoded)


def signature_status(data, signer):
    records = [line.split()[1:] for line in data.decode("ascii").splitlines() if line.startswith("[GNUPG:] ")]
    bad = {"BADSIG", "ERRSIG", "NO_PUBKEY", "EXPKEYSIG", "EXPSIG", "REVKEYSIG", "KEYEXPIRED", "SIGEXPIRED",
           "FAILURE", "ERROR", "NODATA", "BADARMOR"}
    need(not any(row and row[0] in bad for row in records), "bad signature status")
    valid = [row for row in records if row and row[0] == "VALIDSIG"]
    need(len(valid) == 1 and len(valid[0]) == 11 and valid[0][8] in {"8", "9", "10", "11"}
         and valid[0][-1] == signer, "signature primary/digest/status refused")
    return {"status": "cryptographic-signature-valid", "primary_fingerprint": signer,
            "independent_owner_trust_accepted": False, "fresh_verification": True}


class SignatureFailure(ValueError):
    def __init__(self, message, observation):
        super().__init__(message)
        self.observation = observation


def verify(directory, certificate, archive, signature, signer):
    with tempfile.TemporaryDirectory(prefix="public-gpg-", dir=directory) as scratch:
        home = Path(scratch)
        command = ["gpg", "--no-options", "--batch", "--homedir", str(home), "--no-auto-key-retrieve", "--no-autostart"]
        capture.bounded_command(command + ["--import", str(certificate)], timeout=60)
        exported, _ = capture.bounded_command(command + ["--export", signer], timeout=60, limit=MIB)
        need(exported, "pinned public key export missing")
        public = home / "public.gpg"
        public.write_bytes(exported); os.chmod(public, 0o600)
        outcome = process.bounded_process(["gpgv", "--homedir", str(home), "--keyring", str(public),
                                           "--status-fd", "1", str(signature), str(archive)], timeout=90,
                                          stdout_limit=MIB, stderr_limit=MIB,
                                          env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        observation = {"gpg_status": outcome["stdout"].decode("ascii", errors="backslashreplace"),
                       "diagnostic": outcome["stderr"].decode("utf-8", errors="backslashreplace").replace(str(home), "<public-scratch>"),
                       "exit": outcome["returncode"], "reason": outcome["reason"], "private_key_access": False,
                       "ownertrust_modified": False, "installed_keyring_access": False}
        try:
            need(outcome["reason"] == "exit" and outcome["returncode"] == 0, "signature verifier failed")
            result = signature_status(outcome["stdout"], signer)
        except (ValueError, UnicodeError) as error:
            raise SignatureFailure(str(error), observation) from error
        return result, observation


def pkginfo(path):
    with tarfile.open(path, "r|xz") as archive:
        for member in archive:
            if member.name.removeprefix("./") == ".PKGINFO":
                need(member.isfile() and member.size <= MIB, "PKGINFO bound refused")
                data = archive.extractfile(member).read(MIB + 1)
                need(len(data) == member.size, "PKGINFO size mismatch")
                return {"text": data.decode("utf-8"), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    raise ValueError("archive PKGINFO missing")


def failure(error):
    if isinstance(error, urllib.error.HTTPError):
        code = error.code
        error.close()
        return {"kind": "HTTPError", "code": code}
    # Retain useful refusals without ephemeral HTTPS redirect credentials.
    return {"kind": type(error).__name__, "diagnostic": re.sub(r"https?://\S+", "<source-url>", str(error))[:1500]}


def run(contract, output, contract_pin):
    packages, budget = plan(contract)
    output = destination(output, budget)
    public = {}
    for label in KEYS:
        path = output / "keys" / (label + ".gpg")
        path.write_bytes(bound_bytes(contract["keys"][label], MIB)); os.chmod(path, 0o600)
        public[label] = {"path": str(path), "size": path.stat().st_size, "sha256": hash_file(path)}
    receipt = {"schema_version": 1, "kind": "finite-missing-candidate-archive-authentication", "status": "IN_PROGRESS",
               "contract_sha256": contract_pin, "inputs": contract, "planned_count": len(packages),
               "missing_candidate_count": EXPECTED_MISSING, "additional_target_count": 1,
               "download_upper_bound_bytes": budget, "transaction_status": reference(contract["transaction_report"])["status"],
               "evidence_bytes": 0, "evidence_byte_limit": EVIDENCE_LIMIT,
               "full_receipt_byte_limit": JSON_LIMIT, "atomic_receipt_peak_byte_limit": 2 * JSON_LIMIT,
               "source_database_signature_authentication": "NOT ESTABLISHED for ALARM core/extra metadata",
               "system_mutation": False, "installation_accepted": False, "hardware_accepted": False,
               "source_grants_complete": False, "complete_baseline_archive_authentication": False,
               "independent_owner_trust_accepted": False, "packages": [], "failures": [],
               "source_sha256": {"authenticate_missing.py": hash_file(Path(__file__)), "capture.py": hash_file(Path(capture.__file__)),
                                 "archive_coverage.py": hash_file(Path(coverage.__file__)),
                                 "authenticate.py": hash_file(Path(coverage.authenticate.__file__)),
                                 "transaction.py": hash_file(Path(transaction.__file__)),
                                 "lifecycle.py": hash_file(Path(process.__file__))}}
    receipt_path = output / "authentication-receipt.json"
    save(receipt_path, receipt)
    started = time.monotonic()
    for package in packages:
        row = {"name": package["name"], "version": package["version"], "scope": package["scope"],
               "metadata": package["metadata"], "repo": package["repo"], "status": "FAIL"}
        try:
            need(time.monotonic() - started < RUN_SECONDS, "finite run deadline exceeded")
            path = output / "cache" / package["filename"]
            row["archive"] = download(package["url"], path, package["size"], package["sha256"], package["size"])
            pin = package["signature_pin"]
            sig = output / "cache" / (package["filename"] + ".sig")
            row["signature"] = download(package["url"] + ".sig", sig, SIGNATURE_LIMIT,
                                        pin["sha256"] if pin else None, pin["size"] if pin else None)
            row["signature_verification"], row["signature_observation"] = verify(
                output, Path(public[package["key"]]["path"]), path, sig, KEYS[package["key"]][0])
            inspection = coverage.authenticate.observe(path, expected(package["metadata"]))
            inspection_path = output / "observations" / (package["name"] + ".json")
            receipt["evidence_bytes"] += save(inspection_path, inspection,
                                               remaining=EVIDENCE_LIMIT - receipt["evidence_bytes"])
            row["inspection"] = {"path": str(inspection_path), "size": inspection_path.stat().st_size,
                                 "sha256": hash_file(inspection_path)}
            row["status"] = "PASS-authenticated-and-inspected-data"
            if package["scope"] == "additional-coordinated-python-target":
                text = pkginfo(path)
                need(coverage.authenticate.native.pkginfo(text["text"]) == inspection["metadata"], "Python PKGINFO inspection binding mismatch")
                python_receipt = {"schema_version": 1, "status": "signed-coordinated-python-candidate-data",
                                  "kind": "signed-coordinated-python-candidate-data", "scope": package["scope"],
                                  "name": package["name"], "version": package["version"], "metadata": package["metadata"],
                                  "archive": row["archive"], "signature": row["signature"],
                                  "public_certificate": public[package["key"]], "source_db": contract["additional_python"]["database"],
                                  "signature_verification": row["signature_verification"], "pkginfo": text,
                                  "inspection": row["inspection"], "system_mutation": False,
                                  "installation_accepted": False, "hardware_accepted": False, "source_grants_complete": False,
                                  "independent_owner_trust_accepted": False, "contract_sha256": contract_pin}
                receipt["evidence_bytes"] += save(output / "python-receipt.json", python_receipt,
                                                   remaining=EVIDENCE_LIMIT - receipt["evidence_bytes"])
                print(json.dumps({"python_receipt": str(output / "python-receipt.json"),
                                  "sha256": hash_file(output / "python-receipt.json"), "status": python_receipt["status"]}), flush=True)
        except Exception as error:
            row["status"] = "FAIL"
            if isinstance(error, SignatureFailure):
                row["signature_observation"] = error.observation
            row["failure"] = failure(error)
            receipt["failures"].append({"name": package["name"], "scope": package["scope"], **row["failure"]})
        receipt["packages"].append(row)
        receipt["verified_count"] = sum(p["status"] == "PASS-authenticated-and-inspected-data" for p in receipt["packages"])
        save(receipt_path, receipt, replace=True)
    receipt["status"] = "PASS-all-planned-archive-data-authenticated" if not receipt["failures"] else "FAIL-incomplete-archive-authentication"
    save(receipt_path, receipt, replace=True)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--contract-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    contract = reference({"path": str(args.contract.absolute()), "size": regular(args.contract.absolute()).st_size,
                          "sha256": args.contract_sha256})
    result = run(contract, args.output, args.contract_sha256)
    print(json.dumps({"status": result["status"], "verified_count": result["verified_count"], "planned_count": result["planned_count"]}), flush=True)
    return 0 if not result["failures"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
