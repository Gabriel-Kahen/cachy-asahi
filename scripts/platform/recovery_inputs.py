#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Retain and authenticate exact old recovery archives as data; never install.

Contract v1: image_inventory, old_availability and certificate {path,size,sha256}
references. Archive URLs require actual exact links in fixed operator listings.
Observed post-download hashes are not historical prepins or image payload proof.
"""
import argparse
import copy
from email.utils import parsedate_to_datetime
import hashlib
from html.parser import HTMLParser
import importlib.util
import json
import os
from pathlib import Path
import shutil
import time
import urllib.parse
import urllib.request
import urllib.error

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("recovery_authentication", HERE / "authenticate_missing.py")
auth = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auth)
need, reference, identity, expected = auth.need, auth.reference, auth.identity, auth.expected
ROOT = HERE.parents[1]
HOST = "pkgmirror.sametimetomorrow.net"
MIB = 1024**2
INDEX_LIMIT = MIB
ARCHIVE_LIMIT = 32 * MIB
SIGNATURE_LIMIT = 65536
CACHE_LIMIT = 128 * MIB
METADATA_LIMIT = 64 * MIB
RECEIPT_LIMIT = 64 * MIB
OLD_COUNT = 16
RUN_SECONDS = 2 * 60 * 60


def plan(contract):
    fields = {"schema_version", "image_inventory", "old_availability", "certificate"}
    need(set(contract) in (fields, fields | {"previous_receipt"})
         and type(contract["schema_version"]) is int and contract["schema_version"] == 1, "recovery contract refused")
    image, availability = reference(contract["image_inventory"]), reference(contract["old_availability"])
    need(image.get("kind") == "observed-image-local-package-metadata"
         and image.get("hardware_accepted") is False and image.get("dependency_transaction_accepted") is False,
         "observed image metadata required")
    need(availability.get("kind") == "protected-exact-version-current-catalog-availability"
         and availability.get("inputs", {}).get("image_inventory") == contract["image_inventory"]
         and availability.get("old_archive_url_or_hash_guessed") is False
         and availability.get("installation_accepted") is False and availability.get("hardware_accepted") is False,
         "availability/image binding refused")
    inventory = image["packages"]
    need(isinstance(inventory, list) and 0 < len(inventory) <= 4096, "finite image inventory required")
    by_name = {}
    for item in inventory:
        key = identity(item["metadata"])
        need(key[0] not in by_name, "duplicate image package")
        by_name[key[0]] = item["metadata"]
    packages, seen = [], set()
    rows = availability["packages"]
    need(isinstance(rows, list) and 0 < len(rows) <= 4096, "finite availability package set required")
    for row in rows:
        name = row["name"]
        need(name not in seen and type(row["current_catalog_exact_version"]) is bool, "duplicate or ambiguous availability row")
        seen.add(name)
        metadata = by_name.get(name)
        need(metadata and identity(metadata) == (name, row["protected_version"], row["arch"]), "availability exact image identity mismatch")
        if row["current_catalog_exact_version"]:
            continue
        name, version, arch = identity(metadata)
        filename = f"{name}-{version}-{arch}.pkg.tar.xz"
        packages.append({"name": name, "version": version, "arch": arch, "filename": filename, "metadata": metadata,
                         "index_url": f"https://{HOST}/aarch64/packages/{name[0]}/{name}/"})
    need(len(packages) == OLD_COUNT, "exact superseded recovery set required")
    certificate = contract["certificate"]
    need(certificate["sha256"] == auth.KEYS["alarm"][1], "pinned ALARM certificate required")
    auth.bound_bytes(certificate, MIB)
    if "previous_receipt" in contract:
        previous(contract, packages)
    return packages


def previous(contract, packages):
    prior = reference(contract["previous_receipt"])
    original = {key: value for key, value in contract.items() if key != "previous_receipt"}
    prior_inputs = {key: value for key, value in prior.get("inputs", {}).items() if key != "previous_receipt"}
    need(prior_inputs == original and prior.get("kind") == "exact-superseded-recovery-archive-data"
         and type(prior.get("schema_version")) is int and prior["schema_version"] == 1
         and prior.get("status") in {"FAIL-incomplete-recovery-archive-data", "PASS-all-exact-old-recovery-archive-data"}
         and all(prior.get(field) is False for field in ("system_mutation", "installation_accepted", "hardware_accepted",
                                                         "image_payload_correspondence_accepted", "independent_owner_trust_accepted")),
         "previous recovery input/classification binding refused")
    rows = prior.get("packages")
    need(isinstance(rows, list) and len(rows) == len(packages), "whole previous recovery set required")
    wanted = {p["name"]: p for p in packages}
    seen = set()
    cache_bytes, metadata_bytes, completed = 0, 0, 0
    for row in rows:
        package = wanted.get(row["name"])
        need(package and row["name"] not in seen and row["version"] == package["version"]
             and row["arch"] == package["arch"] and row["observed_image_metadata"] == package["metadata"],
             "previous recovery package/image identity mismatch")
        need(row.get("status") in {"FAIL", "PASS-signed-old-archive-data-matches-image-metadata"}, "previous row classification refused")
        if row["status"] != "FAIL":
            completed += 1
            for field, limit in (("archive", ARCHIVE_LIMIT), ("signature", SIGNATURE_LIMIT),
                                 ("operator_index", INDEX_LIMIT), ("inspection", METADATA_LIMIT)):
                size = row[field]["size"]
                need(type(size) is int and 0 < size <= limit, "previous retained size bound refused")
            cache_bytes += row["archive"]["size"] + row["signature"]["size"]
            metadata_bytes += row["operator_index"]["size"] + row["inspection"]["size"]
        seen.add(row["name"])
    need(type(prior.get("verified_count")) is int and prior["verified_count"] == completed
         and type(prior.get("planned_count")) is int and prior["planned_count"] == len(packages), "previous completion count refused")
    need(cache_bytes <= CACHE_LIMIT and metadata_bytes <= METADATA_LIMIT, "aggregate previous retained quota exceeded")
    return prior


def ref_only(value):
    return {key: value[key] for key in ("path", "size", "sha256")}


def reuse(row, package, receipt, previous_ref):
    """Rehash prior data and reinspect metadata; preserve prior signature evidence."""
    index = auth.bound_bytes(ref_only(row["operator_index"]), INDEX_LIMIT)
    need(row["index_url"] == package["index_url"], "previous operator index origin mismatch")
    links = exact_links(index, package["index_url"], package["filename"])
    need(links == row["actual_index_links"], "previous actual index link binding mismatch")
    for field, limit in (("archive", ARCHIVE_LIMIT), ("signature", SIGNATURE_LIMIT)):
        need(row[field]["url"] == links[field], "previous archive link mismatch")
        auth.bound_bytes(ref_only(row[field]), limit)
    verification = row["signature_verification"]
    need(verification.get("status") == "cryptographic-signature-valid"
         and verification.get("primary_fingerprint") == auth.KEYS["alarm"][0]
         and verification.get("independent_owner_trust_accepted") is False, "previous signature claim refused")
    observation = row["signature_observation"]
    need(observation.get("exit") == 0 and observation.get("reason", "exit") == "exit", "previous signature exit refused")
    auth.signature_status(observation["gpg_status"].encode("ascii"), auth.KEYS["alarm"][0])
    old_inspection = reference(ref_only(row["inspection"]))
    actual = auth.coverage.authenticate.observe(Path(row["archive"]["path"]), expected(package["metadata"]))
    need(actual == old_inspection, "previous archive inspection binding mismatch")
    cache_bytes = row["archive"]["size"] + row["signature"]["size"]
    metadata_bytes = row["operator_index"]["size"] + row["inspection"]["size"]
    need(receipt["cache_bytes"] + cache_bytes <= CACHE_LIMIT
         and receipt["metadata_bytes"] + metadata_bytes <= METADATA_LIMIT, "aggregate retained recovery quota exceeded")
    receipt["cache_bytes"] += cache_bytes
    receipt["metadata_bytes"] += metadata_bytes
    receipt["external_retained_cache_bytes"] += cache_bytes
    receipt["external_retained_metadata_bytes"] += metadata_bytes
    result = copy.deepcopy(row)
    result["signature_verification"]["fresh_verification"] = False
    result["fresh_signature_verification_this_run"] = False
    result["retained_signature_verification_receipt"] = previous_ref
    result["prior_data_rehashed_and_metadata_reinspected"] = True
    return result


class Requests:
    """One-second spacing, at most two bounded retries for each HTTP 429."""
    def __init__(self, deadline):
        self.deadline, self.last_request, self.cooldown_until = deadline, None, 0

    def open(self, url, attempts):
        for attempt in range(3):
            now = time.monotonic()
            earliest = max(self.cooldown_until, (self.last_request + 1) if self.last_request is not None else now)
            wait = max(0, earliest - now)
            need(now + wait < self.deadline, "request pacing deadline exceeded")
            if wait:
                time.sleep(wait)
            self.last_request = time.monotonic()
            entry = {"url": url, "attempt": attempt + 1, "pace_wait_seconds": wait}
            attempts.append(entry)
            try:
                response = urllib.request.urlopen(url, timeout=30)
                entry["status"] = response.status
                return response
            except urllib.error.HTTPError as error:
                entry["status"] = error.code
                if error.code != 429:
                    raise
                header = error.headers.get("Retry-After", "") if error.headers else ""
                delay = retry_after(header)
                entry["retry_after_seconds"] = delay
                self.cooldown_until = time.monotonic() + delay
                if attempt == 2:
                    raise
                error.close()
        raise ValueError("request retry bound exceeded")


def retry_after(header):
    try:
        value = int(header) if header.isdigit() else parsedate_to_datetime(header).timestamp() - time.time()
    except (ValueError, TypeError, OverflowError):
        value = 30
    return min(60, max(1, value))


class Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []

    def handle_starttag(self, tag, attributes):
        if tag.lower() != "a":
            return
        hrefs = [value for key, value in attributes if key.lower() == "href"]
        need(len(hrefs) <= 1, "ambiguous duplicate anchor href")
        if hrefs and hrefs[0] is not None:
            need(len(hrefs[0]) <= 4096 and len(self.links) < 50000, "HTML link inventory bound exceeded")
            self.links.append(hrefs[0])


def exact_links(data, index_url, filename):
    need(len(data) <= INDEX_LIMIT, "operator index byte limit exceeded")
    parsed_index = urllib.parse.urlsplit(index_url)
    need(parsed_index.scheme == "https" and parsed_index.netloc == HOST
         and not parsed_index.query and not parsed_index.fragment, "operator index origin refused")
    need(auth.coverage.authenticate.native.input_name(filename) == filename and filename.endswith(".pkg.tar.xz"), "exact filename refused")
    parser = Links()
    parser.feed(data.decode("utf-8")); parser.close()
    selected = {filename: set(), filename + ".sig": set()}
    for href in parser.links:
        direct = urllib.parse.urlsplit(href)
        if (direct.scheme not in {"", "https"} or direct.netloc not in {"", HOST}
                or direct.query or direct.fragment or direct.username or direct.password
                or ".." in urllib.parse.unquote(direct.path).split("/")):
            continue
        url = urllib.parse.urljoin(index_url, href)
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc != HOST:
            continue
        path = urllib.parse.unquote(parsed.path)
        for wanted in selected:
            if path == parsed_index.path + wanted:
                selected[wanted].add(url)
    need(all(len(urls) == 1 for urls in selected.values()), "one actual exact archive and signature link required")
    return {"archive": next(iter(selected[filename])), "signature": next(iter(selected[filename + ".sig"]))}


def fetch(url, target, maximum, *, requests=None, attempts=None):
    origin = urllib.parse.urlsplit(url)
    need(origin.scheme == "https" and origin.netloc == HOST and not origin.query and not origin.fragment
         and not origin.username and not origin.password and maximum > 0, "fixed operator HTTPS request required")
    temporary = target.with_name(target.name + ".partial")
    size, h, started = 0, hashlib.sha256(), time.monotonic()
    if attempts is None:
        attempts = []
    try:
        with (requests.open(url, attempts) if requests is not None else urllib.request.urlopen(url, timeout=30)) as response:
            final = urllib.parse.urlsplit(response.url)
            need(response.status == 200 and final.scheme == "https" and final.netloc == HOST
                 and not final.query and not final.fragment and not final.username and not final.password,
                 "operator HTTPS redirect/response refused")
            advertised = response.headers.get("Content-Length")
            need(not advertised or advertised.isdigit() and int(advertised) <= maximum, "operator advertised byte bound exceeded")
            with temporary.open("xb") as out:
                os.chmod(temporary, 0o600)
                while True:
                    need(time.monotonic() - started <= 600, "operator download deadline exceeded")
                    block = response.read1(min(MIB, maximum - size + 1))
                    if not block:
                        break
                    size += len(block)
                    need(size <= maximum, "operator observed byte bound exceeded")
                    out.write(block); h.update(block)
            need(size > 0 and (not advertised or size == int(advertised)), "operator source size mismatch")
        temporary.rename(target)
        return {"path": str(target), "size": size, "sha256": h.hexdigest(), "url": url,
                "predeclared_sha256": None, "hash_provenance": "observed-post-download-only"}
    finally:
        temporary.unlink(missing_ok=True)


def save(path, document, *, replace=False, remaining=None):
    encoded = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    need(len(encoded) <= RECEIPT_LIMIT and (remaining is None or len(encoded) <= remaining), "recovery serialized metadata quota exceeded")
    temporary = path.with_name(path.name + ".new") if replace else path
    with temporary.open("xb") as out:
        os.chmod(temporary, 0o600); out.write(encoded)
    if replace:
        os.replace(temporary, path)
    return len(encoded)


def destination(output):
    need(output.is_absolute() and ".." not in output.parts, "absolute canonical private recovery output required")
    output.relative_to(ROOT / "artifacts/platform")
    need(not output.exists() and not any(path.is_symlink() for path in [output, *output.parents]), "absent nonsymlink recovery output required")
    reserve = CACHE_LIMIT + METADATA_LIMIT + 2 * RECEIPT_LIMIT + 256 * MIB
    need(output.parent.is_dir() and shutil.disk_usage(output.parent).free >= reserve, "recovery output parent/space reserve refused")
    output.mkdir(mode=0o700)
    for name in ("indexes", "cache", "observations", "keys"):
        (output / name).mkdir(mode=0o700)
    return output


def run(contract, output, contract_pin):
    packages = plan(contract)
    output = destination(output)
    certificate = output / "keys/archlinuxarm.gpg"
    certificate.write_bytes(auth.bound_bytes(contract["certificate"], MIB)); os.chmod(certificate, 0o600)
    receipt = {"schema_version": 1, "kind": "exact-superseded-recovery-archive-data", "status": "IN_PROGRESS",
               "inputs": contract, "contract_sha256": contract_pin, "planned_count": len(packages), "verified_count": 0,
               "cache_bytes": 0, "metadata_bytes": 0, "external_retained_cache_bytes": 0, "external_retained_metadata_bytes": 0,
               "cache_byte_limit": CACHE_LIMIT, "metadata_byte_limit": METADATA_LIMIT,
               "receipt_byte_limit": RECEIPT_LIMIT, "atomic_receipt_peak_byte_limit": 2 * RECEIPT_LIMIT,
               "system_mutation": False, "installation_accepted": False, "hardware_accepted": False,
               "image_payload_correspondence_accepted": False, "independent_owner_trust_accepted": False,
               "source_distribution": False, "source_grants_complete": False, "complete_baseline_archive_authentication": False,
               "old_archive_prehashes_known": False, "packages": [], "failures": [],
               "source_sha256": {"recovery_inputs.py": auth.hash_file(Path(__file__)),
                                 "authenticate_missing.py": auth.hash_file(Path(auth.__file__)),
                                 "archive_inspector.py": auth.hash_file(Path(auth.coverage.authenticate.__file__))}}
    receipt_path = output / "recovery-receipt.json"
    prior = previous(contract, packages) if "previous_receipt" in contract else None
    prior_rows = {row["name"]: row for row in prior["packages"]} if prior else {}
    if prior:
        receipt["previous_receipt"] = contract["previous_receipt"]
        receipt["previous_failures"] = prior["failures"]
    save(receipt_path, receipt)
    started = time.monotonic()
    requests = Requests(started + RUN_SECONDS)
    for package in packages:
        row = {"name": package["name"], "version": package["version"], "arch": package["arch"], "status": "FAIL",
               "observed_image_metadata": package["metadata"], "index_url": package["index_url"],
               "old_archive_prehash_known": False, "image_payload_correspondence_accepted": False, "http_attempts": []}
        try:
            need(time.monotonic() - started < RUN_SECONDS, "finite recovery run deadline exceeded")
            prior_row = prior_rows.get(package["name"])
            if prior_row and prior_row["status"] == "PASS-signed-old-archive-data-matches-image-metadata":
                row = reuse(prior_row, package, receipt, contract["previous_receipt"])
                row["http_attempts_this_run"] = []
                receipt["packages"].append(row)
                receipt["verified_count"] = sum(p["status"] == "PASS-signed-old-archive-data-matches-image-metadata" for p in receipt["packages"])
                save(receipt_path, receipt, replace=True)
                continue
            if prior_row:
                row["previous_failure"] = prior_row.get("failure")
            index_path = output / "indexes" / (package["name"] + ".html")
            maximum = min(INDEX_LIMIT, METADATA_LIMIT - receipt["metadata_bytes"])
            need(maximum > 0, "aggregate recovery metadata exhausted")
            row["operator_index"] = fetch(package["index_url"], index_path, maximum, requests=requests, attempts=row["http_attempts"])
            receipt["metadata_bytes"] += row["operator_index"]["size"]
            links = exact_links(index_path.read_bytes(), package["index_url"], package["filename"])
            row["actual_index_links"] = links
            for key, filename, limit in (("archive", package["filename"], ARCHIVE_LIMIT),
                                          ("signature", package["filename"] + ".sig", SIGNATURE_LIMIT)):
                maximum = min(limit, CACHE_LIMIT - receipt["cache_bytes"])
                need(maximum > 0, "aggregate recovery cache exhausted")
                row[key] = fetch(links[key], output / "cache" / filename, maximum, requests=requests, attempts=row["http_attempts"])
                receipt["cache_bytes"] += row[key]["size"]
            row["signature_verification"], row["signature_observation"] = auth.verify(
                output, certificate, Path(row["archive"]["path"]), Path(row["signature"]["path"]), auth.KEYS["alarm"][0])
            inspection = auth.coverage.authenticate.observe(Path(row["archive"]["path"]), expected(package["metadata"]))
            path = output / "observations" / (package["name"] + ".json")
            receipt["metadata_bytes"] += save(path, inspection, remaining=METADATA_LIMIT - receipt["metadata_bytes"])
            row["inspection"] = {"path": str(path), "size": path.stat().st_size, "sha256": auth.hash_file(path)}
            row["status"] = "PASS-signed-old-archive-data-matches-image-metadata"
            row["fresh_signature_verification_this_run"] = True
        except Exception as error:
            if isinstance(error, auth.SignatureFailure):
                row["signature_observation"] = error.observation
            row["failure"] = auth.failure(error)
            receipt["failures"].append({"name": package["name"], "version": package["version"], **row["failure"]})
        receipt["packages"].append(row)
        receipt["verified_count"] = sum(p["status"] == "PASS-signed-old-archive-data-matches-image-metadata" for p in receipt["packages"])
        save(receipt_path, receipt, replace=True)
    receipt["status"] = "PASS-all-exact-old-recovery-archive-data" if not receipt["failures"] else "FAIL-incomplete-recovery-archive-data"
    save(receipt_path, receipt, replace=True)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--contract-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    path = args.contract.absolute()
    contract = reference({"path": str(path), "size": auth.regular(path).st_size, "sha256": args.contract_sha256})
    receipt = run(contract, args.output, args.contract_sha256)
    print(json.dumps({"status": receipt["status"], "verified_count": receipt["verified_count"], "planned_count": receipt["planned_count"]}))
    return 0 if not receipt["failures"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
