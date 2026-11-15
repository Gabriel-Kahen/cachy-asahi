#!/usr/bin/env python3
"""Offline source-signature successor. Read compressed bytes; never unpack them."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
BAD_STATUS = {
    "BADSIG", "ERRSIG", "NO_PUBKEY", "EXPSIG", "EXPKEYSIG", "REVKEYSIG",
    "KEYREVOKED", "KEYEXPIRED", "SIGEXPIRED", "NODATA", "FAILURE", "ERROR",
}


def describe(path, expected_bytes=None):
    digest = hashlib.sha256()
    size = 0
    # O_NONBLOCK avoids hanging on a FIFO before fstat can reject it.
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        raise ValueError(f"cannot safely open input: {path.name}") from error
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        limit = expected_bytes if expected_bytes is not None else 8 * 1024**2
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError(f"nonregular or oversized input: {path.name}")
        if expected_bytes is not None and info.st_size != expected_bytes:
            raise ValueError(f"byte size mismatch: {path.name}")
        while block := source.read(min(1024 * 1024, limit + 1 - size)):
            digest.update(block)
            size += len(block)
            if size > limit:
                raise ValueError(f"input grew beyond byte limit: {path.name}")
    return {"bytes": size, "sha256": digest.hexdigest()}


def check_pin(path, expected):
    actual = describe(path, expected["bytes"])
    if any(actual[key] != expected[key] for key in actual):
        raise ValueError(f"byte pin mismatch: {path.name}")
    return actual


def accepted_signature(returncode, status, allowed):
    rows = [line.removeprefix("[GNUPG:] ").split() for line in status.splitlines()
            if line.startswith("[GNUPG:] ")]
    valid = [row for row in rows if row and row[0] == "VALIDSIG"]
    if (returncode or any(row and row[0] in BAD_STATUS for row in rows)
            or len(valid) != 1 or len(valid[0]) != 11
            or valid[0][-1] not in allowed):
        raise ValueError("detached signature rejected: status, count, or primary fingerprint")
    return {"signing_fingerprint": valid[0][1],
            "primary_fingerprint": valid[0][-1], "signature_date": valid[0][2]}


def run(command, data=None):
    # Explicit private homedir and no-options isolate public-key data processing.
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"}
    return subprocess.run(command, input=data, capture_output=True, timeout=30, env=env)


def check_archive_binding(spec, parent):
    original = parent["archives"].get(spec["archive"])
    if (original is None or spec["bytes"] != original["bytes"]
            or spec["sha256"] != original["checksums"]["sha256"]):
        raise ValueError("successor archive differs from original source manifest")


def check_redactions(base, manifest):
    for filename in manifest.get("history_redactions", {}):
        path = base / filename
        if path.exists() or path.is_symlink():
            raise ValueError(f"redacted history payload reappeared: {path.name}")


def verify_signature(key, signature, archive, allowed, expected_ring=None):
    with tempfile.TemporaryDirectory(prefix="source-auth-", dir="/tmp") as folder:
        home = Path(folder)
        listing = run(["/usr/bin/gpg", "--no-options", "--homedir", folder,
                       "--batch", "--with-colons", "--show-keys", "--fingerprint",
                       "--fingerprint"], key)
        ring = run(["/usr/bin/gpg", "--no-options", "--homedir", folder,
                    "--batch", "--dearmor"], key)
        if listing.returncode or ring.returncode:
            raise ValueError("public-key parsing failed")
        ring_sha = hashlib.sha256(ring.stdout).hexdigest()
        if expected_ring and ring_sha != expected_ring:
            raise ValueError("dearmored public-key pin mismatch")
        (home / "keys.gpg").write_bytes(ring.stdout)
        (home / "source.sig").write_bytes(signature)
        result = run(["/usr/bin/gpgv", "--homedir", folder, "--keyring",
                      str(home / "keys.gpg"), "--status-fd", "1",
                      str(home / "source.sig"), str(archive)])
        status = result.stdout.decode("utf-8", errors="replace")
        accepted = accepted_signature(result.returncode, status, allowed)
        return {**accepted, "gpgv_exit": result.returncode, "status": status,
                "diagnostic": result.stderr.decode("utf-8", errors="replace"),
                "public_key_listing": listing.stdout.decode("utf-8"),
                "binary_keyring_sha256": ring_sha, "signature_mathematics": "PASS"}


def verify(cache, original_report, original_ledger):
    manifest = json.loads((HERE / "manifest.json").read_text())
    original = check_pin(original_report, manifest["original_opaque_report"])
    ledger = check_pin(original_ledger, manifest["original_http_ledger"])
    check_pin(BASE / "source-inputs.json", manifest["parent_manifest"])
    for category, root in [("materials", HERE), ("receipts", HERE), ("history", BASE)]:
        for filename, pin in manifest[category].items():
            check_pin(root / filename, pin)
    for filename, pin in manifest.get("prior_private_stage", {}).items():
        check_pin(HERE / filename, pin)
    check_redactions(BASE, manifest)
    parent = json.loads((BASE / "source-inputs.json").read_text())
    for filename, pin in parent["materials"].items():
        check_pin(BASE / filename, pin)
    signatures = {}
    for name, spec in manifest["signatures"].items():
        check_archive_binding(spec, parent)
        archive = cache / spec["archive"]
        check_pin(archive, spec)
        signatures[name] = verify_signature(
            (HERE / spec["key"]).read_bytes(), (HERE / spec["signature"]).read_bytes(),
            archive, spec["allowed_primary_fingerprints"],
            spec["expected_binary_keyring_sha256"])
        # Detect mutation during GPG's opaque-byte read; no archive copies are made.
        check_pin(archive, spec)
        signatures[name]["archive"] = {key: spec[key] for key in ("archive", "bytes", "sha256")}
    history = json.loads((BASE / "history-search/results.json").read_text())
    recipes = []
    for recipe in history["recipes"]:
        candidates = []
        for candidate in recipe["candidates"]:
            actual = check_pin(BASE / "history-search" / candidate["file"], candidate)
            candidates.append({"file": candidate["file"], **actual,
                               "matches_required": actual["sha256"] == recipe["required_pkgbuild_sha256"]})
        recipes.append({"package": recipe["package"], "candidates": candidates,
                        "required_sha256": recipe["required_pkgbuild_sha256"],
                        "exact_original_recovered": any(c["matches_required"] for c in candidates)})
    # Preserve both original artifact bytes and original semantics as a past snapshot.
    check_pin(original_report, manifest["original_opaque_report"])
    check_pin(original_ledger, manifest["original_http_ledger"])
    return {"schema": 1, "purpose": manifest["purpose"], "successor_only": True,
            "authentication_manifest": describe(HERE / "manifest.json"),
            "source_material_manifest": manifest["parent_manifest"],
            "history_search_result": manifest["history"]["history-search/results.json"],
            "history_material_redactions": manifest.get("history_redactions", {}),
            "private_stage_metadata_retained": manifest.get("prior_private_stage", {}),
            "original_opaque_report_unchanged": original, "original_http_ledger_unchanged": ledger,
            "source_signatures": signatures, "recipe_correspondence": recipes,
            "original_recipe_hashes_resolved": sum(r["exact_original_recovered"] for r in recipes),
            "network_acquisition": manifest["network"], "replay_network_requests": 0,
            "original_source_material_and_license_pins": "ALL_PASS",
            "limits": manifest["limits"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-cache", required=True, type=Path)
    parser.add_argument("--original-report", required=True, type=Path)
    parser.add_argument("--original-ledger", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    # All writes are private disposable output; no host keyring or project mutation.
    if not output.is_relative_to(Path("/tmp")):
        parser.error("output must be below /tmp")
    protected = {args.original_report.resolve(), args.original_ledger.resolve()}
    protected.update(p.resolve() for p in args.source_cache.iterdir())
    if output in protected:
        parser.error("output cannot replace original evidence")
    report = verify(args.source_cache.resolve(), args.original_report.resolve(),
                    args.original_ledger.resolve())
    with output.open("x") as target:
        json.dump(report, target, indent=2, sort_keys=True)
        target.write("\n")
    print(json.dumps({"source_signatures": 2, "original_recipe_hashes_resolved":
                      report["original_recipe_hashes_resolved"], "output": str(output)}))


if __name__ == "__main__":
    main()
