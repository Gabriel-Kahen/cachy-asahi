#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Join retained signed forward and rollback archives to exact public recipe blobs.

The pinned config names a maintenance archive join result (archive_join) and
the candidate Git API responses (candidates). Each candidate identifies an
exact package, version, repository, commit, PKGBUILD path, and file_response.
The command reads existing signature verification evidence and rechecks its
archive and signature bytes. It executes neither recipes nor network requests.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("maintenance_archive_join", HERE / "join_maintenance_rollback.py")
rollback = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rollback)
history = rollback.load("join_signed_recipe_history")
index = rollback.load("index_signed_addition_sources")
source = history.source
KIND = "supported-Asahi-maintenance-recipe-history-DATA"
DIRECTIONS = {"forward": "after", "rollback": "before"}


def signed_input(name, version, arch, repo, pair, temporary):
    verification = pair["verification"]
    source.need(verification["status"] == "cryptographic-signature-valid"
                and verification["fresh_verification"] is True
                and verification["independent_owner_trust_accepted"] is False
                and re.fullmatch(r"[0-9A-F]{40}", verification["primary_fingerprint"]),
                "maintenance archive requires retained signature evidence")
    archive, signature = pair["archive"], pair["signature"]
    filename = f"{name}-{version}-{arch}.pkg.tar.xz"
    rollback.pair_paths(pair, filename)
    index.checked(signature, 65_536)
    with tempfile.TemporaryDirectory(prefix="metadata-", dir=temporary) as scratch:
        snapshot = Path(scratch) / filename
        rollback.A.checked_file(archive, index.MAX_ARCHIVE, snapshot)
        metadata = index.archive_metadata(dict(archive, path=str(snapshot)))
    pkginfo, pkginfo_ref = metadata[".PKGINFO"]
    source.need(".BUILDINFO" in metadata, f"missing signed BUILDINFO: {filename}")
    build, build_ref = metadata[".BUILDINFO"]
    pkgbase = source.name(index.one(pkginfo, "pkgbase"))
    source.need(pkginfo_ref["sha256"] == verification["pkginfo_sha256"]
                and index.identity(pkginfo) == (name, version, arch)
                and tuple(index.one(build, key) for key in ("pkgname", "pkgver", "pkgarch", "pkgbase"))
                == (name, version, arch, pkgbase), f"signed package identity differs: {filename}")
    recipe = source.sha(index.one(build, "pkgbuild_sha256sum"))
    return dict(package=source.identity(dict(name=name, version=version, arch=arch, sha256=archive["sha256"])),
                pkgbase=pkgbase, repo=repo, archive=archive, signature=signature, signature_verification=verification,
                pkginfo=pkginfo_ref, buildinfo=dict(build_ref, format=index.one(build, "format"),
                                                   builddate=index.one(build, "builddate")),
                declared_licenses=pkginfo.get("license", []), signed_pkgbuild_sha256=recipe)


def signed_packages(join, temporary):
    exact = rollback.EXACT
    source.need(join["kind"] == rollback.KIND + "-result" and join["schema_version"] == 1
                and join["status"] == "HOLD" and join["approval_status"] == "UNAPPROVED"
                and join["production_trust"] is False and join["transaction_accepted"] is False
                and join["packages"].keys() == exact.keys()
                and join["verified_forward_pair_count"] == join["verified_rollback_pair_count"] == len(exact),
                "exact unapproved archive join evidence required")
    packages = {}
    for name, (before, after, repo) in sorted(exact.items()):
        row = join["packages"][name]
        source.need(row["arch"] == "aarch64" and row["change"] == dict(name=name, before=before, after=after, repo=repo),
                    f"maintenance package scope differs: {name}")
        for direction, version_key in DIRECTIONS.items():
            version = row["change"][version_key]
            packages[name, version] = dict(direction=direction,
                                           **signed_input(name, version, row["arch"], repo, row[direction], temporary))
    return packages


def compare(config, pin):
    source.fields(config, ("kind", "schema_version", "archive_join", "candidates"))
    candidates = config["candidates"]
    source.need(config["kind"] == KIND and config["schema_version"] == 1
                and type(candidates) is list and 0 < len(candidates) <= 96, "bounded maintenance history config required")
    join = history.read_reference(config["archive_join"], source.MAX_JSON)
    with tempfile.TemporaryDirectory(prefix="maintenance-recipe-history-") as temporary:
        packages = signed_packages(join, temporary)
    grouped = {key: [] for key in packages}
    seen = set()
    for row in candidates:
        source.fields(row, ("package", "version", "repository", "commit", "path", "file_response"))
        key = row["package"], row["version"]
        candidate = key + (row["repository"], row["commit"], row["path"])
        source.need(key in packages and candidate not in seen, "duplicate candidate or unrelated package version")
        seen.add(candidate)
        snapshot = history.match_file(row["repository"], row["commit"], row["path"],
                                      history.read_reference(row["file_response"], history.MAX_RESPONSE))
        match = snapshot["pkgbuild_sha256"] == packages[key]["signed_pkgbuild_sha256"]
        grouped[key].append(dict(**snapshot, file_response=row["file_response"],
                                 status="EXACT_SIGNED_RECIPE_MATCH" if match else "SIGNED_RECIPE_DIGEST_MISMATCH"))
    for key, result in packages.items():
        entries = grouped[key]
        result["candidates"] = entries
        matched = any(row["status"] == "EXACT_SIGNED_RECIPE_MATCH" for row in entries)
        result["status"] = "EXACT_SIGNED_RECIPE_MATCH" if matched else "SIGNED_RECIPE_UNRECOVERED"
    return dict(kind=KIND + "-result", schema_version=1, config_sha256=pin, archive_join=config["archive_join"],
                packages=list(packages.values()), package_count=len(packages),
                exact_recipe_count=sum(row["status"] == "EXACT_SIGNED_RECIPE_MATCH" for row in packages.values()),
                candidate_count=len(seen), approval_status="UNAPPROVED", production_trust=False,
                corresponding_source_fulfillment="NOT ESTABLISHED", license_review="NOT REVIEWED")


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--config", type=Path, required=True)
    cli.add_argument("--config-sha256", required=True)
    cli.add_argument("--output", type=Path, required=True)
    args = cli.parse_args()
    try:
        raw = source.local_read(args.config.parent, args.config.name, source.MAX_JSON)
        source.need(source.digest(raw) == args.config_sha256, "maintenance recipe config SHA-256 differs")
        result = compare(source.decode(raw), args.config_sha256)
        output = args.output
        source.need(output.is_absolute() and output.parent.resolve(strict=True) == output.parent
                    and output.name not in {".", ".."}, "canonical absolute fresh output required")
        encoded = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode()
        with os.fdopen(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as target:
            target.write(encoded)
        print(f"{result['exact_recipe_count']}/{result['package_count']} exact recipes, "
              f"{result['candidate_count']} candidates, SHA-256 {source.digest(encoded)}")
    except (OSError, ValueError, TypeError, KeyError, AttributeError, *index.stream.DECODER_ERRORS) as error:
        print(f"maintenance recipe history refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
