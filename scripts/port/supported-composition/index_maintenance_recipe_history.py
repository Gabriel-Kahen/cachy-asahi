#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Join retained signed forward and rollback archives to exact public recipe blobs.

The pinned config names a maintenance archive join result (archive_join) and
the candidate Git API responses (candidates). Each candidate identifies an
exact package, version, repository, commit, PKGBUILD path, and file_response.
The command reads existing signature verification evidence and rechecks its
archive and signature bytes. It executes neither recipes nor network requests.
The optional plugbuild_client reference enables a candidate reconstruction
using the archived Arch Linux ARM client's checksum append step.
"""

import argparse
import base64
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
PLUGBUILD_CLIENT_SHA256 = "8f9d420cd28ddafa66658e07c60cf5ea052f139894d3c4ef062b7309b3c9a3da"
PLUGBUILD_REVISION = "6ee09edc822e01ec6cce676fb73731cfd28d171b"
PLUGBUILD_SOURCE = (
    f"https://archive.softwareheritage.org/api/1/revision/{PLUGBUILD_REVISION}/directory/client.pl/"
)
CHECKSUM_FIELD = re.compile(rb"(?m)^((?:md5|sha1|sha224|sha256|sha384|sha512|b2)sums)(?:_\w+)?=")
CHECKSUM_ARRAY = re.compile(rb"(?m)^((?:sha512|b2)sums)=\(([^)]+)\)[ \t]*$")
CHECKSUM_VALUES = re.compile(rb"'[0-9a-f]{128}'(?:[ \t\n]+'[0-9a-f]{128}')*")


def plugbuild_candidate(raw, expected):
    """Retain the historical append projection only when the signed hash agrees."""
    declarations = CHECKSUM_FIELD.findall(raw)
    arrays = CHECKSUM_ARRAY.findall(raw)
    if (len(declarations) != 1 or len(arrays) != 1 or re.search(rb"(?m)^source_\w+=", raw)
            or not CHECKSUM_VALUES.fullmatch(arrays[0][1].strip())):
        return dict(status="UNSUPPORTED_CHECKSUM_LAYOUT")
    field, body = arrays[0]
    prefix = field + b"=("
    values = body.split()
    generated = prefix + (b"\n" + b" " * len(prefix)).join(values) + b")\n"
    # client.pl appends the output of echo '' followed by makepkg -g.
    expanded = raw + b"\n" + generated
    digest = source.digest(expanded)
    detail = dict(bytes=len(expanded), pkgbuild_sha256=digest)
    if digest != expected:
        return dict(detail, status="SIGNED_RECIPE_DIGEST_MISMATCH")
    return dict(detail, status="EXACT_SIGNED_RECIPE_MATCH",
                body_base64=base64.b64encode(expanded).decode("ascii"))


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
    fields = ("kind", "schema_version", "archive_join", "candidates")
    use_plugbuild = "plugbuild_client" in config
    source.fields(config, (*fields, "plugbuild_client") if use_plugbuild else fields)
    if use_plugbuild:
        ref = config["plugbuild_client"]
        client = history.read_reference_bytes(ref, history.MAX_RESPONSE)
        source.need(source.digest(client) == PLUGBUILD_CLIENT_SHA256,
                    "exact archived Arch Linux ARM plugbuild client required")
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
        snapshot, raw = history.match_file(row["repository"], row["commit"], row["path"],
                                           history.read_reference(row["file_response"], history.MAX_RESPONSE),
                                           include_body=True)
        expected = packages[key]["signed_pkgbuild_sha256"]
        match = snapshot["pkgbuild_sha256"] == expected
        candidate = dict(**snapshot, file_response=row["file_response"],
                         status="EXACT_SIGNED_RECIPE_MATCH" if match else "SIGNED_RECIPE_DIGEST_MISMATCH")
        if use_plugbuild and not match:
            candidate["plugbuild_candidate"] = plugbuild_candidate(raw, expected)
        grouped[key].append(candidate)
    for key, result in packages.items():
        entries = grouped[key]
        result["candidates"] = entries
        matched = any(row["status"] == "EXACT_SIGNED_RECIPE_MATCH"
                      or row.get("plugbuild_candidate", {}).get("status") == "EXACT_SIGNED_RECIPE_MATCH"
                      for row in entries)
        result["status"] = "EXACT_SIGNED_RECIPE_MATCH" if matched else "SIGNED_RECIPE_UNRECOVERED"
    result = dict(kind=KIND + "-result", schema_version=1, config_sha256=pin, archive_join=config["archive_join"],
                  packages=list(packages.values()), package_count=len(packages),
                  exact_recipe_count=sum(row["status"] == "EXACT_SIGNED_RECIPE_MATCH" for row in packages.values()),
                  candidate_count=len(seen), approval_status="UNAPPROVED", production_trust=False,
                  corresponding_source_fulfillment="NOT ESTABLISHED", license_review="NOT REVIEWED")
    if use_plugbuild:
        result["plugbuild"] = dict(method="APPEND_BLANK_LINE_AND_MAKEPKG_GENERATED_CHECKSUMS", client=ref,
                                   source_url=PLUGBUILD_SOURCE, source_revision=PLUGBUILD_REVISION,
                                   checksum_values="PUBLIC_RECIPE_DECLARATIONS")
    return result


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
