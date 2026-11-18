#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Index source-input evidence for a pinned, previously authenticated addition stage.

The v1 config supplies a stage_receipt file pin and an originals list. Each
original has name, recipe, srcinfo and provenance. File pins use absolute path,
size and sha256. For zstd packages use Python with compression.zstd support.
The index records evidence and retains the prepare verdict without approving
a release, legal review or corresponding-source delivery.
"""

import argparse
from collections import Counter, defaultdict
from contextlib import contextmanager
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("addition_source_release_sbom", ROOT / "scripts/release/release_sbom.py")
sbom = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sbom)
source, recipe, stream = sbom.dependencies()
coverage = sbom.module("addition_composition_report", ROOT / "scripts/platform/archive_coverage.py")
need = source.need
KIND = "supported-Asahi-signed-addition-source-index-DATA"
STAGE_KIND = "supported-Asahi-signed-additions-DATA-receipt"
REPORT_KIND = "supported-Asahi-composition-DATA-proposal"
MIB = 1024**2
MAX_STAGE = 1024 * MIB
MAX_ARCHIVE = 300_000_000
MAX_METADATA = MIB
META_NAMES = {".PKGINFO", ".BUILDINFO"}


def reference(ref, limit):
    source.fields(ref, ("path", "size", "sha256"))
    path = Path(ref["path"])
    source.sha(ref["sha256"])
    need(path.is_absolute() and str(path) == ref["path"] and ".." not in path.parts
         and type(ref["size"]) is int and 0 < ref["size"] <= limit, "absolute whole-file reference refused")
    return path


def checked(ref, limit):
    path = reference(ref, limit)
    raw = source.local_read(path.parent, path.name, limit)
    need(len(raw) == ref["size"] and source.digest(raw) == ref["sha256"], f"whole-file reference differs: {path.name}")
    return raw


def pinned_json(path, digest):
    source.sha(digest)
    raw = source.local_read(path.parent, path.name, source.MAX_JSON)
    need(source.digest(raw) == digest, "configuration digest mismatch")
    return source.decode(raw)


def identity(info):
    return tuple(one(info, k) for k in ("pkgname", "pkgver", "arch"))


def one(fields, key):
    values = fields.get(key, [])
    need(len(values) == 1, f"unique package metadata field required: {key}")
    return values[0]


def fd_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@contextmanager
def archive_fd(ref):
    path = reference(ref, MAX_ARCHIVE)
    parent = source.directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        with os.fdopen(fd, "rb") as archive:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o444
                 and before.st_nlink == 1 and before.st_size == ref["size"], f"staged archive identity refused: {path.name}")
            digest = hashlib.sha256()
            remaining = before.st_size
            while remaining:
                data = archive.read(min(MIB, remaining))
                need(data, f"pinned archive ended early: {path.name}")
                digest.update(data)
                remaining -= len(data)
            need(not archive.read(1) and digest.hexdigest() == ref["sha256"], f"pinned archive checksum differs: {path.name}")
            archive.seek(0)
            yield archive
            need(fd_identity(before) == fd_identity(os.fstat(fd))
                 == fd_identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)),
                 f"staged archive changed during index: {path.name}")
    finally:
        os.close(parent)


def archive_metadata(ref):
    limits = stream.Limits(MAX_ARCHIVE, MAX_STAGE, 2 * MIB, 16, MAX_METADATA, 128 * MIB, time.monotonic() + 15)
    with archive_fd(ref) as archive:
        decoder = stream.Decoded(archive, limits, 0)
        found = {}
        with tarfile.open(fileobj=decoder, mode="r|") as tar:
            for index, member in enumerate(tar):
                if index >= limits.members:
                    break
                label = member.name.removeprefix("./")
                if label in META_NAMES:
                    need(label not in found and member.isfile() and 0 < member.size <= limits.file_bytes,
                         f"duplicate, unsafe or oversized package metadata: {label}")
                    raw = tar.extractfile(member).read()
                    need(len(raw) == member.size, f"short package metadata: {label}")
                    found[label] = (sbom.metadata(raw, source), dict(bytes=len(raw), sha256=source.digest(raw)))
                if found.keys() == META_NAMES or label not in stream.CONTROLS and not member.isdir():
                    break
    need(".PKGINFO" in found, "signed package metadata missing")
    return found


def original_materials(row, package, pkgbase, recipe_digest):
    source.fields(row, ("name", "recipe", "srcinfo", "provenance"))
    provenance_path = reference(row["provenance"], source.MAX_JSON)
    recipe_path = reference(row["recipe"], MAX_METADATA)
    srcinfo_path = reference(row["srcinfo"], MAX_METADATA)
    need(provenance_path.parent == recipe_path.parent == srcinfo_path.parent
         and (recipe_path.name, srcinfo_path.name, provenance_path.name) == ("PKGBUILD", ".SRCINFO", "source-provenance.json"),
         "retained package original layout refused")
    need(source.digest(checked(row["recipe"], MAX_METADATA)) == recipe_digest, "retained original does not match signed PKGBUILD")
    declared = recipe.metadata(checked(row["srcinfo"], MAX_METADATA))
    pkgver = f"{one(declared, 'pkgver')}-{one(declared, 'pkgrel')}"
    version = f"{one(declared, 'epoch')}:{pkgver}" if "epoch" in declared else pkgver
    need(version == package["version"] and one(declared, "pkgbase") == pkgbase
         and package["name"] in declared["pkgname"] and package["arch"] in declared["arch"]
         and sorted(declared.get("license", [])) == sorted(package["declared_licenses"]),
         "retained .SRCINFO package or declared license differs")
    record = source.decode(checked(row["provenance"], source.MAX_JSON))
    inputs = record["input_sha256"]
    need(record["schema_version"] == 1 and record["candidate_version"] == package["version"]
         and isinstance(inputs, dict) and 0 < len(inputs) <= 128 and {"LICENSE", "NOTICE"} <= inputs.keys(),
         "retained source-provenance record refused")
    names = declared.get("source", [])
    pins = declared.get("sha256sums", [])
    need(len(names) == len(pins) == len(set(names))
         and all(not key.startswith(("source_", "sha256sums_")) for key in declared)
         and "source-provenance.json" not in inputs
         and dict(zip(names, pins)) == {**inputs, "source-provenance.json": row["provenance"]["sha256"]},
         "retained source record differs from declared local .SRCINFO inputs")
    materials = {}
    for rel, pin in sorted(inputs.items()):
        source.sha(pin)
        raw = source.local_read(provenance_path.parent, rel, 8 * MIB)
        need(raw and source.digest(raw) == pin, f"retained original file differs: {rel}")
        materials[rel] = dict(bytes=len(raw), sha256=pin)
    return dict(status="RETAINED_ORIGINAL_INPUTS_HASH_MATCHED", recipe=row["recipe"], srcinfo=row["srcinfo"],
                provenance=row["provenance"], retained_files=materials, declared_local_source_count=len(names),
                corresponding_source_review="NOT REVIEWED", license_review="NOT REVIEWED")


def stage_pair(name, pair, selected, cache, original):
    archive = reference(pair["archive"], MAX_ARCHIVE)
    signature = reference(pair["signature"], 65536)
    verification = pair["verification"]
    need(archive.parent == signature.parent == cache and signature.name == archive.name + ".sig"
         and verification["status"] == "cryptographic-signature-valid" and verification["fresh_verification"] is True
         and re.fullmatch("[A-F0-9]{40}", verification["primary_fingerprint"])
         and pair["signer_role"] == ("project-test" if selected["repo"] == "project" else "vendor"),
         "staged detached signature or signer scope differs")
    checked(pair["signature"], 65536)
    metadata = archive_metadata(pair["archive"])
    pkginfo, pkginfo_ref = metadata[".PKGINFO"]
    name_seen, version, arch = identity(pkginfo)
    pkgbase = source.name(one(pkginfo, "pkgbase"))
    need(pkginfo_ref["sha256"] == verification["pkginfo_sha256"] and name_seen == name and version == selected["version"],
         "signed PKGINFO differs from stage or prepared add")
    package = source.identity(dict(name=name, version=version, arch=arch, sha256=pair["archive"]["sha256"]))
    package.update(repo=selected["repo"], declared_licenses=pkginfo.get("license", []))
    build, build_ref = metadata.get(".BUILDINFO", ({}, None))
    recipe_digest = None
    if build:
        need((one(build, "pkgname"), one(build, "pkgver"), one(build, "pkgarch"), one(build, "pkgbase"))
             == (name, version, arch, pkgbase), "signed BUILDINFO package identity differs")
        if "pkgbuild_sha256sum" in build:
            recipe_digest = source.sha(one(build, "pkgbuild_sha256sum"))
        installed = build.get("installed", [])
        build_ref.update(format=one(build, "format"), installed_count=len(installed),
                         installed_lock_sha256=source.digest(("\n".join(installed) + "\n").encode()) if installed else None)
    if original is not None:
        need(recipe_digest is not None, "retained original requires a signed recipe pin")
        original = original_materials(original, package, pkgbase, recipe_digest)
    status = original["status"] if original else ("RECIPE_DIGEST_ONLY" if recipe_digest else "RECIPE_DIGEST_MISSING")
    return dict(package=package, pkgbase=pkgbase, signature=pair["signature"], archive=pair["archive"],
                stage_signer_role=pair["signer_role"], stage_primary_fingerprint=verification["primary_fingerprint"],
                pkginfo=pkginfo_ref, buildinfo=build_ref, pkgbuild_sha256=recipe_digest, source_status=status,
                retained_original=original, corresponding_source_review="NOT REVIEWED", license_review="NOT REVIEWED")


def index(config, config_sha256):
    source.fields(config, ("kind", "schema_version", "stage_receipt", "originals"))
    need(config["kind"] == KIND and config["schema_version"] == 1, "source index input kind or version refused")
    stage_ref = config["stage_receipt"]
    stage_path = reference(stage_ref, source.MAX_JSON)
    stage = source.decode(checked(stage_ref, source.MAX_JSON))
    need(stage["kind"] == STAGE_KIND and stage["schema_version"] == 1 and stage["status"] == "PASS"
         and stage["transaction_accepted"] is False and stage["production_trust"] is False, "verified DATA stage receipt required")
    plan = coverage.load(checked(stage["composition"], 16 * MIB))
    need(plan["kind"] == REPORT_KIND and plan["status"] == stage["proposal_status"]
         and plan["blockers"] == stage["proposal_blockers"], "stage and private prepare policy disagree")
    selected = {r["name"]: r for r in plan["prepare"]["add"]}
    pairs = stage["pairs"]
    need(0 < len(pairs) == stage["operand_count"] == len(plan["prepare"]["add"]) <= 2048
         and selected.keys() == pairs.keys(), "exact prepared-add scope differs")
    need(sum(row[k]["size"] for row in pairs.values() for k in ("archive", "signature")) == stage["operand_bytes"] <= MAX_STAGE,
         "exact archive and signature aggregate bytes differ")
    originals = {source.name(row["name"]): row for row in config["originals"]}
    need(len(originals) == len(config["originals"]) and originals.keys() <= pairs.keys(), "duplicate or unrelated retained original")
    rows = []
    for name, pair in sorted(pairs.items()):
        try:
            rows.append(stage_pair(name, pair, selected[name], stage_path.parent / "cache", originals.get(name)))
        except (ValueError, OSError, KeyError, *stream.DECODER_ERRORS) as error:
            raise ValueError(f"{name}: {error}") from error
    groups = defaultdict(list)
    for row in rows:
        if row["pkgbuild_sha256"] is not None:
            groups[row["pkgbase"], row["pkgbuild_sha256"]].append(row["package"]["name"])
    return dict(kind=KIND, schema_version=1, config_sha256=config_sha256, staged_receipt=stage_ref,
                selected_composition=stage["composition"], proposal_status=stage["proposal_status"],
                proposal_blockers=stage["proposal_blockers"], package_count=len(rows),
                distinct_recipe_count=len({digest for _, digest in groups}),
                evidence_counts=dict(sorted(Counter(row["source_status"] for row in rows).items())),
                recipes=[dict(pkgbase=base, pkgbuild_sha256=digest, packages=members)
                         for (base, digest), members in sorted(groups.items())],
                packages=rows, corresponding_source_fulfillment="NOT ESTABLISHED",
                license_approval=False, transaction_accepted=False, production_trust=False)


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--config", type=Path, required=True)
    cli.add_argument("--config-sha256", required=True)
    cli.add_argument("--output", type=Path, required=True)
    args = cli.parse_args()
    try:
        result = index(pinned_json(args.config, args.config_sha256), args.config_sha256)
        output = args.output
        need(output.is_absolute() and output.parent.resolve(strict=True) == output.parent and output.name not in {".", ".."},
             "canonical absolute output required")
        raw = sbom.encoded(result)
        need(len(raw) <= 16 * MIB, "source index exceeds byte bound")
        with os.fdopen(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as target:
            target.write(raw)
        print(f"{result['package_count']} packages, {result['distinct_recipe_count']} recipe digests, sha256={source.digest(raw)}")
    except (OSError, ValueError, KeyError, AttributeError, TypeError, *stream.DECODER_ERRORS) as error:
        print(f"signed addition source index refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
