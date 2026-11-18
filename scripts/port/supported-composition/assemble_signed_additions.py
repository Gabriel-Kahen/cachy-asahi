#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stage exact signed operands for a supported-composition DATA proposal."""

import argparse
from contextlib import contextmanager, nullcontext
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[3]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


auth = module("addition_auth", "scripts/platform/authenticate_missing.py")
native = module("addition_metadata", "scripts/ci/native_arm.py")
need, load = auth.need, auth.coverage.load
MIB = 1024**2
DIGEST = re.compile(r"[a-f0-9]{64}")
FINGERPRINT = re.compile(r"[A-F0-9]{40}")
PACKAGE = re.compile(r"[A-Za-z0-9@._+-]+")
KIND = "supported-Asahi-signed-additions-DATA"
REPORT = "supported-Asahi-composition-DATA-proposal"
POLICY_FIELDS = ("status", "metadata_prepare_status", "workflow", "policy_scope", "roots", "holds", "blockers",
                 "provider_bindings", "base_changes", "dependencies", "protected", "catalog_diagnostics",
                 "original_protected_count", "protected_package_count", "image_package_count",
                 "final_package_count", "added_package_count")
BUILD_FIELDS = {"FILENAME", "SHA256SUM", "CSIZE", "MD5SUM", "PGPSIG", "VERSION", "BUILDDATE", "PACKAGER",
                "MAKEDEPENDS", "CHECKDEPENDS"}
INSPECT_FIELDS = dict(pkgname="name", pkgver="version", arch="arch", depend="depends", provides="provides",
                      conflict="conflicts", replaces="replaces", license="license")


def shape(row, fields, label):
    need(isinstance(row, dict) and row.keys() == set(fields.split()), f"{label} fields refused")


def reference(row, limit):
    shape(row, "path size sha256", "file reference")
    path = Path(row["path"])
    need(path.is_absolute() and str(path) == row["path"] and ".." not in path.parts
         and type(row["size"]) is int and 0 < row["size"] <= limit
         and DIGEST.fullmatch(row["sha256"]), "file reference path, size or digest refused")
    return path


def file_identity(info):
    return (info.st_dev, info.st_ino, info.st_nlink, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@contextmanager
def pinned_open(path, limit):
    observed = auth.regular(path)
    need(0 < observed.st_size <= limit, "file exceeds size bound")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = file_identity(observed)
        need(before == file_identity(os.fstat(fd)), "file changed before open")
        yield stream, observed
        need(before == file_identity(os.fstat(fd)) == file_identity(auth.regular(path)), "file changed during read")


def checked_file(ref, limit, target=None, staged=False):
    path = reference(ref, limit)
    digest = hashlib.sha256()
    with pinned_open(path, limit) as (src, info):
        need(info.st_size == ref["size"], f"file size mismatch: {path.name}")
        if staged:
            need(stat.S_IMODE(info.st_mode) == 0o444, f"staged mode mismatch: {path.name}")
        with (target.open("xb") if target is not None else nullcontext()) as out:
            remaining = info.st_size
            while remaining:
                block = src.read(min(MIB, remaining))
                need(block, f"short pinned file: {path.name}")
                digest.update(block)
                if out is not None:
                    out.write(block)
                remaining -= len(block)
            need(not src.read(1), f"pinned file grew: {path.name}")
        if target is not None:
            target.chmod(0o444)
    need(digest.hexdigest() == ref["sha256"], f"file digest mismatch: {path.name}")


def pinned_json(path, pin, size=None):
    need(DIGEST.fullmatch(pin), "JSON digest refused")
    with pinned_open(path, auth.JSON_LIMIT) as (stream, observed):
        need(size is None or size == observed.st_size, "JSON size mismatch")
        data = stream.read(observed.st_size + 1)
    need(len(data) == observed.st_size and hashlib.sha256(data).hexdigest() == pin,
         f"JSON digest mismatch: {path.name}")
    return load(data)


def json_ref(ref):
    return pinned_json(reference(ref, auth.JSON_LIMIT), ref["sha256"], ref["size"])


def indexed(rows, field):
    need(isinstance(rows, list) and len(rows) <= 2048, f"{field} row bound refused")
    result = {}
    for row in rows:
        name = row[field]
        need(PACKAGE.fullmatch(name) and name not in result, f"duplicate or unsafe {field}: {name}")
        result[name] = row
    return result


def plan(report):
    need(report["kind"] == REPORT and report["schema_version"] == 1
         and report["status"] in {"HOLD", "FAIL"} and "error" not in report
         and report["metadata_prepare_status"] in {"PASS", "FAIL"}
         and report["private_database_removed"] is True
         and all(report[k] is False for k in ("transaction_accepted", "full_supported_system_accepted", "system_mutation",
                                             "payload_execution", "network_used"))
         and all(report[k] == "NOT RUN" for k in ("hardware", "installation", "native_build")),
         "only a clean private composition DATA report is supported")
    prepare = report["prepare"]
    need(prepare["prepare_exit"] == prepare["prepare_errno"] == 0
         and prepare["callback_errors"] == prepare["remove"] == [],
         "private prepare failed, callbacks failed or removals were proposed")
    final = indexed(report["proposed_final_inventory"], "name")
    adds = indexed(prepare["add"], "name")
    need(len(final) == report["final_package_count"] and 0 < len(adds) <= len(final),
         "composition inventory or add count mismatch")
    for name, row in adds.items():
        shape(row, "name version repo", "ALPM operand")
        selected = final.get(name, {})
        md_name, version, _ = auth.identity(selected["metadata"])
        need(row["repo"] == selected["repo"] and row["version"] == selected["version"] == version and md_name == name,
             f"add/inventory identity mismatch: {name}")
    return final, adds


def archive_details(row):
    metadata = row["metadata"]
    if row["repo"] != "project":
        details = auth.archive_spec(metadata, row["repo"], "signed-additions")
        need(details["signature_pin"] is not None or row["repo"] == "asahi-alarm", "vendor catalog signature required")
        return details
    name, version, arch = auth.identity(metadata)
    need(all(type(metadata.get(k)) is list and len(metadata[k]) == 1 and isinstance(metadata[k][0], str)
             for k in ("FILENAME", "CSIZE", "SHA256SUM")), "incomplete project archive pins")
    filename, size, digest = (metadata[k][0] for k in ("FILENAME", "CSIZE", "SHA256SUM"))
    need(filename in {f"{name}-{version.split(':')[-1]}-{arch}.pkg.tar.{extension}" for extension in ("xz", "zst")}
         and size.isdecimal() and 0 < int(size) <= auth.coverage.ARCHIVE_LIMIT and DIGEST.fullmatch(digest)
         and not metadata.get("PGPSIG"), "project archive pins refused")
    return dict(filename=filename, size=int(size), sha256=digest, signature_pin=None, key=name)


def artifact(row):
    pins = archive_details(row)
    return dict(repo=row["repo"], version=row["version"], **{key: pins[key] for key in ("filename", "size", "sha256")})


def alternatives(contract, original, selected, before, after, before_adds, after_adds):
    need(all(original[field] == selected[field] for field in POLICY_FIELDS),
         "protected composition, graph or policy changed")
    need({k: v for k, v in original["prepare"].items() if k != "add"}
         == {k: v for k, v in selected["prepare"].items() if k != "add"}, "private prepare history changed")
    need(before.keys() == after.keys() and before_adds.keys() == after_adds.keys(), "composition membership changed")
    changed = {name for name in before if any(before[name][k] != after[name][k] for k in ("repo", "version", "metadata"))}
    declared = indexed(contract["alternatives"], "name")
    need(changed == declared.keys() and changed <= after_adds.keys(), "undeclared or unused archive alternative")
    need(not changed.intersection(row["name"] for row in original["protected"]), "protected archive alternative refused")
    for name, row in declared.items():
        shape(row, "name before after evidence", "archive alternative")
        old, new = before[name], after[name]
        need(row["before"] == artifact(old) and row["after"] == artifact(new)
             and row["before"] != row["after"] and old["repo"] == new["repo"],
             f"original/alternate archive pin mismatch: {name}")
        need({k: v for k, v in old["metadata"].items() if k not in BUILD_FIELDS}
             == {k: v for k, v in new["metadata"].items() if k not in BUILD_FIELDS},
             f"alternate changed dependency or package metadata: {name}")
        checked_file(row["evidence"], auth.JSON_LIMIT)


def contract_inputs(contract):
    shape(contract, "kind schema_version original composition alternatives keys operands byte_limit", "assembly contract")
    need(contract["kind"] == KIND and contract["schema_version"] == 1
         and type(contract["byte_limit"]) is int and 0 < contract["byte_limit"] <= auth.coverage.TOTAL_LIMIT,
         "assembly contract kind, version or byte bound refused")
    original, selected = json_ref(contract["original"]), json_ref(contract["composition"])
    before, before_adds = plan(original)
    after, after_adds = plan(selected)
    alternatives(contract, original, selected, before, after, before_adds, after_adds)
    operands, keys = indexed(contract["operands"], "name"), indexed(contract["keys"], "id")
    need(operands.keys() == after_adds.keys(), "each exact ALPM add requires one signed pair")
    cache, total = set(), 0
    for name, row in operands.items():
        shape(row, "name version repo key archive signature", "signed operand")
        detail = archive_details(after[name])
        body = reference(row["archive"], auth.coverage.ARCHIVE_LIMIT)
        sig = reference(row["signature"], auth.SIGNATURE_LIMIT)
        need(all(row[k] == after_adds[name][k] for k in ("name", "version", "repo"))
             and body.name == detail["filename"] and sig.name == body.name + ".sig"
             and all(row["archive"][k] == detail[k] for k in ("size", "sha256"))
             and body.name not in cache, f"archive operand mismatch: {name}")
        key = row["key"]
        need(key == detail["key"], f"archive signer scope mismatch: {name}")
        if detail["signature_pin"] is not None:
            need(all(row["signature"][k] == v for k, v in detail["signature_pin"].items()),
                 f"catalog detached signature mismatch: {name}")
        cache.update((body.name, sig.name))
        total += row["archive"]["size"] + row["signature"]["size"]
    need(total <= contract["byte_limit"] and keys.keys() == {row["key"] for row in operands.values()},
         "assembly byte budget or signer set mismatch")
    for key, row in keys.items():
        shape(row, "id role fingerprint certificate", "signer")
        reference(row["certificate"], MIB)
        need(FINGERPRINT.fullmatch(row["fingerprint"]), "primary fingerprint refused")
        if key in auth.KEYS:
            need(row["role"] == "vendor" and (row["fingerprint"], row["certificate"]["sha256"]) == auth.KEYS[key],
                 f"vendor certificate pin mismatch: {key}")
        else:
            need(row["role"] == "project-test" and row["fingerprint"] not in {item[0] for item in auth.KEYS.values()},
                 f"project TEST certificate scope mismatch: {key}")
    need(len({row["fingerprint"] for row in keys.values()}) == len(keys), "signer reused across scopes")
    return selected, after, operands, keys, total


def run(argv, timeout=30):
    return auth.capture.bounded_command(argv, timeout=timeout, limit=MIB)[0]


def public_ring(home, certificate, ring, fingerprint):
    gpg = ["gpg", "--batch", "--no-options", "--homedir", home, "--no-auto-key-retrieve", "--no-autostart"]
    display = run(gpg + ["--with-colons", "--import-options", "show-only", "--dry-run", "--import", certificate])
    records = [row.split(b":") for row in display.splitlines()]
    primaries = [row[0] for row in records if row[0] in {b"pub", b"sec", b"ssb"}]
    fingerprints = [row[9] for row in records if row[0] == b"fpr"]
    need(primaries == [b"pub"] and fingerprints and fingerprints[0] == fingerprint.encode(),
         "exact public primary and public-only certificate required")
    run(gpg + ["--dearmor", "--output", ring, certificate])


def verify_pair(archive, signature, metadata, home, ring, fingerprint):
    status = run(["gpgv", "--homedir", home, "--keyring", ring, "--status-fd", "1", signature, archive], 90)
    result = auth.signature_status(status, fingerprint)
    if archive.suffix == ".xz":
        info = auth.pkginfo(archive)
    else:
        raw = run(["bsdtar", "-xOf", archive, ".PKGINFO"])
        info = dict(text=raw.decode(), sha256=hashlib.sha256(raw).hexdigest())
    actual = native.pkginfo(info["text"])
    expected = auth.expected(metadata)
    for field, key in INSPECT_FIELDS.items():
        values = expected[key]
        need(sorted(actual.get(field, [])) == sorted(values if isinstance(values, list) else [values]),
             f"exact signed PKGINFO {field} mismatch: {archive.name}")
    return dict(result, pkginfo_sha256=info["sha256"])


def staged_reference(ref, path):
    return dict(ref, path=str(path))


def receipt_base(contract, pin, selected, operands, total):
    return dict(kind=KIND + "-receipt", schema_version=1, status="PASS", contract_sha256=pin,
                original=contract["original"], composition=contract["composition"], alternatives=contract["alternatives"],
                proposal_status=selected["status"], metadata_prepare_status=selected["metadata_prepare_status"],
                proposal_blockers=selected["blockers"], operand_count=len(operands), operand_bytes=total,
                transaction_accepted=False, production_trust=False, installation="NOT RUN")


def destination(output):
    need(output.is_absolute() and output.parent.resolve(strict=True) == output.parent
         and output.name not in {"", ".", ".."}, "canonical absolute output with an existing parent required")


def assemble(contract, pin, output, selected, inventory, operands, keys, total):
    destination(output)
    output.mkdir(mode=0o700)
    receipt = receipt_base(contract, pin, selected, operands, total)
    # The detached receipt appears atomically only after every pair verifies.
    cache, public = output / "cache", output / "public-keys"
    cache.mkdir(mode=0o700)
    public.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix=".verify-", dir=output) as temporary:
        home = Path(temporary)
        for key, row in keys.items():
            certificate = home / ("certificate-" + key + ".gpg")
            checked_file(row["certificate"], MIB, certificate)
            public_ring(home, certificate, home / (key + ".gpg"), row["fingerprint"])
            certificate.rename(public / (key + ".gpg"))
        results = {}
        for name, row in sorted(operands.items()):
            refs = {k: staged_reference(row[k], cache / Path(row[k]["path"]).name) for k in ("archive", "signature")}
            checked_file(row["archive"], auth.coverage.ARCHIVE_LIMIT, Path(refs["archive"]["path"]))
            checked_file(row["signature"], auth.SIGNATURE_LIMIT, Path(refs["signature"]["path"]))
            signer = keys[row["key"]]
            verification = verify_pair(Path(refs["archive"]["path"]),
                                       Path(refs["signature"]["path"]), inventory[name]["metadata"],
                                       home, home / (row["key"] + ".gpg"), signer["fingerprint"])
            results[name] = dict(refs, signer_role=signer["role"], verification=verification)
    receipt["pairs"] = results
    auth.save(output / "receipt.json", receipt, replace=True)
    return receipt


def readback(contract, pin, output, selected, operands, keys, total, receipt_pin):
    destination(output)
    need(not output.is_symlink() and {x.name for x in output.iterdir()} == {"receipt.json", "cache", "public-keys"},
         "staged output namespace mismatch")
    receipt = pinned_json(output / "receipt.json", receipt_pin)
    expected = receipt_base(contract, pin, selected, operands, total)
    need({k: v for k, v in receipt.items() if k != "pairs"} == expected
         and receipt["pairs"].keys() == operands.keys(), "receipt does not match exact contract")
    leaves = {"cache": {}, "public-keys": {}}
    for key, row in keys.items():
        leaves["public-keys"][key + ".gpg"] = row["certificate"]
    for name, row in operands.items():
        actual = receipt["pairs"][name]
        signer = keys[row["key"]]
        shape(actual, "archive signature signer_role verification", "receipt pair")
        verification = actual["verification"]
        shape(verification, "status primary_fingerprint independent_owner_trust_accepted fresh_verification pkginfo_sha256",
              "receipt verification")
        need(actual["signer_role"] == signer["role"] and verification["primary_fingerprint"] == signer["fingerprint"]
             and verification["status"] == "cryptographic-signature-valid"
             and verification["independent_owner_trust_accepted"] is False and verification["fresh_verification"] is True
             and DIGEST.fullmatch(verification["pkginfo_sha256"]), f"receipt signature observation mismatch: {name}")
        for k in ("archive", "signature"):
            leaf = Path(row[k]["path"]).name
            need(actual[k] == staged_reference(row[k], output / "cache" / leaf), f"receipt file pin mismatch: {name}")
            leaves["cache"][leaf] = row[k]
    for subdir, expected_files in leaves.items():
        directory = output / subdir
        need(not directory.is_symlink() and {x.name for x in directory.iterdir()} == expected_files.keys(),
             f"staged {subdir} leaf set mismatch")
        for leaf, ref in expected_files.items():
            checked_file(staged_reference(ref, directory / leaf), auth.coverage.ARCHIVE_LIMIT, staged=True)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("assemble", "verify"))
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--contract-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--receipt-sha256")
    args = parser.parse_args()
    try:
        need(bool(args.receipt_sha256) == (args.action == "verify"), "verify requires the independently pinned receipt digest")
        pin = args.contract_sha256
        contract = pinned_json(args.contract, pin)
        selected, inventory, operands, keys, total = contract_inputs(contract)
        if args.action == "assemble":
            receipt = assemble(contract, pin, args.output, selected, inventory, operands, keys, total)
        else:
            receipt = readback(contract, pin, args.output, selected, operands, keys, total, args.receipt_sha256)
        print(json.dumps(dict(action=args.action, status=receipt["status"], operand_count=receipt["operand_count"],
                              operand_bytes=receipt["operand_bytes"], proposal_status=receipt["proposal_status"],
                              receipt_sha256=args.receipt_sha256 or auth.hash_file(args.output / "receipt.json")), sort_keys=True))
    except (ValueError, OSError, TypeError, KeyError, IndexError, AttributeError, tarfile.TarError, subprocess.SubprocessError) as error:
        print(f"signed additions refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
