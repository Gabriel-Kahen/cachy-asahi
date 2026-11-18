#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind exactly three proposed maintenance updates to signed forward/rollback DATA.

The config pins both composition reports, the signed stage receipt and its
ALARM certificate. A supplements row supplies the additional Python forward
pair. Each rollback_pairs row carries the original archive, detached signature
and prior custody evidence. File references use path, size and sha256.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(f"rollback_{name}", HERE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


A, C = load("assemble_signed_additions"), load("compose")
need, shape, read = A.need, A.shape, A.json_ref
EXACT = C.maintenance.EXACT
KIND = "supported-Asahi-maintenance-archive-rollback-DATA"
PKGINFO_FIELDS = {
    "NAME": "pkgname", "BASE": "pkgbase", "VERSION": "pkgver", "ARCH": "arch",
    "BUILDDATE": "builddate", "PACKAGER": "packager", "SIZE": "size", "DESC": "pkgdesc", "URL": "url",
    "LICENSE": "license", "DEPENDS": "depend", "PROVIDES": "provides", "CONFLICTS": "conflict",
    "REPLACES": "replaces", "OPTDEPENDS": "optdepend", "XDATA": "xdata",
}
ORIGINAL_FIELDS = ("blockers", "protected", "prepare", "roots", "provider_bindings", "dependencies",
                   "base_changes", "final_package_count", "original_protected_count", "protected_package_count",
                   "proposed_final_inventory", "workflow", "metadata_prepare_status")


def inputs(config):
    shape(config, "kind schema_version original_report maintenance_report stage_receipt "
          "public_certificate supplements rollback_pairs", "maintenance/archive contract")
    need(config["kind"] == KIND and config["schema_version"] == 1, "exact maintenance archive contract required")
    original, replay, stage = (read(config[k]) for k in ("original_report", "maintenance_report", "stage_receipt"))
    before, adds = A.plan(original)
    need(replay["kind"] == A.REPORT and replay["status"] == "HOLD" and original["status"] == "FAIL"
         and replay["approval_status"] == "UNAPPROVED" and replay["original_policy_failure_retained"] is True
         and replay["private_database_removed"] is True
         and all(replay[k] is False for k in ("transaction_accepted", "full_supported_system_accepted",
                                             "system_mutation", "payload_execution", "network_used"))
         and all(replay[k] == original[k] for k in ORIGINAL_FIELDS)
         and all(original[k] == value for k, value in replay["original_policy"].items()),
         "original failed composition or protected tuple changed in replay")
    proposal = replay["proposed_maintenance"]
    need(proposal["status"] == "HOLD" and proposal["approval_status"] == "UNAPPROVED"
         and proposal["metadata_prepare_status"] == "PASS" and proposal["transaction_accepted"] is False
         and proposal["selection_changed"] is False and proposal["private_database_removed"] is True
         and not proposal["blockers"] and proposal["proposal_reference"] in replay["input_references"],
         "only successful unapproved maintenance metadata may be joined")
    proposal_ref = read(proposal["proposal_reference"])
    need(proposal_ref["changes"] == proposal["changes"], "recorded maintenance changes differ from proposal")
    baseline = read(proposal_ref["image_inventory"])
    need(baseline["kind"] == "observed-image-local-package-metadata"
         and proposal_ref["image_inventory"] in original["input_references"], "original observed image required")
    image = {entry["metadata"]["NAME"][0]: entry for entry in baseline["packages"]}
    need(len(image) == len(baseline["packages"]), "duplicate original image identity")
    requested = {name: dict(name=name, before=old, after=new, repo=repo) for name, (old, new, repo) in EXACT.items()}
    declared = A.indexed(proposal["changes"], "name")
    need({name: {k: row[k] for k in ("name", "before", "after", "repo")} for name, row in declared.items()}
         == requested and A.indexed(proposal["base_changes"], "name") == {
             name: dict(row, exact_proposal_matches=True) for name, row in requested.items()},
         "forward and rollback may only cover the three exact proposed changes")
    prepared = proposal["prepare"]
    need(prepared["prepare_exit"] == prepared["prepare_errno"] == 0
         and all(not prepared[k] for k in ("errors", "callback_errors", "remove", "questions")),
         "maintenance resolver or provider state differs")
    forward_adds = A.indexed(prepared["add"], "name")
    inventory = read(proposal["final_inventory"])
    need(inventory["kind"] == "UNAPPROVED-maintenance-metadata-inventory"
         and inventory["dependency_transaction_accepted"] is False, "unapproved forward inventory required")
    final = A.indexed(inventory["proposed_final_inventory"], "name")
    need(len(final) == proposal["final_package_count"] == original["final_package_count"]
         and final.keys() == before.keys(), "unexpected maintenance membership change")
    for name in final.keys() - {"python"}:
        need(final[name] == before[name], f"unexpected maintenance archive or metadata change: {name}")
    need(stage["kind"] == A.KIND + "-receipt" and stage["status"] == "PASS"
         and stage["transaction_accepted"] is False and stage["production_trust"] is False
         and stage["composition"] == config["original_report"] and stage["proposal_status"] == "FAIL"
         and stage["pairs"].keys() == adds.keys() and stage["operand_count"] == len(adds),
         "pinned signed additions do not cover exact original prepare")
    supplement = A.indexed(config["supplements"], "name")
    rollback = A.indexed(config["rollback_pairs"], "name")
    need(rollback.keys() == requested.keys() and forward_adds.keys() == adds.keys() | supplement.keys()
         and supplement.keys() == {"python"} and supplement.keys().isdisjoint(adds),
         "exact forward supplement and three rollback pairs required")
    for name, row in adds.items():
        need(forward_adds[name] == row, f"changed existing forward add: {name}")
    for name, (old, new, repo) in EXACT.items():
        need(forward_adds[name] == dict(name=name, version=new, repo=repo)
             and final[name]["repo"] == repo and final[name]["version"] == new
             and image[name]["metadata"]["VERSION"] == [old], f"wrong maintenance before/after identity: {name}")
    return replay, proposal, stage, final, image, requested, supplement, rollback


def pair_paths(pair, filename):
    archive = A.reference(pair["archive"], A.auth.coverage.ARCHIVE_LIMIT)
    signature = A.reference(pair["signature"], A.auth.SIGNATURE_LIMIT)
    need(archive.name == filename and signature.name == filename + ".sig", f"exact archive/signature name required: {filename}")
    return archive.name, signature.name


def verify_forward_pins(pair, row):
    spec = A.archive_details(row)
    names = pair_paths(pair, spec["filename"])
    need(all(pair["archive"][k] == spec[k] for k in ("size", "sha256"))
         and spec["signature_pin"] is not None
         and all(pair["signature"][k] == v for k, v in spec["signature_pin"].items()),
         f"forward archive or signature differs from exact catalog: {row['name']}")
    return names


def exact_baseline_pkginfo(expected, observed):
    for catalog, package in PKGINFO_FIELDS.items():
        need(sorted(expected.get(catalog, [])) == sorted(observed.get(package, [])),
             f"rollback signed installed metadata differs: {catalog}")


def authenticated(pair, names, metadata, temp, ring, signer, baseline=False):
    archive_name, signature_name = names
    with tempfile.TemporaryDirectory(prefix="pair-", dir=temp) as scratch:
        archive, signature = Path(scratch) / archive_name, Path(scratch) / signature_name
        A.checked_file(pair["archive"], A.auth.coverage.ARCHIVE_LIMIT, archive)
        A.checked_file(pair["signature"], A.auth.SIGNATURE_LIMIT, signature)
        proof = A.verify_pair(archive, signature, metadata, temp, ring, signer)
        if baseline:
            info = A.auth.pkginfo(archive)
            need(info["sha256"] == proof["pkginfo_sha256"], "rollback metadata readback differs")
            exact_baseline_pkginfo(metadata, A.native.pkginfo(info["text"]))
    return dict(archive=pair["archive"], signature=pair["signature"], verification=proof)


def evaluate(config, config_pin):
    replay, proposal, stage, final, image, requested, supplement, rollback = inputs(config)
    cert = config["public_certificate"]
    signer, key_digest = A.auth.KEYS["alarm"]
    need(cert["sha256"] == key_digest, "exact ALARM public key required")
    versions = C.t.tuple_audit.Versions()
    rows = {}
    with tempfile.TemporaryDirectory(prefix="maintenance-public-") as scratch:
        home = Path(scratch)
        certificate, ring = home / "certificate.gpg", home / "public.gpg"
        A.checked_file(cert, A.MIB, certificate)
        A.public_ring(home, certificate, ring, signer)
        for name, change in sorted(requested.items()):
            row, original = final[name], image[name]
            rollback_pair = rollback[name]
            shape(rollback_pair, "name archive signature prior_evidence", "rollback pair")
            prior = rollback_pair["prior_evidence"]
            A.checked_file(prior, A.auth.JSON_LIMIT)
            candidate = supplement.get(name, stage["pairs"].get(name))
            if name in supplement:
                shape(candidate, "name archive signature", "forward supplement")
            else:
                need(candidate["signer_role"] == "vendor" and candidate["verification"]["primary_fingerprint"] == signer,
                     f"retained forward signer differs: {name}")
            forward = authenticated(candidate, verify_forward_pins(candidate, row), row["metadata"], home, ring, signer)
            metadata = original["metadata"]
            _, version, arch = A.auth.identity(metadata)
            old_archive = pair_paths(rollback_pair, f"{name}-{version}-{arch}.pkg.tar.xz")
            backward = authenticated(rollback_pair, old_archive, metadata, home, ring, signer, baseline=True)
            affected = [edge for edge in proposal["dependencies"] if edge["provider"] == name]
            incompatible = [edge for edge in affected if not C.t.tuple_audit.witnesses(edge["relation"], {name: metadata}, versions)]
            rows[name] = dict(change=change, arch=arch, forward=forward,
                              forward_origin="exact catalog supplement" if name in supplement else "pinned signed addition stage",
                              rollback=dict(backward, observed_descriptor_sha256=original["descriptor_sha256"], prior_evidence=prior,
                                            installed_metadata_fields=sorted(PKGINFO_FIELDS)),
                              forward_edges_to_provider=len(affected), recorded_edges_without_old_witness=incompatible)
    return dict(kind=KIND + "-result", schema_version=1, config_sha256=config_pin, status="HOLD",
                approval_status="UNAPPROVED", original_report=config["original_report"],
                original_policy=replay["original_policy"], unapproved_maintenance_report=config["maintenance_report"],
                selected_inventory=proposal["final_inventory"], signed_addition_stage=config["stage_receipt"],
                prepared_add_count=len(proposal["prepare"]["add"]), reused_addition_count=stage["operand_count"],
                verified_forward_pair_count=len(rows), verified_rollback_pair_count=len(rows), packages=rows,
                signature_scope="cryptographic public-key evidence", installed_payload_correspondence="NOT ESTABLISHED",
                rollback_transaction="NOT RUN", transaction_accepted=False, production_trust=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--config-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = evaluate(A.pinned_json(args.config, args.config_sha256), args.config_sha256)
        path = args.output
        need(path.is_absolute() and path.parent.resolve(strict=True) == path.parent, "canonical absolute output required")
        raw = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode()
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as out:
            out.write(raw)
        print(f"Verified {report['verified_forward_pair_count']} forward and {report['verified_rollback_pair_count']} rollback pairs")
    except (ValueError, TypeError, AttributeError, KeyError, OSError, tarfile.TarError) as error:
        print(f"maintenance archive join refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
