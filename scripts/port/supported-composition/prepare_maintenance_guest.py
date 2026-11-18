#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Materialize and verify a passive Asahi baseline and a three-phase guest plan.

The configuration pins the recovered-image capture, archive join, signed-stage
contract and existing Overlay583 boot tool inputs. This entry has no actor
launcher. Its output is a private read-only root seed and operand manifests.
"""

import argparse
import hashlib
import importlib.util
from pathlib import Path
import os
import shutil
import stat
import struct
import sys
import time
import uuid
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
MIB = 1024**2


def load(path):
    spec = importlib.util.spec_from_file_location("maintenance_guest_" + path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


A = load(HERE / "assemble_signed_additions.py")
S = load(HERE / "index_signed_addition_sources.py")
C = load(ROOT / "scripts/install/overlay583_trial/controller.py")
T = C.T
need, shape = A.need, A.shape
KIND = "supported-Asahi-maintenance-disposable-guest-preflight-DATA"
CHANGES = {
    "networkmanager": ("1.58.1-1", "1.58.1-2", "extra"),
    "perl": ("5.42.2-2", "5.42.3-1", "core"),
    "python": ("3.14.7-1", "3.14.8-1", "core"),
}


def file_pin(ref, cap, observed):
    path = T.ordinary(ref["path"])
    shape(ref, "path size sha256", "whole-file reference")
    return T.read(path, dict(bytes=ref["size"], sha256=ref["sha256"]), cap=cap, collect=False, observed=observed)


def ingress_pin(ref, seen):
    shape(ref, "path size sha256", "whole-file reference")
    raw = T.read(Path(ref["path"]), dict(bytes=ref["size"], sha256=ref["sha256"]),
                 cap=A.auth.JSON_LIMIT, observed=seen)
    return A.load(raw)


def capture_inputs(config, original, seen):
    captured = ingress_pin(config["image_capture"], seen)
    archive = config["image_zip"]
    need(captured["status"] == "data-captured-not-installation-accepted"
         and captured["system_mutation"] is False and captured["installation_accepted"] is False
         and captured["image_authentication"] == "observed-HTTPS-bytes-no-independent-image-signature",
         "historical target capture scope differs")
    recorded = captured["files"]["asahi-base.zip"]
    need((archive["size"], archive["sha256"]) == (recorded["bytes"], recorded["sha256"]),
         "retained image ZIP pin differs from original capture")
    raw_pin = captured["files"]["root.img"]
    need(raw_pin["zip_member"] == "root.img" and 1024 < raw_pin["bytes"] <= 4 * 1024**3,
         "bounded recorded ext4 root member required")
    capture_inventory = captured["files"]["image-inventory.json"]
    inv = config["image_inventory"]
    need((inv["size"], inv["sha256"]) == (capture_inventory["bytes"], capture_inventory["sha256"])
         and inv in original["input_references"], "exact original capture inventory binding required")
    baseline = ingress_pin(inv, seen)
    need(baseline["kind"] == "observed-image-local-package-metadata"
         and baseline["hardware_accepted"] is False and baseline["dependency_transaction_accepted"] is False,
         "original observed image inventory required")
    return captured, raw_pin, baseline


def ext4_geometry(head, image_size):
    meta = head[1024:2048]
    need(len(meta) == 1024 and meta[56:58] == b"\x53\xef" and meta[58:60] == b"\x01\x00",
         "expected clean ext4 superblock")
    u32 = lambda offset: struct.unpack_from("<I", meta, offset)[0]
    exponent = u32(24)
    need(exponent <= 4, "bounded ext4 block size")
    block_size = 1024 << exponent
    counts_64bit = bool(u32(96) & 0x80)
    blocks = u32(4) + ((u32(0x150) << 32) if counts_64bit else 0)
    available = u32(12) + ((u32(0x158) << 32) if counts_64bit else 0)
    need(blocks * block_size == image_size and available < blocks, "ext4 geometry differs from raw image size")
    return dict(block_size=block_size, bytes=image_size, free_bytes=available * block_size,
                uuid=str(uuid.UUID(bytes=meta[104:120])))


def root_seed(zip_ref, root_ref, destination, observed):
    file_pin(zip_ref, 2 * 1024**3, observed)
    path = T.ordinary(zip_ref["path"])
    need(shutil.disk_usage(destination.parent).free >= root_ref["bytes"] + C.RESERVE, "insufficient passive staging reserve")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    partial = destination.with_suffix(".part")
    start = time.monotonic()
    with os.fdopen(fd, "rb") as carrier:
        before = T.identity(os.fstat(fd))
        need(before == observed[str(path)], "historical image ZIP changed after whole-file check")
        with zipfile.ZipFile(carrier) as archive:
            candidates = [item for item in archive.infolist() if item.filename == "root.img"]
            need(len(candidates) == 1, "one exact root member required")
            member = candidates[0]
            need(stat.S_ISREG(member.external_attr >> 16) and not member.flag_bits & 1
                 and member.file_size == root_ref["bytes"], "ordinary exact root image member required")
            count, digest = 0, hashlib.sha256()
            with archive.open(member) as stream, partial.open("xb") as out:
                head = stream.read(2048)
                geometry = ext4_geometry(head, root_ref["bytes"])
                out.write(head)
                digest.update(head)
                count += len(head)
                while count < root_ref["bytes"]:
                    block = stream.read(min(MIB, root_ref["bytes"] - count))
                    need(block and time.monotonic() - start < 180, "root image read exceeded length or time bound")
                    if block.count(0) == len(block):
                        out.seek(len(block), os.SEEK_CUR)
                    else:
                        out.write(block)
                    digest.update(block)
                    count += len(block)
                out.truncate(count)
                need(not stream.read(1) and digest.hexdigest() == root_ref["sha256"], "raw root does not match original capture")
        need(T.identity(os.fstat(fd)) == before == T.identity(path.lstat()), "historical image carrier changed during staging")
    partial.chmod(0o444)
    partial.rename(destination)
    ref = dict(path=str(destination), size=count, sha256=root_ref["sha256"])
    file_pin(ref, 4 * 1024**3, observed)
    return ref, geometry


def existing_root_seed(path, root_ref, observed):
    path = T.ordinary(path)
    ref = dict(path=str(path), size=root_ref["bytes"], sha256=root_ref["sha256"])
    file_pin(ref, 4 * 1024**3, observed)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as image:
        info = os.fstat(fd)
        need(T.identity(info) == observed[str(path)] and stat.S_IMODE(info.st_mode) == 0o444,
             "existing raw seed must be the same read-only file")
        geometry = ext4_geometry(image.read(2048), root_ref["bytes"])
        need(T.identity(os.fstat(fd)) == observed[str(path)], "raw seed changed during metadata read")
    return ref, geometry


def lock(rows):
    body = "".join(f"{name} {version}\n" for name, version in sorted(rows.items())).encode("ascii")
    need(T.canonical_lock(body, len(rows)) == rows, "invalid package lock")
    return body


def phase_locks(baseline, original, proposed, prepare):
    old = {row["metadata"]["NAME"][0]: row["metadata"]["VERSION"][0] for row in baseline["packages"]}
    final = {name: row["version"] for name, row in proposed.items()}
    prior = {row["name"]: row["expected"] for row in original["protected"]}
    additions = A.indexed(prepare["add"], "name")
    need(len(old) == len(baseline["packages"]) == 261 and len(final) == 626 and old.keys() <= final.keys()
         and len(prior) == len(original["protected"]) == 201 and all(old[name] == version for name, version in prior.items())
         and len(additions) == 368 and not prepare["remove"], "unexpected baseline, protected or solver scope")
    delta = {name for name in final if old.get(name) != final[name]}
    need(additions.keys() == delta and {name for name in old if old[name] != final[name]} == CHANGES.keys()
         and all((old[name], final[name], proposed[name]["repo"]) == change for name, change in CHANGES.items())
         and all((row["version"], row["repo"]) == (final[name], proposed[name]["repo"]) for name, row in additions.items()),
         "unexpected change to original or selected package identities")
    rollback = dict(final)
    rollback.update({name: change[0] for name, change in CHANGES.items()})
    need(all(rollback[name] == version for name, version in prior.items()), "rollback does not restore every original protected version")
    return dict(baseline=lock(old), forward=lock(final), rollback=lock(rollback)), additions


def inspect_inputs(config, seen):
    shape(config, "kind schema_version image_zip image_inventory image_capture archive_join stage_contract boot", "passive preflight config")
    need(config["kind"] == KIND and config["schema_version"] == 1, "unsupported passive preflight configuration")
    join = ingress_pin(config["archive_join"], seen)
    need(join["kind"] == "supported-Asahi-maintenance-archive-rollback-DATA-result"
         and join["status"] == "HOLD" and join["approval_status"] == "UNAPPROVED"
         and join["verified_forward_pair_count"] == join["verified_rollback_pair_count"] == 3
         and join["transaction_accepted"] is join["production_trust"] is False
         and join["packages"].keys() == CHANGES.keys(), "exact unapproved archive-join receipt required")
    original = ingress_pin(join["original_report"], seen)
    maintenance = ingress_pin(join["unapproved_maintenance_report"], seen)
    proposal = maintenance["proposed_maintenance"]
    need(original["status"] == "FAIL" and original["metadata_prepare_status"] == "FAIL"
         and maintenance["original_policy"] == join["original_policy"]
         and all(original[key] == value for key, value in join["original_policy"].items())
         and proposal["metadata_prepare_status"] == "PASS" and proposal["approval_status"] == "UNAPPROVED"
         and proposal["transaction_accepted"] is proposal["selection_changed"] is False
         and proposal["final_inventory"] == join["selected_inventory"], "original and unapproved solver policy binding differs")
    inventory = ingress_pin(join["selected_inventory"], seen)
    need(inventory["dependency_transaction_accepted"] is False, "unapproved candidate inventory required")
    selected = A.indexed(inventory["proposed_final_inventory"], "name")
    capture, raw_pin, baseline = capture_inputs(config, original, seen)
    locks, adds = phase_locks(baseline, original, selected, proposal["prepare"])
    stage_ref = join["signed_addition_stage"]
    descriptor = config["stage_contract"]
    contract = ingress_pin(descriptor, seen)
    need(contract["composition"] == join["original_report"], "signed stage bound to a different original composition")
    prepared, _, operands, signers, total = A.contract_inputs(contract)
    stage = A.readback(contract, descriptor["sha256"], Path(stage_ref["path"]).parent,
                       prepared, operands, signers, total, stage_ref["sha256"])
    file_pin(stage_ref, A.auth.JSON_LIMIT, seen)
    need(stage["operand_count"] == 367 and stage["pairs"].keys() == adds.keys() - {"python"},
         "signed stage and one additional Python must cover every forward add")
    return join, selected, capture, raw_pin, locks, adds, stage, signers


def operable_pairs(join, selected, stage, adds, seen):
    forward = {name: dict(archive=pair["archive"], signature=pair["signature"],
                          primary_fingerprint=pair["verification"]["primary_fingerprint"], signer_role=pair["signer_role"])
               for name, pair in stage["pairs"].items()}
    old_pairs = {}
    for name, row in join["packages"].items():
        old, new, repo = CHANGES[name]
        need(row["change"] == dict(name=name, before=old, after=new, repo=repo), "signed maintenance version pairing differs")
        proof = row["forward"]
        current = forward.get(name)
        if current is not None:
            need(all(current[k] == proof[k] for k in ("archive", "signature")), "maintenance file differs from signed stage")
        for role, record in (("forward", proof), ("rollback", row["rollback"])):
            signer = record["verification"]["primary_fingerprint"]
            need(signer == A.auth.KEYS["alarm"][0] and record["verification"]["status"] == "cryptographic-signature-valid",
                 "exact ALARM signed change pair required")
            file_pin(record["archive"], A.auth.coverage.ARCHIVE_LIMIT, seen)
            file_pin(record["signature"], A.auth.SIGNATURE_LIMIT, seen)
            pair = dict(archive=record["archive"], signature=record["signature"], primary_fingerprint=signer, signer_role="vendor")
            if role == "rollback":
                old_pairs[name] = pair
            elif current is None:
                synthetic_row = selected[name]
                catalog = A.archive_details(synthetic_row)
                need(all(proof["archive"][key] == catalog[key] for key in ("size", "sha256"))
                     and catalog["signature_pin"] is not None
                     and all(proof["signature"][key] == value for key, value in catalog["signature_pin"].items()),
                     "supplement differs from the selected catalog")
                forward[name] = pair
    need(forward.keys() == adds.keys(), "incomplete exact forward archive operands")
    target_growth_bound = 0
    for name, pair in forward.items():
        metadata = selected[name]["metadata"]
        filename = Path(pair["archive"]["path"]).name
        need(metadata["FILENAME"] == [filename] and metadata["SHA256SUM"] == [pair["archive"]["sha256"]]
             and metadata["CSIZE"] == [str(pair["archive"]["size"])]
             and Path(pair["signature"]["path"]).name == filename + ".sig", "archive operand differs from forward inventory")
        sizes = metadata.get("ISIZE")
        if sizes is None:
            need(selected[name]["repo"] == "project", "catalog installed-size evidence required")
            sizes = S.archive_metadata(pair["archive"])[".PKGINFO"][0]["size"]
        need(len(sizes) == 1 and sizes[0].isdigit(), "finite installed-size evidence required")
        target_growth_bound += int(sizes[0])
    return forward, old_pairs, target_growth_bound


def save(path, raw):
    with path.open("xb") as fd:
        fd.write(raw)
    path.chmod(0o444)
    return dict(path=str(path), **T.pin(raw))


def stage(config, config_pin, output, *, reuse_seed=None):
    observed = {}
    join, selected, capture, raw_pin, locks, adds, signed, signers = inspect_inputs(config, observed)
    forward, rollback, installed_size = operable_pairs(join, selected, signed, adds, observed)
    boot = config["boot"]
    need(boot.keys() == C.REFERENCES.keys(), "selected Overlay583 boot input set required")
    for name, item in boot.items():
        need((item["size"], item["sha256"]) == C.REFERENCES[name], "selected Overlay583 boot reference differs")
        file_pin(item, item["size"], observed)
    controller_source = C.source_pins()
    out = T.ordinary(output)
    out.mkdir(mode=0o700)
    if reuse_seed is None:
        root_ref, geometry = root_seed(config["image_zip"], raw_pin, out / "seed-root.img", observed)
    else:
        root_ref, geometry = existing_root_seed(reuse_seed, raw_pin, observed)
    need(geometry["bytes"] + installed_size + C.RESERVE < C.WORK_SIZE, "forward payload exceeds eventual guest scratch bound")
    needs_grow = geometry["free_bytes"] < installed_size + C.RESERVE
    lock_refs = {phase: save(out / (phase + ".lock"), body) for phase, body in locks.items()}
    previews = {
        "forward": lock({name: row["version"] for name, row in adds.items()}),
        "rollback": lock({name: CHANGES[name][0] for name in rollback}),
    }
    preview_refs = {phase: save(out / (phase + "-preview.lock"), body) for phase, body in previews.items()}
    keys_out = {}
    public = Path(join["signed_addition_stage"]["path"]).parent / "public-keys"
    for key, row in signers.items():
        cert = public / (key + ".gpg")
        expected = row["certificate"]
        ref = dict(expected, path=str(cert))
        file_pin(ref, A.MIB, observed)
        keys_out[key] = dict(file=ref, primary_fingerprint=row["fingerprint"], scope=row["role"])
    T.unchanged(observed)
    result = dict(kind=KIND + "-plan", schema_version=1, config_sha256=config_pin, status="HOLD_UNAPPROVED_GUEST",
                  approval_status="UNAPPROVED", actor_authorized=False, transaction_started=False, installation="NOT RUN",
                  original_policy=join["original_policy"], original_root=dict(seed=root_ref, capture=config["image_capture"],
                      image_zip=config["image_zip"], zip_reverified_this_run=reuse_seed is None,
                      capture_authentication=capture["image_authentication"],
                      image_inventory=config["image_inventory"], geometry=geometry),
                  boot=boot, controller_source=controller_source, controller_actor_image=C.ACTOR_IMAGE,
                  guest=dict(architecture="aarch64", page_size=16384, network="none", use_control_root_as_boot=True,
                      writable_target_is_disposable_clone=True, scratch_bytes=C.WORK_SIZE,
                      expand_clone_before_forward=needs_grow, forward_archive_installed_bytes=installed_size),
                  expected_locks=lock_refs, expected_previews=preview_refs, operand_sources=dict(forward=forward, rollback=rollback, public_keys=keys_out),
                  phases=[
                      dict(role="baseline", package_count=261, compare_full_inventory=True),
                      dict(role="forward", package_count=626, additions=len(forward), removals=0, compare_full_inventory=True),
                      dict(role="rollback", package_count=626, replacements=sorted(rollback), compare_full_inventory=True),
                  ],
                  operator_requirements=[
                      "Bind a new controller and guest worker for this plan and issue separate guest authority.",
                      "Present the verified original root only as the seed for a separate writable target on the existing offline control guest.",
                      "Grow the cloned target filesystem inside the disposable guest before the forward operation.",
                      "Reverify the public signer scopes and current TEST certificates in a private guest keyring.",
                      "Compare exact local-file transaction previews with the pinned preview locks before forward or rollback.",
                      "Use normal detached signature verification, dependency checks, hooks and scriptlets.",
                      "Confirm the full inventory and local database at baseline, forward and rollback and return pinned evidence after retirement.",
                  ],
                  archive_join=config["archive_join"], protected_versions_restored_after_rollback=201)
    return save(out / "guest-plan.DATA.json", T.encoded(result))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--config-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reuse-seed", type=Path, help="rehash a previously materialized read-only raw image without recopying it")
    args = parser.parse_args()
    sys.addaudithook(C.passive_fence)
    try:
        result = stage(A.pinned_json(args.config, args.config_sha256), args.config_sha256, args.output, reuse_seed=args.reuse_seed)
        print(T.encoded(result).decode(), end="")
    except (OSError, ValueError, KeyError, TypeError, AttributeError, zipfile.BadZipFile) as error:
        print(f"passive maintenance preflight refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
