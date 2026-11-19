#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare sanitized draft release evidence from independently reviewed captures."""
import argparse
from datetime import datetime, timezone
import importlib.util
import os
from pathlib import Path
import re
import sys
import tempfile

HERE = Path(__file__).resolve().parent


def module(path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


kit = module(HERE.parent / "release" / "offline_kit.py")
client = kit.c
capture = module(HERE / "capture-baseline.py")
MODELS = {"13-inch": ("apple,j413", "m2-air-13"), "15-inch": ("apple,j415", "m2-air-15")}
REVIEW_KIND = "physical-m2-air-baseline-review-v1"
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+~:_-]{0,127}")
ROLES = {"m1n1", "uboot", "asahi_scripts", "kernel", "mesa", "hyprland", "aquamarine",
         "asahi_audio", "pipewire", "wireplumber", "speakersafetyd"}
MAX_BASE = 32 * 1024**2


def token(value):
    client.need(isinstance(value, str) and VERSION.fullmatch(value), "expected a package, kernel or firmware version")
    return value


def captured_at(value):
    stamp = datetime.fromisoformat(value)
    client.need(stamp.tzinfo is not None, "capture time requires an explicit timezone")
    return stamp.astimezone(timezone.utc)


def model_identity(baseline):
    size = capture.exact_target_size(baseline["architecture"], baseline["device_tree_compatible"])
    client.need(baseline["record_type"] == "environment-baseline" and baseline["schema_version"] == 1
                and baseline["validation_result"] == "NOT RUN" and baseline["execution_context"] == "physical"
                and size in MODELS and baseline["m2_air_size"] == size
                and baseline["page_size_bytes"] == capture.TARGET_PAGE_SIZE,
                "an unambiguous captured physical-context M2 Air with 16 KiB pages is required")
    return MODELS[size]


def inventory(query):
    client.need(query["command"] == ["pacman", "-Q"] and type(query["returncode"]) is int
                and query["returncode"] == 0, "a successful captured pacman -Q inventory is required")
    packages = {}
    for line in query["stdout"].splitlines():
        pair = line.split()
        client.need(len(pair) == 2 and client.NAME.fullmatch(pair[0]) and pair[0] not in packages,
                    "malformed or duplicated captured package")
        packages[pair[0]] = token(pair[1])
    return packages


def release_inputs(path, expected, model):
    root = client.directory(path.parent)
    try:
        raw = client.read_member(root, path.name)
        spec = client.decode(raw)
        client.need(client.digest(raw) == expected["spec_sha256"] and spec["schema_version"] == 1
                    and spec["target_arch"] == "aarch64" and spec["synthetic"] is False
                    and model in spec["policy"]["supported_models"] and client.NAME.fullmatch(spec["release_id"])
                    and re.fullmatch(r"[a-f0-9]{40}", spec["source_commit"]),
                    "release specification pin, model, or non-synthetic scope differs")
        base_ref = spec["base"]
        base_raw = client.read_member(root, base_ref["path"], MAX_BASE)
        client.need(client.digest(base_raw) == base_ref["sha256"] == expected["base_sha256"],
                    "release base checksum differs")
        base = client.decode(base_raw)
        client.need(base["schema_version"] == 1 and base["kind"] == "complete-target-transaction"
                    and base["target_arch"] == "aarch64" and base["snapshot_id"] == base_ref["snapshot_id"],
                    "exact complete release base inventory is required")
        versions = {row["name"]: token(row["version"]) for row in base["packages"]}
        protected = set(spec["policy"]["protected_packages"])
        client.need(len(versions) == len(base["packages"]) and protected and protected <= versions.keys(),
                    "base inventory or protected package policy differs")
        overlay, overlay_versions = {}, {}
        for row in spec["packages"]:
            artifact, provenance = row["artifact"], row["provenance"]
            prov = client.read_member(root, provenance["path"])
            digest, _ = client.hash_member(root, artifact["path"])
            record = client.decode(prov)
            label = record["package"]["name"]
            client.need(client.digest(prov) == provenance["sha256"] and record["schema_version"] == 1
                        and record["source_commit"] == spec["source_commit"] and client.NAME.fullmatch(label)
                        and record["package"]["arch"] in {"aarch64", "any"} and label not in overlay
                        and digest == artifact["sha256"] == record["artifact_sha256"],
                        "release overlay artifact identity, provenance, or bytes differ")
            overlay[label] = digest
            overlay_versions[label] = token(record["package"]["version"])
        selected = spec["policy"]["selected_packages"]
        client.need(overlay and len(selected) == len(overlay) and set(selected) == overlay.keys()
                    and not protected.intersection(overlay), "the exact unprotected selected overlay is required")
        return spec, versions, protected, overlay, versions | overlay_versions
    finally:
        os.close(root)


def session_identity(raw, review, model_id, kernel, release_source, baseline_time):
    if raw is None:
        client.need(review["session_sha256"] is None, "reviewed session capture is missing")
        return None
    probe = client.decode(raw)
    identities = probe["identity"]
    when = captured_at(probe["collected_at"])
    client.need(client.digest(raw) == review["session_sha256"] and probe["schema_version"] == 1
                and probe["record_type"] == "session-observations" and identities["architecture"] == "aarch64"
                and identities["observed_model_id"] == identities["declared_model_id"] == model_id
                and identities["declared_model_matches_observation"] is True and identities["execution_context"] == "physical"
                and identities["page_size_bytes"] == 16_384 and identities["kernel"] == kernel
                and identities["baseline_sha256"] == review["baseline_sha256"]
                and identities["source_revision"] == release_source
                and baseline_time <= when <= client.stamp(review["reviewed_utc"])
                and probe["physical_checks"] and set(probe["physical_checks"].values()) == {"NOT RUN"},
                "session observation differs from reviewed machine, baseline, or source")
    return dict(kind="sanitized-session-context", capture_sha256=review["session_sha256"],
                collected_at=client.utc(when), model_id=model_id, kernel=kernel, page_size_bytes=16_384)


def prepare(baseline_raw, session_raw, spec_path, contract_raw, review):
    baseline = client.decode(baseline_raw)
    model_id, model = model_identity(baseline)
    baseline_time = captured_at(baseline["collected_at"])
    machine_id = review["machine_id"]
    client.need(review["kind"] == REVIEW_KIND and review["decision"] == "REVIEWED_PHYSICAL_BASELINE"
                and review["model_id"] == model_id and re.fullmatch(r"m2-[a-f0-9]{32}", machine_id)
                and isinstance(review["reviewer"], str) and review["reviewer"].strip()
                and isinstance(baseline["operator"], str) and baseline["operator"].strip()
                and review["reviewer"].strip().casefold() != baseline["operator"].strip().casefold()
                and baseline_time <= client.stamp(review["reviewed_utc"])
                and client.digest(baseline_raw) == review["baseline_sha256"]
                and client.digest(contract_raw) == review["contract_sha256"],
                "an independently pinned physical review of these exact inputs is required")
    spec, base, protected, overlay, target_versions = release_inputs(spec_path, review, model)
    observed = inventory(baseline["packages"])
    client.need(all(observed.get(name) == base[name] for name in protected),
                "captured protected package versions differ from the release base")
    roles = review["platform_packages"]
    client.need(isinstance(roles, dict) and ROLES <= roles.keys() <= ROLES | {"linux_firmware"}
                and all(isinstance(name, str) and name in observed and name in target_versions for name in roles.values()),
                "review must map every platform role to a captured package in the release transaction")
    platform = {role: dict(package=name, baseline_version=observed[name], release_version=target_versions[name])
                for role, name in sorted(roles.items())}
    kernel = token(baseline["kernel"])
    platform.update(running_kernel=kernel, boot_firmware=token(review["boot_firmware_version"]))
    session = session_identity(session_raw, review, model_id, kernel, spec["source_commit"], baseline_time)
    count = client.decode(contract_raw)["sleep_wake_repetitions"]
    client.need(type(count) is int and count > 0, "frozen acceptance contract needs positive sleep/wake repetitions")
    files = {
        f"{model}-{machine_id}-baseline.json": dict(kind="sanitized-baseline", model_id=model_id,
            collected_at=client.utc(baseline_time), capture_sha256=review["baseline_sha256"],
            architecture="aarch64", page_size_bytes=16_384, platform_versions=platform,
            protected_package_versions={name: observed[name] for name in sorted(protected)}),
        f"{model}-{machine_id}-acceptance.json": dict(kind="sanitized-acceptance-contract-binding",
            frozen_contract_sha256=review["contract_sha256"], sleep_wake_repetitions=count),
    }
    base_id, contract_id = files
    machine_id_file = f"{model}-{machine_id}-machine.json"
    machine = dict(kind="draft-machine-record", model=model, machine_id=machine_id, soc="M2", execution="physical",
                   model_id=model_id, base_sha256=review["base_sha256"], package_sha256=overlay,
                   pre_evidence_spec_sha256=review["spec_sha256"], release_id=spec["release_id"],
                   source_commit=spec["source_commit"], platform_versions=platform,
                   baseline=base_id, acceptance_contract=contract_id)
    if session is not None:
        machine["session"] = f"{model}-{machine_id}-session.json"
        files[machine["session"]] = session
    files[machine_id_file] = machine
    client.need(not {row["id"] for row in spec.get("evidence", [])}.intersection(files),
                "draft evidence ID already occurs in the release spec")
    return machine_id_file, files


def publish(output, spec, review_pin, machine_id_file, files):
    client.need(output.parent == spec.parent and not output.exists() and not output.is_symlink(),
                "fresh output directly beside the release spec is required")
    files[machine_id_file]["physical_review_sha256"] = review_pin
    parent = client.directory(output.parent)
    try:
        info = os.fstat(parent)
        client.need(info.st_uid == os.geteuid() and not info.st_mode & 0o022, "spec directory must be privately controlled")
        with tempfile.TemporaryDirectory(prefix=".hardware-draft-", dir=output.parent) as temporary:
            staging = Path(temporary) / "draft"
            staging.mkdir(mode=0o700)
            evidence = []
            for name, value in files.items():
                raw = client.encoded(value)
                (staging / name).write_bytes(raw)
                evidence.append(dict(id=name, path=f"{output.name}/{name}", sha256=client.digest(raw)))
            draft = dict(status="DRAFT_MACHINE_EVIDENCE", machine_record=machine_id_file,
                         review_sha256=review_pin, hardware_validation="NOT RUN", evidence=evidence)
            (staging / "draft.json").write_bytes(client.encoded(draft))
            info = staging.stat()
            kit.publish(staging, parent, output, (info.st_dev, info.st_ino))
        return draft
    finally:
        os.close(parent)


def main(argv=None):
    cli = argparse.ArgumentParser(description=__doc__)
    for name in ("baseline", "contract", "review", "spec", "output"):
        cli.add_argument("--" + name, required=True)
    cli.add_argument("--review-sha256", required=True)
    cli.add_argument("--session")
    args = cli.parse_args(argv)
    try:
        baseline = client.read_path(args.baseline, client.MAX_JSON)
        model_identity(client.decode(baseline))
        review = client.read_path(args.review, client.MAX_JSON)
        client.need(client.digest(review) == args.review_sha256, "review differs from independently supplied SHA-256")
        spec = client.absolute(args.spec)
        contract = client.read_path(args.contract, client.MAX_JSON)
        session = client.read_path(args.session, client.MAX_JSON) if args.session else None
        machine, files = prepare(baseline, session, spec, contract, client.decode(review))
        result = publish(client.absolute(args.output), spec, args.review_sha256, machine, files)
        print(client.encoded(result).decode(), end="")
    except (OSError, ValueError, TypeError, AttributeError, KeyError, client.Error) as error:
        print(f"hardware evidence refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
