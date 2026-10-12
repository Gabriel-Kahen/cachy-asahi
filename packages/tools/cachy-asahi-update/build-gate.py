#!/usr/bin/env python3
"""Gate private native compilation on observed isolation and pinned actual inputs.

Never starts Cargo, a compiler or a container. Controller provenance is supplied
externally; this gate grants neither distribution nor Apple update acceptance.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
EVIDENCE = {
    "source-audit.json": "f0ab84e1295c4f2df7640266944901eac7fa052c00ee4ef48fb498f5a1ff2c85",
    "cargo-audit.json": "01d8fdc321d58f0153019b576db5abfd3e4a66320d5c26507cb40df7e9ff7ff8",
    "build-script-review.json": "11e687a1633cd09db2a24a9a6f7c32086a86e83dec615ec08a05143ed273ac49",
    "additional-cargo-licenses.json": "74a1dbfa75de13df5c82525af8d684e38b772c31bdf912d61f7fe74e7646c591",
}
INVENTORY = "d5e2b02a4af36b763c24c0eded8d4b7326874448996f94126fbfc3f787946271"
MODULE_PINS = {
    "linux-closure.py": "a73d7ba17018d2fd359e630675b7ca207965b01eca358f7574a80f690124d2a2",
    "worker-metadata.py": "f54226c068f3f8a51556ed9185168b89f793c1c8f2219c81557246f587e0edf2",
}


def require(condition, message):
    if not condition:
        raise ValueError("compile refused: " + message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def module(policy, name):
    path = HERE / name
    require(sha(path.read_bytes()) == policy["module_sha256"][name], "validator/observer module pin differs")
    spec = importlib.util.spec_from_file_location("updater_gate_" + name.replace("-", "_"), path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def policy_check(policy):
    require(policy.get("schema_version") == 2 and policy.get("scope") == "private isolated native Linux compilation",
            "actual-input compile policy required; PASS flags do not grant execution")
    require(policy.get("evidence_sha256") == EVIDENCE and policy.get("builder_inventory_sha256") == INVENTORY,
            "pinned review/source/builder constraints differ")
    require(policy.get("module_sha256") == MODULE_PINS, "source-reviewed observer/validator code pins differ")


def source_gate(source, manifest, closure):
    """All tray compile inputs remain upstream bytes; both patches affect shells."""
    expected = {p[len("src/tray/"):]: h for p, h in source["files_sha256"].items() if p.startswith("src/tray/")}
    require(expected and expected.get("Cargo.toml") == closure.PINS["manifest"]
            and expected.get("Cargo.lock") == closure.PINS["lock"], "tray source ledger binding")
    root, actual = manifest.parent, {}
    deadline = time.monotonic() + 30
    count = 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        directory = Path(directory)
        count += 1
        require(count <= 10000 and time.monotonic() <= deadline, "tray traversal bound")
        for name in list(dirs):
            path = directory / name
            require(not path.is_symlink(), "tray directory symlink")
            if directory == root and name == "target":
                require(path.is_dir() and path.resolve(strict=True) == root / "target", "unsafe generated target directory")
                dirs.remove(name)  # The sole canonical Cargo output, not source.
        for name in files:
            count += 1
            require(count <= 10000 and time.monotonic() <= deadline, "tray traversal bound")
            path = directory / name
            require(not path.is_symlink(), "tray symlink")
            relative = path.relative_to(root).as_posix()
            require(relative in expected, "unreviewed extra tray input")
            actual[relative] = sha(closure.read(path, 8 * 1024 * 1024))
    require(actual == expected, "actual tray source bytes differ")


def script_gate(review, audit, sources):
    """Hash bindings, not report PASS strings, identify inspected script paths."""
    ledger = {(r["name"], r["version"]): r for r in audit["registry_sources"]}
    reviewed = {(r["name"], r["version"]): r for r in review["packages"]}
    scripts = {k: r for k, r in ledger.items() if r["build_scripts"]}
    require(len(reviewed) == len(review["packages"]) == len(scripts) == 38
            and set(reviewed) == set(scripts), "complete original 38-script review ledger required")
    require(review["cargo_lock_sha256"] == audit["cargo_lock_sha256"]
            and review["audit_input_sha256"] == EVIDENCE["cargo-audit.json"], "script review original audit binding")
    helper_rows = {r["package"]: r for r in review["helper_paths"]}
    require(len(helper_rows) == len(review["helper_paths"]), "ambiguous helper review")
    for key, row in reviewed.items():
        original = ledger[key]
        require(row["archive_sha256"] == original["archive_sha256"]
                and row["source_files_sha256"] == original["source_files_sha256"]
                and row["manifest_sha256"] == original["normalized_manifest_sha256"]
                and row["build_dependencies"] == original["build_dependencies"]
                and row["target_build_dependencies"] == original["target_build_dependencies"], "reviewed script source drift")
        script_map = {f["path"]: f["sha256"] for f in row["scripts"]}
        require(len(script_map) == len(row["scripts"])
                and script_map == {f["path"]: f["sha256"] for f in original["build_scripts"]}, "script entrypoint drift")
        if key not in sources:
            continue
        for item in row["scripts"] + row["input_files"]:
            data = sources[key].get(item["path"])
            require(data is not None and sha(data) == item["sha256"] and len(data) == item["bytes"], "actual script/include/helper input differs")
        for helper in row["helper_dependencies"]:
            matches = [k for k in ledger if "-".join(k) == helper]
            require(len(matches) == 1 and matches[0] in sources, "selected build helper missing from actual graph")
    for helper, row in helper_rows.items():
        matches = [k for k in ledger if "-".join(k) == helper]
        require(len(matches) == 1, "unknown helper source")
        key = matches[0]
        if key in sources:
            for item in row["files"]:
                data = sources[key].get(item["path"])
                require(data is not None and sha(data) == item["sha256"] and len(data) == item["bytes"], "actual helper source differs")
    return len(set(sources) & set(reviewed))


def receipt_gate(worker, controller, facts, metadata, cfg, artifact_root, read):
    require(worker["observed_worker"] == facts, "fresh worker observation differs from metadata receipt")
    require(worker["image_id"] == controller["image_id"] == facts["image_id"]
            and controller["nonce"] == facts["nonce"], "worker launch identity differs")
    require(worker["builder_inventory_sha256"] == controller["builder_inventory_sha256"] == INVENTORY,
            "worker builder inventory differs")
    require(worker["controller_sha256"] == os.environ.get("CACHY_ASAHI_CONTROLLER_SHA256"), "receipt controller binding differs")
    require(worker["verified_tool_pins"] == controller["tool_pins"], "receipt tool pins differ")
    for name, hash_value in worker["tool_sha256"].items():
        require(hash_value == controller["tool_pins"]["tools"]["/usr/bin/" + name]["sha256"], "receipt tool content differs")
    target = "aarch64-unknown-linux-gnu"
    commands = {"cargo-metadata": worker["metadata_argv"], "target-cfg": ["/usr/bin/rustc", "--print", "cfg", "--target", target],
                "rustc-version": ["/usr/bin/rustc", "-vV"], "inventory": ["/usr/bin/pacman", "-Q"]}
    output = {}
    for stem, argv in commands.items():
        record = json.loads(read(artifact_root / (stem + ".command.json"), 1024 * 1024))
        require(record["argv"] == argv and record["exit_code"] == 0 and record["failure"] is None and not record.get("cleanup_errors"),
                "fresh worker command evidence failed/differs")
        output[stem] = read(artifact_root / (stem + ".stdout"), 16 * 1024 * 1024)
        read(artifact_root / (stem + ".stderr"), 16 * 1024 * 1024)
    require(output["cargo-metadata"] == metadata and output["target-cfg"] == cfg, "metadata/cfg command bytes differ")
    require(sha(b"".join(sorted(output["inventory"].splitlines(keepends=True)))) == INVENTORY, "observed native inventory differs")
    version = output["rustc-version"].decode()
    release = re.search(r"^release: ([0-9]+)\.([0-9]+)\.([0-9]+)", version, re.M)
    require(sha(output["rustc-version"]) == worker["rustc_vv_sha256"]
            and "host: " + target in version.splitlines() and release
            and tuple(map(int, release.groups())) >= (1, 92, 0), "native reviewed compiler version differs")


def save_report(path, data, read):
    """Repeat checks reuse only identical fresh-worker evidence; no overwrite."""
    if path.exists() or path.is_symlink():
        require(read(path, 8 * 1024 * 1024) == data, "existing selected-closure evidence differs")
    else:
        with path.open("xb") as stream:
            stream.write(data)


def compile_inputs(args, policy, worker_module, closure):
    """Production entry: observation/controller checks precede source reads."""
    facts = worker_module.observe()
    worker_module.guard(facts)
    require(args.controller_input == Path("/inputs/controller-input.json"), "fixed immutable controller path required")
    externally_injected = os.environ.get("CACHY_ASAHI_CONTROLLER_SHA256")
    require(args.controller_input_sha256 == externally_injected, "externally injected controller digest required")
    controller = worker_module.verify_controller(args.controller_input, externally_injected, facts)
    required_recipe = {"build-gate.py", "build-policy.json", "worker-metadata.py", "worker-build.py", "linux-closure.py"} | set(EVIDENCE)
    require(required_recipe <= set(controller["recipe_input_sha256"]), "controller must bind all executed gate/adapter/evidence files")
    for name in required_recipe:
        require(sha(closure.read(HERE / name, 8 * 1024 * 1024)) == controller["recipe_input_sha256"][name], "loaded gate/adapter recipe snapshot differs")
    require(args.policy == HERE / "build-policy.json", "controller-bound policy path required")
    paths = {"source-audit.json": args.source_audit, "cargo-audit.json": args.cargo_audit,
             "build-script-review.json": args.build_script_review, "additional-cargo-licenses.json": args.additional_licenses}
    evidence = {name: closure.read(path, 8 * 1024 * 1024) for name, path in paths.items()}
    require({k: sha(v) for k, v in evidence.items()} == EVIDENCE, "actual evidence file pins differ")
    output = Path("/out/target-metadata")
    require(args.metadata == output / "cargo-metadata.stdout" and args.worker == output / "worker.json"
            and args.cfg == output / "target-cfg.stdout", "fixed fresh metadata evidence paths required")
    worker = closure.load(closure.read(args.worker, 1024 * 1024))
    metadata, cfg = closure.read(args.metadata, 16 * 1024 * 1024), closure.read(args.cfg, 1024 * 1024)
    receipt_gate(worker, controller, facts, metadata, cfg, output, closure.read)
    require(args.manifest.is_relative_to("/tmp") and args.vendor.is_relative_to("/tmp")
            and args.lock == args.manifest.with_name("Cargo.lock"), "private native source/vendor paths required")
    # Verify all 167 original sources before evaluating filtered metadata: the
    # unchanged lock needs private all-target manifests for offline resolution.
    worker_module.preflight(args.manifest, args.vendor, args.cargo_audit)
    manifest, lock = closure.read(args.manifest, 1024 * 1024), closure.read(args.lock, 1024 * 1024)
    source_gate(closure.load(evidence["source-audit.json"]), args.manifest, closure)
    report, sources = closure.validate(metadata, worker, manifest, lock, evidence["cargo-audit.json"], cfg, args.vendor,
                                       supplemental_data=evidence["additional-cargo-licenses.json"], notice_root=args.notice_root)
    script_count = script_gate(closure.load(evidence["build-script-review.json"]),
                               closure.load(evidence["cargo-audit.json"]), sources)
    if getattr(args, "retain_linux_source", False):
        scratch = Path("/tmp/cachy-update-linux-source-" + facts["nonce"])
        projection = Path("/out/linux-source-closure")
        require(not projection.exists() and not projection.is_symlink(), "fresh fixed Linux projection required")
        closure.retain(scratch, report, sources, {"Cargo.lock": lock, "Cargo.toml": manifest,
                       "cargo-audit-all-target.json": evidence["cargo-audit.json"], "metadata.json": metadata,
                       "worker.json": closure.read(args.worker, 1024 * 1024), "target-cfg.txt": cfg})
        shutil.copytree(scratch, projection)
    save_report(output / "selected-closure.json", closure.canonical(report) + b"\n", closure.read)
    return {"schema_version": 1, "decision": "PRIVATE NATIVE COMPILE INPUTS VERIFIED",
            "controller_sha256": externally_injected, "worker_image_id": facts["image_id"],
            "metadata_sha256": sha(metadata), "selected_registry_sources": len(sources),
            "selected_script_candidates": script_count, "original_lock_packages": 168,
            "native_compilation": "NOT RUN", "distribution": "NOT ACCEPTED", "Apple_updater": "NOT ACCEPTED",
            "limits": ["Metadata feature unions are not compilation-unit feature evidence.",
                       "The worker adapter must use its fixed sanitized compile environment and enforce total build limits.",
                       "Controller image/tool provenance is independently authenticated by the outer launcher."]}


def elf_gate(data):
    if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('compiled ELF64 little-endian tray required')
    if struct.unpack_from('<H', data, 18)[0] != 183:
        raise ValueError('aarch64 ELF required')
    offset = struct.unpack_from('<Q', data, 32)[0]
    width, count = struct.unpack_from('<HH', data, 54)
    if width != 56 or not count or offset + count * width > len(data):
        raise ValueError('invalid ELF program headers')
    loads = 0
    for index in range(count):
        kind, flags, file_offset, virtual, physical, file_size, memory_size, alignment = struct.unpack_from(
            '<IIQQQQQQ', data, offset + index * width)
        if kind == 1:
            loads += 1
            if alignment < 16384 or file_offset % 16384 != virtual % 16384:
                raise ValueError('ELF LOAD cannot satisfy 16K alignment')
            if file_offset + file_size > len(data) or file_size > memory_size:
                raise ValueError('ELF LOAD outside file')
    if not loads:
        raise ValueError('ELF LOAD headers absent')



def elf(value):
    """Static byte/header check; no native loader or hardware acceptance."""
    if isinstance(value, (str, Path)):
        value = Path(value).read_bytes()
    elf_gate(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path)
    parser.add_argument("--policy", type=Path, default=HERE / "build-policy.json")
    parser.add_argument("--source-audit", type=Path, default=HERE / "source-audit.json")
    for name in ("metadata", "worker", "cfg", "manifest", "lock", "cargo-audit", "vendor", "build-script-review", "additional-licenses", "controller-input"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--controller-input-sha256")
    parser.add_argument("--notice-root", type=Path)
    parser.add_argument("--retain-linux-source", action="store_true")
    args = parser.parse_args()
    try:
        if args.elf:
            elf(args.elf)
            return
        require(all(getattr(args, name.replace("-", "_")) for name in ("metadata", "worker", "cfg", "manifest", "lock", "cargo-audit", "vendor", "build-script-review", "additional-licenses", "controller-input")), "explicit actual native inputs required")
        policy = json.loads(args.policy.read_bytes())
        policy_check(policy)
        worker = module(policy, "worker-metadata.py")
        closure = module(policy, "linux-closure.py")
        print(json.dumps(compile_inputs(args, policy, worker, closure), sort_keys=True))
    except (ValueError, KeyError, TypeError, OSError) as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
