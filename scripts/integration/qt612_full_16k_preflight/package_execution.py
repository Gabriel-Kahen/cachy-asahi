#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Derive a passive role and boot-file map for a future owned Qt packaging actor."""

import argparse
from pathlib import Path
import re
from runpy import run_path
import sys
import time
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
F = SimpleNamespace(**run_path(str(HERE / "full_capsule.py")))
W = SimpleNamespace(**run_path(str(HERE / "package_guest.py")))
C, P = F.C, F.P
BOOT_DIR = "/qtbase-package"
SCRATCH_UUID = F.K.F.SCRATCH_UUID
RESULT_LABEL = "QT16K_PKG"
RESULT_BYTES = 1 << 30
WORKER_DEADLINE = 3300
QEMU_SECONDS = 3600
ATTACH_SECONDS = 3900
SERIAL_CAP = 1 << 20
COMMON_INIT_PIN = C.file_pin(12843, "cd7a48f5cd16011501508ff2bf99fd724e1f11ba9725cb2a000fd7bfd87fc9f8")
TERMINAL = b"QTBASE_PACKAGE16K_TERMINAL"
PHASES = ("boot", "storage", "package", "retain", "cleanup")
CHAIN = ("/out/overlay.qcow2", "/inputs/complete.qcow2", "/inputs/gui.qcow2", "/inputs/core.qcow2", "/inputs/scratch.raw")
READONLY_BACKING_CAPS = {"complete.qcow2": 8 << 30, "gui.qcow2": 4 << 30, "core.qcow2": 4 << 30,
                         "scratch.raw": 16 << 30}


def evidence_caps(plan):
    steps = plan["worker"]["actions"]
    C.need(steps == W.packaging_sequence(steps[1]["argv"][2:]), "Expected exact package-only actions")
    caps = {step["role"] + ".log": (int(bool(step["expected"]) and not step["expected"].get("empty")),
                                   step["combined_stream_cap"]) for step in steps}
    caps |= {W.ARCHIVE: (1, W.FILE_CAP), "stage-contract.json": (1, W.STREAM_CAP),
             "result.json": (1, 64 << 10)}
    C.need(len(caps) == 13 and sum(maximum for _, maximum in caps.values()) + (8 << 20) <= RESULT_BYTES,
           "Container result carrier cannot hold the package evidence budget")
    return caps


def caps_bytes(plan):
    return "".join(f"{name} {minimum} {maximum}\n"
                   for name, (minimum, maximum) in sorted(evidence_caps(plan).items())).encode()


def manifest_bytes(files):
    C.need(len(files) == 27 and all(re.fullmatch(
        r"(?:CAPS\.tsv|guest-init\.sh|full-guest-init\.sh|packaging/(?:recipe/)?[A-Za-z0-9._-]{1,127})", name)
        and Path(name).name not in (".", "..") and 0 < len(body) <= 128 * 1024 for name, body in files.items()),
           "Exact finite package boot manifest required")
    return "".join(f"{C.pin(body)['sha256']}  {name}\n" for name, body in sorted(files.items())).encode()


def staged_inputs(staged, plan):
    rooted = staged.resolve(strict=True)
    expected = plan["staging_files"]
    root_leaves = {"expected356.lock", "configure-dependencies.list", "metadata-projection.json",
                   "package_checks.py", "package_guest.py", "full_guest.py", "guest_link.py"}
    C.need(staged.is_absolute() and staged == rooted and type(expected) is dict and len(expected) == 22
           and {name for name in expected if "/" not in name} == root_leaves
           and (staged / "recipe").resolve(strict=True) == staged / "recipe",
           "Exact ordinary package staging directory required")
    C.need({path.name for path in staged.iterdir()} == {"recipe", W.PLAN_NAME} | root_leaves
           and {path.name for path in (staged / "recipe").iterdir()} ==
           {Path(name).name for name in expected if Path(name).parent == Path("recipe")},
           "Exact unissued package staging namespace required")
    files = {}
    for name, record in expected.items():
        C.need(re.fullmatch(r"(?:recipe/)?[A-Za-z0-9._-]{1,127}", name) and Path(name).name not in (".", ".."),
               "Unexpected package staged leaf")
        files[name] = C.read(staged / name, 128 * 1024, record)[0]
    return files


def boot_bundle(plan_raw, files, authority_raw, authority_sha, now):
    plan = C.json_body(plan_raw, canonical=True)
    plan_pin, selection_pin = C.pin(plan_raw), C.pin(authority_raw)
    C.need(selection_pin["sha256"] == authority_sha, "Exact external package selection pin required")
    issued = W.selection(authority_raw, plan, plan_pin["sha256"], now)
    C.need(W.pair(files["package_checks.py"]) == W.PACKAGE_CHECKER_PIN
           and files["package_guest.py"] == C.read(HERE / "package_guest.py", 128 * 1024)[0],
           "Expected the reviewed package worker and normal archive validator")
    full = W.module(files["full_guest.py"], Path("full_guest.py"), W.FULL_GUEST_PIN)
    guest = W.module(files["guest_link.py"], Path("guest_link.py"), full.SIDECAR_PIN)
    W.validate_stage_plan(plan, guest, full, files)
    C.need(plan["staging_files"] == {name: C.pin(body) for name, body in files.items()},
           "Selected boot payload differs from the staged plan")
    boot = {"CAPS.tsv": caps_bytes(plan),
            "guest-init.sh": C.read(HERE / "package-guest-init.sh", 128 * 1024)[0],
            "full-guest-init.sh": C.read(HERE / "full-guest-init.sh", 128 * 1024, COMMON_INIT_PIN)[0],
            "packaging/" + W.PLAN_NAME: plan_raw, "packaging/" + W.SELECTION_NAME: authority_raw}
    boot |= {"packaging/" + name: body for name, body in files.items()}
    boot["MANIFEST.sha256"] = manifest_bytes(boot)
    return plan, issued, boot


def role_descriptor(plan, boot):
    nonce = plan["nonce"]
    plan_pin = C.pin(boot["packaging/" + W.PLAN_NAME])
    selection_pin = C.pin(boot["packaging/" + W.SELECTION_NAME])
    manifest = C.pin(boot["MANIFEST.sha256"])
    result_uuid = P.result_uuid(nonce)
    inputs = plan["readonly_media"]
    C.need(inputs.keys() == {"Image", "scratch.raw", "core.qcow2", "gui.qcow2", "complete.qcow2"}
           and {name: P.ref_pin(inputs[name]) for name in F.LOWER} == F.LOWER,
           "Exact already reviewed immutable backings required")
    caps = READONLY_BACKING_CAPS | {"Image": F.LOWER["Image"]["bytes"]}
    for name, operand in inputs.items():
        P.ref_shape(operand, caps[name])
        C.need(operand["bytes"] > 0, "Empty package backing refused")
    C.need(plan["fresh_child"] == dict(path=CHAIN[0], backing=CHAIN[1], backing_format="qcow2",
                                      storage="fresh-writable-child-only"), "Fresh package child contract differs")
    template = plan["source_evidence"]["boot_template"]
    P.ref_shape(template, F.Q.BOOT_BYTES)
    C.need(template["bytes"] == F.Q.BOOT_BYTES, "Expected exact original disposable boot template size")
    fields = dict(nonce=nonce, manifest=manifest["sha256"], plan=plan_pin["sha256"],
                  selection=selection_pin["sha256"], scratch_uuid=SCRATCH_UUID, result_uuid=result_uuid,
                  result_bytes=RESULT_BYTES, deadline=WORKER_DEADLINE)
    append = P.boot_cmdline(nonce, BOOT_DIR + "/guest-init.sh") + "".join(
        f" cachy_qt_pkg_{key}={value}" for key, value in fields.items())
    argv = P.vm_argv("/inputs/Image", append, "qtbase-package-" + nonce,
                    (("boot", "file=/inputs/boot.raw,format=raw,readonly=on"),
                     ("scratch", f"file={CHAIN[0]},format=qcow2,readonly=off,discard=ignore"),
                     ("result", "file=/out/result.raw,format=raw,readonly=off")))
    argv[argv.index("-m") + 1] = "6144"
    return dict(kind="QTBASE16K_PACKAGE_EXECUTION_ADAPTER_V1", authority=None, scope=W.SCOPE,
                claim="package-build.claim", nonce=nonce, plan=plan_pin, selection=selection_pin,
                readonly_media=inputs, boot_template=template, boot_directory=BOOT_DIR,
                boot_subdirectories=["packaging", "packaging/recipe"], boot_payload={
                    name: C.pin(body) | {"mode": 0o555 if name == "guest-init.sh" else 0o444}
                    for name, body in sorted(boot.items())},
                result_carrier=dict(path="/out/result.raw", bytes=RESULT_BYTES, uuid=result_uuid, label=RESULT_LABEL),
                evidence_caps={name: dict(minimum=minimum, maximum=maximum)
                               for name, (minimum, maximum) in evidence_caps(plan).items()},
                chain=list(CHAIN),
                overlay_create=["/usr/bin/qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", CHAIN[1], CHAIN[0]],
                overlay_inspect=["/usr/bin/qemu-img", "info", "-f", "qcow2", "--output=json", "--backing-chain", CHAIN[0]],
                result_fsck=["/usr/bin/e2fsck", "-fn", "/out/result.raw"],
                serial=dict(path="/out/qemu.stdout", maximum=SERIAL_CAP),
                qemu_argv=argv, times=dict(worker_uptime=WORKER_DEADLINE, qemu=QEMU_SECONDS, attach=ATTACH_SECONDS,
                                         scope_stop_grace=360),
                runtime=dict(actor_memory_bytes=8 << 30, guest_memory_bytes=6 << 30, cpus=4, network="none",
                             actor_no_swap=True, child_file_size_cap=4 << 30),
                host_adapter="REQUIRES_ROLE_AWARE_OWNED_SITE", packaging="NOT_RUN", installation="NOT_RUN")


def terminal(raw, nonce):
    C.need(W.NONCE.fullmatch(nonce), "Exact packaging nonce required")
    prefix = TERMINAL + b" "
    rows = [line for line in raw.splitlines() if line.startswith(prefix)]
    C.need(len(rows) == 1, "Expected one original package guest terminal")
    found = re.fullmatch(prefix + nonce.encode() + rb" (PASS|HOLD) ([a-z]+)", rows[0])
    C.need(found is not None and (found[2] == b"complete" if found[1] == b"PASS"
                                  else found[2].decode() in PHASES), "Package guest terminal scope or phase differs")
    return found[1].decode(), found[2].decode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged", type=Path, required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--selection-sha256", required=True)
    args = parser.parse_args()
    sys.addaudithook(C.audit_fence)
    try:
        body, _ = C.external(args.staged / W.PLAN_NAME, 128 * 1024, args.plan_sha256)
        raw, _ = C.external(args.selection, 16 * 1024, args.selection_sha256)
        files = staged_inputs(args.staged, C.json_body(body, canonical=True))
        plan, _, bundle = boot_bundle(body, files, raw, args.selection_sha256, int(time.time()))
        sys.stdout.buffer.write(C.wire(role_descriptor(plan, bundle)))
    except (OSError, KeyError, TypeError, ValueError):
        sys.exit("Qtbase packaging execution adapter refused")


if __name__ == "__main__":
    main()
