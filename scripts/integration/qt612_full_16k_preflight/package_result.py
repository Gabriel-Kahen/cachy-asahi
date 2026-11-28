#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read pinned package-only serial and ext4 evidence without host lifecycle authority."""

import argparse
from pathlib import Path
from runpy import run_path
import struct
import sys
from types import SimpleNamespace


E = SimpleNamespace(**run_path(str(Path(__file__).with_name("package_execution.py"))))
C, W = E.C, E.W
TRUE_METRICS = {"log_complete", "natural", "group_empty"}
FALSE_METRICS = {"timeout", "overflow"}


def retained(path, sha, uuid, caps, passed):
    expected = C.file_pin(E.RESULT_BYTES, sha)
    C.read(path, E.RESULT_BYTES, expected, collect=False)
    before = C.identity(path.lstat())
    reader = C.ext4_reader()
    with reader(path, max_nodes=len(caps) + 3, max_file_bytes=max(64 << 10, *(high for _, high in caps.values()))) as fs:
        superblock = fs.read(1024, 1024)
        C.need(struct.unpack_from("<HH", superblock, 56) == (0xEF53, 1) and not fs.incompat & 4
               and superblock[120:136].rstrip(b"\0") == E.RESULT_LABEL.encode() and fs.uuid == uuid,
               "Exact clean package result ext4 with sealed label and UUID required")
        nodes = fs.inventory()["nodes"]
        fixed = {".", "lost+found"}
        folders = fixed | {"evidence"}
        leaves = nodes.keys() - folders
        names = {name.removeprefix("evidence/") for name in leaves}
        C.need(fixed <= nodes.keys() and leaves == {"evidence/" + name for name in names}
               and names <= caps.keys() and (not leaves or "evidence" in nodes)
               and (not passed or names == caps.keys()), "Exact bounded package evidence namespace required")
        for name in folders & nodes.keys():
            row = nodes[name]
            C.need(row["type"] == "directory" and row["uid"] == row["gid"] == 0 and not row["xattrs"]
                   and row["mode"] == (0o755 if name == "." else 0o700),
                   "Unexpected package evidence directory metadata")
        pins, files = {}, {}
        for name in sorted(names):
            row = nodes["evidence/" + name]
            minimum, maximum = caps[name]
            C.need(row["type"] == "file" and row["links"] == 1 and row["mode"] == 0o600 and not row["xattrs"]
                   and row["uid"] == row["gid"] == 0 and (minimum if passed else 0) <= row["size"] <= maximum,
                   "Bounded ordinary package evidence file required")
            pins[name] = C.file_pin(row["size"], row["sha256"])
            # Inventory already streams the archive and hashes it. Collect only the bounded controls and logs.
            if name != W.ARCHIVE:
                inode, raw = fs.inode(row["inode"])
                body = b"".join(fs.chunks(inode, raw))
                C.need(C.pin(body) == pins[name], "Package result evidence changed during readback")
                files[name] = body
    C.read(path, E.RESULT_BYTES, expected, collect=False)
    C.need(C.identity(path.lstat()) == before, "Package result carrier changed during readback")
    return pins, files


def confirm_command(receipt, step, log_pin, body, inventory):
    metric = receipt["metrics"]
    C.need(receipt.keys() == {"log", "metrics"} and receipt["log"] == log_pin == C.pin(body)
           and metric.keys() == TRUE_METRICS | FALSE_METRICS | {"exit_code", "elapsed_ms", "peak_child_rss_kib"}
           and all(metric[key] is True for key in TRUE_METRICS)
           and all(metric[key] is False for key in FALSE_METRICS)
           and type(metric["exit_code"]) is int and metric["exit_code"] == 0
           and type(metric["elapsed_ms"]) is int and 0 <= metric["elapsed_ms"] <= step["seconds"] * 1000
           and type(metric["peak_child_rss_kib"]) is int and 0 <= metric["peak_child_rss_kib"] <= 6 << 20,
           "Package command did not retain its exact natural-success receipt")
    W.check_stream(body, step["expected"], inventory)


def worker_evidence(pins, files, plan, staged, plan_pin, selection_pin, terminal):
    outcome, phase = terminal
    passed = outcome == "PASS"
    if "result.json" not in files:
        C.need(not passed, "Complete package terminal lacks a worker receipt")
        return None
    worker = C.json_body(files["result.json"], canonical=True)
    base = dict(kind="QTBASE16K_PACKAGING_RESULT_V1", scope=W.SCOPE, nonce=plan["nonce"],
                plan_sha256=plan_pin["sha256"], selection_sha256=selection_pin["sha256"], signing="NOT_RUN",
                installation="NOT_RUN", hardware="NOT_RUN")
    C.need(all(worker[key] == value for key, value in base.items())
           and phase in ("package", "retain", "cleanup", "complete"),
           "Worker receipt scope or terminal phase differs")
    actions = plan["worker"]["actions"]
    roles = [step["role"] for step in actions]
    inventory = staged["expected356.lock"]
    commands = worker["commands"]
    succeeded = worker["status"] == "PASS_UNSIGNED_PACKAGE_FOR_REVIEW"
    if succeeded:
        C.need(worker.keys() == base.keys() | {"status", "phase", "commands", "archive", "metadata", "stage_contract"}
               and worker["phase"] == "complete" and phase != "package" and commands.keys() == set(roles),
               "Complete worker receipt does not match the package action sequence")
    else:
        failed = worker["phase"]
        prior = roles.index(failed) if failed in roles else len(roles) if failed == "final-evidence" else 0
        C.need(worker.keys() == base.keys() | {"status", "phase", "commands"} and worker["status"] == "HOLD"
               and failed in {"preflight", "final-evidence", *roles} and not passed
               and commands.keys() == set(roles[:prior]), "Invalid package worker HOLD receipt")
    for step in actions:
        role = step["role"]
        name = role + ".log"
        if role in commands and name in files:
            confirm_command(commands[role], step, pins[name], files[name], inventory)
    if passed:
        C.need(set(files) == pins.keys() - {W.ARCHIVE} and all(role + ".log" in files for role in roles)
               and pins[W.ARCHIVE] == worker["archive"] and pins["stage-contract.json"] == worker["stage_contract"],
               "Complete worker receipt does not bind its retained archive and evidence")
        metadata = W.archive_receipt(files["archive-validation.log"], C.json_body(files["stage-contract.json"]),
                                     pins[W.ARCHIVE], staged["recipe/.SRCINFO"], staged["recipe/PKGBUILD"], inventory,
                                     plan["worker"]["completed_build"]["libraries"])
        C.need(metadata == worker["metadata"], "Original archive metadata digest differs")
    return worker


def readback(staged, plan_sha, selection, selection_sha, serial, serial_sha, result, result_sha):
    plan_raw, plan_pin = C.external(staged / W.PLAN_NAME, 128 * 1024, plan_sha)
    plan = C.json_body(plan_raw, canonical=True)
    authority, selection_pin = C.external(selection, 16 * 1024, selection_sha)
    files = E.staged_inputs(staged, plan)
    # Validate the historical selection at issuance. Passive readback does not renew its validity.
    issued = C.json_body(authority, canonical=True)
    plan, _ = E.validate_package_inputs(plan_raw, files, authority, selection_sha, issued["created_utc"],
                                        historical_readback=True)
    raw, serial_pin = C.external(serial, E.SERIAL_CAP, serial_sha)
    outcome = E.terminal(raw, plan["nonce"])
    pins, evidence = retained(result, result_sha, E.P.result_uuid(plan["nonce"]), E.evidence_caps(plan),
                              outcome[0] == "PASS")
    worker = worker_evidence(pins, evidence, plan, files, plan_pin, selection_pin, outcome)
    return dict(kind="QTBASE16K_PACKAGE_OFFLINE_READBACK_V1", nonce=plan["nonce"], status=outcome[0], phase=outcome[1],
                plan=plan_pin, selection=selection_pin, serial=serial_pin, result=C.file_pin(E.RESULT_BYTES, result_sha),
                evidence=pins, worker=worker, host_retirement="NOT_OBSERVED", signing="NOT_RUN",
                installation="NOT_RUN", hardware="NOT_RUN")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged", type=Path, required=True)
    parser.add_argument("--plan-sha256", required=True)
    for leaf in ("selection", "serial", "result"):
        parser.add_argument("--" + leaf, type=Path, required=True)
        parser.add_argument("--" + leaf + "-sha256", required=True)
    args = parser.parse_args()
    sys.addaudithook(C.audit_fence)
    try:
        sys.stdout.buffer.write(C.wire(readback(args.staged, args.plan_sha256, args.selection, args.selection_sha256,
                                               args.serial, args.serial_sha256, args.result, args.result_sha256)))
    except (OSError, KeyError, TypeError, ValueError):
        sys.exit("Qtbase package offline readback refused")


if __name__ == "__main__":
    main()
