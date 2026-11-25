# SPDX-License-Identifier: MIT
"""Read a retired full Qtbase QEMU attempt's original receipts and ext4 evidence."""

import argparse
from pathlib import Path
import stat
import struct
import sys


HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))
import full_capsule as F
import full_guest as G

C = F.C
ACTOR_KIND = "QTBASE_FULL16K_ACTOR_RESULT_V1"
ACTOR_PASS = "PASS_QTBASE_ALL_FOR_REVIEW"
GUEST_PLAN = "FULL-GUEST-PLAN.json"
GIB = 1 << 30


def capacity(row, policy, actor_memory, *, admission):
    measurements = ("free_bytes", "memory_available_bytes", "allowed_cpus")
    minima = ("required_bytes", "minimum_memory_bytes", "minimum_cpus")
    C.need(row.keys() == set(measurements + minima) | {"fits"}
           and all(type(row[key]) is int and row[key] >= 0 for key in measurements + minima)
           and tuple(row[key] for key in minima) == (policy["admission_disk_bytes"], actor_memory + 2 * GIB, 4)
           and row["fits"] is all(row[key] >= row[minimum] for key, minimum in zip(measurements, minima, strict=True))
           and (row["fits"] if admission else row["free_bytes"] >= policy["watched_tree"][2]),
           "Exact full Qtbase capacity receipt required")


def review_actor(output, plan, report_sha, handoff_sha, authority_sha, plan_sha):
    C.need(output.is_absolute() and output == output.resolve(strict=True) and output.is_dir()
           and stat.S_IMODE(output.lstat().st_mode) == 0o700, "Private ordinary original output directory required")
    policy, limits = plan["actor"], plan["limits"]
    stream_cap = policy["serial_combined_cap"]
    phases = (
        ("overlay-create", "overlay_create", policy["overlay_create"], 10, None),
        ("overlay-inspect", "overlay_inspect", policy["overlay_inspect"], 10, None),
        ("qemu", "qemu", plan["qemu_argv"], plan["qemu_seconds"], policy["child_file_size_cap"]),
        ("fsck-result", "fsck_result", ["/usr/bin/e2fsck", "-fn", "/out/result.raw"], 60, None),
    )
    names = {"actor-result.json", "overlay.qcow2", "result.raw"} | {
        label + suffix for label, *_ in phases for suffix in (".json", ".stdout", ".stderr", ".log")}
    C.need({path.name for path in output.iterdir()} == names, "Exact original actor output namespace required")
    raw, report_pin = C.external(output / "actor-result.json", 16 << 10, report_sha)
    report = C.json_body(raw, canonical=True)
    C.need(report.keys() == C.ACTOR_KEYS and report["kind"] == ACTOR_KIND
           and (report["nonce"], report["handoff_sha256"], report["authority_sha256"], report["plan_sha256"])
           == (plan["nonce"], handoff_sha, authority_sha, plan_sha)
           and report["result_uuid"] == plan["result_uuid"] and report["tools"] == policy["profile"]["tools"]
           and report["watched_tree"] == policy["watched_tree"] and report["watched_paths"] == policy["watched_paths"]
           and report["native_Qt_full_build"] == report["physical_M2"] == "NOT_RUN"
           and report["Root_acceptance"] is None, "Exact scoped full Qtbase actor and resource policy required")
    capacity(report["capacity_before"], policy, limits["actor_memory_bytes"], admission=True)
    capacity(report["capacity_after"], policy, limits["actor_memory_bytes"], admission=False)
    commands, streams = {}, {}
    for label, field, argv, seconds, cap in phases:
        commands[label], streams[label] = C.command_receipt(output, label, report[field], argv, seconds, cap, stream_cap)
    C.need(commands["qemu"]["stdout"] == report["serial"]
           and commands["overlay-inspect"]["stdout"] == report["overlay_inspect_stdout"],
           "Original selected command streams differ")
    sizes = {name: plan["inputs"][name]["bytes"] for name in ("gui.qcow2", "core.qcow2", "scratch.raw")}
    initial = report["overlay_initial_eof"]
    F.validate_chain(streams["overlay-inspect"], sizes | {"overlay.qcow2": initial})
    passed, phase = F.terminal(streams["qemu"], plan["nonce"])
    C.need(report["phase"] == phase and report["status"] == (ACTOR_PASS if passed else "HOLD"),
           "Exact matching full Qtbase actor and serial outcomes required")
    path = output / "overlay.qcow2"
    _, overlay = C.read(path, policy["child_file_size_cap"], report["overlay"], collect=False)
    F.K.inspect_overlay(path, overlay, "/inputs/gui.qcow2", "qcow2")
    C.check_watch(report["allocation"], policy, overlay["bytes"])
    C.need(report["allocation"]["before"]["free"] >= policy["admission_disk_bytes"],
           "Owned allocation start lacks the reviewed admission reserve")
    C.need(overlay["bytes"] >= initial and (not passed or overlay["bytes"] > initial),
           "Successful full Qtbase build requires a grown owned overlay")
    result = report["result_disk"]
    C.need(C.check_pin(result, limits["result_disk_bytes"]) and result["bytes"] == limits["result_disk_bytes"]
           and (not passed or result != plan["inputs"]["result.raw"]), "Exact fresh full Qtbase result carrier required")
    peak = report["host_cgroup_memory_peak_bytes"]
    C.need(type(peak) is int and 0 < peak <= limits["actor_memory_bytes"],
           "Expected bounded observed cgroup memory peak")
    return dict(status="ACTOR_PASS" if passed else "HOLD", phase=phase, actor_result=report_pin,
                commands=commands, allocation=report["allocation"], result_disk=result, overlay=overlay,
                host_cgroup_memory_peak_bytes=peak)


def read_evidence(path, pin, uuid, caps, passed, artifact_cap):
    C.read(path, pin["bytes"], pin, collect=False)
    before = C.identity(path.lstat())
    reader = C.ext4_reader()
    options = dict(max_nodes=len(caps) + 3, max_file_bytes=max(64 << 10, *caps.values()))
    with reader(path, **options) as fs:
        sb = fs.read(1024, 1024)
        C.need(struct.unpack_from("<HH", sb, 56) == (0xEF53, 1) and not fs.incompat & 4
               and sb[120:136].rstrip(b"\0") == b"QT16K_FULL" and fs.uuid == uuid,
               "Exact clean full Qtbase ext4 result with sealed UUID and label required")
        nodes = fs.inventory()["nodes"]
    fixed = {".", "lost+found"}
    folders = fixed | {"evidence"}
    leaves = nodes.keys() - folders
    names = {leaf.removeprefix("evidence/") for leaf in leaves}
    C.need(fixed <= nodes.keys() and leaves == {"evidence/" + name for name in names}
           and names <= caps.keys() and (not leaves or "evidence" in nodes)
           and (not passed or names == caps.keys()), "Exact finite full Qtbase evidence namespace required")
    for name in folders & nodes.keys():
        row = nodes[name]
        C.need(row["type"] == "directory" and row["uid"] == row["gid"] == 0 and not row["xattrs"]
               and row["mode"] == (0o755 if name == "." else 0o700),
               "Unexpected full Qtbase evidence directory metadata")
    rows = {name: nodes["evidence/" + name] for name in sorted(names)}
    for name, row in rows.items():
        C.need(row["type"] == "file" and row["links"] == 1 and row["mode"] == 0o600 and not row["xattrs"]
               and row["uid"] == row["gid"] == 0 and (1 if passed else 0) <= row["size"] <= caps[name],
               "Bounded ordinary full Qtbase evidence file required")
    C.need(sum(rows[name]["size"] for name in rows.keys() & set(G.LIBRARIES)) <= artifact_cap
           and sum(row["size"] for row in rows.values()) <= pin["bytes"], "Aggregate full Qtbase evidence exceeds its cap")
    # The frozen reader budgets 2 GiB per handle. Inventory hashes files once;
    # collecting up to 1 GiB of libraries plus logs needs its own bounded pass.
    C.need(C.identity(path.lstat()) == before, "Original result carrier changed during inventory")
    files = {}
    with reader(path, **options) as fs:
        for name, row in rows.items():
            inode, raw = fs.inode(row["inode"])
            body = b"".join(fs.chunks(inode, raw))
            C.need(C.pin(body) == C.file_pin(row["size"], row["sha256"]), "Original ext4 evidence file changed")
            files[name] = body
    C.read(path, pin["bytes"], pin, collect=False)
    C.need(C.identity(path.lstat()) == before, "Original result carrier changed during readback")
    return files


def review_guest(root, output, plan, actor):
    result = output / "result.raw"
    pin = actor["result_disk"]
    C.need(F.result_uuid(result, pin["bytes"]) == plan["result_uuid"], "Original result UUID differs")
    guest_sha = plan["guest_plan"]["sha256"]
    raw, _ = C.read(root / GUEST_PLAN, 4096, plan["guest_plan"])
    guest = G.validate_plan(C.json_body(raw))
    C.need(G.wire_plan(guest) == raw, "Exact canonical full Qtbase guest plan required")
    C.need(guest["nonce"] == plan["nonce"] and all(plan["limits"].get(name) == value
           for name, value in guest["limits"].items()), "Exact sealed guest nonce and limits required")
    passed = actor["status"] == "ACTOR_PASS"
    files = read_evidence(result, pin, plan["result_uuid"], G.evidence_caps(guest), passed,
                          guest["limits"]["artifact_bytes"])
    if passed:
        return G.verify_evidence(files, guest, guest_sha)
    worker = None
    if "result.json" in files:
        worker = C.json_body(files["result.json"], canonical=True)
        base = dict(kind=G.RESULT_KIND, nonce=plan["nonce"], plan_sha256=guest_sha, target=G.TARGET)
        success = worker == (base | dict(status="PASS", phase="complete"))
        phase = worker["phase"]
        hold = (type(phase) is str and phase in G.FAILURE_CODES
                and worker == (base | dict(status="HOLD", phase=phase, failure_code=G.FAILURE_CODES[phase])))
        C.need(actor["phase"] in ("build", "retain", "cleanup") and (success or hold),
               "Worker evidence differs from the sealed plan or outer HOLD phase")
    return dict(status="HOLD", worker=worker, evidence={name: C.pin(body) for name, body in files.items()})


def readback(root, handoff_sha, authority_path, authority_sha, output, actor_sha):
    handoff, plan = F.load_capsule(root, handoff_sha)
    authority_raw, authority_pin = C.external(authority_path, 128 << 10, authority_sha)
    F.verify_selection(authority_raw, authority_sha, handoff, plan, handoff_sha, live=False)
    F.verify_source(root / "source", handoff)
    F.verify_inputs(root / "inputs", plan)
    actor = review_actor(output, plan, actor_sha, handoff_sha, authority_sha, handoff["plan"]["sha256"])
    guest = review_guest(root, output, plan, actor)
    F.verify_source(root / "source", handoff)
    return dict(kind="QTBASE_FULL16K_INDEPENDENT_READBACK_V1", nonce=plan["nonce"],
                status="PASS_EXACT_EMULATED_QTBASE_ALL_BUILD" if actor["status"] == "ACTOR_PASS" else "HOLD",
                handoff_sha256=handoff_sha, plan_sha256=handoff["plan"]["sha256"], authority=authority_pin,
                actor=actor, guest=guest, outer_container_and_scope_retirement="NOT_OBSERVED", Root_acceptance=None,
                native_Qt_full_build="NOT_RUN", installation="NOT_RUN", physical_M2="NOT_RUN")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("capsule", "authority", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("handoff-sha256", "authority-sha256", "actor-result-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    sys.addaudithook(C.audit_fence)
    try:
        report = readback(args.capsule, args.handoff_sha256, args.authority, args.authority_sha256,
                          args.output, args.actor_result_sha256)
        sys.stdout.buffer.write(C.wire(report))
        return 0 if report["status"] == "PASS_EXACT_EMULATED_QTBASE_ALL_BUILD" else 2
    except (OSError, ValueError, KeyError, TypeError):
        sys.exit("Full Qtbase readback refused")


if __name__ == "__main__":
    sys.exit(main())
