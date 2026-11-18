# SPDX-License-Identifier: MIT
"""Read the original retired QtGui capsule, raw result and linkage evidence offline."""

import argparse
from pathlib import Path
from runpy import run_path
import struct
import sys
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import gui_capsule as Q

S = SimpleNamespace(**run_path(str(HERE / "site.py")))
A = SimpleNamespace(**run_path(str(HERE / "actor.py")))
I = SimpleNamespace(**run_path(str(HERE / "inspect_checkpoint.py")))
C = Q.C


def raw_files(path, pin, uuid, caps, passed):
    before = C.identity(path.lstat())
    C.read(path, pin["bytes"], pin, collect=False)
    with C.ext4_reader()(path, max_nodes=len(caps) + 3, max_file_bytes=max(64 << 10, *caps.values())) as fs:
        header = fs.read(1024, 1024)
        C.need(struct.unpack_from("<HH", header, 56) == (0xEF53, 1) and not fs.incompat & 4
               and header[120:136].rstrip(b"\0") == b"QT16K_GUI" and fs.uuid == uuid,
               "Original clean QtGui result ext4 and exact UUID required")
        nodes = fs.inventory()["nodes"]
        folders = {".", "lost+found", "evidence"}
        leaves = set(nodes) - folders
        names = {leaf.removeprefix("evidence/") for leaf in leaves}
        C.need({".", "lost+found"} <= nodes.keys() and leaves == {"evidence/" + name for name in names}
               and names <= caps.keys() and (not leaves or "evidence" in nodes)
               and (not passed or names == caps.keys()), "Exact finite QtGui result namespace required")
        for folder in folders & nodes.keys():
            row = nodes[folder]
            C.need(row["type"] == "directory" and row["uid"] == row["gid"] == 0 and not row["xattrs"]
                   and row["mode"] == (0o755 if folder == "." else 0o700), "Exact QtGui result directory metadata")
        bodies = {}
        for name in sorted(names):
            row = nodes["evidence/" + name]
            C.need(row["type"] == "file" and row["links"] == 1 and row["mode"] == 0o600 and not row["xattrs"]
                   and row["uid"] == row["gid"] == 0 and (1 if passed else 0) <= row["size"] <= caps[name],
                   "Bounded ordinary QtGui result leaf required")
            inode, raw = fs.inode(row["inode"])
            body = b"".join(fs.chunks(inode, raw))
            C.need(C.pin(body) == C.file_pin(row["size"], row["sha256"]), "Original ext4 leaf changed")
            bodies[name] = body
    C.read(path, pin["bytes"], pin, collect=False)
    C.need(C.identity(path.lstat()) == before, "Original result carrier changed during replay")
    return bodies


def scope_join(root, handoff, plan, handoff_sha, attempt, post_path, post_sha):
    meta, host, host_pin = S.read_attempt(root, handoff, plan, handoff_sha, attempt)
    raw, post_pin = C.external(post_path, 32 << 10, post_sha)
    expected = dict(kind=S.OBSERVATION_KIND, cid=host["cid"], host_result=host_pin,
                    observations=[dict(scope_absent=True, container_absent=True)] * 2,
                    **{key: meta[key] for key in ("nonce", "authority_sha256", "handoff_sha256",
                                                  "plan_sha256", "scope", "scope_group")})
    C.need(raw == C.wire(expected), "Exact original twice-absent QtGui scope observation required")
    return meta, host, post_pin


def capacity_snapshot(row, policy, memory_min, *, first):
    fields = ("free_bytes", "memory_available_bytes", "allowed_cpus")
    minima = ("required_bytes", "minimum_memory_bytes", "minimum_cpus")
    C.need(set(row) == set(fields + minima) | {"fits"}
           and all(type(row[key]) is int and row[key] >= 0 for key in fields + minima)
           and tuple(row[key] for key in minima) == (policy["admission_disk_bytes"], memory_min, 4),
           "Exact live QtGui capacity record required")
    fits = all(row[key] >= row[minimum] for key, minimum in zip(fields, minima, strict=True))
    C.need(row["fits"] is fits and (fits if first else row["free_bytes"] >= policy["watched_tree"][2]),
           "QtGui admission or live reserve evidence differs")


def retained(output, plan, meta, host, digest):
    policy = plan["actor"]
    caps = {"result.raw": policy["result_disk_bytes"], "overlay.qcow2": policy["child_file_size_cap"]}
    phases = (
        ("overlay-create", "overlay_create", policy["overlay_create"], 10, None),
        ("overlay-inspect", "overlay_inspect", policy["overlay_inspect"], 10, None),
        ("qemu", "qemu", plan["qemu_argv"], plan["qemu_seconds"], policy["child_file_size_cap"]),
        ("fsck-result", "fsck_result", ["/usr/bin/e2fsck", "-fn", "/out/result.raw"], 60, None),
    )
    for label, *_ in phases:
        caps.update({label + suffix: policy["serial_combined_cap"] for suffix in (".stdout", ".stderr", ".log")})
        caps[label + ".json"] = 128 << 10
    names = {path.name for path in output.iterdir()}
    if digest is None:
        C.need(0 < host["exit_code"] < 124 and names <= caps.keys(),
               "Incomplete QtGui actor requires an exact naturally retired nonzero exit")
        return dict(status="HOLD_NO_COMPLETE_ACTOR_REPORT",
                    diagnostics={key: C.read(output / key, caps[key], collect=False)[1] for key in sorted(names)})
    C.need(names == caps.keys() | {"actor-result.json"}, "Complete actor result requires exact output namespace")
    raw, actor_pin = C.external(output / "actor-result.json", 16 << 10, digest)
    report = C.json_body(raw, canonical=True)
    C.need(set(report) == C.ACTOR_KEYS and report["kind"] == "QTGUI_LINK_ACTOR_RESULT_V1"
           and all(report[key] == meta[key] for key in ("nonce", "authority_sha256", "handoff_sha256", "plan_sha256"))
           and report["result_uuid"] == plan["result_uuid"] and report["tools"] == policy["profile"]["tools"]
           and report["watched_tree"] == policy["watched_tree"] and report["watched_paths"] == policy["watched_paths"]
           and report["native_Qt_full_build"] == report["physical_M2"] == "NOT_RUN" and report["Root_acceptance"] is None,
           "Exact sealed QtGui actor and tool/resource policy required")
    minimum_memory = plan["limits"]["actor_memory_bytes"] + 2 * Q.K.GIB
    capacity_snapshot(report["capacity_before"], policy, minimum_memory, first=True)
    capacity_snapshot(report["capacity_after"], policy, minimum_memory, first=False)
    commands, streams = {}, {}
    for label, field, argv, seconds, cap in phases:
        commands[label], streams[label] = C.command_receipt(output, label, report[field], argv, seconds, cap,
                                                            policy["serial_combined_cap"])
    C.need(commands["qemu"]["stdout"] == report["serial"]
           and commands["overlay-inspect"]["stdout"] == report["overlay_inspect_stdout"], "Original selected streams differ")
    A.validate_overlay_chain(streams["overlay-inspect"], report["overlay_initial_eof"], plan["inputs"]["core.qcow2"]["bytes"])
    passed, phase = A.terminal(streams["qemu"], plan["nonce"])
    C.need(report["phase"] == phase and report["status"] == ("PASS_QTGUI_LINK_FOR_ROOT_REVIEW" if passed else "HOLD")
           and host["exit_code"] == (0 if passed else 2), "QtGui original serial, actor and site outcomes differ")
    _, overlay = C.read(output / "overlay.qcow2", caps["overlay.qcow2"], report["overlay"], collect=False)
    Q.K.inspect_overlay(output / "overlay.qcow2", overlay, Q.K.CORE_OVERLAY, "qcow2")
    C.check_watch(report["allocation"], policy, overlay["bytes"])
    peak = report["host_cgroup_memory_peak_bytes"]
    C.need(peak is None or type(peak) is int and 0 < peak <= plan["limits"]["actor_memory_bytes"],
           "Expected bounded observed cgroup peak")
    result = report["result_disk"]
    C.need(result["bytes"] == policy["result_disk_bytes"] and
           (not passed or result != plan["inputs"]["result.raw"]), "Fresh original QtGui result disk required")
    return dict(status="LINK_PASS" if passed else "HOLD", phase=phase, actor_result=actor_pin,
                commands=commands, allocation=report["allocation"], result_disk=result, overlay=overlay,
                host_cgroup_memory_peak_bytes=peak)


def readback(handoff_path, handoff_sha, attempt, post_path, post_sha, actor_sha):
    root, handoff, plan = S.load_site(handoff_path, handoff_sha)
    meta, host, post_pin = scope_join(root, handoff, plan, handoff_sha, attempt, post_path, post_sha)
    output = attempt / "output"
    observed = retained(output, plan, meta, host, actor_sha)
    if actor_sha is not None:
        guest_sha = plan["guest_plan"]["sha256"]
        guest = I.G.read_plan(root / "GUI-GUEST-PLAN.json", guest_sha)
        caps = I.evidence_caps(guest)
        passed = observed["status"] == "LINK_PASS"
        if not passed:
            caps |= {"inventory.before.raw": 16384, "inventory.after.raw": 16384, "gui.commands.after": I.G.GUI_COMMANDS[0]}
        bodies = raw_files(output / "result.raw", observed["result_disk"], plan["result_uuid"], caps, passed)
        if passed:
            core = C.read(root / "accepted-core" / Q.K.CORE_ELF, 48 * Q.K.MIB, plan["core_elf"])[0]
            observed["guest"] = I.verify_guest_files(bodies, guest, guest_sha, core)
            observed["status"] = "PASS_EXACT_QTGUI_LINK_ONLY"
        else:
            observed["guest_evidence"] = {name: C.pin(body) for name, body in bodies.items()}
    Q.verify_source(handoff, root / "source")
    return dict(kind="QTGUI_LINK_INDEPENDENT_READBACK_V1", scope=Q.SCOPE, nonce=plan["nonce"],
                plan_sha256=handoff["plan"]["sha256"], post_scope=post_pin, Root_acceptance=None, **observed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("handoff", "attempt", "post-scope"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("handoff-sha256", "post-scope-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--actor-result-sha256")
    args = parser.parse_args()
    sys.addaudithook(C.audit_fence)
    try:
        sys.stdout.buffer.write(C.wire(readback(args.handoff, args.handoff_sha256, args.attempt,
                                               args.post_scope, args.post_scope_sha256, args.actor_result_sha256)))
    except (OSError, ValueError, KeyError, TypeError) as error:
        sys.exit("QtGui original readback refused: " + str(error))


if __name__ == "__main__":
    main()
