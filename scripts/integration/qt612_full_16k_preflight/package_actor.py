# SPDX-License-Identifier: MIT
"""Execute only the separately selected and provisioned Qtbase packaging actor."""

import argparse
import json
import os
from pathlib import Path
from runpy import run_path
import stat
import subprocess
import sys
import time
from types import SimpleNamespace


HERE = Path(__file__).resolve().parent
M = SimpleNamespace(**run_path(str(HERE / "package_media.py")))
A = SimpleNamespace(**run_path(str(HERE / "full_actor.py")))
C, F, E = M.C, M.F, M.E
B, P, T = F.B, F.P, F.T
SOURCE, STAGE, INPUTS, OUT = (Path("/" + name) for name in ("src", "stage", "inputs", "out"))
MEDIA, SELECTION = Path("/media.json"), Path("/selection.json")
ROLE_FLAG = "CACHY_ASAHI_QTBASE16K_PACKAGE_ACTOR"
RESULT_KIND = "QTBASE16K_PACKAGE_ACTOR_RESULT_V1"
PASS = "PASS_UNSIGNED_PACKAGE_FOR_REVIEW"
RESULT_REPORT = "actor-result.json"
CHAIN_CAP = 16 << 10
REPORT_CAP = 16 << 10
FSCK_SECONDS = 60


def runner_plan(role, media):
    limit = role["runtime"]
    paths = {name: P.ref_pin(ref) for name, ref in role["readonly_media"].items()}
    paths |= {"boot.raw": media["boot"], "result.raw": media["result"]}
    profile = dict(kind=P.TOOL_PROFILE_KIND, actor_image=media["runner"]["actor_image"], tools=media["runner"]["tools"])
    policy = P.actor_policy(profile, sum(paths[name]["bytes"] for name in ("Image", "boot.raw", "scratch.raw")))
    backing_cap = limit["child_file_size_cap"]
    result_bytes = role["result_carrier"]["bytes"]
    reports, reserve = 128 << 20, 2 << 30
    allocation = backing_cap + result_bytes + reports
    policy.update(overlay_create=role["overlay_create"], overlay_inspect=role["overlay_inspect"],
                  preparation_readonly_logical_bytes=sum(pin["bytes"] for name, pin in paths.items() if name != "result.raw"),
                  result_disk_bytes=result_bytes, report_allocation_bytes=reports, admission_disk_bytes=allocation + reserve,
                  child_file_size_cap=backing_cap, serial_combined_cap=role["serial"]["maximum"],
                  watched_tree=[str(OUT), allocation, reserve],
                  watched_paths=[[E.CHAIN[0], backing_cap], [role["result_carrier"]["path"], result_bytes]])
    return dict(nonce=role["nonce"], inputs=paths, actor=policy,
                limits={"actor_memory_bytes": limit["actor_memory_bytes"]})


def validate_chain(raw, sizes):
    chain = E.CHAIN
    C.need(0 < len(raw) <= CHAIN_CAP and len(sizes) == len(chain), "Finite package chain receipt required")

    def distinct(fields):
        row = dict(fields)
        C.need(len(row) == len(fields), "Duplicate package chain JSON field")
        return row

    def reject(_):
        raise ValueError("Nonfinite package chain JSON")

    nodes = json.loads(raw, object_pairs_hook=distinct, parse_constant=reject)
    C.need(type(nodes) is list and len(nodes) == 5 and sizes.keys() == {Path(name).name for name in chain},
           "Exact five local package backing nodes required")
    qcow = dict(type="qcow2", data={"compat": "1.1", "compression-type": "zlib",
                                    "lazy-refcounts": False, "refcount-bits": 16,
                                    "corrupt": False, "extended-l2": False})
    for i, (node, name, backing) in enumerate(zip(nodes, chain, (*chain[1:], None), strict=True)):
        eof, capacity = sizes[Path(name).name], (1 << 20 if i == 0 else 4 << 30 if backing else 16 << 30)
        C.need(type(node) is dict and type(eof) is int and 0 < eof <= capacity, "Bounded local package backing required")
        space = node["actual-size"]
        C.need(type(space) is int and 0 < space <= capacity and space % 512 == 0,
               "Expected bounded sector-aligned backing allocation")
        child = {"name": "file", "info": {"filename": name, "format": "file", "actual-size": space,
                 "virtual-size": (eof + 511) // 512 * 512, "children": [], "dirty-flag": False,
                 "format-specific": {"type": "file", "data": {}}}}
        expected = {"filename": name, "format": "qcow2" if backing else "raw", "actual-size": space,
                    "virtual-size": 16 << 30, "children": [child], "dirty-flag": False}
        if backing:
            expected.update({"backing-filename": backing, "full-backing-filename": backing,
                             "backing-filename-format": "qcow2" if i < 3 else "raw", "cluster-size": 65536,
                             "format-specific": qcow})
        C.need(C.wire(node) == C.wire(expected), "Package backing path, format or geometry differs")


def require_absence(role):
    argv = role["qemu_argv"]
    token = argv[argv.index("-name") + 1].encode()
    for _ in range(2):
        deadline = time.monotonic() + 3
        with os.scandir("/proc") as processes:
            for count, entry in enumerate(processes, 1):
                C.need(count <= 131072 and time.monotonic() < deadline, "Package process census exhausted")
                if not entry.name.isdecimal():
                    continue
                node = Path(entry.path)
                try:
                    if node.stat().st_uid != os.getuid():
                        continue
                    with (node / "cmdline").open("rb") as stream:
                        body = stream.read(131073)
                except (FileNotFoundError, ProcessLookupError):
                    continue
                C.need(len(body) <= 131072 and token not in body.split(b"\0"), "Original package QEMU still exists")
        time.sleep(0.02)


def run(role, media, runner):
    policy = runner.actor
    result, overlay = OUT / "result.raw", OUT / "overlay.qcow2"
    C.need(T.ordinary(OUT) == OUT and stat.S_IMODE(OUT.lstat().st_mode) == 0o700
           and {file.name for file in OUT.iterdir()} == {"result.raw"}
           and stat.S_IMODE(B.clean_file(result).st_mode) == 0o600, "Fresh private writable result clone required")
    uuid = role["result_carrier"]["uuid"]
    C.read(result, media["result"]["bytes"], media["result"], collect=False)
    M.verify_result(result, uuid, empty=True)
    M.verify_inputs(INPUTS, role, media)
    runner.verify_tools()
    require_absence(role)
    start = F.capacity(OUT, runner.plan)
    C.need(start["fits"] and runner.runtime.GUARD is None
           and time.time() < runner.issued["expires_utc"], "Current package admission and unused runtime required")
    runner.watch = B.AllocationWatch(runner.runtime, policy, OUT, runner.deadline)
    before = runner.watch.record()
    C.need(before["free"] >= policy["admission_disk_bytes"], "Package admission disk reserve changed")
    runner.runtime.GUARD = lambda: A.poll_allocation(runner.watch)
    try:
        create = runner.phase("overlay-create", role["overlay_create"], 10)
        initial = B.clean_file(overlay).st_size
        F.K.inspect_overlay(overlay, {"bytes": initial}, E.CHAIN[1], "qcow2")
        inspect = runner.phase("overlay-inspect", role["overlay_inspect"], 10)
        chain = T.read(OUT / "overlay-inspect.stdout", cap=CHAIN_CAP)
        sizes = {name: item["bytes"] for name, item in runner.plan["inputs"].items()
                 if name in {Path(node).name for node in E.CHAIN[1:]}}
        validate_chain(chain, sizes | {"overlay.qcow2": initial})
        qemu_seconds = role["times"]["qemu"]
        C.need(time.time() < runner.issued["expires_utc"]
               and time.monotonic() + qemu_seconds + FSCK_SECONDS + 10 < runner.deadline,
               "Package selection or reserved process and fsck window expired")
        qemu = runner.phase("qemu", role["qemu_argv"], qemu_seconds, file_cap=policy["child_file_size_cap"])
        require_absence(role)
        serial = T.read(OUT / "qemu.stdout", cap=policy["serial_combined_cap"])
        status, phase = E.terminal(serial, role["nonce"])
        fsck = runner.phase("fsck-result", role["result_fsck"], FSCK_SECONDS)
        M.verify_result(result, uuid)
        M.verify_inputs(INPUTS, role, media)
        C.need(M.source_records(SOURCE) == media["source"], "Original package actor source changed")
        runner.verify_tools()
        end = F.capacity(OUT, runner.plan)
        C.need(end["free_bytes"] >= policy["watched_tree"][2], "Package actor reserve exhausted")
        overlay_pin = T.read(overlay, cap=policy["child_file_size_cap"], collect=False)
        F.K.inspect_overlay(overlay, overlay_pin, E.CHAIN[1], "qcow2")
        result_pin = T.read(result, cap=policy["result_disk_bytes"], collect=False)
        C.need(overlay_pin["bytes"] >= initial and (status != "PASS"
               or overlay_pin["bytes"] > initial and result_pin != media["result"]),
               "Package PASS requires an original changed child and result")
        after = runner.watch.record()
        report = dict(kind=RESULT_KIND, status=PASS if status == "PASS" else "HOLD", phase=phase,
                      nonce=role["nonce"], scope=role["scope"], plan_sha256=media["plan"]["sha256"],
                      selection_sha256=runner.authority_sha, media_sha256=runner.handoff_sha,
                      result_uuid=uuid, result_disk=result_pin, overlay=overlay_pin, overlay_initial_eof=initial,
                      serial=T.pin(serial), overlay_inspect_stdout=T.pin(chain), tools=runner.tools,
                      overlay_create=create, overlay_inspect=inspect, qemu=qemu, fsck_result=fsck,
                      capacity_before=start, capacity_after=end, watched_tree=policy["watched_tree"],
                      watched_paths=policy["watched_paths"],
                      allocation=dict(before=before, after=after, peak=runner.watch.peak, samples=runner.watch.samples),
                      host_cgroup_memory_peak_bytes=A.cgroup_peak(runner.plan["limits"]["actor_memory_bytes"]),
                      signing="NOT_RUN", installation="NOT_RUN", hardware="NOT_RUN")
        body = C.wire(report)
        C.need(len(body) <= REPORT_CAP, "Finite package actor receipt required")
        path = OUT / RESULT_REPORT
        created = False
        try:
            with path.open("xb") as stream:
                created = True
                stream.write(body)
            runner.watch.record()
        except (OSError, ValueError, KeyboardInterrupt):
            if created:
                path.unlink()
            raise
        return 0 if status == "PASS" else 2
    finally:
        runner.runtime.GUARD = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--selection-sha256", required=True)
    parser.add_argument("--media-sha256", required=True)
    args = parser.parse_args()
    started = time.monotonic()
    try:
        C.need(os.environ.get(ROLE_FLAG) == "1" and sys.flags.isolated and sys.dont_write_bytecode and __debug__,
               "Explicit isolated package actor role required")
        os.umask(0o077)
        F.Q.O.actor_boundary(dict(source=SOURCE, stage=STAGE, inputs=INPUTS, output=OUT, media=MEDIA, selection=SELECTION))
        _, issued, role, _ = M.selected_role(STAGE, args.plan_sha256, SELECTION, args.selection_sha256, int(time.time()))
        media = M.load_media(MEDIA, args.media_sha256, role)
        C.need(M.source_records(SOURCE) == media["source"], "Exact sealed package actor source required")
        plan = runner_plan(role, media)
        A.verify_runtime(plan)
        runner = B.Runner(plan, media, args.media_sha256, args.selection_sha256, issued,
                          started + role["times"]["attach"] - 90)
        return run(role, media, runner)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, KeyboardInterrupt):
        sys.exit("Qtbase package actor refused or held")


if __name__ == "__main__":
    raise SystemExit(main())
