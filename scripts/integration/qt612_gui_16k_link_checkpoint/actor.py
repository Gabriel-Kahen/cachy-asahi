# SPDX-License-Identifier: MIT
"""Run the issued offline QtGui continuation in its owned QEMU actor."""

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
import time


HERE = Path(__file__).resolve().parent
MIB, GIB = 1 << 20, 1 << 30
OUT, INPUTS, SOURCE = Path("/out"), Path("/inputs"), Path("/src")
HANDOFF, PLAN, SELECTION = (Path("/" + name) for name in ("handoff.json", "plan.json", "selection.json"))
TOP, CORE, RAW = "/out/overlay.qcow2", "/inputs/core.qcow2", "/inputs/scratch.raw"
TERMINAL = b"QTGUI_LINK_TERMINAL "
IMAGE_BYTES = 16 * GIB


def need(condition, message):
    if not condition:
        raise ValueError(message)


def validate_overlay_chain(raw, top_eof, core_eof):
    """Require one empty child and exactly the two pinned local backing nodes."""
    need(type(top_eof) is type(core_eof) is int and 0 < top_eof <= MIB
         and 0 < core_eof <= 4 * GIB and 0 < len(raw) <= 16 << 10, "Finite overlay chain metadata required")

    def distinct(items):
        value = dict(items)
        need(len(value) == len(items), "Duplicate QEMU metadata key")
        return value

    def reject_constant(_):
        raise ValueError("Nonfinite QEMU metadata")

    chain = json.loads(raw, object_pairs_hook=distinct, parse_constant=reject_constant)
    need(type(chain) is list and len(chain) == 3, "Expected exact three-node overlay chain")
    qcow = dict(type="qcow2", data={"compat": "1.1", "compression-type": "zlib",
                                    "lazy-refcounts": False, "refcount-bits": 16,
                                    "corrupt": False, "extended-l2": False})
    nodes = ((TOP, "qcow2", top_eof, MIB, CORE, "qcow2"),
             (CORE, "qcow2", core_eof, 4 * GIB, RAW, "raw"),
             (RAW, "raw", IMAGE_BYTES, IMAGE_BYTES, None, None))
    for row, (path, fmt, eof, ceiling, backing, backing_format) in zip(chain, nodes, strict=True):
        need(type(row) is dict, "Exact local QEMU image node required")
        allocated = row.get("actual-size")
        need(type(allocated) is int and 0 < allocated <= ceiling and allocated % 512 == 0,
             "Finite sector-aligned file allocation required")
        file = {"filename": path, "format": "file", "actual-size": allocated,
                "virtual-size": (eof + 511) // 512 * 512, "children": [], "dirty-flag": False,
                "format-specific": {"type": "file", "data": {}}}
        expected = {"filename": path, "format": fmt, "actual-size": allocated, "virtual-size": IMAGE_BYTES,
                    "children": [{"name": "file", "info": file}], "dirty-flag": False}
        if backing is not None:
            expected.update({"backing-filename": backing, "full-backing-filename": backing,
                             "backing-filename-format": backing_format, "cluster-size": 65536,
                             "format-specific": qcow})
        need(json.dumps(row, sort_keys=True) == json.dumps(expected, sort_keys=True),
             "Exact clean local QEMU file node and backing required: " + path)


def terminal(serial, nonce):
    need(re.fullmatch("[0-9a-f]{32}", nonce) is not None, "Exact QtGui nonce required")
    rows = [line for line in serial.splitlines() if line.startswith(TERMINAL)]
    need(len(rows) == 1, "Exactly one original QtGui guest terminal required")
    marker = re.fullmatch(TERMINAL + nonce.encode("ascii") + rb" (PASS|HOLD) ([a-z][a-z0-9_-]{0,31})", rows[0])
    need(marker is not None and (marker[1] == b"HOLD" or marker[2] == b"complete"),
         "Exact same-nonce QtGui terminal required")
    return marker[1] == b"PASS", marker[2].decode("ascii")


def require_absence(nonce):
    token = ("qtgui-" + nonce).encode("ascii")
    for _ in range(2):
        deadline = time.monotonic() + 3
        with os.scandir("/proc") as entries:
            for count, entry in enumerate(entries, 1):
                need(count <= 131072 and time.monotonic() < deadline, "Owned QEMU census exhausted")
                if not entry.name.isdecimal():
                    continue
                path = Path(entry.path)
                try:
                    if path.stat().st_uid != os.getuid():
                        continue
                    with (path / "cmdline").open("rb") as stream:
                        command = stream.read(131073)
                except (FileNotFoundError, ProcessLookupError):
                    continue
                need(len(command) <= 131072 and token not in command.split(b"\0"), "Surviving owned QtGui QEMU")
        time.sleep(0.02)


def memory_peak(memory_limit):
    try:
        with Path("/sys/fs/cgroup/memory.peak").open() as stream:
            raw = stream.read(64)
    except (FileNotFoundError, PermissionError):
        return None
    need(re.fullmatch(r"[1-9][0-9]{0,15}\n", raw) is not None, "Invalid actor memory peak counter")
    peak = int(raw)
    need(peak <= memory_limit, "Actor memory peak exceeds the inspected cgroup limit")
    return peak


def run(config, runner):
    plan, policy, data, t = runner.plan, runner.actor, runner.data, config.T
    nonce, result = plan["nonce"], OUT / "result.raw"
    need({path.name for path in OUT.iterdir()} == {"result.raw"}
         and stat.S_IMODE(config.B.clean_file(result).st_mode) == 0o600, "Fresh attempt-owned result clone required")
    config.check_pinned_file(result, plan["inputs"]["result.raw"])
    uuid = config.result_uuid(result, policy["result_disk_bytes"])
    need(uuid == plan["result_uuid"], "Exact sealed result UUID required")
    runner.verify_tools()
    runner.verify_inputs()
    core = plan["inputs"]["core.qcow2"]
    config.K.inspect_overlay(INPUTS / "core.qcow2", core, RAW, "raw")
    require_absence(nonce)
    before_capacity = config.capacity(OUT, plan)
    need(before_capacity["fits"] and time.time() < runner.issued["expires_utc"],
         "Fresh QtGui capacity and Root entry required")

    runner.watch = config.B.AllocationWatch(runner.runtime, policy, OUT, runner.deadline)
    before = runner.watch.record()
    need(before["free"] >= policy["admission_disk_bytes"] and runner.runtime.GUARD is None,
         "Unused owned runtime and live disk gate required")
    runner.runtime.GUARD = runner.watch
    try:
        create = runner.phase("overlay-create", policy["overlay_create"], 10)
        overlay = OUT / "overlay.qcow2"
        initial_eof = config.B.clean_file(overlay).st_size
        config.K.inspect_overlay(overlay, {"bytes": initial_eof}, CORE, "qcow2")
        inspect = runner.phase("overlay-inspect", policy["overlay_inspect"], 10)
        inspect_output = t.read(OUT / "overlay-inspect.stdout", cap=16 << 10)
        validate_overlay_chain(inspect_output, initial_eof, core["bytes"])
        need(time.time() < runner.issued["expires_utc"], "Root entry window closed before QEMU")
        qemu = runner.phase("qemu", plan["qemu_argv"], plan["qemu_seconds"], file_cap=policy["child_file_size_cap"])
        require_absence(nonce)
        serial = t.read(OUT / "qemu.stdout", cap=policy["serial_combined_cap"])
        passed, phase = terminal(serial, nonce)
        fsck = runner.phase("fsck-result", ["/usr/bin/e2fsck", "-fn", str(result)], 60)
        need(config.result_uuid(result, policy["result_disk_bytes"]) == uuid, "Original result UUID changed")
        runner.verify_inputs()
        runner.verify_tools()
        config.verify_source(data, SOURCE)
        after_capacity = config.capacity(OUT, plan)
        need(after_capacity["free_bytes"] >= runner.watch.tree[2], "Live reserve fell below the sealed minimum")
        overlay_pin = t.read(overlay, cap=policy["child_file_size_cap"], collect=False)
        config.K.inspect_overlay(overlay, overlay_pin, CORE, "qcow2")
        result_pin = t.read(result, cap=policy["result_disk_bytes"], collect=False)
        need(overlay_pin["bytes"] >= initial_eof, "Original overlay shrank unexpectedly")
        if passed:
            need(overlay_pin["bytes"] > initial_eof and result_pin != plan["inputs"]["result.raw"],
                 "QtGui PASS requires a changed overlay and result disk")
        after = runner.watch.record()
    finally:
        runner.runtime.GUARD = None

    # Preserve the owned runner's original command receipt names so the
    # passive reader can independently join their exact streams.
    report = dict(kind="QTGUI_LINK_ACTOR_RESULT_V1", status="PASS_QTGUI_LINK_FOR_ROOT_REVIEW" if passed else "HOLD",
                  phase=phase, nonce=nonce, authority_sha256=runner.authority_sha, handoff_sha256=runner.handoff_sha,
                  plan_sha256=data["plan"]["sha256"], tools=runner.tools, watched_tree=policy["watched_tree"],
                  watched_paths=policy["watched_paths"], capacity_before=before_capacity, capacity_after=after_capacity,
                  allocation=dict(before=before, after=after, peak=runner.watch.peak, samples=runner.watch.samples),
                  qemu=qemu, serial=t.pin(serial), fsck_result=fsck, overlay_create=create, overlay_inspect=inspect,
                  overlay_inspect_stdout=t.pin(inspect_output), overlay_initial_eof=initial_eof, result_disk=result_pin,
                  overlay=overlay_pin, result_uuid=uuid,
                  host_cgroup_memory_peak_bytes=memory_peak(plan["limits"]["actor_memory_bytes"]),
                  native_Qt_full_build="NOT_RUN", physical_M2="NOT_RUN", Root_acceptance=None)
    body = t.encoded(report)
    need(len(body) <= 16 << 10, "Finite QtGui actor report required")
    with (OUT / "actor-result.json").open("xb") as stream:
        stream.write(body)
    runner.watch.record()
    return 0 if passed else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--handoff-sha256", required=True)
    parser.add_argument("--authority-sha256", required=True)
    args = parser.parse_args()
    need(os.environ.get("CACHY_ASAHI_QTBASE16K_ACTOR") == "1" and sys.flags.isolated
         and sys.dont_write_bytecode and __debug__, "Explicit isolated QtGui actor required")
    started = time.monotonic()
    os.umask(0o077)
    sys.path.insert(0, str(HERE))
    import gui_capsule as config

    config.O.actor_boundary(dict(inputs=INPUTS, output=OUT, handoff=HANDOFF, plan=PLAN, selection=SELECTION))
    data = config.load_handoff(HANDOFF, args.handoff_sha256)
    config.verify_source(data, SOURCE)
    plan = config.load_plan(PLAN, data["plan"]["sha256"])
    config.verify_binding(data, plan)
    issued = config.verify_selection(config.T.read(SELECTION, cap=128 << 10), args.authority_sha256,
                                     data, plan, args.handoff_sha256)
    runner = config.B.Runner(plan, data, args.handoff_sha256, args.authority_sha256, issued,
                             started + plan["attach_seconds"] - 90)
    return run(config, runner)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise SystemExit("QtGui actor refused: " + str(error)) from None
