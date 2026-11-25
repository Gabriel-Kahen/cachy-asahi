# SPDX-License-Identifier: MIT
"""Bind the full Qtbase continuation graph to retained Q3 link measurements."""

import argparse
from collections import Counter
from pathlib import Path
from runpy import run_path
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace


GUI = Path(__file__).resolve().parent.parent / "qt612_gui_16k_link_checkpoint"
CHECKPOINT = SimpleNamespace(**run_path(str(GUI / "inspect_checkpoint.py")))
C, F, G = CHECKPOINT.C, CHECKPOINT.F, CHECKPOINT.G
CORE_READBACK = C.file_pin(6869, "62abf64821e9a9f7f6f23450c5caae045e150a36150122ab0dd86d22b2819193")
GUI_READBACK = C.file_pin(11023, "fe12a973f212ee92cb849a155fdf834a5ac1aad98dff549576f5763c65415d9c")
CONTINUATION = C.file_pin(2078658, "3147ef87084e1075d35abd18d27ed97f47ae0a9287df3c8a7ba4f3b9d2a71f97")
REMAINDER_COUNT = 1216
NINJA_IDLE = b"ninja: no work to do.\n"


def read_graph(manifests, work):
    operands = ("build.ninja", "CMakeFiles/rules.ninja")
    files = {}
    graph = []
    for relative in operands:
        path = manifests / relative
        expected = F.file_record(F.OPERANDS["src/build/" + relative])
        raw, observed = C.read(path, expected["bytes"], expected)
        files[relative] = dict(path=str(path), **observed)
        graph.append(raw)
    flat = F.flatten(*graph)
    targets = F.audit_targets(work, flat)
    streams = {}
    for name in ("gui", "all"):
        target = targets[name]
        argv = [G.NINJA, "-f", "/dev/stdin", "-t", "commands", target["target"]]
        body = F.inspect_tool(work, argv, flat)
        C.need(C.pin(body) == target["transcript"], "Exact selected Ninja command stream required")
        streams[name] = body
    difference = b"".join(CHECKPOINT.difference(streams["gui"], streams["all"]))
    C.need(C.pin(difference) == CONTINUATION and difference.count(b"\n") == REMAINDER_COUNT,
           "Exact Q3 All-minus-QtGui command multiset required")
    return files, targets, difference


def observed_run(path, expected, stage):
    raw, pin = C.read(path, expected["bytes"], expected)
    run = C.json_body(raw, canonical=True)
    C.need(run["kind"] == f"QT{stage.upper()}_LINK_INDEPENDENT_READBACK_V1"
           and run["status"] == f"PASS_EXACT_QT{stage.upper()}_LINK_ONLY"
           and run["phase"] == "complete", "Exact completed original link observation required")
    evidence = run["guest"] if stage == "gui" else run
    logs = evidence["guest_evidence"] if stage == "gui" else run["evidence"]
    metrics = evidence["metrics"]
    peak = run["allocation"]["peak"]
    qemu = run["commands"]["qemu"]
    result = dict(readback=dict(path=str(path), **pin), build_elapsed_ms=metrics["elapsed_ms"],
                  peak_child_rss_kib=metrics["peak_child_rss_kib"], qemu_elapsed_seconds=qemu["elapsed_seconds"],
                  peak_actor_cgroup_bytes=run["host_cgroup_memory_peak_bytes"],
                  peak_watched_tree_allocated_bytes=peak["tree_allocated"], overlay=run["overlay"],
                  original_result_disk=run["result_disk"], original_build_log=logs["build.log"])
    if stage == "gui":
        result["original_inventory"] = logs["inventory.after"]
        result["original_libraries"] = {name: row["pin"] for name, row in evidence["linkage"]["libraries"].items()}
    return result


def dry_run_actions(gui_log, all_log, remainder):
    """Check reported actions, with multiplicity, against the static continuation."""
    C.need(gui_log == NINJA_IDLE, "The prior QtGui target is scheduled to rebuild")
    if all_log == NINJA_IDLE:
        return 0
    available = Counter(remainder.splitlines())
    lines = all_log.splitlines()
    C.need(all_log.endswith(b"\n") and 0 < len(lines) <= sum(available.values()),
           "Expected a finite Ninja dry-run transcript")
    for index, line in enumerate(lines, 1):
        match = G.PROGRESS.fullmatch(line)
        C.need(match is not None and int(match[1]) == index and int(match[2]) == len(lines),
               "Unexpected Ninja dry-run progress")
        command = match[3]
        C.need(available[command] > 0, "Dry run exceeds the pinned continuation graph")
        available[command] -= 1
    return len(lines)


def inspect_dry_run(logs, remainder):
    bodies, refs = {}, {}
    for label, (path, digest) in logs.items():
        cap = 4096 if label == "gui" else len(remainder) + 64 * 1024
        bodies[label], pin = C.external(path, cap, digest)
        refs[label] = dict(path=str(path), **pin)
    return dict(status="CALLER_CAPTURE_MATCHES_STATIC_GRAPH", files=refs,
                reported_actions=dry_run_actions(bodies["gui"], bodies["all"], remainder),
                producer_authenticated=False, timing="NOT MEASURED")


def prepare(manifests, core_readback, gui_readback, logs=None):
    core = observed_run(core_readback, CORE_READBACK, "core")
    gui = observed_run(gui_readback, GUI_READBACK, "gui")
    with TemporaryDirectory(prefix="qtbase-all-graph-") as directory:
        sources, targets, remainder = read_graph(manifests, Path(directory))
    return dict(
        kind="QTBASE_FULL16K_PREFLIGHT_DATA_V1", status="HOLD_UNISSUED",
        authority=None, guest_architecture="aarch64", guest_page_size=16384,
        source_revision=F.Q3_SOURCE, q3_configure_terminal=F.file_record(F.Q3_TERMINAL),
        q3_scratch=F.file_record(F.Q3_SCRATCH),
        graph=dict(manifests=sources, flat=F.file_record(F.GRAPH), targets=targets,
                   continuation=dict(commands=REMAINDER_COUNT, transcript=CONTINUATION,
                                     compiler_edges=targets["all"]["compiles"] - targets["gui"]["compiles"],
                                     scope="STATIC_COMMAND_MULTISET_DIFFERENCE")),
        historical_build_measurements=dict(core=core, gui_increment=gui),
        proposed_guest_commands=dict(
            preexisting_gui=[G.NINJA, "-n", "-v", G.TARGET],
            full_dry_run=[G.NINJA, "-n", "-v", "all"],
            build=["/usr/bin/cmake", "--build", F.BUILD, "--parallel", "1", "--target", "all"]),
        ninja_working_directory=F.BUILD, ninja_status=G.ENV["NINJA_STATUS"],
        dry_run=inspect_dry_run(logs, remainder) if logs else dict(status="NOT RUN", timing="NOT MEASURED"),
        full_build_timing="NOT MEASURED", executable_limits=None, package_and_installed_checks="NOT RUN")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("manifests", "core-readback", "gui-readback"):
        parser.add_argument("--" + name, type=Path, required=True)
    for label in ("gui", "all"):
        parser.add_argument("--" + label + "-dry-run", type=Path)
        parser.add_argument("--" + label + "-dry-run-sha256")
    args = parser.parse_args()
    try:
        refs = (args.gui_dry_run, args.gui_dry_run_sha256, args.all_dry_run, args.all_dry_run_sha256)
        C.need(not any(refs) or all(refs), "Supply both dry-run transcripts and their SHA-256 values")
        logs = {"gui": refs[:2], "all": refs[2:]} if all(refs) else None
        sys.stdout.buffer.write(C.wire(prepare(args.manifests, args.core_readback, args.gui_readback, logs)))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        sys.exit("Full Qtbase preflight refused: " + str(error))


if __name__ == "__main__":
    main()
