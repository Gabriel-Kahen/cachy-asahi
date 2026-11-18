# SPDX-License-Identifier: MIT
"""Read an exact graph delta or the finite guest evidence of the QtGui checkpoint."""

import argparse
from collections import Counter
from pathlib import Path
from runpy import run_path
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
K = SimpleNamespace(**run_path(str(HERE / "continuation.py")))
C, F = K.C, K.F
ELF = SimpleNamespace(**run_path(str(HERE / "elf_readback.py")))
G = SimpleNamespace(**run_path(str(HERE / "guest_link.py")))
DELTA = C.file_pin(701521, "c446771c44d849c4d04d822341d2ad74c0f80c05937add19f4347cf25b862e5e")
ALIASES = b"libQt6Gui.so -> libQt6Gui.so.6\nlibQt6Gui.so.6 -> libQt6Gui.so.6.12.0\n"
DSOS = ("libQt6Gui.so.6.12.0", "libQt6DBus.so.6.12.0", "libmd4c.so.0.5.3")


def difference(core, gui):
    inherited = Counter(core.splitlines(keepends=True))
    C.need(inherited <= Counter(gui.splitlines(keepends=True)), "Exact Core closure must be contained in Gui")
    extra = []
    for command in gui.splitlines(keepends=True):
        if inherited[command]:
            inherited[command] -= 1
        else:
            extra.append(command)
    return extra


def graph(manifests):
    rows = (("build.ninja", "src/build/build.ninja"), ("CMakeFiles/rules.ninja", "src/build/CMakeFiles/rules.ninja"))
    graph_input = F.flatten(*(C.read(manifests / leaf, F.OPERANDS[key][0], F.file_record(F.OPERANDS[key]))[0]
                              for leaf, key in rows))
    with TemporaryDirectory(prefix="qtgui-graph-") as directory:
        work = Path(directory)
        verified = F.audit_targets(work, graph_input)
        streams = []
        for key in ("core", "gui"):
            target = verified[key]
            body = F.inspect_tool(work, ["/usr/bin/ninja", "-f", "/dev/stdin", "-t", "commands", target["target"]],
                                  graph_input)
            C.need(C.pin(body) == target["transcript"], "Exact retained command stream required")
            streams.append(body)
    delta = difference(*streams)
    C.need(C.pin(b"".join(delta)) == DELTA and len(delta) == 318, "QtGui incremental graph projection differs")
    return dict(status="EXACT_Q3_QTGUI_GRAPH_DELTA", core=verified["core"], gui=verified["gui"],
                extra_commands=len(delta), extra_compiler_edges=verified["gui"]["compiles"] - verified["core"]["compiles"],
                incremental_transcript=DELTA, incremental_run="NOT_RUN")


def guest_result(evidence, guest_plan, guest_sha, result_sha, accepted_core):
    plan = G.read_plan(guest_plan, guest_sha)
    raw, result_pin = C.external(evidence / "result.json", 4096, result_sha)
    result = C.json_body(raw, canonical=True)
    C.need(result == dict(kind="QTGUI_LINK_GUEST_RESULT_V1", status="PASS", phase="complete",
                          plan_sha256=guest_sha, nonce=plan["nonce"], core=plan["core"], target=K.TARGET),
           "Exact successful original guest outcome required")
    cap = {"inventory.before": G.INVENTORY[0], "inventory.after": G.INVENTORY[0],
           "core.commands": G.CORE_COMMANDS[0], "gui.commands": G.GUI_COMMANDS[0],
           "gui.link-command": G.GUI_LINK[0], "core-dry-run.log": 4096,
           "gui-dry-run.log": G.GUI_COMMANDS[0] + 64 * 1024, "build.log": plan["limits"]["build_log_bytes"],
           "metrics.json": 4096, "aliases.txt": len(ALIASES)}
    C.need(evidence.is_absolute() and evidence == evidence.resolve(strict=True)
           and {p.name for p in evidence.iterdir()} == set(cap) | set(DSOS) | {"result.json"},
           "Exact finite QtGui guest evidence directory required")
    files = {name: C.read(evidence / name, size)[0] for name, size in cap.items()}
    C.need(all(F.pin(files[name]) == expected for name, expected in (
        ("inventory.before", G.INVENTORY), ("inventory.after", G.INVENTORY), ("core.commands", G.CORE_COMMANDS),
        ("gui.commands", G.GUI_COMMANDS), ("gui.link-command", G.GUI_LINK)))
        and files["core-dry-run.log"] == b"ninja: no work to do.\n" and files["aliases.txt"] == ALIASES
        and bool(files["build.log"]), "Exact pinned graph, inventory, alias chain and build log required")
    metrics = C.json_body(files["metrics.json"], canonical=True)
    steps = G.dry_run_steps(files["gui-dry-run.log"], files["core.commands"], files["gui.commands"], files["gui.link-command"])
    C.need(set(metrics) == {"exit_code", "elapsed_ms", "peak_child_rss_kib", "log_complete", "natural",
                            "group_empty", "timeout", "overflow", "dry_run_steps"}
           and type(metrics["exit_code"]) is int and metrics["exit_code"] == 0
           and type(metrics["dry_run_steps"]) is int and metrics["dry_run_steps"] == steps
           and type(metrics["elapsed_ms"]) is int and 0 < metrics["elapsed_ms"] <= plan["limits"]["guest_build_seconds"] * 1000
           and type(metrics["peak_child_rss_kib"]) is int and metrics["peak_child_rss_kib"] > 0
           and metrics["log_complete"] is metrics["natural"] is metrics["group_empty"] is True
           and metrics["timeout"] is metrics["overflow"] is False, "Exact natural bounded guest result required")
    left, libraries = plan["limits"]["artifact_bytes"], {}
    for name in DSOS:
        libraries[name], pin = C.read(evidence / name, min(left, ELF.MAX_DSO))
        left -= pin["bytes"]
    core, _ = C.read(accepted_core, 48 * K.MIB, plan["core"])
    linkage = ELF.verify_link(libraries[DSOS[0]], core, libraries[DSOS[1]], libraries[DSOS[2]],
                              accepted_core=plan["core"])
    return dict(status="VERIFIED_QTGUI_GUEST_LINK_EVIDENCE", result=result_pin, metrics=metrics, linkage=linkage,
                guest_evidence={name: C.pin(body) for name, body in (files | libraries).items()},
                Root_acceptance=None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    graphs = sub.add_parser("graph")
    graphs.add_argument("--manifests", type=Path, required=True)
    result = sub.add_parser("guest-result")
    for name in ("evidence", "guest-plan", "accepted-core"):
        result.add_argument("--" + name, type=Path, required=True)
    for name in ("guest-plan-sha256", "result-sha256"):
        result.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        if args.mode == "graph":
            selected = graph(args.manifests)
        else:
            sys.addaudithook(C.audit_fence)
            selected = guest_result(args.evidence, args.guest_plan, args.guest_plan_sha256,
                                    args.result_sha256, args.accepted_core)
        sys.stdout.buffer.write(C.wire(selected))
    except (OSError, ValueError, KeyError, TypeError) as error:
        sys.exit("QtGui checkpoint refused: " + str(error))


if __name__ == "__main__":
    main()
