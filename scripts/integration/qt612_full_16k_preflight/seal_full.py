# SPDX-License-Identifier: MIT
"""Prepare an unissued full-target capsule from the retained QtGui checkpoint."""

import argparse
import os
from pathlib import Path
import re
from runpy import run_path
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace


HERE = Path(__file__).resolve().parent
F = SimpleNamespace(**run_path(str(HERE / "full_capsule.py")))
C, Q, K = F.C, F.Q, F.K
FORMATTING = SimpleNamespace(**run_path(str(F.GUI / "prepare.py")))


def stage_source(destination, archived, records):
    for name in sorted(F.SOURCE_FILES):
        inherited = name in Q.SOURCE_FILES
        parent = archived if inherited else Q.ROOT
        expected = Q.pin_ref(records[name]) if inherited else None
        body, _ = C.read(parent / name, 128 * 1024, expected)
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        K.save(target, body)
    for path in destination.rglob("*"):
        if path.is_dir():
            path.chmod(0o555)
    destination.chmod(0o555)
    return F.source_manifest(destination)


def stage_result(path, tools, plan):
    size, uuid = plan["limits"]["result_disk_bytes"], plan["result_uuid"]
    with path.open("xb") as stream:
        stream.truncate(size)
    tools.run("mke2fs", ["-q", "-F", "-t", "ext4", "-b", "4096", "-L", "QT16K_FULL", "-U", uuid,
                         "-O", "^orphan_file", "-E", "lazy_itable_init=0,lazy_journal_init=0", path], path.parent)
    tools.run("e2fsck", ["-fn", path], path.parent)
    C.need(F.result_uuid(path, size) == uuid, "Fresh result UUID required")
    path.chmod(0o444)


def seal(prior, backings, output, nonce, limits, tool_pins):
    prior, output = F.T.ordinary(prior), F.T.ordinary(output)
    originals = dict(backings) | {name: prior / "inputs" / name for name in ("boot.raw", "Image")}
    C.need(set(originals) == F.INPUTS - {"result.raw"} and not os.path.lexists(output)
           and not output.is_relative_to(prior) and not output.is_relative_to(Q.ROOT)
           and re.fullmatch(r"/[A-Za-z0-9_./-]+", str(output)) and output.parent.is_dir()
           and output.parent.stat().st_uid == os.getuid() and not output.parent.stat().st_mode & 0o022,
           "Fresh private output separate from the source and old capsule required")
    old = Q.load_handoff(prior / Q.HANDOFF_LEAF, F.HISTORICAL_HANDOFF)
    old_plan = Q.load_plan(prior / Q.PLAN_LEAF, old["plan"]["sha256"])
    C.need(Q.NONCE.fullmatch(nonce) and nonce[:8] not in {"00000000", old_plan["nonce"][:8]},
           "Distinct full-target boot identity required")
    F.limit_shape(limits)
    pins = F.LOWER | {"boot.raw": old_plan["inputs"]["boot.raw"],
                      "result.raw": C.file_pin(limits["result_disk_bytes"], "0" * 64)}
    for name, path in originals.items():
        F.pinned_file(path, pins[name])
    tools = FORMATTING.Formatting(Q, tool_pins)
    with TemporaryDirectory(prefix="qtbase-full-seal-", dir=output.parent) as temp:
        root = Path(temp) / "capsule"
        root.mkdir(mode=0o700)
        source, inputs, templates = (root / name for name in ("source", "inputs", "templates"))
        for folder in (source, inputs, templates):
            folder.mkdir(mode=0o700)
        records = stage_source(source, prior / "source", old["source"])
        pieces = F.payload(nonce, limits, source, records)
        provisional = F.canonical_plan(nonce, pins, limits, old["runner"], pieces)
        C.need(F.capacity(root, provisional)["fits"], "Staging and runtime reserve are unavailable")
        for name, original in originals.items():
            K.clone(original, inputs / name, pins[name])
        boot = inputs / "boot.raw"
        boot.chmod(0o600)
        FORMATTING.patch_boot(SimpleNamespace(P=F.P, PAYLOAD=F.PAYLOAD, BOOT_BYTES=Q.BOOT_BYTES),
                             tools, boot, nonce, pieces)
        boot.chmod(0o444)
        result = templates / "result.raw"
        stage_result(result, tools, provisional)
        pins = pins | {"boot.raw": C.read(boot, Q.BOOT_BYTES, collect=False)[1],
                       "result.raw": C.read(result, limits["result_disk_bytes"], collect=False)[1]}
        plan = F.canonical_plan(nonce, pins, limits, old["runner"], pieces)
        plan_body = C.wire(plan)
        handoff = dict(kind="QTBASE_FULL16K_HANDOFF_UNISSUED_V1", authority=None, scope=F.SCOPE,
                       source=records, source_tree_sha256=C.pin(C.wire(records))["sha256"],
                       runner=old["runner"], plan=C.pin(plan_body))
        handoff_body = C.wire(handoff)
        digest = C.pin(handoff_body)["sha256"]
        for name, body in {F.PLAN: plan_body, F.HANDOFF: handoff_body, F.GUEST: pieces[F.GUEST],
                           "binding.UNISSUED.json": C.wire(F.unsupplied_selection(handoff, plan, digest))}.items():
            K.save(root / name, body)
        for folder in (inputs, templates):
            folder.chmod(0o555)
        for name, original in originals.items():
            F.pinned_file(original, old_plan["inputs"]["boot.raw"] if name == "boot.raw" else pins[name])
        result = F.preflight(root, digest)
        C.need(not os.path.lexists(output), "Fresh capsule output required")
        root.rename(output)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("qtgui-capsule", "scratch", "core", "gui", "tools", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("tools-sha256", "nonce"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--overlay-file-bytes", type=int, default=F.LEGACY_QEMU_FILE_SIZE_CAP,
                        help="Explicit unissued child overlay cap in bytes")
    args = parser.parse_args()
    try:
        tools = C.json_body(C.external(args.tools, 16 * 1024, args.tools_sha256)[0], canonical=True)
        backings = {"scratch.raw": args.scratch, "core.qcow2": args.core, "gui.qcow2": args.gui}
        limits = F.DEFAULT_LIMITS | {"overlay_file_bytes": args.overlay_file_bytes}
        report = seal(args.qtgui_capsule, backings, args.output, args.nonce, limits, tools)
        sys.stdout.buffer.write(C.wire(report))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        sys.exit("Full Qtbase capsule sealing refused")


if __name__ == "__main__":
    main()
