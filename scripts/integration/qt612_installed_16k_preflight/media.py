#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Seal one installed Q3 child boot, read-only inputs and empty result."""

import argparse
import os
from pathlib import Path
from runpy import run_path
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
H = SimpleNamespace(**run_path(str(HERE / "owned.py")))
C, F, T, W = H.C, H.F, H.T, H.W
G = SimpleNamespace(**run_path(str(HERE / "guest.py")))
BOOT = C.file_pin(F.Q.BOOT_BYTES, "951bdc40ec6d3c4735d688acda30f153a22019862bc255059b874d9c27e0a858")
RTC_CLOCK = C.file_pin(1344, "fed8c8eabe89ad8cb979994c35dc44ad3e8704f5481c3dd00560192018c504fa")


def copy_archive(path, target, pin):
    before = C.identity(T.ordinary(path).lstat())
    with F.K.F.open_original(path) as source, target.open("xb") as output:
        F.K.F.verify_original(source, path, pin["bytes"])
        remaining = pin["bytes"]
        while remaining:
            chunk = source.read(min(remaining, 1 << 20))
            C.need(chunk, "Short signed archive while staging")
            output.write(chunk)
            remaining -= len(chunk)
        C.need(not source.read(1) and C.identity(os.fstat(source.fileno())) == C.identity(path.lstat()) == before,
               "Signed archive source changed during staging")
    C.read(target, W.INPUT_LIMITS["archive"], pin, collect=False)
    target.chmod(0o444)


def keep(path, data):
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    F.K.save(path, data)


def boot_payload(records, protected):
    paths = "".join(str(path) + "\n" for path in protected).encode() if protected else b"\n"
    C.need(0 < len(paths) <= 128 << 10, "Bounded installed protected path selection required")
    bodies = {
        "guest-init.sh": C.read(HERE / "owned-guest-init.sh", 128 << 10)[0],
        "root-helpers.sh": C.read(H.PACKAGE / "full-guest-init.sh", 128 << 10, H.M.E.COMMON_INIT_PIN)[0],
        "rtc-clock.sh": C.read(HERE.parent / "arm16k_project_lifecycle_rtc/rtc-clock.sh", 128 << 10, RTC_CLOCK)[0],
        "protect.list": paths,
        "source.sha256": H.source_manifest(records),
    }
    bodies["MANIFEST.sha256"] = H.source_manifest({name: C.pin(body) for name, body in bodies.items()})
    return bodies


def prepare(args):
    stage, output = T.ordinary(args.stage), T.ordinary(args.output)
    C.need(not os.path.lexists(output) and not output.is_relative_to(stage) and not output.is_relative_to(H.P.ROOT)
           and output.parent.stat().st_uid == os.getuid() and not output.parent.stat().st_mode & 0o022,
           "Fresh private installed media root required")
    plan_raw, plan_pin = C.external(stage / "inputs/PLAN.json", 64 << 10, args.plan_sha256)
    inventory = T.read(stage / "inputs/expected356.lock", H.P.Q3_INVENTORY, cap=16 << 10)
    plan = W.read_plan(plan_raw, args.plan_sha256, inventory)
    H.clone_id(args.case, args.clone, plan["nonce"])
    C.need(bool(args.protect) == (args.case == "main"), "Main installed case requires selected protected paths")
    protected = G.protected_paths(args.protect) if args.protect else ()
    signed_raw, signed_pin = C.external(args.selection, W.MAX_SELECTION, args.selection_sha256)
    now = int(time.time())
    selected = W.read_selection(signed_raw, args.selection_sha256, args.plan_sha256, now)
    original, pinned = selected["inputs"], {}
    for name, path in (("certificate", args.certificate), ("signature", args.signature)):
        pinned[name] = T.read(path, original[name], cap=W.INPUT_LIMITS[name])
    C.need(W.L.packet_tags(pinned["certificate"]) == [6, 13, 2] and W.L.packet_tags(pinned["signature"]) == [2],
           "Exact public-only TEST certificate and original detached signature required")
    C.need((args.tampered_signature is not None) == (args.case == "tampered_signature"),
           "Use a separately selected tampered signature for that sibling only")
    signature = (T.read(args.tampered_signature, cap=W.INPUT_LIMITS["signature"]) if args.tampered_signature
                 else pinned["signature"])
    C.need(W.L.packet_tags(signature) == [2], "Detached signature packet required for every case")
    C.need(args.archive.name == Path(H.P.ARCHIVE).name, "Expected original installed archive filename")
    C.read(args.archive, W.INPUT_LIMITS["archive"], original["archive"], collect=False)
    handoff, handoff_pin = C.external(args.handoff, 16 << 10, args.handoff_sha256)
    retired, retired_pin = C.external(args.retirement, 16 << 10, args.retirement_sha256)
    runner_raw, _ = C.external(args.runner, 32 << 10, F.RUNNER_PIN["sha256"])
    runner = C.json_body(runner_raw, canonical=True)
    F.Q.runner_shape(runner)
    C.need(C.pin(runner_raw) == F.RUNNER_PIN, "Exact reviewed local runner")
    controls = {"PLAN.json": plan_raw, "SELECTION.json": signed_raw, "expected356.lock": inventory,
                "PACKAGE-HANDOFF.json": handoff, "PACKAGE-RETIREMENT.json": retired}
    media = dict(kind=H.MEDIA_KIND, authority=None, case=args.case, clone=args.clone, plan=plan_pin,
                 selection=signed_pin, handoff=handoff_pin, retirement=retired_pin, runner=runner,
                 signature=C.pin(signature))
    fmt_raw, _ = C.external(args.format_tools, 16 << 10, args.format_tools_sha256)
    tools = run_path(str(F.GUI / "prepare.py"))["Formatting"](F.Q, C.json_body(fmt_raw, canonical=True))
    template = T.ordinary(args.boot_template)
    scratch = Path(plan["baseline"]["scratch"]["path"])
    image = T.ordinary(args.image)
    C.need(not any(output.is_relative_to(path.parent) for path in (template, scratch, image)),
           "Installed output must stay outside original carrier directories")
    C.read(template, BOOT["bytes"], BOOT, collect=False)
    C.read(image, F.LOWER["Image"]["bytes"], F.LOWER["Image"], collect=False)
    staged = {"consumer/" + name: T.read(stage / "inputs" / "consumer" / name, pin, cap=128 << 10)
              for name, pin in plan["consumer"]["files"].items()}
    staged["loader_probe.py"] = T.read(stage / "inputs/loader_probe.py", C.pin(T.read(HERE / "loader_probe.py")),
                                       cap=128 << 10)
    staged["PLAN.json"], staged["SELECTION.json"], staged["expected356.lock"] = plan_raw, signed_raw, inventory
    staged[Path(H.P.CERT).name], staged[args.archive.name + ".sig"] = pinned["certificate"], signature
    config = T.read(stage / "work/pacman.conf", C.pin(H.P.CONFIG.encode()), cap=4096)
    sources = {name: C.read(H.P.ROOT / name, 128 << 10)[0] for name in H.SOURCE_FILES}
    records = {name: C.pin(body) for name, body in sources.items()}
    boot = boot_payload(records, protected)
    media.update(boot_manifest=C.pin(boot["MANIFEST.sha256"])["sha256"],
                 boot_payload={name: C.pin(body) for name, body in boot.items()}, source=records)
    with TemporaryDirectory(prefix="qt-installed-media-", dir=output.parent) as temp:
        work = Path(temp)
        for name, body in controls.items():
            keep(work / "control" / name, body)
        H.verify_controls(work / "control", media, now=now)
        root, payload = work / "capsule", work / "payload"
        root.mkdir(mode=0o700)
        (root / "inputs").mkdir(mode=0o755)
        (root / "templates").mkdir(mode=0o755)
        control = root / "control"
        (work / "control").rename(control)
        control.chmod(0o700)
        for name, body in sources.items():
            keep(root / "source" / name, body)
            keep(payload / "source" / name, body)
        for name, body in staged.items():
            keep(payload / "media" / name, body)
        keep(payload / "pacman.conf", config)
        copy_archive(args.archive, payload / "media" / args.archive.name, original["archive"])
        for path in (payload, *(node for node in payload.rglob("*") if node.is_dir())):
            path.chmod(0o755)
        paths = {name: root / "inputs" / name for name in ("Image", "scratch.raw", "boot.raw", "operands.raw")}
        for name, origin, pin in (("Image", image, F.LOWER["Image"]), ("scratch.raw", scratch, H.P.Q3_SCRATCH),
                                  ("boot.raw", template, BOOT)):
            F.K.clone(origin, paths[name], pin)
        paths["boot.raw"].chmod(0o600)
        role = H.boot_role(media)
        H.M.patch_boot(paths["boot.raw"], tools, role, boot)
        result = root / "templates/result.raw"
        H.M.format_result(result, tools, role)
        data = paths["operands.raw"]
        with data.open("xb") as stream:
            stream.truncate(H.DATA_BYTES)
        tools.run("mke2fs", ["-q", "-F", "-t", "ext4", "-b", "4096", "-L", "QT16K_INST_IN",
                            "-U", H.volume_uuid("operands", args.clone), "-O", "^orphan_file",
                            "-E", "lazy_itable_init=0,lazy_journal_init=0", "-d", payload, data], root)
        tools.run("e2fsck", ["-fn", data], root)
        data.chmod(0o444)
        media["inputs"] = {name: C.read(path, H.DATA_BYTES if name == "operands.raw" else path.lstat().st_size,
                                       collect=False)[1] for name, path in paths.items()}
        media["result"] = C.read(result, H.RESULT_BYTES, collect=False)[1]
        body = C.wire(media)
        digest = C.pin(body)
        H.load_media(body, digest["sha256"])
        keep(root / H.MEDIA_NAME, body)
        C.need(not os.path.lexists(output), "Fresh installed output directory required")
        root.rename(output)
    return dict(status="PASS_INSTALLED_MEDIA_UNISSUED_ONLY", authority=None, case=args.case, clone=args.clone,
                media=digest, installation="NOT_RUN")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("stage", "output", "selection", "handoff", "retirement", "archive", "certificate", "signature",
                 "runner", "boot-template", "image", "format-tools"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("plan", "selection", "handoff", "retirement", "format-tools"):
        parser.add_argument("--" + name + "-sha256", required=True)
    parser.add_argument("--case", choices=H.CASES, required=True)
    parser.add_argument("--clone", required=True)
    parser.add_argument("--protect", action="append", default=[])
    parser.add_argument("--tampered-signature", type=Path)
    try:
        C.need(sys.flags.isolated and sys.dont_write_bytecode and __debug__, "Use isolated unoptimized Python")
        os.umask(0o077)
        sys.stdout.buffer.write(C.wire(prepare(parser.parse_args())))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, KeyboardInterrupt):
        sys.exit("Qtbase installed media preparation refused")


if __name__ == "__main__":
    main()
