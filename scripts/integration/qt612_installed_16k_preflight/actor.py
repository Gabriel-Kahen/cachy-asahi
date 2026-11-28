#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run one separately selected installed Q3 child in the pinned Qt actor."""

import argparse
import os
from pathlib import Path
from runpy import run_path
import stat
import subprocess
import sys
import time
from types import SimpleNamespace

H = SimpleNamespace(**run_path(str(Path(__file__).with_name("owned.py"))))
C, F, B = H.C, H.F, H.F.B
A = SimpleNamespace(**run_path(str(H.PACKAGE / "full_actor.py")))
K = SimpleNamespace(**run_path(str(H.PACKAGE / "package_actor.py")))
SOURCE, INPUTS, OUT, STAGE = map(Path, ("/src", "/inputs", "/out", "/stage"))
MEDIA, AUTHORITY = Path("/media.json"), Path("/selection.json")


def runner_plan(media):
    runner = media["runner"]
    profile = dict(kind=F.P.TOOL_PROFILE_KIND, actor_image=runner["actor_image"], tools=runner["tools"])
    policy = F.P.actor_policy(profile, sum(media["inputs"][key]["bytes"] for key in ("Image", "boot.raw", "scratch.raw")))
    envelope = H.WRITER_CAP + H.RESULT_BYTES + (128 << 20)
    policy.update(result_disk_bytes=H.RESULT_BYTES, child_file_size_cap=H.WRITER_CAP,
                  admission_disk_bytes=envelope + (2 << 30), watched_tree=[str(OUT), envelope, 2 << 30],
                  watched_paths=[[str(OUT / "overlay.qcow2"), H.WRITER_CAP], [str(OUT / "result.raw"), H.RESULT_BYTES]])
    return dict(nonce=media["clone"], actor=policy, inputs=media["inputs"] | {"result.raw": media["result"]},
                limits={"actor_memory_bytes": H.ACTOR_BYTES})


def run(media, plan, issued, media_sha, authority_sha, *, started):
    runner = B.Runner(runner_plan(media), media, media_sha, authority_sha, issued, started + H.ATTACH_SECONDS - 90)
    A.verify_runtime(runner.plan)
    runner.verify_tools()
    H.verify_source(SOURCE, media["source"])
    runner.verify_inputs()
    H.M.verify_boot(INPUTS / "boot.raw", H.boot_role(media))
    result = OUT / "result.raw"
    overlay = OUT / "overlay.qcow2"
    C.need({path.name for path in OUT.iterdir()} == {result.name}
           and stat.S_IMODE(B.clean_file(result).st_mode) == 0o600, "Fresh installed writable result clone required")
    C.read(result, H.RESULT_BYTES, media["result"], collect=False)
    uuid = F.P.result_uuid(media["clone"])
    H.M.verify_result(result, uuid, empty=True)
    C.need(F.capacity(OUT, runner.plan)["fits"] and runner.runtime.GUARD is None,
           "Fresh installed actor host capacity and unused runtime required")
    runner.watch = B.AllocationWatch(runner.runtime, runner.actor, OUT, runner.deadline)
    runner.runtime.GUARD = lambda: A.poll_allocation(runner.watch)
    try:
        create = runner.phase("overlay-create", runner.actor["overlay_create"], 10)
        initial = B.clean_file(overlay).st_size
        inspect = runner.phase("overlay-inspect", runner.actor["overlay_inspect"], 10)
        chain = C.read(OUT / "overlay-inspect.stdout", 16 << 10)[0]
        B.validate_empty_overlay(chain, initial)
        epoch = int(time.time())
        C.need(epoch < issued["expires_utc"] and time.monotonic() + H.QEMU_SECONDS + 75 < runner.deadline,
               "Installed entry window or cleanup reserve expired")
        boot = H.role(plan["nonce"], media["case"], media["clone"], media["boot_manifest"],
                      media["plan"]["sha256"], media["selection"]["sha256"], media["signature"]["sha256"], epoch)
        K.require_absence(boot)
        qemu = runner.phase("qemu", boot["qemu_argv"], H.QEMU_SECONDS, file_cap=H.WRITER_CAP)
        K.require_absence(boot)
        serial, serial_pin = C.read(OUT / "qemu.stdout", 1 << 20)
        status = H.terminal(serial, media["clone"])
        fsck = runner.phase("fsck-result", ["/usr/bin/e2fsck", "-fn", str(result)], 60)
        H.M.verify_result(result, uuid)
        runner.verify_inputs()
        H.verify_source(SOURCE, media["source"])
        runner.verify_tools()
        _, child = C.read(overlay, H.WRITER_CAP, collect=False)
        F.K.inspect_overlay(overlay, child, "/inputs/scratch.raw", "raw")
        _, result_pin = C.read(result, H.RESULT_BYTES, collect=False)
        C.need(status != "PASS" or child["bytes"] > initial and result_pin != media["result"],
               "Installed PASS requires a changed child and result carrier")
        summary = dict(kind=H.RESULT_KIND, case=media["case"], clone=media["clone"], status=status,
                       media_sha256=media_sha, authority_sha256=authority_sha, plan=media["plan"],
                       selection=media["selection"], qemu_argv=boot["qemu_argv"], qemu=qemu, serial=serial_pin,
                       fsck=fsck, create=create, inspect=inspect, overlay=child, result=result_pin,
                       result_uuid=uuid, allocation_peak=runner.watch.peak)
        body = C.wire(summary)
        C.need(len(body) <= 16 << 10, "Bounded installed actor result required")
        with (OUT / "actor-result.json").open("xb") as output:
            output.write(body)
        runner.watch.record()
        return 0 if status == "PASS" else 2
    finally:
        runner.runtime.GUARD = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--media-sha256", required=True)
    parser.add_argument("--authority-sha256", required=True)
    args = parser.parse_args()
    started = time.monotonic()
    try:
        C.need(os.environ.get(H.ROLE_FLAG) == "1" and sys.flags.isolated and sys.dont_write_bytecode and __debug__,
               "Explicit isolated installed actor role required")
        os.umask(0o077)
        F.Q.O.actor_boundary(dict(source=SOURCE, stage=STAGE, inputs=INPUTS, output=OUT, media=MEDIA, selection=AUTHORITY))
        raw, _ = C.external(MEDIA, 128 << 10, args.media_sha256)
        media = H.load_media(raw, args.media_sha256)
        authority, _ = C.external(AUTHORITY, 16 << 10, args.authority_sha256)
        now = int(time.time())
        issued = H.read_authority(authority, args.authority_sha256, media, args.media_sha256, now=now)
        plan, _ = H.verify_controls(STAGE, media, now=now)
        return run(media, plan, issued, args.media_sha256, args.authority_sha256, started=started)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, KeyboardInterrupt):
        sys.exit("Qtbase installed actor refused or held")


if __name__ == "__main__":
    raise SystemExit(main())
