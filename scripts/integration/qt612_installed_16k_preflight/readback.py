#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reopen one retired installed Qt trial result without mounting the guest filesystem."""

import argparse
from contextlib import contextmanager
from pathlib import Path
import re
from runpy import run_path
import sys
from types import SimpleNamespace

H = SimpleNamespace(**run_path(str(Path(__file__).with_name("owned.py"))))
C, W, T = H.C, H.W, H.T
ROOT_DIRS = {".", "lost+found", "evidence", "evidence/commands"}
LEAF = re.compile(r"evidence/(?:commands/)?[a-z][a-z0-9.-]{0,95}")


@contextmanager
def file_views(path, result):
    C.read(path, H.RESULT_BYTES, result, collect=False)
    original = C.identity(path.lstat())
    disk = C.ext4_reader()(path, max_nodes=905, max_file_bytes=128 << 20)
    with disk as fs:
        nodes = fs.inventory()["nodes"]
        C.need(ROOT_DIRS <= nodes.keys() and "rtc-clock.env" in nodes, "Installed result namespace missing")
        leaves = {}
        for name, node in nodes.items():
            C.need(node["uid"] == node["gid"] == 0 and not node["xattrs"], "Unowned installed result entry")
            if name in ROOT_DIRS:
                C.need(node["type"] == "directory" and node["mode"] == (0o755 if name == "." else 0o700),
                       "Unexpected installed result directory")
            else:
                limit = 1 << 20 if name.startswith("evidence/commands/") else 128 << 20
                C.need((name == "rtc-clock.env" or LEAF.fullmatch(name)) and node["type"] == "file"
                       and node["links"] == 1 and node["mode"] == 0o600 and node["size"] <= limit,
                       "Unbounded installed result member")
                leaves[name] = dict(bytes=node["size"], sha256=node["sha256"])
        C.need(sum(pin["bytes"] for pin in leaves.values()) < 768 << 20,
               "Installed result data exceeds the export budget")

        def get(name, cap):
            pin = leaves[name]
            C.need(pin["bytes"] <= cap, "Installed result member exceeds role limit")
            body = b"".join(fs.chunks(*fs.inode(nodes[name]["inode"])))
            C.need(C.pin(body) == pin and C.identity(path.lstat()) == original,
                   "Installed result file changed during readback")
            return body

        yield leaves, get
    C.need(C.identity(path.lstat()) == original, "Installed result carrier changed")


def review_case(media, plan, selection, get):
    report = C.json_body(get("evidence/result.json", 256 << 10), canonical=True)
    C.need(report["plan_sha256"] == media["plan"]["sha256"]
           and report["selection_sha256"] == media["selection"]["sha256"], "Wrong installed case worker selection")
    if media["case"] == "main":
        C.need(report["status"] == "LIFECYCLE_CALLBACKS_VERIFIED_ONLY", "Installed main worker did not pass")
        baseline = None
        for stage in plan["stages"]:
            role = stage["name"]
            inventory = get(f"evidence/commands/{role}-inventory.stdout", 1 << 20)
            C.need(C.pin(T.sorted_rows(inventory)) == stage["inventory"], "Original installed-stage inventory differs")
            view = C.json_body(get(f"evidence/{role}-observed.json", W.MAX_SELECTION), canonical=True)
            for name, limit in (("protected", 16 << 20), ("database", 128 << 20)):
                if view[name] is not None:
                    data = get(f"evidence/{role}-{name}.json", limit)
                    C.need(C.pin(data) == view[name], "Original installed-stage observation differs")
                    view[name] = data
            W.check_view(plan, stage, selection["payload"], selection["providers"], view, baseline)
            if baseline is None:
                baseline = view
        return C.pin(baseline["database"])

    C.need(report["kind"] == "QTBASE16K_INSTALLED_NEGATIVE_RESULT_V1"
           and report["status"] == "SIGNATURE_REFUSAL_VERIFIED_ONLY" and report["case"] == media["case"]
           and report["nonce"] == plan["nonce"] and report["clone"] == media["clone"]
           and report["signature"] == media["signature"]
           and report["inventory_before"] == report["inventory_after"] == H.P.Q3_INVENTORY,
           "Wrong signature-refusal guest result")
    fields = {"database_before": ("database-before.json", 128 << 20),
              "database_after": ("database-after.json", 128 << 20),
              "stderr": ("commands/signature-refusal.stderr", 1 << 20)}
    for name, (leaf, limit) in fields.items():
        data = get(f"evidence/{leaf}", limit)
        C.need(C.pin(data) == report[name], "Original signature refusal evidence differs")
        report[name] = data
    reviewed = {key: report[key] for key in ("clone", "scratch", "configuration", "archive", "signature", "argv",
                                            "exit_code", "natural", "group_empty", *fields)}
    W.review_negative(plan, selection, reviewed["database_before"], {plan["nonce"]}, media["case"], reviewed)
    return C.pin(reviewed["database_before"])


def readback(root, media_sha, retirement, retirement_sha):
    raw, _ = C.external(root / H.MEDIA_NAME, 128 << 10, media_sha)
    media = H.load_media(raw, media_sha)
    raw, post_pin = C.external(retirement, 16 << 10, retirement_sha)
    post = C.json_body(raw, canonical=True)
    C.need(post["kind"] == H.OBSERVATION_KIND and post["scope"] == H.P.SCOPE and post["nonce"] == media["clone"]
           and post["authority"] is None and type(post["exit_code"]) is int and post["exit_code"] == 0
           and post["handoff_sha256"] == media_sha and post["plan_sha256"] == media["plan"]["sha256"]
           and post["observations"] == [dict(scope_absent=True, container_absent=True)] * 2,
           "Exact successful retired installed scope required")
    attempt = root / H.CLAIM
    authority_raw, _ = C.external(attempt / "selection.json", 16 << 10, post["authority_sha256"])
    authority = H.read_authority(authority_raw, post["authority_sha256"], media, media_sha)
    stage = root / "control"
    plan, _ = H.verify_controls(stage, media, now=authority["created_utc"])
    selection = C.json_body(C.read(stage / "SELECTION.json", 16 << 20, media["selection"])[0], canonical=True)
    output = attempt / "output"
    C.need(C.check_pin(post["actor_result"], 16 << 10), "Exact original installed actor receipt required")
    report = C.json_body(C.read(output / "actor-result.json", 16 << 10, post["actor_result"])[0], canonical=True)
    C.need(report["kind"] == H.RESULT_KIND and report["status"] == "PASS" and report["case"] == media["case"]
           and report["clone"] == media["clone"] and report["media_sha256"] == media_sha
           and report["authority_sha256"] == post["authority_sha256"] and report["plan"] == media["plan"]
           and report["selection"] == media["selection"], "Exact successful installed actor report required")
    argv = report["qemu_argv"]
    epoch, = re.findall(r"(?:^| )arm16k_rtc_host_epoch=([0-9]{9,12})(?: |$)", argv[argv.index("-append") + 1])
    role = H.role(plan["nonce"], media["case"], media["clone"], media["boot_manifest"], media["plan"]["sha256"],
                  media["selection"]["sha256"], media["signature"]["sha256"], int(epoch))
    C.need(argv == role["qemu_argv"] and role["result_uuid"] == report["result_uuid"]
           and authority["created_utc"] <= int(epoch) < authority["expires_utc"], "Exact installed boot identity required")
    qemu, serial = C.command_receipt(output, "qemu", report["qemu"], argv, H.QEMU_SECONDS, H.WRITER_CAP, 1 << 20)
    C.need(qemu["stdout"] == report["serial"] and H.terminal(serial, media["clone"]) == "PASS",
           "Exact retired installed guest terminal required")
    C.command_receipt(output, "fsck-result", report["fsck"], ["/usr/bin/e2fsck", "-fn", "/out/result.raw"],
                      60, None, 1 << 20)
    result = output / "result.raw"
    H.M.verify_result(result, role["result_uuid"])
    with file_views(result, report["result"]) as (files, get):
        database = review_case(media, plan, selection, get)
        rtc = get("rtc-clock.env", 4096)
        C.need(f"HOST_BOOT_UTC={epoch}\n".encode() in rtc and b"RTC_CLOCK_ADVANCED=yes\n" in rtc
               and b"CLOCK_SETTING=none\n" in rtc, "Installed result lacks the original RTC guard")
    return dict(kind="QTBASE16K_INSTALLED_CASE_READBACK_V1", status="PASS_INSTALLED_CASE_READBACK_ONLY",
                case=media["case"], clone=media["clone"], plan=media["plan"], selection=media["selection"],
                scratch=H.P.Q3_SCRATCH, retirement=post_pin, baseline_database=database, original_files=files,
                physical_M2="NOT_RUN")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for leaf in ("media", "retirement"):
        parser.add_argument("--" + leaf, type=Path, required=True)
        parser.add_argument("--" + leaf + "-sha256", required=True)
    args = parser.parse_args()
    try:
        sys.addaudithook(C.audit_fence)
        sys.stdout.buffer.write(C.wire(readback(args.media, args.media_sha256, args.retirement, args.retirement_sha256)))
    except (OSError, ValueError, KeyError, TypeError):
        sys.exit("Qtbase installed result readback refused")


if __name__ == "__main__":
    main()
