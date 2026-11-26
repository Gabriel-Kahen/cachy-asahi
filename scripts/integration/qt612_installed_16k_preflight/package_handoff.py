#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read a retired Qtbase package attempt and bind the exact unsigned archive."""

import argparse
from pathlib import Path
from runpy import run_path
import sys
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
P = SimpleNamespace(**run_path(str(HERE / "preflight.py")))
E = SimpleNamespace(**run_path(str(P.PROJECT / "qt612_full_16k_preflight/package_execution.py")))
C, W = E.C, E.W
PACKAGE_SCOPE = W.SCOPE
PACKAGE_PASS = "PASS_UNSIGNED_PACKAGE_FOR_REVIEW"
ARCHIVE_NAME = Path(P.ARCHIVE).name


def receipt(path, expected, cap):
    body, pin = C.external(path, cap, expected) if type(expected) is str else C.read(path, cap, expected)
    return C.json_body(body, canonical=True), pin


def bind(archive, retirement, retirement_sha, actor, readback, readback_sha):
    post, post_pin = receipt(retirement, retirement_sha, 16 << 10)
    C.need(post["kind"] == "QTBASE16K_PACKAGE_POST_SCOPE_V1" and post["scope"] == PACKAGE_SCOPE
           and post["authority"] is None and type(post["exit_code"]) is int and post["exit_code"] == 0
           and post["observations"] == [{"scope_absent": True, "container_absent": True}] * 2
           and C.check_pin(post["actor_result"], 16 << 10),
           "Successful original package scope retirement required")
    original, actor_pin = receipt(actor, post["actor_result"], 16 << 10)
    report, package_pin = receipt(readback, readback_sha, 256 << 10)
    worker = report["worker"]
    C.need(original["kind"] == "QTBASE16K_PACKAGE_ACTOR_RESULT_V1"
           and original["scope"] == worker["scope"] == PACKAGE_SCOPE
           and report["kind"] == "QTBASE16K_PACKAGE_OFFLINE_READBACK_V1"
           and worker["kind"] == "QTBASE16K_PACKAGING_RESULT_V1"
           and original["status"] == worker["status"] == PACKAGE_PASS and report["status"] == "PASS"
           and original["phase"] == report["phase"] == worker["phase"] == "complete"
           and original["signing"] == report["signing"] == worker["signing"] == "NOT_RUN",
           "Exact clean package-only PASS and independent readback required")
    C.need(W.NONCE.fullmatch(post["nonce"])
           and post["nonce"] == original["nonce"] == report["nonce"] == worker["nonce"]
           and post["plan_sha256"] == original["plan_sha256"] == report["plan"]["sha256"] == worker["plan_sha256"]
           and post["authority_sha256"] == original["selection_sha256"] == report["selection"]["sha256"]
           == worker["selection_sha256"]
           and post["handoff_sha256"] == original["media_sha256"]
           and original["result_disk"] == report["result"] and original["serial"] == report["serial"],
           "Package readback and retirement must describe the same original attempt")
    expected = report["evidence"][ARCHIVE_NAME]
    C.need(archive.name == ARCHIVE_NAME and expected == worker["archive"] and 0 < expected["bytes"] <= W.FILE_CAP,
           "Expected the exact unsigned archive from the package result")
    fsck, _ = C.command_receipt(actor.parent, "fsck-result", original["fsck_result"],
                               ["/usr/bin/e2fsck", "-fn", "/out/result.raw"], 60, None, E.SERIAL_CAP)
    _, archive_pin = C.read(archive, W.FILE_CAP, expected, collect=False)
    return dict(kind="QTBASE16K_UNSIGNED_ARCHIVE_HANDOFF_V1", status="PASS_UNSIGNED_ARCHIVE_FOR_TEST_REVIEW",
                authority=None, package_nonce=post["nonce"], archive=archive_pin,
                packaging_receipt=package_pin, package_actor=actor_pin, package_retirement=post_pin, result_fsck=fsck,
                signing="NOT_RUN", installation="NOT_RUN")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "retirement", "actor", "readback"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("retirement-sha256", "readback-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        result = bind(args.archive, args.retirement, args.retirement_sha256,
                      args.actor, args.readback, args.readback_sha256)
        sys.stdout.buffer.write(C.wire(result))
    except (OSError, ValueError, TypeError, KeyError):
        sys.exit("Qtbase unsigned archive handoff refused")


if __name__ == "__main__":
    main()
