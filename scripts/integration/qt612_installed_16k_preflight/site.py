#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Own one selected Qt installed guest or signature-refusal sibling."""

import argparse
import os
from pathlib import Path
from runpy import run_path
import stat
import subprocess
import sys
import time
from types import ModuleType, SimpleNamespace

HERE = Path(__file__).resolve().parent
H = SimpleNamespace(**run_path(str(HERE / "owned.py")))
C, T = H.C, H.T
ACTOR = "/src/scripts/integration/qt612_installed_16k_preflight/actor.py"
SITE_KIND = "QTBASE16K_INSTALLED_SITE_UNISSUED_V1"
ATTEMPT_KIND = "QTBASE16K_INSTALLED_HOST_ATTEMPT_V1"
LABEL = "org.cachy-asahi.qtbase16k-installed.nonce"
PACKAGE_SITE_PIN = C.file_pin(14048, "499a9b4cf8403854c85b73850c6efe0a89b1366644dfcaf7db3edb932daf1c61")


def current_authority(selected):
    H.read_authority(selected.raw_selection, selected.role["selection"]["sha256"], selected.media,
                     selected.media_sha, site_sha=selected.site_sha, now=int(time.time()))


def meta(selected, group):
    role = selected.role
    owner = selected.owner
    C.need(owner.OLD.GROUP.fullmatch(group) and group.endswith("/" + H.P.SCOPE),
           "Exact installed guest systemd scope required")
    return dict(kind=ATTEMPT_KIND, one_original=True, scope=H.P.SCOPE, scope_group=group,
                image=selected.media["runner"]["actor_image"], name="caa-qtbase16k-installed-" + role["nonce"],
                nonce=role["nonce"], authority_sha256=role["selection"]["sha256"], site_sha256=selected.site_sha,
                handoff_sha256=selected.media_sha, plan_sha256=selected.media["plan"]["sha256"],
                output=str(selected.root / H.CLAIM / "output"), memory_bytes=H.ACTOR_BYTES, vcpus=4,
                attach_seconds=H.ATTACH_SECONDS, scope_stop_grace_seconds=owner.SCOPE_STOP_GRACE_SECONDS)


def owner_modules(stage, plan_sha):
    path = H.PACKAGE / "package_site.py"
    body, _ = C.read(path, 64 << 10, PACKAGE_SITE_PIN)
    lifecycle = ModuleType("qtbase_installed_host_lifecycle")
    lifecycle.__file__ = str(path)
    exec(compile(body, str(path), "exec"), lifecycle.__dict__)
    owner = lifecycle.package_owner(stage, plan_sha)

    def args(media_sha, authority_sha):
        return ["-I", "-B", "-Werror", ACTOR, "--media-sha256", media_sha, "--authority-sha256", authority_sha]

    owner.__dict__.update(SCOPE=H.P.SCOPE, CLAIM=H.CLAIM, ACTOR=ACTOR, NONCE_LABEL=LABEL, actor_args=args,
                          ROLE_FLAGS=(H.ROLE_FLAG + "=1", "CACHY_ASAHI_OVERLAY583_ACTOR=1"),
                          RETIREMENT_KIND=H.HOST_KIND)
    lifecycle.__dict__.update(W=SimpleNamespace(SCOPE=H.P.SCOPE), CLAIM=H.CLAIM, attempt_meta=meta,
                              OBSERVATION_KIND=H.OBSERVATION_KIND, verify_current_selection=current_authority)
    return lifecycle, owner


def site_media(root, media_sha):
    root = T.ordinary(root)
    raw, _ = C.external(root / H.MEDIA_NAME, 128 << 10, media_sha)
    media = H.load_media(raw, media_sha)
    stage = root / "control"
    lifecycle, owner = owner_modules(stage, media["plan"]["sha256"])
    identity, stage_identity = owner.capsule_identity(root), owner.capsule_identity(stage)
    launcher = C.read(HERE / "site.py", 64 << 10, collect=False)[1]
    site = dict(kind=SITE_KIND, authority=None, scope=H.P.SCOPE, root=identity, stage=stage_identity,
                launcher=launcher, media_sha256=media_sha, plan_sha256=media["plan"]["sha256"],
                case=media["case"], clone=media["clone"])
    return lifecycle, owner, root, stage, media, site


def describe_site(root, media_sha):
    """Describe the capsule and control identities for independent Root review."""
    return site_media(root, media_sha)[-1]


def selected_site(root, media_sha, site_path, site_sha, authority_path, authority_sha, *, live, connect=True):
    lifecycle, owner, root, stage, media, site = site_media(root, media_sha)
    described, _ = C.external(site_path, 16 << 10, site_sha)
    C.need(described == C.wire(site), "Exact original installed media and control identities required")
    authority, pin = C.external(authority_path, 16 << 10, authority_sha)
    now = int(time.time()) if live else C.json_body(authority, canonical=True)["created_utc"]
    H.read_authority(authority, authority_sha, media, media_sha, site_sha=site_sha, now=now)
    plan, predecessor = H.verify_controls(stage, media, now=now)
    contract = HERE / "owned.py"
    C.read(contract, 128 << 10, media["source"][str(contract.relative_to(H.P.ROOT))], collect=False)
    H.verify_source(root / "source", media["source"])
    H.verify_carriers(root / "inputs", media)
    template = root / "templates/result.raw"
    C.need(stat.S_IMODE(template.lstat().st_mode) == 0o444
           and {leaf.name for leaf in template.parent.iterdir()} == {template.name},
           "Exact read-only installed result template required")
    C.read(template, H.RESULT_BYTES, media["result"], collect=False)
    boot = H.boot_role(media)
    H.M.verify_result(template, boot["result_carrier"]["uuid"], empty=True)
    role = dict(nonce=media["clone"], selection=pin, result_carrier=boot["result_carrier"] | {"bytes": H.RESULT_BYTES},
                runtime=dict(child_file_size_cap=H.WRITER_CAP, actor_memory_bytes=H.ACTOR_BYTES))
    client = owner.client_for({"runner": media["runner"]}, {"attach_seconds": H.ATTACH_SECONDS}) if connect else None
    return lifecycle, SimpleNamespace(owner=owner, packaging=H.M, root=root, stage=stage, identity=site["root"],
        stage_identity=site["stage"], client=client, predecessor=predecessor, plan=plan, role=role, media=media,
        media_sha=media_sha, site_sha=site_sha, raw_selection=authority)


def original_claim(lifecycle, selected):
    lifecycle.confirm_identity(selected)
    owner = selected.owner
    attempt = T.ordinary(selected.root / H.CLAIM)
    owner.capsule_identity(attempt)
    C.need(not os.path.lexists(attempt / "host-HOLD.json"), "Exact original natural installed claim required")
    receipt, meta_pin = owner.OLD.encoded_file(attempt / "attempt.json")
    expected = meta(selected, receipt["scope_group"])
    C.need(meta_pin == C.pin(C.wire(expected))
           and C.read(attempt / "selection.json", 16 << 10, selected.role["selection"])[0] == selected.raw_selection,
           "Original installed host claim or authority differs")
    C.read(attempt / "prior-full-closure.json", 16 << 10, C.pin(selected.predecessor[2]), collect=False)
    host, pin = owner.OLD.encoded_file(attempt / "host-result.json")
    receipts = host["receipts"]

    def retained(name, cap):
        return T.read(attempt / name, receipts[name], cap=cap)

    cid = owner.OLD.scoped_identity(retained("run.cid", 70))
    code = host["exit_code"]
    C.need(type(code) is int and code in owner.ORIGINAL_CODES
           and pin == C.pin(C.wire(owner.host_result(attempt, expected, cid, code)))
           and (code != 0 or C.check_pin(host["actor_result"], 16 << 10))
           and retained("run.attach-exit", 8) == f"{code}\n".encode()
           and retained("run.create.stdout", 70) == (cid + "\n").encode()
           and all(retained(f"run.absence-{number}", 1) == b"" for number in (1, 2)),
           "Exact original installed lifecycle evidence required")
    owner.matching_inspects(*(retained(f"run.{state}.inspect.json", owner.OLD.OUTPUT_CAP)
                              for state in ("created", "exited")), attempt, expected, cid, code)
    return dict(kind=H.OBSERVATION_KIND, host_result=pin, cid=cid, exit_code=code,
                actor_result=host["actor_result"], authority=None,
                **{key: expected[key] for key in ("nonce", "scope", "scope_group", "site_sha256", "authority_sha256",
                                                  "handoff_sha256", "plan_sha256", "scope_stop_grace_seconds")})


def replay_host(root, media_sha, site_path, site_sha, authority_path, authority_sha):
    """Replay the original host claim from local receipts without live checks."""
    lifecycle, selected = selected_site(root, media_sha, site_path, site_sha, authority_path, authority_sha,
                                        live=False, connect=False)
    return original_claim(lifecycle, selected)


def observe(lifecycle, selected):
    report = original_claim(lifecycle, selected)
    selected.client.verify_daemon()
    selected.owner.predecessors_absent(selected.client, {"installed": (H.P.SCOPE, report["cid"], b"")})
    return report | dict(observations=[dict(scope_absent=True, container_absent=True)] * 2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("describe", "preflight", "run", "observe"))
    parser.add_argument("--media", type=Path, required=True)
    parser.add_argument("--media-sha256", required=True)
    parser.add_argument("--site", type=Path)
    parser.add_argument("--site-sha256")
    parser.add_argument("--authority", type=Path)
    parser.add_argument("--authority-sha256")
    args = parser.parse_args()
    try:
        C.need(sys.flags.isolated and sys.dont_write_bytecode and __debug__, "Use isolated unoptimized Python")
        os.umask(0o077)
        if args.mode in ("describe", "preflight"):
            sys.addaudithook(C.audit_fence)
        operands = args.site, args.site_sha256, args.authority, args.authority_sha256
        if args.mode == "describe":
            C.need(not any(operands), "Describe accepts unissued media only")
            sys.stdout.buffer.write(C.wire(describe_site(args.media, args.media_sha256)))
            return 0
        C.need(all(operands), "Independent site and Root authority paths and digests required")
        lifecycle, selected = selected_site(args.media, args.media_sha256, *operands,
                                            live=args.mode != "observe")
        if args.mode == "run":
            return lifecycle.run(selected)
        if args.mode == "observe":
            report, passed = observe(lifecycle, selected), True
        else:
            report, passed = lifecycle.preflight(selected)
            report = report | dict(status="PASS_INSTALLED_HOST_PREFLIGHT_ONLY" if passed else "HOLD",
                                   installation="NOT_RUN", case=selected.media["case"])
            del report["packaging"]
        sys.stdout.buffer.write(C.wire(report))
        return 0 if passed else 2
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, KeyboardInterrupt):
        sys.exit("Qtbase installed host refused or held")


if __name__ == "__main__":
    raise SystemExit(main())
