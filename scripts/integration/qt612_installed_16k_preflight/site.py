#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Own one selected Qt installed guest or signature-refusal sibling."""

import argparse
from pathlib import Path
from runpy import run_path
import stat
import subprocess
import sys
import time
from types import ModuleType, SimpleNamespace

HERE = Path(__file__).resolve().parent
H = SimpleNamespace(**run_path(str(HERE / "owned.py")))
C, F, T = H.C, H.F, H.T
ACTOR = "/src/scripts/integration/qt612_installed_16k_preflight/actor.py"
ATTEMPT_KIND = "QTBASE16K_INSTALLED_HOST_ATTEMPT_V1"
LABEL = "org.cachy-asahi.qtbase16k-installed.nonce"
PACKAGE_SITE_PIN = C.file_pin(14048, "499a9b4cf8403854c85b73850c6efe0a89b1366644dfcaf7db3edb932daf1c61")


def current_authority(selected):
    H.read_authority(selected.raw_selection, selected.role["selection"]["sha256"], selected.media,
                     selected.media_sha, now=int(time.time()))


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


def selected_site(root, media_sha, authority_path, authority_sha, *, live):
    root = T.ordinary(root)
    raw, _ = C.external(root / H.MEDIA_NAME, 128 << 10, media_sha)
    media = H.load_media(raw, media_sha)
    authority, pin = C.external(authority_path, 16 << 10, authority_sha)
    now = int(time.time()) if live else C.json_body(authority, canonical=True)["created_utc"]
    H.read_authority(authority, authority_sha, media, media_sha, now=now)
    stage = root / "control"
    lifecycle, owner = owner_modules(stage, media["plan"]["sha256"])
    identity, stage_identity = owner.capsule_identity(root), owner.capsule_identity(stage)
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
    launcher = C.read(Path(__file__), 64 << 10, collect=False)[1]
    site_pin = C.pin(C.wire(dict(root=identity, stage=stage_identity, launcher=launcher,
                                 media_sha256=media_sha, authority_sha256=authority_sha)))
    client = owner.client_for({"runner": media["runner"]}, {"attach_seconds": H.ATTACH_SECONDS})
    return lifecycle, SimpleNamespace(owner=owner, packaging=H.M, root=root, stage=stage, identity=identity,
        stage_identity=stage_identity, client=client, predecessor=predecessor, plan=plan, role=role, media=media,
        media_sha=media_sha, site_sha=site_pin["sha256"], raw_selection=authority)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("preflight", "run", "observe"))
    parser.add_argument("--media", type=Path, required=True)
    parser.add_argument("--media-sha256", required=True)
    parser.add_argument("--authority", type=Path, required=True)
    parser.add_argument("--authority-sha256", required=True)
    args = parser.parse_args()
    try:
        C.need(sys.flags.isolated and sys.dont_write_bytecode and __debug__, "Use isolated unoptimized Python")
        if args.mode == "preflight":
            sys.addaudithook(C.audit_fence)
        lifecycle, selected = selected_site(args.media, args.media_sha256, args.authority, args.authority_sha256,
                                            live=args.mode != "observe")
        if args.mode == "run":
            return lifecycle.run(selected)
        if args.mode == "observe":
            report, passed = lifecycle.observe(selected), True
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
