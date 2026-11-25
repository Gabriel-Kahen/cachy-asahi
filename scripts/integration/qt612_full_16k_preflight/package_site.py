#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the separate Qtbase package scope through the existing host owner."""

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
E = SimpleNamespace(**run_path(str(HERE / "package_execution.py")))
C, F, W = E.C, E.F, E.W
T = F.T
CLAIM = "package-build.claim"
MEDIA = "MEDIA.UNISSUED.json"
ACTOR = "/src/" + F.GUEST_SOURCE + "/package_actor.py"
ROLE_FLAGS = ("CACHY_ASAHI_QTBASE16K_PACKAGE_ACTOR=1", "CACHY_ASAHI_OVERLAY583_ACTOR=1")
NONCE_LABEL = "org.cachy-asahi.qtbase16k-package.nonce"
PARENT_OWNER = C.file_pin(26233, "af56bc704261aa7ce54f5ae48d553ab1de8f4d0dc41995fb250573eb456fe5c2")
ATTEMPT_KIND = "QTBASE16K_PACKAGE_HOST_ATTEMPT_V1"
RETIREMENT_KIND = "QTBASE16K_PACKAGE_HOST_RETIREMENT_V1"
OBSERVATION_KIND = "QTBASE16K_PACKAGE_POST_SCOPE_V1"
CAPSULE_REPORT_RESERVE = 128 << 20
HOST_FREE_RESERVE = 2 << 30


def mounts_for(attempt, stage):
    root = attempt.parent
    return [(str(root / "source"), "/src", False), (str(stage), "/stage", False),
            (str(attempt / "selection.json"), "/selection.json", False),
            (str(root / MEDIA), "/media.json", False), (str(root / "inputs"), "/inputs", False),
            (str(attempt / "output"), "/out", True)]


def actor_args(plan_sha, media_sha, selection_sha):
    C.need(all(type(digest) is str and C.SHA.fullmatch(digest)
               for digest in (plan_sha, media_sha, selection_sha)), "Exact packaging actor digests required")
    return ["-I", "-B", "-Werror", ACTOR, "--plan-sha256", plan_sha,
            "--selection-sha256", selection_sha, "--media-sha256", media_sha]


def package_owner(stage, plan_sha):
    # The reviewed lifecycle has role-specific globals. Give the package role
    # a private module instance so the full-build owner's bytes and namespace
    # remain independent, and reuse its unchanged create/attach/retire path.
    path = HERE / "full_site.py"
    body, _ = C.read(path, PARENT_OWNER["bytes"], PARENT_OWNER)
    owner = ModuleType("qtbase_package_owned_runtime")
    owner.__file__ = str(path)
    exec(compile(body, str(path), "exec"), owner.__dict__)
    def selected_mounts(attempt):
        return mounts_for(attempt, stage)

    def selected_actor(media_sha, selection_sha):
        return actor_args(plan_sha, media_sha, selection_sha)

    owner.__dict__.update(SCOPE=W.SCOPE, CLAIM=CLAIM, ACTOR=ACTOR, ROLE_FLAGS=ROLE_FLAGS,
                          NONCE_LABEL=NONCE_LABEL, RETIREMENT_KIND=RETIREMENT_KIND,
                          mounts_for=selected_mounts, actor_args=selected_actor)
    return owner


def attempt_meta(selected, group):
    owner, role = selected.owner, selected.role
    C.need(owner.OLD.GROUP.fullmatch(group) and group.endswith("/" + W.SCOPE),
           "Exact owned package scope required")
    return dict(kind=ATTEMPT_KIND, one_original=True, scope=W.SCOPE, scope_group=group,
                image=selected.media["runner"]["actor_image"], name="caa-qtbase16k-package-" + role["nonce"],
                nonce=role["nonce"], authority_sha256=role["selection"]["sha256"],
                site_sha256=selected.site_sha, handoff_sha256=selected.media_sha,
                plan_sha256=role["plan"]["sha256"], output=str(selected.root / CLAIM / "output"),
                memory_bytes=role["runtime"]["actor_memory_bytes"], vcpus=role["runtime"]["cpus"],
                attach_seconds=role["times"]["attach"], scope_stop_grace_seconds=role["times"]["scope_stop_grace"])


def predecessor(plan):
    ref = plan["source_evidence"]["retirement"]
    body, _ = C.read(Path(ref["path"]), 16 * 1024, F.P.ref_pin(ref))
    report = C.json_body(body, canonical=True)
    evidence = plan["source_evidence"]
    C.need(report["kind"] == "QTBASE_FULL16K_POST_SCOPE_V1" and report["scope"] == F.SCOPE
           and report["nonce"] == plan["source_build_nonce"] and C.SHA.fullmatch(report["cid"])
           and report["authority"] is None and type(report["exit_code"]) is int and report["exit_code"] == 0
           and report["observations"] == [dict(container_absent=True, scope_absent=True)] * 2
           and report["plan_sha256"] == evidence["plan"]["sha256"]
           and report["handoff_sha256"] == evidence["handoff"]["sha256"]
           and report["host_result"] == F.P.ref_pin(evidence["host"])
           and report["actor_result"] == F.P.ref_pin(evidence["actor"]),
           "Exact retired full-build predecessor required for packaging")
    return report["scope"], report["cid"], body


def capacity(selected):
    role = selected.role
    bounds = dict(actor={"admission_disk_bytes": role["runtime"]["child_file_size_cap"] +
                          role["result_carrier"]["bytes"] + CAPSULE_REPORT_RESERVE + HOST_FREE_RESERVE},
                  limits={"actor_memory_bytes": role["runtime"]["actor_memory_bytes"]})
    return F.capacity(selected.root, bounds)


def verify_current_selection(selected):
    W.selection(selected.raw_selection, selected.plan, selected.role["plan"]["sha256"], int(time.time()))


def confirm_identity(selected):
    C.need(selected.owner.capsule_identity(selected.root) == selected.identity
           and selected.owner.capsule_identity(selected.stage) == selected.stage_identity,
           "Original packaging media and source stage required")


def verify_source(root, plan, media, packaging):
    records = packaging.source_records(root / "source")
    C.need(records == media["source"], "Selected package actor source changed")
    ref = plan["source_evidence"]["handoff"]
    prior = C.json_body(C.read(Path(ref["path"]), 64 * 1024, F.P.ref_pin(ref))[0], canonical=True)
    C.need({name: records[name] for name in F.SOURCE_FILES} == prior["source"],
           "Preserve the retired full-build actor source")
    for name in records.keys() - F.SOURCE_FILES:
        C.read(F.Q.ROOT / name, packaging.CONTROL_CAP, F.Q.pin_ref(records[name]), collect=False)


def load(args, packaging, *, live):
    root, stage = args.media, args.stage
    owner = package_owner(stage, args.plan_sha256)
    identity, stage_identity = (owner.capsule_identity(path) for path in (root, stage))
    C.need(not root.is_relative_to(stage) and not stage.is_relative_to(root),
           "Disjoint private package media and source stage required")
    selection, selection_pin = C.external(args.selection, 16 * 1024, args.selection_sha256)
    now = int(time.time()) if live else C.json_body(selection, canonical=True)["created_utc"]
    plan, _, role, _ = packaging.selected_role(stage, args.plan_sha256, args.selection, args.selection_sha256, now)
    C.need(role["claim"] == CLAIM and role["scope"] == W.SCOPE and role["selection"] == selection_pin
           and role["times"]["scope_stop_grace"] == owner.SCOPE_STOP_GRACE_SECONDS,
           "Exact package host role required")
    media = packaging.load_media(root / MEDIA, args.media_sha256, role)
    verify_source(root, plan, media, packaging)
    packaging.verify_inputs(root / "inputs", role, media)
    templates = T.ordinary(root / "templates")
    template = templates / "result.raw"
    C.need(stat.S_IMODE(templates.lstat().st_mode) == 0o555
           and {leaf.name for leaf in templates.iterdir()} == {"result.raw"}
           and stat.S_IMODE(template.lstat().st_mode) == 0o444, "Exact readonly package result template required")
    F.pinned_file(template, media["result"])
    packaging.verify_result(template, role["result_carrier"]["uuid"], empty=True)
    site_pin = C.pin(C.wire(dict(media=identity | {"sha256": args.media_sha256}, stage=stage_identity,
                                 launcher=C.read(HERE / "package_site.py", 64 * 1024, collect=False)[1])))
    client = owner.client_for({"runner": media["runner"]}, {"attach_seconds": role["times"]["attach"]})
    return SimpleNamespace(owner=owner, packaging=packaging, root=root, stage=stage, identity=identity,
                           stage_identity=stage_identity, client=client, predecessor=predecessor(plan),
                           plan=plan, role=role, media=media, media_sha=args.media_sha256,
                           site_sha=site_pin["sha256"], raw_selection=selection)


def preflight(selected):
    confirm_identity(selected)
    selected.client.check()
    measured = capacity(selected)
    claimed = os.path.lexists(selected.root / CLAIM)
    passed = measured["fits"] and not claimed
    return dict(status="PASS_PACKAGE_HOST_PREFLIGHT_ONLY" if passed else "HOLD",
                authority=None, actor_entered=False, packaging="NOT_RUN",
                claim_exists=claimed, capacity=measured, site_sha256=selected.site_sha,
                media_sha256=selected.media_sha, scope=W.SCOPE), passed


def run(selected):
    confirm_identity(selected)
    owner, role = selected.owner, selected.role
    attempt = selected.root / CLAIM
    C.need(not os.path.lexists(attempt), "Package attempt already claimed")
    verify_current_selection(selected)
    group = owner.owning_group()
    client = selected.client
    client.verify_daemon()
    owner.predecessors_absent(client, {"full": selected.predecessor})
    meta = attempt_meta(selected, group)
    C.need(client.docker("container", "ls", "-a", "--no-trunc", "--filter", "name=^/" + meta["name"] + "$",
                         "--format", "{{.ID}}") == b"", "A container already occupies the selected package name")

    def entry():
        confirm_identity(selected)
        verify_current_selection(selected)
        current = capacity(selected)
        C.need(current["fits"], "Current package host admission limits are unmet")
        return current

    current = entry()
    attempt.mkdir(mode=0o700)
    output = attempt / "output"
    output.mkdir(mode=0o700)
    for name, body in (("attempt.json", C.wire(meta)), ("selection.json", selected.raw_selection),
                       ("prior-full-closure.json", selected.predecessor[2]), ("capacity.json", C.wire(current))):
        owner.OLD.save(attempt / name, body)
    template, target = selected.root / "templates/result.raw", output / "result.raw"
    F.K.clone(template, target, selected.media["result"])
    target.chmod(0o600)
    C.need(stat.S_IMODE(target.lstat().st_mode) == 0o600 and not target.samefile(template),
           "Fresh private package result clone required")
    selected.packaging.verify_result(target, role["result_carrier"]["uuid"], empty=True)
    return owner.execute_owned(client, attempt, meta, entry)


def observe(selected):
    confirm_identity(selected)
    owner = selected.owner
    attempt = T.ordinary(selected.root / CLAIM)
    owner.capsule_identity(attempt)
    C.need(not os.path.lexists(attempt / "host-HOLD.json"), "Exact original natural package claim required")
    meta, _ = owner.OLD.encoded_file(attempt / "attempt.json")
    C.need(meta == attempt_meta(selected, meta["scope_group"])
           and C.read(attempt / "selection.json", 16 * 1024, selected.role["selection"])[0] == selected.raw_selection,
           "Original package host claim or selection differs")
    C.read(attempt / "prior-full-closure.json", 16 * 1024, C.pin(selected.predecessor[2]), collect=False)
    host, pin = owner.OLD.encoded_file(attempt / "host-result.json")
    cid = owner.OLD.scoped_identity(T.read(attempt / "run.cid", cap=70))
    code = host["exit_code"]
    C.need(type(code) is int and code in owner.ORIGINAL_CODES
           and host == owner.host_result(attempt, meta, cid, code)
           and (code != 0 or C.check_pin(host["actor_result"], 16 * 1024))
           and T.read(attempt / "run.attach-exit", cap=8) == f"{code}\n".encode()
           and T.read(attempt / "run.create.stdout", cap=70) == (cid + "\n").encode()
           and all(T.read(attempt / f"run.absence-{number}", cap=1) == b"" for number in (1, 2)),
           "Exact original package lifecycle evidence required")
    owner.matching_inspects(*(T.read(attempt / f"run.{state}.inspect.json", cap=owner.OLD.OUTPUT_CAP)
                              for state in ("created", "exited")), attempt, meta, cid, code)
    client = selected.client
    client.verify_daemon()
    owner.predecessors_absent(client, {"package": (W.SCOPE, cid, b"")})
    return dict(kind=OBSERVATION_KIND, host_result=pin, cid=cid, exit_code=code,
                actor_result=host["actor_result"], authority=None,
                observations=[dict(scope_absent=True, container_absent=True)] * 2,
                **{key: meta[key] for key in ("nonce", "scope", "scope_group", "site_sha256", "authority_sha256",
                                              "handoff_sha256", "plan_sha256", "scope_stop_grace_seconds")})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("preflight", "run", "observe"))
    for name in ("stage", "media", "selection"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("plan", "media", "selection"):
        parser.add_argument("--" + name + "-sha256", required=True)
    args = parser.parse_args()
    C.need(sys.flags.isolated and sys.dont_write_bytecode and __debug__, "Use isolated unoptimized Python")
    os.umask(0o077)
    packaging = SimpleNamespace(**run_path(str(HERE / "package_media.py")))
    if args.mode == "preflight":
        sys.addaudithook(C.audit_fence)
    selected = load(args, packaging, live=args.mode != "observe")
    if args.mode == "run":
        return run(selected)
    if args.mode == "observe":
        sys.stdout.buffer.write(C.wire(observe(selected)))
        return 0
    report, passed = preflight(selected)
    sys.stdout.buffer.write(C.wire(report))
    return 0 if passed else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, KeyboardInterrupt):
        raise SystemExit("Qtbase package host refused or held") from None
