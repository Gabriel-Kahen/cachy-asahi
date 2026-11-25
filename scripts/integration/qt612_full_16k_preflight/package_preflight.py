#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify a retired Qtbase all-target attempt and stage an unissued packaging plan."""

import argparse
import os
from pathlib import Path
from runpy import run_path
import stat
import sys
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
S = SimpleNamespace(**run_path(str(HERE / "full_site.py")))
R = SimpleNamespace(**run_path(str(HERE / "full_readback.py")))
M = SimpleNamespace(**run_path(str(HERE / "package_metadata.py")))
W = SimpleNamespace(**run_path(str(HERE / "package_guest.py")))
F, C, T = S.F, S.C, S.T
ROOT = F.Q.ROOT
Q3_PLAN_NAME = "plan.json"
Q3_PLAN_PIN = C.file_pin(94704, "76dde3261964f2809798cb3a64571086738ddd9fa191f0f73859f1e33a5256a7")
Q3_SOURCE_ARCHIVE = "qtbase-everywhere-src-6.12.0.tar.xz"
PACKAGE_CHECKER = ROOT / "scripts/checks/package_checks.py"
PACKAGE_CHECKER_PIN = F.K.F.file_record(W.PACKAGE_CHECKER_PIN)
INDEPENDENT_KIND = "QTBASE_FULL16K_INDEPENDENT_READBACK_V1"
INDEPENDENT_PASS = "PASS_EXACT_EMULATED_QTBASE_ALL_BUILD"
PLAN_NAME = W.PLAN_NAME
PACKAGE_WORKER = ("package_guest.py", "full_guest.py", "guest_link.py")


def ref(path, pin):
    return dict(path=str(path), **pin)


def json_record(path, digest, cap):
    body, pin = C.external(path, cap, digest)
    return C.json_body(body, canonical=True), ref(path, pin)


def q3_inputs(q3):
    q3 = T.ordinary(q3)
    raw, _ = C.read(q3 / Q3_PLAN_NAME, Q3_PLAN_PIN["bytes"], Q3_PLAN_PIN)
    plan = C.json_body(raw)
    C.need(plan["kind"] == "QTBASE_16K_OFFLINE_OPERANDS_V1" and plan["Root_authority"] is None,
           "Expected exact historical Q3 operand plan")
    files = plan["files"]
    q3refs = {"plan": ref(q3 / Q3_PLAN_NAME, Q3_PLAN_PIN)}
    for name in ("expected356.lock", "configure-dependencies.list", Q3_SOURCE_ARCHIVE):
        expected = files[name]
        q3refs[name] = ref(q3 / name, F.pinned_file(q3 / name, expected))
    C.need(files["expected356.lock"] == F.INVENTORY, "Q3 inventory differs from the completed Qtbase build")
    lock = C.read(q3 / "expected356.lock", 16 * 1024, F.INVENTORY)[0]
    inventory = T.canonical_lock(lock, 356)
    C.need(inventory["md4c"] == "0.5.3-1" and inventory["wayland"] == "1.26.0-1"
           and inventory["libglvnd"] == "1.7.0-3", "Expected original Q3 Qt providers")
    dep_bytes = C.read(q3 / "configure-dependencies.list", 8192, files["configure-dependencies.list"])[0]
    deps = dep_bytes.decode("ascii").splitlines()

    # The archived family-contract describes the old package metadata. Keep it
    # in the original operands and stage only the true Q3 recipe inputs.
    recipe = {}
    for relative, pin in files.items():
        if relative.startswith("recipe/") and relative != "recipe/family-contract.json":
            name = relative.removeprefix("recipe/")
            C.need(Path(name).name == name, "Flat Q3 recipe source required")
            recipe[name] = C.read(q3 / relative, 128 * 1024, pin)[0]
    C.need(len(recipe) == 15, "Exact prepared Q3 recipe source set required")
    original = C.pin(recipe["PKGBUILD"])
    projection = M.successor(recipe["PKGBUILD"], recipe[".SRCINFO"])
    C.need(C.json_body(projection["receipt"])["profile"] == "q3", "Expected the completed build's Q3 recipe profile")
    recipe["PKGBUILD"], recipe[".SRCINFO"] = projection["PKGBUILD"], projection[".SRCINFO"]
    checker = C.read(PACKAGE_CHECKER, 64 * 1024, PACKAGE_CHECKER_PIN)[0]
    payload = {"recipe/" + name: body for name, body in recipe.items()}
    full, _ = C.read(HERE / "full_guest.py", 128 * 1024, F.K.F.file_record(W.FULL_GUEST_PIN))
    sidecar, _ = C.read(F.Q.ROOT / F.Q.LANE / "guest_link.py", 128 * 1024,
                        F.K.F.file_record(R.G.SIDECAR_PIN))
    payload |= {"expected356.lock": lock, "configure-dependencies.list": dep_bytes,
                "metadata-projection.json": projection["receipt"], "package_checks.py": checker,
                "package_guest.py": C.read(HERE / "package_guest.py", 128 * 1024)[0],
                "full_guest.py": full, "guest_link.py": sidecar}
    return q3refs, original, deps, payload


def completed_build(root, site_path, site_sha, retrospective, retrospective_sha, independent, independent_sha):
    post, post_ref = json_record(retrospective, retrospective_sha, 16 * 1024)
    full, full_ref = json_record(independent, independent_sha, 256 * 1024)
    C.need(post.get("kind") == S.OBSERVATION_KIND and post.get("scope") == S.SCOPE
           and type(post.get("exit_code")) is int and post["exit_code"] == 0
           and post.get("observations") == [dict(scope_absent=True, container_absent=True)] * 2
           and post["authority"] is None and full.get("kind") == INDEPENDENT_KIND
           and full.get("status") == INDEPENDENT_PASS and full["guest"]["status"] == "VERIFIED_QTBASE_BUILD_ONLY",
           "Successful full Qtbase readback and two original retirement observations required")

    site, handoff, plan = S.load_site(site_path, site_sha, root)
    meta, host, host_pin = S.read_attempt(site, handoff, plan, site_sha)
    expected_post = dict(kind=S.OBSERVATION_KIND, host_result=host_pin, cid=host["cid"], exit_code=host["exit_code"],
                         actor_result=host["actor_result"], observations=post["observations"], authority=None,
                         **{key: meta[key] for key in ("nonce", "scope", "scope_group", "site_sha256", "authority_sha256",
                                                       "handoff_sha256", "plan_sha256", "scope_stop_grace_seconds")})
    C.need(C.wire(post) == C.wire(expected_post) and host["exit_code"] == 0
           and C.check_pin(host["actor_result"], 16 * 1024) and full["actor"]["actor_result"] == host["actor_result"]
           and full["nonce"] == meta["nonce"] and full["handoff_sha256"] == meta["handoff_sha256"]
           and full["plan_sha256"] == meta["plan_sha256"] and full["authority"]["sha256"] == meta["authority_sha256"],
           "Readback and retirement must describe the same exact original build attempt")

    attempt = root / S.CLAIM
    output = attempt / "output"
    current = R.readback(root, meta["handoff_sha256"], attempt / "selection.json", meta["authority_sha256"],
                         output, host["actor_result"]["sha256"])
    C.need(C.wire(full) == C.wire(current), "Retained independent full-build report differs from original evidence")
    readonly = {name: ref(root / "inputs" / name, plan["inputs"][name])
                for name in ("Image", "scratch.raw", "core.qcow2", "gui.qcow2")}
    readonly["complete.qcow2"] = ref(output / "overlay.qcow2", current["actor"]["overlay"])
    evidence = dict(handoff=ref(root / F.HANDOFF, C.pin(C.wire(handoff))),
                    plan=ref(root / F.PLAN, handoff["plan"]), retirement=post_ref, independent=full_ref,
                    host=ref(attempt / "host-result.json", host_pin),
                    actor=ref(output / "actor-result.json", host["actor_result"]),
                    result=ref(output / "result.raw", current["actor"]["result_disk"]),
                    boot_template=ref(root / "inputs" / "boot.raw", plan["inputs"]["boot.raw"]))
    completed = dict(libraries=current["guest"]["outputs"]["libraries"],
                     ninja_log=current["guest"]["outputs"]["ninja_log"]["after"])
    return meta["nonce"], readonly, evidence, completed


def prepare(args):
    C.need(type(args.nonce) is str and F.Q.NONCE.fullmatch(args.nonce), "Fresh 32-hex packaging nonce required")
    q3refs, original, deps, files = q3_inputs(args.q3_media)
    old_nonce, readonly, evidence, completed = completed_build(args.capsule, args.site, args.site_sha256,
                                                     args.retirement, args.retirement_sha256,
                                                     args.readback, args.readback_sha256)
    C.need(args.nonce[:8] not in {"00000000", old_nonce[:8]}, "Packaging requires a distinct boot identity")
    sidecar = guest_sidecar()
    checks = {name: F.K.F.file_record(pin) for name, pin in sidecar.Q3_PINS.items()}
    C.need(checks["PKGBUILD"] == original, "Packaged recipe must derive from the exact Q3 build recipe")
    plan = dict(kind=W.PLAN_KIND, authority=None, scope=W.SCOPE, nonce=args.nonce,
                source_build_nonce=old_nonce, source_evidence=evidence, readonly_media=readonly, q3=q3refs,
                fresh_child=dict(path="/out/package-overlay.qcow2", backing="/inputs/complete.qcow2",
                                 backing_format="qcow2", storage="fresh-writable-child-only"),
                worker=W.worker_contract(sidecar, R.G, deps, files, completed),
                expected_archive=W.archive_contract(files["recipe/PKGBUILD"]),
                staging_files={name: C.pin(body) for name, body in sorted(files.items())},
                packaging="NOT_RUN", signing="NOT_RUN", installation="NOT_RUN", hardware="NOT_RUN")
    return plan, files


def guest_sidecar():
    path = F.Q.ROOT / F.Q.LANE / "guest_link.py"
    return C.pinned_module("qtbase_q3_guest_contract", path, R.G.SIDECAR_PIN)


def stage(output, plan, files, protected):
    fixed = {"expected356.lock", "configure-dependencies.list", "metadata-projection.json",
             "package_checks.py", *PACKAGE_WORKER}
    C.need(all(name in fixed or (Path(name).parent == Path("recipe") and Path(name).name != "..")
               for name in files) and {name: C.pin(body) for name, body in files.items()} == plan["staging_files"],
           "Exact bounded staging leaves required")
    absolute = output.is_absolute() and output == output.resolve()
    C.need(absolute and not any(output.is_relative_to(path) for path in protected)
           and not os.path.lexists(output), "Fresh staging path outside every selected source required")
    parent = output.parent.stat()
    C.need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid()
           and not stat.S_IMODE(parent.st_mode) & 0o022, "Owned nonshared staging parent required")
    output.mkdir(mode=0o700)
    (output / "recipe").mkdir(mode=0o700)
    # The plan is written last. An interrupted staging directory has no plan.
    for name, data in sorted(files.items()) + [(PLAN_NAME, C.wire(plan))]:
        with (output / name).open("xb") as stream:
            stream.write(data)
        (output / name).chmod(0o444)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("capsule", "site", "retirement", "readback", "q3-media"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("site-sha256", "retirement-sha256", "readback-sha256", "nonce"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    may_stage = False

    def fence(event, parameters):
        if not may_stage or event not in {"open", "os.mkdir", "os.chmod"}:
            C.audit_fence(event, parameters)

    sys.addaudithook(fence)
    try:
        plan, files = prepare(args)
        if args.output is not None:
            may_stage = True
            stage(args.output, plan, files, (args.capsule, args.q3_media, ROOT))
        report = dict(status="PASS_UNISSUED_PACKAGING_PREFLIGHT_ONLY", authority=None, plan=C.pin(C.wire(plan)),
                      staged=args.output is not None, packaging="NOT_RUN", signing="NOT_RUN", installation="NOT_RUN")
        sys.stdout.buffer.write(C.wire(report))
    except (OSError, KeyError, TypeError, ValueError):
        sys.exit("Qtbase packaging preflight refused")


if __name__ == "__main__":
    main()
