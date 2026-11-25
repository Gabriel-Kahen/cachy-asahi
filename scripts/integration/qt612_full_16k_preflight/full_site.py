# SPDX-License-Identifier: MIT
"""Own one full Qtbase invocation and independently observe its retirement."""

import argparse
import os
from pathlib import Path
import re
from runpy import run_path
import signal
import stat
import subprocess
import sys
import time
from types import SimpleNamespace


HERE = Path(__file__).resolve().parent
F = SimpleNamespace(**run_path(str(HERE / "full_capsule.py")))
C, T, SCOPE = F.C, F.T, F.SCOPE
OLD = SimpleNamespace(**run_path(str(F.GUI / "site.py")))
ACTOR = "/src/" + F.GUEST_SOURCE + "/full_actor.py"
ROLE_FLAGS = ("CACHY_ASAHI_QTBASE_FULL16K_ACTOR=1", "CACHY_ASAHI_OVERLAY583_ACTOR=1")
NONCE_LABEL = "org.cachy-asahi.qtbase16k-full.nonce"
CLAIM = "full-build.claim"
SITE_KIND = "QTBASE_FULL16K_HOST_SITE_DATA_V1"
ATTEMPT_KIND = "QTBASE_FULL16K_HOST_ATTEMPT_V1"
RETIREMENT_KIND = "QTBASE_FULL16K_HOST_RETIREMENT_V1"
OBSERVATION_KIND = "QTBASE_FULL16K_POST_SCOPE_V1"
GUI_CLOSE = C.file_pin(887, "c6f0b9e8bb5cd029df1785aaef38390c4479777779f2c9b6b389879b8db29aaa")
ORIGINAL_CODES = (0, 1, 2)


def capsule_identity(root):
    root = T.ordinary(root)
    info = root.lstat()
    C.need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.getuid()
           and re.fullmatch(r"/[A-Za-z0-9_./-]+", str(root)), "Exact private capsule root required")
    return dict(path=str(root), device=info.st_dev, inode=info.st_ino)


def predecessors(historical, retirement):
    old = F.Q.load_handoff(historical, F.HISTORICAL_HANDOFF)
    raw, _ = C.read(retirement, 8192, GUI_CLOSE)
    gui = C.json_body(raw, canonical=True)
    C.need(gui["kind"] == "QTGUI_LINK_POST_SCOPE_V1" and gui["scope"] == F.Q.SCOPE
           and gui["handoff_sha256"] == F.HISTORICAL_HANDOFF and gui["plan_sha256"] == old["plan"]["sha256"]
           and gui["observations"] == [dict(container_absent=True, scope_absent=True)] * 2
           and C.SHA.fullmatch(gui["cid"]), "Exact retired QtGui scope required")
    claim, _ = C.read(historical.parent / "root-run.claim/attempt.path", 4096)
    attempt = T.ordinary(Path(claim.decode("ascii").removesuffix("\n")))
    C.need(attempt.parent == historical.parent and re.fullmatch(r"issued\.[A-Za-z0-9_]+", attempt.name),
           "Exact original QtGui attempt required")
    C.read(attempt / "host-result.json", 16 * 1024, gui["host_result"], collect=False)
    retained = {name: ref | {"path": str(attempt / f"prior-{name}-closure.json")}
                for name, ref in old["prior_closures"].items()}
    rows = F.Q.read_predecessors(old | {"prior_closures": retained}) | {"gui": (gui["scope"], gui["cid"], raw)}
    C.need(set(rows) == {"q3", "r4", "core", "gui"} and
           len({scope for scope, _, _ in rows.values()}) == len({cid for _, cid, _ in rows.values()}) == 4
           and all(scope != SCOPE for scope, _, _ in rows.values()), "Four distinct retired prerequisites required")
    return rows


def launcher_pin(handoff):
    # The sealed historical ELF reader is kept for provenance. The host launcher
    # never imports it and the checkout contains its later corrected version.
    unused_historical_elf = F.Q.LANE + "/elf_readback.py"
    for name, row in handoff["source"].items():
        if name != unused_historical_elf:
            F.pinned_file(F.Q.ROOT / name, F.Q.pin_ref(row))
    return C.read(Path(__file__).resolve(), 64 * 1024, collect=False)[1]


def site_descriptor(root, handoff_sha, historical, retirement):
    identity = capsule_identity(root)
    handoff, plan = F.load_capsule(root, handoff_sha)
    predecessors(historical, retirement)
    return dict(kind=SITE_KIND, scope=SCOPE, nonce=plan["nonce"], plan_sha256=handoff["plan"]["sha256"],
                capsule=identity | {"handoff_sha256": handoff_sha}, launcher=launcher_pin(handoff),
                qtgui_handoff=str(historical), qtgui_retirement=str(retirement))


def load_site(path, site_sha, root):
    site = C.json_body(C.external(path, 16 * 1024, site_sha)[0], canonical=True)
    capsule = site["capsule"]
    matches_root(site, root)
    expected = site_descriptor(root, capsule["handoff_sha256"], Path(site["qtgui_handoff"]),
                               Path(site["qtgui_retirement"]))
    C.need(C.wire(site) == C.wire(expected), "Exact selected full-target host site required")
    handoff, plan = F.load_capsule(root, capsule["handoff_sha256"])
    return site, handoff, plan


def matches_root(site, root):
    capsule = site["capsule"]
    C.need(capsule == capsule_identity(root) | {"handoff_sha256": capsule["handoff_sha256"]},
           "Selected site and capsule root differ")


def client_for(handoff, plan):
    return OLD.Client(handoff | {"docker": handoff["runner"]["docker"]}, plan)


def preflight(site, handoff, plan, site_sha):
    root = Path(site["capsule"]["path"])
    matches_root(site, root)
    claimed = os.path.lexists(root / CLAIM)
    checked = F.preflight(root, site["capsule"]["handoff_sha256"])
    client_for(handoff, plan).check()  # No daemon process under the passive fence.
    return checked | dict(status="HOLD_PREVIOUS_CLAIM" if claimed else "PASS_FULL_TARGET_HOST_PREFLIGHT_ONLY",
                          previous_claim_present=claimed, scope=SCOPE, site_sha256=site_sha, actor_entered=False)


def owning_group():
    group = OLD.run_bounded(["/usr/bin/systemctl", "--user", "show", "--property=ControlGroup", "--value", SCOPE],
                           15).decode("ascii").removesuffix("\n")
    C.need(OLD.GROUP.fullmatch(group) and group.endswith("/" + SCOPE)
           and Path("/proc/self/cgroup").read_text() == f"0::{group}\n", "Exact owning full-target scope required")
    return group


def predecessors_absent(client, rows):
    for _ in range(2):
        for scope, cid, _ in rows.values():
            C.need(OLD.scope_listing(scope) == client.absent(cid) == b"", "A selected predecessor remains")
        time.sleep(0.1)


def actor_args(handoff_sha, authority_sha):
    C.need(C.SHA.fullmatch(handoff_sha) and C.SHA.fullmatch(authority_sha), "Exact actor digests required")
    return ["-I", "-B", "-Werror", ACTOR, "--handoff-sha256", handoff_sha, "--authority-sha256", authority_sha]


def mounts_for(attempt):
    root = attempt.parent
    return [(str(root / "source"), "/src", False), (str(root / F.HANDOFF), "/handoff.json", False),
            (str(root / F.PLAN), "/plan.json", False), (str(attempt / "selection.json"), "/selection.json", False),
            (str(root / "inputs"), "/inputs", False), (str(attempt / "output"), "/out", True)]


def attempt_meta(site, handoff, plan, group, attempt, authority_sha, site_sha):
    C.need(OLD.GROUP.fullmatch(group) and group.endswith("/" + SCOPE)
           and attempt == Path(site["capsule"]["path"]) / CLAIM and F.Q.NONCE.fullmatch(plan["nonce"]),
           "Exact scoped capsule claim required")
    return dict(kind=ATTEMPT_KIND, one_original=True, scope=SCOPE, scope_group=group,
                image=handoff["runner"]["actor_image"], name="caa-qtbase16k-full-" + plan["nonce"],
                nonce=plan["nonce"], authority_sha256=authority_sha, site_sha256=site_sha,
                handoff_sha256=site["capsule"]["handoff_sha256"], plan_sha256=handoff["plan"]["sha256"],
                output=str(attempt / "output"), memory_bytes=plan["limits"]["actor_memory_bytes"],
                vcpus=handoff["runner"]["vcpus"], attach_seconds=plan["attach_seconds"])


def create_args(attempt, meta):
    mounts = []
    for source, target, rw in mounts_for(attempt):
        C.need(re.fullmatch(r"/[A-Za-z0-9_./-]+", source), "Literal private bind path required")
        mounts += ["--mount", f"type=bind,source={source},target={target}" + ("" if rw else ",readonly")]
    roles = [word for flag in ROLE_FLAGS for word in ("--env", flag)]
    return ["container", "create", "--name", meta["name"], "--cidfile", str(attempt / "run.cid"),
            "--pull=never", "--init=false", "--read-only", "--network=none", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--cgroupns=private", "--ipc=private", "--restart=no",
            "--runtime=runc", "--log-driver=json-file", "--log-opt=max-size=2m", "--log-opt=max-file=1",
            f"--cpus={meta['vcpus']}", f"--memory={meta['memory_bytes']}", f"--memory-swap={meta['memory_bytes']}",
            "--pids-limit=256", "--tmpfs", "/tmp:rw,nodev,nosuid,noexec,size=32m",
            "--label", NONCE_LABEL + "=" + meta["nonce"], *roles, *mounts,
            "--entrypoint", "/usr/bin/python3", meta["image"], *actor_args(meta["handoff_sha256"], meta["authority_sha256"])]


def owned_row(raw, meta, cid):
    rows = T.decode(raw)
    C.need(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict, "Exact original container receipt required")
    row = rows[0]
    args = actor_args(meta["handoff_sha256"], meta["authority_sha256"])
    C.need(row["Id"] == cid and row["Image"] == meta["image"] and row["Name"] == "/" + meta["name"]
           and row["Path"] == "/usr/bin/python3" and row["Args"] == args
           and row["Config"]["Labels"].get(NONCE_LABEL) == meta["nonce"], "Exact owned full-target CID required")
    return row


def inspect_row(raw, attempt, meta, cid):
    row = owned_row(raw, meta, cid)
    mounts, host, cfg = row["Mounts"], row["HostConfig"], row["Config"]
    C.need(cfg["Entrypoint"] == ["/usr/bin/python3"] and cfg["Cmd"] == row["Args"]
           and cfg["User"] == "" and cfg["WorkingDir"] == "/"
           and all(cfg["Env"].count(flag) == 1 for flag in ROLE_FLAGS)
           and all(env.split("=", 1)[0] not in {"LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PYTHONHOME",
                                                "CACHY_ASAHI_QTBASE16K_ACTOR"} for env in cfg["Env"]),
           "Exact full-target actor configuration required")
    C.need(host["NetworkMode"] == "none" and host["ReadonlyRootfs"] is True and host["Privileged"] is False
           and host["Init"] is host["AutoRemove"] is False and host["CapDrop"] == ["ALL"]
           and host["Memory"] == host["MemorySwap"] == meta["memory_bytes"]
           and host["NanoCpus"] == meta["vcpus"] * 1_000_000_000 and host["PidsLimit"] == 256
           and host["SecurityOpt"] in (["no-new-privileges"], ["no-new-privileges=true"])
           and host["CgroupnsMode"] == host["IpcMode"] == "private"
           and host["RestartPolicy"] == dict(Name="no", MaximumRetryCount=0)
           and host["Runtime"] == "runc"
           and host["LogConfig"] == {"Type": "json-file", "Config": {"max-size": "2m", "max-file": "1"}}
           and not any(host.get(key) for key in ("CapAdd", "Devices", "DeviceRequests", "DeviceCgroupRules",
                       "PortBindings", "VolumesFrom", "PidMode", "UsernsMode", "UTSMode", "Binds", "Links",
                       "ExtraHosts", "GroupAdd", "PublishAllPorts", "CgroupParent"))
           and OLD.exact_tmpfs(host) and len(mounts) == len(mounts_for(attempt))
           and all(item["Type"] == "bind" and item["Propagation"] == "rprivate" and type(item["RW"]) is bool
                   for item in mounts)
           and {(item["Source"], item["Destination"], item["RW"]) for item in mounts} == set(mounts_for(attempt)),
           "Exact offline root, owned binds and resource limits required")
    return row


def matching_inspects(before, after, attempt, meta, cid, code):
    first, last = (inspect_row(raw, attempt, meta, cid) for raw in (before, after))
    C.need(OLD.genuine_state(first, "created") and OLD.genuine_state(last, "exited", code)
           and OLD.stable_config(first["HostConfig"], last["HostConfig"])
           and all(T.encoded(first[key]) == T.encoded(last[key]) for key in ("Config", "Mounts")),
           "Exact created and naturally exited full-target actor required")


def retained_receipts(attempt):
    files = ("run.cid", "run.create.stdout", "run.created.inspect.json", "run.exited.inspect.json",
             "run.attach-exit", "run.stdout", "run.stderr", "run.absence-1", "run.absence-2")
    receipts = {name: C.read(attempt / name, OLD.OUTPUT_CAP, collect=False)[1] for name in files}
    C.need(sum(receipts[name]["bytes"] for name in ("run.stdout", "run.stderr")) <= OLD.OUTPUT_CAP,
           "Combined attached streams exceed the output bound")
    return receipts


def host_result(attempt, meta, cid, code):
    actor = attempt / "output/actor-result.json"
    actor_pin = C.read(actor, 16 * 1024, collect=False)[1] if os.path.lexists(actor) else None
    return dict(kind=RETIREMENT_KIND, cid=cid, exit_code=code, natural=True,
                container_removed=True, absent_twice=True, receipts=retained_receipts(attempt), actor_result=actor_pin,
                **{key: meta[key] for key in ("nonce", "scope", "scope_group", "site_sha256", "authority_sha256",
                                              "handoff_sha256", "plan_sha256")})


def execute_owned(client, attempt, meta, check_entry):
    cid_file = attempt / "run.cid"
    cid = code = None
    removed = complete = False

    def inspect():
        return owned_row(client.docker("container", "inspect", cid), meta, cid)

    def cancel(_signum, _frame):
        raise InterruptedError("Full-target scope canceled")

    previous = {number: signal.signal(number, cancel) for number in OLD.ATTACH_SIGNAL_SET}
    try:
        check_entry()
        created = client.docker(*create_args(attempt, meta))
        OLD.save(attempt / "run.create.stdout", created)
        cid = OLD.scoped_identity(T.read(cid_file, cap=70))
        C.need(OLD.scoped_identity(created) == cid, "Create stdout and claimed CID differ")
        before = client.docker("container", "inspect", cid)
        OLD.save(attempt / "run.created.inspect.json", before)
        C.need(OLD.genuine_state(inspect_row(before, attempt, meta, cid), "created"), "Fresh original actor required")
        check_entry()
        code = client.attach(attempt, cid)
        OLD.save(attempt / "run.attach-exit", f"{code}\n".encode())
        after = client.docker("container", "inspect", cid)
        OLD.save(attempt / "run.exited.inspect.json", after)
        C.need(type(code) is int and code in ORIGINAL_CODES, "Expected an original actor exit")
        matching_inspects(before, after, attempt, meta, cid, code)
        OLD.remove_owned(client, cid, inspect)
        removed = True
        for index in (1, 2):
            OLD.save(attempt / f"run.absence-{index}", b"")
        OLD.save(attempt / "host-result.json", C.wire(host_result(attempt, meta, cid, code)))
        complete = True
        return code
    finally:
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, OLD.ATTACH_SIGNAL_SET)
        try:
            if not complete:
                try:
                    if not removed and cid_file.is_file():
                        cid = OLD.scoped_identity(T.read(cid_file, cap=70))
                        listing = client.absent(cid)
                        C.need(listing in (b"", (cid + "\n").encode()), "Ambiguous emergency CID census")
                        if listing:
                            OLD.remove_owned(client, cid, inspect, emergency=True)
                            removed = True
                finally:
                    hold = dict(kind=RETIREMENT_KIND, cid=cid, exit_code=code, natural=False,
                                container_removed=removed, nonce=meta["nonce"], site_sha256=meta["site_sha256"])
                    OLD.save(attempt / "host-HOLD.json", C.wire(hold))
        finally:
            for number, handler in previous.items():
                signal.signal(number, handler)
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)


def clone_result(root, attempt, plan):
    template, result = root / "templates/result.raw", attempt / "output/result.raw"
    F.K.clone(template, result, plan["inputs"]["result.raw"])
    result.chmod(0o600)
    C.need(stat.S_IMODE(result.lstat().st_mode) == 0o600 and not result.samefile(template),
           "Separate private writable result required")
    F.verify_result_template(result, plan)


def run(site, handoff, plan, site_sha, authority_path, authority_sha):
    root = Path(site["capsule"]["path"])
    matches_root(site, root)
    attempt = root / CLAIM
    C.need(not os.path.lexists(attempt), "Full-target attempt already claimed")
    handoff_sha = site["capsule"]["handoff_sha256"]
    raw, _ = C.external(authority_path, 16 * 1024, authority_sha)
    F.verify_selection(raw, authority_sha, handoff, plan, handoff_sha)
    group = owning_group()
    before = F.preflight(root, handoff_sha)
    client = client_for(handoff, plan)
    client.verify_daemon()
    rows = predecessors(Path(site["qtgui_handoff"]), Path(site["qtgui_retirement"]))
    predecessors_absent(client, rows)
    meta = attempt_meta(site, handoff, plan, group, attempt, authority_sha, site_sha)
    C.need(client.docker("container", "ls", "-a", "--no-trunc", "--filter", "name=^/" + meta["name"] + "$",
                         "--format", "{{.ID}}") == b"", "A container already occupies the selected name")

    def entry():
        matches_root(site, root)
        F.verify_selection(raw, authority_sha, handoff, plan, handoff_sha)
        C.need(F.capacity(root, plan)["fits"], "Current host admission limits are unmet")

    entry()
    attempt.mkdir(mode=0o700)  # Atomic and permanent, including a failed attempt.
    (attempt / "output").mkdir(mode=0o700)
    OLD.save(attempt / "attempt.json", C.wire(meta))
    OLD.save(attempt / "selection.json", raw)
    for name, (_, _, body) in rows.items():
        OLD.save(attempt / f"prior-{name}-closure.json", body)
    OLD.save(attempt / "capacity.json", C.wire(before["capacity"]))
    clone_result(root, attempt, plan)
    return execute_owned(client, attempt, meta, entry)


def read_attempt(site, handoff, plan, site_sha):
    root = Path(site["capsule"]["path"])
    matches_root(site, root)
    attempt = T.ordinary(root / CLAIM)
    C.need(stat.S_IMODE(attempt.lstat().st_mode) == 0o700 and attempt.is_dir()
           and attempt.lstat().st_uid == os.getuid() and not os.path.lexists(attempt / "host-HOLD.json"),
           "Exact original natural full-target claim required")
    meta, _ = OLD.encoded_file(attempt / "attempt.json")
    authority_sha = meta["authority_sha256"]
    C.need(meta == attempt_meta(site, handoff, plan, meta["scope_group"], attempt, authority_sha, site_sha),
           "Original full-target claim differs")
    F.verify_selection(C.read(attempt / "selection.json", 16 * 1024)[0], authority_sha, handoff, plan,
                       meta["handoff_sha256"], live=False)
    rows = predecessors(Path(site["qtgui_handoff"]), Path(site["qtgui_retirement"]))
    for name, (_, _, raw) in rows.items():
        C.read(attempt / f"prior-{name}-closure.json", 128 << 10, C.pin(raw), collect=False)
    host, pin = OLD.encoded_file(attempt / "host-result.json")
    cid = OLD.scoped_identity(T.read(attempt / "run.cid", cap=70))
    code = host["exit_code"]
    C.need(type(code) is int and code in ORIGINAL_CODES and host == host_result(attempt, meta, cid, code)
           and T.read(attempt / "run.attach-exit", cap=8) == f"{code}\n".encode()
           and T.read(attempt / "run.create.stdout", cap=70) == (cid + "\n").encode()
           and all(T.read(attempt / f"run.absence-{n}", cap=1) == b"" for n in (1, 2)),
           "Exact retained original full-target lifecycle required")
    matching_inspects(*(T.read(attempt / f"run.{state}.inspect.json", cap=OLD.OUTPUT_CAP)
                        for state in ("created", "exited")), attempt, meta, cid, code)
    return meta, host, pin


def observe(site, handoff, plan, site_sha):
    meta, host, pin = read_attempt(site, handoff, plan, site_sha)
    client = client_for(handoff, plan)
    client.verify_daemon()
    for _ in range(2):
        C.need(OLD.scope_listing(SCOPE) == client.absent(host["cid"]) == b"",
               "Original full-target scope or container remains")
        time.sleep(0.1)
    return dict(kind=OBSERVATION_KIND, host_result=pin, cid=host["cid"], exit_code=host["exit_code"],
                actor_result=host["actor_result"],
                observations=[dict(scope_absent=True, container_absent=True)] * 2, authority=None,
                **{key: meta[key] for key in ("nonce", "scope", "scope_group", "site_sha256", "authority_sha256",
                                              "handoff_sha256", "plan_sha256")})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capsule", type=Path, required=True)
    modes = parser.add_subparsers(dest="mode", required=True)
    prepare = modes.add_parser("describe")
    prepare.add_argument("--handoff-sha256", required=True)
    prepare.add_argument("--qtgui-handoff", type=Path, required=True)
    prepare.add_argument("--qtgui-retirement", type=Path, required=True)
    for mode in ("preflight", "run", "observe"):
        sub = modes.add_parser(mode)
        sub.add_argument("--site", type=Path, required=True)
        sub.add_argument("--site-sha256", required=True)
        if mode == "run":
            sub.add_argument("--authority", type=Path, required=True)
            sub.add_argument("--authority-sha256", required=True)
    args = parser.parse_args()
    C.need(sys.flags.isolated and sys.dont_write_bytecode and __debug__, "Use isolated unoptimized Python")
    os.umask(0o077)
    if args.mode in ("describe", "preflight"):
        sys.addaudithook(C.audit_fence)
    if args.mode == "describe":
        doc = site_descriptor(args.capsule, args.handoff_sha256, args.qtgui_handoff, args.qtgui_retirement)
        sys.stdout.buffer.write(C.wire(doc))
        return 0
    site, handoff, plan = load_site(args.site, args.site_sha256, args.capsule)
    if args.mode == "run":
        return run(site, handoff, plan, args.site_sha256, args.authority, args.authority_sha256)
    if args.mode == "observe":
        sys.stdout.buffer.write(C.wire(observe(site, handoff, plan, args.site_sha256)))
        return 0
    report = preflight(site, handoff, plan, args.site_sha256)
    sys.stdout.buffer.write(C.wire(report))
    return 2 if report["previous_claim_present"] else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, KeyboardInterrupt):
        raise SystemExit("Full Qtbase host refused or held") from None
