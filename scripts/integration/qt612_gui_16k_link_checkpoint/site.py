# SPDX-License-Identifier: MIT
"""Root's once-only host entry and post-scope observer for a sealed QtGui capsule."""

import argparse
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import gui_capsule as C

T = C.T
LANE = "scripts/integration/qt612_gui_16k_link_checkpoint"
HANDOFF, PLAN = C.HANDOFF_LEAF, C.PLAN_LEAF
BINDING = "binding.UNISSUED.json"
ATTEMPT_KIND = "QTGUI_LINK_HOST_ATTEMPT_V1"
RETIREMENT_KIND = "QTGUI_LINK_HOST_RETIREMENT_V1"
OBSERVATION_KIND = "QTGUI_LINK_POST_SCOPE_V1"
ROLE_FLAGS = ("CACHY_ASAHI_QTBASE16K_ACTOR=1", "CACHY_ASAHI_OVERLAY583_ACTOR=1")
NONCE_LABEL = "org.cachy-asahi.qtgui16k.nonce"
HEX = re.compile("[a-f0-9]{64}")
NONCE = re.compile("[a-f0-9]{32}")
GROUP = re.compile(r"(?:/[A-Za-z0-9_.@-]+)+")
UNIT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,247}\.scope")
OUTPUT_CAP = 2 << 20
ATTACH_SIGNAL_SET = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


def fence(event, _args):
    if event.startswith(("subprocess.", "socket.", "os.exec", "os.posix_spawn", "os.system")):
        raise RuntimeError("Passive preflight forbids execution and network: " + event)


def save(path, raw):
    with path.open("xb") as stream:
        stream.write(raw)
    path.chmod(0o444)


def encoded_file(path, cap=128 << 10):
    raw = T.read(path, cap=cap)
    value = T.decode(raw)
    T.need(type(value) is dict and raw == T.encoded(value), "Expected canonical host receipt " + path.name)
    return value, T.pin(raw)


def plan_path(root):
    return root / PLAN


def load_site(path, digest):
    selected = T.ordinary(path)
    root = selected.parent
    T.need(selected.name == HANDOFF and root / "source" / LANE == HERE
           and stat.S_IMODE(root.stat().st_mode) == 0o700,
           "Run the sealed site inside the exact private QtGui capsule")
    handoff = C.load_handoff(selected, digest)
    expected_plan = handoff["plan"]
    plan = C.load_plan(plan_path(root), expected_plan["sha256"])
    T.read(plan_path(root), expected_plan, cap=128 << 10, collect=False)
    C.verify_source(handoff, root / "source")
    binding = T.read(root / BINDING, cap=128 << 10)
    T.need(binding == T.encoded(C.binding(handoff, plan, digest)), "Exact unissued Root binding differs")
    return root, handoff, plan


def actor_args(handoff_sha, authority_sha):
    T.need(all(type(value) is str and HEX.fullmatch(value) for value in (handoff_sha, authority_sha)),
           "Exact actor input digests required")
    return ["-I", "-B", "-Werror", C.ACTOR_PATH, "--handoff-sha256", handoff_sha,
            "--authority-sha256", authority_sha]


def mounts_for(attempt):
    root = attempt.parent
    return [(str(root / "source"), "/src", False),
            (str(root / HANDOFF), "/handoff.json", False),
            (str(plan_path(root)), "/plan.json", False),
            (str(attempt / "selection.json"), "/selection.json", False),
            (str(root / "inputs"), "/inputs", False),
            (str(attempt / "output"), "/out", True)]


def attempt_meta(handoff, plan, handoff_sha, authority_sha, group, attempt):
    T.need(GROUP.fullmatch(group) and group.endswith("/" + C.SCOPE), "Exact owning scope group required")
    T.need(NONCE.fullmatch(plan["nonce"]), "Exact QtGui run nonce required")
    return dict(kind=ATTEMPT_KIND, one_original=True, scope=C.SCOPE, scope_group=group, image=handoff["runner"]["actor_image"],
                name="caa-qtgui-link-" + plan["nonce"], nonce=plan["nonce"], authority_sha256=authority_sha,
                handoff_sha256=handoff_sha, plan_sha256=handoff["plan"]["sha256"], output=str(attempt / "output"),
                memory_bytes=plan["limits"]["actor_memory_bytes"], vcpus=handoff["runner"]["vcpus"],
                attach_seconds=plan["attach_seconds"])


def bound_output():
    resource.setrlimit(resource.RLIMIT_FSIZE, (OUTPUT_CAP, OUTPUT_CAP))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def env_for_cli():
    keys = ("HOME", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "XDG_CONFIG_HOME")
    return {"PATH": "/usr/bin:/bin", "LC_ALL": "C", **{key: os.environ[key] for key in keys if key in os.environ}}


def run_bounded(argv, seconds=45):
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        subprocess.run(argv, env=env_for_cli(), stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                       timeout=seconds, check=True, preexec_fn=bound_output)
        stdout.seek(0)
        stderr.seek(0)
        body = stdout.read(OUTPUT_CAP + 1)
        T.need(len(body) <= OUTPUT_CAP and not stderr.read(1), "Bounded command output and quiet stderr required")
        return body


class Client:
    def __init__(self, handoff, plan):
        selected = handoff["docker"]
        self.path = T.ordinary(Path(selected["path"]))
        self.endpoint = selected["endpoint"]
        self.image = handoff["runner"]["actor_image"]
        self.attach_seconds = plan["attach_seconds"]
        uid = os.getuid()
        T.need(uid == os.geteuid() and uid > 0 and
               re.fullmatch(rf"unix:///run/user/{uid}/[A-Za-z0-9_.-]+", self.endpoint),
               "Exact current-user rootless Docker endpoint required")
        self.socket_path = T.ordinary(Path(self.endpoint.removeprefix("unix://")))
        cli, socket = self.path.lstat(), self.socket_path.lstat()
        T.need(cli.st_uid in (0, uid) and socket.st_uid == uid and
               stat.S_ISREG(cli.st_mode) and cli.st_nlink == 1 and cli.st_mode & 0o111
               and not cli.st_mode & 0o022 and stat.S_ISSOCK(socket.st_mode),
               "Exact ordinary executable Docker CLI and rootless socket required")
        self.cli = T.identity(cli)
        self.socket = (socket.st_dev, socket.st_ino, socket.st_uid)
        T.read(self.path, {key: selected[key] for key in ("bytes", "sha256")}, cap=64 << 20, collect=False)
        self.check()

    def check(self):
        cli, socket = self.path.lstat(), self.socket_path.lstat()
        T.need(T.identity(cli) == self.cli and stat.S_ISSOCK(socket.st_mode)
               and (socket.st_dev, socket.st_ino, socket.st_uid) == self.socket,
               "Reviewed Docker CLI or endpoint identity changed")

    def argv(self, args):
        self.check()
        return [str(self.path), "--host", self.endpoint, *args]

    def docker(self, *args):
        raw = run_bounded(self.argv(args))
        self.check()
        return raw

    def absent(self, cid):
        return self.docker("container", "ls", "-a", "--no-trunc", "--filter", "id=" + cid, "--format", "{{.ID}}")

    def attach(self, attempt, cid):
        argv = self.argv(("container", "start", "--attach", cid))
        with (attempt / "run.stdout").open("xb") as stdout, (attempt / "run.stderr").open("xb") as stderr:
            row = subprocess.run(argv, env=env_for_cli(), stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                 timeout=self.attach_seconds, preexec_fn=bound_output)
        self.check()
        return row.returncode

    def verify_daemon(self):
        options = T.decode(self.docker("info", "--format", "{{json .SecurityOptions}}"))
        T.need(type(options) is list and "name=rootless" in options
               and self.docker("image", "inspect", "--format", "{{.Id}}", self.image) == (self.image + "\n").encode(),
               "Exact image already present in reviewed rootless Docker daemon required")


def scope_listing(scope):
    T.need(UNIT.fullmatch(scope), "Exact systemd scope identifier required")
    return run_bounded(["/usr/bin/systemctl", "--user", "list-units", "--all", "--type=scope",
                        "--no-legend", "--no-pager", scope], 15)


def scoped_identity(raw):
    value = raw.decode("ascii").removesuffix("\n")
    T.need(HEX.fullmatch(value), "Exact original full CID required")
    return value


def local_scope(client, predecessors):
    group = run_bounded(["/usr/bin/systemctl", "--user", "show", "--property=ControlGroup",
                         "--value", C.SCOPE], 15).decode("ascii").removesuffix("\n")
    T.need(GROUP.fullmatch(group) and group.endswith("/" + C.SCOPE)
           and Path("/proc/self/cgroup").read_text() == f"0::{group}\n", "Exact owned QtGui scope required")
    T.need(set(predecessors) == {"q3", "r4", "core"}, "Exact Q3, R4 and QtCore closure set required")
    for _ in range(2):
        for scope, cid, _ in predecessors.values():
            T.need(scope != C.SCOPE and UNIT.fullmatch(scope) and HEX.fullmatch(cid)
                   and scope_listing(scope) == client.absent(cid) == b"",
                   "A selected predecessor scope or CID remains")
        time.sleep(0.1)
    return group


def exact_tmpfs(host):
    options = host.get("Tmpfs") or {}
    fields = options.get("/tmp", "").split(",")
    security = {"rw", "nodev", "nosuid", "noexec"}
    return set(options) == {"/tmp"} and len(fields) == 5 and set(fields) in (
        security | {"size=32m"}, security | {"size=33554432"})


def inspect_row(raw, attempt, meta, cid):
    rows = T.decode(raw)
    T.need(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict, "Exactly one original inspect row")
    row = rows[0]
    tags, host, cfg = row["Mounts"], row["HostConfig"], row["Config"]
    args = actor_args(meta["handoff_sha256"], meta["authority_sha256"])
    mounts = mounts_for(attempt)
    T.need(row["Id"] == cid and row["Image"] == meta["image"] and row["Name"] == "/" + meta["name"]
           and row["Path"] == "/usr/bin/python3" and row["Args"] == args
           and cfg["Entrypoint"] == ["/usr/bin/python3"] and cfg["Cmd"] == args
           and cfg["User"] == "" and cfg["WorkingDir"] == "/" and cfg["Labels"][NONCE_LABEL] == meta["nonce"]
           and all(cfg["Env"].count(flag) == 1 for flag in ROLE_FLAGS),
           "Exact original image, actor args and nonce label required")
    T.need(host["NetworkMode"] == "none" and host["ReadonlyRootfs"] is True and host["Privileged"] is False
           and host["Init"] is False and host["AutoRemove"] is False and host["CapDrop"] == ["ALL"]
           and host["Memory"] == host["MemorySwap"] == meta["memory_bytes"]
           and host["NanoCpus"] == meta["vcpus"] * 1_000_000_000
           and host["PidsLimit"] == 256 and host["SecurityOpt"] in (["no-new-privileges"], ["no-new-privileges=true"])
           and not any(host.get(key) for key in
                       ("CapAdd", "Devices", "DeviceRequests", "DeviceCgroupRules", "PortBindings", "VolumesFrom"))
           and exact_tmpfs(host) and len(tags) == len(mounts)
           and all(item["Type"] == "bind" and item["Propagation"] == "rprivate" and type(item["RW"]) is bool
                   for item in tags)
           and {(item["Source"], item["Destination"], item["RW"]) for item in tags} == set(mounts),
           "Exact offline read-only root, sole writable output and owned container limits required")
    return row


def genuine_state(row, expected, exit_code=None):
    state = row["State"]
    return (state["Status"] == expected and state["Running"] is state["OOMKilled"] is False
            and state["Pid"] == 0 and state["Error"] == ""
            and (exit_code is None or (type(state["ExitCode"]) is int and state["ExitCode"] == exit_code)))


def stable_config(first, last):
    if T.encoded(first) == T.encoded(last):
        return True
    before, after = dict(first), dict(last)
    absent = object()
    observed = (before.pop("OomKillDisable", absent), after.pop("OomKillDisable", absent),
                before.pop("OomScoreAdj", absent), after.pop("OomScoreAdj", absent))
    return (observed[0] is False and observed[1] is None and type(observed[2]) is type(observed[3]) is int
            and observed[2:] == (0, 200) and T.encoded(before) == T.encoded(after))


def matching_inspects(before, after, attempt, meta, cid, exit_code):
    first, last = (inspect_row(raw, attempt, meta, cid) for raw in (before, after))
    T.need(genuine_state(first, "created") and genuine_state(last, "exited", exit_code)
           and stable_config(first["HostConfig"], last["HostConfig"])
           and all(T.encoded(first[key]) == T.encoded(last[key]) for key in ("Config", "Mounts")),
           "Exact original created/exited states and allowed rootless Docker defaults required")


def create_args(attempt, meta):
    options = []
    for source, target, rw in mounts_for(attempt):
        T.need(not any(char in source for char in ",\0\n\r"), "Literal private bind path required")
        options += ["--mount", f"type=bind,source={source},target={target}" + ("" if rw else ",readonly")]
    role = [item for flag in ROLE_FLAGS for item in ("--env", flag)]
    return ["container", "create", "--name", meta["name"], "--cidfile", str(attempt / "run.cid"),
            "--pull=never", "--init=false", "--read-only", "--network=none", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", f"--cpus={meta['vcpus']}", f"--memory={meta['memory_bytes']}",
            f"--memory-swap={meta['memory_bytes']}",
            "--pids-limit=256", "--tmpfs", "/tmp:rw,nodev,nosuid,noexec,size=32m",
            "--label", NONCE_LABEL + "=" + meta["nonce"], *role, *options, "--entrypoint", "/usr/bin/python3",
            meta["image"], *actor_args(meta["handoff_sha256"], meta["authority_sha256"])]


def remove_owned(client, cid, inspect, *, emergency=False):
    if inspect()["State"]["Running"]:
        T.need(emergency, "Original actor unexpectedly still running")
        client.docker("container", "stop", "--time", "20", cid)
        T.need(inspect()["State"]["Running"] is False, "Original actor did not stop")
    client.docker("container", "rm", cid)
    for _ in range(2):
        T.need(client.absent(cid) == b"", "Original CID still present or listing is ambiguous")
        time.sleep(0.1)


def host_result(meta, cid, exit_code):
    keys = ("authority_sha256", "handoff_sha256", "plan_sha256", "scope", "scope_group", "nonce")
    return dict(kind=RETIREMENT_KIND, cid=cid, natural=True, exit_code=exit_code, container_removed=True,
                absent_twice=True, **{key: meta[key] for key in keys})


def execute_owned(client, attempt, meta):
    claimed_cid = attempt / "run.cid"
    removed = False

    def inspect():
        return inspect_row(client.docker("container", "inspect", cid), attempt, meta, cid)

    def cancel(signum, _frame):
        raise InterruptedError(f"QtGui host scope signal {signum}")

    previous = {number: signal.signal(number, cancel) for number in ATTACH_SIGNAL_SET}
    try:
        created = client.docker(*create_args(attempt, meta))
        cid = scoped_identity(T.read(claimed_cid, cap=70))
        T.need(scoped_identity(created) == cid, "Create stdout and original CID file differ")
        before = client.docker("container", "inspect", cid)
        T.need(genuine_state(inspect_row(before, attempt, meta, cid), "created"), "Fresh original actor required")
        save(attempt / "run.created.inspect.json", before)
        exit_code = client.attach(attempt, cid)
        save(attempt / "run.attach-exit", f"{exit_code}\n".encode())
        after = client.docker("container", "inspect", cid)
        save(attempt / "run.exited.inspect.json", after)
        T.need(type(exit_code) is int and 0 <= exit_code < 124, "Natural attached actor exit required")
        matching_inspects(before, after, attempt, meta, cid, exit_code)
        remove_owned(client, cid, inspect)
        removed = True
        for index in (1, 2):
            save(attempt / f"run.absence-{index}", b"")
        save(attempt / "host-result.json", T.encoded(host_result(meta, cid, exit_code)))
        return exit_code
    finally:
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, ATTACH_SIGNAL_SET)
        try:
            if not removed and claimed_cid.is_file():
                cid = scoped_identity(T.read(claimed_cid, cap=70))
                listing = client.absent(cid)
                T.need(listing in (b"", (cid + "\n").encode()), "Ambiguous emergency CID census")
                if listing:
                    remove_owned(client, cid, inspect, emergency=True)
        finally:
            for number, handler in previous.items():
                signal.signal(number, handler)
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)


def clone_result(root, attempt, plan):
    template, target = root / "templates/result.raw", attempt / "output/result.raw"
    selected = plan["inputs"]["result.raw"]
    C.K.clone(template, target, selected)
    target.chmod(0o600)
    T.need(stat.S_IMODE(target.lstat().st_mode) == 0o600 and not target.samefile(template)
           and C.result_uuid(target, plan["limits"]["result_disk_bytes"]) == plan["result_uuid"],
           "Attempt result must be the exact separate writable inode")
    C.check_pinned_file(target, selected)


def run(root, handoff, plan, handoff_sha, authority, authority_sha):
    claim = root / "root-run.claim"
    T.need(not os.path.lexists(claim), "One original QtGui attempt already claimed")
    raw = T.read(authority, cap=128 << 10)
    issued = C.verify_selection(raw, authority_sha, handoff, plan, handoff_sha, live=True)
    T.need(C.preflight_root(root, handoff, plan)["fits"], "Current host gates are below the sealed limits")
    predecessors = C.read_predecessors(handoff)
    client = Client(handoff, plan)
    group = local_scope(client, predecessors)
    client.verify_daemon()
    claim.mkdir(mode=0o700)
    attempt = Path(tempfile.mkdtemp(prefix="issued.", dir=root))
    (attempt / "output").mkdir(mode=0o700)
    save(claim / "attempt.path", (str(attempt) + "\n").encode())
    save(attempt / "scope.path", (group + "\n").encode())
    meta = attempt_meta(handoff, plan, handoff_sha, authority_sha, group, attempt)
    save(attempt / "attempt.json", T.encoded(meta))
    save(attempt / "selection.json", raw)
    for name, (_, _, body) in predecessors.items():
        save(attempt / f"prior-{name}-closure.json", body)
    clone_result(root, attempt, plan)
    current = C.preflight_root(root, handoff, plan)
    save(attempt / "capacity.json", T.encoded(current))
    T.need(current["fits"] and int(time.time()) < issued["expires_utc"],
           "Host capacity or exact Root entry window changed before create")
    return execute_owned(client, attempt, meta)


def read_attempt(root, handoff, plan, handoff_sha, attempt):
    attempt = T.ordinary(attempt)
    T.need(attempt.parent == root and re.fullmatch(r"issued\.[A-Za-z0-9_]+", attempt.name)
           and stat.S_IMODE(attempt.stat().st_mode) == 0o700
           and T.read(root / "root-run.claim/attempt.path", cap=4096) == (str(attempt) + "\n").encode(),
           "Exact original once-claimed attempt required")
    meta, _ = encoded_file(attempt / "attempt.json")
    group = T.read(attempt / "scope.path", cap=1024).decode("ascii").removesuffix("\n")
    authority_sha = meta["authority_sha256"]
    T.need(meta == attempt_meta(handoff, plan, handoff_sha, authority_sha, group, attempt),
           "Exact original host attempt identity required")
    C.verify_selection(T.read(attempt / "selection.json", cap=128 << 10), authority_sha,
                       handoff, plan, handoff_sha, live=False)
    cid = scoped_identity(T.read(attempt / "run.cid", cap=70))
    host, pin = encoded_file(attempt / "host-result.json")
    code = host["exit_code"]
    T.need(type(code) is int and 0 <= code < 124 and T.encoded(host) == T.encoded(host_result(meta, cid, code))
           and T.read(attempt / "run.attach-exit", cap=8) == f"{code}\n".encode()
           and all(T.read(attempt / f"run.absence-{index}", cap=8) == b"" for index in (1, 2)),
           "Exact original natural host retirement and once-only evidence required")
    matching_inspects(*(T.read(attempt / leaf, cap=OUTPUT_CAP) for leaf in
                        ("run.created.inspect.json", "run.exited.inspect.json")), attempt, meta, cid, code)
    for name, ref in handoff["prior_closures"].items():
        T.read(attempt / f"prior-{name}-closure.json", {field: ref[field] for field in ("bytes", "sha256")}, cap=128 << 10)
    return meta, host, pin


def observe(root, handoff, plan, handoff_sha, attempt):
    meta, host, pin = read_attempt(root, handoff, plan, handoff_sha, attempt)
    client = Client(handoff, plan)
    for _ in range(2):
        T.need(scope_listing(C.SCOPE) == client.absent(host["cid"]) == b"",
               "Exact QtGui scope or original CID still present")
        time.sleep(0.1)
    return dict(kind=OBSERVATION_KIND, cid=host["cid"], host_result=pin,
                observations=[dict(scope_absent=True, container_absent=True)] * 2,
                **{key: meta[key] for key in
                   ("nonce", "authority_sha256", "handoff_sha256", "plan_sha256", "scope", "scope_group")})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--handoff", type=Path, required=True)
    parser.add_argument("--handoff-sha256", required=True)
    sub = parser.add_subparsers(dest="mode", required=True)
    sub.add_parser("preflight")
    actor = sub.add_parser("run")
    actor.add_argument("--authority", type=Path, required=True)
    actor.add_argument("--authority-sha256", required=True)
    observer = sub.add_parser("observe")
    observer.add_argument("--attempt", type=Path, required=True)
    args = parser.parse_args()
    T.need(sys.flags.isolated and sys.dont_write_bytecode and __debug__, "Use isolated unoptimized Python")
    os.umask(0o077)
    if args.mode == "preflight":
        sys.addaudithook(fence)
    root, handoff, plan = load_site(args.handoff, args.handoff_sha256)
    if args.mode == "run":
        return run(root, handoff, plan, args.handoff_sha256, args.authority, args.authority_sha256)
    if args.mode == "observe":
        sys.stdout.buffer.write(T.encoded(observe(root, handoff, plan, args.handoff_sha256, args.attempt)))
        return 0
    measured = C.preflight_root(root, handoff, plan)
    client = Client(handoff, plan)
    client.check()
    claimed = os.path.lexists(root / "root-run.claim")
    status = ("HOLD_PREVIOUS_CLAIM" if claimed else
              "PASS_SEALED_UNISSUED_PREFLIGHT" if measured["fits"] else "HOLD_CURRENT_HOST_CAPACITY")
    sys.stdout.buffer.write(T.encoded(dict(status=status, authority=None, actor_entered=False,
                            previous_claim_present=claimed, capacity=measured, scope=C.SCOPE,
                            handoff_sha256=args.handoff_sha256, plan_sha256=handoff["plan"]["sha256"])))
    return 0 if measured["fits"] and not claimed else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        raise SystemExit("QtGui host refused: " + str(error)) from None
