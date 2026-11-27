# SPDX-License-Identifier: MIT
"""Owned execution of a separately issued, fully staged Qt629 trial.

Root selects an authority JSON with kind QT629_ROOT_LAUNCH_SELECTION_V1,
issuer Root, scope qt629-offline-test, the fresh nonce, launcher and receipt pins,
the preparation path and pin, and absolute paths for source, retained, seed,
control, control_boot, transaction_kernel and output. Pass its externally
selected digest to `run --authority … --authority-sha256 …` from a user scope
named cachy-qt629-run-<nonce>. This program never issues authority or signs.
"""

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
from runpy import run_path
import signal
import stat
import subprocess
import sys
import time
from types import FunctionType


HERE = Path(__file__).resolve().parent
LANE = "scripts/integration/qt612_r132_replacement"
M = run_path(str(HERE / "controller.py"))
ASSEMBLER = run_path(str(HERE / "receipt.py"))
C, H, R, need = (M[name] for name in ("C", "H", "R", "need"))
KIND = "QT629_ROOT_LAUNCH_SELECTION_V1"
SCOPE = "qt629-offline-test"
CAP = 128 << 10
GIB = 1 << 30
ATTACH_TIMEOUT = 5100
RETIRE_TIMEOUT = 90
DOCKER_SHA = "e966e0e6ea215b74fdbee17fbe7ed8bff15b65930bfc8e131652ceae4ed0210e"
ACTOR_IMAGE = "sha256:52958d534193d739aeb6d3c9239ed31b97f8fb357a618e14391293068b28cd2a"
AUTHORITY = Path("/inputs/authority.json")
PREPARED = Path("/inputs/preparation.json")
STAGE = Path("/inputs/stage")
FROZEN_SOURCE = Path("/inputs/retained-source")
FROZEN_AUTHORITY = Path("/inputs/retained-authority.json")
ACTOR_OUT = Path("/out/qt629")
ACTOR_PATHS = dict(staging=Path("/inputs/staging"), seed=Path("/inputs/seed/seed-root.img"),
                   control=Path("/inputs/control"), control_boot=Path("/inputs/control-boot"),
                   transaction_kernel=Path("/inputs/transaction-kernel"), output=ACTOR_OUT)
PATHS = {"source", "retained", "seed", "control", "control_boot", "transaction_kernel", "output"}
CID = re.compile(r"[0-9a-f]{64}")


def selected(path, digest):
    raw, pin = C.external(path, CAP, digest)
    row = C.json_body(raw, canonical=True)
    need(row.keys() == {"kind", "issuer", "scope", "nonce", "launcher", "receipt", "preparation", "paths"}
         and row["kind"] == KIND and row["issuer"] == "Root" and row["scope"] == SCOPE
         and type(row["nonce"]) is str and R["NONCE"].fullmatch(row["nonce"])
         and all(C.check_pin(row[name], CAP) for name in ("launcher", "receipt"))
         and type(row["paths"]) is dict and row["paths"].keys() == PATHS,
         "Exact separately Root-issued Qt629 launch authority required")
    prep = row["preparation"]
    need(type(prep) is dict and prep.keys() == {"path", "bytes", "sha256"}
         and type(prep["path"]) is str and Path(prep["path"]).is_absolute()
         and C.check_pin(C.file_pin(prep["bytes"], prep["sha256"]), CAP)
         and all(type(value) is str and Path(value).is_absolute() for value in row["paths"].values()),
         "Exact absolute issued operand paths and pins required")
    C.read(HERE / "launch.py", CAP, row["launcher"], collect=False)
    C.read(HERE / "receipt.py", CAP, row["receipt"], collect=False)
    return row, pin


def parity_profile(packet):
    return M["P"]["checked_profile"](packet["parity_profile"]) if "parity_profile" in packet else None


def prepared(authority, path, stage, source, *, current=True):
    ref = authority["preparation"]
    raw, _ = C.read(path, CAP, C.file_pin(ref["bytes"], ref["sha256"]))
    packet = C.json_body(raw, canonical=True)
    need(packet["kind"] == M["KIND"] and packet["authority"] is None
         and packet["preparation"] == "GUEST_FRAGMENT_STAGED" and packet["pending"] == []
         and packet["nonce"] == authority["nonce"] and packet["predecessor_nonce"] != packet["nonce"]
         and packet["retained"]["actor_image"] == ACTOR_IMAGE, "Completed fresh unissued Qt629 preparation required")
    pins = packet["staged"]
    need(pins["kind"] == "QT629_HOST_STAGE_UNISSUED_V1" and pins["authority"] is None
         and pins["path"] == str(Path(ref["path"]).parent / "stage")
         and pins["plan"] == pins["files"]["code/plan.json"], "Staged guest plan pin differs")
    need(packet["source"].keys() == {"controller.py", "host_stage.py", "export.py", "readback.py"}
         and packet["qt_source"].keys() == H["GUEST_ENTRY"]["SOURCES"], "Exact reviewed Qt source closure required")
    for name, expected in packet["source"].items():
        C.read(source / LANE / name, CAP, expected, collect=False)
    for name, expected in packet["qt_source"].items():
        C.read(source / name, CAP, expected, collect=False)
    plan_body, _ = C.read(stage / "code/plan.json", H["MAX_PLAN"], pins["plan"])
    plan = C.json_body(plan_body, canonical=True)
    profile = parity_profile(packet)
    need(M["P"]["plan_profile"](plan["qt_replacement"]) == profile,
         "Staged Qt profile differs from the reviewed preparation")
    base = {name: C.file_pin(size, digest) for name, (_, size, digest) in H["BASE"].items()}
    media_names = M["fixed_media"](profile).keys() | M["test_media"](profile) | M["WESTON_MEDIA"]
    overlay = {"code/" + name: pin for name, pin in plan["code"].items()} | {
        "inputs/" + name: pin for name, pin in plan["qt_media"].items()} | {"code/plan.json": pins["plan"]}
    need(plan["kind"] == H["KIND"] and plan["nonce"] == authority["nonce"]
         and plan["manifest"] == packet["preview"]["manifest"] and C.pin(C.wire(plan["media"])) == plan["manifest"]
         and plan["code"].keys() == base.keys() | packet["qt_source"].keys()
         and all(plan["code"][name] == pin for name, pin in packet["qt_source"].items())
         and plan["qt_media"].keys() == {"qt-replacement/" + name for name in media_names}
         and plan["code"]["asahi-guest.py"] == pins["worker"] and pins["files"] == overlay
         and plan["qt_replacement"]["wayland_socket"] == M["DISPLAY_SOCKET"], "Exact completed worker and media pins required")
    expected = overlay | {"guest-init.sh": pins["init"]}
    directories = {str(parent) for leaf in expected for parent in Path(leaf).parents if parent != Path(".")}
    actual = {str(node.relative_to(stage)): node for node in stage.rglob("*")}
    need(actual.keys() == expected.keys() | directories
         and all(actual[name].is_dir() and not actual[name].is_symlink() for name in directories),
         "Exact staged input tree required")
    for name, pin in expected.items():
        C.read(stage / name, pin["bytes"], pin, collect=False)
    review = plan["qt_replacement"]["project_review"]
    now = int(time.time())
    preview = plan["media"]["keys"]["preview-test"]
    need(review["fingerprint"] != preview["fingerprint"]
         and plan["qt_media"]["qt-replacement/test-certificate.gpg"] == review["certificate"]
         and plan["qt_media"]["qt-replacement/" + M["P"]["project_name"](profile) + ".sig"] == review["signature"],
         "Exact distinct Qt TEST selection required")
    need(not current or all(item["not_before"] <= now and now + 5820 < item["not_after"] for item in (preview, review)),
         "Current trust windows must cover the retained run allowance")
    return packet, plan


def legacy_actor():
    row = C.json_body(C.external(FROZEN_AUTHORITY, CAP, M["RETAINED_AUTHORITY"])[0], canonical=True)
    for leaf, pin in row["source"].items():
        C.read(FROZEN_SOURCE / leaf, CAP, pin, collect=False)
    legacy = run_path(str(FROZEN_SOURCE / M["LEGACY"]))
    return legacy, row


def adapted(function, **bindings):
    """Reuse pinned runner control flow with only the named Qt seams replaced."""
    return FunctionType(function.__code__, function.__globals__ | bindings,
                        function.__name__, function.__defaults__, function.__closure__)


def verify_derivation(legacy, packet, plan):
    paths, pins = legacy["selection"]()
    source = {name: C.read(path, CAP, pins[name])[0] for name, path in paths.items()}
    worker, operands = H["guest_checkpoint"](source["asahi-guest.py"], source["operands.py"], plan["qt_media"])
    legacy_init = legacy["init_bytes"]()
    expected = pins | {"asahi-guest.py": C.pin(worker), "operands.py": C.pin(operands)}
    need(all(plan["code"][name] == pin for name, pin in expected.items())
         and C.pin(legacy_init) == H["PID1"] and C.pin(H["guest_init"](legacy_init)) == packet["staged"]["init"],
         "Selected Qt worker or PID 1 does not derive from the frozen runner")
    profile = parity_profile(packet)
    originals = R["originals"](profile)
    known = {"qt-replacement/" + leaf: originals[role] for leaf, role in M["fixed_media"](profile).items()}
    known.update({"qt-replacement/" + leaf: C.file_pin(row["bytes"], row["sha256"])
                  for leaf, row in packet["display"]["media"].items()})
    need(all(plan["qt_media"][name] == pin for name, pin in known.items()), "Fixed guest media selection differs")


def actor(authority_path, digest):
    authority, _ = selected(authority_path, digest)
    need(authority_path == AUTHORITY and sys.flags.isolated and sys.dont_write_bytecode
         and os.environ.get("CACHY_ASAHI_QT629_ACTOR") == "1", "Exact isolated Qt629 actor entry required")
    legacy, predecessor = legacy_actor()
    legacy["C"].actor_boundary(ACTOR_PATHS | {"authority": authority_path, "preparation": PREPARED, "stage": STAGE})
    packet, plan = prepared(authority, PREPARED, STAGE, Path("/src"))
    verify_derivation(legacy, packet, plan)
    profile = parity_profile(packet)
    profile_arg = {"profile": profile} if profile is not None else {}
    nonce = authority["nonce"]
    actual, base_plan = legacy["binding"](**ACTOR_PATHS, nonce=nonce, issuer="Root",
                                         media_digest=packet["preview"]["manifest"]["sha256"],
                                         control_receipt_sha256=predecessor["control"]["receipt"]["sha256"],
                                         control_boot_receipt_sha256=predecessor["control_boot"]["receipt"]["sha256"])
    need(all(actual[key] == predecessor[key] for key in ("actor_image", "tools", "source", "control", "control_boot", "references")),
         "Pinned 629 image, control and tool operands differ")
    stage = packet["staged"] | {"path": str(STAGE)}
    actual = actual | {"plan": stage["plan"], "init": stage["init"]}
    start_state = {}

    def packed(preview, selected_plan, root):
        built, manifest = M["pack_inputs"](legacy, preview, base_plan, root, STAGE, stage, display=packet["display"])
        need(built == selected_plan == plan, "Packed Qt plan differs from issued selection")
        return manifest

    def export(_reader, disk, destination, *, held):
        _, pin = C.read(disk, H["E"]["RESULT_BYTES"], collect=False)
        if held:
            M["require_result_uuid"](disk, pin, nonce)
        H["export_result"](disk, pin, ACTOR_OUT / "actor-qt", held=held, asahi_bundle=destination,
                           expected_nonce=nonce, **profile_arg)

    def stage_pid1():
        return C.read(STAGE / "guest-init.sh", CAP, stage["init"])[0]

    base = legacy["Controller"]

    class QtActor(base):
        def rehearse(self, actual, chosen, path, sha):
            command = self.runtime.command

            def observe(argv, out, label, *args, **kwargs):
                if label != "qemu":
                    return command(argv, out, label, *args, **kwargs)
                start_state["inputs_verified_at_ns"] = time.time_ns()
                try:
                    return command(argv, out, label, *args, **kwargs)
                finally:
                    start_state["vm_exited_at_ns"] = time.time_ns()
                    M["put"](ACTOR_OUT / "vm-observation.json", C.wire(dict(nonce=nonce, **start_state)))

            self.runtime.command = observe
            try:
                execute = adapted(base.rehearse, init_bytes=stage_pid1, copy_transport=packed, export=export)
                return execute(self, actual, chosen, path, sha)
            finally:
                self.runtime.command = command

    instance = QtActor(actual)
    run = adapted(base.run_asahi629, binding=lambda **_kwargs: (actual, plan))
    report = run(instance, authority_path, digest)
    return report, int(report["status"] != legacy["G"].PASS)


def mount_roles(paths, authority, prep, stage, out):
    retained, control, kernel = (paths[name] for name in ("retained", "control", "transaction_kernel"))
    roles = {Path("/src"): (paths["source"], False), AUTHORITY: (authority, False),
             PREPARED: (prep, False), STAGE: (stage, False),
             FROZEN_SOURCE: (retained / "source", False), FROZEN_AUTHORITY: (retained / "authority.ROOT.json", False),
             ACTOR_PATHS["seed"]: (paths["seed"], False), ACTOR_PATHS["control_boot"]: (paths["control_boot"], False),
             Path("/out"): (out, True)}
    for leaf in ("verified-candidate", "independent-readback-PASS.json", "assembly-only-receipt.json",
                 "independent-database-paths.txt", "independent-e2fsck.log"):
        roles[ACTOR_PATHS["control"] / leaf] = (control / leaf, False)
    for leaf in ("Image", "config"):
        roles[ACTOR_PATHS["transaction_kernel"] / leaf] = (kernel / leaf, False)
    return roles


def actor_args(digest):
    return ["-I", "-B", f"/src/{LANE}/launch.py", "actor", "--authority", str(AUTHORITY), "--authority-sha256", digest]


def name_labels(nonce):
    return ("caa-qt629-run-" + nonce,
            {"org.cachy-asahi.overlay583.nonce": nonce, "org.cachy-asahi.qt629.phase": "run"})


def create_args(name, labels, roles, args, cidfile):
    need(all("," not in str(src) and "\n" not in str(src) for src, _ in roles.values()), "Ordinary bind source path required")
    return ["container", "create", "--name", name, "--cidfile", str(cidfile), "--pull=never", "--init=false", "--read-only",
            "--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--cpus=4", "--memory=6g",
            "--memory-swap=6g", "--pids-limit=256", "--tmpfs", "/tmp:rw,nodev,nosuid,noexec,size=32m",
            "--env", "CACHY_ASAHI_OVERLAY583_ACTOR=1", "--env", "CACHY_ASAHI_629_ACTOR=1", "--env", "CACHY_ASAHI_QT629_ACTOR=1",
            *[item for key, value in labels.items() for item in ("--label", f"{key}={value}")],
            *[item for dest, (src, rw) in roles.items()
              for item in ("--mount", f"type=bind,source={src},target={dest}" + ("" if rw else ",readonly"))],
            "--entrypoint", "/usr/bin/python3", ACTOR_IMAGE, *args]


def owned_container(raw, cid, name, labels, roles, args):
    rows = json.loads(raw)
    need(type(rows) is list and len(rows) == 1, "Exact single container inspection required")
    row = rows[0]
    cfg, host = row["Config"], row["HostConfig"]
    need(row["Id"] == cid and row["Name"] == "/" + name and row["Image"] == ACTOR_IMAGE
         and cfg["Entrypoint"] == ["/usr/bin/python3"] and cfg["Cmd"] == args
         and all(cfg["Labels"].get(key) == value for key, value in labels.items())
         and {"CACHY_ASAHI_OVERLAY583_ACTOR=1", "CACHY_ASAHI_629_ACTOR=1", "CACHY_ASAHI_QT629_ACTOR=1"} <= set(cfg["Env"])
         and host["NetworkMode"] == "none" and host["ReadonlyRootfs"] is True and host["CapDrop"] == ["ALL"]
         and not host["CapAdd"] and not host["Privileged"] and not host["Devices"] and host["Init"] is False
         and host["Memory"] == host["MemorySwap"] == 6 * GIB and host["NanoCpus"] == 4_000_000_000
         and host["PidsLimit"] == 256 and host["SecurityOpt"] == ["no-new-privileges"]
         and host["Tmpfs"] == {"/tmp": "rw,nodev,nosuid,noexec,size=32m"},
         "Owned container identity, invocation or confinement differs")
    mounts = {(item["Type"], item["Destination"], item["Source"], item["RW"]) for item in row["Mounts"]}
    need(len(row["Mounts"]) == len(roles) and mounts == {("bind", str(dst), str(src), rw) for dst, (src, rw) in roles.items()},
         "Owned actor mount census differs")
    return row["State"]


class DockerCommandError(ValueError):
    pass


class Docker:
    def __init__(self):
        binary = Path.home() / "bin/docker"
        C.external(binary, 64 << 20, DOCKER_SHA)
        endpoint = Path(f"/run/user/{os.getuid()}/docker.sock")
        info = endpoint.lstat()
        need(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid(), "Expected own-UID rootless Docker socket")
        self.prefix = [str(binary), "--host", f"unix://{endpoint}"]
        self.env = {key: value for key, value in os.environ.items() if key not in (
            "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")}

    def call(self, *args, timeout=45):
        result = subprocess.run([*self.prefix, *args], env=self.env, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=timeout)
        if result.returncode:
            raise DockerCommandError("Owned Docker command failed: " + " ".join(args[:2]) +
                                     ": " + result.stderr.decode(errors="replace")[:512])
        return result.stdout

    def attach(self, cid, out, pending):
        with (out / "actor.stdout").open("xb") as stdout, (out / "actor.stderr").open("xb") as stderr:
            argv = [*self.prefix, "container", "start", "--attach", cid]
            with subprocess.Popen(argv, env=self.env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                  start_new_session=True) as child:
                deadline = time.monotonic() + ATTACH_TIMEOUT
                while child.poll() is None and not pending and time.monotonic() < deadline:
                    time.sleep(.2)
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=5)
                    raise ValueError("Owned container attach cancelled or timed out")
                return child.returncode


def listed(docker, field, value, *, timeout=45):
    payload = docker.call("container", "ls", "-a", "--no-trunc", "--filter", f"{field}={value}", "--format", "{{.ID}}",
                          timeout=timeout)
    result = payload.decode("ascii").strip()
    need(not result or CID.fullmatch(result), "Unexpected owned container listing")
    return result


def saved_cid(path):
    try:
        body, _ = C.read(path, 128)
    except FileNotFoundError:
        return None
    if not body:
        return None
    value = body.decode("ascii").strip()
    need(CID.fullmatch(value), "Malformed saved owned container CID")
    return value


def retire(docker, name, claimed, inspect, *, cidfile, create_uncertain=False):
    """Reconcile a daemon-side start or create that can outlive its CLI."""
    deadline = time.monotonic() + RETIRE_TIMEOUT
    terminal, failure = None, None
    observations = []

    def remaining():
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("Owned container retirement deadline exhausted")
        return min(45, left)

    while time.monotonic() < deadline:
        try:
            saved = saved_cid(cidfile)
            need(not saved or not claimed or saved == claimed, "Ambiguous saved owned container CID")
            claimed = claimed or saved
            named = listed(docker, "name", "^/" + name + "$", timeout=remaining())
            by_id = listed(docker, "id", claimed, timeout=remaining()) if claimed else ""
            need((not named or not claimed or named == claimed) and (not by_id or by_id == claimed),
                 "Ambiguous owned container CID")
            current = named or by_id
            if current:
                observations.clear()
                state = inspect(current, timeout=remaining())
                claimed = current
                if state["Running"]:
                    left = remaining()
                    docker.call("container", "stop", "--time", str(min(30, max(0, int(left) - 1))), current, timeout=left)
                else:
                    terminal = state
                    docker.call("container", "rm", current, timeout=remaining())
            elif not create_uncertain or claimed is not None:
                observations.append(time.time_ns())
                if len(observations) == 2:
                    return claimed, observations, terminal
        except (DockerCommandError, OSError, subprocess.SubprocessError) as error:
            observations.clear()
            failure = error
        time.sleep(max(0, min(.2, deadline - time.monotonic())))
    if create_uncertain and claimed is None:
        raise ValueError("Owned Docker create outcome remains unresolved at the bounded retirement deadline") from failure
    raise ValueError("Owned container retirement could not be verified before the bounded deadline") from failure


@contextmanager
def cancellation():
    pending = []
    def record(number, _frame):
        pending.append(number)
    old = {number: signal.signal(number, record) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        yield pending
    finally:
        for number, handler in old.items():
            signal.signal(number, handler)


def host_scope(nonce):
    group = Path("/proc/self/cgroup").read_text().strip()
    need(group.startswith(f"0::/user.slice/user-{os.getuid()}.slice/")
         and group.endswith(f"/cachy-qt629-run-{nonce}.scope"), "Exact user-owned Qt629 launch scope required")
    rows = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
    available = int(rows["MemAvailable"].split()[0]) * 1024
    need(available >= 8 * GIB, "The 6 GiB actor and 2 GiB host reserve do not fit")
    return group


def error_record(error):
    return dict(type=type(error).__name__, detail=str(error)[:1024])


def export_after_retirement(out, nonce, packet, stage, cid, state, absence, held, expected_qemu, actor_result_pin=None):
    actor_out = out / "actor/qt629"
    disk = actor_out / "result.raw"
    qemu = C.json_body(C.read(actor_out / "qemu.json", CAP)[0], canonical=True)
    vm = C.json_body(C.read(actor_out / "vm-observation.json", CAP)[0], canonical=True)
    need(state.get("Status") in ("exited", "dead") and type(state.get("ExitCode")) is int
         and state["Running"] is False, "Exact observed outer terminal state required before result export")
    need(vm.keys() == {"nonce", "inputs_verified_at_ns", "vm_exited_at_ns"} and vm["nonce"] == nonce
         and qemu["reaped"] is True and qemu["ownership"] == "REAPED"
         and qemu["group_census"] == "EMPTY_TWICE" and qemu["argv"] == expected_qemu,
         "Exact owned and reaped QEMU result required")
    timestamps = [vm["inputs_verified_at_ns"], vm["vm_exited_at_ns"], *absence]
    need(len(timestamps) == 4 and all(type(stamp) is int and 0 < stamp < 2**63 for stamp in timestamps)
         and all(left < right for left, right in zip(timestamps, timestamps[1:])),
         "Exact ordered host retirement observations required")
    cleanup = {}
    if (actor_out / "evidence/cleanup.json").is_file():
        cleanup = C.json_body(C.read(actor_out / "evidence/cleanup.json", CAP)[0], canonical=True)
    size = H["E"]["RESULT_BYTES"]
    need(held or C.check_pin(actor_result_pin, size) and actor_result_pin["bytes"] == size,
         "Completed actor must seal its exact result disk")
    _, disk_pin = C.read(disk, size, actor_result_pin, collect=False)
    retirement = dict(nonce=nonce, target_submounts=cleanup.get("target_submounts"), keyrings=cleanup.get("keyrings"),
                      qemu={key: qemu[key] for key in ("exit", "reaped", "output_complete", "timeout", "signals")},
                      outer_container=dict(id=cid, exit=state.get("ExitCode"), removed=True),
                      observations=[dict(event=event, qemu=[], outer_containers=[]) for event in R["EVENTS"][-2:]])
    stopped = dict(kind=M["STOPPED"], nonce=nonce, disk=disk_pin, held=held, retirement=retirement)
    observed = stopped | {"kind": ASSEMBLER["STOPPED"], "host_times": dict(zip(ASSEMBLER["HOST_TIMES"], timestamps, strict=True))}
    observation = out / "stopped-result.json"
    stopped_pin = M["put"](observation, C.wire(observed))
    originals = {name: Path(row["path"]) for name, row in packet["originals"].items()}
    profile = parity_profile(packet)
    profile_arg = {"profile": profile} if profile is not None else {}
    media = packet["staged"]["files"]
    inputs = {"test-certificate.gpg": "test-certificate.gpg",
              "test-signature.sig": M["P"]["project_name"](profile) + ".sig"}
    test_inputs = {name: (stage / leaf, media[leaf]) for name, operand in inputs.items()
                   for leaf in ("inputs/qt-replacement/" + operand,)}
    bundle = out / "qt-evidence"
    if not held:
        return ASSEMBLER["assemble"](disk_path=disk, observation=observation, observation_sha=stopped_pin["sha256"],
                                     nonce=nonce, bundle=bundle, originals=originals, test_inputs=test_inputs,
                                     **profile_arg)
    selection = out / "result-export-selection.json"
    pin = M["put"](selection, C.wire(stopped))
    exported = M["export_stopped"](disk_path=disk, disk_pin=disk_pin, retirement=selection,
                                   retirement_sha=pin["sha256"], nonce=nonce, bundle=bundle, originals=originals,
                                   test_inputs=test_inputs, asahi_bundle=out / "asahi-evidence", **profile_arg)
    return dict(stopped_observation=stopped_pin, **exported)


def owner(authority_path, digest):
    need(sys.flags.isolated and sys.dont_write_bytecode, "Use isolated no-bytecode Python for the launch owner")
    authority, authority_pin = selected(authority_path, digest)
    nonce = authority["nonce"]
    paths = {key: Path(value) for key, value in authority["paths"].items()}
    out = paths["output"]
    profile = host_scope(nonce)
    prep = Path(authority["preparation"]["path"])
    stage = prep.parent / "stage"
    packet, plan = prepared(authority, prep, stage, paths["source"])
    parity = parity_profile(packet)
    parity_arg = {"profile": parity} if parity is not None else {}
    need(paths["source"] == HERE.parents[2] and Path(packet["originals"]["owned_terminal"]["path"]).parent == paths["retained"],
         "Run from the selected source and canonical retained owner")
    legacy, preceding, _ = M["retained_controller"](paths["retained"])
    verify_derivation(legacy, packet, plan)
    if parity is not None:
        originals = packet["originals"]
        need(M["records"]({name: Path(row["path"]) for name, row in originals.items()}, R["originals"](parity))
             == originals, "Selected parity originals changed before launch")
    preview = Path(packet["preview"]["path"])
    legacy["O"].rehash(legacy["T"], preview, plan["media"])
    control, refs = legacy["control_refs"](paths["control"], preceding["control"]["receipt"]["sha256"])
    boot = legacy["cold_boot_refs"](paths["control_boot"], preceding["control_boot"]["receipt"]["sha256"],
                                   paths["control"], control, refs)
    need(control == preceding["control"] and boot == preceding["control_boot"], "Selected cold control provenance differs")
    refs |= legacy["transaction_kernel_refs"](paths["transaction_kernel"])
    refs["seed"] = C.read(paths["seed"], preceding["references"]["seed"]["bytes"], preceding["references"]["seed"], collect=False)[1]
    need(refs == preceding["references"], "Selected seed, control or transaction kernel differs")
    roles = mount_roles(paths, authority_path, prep, stage, out / "actor") | {ACTOR_PATHS["staging"]: (preview, False)}
    need(out.parent.resolve(strict=True) == out.parent and not os.path.lexists(out)
         and all(not out.is_relative_to(src) and not src.is_relative_to(out) and src.resolve(strict=True) == src
                 for src, rw in roles.values() if not rw), "Fresh output must be disjoint from canonical inputs")
    review = plan["qt_replacement"]["project_review"]
    prior_keys = {key["fingerprint"] for key in plan["media"]["keys"].values()} | legacy["O"].HISTORICAL_TEST
    need(review["fingerprint"] not in prior_keys, "Qt TEST signer must be separate from the Asahi629 keys")
    qt_test = H["verify_qt_test"](stage / "inputs/qt-replacement", review, **parity_arg)
    args = actor_args(digest)
    docker = Docker()
    name, labels = name_labels(nonce)
    need(not listed(docker, "name", "^/" + name + "$"), "Owned container name is already present")
    claim = paths["retained"].parent / ("qt629-host-claim-" + nonce)
    ledger = dict(nonce=nonce, authority=authority_pin, profile=profile, output=str(out), qt_test=qt_test)
    M["put"](claim, C.wire(ledger))
    out.mkdir(mode=0o700)
    (out / "actor").mkdir(mode=0o700)
    cidfile = out / "actor.cid"
    command = create_args(name, labels, roles, args, cidfile)
    M["put"](out / "actor-create.json", C.wire(command))
    report = dict(kind="QT629_OWNED_LAUNCH_RESULT_V1", status="HOLD_QT629_OWNED_LAUNCH", nonce=nonce,
                  authority=authority_pin, qt_test=qt_test)
    cid, state, absence = None, {}, []

    def inspect(value, *, timeout=45):
        return owned_container(docker.call("container", "inspect", value, timeout=timeout), value, name, labels, roles, args)

    create_attempted = False
    with cancellation() as pending:
        try:
            need(not pending, "Cancelled before owned container creation")
            create_attempted = True
            docker.call(*command)
            claimed = saved_cid(cidfile)
            need(claimed is not None and listed(docker, "name", "^/" + name + "$") == claimed,
                 "Exact owned CID claim required")
            cid = claimed
            state = inspect(cid)
            need(state["Status"] == "created" and state["Running"] is False, "Expected fresh owned actor")
            need(not pending, "Cancelled before actor start")
            result = docker.attach(cid, out, pending)
            state = inspect(cid)
            report["attach_exit"] = result
            need(state["Status"] == "exited" and state["Running"] is False and state["OOMKilled"] is False
                 and result == state["ExitCode"], "Owned actor did not reach an exact natural terminal")
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, RuntimeError) as error:
            report["failure"] = error_record(error)
        finally:
            try:
                cid, absence, terminal = retire(docker, name, cid, inspect, cidfile=cidfile,
                                                create_uncertain=create_attempted and cid is None)
                if terminal is not None:
                    state = terminal
                report["outer_container_absent_twice"] = True
                report["container_absence_at_ns"] = absence
                if state.get("Status") in ("exited", "dead"):
                    report["container_terminal"] = {name: state[name] for name in ("Status", "ExitCode", "OOMKilled")}
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, RuntimeError) as error:
                report["cleanup_failure"] = error_record(error)
        if pending:
            report["signals"] = pending
    try:
        selected(authority_path, digest)
        prepared(authority, prep, stage, paths["source"], current=False)
        observed = out / "actor/qt629/report.json"
        if cid and absence and (out / "actor/qt629/qemu.json").is_file():
            inner = {}
            if observed.is_file():
                body, report["actor_report"] = C.read(observed, CAP)
                inner = C.json_body(body, canonical=True)
            displayed = C.read(out / "actor.stdout", CAP)[0] if (out / "actor.stdout").is_file() else b""
            host_pass = (not {"failure", "cleanup_failure", "signals"} & report.keys()
                         and report.get("attach_exit") == 0 and state["Status"] == "exited"
                         and state["ExitCode"] == 0 and state["OOMKilled"] is False and inner.get("status") == legacy["G"].PASS
                         and displayed == C.wire(inner) and inner.get("originals_verified") is True
                         and inner["cleanup"]["qemu_absent_twice"] and inner["cleanup"]["disposable_media_absent"])
            partuuid = f"{int(nonce[:8], 16) or 1:08x}-01"
            stage_pins = packet["staged"]
            argv = legacy["C"].qemu_argv(ACTOR_OUT, nonce, partuuid, stage_pins["plan"]["sha256"],
                                        stage_pins["worker"]["sha256"])
            exported = export_after_retirement(out, nonce, packet, stage, cid, state, absence, not host_pass, argv,
                                               actor_result_pin=inner.get("result_disk"))
            report["stopped_export"] = exported
            if host_pass:
                report["status"] = "PASS_QT629_OWNED_REPLACEMENT_AND_RESTORATION"
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
        report["readback_failure"] = error_record(error)
    M["put"](out / "owned-terminal.json", C.wire(report))
    return report, int(not report["status"].startswith("PASS"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("run", "actor"))
    parser.add_argument("--authority", required=True, type=Path)
    parser.add_argument("--authority-sha256", required=True)
    args = parser.parse_args()
    try:
        method = owner if args.mode == "run" else actor
        report, status = method(args.authority, args.authority_sha256)
        sys.stdout.buffer.write(C.wire(report))
        return status
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, RuntimeError) as error:
        parser.exit(1, f"Qt629 scoped launch refused: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
