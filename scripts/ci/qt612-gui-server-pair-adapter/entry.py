#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root dispatch and ordinary-service entry for the first hosted Qt GUI pair."""

import argparse
from enum import Enum, auto
import importlib.util
import math
import os
from pathlib import Path
import re
import resource
import select
import shutil
import stat
import subprocess
import sys
import time
from types import SimpleNamespace
import urllib.error
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import contract as C

API = "https://api.github.com/repos/" + C.REPO + "/actions/"
TOKEN = "QT612_ACTIONS_READ_TOKEN"
LOG_URL = API + "jobs/134591565463/logs"
RUNTIME_READER = "scripts/ci/qt612-gui-pair-runtime-source/runtime.py"
RUNTIME_READER_SHA = "abfed5c1804099ae74e93bb7a30b423fc24d3f7a617fbfa0320f65369db13ad8"
LIMIT_FILES = ("memory.max", "memory.swap.max", "pids.max", "cpu.max")
RETIRE_EXPORT_SECONDS = 180
OWNER_PROGRESS = ("SERVICE_JOIN", "SERVICE_HELPERS", "SERVICE_VOLUME", "SERVICE_DOMAIN",
                  "SIGNED349_BUILD", "SIGNED356_BUILD", "SOURCE_CACHE", "REQUEST_HANDOFF")
HELPERS = {
    f"{C.HOSTED}/launch.py": "5c2171f499b9aa79645928959c597d0a18e98a37dd4c5604bc7b5ceca17c19d2",
    f"{C.HOSTED}/executor.py": "d91457ba75dd5d61c1bae9cc09ac468d5e05de049f87409669dd769efe7b4ba6",
    f"{C.HOSTED}/evidence.py": "47815cc2d62e8cc8d6488ce0f92efe7d608dda1d6c0aa3451dff22414ef0dbcc",
    f"{C.HOSTED}/capacity.py": "74fd7b29b12264c85e4475f4fdcc067dfa6fa56f9879f94f13d6ba1e2e306075",
    f"{C.FAMILY}/pipeline.py": "9a1c8ead909e0a72ca435188e075eff9107dd0700c375db0c6c76db7d69b8024",
    f"{C.FAMILY}/source.py": "ffe26712c63d7f826cdb2185f3c05b1a049534ea81aa4c04a835f4e9e90051ce",
    f"{C.FAMILY}/runner_inputs.py": "6441ca1d47bdb10d0ac8c514f2677e934fa8b6ce05fe4324e21c289989528201",
    f"{C.FAMILY}/acquire_runner_inputs.py": "4c771a358f3a65c10cad3e940b886e768e5cdd4771c21dab8ae5aaae07f6ad3a",
}


class Stage(Enum):
    ROOT_IDENTITY = auto()
    CONTROLLER_PATHS = auto()
    DISPATCH_APPROVAL = auto()
    CHECKOUT_IDENTITY = auto()
    CONTROLLER_SCOPE = auto()
    SEAL_RUNTIME = auto()
    RETAINED_R128_COPY = auto()
    TEST_TRUST = auto()
    HELPER_STAGING = auto()
    HELPER_EXPOSURE = auto()
    RETAINED_CONTROLLER_LOAD = auto()
    TRANSFER_PLAN = auto()
    CURRENT_JOB_IDENTITY = auto()
    CONTROLLER_LIMITS = auto()
    CONTROLLER_INIT = auto()
    STORAGE_FRESHNESS = auto()
    OWNED_HOST_SETUP = auto()
    STORAGE_ALLOCATION_ADMISSION = auto()
    STORAGE_ALLOCATION = auto()
    STORAGE_ALLOCATION_READBACK = auto()
    OWNED_VOLUME_JOIN = auto()
    INPUT_ACQUISITION = auto()
    INPUT_TRANSFER_WINDOW = auto()
    INPUT_PORTABLE_COPY = auto()
    R128_LOG_TOKEN = auto()
    R128_LOG_API = auto()
    R128_LOG_REDIRECT = auto()
    R128_LOG_BODY = auto()
    R128_LOG_PIN = auto()
    INPUT_TRUST_STAGING = auto()
    ACQUISITION_INPUT_CHECK = auto()
    R128_PACKAGE_REPLAY = auto()
    PUBLIC_INPUT_RETRIEVAL = auto()
    ACQUIRED_INPUT_COMMIT = auto()
    INPUT_BINDING = auto()
    INPUT_EXPOSURE = auto()
    ORDINARY_SERVICE_HANDOFF = auto()
    SIGNED356_REQUEST_WAIT = auto()
    SIGNED356_DAEMON_JOIN = auto()
    SIGNED356_REQUEST_VALIDATE = auto()
    SIGNED356_READBACK = auto()
    SIGNED356_INVENTORY_READBACK = auto()
    SIGNED356_BINDING = auto()
    NATIVE_PAIR_COMPLETION = auto()
    CLOSED_EVIDENCE_EXPORT = auto()
    OWNED_CLEANUP = auto()
    OWNER_REPORT = auto()


class ControllerTrace:
    stage = Stage.ROOT_IDENTITY
    acquisition_detail = None
    owner_detail = None

    def mark(self, name):
        self.stage = Stage[name]

    def hold(self):
        print("HOLD_QT612_PAIR: " + self.stage.name, file=sys.stderr, flush=True)
        if self.acquisition_detail is not None:
            print("HOLD_QT612_ACQUISITION: " + self.acquisition_detail, file=sys.stderr, flush=True)
        if self.owner_detail is not None:
            print("HOLD_QT612_OWNER: " + " ".join(self.owner_detail), file=sys.stderr, flush=True)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HTTPReadRefused(ValueError):
    def __init__(self, status):
        self.reason = f"HTTP_{status}" if type(status) is int and 100 <= status <= 599 else "HTTP_REFUSAL"
        super().__init__("SELECTED_HTTP_READ_REFUSED")


def fetch(url, cap, *, token=None, timeout=8, mark=lambda _: None):
    headers = {"Accept-Encoding": "identity", "User-Agent": "cachy-asahi-qt612-owner"}
    if url.startswith(API):
        headers["Accept"] = "application/vnd.github+json"
    request = urllib.request.Request(url, headers=headers)
    if token is not None:
        # Treat the Actions credential as opaque visible ASCII within one header.
        C.need(url == LOG_URL and token and all("!" <= char <= "~" for char in token),
               "EXACT_R128_READ_CUSTODY")
        mark("R128_LOG_API")
        request.add_unredirected_header("Authorization", "Bearer " + token)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        with error:
            if token is None or error.code != 302:
                raise HTTPReadRefused(error.code) from None
            target = error.headers.get("Location", "")
        mark("R128_LOG_REDIRECT")
        endpoint = urllib.parse.urlsplit(target)
        C.need(endpoint.scheme == "https" and endpoint.username is None and endpoint.password is None
               and endpoint.port in (None, 443) and not endpoint.fragment
               and re.fullmatch(r"[a-z0-9]{1,63}\.blob\.core\.windows\.net", endpoint.hostname or ""),
               "EXACT_R128_SIGNED_DOWNLOAD_REDIRECT")
        mark("R128_LOG_BODY")
        return fetch(target, cap, timeout=timeout)
    with response:
        C.need(response.status == 200 and response.headers.get("Content-Encoding", "identity") == "identity",
               "IDENTITY_HTTP_BODY_REQUIRED")
        raw = response.read(cap + 1)
    C.need(0 < len(raw) <= cap, "BOUNDED_HTTP_BODY")
    return raw


def command(argv):
    value = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=8,
                           env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
                                "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_OPTIONAL_LOCKS": "0"})
    C.need(len(value.stdout) <= 65536 and not value.stderr, "BOUNDED_IDENTITY_COMMAND")
    return value.stdout.decode("ascii")


def git_identity(root):
    # Disabling replacement avoids interpreting a different object at the selected commit.
    git = ["/usr/bin/git", "-c", f"safe.directory={root}", "--no-replace-objects",
           "--no-optional-locks", "-C", str(root), "rev-parse", "--verify"]
    return tuple(command([*git, operand]).strip() for operand in ("HEAD", "HEAD^{tree}"))


def duration(value):
    units = dict(h=3600, min=60, s=1, ms=.001, us=.000001)
    if value.isdecimal():
        return int(value) / 1_000_000
    parts = re.findall(r"([0-9]+)(min|ms|us|h|s)", value)
    C.need(len(parts) <= 5 and "".join(a+b for a, b in parts) == "".join(value.split()),
           "FINITE_SYSTEMD_RUNTIME")
    return sum(int(a)*units[b] for a, b in parts)


def controller_time(env):
    name = C.scope_name(env["GITHUB_RUN_ID"])
    group = "/system.slice/" + name
    raw = command(["/usr/bin/systemctl", "show", name, "--no-pager",
                   "--property=ControlGroup,ActiveEnterTimestampMonotonic,RuntimeMaxUSec"])
    values = dict(line.split("=", 1) for line in raw.splitlines())
    C.need(values["ControlGroup"] == group and proc(os.getpid())[1] == group
           and duration(values["RuntimeMaxUSec"]) == C.SCOPE, "ACTUAL_FINITE_ROOT_CONTROLLER_SCOPE")
    return group, int(values["ActiveEnterTimestampMonotonic"]) / 1_000_000


def proc(pid):
    base = Path("/proc") / str(pid)
    row = (base/"stat").read_text().rpartition(")")[2].split()
    cgroup = (base/"cgroup").read_text().strip()
    C.need(cgroup.startswith("0::/") and "\n" not in cgroup, "ACTUAL_UNIFIED_CGROUP")
    return int(row[19]), cgroup[3:], int(row[1])


def limits(group):
    return {name: (Path("/sys/fs/cgroup")/group.removeprefix("/")/name).read_text().strip()
            for name in LIMIT_FILES}


def r128_copy(root, output):
    raw = C.read(root/"source-map.json", C.MIB, C.R128_MAP)
    mapping = C.decode(raw)
    C.need(mapping["kind"] == "LLHTTP_REFERENCE_OWNED_HOSTED_SOURCE_V2" and len(mapping["files"]) == 95,
           "EXACT_R128_NAMESPACE")
    for name, row in sorted(mapping["files"].items()):
        C.relative(name)
        body = C.read(root/name, C.MIB, row, mode=row["mode"])
        item = output/name
        item.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        C.write(item, body, row["mode"])
    C.write(output/"source-map.json", raw, 0o644)


def helpers(runtime):
    for name, expected in HELPERS.items():
        C.need(C.pin(C.read(runtime/name, C.MIB))["sha256"] == expected, "EXACT_SEALED_QT_HELPER")
    sys.path.insert(0, str(runtime/C.HOSTED))
    launch = load(runtime/C.HOSTED/"launch.py", "qt612_sealed_launch")
    return launch


def stage_runtime_helpers(source, map_ref, workflow, output):
    path = source/RUNTIME_READER
    C.need(C.pin(C.read(path, C.MIB))["sha256"] == RUNTIME_READER_SHA, "EXACT_RUNTIME_STAGING_READER")
    module = load(path, "qt612_selected_runtime_reader")
    # Path.mkdir(parents=True) uses the umask for intermediate directories.
    previous_umask = os.umask(0o077)
    try:
        result = module.stage_helpers(source=source, map_sha256=map_ref["sha256"],
                                      frozen_locks=workflow, output=output)
    finally:
        os.umask(previous_umask)
    C.need(result["status"] == "PASS_EXACT_RUNTIME_HELPER_STAGE_DATA_ONLY", "CLOSED_RUNTIME_HELPER_STAGE")
    return result


def root_inputs(runtime, approved):
    return {key: runtime/ref["path"] for key, ref in approved["inputs"].items()}


def ordinary_volume(launch, work, root_identity, gid):
    volume = launch.capacity.observe(work.parent)
    writable = launch.capacity.observe(work)
    info = work.lstat()
    rows = [row.split() for row in Path("/proc/self/mountinfo").read_text().splitlines()]
    row, = [row for row in rows if row[0] == str(volume["mount"])]
    C.need([volume["device"], volume["inode"]] == root_identity[:2]
           and volume["device"] == writable["device"] and row[row.index("-")+1] == "ext4"
           and not writable["readonly"] and info.st_uid == 0 and info.st_gid == gid
           and stat.S_IMODE(info.st_mode) == 0o1770, "EXACT_ORDINARY_WORK_ON_OWNED_EXT4")


def portable_plan(acquire, paths, approval):
    selected = paths["portable_selection"]
    R = acquire.R
    C.need(selected.name == R.SELECTION, "EXACT_PORTABLE_SELECTION_NAME")
    raw = C.read(selected, C.MIB, approval["inputs"]["portable_selection"])
    selection = C.decode(raw)
    original = C.decode(C.read(selected.parent/R.ORIGINAL, C.MIB, selection["original_source_map"]))
    pipeline = f"{C.FAMILY}/pipeline.py"
    C.need(original["files"][pipeline]["sha256"] == HELPERS[pipeline]
           and C.pin(C.read(selected.parent/"skeleton"/pipeline, C.MIB)) == C.whole(original["files"][pipeline]),
           "EXACT_PAIR_ONLY_PORTABLE_PIPELINE")
    targets = acquire.public_targets(selected.parent, selection,
                                     C.decode(C.read(paths["route_plan"], C.MIB, approval["inputs"]["route_plan"])))
    return max(1_752_637_011, sum(row["pin"]["bytes"] for row in targets.values()))


def transfer_function(acquire, paths, approval, deadline, trace, token):
    def transfer(*, owned_workspace, device, inode, mount_id, portable, output):
        nonlocal token
        trace.mark("INPUT_TRANSFER_WINDOW")
        remaining = math.floor(deadline - time.monotonic())
        with acquire.time_limit(remaining):
            trace.mark("INPUT_PORTABLE_COPY")
            shutil.copytree(paths["portable_selection"].parent, portable)
            work = output.parent
            md4c = work/"md4c-input"
            md4c.mkdir(mode=0o700)
            log = work/"r128-original.log"
            trace.mark("R128_LOG_TOKEN")
            try:
                body = fetch(LOG_URL, C.R128_LOG["bytes"], token=token, mark=trace.mark)
            except HTTPReadRefused as error:
                trace.acquisition_detail = error.reason
                raise
            finally:
                token = ""
            trace.mark("R128_LOG_PIN")
            C.need(C.pin(body) == C.R128_LOG, "EXACT_R128_LOG_ORIGINAL")
            trace.mark("INPUT_TRUST_STAGING")
            C.write(log, body)
            route = work/"public-route-plan.json"
            C.write(route, C.read(paths["route_plan"], C.MIB, approval["inputs"]["route_plan"]))
            C.write(md4c/(C.PACKAGE+".sig"), C.read(paths["md4c_signature"], C.MIB, C.SIGNATURE))
            C.write(md4c/C.CERT, C.read(paths["md4c_certificate"], C.MIB, C.CERTIFICATE))
            options = SimpleNamespace(portable=portable, route_plan=route, md4c_input=md4c, output=output,
                        r128_job_log=log, selection_sha256=approval["inputs"]["portable_selection"]["sha256"],
                        route_plan_sha256=approval["inputs"]["route_plan"]["sha256"],
                        md4c_cert_bytes=C.CERTIFICATE["bytes"], md4c_cert_sha256=C.CERTIFICATE["sha256"])
            try:
                return acquire.acquire(options, owned_workspace, acquire.open_public(), mark=trace.mark)
            except acquire.AcquisitionError as error:
                trace.acquisition_detail = f"LEAF_{error.ordinal:04d} {error.reason}"
                raise
            finally:
                log.unlink()
                route.unlink()
                shutil.rmtree(md4c)
    return transfer


def atomic_marker(path, value, mode=0o444):
    pending = path.with_suffix(".partial")
    C.need(not os.path.lexists(path), "FRESH_SINGLE_HANDOFF")
    C.write(pending, C.encoded(value), mode)
    os.rename(pending, path)


def wait_for(path, end, owner, *, mode=None):
    while time.monotonic() < end:
        try:
            return C.read(path, C.MIB, owner=owner, mode=mode)
        except FileNotFoundError:
            time.sleep(.25)
    raise TimeoutError("BOUND_HANDOFF_DEADLINE")


def ordinary_progress_marker(work, stage):
    C.need(stage in OWNER_PROGRESS, "FIXED_ORDINARY_PROGRESS_STAGE")
    return work/f"ordinary-progress-{stage}.json"


def last_ordinary_progress(work, uid):
    # Publish only allowlisted phase names. Untrusted files never supply log text.
    last = "UNOBSERVED"
    missing = False
    for stage in OWNER_PROGRESS:
        try:
            body = C.read(ordinary_progress_marker(work, stage), 64, owner=uid, mode=0o600)
        except FileNotFoundError:
            missing = True
            continue
        except (OSError, ValueError):
            return "INVALID_PROGRESS"
        if missing or body != C.encoded(stage):
            return "INVALID_PROGRESS"
        last = stage
    return last


def wait_for_image_request(owner, marker, work, trace):
    poll = select.poll()
    pidfd = owner.pidfds["owner"]  # The exact original service PID, pinned by Controller.start.
    poll.register(pidfd, select.POLLIN)
    end, uid = marker["ends"]["bootstrap"], marker["uid"]
    while (remaining := end - time.monotonic()) > 0:
        try:
            return C.read(work/"image-request.json", C.MIB, owner=uid, mode=0o600)
        except FileNotFoundError:
            ready = poll.poll(min(250, math.ceil(remaining*1000)))
            if ready:
                (observed_fd, events), = ready
                C.need(observed_fd == pidfd and events & (select.POLLIN | select.POLLHUP)
                       and not events & (select.POLLERR | select.POLLNVAL), "ACTUAL_ORDINARY_PIDFD_EXIT")
                trace.owner_detail = ("OWNER_EXITED", last_ordinary_progress(work, uid))
                raise ValueError("ORIGINAL_ORDINARY_SERVICE_EXITED_BEFORE_IMAGE_HANDOFF") from None
    trace.owner_detail = ("REQUEST_DEADLINE", last_ordinary_progress(work, uid))
    raise TimeoutError("BOUND_IMAGE_REQUEST_DEADLINE")


def check_daemon(marker, retained):
    D, Q = retained["controller"].D, retained["controller"].Q
    daemon = marker["daemon"]
    start, group, _ = proc(daemon["pid"])
    expected = "/system.slice/" + D.unit(marker["nonce"], "daemon")
    C.need(start == daemon["starttime"] and group == expected+"/daemon" and daemon["cgroup"] == expected,
           "SAME_LIVE_OWNED_DAEMON")
    D.domain(limits(expected), retained["policy"]["daemon"])
    runtime = Q.managed_receipt(daemon["managed_containerd"], daemon["pid"], start, group)
    C.need(proc(runtime["pid"]) == (runtime["starttime"], runtime["cgroup"], daemon["pid"]),
           "SAME_LIVE_MANAGED_CONTAINERD")
    socket = C.ordinary(marker["socket"])
    info = socket.lstat()
    C.need(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0 and info.st_gid == marker["gid"]
           and stat.S_IMODE(info.st_mode) == 0o660
           and [info.st_dev, info.st_ino] == marker["socket_identity"], "SAME_LIVE_OWNED_SOCKET")
    return socket


class OrdinarySupervisor:
    def __init__(self, marker, retained, pipeline, commands, control, work):
        self.marker, self.retained, self.pipeline = marker, retained, pipeline
        self.commands, self.control, self.work = commands, control, work
        self.selected = None

    def require_domain(self, policy):
        row = self.marker
        own = row["owner"]
        D = self.retained["controller"].D
        start, group, _ = proc(os.getpid())
        C.need((os.getuid(), os.geteuid(), os.getgid(), os.getegid(), os.getpid(), start, group)
               == (row["uid"], row["uid"], row["gid"], row["gid"], own["pid"], own["starttime"], own["cgroup"])
               and group == "/system.slice/"+D.unit(row["nonce"], "owner")
               and policy == self.pipeline.POLICY and not os.access("/tmp", os.W_OK)
               and not os.access("/var/tmp", os.W_OK), "ACTUAL_READ_ONLY_ORDINARY_DOMAIN")
        D.domain(limits(group), self.retained["policy"]["owner"])
        return check_daemon(row, self.retained)

    def authenticate_md4c_input(self, auth):
        C.need(auth == self.marker["md4c"] and int(time.time()) < auth["expires_epoch"],
               "SAME_ROOT_ADMITTED_MD4C_INPUT")
        C.read(auth["certificate"]["path"], 65536, C.CERTIFICATE, owner=0)

    def select_stage_binding(self, *, image, inventory_pin, source_map_sha256, component, nonce, mode):
        row = self.marker
        C.need(self.selected is None and component == "gui_server" and mode == "pair-only"
               and source_map_sha256 == row["source_map"]["sha256"] and nonce == row["nonce"]
               and inventory_pin == row["inventory"] and time.monotonic() < row["ends"]["bootstrap"],
               "SAME_OBSERVED_PAIR_ONLY_SEAM")
        request = dict(image=image, inventory=inventory_pin, source_map_sha256=source_map_sha256, nonce=nonce)
        atomic_marker(self.work/"image-request.json", request, 0o600)
        reply = self.control/"stage-binding.json"
        body = wait_for(reply, row["ends"]["bootstrap"], 0, mode=0o444)
        binding = C.decode(body)
        expected = C.late_binding(self.pipeline.binding_template(), dispatch=row["dispatch"], nonce=nonce,
                                  map_sha=source_map_sha256, image=image, inventory=inventory_pin,
                                  now=binding["created_utc"], expiry=binding["expires_utc"])
        C.need(C.encoded(binding) == C.encoded(expected) and binding["created_utc"] <= int(time.time())
               < binding["expires_utc"] <= row["expires"], "ROOT_LATE_STAGE_BINDING_JOIN")
        self.selected = binding
        self.commands.end = min(row["ends"]["work"] - RETIRE_EXPORT_SECONDS,
                                time.monotonic() + binding["expires_utc"] - time.time())
        return reply, C.pin(body)["sha256"]

    def authenticate_Root_stage_binding(self, binding):
        body = C.read(self.control/"stage-binding.json", C.MIB, owner=0, mode=0o444)
        C.need(self.selected == binding == C.decode(body), "ROOT_OWNED_LATE_BINDING_ONLY")

    def require_signed_inventory(self, **selected):
        C.need(self.selected is not None and selected == dict(component="gui_server",
               image=self.selected["image"], inventory_pin=self.marker["inventory"],
               signature_policy="Required TrustedOnly", previous_providers=[]), "EXACT_ROOT_OBSERVED_SIGNED_356")

    def retain_owner_evidence(self, *, work, commands):
        C.need(work == self.work and commands is self.commands and 0 < len(commands.rows) <= 512,
               "COMPLETE_OWNED_COMMAND_JOURNAL")
        C.write(self.work/"command-retention.json", C.encoded(dict(commands=len(commands.rows),
                  last=C.pin(C.read(commands.out/(f"{len(commands.rows)-1:03d}.json"), C.MIB)))))


def ordinary_service(marker_path, approval_sha):
    C.need(os.getuid() == os.geteuid() > 0 and os.getgid() == os.getegid() > 0
           and os.uname().machine in ("aarch64", "arm64"), "ACTUAL_ORDINARY_ARM_SERVICE")
    marker_path = C.ordinary(marker_path)
    control = marker_path.parent
    owner = control.lstat()
    C.need(owner.st_uid == 0 and stat.S_IMODE(owner.st_mode) == 0o755,
           "ROOT_OWNED_CONTROL_OUTSIDE_ORDINARY_WORK")
    marker = C.decode(wait_for(marker_path, time.monotonic()+30, 0, mode=0o444))
    C.need(marker["approval_sha256"] == approval_sha and marker["kind"] == "QT612_ROOT_SERVICE_HANDOFF_V1",
           "SAME_ROOT_SERVICE_APPROVAL")
    runtime, r128 = control/"runtime", control/"r128"
    C.need(HERE == (runtime/C.ENTRY).parent, "SAME_ROOT_OWNED_SERVICE_CODE")
    approval = C.approval(C.read(control/"approval.json", 65536, owner=0, mode=0o444), approval_sha,
                          marker["environment"], int(time.time()))
    work = C.ordinary(marker["work"])

    def mark(stage):
        atomic_marker(ordinary_progress_marker(work, stage), stage, 0o600)

    mark("SERVICE_JOIN")
    C.entries(runtime, approval)
    os.environ.clear()
    os.environ.update(marker["environment"])
    os.environ.update(PATH="/usr/bin:/bin", HOME=str(work), TMPDIR=str(work/"tmp"), LC_ALL="C.UTF-8", TZ="UTC")
    mark("SERVICE_HELPERS")
    code = control/"helpers"
    launch = helpers(code)
    retained = launch.load_retained_runtime(r128)
    source = work/"bound/Source-DATA"
    pipeline = load(code/C.FAMILY/"pipeline.py", "qt612_pair_pipeline")
    family_source = load(code/C.FAMILY/"source.py", "qt612_pair_family_source")
    mark("SERVICE_VOLUME")
    C.need(all(not os.access(path, os.W_OK) for path in (source, runtime, code)), "READ_ONLY_SELECTED_ACTOR_SOURCES")
    ordinary_volume(launch, work, marker["volume_identity"], marker["gid"])
    mark("SERVICE_DOMAIN")
    pipeline.C.read_source(source, marker["source_map"]["sha256"])
    journal = work/"commands"
    journal.mkdir(mode=0o700)
    with retained["container_runtime"].Cancellation() as cancellation:
        commands = retained["entry"].Commands(retained["owned_process"], journal, marker["ends"]["bootstrap"],
                                               marker["ends"]["work"], cancellation)
        supervisor = OrdinarySupervisor(marker, retained, pipeline, commands, control, work)
        socket = supervisor.require_domain(pipeline.POLICY)
        result = launch.run_owned_payload(pipeline=pipeline, family_source=family_source,
            bootstrap={key:retained[key] for key in ("entry", "carrier", "rootfs", "native", "container_runtime")},
            supervisor=supervisor, commands=commands,
            prepared=dict(source=source, work=work, input_receipt=dict(new_source_map=marker["source_map"]),
                          input_test_certificate=Path(marker["md4c"]["certificate"]["path"]),
                          acquisition=dict(md4c_public_certificate=C.CERTIFICATE)),
            socket=socket, nonce=marker["nonce"], auth=marker["md4c"], stage_mode="pair-only", stage=mark)
    C.need(result["status"] == "PASS_QT612_FAMILY_COMPONENT_PAIR_ONLY" and result["lifecycle_status"] == "NOT_RUN",
           "NATURAL_PAIR_ONLY_RESULT")
    C.write(work/"ordinary-result.json", C.encoded(result["passive_export"]))


def authenticate_356(owner, launch, pipeline, marker, inventory, request_raw, trace):
    trace.mark("SIGNED356_REQUEST_VALIDATE")
    request = C.decode(request_raw)
    C.shape(request, ("image", "inventory", "source_map_sha256", "nonce"), "EXACT_IMAGE_HANDOFF_FIELDS")
    nonce = marker["nonce"]
    image = request["image"]
    C.need(type(image) is str and image.startswith("sha256:") and C.hexid(image[7:])
           and C.encoded(request) == C.encoded(dict(image=image, inventory=C.pin(inventory),
                      source_map_sha256=marker["source_map"]["sha256"], nonce=nonce)),
           "EXACT_ACTUAL_356_HANDOFF")
    end = marker["ends"]["bootstrap"]
    C.need(time.monotonic()+45 < end, "REMAINING_SIGNED_356_READBACK_BUDGET")
    trace.mark("SIGNED356_READBACK")
    _, row_raw = owner.docker("image", "inspect", image)
    row, = C.decode(row_raw)
    config = row["Config"]
    expected_user = f"{marker['uid']}:{marker['gid']}"
    C.need(row["Id"] == image and row["Architecture"] == "arm64" and row["Os"] == "linux"
           and row["RepoTags"] == [f"cachy-qt612-native-{nonce}:gui-server356"] and not row.get("RepoDigests")
           and (config["Labels"] or {}).get(launch.executor.LABEL) == nonce and config["User"] == expected_user,
           "ROOT_READBACK_OF_FRESH_NATIVE_356_IMAGE")
    C.need(owner.docker("container", "ls", "-a", "--quiet", "--no-trunc")[1] == b"", "FRESH_DAEMON_CONTAINER_CENSUS")
    trace.mark("SIGNED356_INVENTORY_READBACK")
    _, actual = owner.docker("run", "--rm", "--pull=never", "--platform=linux/arm64", "--network=none",
        "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--cpus=1", "--memory=512m",
        "--memory-swap=512m", "--pids-limit=32", "--name", f"cachy-qt612-family-{nonce}-root-inventory356",
        "--user", expected_user, "--entrypoint=/bin/sh", image, "-ec",
        f"test -r /etc/pacman.conf && test ! -e {launch.GPGDIR} && test ! -e {launch.TEST_CERT}"
        " && pacman -Q | LC_ALL=C sort")
    C.need(actual == inventory and time.monotonic() < end, "ROOT_OBSERVED_EXACT_SIGNED_356_INVENTORY")
    for _ in range(2):
        C.need(owner.docker("container", "ls", "-a", "--quiet", "--no-trunc")[1] == b"", "ROOT_INVENTORY_ABSENT_TWICE")
    trace.mark("SIGNED356_BINDING")
    now = int(time.time())
    remaining = marker["ends"]["work"] - time.monotonic() - RETIRE_EXPORT_SECONDS
    expiry = min(marker["expires"], now+C.COMPONENT, math.floor(time.time()+remaining))
    C.need(expiry-now >= 15400, "BOUND_PAIR_COMMAND_TIME_AVAILABLE")
    return C.late_binding(pipeline.binding_template(), dispatch=marker["dispatch"], nonce=nonce,
                          map_sha=marker["source_map"]["sha256"], image=image, inventory=C.pin(actual),
                          now=now, expiry=expiry)


def preserve_export(launch, pipeline, marker, binding, binding_sha, work, output):
    journal = C.decode(C.read(work/"command-retention.json", C.MIB, owner=marker["uid"]))
    C.shape(journal, ("commands", "last"), "EXACT_ORDINARY_COMMAND_RETENTION")
    count = journal["commands"]
    C.need(type(count) is int and 0 < count <= 512, "FINITE_RETAINED_COMMAND_COUNT")
    C.read(work/"commands"/f"{count-1:03d}.json", C.MIB, journal["last"], owner=marker["uid"])
    result = C.decode(C.read(work/"ordinary-result.json", C.MIB, owner=marker["uid"]))
    C.shape(result, ("path", "manifest_pin", "selected"), "EXACT_ORDINARY_EXPORT_HANDOFF")
    root = work/"gui-pair-evidence"
    selected = result["selected"]
    C.need(result["path"] == str(root) and selected["dispatch"] == marker["dispatch"]
           and selected["source_map"] == marker["source_map"] and selected["stage_binding_sha256"] == binding_sha,
           "ROOT_SELECTED_EXPORT_IDENTITY")
    manifest = C.decode(C.read(root/"pair-export.json", C.MIB, result["manifest_pin"], owner=marker["uid"]))
    witness = C.decode(C.read(root/"owned-pair.json", C.MIB, selected["owner"], owner=marker["uid"]))
    C.need(witness["image"] == binding["image"] and witness["inventory_pin"] == binding["inventory_pin"]
           and witness["nonce"] == marker["nonce"], "ROOT_OBSERVED_IMAGE_PAIR_JOIN")
    wire = launch.evidence.verify_export
    verified = wire(pipeline.C, root=root, manifest_pin=result["manifest_pin"], selected=selected)
    material = pipeline.C.M
    writer = material.Writer(output)
    observed = {}
    try:
        for name, pin in sorted({**manifest["files"], "pair-export.json": result["manifest_pin"]}.items()):
            writer.put(name, source=root/name, expected=pin, observed=observed, cap=512*C.MIB)
        material.unchanged(observed)
    finally:
        writer.close()
    C.need(wire(pipeline.C, root=output, manifest_pin=result["manifest_pin"], selected=selected) == verified,
           "SAME_ROOT_CUSTODY_EXPORT_READBACK")
    return dict(manifest_pin=result["manifest_pin"], selected=selected, qualification=verified,
                ordinary_journal=journal)


def started_owner(owner, marker, control):
    marker_path = control/"service.json"
    observed = owner.start("owner", [owner.tool("python3"), "-I", "-B", str(control/"runtime"/C.ENTRY),
                           "service", "--marker", str(marker_path), "--approval-sha256", marker["approval_sha256"]],
                           marker["uid"], marker["gid"])
    marker["owner"] = observed
    atomic_marker(marker_path, marker)


def owner_finished(owner, marker):
    end = marker["ends"]["work"]
    while time.monotonic()+2 < end:
        row = owner.show("owner")
        if row.get("SubState") == "exited":
            C.need(row.get("Result") == "success" and row.get("ExecMainCode") == "1"
                   and row.get("ExecMainStatus") == "0", "NATURAL_ORDINARY_SERVICE_EXIT")
            return {key: row[key] for key in ("Result", "ExecMainCode", "ExecMainStatus", "SubState")}
        C.need(row.get("LoadState") != "not-found" and row.get("ActiveState") == "active",
               "SAME_OWNED_ORDINARY_SERVICE_RUNNING")
        time.sleep(min(60, max(0, end - time.monotonic() - 2)))
    raise TimeoutError("ORDINARY_SERVICE_WORK_DEADLINE")


def cleanup_passes(value):
    services = value.get("services", {})
    return (value.get("owned_storage_absent") is True and value.get("host_package_mutations") == 0
            and value.get("errors") == [] and set(services) == {"owner", "daemon"}
            and all(row.get("empty_twice") is True and row.get("pidfd_exited") is True
                    and row.get("result") in (None, "success") for row in services.values()))


def root_dispatch(args, trace):
    token = os.environ.pop(TOKEN, "")
    C.need(os.getresuid() == (0, 0, 0) and os.uname().machine in ("aarch64", "arm64"),
           "ACTUAL_ROOT_NATIVE_ARM_CONTROLLER")
    C.need(type(args.runner_uid) is int and type(args.runner_gid) is int and
           0 < args.runner_uid <= 65535 and 0 < args.runner_gid <= 65535, "ORDINARY_RUNNER_UID_GID")
    trace.mark("CONTROLLER_PATHS")
    workflow, runtime, r128, output = map(C.ordinary, (args.workflow_root, args.runtime_source,
                                                     args.r128_source, args.output))
    control = output.with_name(output.name+".authority")
    C.need(all(path.is_dir() for path in (workflow, runtime, r128))
           and all(not os.path.lexists(item) and not item.is_relative_to(path) and not path.is_relative_to(item)
                   for item in (output, control) for path in (workflow, runtime, r128))
           and HERE == (runtime/C.ENTRY).parent, "FRESH_DISJOINT_CONTROLLER_OUTPUT")
    trace.mark("DISPATCH_APPROVAL")
    env = {key: os.environ[key] for key in C.DISPATCH_ENV}
    approval_raw = C.read(args.approval, 65536)
    approval = C.approval(approval_raw, args.approval_sha256, env, int(time.time()))
    selected = approval["runtime_source"]
    trace.mark("CHECKOUT_IDENTITY")
    C.need(git_identity(workflow)[0] == approval["workflow_sha"] and
           git_identity(runtime) == (selected["commit"], selected["tree"]) and
           git_identity(r128) == (C.R128_COMMIT, C.R128_TREE), "EXACT_OBSERVED_WORKFLOW_RUNTIME_R128_IDENTITY")
    trace.mark("CONTROLLER_SCOPE")
    group, start = controller_time(env)
    ends = C.deadlines(start, time.monotonic(), time.time(), approval["expires_utc"])
    trace.mark("SEAL_RUNTIME")
    os.umask(0o022)
    output.mkdir(mode=0o711)
    control.mkdir(mode=0o755)
    sealed, base = control/"runtime", control/"r128"
    sealed.mkdir(mode=0o755)
    base.mkdir(mode=0o755)
    C.entries(runtime, approval, destination=sealed)
    trace.mark("RETAINED_R128_COPY")
    r128_copy(r128, base)
    trace.mark("TEST_TRUST")
    paths = root_inputs(sealed, approval)
    trust_raw = C.read(paths["md4c_authority"], 8192, approval["inputs"]["md4c_authority"])
    C.trust(trust_raw, approval["inputs"]["md4c_authority"], int(time.time()),
            math.ceil(time.time()+ends["bootstrap"]-time.monotonic()), paths["md4c_certificate"])
    C.write(control/"approval.json", approval_raw, 0o444)
    code = control/"helpers"
    trace.mark("HELPER_STAGING")
    helper_receipt = stage_runtime_helpers(sealed, selected["map"], workflow, code)
    launch = helpers(code)
    trace.mark("HELPER_EXPOSURE")
    launch.expose_readonly_tree(code)
    trace.mark("RETAINED_CONTROLLER_LOAD")
    retained = launch.load_retained_runtime(base)
    trace.mark("TRANSFER_PLAN")
    pipeline = load(code/C.FAMILY/"pipeline.py", "qt612_root_pipeline")
    acquire = load(code/C.FAMILY/"acquire_runner_inputs.py", "qt612_pinned_acquisition")
    logical_bytes = portable_plan(acquire, paths, approval)
    transfer = transfer_function(acquire, paths, approval, ends["transfer"], trace, token)
    del token
    # The current job lookup is public. The historical log credential stays in Root
    # custody and the controller/service commands receive only their scrubbed env.
    trace.mark("CURRENT_JOB_IDENTITY")
    with acquire.time_limit(min(20, math.floor(ends["transfer"]-time.monotonic()))):
        realm = fetch(API + "runs/" + env["GITHUB_RUN_ID"] + "/attempts/1/jobs?per_page=100", C.MIB)
    dispatch = C.dispatch(env, C.job_id(realm, env))
    nonce = C.pin(C.encoded(dict(approval=args.approval_sha256, dispatch=dispatch)))["sha256"][:32]
    inherited = retained["controller"]
    trace.mark("CONTROLLER_LIMITS")
    controller_limits = limits(group)
    inherited.D.domain(controller_limits, retained["policy"]["controller"])
    resource.setrlimit(resource.RLIMIT_AS, inherited.V.controller_limit(retained["policy"]))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    trace.mark("CONTROLLER_INIT")
    owner = launch.first_stage_controller(retained, base, output, nonce, args.runner_uid, args.runner_gid)
    owner.end, owner.cleanup_end = ends["work"], ends["cleanup"]
    report = dict(status="HOLD", nonce=nonce, dispatch=dispatch, approval=C.pin(approval_raw),
                  runtime_source=selected, lifecycle_status="NOT_RUN", Root_acceptance=None,
                  native_acceptance=None, helpers=helper_receipt,
                  controller=dict(cgroup=group, limits=controller_limits, ends=ends))
    private = output/".pair-retained"
    with retained["container_runtime"].Cancellation() as cancellation:
        try:
            prepared = launch.reserve_and_bind(owner, acquire.R, transfer,
                selection_sha256=approval["inputs"]["portable_selection"]["sha256"], logical_bytes=logical_bytes,
                stage=trace.mark)
            trace.mark("ORDINARY_SERVICE_HANDOFF")
            work, source = prepared["work"], prepared["source"]
            os.chown(work, 0, args.runner_gid)
            work.chmod(0o1770)
            map_pin = prepared["input_receipt"]["new_source_map"]
            mapped = pipeline.C.read_source(source, map_pin["sha256"])
            C.need(mapped["files"][f"{C.FAMILY}/pipeline.py"]["sha256"] == HELPERS[f"{C.FAMILY}/pipeline.py"],
                   "EXACT_PAIR_ONLY_REBOUND_PIPELINE")
            inventory = C.read(source/"expected356.lock", C.MIB, mapped["files"]["expected356.lock"])
            C.need(len(inventory.splitlines()) == 356, "EXACT_EXPECTED_356_ROWS")
            socket = work.parent/"docker.sock"
            info = socket.lstat()
            vol = prepared["transfer_budget"]["volume"]
            auth = C.trust(trust_raw, approval["inputs"]["md4c_authority"], int(time.time()),
                    math.ceil(time.time()+ends["bootstrap"]-time.monotonic()), prepared["input_test_certificate"])
            marker = dict(kind="QT612_ROOT_SERVICE_HANDOFF_V1", environment=env, work=str(work),
                approval_sha256=args.approval_sha256, daemon=prepared["daemon"], socket=str(socket),
                socket_identity=[info.st_dev, info.st_ino], inventory=C.pin(inventory), source_map=map_pin,
                volume_identity=[vol["device"], vol["inode"], vol["mount"]],
                dispatch=dispatch, nonce=nonce, expires=approval["expires_utc"], uid=args.runner_uid,
                gid=args.runner_gid, ends=ends, md4c=auth)
            check_daemon(marker, retained)
            C.need(time.monotonic() < ends["transfer"], "WHOLE_TRANSFER_BUDGET")
            report.update(acquisition=prepared["acquisition"], storage=prepared["storage"], source_map=map_pin)
            started_owner(owner, marker, control)
            trace.mark("SIGNED356_REQUEST_WAIT")
            request = wait_for_image_request(owner, marker, work, trace)
            trace.mark("SIGNED356_DAEMON_JOIN")
            check_daemon(marker, retained)
            binding = authenticate_356(owner, launch, pipeline, marker, inventory, request, trace)
            atomic_marker(control/"stage-binding.json", binding)
            binding_sha = C.pin(C.encoded(binding))["sha256"]
            report["stage_binding"] = dict(pin=C.pin(C.encoded(binding)), value=binding)
            report["signed356"] = dict(image=binding["image"], inventory=binding["inventory_pin"])
            trace.mark("NATIVE_PAIR_COMPLETION")
            report["natural_exit"] = owner_finished(owner, marker)
            for _ in range(2):
                C.need(owner.docker("container", "ls", "-a", "--quiet", "--no-trunc")[1] == b"" and
                       owner.docker("image", "ls", "-a", "--quiet", "--no-trunc")[1] == b"",
                       "OWNED_DAEMON_CONTAINERS_AND_IMAGES_ABSENT_TWICE")
            trace.mark("CLOSED_EVIDENCE_EXPORT")
            report["evidence"] = preserve_export(launch, pipeline, marker, binding, binding_sha, work, private)
        except BaseException as failure:
            report["failure"] = type(failure).__name__
            report["failure_stage"] = trace.stage.name
            if trace.owner_detail is not None:
                reason, phase = trace.owner_detail
                report["ordinary_handoff"] = dict(reason=reason, last_observed_stage=phase)
        finally:
            trace.mark("OWNED_CLEANUP")
            cancellation.cleaning = True
            try:
                report["cleanup"] = owner.cleanup()
            except BaseException as failure:
                report["cleanup"] = dict(errors=[dict(type=type(failure).__name__)])
        if "evidence" in report and not cancellation.pending and cleanup_passes(report["cleanup"]):
            trace.mark("CLOSED_EVIDENCE_EXPORT")
            for folder, dirs, _ in os.walk(private):
                Path(folder).chmod(0o755)
            os.rename(private, output/"evidence")
            report["status"] = "PASS_QT612_GUI_SERVER_PAIR_EXTERNAL_CLEANUP_ONLY"
        else:
            trace.mark(report.setdefault("failure_stage", "OWNED_CLEANUP"))
            trace.hold()
        trace.mark("OWNER_REPORT")
        C.write(output/"owner-report.json", C.encoded(report), 0o444)
    return 0 if report["status"].startswith("PASS_") else 2


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    C.need(sys.flags.isolated and sys.dont_write_bytecode and __debug__, "ISOLATED_BOUNDED_PYTHON_REQUIRED")
    if argv and argv[0] == "service":
        parser = argparse.ArgumentParser(description="Enter the independently admitted ordinary Qt service")
        parser.add_argument("--marker", type=Path, required=True)
        parser.add_argument("--approval-sha256", required=True)
        args = parser.parse_args(argv[1:])
        ordinary_service(args.marker, args.approval_sha256)
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    for path in ("workflow-root", "runtime-source", "r128-source", "approval", "output"):
        parser.add_argument("--"+path, type=Path, required=True)
    parser.add_argument("--approval-sha256", required=True)
    parser.add_argument("--runner-uid", required=True, type=int)
    parser.add_argument("--runner-gid", required=True, type=int)
    args = parser.parse_args(argv)
    trace = ControllerTrace()
    try:
        return root_dispatch(args, trace)
    except Exception:
        trace.hold()
        return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print("HOLD_QT612_PAIR: SERVICE_OR_ARGUMENTS", file=sys.stderr)
        raise SystemExit(2)
