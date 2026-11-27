#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Seal and run a fresh, offline Qtbase Vulkan/md4c ARM16K guest."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import secrets
import shutil
import signal
import stat
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory
import time


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BASE = "cbc877a35f40aba98aeb53cbcfebd7d18422e5ec"
C = runpy.run_path(str(HERE.parent / "qt612_md4c_compile/prepare.py"))
A = runpy.run_path(str(HERE / "arm16k_actor.py"))
AUTH = runpy.run_path(str(HERE / "arm16k_inputs.py"))
need, pin = A["need"], A["pin"]
GIB = 1 << 30
BOOTS = "boot.raw"
KERNEL = "Image"
SCRATCH = "scratch.raw"
GUEST_PAYLOAD = "/qt-successor"
RESULT_LABEL = "QT16K_SUCC"
DOCKER_PIN = dict(bytes=44217952, sha256="e966e0e6ea215b74fdbee17fbe7ed8bff15b65930bfc8e131652ceae4ed0210e")
IMAGE = C["QEMU_ACTOR_IMAGE"]
ROLE_LABEL = "org.cachy-asahi.qtbase-successor16k.nonce"
TOOLS = {
    "qemu-img": dict(bytes=2567104, sha256="2139b2c8d5a9f28dbef2c5cdb663ce842648105fa76720ec691f8f5cddc8b002"),
    "qemu-system-aarch64": dict(bytes=34622584,
                               sha256="6f16cea44da813a65a1076886f63687350a0173e188873ba227dcc06f5c16b27"),
    "e2fsck": dict(bytes=356568, sha256="a9ea133a844edd695b5172abadc8bbbbb03aaedad80fc24d039bdbf4563a125c"),
}
FORMAT_TOOLS = {
    "debugfs": dict(bytes=218712, sha256="41d0fc883db19d89f65503ce3cd1c016bd7a33ad750f28a349c050742de0e9b1"),
    "e2fsck": dict(bytes=405720, sha256="3287fdce1c7f9ffadc760e24fbae88a0ecd9abe7536f2f60725c9bfbd480333d"),
    "mke2fs": dict(bytes=145768, sha256="0b645e158b060a7ff22bff543b20c6aeba043f7ebca24e7a2f63a20bd3e46130"),
}
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"}
GUEST_SOURCES = {"arm16k-guest-init.sh": "guest-init.sh", "arm16k-build.sh": "arm16k-build.sh"}


def put(path, body):
    with path.open("xb") as file:
        file.write(body)
    path.chmod(0o444)


def wire(data):
    return (json.dumps(data, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def canonical_path(path):
    need(path.is_absolute() and path == path.resolve() and re.fullmatch(r"/[a-zA-Z0-9_.+/-]+", str(path)),
         f"Need a normalized absolute path without spaces: {path}")
    return path


def local_tool(name, *argv, timeout=180):
    executable = Path("/usr/bin") / name
    need(pin(executable) == FORMAT_TOOLS[name], f"Host tool changed: {name}")
    call = subprocess.run([executable, *map(str, argv)], env=ENV, capture_output=True,
                          stdin=subprocess.DEVNULL, check=True, timeout=timeout)
    need(len(call.stdout) + len(call.stderr) <= 2 << 20, f"Host tool output too large: {name}")
    return call.stdout


def limits(mode):
    qemu_seconds = {"full": 16 * 3600 + 180, "configure": 2400}[mode]
    return dict(vcpus=4, guest_bytes=6 * GIB, container_bytes=8 * GIB, overlay_bytes=10 * GIB,
                result_bytes=2 * GIB, host_disk_reserve_bytes=2 * GIB, host_memory_reserve_bytes=2 * GIB,
                serial_bytes=16 << 20, qemu_seconds=qemu_seconds, guest_seconds=qemu_seconds - 180)


def capacity(path, budget):
    available = int(re.search(r"^MemAvailable:\s+(\d+) kB$", Path("/proc/meminfo").read_text(),
                              re.MULTILINE)[1]) * 1024
    cpus = len(os.sched_getaffinity(0))
    cgroup = Path("/sys/fs/cgroup") / Path(Path("/proc/self/cgroup").read_text().strip()[4:])
    for scope in (cgroup, *cgroup.parents):
        if (scope / "memory.max").is_file():
            ceiling = (scope / "memory.max").read_text().strip()
            if ceiling != "max":
                available = min(available, int(ceiling) - int((scope / "memory.current").read_text()))
        if (scope / "cpu.max").is_file():
            quota, period = (scope / "cpu.max").read_text().split()
            if quota != "max":
                cpus = min(cpus, int(quota) // int(period))
        if scope == Path("/sys/fs/cgroup"):
            break
    disk = shutil.disk_usage(path).free
    need(available >= budget["container_bytes"] + budget["host_memory_reserve_bytes"]
         and disk >= budget["overlay_bytes"] + budget["result_bytes"] + budget["host_disk_reserve_bytes"] + (128 << 20)
         and cpus >= budget["vcpus"], "Current host memory, disk or CPUs cannot cover the build envelope")
    return dict(available_bytes=available, free_bytes=disk, eligible_cpus=cpus)


def make_boot(original, target, folder, staged, nonce):
    offset = C["OFFSET"]
    extent = original.stat().st_size - offset
    partition = folder / "boot.ext4"
    C["clone"](original, target)
    C["clone"](original, partition, start=offset, count=extent)
    with target.open("r+b") as stream:
        mbr = stream.read(512)
        signature = struct.pack("<I", int(nonce[:8], 16))
        need(mbr[510:] == b"\x55\xaa" and mbr[450] == 0x83 and mbr[462:510] == bytes(48)
             and struct.unpack_from("<II", mbr, 454) == (offset // 512, extent // 512)
             and signature != mbr[440:444], "Expected retained partition geometry and fresh boot identity")
        stream.seek(440)
        stream.write(signature)

    edits = [f"mkdir {GUEST_PAYLOAD}", f"set_inode_field {GUEST_PAYLOAD} mode 040755"]
    files = {}
    for path in sorted(staged.rglob("*")):
        leaf = path.relative_to(staged).as_posix()
        name = f"{GUEST_PAYLOAD}/{leaf}"
        need(re.fullmatch(r"[a-zA-Z0-9_.+:/@-]+", leaf) is not None and not path.is_symlink(),
             "Unexpected boot payload path")
        if path.is_dir():
            edits.extend([f"mkdir {name}", f"set_inode_field {name} mode 040755"])
            continue
        mode = "0555" if leaf == "guest-init.sh" else "0444"
        files[leaf] = pin(path)
        edits.extend([f"write {path} {name}", f"set_inode_field {name} mode 010{mode}"])
    commands = folder / "debugfs.commands"
    commands.write_text("\n".join(edits) + "\n")
    local_tool("debugfs", "-w", "-f", commands, partition)
    local_tool("e2fsck", "-fn", partition)
    dump = folder / "readback"
    for name, expected in files.items():
        local_tool("debugfs", "-R", f"dump {GUEST_PAYLOAD}/{name} {dump}", partition)
        need(pin(dump) == expected, f"Boot payload readback differs: {name}")
        dump.unlink()
    C["clone"](partition, target, count=extent, destination=offset, existing=True)
    target.chmod(0o444)
    return files


def qemu_args(nonce, manifest, mode, budget):
    uuid = C["result_uuid"](nonce)
    fields = dict(nonce=nonce, manifest=manifest, result_uuid=uuid, result_bytes=budget["result_bytes"],
                  deadline=budget["guest_seconds"], mode=mode)
    append = C["boot_cmdline"](nonce, GUEST_PAYLOAD + "/guest-init.sh")
    append += "".join(f" cachy_qt_successor_{key}={val}" for key, val in fields.items())
    args = C["vm_argv"]("/inputs/Image", append, "qtbase-successor-" + nonce, (
        ("boot", "file=/inputs/boot.raw,format=raw,readonly=on"),
        ("scratch", "file=/out/overlay.qcow2,format=qcow2,readonly=off,discard=ignore"),
        ("result", "file=/out/result.raw,format=raw,readonly=off"),
    ))
    args[args.index("-m") + 1] = str(budget["guest_bytes"] >> 20)
    return args


def prepare(args):
    output = canonical_path(args.output)
    budget = limits(args.mode)
    need(not output.exists() and output.parent.is_dir() and not output.is_relative_to(ROOT),
         "Choose a fresh private capsule path outside the source checkout")
    capacity(output.parent, budget)
    chosen = {name: canonical_path(getattr(args, name)) for name in
              ("evidence", "q3", "boot", "kernel", "config", "backing", "docker")}
    need(pin(chosen["docker"]) == DOCKER_PIN, "Retained rootless Docker CLI differs")
    output.mkdir(mode=0o700)
    media = output / "media"
    media.mkdir()
    nonce = secrets.token_hex(16)
    need(nonce[:8] != "00000000", "Fresh nonzero partition identity required")
    with TemporaryDirectory(prefix="prepare-", dir=output) as temporary:
        work = Path(temporary)
        staged = work / "stage"
        inputs = AUTH["authenticate"](*(chosen[name] for name in
                                        ("evidence", "q3", "boot", "kernel", "config", "backing")), staged)
        for source, filename in GUEST_SOURCES.items():
            put(staged / filename, (HERE / source).read_bytes())
        manifest = C["checksums"]({p.relative_to(staged).as_posix(): pin(p)["sha256"]
                                  for p in staged.rglob("*") if p.is_file()})
        put(staged / "manifest.sha256", manifest)
        payload = make_boot(chosen["boot"], media / BOOTS, work, staged, nonce)
        recipe = output / "recipe"
        recipe.mkdir(mode=0o700)
        for path in (staged / "recipe").iterdir():
            put(recipe / path.name, path.read_bytes())
        recipe.chmod(0o555)
    result = media / "result.template"
    with result.open("xb") as file:
        file.truncate(budget["result_bytes"])
    uuid = C["result_uuid"](nonce)
    local_tool("mke2fs", "-q", "-F", "-t", "ext4", "-b", "4096", "-L", RESULT_LABEL,
               "-U", uuid, "-O", "^orphan_file", "-E", "lazy_itable_init=0,lazy_journal_init=0", result)
    local_tool("e2fsck", "-fn", result)
    result.chmod(0o444)
    put(media / "actor.py", (HERE / "arm16k_actor.py").read_bytes())
    C["clone"](chosen["kernel"], media / KERNEL)
    (media / KERNEL).chmod(0o444)
    for name in ("boot", "config", "kernel", "backing"):
        need(pin(chosen[name]) == {key: inputs["originals"][name][key] for key in ("bytes", "sha256")},
             f"Original media changed during staging: {name}")
    endpoint = f"/run/user/{os.getuid()}/docker.sock"
    revision = subprocess.run(["/usr/bin/git", "-C", ROOT, "rev-parse", "HEAD"], env=ENV, check=True,
                              capture_output=True, text=True, timeout=5).stdout.strip()
    plan = dict(kind="QTBASE_SUCCESSOR16K_PLAN_V1", base_revision=BASE, source_revision=revision,
                launcher=pin(Path(__file__)), actor=pin(media / "actor.py"),
                nonce=nonce, mode=args.mode, limits=budget, runner_image=IMAGE, tools=TOOLS,
                docker=dict(path=str(chosen["docker"]), socket=endpoint, **DOCKER_PIN),
                inputs=inputs, media={name: pin(media / name) for name in (BOOTS, KERNEL)},
                result_uuid=uuid, result_template=pin(result), payload=payload,
                qemu_argv=qemu_args(nonce, payload["manifest.sha256"]["sha256"], args.mode, budget))
    put(output / "plan.json", wire(plan))
    print(json.dumps(dict(capsule=str(output), plan_sha256=pin(output / "plan.json")["sha256"],
                          status="SEALED_OFFLINE_SUCCESSOR16K"), sort_keys=True))


class Docker:
    def __init__(self, ref):
        self.path = canonical_path(Path(ref["path"]))
        self.sock = Path(ref["socket"])
        observed = self.sock.lstat()
        need(self.sock == Path(f"/run/user/{os.getuid()}/docker.sock") and stat.S_ISSOCK(observed.st_mode)
             and observed.st_uid == os.getuid() and pin(self.path) == DOCKER_PIN,
             "Expected retained user-owned Docker endpoint and pinned CLI")
        self.identity = observed.st_dev, observed.st_ino
        info = json.loads(self.call("info", "--format", "{{json .}}").stdout)
        need("name=rootless" in info["SecurityOptions"] and info["CgroupVersion"] == "2",
             "Expected rootless Docker with cgroup v2")
        image = json.loads(self.call("image", "inspect", IMAGE).stdout)
        need(len(image) == 1 and image[0]["Id"] == IMAGE and not image[0]["Config"].get("Volumes"),
             "Pinned local runner image unavailable")

    def argv(self, *args):
        observed = self.sock.lstat()
        need(self.identity == (observed.st_dev, observed.st_ino),
             "The selected rootless Docker endpoint changed")
        return [self.path, "--host", "unix://" + str(self.sock), *args]

    def call(self, *args, check=True):
        result = subprocess.run(self.argv(*args), env=ENV, stdin=subprocess.DEVNULL,
                                capture_output=True, check=check, timeout=30)
        need(len(result.stdout) + len(result.stderr) <= 2 << 20, "Docker command output exceeded its ceiling")
        return result


def host_identity(row, cid, name, plan):
    need(row["Id"] == cid and row["Name"] == "/" + name and row["Image"] == IMAGE
         and row["Config"]["Labels"].get(ROLE_LABEL) == plan["nonce"],
         "Docker container identity differs")


def inspect(docker, cid, name, plan, mounts, entry):
    rows = json.loads(docker.call("container", "inspect", cid).stdout)
    need(len(rows) == 1, "Expected a single owned container record")
    row = rows[0]
    host_identity(row, cid, name, plan)
    host, cfg = row["HostConfig"], row["Config"]
    budget = plan["limits"]
    need(row["Path"] == "/usr/bin/python3" and row["Args"] == entry
         and host["NetworkMode"] == "none" and host["ReadonlyRootfs"] and not host["Privileged"]
         and host["CapDrop"] == ["ALL"] and host["PidsLimit"] == 256
         and host["Memory"] == host["MemorySwap"] == budget["container_bytes"]
         and host["NanoCpus"] == budget["vcpus"] * 10**9 and host["CgroupnsMode"] == "private"
         and host["SecurityOpt"] in (["no-new-privileges"], ["no-new-privileges=true"])
         and not any(host.get(key) for key in ("CapAdd", "Devices", "DeviceRequests", "DeviceCgroupRules",
                                              "PortBindings", "PublishAllPorts", "PidMode", "Binds", "VolumesFrom"))
         and all(leaf["Type"] == "bind" and leaf["Propagation"] == "rprivate" for leaf in row["Mounts"])
         and {(leaf["Source"], leaf["Destination"], leaf["RW"]) for leaf in row["Mounts"]} == set(mounts)
         and not cfg.get("Tty") and not cfg.get("OpenStdin"), "Unexpected container resource or isolation setup")
    return row["State"]


def mount_flags(mounts):
    result = []
    for path, target, writable in mounts:
        option = f"type=bind,source={path},target={target}"
        result.extend(("--mount", option if writable else option + ",readonly"))
    return result


def original_media(plan):
    observed = {}
    for name, ref in plan["inputs"]["originals"].items():
        path = canonical_path(Path(ref["path"]))
        expected = {key: ref[key] for key in ("bytes", "sha256")}
        observed[name] = AUTH["verify"](path, expected, readonly=name != "config")
    return observed


def start(args):
    root = canonical_path(args.capsule)
    need(root.stat().st_uid == os.getuid() and stat.S_IMODE(root.stat().st_mode) == 0o700,
         "Expected private owned capsule")
    body = (root / "plan.json").read_bytes()
    digest = hashlib.sha256(body).hexdigest()
    need(len(body) <= 128 << 10 and digest == args.plan_sha256, "Independent plan digest differs")
    plan = json.loads(body)
    budget = limits(plan["mode"])
    media = root / "media"
    nonce = plan["nonce"]
    need(plan["kind"] == "QTBASE_SUCCESSOR16K_PLAN_V1" and plan["base_revision"] == BASE
         and plan["limits"] == budget and plan["launcher"] == pin(Path(__file__))
         and plan["actor"] == pin(media / "actor.py") == pin(HERE / "arm16k_actor.py")
         and plan["runner_image"] == IMAGE and plan["tools"] == TOOLS and re.fullmatch("[0-9a-f]{32}", nonce)
         and plan["result_uuid"] == C["result_uuid"](nonce)
         and plan["qemu_argv"] == qemu_args(nonce, plan["payload"]["manifest.sha256"]["sha256"], plan["mode"], budget),
         "Unexpected successor plan configuration")
    need(plan["media"] == {name: pin(media / name) for name in (BOOTS, KERNEL)}
         and plan["result_template"] == pin(media / "result.template"), "Prepared media differs")
    originals = original_media(plan)
    ready = capacity(root, budget)
    docker = Docker(plan["docker"])
    out = root / "run"
    out.mkdir(mode=0o700)
    C["clone"](media / "result.template", out / "result.raw")
    backing = canonical_path(Path(plan["inputs"]["originals"]["backing"]["path"]))
    mounts = [(str(media / BOOTS), "/inputs/boot.raw", False), (str(media / KERNEL), "/inputs/Image", False),
              (str(backing), "/inputs/scratch.raw", False), (str(media / "actor.py"), "/actor.py", False),
              (str(root / "plan.json"), "/input-plan.json", False), (str(out), "/out", True)]
    name, label = "caa-qtbase-successor16k-" + nonce, ROLE_LABEL + "=" + nonce
    mem = budget["container_bytes"]
    entry = ["-I", "-B", "/actor.py", digest]
    ci = docker.call("container", "create", "--name", name, "--label", label, "--pull=never",
                     "--read-only", "--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                     "--restart=no", "--no-healthcheck", "--cgroupns=private", "--ipc=private",
                     "--pids-limit=256", "--cpus=4", f"--memory={mem}", f"--memory-swap={mem}",
                     "--log-driver=json-file", "--log-opt=max-size=2m", "--log-opt=max-file=1",
                     *mount_flags(mounts), "--entrypoint=/usr/bin/python3", IMAGE, *entry)
    cid = ci.stdout.decode("ascii").strip()
    need(re.fullmatch("[0-9a-f]{64}", cid), "Container create did not report an exact ID")
    started = time.time()
    put(root / "launch.started.json", wire(dict(cid=cid, name=name, nonce=nonce, started=started,
                                                plan_sha256=digest, capacity=ready)))
    exit_code = None
    absence = []
    state = None
    error = None

    def interrupted(signum, _frame):
        raise InterruptedError(f"Launcher received signal {signum}")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        need(inspect(docker, cid, name, plan, mounts, entry)["Status"] == "created",
             "Selected actor already started")
        with (root / "container.log").open("xb") as log:
            attach = subprocess.run(docker.argv("container", "start", "-a", cid), env=ENV,
                                    stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                    timeout=budget["qemu_seconds"] + 420)
        state = inspect(docker, cid, name, plan, mounts, entry)
        need(state["Status"] == "exited" and state["Running"] is False, "Actor did not exit")
        exit_code = state["ExitCode"]
        need(attach.returncode == exit_code, "Attach receipt and actor exit status differ")
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        error = str(exc)
    finally:
        found = docker.call("container", "inspect", cid, check=False)
        need(found.returncode == 0, "The owned actor could not be located for retirement")
        row = json.loads(found.stdout)[0]
        host_identity(row, cid, name, plan)
        if row["State"]["Running"]:
            docker.call("container", "stop", "--time=20", cid)
        need(docker.call("container", "rm", cid).stdout.decode().strip() == cid, "Retirement ID differs")
        for _ in range(2):
            found = docker.call("container", "ls", "-a", "--no-trunc", "--filter", "id=" + cid, "--format", "{{.ID}}")
            need(not found.stdout, "Retired container is still present")
            absence.append(True)
            time.sleep(0.2)

    unchanged = originals == original_media(plan)
    need(unchanged and plan["media"] == {name: pin(media / name) for name in (BOOTS, KERNEL)},
         "Read-only input media changed")
    observed = {p.name: pin(p) for p in out.iterdir()}
    actor = json.loads((out / "actor.json").read_bytes()) if "actor.json" in observed else {}
    attach_log = pin(root / "container.log") if (root / "container.log").is_file() else None
    launch = dict(kind="QTBASE_SUCCESSOR16K_LAUNCH_V1", nonce=nonce, plan_sha256=digest, cid=cid,
                  started=started, completed=time.time(), container_exit=exit_code, container_state=state,
                  qemu_exit=actor.get("qemu_exit"), process_reaped=actor.get("process_reaped", False),
                  container_absent=absence, originals_unchanged=unchanged, error=error, files=observed,
                  attach_log=attach_log)
    put(root / "launch.json", wire(launch))
    print(json.dumps(dict(launch_sha256=pin(root / "launch.json")["sha256"], container_exit=exit_code,
                          qemu_exit=launch["qemu_exit"], error=error), sort_keys=True))
    return 0 if exit_code == launch["qemu_exit"] == 0 and error is None and launch["process_reaped"] else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    seal = sub.add_parser("prepare")
    for name in ("evidence", "q3", "boot", "kernel", "config", "backing", "docker", "output"):
        seal.add_argument("--" + name, type=Path, required=True)
    seal.add_argument("--mode", choices=("full", "configure"), default="full")
    launch = sub.add_parser("start")
    launch.add_argument("--capsule", type=Path, required=True)
    launch.add_argument("--plan-sha256", required=True)
    args = parser.parse_args()
    return prepare(args) if args.action == "prepare" else start(args)


if __name__ == "__main__":
    os.umask(0o077)
    try:
        sys.exit(main())
    except subprocess.CalledProcessError as exc:
        diagnostics = exc.stderr.decode(errors="replace").strip() if exc.stderr else ""
        sys.exit(f"{exc}\n{diagnostics}")
    except (KeyError, OSError, ValueError, subprocess.SubprocessError) as exc:
        sys.exit(str(exc))
