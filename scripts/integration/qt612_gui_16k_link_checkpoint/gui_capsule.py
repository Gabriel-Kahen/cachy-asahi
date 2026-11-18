# SPDX-License-Identifier: MIT
"""Exact staged QtGui capsule, resource and Root entry contracts."""

import importlib.util
import os
from pathlib import Path
import re
from runpy import run_path
import stat
import struct
import time
from types import SimpleNamespace
from uuid import UUID

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
LANE = HERE.relative_to(ROOT).as_posix()
PORTABLE = "scripts/integration/qt612_md4c_compile"
SCOPE = "cachy-asahi-qtbase16k-qtgui-link.scope"
ACTOR_PATH = "/src/" + LANE + "/actor.py"
PAYLOAD = "/qtgui-link"
PLAN_LEAF, HANDOFF_LEAF = "PLAN.UNISSUED.json", "HANDOFF.UNISSUED.json"
GUEST_NAMES = ("GUI-GUEST-PLAN.json", "guest-init.sh", "guest_link.py")
CARRIER_NAMES = {"Image", "boot.raw", "core.qcow2", "scratch.raw", "result.raw"}
CORE_KERNEL = dict(bytes=9019400, sha256="36066ded2f5721fd9bb257cebb2e4cb32084f45c3717f4d7a45430fe3cdcc494")
BOOT_BYTES = 1611661312
Q3_CLOSE = dict(bytes=3084, sha256="f60a619b67c097cb90cbcbdd24ba35dc23c367a735c26430583685e4d1729f21")
R4_CLOSE = dict(bytes=3598, sha256="c930b0cd60456d7f7e756829f71a72c8b7bad7faa3ab5664bb4f60c4c541f9b3")
CORE_SCOPE = "cachy-asahi-qtbase16k-qtcore-link.scope"
SOURCE_FILES = {LANE + "/" + leaf for leaf in (
    "actor.py", "gui_capsule.py", "guest-init.sh", "guest_link.py", "continuation.py",
    "elf_readback.py", "inspect_checkpoint.py", "read_capsule.py", "site.py")
} | {
    PORTABLE + "/" + leaf for leaf in ("actor.py", "common.py", "prepare.py", "guest.sh")
} | {
    "scripts/install/overlay583_trial/controller.py", "scripts/install/overlay583_trial/trial.py",
    "scripts/integration/arm16k_perl5423_vm/contracts.py", "scripts/integration/arm16k_perl5423_vm/runtime.py",
    "scripts/integration/arm16k_perl5423_vm/helper-origin.json",
    "scripts/integration/arm16k_perl5423_vm/frozen/owned_process.py",
    "scripts/integration/arm16k_perl5423_vm/frozen/independent_readback.py",
    "scripts/integration/qt612_base_16k_link_preflight/readback.py",
    "scripts/integration/qt612_base_16k_link_preflight/preflight.py",
    "packages/port/qt612-gui-server-source-reference/check_stage.py",
}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


K = SimpleNamespace(**run_path(str(HERE / "continuation.py")))
B = load("qtgui_portable_actor", ROOT / PORTABLE / "actor.py")
O, T, P = B.O, B.T, B.P
C = K.C
IMAGE = O.ACTOR_IMAGE
HEX, NONCE = C.SHA, C.NONCE


def pin_ref(reference):
    return {key: reference[key] for key in ("bytes", "sha256")}


def check_pinned_file(path, pin):
    return C.read(path, pin["bytes"], pin, collect=False)[1]


def canonical_plan(nonce, inputs, guest_raw, backing, runner):
    limits = backing["limits"]
    payload = {"GUI-GUEST-PLAN.json": guest_raw}
    payload.update({name: (HERE / name).read_bytes() for name in GUEST_NAMES[1:]})
    guest_files = {name: P.sha(body) for name, body in payload.items()}
    payload["MANIFEST.sha256"] = P.checksums(guest_files)
    guest_files["MANIFEST.sha256"] = P.sha(payload["MANIFEST.sha256"])

    claim = P.result_uuid(nonce)
    seconds = limits["qemu_seconds"]
    extra = dict(nonce=nonce, manifest=guest_files["MANIFEST.sha256"], guest_plan=guest_files["GUI-GUEST-PLAN.json"],
                 scratch_uuid=K.F.SCRATCH_UUID, result_uuid=claim, result_bytes=limits["result_disk_bytes"],
                 guest_deadline=seconds - 40)
    args = P.vm_argv("/inputs/Image", P.boot_cmdline(nonce, PAYLOAD + "/guest-init.sh") +
                    "".join(f" cachy_qt_gui_{key}={val}" for key, val in extra.items()), "qtgui-" + nonce, (
                        ("boot", "file=/inputs/boot.raw,format=raw,readonly=on"),
                        ("scratch", "file=/out/overlay.qcow2,format=qcow2,readonly=off,discard=ignore"),
                        ("result", "file=/out/result.raw,format=raw,readonly=off"),
                    ))
    args[args.index("-m") + 1] = str(limits["guest_memory_bytes"] // K.MIB)

    profile = dict(kind=P.TOOL_PROFILE_KIND, actor_image=runner["actor_image"], tools=runner["tools"])
    policy = P.actor_policy(profile, K.CORE_SCRATCH["bytes"] + BOOT_BYTES + CORE_KERNEL["bytes"])
    out_max = sum(limits[x] for x in ("overlay_file_bytes", "result_disk_bytes", "report_allocation_bytes"))
    policy.update(overlay_create=backing["overlay_create"], result_disk_bytes=limits["result_disk_bytes"],
                  preparation_readonly_logical_bytes=sum(pin["bytes"] for name, pin in inputs.items()
                                                         if name != "result.raw"),
                  report_allocation_bytes=limits["report_allocation_bytes"],
                  admission_disk_bytes=out_max + limits["host_disk_reserve_bytes"],
                  child_file_size_cap=limits["overlay_file_bytes"],
                  watched_tree=["/out", out_max, limits["host_disk_reserve_bytes"]],
                  watched_paths=[["/out/overlay.qcow2", limits["overlay_file_bytes"]],
                                 ["/out/result.raw", limits["result_disk_bytes"]]])
    plan = dict(kind="QTGUI_LINK_CAPSULE_PLAN_UNISSUED_V1", authority=None, nonce=nonce, inputs=inputs,
                qemu_argv=args, qemu_seconds=seconds, attach_seconds=seconds + 300, actor=policy,
                limits=limits, result_uuid=claim, guest_payload=guest_files, guest_plan=C.pin(guest_raw),
                core_readback=backing["core_readback"], core_elf=backing["core_elf"])
    return plan, payload


def load_plan(path, digest):
    raw, _ = C.external(path, 64 << 10, digest)
    plan = C.json_body(raw, canonical=True)
    C.need(plan["kind"] == "QTGUI_LINK_CAPSULE_PLAN_UNISSUED_V1" and plan["authority"] is None
           and isinstance(plan["nonce"], str) and NONCE.fullmatch(plan["nonce"])
           and set(plan["inputs"]) == CARRIER_NAMES
           and all(C.check_pin(pin, 16 * K.GIB) and pin["bytes"] > 0 for pin in plan["inputs"].values())
           and plan["inputs"]["scratch.raw"] == K.CORE_SCRATCH and plan["inputs"]["Image"] == CORE_KERNEL
           and plan["inputs"]["boot.raw"]["bytes"] == BOOT_BYTES
           and plan["inputs"]["core.qcow2"]["bytes"] <= 4 * K.GIB
           and plan["inputs"]["result.raw"]["bytes"] == plan["limits"]["result_disk_bytes"]
           and plan["result_uuid"] == P.result_uuid(plan["nonce"])
           and plan["attach_seconds"] == plan["qemu_seconds"] + 300
           and plan["actor"]["overlay_create"] == [
               "/usr/bin/qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", K.CORE_OVERLAY, K.TOP_OVERLAY],
           "Exact finite QtGui plan and read-only Core chain required")
    return plan


def runner_shape(runner):
    C.need(set(runner) == {"kind", "actor_image", "tools", "docker", "vcpus"}
           and runner["kind"] == "ROOT_QTGUI_LINK_RUNNER_PROFILE_V1" and runner["actor_image"] == IMAGE
           and type(runner["vcpus"]) is int and runner["vcpus"] == 4
           and set(runner["tools"]) == P.TOOL_NAMES | {"/usr/bin/qemu-img"}
           and all(C.check_pin(pin, 64 << 20) and pin["bytes"] > 0 for pin in runner["tools"].values()),
           "Exact reviewed runner image, tools and vCPU shape required")
    docker = runner["docker"]
    C.need(set(docker) == {"path", "endpoint", "bytes", "sha256"} and C.check_pin(pin_ref(docker), 64 << 20)
           and isinstance(docker["path"], str) and Path(docker["path"]).is_absolute()
           and isinstance(docker["endpoint"], str) and re.fullmatch(r"unix:///run/user/[1-9][0-9]*/docker\.sock",
                                                                     docker["endpoint"]),
           "Explicit pinned local Docker CLI and rootless endpoint required")
    return runner


def load_handoff(path, digest):
    raw, _ = C.external(path, 64 << 10, digest)
    value = C.json_body(raw, canonical=True)
    C.need(set(value) == {"kind", "authority", "scope", "actor_image", "docker", "runner", "plan",
                          "source", "source_tree_sha256", "prior_closures", "input_refs"}
           and value["kind"] == "QTGUI_LINK_CAPSULE_HANDOFF_UNISSUED_V1" and value["authority"] is None
           and value["scope"] == SCOPE and value["actor_image"] == IMAGE and C.check_pin(value["plan"], 64 << 10)
           and value["docker"] == runner_shape(value["runner"])["docker"] and set(value["source"]) == SOURCE_FILES
           and P.sha(C.wire(value["source"])) == value["source_tree_sha256"]
           and set(value["input_refs"]) == {"descriptor", "continuation", "runner"}
           and all(C.check_pin(pin_ref(ref), 128 << 10) and Path(ref["path"]).is_absolute()
                   for ref in value["input_refs"].values())
           and set(value["prior_closures"]) == {"q3", "r4", "core"}, "Exact sealed QtGui handoff required")
    return value


def verify_binding(handoff, plan):
    limits = plan["limits"]
    C.need(set(limits) == set(K.LIMITS)
           and all(type(limits[name]) is int and low <= limits[name] <= high
                   for name, (low, high) in K.LIMITS.items())
           and limits["qemu_seconds"] >= limits["guest_build_seconds"] + 60
           and limits["guest_memory_bytes"] % K.MIB == 0 and limits["actor_memory_bytes"] > limits["guest_memory_bytes"]
           and limits["result_disk_bytes"] % 4096 == 0 and limits["artifact_bytes"] > 133128
           and limits["result_disk_bytes"] >= limits["artifact_bytes"] + limits["build_log_bytes"] + 8 * K.MIB,
           "Exact externally selected finite QtGui budgets required")
    guest = K.wire_guest(dict(kind="QTGUI_LINK_GUEST_PLAN_V1", authority=None, nonce=plan["nonce"],
                              core=plan["core_elf"], target=K.TARGET,
                              limits={name: limits[name] for name in K.GUEST_KEYS}))
    backing = dict(limits=limits, overlay_create=plan["actor"]["overlay_create"],
                   core_readback=plan["core_readback"], core_elf=plan["core_elf"])
    expected, _ = canonical_plan(plan["nonce"], plan["inputs"], guest, backing, handoff["runner"])
    C.need(C.wire(expected) == C.wire(plan), "Plan differs from the sealed guest, tool map or owned command policy")


def verify_source(handoff, source):
    source = T.ordinary(source)
    files = handoff["source"]
    paths = list(source.rglob("*"))
    C.need(len(paths) <= 96 and not any(p.is_symlink() for p in paths)
           and stat.S_IMODE(source.stat().st_mode) == 0o555
           and {p.relative_to(source).as_posix() for p in paths if not p.is_dir()} == SOURCE_FILES,
           "Exact private readonly source namespace required")
    for path in paths:
        ref = files.get(path.relative_to(source).as_posix())
        mode = stat.S_IMODE(path.lstat().st_mode)
        if ref is None:
            C.need(path.is_dir() and mode == 0o555, "Readonly source directory required")
        else:
            C.need(mode == ref["mode"] == 0o444, "Exact source leaf mode required")
            check_pinned_file(path, pin_ref(ref))


def read_predecessors(handoff):
    rows = {}
    for key, ref in handoff["prior_closures"].items():
        raw, pin = C.read(Path(ref["path"]), 128 << 10, pin_ref(ref))
        value = C.json_body(raw)
        if key == "core":
            C.need(value["kind"] == "QTCORE_LINK_POST_SCOPE_V1" and value["scope"] == CORE_SCOPE,
                   "Original retired Core scope required")
        else:
            expected = Q3_CLOSE if key == "q3" else R4_CLOSE
            C.need(pin == expected, "Exact Q3 and R4 close pins required")
        C.need(isinstance(value["scope"], str) and re.fullmatch(r"[A-Za-z0-9_.-]+\.scope", value["scope"])
               and value["scope"] != SCOPE and HEX.fullmatch(value["cid"])
               and value["observations"] == [dict(scope_absent=True, container_absent=True)] * 2,
               "Exact retired prerequisite scope and CID required")
        rows[key] = value["scope"], value["cid"], raw
    return rows


def result_uuid(path, size):
    with K.F.open_original(path) as stream:
        before = K.F.verify_original(stream, path, size)
        head = os.pread(stream.fileno(), 1024, 1024)
        C.need(K.F.identity(os.fstat(stream.fileno())) == before == K.F.identity(path.lstat()),
               "Result carrier metadata changed")
    C.need(len(head) == 1024 and head[56:58] == b"\x53\xef" and head[120:136].rstrip(b"\0") == b"QT16K_GUI"
           and struct.unpack_from("<I", head, 24)[0] == 2
           and struct.unpack_from("<I", head, 4)[0] * 4096 == size
           and struct.unpack_from("<I", head, 336)[0] == 0, "Bounded QtGui result ext4 geometry required")
    return str(UUID(bytes=head[104:120]))


def capacity(path, plan):
    volume = os.statvfs(T.ordinary(path))
    free = volume.f_bavail * volume.f_frsize
    memory = int(re.search(r"^MemAvailable:\s+(\d+) kB$", Path("/proc/meminfo").read_text(), re.M)[1]) * 1024
    cpus = len(os.sched_getaffinity(0))
    disk = plan["actor"]["admission_disk_bytes"]
    ram = plan["limits"]["actor_memory_bytes"] + 2 * K.GIB
    return dict(free_bytes=free, memory_available_bytes=memory, allowed_cpus=cpus,
                required_bytes=disk, minimum_memory_bytes=ram, minimum_cpus=4,
                fits=free >= disk and memory >= ram and cpus >= 4)


def preflight_root(root, handoff, plan):
    root = T.ordinary(root)
    C.need(stat.S_IMODE(root.stat().st_mode) == 0o700, "Private capsule root required")
    verify_source(handoff, root / "source")
    verify_binding(handoff, plan)
    documents = {}
    for name, reference in handoff["input_refs"].items():
        raw, _ = C.read(Path(reference["path"]), 128 << 10, pin_ref(reference))
        documents[name] = C.json_body(raw, canonical=True)
    C.need(documents["runner"] == handoff["runner"]
           and documents["descriptor"]["kind"] == "QTGUI_LINK_CAPSULE_DESCRIPTOR_V1"
           and documents["continuation"]["budget_basis_sha256"] == plan["core_readback"]["sha256"],
           "Exact external runner and retired Core budget basis required")
    predecessors = read_predecessors(handoff)
    post = C.json_body(predecessors["core"][2])
    C.need(post["plan_sha256"] and post["nonce"] != plan["nonce"], "Distinct fresh QtGui continuation required")
    inputs, template = (T.ordinary(root / name) for name in ("inputs", "templates"))
    C.need({p.name for p in inputs.iterdir()} == CARRIER_NAMES - {"result.raw"}
           and {p.name for p in template.iterdir()} == {"result.raw"}
           and stat.S_IMODE(inputs.stat().st_mode) == stat.S_IMODE(template.stat().st_mode) == 0o555,
           "Exact read-only staged images required")
    for name, pin in plan["inputs"].items():
        path = (template if name == "result.raw" else inputs) / name
        C.need(stat.S_IMODE(path.lstat().st_mode) == 0o444, "Exact read-only carrier mode required")
        check_pinned_file(path, pin)
    K.inspect_overlay(inputs / "core.qcow2", plan["inputs"]["core.qcow2"], K.RAW_BACKING, "raw")
    C.need(result_uuid(template / "result.raw", plan["inputs"]["result.raw"]["bytes"]) == plan["result_uuid"],
           "Exact result template identity required")
    check_pinned_file(root / "accepted-core" / K.CORE_ELF, plan["core_elf"])
    check_pinned_file(root / "GUI-GUEST-PLAN.json", plan["guest_plan"])
    return capacity(root, plan)


def binding(handoff, plan, handoff_sha):
    return dict(kind="ROOT_QTGUI_LINK_CAPSULE_SELECTION_V1", issuer=None, approved=None, created_utc=None,
                expires_utc=None, handoff_sha256=handoff_sha, plan_sha256=handoff["plan"]["sha256"],
                scope=SCOPE, nonce=plan["nonce"], actor_image=IMAGE, core_readback=plan["core_readback"])


def verify_selection(raw, digest, handoff, plan, handoff_sha, *, live=True):
    C.need(P.sha(raw) == digest, "Exact independently selected Root entry pin required")
    value = C.json_body(raw, canonical=True)
    start, end = value["created_utc"], value["expires_utc"]
    C.need(type(start) is type(end) is int and 0 < end - start <= 3600
           and (not live or start <= int(time.time()) < end), "Fresh separately issued Root window required")
    expected = binding(handoff, plan, handoff_sha) | dict(issuer="Root", approved=True, created_utc=start, expires_utc=end)
    C.need(raw == C.wire(expected), "Authority differs from the sealed unissued QtGui binding")
    return value
