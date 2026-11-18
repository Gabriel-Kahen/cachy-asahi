# SPDX-License-Identifier: MIT
"""Stage one private, unissued QtGui capsule from a retired and accepted QtCore attempt."""

import argparse
import importlib.util
import os
from pathlib import Path
import re
import resource
from runpy import run_path
import stat
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory, TemporaryFile
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
LANE = HERE.relative_to(REPO).as_posix()
K = SimpleNamespace(**run_path(str(HERE / "continuation.py")))
C = K.C
PORTABLE = "scripts/integration/qt612_md4c_compile"
# The original importer 500223f8 and public port ac9ed3ce have the same four
# bodies. Checkout admission uses the held pins from the QtCore capsule.
PORTABLE_PINS = {PORTABLE + "/" + name: C.file_pin(size, digest) for name, (size, digest) in {
    "actor.py": (13358, "69ec1bde10f36ff727dda51a80d354b6265b8a2295b46fdc1f86838382191f22"),
    "common.py": (10435, "c83ff6391a56c05fbae56668af8f3f020c739531488eedb99b0309dc54465ddf"),
    "prepare.py": (29158, "e0212da30780cdf3507c796f6f523d4c5e0e37716395b3477fc66b8daa0e2740"),
    "guest.sh": (8854, "4c9f3c4f19ab72474091eb65ff2f4970635e70fd91c5fce143802b46b466d485"),
}.items()}
FORMAT_TOOLS = {"debugfs", "e2fsck", "mke2fs"}
OWN = {LANE + "/" + leaf for leaf in ("actor.py", "gui_capsule.py", "guest-init.sh", "guest_link.py",
                                      "continuation.py", "elf_readback.py", "inspect_checkpoint.py",
                                      "read_capsule.py", "site.py")}
SHARED = {
    "scripts/install/overlay583_trial/controller.py", "scripts/install/overlay583_trial/trial.py",
    "scripts/integration/arm16k_perl5423_vm/contracts.py", "scripts/integration/arm16k_perl5423_vm/runtime.py",
    "scripts/integration/arm16k_perl5423_vm/helper-origin.json",
    "scripts/integration/arm16k_perl5423_vm/frozen/owned_process.py",
    "scripts/integration/arm16k_perl5423_vm/frozen/independent_readback.py",
    "scripts/integration/qt612_base_16k_link_preflight/readback.py",
    "scripts/integration/qt612_base_16k_link_preflight/preflight.py",
    "packages/port/qt612-gui-server-source-reference/check_stage.py",
}


def stage_source(source):
    inherited = {name: C.read(REPO / name, pin["bytes"], pin)[0] for name, pin in PORTABLE_PINS.items()}
    source_files = OWN | SHARED | inherited.keys()
    for name in sorted(source_files):
        body = inherited[name] if name in inherited else C.read(REPO / name, 2 << 20)[0]
        C.need(0 < len(body) <= 2 << 20, "Bounded complete source leaf required")
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        K.save(path, body)
    directories = sorted((p for p in source.rglob("*") if p.is_dir()), key=lambda p: len(p.parts), reverse=True)
    for path in [*directories, source]:
        path.chmod(0o555)
    spec = importlib.util.spec_from_file_location("qtgui_preparer_capsule", source / LANE / "gui_capsule.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    C.need(module.SOURCE_FILES == source_files, "Exact runtime source namespace required")
    return module


class Formatting:
    def __init__(self, capsule, pins):
        C.need(type(pins) is dict and set(pins) == FORMAT_TOOLS, "Explicit pinned host preparation tools required")
        self.capsule, self.pins = capsule, pins
        for name in pins:
            self.verify(name)

    def verify(self, name):
        ref = self.pins[name]
        path = Path("/usr/bin") / name
        C.need(set(ref) == {"path", "bytes", "sha256"} and Path(ref["path"]) == path,
               "Exact local filesystem preparation tool required")
        info = path.lstat()
        C.need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o755,
               "Ordinary root-owned filesystem preparation tool required")
        self.capsule.T.read(path, self.capsule.pin_ref(ref), cap=32 << 20, collect=False,
                            allowed_links=(1,) if name == "debugfs" else (1, 4))
        return C.identity(info)

    def run(self, name, args, cwd, seconds=120):
        original = self.verify(name)

        def limits():
            resource.setrlimit(resource.RLIMIT_FSIZE, (2 << 30, 2 << 30))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

        with TemporaryFile(dir=cwd) as stdout, TemporaryFile(dir=cwd) as stderr:
            subprocess.run([self.pins[name]["path"], *map(str, args)], cwd=cwd, stdin=subprocess.DEVNULL,
                           stdout=stdout, stderr=stderr, timeout=seconds, check=True, preexec_fn=limits,
                           env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"})
            stdout.seek(0)
            stderr.seek(0)
            body, diagnostic = stdout.read((1 << 20) + 1), stderr.read((64 << 10) + 1)
        # Reopening an executable may update atime. Its tracked file identity
        # and exact bytes must still match at the end of the operation.
        after = self.verify(name)
        C.need(original[:7] == after[:7] and original[8:] == after[8:]
               and len(body) <= 1 << 20 and len(diagnostic) <= 64 << 10, "Bounded immutable preparation tool required")
        return body


def patch_boot(module, tools, carrier, nonce, payload, *, size=None):
    boot_bytes = module.BOOT_BYTES if size is None else size
    offset = module.P.OFFSET
    extent = boot_bytes - offset
    with TemporaryDirectory(prefix="qtgui-boot-", dir=carrier.parent) as folder:
        work = Path(folder)
        partition = work / "root.ext4"
        module.P.clone(carrier, partition, start=offset, count=extent)
        edits = [f"mkdir {module.PAYLOAD}", f"set_inode_field {module.PAYLOAD} mode 040755"]
        for name, body in sorted(payload.items()):
            leaf = work / name
            K.save(leaf, body)
            target = f"{module.PAYLOAD}/{name}"
            mode = "0100555" if name == "guest-init.sh" else "0100444"
            edits.extend((f"write {leaf} {target}", f"set_inode_field {target} mode {mode}"))
        commands = work / "patch.debugfs"
        K.save(commands, ("\n".join(edits) + "\n").encode())
        tools.run("debugfs", ["-w", "-f", commands, partition], work)
        tools.run("e2fsck", ["-fn", partition], work)
        for name, body in payload.items():
            target = module.PAYLOAD + "/" + name
            actual = tools.run("debugfs", ["-R", "cat " + target, partition], work)
            row = tools.run("debugfs", ["-R", "stat " + target, partition], work)
            mode = b"0555" if name == "guest-init.sh" else b"0444"
            C.need(actual == body and re.search(rb"Type:\s+regular\s+Mode:\s+" + mode + rb"\b", row),
                   "Exact new boot payload bytes and modes required")
        module.P.clone(partition, carrier, count=extent, destination=offset, existing=True)
    with carrier.open("r+b") as stream:
        mbr = stream.read(512)
        C.need(mbr[510:] == b"\x55\xaa" and mbr[450] == 0x83 and mbr[462:510] == bytes(48)
               and struct.unpack_from("<II", mbr, 454) == (offset // 512, extent // 512),
               "Exact original single-partition boot geometry required")
        C.need(mbr[440:444] != struct.pack("<I", int(nonce[:8], 16)), "Fresh distinct boot identity required")
        stream.seek(440)
        stream.write(struct.pack("<I", int(nonce[:8], 16)))


def make_result(module, tools, path, size, nonce):
    with path.open("xb") as stream:
        stream.truncate(size)
    uuid = module.P.result_uuid(nonce)
    tools.run("mke2fs", ["-q", "-F", "-t", "ext4", "-b", "4096", "-L", "QT16K_GUI", "-U", uuid,
                         "-O", "^orphan_file", "-E", "lazy_itable_init=0,lazy_journal_init=0", path], path.parent)
    tools.run("e2fsck", ["-fn", path], path.parent)
    C.need(module.result_uuid(path, size) == uuid, "Fresh result template UUID required")


def descriptor(path, digest):
    body, pin = C.external(path, 32 << 10, digest)
    value = C.json_body(body, canonical=True)
    C.need(set(value) == {"kind", "continuation", "runner", "prepare_tools"}
           and value["kind"] == "QTGUI_LINK_CAPSULE_DESCRIPTOR_V1",
           "Exact passive QtGui capsule descriptor required")
    result = {"descriptor": dict(path=str(path), **pin)}
    for name in ("continuation", "runner"):
        selected, sha = K.reference(value[name])
        _, ref = C.external(selected, 128 << 10, sha)
        result[name] = dict(path=str(selected), **ref)
    return value, result


def select_runner(module, runner_ref, core_handoff, core_plan):
    raw, _ = C.read(Path(runner_ref["path"]), 128 << 10, module.pin_ref(runner_ref))
    runner = module.runner_shape(C.json_body(raw, canonical=True))
    profile = core_plan["actor"]["profile"]
    C.need(runner["actor_image"] == profile["actor_image"] == core_handoff["actor_image"]
           and runner["tools"] == profile["tools"] and runner["docker"] == core_handoff["docker"],
           "Explicit reviewed runner tools, site endpoint and retired Core selection must agree")
    module.check_pinned_file(Path(runner["docker"]["path"]), module.pin_ref(runner["docker"]))
    return runner


def seal(module, packet, refs, closures, backing, guest, inputs, runner):
    nonce = backing["nonce"]
    plan, _ = module.canonical_plan(nonce, inputs, guest, backing, runner)
    plan_raw = C.wire(plan)
    plan_pin = C.pin(plan_raw)
    K.save(packet / module.PLAN_LEAF, plan_raw)
    source = {name: C.read(packet / "source" / name, 2 << 20, collect=False)[1] | {"mode": 0o444}
              for name in sorted(module.SOURCE_FILES)}
    handoff = dict(kind="QTGUI_LINK_CAPSULE_HANDOFF_UNISSUED_V1", authority=None, scope=module.SCOPE,
                   actor_image=module.IMAGE, docker=runner["docker"], runner=runner, plan=plan_pin,
                   source=source, source_tree_sha256=C.pin(C.wire(source))["sha256"],
                   prior_closures=closures, input_refs=refs)
    raw = C.wire(handoff)
    pin = C.pin(raw)
    K.save(packet / module.HANDOFF_LEAF, raw)
    handoff = module.load_handoff(packet / module.HANDOFF_LEAF, pin["sha256"])
    plan = module.load_plan(packet / module.PLAN_LEAF, plan_pin["sha256"])
    K.save(packet / "binding.UNISSUED.json", C.wire(module.binding(handoff, plan, pin["sha256"])))
    return handoff, pin, plan


def prepare(path, digest, output):
    spec, refs = descriptor(path, digest)
    closed = refs["continuation"]
    chosen, old, overlay, scratch, core, backing, guest, actual = K.reviewed_backing(
        Path(closed["path"]), closed["sha256"])
    C.need(output.is_absolute() and output == output.resolve() and re.fullmatch(r"/[A-Za-z0-9_./-]+", str(output))
           and not os.path.lexists(output) and not output.is_relative_to(old)
           and output.parent.is_dir() and not output.parent.stat().st_mode & 0o022,
           "Fresh private output disjoint from the original Core capsule required")
    handoff_path, handoff_sha = K.reference(chosen["core"]["handoff"])
    core_handoff = C.json_body(C.external(handoff_path, 64 << 10, handoff_sha)[0], canonical=True)
    core_plan = C.json_body(C.read(old / "PLAN.UNISSUED.json", 64 << 10, core_handoff["plan"])[0], canonical=True)
    post_path, post_sha = K.reference(chosen["core"]["post_scope"])
    closures = core_handoff["prior_closures"] | {
        "core": dict(path=str(post_path), **C.external(post_path, 128 << 10, post_sha)[1])}
    C.need(actual["post_scope"]["closure"]["sha256"] == post_sha
           and backing["nonce"][:8] != core_plan["nonce"][:8], "Exact retired Core and fresh boot nonce required")
    with TemporaryDirectory(prefix="qtgui-prep-", dir=output.parent) as temporary:
        packet = Path(temporary) / "capsule"
        packet.mkdir(mode=0o700)
        source, inputs, templates, accepted = (packet / name for name in ("source", "inputs", "templates", "accepted-core"))
        for folder in (source, inputs, templates, accepted):
            folder.mkdir(mode=0o700)
        module = stage_source(source)
        runner = select_runner(module, refs["runner"], core_handoff, core_plan)
        tools = Formatting(module, spec["prepare_tools"])
        pins = {**backing["inputs"], "Image": core_plan["inputs"]["Image"], "boot.raw": core_plan["inputs"]["boot.raw"]}
        C.need(pins["Image"] == module.CORE_KERNEL and pins["boot.raw"]["bytes"] == module.BOOT_BYTES,
               "Exact already verified Core boot carrier and kernel required")
        originals = {name: old / "inputs" / name for name in ("Image", "boot.raw")} | {
            "core.qcow2": overlay, "scratch.raw": scratch}
        identities = {name: C.identity(value.lstat()) for name, value in originals.items()}
        for name, original in originals.items():
            K.clone(original, inputs / name, pins[name])
        K.inspect_overlay(inputs / "core.qcow2", pins["core.qcow2"], K.RAW_BACKING, "raw")
        provisional, payload = module.canonical_plan(backing["nonce"], pins, guest, backing, runner)
        C.need(module.capacity(packet, provisional)["free_bytes"] >= provisional["actor"]["admission_disk_bytes"],
               "Staging filesystem is below selected QtGui disk and reserve")
        boot = inputs / "boot.raw"
        boot.chmod(0o600)
        patch_boot(module, tools, boot, backing["nonce"], payload)
        boot.chmod(0o444)
        pins["boot.raw"] = C.read(boot, module.BOOT_BYTES, collect=False)[1]
        result = templates / "result.raw"
        size = backing["limits"]["result_disk_bytes"]
        make_result(module, tools, result, size, backing["nonce"])
        result.chmod(0o444)
        pins["result.raw"] = C.read(result, size, collect=False)[1]
        K.save(accepted / K.CORE_ELF, core)
        K.save(packet / "GUI-GUEST-PLAN.json", guest)
        for folder in (inputs, templates, accepted):
            folder.chmod(0o555)
        handoff, handoff_pin, plan = seal(module, packet, refs, closures, backing, guest, pins, runner)
        measured = module.preflight_root(packet, handoff, plan)
        C.need(all(C.identity(value.lstat()) == identities[name] for name, value in originals.items()),
               "Original closed Core backing or boot data changed")
        report = dict(status="PREPARED_UNISSUED" if measured["fits"] else "PREPARED_HOLD_LIVE_CAPACITY",
                      root=str(output), actor_started=False, qemu_started=False, issued=False, authority=None,
                      claim_present=False, handoff=handoff_pin, plan=handoff["plan"], nonce=plan["nonce"],
                      source_tree_sha256=handoff["source_tree_sha256"], core_readback=backing["core_readback"],
                      original_carriers_unchanged=True, capacity=measured)
        K.save(packet / "PREPARATION.DATA.json", C.wire(report))
        packet.rename(output)
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--descriptor", type=Path, required=True)
    parser.add_argument("--descriptor-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        sys.stdout.buffer.write(C.wire(prepare(args.descriptor, args.descriptor_sha256, args.output)))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        sys.exit("QtGui preparation refused: " + str(error))


if __name__ == "__main__":
    main()
