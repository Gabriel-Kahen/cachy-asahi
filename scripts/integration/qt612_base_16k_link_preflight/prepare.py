# SPDX-License-Identifier: MIT
"""Materialize a private, unissued QtCore capsule without opening a VM."""

import argparse
import fcntl
import importlib.util
import os
from pathlib import Path
import re
import secrets
import stat
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
LANE = HERE.relative_to(REPO).as_posix()
PORTABLE = "scripts/integration/qt612_md4c_compile"
APP_B = "ac9ed3ceb1df938473a6a9bfe4dcd941120c923a"
ORIGINAL_CLOSURES = {
    "q3": dict(bytes=3084, sha256="f60a619b67c097cb90cbcbdd24ba35dc23c367a735c26430583685e4d1729f21"),
    "r4": dict(bytes=3598, sha256="c930b0cd60456d7f7e756829f71a72c8b7bad7faa3ab5664bb4f60c4c541f9b3"),
}


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def stage_source(root):
    app_b = {PORTABLE + "/" + leaf for leaf in ("actor.py", "common.py", "prepare.py", "guest.sh")}
    local = {
        LANE + "/" + leaf for leaf in ("actor.py", "capsule.py", "guest.sh", "preflight.py", "readback.py", "site.py")
    } | {
        "scripts/install/overlay583_trial/controller.py",
        "scripts/install/overlay583_trial/trial.py",
        "scripts/integration/arm16k_perl5423_vm/contracts.py",
        "scripts/integration/arm16k_perl5423_vm/runtime.py",
        "scripts/integration/arm16k_perl5423_vm/helper-origin.json",
        "scripts/integration/arm16k_perl5423_vm/frozen/owned_process.py",
        "scripts/integration/arm16k_perl5423_vm/frozen/independent_readback.py",
        "packages/port/qt612-gui-server-source-reference/check_stage.py",
    }
    for relative in sorted(local | app_b):
        if relative in app_b:
            raw = subprocess.check_output(["/usr/bin/git", "--no-replace-objects", "show", APP_B + ":" + relative],
                                          cwd=REPO, timeout=15)
        else:
            original = REPO / relative
            need(original.resolve() == original and original.is_file(), "Canonical source leaf required")
            raw = original.read_bytes()
        need(0 < len(raw) <= 2 << 20, "Bounded complete source leaf required")
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with path.open("xb") as stream:
            stream.write(raw)
        path.chmod(0o444)
    for folder in sorted((p for p in root.rglob("*") if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
        folder.chmod(0o555)
    root.chmod(0o555)
    path = root / LANE / "capsule.py"
    spec = importlib.util.spec_from_file_location("qtcore_preparer_contract", path)
    capsule = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(capsule)
    need(capsule.SOURCE_FILES == local | app_b and capsule.PORTABLE_COMMIT == APP_B
         and all(capsule.P.sha((root / name).read_bytes()) == digest
                 for name, digest in capsule.PORTABLE_HASHES.items()), "Exact merged importer runtime leaves required")
    return capsule


def reflink_original(C, original, destination, expected):
    with C.F.open_original(original) as src, destination.open("xb") as dst:
        before = C.F.verify_original(src, original, expected["bytes"])
        need(os.fstat(dst.fileno()).st_dev == before[0], "Same-filesystem source reflink required")
        fcntl.ioctl(dst, 0x40049409, src.fileno())
        need(C.F.identity(os.fstat(src.fileno())) == before == C.F.identity(original.lstat()),
             "Original input metadata changed through reflink")
    C.check_pinned_file(destination, expected)
    return before


def patch_boot(C, inputs, nonce):
    p = C.P
    disk = inputs / "boot.raw"
    extent = C.ORIGINALS["boot.raw"]["bytes"] - p.OFFSET
    with TemporaryDirectory(prefix="qtcore-boot-", dir=inputs) as where:
        directory = Path(where)
        root = directory / "boot.ext4"
        p.clone(disk, root, start=p.OFFSET, count=extent)
        payload = C.guest_files()
        edits = [f"mkdir {C.PAYLOAD}", f"set_inode_field {C.PAYLOAD} mode 040755"]
        for name, raw in payload.items():
            local = directory / name
            p.new(local, raw)
            target = C.PAYLOAD + "/" + name
            mode = "0100555" if name == "guest.sh" else "0100444"
            edits += [f"write {local} {target}", f"set_inode_field {target} mode {mode}"]
        command_file = directory / "changes.debugfs"
        p.new(command_file, ("\n".join(edits) + "\n").encode())
        p.tool("debugfs", ["-w", "-f", command_file, root])
        p.tool("e2fsck", ["-fn", root], seconds=120)
        for name, raw in payload.items():
            target = C.PAYLOAD + "/" + name
            need(p.tool("debugfs", ["-R", "cat " + target, root]) == raw, "Fresh boot guest bytes differ")
            metadata = p.tool("debugfs", ["-R", "stat " + target, root])
            mode = b"0555" if name == "guest.sh" else b"0444"
            need(re.search(rb"Type:\s+regular\s+Mode:\s+" + mode + rb"\b", metadata), "Fresh boot guest mode differs")
        p.clone(root, disk, count=extent, destination=p.OFFSET, existing=True)
    with disk.open("r+b") as stream:
        mbr = stream.read(512)
        need(mbr[510:] == b"\x55\xaa" and mbr[450] == 0x83 and mbr[462:510] == bytes(48)
             and struct.unpack_from("<II", mbr, 454) == (p.OFFSET // 512, extent // 512),
             "Exact original partition geometry required")
        stream.seek(440)
        stream.write(struct.pack("<I", int(nonce[:8], 16)))


def create_result(C, template, nonce):
    with template.open("xb") as stream:
        stream.truncate(C.RESULT_BYTES)
    C.P.tool("mke2fs", ["-q", "-F", "-t", "ext4", "-b", "4096", "-L", C.RESULT_LABEL, "-U", C.P.result_uuid(nonce),
                        "-O", "^orphan_file", "-E", "lazy_itable_init=0,lazy_journal_init=0", template])
    C.P.tool("e2fsck", ["-fn", template], seconds=120)
    need(C.result_uuid(template) == C.P.result_uuid(nonce), "Exact fresh empty result UUID required")


def seal(C, packet, closures, nonce, docker):
    t, p = C.T, C.P
    source = packet / "source"
    files = {leaf: t.read(source / leaf, cap=2 << 20, collect=False) | {"mode": 0o444}
             for leaf in sorted(C.SOURCE_FILES)}
    carriers = {name: t.read(packet / "inputs" / name, cap=expected["bytes"], collect=False)
                for name, expected in C.ORIGINALS.items()}
    carriers["result.raw"] = t.read(packet / "templates/result.raw", cap=C.RESULT_BYTES, collect=False)
    body = t.encoded(C.plan_data(nonce, carriers))
    p.new(packet / C.PLAN_LEAF, body)
    plan = C.load_plan(packet / C.PLAN_LEAF, p.sha(body))
    handoff = dict(kind=C.HANDOFF_KIND, authority=None, scope=C.SCOPE, actor_image=C.IMAGE,
                   plan=t.pin(body), source=files, source_tree_sha256=p.sha(t.encoded(files)),
                   prior_closures=closures, docker=docker, portable_commit=C.PORTABLE_COMMIT)
    raw = t.encoded(handoff)
    p.new(packet / C.HANDOFF_LEAF, raw)
    handoff = C.load_handoff(packet / C.HANDOFF_LEAF, p.sha(raw))
    p.new(packet / "binding.UNISSUED.json", t.encoded(C.binding(handoff, plan, p.sha(raw))))
    return plan, handoff, t.pin(raw)


def prepare(output, q3, r4, docker_client, docker_socket, docker_client_bytes, docker_client_sha256):
    need(output.is_absolute() and output == output.resolve() and re.fullmatch(r"/[A-Za-z0-9_./-]+", str(output))
         and not output.exists() and not output.is_symlink() and output.parent.is_dir()
         and not output.parent.stat().st_mode & 0o022, "Fresh output under a private ordinary parent required")
    closures = {name: dict(path=str(path), **ORIGINAL_CLOSURES[name]) for name, path in (("q3", q3), ("r4", r4))}
    with TemporaryDirectory(prefix="qtcore-prepare-", dir=output.parent) as tmp:
        packet = Path(tmp) / "packet"
        packet.mkdir(mode=0o700)
        source, inputs, templates = (packet / name for name in ("source", "inputs", "templates"))
        for folder in (source, inputs, templates):
            folder.mkdir(mode=0o700)
        C = stage_source(source)
        docker = C.seal_docker(docker_client, docker_socket, docker_client_bytes, docker_client_sha256)
        attempt = C.validate_prior(closures)
        need(not any(output.is_relative_to(path) for path in (attempt.parent, q3.parent, r4.parent)),
             "Capsule must be disjoint from the original Q3 and R4 data")
        original_root = attempt / "output/qtbase16k"
        closure = C.T.decode(C.read_original(q3, C.Q3_TERMINAL))
        qemu = C.T.decode(C.read_original(original_root / "qemu.json", closure["original_qemu"]))
        previous = C.P.validate_predecessor_argv(qemu["argv"])
        nonce = secrets.token_hex(16)
        need(nonce[:8] != previous[:8], "Fresh boot identity required")
        before = {name: reflink_original(C, original_root / name, inputs / name, pin)
                  for name, pin in C.ORIGINALS.items()}
        C.P.tool("e2fsck", ["-fn", inputs / "scratch.raw"], seconds=150)
        need(C.P.ext4_uuid(inputs / "scratch.raw", "QT16K_WORK") == C.F.SCRATCH_UUID,
             "Exact original scratch storage identity required")
        patch_boot(C, inputs, nonce)
        create_result(C, templates / "result.raw", nonce)
        for folder in (inputs, templates):
            for path in folder.iterdir():
                path.chmod(0o444)
            folder.chmod(0o555)
        plan, handoff, handoff_pin = seal(C, packet, closures, nonce, docker)
        measured = C.preflight_root(packet, handoff, plan)
        need(all(C.F.identity((original_root / name).lstat()) == identity for name, identity in before.items()),
             "Original Q3 files changed during the capsule assembly")
        report = dict(status="PREPARED_UNISSUED" if measured["fits"] else "PREPARED_HOLD_LIVE_CAPACITY",
                      root=str(output), authority=None, actor_started=False, qemu_started=False,
                      plan=handoff["plan"], handoff=handoff_pin, source_tree_sha256=handoff["source_tree_sha256"],
                      docker_binding=C.T.pin(C.T.encoded(docker)),
                      predecessor_files_unchanged=True, nonce=nonce, capacity=measured)
        C.P.new(packet / "PREPARATION.DATA.json", C.T.encoded(report))
        packet.rename(output)
        return C.T.encoded(report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("output", "q3-terminal", "r4-terminal", "docker-client", "docker-socket"):
        parser.add_argument("--" + arg, type=Path, required=True)
    parser.add_argument("--docker-client-bytes", type=int, required=True)
    parser.add_argument("--docker-client-sha256", required=True)
    args = parser.parse_args()
    try:
        os.umask(0o077)
        sys.stdout.buffer.write(prepare(args.output, args.q3_terminal, args.r4_terminal, args.docker_client,
                                        args.docker_socket, args.docker_client_bytes, args.docker_client_sha256))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        sys.exit("QtCore preparation refused: " + str(error))


if __name__ == "__main__":
    main()
