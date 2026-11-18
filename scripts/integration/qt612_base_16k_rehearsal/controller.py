# SPDX-License-Identifier: MIT
"""Bind data or execute the separately Root-issued offline Qtbase guest."""
import argparse
from itertools import islice
import os
from pathlib import Path
import re
import shutil
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from support import O, T, checked, load, pair, put_json, put_text

ENTRY = "qtbase16k-init"
ROOT_MOUNTS = ("qtmedia", "qtwork", "qtexport")
ACTOR_PATHS = {"media": Path("/qt-input"), "kernel": Path("/qt-kernel"),
               "config": Path("/qt-kconfig"), "baseline": Path("/qt-boot")}
OUTPUT = Path("/out/qtbase16k")
KIND = "ROOT_QTBASE_OFFLINE_16K_CONFIGURE_SELECTION_V1"
GUEST_SECONDS = 4800
BOOTSTRAP_SECONDS = 750
DISK_GATE = 24 << 30
TOOL_PROFILE_KIND = "QTBASE_16K_QEMU_TOOL_PROFILE_V1"
LEAF = re.compile(r"[A-Za-z0-9._+@:-]+(?:/[A-Za-z0-9._+@:-]+)*")
EVIDENCE = re.compile(r"result\.json|rootfs-gpgv\.log|(alpm|configure|md4c)-[A-Za-z0-9._-]+")


def selected_tools(tools):
    T.need(type(tools) is dict and set(tools) == set(O.TOOL_PATHS),
           "Exact five-tool QEMU profile required")
    for row in tools.values():
        T.need(type(row) is dict and set(row) == {"bytes", "sha256"}
               and pair(row) == row and 0 < row["bytes"] <= 64 << 20,
               "Every QEMU tool requires a complete bounded pin")
    for name, (size, digest) in O.PROVEN_TOOLS.items():
        T.need(tools[name] == dict(bytes=size, sha256=digest), "Shared Overlay QEMU tool pin differs: " + name)
    return tools


def load_tool_profile(path, digest):
    raw = T.read(path, cap=16 << 10)
    profile = T.decode(raw)
    T.need(T.pin(raw)["sha256"] == digest and raw == T.encoded(profile)
           and type(profile) is dict and set(profile) == {"kind", "actor_image", "tools"}
           and profile["kind"] == TOOL_PROFILE_KIND and profile["actor_image"] == O.ACTOR_IMAGE,
           "Exact independently pinned tool profile for the shared actor image required")
    return selected_tools(profile["tools"])


def media_plan(media):
    path = media / "plan.json"
    raw = T.read(path, cap=128 << 10)
    plan = T.decode(raw)
    T.need(raw == T.encoded(plan) and set(plan) ==
           {"kind", "Qt_source_map", "files", "signer", "Root_authority"} and
           plan["kind"] == "QTBASE_16K_OFFLINE_OPERANDS_V1" and plan["Root_authority"] is None,
           "Canonical unissued offline media plan")
    files = plan["files"]
    T.need(type(files) is dict and 530 < len(files) < 600 and
           all(LEAF.fullmatch(name) and not {".", ".."} & set(name.split("/")) for name in files),
           "Literal bounded media namespace")
    for ref in files.values():
        T.need(pair(ref) == ref, "Exact finite media file pin")
    T.need(sum(row["bytes"] for row in files.values()) < 1850 << 20, "Offline media byte budget")
    paths = list(islice(media.rglob("*"), 651))
    T.need(len(paths) <= 650 and not any(p.is_symlink() for p in paths) and
           {str(p.relative_to(media)) for p in paths if not p.is_dir()} == set(files) | {"plan.json"},
           "Exact ordinary offline media leaves")
    for name, ref in files.items():
        checked(media / name, ref, collect=False)
    return plan, T.pin(raw)


def bind(paths, nonce, tools):
    selected_tools(tools)
    T.need(set(paths) == set(ACTOR_PATHS), "Exact offline rehearsal media roles required")
    T.need(re.fullmatch("[0-9a-f]{32}", nonce), "Explicit fresh operation nonce")
    for key, ref in O.REFERENCES.items():
        O.pinned(paths[key], ref)
    config = T.read(paths["config"], cap=128 << 10)
    T.need(b"CONFIG_ARM64_16K_PAGES=y\n" in config, "Exact 16 KiB boot kernel configuration")
    plan, plan_pin = media_plan(paths["media"])
    signer = plan["signer"]
    T.need(signer["test_only"] is True and type(signer["expires"]) is int and
           type(signer["created"]) is int and signer["created"] <= int(time.time()) and
           signer["expires"] > int(time.time()) + GUEST_SECONDS + BOOTSTRAP_SECONDS,
           "Current scoped TEST signer must cover the complete rehearsal budget")
    sources = O.source_pins()
    for name in ("controller.py", "support.py", "guest-init.sh", "alpm.sh", "configure.sh"):
        path = HERE / name
        sources[str(path.relative_to(O.REPO))] = T.read(path, cap=128 << 10, collect=False)
    for name in ("alpm.sh", "configure.sh"):
        T.need(plan["files"][name] == sources[str((HERE / name).relative_to(O.REPO))],
               "Staged guest worker differs from reviewed code")
    return dict(kind=KIND, issuer=None, approved=None, created_utc=None, expires_utc=None,
                nonce=nonce, actor_image=O.ACTOR_IMAGE, output=str(OUTPUT),
                media_plan=plan_pin, sources=sources, tools=tools,
                references={key: dict(bytes=row[0], sha256=row[1]) for key, row in O.REFERENCES.items()})


def verify_authority(raw, digest, paths, boundary=bind, now=None):
    T.need(T.pin(raw)["sha256"] == digest, "Exact independently supplied authority digest")
    issued = T.decode(raw)
    T.need(type(issued) is dict, "Root authority must be an object")
    created, expires = issued.get("created_utc"), issued.get("expires_utc")
    at = int(time.time()) if now is None else now
    T.need(raw == T.encoded(issued) and issued.get("issuer") == "Root" and issued.get("approved") is True and
           type(created) is int and type(expires) is int and created <= at < expires and
           expires - created <= 3600, "Fresh separately issued Root authority required")
    selected = boundary(paths, issued["nonce"], selected_tools(issued.get("tools")))
    selected.update(issuer="Root", approved=True, created_utc=created, expires_utc=expires)
    T.need(issued == selected, "Root authority and current rehearsal operands differ")
    return issued


def qemu_argv(out, nonce, partuuid, plan_sha):
    original = O.qemu_argv(out, nonce, partuuid, plan_sha, "0" * 64)
    idx = original.index("-append") + 1
    original[idx] = (f"root=PARTUUID={partuuid} rootfstype=ext4 rootflags=noload ro rootwait "
                     f"console=ttyAMA0,115200n8 init=/{ENTRY} "
                     f"cachy_qtbase_nonce={nonce} cachy_qtbase_plan={plan_sha}")
    return original


def verify_media_disk(reader, disk, plan, manifest):
    with reader.Ext4Reader(disk, max_nodes=850, max_file_bytes=1 << 30) as fs:
        nodes = fs.inventory()["nodes"]
    files = plan["files"] | {"plan.json": manifest}
    leaves = {name for name, node in nodes.items() if node["type"] != "directory"}
    T.need(leaves == set(files), "Exact readonly media disk leaves")
    for name, ref in files.items():
        node = nodes[name]
        T.need(node["type"] == "file" and node["links"] == 1 and
               dict(bytes=node["size"], sha256=node["sha256"]) == ref,
               "Packed offline input differs: " + name)


def terminal(serial, nonce):
    rows = [line for line in serial.splitlines() if line.startswith(b"QTBASE16K ")]
    T.need(len(rows) == 1 and
           re.fullmatch(rb"QTBASE16K " + nonce.encode() +
                        rb" (?:PASS 16384|HOLD [a-z-]+)", rows[0]), "Guest terminal marker absent or ambiguous")
    return rows[0].endswith(b" PASS 16384")


def export_evidence(reader, disk, output, nonce, passed, plan):
    with reader.Ext4Reader(disk, max_nodes=60, max_file_bytes=4 << 20) as fs:
        nodes = fs.inventory()["nodes"]
        files = {name for name in nodes if name not in {".", "lost+found", "evidence"}}
        if not passed and not files and "evidence" not in nodes:
            return {}
        T.need("evidence/result.json" in files and
               sum(nodes[name]["size"] for name in files) <= 32 << 20, "Complete bounded result directory")
        output.mkdir(mode=0o700)
        for name in sorted(files):
            node, leaf = nodes[name], Path(name).name
            T.need(name == "evidence/" + leaf and EVIDENCE.fullmatch(leaf) and node["type"] == "file" and
                   node["mode"] == 0o600 and node["uid"] == node["gid"] == 0 and node["links"] == 1,
                   "Ordinary allowlisted guest evidence required")
            row, raw = fs.inode(node["inode"])
            body = b"".join(fs.chunks(row, raw))
            T.need(T.pin(body) == dict(bytes=node["size"], sha256=node["sha256"]), "Guest result reread changed")
            with (output / leaf).open("xb") as stream:
                stream.write(body)
    result = T.decode(T.read(output / "result.json", cap=1024))
    T.need(result["nonce"] == nonce and result["status"] == ("PASS" if passed else "HOLD"),
           "Guest evidence and serial marker differ")
    if passed:
        T.need(result == dict(status="PASS", phase="complete", nonce=nonce, pages=16384, Qt_build="NOT_RUN"),
               "Exact configure-only result")
        for current, expected, count in (("rootfs", "rootfs.expected.lock", 165),
                                         ("349", "expected349.lock", 349), ("356", "expected356.lock", 356)):
            raw = checked(output / f"alpm-{current}.lock", plan["files"][expected])
            T.canonical_lock(raw, count)
        T.need(T.read(output / "alpm-result", cap=1024) == b"ALPM_EXACT_349_TO_356_PASS\n" and
               b"PRIVATE_ALPM_KEYRINGS_RETIRED\n" in T.read(output / "alpm-cleanup.log", cap=4 << 20),
               "Exact ALPM success and private keyring retirement required")
        configure = T.decode(T.read(output / "configure-result.json", cap=1024))
        T.need(configure == dict(status="PASS_QT612_CONFIGURE_ONLY", architecture="aarch64",
                                 page_size=16384, md4c="0.5.3-1", full_build="NOT_RUN"),
               "Exact guest configure-only readback")
        md4c = T.read(output / "md4c-cmake-selection.log", cap=4 << 20)
        T.need(b"md4c_DIR:PATH=/usr/lib/cmake/md4c\n" in md4c and
               b"QT_FEATURE_system_textmarkdownreader:INTERNAL=ON\n" in md4c,
               "Genuine system md4c CMake selection required")
    return result


class Runner(O.Controller):
    def __init__(self, authority, authority_sha256):
        self.authority = authority
        self.authority_sha256 = authority_sha256
        self.out = OUTPUT
        self.runtime = O.module(O.PERL / "runtime.py")
        self.reader = O.module(O.PERL / "frozen/independent_readback.py")

    def check_result_disk(self, path):
        self.command("fsck-result-readback", "e2fsck", ["-fn", path], 60, time.monotonic() + 70)

    def run(self):
        nonce = self.authority["nonce"]
        self.require_absent_twice(nonce)
        T.need(not self.out.exists() and shutil.disk_usage(self.out.parent).free >= DISK_GATE,
               "Fresh output and 24 GiB free on the owned output filesystem required")
        self.out.mkdir(mode=0o700)
        deadline = time.monotonic() + BOOTSTRAP_SECONDS
        out, paths = self.out, ACTOR_PATHS
        O.checked_copy(paths["kernel"], out / "Image", self.authority["references"]["kernel"])
        clone = out / "reference.raw"
        self.command("clone-reference", "cp", ["--sparse=always", "--reflink=never", paths["baseline"], clone], 180, deadline)
        O.pinned(clone, O.REFERENCES["baseline"])
        edits, init = out / "qtbase.debugfs", HERE / "guest-init.sh"
        put_text(edits, "".join(f"mkdir /{name}\n" for name in ROOT_MOUNTS) +
                 f"write {init} /{ENTRY}\nset_inode_field /{ENTRY} mode 0100755\n"
                 f"set_inode_field /{ENTRY} uid 0\nset_inode_field /{ENTRY} gid 0\n")
        self.command("patch-boot", "debugfs", ["-w", "-f", edits, clone], 90, deadline)
        self.command("fsck-boot", "e2fsck", ["-fn", clone], 120, deadline)
        dumped = out / "init.readback"
        self.command("read-boot-init", "debugfs", ["-R", f"dump /{ENTRY} {dumped}", clone], 30, deadline)
        checked(dumped, self.authority["sources"][str(init.relative_to(O.REPO))], collect=False)
        partuuid = O.partition_boot(clone, out / "boot.raw", nonce)
        clone.unlink()

        plan, manifest = media_plan(paths["media"])
        T.need(manifest == self.authority["media_plan"], "Reviewed media plan changed")
        media = self.filesystem("inputs", "QT16K_INPUT", O.INPUT_SIZE, nonce, deadline, paths["media"])
        verify_media_disk(self.reader, media, plan, manifest)
        media.chmod(0o444)
        self.filesystem("scratch", "QT16K_WORK", O.WORK_SIZE, nonce, deadline)
        result = self.filesystem("result", "QT16K_RESULT", O.RESULT_SIZE, nonce, deadline)
        pins = {name: T.read(out / name, cap=O.INPUT_SIZE, collect=False)
                for name in ("Image", "boot.raw", "inputs.raw")}
        command = qemu_argv(out, nonce, partuuid, manifest["sha256"])
        self.runtime.command(command, out, "qemu", seconds=GUEST_SECONDS,
                             deadline=time.monotonic() + GUEST_SECONDS,
                             watched_tree=(out, DISK_GATE, O.RESERVE))
        retirement = self.runtime.receipt(out / "qemu.json")
        T.need(self.runtime.natural(retirement) and retirement["argv"] == command,
               "Natural owned QEMU retirement required")
        self.require_absent_twice(nonce)
        for name, ref in pins.items():
            checked(out / name, ref, collect=False)
        O.pinned(paths["baseline"], O.REFERENCES["baseline"])
        self.check_result_disk(result)
        passed = terminal(T.read(out / "qemu.stdout", cap=1 << 20), nonce)
        evidence = out / "evidence"
        observed = export_evidence(self.reader, result, evidence, nonce, passed, plan)
        files = {path.name: T.read(path, cap=4 << 20, collect=False)
                 for path in sorted(evidence.iterdir())} if evidence.is_dir() else {}
        put_json(out / "result.json", dict(status="GUEST_CONFIGURE_PASS_FOR_ROOT_REVIEW" if passed else "HOLD",
                                          observation=observed, authority_sha256=self.authority_sha256,
                                          result_disk=T.read(result, cap=O.RESULT_SIZE, collect=False),
                                          qemu_retirement=T.read(out / "qemu.json", cap=128 << 10, collect=False),
                                          serial=T.read(out / "qemu.stdout", cap=1 << 20, collect=False),
                                          files=files, native_Qt_build="NOT_RUN", M2="NOT_RUN", Root_acceptance=None))
        return 0 if passed else 2


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="operation", required=True)
    passive = sub.add_parser("bind")
    for name in ACTOR_PATHS:
        passive.add_argument("--" + name, type=O.absolute, required=True)
    passive.add_argument("--nonce", required=True)
    passive.add_argument("--tool-profile", type=O.absolute, required=True)
    passive.add_argument("--tool-profile-sha256", required=True)
    run = sub.add_parser("run")
    run.add_argument("--authority", type=O.absolute, required=True)
    run.add_argument("--authority-sha256", required=True)
    args = p.parse_args()
    if args.operation == "bind":
        sys.addaudithook(O.passive_fence)
        tools = load_tool_profile(args.tool_profile, args.tool_profile_sha256)
        value = bind({name: getattr(args, name) for name in ACTOR_PATHS}, args.nonce, tools)
        sys.stdout.buffer.write(T.encoded(value))
        return 0
    T.need(os.environ.get("CACHY_ASAHI_QTBASE16K_ACTOR") == "1" and
           sys.flags.isolated and sys.dont_write_bytecode and __debug__, "Explicit isolated Qtbase actor")
    O.actor_boundary(ACTOR_PATHS | {"output": OUTPUT, "authority": args.authority})
    raw = T.read(args.authority, cap=128 << 10)
    issued = verify_authority(raw, args.authority_sha256, ACTOR_PATHS)
    T.need(O.tool_pins() == issued["tools"], "Exact retained QEMU tools required")
    return Runner(issued, args.authority_sha256).run()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from None
