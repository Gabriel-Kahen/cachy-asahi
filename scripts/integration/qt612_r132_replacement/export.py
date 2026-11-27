# SPDX-License-Identifier: MIT
"""Export the Qt actor's exact evidence from a selected, already stopped result disk.

The caller owns disk selection and retirement. The collector copies the root
directory qt-replacement-evidence/ into a fresh readback bundle. A sibling
evidence/ directory belongs to Asahi629 and is handled by its own exporter.
Missing actor files, including a missing directory, are reported for held runs.
The runtime reports and Weston trace are copied verbatim, including HOLD data.
Supply expected_nonce from the stopped observation for guest identity checks.

Pass original body paths by role and reviewed TEST operands as
{filename: (absolute_path, pin)} to include them in the bundle. The returned
pins are observations for the outer controller. When provided, the reviewed
certificate must byte-match the guest's exported certificate. The controller
supplies the selected boot nonce, verified TEST review and retirement evidence,
then publishes its separately selected receipt.
"""

from contextlib import contextmanager
import ctypes
import json
import os
from pathlib import Path
from runpy import run_path
import secrets
import shutil
import stat


R = run_path(str(Path(__file__).with_name("readback.py")))
C, need = R["C"], R["need"]
RESULT_BYTES = 64 << 20
MAX_NODE_BYTES = 14 << 20
ACTOR_DIR = "qt-replacement-evidence"
TEST_SIGNATURE = "test-signature.sig"
TEST_FILES = {"test-certificate.gpg", TEST_SIGNATURE}
ACTOR_FILES = {name: cap for name, cap in R["EVIDENCE"].items() if name != TEST_SIGNATURE}
DIRECTORY_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC
NONCE_REPORTS = ("runtime-probes.json", "vendor-runtime-probes.json", "weston-lifecycle.json")


def require_guest_nonce(nonce, owner, bodies):
    """Compare every available guest nonce with the selected stopped observation."""
    need(type(nonce) is str and R["NONCE"].fullmatch(nonce), "Exact stopped observation nonce required")
    observed = {}
    if owner is not None:
        observed["Asahi result"] = owner.get("nonce")
        checkpoint = owner.get("qt_checkpoint")
        if checkpoint is not None:
            need(type(checkpoint) is dict, "Expected structured Qt checkpoint evidence")
            observed["Qt checkpoint"] = checkpoint.get("nonce")
    reports = {name: bodies.get(name, b"") for name in NONCE_REPORTS}
    reports["transaction.jsonl"] = bodies.get("transaction.jsonl", b"").partition(b"\n")[0]
    for name, raw in reports.items():
        if not raw:
            continue
        try:
            row = C.json_body(raw)
        except json.JSONDecodeError:
            # An interrupted writer may leave an incomplete record on a held disk.
            continue
        if name == "transaction.jsonl":
            need(row.get("phase") == "entry" and row.get("kind") == R["JOURNAL_KIND"],
                 "Expected the first Qt journal record to be the actor entry")
        observed[name] = row.get("nonce")
    for role, actual in observed.items():
        need(actual == nonce, f"Stopped guest evidence nonce differs from the outer observation: {role}")


def member_body(disk, node, cap, scope, name):
    need(node["type"] == "file" and node["uid"] == node["gid"] == 0 and node["mode"] == 0o600
         and node["links"] == 1 and not node["xattrs"] and 0 <= node["size"] <= cap,
         f"Unexpected {scope} file identity or size: {name}")
    fields, raw = disk.inode(node["inode"])
    expected = C.file_pin(node["size"], node["sha256"])
    need(fields | {"sha256": node["sha256"]} == node, f"{scope} inode changed: {name}")
    body = b"".join(disk.chunks(fields, raw))
    need(C.pin(body) == expected, f"{scope} body changed: {name}")
    return body


def actor_bodies(disk_path, disk_pin, *, expected_nonce=None):
    need(C.check_pin(disk_pin, RESULT_BYTES) and disk_pin["bytes"] == RESULT_BYTES,
         "Exact stopped result-disk pin required")
    before = C.identity(disk_path.lstat())
    C.read(disk_path, RESULT_BYTES, disk_pin, collect=False)
    bodies = {}
    with C.ext4_reader()(disk_path, max_nodes=64, max_file_bytes=MAX_NODE_BYTES) as disk:
        need(C.identity(os.fstat(disk.fd)) == before, "Stopped result disk changed before inventory")
        nodes = disk.inventory()["nodes"]
        need({".", "lost+found"} <= nodes.keys()
             and all(nodes[name]["type"] == "directory" for name in (".", "lost+found")),
             "Result disk root directories differ")
        if "evidence" in nodes:
            need(nodes["evidence"]["type"] == "directory", "Expected a distinct Asahi629 evidence directory")
        present = ACTOR_DIR in nodes
        if present:
            actor = nodes[ACTOR_DIR]
            need(actor["type"] == "directory" and actor["uid"] == actor["gid"] == 0
                 and actor["mode"] == 0o700 and not actor["xattrs"], "Unexpected Qt actor directory identity")
        for name, node in nodes.items():
            if name in {".", "lost+found", "evidence", ACTOR_DIR} or name.startswith("evidence/"):
                continue
            prefix, _, leaf = name.partition("/")
            need(present and prefix == ACTOR_DIR and leaf in ACTOR_FILES, f"Unexpected result member: {name}")
            bodies[leaf] = member_body(disk, node, ACTOR_FILES[leaf], "Qt actor", leaf)
        if expected_nonce is not None:
            owner = nodes.get("evidence/result.json")
            if owner is not None:
                owner = C.json_body(member_body(disk, owner, 128 << 10, "Asahi result", "result.json"), canonical=True)
            require_guest_nonce(expected_nonce, owner, bodies)
        need(C.identity(os.fstat(disk.fd)) == before, "Stopped result disk changed while collecting")
    need(C.identity(disk_path.lstat()) == before, "Stopped result disk pathname changed")
    return present, bodies


def reviewed_bodies(originals, test_inputs, *, profile=None):
    original_bodies, test_bodies = {}, {}
    expected = R["originals"](profile)
    if originals is not None:
        need(originals.keys() == expected.keys(), "Exact original input roles required")
        original_bodies = {role: C.read(originals[role], pin["bytes"], pin)[0] for role, pin in expected.items()}
    if test_inputs is not None:
        need(test_inputs.keys() == TEST_FILES, "Exact pair of reviewed TEST operands required")
        for name, (path, pin) in test_inputs.items():
            cap = R["EVIDENCE"][name]
            need(C.check_pin(pin, cap) and pin["bytes"] > 0, f"Expected reviewed TEST operand pin: {name}")
            if profile is not None:
                role = "signature" if name == TEST_SIGNATURE else "certificate"
                need(pin == profile["test_review"][role], f"TEST operand differs from the parity profile: {name}")
            test_bodies[name] = C.read(path, cap, pin)[0]
    return original_bodies, test_bodies


@contextmanager
def directory(path, *, parent=None):
    fd = os.open(path, DIRECTORY_FLAGS, dir_fd=parent)
    try:
        yield fd
    finally:
        os.close(fd)


def write_bodies(parent, bodies):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    for name, body in bodies.items():
        with os.fdopen(os.open(name, flags, 0o600, dir_fd=parent), "wb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
    os.fsync(parent)


def publish(parent, source, target, *, source_parent=None):
    rename = ctypes.CDLL(None, use_errno=True).renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    source_parent = parent if source_parent is None else source_parent
    if rename(source_parent, os.fsencode(source), parent, os.fsencode(target), 1) != 0:  # RENAME_NOREPLACE
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), target)


@contextmanager
def output_parent(bundle):
    parent_path = bundle.parent
    need(bundle.is_absolute() and bundle.name not in ("", ".", "..")
         and parent_path.resolve(strict=True) == parent_path, "Canonical fresh export path required")
    with directory(parent_path) as parent:
        meta = os.fstat(parent)
        need(meta.st_uid == os.getuid() and not meta.st_mode & (stat.S_IWGRP | stat.S_IWOTH),
             "Export parent must be owned and protected from other writers")
        yield parent


def write_bundle(bundle, evidence, originals):
    with output_parent(bundle) as parent:
        stage = ".qt629-export." + secrets.token_hex(16)
        os.mkdir(stage, 0o700, dir_fd=parent)
        try:
            with directory(stage, parent=parent) as out:
                if originals:
                    os.mkdir("inputs", 0o700, dir_fd=out)
                    with directory("inputs", parent=out) as inputs:
                        write_bodies(inputs, originals)
                write_bodies(out, evidence)
            publish(parent, stage, bundle.name)
        except BaseException:
            try:
                shutil.rmtree(stage, dir_fd=parent)
            except FileNotFoundError:
                pass
            raise
        os.fsync(parent)


def export(disk_path, disk_pin, bundle, *, originals=None, test_inputs=None, expected_nonce=None, profile=None):
    """Collect bounded evidence and publish it atomically at a new bundle path."""
    present, guest = actor_bodies(disk_path, disk_pin, expected_nonce=expected_nonce)
    original_bodies, test_bodies = reviewed_bodies(originals, test_inputs, profile=profile)
    for name in guest.keys() & test_bodies.keys():
        need(guest[name] == test_bodies[name], f"Guest evidence differs from reviewed TEST operand: {name}")
    bodies = test_bodies | guest
    write_bundle(bundle, bodies, original_bodies)
    return dict(result_disk=disk_pin, actor_directory_present=present,
                missing_actor_files=sorted(ACTOR_FILES.keys() - guest.keys()),
                original_inputs={role: C.pin(body) for role, body in original_bodies.items()},
                evidence={name: C.pin(body) for name, body in bodies.items()})
