# SPDX-License-Identifier: MIT
"""Capture a stopped disposable Asahi629 local database as private pending evidence."""

from contextlib import ExitStack
import ctypes
import os
from pathlib import Path
import re
import selectors
import stat
import struct
import subprocess
import tempfile
import time
from uuid import UUID


DEBUGFS = Path("/usr/bin/debugfs")
COUNT = 629
MAX_IMAGE = 16 << 30
MAX_DB = 128 << 20
MEMBER_CAPS = {"desc": 256 << 10, "files": 8 << 20, "mtree": 8 << 20,
               "install": 256 << 10, "changelog": 8 << 20}


def command(T, tool_fd, image_fd, request, cap, deadline):
    end = min(deadline, time.monotonic() + 5)
    T.need(end > time.monotonic(), "Local database capture deadline expired")
    output, errors = bytearray(), bytearray()
    with subprocess.Popen([str(DEBUGFS), "-R", request, f"/proc/self/fd/{image_fd}"],
                          executable=f"/proc/self/fd/{tool_fd}", pass_fds=(tool_fd, image_fd),
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          env={"LC_ALL": "C", "TZ": "UTC"}) as child, selectors.DefaultSelector() as pipes:
        pipes.register(child.stdout, selectors.EVENT_READ, (output, cap))
        pipes.register(child.stderr, selectors.EVENT_READ, (errors, 4096))
        try:
            while pipes.get_map():
                remaining = end - time.monotonic()
                T.need(remaining > 0, "Local database image read timed out")
                for event, _ in pipes.select(remaining):
                    body, maximum = event.data
                    chunk = os.read(event.fd, min(65536, maximum - len(body) + 1))
                    if chunk:
                        body.extend(chunk)
                        T.need(len(body) <= maximum, "Local database image read exceeded its output bound")
                    else:
                        pipes.unregister(event.fd)
            T.need(child.wait(timeout=max(0.001, end - time.monotonic())) == 0,
                   "Local database image reader failed")
        except subprocess.TimeoutExpired as error:
            raise ValueError("Local database image reader did not retire in time") from error
        finally:
            if child.poll() is None:
                child.kill()
    T.need(re.fullmatch(rb"debugfs [0-9]+\.[0-9]+\.[0-9]+ \([A-Za-z0-9 .-]{1,64}\)\n", errors),
           "Local database image reader emitted a diagnostic")
    return bytes(output)


def listing(T, invoke, inode, parent):
    raw = invoke(f"ls -p <{inode}>", 256 << 10)
    entries = {}
    for line in raw.decode("utf-8").splitlines():
        if not line:
            continue
        row = line.split("/")
        T.need(len(row) == 8 and row[0] == row[7] == "" and len(entries) < 1024
               and all(re.fullmatch(r"[0-9]{1,10}", row[i]) for i in (1, 3, 4))
               and re.fullmatch(r"[0-7]{6}", row[2]), "Malformed local database directory listing")
        name = row[5]
        number, mode, uid, gid = int(row[1]), int(row[2], 8), int(row[3]), int(row[4])
        T.need(0 < number < 1 << 32 and 0 < len(name.encode()) <= 255 and name not in entries
               and not re.search(r"[\x00-\x1f\x7f]", name), "Invalid or repeated image directory entry")
        T.need(re.fullmatch(r"[0-9]{1,12}", row[6]) or not row[6] and stat.S_ISDIR(mode),
               "Invalid local database directory entry size")
        entries[name] = (number, mode, uid, gid, int(row[6]) if row[6] else None)
    for name, number in ((".", inode), ("..", parent)):
        T.need(name in entries and entries[name][0] == number and stat.S_ISDIR(entries[name][1]),
               "Local database directory ancestry differs")
        del entries[name]
    return entries, T.pin(raw)


def metadata(T, invoke, entry, cap):
    inode, mode, uid, gid, size = entry
    T.need(stat.S_ISREG(mode) and (uid, gid) == (0, 0) and size is not None and size <= cap,
           "Expected a root-owned bounded local database file")
    details = invoke(f"stat <{inode}>", 16 << 10).decode("ascii")
    observed = re.findall(r"^Inode: ([0-9]+)   Type: regular    Mode:  (0[0-7]{3,4})   Flags: 0x[0-9a-fA-F]+$",
                          details, re.MULTILINE)
    size_rows = re.findall(r"^User:\s+([0-9]+)\s+Group:\s+([0-9]+)(?:\s+Project:\s+[0-9]+)?\s+Size: ([0-9]+)$",
                           details, re.MULTILINE)
    links = re.findall(r"^Links: ([0-9]+)   Blockcount: [0-9]+$", details, re.MULTILINE)
    T.need(len(observed) == 1 and int(observed[0][0]) == inode and int(observed[0][1], 8) == stat.S_IMODE(mode)
           and size_rows == [(str(uid), str(gid), str(size))] and links == ["1"],
           "Local database inode differs or has another link")
    body = invoke(f"cat <{inode}>", size)
    T.need(len(body) == size, "Local database file length differs")
    return body


def descriptor(T, raw, name, version):
    lines = raw.decode("utf-8").splitlines()
    for key, allowed in (("NAME", {name}), ("VERSION", {version}), ("ARCH", {"aarch64", "any"})):
        positions = [i for i, line in enumerate(lines) if line == f"%{key}%"]
        T.need(len(positions) == 1 and positions[0] + 2 < len(lines) and lines[positions[0] + 1] in allowed
               and lines[positions[0] + 2] == "", "Local database descriptor identity differs: " + name)


def write(path, body):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags, 0o600), "wb") as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def collect(T, invoke, root, rows):
    path, inode, parent = "/", 2, 2
    seen = {inode}
    directories, files = {}, {}

    def directory(path, inode, parent):
        entries, pin = listing(T, invoke, inode, parent)
        directories[path] = {"inode": inode, "listing": pin}
        return entries

    def claim(entry):
        number = entry[0]
        T.need(number not in seen, "Aliased local database inode")
        seen.add(number)
        return number

    for name in ("var", "lib", "pacman", "local"):
        entries = directory(path, inode, parent)
        T.need(name in entries and stat.S_ISDIR(entries[name][1]) and entries[name][2:4] == (0, 0),
               "Local database ancestry is incomplete or not a root-owned directory")
        if name == "local":
            T.need("db.lck" not in entries, "Stopped local database still has a pacman lock")
        parent, inode = inode, claim(entries[name])
        path = path.rstrip("/") + "/" + name

    entries = directory(path, inode, parent)
    expected = {f"{name}-{version}": (name, version) for name, version in rows.items()}
    T.need(len(expected) == len(rows) and entries.keys() == expected.keys() | {"ALPM_DB_VERSION"},
           "Local database directory identities differ from the exact restored lock")
    root.mkdir(mode=0o700)
    remaining = MAX_DB

    def read_member(relative, entry, cap):
        nonlocal remaining
        claim(entry)
        body = metadata(T, invoke, entry, min(cap, remaining))
        remaining -= len(body)
        files[relative] = T.pin(body)
        return body

    version = read_member("ALPM_DB_VERSION", entries["ALPM_DB_VERSION"], 32)
    T.need(re.fullmatch(rb"[0-9]{1,4}\n", version), "Invalid local database format version")
    write(root / "ALPM_DB_VERSION", version)
    for package, (name, version) in sorted(expected.items()):
        entry = entries[package]
        T.need(stat.S_ISDIR(entry[1]) and entry[2:4] == (0, 0), "Invalid local database package directory")
        members = directory(path + "/" + package, claim(entry), inode)
        T.need({"desc", "files"} <= members.keys() <= MEMBER_CAPS.keys(), "Unexpected local database package members")
        target = root / package
        target.mkdir(mode=0o700)
        for member, row in sorted(members.items()):
            body = read_member(package + "/" + member, row, MEMBER_CAPS[member])
            if member == "desc":
                descriptor(T, body, name, version)
            write(target / member, body)
        sync_directory(target)
    sync_directory(root)
    T.need(T.decode(T.local_database_snapshot(root, count=len(rows))) == files,
           "Captured local database differs from its independent file manifest")
    return directories, files, MAX_DB - remaining


def ext4(T, fd, size):
    raw = os.pread(fd, 1024, 1024)
    T.need(len(raw) == 1024 and raw[56:58] == b"\x53\xef", "Expected a stopped ext4 scratch image")
    blocks = struct.unpack_from("<I", raw, 4)[0]
    block_size = struct.unpack_from("<I", raw, 24)[0]
    flags = struct.unpack_from("<I", raw, 96)[0]
    if flags & 0x80:
        blocks |= struct.unpack_from("<I", raw, 336)[0] << 32
    T.need(block_size == 2 and blocks * 4096 == size and raw[58:60] == b"\x01\x00" and not flags & 4,
           "Scratch filesystem geometry or clean shutdown differs")
    return raw, str(UUID(bytes=raw[104:120]))


def publish(parent, source, destination):
    rename = ctypes.CDLL(None, use_errno=True).renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(parent, os.fsencode(source), parent, os.fsencode(destination), 1) != 0:  # RENAME_NOREPLACE
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), destination)
    os.fsync(parent)


def capture(T, scratch, restored_lock, nonce, pending, *, expected_size, expected_uuid, debugfs_pin):
    """After caller-proven natural QEMU exit, capture pending data for the outer owner."""
    scratch, pending = T.ordinary(scratch), T.ordinary(pending)
    T.need(scratch.name == "scratch.raw" and scratch.parent == pending.parent and pending.name.endswith(".pending")
           and not pending.exists() and re.fullmatch(r"[a-f0-9]{32}", nonce), "Fresh owned local database pending path required")
    T.need(type(restored_lock) is bytes and len(restored_lock) <= 64 << 10, "Finite exact restored lock required")
    T.need(type(expected_size) is int and 4096 <= expected_size <= MAX_IMAGE
           and type(expected_uuid) is str and str(UUID(expected_uuid)) == expected_uuid,
           "Exact scratch geometry and UUID are required")
    rows = T.canonical_lock(restored_lock, COUNT)
    deadline = time.monotonic() + 90
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with ExitStack() as stack:
        image_fd = os.open(scratch, flags)
        stack.callback(os.close, image_fd)
        source = os.fstat(image_fd)
        T.need(stat.S_ISREG(source.st_mode) and source.st_nlink == 1 and source.st_uid == os.geteuid()
               and source.st_size == expected_size, "Expected a private ordinary scratch image of the selected size")
        header, uuid = ext4(T, image_fd, source.st_size)
        T.need(uuid == expected_uuid, "Scratch filesystem UUID differs from its selection")
        tool_fd = os.open(DEBUGFS, flags)
        stack.callback(os.close, tool_fd)
        tool = os.fstat(tool_fd)
        T.need(stat.S_ISREG(tool.st_mode) and tool.st_uid == tool.st_gid == 0 and tool.st_nlink == 1
               and stat.S_IMODE(tool.st_mode) == 0o755 and 0 < tool.st_size <= 1 << 20,
               "Expected a bounded root-owned debugfs tool")
        T.need(T.pin(os.pread(tool_fd, tool.st_size + 1, 0)) == debugfs_pin, "Selected debugfs tool pin differs")
        parent_fd = os.open(pending.parent, flags | os.O_DIRECTORY)
        stack.callback(os.close, parent_fd)
        parent = os.fstat(parent_fd)
        T.need(parent.st_uid == os.geteuid() and not parent.st_mode & (stat.S_IWGRP | stat.S_IWOTH),
               "Expected a private local database output parent")

        def invoke(request, cap):
            return command(T, tool_fd, image_fd, request, cap, deadline)

        with tempfile.TemporaryDirectory(prefix=".alpm-capture-", dir=pending.parent) as work:
            staging = Path(work) / "candidate"
            staging.mkdir(mode=0o700)
            local = staging / "local"
            directories, files, size = collect(T, invoke, local, rows)
            write(staging / "rollback.lock", restored_lock)
            receipt = T.encoded(dict(kind="ASAHI629_ALPM_LOCAL_CAPTURE_PENDING_V1", nonce=nonce,
                                     packages=len(rows), lock=T.pin(restored_lock), directories=directories,
                                     files=files, database_bytes=size, scratch={"bytes": source.st_size, "uuid": uuid,
                                     "superblock": T.pin(header), "identity": list(T.identity(source))},
                                     debugfs=debugfs_pin))
            write(staging / "manifest.json", receipt)
            sync_directory(staging)
            T.need(T.identity(source) == T.identity(os.fstat(image_fd)) == T.identity(scratch.lstat())
                   and ext4(T, image_fd, source.st_size)[0] == header, "Stopped scratch image changed during capture")
            T.need(T.identity(tool) == T.identity(os.fstat(tool_fd)) == T.identity(DEBUGFS.lstat()),
                   "Debugfs tool changed during capture")
            named_parent = pending.parent.lstat()
            T.need((parent.st_dev, parent.st_ino) == (named_parent.st_dev, named_parent.st_ino)
                   and time.monotonic() < deadline, "Local database output parent or capture deadline changed")
            publish(parent_fd, staging.relative_to(pending.parent), pending.name)
    return T.pin(receipt)
