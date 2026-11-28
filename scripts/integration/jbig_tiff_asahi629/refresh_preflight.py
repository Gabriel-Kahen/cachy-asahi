# SPDX-License-Identifier: MIT
"""Host-only telemetry and scoped rehashing for bounded stage preparation."""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
from runpy import run_path
import stat
import time
from types import SimpleNamespace


CHUNK_SIZE = 1 << 20
CGROUP_ROOT = Path("/sys/fs/cgroup")
ACTOR_MEMORY = run_path(str(Path(__file__).with_name("host_telemetry.py")))["actor_memory"]


def bulk_read(T, path, expected, *, cap, observed=None):
    """Hash a pinned file and advise discard for fully consumed pages."""
    path = T.ordinary(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        T.need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= cap,
               "Expected an ordinary bounded bulk file with one link: " + path.name)
        T.need(type(expected) is dict and expected.keys() == {"bytes", "sha256"}
               and type(expected["bytes"]) is int and expected["bytes"] == before.st_size
               and type(expected["sha256"]) is str and T.HEX.fullmatch(expected["sha256"]),
               "Expected bulk file length or digest differs: " + path.name)
        page = os.sysconf("SC_PAGE_SIZE")
        os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_RANDOM)
        digest = hashlib.sha256()
        consumed = advised = 0
        while consumed < before.st_size:
            part = stream.read(min(CHUNK_SIZE, before.st_size - consumed))
            T.need(part, "Short pinned bulk file read: " + path.name)
            digest.update(part)
            consumed += len(part)
            boundary = consumed // page * page
            if boundary > advised:
                os.posix_fadvise(fd, advised, boundary - advised, os.POSIX_FADV_DONTNEED)
                advised = boundary
        T.need(not stream.read(1), "Pinned bulk file grew: " + path.name)
        actual = dict(bytes=consumed, sha256=digest.hexdigest())
        identity = T.identity(before)
        T.need(actual == expected and identity == T.identity(os.fstat(fd)) == T.identity(path.lstat()),
               "Changed pinned bulk bytes or identity: " + path.name)
        if observed is not None:
            name = str(path)
            T.need(name not in observed or observed[name] == identity, "Reopened bulk file identity changed")
            observed[name] = identity
    return actual


def preview_reader(T, root, manifest):
    """Change only noncollecting reads of large files named in this Preview manifest."""
    paths = {root / name: pin for name, pin in manifest["files"].items() if pin["bytes"] >= CHUNK_SIZE}

    def read(path, expected=None, *, cap=T.MAX_MEMBER, collect=True, observed=None, allowed_links=(1,)):
        selected = paths.get(Path(path))
        if selected is not None and not collect:
            T.need(selected == expected and allowed_links == (1,), "Unexpected selected Preview bulk read")
            return bulk_read(T, path, selected, cap=cap, observed=observed)
        return T.read(path, expected, cap=cap, collect=collect, observed=observed, allowed_links=allowed_links)

    return SimpleNamespace(**(vars(T) | {"read": read}))


class Worker:
    def __init__(self, runtime, group, emit):
        info = runtime.lstat()
        if (not runtime.is_absolute() or runtime.resolve(strict=True) != runtime
                or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError("Expected an owned private worker runtime directory")
        self.runtime = runtime
        self.group = group
        self.emit = emit

    def _mark(self, name, state):
        self.emit(dict(phase=name, state=state, at_ns=time.time_ns(), monotonic_ns=time.monotonic_ns(),
                       **ACTOR_MEMORY(self.group)))

    @contextmanager
    def phase(self, name):
        self._mark(name, "begin")
        try:
            yield
        except BaseException:
            self._mark(name, "failed")
            raise
        else:
            self._mark(name, "complete")

    def held_disk(self, T, path, expected):
        with self.phase("held-disk-dry-check"):
            return bulk_read(T, path, expected, cap=expected["bytes"])

    def rehash_preview(self, T, operands, root, manifest):
        with self.phase("preview-rehash"):
            operands.rehash(preview_reader(T, root, manifest), root, manifest)


@contextmanager
def systemd_worker(phase_log):
    """Bind phase telemetry to the already admitted service and its runtime directory."""
    runtime = os.environ.get("RUNTIME_DIRECTORY")
    membership = Path("/proc/self/cgroup").read_text(encoding="ascii").strip()
    group = Path(membership.removeprefix("0::/"))
    expected_runtime = Path("/run/user") / str(os.getuid()) / group.name.removesuffix(".service")
    if (runtime != str(expected_runtime) or not membership.startswith("0::/") or group.is_absolute()
            or not group.name.endswith(".service") or ".." in group.parts):
        raise ValueError("Expected a bounded systemd worker with a private runtime directory")
    with phase_log.open("x", encoding="ascii", buffering=1) as log:
        def emit(row):
            log.write(json.dumps(row, sort_keys=True) + "\n")

        yield Worker(expected_runtime, CGROUP_ROOT / group, emit)
