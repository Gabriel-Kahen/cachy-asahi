# SPDX-License-Identifier: MIT
"""Read back the sealed public Qt runtime and stage its two frozen helper locks."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat

KIND = "QT612_GUI_PAIR_WORKFLOW_SOURCE_V1"
MAP = "source-map.json"
INPUTS = "runtime-inputs.DATA.json"
MAX_FILE = 4 * 1024**2
MAX_TOTAL = 12 * 1024**2
MAX_FILES = 384
PARENT = "scripts/ci/qt612-reference-native-source"
EXTERNAL = {
    f"{PARENT}/f-recipe.lock.json": {"bytes": 7754, "sha256": "a6ecf61d9bb36e1525e01f791cd51958426cd59c961b2f0a1d80d912fc0a1d52"},
    f"{PARENT}/f-serial-recipe.lock.json": {"bytes": 10713, "sha256": "020c248a7fc63bb058b0d607b83f6f711f0a5ae1d81354ce22b4dfaf0e2afec0"},
}


def need(ok, why):
    if not ok:
        raise ValueError(why)


def canonical(data):
    return (json.dumps(data, sort_keys=True, indent=2, allow_nan=False)+"\n").encode()


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "Duplicate runtime Source JSON field")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, "Nonfinite runtime Source field"))


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def leaf(value):
    need(type(value) is str and len(value) <= 255 and value == Path(value).as_posix()
         and all(re.fullmatch(r"[A-Za-z0-9._+@~-]+", p) and p not in (".", "..", ".git", ".gnupg", ".ssh")
                 for p in value.split("/")), "Canonical runtime Source member required")
    return value


def ordinary(value, *, exists=True):
    path = Path(value)
    need(path.is_absolute() and path.resolve(strict=exists) == path
         and not any(parent.is_symlink() for parent in (path, *path.parents)), "Ordinary absolute runtime path required")
    return path


def read(path, selected=None, *, mode=None):
    path = ordinary(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and not before.st_mode & 0o022
             and before.st_size <= MAX_FILE and (mode is None or stat.S_IMODE(before.st_mode) == mode),
             "Bounded ordinary runtime Source leaf required")
        body = stream.read(MAX_FILE+1)
        stable = lambda st: (st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        need(len(body) == before.st_size and stable(before) == stable(os.fstat(stream.fileno())) == stable(path.lstat()),
             "Runtime Source leaf changed during independent readback")
        need(selected is None or pin(body) == selected, "Exact runtime Source body pin required")
        return body


def scan(root, *, git_metadata=False):
    """Reject extra folders, symlinks and nonordinary leaves later against the map."""
    need(root.is_dir(), "Runtime Source directory required")
    files, folders, pending = set(), set(), [root]
    while pending:
        for path in pending.pop().iterdir():
            rel = path.relative_to(root).as_posix()
            need(not path.is_symlink(), "Runtime Source symlink refused")
            if git_metadata and rel == ".git":
                need(path.is_file() or path.is_dir(), "Ordinary checkout metadata only")
                continue
            leaf(rel)
            if path.is_dir():
                folders.add(rel)
                pending.append(path)
            else:
                need(path.is_file(), "Ordinary runtime Source file required")
                files.add(rel)
            need(len(files)+len(folders) <= 1024, "Finite runtime Source namespace required")
    return files, folders


def verify(root, map_sha256):
    """Hold independently of runtime entry availability."""
    root = ordinary(root)
    raw = read(root/MAP, mode=0o644)
    need(pin(raw)["sha256"] == map_sha256, "Independently selected whole runtime map required")
    mapping = decode(raw)
    need(set(mapping) == {"kind", "schema", "files"} and mapping["kind"] == KIND
         and type(mapping["schema"]) is int and mapping["schema"] == 1, "Exact GUI pair runtime map schema required")
    files = mapping["files"]
    need(type(files) is dict and 0 < len(files) <= MAX_FILES and MAP not in files,
         "Finite closed runtime map required")
    observed, folders = scan(root, git_metadata=True)
    need(observed == set(files) | {MAP} and folders == {str(parent) for name in files
         for parent in Path(name).parents if str(parent) != "."}, "Exact runtime Source namespace required")
    total = 0
    for path, desc in files.items():
        need(set(desc) == {"bytes", "sha256", "mode"} and desc["mode"] == 0o644
             and type(desc["bytes"]) is int and 0 <= desc["bytes"] <= MAX_FILE,
             "Exact size, digest and mode for every runtime leaf required")
        data = read(root/leaf(path), {k:desc[k] for k in ("bytes", "sha256")}, mode=0o644)
        total += len(data)
        need(total <= MAX_TOTAL, "Finite runtime Source bytes required")
    selected_inputs = decode(read(root/INPUTS, {k:files[INPUTS][k] for k in ("bytes", "sha256")}, mode=0o644))
    entry = selected_inputs["entry"]
    if entry is not None:
        need(set(entry) == {"path", "bytes", "sha256"} and entry["path"].endswith(".py")
             and {k:entry[k] for k in ("bytes", "sha256")}
             == {k:files[entry["path"]][k] for k in ("bytes", "sha256")}, "Exact mapped Root-selected entry required")
    need(read(root/MAP, mode=0o644) == raw, "Same sealed runtime map after readback required")
    return mapping


def write(root, path, body):
    target = root/leaf(path)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    with os.fdopen(fd, "wb") as stream:
        os.fchmod(stream.fileno(), 0o644)
        stream.write(body)


def stage_helpers(*, source, map_sha256, frozen_locks, output):
    """Stage exact importable public helpers in a fresh owned directory."""
    source, frozen_locks = ordinary(source), ordinary(frozen_locks)
    output = ordinary(output, exists=False)
    mapping = verify(source, map_sha256)
    inputs = decode(read(source/INPUTS))
    need(inputs["external_family_locks"] == EXTERNAL and set(inputs["helper_files"]) <= mapping["files"].keys(),
         "Exact helper and deferred frozen-lock selection required")
    need(all(not output.is_relative_to(p) and not p.is_relative_to(output) for p in (source, frozen_locks)),
         "Fresh disjoint helper stage required")
    bodies = {name:read(source/leaf(name), {k:mapping["files"][name][k] for k in ("bytes", "sha256")})
              for name in inputs["helper_files"]}
    for name, selected in EXTERNAL.items():
        bodies[name] = read(frozen_locks/name, selected)
    output.mkdir(mode=0o700)
    for name, body in bodies.items():
        write(output, name, body)
    return dict(status="PASS_EXACT_RUNTIME_HELPER_STAGE_DATA_ONLY", files=len(bodies), Root_acceptance=None)
