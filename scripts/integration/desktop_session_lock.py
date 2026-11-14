#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Offline verification of an explicit settings011/session-lock010 package prefix.

No installation, payload execution, session connection or native qualification.
"""
import argparse
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import selectors
import stat
import subprocess
import sys
import tarfile
import time

SETTINGS = "cachy-asahi-hyprland-settings"
LOCKER = "cachy-asahi-session-lock"
PROFILE = "hyprland011-session-lock010"
MAX_FILE = 262144
MAX_ARCHIVE = 2097152
METADATA = {".PKGINFO", ".BUILDINFO", ".MTREE"}
VERSIONS = {SETTINGS: "0.1.1-1", LOCKER: "0.1.0-1"}
PAYLOAD = {
    SETTINGS: {"usr/bin/cachy-asahi-screenshot", *{f"usr/share/cachy-asahi/hyprland/{name}" for name in
               ("hyprland.lua", "waybar.json", "waybar.css", "mako.conf")},
               *{f"usr/share/doc/{SETTINGS}/{name}" for name in ("README.md", "source-provenance.json")},
               *{f"usr/share/licenses/{SETTINGS}/{name}" for name in ("NOTICE", "LICENSE")}},
    LOCKER: {f"usr/bin/{LOCKER}", f"usr/share/doc/{LOCKER}/README.md",
             *{f"usr/share/licenses/{LOCKER}/{name}" for name in ("NOTICE", "LICENSE")}},
}
BASELINE_CONFIG = "f75aebb1111123dc86c7f1a85e00bff0320edef6e6f071e28370fbabd6a40a6a"
HYPRLAND_COMMIT = "efb50993780079460b0cbed1363e2166a2de1d9f"
OLD_LOCK = 'hl.bind("SUPER + L", hl.dsp.exec_cmd("swaylock --color 000000"))'
NEW_LOCK = 'hl.bind("SUPER + L", hl.dsp.exec_cmd("cachy-asahi-session-lock lock"))'
SUSPEND = 'hl.bind("SUPER + SHIFT + L", hl.dsp.exec_cmd("cachy-asahi-session-lock suspend"))'
HELPER_DEPS = [f"{LOCKER}>=0.1.0", f"{LOCKER}<0.2.0"]


class Refused(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Refused(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unique_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, f"duplicate JSON key: {key}")
            result[key] = value
        return result
    def constant(_):
        raise Refused("nonfinite JSON refused")
    return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
            info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_file(path, limit, *, directory=None):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, f"ordinary unlinked-to regular file required: {path}")
        require(0 <= before.st_size <= limit, f"file exceeds size limit: {path}")
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.stat(path, dir_fd=directory, follow_symlinks=False)
        require(len(data) == before.st_size and identity(before) == identity(os.fstat(fd)) == identity(after),
                f"input changed while reading: {path}")
        return bytes(data), before
    finally:
        os.close(fd)


def clean_path(name):
    path = PurePosixPath(name)
    require(isinstance(name, str) and name and not name.startswith("/") and "\\" not in name and
            "\0" not in name and ".." not in path.parts and str(path) == name,
            "noncanonical archive/profile path")
    return name


def directories(files):
    return {str(parent) for name in files for parent in PurePosixPath(name).parents if str(parent) != "."}


def load_profile(path, checksum):
    data, _ = read_file(path, MAX_FILE)
    require(sha(data) == checksum, "source profile checksum mismatch")
    profile = unique_json(data)
    require(isinstance(profile, dict) and set(profile) == {"schema", "profile", "qualification", "packages"}, "invalid source profile fields")
    require(type(profile["schema"]) is int and profile["schema"] == 1 and profile["profile"] == PROFILE and
            profile["qualification"] == "OFFLINE_PACKAGE_PREFIX_ONLY", "unsupported source profile")
    require(isinstance(profile["packages"], dict) and set(profile["packages"]) == set(VERSIONS), "exact settings/helper pair required")
    for name, item in profile["packages"].items():
        require(isinstance(item, dict) and set(item) == {"source_commit", "metadata", "payload"}, "invalid package profile fields")
        require(re.fullmatch(r"[0-9a-f]{40}", item["source_commit"]) is not None, "invalid source commit")
        require(isinstance(item["payload"], dict) and set(item["payload"]) == PAYLOAD[name], "exact reviewed payload required")
        for path, entry in item["payload"].items():
            clean_path(path)
            require(isinstance(entry, dict) and set(entry) == {"sha256", "bytes", "mode"}, "invalid payload declaration")
            require(isinstance(entry["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is not None,
                    "invalid payload checksum")
            require(type(entry["bytes"]) is int and 0 < entry["bytes"] <= MAX_FILE, "invalid payload byte count")
            require(type(entry["mode"]) is int and entry["mode"] == (0o755 if path.startswith("usr/bin/") else 0o644),
                    "invalid payload mode")
        metadata = item["metadata"]
        require(isinstance(metadata, dict) and all(isinstance(key, str) and isinstance(values, list) and values and
                all(isinstance(value, str) and value for value in values) for key, values in metadata.items()), "invalid metadata declarations")
        for key, value in {"pkgname": [name], "pkgbase": [name], "pkgver": [VERSIONS[name]], "arch": ["any"], "license": ["MIT"]}.items():
            require(metadata.get(key) == value, f"unsupported {name} {key}")
        require(not set(metadata) & {"builddate", "packager", "size", "conflict", "provides", "replaces", "backup"}, "unsupported metadata declaration")
    settings_deps = profile["packages"][SETTINGS]["metadata"].get("depend", [])
    require(all(value in settings_deps for value in HELPER_DEPS + ["hyprland>=0.56.2", "hyprland<0.57.0"]), "missing compatible settings dependency bounds")
    require(profile["packages"][LOCKER]["metadata"].get("depend") == ["python>=3.11", "swaylock>=1.8.6", "systemd>=248"], "unexpected helper dependencies")
    return profile


def decompress(data):
    if not data.startswith(b"\x28\xb5\x2f\xfd"):
        return data
    # Decompress the already-hashed held bytes, never reopen a replaceable pathname.
    with compressed_input(data) as fd:
        process = subprocess.Popen(["/usr/bin/zstd", "-dc"], stdin=fd,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   env={"PATH": "/usr/bin", "LC_ALL": "C"})
        output = bytearray()
        deadline = time.monotonic() + 10
        try:
            os.set_blocking(process.stdout.fileno(), False)
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    require(time.monotonic() < deadline, "archive decompression timeout")
                    if selector.select(.05):
                        chunk = os.read(process.stdout.fileno(), 65536)
                        if not chunk:
                            break
                        output.extend(chunk)
                        require(len(output) <= MAX_ARCHIVE, "archive decompression exceeds limit")
            require(process.wait(timeout=1) == 0, "archive decompression failed")
            return bytes(output)
        finally:
            if process.returncode is None:
                process.kill()
            process.wait()
            process.stdout.close()


@contextmanager
def compressed_input(data):
    """Anonymous memfd input: no writes to the caller's prefix or filesystem."""
    fd = os.memfd_create("desktop-session-lock-archive", os.MFD_CLOEXEC)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.lseek(fd, 0, os.SEEK_SET)
        yield fd
    finally:
        os.close(fd)


def pkginfo(data):
    result = {}
    for line in data.decode("utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition(" = ")
        require(separator and re.fullmatch(r"[a-z][a-z0-9_]*", key) and value, "invalid .PKGINFO line")
        result.setdefault(key, []).append(value)
    return result


def verify_archive(path, checksum, expected):
    data, _ = read_file(path, MAX_ARCHIVE)
    require(sha(data) == checksum, f"package archive checksum mismatch: {path.name}")
    content = decompress(data)
    require(len(content) <= MAX_ARCHIVE, "archive content exceeds limit")
    files, found_dirs = {}, set()
    expected_dirs = directories(expected["payload"])
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:") as archive:
        seen = set()
        total = 0
        for member in archive:
            require(len(seen) < 64, "archive entry count exceeds limit")
            name = clean_path(member.name.rstrip("/") if member.isdir() else member.name)
            require(name not in seen, f"duplicate archive member: {name}")
            seen.add(name)
            require(member.uid == member.gid == 0 and member.mode in (0o644, 0o755), f"unsafe archive ownership/mode: {name}")
            if member.isdir():
                require(name in expected_dirs and member.mode == 0o755 and member.size == 0, f"unexpected archive directory: {name}")
                found_dirs.add(name)
                continue
            require(member.isfile() and not member.linkname and name in set(expected["payload"]) | METADATA, f"unexpected archive payload/type: {name}")
            require(0 <= member.size <= MAX_FILE, "oversized archive member")
            total += member.size
            require(total <= MAX_ARCHIVE, "oversized archive total")
            stream = archive.extractfile(member)
            try:
                value = stream.read(MAX_FILE + 1)
            finally:
                stream.close()
            require(len(value) == member.size, "truncated archive member")
            if name in expected["payload"]:
                entry = expected["payload"][name]
                require(member.mode == entry["mode"] and len(value) == entry["bytes"] and sha(value) == entry["sha256"], f"archive payload differs: {name}")
            else:
                require(member.mode == 0o644, "unsafe archive metadata mode")
            files[name] = value
        require(not any(content[archive.offset:]), "nonzero data after archive members")
    require(set(files) == set(expected["payload"]) | METADATA and found_dirs == expected_dirs, "archive files/directories missing")
    info = pkginfo(files[".PKGINFO"])
    volatile = {key: info.pop(key, None) for key in ("builddate", "packager", "size")}
    require(info == expected["metadata"], "package metadata differs from reviewed source profile")
    for key in ("builddate", "size"):
        require(volatile[key] and len(volatile[key]) == 1 and re.fullmatch(r"[0-9]{1,19}", volatile[key][0]), f"invalid package {key}")
    require(volatile["packager"] and len(volatile["packager"]) == 1 and len(volatile["packager"][0]) <= 512, "invalid package packager")
    require(int(volatile["size"][0]) == sum(len(files[name]) for name in expected["payload"]), "package declared payload size differs")
    return {name: files[name] for name in expected["payload"]}, {"sha256": checksum, "bytes": len(data), "volatile_metadata": volatile}


def verify_semantics(files):
    text = files["usr/share/cachy-asahi/hyprland/hyprland.lua"].decode("utf-8")
    require(text.count(NEW_LOCK) == text.count(SUSPEND) == 1, "required lock/suspend bindings differ")
    restored = text.replace(NEW_LOCK, OLD_LOCK).replace(SUSPEND + "\n", "")
    require(sha(restored.encode()) == BASELINE_CONFIG, "Lua differs beyond reviewed lock/suspend delta")
    provenance = unique_json(files[f"usr/share/doc/{SETTINGS}/source-provenance.json"])
    require(provenance.get("package") == SETTINGS and provenance.get("source") == "local-original" and provenance.get("license") == "MIT" and
            provenance.get("version") == VERSIONS[SETTINGS] and provenance.get("baseline_version") == "0.1.0-3" and
            provenance.get("baseline_hyprland_sha256") == BASELINE_CONFIG and
            provenance.get("hyprland_api_commit") == HYPRLAND_COMMIT and provenance.get("session_lock_dependency") == HELPER_DEPS and
            provenance.get("selected_for_development") is False and provenance.get("selected_for_release") is False, "settings provenance differs")
    unchanged = provenance.get("unchanged_sources", {})
    require(isinstance(unchanged, dict) and set(unchanged) == {"waybar.json", "waybar.css", "mako.conf", "cachy-asahi-screenshot", "NOTICE", "LICENSE"},
            "unchanged auxiliary provenance missing")
    for name, digest in unchanged.items():
        path = (f"usr/bin/{name}" if name == "cachy-asahi-screenshot" else f"usr/share/licenses/{SETTINGS}/{name}"
                if name in ("LICENSE", "NOTICE") else f"usr/share/cachy-asahi/hyprland/{name}")
        require(path in files and sha(files[path]) == digest, "unchanged auxiliary provenance differs")


def verify_prefix(prefix, expected):
    require(prefix.is_absolute() and prefix != Path("/"), "absolute payload-only staging prefix required")
    fd = os.open(prefix, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    before = os.fstat(fd)
    seen_files, seen_dirs = set(), set()
    allowed_dirs = directories(expected)
    def visit(directory, base):
        for name in os.listdir(directory):
            path = f"{base}/{name}" if base else name
            require(len(seen_files) + len(seen_dirs) < 64, "prefix entry count exceeds limit")
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                require(path in allowed_dirs and stat.S_IMODE(info.st_mode) == 0o755, f"unexpected prefix directory/mode: {path}")
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory)
                try:
                    seen_dirs.add(path)
                    visit(child, path)
                finally:
                    os.close(child)
            else:
                require(path in expected, f"unexpected prefix file: {path}")
                data, observed = read_file(name, MAX_FILE, directory=directory)
                require(data == expected[path] and stat.S_IMODE(observed.st_mode) == (0o755 if path.startswith("usr/bin/") else 0o644), f"prefix payload differs: {path}")
                seen_files.add(path)
    try:
        visit(fd, "")
        require(seen_files == set(expected) and seen_dirs == allowed_dirs, "prefix files/directories missing")
        require(identity(before) == identity(os.fstat(fd)) == identity(prefix.lstat()), "prefix changed while reading")
    finally:
        os.close(fd)


def verify(args):
    profile = load_profile(args.profile, args.profile_sha256)
    files, records = {}, {}
    for name, path, checksum in ((SETTINGS, args.settings_package, args.settings_sha256),
                                 (LOCKER, args.session_lock_package, args.session_lock_sha256)):
        payload, record = verify_archive(path, checksum, profile["packages"][name])
        require(not set(payload) & set(files), "packages have conflicting file ownership")
        files.update(payload)
        records[name] = record
    verify_semantics(files)
    verify_prefix(args.prefix, files)
    return {"schema": 1, "record_type": "offline-desktop-session-lock-prefix-verification",
            "status": "desktop-session-lock-prefix-pass", "profile": PROFILE, "profile_sha256": args.profile_sha256,
            "packages": records, "payload_files": len(files), "payload_sha256": {name: sha(data) for name, data in sorted(files.items())},
            "checks": {"exact_archives_metadata_payload": "PASS", "audited_Lua_binding_delta": "PASS", "exact_assembled_prefix": "PASS"},
            "host_arch": platform.machine(), "read_only": True, "payload_executed": False,
            "native_build": "NOT RUN", "installed_database_ownership": "NOT RUN", "dependency_resolution": "NOT RUN",
            "session_runtime": "NOT RUN", "hardware_validation": "NOT RUN"}


def main(argv=None):
    if not sys.flags.isolated:
        print("Python isolated mode (-I) is required", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("profile", "settings-package", "session-lock-package", "prefix"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("profile-sha256", "settings-sha256", "session-lock-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    try:
        require(all(re.fullmatch(r"[0-9a-f]{64}", value) for value in
                    (args.profile_sha256, args.settings_sha256, args.session_lock_sha256)), "exact SHA256 arguments required")
        report = verify(args)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError) as exc:
        print(json.dumps({"schema": 1, "status": "refused", "error": str(exc), "payload_executed": False}))
        return 2
    print(json.dumps(report, sort_keys=True, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
