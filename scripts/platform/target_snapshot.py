#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only exact-target metadata and explicitly selected artifact collector.

Live mode accepts only observed aarch64/16K M2 Air identities. Fixture mode is
explicit and always labeled synthetic. Neither mode establishes hardware support.
No commands, network, package operations, service changes, or directory backups.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
MIB = 1024**2
LIMIT = 64 * MIB
SECONDS = 60
ROLES = {"boot-chain", "kernel", "kernel-release", "firmware", "user-configuration", "system-configuration"}
MODELS = {"apple,j413": 13, "apple,j415": 15}


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


capture = module("snapshot_capture", HERE / "capture.py")
audit = module("snapshot_tuple", HERE / "tuple_audit.py")
baseline = module("snapshot_baseline", HERE.parent / "hardware/capture-baseline.py")


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def absolute(value):
    path = Path(value)
    need(path.is_absolute() and ".." not in path.parts and str(path) == value, "canonical absolute path required")
    return path


def opened(path, directory=False):
    """Open every component without following symlinks; caller owns returned FD."""
    path = absolute(str(path))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, part in enumerate(path.parts[1:]):
            is_dir = directory or index < len(path.parts) - 2
            next_fd = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                              (os.O_DIRECTORY if is_dir else 0), dir_fd=fd)
            os.close(fd)
            fd = next_fd
        result, fd = fd, None
        return result
    finally:
        if fd is not None:
            os.close(fd)


def identity(info):
    return {name: getattr(info, "st_" + name) for name in
            ("dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns")}


def reference(path, data):
    return {"path": str(path), "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


class Reader:
    def __init__(self, *, retain=False, maximum=None):
        need(maximum is None or type(maximum) is int and 0 < maximum <= 512 * MIB, "reader aggregate bound refused")
        self.started, self.total, self.files = time.monotonic(), 0, {}
        self.retained = {} if retain else None
        self.maximum = maximum

    def deadline(self):
        need(time.monotonic() - self.started <= SECONDS, "collection deadline exceeded")

    def read(self, path, maximum, *, remember=True):
        self.deadline()
        path = absolute(str(path))
        fd = opened(path)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum,
                 "single-link regular bounded input required: " + str(path))
            chunks, length = [], 0
            while True:
                self.deadline()
                data = os.read(fd, min(MIB, maximum - length + 1))
                if not data:
                    break
                chunks.append(data)
                length += len(data)
                need(length <= maximum, "input observed byte bound exceeded")
            need(identity(os.fstat(fd)) == identity(before), "input changed during read: " + str(path))
        finally:
            os.close(fd)
        check = opened(path)
        try:
            need(identity(os.fstat(check)) == identity(before), "input path replaced during read: " + str(path))
        finally:
            os.close(check)
        data = b"".join(chunks)
        observation = reference(path, data) | {"node": identity(before)}
        if remember:
            if str(path) not in self.files:
                self.total += len(data)
                need(self.total <= (LIMIT if self.maximum is None else self.maximum), "aggregate source byte bound exceeded")
            else:
                need(self.files[str(path)] == observation, "source changed between reads")
            self.files[str(path)] = observation
            if self.retained is not None:
                self.retained[str(path)] = data
        return data, observation

    def bound(self, ref, maximum):
        need(set(ref) == {"path", "size", "sha256"} and type(ref["size"]) is int
             and 0 < ref["size"] <= maximum and isinstance(ref["sha256"], str)
             and re.fullmatch(r"[a-f0-9]{64}", ref["sha256"]), "input reference refused")
        data, observed = self.read(absolute(ref["path"]), maximum)
        need(all(observed[key] == ref[key] for key in ("path", "size", "sha256")), "input reference size/hash mismatch")
        return data

    def recheck(self):
        for path, original in list(self.files.items()):
            _, actual = self.read(Path(path), max(original["size"], 1), remember=False)
            need(actual == original, "source drift before publication: " + path)


def listing(path):
    fd = opened(path, directory=True)
    try:
        before = identity(os.fstat(fd))
        entries = []
        with os.scandir(fd) as iterator:
            for entry in iterator:
                need(len(entries) < 4097 and entry.name not in {".", ".."}
                     and capture.NAME.fullmatch(entry.name), "local inventory name/count bound refused")
                entries.append(entry.name)
        need(identity(os.fstat(fd)) == before, "inventory directory changed while listing")
        return sorted(entries), before
    finally:
        os.close(fd)


def lock_absent(root):
    try:
        os.lstat(root / "var/lib/pacman/db.lck")
    except FileNotFoundError:
        return
    raise ValueError("pacman database lock present; retry after its owner completes")


def inventory(reader, root):
    local = root / "var/lib/pacman/local"
    lock_absent(root)
    entries, node = listing(local)
    records, retained = [], {}
    for name in entries:
        if name == "ALPM_DB_VERSION":
            data, _ = reader.read(local / name, 32)
            need(re.fullmatch(rb"[0-9]{1,4}\n?", data), "invalid local database format version")
            retained["ALPM_DB_VERSION"] = data
            continue
        directory = local / name
        package_fd = opened(directory, directory=True)
        os.close(package_fd)
        data, observed = reader.read(directory / "desc", 256 * 1024)
        fields = capture.parse_desc(data)
        need(name == fields["NAME"][0] + "-" + fields["VERSION"][0], "package directory/descriptor identity mismatch")
        records.append({"directory": name, "descriptor_sha256": observed["sha256"], "metadata": fields})
        retained[name + ".desc"] = data
    audit.packages([row["metadata"] for row in records])
    need(records, "empty installed inventory refused")
    need(listing(local) == (entries, node), "installed inventory changed during capture")
    lock_absent(root)
    return records, retained, (local, entries, node)


def live_runtime():
    uname = os.uname()
    return {"architecture": uname.machine, "kernel_release": uname.release,
            "page_size": os.sysconf("SC_PAGE_SIZE")}


def validate_runtime(runtime, compatible):
    need(set(runtime) == {"architecture", "kernel_release", "page_size"}
         and runtime["architecture"] == "aarch64" and type(runtime["page_size"]) is int
         and runtime["page_size"] == 16384 and isinstance(runtime["kernel_release"], str)
         and re.fullmatch(r"[A-Za-z0-9._+-]{1,128}", runtime["kernel_release"]),
         "exact aarch64/16K target runtime required")
    need(compatible.endswith(b"\0") and len(compatible) <= 65536, "raw NUL-terminated compatible property required")
    identifiers = compatible[:-1].decode("ascii").split("\0")
    selected = [name for name in identifiers if name in MODELS]
    need(all(identifiers) and len(selected) == 1 and "apple,t8112" in identifiers and len(set(identifiers)) == len(identifiers),
         "exact unambiguous M2 Air device-tree identity required")
    size = baseline.target_size(runtime["architecture"], "\n".join(identifiers))
    need(size == str(MODELS[selected[0]]) + "-inch", "maintained target-size binding refused")
    return {"compatible": selected[0], "air_size_inches": MODELS[selected[0]]}


def save_at(fd, name, data):
    dest = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    with os.fdopen(dest, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def encoded(value):
    data = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
    need(len(data) <= 8 * MIB, "serialized document byte bound exceeded")
    return data


def output_identity(output, parent_fd, output_fd):
    for path, held in ((output.parent, parent_fd), (output, output_fd)):
        fresh = opened(path, directory=True)
        try:
            actual, expected = os.fstat(fresh), os.fstat(held)
            need((actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino),
                 "output pathname identity changed before publication")
            need(actual.st_uid == os.geteuid() and stat.S_IMODE(actual.st_mode) == 0o700,
                 "private output permissions changed before publication")
        finally:
            os.close(fresh)


def run(contract_ref, output, *, retain_inputs=False):
    need(type(retain_inputs) is bool, "retained input mode must be boolean")
    reader = Reader(retain=retain_inputs)
    contract = audit.load_json(reader.bound(contract_ref, MIB))
    fields = {"schema_version", "mode", "selected_files"}
    need(type(contract.get("schema_version")) is int and contract["schema_version"] == 1
         and contract.get("mode") in {"live", "fixture"}, "collector contract mode/version refused")
    fixture = contract["mode"] == "fixture"
    allowed = fields | ({"fixture_root", "fixture_runtime"} if fixture else set())
    need(set(contract) in (allowed, allowed | {"preflight"}), "collector contract fields refused")
    root = absolute(contract["fixture_root"]) if fixture else Path("/")
    runtime = audit.load_json(reader.bound(contract["fixture_runtime"], 65536)) if fixture else live_runtime()
    need(runtime.get("architecture") == "aarch64", "live/fixture architecture is not a supported Apple ARM target")
    compatible, _ = reader.read(root / "sys/firmware/devicetree/base/compatible", 65536)
    model = validate_runtime(runtime, compatible)
    packages, descriptors, db_guard = inventory(reader, root)
    by_name = {row["metadata"]["NAME"][0]: row for row in packages}
    need("linux-asahi" in by_name, "installed linux-asahi metadata required")
    kernel = by_name["linux-asahi"]
    module_path = "usr/lib/modules/" + runtime["kernel_release"] + "/pkgbase"
    pkgbase, _ = reader.read(root / module_path, 4096)
    need(pkgbase == b"linux-asahi\n", "running kernel module package identity mismatch")
    files, _ = reader.read(root / "var/lib/pacman/local" / kernel["directory"] / "files", 4 * MIB)
    fields = audit.parse_desc(files.decode("utf-8"))
    need(module_path in fields.get("FILES", []), "running kernel module identity not owned by installed linux-asahi metadata")
    runtime = runtime | {"kernel_package_version": kernel["metadata"]["VERSION"][0]}
    selections = contract["selected_files"]
    need(isinstance(selections, list) and len(selections) <= len(ROLES), "finite explicit selected files required")
    assets, roles = [], set()
    for item in selections:
        need(set(item) == {"role", "source"} and item["role"] in ROLES and item["role"] not in roles,
             "duplicate/unknown selected file role")
        roles.add(item["role"])
        data = reader.bound(item["source"], 32 * MIB)
        if item["role"] == "kernel-release":
            need(data.decode("ascii").strip() == runtime["kernel_release"], "selected kernel-release artifact mismatch")
        assets.append((item["role"], data, item["source"]))
    preflight = contract.get("preflight")
    if preflight is not None:
        need(set(preflight) == {"prepared_update", "recovery_receipts"}
             and isinstance(preflight["recovery_receipts"], list) and len(preflight["recovery_receipts"]) <= 32,
             "preflight adapter fields refused")
        for ref in [preflight["prepared_update"], *preflight["recovery_receipts"]]:
            audit.load_json(reader.bound(ref, 8 * MIB))
    output = absolute(str(output))
    parent_fd = opened(output.parent, directory=True)
    output_fd = None
    try:
        parent = os.fstat(parent_fd)
        need(parent.st_uid == os.geteuid() and stat.S_IMODE(parent.st_mode) == 0o700,
             "output parent must be caller-owned mode 0700")
        need(not output.is_relative_to(db_guard[0]), "output cannot reside in installed inventory")
        reader.recheck()
        need(listing(db_guard[0]) == (db_guard[1], db_guard[2]), "installed inventory drift before output")
        lock_absent(root)
        os.mkdir(output.name, mode=0o700, dir_fd=parent_fd)
        output_fd = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        output_identity(output, parent_fd, output_fd)
        os.fsync(parent_fd)
        save_at(output_fd, "INCOMPLETE", b"Snapshot is incomplete unless snapshot.json and collection.json are both present.\n")
        save_at(output_fd, "compatible.bin", compatible)
        save_at(output_fd, "kernel-files.txt", files)
        save_at(output_fd, "kernel-pkgbase.txt", pkgbase)
        os.mkdir("descriptors", mode=0o700, dir_fd=output_fd)
        desc_fd = os.open("descriptors", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=output_fd)
        try:
            for name, data in descriptors.items():
                save_at(desc_fd, name, data)
        finally:
            os.close(desc_fd)
        captured = datetime.now(timezone.utc).isoformat()
        snapshot = {"schema_version": 1, "kind": "operator-supplied-offline-Asahi-target-snapshot",
                    "model": model, "device_tree_compatible": reference(output / "compatible.bin", compatible),
                    "packages": packages, "captured_at": ("SYNTHETIC-FIXTURE " if fixture else "OBSERVED-LIVE-METADATA ") + captured,
                    "runtime": runtime, "boot_assets": [], "configuration_backups": []}
        for role, data, source in assets:
            filename = "selected-" + role + ".bin"
            save_at(output_fd, filename, data)
            field = "configuration_backups" if role.endswith("configuration") else "boot_assets"
            snapshot[field].append({"role": role, "artifact": reference(output / filename, data)})
        reader.recheck()
        need(listing(db_guard[0]) == (db_guard[1], db_guard[2]), "installed inventory drift before publication")
        lock_absent(root)
        if not fixture:
            need(live_runtime() == {key: runtime[key] for key in ("architecture", "kernel_release", "page_size")}, "running kernel/runtime changed during capture")
        snapshot_bytes = encoded(snapshot)
        receipt = {"schema_version": 1, "kind": "read-only-Asahi-target-snapshot-collection", "status": "CAPTURED_METADATA_ONLY",
                   "scope": "SYNTHETIC_FIXTURE" if fixture else "OBSERVED_LIVE_METADATA", "contract_reference": contract_ref,
                   "snapshot": reference(output / "snapshot.json", snapshot_bytes), "sources": list(reader.files.values()),
                   "source_code_sha256": {str(Path(path).relative_to(HERE.parents[1])): hashlib.sha256(Path(path).read_bytes()).hexdigest()
                                          for path in ((__file__, capture.__file__, audit.__file__, baseline.__file__)
                                                       + ((str(HERE / "retained_bundle.py"),) if retain_inputs else ()))},
                   "selected_files": selections, "source_bytes": reader.total, "sources_rechecked": True,
                   "hardware_accepted": False, "boot_accepted": False, "recovery_accepted": False,
                   "backup_completeness_accepted": False, "installed_payload_authenticated": False,
                   "limitations": ["No physical behavior or runtime functionality was tested.",
                                   "Kernel association uses supplied installed metadata and pkgbase, not payload authentication.",
                                   "Only explicitly selected individual files were copied; boot/configuration completeness is unknown.",
                                   "Stable observations do not freeze future machine state."]}
        if preflight is not None:
            save_at(output_fd, "preflight-contract.json", encoded({"schema_version": 1, "target_snapshot": receipt["snapshot"], **preflight}))
        receipt_bytes = encoded(receipt)
        if retain_inputs:
            os.mkdir("inputs", mode=0o700, dir_fd=output_fd)
            input_fd = os.open("inputs", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=output_fd)
            retained = []
            try:
                for index, (path, data) in enumerate(reader.retained.items()):
                    filename = str(index) + ".bin"
                    save_at(input_fd, filename, data)
                    retained.append({"source_path": path, "retained": reference(output / "inputs" / filename, data)})
                os.fsync(input_fd)
            finally:
                os.close(input_fd)
            save_at(output_fd, "retained-inputs.json", encoded({"schema_version": 1,
                    "kind": "collector-retained-input-map", "collection": reference(output / "collection.json", receipt_bytes),
                    "files": retained}))
            reader.recheck()
            need(listing(db_guard[0]) == (db_guard[1], db_guard[2]), "installed inventory drift after retention")
            lock_absent(root)
            if not fixture:
                need(live_runtime() == {key: runtime[key] for key in ("architecture", "kernel_release", "page_size")},
                     "running kernel/runtime changed during retention")
        save_at(output_fd, "collection.json", receipt_bytes)
        output_identity(output, parent_fd, output_fd)
        save_at(output_fd, "snapshot.json", snapshot_bytes)
        output_identity(output, parent_fd, output_fd)
        os.unlink("INCOMPLETE", dir_fd=output_fd)
        os.fsync(output_fd)
        os.fsync(parent_fd)
        return receipt
    finally:
        if output_fd is not None:
            os.close(output_fd)
        os.close(parent_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--contract-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        ref = {"path": str(args.contract.absolute()), "size": args.contract.stat().st_size, "sha256": args.contract_sha256}
        report = run(ref, args.output)
    except (ValueError, OSError, KeyError, TypeError, AttributeError, UnicodeError) as error:
        parser.exit(1, "target snapshot refused: " + str(error) + "\n")
    print(json.dumps({"snapshot": report["snapshot"], "scope": report["scope"], "hardware_accepted": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
