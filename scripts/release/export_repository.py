#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Plan or materialize a local stable repository endpoint. Never uploads or edits trust."""
import argparse
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("cachy_asahi_release", Path(__file__).with_name("release.py"))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
MAX_FILES, MAX_BYTES = 16384, 8 * 1024**3
GENERATION = re.compile(r"generations/[0-9a-f]{64}\Z")


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    path = Path(value)
    r.require(path.is_absolute() and path.anchor == "/" and str(path) == str(value) and ".." not in path.parts,
              "canonical absolute path required")
    for part in [*reversed(path.parents), path]:
        r.require(not part.is_symlink(), "symlink path component refused")
    return path


def regular(path):
    info = path.lstat()
    r.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
              and not info.st_mode & 0o022, "caller-owned regular single-link file without group/world writes required")
    return info


def managed_directory(path):
    info = path.lstat()
    r.require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022,
              "managed directory must belong to caller and prohibit group/world writes")


@contextlib.contextmanager
def locks(root, endpoint):
    # The existing release writer locks this same inode exclusively.
    path = root / ".release.lock"
    regular(path)
    source_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(source_fd, "rb") as source:
        fd = os.open(endpoint, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fcntl.flock(source, fcntl.LOCK_SH | fcntl.LOCK_NB)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)


def tree(directory):
    managed_directory(directory)
    files, links, total, members = {}, {}, 0, 0
    for parent, directories, names in os.walk(directory, followlinks=False):
        for name in directories + names:
            path = Path(parent) / name
            relative = path.relative_to(directory).as_posix()
            info = path.lstat()
            members += 1
            r.require(members <= MAX_FILES, "endpoint member bound exceeded")
            if stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                r.require(info.st_uid == os.geteuid() and "/" not in target and target not in {"", ".", ".."},
                          "foreign or escaping symlink refused")
                links[relative] = target
            elif stat.S_ISDIR(info.st_mode):
                managed_directory(path)
                continue
            else:
                regular(path)
                total += info.st_size
                r.require(total <= MAX_BYTES, "endpoint byte bound exceeded")
                files[relative] = r.sha(path)
            r.require(len(files) + len(links) <= MAX_FILES, "endpoint file bound exceeded")
    for name, target in links.items():
        r.require((Path(name).parent / target).as_posix() in files, "symlink target is not a retained regular file")
    return files, links


def stable(directory, promotion, key, env, expected_release):
    manifest, release_spec = r.verify_release(directory, key, env)
    r.require(manifest["release_id"] == expected_release, "stable path/release identity mismatch")
    r.verify_signature(promotion, key, env)
    saved = r.load(promotion)
    r.require(set(saved) == {"schema_version", "release_id", "release_sha256", "gates", "promoted_utc"}
              and saved["schema_version"] == 1 and saved["release_id"] == manifest["release_id"]
              and saved["release_sha256"] == r.sha(directory / "release.json"),
              "promotion record is not bound to this release")
    with tempfile.TemporaryDirectory(prefix="repository-export-gates-") as temporary:
        gates = Path(temporary) / "gates.json"
        r.write(gates, saved["gates"])
        r.gates_check(directory, manifest, release_spec, gates)
    return manifest


def describe(root, key, env, *, release_id=None):
    managed_directory(root)
    for name in ("stable", "promotions", "withdrawals"):
        directory = root / name
        if directory.exists() or directory.is_symlink():
            managed_directory(directory)
    r.storage_check(root)
    sources, files, links = {}, {}, {}
    selected = root / "stable/current"
    rid = None
    if release_id is not None:
        rid = r.valid_name(release_id)
    elif selected.is_symlink():
        rid = r.valid_name(os.readlink(selected))
    else:
        r.require(not selected.exists(), "stable/current must be a managed symlink")
    if rid is not None:
        r.require(not (root / "withdrawals" / f"{rid}.json").exists(), "selected release is withdrawn")
        directory, promotion = root / "stable" / rid, root / "promotions" / f"{rid}.json"
        observed, aliases = tree(directory)
        stable(directory, promotion, key, env, rid)
        files.update({"release/" + name: pin for name, pin in observed.items()})
        links.update({"release/" + name: target for name, target in aliases.items()})
        sources.update({"release/" + name: directory / name for name in observed})
        for suffix in ("", ".sig"):
            path = Path(str(promotion) + suffix)
            regular(path)
            name = "promotion.json" + suffix
            sources[name], files[name] = path, r.sha(path)
    withdrawals = root / "withdrawals"
    if withdrawals.exists():
        entries = sorted(withdrawals.iterdir())
        r.require(len(entries) <= MAX_FILES and all(p.name.endswith((".json", ".json.sig")) for p in entries),
                  "unexpected withdrawal member")
        names = {p.name for p in entries}
        records = [p for p in entries if p.name.endswith(".json")]
        r.require(names == {name for p in records for name in (p.name, p.name + ".sig")},
                  "partial withdrawal record")
        for path in records:
            regular(path)
            regular(Path(str(path) + ".sig"))
            r.verify_signature(path, key, env)
            value = r.load(path)
            wid = r.valid_name(path.name[:-5])
            r.require(set(value) == {"schema_version", "release_id", "signer", "withdrawn_utc", "reason",
                                     "reason_sha256", "packages_retained"}
                      and value["schema_version"] == 1 and value["release_id"] == wid
                      and value["signer"] == key and value["packages_retained"] is True
                      and isinstance(value["reason"], str) and value["reason"]
                      and r.HEX.fullmatch(value["reason_sha256"]), "invalid withdrawal record")
            for suffix in ("", ".sig"):
                source = Path(str(path) + suffix)
                name = "withdrawals/" + source.name
                sources[name], files[name] = source, r.sha(source)
    r.require(rid is not None or files, "no stable selection or signed withdrawals to export")
    r.require(len(files) + len(links) <= MAX_FILES and sum(p.stat().st_size for p in sources.values()) <= MAX_BYTES,
              "complete endpoint exceeds bound")
    plan = {"schema_version": 1, "purpose": "local-repository-endpoint", "selected_release": rid,
            "signer": key, "files": files, "symlinks": links}
    return plan, sources


def generation_check(directory, plan):
    r.require(directory.is_dir() and not directory.is_symlink(), "generation missing or symlink")
    files, links = tree(directory)
    r.require(files.pop("export.json", None) == digest(encoded(plan)) and files == plan["files"]
              and links == plan["symlinks"], "generation differs from its complete export plan")


def endpoint_state(endpoint):
    r.require(set(p.name for p in endpoint.iterdir()) <= {"generations", "current"}, "foreign endpoint entries refused")
    generations = endpoint / "generations"
    if generations.exists() or generations.is_symlink():
        managed_directory(generations)
        for path in generations.iterdir():
            r.require(re.fullmatch(r"[0-9a-f]{64}", path.name), "foreign generation refused")
            managed_directory(path)
    current = endpoint / "current"
    if not current.is_symlink():
        r.require(not current.exists(), "endpoint current must be a managed symlink")
        return None
    target = os.readlink(current)
    r.require(GENERATION.fullmatch(target), "unmanaged endpoint selection refused")
    directory = endpoint / target
    generation_plan(directory)
    return target


def generation_plan(directory):
    """Authenticate a retained generation's complete canonical file/link map."""
    regular(directory / "export.json")
    raw = (directory / "export.json").read_bytes()
    r.require(digest(raw) == directory.name, "generation identity mismatch")
    plan = json.loads(raw)
    r.require(encoded(plan) == raw, "noncanonical generation plan")
    generation_check(directory, plan)
    return plan


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def copy_file(source, destination, expected):
    regular(source)
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        r.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "copy source changed type")
        h, count = hashlib.sha256(), 0
        with os.fdopen(os.dup(fd), "rb") as stream, destination.open("xb") as output:
            for block in iter(lambda: stream.read(1024**2), b""):
                count += len(block)
                r.require(count <= MAX_BYTES, "copy exceeds byte bound")
                h.update(block)
                output.write(block)
            output.flush()
            os.fchmod(output.fileno(), 0o444)
            os.fsync(output.fileno())
        r.require(h.hexdigest() == expected and count == info.st_size, "source changed while copying")
    finally:
        os.close(fd)


def select(endpoint, target):
    temporary = tempfile.TemporaryDirectory(prefix=".selection-", dir=endpoint)
    committed, uncertain = False, False
    try:
        link = Path(temporary.name) / "current"
        link.symlink_to(target)
        os.replace(link, endpoint / "current")  # Visibility commit point.
        committed = True
    finally:
        try:
            temporary.cleanup()
        except OSError:
            if not committed:
                raise
            uncertain = True
    return uncertain


def export(root, endpoint, home, key, apply=False):
    root, endpoint, home = map(canonical, (root, endpoint, home))
    managed_directory(root)
    managed_directory(endpoint)
    r.require(not root.is_relative_to(endpoint) and not endpoint.is_relative_to(root), "source/endpoint overlap refused")
    r.require(not home.is_relative_to(endpoint), "GPG home must stay outside endpoint")
    key, env = r.fingerprint(key), r.gpg_env(home, root)
    with locks(root, endpoint):
        previous = endpoint_state(endpoint)
        plan, sources = describe(root, key, env)
        def recheck():
            r.require(describe(root, key, env)[0] == plan, "source selection changed during export")
        return materialize(root, endpoint, key, env, previous, plan, sources, recheck, apply)


def materialize(root, endpoint, key, env, previous, plan, sources, recheck, apply=False):
    """Shared copy/selection engine; caller must hold locks and authenticate inputs.

    recheck reauthenticates the complete source view immediately before retention
    and selection. It must reject any state drift; it never changes selection.
    """
    ident = digest(encoded(plan))
    result = {"status": "planned-local-endpoint", "generation": ident, "selected_release": plan["selected_release"],
              "previous_selection": previous, "plan": plan,
              "network_published": False, "trust_changed": False}
    if not apply:
        return result
    generations = endpoint / "generations"
    generations.mkdir(exist_ok=True, mode=0o755)
    destination = generations / ident
    if destination.exists():
        generation_check(destination, plan)
    else:
        with tempfile.TemporaryDirectory(prefix=".export-", dir=endpoint) as temporary:
            staging = Path(temporary) / "generation"
            staging.mkdir(mode=0o755)
            for name, source in sorted(sources.items()):
                path = staging / name
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                copy_file(source, path, plan["files"][name])
            for name, target in sorted(plan["symlinks"].items()):
                path = staging / name
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                path.symlink_to(target)
            record = staging / "export.json"
            record.write_bytes(encoded(plan))
            record.chmod(0o444)
            with record.open("rb") as stream:
                os.fsync(stream.fileno())
            generation_check(staging, plan)
            if plan["selected_release"] is not None:
                stable(staging / "release", staging / "promotion.json", key, env, plan["selected_release"])
            recheck()
            for parent, directories, names in os.walk(staging, topdown=False):
                sync_directory(Path(parent))
            os.rename(staging, destination)
            sync_directory(generations)
    r.require(endpoint_state(endpoint) == previous, "endpoint selection changed during export")
    recheck()
    target = "generations/" + ident
    uncertain = select(endpoint, target) if previous != target else False
    result.update(status="materialized-local-endpoint", selection=target, durability_uncertain=uncertain)
    try:
        sync_directory(endpoint)
    except OSError:
        result["durability_uncertain"] = True
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ("root", "endpoint", "gpg-home", "key"):
        parser.add_argument("--" + argument, required=True)
    parser.add_argument("--apply", action="store_true", help="materialize and atomically select the local generation")
    args = parser.parse_args()
    print(json.dumps(export(args.root, args.endpoint, args.gpg_home, args.key, args.apply), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (r.Error, KeyError, TypeError, ValueError, OSError) as error:
        print(f"repository export error: {error}", file=sys.stderr)
        sys.exit(1)
