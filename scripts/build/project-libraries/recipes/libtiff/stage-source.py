"""MIT. Copy only pinned data into a fresh corresponding-source directory."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

TESTS = {"ascii_tag", "long_tag", "short_tag"}
PACKAGING = ("PKGBUILD", "LICENSE.MIT", "PUBLICATION.md", "UPSTREAM-NOTICES.txt", "source-filter.json", "stage-source.py")
GENERATED = ("libtiff/tif_config.h", "libtiff/tiffconf.h", "libtiff/tiffvers.h", "compile_commands.json", "CMakeCache.txt")

def read(path, cap=8 * 1024 * 1024):
    path = Path(path)
    for component in (path, *path.parents):
        if component.is_symlink():
            raise ValueError("symlink input")
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        facts = os.fstat(fd)
        if not stat.S_ISREG(facts.st_mode) or facts.st_size > cap:
            raise ValueError("input type/size")
        with os.fdopen(fd, "rb") as stream:
            fd = None
            data = stream.read(cap + 1)
    finally:
        if fd is not None:
            os.close(fd)
    if len(data) != facts.st_size:
        raise ValueError("input changed/oversize")
    return data

def sha(data):
    return hashlib.sha256(data).hexdigest()

def check_tests(data):
    value = json.loads(data)
    names = [row["name"] for row in value["tests"]]
    if len(names) != 3 or set(names) != TESTS:
        raise ValueError("exact three CTest memberships required")

def stage(start, build, destination):
    start, build, destination = Path(start), Path(build), Path(destination)
    manifest = json.loads(read(start / "source-filter.json"))
    archive = manifest["project_archive"]["filename"]
    if archive != "libtiff-project-4.7.2-source.tar.gz":
        raise ValueError("literal filtered source filename")
    data = {"recipe/" + n: read(start / n) for n in PACKAGING}
    data["recipe/" + archive] = read(start / archive)
    if sha(data["recipe/" + archive]) != manifest["project_archive"]["sha256"]:
        raise ValueError("filtered archive pin")
    selection = read(build.parent / "test-selection.json", 65536)
    check_tests(selection)
    data["actual-build/test-selection.json"] = selection
    for n in GENERATED:
        body = read(build / n, 8 * 1024 * 1024 if n == "compile_commands.json" else 1024 * 1024)
        if n == "compile_commands.json":
            commands = json.loads(body)
            if not isinstance(commands, list) or not commands or len(commands) > 4096:
                raise ValueError("compile command list")
            for row in commands:
                if not isinstance(row, dict) or not all(isinstance(row.get(k), str) for k in ("file", "directory")):
                    raise ValueError("compile command record")
                if not isinstance(row.get("command"), str) and not (isinstance(row.get("arguments"), list) and all(isinstance(x, str) for x in row["arguments"])):
                    raise ValueError("compile command arguments")
        elif b"\0" in body or not body.decode("utf-8").strip():
            raise ValueError("generated text format")
        data["actual-build/" + n] = body
    data["release-association-status.json"] = (json.dumps({"provider_release_association": "NOT_RECORDED", "public_promotion": False, "required_post_build": "Root joins actual libtiff binary and own preferred source with exact locked project-jbig binary, source pack, recipe and dependency provenance in the release index."}, sort_keys=True) + "\n").encode()
    if sum(map(len, data.values())) > 32 * 1024 * 1024:
        raise ValueError("output cap")
    for component in (destination, *destination.parents):
        if component.is_symlink():
            raise ValueError("symlink destination")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.mkdir(mode=0o755)  # Existing/partial output is never reused.
    inventory = {}
    for name, body in sorted(data.items()):
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(body)
        inventory[name] = {"bytes": len(body), "sha256": sha(body)}
    with (destination / "inventory.json").open("x") as stream:
        json.dump(inventory, stream, sort_keys=True, indent=2)
        stream.write("\n")
    return inventory

def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    check = sub.add_parser("check-tests")
    check.add_argument("--selection", required=True)
    copy = sub.add_parser("stage")
    for name in ("startdir", "builddir", "destination"):
        copy.add_argument("--" + name, required=True)
    args = parser.parse_args()
    if args.action == "check-tests":
        check_tests(read(args.selection))
    else:
        stage(args.startdir, args.builddir, args.destination)

if __name__ == "__main__":
    main()
