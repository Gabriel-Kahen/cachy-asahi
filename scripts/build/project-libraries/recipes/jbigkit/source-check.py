# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Validate the finite public source pack without private archive access or actors."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import shlex
import stat
import tarfile


def sha(body):
    return hashlib.sha256(body).hexdigest()


def need(condition, message):
    if not condition:
        raise ValueError(message)


def recipe_inputs(text):
    arrays = []
    for name in ("source", "sha256sums"):
        match = re.search(r"^" + name + r"=\(([^)]*)\)$", text, re.M)
        need(match is not None, "literal input array")
        values = shlex.split(match[1], comments=True)
        need(values and all(re.fullmatch(r"[A-Za-z0-9_.-]+", x) for x in values), "literal input value")
        arrays.append(values)
    names, hashes = arrays
    need(len(names) == len(set(names)) == len(hashes), "input cardinality")
    need(all(re.fullmatch(r"[a-f0-9]{64}", x) for x in hashes), "fixed SHA256 required")
    need(not {"jbigkit-2.2.tar.gz", "jbigkit-2.2.original.tar.gz", "upstream-licensing.html.txt"} & set(names), "private/prose input forbidden")
    need("jbigkit-2.2-project-filtered.tar.gz" in names, "self-contained filtered input required")
    return dict(zip(names, hashes))


def archive_inventory(body, manifest):
    need(len(body) == manifest["filtered_bytes"] and sha(body) == manifest["filtered_sha256"], "filtered archive pin")
    with gzip.GzipFile(fileobj=io.BytesIO(body)) as stream:
        raw = stream.read(16777217)
    need(len(raw) <= 16777216, "decoded byte cap")
    files, directories = {}, set()
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r|") as stream:
        count = 0
        for member in stream:
            count += 1
            name = member.name
            need(count <= 2048 and (name == "jbigkit-2.2" or name.startswith("jbigkit-2.2/")), "member scope")
            need("\\" not in name and all(x not in ("", ".", "..") for x in name.split("/")), "member path")
            need(name not in files and name not in directories, "duplicate member")
            need(member.isfile() or member.isdir(), "member type")
            need(0 <= member.size <= 1048576, "member size")
            need(member.mtime == 1791585070 and member.uid == member.gid == 0, "normalized source metadata")
            if member.isdir():
                directories.add(name)
            else:
                content = stream.extractfile(member).read(member.size + 1)
                need(len(content) == member.size, "truncated source")
                files[name] = {"name": name, "kind": "file", "size": len(content), "sha256": sha(content)}
    wanted = {row["name"]: row for row in manifest["included_files"]}
    excluded = {row["name"] for row in manifest["excluded_files"]}
    need(len(wanted) == len(files) == 37 and len(excluded) == 13, "37/13 source scope")
    need(files == wanted and not set(files) & excluded, "exact included inventory")
    expected_dirs = {"/".join(name.split("/")[:i]) for name in wanted for i in range(1, len(name.split("/")))}
    need(directories == expected_dirs and len(directories) == 5, "exact directory inventory")
    return files, directories


def public_bundle_schema(actual_names, inputs):
    need(set(actual_names) == set(inputs) | {"PKGBUILD"}, "exact public rebuild pack membership")


def ordinary(path):
    need(stat.S_ISREG(path.lstat().st_mode) and path.stat().st_size <= 1048576, "ordinary bounded input")
    return path.read_bytes()


def validate(root, recipe, tree=None, patched=False, bundle=None):
    inputs = recipe_inputs(recipe.read_text())
    for name, digest in inputs.items():
        need(sha(ordinary(root / name)) == digest, "input checksum: " + name)
    manifest = json.loads(ordinary(root / "source-filter.json"))
    files, directories = archive_inventory(ordinary(root / "jbigkit-2.2-project-filtered.tar.gz"), manifest)
    if tree:
        for name in directories:
            relative = name.removeprefix("jbigkit-2.2").lstrip("/")
            need(stat.S_ISDIR((tree / relative).lstat().st_mode), "ordinary tree directory")
        modified = {x["source_member"]: x["project_patch_sha256"] for x in json.loads(ordinary(root / "inputs.json"))["patched_makefiles"]} if patched else {}
        for name, row in files.items():
            relative = name.removeprefix("jbigkit-2.2/")
            need(sha(ordinary(tree / relative)) == modified.get(relative, row["sha256"]), "tree source: " + relative)
    if bundle:
        need(stat.S_ISDIR(bundle.lstat().st_mode), "ordinary public bundle directory")
        public_bundle_schema([x.name for x in bundle.iterdir()], inputs)
        for name, digest in inputs.items():
            need(sha(ordinary(bundle / name)) == digest, "public bundle checksum")
        need(ordinary(bundle / "PKGBUILD") == ordinary(recipe), "public recipe checksum")
    return {"inputs": len(inputs), "source_files": len(files), "directories": len(directories),
            "private_archive_required": False, "public_rebuild_pack_verified": bool(bundle),
            "upstream_actor_executed": False, "public_redistribution_accepted": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--srcdir", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--recipe", type=Path, default=Path(__file__).resolve().parent / "PKGBUILD")
    parser.add_argument("--tree", type=Path)
    parser.add_argument("--patched", action="store_true")
    parser.add_argument("--public-bundle", type=Path)
    args = parser.parse_args()
    need(not args.patched or args.tree is not None, "patched requires tree")
    print(json.dumps(validate(args.srcdir, args.recipe, args.tree, args.patched, args.public_bundle), sort_keys=True))
