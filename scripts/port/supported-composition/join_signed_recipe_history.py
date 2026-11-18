#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare official Git file snapshots with an existing signed addition index.

The pinned config contains an index reference and candidate rows with package,
repository, commit, path and file_response. File references have absolute
path, size and sha256. Preserve the commit-specific GitHub Contents or Arch
GitLab File response when collecting a candidate. This command is offline.
"""

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("recipe_history_source", ROOT / "scripts/release/source_delivery.py")
source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source)
KIND = "supported-Asahi-signed-recipe-history-DATA"
INDEX = "supported-Asahi-signed-addition-source-index-DATA"
MAX_RESPONSE = 384 * 1024
GITHUB = re.compile(r"https://github\.com/([A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+)")
ARCH = re.compile(r"https://gitlab\.archlinux\.org/(archlinux/packaging/packages/[A-Za-z0-9_.+-]+)")
OID = re.compile(r"[a-f0-9]{40}")


def read_reference(row, limit):
    source.fields(row, ("path", "size", "sha256"))
    path = Path(row["path"])
    source.sha(row["sha256"])
    source.need(path.is_absolute() and str(path) == row["path"] and ".." not in path.parts
                and type(row["size"]) is int and 0 < row["size"] <= limit, "absolute exact evidence reference required")
    raw = source.local_read(path.parent, path.name, limit)
    source.need(len(raw) == row["size"] and source.digest(raw) == row["sha256"], "evidence bytes differ from reference")
    return source.decode(raw)


def match_file(repository, commit, path, record):
    parts = source.relative(path)
    source.need(OID.fullmatch(commit) and parts[-1] == "PKGBUILD"
                and all(re.fullmatch(r"[A-Za-z0-9@._+-]+", part) for part in parts), "exact commit and PKGBUILD path required")
    github, arch = GITHUB.fullmatch(repository), ARCH.fullmatch(repository)
    source.need(github or arch, "supported official Git provider and repository URL required")
    if github:
        coord = github[1]
        source.need(coord.rsplit("/", 1)[1] not in {".", ".."}, "noncanonical GitHub repository path")
        page = f"https://api.github.com/repos/{coord}/contents/{quote(path)}?ref={commit}"
        raw_url = f"https://raw.githubusercontent.com/{coord}/{commit}/{quote(path)}"
        source.need(record["type"] == "file" and record["path"] == path and record["url"] == page
                    and record["download_url"] == raw_url, "GitHub file response repository, commit or path differs")
        expected_blob = record["sha"]
    else:
        project = quote(arch[1], safe="")
        page = f"https://gitlab.archlinux.org/api/v4/projects/{project}/repository/files/{quote(path, safe='')}?ref={commit}"
        source.need(record["file_path"] == path and record["ref"] == record["commit_id"] == commit,
                    "Arch GitLab file response commit or path differs")
        expected_blob = record["blob_id"]
    source.need(record["encoding"] == "base64" and type(record["size"]) is int
                and 0 < record["size"] <= 192 * 1024 and OID.fullmatch(expected_blob), "bounded Git blob response required")
    raw = base64.b64decode(record["content"].replace("\n", ""), validate=True)
    sha = source.digest(raw)
    blob = hashlib.sha1(f"blob {len(raw)}\0".encode("ascii") + raw).hexdigest()
    source.need(len(raw) == record["size"] and blob == expected_blob
                and (github or record["content_sha256"] == sha), "Git blob bytes or digest differ")
    return dict(commit=commit, repository=repository, path=path, file_endpoint=page,
                git_blob_sha1=blob, pkgbuild_sha256=sha, bytes=len(raw))


def compare(config, config_sha256):
    source.fields(config, ("kind", "schema_version", "index", "candidates"))
    source.need(config["kind"] == KIND and config["schema_version"] == 1 and type(config["candidates"]) is list
                and 0 < len(config["candidates"]) <= 96, "bounded recipe-history configuration required")
    index = read_reference(config["index"], source.MAX_JSON)
    source.need(index["kind"] == INDEX and index["schema_version"] == 1 and index["production_trust"] is False,
                "signed addition source index required")
    recipes = {row["package"]["name"]: row for row in index["packages"]}
    source.need(len(recipes) == len(index["packages"]) == index["package_count"], "source index package count differs")
    result, seen = [], set()
    for row in config["candidates"]:
        source.fields(row, ("package", "repository", "commit", "path", "file_response"))
        key = (row["package"], row["repository"], row["commit"], row["path"])
        source.need(key not in seen and row["package"] in recipes, "duplicate history request or package absent from source index")
        seen.add(key)
        selected = recipes[row["package"]]
        digest = source.sha(selected["pkgbuild_sha256"])
        file = match_file(row["repository"], row["commit"], row["path"], read_reference(row["file_response"], MAX_RESPONSE))
        status = "EXACT_SIGNED_RECIPE_MATCH" if file["pkgbuild_sha256"] == digest else "SIGNED_RECIPE_DIGEST_MISMATCH"
        result.append(dict(package=selected["package"], pkgbase=selected["pkgbase"], signed_pkgbuild_sha256=digest,
                           file_response=row["file_response"], status=status, **file))
    counts = {status: sum(row["status"] == status for row in result)
              for status in ("EXACT_SIGNED_RECIPE_MATCH", "SIGNED_RECIPE_DIGEST_MISMATCH")}
    return dict(kind=KIND + "-result", schema_version=1, config_sha256=config_sha256, source_index=config["index"],
                counts=counts, results=result, corresponding_source_delivery="REVIEW_REQUIRED")


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--config", type=Path, required=True)
    cli.add_argument("--config-sha256", required=True)
    cli.add_argument("--output", type=Path, required=True)
    args = cli.parse_args()
    try:
        source.sha(args.config_sha256)
        raw = source.local_read(args.config.parent, args.config.name, source.MAX_JSON)
        source.need(source.digest(raw) == args.config_sha256, "config SHA-256 differs")
        result = compare(source.decode(raw), args.config_sha256)
        output = args.output
        source.need(output.is_absolute() and output.parent.resolve(strict=True) == output.parent and output.name not in {".", ".."},
                    "canonical absolute fresh output required")
        encoded = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode()
        with os.fdopen(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as target:
            target.write(encoded)
        print(f"{result['counts']}; result SHA-256 {source.digest(encoded)}")
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        print(f"signed recipe history refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
