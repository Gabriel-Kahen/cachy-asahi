#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Report proposed source/recipe drift from one authenticated local release."""
import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import sys


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


r = module("pin_release", "release.py")
s = module("pin_source_delivery", "source_delivery.py")
MAX_JSON, MAX_TOTAL, MAX_OUTPUT = 4 * 1024**2, 8 * 1024**2, 32 * 1024**2
MAX_PACKAGES, MAX_SOURCES, MAX_ALL_SOURCES = 4096, 128, 16384


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value, *, compact=False):
    encoder = json.JSONEncoder(sort_keys=True, indent=None if compact else 2, allow_nan=False,
                               separators=(",", ":") if compact else None)
    output = bytearray()
    for chunk in encoder.iterencode(value):
        # Reserve the final newline. Character count is a UTF-8 lower bound,
        # so oversized chunks can refuse without allocating encoded bytes.
        r.require(len(chunk) < MAX_OUTPUT - len(output), "report byte bound")
        for start in range(0, len(chunk), 4096):
            raw = chunk[start:start + 4096].encode("utf-8")
            r.require(len(raw) < MAX_OUTPUT - len(output), "report byte bound")
            output.extend(raw)
    r.require(len(output) < MAX_OUTPUT, "report byte bound")
    output.append(10)
    return bytes(output)


def decode(raw):
    r.require(len(raw) <= MAX_JSON, "JSON byte bound")
    def pairs(items):
        value = {}
        for key, item in items:
            r.require(key not in value, "duplicate JSON key")
            value[key] = item
        return value
    def invalid(value):
        raise r.Error("nonfinite JSON number")
    def number(value):
        parsed = float(value)
        r.require(math.isfinite(parsed), "nonfinite JSON number")
        return parsed
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid, parse_float=number)
    r.require(type(value) is dict, "JSON object required")
    return value


def fields(value, keys):
    r.require(type(value) is dict and set(value) == set(keys), "unexpected snapshot fields")


def project(value):
    """Use the existing provenance subtrees; never interpret or fetch a URL."""
    package = value["package"]
    fields(package, ("name", "version", "arch"))
    r.valid_name(package["name"])
    r.require(len(package["name"]) <= 128, "package name bound")
    r.text_field(package, "version")
    r.require(len(package["version"]) <= 256 and not any(c.isspace() or c == "\x00" for c in package["version"]),
              "package version bound")
    r.require(package["arch"] in ("aarch64", "any"), "package architecture")
    recipe, sources = value["recipe_sha256"], value["sources"]
    r.require(type(recipe) is str and r.HEX.fullmatch(recipe), "recipe SHA-256 required")
    r.require(type(sources) is list and 0 < len(sources) <= MAX_SOURCES, "source count bound")
    for src in sources:
        r.require(type(src) is dict, "provenance source object required")
        r.text_field(src, "url")
        # Same inclusive OR as release.provenance_check: preserve both pins,
        # descriptor extras, duplicate descriptors and source-list ordering.
        r.require((type(src.get("sha256")) is str and r.HEX.fullmatch(src["sha256"])) or
                  (type(src.get("commit")) is str and re.fullmatch(r"[0-9a-f]{40}", src["commit"])),
                  "source is not pinned by SHA-256 or full Git commit")
    return {"package": package, "recipe_sha256": recipe, "sources": sources}


def indexed(rows):
    r.require(type(rows) is list and len(rows) <= MAX_PACKAGES, "package count bound")
    result, count = {}, 0
    for row in rows:
        projected = project(row)
        name = projected["package"]["name"]
        r.require(name not in result, "duplicate package name")
        result[name] = projected
        count += len(projected["sources"])
        r.require(count <= MAX_ALL_SOURCES, "total source count bound")
    return result


def candidate(raw, checksum):
    r.require(type(checksum) is str and r.HEX.fullmatch(checksum) and digest(raw) == checksum,
              "candidate checksum mismatch")
    value = decode(raw)
    fields(value, ("schema_version", "packages"))
    r.require(type(value["schema_version"]) is int and value["schema_version"] == 1, "snapshot schema")
    r.require(type(value["packages"]) is list and len(value["packages"]) <= MAX_PACKAGES, "snapshot package count bound")
    for row in value["packages"]:
        fields(row, ("package", "recipe_sha256", "sources"))
    return indexed(value["packages"])


def comparison(before, after):
    changes, unchanged = [], []
    for name in sorted(before.keys() & after.keys()):
        left, right = before[name], after[name]
        changed = [key for key in ("package", "recipe_sha256", "sources")
                   if encoded(left[key], compact=True) != encoded(right[key], compact=True)]
        if changed:
            changes.append({"name": name, "fields": changed, "before": left, "after": right})
        else:
            unchanged.append(name)
    missing, extra = sorted(before.keys() - after.keys()), sorted(after.keys() - before.keys())
    return {"coverage": {"scope": "project-built-release-provenance", "missing": missing, "extra": extra,
                         "exact_package_set": not missing and not extra},
            "changes": changes, "unchanged": unchanged}


def check_source_pins(release, snapshot, checksum, key, env):
    release, snapshot = Path(release).absolute(), Path(snapshot).absolute()
    r.require(all(not str(path).startswith("//") and ".." not in path.parts for path in (release, snapshot)),
              "input path alias refused")
    key = r.fingerprint(key)
    # Descriptor-relative no-follow readers reject symlink ancestors, special
    # files, multiple links and observed changes while reading.
    manifest_raw = s.read_file(release / "release.json", MAX_JSON)
    manifest = decode(manifest_raw)
    r.require(type(manifest.get("packages")) is list and 0 < len(manifest["packages"]) <= MAX_PACKAGES,
              "release package count bound")
    candidate_raw = s.read_file(snapshot, MAX_JSON)
    after = candidate(candidate_raw, checksum)
    verified, release_spec = r.verify_release(release, key, env)
    r.require(verified == manifest and s.read_file(release / "release.json", MAX_JSON) == manifest_raw,
              "release manifest changed")
    spec_raw = s.read_file(release / "spec.json", MAX_JSON)
    r.require(digest(spec_raw) == manifest["files"]["spec.json"] and decode(spec_raw) == release_spec,
              "release specification changed")
    total, rows, retained = len(candidate_raw), [], {}
    r.require(len({p["name"] for p in manifest["packages"]}) == len(manifest["packages"]),
              "duplicate release package name")
    for package in manifest["packages"]:
        path = package["provenance"]
        r.require(path not in retained, "duplicate provenance path")
        raw = s.local_read(release, path, min(MAX_JSON, MAX_TOTAL - total))
        total += len(raw)
        r.require(total <= MAX_TOTAL and digest(raw) == manifest["files"][path], "signed provenance checksum/bound mismatch")
        row = decode(raw)
        r.provenance_check(package, row, package["sha256"], release_spec)
        rows.append(row)
        retained[path] = raw
    before = indexed(rows)
    r.require(set(before) == set(release_spec["policy"]["selected_packages"]), "release selection/provenance mismatch")
    result = {"schema_version": 1, "purpose": "release-source-pin-preview", "signer": key,
              "release": {"release_id": manifest["release_id"], "release_sha256": digest(manifest_raw),
                          "source_commit": release_spec["source_commit"], "synthetic": release_spec.get("synthetic", False),
                          "provenance_sha256": {path: digest(raw) for path, raw in sorted(retained.items())}},
              "candidate": {"sha256": checksum, "authenticated": False},
              **comparison(before, after), "base_source_pins_checked": False,
              "freshness_established": False, "build_dependencies_checked": False,
              "stable_eligibility_checked": False, "installation_authorized": False}
    r.require(len(encoded(result)) <= MAX_OUTPUT, "report byte bound")
    # A report is returned only after final verification and exact raw rereads.
    final, final_spec = r.verify_release(release, key, env)
    r.require(final == manifest and final_spec == release_spec and
              s.read_file(release / "release.json", MAX_JSON) == manifest_raw and
              s.read_file(release / "spec.json", MAX_JSON) == spec_raw, "release changed during preview")
    for path, raw in retained.items():
        r.require(s.local_read(release, path, MAX_JSON) == raw, "provenance changed during preview")
    r.require(s.read_file(snapshot, MAX_JSON) == candidate_raw, "candidate changed during preview")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("release", "candidate", "candidate-sha256", "key", "gpg-home"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    env = r.gpg_env(args.gpg_home, Path(args.release).absolute())
    print(encoded(check_source_pins(args.release, args.candidate, args.candidate_sha256, args.key, env)).decode(), end="")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (r.Error, s.Error, OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        print(f"source pin preview error: {error}", file=sys.stderr)
        sys.exit(1)
