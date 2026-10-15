#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Preview differences between two authenticated local release bundles."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location("comparison_release", Path(__file__).with_name("release.py"))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


def directory(value):
    path = Path(value).absolute()
    r.require(not str(path).startswith("//") and ".." not in path.parts and
              not any(p.is_symlink() for p in (path, *path.parents)), "release path aliases/symlinks forbidden")
    r.require(path.is_dir(), "release directory missing")
    return path


def indexed(rows, label):
    result = {row["name"]: row for row in rows}
    r.require(len(result) == len(rows), "duplicate " + label)
    return result


def changes(before, after):
    return [{"name": name, "before": before.get(name), "after": after.get(name)}
            for name in sorted(before.keys() | after.keys()) if before.get(name) != after.get(name)]


def metadata(package):
    return {key: sorted(value) if isinstance(value, list) else value
            for key, value in package.items() if key not in ("filename", "provenance", "sha256")}


def package_changes(before, after, artifacts=False):
    result = []
    for name in sorted(before.keys() | after.keys()):
        left, right = before.get(name), after.get(name)
        if left is None or right is None:
            result.append({"name": name, "change": "added" if left is None else "removed",
                           "before": left, "after": right})
            continue
        fields = changes(metadata(left), metadata(right))
        byte_change = artifacts and left["sha256"] != right["sha256"]
        artifact_change = artifacts and (byte_change or left["filename"] != right["filename"])
        if not fields and not artifact_change:
            continue
        change = "metadata-changed"
        if left["version"] != right["version"]:
            order = int(r.run(["vercmp", right["version"], left["version"]]).strip())
            change = "upgraded" if order > 0 else "downgraded" if order < 0 else "equivalent-version"
        elif byte_change:
            change = "same-version-byte-change"
        elif artifact_change:
            change = "artifact-renamed"
        result.append({"name": name, "change": change, "before": left, "after": right,
                       "metadata_changes": fields, **({"artifact_bytes_changed": byte_change} if artifacts else {})})
    return result


def verified(directory, key, env):
    # All reported values come from the verified manifest or a payload whose
    # exact bytes join its signed file map, rather than a later unbound reread.
    manifest_raw = (directory / "release.json").read_bytes()
    manifest, release_spec = r.verify_release(directory, key, env)
    r.require((directory / "release.json").read_bytes() == manifest_raw and json.loads(manifest_raw) == manifest,
              "manifest changed during comparison")
    base_raw = (directory / "base.json").read_bytes()
    r.require(hashlib.sha256(base_raw).hexdigest() == manifest["files"]["base.json"], "base changed during comparison")
    packages = indexed(manifest["packages"], "release package")
    for package in packages.values():
        r.require(manifest["files"]["repo/" + package["filename"]] == package["sha256"],
                  "artifact digest differs from signed file map")
    # Bind the returned spec as well: the verifier returns decoded data, not raw bytes.
    spec_raw = (directory / "spec.json").read_bytes()
    r.require(hashlib.sha256(spec_raw).hexdigest() == manifest["files"]["spec.json"] and
              json.loads(spec_raw) == release_spec, "spec changed during comparison")
    return manifest, release_spec, json.loads(base_raw), hashlib.sha256(manifest_raw).hexdigest()


def compare_releases(before, after, key, env):
    before, after, key = directory(before), directory(after), r.fingerprint(key)
    left, old_spec, old_base, old_hash = verified(before, key, env)
    right, new_spec, new_base, new_hash = verified(after, key, env)
    def identity(manifest, release_spec, digest):
        return {"release_id": manifest["release_id"], "release_sha256": digest,
                "source_commit": release_spec["source_commit"], "synthetic": release_spec.get("synthetic", False)}
    def coordinated(policy):
        return {name: row["versions"] for name, row in indexed(policy["coordinated_sets"], "coordinated set").items()}
    old_groups, new_groups = coordinated(old_spec["policy"]), coordinated(new_spec["policy"])
    result = {"schema_version": 1, "purpose": "signed-release-comparison", "signer": key,
              "before": identity(left, old_spec, old_hash), "after": identity(right, new_spec, new_hash),
              "packages": package_changes(indexed(left["packages"], "release package"),
                                          indexed(right["packages"], "release package"), artifacts=True),
              "dependency_inventory": {"before_snapshot": old_base["snapshot_id"], "after_snapshot": new_base["snapshot_id"],
                  "packages": package_changes(indexed(old_base["packages"], "base package"),
                                              indexed(new_base["packages"], "base package"))},
              "coordinated_sets": [{"name": row["name"], "packages": changes(row["before"] or {}, row["after"] or {})}
                                   for row in changes(old_groups, new_groups)],
              "policy": changes({k: sorted(old_spec["policy"][k]) for k in
                                  ("selected_packages", "protected_packages", "supported_models")},
                                {k: sorted(new_spec["policy"][k]) for k in
                                  ("selected_packages", "protected_packages", "supported_models")}),
              "files": changes(left["files"], right["files"]),
              "symlinks": changes(left["symlinks"], right["symlinks"]),
              "stable_eligibility_checked": False}
    # Refuse a source replacement/tamper during reporting. No lock file or
    # selection pointer is created or changed by this utility.
    for path, expected, expected_spec, digest in ((before, left, old_spec, old_hash), (after, right, new_spec, new_hash)):
        manifest, release_spec = r.verify_release(path, key, env)
        r.require(manifest == expected and release_spec == expected_spec and r.sha(path / "release.json") == digest,
                  "release changed during comparison")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("before", "after", "gpg-home", "key"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    before, after = directory(args.before), directory(args.after)
    env = r.gpg_env(args.gpg_home, before)
    r.gpg_env(args.gpg_home, after)
    result = compare_releases(before, after, args.key, env)
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (r.Error, OSError, ValueError, KeyError, TypeError) as error:
        print(f"release comparison error: {error}", file=sys.stderr)
        sys.exit(1)
