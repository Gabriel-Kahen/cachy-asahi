#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare one unissued Build Tools ARM4K Source from exact local Git objects."""

import argparse
import ast
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parent))

from actor import adapt_actor, adapt_tools
from probe import adapt_probe
from reader import adapt_projection, adapt_reader

PACKAGE_COMMIT = "78c44877d4966fd85a8112cd33daeee3d80137a0"
PARENT = "97a44c4c7cb206704bf76e9fd1f1afb2266278c2"
PARENT_TREE = "81d61d9e1f33c1638e9f67fbd7e39b158c603451"
PARENT_MAP_SHA256 = "fac22275902476bd32c9aeb03778a5a97383bb6f65347ec74a7944aefc5edfaa"
MAP = "native/source-map.json"
BUNDLE = "native/build-tools-sources-v2.tar"
CONTRACT = "native/build-tools-contract-v2.json"
ACTOR = "native/build_tools_alpm_v2.py"
TOOLS = "native/build_tools_tools_v2.py"
PROBE = "native/build_tools_probe_v2.py"
GUEST = "native/build_tools_guest_v2.py"
PROJECTION = "native/build_tools_projection_v2.py"
READER = "native/build_tools_reader_v2.py"
WORKFLOWS = (
    ".github/workflows/native-arm-build.yml",
    ".github/workflows/native-arm-developer-workflows.yml",
)
OPER = "build-tools-alpm-v2"
RELEASES = {
    "0.1.1-2": {
        "package": "packages/tools/cachy-asahi-build-tools", "source_count": 15,
        "payload_count": 11, "tests": 8, "consistency": False,
        "recipe_sha256": "4a143efbdc79fd3209414938899f86f62829f614bcca48ea67765f83fd6d6c26",
        "bundle_sha256": "adb799805a7a95a61faa7baeec6c63f0affb01356c7c05d26c78e0ecef19d4d1",
    },
    "0.2.0-2": {
        "package": "packages/tools/cachy-asahi-build-tools-v2", "source_count": 16,
        "payload_count": 12, "tests": 11, "consistency": True,
        "recipe_sha256": "1227d35952e3bc4cab45d7966f5b84fe6b82993d2f3895b5db708b563c472237",
        "bundle_sha256": "bab016752081c31676b0132d170bbc8797cc16bd246ecdda32104cdb0d1163d3",
    },
}
NAME = "cachy-asahi-build-tools"
NULL_ACTUAL = dict(source=None, ref=None, run=None)
CHANGED = {MAP, BUNDLE, CONTRACT, ACTOR, TOOLS, PROBE, PROJECTION, READER, *WORKFLOWS}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def pin(data):
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def git(repo, *args):
    env = dict(PATH="/usr/bin:/bin", LC_ALL="C", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null",
               GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0",
               GIT_OPTIONAL_LOCKS="0")
    return subprocess.check_output(
        ["/usr/bin/git", "-C", str(repo), "-c", "protocol.allow=never", *args],
        env=env, timeout=60)


def git_files(repo, commit, subtree=None):
    args = ["ls-tree", "-rz", "--full-tree", commit]
    if subtree is not None:
        args += ["--", subtree]
    rows = git(repo, *args).decode().split("\0")
    files = {}
    for row in filter(None, rows):
        header, name = row.split("\t", 1)
        mode, kind, oid = header.split()
        path = PurePosixPath(name)
        require(not path.is_absolute() and path.as_posix() == name
                and ".." not in path.parts and len(path.parts) <= 16 and name not in files
                and kind == "blob" and mode in {"100644", "100755"}, "exact ordinary Git leaf required")
        data = git(repo, "cat-file", "blob", oid)
        expected = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        require(expected == oid and len(data) <= 64 * 1024**2, "exact bounded Git blob required")
        files[name] = (data, int(mode[-3:], 8))
    return files


def source_rows(files):
    return {name: pin(data) | {"mode": mode} for name, (data, mode) in files.items()}


def parent_files(repo):
    require(git(repo, "rev-parse", PARENT + "^{tree}").decode().strip() == PARENT_TREE,
            "exact qualified predecessor tree required")
    files = git_files(repo, PARENT)
    require(len(files) == 200 and sum(len(data) for data, _ in files.values()) <= 128 * 1024**2
            and pin(files[MAP][0])["sha256"] == PARENT_MAP_SHA256,
            "exact predecessor Source200 and map required")
    manifest = json.loads(files[MAP][0])
    require(manifest["actual"] == NULL_ACTUAL
            and manifest["files"] == source_rows({name: row for name, row in files.items() if name != MAP}),
            "predecessor map did not bind the entire source")
    return files, manifest


def package_files(repo, spec):
    package = spec["package"]
    files = {name.removeprefix(package + "/"): row
             for name, row in git_files(repo, PACKAGE_COMMIT, package).items()}
    require(len(files) == spec["source_count"]
            and all(PurePosixPath(name).name == name and mode == 0o644 for name, (_, mode) in files.items()),
            "exact flat current recipe set required")
    recipe = files["PKGBUILD"][0]
    require(pin(recipe)["sha256"] == spec["recipe_sha256"], "package origin recipe pin differs")
    declared = shlex.split(re.search(rb"^source=\(([^)]*)\)", recipe, re.M)[1].decode())
    checksums = shlex.split(re.search(rb"^sha256sums=\(([^)]*)\)", recipe, re.M)[1].decode())
    require(len(set(declared)) == len(declared)
            and set(files) == {"PKGBUILD", ".SRCINFO", *declared}
            and all(pin(files[name][0])["sha256"] == checksum
                    for name, checksum in zip(declared, checksums, strict=True)), "declared source bytes differ")
    metadata = files[".SRCINFO"][0]
    ver, rel = spec["version"].rsplit("-", 1)
    for field, value in (("pkgver", ver), ("pkgrel", rel)):
        require(f"{field}={value}".encode() in recipe.splitlines()
                and f"\t{field} = {value}".encode() in metadata.splitlines(), "recipe version differs")
    owner = git(repo, "show", PACKAGE_COMMIT + ":scripts/checks/package_checks_v2.py")
    require(files["package_checks.py"][0] == owner, "packaged checker differs from exact project owner")
    return files


def package_contract(files, spec):
    provenance = json.loads(files["source-provenance.json"][0])
    require(provenance["version"] == spec["version"] and not provenance["install_hooks"],
            "exact packaged provenance identity and hook policy required")
    payload = {}
    for row in provenance["trusted_code"].values():
        name = row["local_source"]
        path = row["installed_path"].removeprefix("/")
        require(path.startswith("usr/lib/cachy-asahi-build-tools/trusted/")
                and path not in payload and pin(files[name][0]) == {key: row[key] for key in ("bytes", "sha256")},
                "exact installed source provenance required")
        payload[path] = pin(files[name][0]) | {"mode": 0o644}
    for name, path in (
        (NAME, "usr/bin/" + NAME),
        ("README.md", "usr/share/doc/" + NAME + "/README.md"),
        ("source-provenance.json", "usr/share/doc/" + NAME + "/source-provenance.json"),
        ("LICENSE", "usr/share/licenses/" + NAME + "/LICENSE"),
        ("NOTICE", "usr/share/licenses/" + NAME + "/NOTICE"),
    ):
        payload[path] = pin(files[name][0]) | {"mode": 0o755 if name == NAME else 0o644}
    require(len(payload) == spec["payload_count"], "exact expected payload count")
    owner, = (node for node in ast.parse(files["test_package.py"][0]).body
              if isinstance(node, ast.ClassDef) and node.name == "PackageTests")
    names = sorted(node.name for node in owner.body if isinstance(node, ast.FunctionDef)
                   and node.name.startswith("test_"))
    require(len(names) == len(set(names)) == spec["tests"], "exact check() test count")
    return dict(version=spec["version"], archive=f'{NAME}-{spec["version"]}-any.pkg.tar.zst',
                expected_test_count=len(names), expected_test_names=names,
                source_files=source_rows(files), payload_files=payload)


def package_bundle(files, expected_sha256):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:", format=tarfile.USTAR_FORMAT) as tar:
        for name, (data, mode) in sorted(files.items()):
            entry = tarfile.TarInfo("recipe/" + name)
            entry.size = len(data)
            entry.mode = mode
            tar.addfile(entry, io.BytesIO(data))
    raw = stream.getvalue()
    require(len(raw) <= 4 * 1024**2 and pin(raw)["sha256"] == expected_sha256,
            "exact reviewed deterministic package bundle required")
    return raw


def host_archive_pin(repo, version):
    manifest = tomllib.loads(git(repo, "show", PACKAGE_COMMIT + ":manifests/packages.toml").decode())
    package, = (row for row in manifest["packages"] if row["name"] == NAME)
    variant, = package["development_variants"]
    row = package if version == package["candidate_version"] else variant
    require(version == row.get("candidate_version", row.get("version")), "host evidence release differs")
    return dict(bytes=row["host_package_bytes"], sha256=row["host_package_sha256"], mode=0o644)


def revise_contract(repo, old, spec, recipe, bundle):
    previous = json.loads(old)
    version = spec["version"]
    require(previous["recipe"]["version"] == "0.2.0-1" and previous["operation"] == OPER
            and all(value is None for value in previous["actual"].values()), "exact qualified contract schema required")
    previous["recipe"] = recipe
    previous["bundle"].update(pin(bundle) | {"members": spec["source_count"]})
    previous["frozen_host_archive"] = host_archive_pin(repo, version)
    previous["package_origin"] = {
        "commit": PACKAGE_COMMIT, "recipe_path": spec["package"],
        "tree": git(repo, "rev-parse", PACKAGE_COMMIT + ":" + spec["package"]).decode().strip(),
        "predecessor_source": PARENT, "predecessor_contract": pin(old),
    }
    commands = 6 if spec["consistency"] else 5
    observations = 9 if spec["consistency"] else 6
    previous["probe"].update(commands=commands, observations_per_location=observations)
    previous["invocation"].update(
        payload_counts=[spec["payload_count"], 0],
        lifecycle=f"clean-a -> clean-b -> exact archive/payload/provenance -> TEST Required install -> "
                  f"{commands} /usr and moved CLI commands/{observations} observations -> "
                  "remove -> DB/home/trust/cache/reasons/inventory restoration")
    previous["build_pair"]["logical_build_directory"] = "/opt/native-build-tools-alpm-v2/build-current"
    return encoded(previous)


def workflow(raw):
    old_options = b"        default: source184\n        options: [source184, build-tools-alpm-v2]"
    step = b"          cmp --silent .github/workflows/native-arm-build.yml .github/workflows/native-arm-developer-workflows.yml\n"
    require(raw.count(old_options) == raw.count(step) == 1, "exact workflow adaptation seams required")
    return raw.replace(old_options, b"        default: build-tools-alpm-v2\n        options: [build-tools-alpm-v2]").replace(
        step, step + b'          test "$(getconf PAGESIZE)" = 4096\n')


def render(repo, version, parent=None):
    spec = RELEASES[version] | {"version": version}
    original, manifest = parent_files(repo) if parent is None else parent
    files = dict(original)
    manifest = dict(manifest)
    package = package_files(repo, spec)
    recipe = package_contract(package, spec)
    spec.update(test_names=recipe["expected_test_names"], source_names=sorted(package))
    bundle = package_bundle(package, spec["bundle_sha256"])
    require(original[WORKFLOWS[0]] == original[WORKFLOWS[1]], "qualified workflow aliases must be identical")
    changed = {
        BUNDLE: bundle, CONTRACT: revise_contract(repo, files[CONTRACT][0], spec, recipe, bundle),
        ACTOR: adapt_actor(files[ACTOR][0], spec), TOOLS: adapt_tools(files[TOOLS][0], spec),
        PROBE: adapt_probe(files[PROBE][0], spec),
        **{name: workflow(files[name][0]) for name in WORKFLOWS},
    }
    producer_pins = {name: pin(changed[name] if name in changed else files[name][0])["sha256"]
                     for name in (ACTOR, TOOLS, GUEST, PROBE, CONTRACT)}
    changed[PROJECTION] = adapt_projection(files[PROJECTION][0], producer_pins)
    changed[READER] = adapt_reader(files[READER][0], spec, producer_pins)
    for name, raw in changed.items():
        if name.endswith(".py"):
            compile(raw, name, "exec")
        files[name] = (raw, files[name][1])
    manifest["build_tools_release"] = {"version": version, "package_commit": PACKAGE_COMMIT, "predecessor": PARENT}
    manifest["files"] = source_rows({name: row for name, row in files.items() if name != MAP})
    files[MAP] = (encoded(manifest), files[MAP][1])
    require({name for name in files if files[name] != original[name]} == CHANGED and len(manifest["files"]) == 199,
            "exact closed Source200 delta required")
    return files


def write_source(output, files):
    require(output.is_absolute() and output.parent.resolve(strict=True) / output.name == output,
            "fresh absolute source directory required")
    output.mkdir(mode=0o700)
    try:
        for name, (raw, mode) in sorted(files.items()):
            path = output / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(raw)
            path.chmod(mode)
    except BaseException:
        shutil.rmtree(output)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument("--release", choices=tuple(RELEASES), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repo = args.repo.resolve(strict=True)
    require(not args.output.is_relative_to(repo), "output must be outside the repository")
    files = render(repo, args.release)
    write_source(args.output, files)
    print(json.dumps({"version": args.release, "package_commit": PACKAGE_COMMIT, "predecessor": PARENT,
                      "source_map_sha256": pin(files[MAP][0])["sha256"], "source_files": len(files),
                      "native": "NOT RUN", "installation": "NOT RUN"}, sort_keys=True))


if __name__ == "__main__":
    main()
