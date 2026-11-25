# SPDX-License-Identifier: MIT
"""Inspect the native JBIG/TIFF package pair without installing or loading it."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tarfile

from baseline import JBIG_PROVIDER
from materialize import need, sha
from prepare import load_plan, verify_recipe
from package_checks import conflicts, package

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from build_v2 import bind_artifact

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "platform"))
from elf_audit import parse_elf


C_RUNTIME = {"libc.so.6"}
TOOLCHAIN = {"ld-linux-aarch64.so.1", "libgcc_s.so.1"}
LIBRARIES = {
    "jbigkit": {
        "libjbig.so.2.2": C_RUNTIME,
        "libjbig85.so.2.2": C_RUNTIME,
    },
    "libtiff": {
        "libtiff.so.6": C_RUNTIME | {
            "libdeflate.so.0", "libjpeg.so.8", "libjbig.so.2.2", "liblzma.so.5",
            "libm.so.6", "libwebp.so.7", "libz.so.1", "libzstd.so.1",
        },
        "libtiffxx.so.6": C_RUNTIME | {"libstdc++.so.6", "libtiff.so.6"},
    },
}
GENERATED = {
    "actual-build/CMakeCache.txt", "actual-build/compile_commands.json",
    "actual-build/libtiff/tif_config.h", "actual-build/libtiff/tiffconf.h",
    "actual-build/libtiff/tiffvers.h", "actual-build/test-selection.json",
    "release-association-status.json",
}


def member_bytes(archive, path, member):
    need(member["type"] == "0" and 0 < member["size"] <= 8 * 2**20, f"bounded regular member: {path}")
    data = subprocess.check_output(["bsdtar", "-xOf", str(archive.resolve()), "--", path], timeout=30)
    need(len(data) == member["size"] and sha(data) == member["sha256"], f"archive member changed: {path}")
    return data


def check_sources(archive, name, members, expected):
    tiff = name == "libtiff"
    prefix = ("usr/share/cachy-asahi-libtiff/corresponding-source/" if tiff
              else "usr/share/doc/cachy-asahi-jbigkit/source/")
    source = {path.removeprefix(prefix): row for path, row in members.items()
              if path.startswith(prefix) and row["type"] != "5"}
    pins = {("recipe/" if tiff else "") + path: pin for path, pin in expected.items()}
    need(source.keys() == (pins.keys() | GENERATED | {"inventory.json"} if tiff else pins.keys()),
         f"{name} packaged corresponding-source file set")
    need(all(row["type"] == "0" and row["mode"] == 0o644 for row in source.values()),
         f"{name} packaged corresponding-source file type/mode")
    need(all(source[path]["sha256"] == pin for path, pin in pins.items()),
         f"{name} packaged corresponding-source checksum")
    if tiff:
        inventory = json.loads(member_bytes(archive, prefix + "inventory.json", source["inventory.json"]))
        expected_inventory = {path: {"sha256": row["sha256"], "bytes": row["size"]}
                              for path, row in source.items() if path != "inventory.json"}
        need(inventory == expected_inventory, "TIFF generated-source inventory differs from payload")
    return len(source)


def check_notices(directory, name, members, expected):
    if name == "jbigkit":
        notice_names = ("COPYING", "LICENSE.recipe", "NOTICE", "upstream-ANNOUNCE", "packaging-REUSE.toml")
        notices = {path: expected[path] for path in notice_names}
    else:
        notice_names = ("LICENSE.MIT", "PUBLICATION.md", "UPSTREAM-NOTICES.txt")
        notices = {path: expected[path] for path in notice_names}
        source_filter = json.loads((directory / "source-filter.json").read_text())
        notices["LICENSE.md"] = source_filter["allowlist"]["LICENSE.md"]["sha256"]
    for filename, pin in notices.items():
        path = f"usr/share/licenses/cachy-asahi-{name}/{filename}"
        row = members.get(path, {})
        need(row.get("type") == "0" and row["mode"] == 0o644 and row["sha256"] == pin,
             f"packaged notice: {path}")


def check_library(archive, soname, members, required):
    versioned = "usr/lib/" + soname
    link = "usr/lib/" + soname.split(".so.", 1)[0] + ".so"
    development = members.get(link, {})
    need(development.get("type") == "2" and development["link"] == soname,
         f"development symlink: {link}")
    target = members.get(versioned, {})
    if target.get("type") == "2":
        suffix = target["link"].removeprefix(soname + ".")
        need(suffix != target["link"] and all(piece.isascii() and piece.isdecimal() for piece in suffix.split(".")),
             f"versioned symlink: {soname}")
        versioned = "usr/lib/" + target["link"]
    need(versioned in members, f"SONAME payload: {soname}")
    elf = parse_elf(member_bytes(archive, versioned, members[versioned]))
    need(elf and elf["classification"] == "aarch64-loadable-elf" and elf["type"] == 3 and
         elf["interpreter"] is None and elf["soname"] == soname, f"AArch64 SONAME: {soname}")
    needed = set(elf["needed"])
    optional = TOOLCHAIN | ({"libm.so.6"} if soname == "libtiffxx.so.6" else set())
    need(len(needed) == len(elf["needed"]) and required <= needed <= required | optional and
         elf["rpath"] is None and elf["runpath"] is None, f"dynamic dependencies or paths: {soname}")
    return {"path": versioned, "needed": sorted(needed), "sha256": members[versioned]["sha256"]}


def inspect(archives, recipe_root):
    plan = load_plan(lambda label: None)
    reports = {}
    observations = {}
    for name, archive in archives.items():
        directory = recipe_root / name
        review = verify_recipe(directory, name, plan)
        report = reports[name] = package(archive)
        need(not report["errors"], f"{name} package checks: {report['errors']}")
        expected = review["input_sha256"]
        errors = bind_artifact(review["metadata"], report, expected["PKGBUILD"])
        need(not errors, f"{name} packaged metadata and recipe identity: {errors}")
        buildinfo = report["metadata"][".BUILDINFO"]
        if name == "libtiff":
            need("-".join((*JBIG_PROVIDER, "aarch64")) in buildinfo.get("installed", []),
                 "TIFF build inventory is missing the project JBIG provider")
        members = report["members"]
        check_notices(directory, name, members, expected)
        observations[name] = {
            "archive_sha256": report["sha256"],
            "source_files": check_sources(archive, name, members, expected),
            "libraries": {soname: check_library(archive, soname, members, needed)
                          for soname, needed in LIBRARIES[name].items()},
        }
    need(not conflicts(reports.values()), "project package payloads conflict")
    return observations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jbigkit", type=Path, required=True)
    parser.add_argument("--libtiff", type=Path, required=True)
    parser.add_argument("--recipes", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(inspect({"jbigkit": args.jbigkit, "libtiff": args.libtiff}, args.recipes),
                         indent=2, sort_keys=True))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, tarfile.TarError) as error:
        parser.exit(1, f"Package pair inspection failed: {error}\n")


if __name__ == "__main__":
    main()
