#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the separately selected Qtbase package-only steps in a disposable 16 KiB guest."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import sys
import time
from types import SimpleNamespace

MIB = 1 << 20
SCOPE = "cachy-asahi-qtbase16k-package.scope"
PLAN_KIND = "QTBASE16K_PACKAGING_PLAN_UNISSUED_V1"
SELECTION_KIND = "ROOT_QTBASE16K_PACKAGING_WORKER_V1"
PLAN_NAME = "PACKAGING-PLAN.UNISSUED.json"
SELECTION_NAME = "PACKAGING-SELECTION.json"
OUTPUT = "/qtbase-packaging-output"
MEDIA = "/qtmedia/packaging"
RECIPE = "/qt-recipe"
SRC = RECIPE + "/src"
BUILD = SRC + "/build"
RECIPE_NAME = "PKGBUILD.package"
PACKAGE = "cachy-asahi-qt612-gui-server-source-reference"
VERSION = "6.12.0-2"
ARCHIVE = PACKAGE + "-" + VERSION + "-aarch64.pkg.tar.xz"
SMOKE = "PASS_QT612_GUI_SERVER_OFFSCREEN_AND_LOCAL_DISPLAY_API_ONLY"
SHA = re.compile(r"[a-f0-9]{64}")
NONCE = re.compile(r"[a-f0-9]{32}")
FULL_GUEST_PIN = (22247, "1b7d087192f202b595ac04963d5ef38d84362cedc0baf0c32171c3a468560431")
PACKAGE_CHECKER_PIN = (19390, "306ea3dfa1ce4eb14796c0526a8ca9086043bdcb8e6698c0993d640d076f19cd")
SOURCE_ARCHIVE_PIN = (51220268, "a951bd163c7b80fc6b8c88d7668fb56abf91c152373e13c10666763238131307")
STREAM_CAP = 8 * MIB
FILE_CAP = 512 * MIB
FINISH_RESERVE = 45


def need(ok, message):
    if not ok:
        raise ValueError(message)


def pair(body):
    return len(body), hashlib.sha256(body).hexdigest()


def pin(body):
    size, digest = pair(body)
    return dict(bytes=size, sha256=digest)


def selected_pin(value, cap):
    need(type(value) is dict and value.keys() == {"bytes", "sha256"}
         and type(value["bytes"]) is int and 0 < value["bytes"] <= cap
         and type(value["sha256"]) is str and SHA.fullmatch(value["sha256"]), "Expected a finite exact file pin")
    return value["bytes"], value["sha256"]


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def decode(raw, *, canonical=False):
    value = json.loads(raw)
    need(type(value) is dict and (not canonical or wire(value) == raw), "Expected bounded canonical object")
    return value


def ordinary_body(path, limit, *, allow_empty=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and (0 if allow_empty else 1) <= before.st_size <= limit,
             "Expected bounded ordinary packaging input")
        raw = stream.read(before.st_size + 1)
        identify = lambda row: (row.st_dev, row.st_ino, row.st_mode, row.st_size, row.st_mtime_ns, row.st_ctime_ns)
        need(len(raw) == before.st_size and identify(before) == identify(os.fstat(fd)) == identify(path.lstat()),
             "Packaging input changed while reading")
        return raw


def module(raw, path, expected):
    need(pair(raw) == expected, "Exact frozen package helper required")
    namespace = {"__name__": "qtbase_package_helper", "__file__": str(path)}
    exec(compile(raw, str(path), "exec"), namespace)
    return SimpleNamespace(**namespace)


def packaging_sequence(deps):
    shell = 'set -euo pipefail; source "$1"; srcdir=/qt-recipe/src; check'
    makepkg = ["/usr/bin/makepkg", "--config", "/etc/makepkg.conf", "-p", RECIPE_NAME]
    steps = [
        ("inventory", ["/usr/bin/pacman", "-Q"], 90, {"inventory": True}),
        ("dependencies", ["/usr/bin/pacman", "-T", *deps], 90, {"empty": True}),
        ("recipe-source", makepkg + ["--verifysource", "--noconfirm"], 180, {}),
        ("patched-source", ["/usr/bin/python", "-I", "-B", MEDIA + "/recipe/source.py", "verify",
                           "--root", SRC + "/qtbase-everywhere-src-6.12.0",
                           "--policy", MEDIA + "/recipe/source-notices.json"], 240, {}),
        ("configuration", ["/usr/bin/python", "-I", "-B", MEDIA + "/recipe/source.py", "configuration",
                          "--build", BUILD, "--profile", MEDIA + "/recipe/configure.cmake"], 90, {}),
        ("idle-built-tree", ["/usr/bin/ninja", "-C", BUILD, "-n", "all"], 90,
         {"last_line": "ninja: no work to do."}),
        ("recipe-check", ["/usr/bin/bash", "--noprofile", "--norc", "-c", shell, "qtbase-check",
                          RECIPE + "/" + RECIPE_NAME], 600, {"line": SMOKE}),
        ("repackage", makepkg + ["--repackage", "--nosign", "--noconfirm"], 900, {}),
        ("archive-validation", ["/usr/bin/python", "-I", "-B", MEDIA + "/package_checks.py", "artifacts",
                                OUTPUT + "/" + ARCHIVE], 240, {}),
        ("inventory-after", ["/usr/bin/pacman", "-Q"], 90, {"inventory": True}),
    ]
    return [dict(role=role, argv=argv, seconds=seconds, expected=expected, combined_stream_cap=STREAM_CAP)
            for role, argv, seconds, expected in steps]


def worker_contract(g, full, deps, files, completed):
    return dict(uid=1000, gid=1000, architecture="aarch64", runtime_page_bytes=16384,
                networking="offline", cwd=RECIPE, stage_mount=MEDIA, output=OUTPUT,
                exact_build_inputs={name: dict(bytes=size, sha256=digest)
                                    for name, (size, digest) in g.Q3_PINS.items()},
                original_libraries=full.INHERITED, completed_build=completed,
                environment=g.ENV | dict(SRCDEST=RECIPE + "/srcdest", BUILDDIR=RECIPE,
                                         PKGDEST=OUTPUT, BASH_ENV="/dev/null"),
                fresh_paths=[RECIPE + "/" + RECIPE_NAME, SRC + "/smoke-source", SRC + "/smoke-build",
                             SRC + "/smoke-home", SRC + "/stage-contract.json", OUTPUT + "/" + ARCHIVE, RECIPE + "/pkg"],
                stage_recipe=dict(source=MEDIA + "/recipe/PKGBUILD", destination=RECIPE + "/" + RECIPE_NAME,
                                  must_be_absent=True),
                check_source_files={name.removeprefix("recipe/"): pin(body) for name, body in files.items()
                                    if name.startswith("recipe/") and Path(name).name not in {"PKGBUILD", ".SRCINFO"}},
                actions=packaging_sequence(deps))


def archive_contract(recipe):
    return dict(filename=ARCHIVE, package=PACKAGE, version=VERSION, signed=False, provided_qtbase=VERSION,
                buildinfo_recipe=pin(recipe), stage_receipt=SRC + "/stage-contract.json")


def selection(raw, plan, plan_sha, now):
    issued = decode(raw, canonical=True)
    start, end = issued["created_utc"], issued["expires_utc"]
    conf = issued["makepkg_configuration"]
    need(type(conf) is dict and conf.keys() == {"main", "dropins"} and type(conf["dropins"]) is dict
         and len(conf["dropins"]) <= 16, "Exact makepkg configuration selection required")
    for name, expected in conf["dropins"].items():
        need(re.fullmatch(r"[A-Za-z0-9_.-]+\.conf", name) and name not in (".", ".."),
             "Unsafe makepkg configuration drop-in name")
        selected_pin(expected, 128 * 1024)
    selected_pin(conf["main"], 128 * 1024)
    expected = dict(kind=SELECTION_KIND, issuer="Root", approved=True, scope=SCOPE, nonce=plan["nonce"],
                    plan_sha256=plan_sha, created_utc=start, expires_utc=end, makepkg_configuration=conf)
    need(raw == wire(expected) and type(start) is type(end) is int and 0 < end - start <= 3600 and start <= now < end,
         "Current independently pinned package-only selection required")
    return issued


def stage_files(path, plan):
    expected = plan["staging_files"]
    files = {}
    names = {"expected356.lock", "configure-dependencies.list", "metadata-projection.json",
             "package_checks.py", "package_guest.py", "full_guest.py", "guest_link.py"}
    need(type(expected) is dict and len(expected) == 22 and names <= set(expected)
         and all(name in names or Path(name).parent == Path("recipe") for name in expected),
         "Exact finite packaging staging map required")
    need({leaf.name for leaf in path.iterdir()} == names | {"recipe", PLAN_NAME, SELECTION_NAME}
         and (path / "recipe").resolve(strict=True) == path / "recipe"
         and {leaf.name for leaf in (path / "recipe").iterdir()} ==
             {Path(name).name for name in expected if name.startswith("recipe/")},
         "Exact packaging staging namespace required")
    for name, row in expected.items():
        leaf = path / name
        size, digest = selected_pin(row, 128 * 1024)
        raw = ordinary_body(leaf, size)
        need(pair(raw) == (size, digest) and stat.S_IMODE(leaf.lstat().st_mode) == 0o444,
             "Staged package input differs")
        files[name] = raw
    need(pair(files["package_checks.py"]) == PACKAGE_CHECKER_PIN, "Expected exact normal package validator")
    return files


def metadata_rows(raw, field):
    prefix = "\t" + field + " = "
    return [line.removeprefix(prefix) for line in raw.decode("utf-8").splitlines() if line.startswith(prefix)]


def validate_stage_plan(plan, g, full, files):
    current = plan["nonce"]
    original = plan["source_build_nonce"]
    need(plan["kind"] == PLAN_KIND and plan["authority"] is None and plan["scope"] == SCOPE
         and NONCE.fullmatch(current) and NONCE.fullmatch(original) and current[:8] not in ("00000000", original[:8])
         and all(plan[name] == "NOT_RUN" for name in ("packaging", "signing", "installation", "hardware")),
         "Expected distinct unissued package-only plan")
    deps = files["configure-dependencies.list"].decode("ascii").splitlines()
    info = files["recipe/.SRCINFO"]
    inventory = files["expected356.lock"]
    need(deps == sorted(set(metadata_rows(info, "depends") + metadata_rows(info, "makedepends")
                            + metadata_rows(info, "checkdepends"))) and len(deps) == 47
         and pair(inventory) == g.INVENTORY and len(inventory.splitlines()) == 356,
         "Exact historical signed Q3 inventory and package dependency expressions required")
    completed = plan["worker"]["completed_build"]
    need(type(completed) is dict and completed.keys() == {"libraries", "ninja_log"}
         and completed["libraries"].keys() == set(full.LIBRARIES), "Exact accepted completed Qtbase library map required")
    for name, row in completed["libraries"].items():
        need(row.keys() == {"bytes", "sha256", "aliases"} and row["aliases"] == full.alias_metadata(name),
             "Completed library alias record differs")
        selected_pin({field: row[field] for field in ("bytes", "sha256")}, full.MAX_LIBRARY)
    selected_pin(completed["ninja_log"], full.NINJA_LOG_CAP)
    need(wire(plan["worker"]) == wire(worker_contract(g, full, deps, files, completed))
         and wire(plan["expected_archive"]) == wire(archive_contract(files["recipe/PKGBUILD"])),
         "Package worker commands or archive metadata drifted")
    return inventory


def reviewed_configuration(g, config):
    system = Path("/etc/makepkg.conf")
    dropins = system.with_name("makepkg.conf.d")
    expected = {system: config["main"]} | {dropins / name: item for name, item in config["dropins"].items()}
    home = Path(g.ENV["HOME"])
    config_home = Path(g.ENV["XDG_CONFIG_HOME"])
    need(not any(os.path.lexists(path) for path in (home / ".makepkg.conf", config_home / "pacman/makepkg.conf")),
         "Private makepkg user overrides refused")
    if os.path.lexists(dropins):
        need(dropins.resolve(strict=True) == dropins and {path.name for path in dropins.glob("*.conf")} ==
             set(config["dropins"]), "Unexpected makepkg configuration drop-ins")
    else:
        need(not config["dropins"], "Selected makepkg configuration drop-ins are missing")
    for path, value in expected.items():
        size, digest = selected_pin(value, 128 * 1024)
        need(path.resolve(strict=True) == path and path.lstat().st_uid == 0
             and not path.lstat().st_mode & 0o022, "Ordinary root-owned makepkg configuration required")
        g.file_data(path, size, expected=(size, digest))


def preserve_build(g, full, worker):
    g.check_inputs()
    completed = worker["completed_build"]
    log = selected_pin(completed["ninja_log"], full.NINJA_LOG_CAP)
    g.file_data(g.BUILD / ".ninja_log", log[0], expected=log)
    for name, row in completed["libraries"].items():
        size, digest = row["bytes"], row["sha256"]
        g.file_data(g.BUILD / "lib" / name, size, expected=(size, digest))
        aliases = g.alias_chain(name.removesuffix(full.VERSION))
        need({alias: target for alias, target, _ in aliases} == row["aliases"], "Completed build alias changed")
    for name, row in worker["check_source_files"].items():
        original = g.RECIPE / name
        prepared = g.RECIPE / "src" / name
        size, digest = selected_pin(row, 128 * 1024)
        g.file_data(original, size, expected=(size, digest))
        if prepared.is_symlink():
            need(prepared.resolve(strict=True) == original, "Prepared package source points outside the original recipe")
        else:
            g.file_data(prepared, size, expected=(size, digest))
    raw = g.RECIPE / "srcdest" / "qtbase-everywhere-src-6.12.0.tar.xz"
    g.file_data(raw, SOURCE_ARCHIVE_PIN[0], expected=SOURCE_ARCHIVE_PIN)


def check_stream(raw, expected, inventory):
    if expected.get("inventory"):
        need(b"".join(sorted(raw.splitlines(keepends=True))) == inventory, "Installed Q3 inventory changed")
    if expected.get("empty"):
        need(raw == b"", "Normal package dependency resolution produced diagnostics")
    if "last_line" in expected:
        need(raw.splitlines()[-1:] == [expected["last_line"].encode()], "Completed Ninja graph is no longer idle")
    if "line" in expected:
        need(raw.splitlines().count(expected["line"].encode()) == 1, "Expected exactly one real recipe smoke marker")


def archive_receipt(raw, stage, archive, info, recipe, inventory, libraries):
    checked = decode(raw)
    need(checked.keys() == {"artifacts", "errors"} and checked["errors"] == []
         and type(checked["artifacts"]) is list and len(checked["artifacts"]) == 1,
         "Expected clean original single Qt package validation")
    row = checked["artifacts"][0]
    need(row["artifact"] == ARCHIVE and row["status"] == "artifact-static-pass" and row["errors"] == []
         and row["sha256"] == archive["sha256"], "Final package does not match the validated archive")
    package, build = (row["metadata"][name] for name in (".PKGINFO", ".BUILDINFO"))
    for item in (package, build):
        need(item["pkgname"] == [PACKAGE] and item["pkgver"] == [VERSION], "Wrong exact packaged Qtbase identity")
    need(package["arch"] == build["pkgarch"] == ["aarch64"] and build["format"] == ["2"]
         and build["pkgbuild_sha256sum"] == [pin(recipe)["sha256"]]
         and build["startdir"] == build["builddir"] == [RECIPE]
         and not any(package.get(field) for field in ("replaces", "backup")),
         "Official provider metadata or packaging build record does not match")
    for old, new in (("depends", "depend"), ("provides", "provides"), ("conflicts", "conflict"), ("license", "license")):
        need(sorted(package[new]) == sorted(metadata_rows(info, old)), "Final package metadata differs from SRCINFO")
    installed = [value.rsplit("-", 1) for value in build["installed"]]
    need(all(len(parts) == 2 and parts[1] in {"any", "aarch64"} for parts in installed)
         and sorted(parts[0] for parts in installed) ==
             sorted(line.replace(" ", "-", 1) for line in inventory.decode("ascii").splitlines()),
         "Final BUILDINFO does not bind the original signed Q3 inventory")
    members = row["members"]
    need(all(name in members for name in (".PKGINFO", ".BUILDINFO", ".MTREE")) and ".INSTALL" not in members
         and stage["status"] == "PASS_QT612_GUI_SERVER_DESTDIR_CONTRACT_ONLY"
         and stage["server_feature_export"]["status"] == "PASS_QT612_GUI_SERVER_FEATURE_EXPORT_BYTES_ONLY",
         "Qt package stage, metadata, and server feature evidence required")
    for name, body in stage["server_feature_export"]["files"].items():
        file = members[name]
        need((file["size"], file["sha256"]) == (body["bytes"], body["sha256"]), "Final Qt server feature data changed")
    for name in libraries:
        library = "usr/lib/" + name
        result = row["elf"][library]
        need(result["machine"] == 183 and result["errors"] == [] and result["load_segments"] > 0
             and stage["elf"][library]["soname"] == name.removesuffix(".so.6.12.0") + ".so.6",
             "Validated Qt stage and final archive library contracts disagree")
        root = library.removesuffix(".so.6.12.0")
        for link, target in ((root + ".so", Path(root + ".so.6").name), (root + ".so.6", name)):
            need(members[link]["type"] == "2" and members[link]["link"] == target, "Final Qt SONAME alias changed")
    return {name: members[name]["sha256"] for name in (".PKGINFO", ".BUILDINFO", ".MTREE")}


def require_time(deadline, seconds):
    now = time.clock_gettime(time.CLOCK_BOOTTIME)
    need(type(deadline) is int and now + seconds + FINISH_RESERVE < deadline <= now + 3600,
         "Insufficient sealed packaging time")


def execute(g, full, plan, plan_sha, selection_sha, issued, files, inventory, output, deadline):
    worker = plan["worker"]
    role, receipts = "preflight", {}
    result = dict(kind="QTBASE16K_PACKAGING_RESULT_V1", scope=SCOPE, nonce=plan["nonce"], plan_sha256=plan_sha,
                  selection_sha256=selection_sha, signing="NOT_RUN", installation="NOT_RUN", hardware="NOT_RUN")
    try:
        need(not any(os.path.lexists(name) for name in worker["fresh_paths"]), "Fresh package-only attempt required")
        reviewed_configuration(g, issued["makepkg_configuration"])
        preserve_build(g, full, worker)
        steps = worker["actions"]
        require_time(deadline, sum(step["seconds"] for step in steps))
        need(int(time.time()) < issued["expires_utc"], "Packaging selection expired before mutation")
        g.put(Path(worker["stage_recipe"]["destination"]), files["recipe/PKGBUILD"])
        g.capture.__globals__["ENV"] = worker["environment"]
        report = None
        for step in steps:
            role = step["role"]
            require_time(deadline, step["seconds"])
            log = output / (role + ".log")
            metrics = g.capture(step["argv"], log, step["seconds"], step["combined_stream_cap"], cwd=g.RECIPE)
            g.require_success(metrics, role)
            raw = ordinary_body(log, step["combined_stream_cap"], allow_empty=True)
            check_stream(raw, step["expected"], inventory)
            receipts[role] = dict(metrics=metrics, log=pin(raw))
            if role == "archive-validation":
                report = raw

        role = "final-evidence"
        reviewed_configuration(g, issued["makepkg_configuration"])
        preserve_build(g, full, worker)
        stage_path = Path(plan["expected_archive"]["stage_receipt"])
        _, _, stage_raw = g.file_data(stage_path, STREAM_CAP, collect=True)
        need({path.name for path in output.iterdir()} == {name + ".log" for name in receipts} | {ARCHIVE},
             "Unexpected archive or signature in private packaging output")
        art, _, _ = g.file_data(output / ARCHIVE, FILE_CAP)
        archive = dict(bytes=art[0], sha256=art[1])
        metadata = archive_receipt(report, decode(stage_raw), archive, files["recipe/.SRCINFO"], files["recipe/PKGBUILD"],
                                   inventory, full.LIBRARIES)
        g.put(output / "stage-contract.json", stage_raw)
        result.update(status="PASS_UNSIGNED_PACKAGE_FOR_REVIEW", phase="complete", archive=archive,
                      metadata=metadata, stage_contract=pin(stage_raw))
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        result.update(status="HOLD", phase=role)
    g.put_json(output / "result.json", result | {"commands": receipts})
    return result["status"]


def guard(output):
    need(sys.flags.isolated and sys.dont_write_bytecode and __debug__
         and os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 1000
         and os.uname().machine == "aarch64" and os.sysconf("SC_PAGE_SIZE") == 16384,
         "Expected isolated ordinary AArch64 worker on a 16 KiB guest")
    mount = Path("/proc/self/mountinfo").read_text()
    need({p.name for p in Path("/sys/class/net").iterdir()} == {"lo"}
         and os.statvfs(MEDIA).f_flag & os.ST_RDONLY
         and any(line.split()[4] == "/qtmedia" and "ro" in line.split()[5].split(",")
                 for line in mount.splitlines()), "Expected offline guest and read-only package media")
    info = output.lstat()
    need(output == output.resolve(strict=True) and stat.S_ISDIR(info.st_mode)
         and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == info.st_gid == 1000
         and not any(output.iterdir()), "Expected empty private ordinary-user package output")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--selection-sha256", required=True)
    parser.add_argument("--worker-deadline-uptime", type=int, required=True)
    args = parser.parse_args()
    output, media = Path(OUTPUT), Path(MEDIA)
    guard(output)
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_CAP, FILE_CAP))
    plan_raw = ordinary_body(media / PLAN_NAME, 128 * 1024)
    issued_raw = ordinary_body(media / SELECTION_NAME, 16 * 1024)
    need(pin(plan_raw)["sha256"] == args.plan_sha256 and pin(issued_raw)["sha256"] == args.selection_sha256,
         "Expected exact independently pinned packaging plan and selection")
    plan = decode(plan_raw, canonical=True)
    issued = selection(issued_raw, plan, args.plan_sha256, int(time.time()))
    files = stage_files(media, plan)
    need(ordinary_body(Path(__file__), 128 * 1024) == files["package_guest.py"], "Executed package worker differs")
    full = module(files["full_guest.py"], media / "full_guest.py", FULL_GUEST_PIN)
    g = module(files["guest_link.py"], media / "guest_link.py", full.SIDECAR_PIN)
    inventory = validate_stage_plan(plan, g, full, files)
    for signum in g.INTERRUPTS:
        signal.signal(signum, g.interrupt)
    status = execute(g, full, plan, args.plan_sha256, args.selection_sha256, issued, files, inventory, output,
                     args.worker_deadline_uptime)
    return 0 if status == "PASS_UNSIGNED_PACKAGE_FOR_REVIEW" else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        raise SystemExit("Qtbase package worker refused") from None
