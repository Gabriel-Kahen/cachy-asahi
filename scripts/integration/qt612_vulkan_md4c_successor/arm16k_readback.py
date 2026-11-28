#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read the retired Qtbase successor VM and package without mounting an image."""

import argparse
from decimal import Decimal
import gzip
import hashlib
import io
import lzma
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
from runpy import run_path
import stat
import struct
import sys
import tarfile
from tempfile import NamedTemporaryFile
from types import SimpleNamespace


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
C = SimpleNamespace(**run_path(str(HERE.parent / "qt612_base_16k_link_preflight/readback.py")))
AUTH = run_path(str(HERE / "arm16k_inputs.py"))
DEFAULT_PROFILE, PROFILES = AUTH["DEFAULT_PROFILE"], AUTH["PROFILES"]
MIB = 1 << 20
PACKAGE = "cachy-asahi-qt612-gui-server-source-reference"
VERSION = PROFILES[DEFAULT_PROFILE]["version"]
BASE_ARCHIVE = C.file_pin(14172388, "6420f8ee8d8ebc106072c9bedb111c6b2dd780eb4e4629bceec4dc71a2b774c4")
BEFORE = C.file_pin(6925, "e2a4da7903e6de26b0ee37758ad424439f83196fa6a3b0bdffa501f35a02d0b9")
AFTER = C.file_pin(6954, "cd7f0f45ee485edc315e27370e954ba11ab3f5e6168a2653c40220a698c102a1")
BUILD_EPOCH = "1792021458"
SIGNER = b"68B3537F39A313B3E574D06777193F152BDBE6A6"
STAGES = {"boot", "storage", "setup", "build", "retain", "cleanup", "configured", "complete"}
SETUP = {"before.lock": 32 << 10, "after.lock": 32 << 10, "alpm.log": MIB, "gpgv.log": MIB,
         "package-check.log": 64 << 10}
GRAPH = {"CMakeCache.txt": 2 * MIB, "build.ninja": 32 * MIB, "rules.ninja": 2 * MIB}
CONFIGURED = GRAPH | {"features.txt": 64 << 10, "graph.sha256": 4096, "profile.json": 4096}
FULL = {"stage-contract.json": 8 * MIB, "vulkan-md4c-elf.json": 4096,
        "archive.sha256": 4096}
CAPS = SETUP | CONFIGURED | FULL | {"result.json": 4096, "build.log": 64 * MIB, "dependencies.log": 64 << 10}
NAMESPACE = {".", "lost+found", "evidence"}
SMOKE = b"PASS_QT612_GUI_SERVER_OFFSCREEN_AND_LOCAL_DISPLAY_API_ONLY"
FEATURES = {
    "CMAKE_BUILD_TYPE": "Release", "CMAKE_GENERATOR": "Ninja",
    "CMAKE_HOME_DIRECTORY": "/qt-successor/src/qtbase-everywhere-src-6.12.0",
    "CMAKE_CACHEFILE_DIR": "/qt-successor/src/build", "Vulkan_INCLUDE_DIR": "/usr/include",
    "md4c_DIR": "/usr/lib/cmake/md4c", "QT_FEATURE_vulkan": "ON", "QT_FEATURE_vkgen": "ON",
    "QT_FEATURE_vkkhrdisplay": "OFF", "QT_FEATURE_system_textmarkdownreader": "ON",
    "QT_FEATURE_wayland_server": "ON",
}
CHECK_MARKERS = {
    b"md4c 0.6.0-2", b"vulkan-headers 1:1.4.363.0-1", b"md4c-pkg-config=0.6.0", b"md4c-dlopen=PASS",
    b"owner=md4c path=/usr/lib/libmd4c.so.0.6.0", b"owner=vulkan-headers path=/usr/include/vulkan/vulkan.h",
}


class ResultPinError(ValueError):
    """The result carrier does not match its retired launch receipt."""


def serial_state(body, nonce):
    suffix = nonce.encode("ascii")
    prefixes = [b"QTBASE_SUCCESSOR16K_" + marker for marker in (b"SETUP", b"CONFIGURED", b"TERMINAL")]
    lines = [(index, line) for index, line in enumerate(body.splitlines()) if line.startswith(tuple(prefixes))]
    positions = {}
    terminal = None
    for index, line in lines:
        fields = line.split()
        C.need(len(fields) >= 2 and line == b" ".join(fields), "Malformed successor serial marker")
        prefix, token, *tail = fields
        C.need(prefix in prefixes and token == suffix and prefix not in positions,
               "Foreign or repeated successor serial marker")
        positions[prefix] = index
        if prefix == prefixes[2]:
            C.need(len(tail) == 2 and tail[0] in (b"PASS", b"HOLD") and tail[1].decode("ascii") in STAGES,
                   "Invalid successor guest terminal")
            terminal = tuple(field.decode("ascii") for field in tail)
        else:
            C.need(not tail and line == prefix + b" " + suffix, "Invalid successor progress marker")
    C.need(list(positions) == [prefix for prefix in prefixes if prefix in positions]
           and (prefixes[1] not in positions or prefixes[0] in positions), "Successor markers are out of order")
    return terminal, prefixes[0] in positions, prefixes[1] in positions


def recipe_inputs(path, *, profile=DEFAULT_PROFILE):
    selected = PROFILES[profile]
    expected = selected["recipe"]
    raw, _ = C.read(path / selected["receipt"], expected["bytes"], expected)
    receipt = C.json_body(raw, canonical=True)
    files = {name: C.read(path / name, 128 << 10, receipt["files"][name])[0]
             for name in (".SRCINFO", "configure.cmake", "source-notices.json")}
    C.need(receipt["artifact_version"] == selected["version"], "Staged recipe version differs")
    return receipt, files


def digest_list(body, expected):
    rows = body.decode("ascii").splitlines()
    actual = {}
    for row in rows:
        match = re.fullmatch(r"([a-f0-9]{64})  ([A-Za-z0-9._+-]+)", row)
        C.need(match and match[2] not in actual, "Malformed or repeated evidence digest")
        actual[match[2]] = match[1]
    C.need(actual == {name: pin["sha256"] for name, pin in expected.items()}, "Guest artifact digests differ")


def setup_checks(pins, files):
    C.need(pins["before.lock"] == BEFORE and pins["after.lock"] == AFTER,
           "Actual before/after pacman inventories differ from the signed-input projections")
    C.need(len(files["before.lock"].splitlines()) == 356 and len(files["after.lock"].splitlines()) == 357,
           "Unexpected pacman inventory sizes")
    C.need(CHECK_MARKERS.issubset(files["package-check.log"].splitlines()), "Signed dependency evidence differs")
    changes = re.findall(rb"^\[[^\]\n]+\] \[ALPM\] (?:upgraded|installed|removed|downgraded|reinstalled) [^\n]+$",
                         files["alpm.log"], re.MULTILINE)
    C.need(sorted(line.split(b" [ALPM] ", 1)[1] for line in changes) == [
        b"installed vulkan-headers (1:1.4.363.0-1)",
        b"upgraded md4c (0.5.3-1 -> 0.6.0-2)",
    ], "ALPM log does not show exactly the two successor dependency changes")
    names = [b"md4c-0.6.0-2-aarch64.pkg.tar.xz", b"vulkan-headers-1:1.4.363.0-1-any.pkg.tar.xz"]
    sections = []
    for line in files["gpgv.log"].splitlines():
        if line in names:
            sections.append((line, []))
        else:
            C.need(sections and line.startswith(b"[GNUPG:] "), "Invalid guest signature transcript")
            sections[-1][1].append(line.split())
    C.need([name for name, _ in sections] == names, "Guest signature transcript has the wrong archives")
    for _, rows in sections:
        invalid = {b"BADSIG", b"ERRSIG", b"EXPKEYSIG", b"EXPSIG", b"REVKEYSIG", b"NO_PUBKEY",
                   b"KEYEXPIRED", b"SIGEXPIRED"}
        valid = [row for row in rows if row[1:2] == [b"VALIDSIG"]]
        C.need(len(valid) == 1 and len(valid[0]) == 12 and valid[0][2] == valid[0][-1] == SIGNER
               and not any(row[1:2] and row[1] in invalid for row in rows),
               "Missing exact current ALARM VALIDSIG evidence")


def graph_checks(pins, files, profile):
    digest_list(files["graph.sha256"], {name: pins[name] for name in GRAPH})
    cache = {}
    for match in re.finditer(rb"^([A-Za-z0-9_]+):([^=\n]+)=(.*)$", files["CMakeCache.txt"], re.MULTILINE):
        name, kind, value = (field.decode("utf-8") for field in match.groups())
        C.need(name not in cache, "Duplicate CMake cache setting")
        cache[name] = (kind, value)
    settings = dict(re.findall(rb'^set\((\w+) (\S+) CACHE (?:BOOL|STRING) "" FORCE\)$', profile, re.MULTILINE))
    wanted = FEATURES | {("QT_" if key.startswith(b"FEATURE_") else "") + key.decode(): value.decode()
                         for key, value in settings.items()}
    C.need(all(cache.get(name, (None, None))[1] == value for name, value in wanted.items()),
           "The fresh CMake cache differs from the staged feature profile")
    features = files["features.txt"].decode("utf-8").splitlines()
    explicit = {"Vulkan_INCLUDE_DIR", "md4c_DIR", "QT_FEATURE_vulkan", "QT_FEATURE_vkkhrdisplay",
                "QT_FEATURE_system_textmarkdownreader"}
    C.need({f"{name}:{cache[name][0]}={cache[name][1]}" for name in explicit} <= set(features),
           "Retained feature lines disagree with original CMake cache bytes")
    C.need(cache.get("QT612_SERVER_API_LINKS", (None, None))[1] in ("1", "ON", "TRUE"),
           "Wayland server dependency link probe is missing")
    C.need(C.json_body(files["profile.json"]) == dict(status="PASS_CONFIGURED_PROFILE_ONLY", settings=len(settings),
                                                      native="NOT_ESTABLISHED"), "Configured profile result differs")
    C.need(b"include CMakeFiles/rules.ninja\n" in files["build.ninja"]
           and b"build all: phony " in files["build.ninja"]
           and files["rules.ninja"].startswith(b"# CMAKE generated file:"), "Original generated Ninja graph required")
    return {name: cache[name][1] for name in FEATURES}


def readelf(body, *flags):
    bounded = run_path(str(HERE.parent / "lifecycle.py"))["bounded_process"]
    with os.fdopen(os.memfd_create("qtbase-parity-elf", os.MFD_CLOEXEC), "wb") as stream:
        stream.write(body)
        stream.flush()
        result = bounded(["/usr/bin/readelf", "--wide", *flags, f"/proc/{os.getpid()}/fd/{stream.fileno()}"],
                         timeout=30, stdout_limit=16 * MIB, stderr_limit=8192,
                         env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"})
    C.need(result["returncode"] == 0 and result["reason"] == "exit" and result["cleanup"]["reaped"]
           and not result["stderr"], "Bounded independent Qt ELF readelf failed")
    return result["stdout"].decode("ascii")


def gui_abi(body):
    return run_path(str(HERE / "check_gui.py"))["check_readback"](
        readelf(body, "--dynamic", "--dyn-syms", "--relocs"))


def dynamic_symbols(body):
    exports, imports = set(), set()
    for line in readelf(body, "--dyn-syms").splitlines():
        fields = line.split()
        if len(fields) < 8 or not re.fullmatch(r"\d+:", fields[0]):
            continue
        _, _, _, _, binding, visibility, section, name, *_ = fields
        if section == "UND" and binding == "GLOBAL":
            imports.add(name)
        elif section != "UND" and binding in {"GLOBAL", "WEAK", "UNIQUE"} and visibility in {"DEFAULT", "PROTECTED"}:
            exports.add(name)
    C.need(exports, "A Qt library has no visible dynamic symbols")
    return exports, imports


def package_metadata(controls, sourceinfo, inventory, recipe, payload_bytes, parse, *, version=VERSION):
    package, build = (parse(controls[name].decode("utf-8")) for name in (".PKGINFO", ".BUILDINFO"))
    expected = parse(sourceinfo.decode("utf-8"))
    common = dict(pkgname=[PACKAGE], pkgbase=[PACKAGE], pkgver=[version], builddate=[BUILD_EPOCH])
    relations = {"depends": "depend", "makedepends": "makedepend", "checkdepends": "checkdepend",
                 "optdepends": "optdepend", "provides": "provides", "conflicts": "conflict",
                 "license": "license", "groups": "group", "replaces": "replaces", "backup": "backup"}
    package_fields = common | dict(arch=["aarch64"], xdata=["pkgtype=pkg"], size=[str(payload_bytes)],
                                   pkgdesc=expected["pkgdesc"], url=expected["url"])
    for src_key, pkg_key in relations.items():
        if expected.get(src_key):
            package_fields[pkg_key] = expected[src_key]
    C.need(package.keys() == package_fields.keys() | {"packager"}
           and all(sorted(package[key]) == sorted(values) for key, values in package_fields.items())
           and len(package["packager"]) == 1 and package["packager"][0],
           "Archive PKGINFO differs from the exact recipe and final payload")
    build_fields = common | dict(pkgarch=["aarch64"], format=["2"], packager=package["packager"],
                                pkgbuild_sha256sum=[recipe["files"]["PKGBUILD"]["sha256"]],
                                startdir=["/qt-successor"], builddir=["/qt-successor"], buildtool=["makepkg"])
    C.need(build.keys() == build_fields.keys() | {"buildtoolver", "buildenv", "options", "installed"}
           and all(build[key] == values for key, values in build_fields.items())
           and len(build["buildtoolver"]) == 1 and build["buildtoolver"][0],
           "Unexpected successor package BUILDINFO record")
    env, options = set(build["buildenv"]), set(build["options"])
    required = set(expected["options"])
    opposite = {option[1:] if option.startswith("!") else "!" + option for option in required}
    C.need({"check", "!sign"} <= env and not {"!check", "sign"} & env
           and required <= options and not opposite & options
           and len(env) == len(build["buildenv"]) and len(options) == len(build["options"]),
           "Unexpected successor package BUILDINFO build options")
    installed = [value.rsplit("-", 1) for value in build["installed"]]
    C.need(all(len(row) == 2 and row[1] in {"any", "aarch64"} for row in installed)
           and sorted(row[0] for row in installed) ==
           sorted(line.replace(" ", "-", 1) for line in inventory.decode("ascii").splitlines()),
           "The final package BUILDINFO differs from the actual 357-package inventory")


def development_files(stage):
    public = {path for module in stage.MODULES for path in (
        f"usr/include/qt6/Qt{module}/Qt{module}",
        f"usr/lib/pkgconfig/Qt6{module}.pc",
        f"usr/lib/cmake/Qt6{module}/Qt6{module}Config.cmake",
    )}
    private = {path for module, header in stage.PRIVATE_HEADERS.items() for path in (
        f"usr/include/qt6/Qt{module}/6.12.0/Qt{module}/private/{header}",
        f"usr/lib/cmake/Qt6{module}Private/Qt6{module}PrivateConfig.cmake",
    )}
    return public | private | {"usr/include/qt6/QtCore/qtcoreversion.h"} | set(stage.SERVER_METADATA)


def payload_contract(stage, packaged, staged_contract):
    expected = {
        **{name: ("file", row["mode"], None) for name, row in staged_contract["files"].items()},
        **{name: ("symlink", row["mode"], row["target"]) for name, row in staged_contract["symlinks"].items()},
        **{name: ("directory", mode, None) for name, mode in staged_contract["directories"].items()},
    }
    C.need(len(expected) == sum(len(staged_contract[key]) for key in ("files", "directories", "symlinks"))
           and packaged == expected, "Final archive path, type, mode or link target differs from staging")
    C.need(development_files(stage) <= staged_contract["files"].keys(),
           "Final archive lacks required Qt development files")


def mtree_fields(member, body):
    kind = "file" if member.isfile() else "dir" if member.isdir() else "link"
    record = dict(type=kind, mode=f"{member.mode:o}", uid=str(member.uid), gid=str(member.gid),
                  time=Decimal(str(member.mtime)).normalize().to_eng_string())
    if kind == "file":
        record.update(size=str(len(body)), sha256digest=hashlib.sha256(body).hexdigest())
    elif kind == "link":
        record["link"] = member.linkname
    return record


def verify_mtree(compressed, inventory):
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
        text = stream.read((8 << 20) + 1)
    C.need(len(text) <= 8 << 20 and text.startswith(b"#mtree\n"), "Invalid or oversized package MTREE")
    defaults, observed = {}, {}
    for row in text.decode("utf-8").splitlines()[1:]:
        fields = row.split()
        C.need(fields and fields[0] != "/unset", "Unexpected MTREE record")
        name, *items = fields
        pairs = [item.split("=", 1) for item in items]
        values = dict(pairs)
        C.need(len(values) == len(pairs), "Duplicate MTREE attributes")
        if name == "/set":
            C.need(values.keys() <= {"mode", "type", "uid", "gid"}, "Unexpected MTREE defaults")
            defaults.update(values)
            continue
        C.need(name.startswith("./") and name[2:] not in observed and re.fullmatch(r"[0-9]{1,12}(?:\.[0-9]{1,9})?", values.get("time", "")),
               f"Invalid or repeated MTREE path: {name}")
        values["time"] = Decimal(values["time"]).normalize().to_eng_string()
        if "link" in values:
            values["link"] = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), values["link"])
        name = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), name[2:])
        C.need(name not in observed and inventory.get(name) == defaults | values,
               f"MTREE metadata disagrees with archive bytes: {name}")
        observed[name] = defaults | values
    C.need(observed == inventory, "MTREE path census differs from the final archive")
    return observed


def parity_delta(baseline, candidate, maps, expected, symbols):
    old, abi = {}, {}
    expanded = maps.expand_archive(io.BytesIO(baseline))
    with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as archive:
        for member in archive:
            name = maps.PKG.clean_name(member.name)
            if name in maps.CONTROLS | {"."}:
                continue
            C.need(name not in old and (member.isfile() or member.isdir() or member.issym()),
                   "Unexpected reference archive path")
            old[name] = ("file" if member.isfile() else "directory" if member.isdir() else "symlink",
                         member.mode, member.linkname if member.issym() else None)
            if name in symbols:
                prior, _ = dynamic_symbols(archive.extractfile(member).read())
                current, _ = symbols[name]
                C.need(prior <= current, f"Project Qt export lost in {name}: {sorted(prior - current)[:20]}")
                abi[name] = dict(retained_exports=len(prior), new_exports=sorted(current - prior))
    C.need(abi.keys() == symbols.keys(), "Reference Qt dynamic symbol census differs")
    new = {name: row for name, row in candidate.items() if name not in maps.CONTROLS | {"."}}
    added, removed = new.keys() - old.keys(), old.keys() - new.keys()
    changed = {name for name in old.keys() & new.keys() if old[name] != new[name]}
    expected_dir = "usr/lib/qt6/plugins/printsupport"
    C.need(added == expected | {expected_dir} and not removed and not changed
           and new[expected_dir] == ("directory", 0o755, None) and all(new[name][0] == "file" for name in expected),
           f"Unexpected parity path delta (extra {sorted(added - expected - {expected_dir})}, "
           f"missing {sorted(expected - added)}, removed {sorted(removed)}, changed {sorted(changed)})")
    return dict(added_files=sorted(expected), added_directories=[expected_dir], removed=[], metadata_changed=[],
                baseline_nodes=len(old), candidate_nodes=len(new), qt_dynamic_exports=abi)


def atspi_bridge_abi(symbols):
    constructor = "_ZN20QSpiAccessibleBridgeC1Ev"
    exported = f"{constructor}@@Qt_6_PRIVATE_API"
    imported = f"{constructor}@Qt_6_PRIVATE_API"
    gui_exports = symbols["usr/lib/libQt6Gui.so.6.12.0"][0]
    consumers = ["libQt6WaylandClient.so.6.12.0", "libQt6XcbQpa.so.6.12.0"]
    C.need(exported in gui_exports and all(imported in symbols["usr/lib/" + name][1] for name in consumers),
           "AT-SPI bridge ABI absent from QtGui or its Wayland/XCB consumers")
    return dict(qtgui_export=exported, consumers=consumers)


def archive_contents(raw, files, recipe, staged, *, profile=DEFAULT_PROFILE, baseline=None):
    maps = SimpleNamespace(**run_path(str(HERE.parent / "qt612_installed_16k_preflight/selection_maps.py")))
    stage = SimpleNamespace(**run_path(str(ROOT / "packages/port/qt612-gui-server-source-reference/check_stage.py")))
    expanded = maps.expand_archive(io.BytesIO(raw))
    maps.archive_headers(expanded)
    library_roots = {f"usr/lib/libQt6{module}.so" for module in (*stage.MODULES, *stage.PRIVATE_MODULES)}
    staged_contract = C.json_body(files["stage-contract.json"])
    libraries, links, controls, nodes, notices, server_bodies, elf = {}, {}, {}, {}, {}, {}, {}
    inventory, symbols = {}, {}
    is_parity = profile == "parity"
    payload_bytes = 0
    notice_root = stage.NOTICE_ROOT + "/"
    abi = None
    with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:", encoding="utf-8", errors="strict") as archive:
        for member in archive:
            name = maps.PKG.clean_name(member.name)
            C.need(name not in nodes and len(nodes) < 32768 and member.name in (name, "./" + name)
                   and member.uid == member.gid == 0 and not member.mode & 0o6000 and not member.sparse
                   and 0 <= member.size <= maps.PKG.MAX_MEMBER
                   and (member.isfile() or member.isdir() or member.issym()), f"Unexpected package member: {name}")
            kind = "directory" if member.isdir() else "symlink" if member.issym() else "file"
            nodes[name] = (kind, member.mode, member.linkname if member.issym() else None)
            C.need(kind == "file" or member.size == 0, f"Non-file package member has data: {name}")
            if name in maps.CONTROLS:
                C.need(member.isfile() and member.mode == 0o644 and 0 < member.size <= 4 * MIB,
                       "Invalid package control file")
                controls[name] = archive.extractfile(member).read()
                if is_parity and name != ".MTREE":
                    inventory[name] = mtree_fields(member, controls[name])
                continue
            C.need((name == "." and nodes[name] == ("directory", 0o755, None)) or stage.owned(name),
                   f"Package member escapes Qt ownership: {name}")
            C.need(member.issym() or not member.mode & 0o7022, f"Unsafe package member mode: {name}")
            C.need(not name.startswith("usr/lib/qt6/plugins/platforms/libqvkkhrdisplay"),
                   "Disabled VK_KHR_display plugin in the final package")
            if member.issym():
                dest = posixpath.normpath(posixpath.join(posixpath.dirname(name), member.linkname))
                C.need(not name.startswith(notice_root) and member.linkname
                       and not member.linkname.startswith("/") and "\\" not in member.linkname
                       and dest.startswith("usr/"),
                       f"Unexpected or escaping package link: {name}")
            body = archive.extractfile(member).read() if member.isfile() else b""
            payload_bytes += len(body)
            if is_parity and name != ".":
                inventory[name] = mtree_fields(member, body)
            if body.startswith(b"\x7fELF"):
                observed = stage.elf_info(body)
                elf[name] = observed
            else:
                observed = None
            if member.isfile() and not observed:
                # makepkg strips both ELF and static archives after package().
                if name.endswith(".a"):
                    C.need(body.startswith(b"!<arch>\n"), f"Invalid final static library: {name}")
                else:
                    row = staged_contract["files"].get(name, {})
                    C.need(C.pin(body) == {key: row.get(key) for key in ("bytes", "sha256")},
                           f"Final non-ELF payload bytes differ from staging: {name}")
            if name in stage.SERVER_METADATA:
                server_bodies[name] = body
            if re.fullmatch(r"usr/lib/libQt6[^/]+\.so(?:\..+)?", name):
                root = name.split(".so", 1)[0] + ".so"
                C.need(root in library_roots, f"Unexpected Qt shared library: {name}")
                if name in (root, root + ".6"):
                    expected = Path(root).name + (".6" if name == root else ".6.12.0")
                    C.need(member.issym() and member.linkname == expected, f"Unexpected Qt library alias: {name}")
                    links[name] = member.linkname
                    continue
                C.need(name == root + ".6.12.0" and member.isfile(), f"Invalid Qt shared library entry: {name}")
                interpreter = "/lib/ld-linux-aarch64.so.1" if root.endswith("/libQt6Core.so") else None
                C.need(observed and observed["type"] == 3 and observed["soname"] == Path(root).name + ".6"
                       and observed["interpreter"] in (None, interpreter), f"Wrong Qt shared library loader metadata: {name}")
                libraries[name] = C.pin(body)
                if is_parity and baseline is not None:
                    symbols[name] = dynamic_symbols(body)
                if root.endswith("/libQt6Gui.so"):
                    abi = gui_abi(body)
            if name.startswith(notice_root) and member.isfile():
                notices[name.removeprefix(notice_root)] = C.pin(body)["sha256"]
    C.need(all(nodes.get(str(parent), ("directory", 0, None))[0] == "directory"
               for name in nodes for parent in PurePosixPath(name).parents),
           "An archive path has a non-directory ancestor")
    C.need(controls.keys() == maps.CONTROLS and libraries.keys() == {root + ".6.12.0" for root in library_roots}
           and links.keys() == {name for root in library_roots for name in (root, root + ".6")},
           "Expected package controls and eighteen library alias chains")
    C.need(notices == C.json_body(staged["source-notices.json"])["source_notices"] and len(notices) == 173,
           "Final archive source notices differ from the exact recipe policy")
    C.need(abi is not None and abi == C.json_body(files["vulkan-md4c-elf.json"]),
           "Final archive QtGui ABI differs from the packaging-stage check")
    payload_contract(stage, {name: row for name, row in nodes.items() if name not in maps.CONTROLS | {"."}},
                     staged_contract)
    C.need(elf.keys() == staged_contract["elf"].keys(), "Final ELF path census differs from staging")
    plugins = {"usr/lib/qt6/plugins/" + name for name in stage.PLUGINS}
    C.need(all(name in elf and nodes[name][1] & 0o111 for name in set(stage.TOOLS) | plugins)
           and all(elf[name]["type"] == 3 for name in plugins), "Expected final executable Qt tools and shared plugins")
    server = stage.server_feature_export(server_bodies, {name: C.pin(body) for name, body in server_bodies.items()})
    C.need(server == staged_contract["server_feature_export"],
           "Final archive Wayland server export differs from staging")
    package_metadata(controls, staged[".SRCINFO"], files["after.lock"], recipe, payload_bytes, maps.PKG.metadata,
                     version=PROFILES[profile]["version"])
    report = dict(libraries=libraries, gui_abi=abi, source_notices=len(notices), elf_objects=len(elf),
                  controls={name: C.pin(body) for name, body in controls.items()})
    if is_parity:
        parity = run_path(str(HERE / "check_parity.py"))
        parity["check_parity"]({"files": {name: {"mode": row[1]} for name, row in nodes.items() if row[0] == "file"},
                                "elf": elf})
        verify_mtree(controls[".MTREE"], inventory)
        report["mtree"] = dict(entries=len(inventory), inventory=C.pin(C.wire(inventory)))
        if baseline is not None:
            report["path_delta"] = parity_delta(baseline, nodes, maps, parity["ADDED_FILES"], symbols)
            report["atspi_bridge_abi"] = atspi_bridge_abi(symbols)
    return report


def result_files(path, plan, result_pin, load_archive, *, profile=DEFAULT_PROFILE):
    archive = AUTH["archive_name"](profile)
    caps = CAPS | {archive: 512 * MIB}
    C.need(C.check_pin(result_pin, 4 << 30) and result_pin["bytes"] == plan["limits"]["result_bytes"]
           and result_pin["bytes"] > 0, "Exact planned result size required")
    original = path.lstat()
    before = C.identity(original)
    C.need(path.is_absolute() and path.resolve(strict=True) == path and stat.S_ISREG(original.st_mode)
           and original.st_nlink == 1 and original.st_size == result_pin["bytes"],
           "Exact planned result size required")
    with C.ext4_reader()(path, max_nodes=len(caps) + len(NAMESPACE), max_file_bytes=max(caps.values())) as fs:
        C.need(C.identity(os.fstat(fs.fd)) == before, "Result carrier changed at open")
        # The ext4 reader uses pread. Hash its already-held descriptor before
        # reading the inventory, rather than verifying and reopening the path.
        with os.fdopen(os.dup(fs.fd), "rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != result_pin["sha256"]:
                raise ResultPinError("Result carrier digest differs from the retired launch")
        C.need(C.identity(os.fstat(fs.fd)) == before == C.identity(path.lstat()),
               "Result carrier changed while hashing")
        sb = fs.read(1024, 1024)
        C.need(struct.unpack_from("<HH", sb, 56) == (0xEF53, 1) and not fs.incompat & 4
               and sb[120:136].rstrip(b"\0") == b"QT16K_SUCC" and fs.uuid == plan["result_uuid"],
               "Expected clean successor result ext4 with the planned label and UUID")
        nodes = fs.inventory()["nodes"]
        leaves = nodes.keys() - NAMESPACE
        C.need({".", "lost+found"} <= nodes.keys() and leaves <= {"evidence/" + name for name in caps},
               "Unexpected successor result namespace")
        for name in NAMESPACE & nodes.keys():
            row = nodes[name]
            C.need(row["type"] == "directory" and row["uid"] == row["gid"] == 0 and not row["xattrs"]
                   and row["mode"] == (0o755 if name == "." else 0o700), "Unexpected result directory metadata")
        pins, files = {}, {}
        for leaf in sorted(leaves):
            name, row = leaf.removeprefix("evidence/"), nodes[leaf]
            C.need(row["type"] == "file" and row["links"] == 1 and row["uid"] == row["gid"] == 0
                   and row["mode"] == 0o600 and not row["xattrs"] and 0 <= row["size"] <= caps[name],
                   f"Unexpected result file metadata: {name}")
            pins[name] = C.file_pin(row["size"], row["sha256"])
            if name != archive or load_archive:
                inode, body = fs.inode(row["inode"])
                files[name] = b"".join(fs.chunks(inode, body))
                C.need(C.pin(files[name]) == pins[name], f"Result file changed during readback: {name}")
        C.need(before == C.identity(os.fstat(fs.fd)) == C.identity(path.lstat()),
               "Result carrier changed during readback")
    return pins, files


def dependencies_check(raw, sourceinfo):
    checks = {row.split(b" = ", 1)[1] for row in sourceinfo.splitlines()
              if row.startswith((b"\tdepends = ", b"\tmakedepends = "))}
    C.need(len(checks) > 0 and raw.splitlines() == sorted(checks) + [b"ALL_BUILD_DEPENDENCIES_PRESENT"],
           "Failed or changed recipe dependency solver evidence")


def stage_checks(body, staged):
    stage = C.json_body(body)
    C.need(stage["status"] == "PASS_QT612_GUI_SERVER_DESTDIR_CONTRACT_ONLY" and stage["architecture"] == "aarch64"
           and stage["license_policy_pin"] == C.pin(staged["source-notices.json"])
           and stage["server_feature_export"]["status"] == "PASS_QT612_GUI_SERVER_FEATURE_EXPORT_BYTES_ONLY",
           "Original stage-contract result differs")


def guest_checks(plan, pins, files, markers, recipe, staged, host_pass, *, profile=DEFAULT_PROFILE, baseline=None):
    terminal, setup_serial, config_serial = markers
    passed = terminal is not None and terminal[0] == "PASS"
    errors, features = {}, None
    setup_verified = False
    if SETUP.keys() <= files.keys():
        try:
            setup_checks(pins, files)
            setup_verified = True
        except ValueError as error:
            errors["setup"] = str(error)
    if CONFIGURED.keys() | {"dependencies.log"} <= files.keys():
        try:
            dependencies_check(files["dependencies.log"], staged[".SRCINFO"])
            features = graph_checks(pins, files, staged["configure.cmake"])
        except ValueError as error:
            errors["configured"] = str(error)
    worker = C.json_body(files["result.json"]) if "result.json" in files else None
    report = dict(terminal=list(terminal) if terminal else None, setup_reported=setup_serial,
                  setup_independent=setup_verified, configured_reported=config_serial,
                  configured_independent=features is not None, features=features, worker=worker,
                  evidence=pins, errors=errors)
    if not passed:
        return report, "HOLD"
    mode = plan["mode"]
    phase = {"configure": "configured", "full": "complete"}[mode]
    expected = SETUP.keys() | CONFIGURED.keys() | {"result.json", "build.log", "dependencies.log"}
    archive = AUTH["archive_name"](profile)
    if mode == "full":
        expected |= FULL.keys() | {archive}
    C.need(not errors, f"Guest PASS has invalid evidence: {errors}")
    C.need(host_pass and terminal == ("PASS", phase) and setup_serial and config_serial
           and setup_verified and features is not None and worker == dict(status="PASS", phase=phase, nonce=plan["nonce"], mode=mode,
                              architecture="aarch64", page_size=16384)
           and pins.keys() == expected and all(files[name] for name in expected),
           "Guest PASS lacks complete matching host and guest evidence")
    if mode == "full":
        C.need(files["build.log"].splitlines().count(SMOKE) == 1, "Original makepkg smoke result absent")
        digest_list(files["archive.sha256"], {archive: pins[archive]})
        stage_checks(files["stage-contract.json"], staged)
        report["archive"] = archive_contents(files[archive], files, recipe, staged, profile=profile, baseline=baseline)
        return report, "PASS_UNSIGNED_EMULATED_AARCH64_16K_PACKAGE"
    return report, "PASS_EMULATED_AARCH64_16K_CONFIGURE"


def host_receipts(capsule, plan, plan_sha, launch_sha):
    raw, launch_pin = C.external(capsule / "launch.json", 128 << 10, launch_sha)
    launch = C.json_body(raw, canonical=True)
    nonce = plan["nonce"]
    C.need(launch["kind"] == "QTBASE_SUCCESSOR16K_LAUNCH_V1" and launch["nonce"] == nonce
           and launch["plan_sha256"] == plan_sha and C.SHA.fullmatch(launch["cid"])
           and launch["container_absent"] == [True, True] and launch["originals_unchanged"] is True,
           "Missing matching original-input check or container retirement receipt")
    raw, started_pin = C.read(capsule / "launch.started.json", 64 << 10)
    started = C.json_body(raw, canonical=True)
    C.need(all(started[key] == launch[key] for key in ("cid", "started", "nonce", "plan_sha256"))
           and started["name"] == "caa-qtbase-successor16k-" + nonce
           and 0 < launch["started"] <= launch["completed"], "Launch receipt does not match owned start record")
    caps = {
        "actor.json": 128 << 10, "serial.log": plan["limits"]["serial_bytes"],
        "result.raw": plan["limits"]["result_bytes"], "overlay.qcow2": plan["limits"]["overlay_bytes"],
        "result-fsck.log": 128 << 10,
    }
    attach = launch.get("attach_log")
    if attach is not None:
        C.read(capsule / "container.log", 2 * MIB, attach)
    paths = capsule / "run"
    allowed = caps if "attach_log" in launch else caps | {"container.log": 2 * MIB}
    C.need(paths.is_dir() and paths == paths.resolve(strict=True)
           and {path.name for path in paths.iterdir()} == launch["files"].keys()
           and launch["files"].keys() <= allowed.keys() and "result.raw" in launch["files"],
           "Unexpected original run output namespace")
    bodies = {name: C.read(paths / name, allowed[name], expected, collect=name != "overlay.qcow2")[0]
              for name, expected in launch["files"].items() if name != "result.raw"}
    actor = C.json_body(bodies["actor.json"]) if "actor.json" in bodies else None
    if actor:
        C.need(actor["kind"] == "QTBASE_SUCCESSOR16K_ACTOR_V1" and actor["nonce"] == nonce
               and actor["qemu_exit"] == launch["qemu_exit"] and actor["process_reaped"] is launch["process_reaped"],
               "Outer and inner owned process receipts differ")
    state = launch["container_state"]
    host_pass = bool(actor and state and actor["error"] is None and launch["error"] is None
                     and actor["process_reaped"] is True and state["Running"] is False and state["Status"] == "exited"
                     and not state["OOMKilled"] and not state["Error"]
                     and state["ExitCode"] == launch["container_exit"] == launch["qemu_exit"] == actor["fsck_exit"] == 0
                     and launch["files"].keys() == caps.keys())
    if host_pass:
        C.need(0 < actor["memory_peak_bytes"] <= plan["limits"]["container_bytes"]
               and launch["files"]["overlay.qcow2"]["bytes"] <= actor["peak_overlay_bytes"] <= caps["overlay.qcow2"]
               and actor["lowest_host_free_bytes"] >= plan["limits"]["host_disk_reserve_bytes"],
               "Owned run exceeded reviewed resource limits")
    serial = serial_state(bodies.get("serial.log", b""), nonce)
    return launch, launch_pin, started_pin, actor, serial, host_pass


def readback(capsule, plan_sha, launch_sha, recipe_path=None, *, profile=DEFAULT_PROFILE,
             baseline_path=None, export=None):
    raw, plan_pin = C.external(capsule / "plan.json", 128 << 10, plan_sha)
    plan = C.json_body(raw, canonical=True)
    C.need(plan["kind"] == "QTBASE_SUCCESSOR16K_PLAN_V1" and C.NONCE.fullmatch(plan["nonce"])
           and plan["mode"] in {"configure", "full"}
           and plan["base_revision"] == "cbc877a35f40aba98aeb53cbcfebd7d18422e5ec", "Unexpected successor plan")
    AUTH["check_plan_profile"](plan, profile, historical=True)
    C.need(baseline_path is None or (profile == "parity" and plan["mode"] == "full"),
           "Archive comparison requires the full parity profile")
    C.need(export is None or baseline_path is not None, "Archive export requires the pinned parity baseline")
    recipe, staged = recipe_inputs(recipe_path or capsule / "recipe", profile=profile)
    C.need(all(plan["payload"]["recipe/" + name] == pin for name, pin in recipe["files"].items()),
           "Recipe data does not bind the sealed boot payload")
    upstream = AUTH["SOURCE_NAME"]
    source = plan["inputs"]["source"]
    C.need({key: source[key] for key in ("bytes", "sha256")} == plan["payload"][upstream] == recipe["qt_source"],
           "Upstream Qt archive does not bind the selected recipe")
    launch, launch_pin, started_pin, actor, markers, host_pass = host_receipts(capsule, plan, plan_sha, launch_sha)
    guest_pass = markers[0] is not None and markers[0][0] == "PASS"
    try:
        baseline = C.read(baseline_path, BASE_ARCHIVE["bytes"], BASE_ARCHIVE)[0] if baseline_path else None
        pins, files = result_files(capsule / "run/result.raw", plan, launch["files"]["result.raw"],
                                   load_archive=guest_pass and host_pass and plan["mode"] == "full", profile=profile)
        guest, status = guest_checks(plan, pins, files, markers, recipe, staged, host_pass,
                                     profile=profile, baseline=baseline)
        if export is not None:
            C.need(guest_pass and host_pass and status == "PASS_UNSIGNED_EMULATED_AARCH64_16K_PACKAGE"
                   and baseline is not None
                   and {"mtree", "path_delta", "atspi_bridge_abi"} <= guest["archive"].keys(),
                   "Archive export requires a full PASS with the pinned parity path and ABI comparison")
            with NamedTemporaryFile(prefix=f".{export.name}.", dir=export.parent) as stream:
                stream.write(files[AUTH["archive_name"](profile)])
                stream.flush()
                os.fchmod(stream.fileno(), 0o444)
                os.fsync(stream.fileno())
                os.link(stream.name, export)
    except (OSError, EOFError, KeyError, ValueError, UnicodeError) as error:
        if guest_pass or isinstance(error, ResultPinError):
            raise
        status = "HOLD"
        guest = dict(terminal=markers[0], setup_reported=markers[1], configured_reported=markers[2],
                     readback_error=str(error))
    provenance = {name: plan[name] for name in ("profile", "source_sha256")} if "source_sha256" in plan else {}
    return dict(kind="QTBASE_SUCCESSOR16K_INDEPENDENT_READBACK_V1", status=status,
                nonce=plan["nonce"], mode=plan["mode"], plan=plan_pin, launch=launch_pin, start=started_pin,
                originals_unchanged=launch["originals_unchanged"], container_retired=launch["container_absent"],
                container_exit=launch["container_exit"], qemu_exit=launch["qemu_exit"], host_error=launch["error"],
                actor=actor, run_files=launch["files"], guest=guest,
                signing="NOT_RUN", installation="NOT_RUN", hardware="NOT_RUN", **provenance)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capsule", type=Path, required=True)
    parser.add_argument("--recipe", type=Path)
    parser.add_argument("--profile", choices=PROFILES, default=DEFAULT_PROFILE)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--export-archive", type=Path)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--launch-sha256", required=True)
    args = parser.parse_args()
    try:
        report = readback(args.capsule, args.plan_sha256, args.launch_sha256, args.recipe, profile=args.profile,
                          baseline_path=args.baseline, export=args.export_archive)
        sys.stdout.buffer.write(C.wire(report))
        return 2 if report["status"] == "HOLD" else 0
    except (OSError, EOFError, KeyError, TypeError, ValueError, lzma.LZMAError, tarfile.TarError) as error:
        print(f"Qtbase ARM16K successor readback refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
