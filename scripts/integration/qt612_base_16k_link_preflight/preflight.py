# SPDX-License-Identifier: MIT
"""Select an unissued QtCore link checkpoint from the exact retained Q3 scratch."""

import argparse
from collections import Counter
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import resource
from runpy import run_path
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory, TemporaryFile


REPO = Path(__file__).resolve().parents[3]
GIB = 1 << 30
MIB = 1 << 20
Q3_SOURCE = "ed458826d8a55b7b73461adafdfaaefb669ce4a9"
Q3_TERMINAL = (3084, "f60a619b67c097cb90cbcbdd24ba35dc23c367a735c26430583685e4d1729f21")
Q3_SCRATCH = (16 * GIB, "70ca6c345fcf5e5d29d0bb90993d54c17a54164f23b2a6fe839e061b51edca45")
SCRATCH_UUID = "ed56022f-4e82-f6e3-fbde-502489347154"
BASE = "/qt-recipe/src"
BUILD = BASE + "/build"
RECIPE = "packages/port/qt612-gui-server-source-reference"
OPERANDS = {
    "PKGBUILD": (6232, "b8ab08950fc2e5729e00bc066e13897163ae52362105aa90d58569f603e07296"),
    "configure.cmake": (5695, "eaa27120efac20a30c6c8d256385532aa988af0dee00dd1f8117f24922674350"),
    "SERVER_DEPENDENCY_GUARD.cmake": (830, "77ee32886383da2d2b7c30b03269c7c482a6386237ad7c0bc111dd960579e379"),
    "source.py": (6717, "efe21d53a77c92ea66997923529b4d6e34635db7f1cb760af99d01774bdb7870"),
    "src/build/CMakeCache.txt": (310254, "2848e83fcf21d6819bb3d183a025a02ba944f05f849b3489c850922a9a89f742"),
    "src/build/build.ninja": (5774833, "cef51ef9f4a7fce92141f3b31d446da5ada824347da5ec713ead1f800858439a"),
    "src/build/CMakeFiles/rules.ninja": (47548, "b71df9759d13435ec44b87f1adf866c5ec8aebd44b4a6d41e78ee4ff4bf014cb"),
}
GRAPH = (5822350, "2df5cefe432f58d19af7c9f7bd394990ef35b169d40a79a01b1223cceff23f55")
TARGETS = {
    "core": ("lib/libQt6Core.so", 321, 303, ("Core",),
             (671480, "1836d53ff5aa42d6d115b8c5301938ccccdd8e3d1fffc29e52d524e44a701769")),
    "gui": ("lib/libQt6Gui.so", 639, 597, ("Core", "DBus", "Gui"),
            (1373001, "df7af2605c3ef1a3224532a3cc2c33f5d9b7da92a1e1b0c4a8e82932bcb16fdb")),
    "all": ("all", 1855, 1385, None,
            (3451659, "e9bdd7b241d2c28d035e3a084ca7fbeefd7d90f64748e0c0c356e1ea9baff628")),
}
LINKS = {
    "core": (14733, "d4e8c1733571c4da1219df08fcca9c8825848238fb5f4577903b5356eb38ede7"),
    "gui": (15466, "e5a0eb03a89b10a95535332c2fffde837f753c07adef8fae98926262407f374e"),
}
ELLIPSE = re.compile(rb'^"[^"]+" \[label="([^"]+)", shape=ellipse\]$')
EDGE = re.compile(rb'^"[^"]+" -> "[^"]+" \[label=" ([^"]+)"\]$')
SHARED_LINK = re.compile(rb"CXX_SHARED_LIBRARY_LINKER__([A-Za-z0-9_]+)_Release")
# The R4 importer established the boundary, including 4 vCPUs, 4 GiB guest
# RAM, 6 GiB actor RAM, 64 MiB result media, and a 2 GiB live reserve.
CORE_LIMITS = dict(vcpus=4, guest_memory_bytes=4 * GIB, actor_memory_bytes=6 * GIB,
                   host_memory_reserve_bytes=2 * GIB, guest_build_seconds=6900,
                   qemu_seconds=7200, attach_seconds=7500, overlay_file_bytes=4 * GIB,
                   result_bytes=64 * MIB, reports_bytes=32 * MIB, live_disk_reserve_bytes=2 * GIB)


def need(condition, message):
    if not condition:
        raise ValueError(message)


def pin(body):
    return len(body), hashlib.sha256(body).hexdigest()


def file_record(pair):
    return dict(zip(("bytes", "sha256"), pair, strict=True))


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid, info.st_gid,
            info.st_size, info.st_atime_ns, info.st_mtime_ns, info.st_ctime_ns)


def open_original(path):
    need(path.is_absolute() and path == path.resolve(strict=True), "Canonical original path required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NOATIME | os.O_NONBLOCK | os.O_CLOEXEC)
    return os.fdopen(fd, "rb")


def verify_original(stream, path, expected_size):
    info = os.fstat(stream.fileno())
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == expected_size
         and identity(info) == identity(path.lstat()), "Exact ordinary original file required")
    return identity(info)


def verify_terminal(path):
    with open_original(path) as stream:
        before = verify_original(stream, path, Q3_TERMINAL[0])
        body = stream.read(Q3_TERMINAL[0] + 1)
        need(pin(body) == Q3_TERMINAL and identity(os.fstat(stream.fileno())) == before == identity(path.lstat()),
             "Exact Q3 terminal bytes required")
    value = json.loads(body)
    need((value["status"], value["source"], value["page_size"], value["full_Qt_build"],
          value["inventories"]["356"]["count"], value["original_custody_pass"])
         == ("CLOSED_QTBASE16K_Q3_PASS", Q3_SOURCE, 16384, "NOT RUN", 356, True),
         "Exact Q3 configure-only closure required")
    return Path(value["attempt"])


def clone_scratch(source, copy):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    with open_original(source) as src, os.fdopen(os.open(copy, flags, 0o600), "wb") as dst:
        before = verify_original(src, source, Q3_SCRATCH[0])
        fcntl.ioctl(dst, 0x40049409, src.fileno())  # FICLONE. No full-copy fallback.
        need(identity(os.fstat(src.fileno())) == before == identity(source.lstat()),
             "Q3 scratch metadata changed during the reflink")
    copy.chmod(0o400)
    with copy.open("rb") as stream:
        observed = stream.seek(0, os.SEEK_END)
        stream.seek(0)
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    need((observed, digest) == Q3_SCRATCH, "Exact complete Q3 scratch bytes required")
    return before


def inspect_tool(work, argv, body=None):
    # Only our literal debugfs read requests and Ninja inspection commands
    # reach this helper. Retained commands are evidence and never executed.
    debugfs = (len(argv) == 4 and argv[:2] == ["/usr/bin/debugfs", "-R"]
               and argv[2] in {"stats", *("cat /root/qt-recipe/" + leaf for leaf in OPERANDS)}
               and argv[3] == str(work / "scratch.raw") and body is None)
    ninja = (argv[:4] == ["/usr/bin/ninja", "-f", "/dev/stdin", "-t"]
             and (argv[4:] in [[action, target[0]] for target in TARGETS.values()
                               for action in ("commands", "graph")]
                  or argv[4:] in [["commands", "-s", TARGETS[name][0] + ".6.12.0"] for name in LINKS])
             and body is not None)
    need(debugfs or ninja, "Read-only graph tool required")
    cap = 8 * MIB

    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (cap, cap))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    with TemporaryFile(dir=work) as out, TemporaryFile(dir=work) as err:
        subprocess.run(argv, input=b"" if body is None else body, stdout=out, stderr=err, cwd=work,
                       env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"},
                       preexec_fn=limits, timeout=45, check=True)
        need(out.tell() < cap and err.tell() <= 64 * 1024, "Graph tool output exceeded its bound")
        out.seek(0)
        return out.read()


def flatten(manifest, rules):
    directive = b"include CMakeFiles/rules.ninja"
    allowed = re.compile(rb"^(?:include|subninja) [^\n]*$", re.MULTILINE)
    need(allowed.findall(manifest) == [directive] and not allowed.search(rules), "Exact single Ninja rules include required")
    result = manifest.replace(directive + b"\n", rules, 1)
    need(pin(result) == GRAPH, "Exact flattened Q3 Ninja graph required")
    return result


def graph_cost(dot):
    rules = Counter(rule.group(1) for line in dot.splitlines()
                    if (rule := ELLIPSE.fullmatch(line) or EDGE.fullmatch(line)))
    libs = sorted(match.group(1).decode("ascii") for rule in rules if (match := SHARED_LINK.fullmatch(rule)))
    compiles = sum(count for rule, count in rules.items() if rule.startswith((b"C_COMPILER__", b"CXX_COMPILER__")))
    return dict(edges=sum(rules.values()), compiles=compiles, shared_libraries=libs,
                shared_links=sum(count for rule, count in rules.items() if SHARED_LINK.fullmatch(rule)),
                symlink_edges=rules[b"CMAKE_SYMLINK_LIBRARY"])


def audit_targets(work, graph):
    def ninja(action, *options):
        return inspect_tool(work, ["/usr/bin/ninja", "-f", "/dev/stdin", "-t", action, *options], graph)

    result = {}
    for name, (target, count, compiles, libs, expected) in TARGETS.items():
        actions = ninja("commands", target)
        cost = graph_cost(ninja("graph", target))
        need(pin(actions) == expected and actions.count(b"\n") == count and actions.endswith(b"\n")
             and cost["compiles"] == compiles, f"Q3 Ninja command closure differs for {name}")
        if name in LINKS:
            link = ninja("commands", "-s", target + ".6.12.0")
            soname = Path(target).name + ".6"
            need(pin(link) == LINKS[name] and b"-Wl,-soname," + soname.encode() in link
                 and b"-o " + (target + ".6.12.0").encode() in link
                 and cost["shared_libraries"] == list(libs) and cost["shared_links"] == len(libs)
                 and cost["symlink_edges"] >= 1, f"Q3 shared-library link edge differs for {name}")
            if name == "gui":
                need(all(pair in link for pair in (b"-Wl,--no-undefined", b"qtextmarkdownimporter.cpp.o",
                         b"/usr/lib/libmd4c.so.0.5.3")), "Exact QtGui system-md4c link required")
            cost.update(soname=soname, direct_link=file_record(pin(link)))
        result[name] = dict(target=target, commands=count, transcript=file_record(expected), **cost)
    return result


def scratch_capacity(stats):
    fields = {}
    for line in stats.decode("ascii").splitlines():
        key, _, value = line.partition(":")
        if key in {"Filesystem volume name", "Filesystem UUID", "Filesystem state", "Block size", "Block count",
                   "Reserved block count", "Free blocks"}:
            need(key not in fields, "Duplicate Q3 scratch geometry")
            fields[key] = value.strip()
    need(fields == {"Filesystem volume name": "QT16K_WORK", "Filesystem UUID": SCRATCH_UUID,
                    "Filesystem state": "clean", "Block size": "4096", "Block count": "4194304",
                    "Reserved block count": "0", "Free blocks": "3047912"}, "Exact clean Q3 scratch geometry required")
    return int(fields["Block size"]) * int(fields["Free blocks"])


def resources(work, guest_free):
    volume = os.statvfs(work)
    available = volume.f_bavail * volume.f_frsize
    limits = CORE_LIMITS.copy()
    max_output = limits["overlay_file_bytes"] + limits["result_bytes"] + limits["reports_bytes"]
    min_disk = max_output + limits["live_disk_reserve_bytes"]
    with Path("/proc/meminfo").open() as stream:
        match = next(re.fullmatch(r"MemAvailable:\s+([0-9]+) kB\n", line)
                     for line in stream if line.startswith("MemAvailable:"))
    need(match is not None, "Host MemAvailable required")
    memory = int(match[1]) * 1024
    min_memory = limits["actor_memory_bytes"] + limits["host_memory_reserve_bytes"]
    cpus = len(os.sched_getaffinity(0))
    fits = (available >= min_disk and memory >= min_memory and cpus >= limits["vcpus"]
            and guest_free > limits["overlay_file_bytes"])
    return dict(**limits, guest_free_bytes=guest_free, min_host_free_bytes=min_disk,
                min_host_memory_bytes=min_memory, host_free_bytes=available, host_memory_available_bytes=memory,
                allowed_host_cpus=cpus, numeric_caps_fit=fits, completion_budget_measured=False,
                owned_command=dict(child_file_size_cap=limits["overlay_file_bytes"],
                                   watched_tree=["/out", max_output, limits["live_disk_reserve_bytes"]],
                                   watched_paths=[["/out/overlay.qcow2", limits["overlay_file_bytes"]],
                                                  ["/out/result.raw", limits["result_bytes"]]]))


def preflight(terminal, scratch, probe_dir):
    attempt = verify_terminal(terminal)
    need(probe_dir.is_absolute() and probe_dir == probe_dir.resolve(strict=True) and probe_dir.is_dir()
         and not any(probe_dir.is_relative_to(path) for path in (attempt.parent, scratch.parent, terminal.parent)),
         "Select a canonical probe directory outside the original receipts and scratch")
    with TemporaryDirectory(prefix="qtbase-link-probe-", dir=probe_dir) as work:
        work = Path(work)
        copy = work / "scratch.raw"
        original = clone_scratch(scratch, copy)
        data = {}
        for leaf, expected in OPERANDS.items():
            body = inspect_tool(work, ["/usr/bin/debugfs", "-R", "cat /root/qt-recipe/" + leaf, str(copy)])
            need(pin(body) == expected, f"Q3 scratch recipe or graph operand differs: {leaf}")
            data[leaf] = body
        common = run_path(str(REPO / "scripts/ci/qt612-complete-family-native-source/common.py"))
        original_recipe = (REPO / RECIPE / "PKGBUILD").read_bytes()
        need(common["project_pkgbuild"](original_recipe, "gui_server") == data["PKGBUILD"],
             "Q3 recipe differs from the current exact Qt family projection")
        cache = data["src/build/CMakeCache.txt"].splitlines()
        need(all(line in cache for line in (b"CMAKE_AUTOGEN_PARALLEL:STRING=1", b"CMAKE_GENERATOR:INTERNAL=Ninja",
                 b"CMAKE_PROJECT_QtBase_INCLUDE:UNINITIALIZED=/qt-recipe/src/SERVER_DEPENDENCY_GUARD.cmake",
                 b"md4c_DIR:PATH=/usr/lib/cmake/md4c", b"QT_FEATURE_system_textmarkdownreader:INTERNAL=ON")),
             "Expected exact serial configure, family guard and system md4c cache")
        graph = flatten(data["src/build/build.ninja"], data["src/build/CMakeFiles/rules.ninja"])
        selected = audit_targets(work, graph)
        free = scratch_capacity(inspect_tool(work, ["/usr/bin/debugfs", "-R", "stats", str(copy)]))
        need(identity(scratch.lstat()) == original, "Original Q3 scratch changed while probing")
    target = selected["core"]["target"]
    return dict(kind="QTBASE16K_QTCORE_LINK_PREFLIGHT_V1", status="VERIFIED_GRAPH_CORE_CHECKPOINT_UNISSUED",
                prior_source=Q3_SOURCE, prior_terminal=file_record(Q3_TERMINAL), scratch=file_record(Q3_SCRATCH),
                scratch_uuid=SCRATCH_UUID, source_operands={leaf: file_record(pair) for leaf, pair in OPERANDS.items()},
                flattened_graph=file_record(GRAPH), inventory_packages=356, architecture="aarch64", page_size=16384,
                graph=selected, resources=resources(probe_dir, free), root_authority=None, actor_started=False,
                checkpoint=dict(argv=["/usr/bin/cmake", "--build", BUILD, "--parallel", "1", "--target", target],
                                cwd="/qt-recipe", uid=1000, gid=1000,
                                environment=dict(PATH="/usr/bin:/bin", LC_ALL="C.UTF-8", TZ="UTC", MAX_JOBS="1",
                                                 CMAKE_BUILD_PARALLEL_LEVEL="1", MAKEFLAGS="-j1",
                                                 SOURCE_DATE_EPOCH="1792021458", HOME="/qt-recipe/.home",
                                                 XDG_CONFIG_HOME="/qt-recipe/.home/.config", TMPDIR="/qt-recipe/.tmp"),
                                output=BUILD + "/" + target + ".6.12.0", soname=selected["core"]["soname"]),
                qtcore_link="NOT RUN", qtgui_link="PENDING_CORE_RESOURCE_MEASUREMENT",
                full_qt_build="PENDING_COMPILE_AND_PACKAGE_RESOURCE_MEASUREMENT", native="NOT RUN")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ("q3-terminal", "q3-scratch", "probe-dir"):
        parser.add_argument("--" + argument, type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(preflight(args.q3_terminal, args.q3_scratch, args.probe_dir), sort_keys=True, indent=2))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(str(error))


if __name__ == "__main__":
    main()
