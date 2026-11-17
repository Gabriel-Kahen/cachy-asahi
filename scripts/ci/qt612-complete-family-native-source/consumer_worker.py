# SPDX-License-Identifier: MIT
"""Execute the installed desktop consumers inside the selected native container."""

import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import xml.etree.ElementTree as ET

SOURCE = "/consumer"
BUILD = "/scratch/build"
OUT = "/out"
MAX_FILE = 4 * 1024**2
LIB = re.compile(r"/usr/lib/libQt6[A-Za-z0-9]+\.so\.6(?:\.12\.0)?")
PLUGIN = re.compile(r"/usr/lib/qt6/(?:plugins|qml)/[A-Za-z0-9_./+-]+\.so")
WAYLAND = re.compile(r"/usr/lib/libwayland-(?:client|server)\.so\.0(?:\.[0-9]+)*")
TOOLS = {"/usr/lib/qt6/bin/qsb", "/usr/lib/qt6/rcc", "/usr/lib/qt6/qtwaylandscanner",
         "/usr/bin/wayland-scanner"}
RENDER = {
    "/usr/lib/libQt6Core.so.6", "/usr/lib/libQt6Gui.so.6", "/usr/lib/libQt6Qml.so.6",
    "/usr/lib/libQt6Quick.so.6", "/usr/lib/libQt6Svg.so.6",
    "/usr/lib/libQt6WaylandCompositor.so.6", "/usr/lib/qt6/plugins/platforms/libqoffscreen.so",
    "/usr/lib/qt6/plugins/imageformats/libqsvg.so",
}


def need(value, message):
    if not value:
        raise ValueError(message)


def commands(checks):
    return [
        ("configure", ["/usr/bin/cmake", "-S", SOURCE, "-B", BUILD, "-G", "Ninja",
                       "-DQT612_INSTALLED_PREFIX=/usr", "-DCMAKE_BUILD_TYPE=Release",
                       "-DCMAKE_AUTOGEN_PARALLEL:STRING=1", "-DBUILD_TESTING=ON"], 60),
        ("build", ["/usr/bin/cmake", "--build", BUILD, "--parallel", "1", "--verbose"], 180),
        ("test-list", ["/usr/bin/ctest", "--test-dir", BUILD, "--show-only=json-v1"], 15),
        ("tests", ["/usr/bin/ctest", "--test-dir", BUILD, "--parallel", "1",
                   "--no-tests=error", "--verbose", "--output-junit", OUT+"/ctest.xml"], 45),
    ]


def validate_list(raw, checks):
    value = json.loads(raw)
    tests = value["tests"]
    need(len(tests) == len(checks) and {test["name"] for test in tests} == set(checks),
         "Unexpected registered CTest set")
    for test in tests:
        props = {row["name"]: row["value"] for row in test["properties"]}
        need(test["command"] == [BUILD+"/"+test["name"]] and props.get("TIMEOUT") == 10
             and not any(props.get(key) for key in ("DISABLED", "SKIP_RETURN_CODE", "SKIP_REGULAR_EXPRESSION", "WILL_FAIL")),
             "Unexpected CTest command, timeout or skip")


def validate_junit(raw, checks):
    need(0 < len(raw) <= MAX_FILE and b"<!" not in raw,
         "Expected finite CTest-generated XML without declarations")
    root = ET.fromstring(raw)
    need(root.tag == "testsuite" and root.get("tests") == str(len(checks))
         and all(root.get(key) == "0" for key in ("failures","disabled","skipped"))
         and root.get("errors","0") == "0", "Expected one successful CTest JUnit suite")
    tests = root.findall("testcase")
    need(len(tests) == len(checks) and {test.get("name") for test in tests} == set(checks),
         "Missing or duplicate CTest results")
    for test in tests:
        need(test.get("status") == "run" and not any(test.find(tag) is not None for tag in ("skipped", "error", "failure")),
             "CTest reported an unsuccessful consumer")
        text = test.findtext("system-out", default="")
        need(text.splitlines().count(checks[test.get("name")]) == 1, "Missing or repeated consumer check marker")


def loader_paths(traces, checks):
    loaded = {}
    for raw in traces:
        body = raw.decode("utf-8", errors="strict")
        programs = re.findall(r"(?m)^\s*[0-9]+:\s+initialize program: (\S+)\s*$", body)
        if len(programs) != 1 or not programs[0].startswith(BUILD+"/"):
            continue
        name = Path(programs[0]).name
        need(programs[0] == BUILD+"/"+name and name in checks and name not in loaded, "Unexpected consumer loader process")
        paths = set()
        for path in re.findall(r"(?m)^\s*[0-9]+:\s+calling init: (\S+)\s*$", body):
            if WAYLAND.fullmatch(path):
                paths.add(path)
            if "libQt6" in path or "/qt6/" in path:
                need((LIB.fullmatch(path) or PLUGIN.fullmatch(path)) and ".." not in Path(path).parts,
                     "Consumer loaded a foreign Qt object")
                paths.add(path)
        need("/usr/lib/libQt6Core.so.6" in paths or "/usr/lib/libQt6Core.so.6.12.0" in paths,
             "Consumer did not load the selected Qt Core")
        loaded[name] = sorted(paths)
    need(set(loaded) == set(checks), "Incomplete per-consumer loader evidence")
    render = {name.removesuffix(".12.0") if LIB.fullmatch(name) else name
              for name in loaded["qt612-desktop-render"]}
    need(RENDER <= render, "Missing selected Quick, Wayland, SVG or offscreen runtime objects")
    protocol = loaded["qt612-desktop-protocol"]
    need(all(any(path.startswith("/usr/lib/libwayland-"+kind+".so.0") for path in protocol)
             for kind in ("client","server")), "Missing normal Wayland protocol libraries")
    return loaded


def main():
    need(os.getenv("QT612_FAMILY_DESKTOP_WORKER") == "1" and os.getuid() == os.geteuid() > 0
         and os.uname().machine == "aarch64", "Expected the selected ordinary native worker")
    need(not Path(BUILD).exists() and not any(Path(OUT).iterdir()), "Fresh private consumer scratch and output required")
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE, MAX_FILE))
    Path("/scratch/home").mkdir(mode=0o700)
    Path("/scratch/tmp").mkdir(mode=0o700)
    env = dict(PATH="/usr/bin:/bin", HOME="/scratch/home", TMPDIR="/scratch/tmp", LC_ALL="C",
               TZ="UTC", CMAKE_BUILD_PARALLEL_LEVEL="1", CTEST_PARALLEL_LEVEL="1", MAKEFLAGS="-j1")
    checks = json.loads(Path(SOURCE+"/INTERFACE.DATA.json").read_bytes())["success_markers"]
    records = []

    def capture(role, argv, timeout, command_env):
        with Path(OUT+"/"+role+".log").open("xb") as log:
            result = subprocess.run(argv, env=command_env, stdin=subprocess.DEVNULL, stdout=log,
                                    stderr=subprocess.STDOUT, timeout=timeout, check=False)
        need(result.returncode == 0, role+" failed")
        records.append(dict(role=role, argv=argv, exit=result.returncode))

    expected = Path("/expected-inventory").read_bytes()
    for phase in ("before", "after"):
        if phase == "after":
            for role, argv, timeout in commands(checks):
                trace_env = dict(env, LD_DEBUG="libs", LD_DEBUG_OUTPUT=OUT+"/loader") if role=="tests" else env
                capture(role, argv, timeout, trace_env)
                if role == "test-list":
                    validate_list(Path(OUT+"/test-list.log").read_bytes(), checks)
            validate_junit(Path(OUT+"/ctest.xml").read_bytes(), checks)
        capture("inventory-"+phase, ["/usr/bin/pacman", "-Q"], 15, env)
        raw = Path(OUT+"/inventory-"+phase+".log").read_bytes()
        need(b"".join(sorted(raw.splitlines(keepends=True))) == expected, "Installed family inventory mismatch")
    traces = sorted(Path(OUT).glob("loader.*"))
    need(3 <= len(traces) <= 16, "Unexpected loader log count")
    loaded = loader_paths([path.read_bytes() for path in traces], checks)
    owners, hashes = {}, {}
    paths = TOOLS | {name for group in loaded.values() for name in group}
    need(len(paths) <= 128, "Unexpected installed object count")
    for path in sorted(paths):
        resolved = str(Path(path).resolve(strict=True))
        queried = subprocess.run(["/usr/bin/pacman", "-Qqo", "--", resolved], env=env,
                                 capture_output=True, timeout=5, check=True).stdout
        need(re.fullmatch(rb"[a-z0-9][a-z0-9+_.-]*\n", queried), "Expected one installed package owner")
        if resolved not in hashes:
            with Path(resolved).open("rb") as stream:
                size = os.fstat(stream.fileno()).st_size
                need(0 < size <= 128*1024**2, "Finite installed object required")
                hashes[resolved] = dict(bytes=size, sha256=hashlib.file_digest(stream,"sha256").hexdigest())
        owners[path] = dict(resolved=resolved, package=queried.decode().strip(), body=hashes[resolved])
    Path(OUT+"/worker.json").write_text(json.dumps(dict(commands=records, owners=owners), sort_keys=True)+"\n")


if __name__ == "__main__":
    main()
