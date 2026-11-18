# SPDX-License-Identifier: MIT
"""Future owned AArch64 guest worker for the selected QtGui link checkpoint."""

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import selectors
import signal
import stat
import subprocess
import sys
import time

MIB = 1 << 20
RECIPE = Path("/qt-recipe")
BUILD = RECIPE / "src/build"
EVIDENCE = Path("/qtgui-evidence")
CORE = "libQt6Core"
GUI = "libQt6Gui"
DBUS = "libQt6DBus"
VERSION = ".so.6.12.0"
TARGET = "lib/libQt6Gui.so"
BUILD_ARGV = ["/usr/bin/cmake", "--build", str(BUILD), "--parallel", "1", "--target", TARGET]
NINJA = "/usr/bin/ninja"
GUI_COMMANDS = (1373001, "df7af2605c3ef1a3224532a3cc2c33f5d9b7da92a1e1b0c4a8e82932bcb16fdb")
CORE_COMMANDS = (671480, "1836d53ff5aa42d6d115b8c5301938ccccdd8e3d1fffc29e52d524e44a701769")
GUI_LINK = (15466, "e5a0eb03a89b10a95535332c2fffde837f753c07adef8fae98926262407f374e")
INVENTORY = (6925, "e2a4da7903e6de26b0ee37758ad424439f83196fa6a3b0bdffa501f35a02d0b9")
MD4C = Path("/usr/lib/libmd4c.so.0.5.3")
MD4C_PIN = (133128, "d7754699fec7db8e53a7813547b4c1c0cfdde079ae09128401c379ec034bdef2")
Q3_PINS = {
    "PKGBUILD": (6232, "b8ab08950fc2e5729e00bc066e13897163ae52362105aa90d58569f603e07296"),
    "configure.cmake": (5695, "eaa27120efac20a30c6c8d256385532aa988af0dee00dd1f8117f24922674350"),
    "SERVER_DEPENDENCY_GUARD.cmake": (830, "77ee32886383da2d2b7c30b03269c7c482a6386237ad7c0bc111dd960579e379"),
    "source.py": (6717, "efe21d53a77c92ea66997923529b4d6e34635db7f1cb760af99d01774bdb7870"),
    "src/build/CMakeCache.txt": (310254, "2848e83fcf21d6819bb3d183a025a02ba944f05f849b3489c850922a9a89f742"),
    "src/build/build.ninja": (5774833, "cef51ef9f4a7fce92141f3b31d446da5ada824347da5ec713ead1f800858439a"),
    "src/build/CMakeFiles/rules.ninja": (47548, "b71df9759d13435ec44b87f1adf866c5ec8aebd44b4a6d41e78ee4ff4bf014cb"),
}
ENV = dict(PATH="/usr/bin:/bin", TZ="UTC", LC_ALL="C.UTF-8", HOME="/qt-recipe/.home",
           XDG_CONFIG_HOME="/qt-recipe/.home/.config", TMPDIR="/qt-recipe/.tmp",
           SOURCE_DATE_EPOCH="1792021458", MAKEFLAGS="-j1", CMAKE_BUILD_PARALLEL_LEVEL="1",
           MAX_JOBS="1", NINJA_STATUS="[%f/%t] ")
HEX = re.compile(r"[0-9a-f]{64}")
PROGRESS = re.compile(rb"\[([1-9][0-9]{0,3})/([1-9][0-9]{0,3})\] (.+)")
INTERRUPTS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


def need(condition, message):
    if not condition:
        raise ValueError(message)


def body_pin(body):
    return len(body), hashlib.sha256(body).hexdigest()


def identity(row):
    return (row.st_dev, row.st_ino, row.st_mode, row.st_nlink, row.st_uid, row.st_gid,
            row.st_size, row.st_mtime_ns, row.st_ctime_ns)


def file_data(path, cap, *, expected=None, copy=None, collect=False):
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), "rb") as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= cap,
             "Expected bounded ordinary file " + path.name)
        digest = hashlib.sha256()
        remaining = before.st_size
        chunks = []
        while remaining:
            data = stream.read(min(remaining, MIB))
            need(data, "Unexpected short file " + path.name)
            remaining -= len(data)
            digest.update(data)
            if copy is not None:
                copy.write(data)
            if collect:
                chunks.append(data)
        need(not stream.read(1) and identity(before) == identity(os.fstat(stream.fileno())) == identity(path.lstat()),
             "File identity changed " + path.name)
    observed = before.st_size, digest.hexdigest()
    need(expected is None or observed == expected, "Exact file pin differs " + path.name)
    return observed, identity(before), b"".join(chunks)


def read_plan(path, sha):
    need(path.is_absolute() and path == path.resolve(strict=True) and HEX.fullmatch(sha),
         "Canonical independently pinned guest plan required")
    pin, _, body = file_data(path, 4096, collect=True)
    need(pin[1] == sha, "Exact guest plan SHA-256 required")
    plan = json.loads(body)
    canonical = (json.dumps(plan, sort_keys=True, separators=(",", ":")) + "\n").encode()
    need(body == canonical and type(plan) is dict and
         plan.keys() == {"kind", "authority", "nonce", "core", "limits", "target"},
         "Exact canonical guest plan fields required")
    need(plan["kind"] == "QTGUI_LINK_GUEST_PLAN_V1" and plan["authority"] is None and plan["target"] == TARGET
         and type(plan["nonce"]) is str and re.fullmatch(r"[0-9a-f]{32}", plan["nonce"]),
         "Wrong guest plan kind, authority, nonce, or target")
    core, limits = plan["core"], plan["limits"]
    need(type(core) is dict and core.keys() == {"bytes", "sha256"} and
         type(core["bytes"]) is int and 0 < core["bytes"] <= 48 * MIB and
         type(core["sha256"]) is str and HEX.fullmatch(core["sha256"]), "Exact accepted Core pin required")
    ceilings = dict(guest_build_seconds=86400, build_log_bytes=64 * MIB, artifact_bytes=1024 * MIB)
    need(type(limits) is dict and limits.keys() == ceilings.keys() and
         all(type(limits[key]) is int and 0 < limits[key] <= ceiling for key, ceiling in ceilings.items()) and
         limits["artifact_bytes"] > MD4C_PIN[0], "Externally selected finite guest limits required")
    return plan


def signal_group(child, signum):
    try:
        os.killpg(child.pid, signum)
    except ProcessLookupError:
        return False
    return True


def retire(child):
    for signum, grace in ((signal.SIGTERM, 2), (signal.SIGKILL, 3)):
        if not signal_group(child, signum):
            break
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            child.poll()
            if not signal_group(child, 0):
                break
            time.sleep(0.025)
    child.poll()
    return child.returncode is not None and not signal_group(child, 0)


def capture(argv, path, seconds, cap, *, cwd):
    """Retain one bounded merged stream and retire its original process group."""
    start = time.monotonic()
    deadline = start + seconds
    exit_code, complete, timeout, overflow = None, False, False, False
    with path.open("xb") as out:
        child = subprocess.Popen(argv, cwd=cwd, env=ENV, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            with selectors.DefaultSelector() as poll:
                poll.register(child.stdout, selectors.EVENT_READ)
                while True:
                    left = deadline - time.monotonic()
                    if left <= 0 or not poll.select(left):
                        timeout = True
                        break
                    chunk = os.read(child.stdout.fileno(), 65536)
                    if not chunk:
                        try:
                            exit_code = child.wait(timeout=max(0, deadline - time.monotonic()))
                            complete = True
                        except subprocess.TimeoutExpired:
                            timeout = True
                        break
                    remain = cap - out.tell()
                    out.write(chunk[:remain])
                    if len(chunk) > remain:
                        overflow = True
                        break
        finally:
            prior = signal.pthread_sigmask(signal.SIG_BLOCK, INTERRUPTS)
            try:
                child.stdout.close()
                natural = complete and not signal_group(child, 0)
                group_empty = child.returncode is not None if natural else retire(child)
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, prior)
    return dict(exit_code=exit_code, elapsed_ms=round((time.monotonic() - start) * 1000),
                peak_child_rss_kib=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
                log_complete=complete, natural=natural, group_empty=group_empty, timeout=timeout, overflow=overflow)


def require_success(result, label):
    need(result["exit_code"] == 0 and result["log_complete"] and result["natural"] and result["group_empty"]
         and not result["timeout"] and not result["overflow"], "Incomplete original " + label)


def alias_chain(stem):
    lib = BUILD / "lib"
    pairs = [(lib / (stem + ".so"), stem + ".so.6"), (lib / (stem + ".so.6"), stem + VERSION)]
    rows = []
    for path, target in pairs:
        before = path.lstat()
        need(stat.S_ISLNK(before.st_mode) and os.readlink(path) == target and identity(before) == identity(path.lstat()),
             "Exact SONAME symlink differs " + path.name)
        rows.append((path.name, target, identity(before)))
    return rows


def core_state(plan):
    expected = plan["core"]["bytes"], plan["core"]["sha256"]
    _, stable, _ = file_data(BUILD / "lib" / (CORE + VERSION), expected[0], expected=expected)
    return stable, alias_chain(CORE)


def require_missing_outputs():
    for stem in (GUI, DBUS):
        for extension in (".so", ".so.6", VERSION):
            need(not os.path.lexists(BUILD / "lib" / (stem + extension)), "Preexisting GUI/DBus output")


def check_inputs():
    for relative, pin in Q3_PINS.items():
        file_data(RECIPE / relative, pin[0], expected=pin)
    file_data(MD4C, MD4C_PIN[0], expected=MD4C_PIN)
    need(Path("/usr/lib/libmd4c.so.0").resolve(strict=True) == MD4C, "Wrong system md4c loader path")


def inventory(evidence, location):
    label = evidence / location
    raw = evidence / (location + ".raw")
    require_success(capture(["/usr/bin/pacman", "-Q"], raw, 30, 16 * 1024, cwd=RECIPE), "inventory query")
    _, _, output = file_data(raw, 16 * 1024, collect=True)
    lines = output.splitlines(keepends=True)
    normalized = b"".join(sorted(lines))
    need(len(lines) == 356 and body_pin(normalized) == INVENTORY, "Exact 356-package inventory differs")
    put(label, normalized)
    raw.unlink()


def command_body(evidence, name, target, pin, count, *, options=()):
    path = evidence / name
    require_success(capture([NINJA, "-t", "commands", *options, target], path, 45, pin[0], cwd=BUILD), name)
    _, _, body = file_data(path, pin[0], expected=pin, collect=True)
    need(body.endswith(b"\n") and body.count(b"\n") == count, "Wrong generated command count " + name)
    return body


def dry_run_steps(dry, core_commands, gui_commands, gui_link):
    lines = dry.splitlines()
    available = Counter(gui_commands.splitlines())
    inherited = set(core_commands.splitlines())
    need(dry.endswith(b"\n") and 0 < len(lines) <= 639, "Expected bounded actionable QtGui dry run")
    commands = []
    for index, line in enumerate(lines, 1):
        match = PROGRESS.fullmatch(line)
        need(match is not None and int(match[1]) == index and int(match[2]) == len(lines),
             "Unexpected Ninja dry-run progress")
        command = match[3]
        need(available[command] > 0 and command not in inherited, "QtGui dry run expanded beyond the selected successor graph")
        available[command] -= 1
        commands.append(command)
    need(gui_link.rstrip(b"\n") in commands, "The dry run omitted the exact QtGui link edge")
    return len(commands)


def put(path, body):
    with path.open("xb") as stream:
        stream.write(body)


def put_json(path, document):
    put(path, (json.dumps(document, sort_keys=True, indent=2) + "\n").encode())


def retain_libraries(evidence, cap):
    files = (BUILD / "lib" / (GUI + VERSION), BUILD / "lib" / (DBUS + VERSION), MD4C)
    for source in files:
        with (evidence / source.name).open("xb") as copy:
            pair, _, _ = file_data(source, cap, expected=MD4C_PIN if source == MD4C else None, copy=copy)
        cap -= pair[0]


def link(plan, sha, evidence):
    phase = "inputs"
    status = "HOLD"
    result = dict(kind="QTGUI_LINK_GUEST_RESULT_V1", status=status, phase=phase, nonce=plan["nonce"],
                  plan_sha256=sha, core=plan["core"], target=TARGET)
    try:
        check_inputs()
        before = core_state(plan)
        require_missing_outputs()
        inventory(evidence, "inventory.before")
        phase = "graph"
        core = command_body(evidence, "core.commands", "lib/" + CORE + ".so", CORE_COMMANDS, 321)
        gui = command_body(evidence, "gui.commands", TARGET, GUI_COMMANDS, 639)
        direct = command_body(evidence, "gui.link-command", "lib/" + GUI + VERSION, GUI_LINK, 1, options=("-s",))
        dry_core, dry_gui = evidence / "core-dry-run.log", evidence / "gui-dry-run.log"
        require_success(capture([NINJA, "-n", "-v", "lib/" + CORE + ".so"], dry_core, 45, 4096, cwd=BUILD),
                        "QtCore dry run")
        need(file_data(dry_core, 4096, collect=True)[2] == b"ninja: no work to do.\n", "Accepted QtCore would rebuild")
        dry_cap = GUI_COMMANDS[0] + 64 * 1024
        require_success(capture([NINJA, "-n", "-v", TARGET], dry_gui, 90, dry_cap, cwd=BUILD), "QtGui dry run")
        steps = dry_run_steps(file_data(dry_gui, dry_cap, collect=True)[2], core, gui, direct)
        phase = "link"
        limits = plan["limits"]
        metrics = capture(BUILD_ARGV, evidence / "build.log", limits["guest_build_seconds"],
                          limits["build_log_bytes"], cwd=RECIPE)
        put_json(evidence / "metrics.json", metrics | {"dry_run_steps": steps})
        require_success(metrics, "QtGui link")
        phase = "verify"
        check_inputs()
        need(core_state(plan) == before, "Accepted QtCore library or aliases changed")
        inventory(evidence, "inventory.after")
        command_body(evidence, "gui.commands.after", TARGET, GUI_COMMANDS, 639)
        (evidence / "gui.commands.after").unlink()
        aliases = alias_chain(GUI)
        alias_chain(DBUS)
        retain_libraries(evidence, limits["artifact_bytes"])
        put(evidence / "aliases.txt", "".join(f"{name} -> {target}\n" for name, target, _ in aliases).encode("ascii"))
        status, phase = "PASS", "complete"
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        result["reason"] = str(error)[:512]
    result.update(status=status, phase=phase)
    put_json(evidence / "result.json", result)
    return status


def interrupt(signum, _frame):
    raise InterruptedError(f"Guest received signal {signum}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    need(sys.flags.isolated and sys.dont_write_bytecode and __debug__, "Isolated unoptimized Python is required")
    need(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 1000 and os.uname().machine == "aarch64"
         and os.sysconf("SC_PAGE_SIZE") == 16384, "Expected ordinary AArch64 guest with 16 KiB pages")
    need(args.evidence == EVIDENCE == EVIDENCE.resolve(strict=True), "Exact private evidence directory required")
    info = EVIDENCE.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 1000 and stat.S_IMODE(info.st_mode) == 0o700
         and not any(EVIDENCE.iterdir()), "Expected empty private guest evidence directory")
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    for signum in INTERRUPTS:
        signal.signal(signum, interrupt)
    plan = read_plan(args.plan, args.plan_sha256)
    return 0 if link(plan, args.plan_sha256, args.evidence) == "PASS" else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit("QtGui guest refused: " + str(error)) from None
