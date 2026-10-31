#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Software-only fresh-home journey in an existing locked native ARM container.

No packages/accounts are installed and no desktop, hardware or performance gate
is exercised. The host runner exposes only new evidence and read-only inputs.
"""
import argparse
import ast
from contextlib import contextmanager
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import pty
import pwd
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import termios
import time
from datetime import datetime, timezone

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
PACKAGES = ("cachy-asahi-hyprland-settings", "cachy-asahi-fish-config",
            "cachy-asahi-zsh-config", "cachy-asahi-setup")
OWNERS = {"/usr/bin/cachy-asahi-setup": "cachy-asahi-setup",
          "/usr/share/cachy-asahi/fish/config.fish": "cachy-asahi-fish-config",
          "/usr/share/cachy-asahi/zsh/config.zsh": "cachy-asahi-zsh-config",
          "/usr/share/cachy-asahi/hyprland/hyprland.lua": "cachy-asahi-hyprland-settings"}
TOOLS = {name: "/usr/bin/" + name for name in ("python3", "pacman", "fish", "zsh", "cc", "vim")}
TOOLS["setup"] = "/usr/bin/cachy-asahi-setup"
TEST_INPUTS = ("scripts/setup/setup.py", "scripts/setup/test_setup.py",
               "scripts/release/release.py", "scripts/release/test_release.py")
TEST_TOOLS = ("gpg", "gpgconf", "repo-add", "bsdtar", "vercmp")
RUNTIME_MOUNTS = {"/", "/inputs", "/out", "/tmp", "/proc", "/sys", "/sys/fs/cgroup", "/dev", "/dev/pts",
                  "/dev/shm", "/dev/mqueue", "/etc/hostname", "/etc/hosts", "/etc/resolv.conf",
                  "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger", "/proc/acpi", "/proc/asound",
                  "/proc/interrupts", "/proc/kcore", "/proc/keys", "/proc/latency_stats", "/proc/timer_list",
                  "/proc/timer_stats", "/proc/sched_debug", "/proc/scsi", "/sys/firmware", "/sys/devices/virtual/powercap"}
RUNTIME_TYPES = {"/proc": ({"proc"}, {"rw", "nosuid", "nodev"}), "/sys": ({"sysfs"}, {"ro", "nosuid", "nodev"}),
                 "/sys/fs/cgroup": ({"cgroup", "cgroup2"}, {"ro"}), "/dev": ({"tmpfs"}, {"rw", "nosuid"}),
                 "/dev/pts": ({"devpts"}, {"rw", "nosuid"}), "/dev/shm": ({"tmpfs"}, {"rw", "nosuid", "nodev"}),
                 "/dev/mqueue": ({"mqueue"}, {"rw", "nosuid", "nodev"})}
RUNTIME_FILES = {"/etc/hostname", "/etc/hosts", "/etc/resolv.conf"}
NULL_MASKS = {"/proc/interrupts", "/proc/kcore", "/proc/keys", "/proc/latency_stats", "/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug"}


class Failure(ValueError):
    pass


class Interrupted(Failure):
    pass


def interrupt(signum, frame):
    raise Interrupted("interrupted by SIGTERM")


@contextmanager
def spawn_signals():
    """Assign the child handle before deferred cancellation can raise in parent."""
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
    try:
        yield lambda: signal.pthread_sigmask(signal.SIG_SETMASK, previous)
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


@contextmanager
def defer_cancellation():
    """Finish bounded cleanup/evidence writes before exposing cancellation again."""
    events = []
    previous = {sig: signal.signal(sig, lambda signum, frame: events.append(signum)) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        yield events
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, data):
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def now():
    return datetime.now(timezone.utc).isoformat()


def pinned_bytes(path, expected):
    if not re.fullmatch(r"[0-9a-f]{64}", expected or ""):
        raise Failure("reviewed full SHA-256 required")
    content = Path(path).read_bytes()
    if hashlib.sha256(content).hexdigest() != expected:
        raise Failure(f"reviewed input changed: {path}")
    return content


def package_lock(text):
    lines = text.splitlines(keepends=True)
    if not lines or text != "".join(sorted(lines)) or not text.endswith("\n"):
        raise Failure("complete nonempty sorted pacman -Q inventory required")
    pairs = [line.split() for line in lines]
    if any(len(pair) != 2 for pair in pairs) or len({pair[0] for pair in pairs}) != len(pairs):
        raise Failure("invalid/duplicate package inventory")
    versions = dict(pairs)
    if not set(PACKAGES) <= versions.keys():
        raise Failure("installed inventory lacks an original overlay package; lifecycle prerequisite incomplete")
    return versions


def baseline_manifest(data, versions):
    rows = data.get("baseline")
    if not isinstance(rows, list) or len(rows) != len(PACKAGES) or {row.get("name") for row in rows} != set(PACKAGES):
        raise Failure("baseline manifest must identify exactly all four original packages")
    paths = set()
    for row in rows:
        if versions.get(row["name"]) != row.get("version") or not re.fullmatch(r"[0-9a-f]{64}", row.get("sha256", "")):
            raise Failure("native baseline version/archive pin differs from installed inventory")
        payload = row.get("payload_sha256")
        if not isinstance(payload, dict) or not payload:
            raise Failure("complete native-baseline regular-file payload map required")
        for relative, digest in payload.items():
            path = PurePosixPath(relative)
            if (path.is_absolute() or ".." in path.parts or str(path) != relative or not relative.startswith("usr/")
                    or relative in paths or not re.fullmatch(r"[0-9a-f]{64}", digest)):
                raise Failure("unsafe/duplicate/unpinned baseline payload path")
            paths.add(relative)
    if not {path.lstrip("/") for path in OWNERS} <= paths:
        raise Failure("baseline map lacks installed helper or shell/desktop templates")
    return rows


def installed_payloads(rows, root=Path("/"), root_owned=True):
    audits = {}
    for row in rows:
        audit = {}
        for relative, expected in row["payload_sha256"].items():
            path = root / relative
            parent = path.parent
            while parent != root:
                if parent.is_symlink():
                    raise Failure(f"installed payload ancestor is a symlink: {relative}")
                parent = parent.parent
            item = path.lstat()
            if (not stat.S_ISREG(item.st_mode) or sha(path) != expected or item.st_mode & 0o6022
                    or (root_owned and (item.st_uid != 0 or item.st_gid != 0))):
                raise Failure(f"installed native-baseline payload differs: {relative}")
            audit[relative] = {"sha256": sha(path), "mode": stat.S_IMODE(item.st_mode), "uid": item.st_uid, "gid": item.st_gid}
        audits[row["name"]] = {"version": row["version"], "native_archive_sha256": row["sha256"], "files": audit}
    return audits


def load_tool(relative, name):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def mounts():
    result = {}
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        before, after = line.split(" - ", 1)
        fields = before.split()
        result[fields[4]] = {"flags": fields[5].split(","), "type": after.split()[0]}
    return result


def container_facts():
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    observed_mounts = mounts()
    return {"system": platform.system(), "architecture": platform.machine(), "uid": os.geteuid(), "gid": os.getegid(),
            "page_size": os.sysconf("SC_PAGE_SIZE"), "kernel": platform.release(),
            "dockerenv": Path("/.dockerenv").is_file(), "mounts": observed_mounts,
            "capabilities": int(status["CapEff"].strip(), 16), "no_new_privileges": status["NoNewPrivs"].strip(),
            "nonce": os.environ.get("CACHY_ASAHI_ONBOARDING"), "home": os.environ.get("HOME"),
            "account": pwd.getpwuid(os.geteuid()).pw_name, "image_id": os.environ.get("CACHY_ASAHI_IMAGE_ID"),
            "docker_socket_exposed": Path("/var/run/docker.sock").exists() or Path("/run/docker.sock").exists(),
            "python": sys.version, "network_interfaces": sorted(p.name for p in Path("/sys/class/net").iterdir()),
            "output_empty": not any(Path("/out").iterdir()), "fresh_home_absent": not Path("/tmp/onboarding").exists(),
            "unexpected_devices": [str(p) for p in Path("/dev").rglob("*")
                                   if (stat.S_ISCHR(p.lstat().st_mode) or stat.S_ISBLK(p.lstat().st_mode))
                                   and str(p) not in {"/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/tty", "/dev/pts/ptmx"}
                                   and not re.fullmatch(r"/dev/pts/[0-9]+", str(p))],
            "unexpected_sockets": [str(p) for directory in ("/run", "/dev", "/inputs") for p in Path(directory).rglob("*")
                                   if stat.S_ISSOCK(p.lstat().st_mode)],
            "directory_owners": {name: {"uid": Path(name).stat().st_uid, "gid": Path(name).stat().st_gid,
                                       "mode": stat.S_IMODE(Path(name).stat().st_mode)} for name in ("/tmp", "/out")},
            "runtime_files": {name: {"regular": stat.S_ISREG(Path(name).lstat().st_mode), "uid": Path(name).stat().st_uid,
                                     "gid": Path(name).stat().st_gid, "mode": stat.S_IMODE(Path(name).stat().st_mode)} for name in RUNTIME_FILES},
            "null_masks": {name: stat.S_ISCHR(Path(name).lstat().st_mode) and os.major(Path(name).stat().st_rdev) == 1
                           and os.minor(Path(name).stat().st_rdev) == 3 for name in NULL_MASKS if name in observed_mounts}}


def validate_container(contract, facts):
    if contract.get("software_only") is not True or not re.fullmatch(r"[0-9a-f]{32}", contract.get("nonce", "")):
        raise Failure("invalid software container contract")
    if facts["system"] != "Linux" or facts["architecture"] != "aarch64" or not facts["dockerenv"]:
        raise Failure("actual disposable Linux/aarch64 Docker runtime required")
    if facts["uid"] == 0 or facts["uid"] != contract["uid"] or facts["gid"] != contract["gid"]:
        raise Failure("ordinary non-root container identity differs from contract")
    if facts["capabilities"] != 0 or facts["no_new_privileges"] != "1":
        raise Failure("capability drop/no-new-privileges contract missing")
    if facts["nonce"] != contract["nonce"] or facts["home"] != "/tmp/onboarding/home":
        raise Failure("isolated HOME/nonce contract missing")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", contract.get("image_id", "")) or facts.get("image_id") != contract["image_id"]:
        raise Failure("actual caller-observed immutable image identity contract missing")
    if facts.get("network_interfaces") != ["lo"]:
        raise Failure("network-disabled container required")
    for point, flag, kind in (("/", "ro", None), ("/inputs", "ro", None), ("/out", "rw", None), ("/tmp", "rw", "tmpfs")):
        mount = facts["mounts"].get(point, {})
        if flag not in mount.get("flags", []) or (kind is not None and mount.get("type") != kind):
            raise Failure(f"required isolated mount missing: {point}")
    if facts["mounts"].get("/dev/pts", {}).get("type") != "devpts":
        raise Failure("pseudo-terminal prerequisite missing")
    if not {"nosuid", "nodev"} <= set(facts["mounts"]["/tmp"]["flags"]):
        raise Failure("owned no-suid/no-device tmpfs required")
    for point, owner in facts.get("directory_owners", {}).items():
        if owner["uid"] != contract["uid"] or owner["gid"] != contract["gid"] or owner["mode"] & 0o022:
            raise Failure(f"unsafe disposable directory ownership: {point}")
    if set(facts.get("directory_owners", {})) != {"/tmp", "/out"}:
        raise Failure("temporary/evidence owner observations missing")
    if any(point.startswith(("/home", "/root", "/usr", "/var/lib/pacman")) for point in facts["mounts"]):
        raise Failure("host home/system mounts forbidden")
    extras = set(facts["mounts"]) - RUNTIME_MOUNTS
    if extras:
        raise Failure(f"unexpected runtime mount: {sorted(extras)}")
    for point, (types, flags) in RUNTIME_TYPES.items():
        mount = facts["mounts"].get(point, {})
        if mount.get("type") not in types or not flags <= set(mount.get("flags", [])):
            raise Failure(f"unsafe runtime filesystem type/flags: {point}")
    for point, mount in facts["mounts"].items():
        if point.startswith(("/proc/", "/sys/")) and point not in RUNTIME_TYPES:
            if (point in NULL_MASKS and mount.get("type") == "tmpfs" and facts.get("null_masks", {}).get(point) is True):
                continue  # runc masks files with the actual null device, which may inherit rw.
            if mount.get("type") not in ("proc", "tmpfs", "sysfs") or "ro" not in mount.get("flags", []):
                raise Failure(f"unsafe runtime mask: {point}")
    if set(facts.get("runtime_files", {})) != RUNTIME_FILES:
        raise Failure("Docker-managed runtime file observations required")
    for point, item in facts["runtime_files"].items():
        if not item["regular"] or item["uid"] != 0 or item["gid"] != 0 or item["mode"] & 0o022:
            raise Failure(f"unsafe Docker-managed runtime file: {point}")
    if facts.get("unexpected_devices") != [] or facts.get("unexpected_sockets") != []:
        raise Failure("host device/socket exposure forbidden")
    if facts.get("output_empty") is not True or facts.get("fresh_home_absent") is not True:
        raise Failure("new empty evidence and absent fresh-home workspace required")
    if facts.get("docker_socket_exposed") is not False:
        raise Failure("Docker socket must not be exposed inside journey")


class Commands:
    def __init__(self, out, env, cwd, timeout=20, phase="journey"):
        self.out, self.env, self.cwd, self.timeout = Path(out), env, Path(cwd), timeout
        self.records, self.phase = [], phase

    def run(self, label, argv, terminal=False, expected=None, prompt_response=None):
        record = {"step": label, "argv": argv, "cwd": str(self.cwd), "environment": self.env,
                  "terminal": "PTY, scripted command" if terminal else "captured process", "started_at": now()}
        stdout, stderr, error, process = b"", b"", None, None
        master = slave = None
        chunks = []
        selector = None
        responded = False
        try:
            if terminal:
                master, slave = pty.openpty()
                flags = termios.tcgetattr(slave)
                flags[3] &= ~termios.ECHO
                termios.tcsetattr(slave, termios.TCSANOW, flags)
                with spawn_signals() as restore_signals:
                    def terminal_session():
                        os.setsid()
                        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
                        restore_signals()
                    process = subprocess.Popen(argv, cwd=self.cwd, env=self.env, stdin=slave, stdout=slave, stderr=slave,
                                               preexec_fn=terminal_session)
                os.close(slave)
                slave = None
                selector = selectors.DefaultSelector()
                selector.register(master, selectors.EVENT_READ)
                deadline = time.monotonic() + self.timeout
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(argv, self.timeout)
                    if selector.select(min(.05, remaining)):
                        try:
                            chunk = os.read(master, 65536)
                        except OSError as exc:
                            if exc.errno != 5:  # Linux PTY signals EOF with EIO.
                                raise
                            chunk = b""
                        if not chunk:
                            break
                        chunks.append(chunk)
                        if prompt_response is not None and not responded and prompt_response[0].encode() in b"".join(chunks):
                            os.write(master, prompt_response[1].encode())
                            responded = True
                    elif process.poll() is not None:
                        break
                stdout = b"".join(chunks)
                process.wait(timeout=max(.01, deadline - time.monotonic()))
            else:
                with spawn_signals() as restore_signals:
                    process = subprocess.Popen(argv, cwd=self.cwd, env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                               stdin=subprocess.DEVNULL, start_new_session=True, preexec_fn=restore_signals)
                stdout, stderr = process.communicate(timeout=self.timeout)
        except (OSError, subprocess.TimeoutExpired, KeyboardInterrupt, Interrupted) as exc:
            error = type(exc).__name__ + ": " + str(exc)
            if isinstance(exc, subprocess.TimeoutExpired) and not terminal:
                stdout, stderr = exc.output or b"", exc.stderr or b""
        finally:
            with defer_cancellation() as cancellation:
                if process is not None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        error = error or "unreaped workload"
                    if not terminal:
                        try:
                            stdout, stderr = process.communicate(timeout=1)
                        except subprocess.TimeoutExpired:
                            error = error or "unclosed workload output"
                if terminal:
                    stdout = b"".join(chunks)
                if selector is not None:
                    selector.close()
                for fd in (master, slave):
                    if fd is not None:
                        os.close(fd)
                index = len(self.records)
                stem = f"{self.phase}-{index:02d}-{label}"
                (self.out / (stem + ".stdout")).write_bytes(stdout)
                (self.out / (stem + ".stderr")).write_bytes(stderr)
                record.update({"returncode": process.returncode if process is not None else None, "error": error,
                               "finished_at": now(), "stdout_file": stem + ".stdout", "stderr_file": stem + ".stderr"})
                text = stdout.decode("utf-8", errors="replace")
                record["expected_output"] = expected
                if prompt_response is not None:
                    record["prompt_response"] = {"prompt": prompt_response[0], "response": prompt_response[1], "observed_and_sent": responded}
                record["success"] = error is None and record["returncode"] == 0 and (expected is None or expected in text)
                self.records.append(record)
                save(self.out / (self.phase + "-commands.json"), self.records)
                if cancellation:
                    record.update({"error": error or "interrupted during cleanup", "success": False})
                    save(self.out / (self.phase + "-commands.json"), self.records)
        if not record["success"]:
            raise Failure(f"step failed: {label}; see recorded output/diagnostics")
        return text


def home_snapshot(home):
    return {str(path.relative_to(home)): sha(path) for path in sorted(Path(home).rglob("*")) if path.is_file()}


def journey(source, out, scratch, tools=TOOLS, templates=Path("/usr/share/cachy-asahi")):
    """Internal ordinary-user implementation; production calls only after mount guard."""
    scratch.mkdir(mode=0o700, exist_ok=False)
    home, workspace = scratch / "home", scratch / "workspace"
    home.mkdir(mode=0o700)
    workspace.mkdir(mode=0o700)
    env = {"HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config"), "XDG_STATE_HOME": str(home / ".local/state"),
           "XDG_CACHE_HOME": str(home / ".cache"), "XDG_DATA_HOME": str(home / ".local/share"), "ZDOTDIR": str(home),
           "PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8", "TZ": "UTC", "TERM": "dumb"}
    log = Commands(out, env, workspace)
    driver = tools["setup"] if isinstance(tools["setup"], list) else [tools["setup"]]
    helper = driver + ["activate", "--components", "fish", "zsh", "--home", str(home), "--template-root", str(templates)]
    before = home_snapshot(home)
    preview = json.loads(log.run("setup-preview", helper))
    if preview.get("mode") != "preview" or home_snapshot(home) != before:
        raise Failure("preview changed fresh user files or did not report preview")
    log.run("setup-apply", helper + ["--apply"])
    config = [home / ".config/fish/config.fish", home / ".zshrc"]
    first = [sha(p) for p in config]
    log.run("setup-repeat", helper + ["--apply"])
    if [sha(p) for p in config] != first:
        raise Failure("repeat setup changed managed configuration bytes")
    log.run("terminal", [tools["python3"], "-I", "-c", "import os;assert all(os.isatty(fd) for fd in (0,1,2));print('CACHY_ASAHI_TERMINAL_OK')"],
            terminal=True, expected="CACHY_ASAHI_TERMINAL_OK")
    (workspace / "sentinel-onboarding").write_text("original journey fixture\n")
    fish = "functions -q caa_ll caa_mcd; or exit 21; caa_ll; caa_mcd 'space directory'; or exit 22; test (basename $PWD) = 'space directory'; or exit 23; caa_mcd; test $status -eq 2; or exit 24; printf '%s\\n' CACHY_ASAHI_FISH_OK"
    text = log.run("fish-startup", [tools["fish"], "--private", "--interactive", "--command", fish], terminal=True, expected="CACHY_ASAHI_FISH_OK")
    if "sentinel-onboarding" not in text or not (workspace / "space directory").is_dir():
        raise Failure("Fish helper listing/directory action missing")
    zsh = "[[ -o interactive && $_CACHY_ASAHI_ZSH_LOADED == 1 && ${+_comps} == 1 && -n $_comps[cd] ]] || exit 25; print -r -- CACHY_ASAHI_ZSH_OK"
    log.run("zsh-startup", [tools["zsh"], "-d", "-i", "-c", zsh], terminal=True, expected="CACHY_ASAHI_ZSH_OK")
    if list(home.rglob(".zcompdump*")):
        raise Failure("unexpected persistent Zsh completion dump")
    target = workspace / "examples/development/hello.c"
    target.parent.mkdir(parents=True)
    target.write_bytes(Path(source).read_bytes())
    original = sha(target)
    log.run("editor", [tools["vim"], "-Nu", "NONE", "-n", "-i", "NONE", "-es", "examples/development/hello.c",
                       "-c", "call append(line('$'), '// Disposable software onboarding edit')", "-c", "wq"])
    expected = Path(source).read_bytes() + b"// Disposable software onboarding edit\n"
    if target.read_bytes() != expected:
        raise Failure("scripted editor did not preserve original program plus exact comment")
    (workspace / "build/onboarding").mkdir(parents=True)
    log.run("compiler-version", [tools["cc"], "--version"])
    log.run("compile", [tools["cc"], "-Wall", "-Wextra", "-Werror", "-O2", "examples/development/hello.c", "-o", "build/onboarding/hello"])
    output = log.run("hello", ["./build/onboarding/hello"])
    if output != "Hello from cachy-asahi\n":
        raise Failure("example output differs from documented exact output")
    removal = driver + ["remove", "--components", "fish", "zsh", "--home", str(home), "--template-root", str(templates), "--apply"]
    log.run("setup-remove", removal)
    log.run("fish-after-remove", [tools["fish"], "--private", "--interactive", "--command",
                                 "functions -q caa_ll; and exit 26; functions -q caa_mcd; and exit 27; printf '%s\\n' CACHY_ASAHI_FISH_REMOVED"],
            terminal=True, expected="CACHY_ASAHI_FISH_REMOVED")
    log.run("zsh-after-remove", [tools["zsh"], "-d", "-i", "-c",
                                "(( ${+_CACHY_ASAHI_ZSH_LOADED} == 0 )) || exit 28; print -r -- CACHY_ASAHI_ZSH_REMOVED"],
            terminal=True, expected="CACHY_ASAHI_ZSH_REMOVED",
            prompt_response=("--- Type one of the keys in parentheses ---", "0\n"))
    shutil.copyfile(target, Path(out) / "edited-hello.c")
    shutil.copyfile(workspace / "build/onboarding/hello", Path(out) / "hello")
    return {"original_source_sha256": original, "edited_source_sha256": sha(target),
            "binary_sha256": sha(workspace / "build/onboarding/hello"), "steps": len(log.records),
            "home": str(home), "editor_scope": "scripted noninteractive Vim, not GUI/editor usability",
            "terminal_scope": "software PTY and interactive shell startup, not graphical terminal integration"}


def test_count(path):
    return sum(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_")
               for node in ast.walk(ast.parse(Path(path).read_text())))


def run_suites(inputs, out, home, counts):
    env = {"HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config"), "XDG_STATE_HOME": str(home / ".local/state"),
           "XDG_CACHE_HOME": str(home / ".cache"), "XDG_DATA_HOME": str(home / ".local/share"), "ZDOTDIR": str(home),
           "PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8", "TZ": "UTC", "PYTHONDONTWRITEBYTECODE": "1"}
    log = Commands(out, env, inputs, timeout=90, phase="suites")
    runner = """import json,sys,unittest
from pathlib import Path
suite=unittest.TestLoader().discover(sys.argv[1],pattern=sys.argv[2])
result=unittest.TextTestRunner(verbosity=2).run(suite)
report={'tests_run':result.testsRun,'skipped':[[str(test),reason] for test,reason in result.skipped],'failures':len(result.failures),'errors':len(result.errors),
        'expected':int(sys.argv[4]),'scope':'software fixtures; no M2/release acceptance'}
Path(sys.argv[3]).write_text(json.dumps(report,indent=2)+'\\n')
raise SystemExit(0 if result.wasSuccessful() and not result.skipped and result.testsRun==int(sys.argv[4]) else 2)
"""
    reports = {}
    for name, filename in (("setup", "test_setup.py"), ("release", "test_release.py")):
        report = Path(out) / (name + "-tests.json")
        log.run(name + "-tests", [TOOLS["python3"], "-I", "-B", "-c", runner, str(inputs / "scripts" / name),
                                 filename, str(report), str(counts[name])])
        reports[name] = json.loads(report.read_text())
    return reports


def inside():
    inputs, out = Path("/inputs"), Path("/out")
    contract = json.loads((inputs / "contract.json").read_text())
    facts = container_facts()
    validate_container(contract, facts)  # No writes/helper execution before the actual mount/security guard.
    report = {"status": "failed", "scope": "disposable native ARM software onboarding", "facts": facts,
              "contract": contract, "started_at": now(), "hardware": "NOT RUN", "full_onboarding": "NOT RUN",
              "package_trust": "external lifecycle prerequisite, not assessed by this journey"}
    env = {"HOME": "/tmp/onboarding/home", "PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8", "TZ": "UTC"}
    query = Commands(out, env, inputs, phase="preflight")
    try:
        for name, path in TOOLS.items():
            if not os.access(path, os.X_OK):
                raise Failure(f"missing installed prerequisite: {name} ({path})")
        for name in TEST_TOOLS:
            if not os.access("/usr/bin/" + name, os.X_OK):
                raise Failure(f"missing installed software-suite prerequisite: {name}")
        lock = pinned_bytes(inputs / "packages.lock", contract["packages_sha256"]).decode()
        versions = package_lock(lock)
        baseline = json.loads(pinned_bytes(inputs / "baseline-manifest.json", contract["baseline_manifest_sha256"]))
        rows = baseline_manifest(baseline, versions)
        report["installed_baseline_payloads"] = installed_payloads(rows)
        pinned_bytes(inputs / "examples/development/hello.c", contract["source_sha256"])
        pinned_bytes(Path(__file__), contract["entry_sha256"])
        for path, expected in contract["test_inputs"].items():
            pinned_bytes(inputs / path, expected)
        if sha(TOOLS["setup"]) != contract["test_inputs"]["scripts/setup/setup.py"]:
            raise Failure("installed helper differs from frozen source tested by the helper suite")
        actual = query.run("inventory-before", [TOOLS["pacman"], "-Q"])
        actual = "".join(sorted(actual.splitlines(keepends=True)))
        if actual != lock:
            raise Failure("installed image package inventory differs from reviewed complete lock")
        for index, (path, expected) in enumerate(OWNERS.items()):
            owner = query.run(f"ownership-{index}", [TOOLS["pacman"], "-Qqo", path]).strip()
            if owner != expected:
                raise Failure(f"installed file has unexpected package owner: {path}")
        for index, row in enumerate(rows):
            listed = query.run(f"payload-list-{index}", [TOOLS["pacman"], "-Ql", row["name"]])
            owned = {line.split(" ", 1)[1].lstrip("/") for line in listed.splitlines() if not line.endswith("/")}
            if owned != set(row["payload_sha256"]):
                raise Failure("package file ownership differs from complete native-baseline payload manifest")
        report["journey"] = journey(inputs / "examples/development/hello.c", out, Path("/tmp/onboarding"))
        report["software_suites"] = run_suites(inputs, out, Path("/tmp/onboarding/home"), contract["test_counts"])
        after = query.run("inventory-after", [TOOLS["pacman"], "-Q"])
        if "".join(sorted(after.splitlines(keepends=True))) != lock:
            raise Failure("journey changed installed package inventory")
        if installed_payloads(rows) != report["installed_baseline_payloads"]:
            raise Failure("journey changed installed baseline payloads")
        report["status"] = "SOFTWARE PASS"
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
        print(str(error), file=sys.stderr)
        return 2
    finally:
        report["finished_at"] = now()
        report["files"] = {p.name: sha(p) for p in out.iterdir() if p.is_file() and p.name != "result.json"}
        save(out / "result.json", report)


def host(args):
    out = args.output.resolve()
    evidence = {"status": "failed", "scope": "native ARM software only", "hardware": "NOT RUN", "full_onboarding": "NOT RUN", "started_at": now()}
    created, container, launcher, exit_code = False, None, None, 2
    try:
        build = load_tool("scripts/build/build.py", "onboarding_build_tools")
        image = build.image_pin(args.image)
        source = pinned_bytes(args.source, args.source_sha256)
        lock = pinned_bytes(args.expected_packages, args.expected_packages_sha256)
        versions = package_lock(lock.decode())
        baseline = pinned_bytes(args.baseline_manifest, args.baseline_manifest_sha256)
        baseline_manifest(json.loads(baseline), versions)
        if args.timeout < 1 or any("," in str(p) or "\n" in str(p) for p in (out, args.source.resolve(), args.expected_packages.resolve())):
            raise Failure("invalid timeout/bind-mount path")
        out.mkdir(parents=True, exist_ok=False)
        created = True
        native = load_tool("scripts/ci/native_arm.py", "onboarding_native_tools")
        evidence["runner"] = native.probe(out)
        info = json.loads(native.run(["docker", "image", "inspect", image], timeout=30))[0]
        if info["Architecture"] != "arm64" or info["Os"] != "linux":
            raise Failure("installed immutable image must be linux/arm64")
        inputs, artifacts = out / "inputs", out / "artifacts"
        (inputs / "scripts/integration").mkdir(parents=True)
        (inputs / "examples/development").mkdir(parents=True)
        artifacts.mkdir()
        (inputs / "examples/development/hello.c").write_bytes(source)
        (inputs / "packages.lock").write_bytes(lock)
        (inputs / "baseline-manifest.json").write_bytes(baseline)
        tests = {}
        for relative in TEST_INPUTS:
            destination = inputs / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((ROOT / relative).read_bytes())
            tests[relative] = sha(destination)
        entry = inputs / "scripts/integration/onboarding.py"
        shutil.copyfile(__file__, entry)
        nonce = os.urandom(16).hex()
        contract = {"software_only": True, "nonce": nonce, "uid": os.getuid(), "gid": os.getgid(),
                    "image_id": info["Id"], "packages_sha256": sha(inputs / "packages.lock"),
                    "source_sha256": sha(inputs / "examples/development/hello.c"), "entry_sha256": sha(entry),
                    "baseline_manifest_sha256": sha(inputs / "baseline-manifest.json"),
                    "test_inputs": tests, "test_counts": {name: test_count(inputs / f"scripts/{name}/test_{name}.py")
                                                         for name in ("setup", "release")}}
        save(inputs / "contract.json", contract)
        container = "cachy-asahi-onboarding-" + nonce
        command = ["docker", "run", "--rm", "--name", container, "--pull=never", "--platform=linux/arm64",
                   "--user", f"{os.getuid()}:{os.getgid()}", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                   "--read-only", "--network=none", "--pids-limit=128", "--memory=512m", "--cpus=2",
                   "--tmpfs", f"/tmp:rw,nosuid,nodev,exec,size=256m,mode=0700,uid={os.getuid()},gid={os.getgid()}",
                   "--env", f"CACHY_ASAHI_ONBOARDING={nonce}", "--env", "HOME=/tmp/onboarding/home",
                   "--env", f"CACHY_ASAHI_IMAGE_ID={info['Id']}",
                   "--mount", f"type=bind,src={inputs},dst=/inputs,readonly",
                   "--mount", f"type=bind,src={artifacts},dst=/out", "--entrypoint=/usr/bin/python3",
                   info["Id"], "-I", "/inputs/scripts/integration/onboarding.py", "--inside"]
        evidence.update({"image": image, "image_id": info["Id"], "container": container, "command": command,
                         "contract": contract, "probe_script_sha256": sha(ROOT / "scripts/ci/native_arm.py"),
                         "image_tools_sha256": sha(ROOT / "scripts/build/build.py")})
        save(out / "provenance.json", evidence)
        with (out / "container.log").open("wb") as log:
            with spawn_signals() as restore_signals:
                launcher = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True, preexec_fn=restore_signals)
            launcher.wait(timeout=args.timeout)
        evidence["exit_code"] = launcher.returncode
        result = json.loads((artifacts / "result.json").read_text())
        if launcher.returncode or result.get("status") != "SOFTWARE PASS" or result.get("contract") != contract:
            raise Failure("container software journey failed; inspect preserved diagnostics")
        evidence["status"] = "SOFTWARE PASS"
        exit_code = 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, argparse.ArgumentTypeError, KeyboardInterrupt) as error:
        evidence["error"] = str(error)
        print(str(error), file=sys.stderr)
    finally:
        with defer_cancellation() as cancellation:
            if launcher is not None:
                try:
                    os.killpg(launcher.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    launcher.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    evidence.update({"launcher_cleanup_error": "unreaped owned Docker launcher", "status": "failed"})
                    exit_code = 2
            if container is not None:
                try:
                    cleanup = subprocess.run(["docker", "rm", "-f", container], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
                    diagnostic = cleanup.stderr.decode(errors="replace")
                    evidence["cleanup"] = {"argv": ["docker", "rm", "-f", container], "returncode": cleanup.returncode, "stderr": diagnostic}
                    if cleanup.returncode and not ("No such container" in diagnostic and container in diagnostic):
                        raise Failure("owned container removal failed")
                except (OSError, subprocess.TimeoutExpired, Failure) as error:
                    evidence.update({"cleanup_error": str(error), "status": "failed"})
                    exit_code = 2
            if cancellation:
                evidence.update({"error": "interrupted during cleanup", "status": "failed"})
                exit_code = 2
            if created:
                evidence["finished_at"] = now()
                save(out / "provenance.json", evidence)
    return exit_code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--image")
    parser.add_argument("--expected-packages", type=Path)
    parser.add_argument("--expected-packages-sha256")
    parser.add_argument("--baseline-manifest", type=Path)
    parser.add_argument("--baseline-manifest-sha256")
    parser.add_argument("--source", type=Path, default=ROOT / "examples/development/hello.c")
    parser.add_argument("--source-sha256")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    previous = signal.signal(signal.SIGTERM, interrupt)
    try:
        if args.inside:
            try:
                return inside()
            except (OSError, ValueError, KeyError) as error:
                print(f"container contract refused: {error}", file=sys.stderr)
                return 2
        if not all((args.image, args.expected_packages, args.expected_packages_sha256, args.baseline_manifest,
                    args.baseline_manifest_sha256, args.source_sha256, args.output)):
            parser.error("image, reviewed installed package/source inputs and new output directory required")
        return host(args)
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    raise SystemExit(main())
