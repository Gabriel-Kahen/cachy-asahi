# SPDX-License-Identifier: MIT
"""Supervise the reviewed Weston fixture in the owned offline Asahi629 guest."""

from contextlib import contextmanager
import hashlib
from itertools import islice
import json
import os
from pathlib import Path
import re
from runpy import run_path
import shutil
import signal
import socket
import stat
import struct
import subprocess
from tempfile import TemporaryFile
import time


F = run_path(str(Path(__file__).with_name("weston_fixture.py")))
need = F["need"]
TARGET = Path("/trial-scratch")
WORK = Path("/trial-work")
FIXTURE = "/tmp/qt629-weston"
RUNTIME = "/run/qt629-wl"
SOCKET = RUNTIME + "/wayland-0"
USER = 65534
LOG_CAP = 1 << 20
STARTUP_SECONDS = 20
TERM_SECONDS = 8
KILL_SECONDS = 3
PROBES = {"vendor-raster": 1, "vendor-qrhi": 2, "replacement-raster": 1, "replacement-qrhi": 2}
LOG_NAME = "weston-server.log"
REPORT_NAME = "weston-lifecycle.json"
KIND = "QT629_WESTON_LIFECYCLE_V1"
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"}
PROTO = re.compile(rb"\[\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}\]\[proto\] client (0x[0-9a-f]+) \(PID ([0-9]+)\) "
                   rb"(rq|ev) ([a-z0-9_]+)@([0-9]+)\.([a-z0-9_]+)\((.*)\)")


def path_inside(path):
    return TARGET / path.lstrip("/")


def pin(body):
    return dict(bytes=len(body), sha256=hashlib.sha256(body).hexdigest())


def environment(nonce):
    need(os.getuid() == os.geteuid() == 0 and os.uname().machine == "aarch64"
         and os.sysconf("SC_PAGE_SIZE") == 16384 and set(os.listdir("/sys/class/net")) == {"lo"},
         "Expected an owned offline AArch64 16 KiB guest")
    with Path("/proc/cmdline").open("rb") as stream:
        cmdline = stream.read((16 << 10) + 1)
    key = b"cachy_overlay583_nonce"
    need(type(nonce) is str and re.fullmatch(r"[0-9a-f]{32}", nonce) and len(cmdline) <= 16 << 10
         and [word for word in cmdline.split() if word.partition(b"=")[0] == key] == [key + b"=" + nonce.encode()],
         "Weston requires the selected guest boot nonce")
    rows = [fields for line in Path("/proc/self/mountinfo").read_text().splitlines() if (fields := line.split())]
    for path, mode, fstype, extra in (
        (Path("/"), "ro", "ext4", set()), (TARGET, "rw", "ext4", {"nosuid", "nodev"}),
        (path_inside("/run"), "rw", "tmpfs", {"nosuid", "nodev", "noexec"}),
        (WORK, "rw", "tmpfs", {"nosuid", "nodev", "noexec"}),
    ):
        matching = [row for row in rows if row[4] == str(path)]
        need(len(matching) == 1, f"Expected one owned mount for {path}")
        row = matching[0]
        need(row[row.index("-") + 1] == fstype and {mode} | extra <= set(row[5].split(",")),
             f"Wrong guest mount policy for {path}")
    need(not any(row[4] == str(path_inside("/tmp")) or row[4].startswith(str(path_inside("/tmp")) + "/") for row in rows),
         "Weston requires executable scratch on the disposable target filesystem")


def identity(path):
    row = path.lstat()
    return row.st_dev, row.st_ino


def path_absent(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    return False


def claim_fixture(path):
    row = path.lstat()
    need(stat.S_ISDIR(row.st_mode) and row.st_uid == row.st_gid == 0 and row.st_dev == TARGET.stat().st_dev
         and stat.S_IMODE(row.st_mode) in (0o700, 0o755) and path.resolve(strict=True) == path,
         "Cannot prove ownership of the staged Weston fixture directory")
    return row.st_dev, row.st_ino


def validate_fixture(receipt):
    expected = {name: dict(type="file", mode=0o755, **ref) for name, ref in F["FILES"].items()}
    expected.update({name: dict(type="symlink", target=target) for name, target in F["LINKS"].items()})
    need(receipt["kind"] == F["KIND"] and receipt["filename"] == F["ARCHIVE"] and receipt["inputs"] == F["PINS"]
         and receipt["signer"] == F["A"]["FINGERPRINT"] and receipt["members"] == expected,
         "Weston intake receipt differs from the reviewed package and members")
    root = path_inside(FIXTURE)
    root_id = identity(root)
    directories = {root, *(root / leaf for leaf in F["DIRECTORIES"])}
    need(root.resolve(strict=True) == root and root_id[0] == TARGET.stat().st_dev, "Wrong Weston fixture mount or path")
    nodes = {root, *islice(root.rglob("*"), len(directories) + len(expected))}
    need(nodes == directories | {root / leaf for leaf in expected}, "Unexpected staged Weston fixture paths")
    for path in directories:
        row = path.lstat()
        need(stat.S_ISDIR(row.st_mode) and (row.st_uid, row.st_gid, stat.S_IMODE(row.st_mode)) == (0, 0, 0o755)
             and row.st_dev == root_id[0], f"Unexpected Weston fixture directory: {path.name}")
    for leaf, entry in expected.items():
        path = root / leaf
        row = path.lstat()
        need((row.st_uid, row.st_gid, row.st_nlink, row.st_dev) == (0, 0, 1, root_id[0]),
             f"Unexpected staged Weston owner or inode: {leaf}")
        if entry["type"] == "symlink":
            need(stat.S_ISLNK(row.st_mode) and os.readlink(path) == entry["target"], f"Weston SONAME link differs: {leaf}")
        else:
            need(stat.S_ISREG(row.st_mode) and stat.S_IMODE(row.st_mode) == entry["mode"],
                 f"Unexpected staged Weston ELF mode: {leaf}")
            F["A"]["verify"](path, F["FILES"][leaf])
    return root_id


def guest_command(*args, compositor=False):
    settings = dict(ENV, HOME=RUNTIME + "/home", TMPDIR=RUNTIME + "/tmp", XDG_RUNTIME_DIR=RUNTIME,
                    LD_LIBRARY_PATH=f"{FIXTURE}/usr/lib:{FIXTURE}/usr/lib/weston")
    if compositor:
        settings["WESTON_MODULE_MAP"] = (f"headless-backend.so={FIXTURE}/usr/lib/libweston-15/headless-backend.so;"
                                         f"kiosk-shell.so={FIXTURE}/usr/lib/weston/kiosk-shell.so")
    return ["/usr/bin/chroot", str(TARGET), "/usr/bin/setpriv", f"--reuid={USER}", f"--regid={USER}",
            "--clear-groups", "--no-new-privs", "--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all",
            "/usr/bin/env", "-i", *(f"{name}={value}" for name, value in sorted(settings.items())), *args]


def command():
    # Weston 15's native proto scope includes the server's observed client PID
    # and connection identity. Generic WAYLAND_DEBUG output lacks both.
    return guest_command("/usr/bin/prlimit", f"--fsize={LOG_CAP}:{LOG_CAP}", "--core=0:0", "--", f"{FIXTURE}/usr/bin/weston",
                         "-B", "headless", "--renderer=pixman", "--shell=kiosk", "--socket=wayland-0",
                         "--width=256", "--height=256", "--idle-time=0", "--no-config", "--logger-scopes=log,proto",
                         compositor=True)


def dependencies(out):
    cap = 32 << 10
    selected = {"libweston-15.so.0": f"{FIXTURE}/usr/lib/libweston-15.so.0",
                "libexec_weston.so.0": f"{FIXTURE}/usr/lib/weston/libexec_weston.so.0"}
    for leaf in sorted(F["FILES"]):
        argv = guest_command("/usr/bin/prlimit", f"--fsize={cap}:{cap}", "--core=0:0", "--",
                             "/usr/lib/ld-linux-aarch64.so.1", "--list", f"{FIXTURE}/{leaf}")
        with TemporaryFile(dir=WORK) as output:
            done = subprocess.run(argv, env=ENV, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, timeout=10)
            raw = os.pread(output.fileno(), cap, 0)
        text = raw.decode("utf-8", errors="replace")
        out[leaf] = dict(exit=done.returncode, output=text, truncated=len(raw) == cap)
        need(done.returncode == 0 and len(raw) < cap and b"not found" not in raw and raw,
             f"Weston loader prerequisites failed for {leaf}")
        used = dict(re.findall(r"^\s*(\S+) => (\S+)\s+\(0x[0-9a-f]+\)$", text, re.M))
        need(used and all(path == selected[name] if name in selected else path.startswith(("/usr/lib/", "/lib/"))
                          for name, path in used.items()), f"Unexpected Weston library resolution for {leaf}")
        if leaf in ("usr/bin/weston", "usr/lib/libweston-15/headless-backend.so", "usr/lib/weston/kiosk-shell.so"):
            need(used.get("libweston-15.so.0") == selected["libweston-15.so.0"], f"Weston runtime library missing for {leaf}")
        if leaf == "usr/bin/weston":
            need(used.get("libexec_weston.so.0") == selected["libexec_weston.so.0"], "Weston frontend helper library missing")


def message(object_id, opcode, payload):
    return struct.pack("=II", object_id, ((8 + len(payload)) << 16) | opcode) + payload


def word(value):
    return struct.pack("=I", value)


def wire_string(value):
    raw = value.encode("ascii") + b"\0"
    return word(len(raw)) + raw + b"\0" * (-len(raw) % 4)


def read_wire_string(raw):
    need(len(raw) >= 4, "Short Wayland string")
    length, = struct.unpack_from("=I", raw)
    padded = (length + 3) & ~3
    need(0 < length <= 256 and 4 + padded <= len(raw) and raw[3 + length:4 + padded] == b"\0" * (padded - length + 1),
         "Malformed Weston readiness string")
    return raw[4:3 + length].decode("ascii"), raw[4 + padded:]


def roundtrip(connection, deadline):
    """Read the live registry and selected output mode on one short-lived connection."""
    events = 0

    def exact(length):
        data = bytearray()
        while len(data) < length:
            remaining = deadline - time.monotonic()
            need(remaining > 0, "Weston readiness timed out")
            connection.settimeout(remaining)
            chunk = connection.recv(length - len(data))
            need(chunk, "Weston closed the readiness connection")
            data.extend(chunk)
        return bytes(data)

    def until(callback):
        nonlocal events
        while events < 128:
            events += 1
            obj, header = struct.unpack("=II", exact(8))
            size, op = header >> 16, header & 0xffff
            need(8 <= size <= 1024 and size % 4 == 0, "Malformed Weston readiness event")
            body = exact(size - 8)
            need((obj, op) != (1, 0), "Weston reported a readiness protocol error")
            if (obj, op, len(body)) == (callback, 0, 4):
                return
            yield obj, op, body
        raise ValueError("Too many Weston readiness events")

    connection.sendall(message(1, 1, word(2)) + message(1, 0, word(3)))
    globals_seen = {}
    for obj, op, payload in until(3):
        if (obj, op) == (2, 0):
            need(len(payload) >= 12, "Short Weston registry event")
            name, = struct.unpack_from("=I", payload)
            interface, trailing = read_wire_string(payload[4:])
            need(len(trailing) == 4, "Malformed Weston registry version")
            version, = struct.unpack("=I", trailing)
            globals_seen.setdefault(interface, []).append((name, version))
    need({"wl_compositor", "wl_shm", "xdg_wm_base", "wl_output"} <= globals_seen.keys()
         and len(globals_seen["wl_output"]) == 1, "Weston must advertise one headless output and the raster/XDG globals")
    name, version = globals_seen["wl_output"][0]
    need(version >= 4, "Weston output must expose its exact name and mode")
    bind = word(name) + wire_string("wl_output") + word(4) + word(4)
    connection.sendall(message(2, 0, bind) + message(1, 0, word(5)))
    names, modes, done = [], [], False
    for obj, op, payload in until(5):
        if obj != 4:
            continue
        if op == 4:
            name, trailing = read_wire_string(payload)
            need(not trailing, "Malformed Weston output name")
            names.append(name)
        elif op == 1:
            need(len(payload) == 16, "Malformed Weston output mode")
            flags, width, height, refresh = struct.unpack("=Iiii", payload)
            if flags & 1:  # WL_OUTPUT_MODE_CURRENT
                modes.append((width, height, refresh))
        elif op == 2 and not payload:
            done = True
    need(done and names == ["headless"] and modes == [(256, 256, 60000)], "Weston headless output mode differs")
    return dict(name="headless", width=256, height=256, refresh_millihz=60000)


def ready_socket(path, process, deadline):
    row = path.lstat()
    original = row.st_dev, row.st_ino
    need(stat.S_ISSOCK(row.st_mode) and (row.st_uid, row.st_gid) == (USER, USER) and row.st_nlink == 1
         and path.resolve(strict=True) == path, "Weston socket has unexpected type, owner or pathname")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(min(1.0, max(0, deadline - time.monotonic())))
        connection.connect(os.fspath(path))
        peer = struct.unpack("=iii", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        need(peer == (process.pid, USER, USER), "Weston socket peer is not the supervised ordinary-user process")
        need(os.getpgid(process.pid) == process.pid == os.getsid(process.pid), "Weston process group is not owned")
        output = roundtrip(connection, deadline)
    need(identity(path) == original and process.poll() is None, "Weston socket or process changed during readiness")
    return dict(peer=dict(pid=peer[0], uid=peer[1], gid=peer[2]), socket_inode=list(original), output=output)


def event(pattern, args):
    match = re.fullmatch(pattern, args)
    return tuple(map(int, match.groups())) if match else None


def connection_presentation(rows, minimum):
    # Object IDs are local to one specific Weston connection. Build the surface
    # chain first, then require real SHM commits and their own frame callback.
    surfaces = set()
    xdg, toplevels, configured, acked, buffers = {}, {}, {}, {}, set()
    pending_buffers, pending_frames, committed_frames, painted, completed = {}, {}, {}, {}, []
    staged_toplevel = set()
    for line, direction, interface, object_id, method, args in rows:
        action = direction, interface, method
        if action == (b"rq", b"wl_compositor", b"create_surface"):
            new = event(rb"new id wl_surface@([0-9]+)", args)
            if new:
                need(new[0] not in surfaces, "Ambiguous Weston surface object reuse")
                surfaces.add(new[0])
        elif action == (b"rq", b"xdg_wm_base", b"get_xdg_surface"):
            new = event(rb"new id xdg_surface@([0-9]+), wl_surface@([0-9]+)", args)
            if new and new[1] in surfaces:
                need(new[0] not in xdg and new[1] not in xdg.values(), "Ambiguous Weston XDG surface reuse")
                xdg[new[0]] = new[1]
        elif action == (b"rq", b"xdg_surface", b"get_toplevel") and object_id in xdg:
            new = event(rb"new id xdg_toplevel@([0-9]+)", args)
            if new:
                need(new[0] not in toplevels, "Ambiguous Weston toplevel reuse")
                toplevels[new[0]] = object_id
        elif action == (b"ev", b"xdg_toplevel", b"configure") and object_id in toplevels:
            staged_toplevel.add(toplevels[object_id])
        elif action == (b"ev", b"xdg_surface", b"configure") and object_id in staged_toplevel:
            serial = event(rb"([0-9]+)", args)
            if serial:
                configured.setdefault(object_id, set()).add(serial[0])
        elif action == (b"rq", b"xdg_surface", b"ack_configure") and object_id in configured:
            serial = event(rb"([0-9]+)", args)
            if serial and serial[0] in configured[object_id]:
                acked[xdg[object_id]] = serial[0]
        elif action == (b"rq", b"wl_shm_pool", b"create_buffer"):
            new = event(rb"new id wl_buffer@([0-9]+), -?[0-9]+, [0-9]+, [0-9]+, [0-9]+, [0-9]+", args)
            if new:
                buffers.add(new[0])
        elif action == (b"rq", b"wl_buffer", b"destroy"):
            buffers.discard(object_id)
        elif action == (b"rq", b"wl_surface", b"attach") and object_id in surfaces:
            attached = event(rb"wl_buffer@([0-9]+), -?[0-9]+, -?[0-9]+", args)
            pending_buffers[object_id] = attached[0] if attached else None
        elif action == (b"rq", b"wl_surface", b"frame") and object_id in surfaces:
            callback = event(rb"new id wl_callback@([0-9]+)", args)
            if callback:
                pending_frames.setdefault(object_id, []).append(callback[0])
        elif action == (b"rq", b"wl_surface", b"commit") and object_id in surfaces and not args:
            buffer = pending_buffers.pop(object_id, None)
            callbacks = pending_frames.pop(object_id, [])
            if object_id in acked and buffer in buffers:
                commits = painted.setdefault(object_id, [])
                commits.append(dict(line=line, buffer=buffer, serial=acked[object_id]))
                for callback in callbacks:
                    need(callback not in committed_frames, "Ambiguous outstanding Weston frame callback")
                    committed_frames[callback] = object_id, len(commits)
        elif (action == (b"ev", b"wl_callback", b"done") and object_id in committed_frames
              and re.fullmatch(rb"[0-9]+", args)):
            surface, count = committed_frames.pop(object_id)
            if count >= minimum:
                completed.append((surface, count, object_id, line))
        elif action == (b"rq", b"wl_surface", b"destroy"):
            acked.pop(object_id, None)
            pending_buffers.pop(object_id, None)
            pending_frames.pop(object_id, None)
            for callback, (surface, _) in list(committed_frames.items()):
                if surface == object_id:
                    del committed_frames[callback]
    if not completed:
        return None
    need(len({surface for surface, _, _, _ in completed}) == 1, "Multiple presented Weston surfaces for one probe")
    surface, count, callback, line = completed[0]
    return dict(surface=surface, commits=painted[surface][:count], callback=callback, callback_line=line)


def presentation(log, pid, minimum):
    need(type(pid) is int and pid > 0 and type(minimum) is int and minimum in (1, 2)
         and len(log) < LOG_CAP and log.endswith(b"\n"), "Incomplete Weston trace or unbound probe PID")
    clients = {}
    for line_number, line in enumerate(log.splitlines(), 1):
        parsed = PROTO.fullmatch(line)
        if not parsed or int(parsed[2]) != pid:
            continue
        client, _, direction, interface, object_id, method, args = parsed.groups()
        clients.setdefault(client, []).append((line_number, direction, interface, int(object_id), method, args))
    matches = [(client, proof) for client, rows in clients.items() if (proof := connection_presentation(rows, minimum))]
    need(len(matches) == 1, "Expected one PID-bound Weston connection with configured SHM commits and a frame callback")
    client, proof = matches[0]
    return dict(pid=pid, connection=client.decode("ascii"), **proof)


def group_absent(pid):
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return True
    return False


def retire(process):
    signals, forced = [], False
    if process.poll() is None:
        need(os.getpgid(process.pid) == process.pid == os.getsid(process.pid), "Refusing to signal an unowned Weston group")
        try:
            os.killpg(process.pid, signal.SIGTERM)
            signals.append("SIGTERM")
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=TERM_SECONDS)
        except subprocess.TimeoutExpired:
            forced = True
            try:
                os.killpg(process.pid, signal.SIGKILL)  # The child remains unreaped by this worker.
                signals.append("SIGKILL")
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=KILL_SECONDS)
            except subprocess.TimeoutExpired:
                pass
    absent = process.returncode is not None and group_absent(process.pid)
    return dict(signals=signals, forced=forced, exit=process.returncode, reaped=process.returncode is not None, group_absent=absent)


def remove_owned(path, original):
    row = path.lstat()
    need((row.st_dev, row.st_ino) == original and stat.S_ISDIR(row.st_mode) and shutil.rmtree.avoids_symlink_attacks,
         f"Refusing cleanup of changed Weston directory: {path.name}")
    shutil.rmtree(path)
    return path_absent(path)


def cleanup(report, process, runtime, runtime_id, fixture, fixture_id):
    errors = []

    def verified_absent(path):
        try:
            return path_absent(path)
        except OSError as error:
            errors.append(f"Cannot verify absence of {path.name}: {error}")
            return False

    retirement = dict(reaped=False, group_absent=process is None)
    if process is not None:
        try:
            retirement = retire(process)
        except (OSError, ValueError) as error:
            errors.append(str(error))
    report["retirement"] = retirement
    socket_absent = None
    if runtime_id is not None:
        socket_absent = all(verified_absent(path_inside(SOCKET + suffix)) for suffix in ("", ".lock"))
    retirement["socket_removed_by_weston"] = socket_absent
    if retirement["group_absent"]:
        for role, path, original in (("runtime", runtime, runtime_id), ("fixture", fixture, fixture_id)):
            retirement[role + "_removed"] = False
            if original is not None:
                try:
                    retirement[role + "_removed"] = remove_owned(path, original)
                except (OSError, ValueError) as error:
                    errors.append(str(error))
    remaining = [path for path in (runtime, fixture) if not verified_absent(path)]
    if errors:
        report["cleanup_error"] = ", ".join(errors)[:768]
    discard = bool(errors or remaining) or not retirement["group_absent"]
    clean = bool(not discard and socket_absent and retirement.get("signals") == ["SIGTERM"]
                 and retirement.get("exit") == 0 and retirement["reaped"]
                 and retirement.get("runtime_removed") and retirement.get("fixture_removed"))
    return clean, discard


def write_file(path, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags, 0o600), "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def publish(report, trace):
    evidence = WORK / "qt-replacement-evidence"
    evidence.mkdir(mode=0o700, exist_ok=True)
    info = evidence.lstat()
    need(stat.S_ISDIR(info.st_mode) and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 0, 0o700),
         "Expected the actor's private Weston evidence directory")
    write_file(evidence / LOG_NAME, trace)
    write_file(evidence / REPORT_NAME, (json.dumps(report, sort_keys=True, indent=2) + "\n").encode())


class Session:
    socket = SOCKET

    def __init__(self, log):
        self.log = log
        self.process = None
        self.pending = None
        self.entries = {}

    def snapshot(self):
        size = os.fstat(self.log.fileno()).st_size
        need(size < LOG_CAP, "Weston server evidence reached its hard byte limit")
        data = os.pread(self.log.fileno(), size, 0)
        need(len(data) == size, "Short Weston server evidence read")
        return data

    def wait_ready(self):
        deadline = time.monotonic() + STARTUP_SECONDS
        while time.monotonic() < deadline:
            need(self.process.poll() is None, f"Weston exited before readiness ({self.process.returncode})")
            trace = self.snapshot()
            enabled = re.search(rb"(?m)^\[[^\n]+\] Output 'headless' enabled with head\(s\) headless\s*$", trace)
            version = re.search(rb"(?m)^\[[^\n]+\] weston 15\.0\.1\s*$", trace)
            try:
                if enabled and version:
                    return ready_socket(path_inside(SOCKET), self.process, deadline)
            except (FileNotFoundError, ConnectionRefusedError):
                pass
            time.sleep(0.05)
        raise ValueError("Timed out waiting for the pinned Weston headless output and socket")

    def begin(self, role):
        need(self.pending is None and role in PROBES and role not in self.entries and self.process.poll() is None,
             "Qt Weston probe boundaries must be live, scoped and non-overlapping")
        trace = self.snapshot()
        need(trace.endswith(b"\n"), "Weston probe trace has an incomplete starting record")
        self.pending = role, len(trace)

    def attest(self, role, pid, start_ticks):
        """Bind the launcher-recorded Qt process identity to this trace slice."""
        need(self.pending is not None and self.pending[0] == role, "Unexpected Weston probe completion boundary")
        _, start = self.pending
        self.pending = None
        result = dict(status="HOLD", pid=pid, start_ticks=start_ticks, socket=self.socket, start=start)
        self.entries[role] = result
        try:
            need(type(pid) is int and pid > 0 and type(start_ticks) is int and start_ticks > 0
                 and pid != self.process.pid
                 and not any(row.get("pid") == pid for name, row in self.entries.items() if name != role)
                 and self.process.poll() is None, "Wrong or repeated Qt client PID")
            trace = self.snapshot()
            result.update(end=len(trace), trace=pin(trace[start:]))
            result["presentation"] = presentation(trace[start:], pid, PROBES[role])
            result["status"] = "PASS"
        except (OSError, ValueError) as error:
            result["error"] = str(error)
        return result


@contextmanager
def supervise(*, nonce, stage_fixture):
    """Yield a ready compositor and report PASS only for all bound Qt probes.

    Supply the signed staging function, which receives a fresh destination.
    Extraction and startup both run within cleanup. For each role in PROBES, call
    session.begin(role) before launching the Qt client, then call
    session.attest(role, actual_popen_pid, proc_start_ticks) after its wait.
    The caller retains the client argv/exit evidence and owns VM retirement.
    """
    environment(nonce)
    report = dict(kind=KIND, status="HOLD", nonce=nonce, socket=SOCKET, dependencies={}, startup=None,
                  retirement=None, presentations={}, error=None)
    fixture_id = runtime_id = None
    runtime, fixture = path_inside(RUNTIME), path_inside(FIXTURE)
    with TemporaryFile(dir=WORK) as log:
        session = Session(log)
        report["presentations"] = session.entries
        try:
            need(path_absent(fixture), "Expected a fresh Weston fixture destination")
            try:
                receipt = stage_fixture(fixture)
            finally:
                if not path_absent(fixture):
                    fixture_id = claim_fixture(fixture)
            need(fixture_id is not None and validate_fixture(receipt) == fixture_id,
                 "Weston fixture identity changed during validation")
            runtime.mkdir(mode=0o700)
            runtime_id = identity(runtime)
            for leaf in ("home", "tmp"):
                directory = runtime / leaf
                directory.mkdir(mode=0o700)
                os.chown(directory, USER, USER)
            os.chown(runtime, USER, USER)
            need(path_absent(path_inside(SOCKET)) and path_absent(path_inside(SOCKET + ".lock")),
                 "Stale Weston socket or lock")
            dependencies(report["dependencies"])
            argv = command()
            report["argv"] = argv
            session.process = subprocess.Popen(argv, env=ENV, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                               start_new_session=True)
            report["startup"] = session.wait_ready()
            yield session
        except BaseException as error:
            report["error"] = {"type": type(error).__name__, "reason": str(error)[:768]}
            raise
        finally:
            clean, discard = cleanup(report, session.process, runtime, runtime_id, fixture, fixture_id)
            if discard:
                report["status"] = "HOLD_DISCARD"
            try:
                size = os.fstat(log.fileno()).st_size
                trace = os.pread(log.fileno(), min(size, LOG_CAP), 0)
                report["log"] = pin(trace)
                report["log_limit_reached"] = size >= LOG_CAP or len(trace) != size
                missing = [role for role in PROBES if session.entries.get(role, {}).get("status") != "PASS"]
                report["missing_presentations"] = missing
                if (report["startup"] and clean and not missing and report["error"] is None
                        and not report["log_limit_reached"] and trace.endswith(b"\n")):
                    report["status"] = "PASS"
                publish(report, trace)
            finally:
                if discard:
                    raise ValueError("Weston HOLD_DISCARD: owned resource retirement could not be verified")
    need(report["status"] == "PASS", "Weston lifecycle HOLD: presentation or retirement evidence incomplete")
