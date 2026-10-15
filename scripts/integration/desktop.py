#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Installed desktop verifier inside a caller-provisioned isolated ARM container.

No installation, compositor launch, daemon launch, or hardware acceptance.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import subprocess
import sys
import tempfile
import time

PACKAGE = "cachy-asahi-hyprland-settings"
PREFIX = Path("/usr/share/cachy-asahi/hyprland")
HYPRLAND_COMMIT = "efb50993780079460b0cbed1363e2166a2de1d9f"
PAYLOAD = {f"usr/share/cachy-asahi/hyprland/{name}" for name in
           ("hyprland.lua", "waybar.json", "waybar.css", "mako.conf")} | {
    f"usr/share/doc/{PACKAGE}/README.md", f"usr/share/licenses/{PACKAGE}/NOTICE",
    f"usr/share/licenses/{PACKAGE}/LICENSE", "usr/bin/cachy-asahi-screenshot"}
OVERLAYS = {PACKAGE, "cachy-asahi-fish-config", "cachy-asahi-zsh-config", "cachy-asahi-setup"}
MAX_TEXT = 1_048_576


class Refused(ValueError):
    pass


def sha(data):
    return hashlib.sha256(data).hexdigest()


def container_facts():
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    mounts = {}
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        before, after = line.split(" - ", 1)
        fields = before.split()
        point = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), fields[4])
        mounts[point] = {"flags": fields[5].split(","), "type": after.split()[0]}
    marker = Path("/.dockerenv")
    return {"marker": marker.is_file() and not marker.is_symlink() and marker.stat().st_uid == 0,
            "arch": platform.machine(), "uid": os.geteuid(), "mounts": mounts,
            "capabilities": {key: int(status[key].strip(), 16) for key in ("CapEff", "CapPrm", "CapBnd")},
            "no_new_privileges": status["NoNewPrivs"].strip(),
            "interfaces": sorted(path.name for path in Path("/sys/class/net").iterdir()),
            "namespaces": {name: os.readlink(f"/proc/self/ns/{name}") for name in ("mnt", "net", "pid", "user")},
            "nonce": os.environ.get("CACHY_ASAHI_DISPOSABLE_DESKTOP", ""),
            "image_id": os.environ.get("CACHY_ASAHI_IMAGE_ID", ""),
            "marker_env": os.environ.get("CACHY_ASAHI_INTEGRATION_CONTAINER"),
            "runner": str(Path(__file__).resolve())}


def validate_container(facts):
    if facts["marker_env"] != "1" or not facts["marker"]:
        raise Refused("explicit disposable-container contract required")
    if facts["arch"] != "aarch64" or facts["uid"] == 0:
        raise Refused("aarch64 non-root container process required")
    if (not re.fullmatch(r"[0-9a-f]{32}", facts["nonce"]) or
            not re.fullmatch(r"sha256:[0-9a-f]{64}", facts["image_id"])):
        raise Refused("disposable nonce and immutable installed-image ID required")
    if any(facts["capabilities"].values()) or facts["no_new_privileges"] != "1":
        raise Refused("capability drop and no-new-privileges required")
    if facts["interfaces"] != ["lo"]:
        raise Refused("isolated loopback-only network required")
    if facts["runner"] != "/runner/desktop.py":
        raise Refused("read-only runner must be /runner/desktop.py")
    mounts = facts["mounts"]
    for point, flag, kind in (("/", "ro", None), ("/inputs", "ro", None), ("/runner", "ro", None),
                              ("/out", "rw", None), ("/tmp", "rw", "tmpfs")):
        entry = mounts.get(point, {})
        if flag not in entry.get("flags", []) or (kind and entry.get("type") != kind):
            raise Refused(f"required isolated mount missing: {point}")
    if mounts["/"]["type"] not in ("overlay", "fuse-overlayfs"):
        raise Refused("disposable read-only overlay root required")
    for point in mounts:
        if any(point.startswith(base + "/") for base in ("/inputs", "/runner", "/tmp", "/out")):
            raise Refused(f"nested input/runner/scratch/evidence mount refused: {point}")
        if any(point == base or point.startswith(base + "/") for base in ("/usr", "/etc", "/var", "/home", "/root", "/run")):
            if point not in ("/etc/hosts", "/etc/hostname", "/etc/resolv.conf"):
                raise Refused(f"host/system-path mount refused: {point}")


def isolation_guard():
    facts = container_facts()
    validate_container(facts)
    for name in ("DISPLAY", "WAYLAND_DISPLAY", "WAYLAND_SOCKET", "DBUS_SESSION_BUS_ADDRESS",
                 "PULSE_SERVER", "PIPEWIRE_REMOTE"):
        if os.environ.get(name):
            raise Refused(f"inherited connection variable forbidden: {name}")
    for path in ("/dev/dri", "/dev/snd", "/dev/input", "/tmp/.X11-unix",
                 "/var/run/docker.sock", "/run/docker.sock"):
        if Path(path).exists():
            raise Refused(f"excluded device/socket tree present: {path}")
    if any(path.is_socket() for path in Path("/run/user").rglob("*")):
        raise Refused("user runtime socket present")
    return facts


def validate_paths(args):
    for path in (args.package, args.runtime_lock):
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to("/inputs"):
            raise Refused("regular archive/runtime lock below read-only /inputs required")
        if path.stat().st_size > MAX_TEXT:
            raise Refused("data-package archive/runtime lock exceeds input limit")
    if args.output != Path("/out/desktop") or args.output.is_symlink() or args.output.exists():
        raise Refused("fresh fixed /out/desktop evidence path required")


def command(argv, cwd, env, log, timeout=15):
    """Bounded trusted subprocess; kill the original group, including descendants."""
    process, error = None, None
    written = 0
    interrupted = []
    previous = signal.signal(signal.SIGTERM, lambda *_: interrupted.append(True))
    start = time.monotonic()
    try:
        with Path(log).open("xb") as output:
            def drain():
                nonlocal written, error
                while True:
                    try:
                        data = os.read(process.stdout.fileno(), min(16384, MAX_TEXT - written + 1))
                    except BlockingIOError:
                        return
                    if not data:
                        return
                    remaining = MAX_TEXT - written
                    output.write(data[:remaining])
                    written += min(len(data), remaining)
                    output.flush()
                    if len(data) > remaining:
                        error = "command output exceeds evidence limit"
                        return
            try:
                process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT, start_new_session=True)
                os.set_blocking(process.stdout.fileno(), False)
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while True:
                        if interrupted or time.monotonic() - start >= timeout:
                            error = "SIGTERM" if interrupted else "timeout"
                            break
                        if selector.select(min(.05, max(.001, timeout - (time.monotonic() - start)))):
                            drain()
                        if error or process.poll() is not None:
                            break
            except (OSError, KeyboardInterrupt) as exc:
                error = str(exc)
            finally:
                if process is not None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        error = "cleanup incomplete"
                    if process.stdout is not None:
                        drain()
                        process.stdout.close()
    finally:
        if interrupted:
            error = "SIGTERM"
        signal.signal(signal.SIGTERM, previous)
    data = Path(log).read_bytes()
    return {"argv": argv, "returncode": process.returncode if process else None,
            "error": error, "log_sha256": sha(data), "stdout": data[:MAX_TEXT].decode(errors="replace")}


def inventory(text):
    result = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 2 or fields[0] in result:
            raise Refused("invalid/duplicate package inventory line")
        result[fields[0]] = fields[1]
    if not result:
        raise Refused("empty package inventory")
    return result


def metadata(text):
    result = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition(" = ")
        if not separator:
            raise Refused("invalid .PKGINFO")
        result.setdefault(key, []).append(value)
    return result


def unique_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Refused(f"duplicate JSON key: {key}")
            result[key] = value
        return result
    def constant(value):
        raise Refused(f"nonfinite JSON: {value}")
    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def mako_subset(text):
    """Source-audited v1.11.0 five-option subset; NOT the Mako runtime parser."""
    colors = {"background-color", "text-color", "border-color"}
    integers = {"border-size", "default-timeout"}
    result = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or key in result or key not in colors | integers:
            raise Refused("Mako template outside audited five-option subset")
        if key in colors and not re.fullmatch(r"#[0-9a-fA-F]{6}(?:[0-9a-fA-F]{2})?", value):
            raise Refused("invalid Mako color")
        if key in integers and (not re.fullmatch(r"[0-9]+", value) or int(value) > 2_147_483_647):
            raise Refused("invalid Mako nonnegative integer")
        result[key] = value
    if set(result) != colors | integers:
        raise Refused("incomplete Mako template subset")
    return result


def optional_startup(text):
    lines = text.splitlines()
    start = '-- hl.on("hyprland.start", function()'
    if lines.count(start) != 1:
        raise Refused("expected one documented optional-startup block")
    index = lines.index(start)
    end = index
    while end < len(lines) and lines[end] != "-- end)":
        if not lines[end].startswith("-- "):
            raise Refused("malformed optional-startup block")
        end += 1
    if end >= len(lines):
        raise Refused("unterminated optional-startup block")
    for position in range(index, end + 1):
        lines[position] = lines[position][3:]
    return "\n".join(lines) + "\n"


def bind_payload(checked, archive, installed_root=Path("/")):
    names = checked(["/usr/bin/bsdtar", "-tf", str(archive)]).splitlines()
    regular = {name for name in names if not name.endswith("/") and name not in (".PKGINFO", ".BUILDINFO", ".MTREE")}
    if regular != PAYLOAD or len(names) != len(set(names)):
        raise Refused("archive differs from reviewed eight-file payload")
    hashes = {}
    for name in sorted(PAYLOAD):
        installed = installed_root / name
        if installed.is_symlink() or not installed.is_file():
            raise Refused(f"installed payload absent or symlink: {name}")
        archived = checked(["/usr/bin/bsdtar", "-xOf", str(archive), name]).encode()
        if installed.read_bytes() != archived:
            raise Refused(f"installed bytes differ: {name}")
        if checked(["/usr/bin/pacman", "-Qoq", str(installed)]).strip() != PACKAGE:
            raise Refused(f"unexpected installed owner: {name}")
        hashes[name] = sha(archived)
    return hashes


def gtk_css(path):
    """GTK3's actual parser without gtk_init, display or application creation."""
    class GError(ctypes.Structure):
        _fields_ = [("domain", ctypes.c_uint), ("code", ctypes.c_int), ("message", ctypes.c_char_p)]
    gtk = ctypes.CDLL("libgtk-3.so.0")
    objects = ctypes.CDLL("libgobject-2.0.so.0")
    glib = ctypes.CDLL("libglib-2.0.so.0")
    gtk.gtk_css_provider_new.restype = ctypes.c_void_p
    gtk.gtk_css_provider_new.argtypes = []
    gtk.gtk_css_provider_load_from_data.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                                   ctypes.c_ssize_t, ctypes.POINTER(ctypes.POINTER(GError))]
    gtk.gtk_css_provider_load_from_data.restype = ctypes.c_int
    objects.g_signal_connect_data.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p,
                                              ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
    objects.g_signal_connect_data.restype = ctypes.c_ulong
    objects.g_object_unref.argtypes = [ctypes.c_void_p]
    objects.g_object_unref.restype = None
    glib.g_error_free.argtypes = [ctypes.POINTER(GError)]
    glib.g_error_free.restype = None
    errors = []
    @ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
    def parsing_error(_provider, _section, error, _data):
        errors.append(ctypes.cast(error, ctypes.POINTER(GError)).contents.message.decode(errors="replace"))
    data = Path(path).read_bytes()
    if len(data) > MAX_TEXT:
        raise Refused("CSS input exceeds limit")
    provider = gtk.gtk_css_provider_new()
    if not provider:
        raise Refused("GTK CSS provider allocation failed")
    error = ctypes.POINTER(GError)()
    try:
        objects.g_signal_connect_data(provider, b"parsing-error", ctypes.cast(parsing_error, ctypes.c_void_p),
                                      None, None, 0)
        ok = gtk.gtk_css_provider_load_from_data(provider, data, len(data), ctypes.byref(error))
        if error:
            errors.append(error.contents.message.decode(errors="replace"))
        if not ok or errors:
            raise Refused("GTK3 stylesheet parse errors: " + "; ".join(errors))
    finally:
        if error:
            glib.g_error_free(error)
        objects.g_object_unref(provider)
    return {"status": "PASS", "parser": "GTK3 CssProvider", "display_created": False}


def verify(args, output):
    facts = isolation_guard()
    report = {"schema_version": 1, "record_type": "desktop-container-verification", "status": "FAILED",
              "container_arch": facts["arch"], "container_facts": facts, "commands": [], "checks": {},
              "hardware_validation": "NOT RUN", "graphics_acceleration": "NOT RUN",
              "portal_audio_session": "NOT RUN", "optimization_acceptance": "NOT RUN",
              "headless_compositor": {"status": "BLOCKED", "attempted": False,
                  "reason": "pinned Aquamarine 0.15.1 requires a DRM-backed GBM allocator; /dev/dri is excluded"}}
    try:
        archive = Path(args.package).resolve(strict=True)
        if sha(archive.read_bytes()) != args.package_sha256:
            raise Refused("package archive checksum mismatch")
        lock = Path(args.runtime_lock).read_text()
        expected = inventory(lock)
        report.update({"archive_sha256": args.package_sha256, "runtime_lock_sha256": sha(lock.encode())})
        with tempfile.TemporaryDirectory(prefix="cachy-asahi-desktop-verify-") as temporary:
            work = Path(temporary)
            for name in ("home", "config", "cache", "runtime"):
                (work / name).mkdir(mode=0o700)
            env = {"PATH": "/usr/bin", "HOME": str(work / "home"), "XDG_CONFIG_HOME": str(work / "config"),
                   "XDG_CACHE_HOME": str(work / "cache"), "XDG_RUNTIME_DIR": str(work / "runtime"),
                   "LC_ALL": "C", "CACHY_ASAHI_INTEGRATION_CONTAINER": "1",
                   "CACHY_ASAHI_DISPOSABLE_DESKTOP": facts["nonce"], "CACHY_ASAHI_IMAGE_ID": facts["image_id"]}
            def checked(argv):
                result = command(argv, work, env, output / f"command-{len(report['commands'])}.txt", args.timeout)
                report["commands"].append(result)
                if result["error"] or result["returncode"] != 0:
                    raise Refused(f"command failed: {argv[0]} ({result['error'] or result['returncode']})")
                return result["stdout"]
            observed = inventory(checked(["/usr/bin/pacman", "-Q"]))
            if any(observed.get(name) != version for name, version in expected.items()) or set(observed) - set(expected) - OVERLAYS:
                raise Refused("runtime inventory differs from frozen lock plus reviewed overlay names")
            if observed.get("hyprland") != "0.56.2-4" or observed.get("aquamarine") != "0.15.1-1":
                raise Refused("unsupported compositor/backend package version")
            if any(name not in expected for name in ("hyprland", "aquamarine", "lua", "gtk3", "python", "libarchive")):
                raise Refused("runtime lock lacks a required preprovisioned check dependency")
            info = metadata(checked(["/usr/bin/bsdtar", "-xOf", str(archive), ".PKGINFO"]))
            if info.get("pkgname") != [PACKAGE] or info.get("arch") != ["any"] or info.get("pkgver") != [observed.get(PACKAGE)]:
                raise Refused("installed package identity differs from archive")
            report["installed_payload_sha256"] = bind_payload(checked, archive)
            version = checked(["/usr/bin/Hyprland", "--version"])
            if not re.search(r"\bHyprland 0\.56\.2\b", version) or HYPRLAND_COMMIT not in version:
                raise Refused("Hyprland binary revision differs from audited pin")
            config = PREFIX / "hyprland.lua"
            checked(["/usr/bin/luac", "-p", str(config)])
            for source in (config, work / "optional-startup.lua"):
                if source != config:
                    source.write_text(optional_startup(config.read_text()))
                parsed = checked(["/usr/bin/Hyprland", "--verify-config", "--config", str(source)])
                if "config ok" not in parsed:
                    raise Refused("Hyprland verifier lacks successful parse result")
            unique_json((PREFIX / "waybar.json").read_text())
            mako_subset((PREFIX / "mako.conf").read_text())
            css = checked([sys.executable, str(Path(__file__).resolve()), "--gtk-css", str(PREFIX / "waybar.css")])
            report["checks"] = {"installed_payload": "PASS", "runtime_inventory": "PASS",
                "lua_syntax": "PASS", "Hyprland_default_and_optional_verifier": "PASS",
                "waybar_strict_JSON_syntax_only": "PASS", "GTK3_CSS_parser": json.loads(css),
                "mako_source_audited_subset_only": "PASS"}
            report["application_runtime"] = {name: {"status": "NOT RUN", "installed": name in observed,
                "reason": "no bar/notifier session launched; optional app not in frozen lock" if name not in expected
                          else "syntax checks do not exercise the application session"} for name in ("waybar", "mako")}
            report["status"] = "desktop-container-verifier-pass"
    except (OSError, ValueError, KeyError) as exc:
        report["error"] = str(exc)
    (output / "desktop.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    return 0 if report["status"] == "desktop-container-verifier-pass" else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path)
    parser.add_argument("--package-sha256")
    parser.add_argument("--runtime-lock", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--gtk-css", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.gtk_css:
        try:
            isolation_guard()
            print(json.dumps(gtk_css(args.gtk_css)))
            return 0
        except (OSError, ValueError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
    if not all((args.package, args.package_sha256, args.runtime_lock, args.output)) or not re.fullmatch(r"[0-9a-f]{64}", args.package_sha256):
        parser.error("package, exact SHA-256, runtime lock and fresh output directory required")
    if not 0 < args.timeout <= 60:
        parser.error("timeout must be finite and within (0, 60] seconds")
    try:
        isolation_guard()
        validate_paths(args)
        args.output.mkdir(exist_ok=False)
        return verify(args, args.output)
    except (OSError, ValueError, KeyError) as exc:
        print(f"desktop refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
