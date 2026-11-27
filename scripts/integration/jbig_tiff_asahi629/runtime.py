# SPDX-License-Identifier: MIT
"""Ordinary-user runtime checks inside the Asahi629 disposable guest."""

import os
from pathlib import Path
import re
import selectors
import shlex
import shutil
import signal
import stat
import subprocess
import tempfile
import time


TARGET = Path("/trial-scratch")
USER = 65534
MAX_OUTPUT = 32768
LOADER = "/usr/lib/ld-linux-aarch64.so.1"
PIPEWIRE = "/usr/lib/spa-0.2/bluez5/libspa-codec-bluez5-hfp-msbc.so"
DIRECT = (
    "/usr/bin/tificc",
    "/usr/bin/gtk4-rendernode-tool",
    "/usr/lib/libgtk-4.so.1.2400.1",
    "/usr/bin/opj_compress",
    "/usr/bin/opj_decompress",
    "/usr/bin/opj_dump",
    "/usr/lib/libspandsp.so.2.0.0",
)
PROBES = {
    "roundtrip": "TIFF JBIG roundtrip passed",
    "tificc": "RGB_TIFF_PIXELS_MATCH",
    "gtk": "GTK_TIFF_PIXELS_MATCH",
    "openjpeg": "RGB_TIFF_PIXELS_MATCH",
    "spandsp": "SPANDSP_TIFF_FAX_PAGE_ENCODED",
    "pipewire": "PIPEWIRE_MSBC_PLUGIN_LOADED",
}
PIPEWIRE_PROBE = """import ctypes
import os
import sys

if (os.getuid(), os.getgid(), os.getgroups()) != (65534, 65534, []):
    raise SystemExit("unexpected PipeWire probe identity")
plugin = ctypes.CDLL(sys.argv[1], mode=os.RTLD_NOW | os.RTLD_LOCAL)
getattr(plugin, "spa_handle_factory_enum")
print("PIPEWIRE_MSBC_PLUGIN_LOADED")
"""


def execute(argv, seconds):
    """Capture a finite diagnostic and retire the command group on failure."""
    deadline = time.monotonic() + seconds
    output = bytearray()
    with subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, start_new_session=True,
                          env={"PATH": "/usr/bin", "LC_ALL": "C"}, cwd="/", umask=0o077) as proc:
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise TimeoutError("command deadline")
                    data = os.read(proc.stdout.fileno(), 4096)
                    if not data:
                        break
                    output.extend(data)
                    if len(output) > MAX_OUTPUT:
                        raise ValueError("command output cap")
            proc.wait(timeout=max(0, deadline - time.monotonic()))
        except (TimeoutError, subprocess.TimeoutExpired, ValueError) as error:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=3)
            raise RuntimeError(f"{argv[-1]}: {error}") from error
        result = output.decode("utf-8", "replace")
        if proc.returncode:
            raise RuntimeError(f"{argv[-1]}: exit {proc.returncode}: {result[-1600:]}")
        return result


def require_guest(root):
    if (root != TARGET or os.geteuid() != 0 or os.uname().machine != "aarch64"
            or os.sysconf("SC_PAGE_SIZE") != 16384 or set(os.listdir("/sys/class/net")) != {"lo"}):
        raise RuntimeError("expected the offline AArch64 16 KiB disposable guest")
    mounts = {}
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        mounts[fields[4]] = (fields[5].split(","), fields[fields.index("-") + 1])
    for path, flag, fs_type in (("/", "ro", "ext4"), (str(root), "rw", "ext4"),
                                (str(root / "run"), "rw", "tmpfs")):
        flags, actual = mounts.get(path, ((), None))
        if actual != fs_type or flag not in flags:
            raise RuntimeError(f"unexpected guest mount: {path}")
    for path in (root, root / "tmp"):
        if path.resolve(strict=True) != path or not path.is_dir() or path.stat().st_uid != 0:
            raise RuntimeError(f"unexpected guest probe directory: {path}")


def copy_source(source, destination):
    info = source.lstat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 32768:
        raise RuntimeError(f"unexpected probe source: {source}")
    with source.open("rb") as incoming, destination.open("xb") as outgoing:
        shutil.copyfileobj(incoming, outgoing)
    destination.chmod(0o444)


def loader_paths(output, soname, *, pipewire=False):
    expected = {"tiff": "libtiff.so.6", "jbig": f"libjbig.so.{soname}"}
    if pipewire:
        expected["span"] = "libspandsp.so.2"
    if "not found" in output or f"libjbig.so.{'2.1' if soname == '2.2' else '2.2'} " in output:
        raise RuntimeError("loader reported an unresolved or stale TIFF/JBIG dependency")
    observed = {}
    for key, library in expected.items():
        escaped = re.escape(library)
        matches = re.findall(rf"^\s*{escaped}\s+=>\s+(/(?:usr/)?lib/{escaped})\s+\(0x[0-9a-fA-F]+\)\s*$",
                             output, re.MULTILINE)
        if len(matches) != 1:
            raise RuntimeError(f"expected one installed loader resolution for {library}")
        observed[key] = matches[0]
    return observed


class Probe:
    def __init__(self, root, scratch):
        self.root = root
        self.inner = "/" + scratch.relative_to(root).as_posix()
        self.work = f"{self.inner}/work"
        self.prefix = ["/usr/bin/chroot", str(self.root), "/usr/bin/setpriv", f"--reuid={USER}", f"--regid={USER}",
                       "--clear-groups", "--no-new-privs", "--inh-caps=-all", "--ambient-caps=-all",
                       "--bounding-set=-all", "/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LC_ALL=C", "TZ=UTC",
                       f"HOME={self.work}", f"TMPDIR={self.work}", f"XDG_CACHE_HOME={self.work}",
                       f"XDG_RUNTIME_DIR={self.work}", "GTK_A11Y=none", "GSETTINGS_BACKEND=memory",
                       "GIO_USE_VFS=local"]

    def command(self, *args, seconds=20):
        return execute([*self.prefix, *args], seconds)

    def marker(self, marker, *args):
        if self.command(*args).splitlines().count(marker) != 1:
            raise RuntimeError(f"expected one marker: {marker}")

    def check(self, soname):
        loaders = {
            path: loader_paths(self.command(LOADER, "--list", path), soname, pipewire=path == PIPEWIRE)
            for path in (*DIRECT, PIPEWIRE)
        }
        flags = shlex.split(self.command("/usr/bin/pkg-config", "--cflags", "--libs", "gtk4", "libtiff-4",
                                         "spandsp"))
        compiler = ("/usr/bin/gcc", "-std=c11", "-O0", "-Wall", "-Wextra", "-Werror", "-Wl,-z,now")
        roundtrip = f"{self.work}/roundtrip"
        fixture = f"{self.work}/fixture"
        self.command(*compiler, f"{self.inner}/roundtrip.c", "-o", roundtrip, "-ltiff", seconds=90)
        self.command(*compiler, f"{self.inner}/consumer.c", "-o", fixture, *flags, seconds=90)

        jbig = f"{self.work}/jbig.tif"
        self.marker(PROBES["roundtrip"], roundtrip, jbig)
        info = self.command("/usr/bin/tiffinfo", jbig)
        if "Image Width: 32 Image Length: 4" not in info or "Compression Scheme: ISO JBIG" not in info:
            raise RuntimeError("tiffinfo did not confirm the JBIG fixture")
        rgb = f"{self.work}/rgb.tif"
        color = f"{self.work}/color.tif"
        self.marker("RGB_TIFF_FIXTURE_WRITTEN", fixture, "write-rgb", rgb)
        self.command("/usr/bin/tificc", "-i*sRGB", "-o*sRGB", rgb, color)
        self.marker(PROBES["tificc"], fixture, "check-rgb", color)

        self.marker(PROBES["gtk"], fixture, "gtk", f"{self.work}/gtk.tif")
        jp2 = f"{self.work}/image.jp2"
        decoded = f"{self.work}/decoded.tif"
        self.command("/usr/bin/opj_compress", "-i", rgb, "-o", jp2, "-n", "3")
        self.command("/usr/bin/opj_dump", "-i", jp2)
        self.command("/usr/bin/opj_decompress", "-i", jp2, "-o", decoded)
        self.marker(PROBES["openjpeg"], fixture, "check-rgb", decoded)
        self.marker(PROBES["spandsp"], fixture, "fax", f"{self.work}/fax.tif")
        self.marker(PROBES["pipewire"], "/usr/bin/python3", "-I", "-B", "-c", PIPEWIRE_PROBE, PIPEWIRE)
        return loaders


def run(root, roundtrip_source, fixture_source, *, soname):
    """Return the checkpoint receipt or fail before the transaction can pass."""
    if soname not in {"2.1", "2.2"}:
        raise ValueError("unknown selected JBIG SONAME")
    require_guest(root)
    with tempfile.TemporaryDirectory(prefix="jbig-tiff629-", dir=root / "tmp") as path:
        scratch = Path(path)
        copy_source(roundtrip_source, scratch / "roundtrip.c")
        copy_source(fixture_source, scratch / "consumer.c")
        os.chown(scratch, 0, USER)
        scratch.chmod(0o750)
        work = scratch / "work"
        work.mkdir(mode=0o700)
        os.chown(work, USER, USER)
        loaders = Probe(root, scratch).check(soname)
    return dict(status="PASS", uid=USER, gid=USER, jbig_soname=soname, loaders=loaders, probes=dict(PROBES))
