# SPDX-License-Identifier: MIT
"""Bounded ordinary-user probes of Qt installed on the disposable Asahi629 clone."""

import json
import os
from pathlib import Path
import re
import selectors
import shlex
import signal
import stat
import subprocess
import tempfile
import time


TARGET = Path("/trial-scratch")
WORK = Path("/trial-work")
EVIDENCE = WORK / "qt-replacement-evidence"
VENDOR_REPORT = "vendor-runtime-probes.json"
RESTORED_REPORT = "restored-runtime-probes.json"
REPORTS = {"vendor": VENDOR_REPORT, "replacement": "runtime-probes.json", "restoration": RESTORED_REPORT}
USER = 65534
VERSION = "6.12.0"
MAX_OUTPUT = 32 * 1024
LAVAPIPE = "/usr/share/vulkan/icd.d/lvp_icd.json"
KIND = "QT629_INSTALLED_RUNTIME_PROBES_V1"
PHASES = ("core_gui_offscreen", "quick_offscreen", "wayland", "vulkan_loader", "vulkan_qrhi")
SAFE_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"}

COMMON = r'''
#include <QCoreApplication>
#include <QGuiApplication>
#include <QImage>
#include <QPainter>
#include <QTimer>
#include <QWindow>
#include <cstdio>
#include <cstring>
#include <unistd.h>

static bool ordinaryUser()
{
    return getuid() == 65534 && geteuid() == 65534 && getgid() == 65534
        && getegid() == 65534 && getgroups(0, nullptr) == 0;
}

static int fail(const char *reason)
{
    std::fprintf(stderr, "QT629_PROBE_FAILURE %s\n", reason);
    return 1;
}
'''

GUI = COMMON + r'''
#include <QBackingStore>
#include <QElapsedTimer>
#include <QEventLoop>

int main(int argc, char **argv)
{
    if (!ordinaryUser() || argc != 2)
        return fail("wrong_user_or_arguments");
    const QByteArray platform(argv[1]);
    QGuiApplication app(argc, argv);
    if (qVersion() != QByteArray("6.12.0") || app.platformName() != QString::fromLatin1(platform))
        return fail("wrong_qt_version_or_qpa_platform");

    const QColor color(37, 93, 151);
    QImage image(16, 16, QImage::Format_RGB32);
    QPainter painter(&image);
    painter.fillRect(image.rect(), color);
    painter.end();
    if (image.pixelColor(8, 8) != color)
        return fail("qpainter_pixel_mismatch");

    QWindow window;
    window.resize(64, 64);
    window.setTitle(QStringLiteral("Asahi629 Qt probe"));
    window.show();
    QElapsedTimer timer;
    timer.start();
    while (!window.isExposed() && timer.elapsed() < 6000) {
        app.processEvents();
        usleep(10000);
    }
    if (!window.isExposed())
        return fail("window_not_exposed");
    QBackingStore backingStore(&window);
    const QRect rect(QPoint(0, 0), window.size());
    backingStore.resize(window.size());
    backingStore.beginPaint(rect);
    if (!painter.begin(backingStore.paintDevice()))
        return fail("backing_store_unavailable");
    painter.fillRect(rect, color);
    painter.end();
    backingStore.endPaint();
    backingStore.flush(rect);
    app.processEvents();
    if (platform == QByteArray("wayland")) {
        QEventLoop callbacks;
        QTimer::singleShot(350, &callbacks, &QEventLoop::quit);
        callbacks.exec();
    }
    std::printf("QT629_GUI_OK %s %s\n", qVersion(), platform.constData());
    return 0;
}
'''

QUICK = COMMON + r'''
#include <QQmlError>
#include <QQuickItem>
#include <QQuickView>
#include <QSGRendererInterface>
#include <QUrl>

int main(int argc, char **argv)
{
    if (!ordinaryUser() || argc != 3)
        return fail("wrong_user_or_arguments");
    const bool vulkan = std::strcmp(argv[1], "vulkan") == 0;
    const QUrl fixture = QUrl::fromLocalFile(QString::fromLocal8Bit(argv[2]));
    QGuiApplication app(argc, argv);
    const QString platform = vulkan ? QStringLiteral("wayland") : QStringLiteral("offscreen");
    if (qVersion() != QByteArray("6.12.0") || app.platformName() != platform)
        return fail("wrong_qt_version_or_qpa_platform");
    const auto api = vulkan ? QSGRendererInterface::Vulkan : QSGRendererInterface::Software;
    QQuickWindow::setGraphicsApi(api);
    QQuickView view;
    view.setSource(fixture);
    if (view.status() != QQuickView::Ready || !view.rootObject()) {
        std::fprintf(stderr, "QT629_QML_STATUS %d\n", int(view.status()));
        for (const auto &error : view.errors()) {
            const QByteArray detail = error.toString().toUtf8();
            std::fprintf(stderr, "QT629_QML_ERROR %s\n", detail.constData());
        }
        return fail("qtquick_qml_fixture_did_not_load");
    }

    if (!vulkan) {
        const QImage image = view.grabWindow();
        if (image.isNull() || view.rendererInterface()->graphicsApi() != api
            || image.pixelColor(image.width() / 2, image.height() / 2) != QColor(37, 93, 151))
            return fail("qtquick_software_pixel_or_backend_mismatch");
        std::puts("QT629_QUICK_OK software pixels=verified");
        return 0;
    }

    int frames = 0;
    bool backendMismatch = false;
    QObject::connect(&view, &QQuickWindow::frameSwapped, &app, [&] {
        if (view.rendererInterface()->graphicsApi() != api || !view.rhi()) {
            backendMismatch = true;
            app.quit();
            return;
        }
        ++frames;
        if (frames == 1) {
            QTimer::singleShot(0, &view, [&] {
                view.rootObject()->setProperty("color", QColor(87, 123, 29));
                view.requestUpdate();
            });
        } else if (frames == 2) {
            QTimer::singleShot(350, &app, &QCoreApplication::quit);
        }
    });
    QTimer::singleShot(10000, &app, &QCoreApplication::quit);
    view.show();
    app.exec();
    if (frames < 2 || backendMismatch)
        return fail("insufficient_vulkan_qrhi_frames");
    std::puts("QT629_QRHI_OK wayland vulkan frame=swapped");
    return 0;
}
'''

QML = 'import QtQuick\nRectangle { width: 32; height: 32; color: "#255d97" }\n'

# Vulkan 1.0 needs no extensions to create an instance and enumerate devices.
# VkInstanceCreateInfo permits pApplicationInfo = NULL, which selects Vulkan 1.0.
VULKAN = '''
import ctypes as c
import os
import struct
import sys

if (os.getuid(), os.geteuid(), os.getgid(), os.getegid(), os.getgroups()) != (65534, 65534, 65534, 65534, []):
    sys.exit("Vulkan loader probe did not run as the ordinary guest user")

class InstanceCreateInfo(c.Structure):
    _fields_ = [("type", c.c_int32), ("next", c.c_void_p), ("flags", c.c_uint32),
                ("app", c.c_void_p), ("layers", c.c_uint32), ("layer_names", c.c_void_p),
                ("extensions", c.c_uint32), ("extension_names", c.c_void_p)]

vk = c.CDLL("libvulkan.so.1")
vk.vkCreateInstance.argtypes = [c.POINTER(InstanceCreateInfo), c.c_void_p, c.POINTER(c.c_void_p)]
vk.vkEnumeratePhysicalDevices.argtypes = [c.c_void_p, c.POINTER(c.c_uint32), c.c_void_p]
vk.vkGetPhysicalDeviceProperties.argtypes = [c.c_void_p, c.c_void_p]
vk.vkGetPhysicalDeviceProperties.restype = None
vk.vkDestroyInstance.argtypes = [c.c_void_p, c.c_void_p]
vk.vkDestroyInstance.restype = None
instance = c.c_void_p()
result = vk.vkCreateInstance(c.byref(InstanceCreateInfo(1)), None, c.byref(instance))
if result != 0 or not instance:
    sys.exit(f"vkCreateInstance failed with VkResult {result}")
try:
    count = c.c_uint32()
    result = vk.vkEnumeratePhysicalDevices(instance, c.byref(count), None)
    if result != 0:
        sys.exit(f"vkEnumeratePhysicalDevices failed with VkResult {result}")
    if count.value > 16:
        sys.exit("Selected Lavapipe returned an unexpectedly large device list")
    if count.value:
        devices = (c.c_void_p * count.value)()
        result = vk.vkEnumeratePhysicalDevices(instance, c.byref(count), devices)
        if result != 0 or not count.value:
            sys.exit(f"Could not obtain the selected Vulkan device handles (VkResult {result})")
        for device in devices[:count.value]:
            # Vulkan 1.0 VkPhysicalDeviceProperties begins with four uint32s,
            # then VkPhysicalDeviceType. Keep ample aligned storage for the
            # rest of the fixed-size Vulkan 1.0 struct.
            properties = (c.c_uint64 * 512)()
            vk.vkGetPhysicalDeviceProperties(device, properties)
            device_type, = struct.unpack_from("=I", properties, 16)
            if device_type != 4:  # VK_PHYSICAL_DEVICE_TYPE_CPU
                sys.exit(f"Selected Lavapipe exposed non-CPU VkPhysicalDeviceType {device_type}")
    print(f"QT629_VULKAN_OK devices={count.value}")
finally:
    vk.vkDestroyInstance(instance, None)
'''


def child_start_ticks(pid):
    with Path(f"/proc/{pid}/stat").open("rb") as stream:
        raw = stream.read(4097)
    head, separator, tail = raw.rpartition(b")")
    fields = tail.split()
    if (len(raw) > 4096 or not separator or head.split(b"(", 1)[0].strip() != str(pid).encode()
            or len(fields) < 20 or fields[1:4] != [str(value).encode() for value in (os.getpid(), pid, pid)]
            or not fields[19].isdigit() or int(fields[19]) <= 0):
        raise ValueError("Wrong supervised Qt child process identity")
    return int(fields[19])


def execute(argv, timeout):
    """Keep bounded merged output and retire the probe process group on an overrun."""
    output = bytearray()
    problem = None
    start_ticks = None
    try:
        process = subprocess.Popen(argv, env=SAFE_ENV, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    except OSError as error:
        return dict(argv=argv, pid=None, start_ticks=None, exit=None, problem="EXEC", output=str(error)[:512])
    deadline = time.monotonic() + timeout
    try:
        try:
            start_ticks = child_start_ticks(process.pid)
        except (OSError, ValueError):
            problem = "PROCESS_IDENTITY"
        with selectors.DefaultSelector() as ready:
            ready.register(process.stdout, selectors.EVENT_READ)
            while problem is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not ready.select(remaining):
                    problem = "TIMEOUT"
                    break
                chunk = os.read(process.stdout.fileno(), 4096)
                if not chunk:
                    break
                room = MAX_OUTPUT - len(output)
                output.extend(chunk[:room])
                if len(chunk) > room:
                    problem = "OUTPUT_LIMIT"
                    break
        if problem is None:
            try:
                process.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                problem = "TIMEOUT"
    finally:
        try:
            if process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    problem = "UNREAPED"
        finally:
            process.stdout.close()
    return dict(argv=argv, pid=process.pid, start_ticks=start_ticks, exit=process.returncode, problem=problem,
                output=output.decode("utf-8", "replace"))


class Guest:
    def __init__(self, directory):
        self.directory = directory
        self.inner = "/" + directory.relative_to(TARGET).as_posix()
        for name, body in (("gui.cpp", GUI), ("quick.cpp", QUICK), ("fixture.qml", QML), ("vulkan.py", VULKAN)):
            source = directory / name
            source.write_text(body, encoding="utf-8")
            source.chmod(0o444)
        for name in ("work", "run"):
            work = directory / name
            work.mkdir(mode=0o700)
            os.chown(work, USER, USER)
        # Qt QML enumerates this directory to check filename case.
        os.chown(directory, -1, USER)
        directory.chmod(0o750)

    def command(self, args, timeout, **settings):
        prefix = ["/usr/bin/chroot", str(TARGET), "/usr/bin/setpriv", f"--reuid={USER}", f"--regid={USER}",
                  "--clear-groups", "--no-new-privs", "--inh-caps=-all", "--ambient-caps=-all",
                  "--bounding-set=-all", "/usr/bin/env", "-i"]
        env = dict(SAFE_ENV, HOME=f"{self.inner}/work", TMPDIR=f"{self.inner}/work",
                   XDG_RUNTIME_DIR=f"{self.inner}/run", XDG_CACHE_HOME=f"{self.inner}/work",
                   QML_DISABLE_DISK_CACHE="1", **settings)
        return execute([*prefix, *(f"{name}={value}" for name, value in sorted(env.items())), *args], timeout)

    def build(self, name, module):
        query = self.command(["/usr/bin/pkg-config", "--cflags", "--libs", module], 10)
        if query["problem"] or query["exit"] != 0:
            return [query]
        try:
            flags = shlex.split(query["output"])
        except ValueError:
            return [query | {"problem": "INVALID_PKG_CONFIG_OUTPUT"}]
        build = self.command(["/usr/bin/g++", "-std=c++17", "-O0", "-fPIC",
                              f"{self.inner}/{name}.cpp", "-o", f"{self.inner}/work/{name}", *flags], 75)
        return [query, build]

    def path(self, path):
        return TARGET / path.lstrip("/")


def result(status, reason, steps=()):
    return dict(status=status, reason=reason, steps=list(steps))


def succeeded(step):
    return step["problem"] is None and step["exit"] == 0


def with_marker(steps, marker, passed, failure):
    last = steps[-1]
    if not succeeded(last):
        return result("FAIL", last["problem"] or failure, steps)
    if last["output"].splitlines().count(marker) != 1:
        return result("FAIL", "EXPECTED_RUNTIME_MARKER_MISSING_OR_DUPLICATED", steps)
    return result("PASS", passed, steps)


def socket_state(guest, wayland_socket):
    if wayland_socket is None:
        return "SKIP", "NO_WAYLAND_COMPOSITOR_SELECTED"
    if (type(wayland_socket) is not str or len(wayland_socket) > 107
            or not re.fullmatch(r"/run/(?:[A-Za-z0-9_.-]+/)*wayland-[0-9]+", wayland_socket)
            or {".", ".."} & set(wayland_socket.split("/"))):
        return "FAIL", "INVALID_SELECTED_WAYLAND_SOCKET_PATH"
    path = guest.path(wayland_socket)
    try:
        info = path.lstat()
        if path.resolve(strict=True) != path or not stat.S_ISSOCK(info.st_mode) or info.st_uid != USER:
            return "FAIL", "SELECTED_WAYLAND_SOCKET_WRONG_TYPE_PATH_OR_OWNER"
    except FileNotFoundError:
        return "FAIL", "SELECTED_WAYLAND_SOCKET_MISSING"
    except (OSError, RuntimeError):
        return "FAIL", "SELECTED_WAYLAND_SOCKET_UNREADABLE"
    return None


def observed_probe(guest, weston, role, argv, timeout, marker, passed, failure, **settings):
    weston.begin(role)
    step = guest.command(argv, timeout, **settings)
    witness = weston.attest(role, step["pid"], step["start_ticks"])
    checked = with_marker([step], marker, passed, failure)
    if checked["status"] == "PASS" and witness["status"] != "PASS":
        checked.update(status="FAIL", reason="PID_BOUND_WESTON_PRESENTATION_MISSING")
    checked["process"] = dict(pid=step["pid"], start_ticks=step["start_ticks"])
    return checked


def collect(guest, wayland_socket, weston=None, *, phase="replacement"):
    checked = {}
    gui_build = guest.build("gui", "Qt6Gui")
    gui_ready = len(gui_build) == 2 and succeeded(gui_build[-1])
    if gui_ready:
        step = guest.command([f"{guest.inner}/work/gui", "offscreen"], 14, QT_QPA_PLATFORM="offscreen")
        checked["core_gui_offscreen"] = with_marker([*gui_build, step], f"QT629_GUI_OK {VERSION} offscreen",
                                                    "OFFSCREEN_PAINTER_AND_BACKING_STORE", "OFFSCREEN_GUI_EXECUTION_FAILED")
    else:
        checked["core_gui_offscreen"] = result("FAIL", "QT_GUI_FIXTURE_BUILD_FAILED", gui_build)

    quick_build = guest.build("quick", "Qt6Quick")
    quick_ready = len(quick_build) == 2 and succeeded(quick_build[-1])
    if quick_ready:
        step = guest.command([f"{guest.inner}/work/quick", "software", f"{guest.inner}/fixture.qml"], 14,
                             QT_QPA_PLATFORM="offscreen")
        checked["quick_offscreen"] = with_marker([*quick_build, step], "QT629_QUICK_OK software pixels=verified",
                                                 "QTQUICK_SOFTWARE_QML_PIXEL_VERIFIED", "QTQUICK_SOFTWARE_EXECUTION_FAILED")
    else:
        checked["quick_offscreen"] = result("FAIL", "QT_QUICK_FIXTURE_BUILD_FAILED", quick_build)

    wayland = socket_state(guest, wayland_socket)
    if wayland:
        checked["wayland"] = result(*wayland)
    elif weston is None or weston.socket != wayland_socket:
        checked["wayland"] = result("FAIL", "SELECTED_WAYLAND_SOCKET_LACKS_OWNED_WESTON_SUPERVISION")
    elif not gui_ready:
        checked["wayland"] = result("SKIP", "QT_GUI_FIXTURE_BUILD_FAILED")
    else:
        checked["wayland"] = observed_probe(
            guest, weston, f"{phase}-raster", [f"{guest.inner}/work/gui", "wayland"], 14,
            f"QT629_GUI_OK {VERSION} wayland", "WAYLAND_RASTER_PRESENTATION_OBSERVED", "SELECTED_WAYLAND_CLIENT_FAILED",
            QT_QPA_PLATFORM="wayland", WAYLAND_DISPLAY=wayland_socket)

    if not guest.path(LAVAPIPE).is_file():
        checked["vulkan_loader"] = result("FAIL", "PINNED_LAVAPIPE_ICD_MISSING")
    else:
        step = guest.command(["/usr/bin/python3", "-I", "-B", f"{guest.inner}/vulkan.py"], 20,
                             VK_DRIVER_FILES=LAVAPIPE, LP_NUM_THREADS="2")
        matches = re.findall(r"^QT629_VULKAN_OK devices=([0-9]{1,10})$", step["output"], re.M)
        if not succeeded(step) or len(matches) != 1:
            checked["vulkan_loader"] = result("FAIL", step["problem"] or "VULKAN_LOADER_OR_ICD_FAILED", [step])
        elif int(matches[0]) == 0:
            checked["vulkan_loader"] = result("FAIL", "PINNED_LAVAPIPE_EXPOSED_NO_VULKAN_DEVICE", [step])
        else:
            checked["vulkan_loader"] = result("PASS", "LAVAPIPE_INSTANCE_AND_DEVICE_ENUMERATION", [step])

    if checked["wayland"]["status"] != "PASS":
        checked["vulkan_qrhi"] = result("SKIP", "WAYLAND_QPA_PATH_UNAVAILABLE")
    elif checked["vulkan_loader"]["status"] != "PASS":
        checked["vulkan_qrhi"] = result("SKIP", "VULKAN_LOADER_OR_DEVICE_UNAVAILABLE")
    elif not quick_ready:
        checked["vulkan_qrhi"] = result("SKIP", "QT_QUICK_FIXTURE_BUILD_FAILED")
    else:
        checked["vulkan_qrhi"] = observed_probe(
            guest, weston, f"{phase}-qrhi", [f"{guest.inner}/work/quick", "vulkan", f"{guest.inner}/fixture.qml"], 20,
            "QT629_QRHI_OK wayland vulkan frame=swapped", "QTQUICK_VULKAN_QRHI_PRESENTATION_OBSERVED",
            "QTQUICK_VULKAN_EXECUTION_FAILED", QT_QPA_PLATFORM="wayland", WAYLAND_DISPLAY=wayland_socket,
            QSG_RENDER_LOOP="basic", VK_DRIVER_FILES=LAVAPIPE, LP_NUM_THREADS="2")
    return checked


def write_result(directory, checks, wayland_socket, *, nonce, name=REPORTS["replacement"]):
    blocked = [name for name in PHASES if checks[name]["status"] != "PASS"]
    statuses = {checks[name]["status"] for name in PHASES}
    status = "FAIL" if "FAIL" in statuses else "PARTIAL" if blocked else "PASS"
    receipt = dict(kind=KIND, status=status, nonce=nonce, uid=USER, gid=USER, wayland_socket=wayland_socket,
                   vulkan_icd=LAVAPIPE, checks=checks)
    if name == RESTORED_REPORT:
        receipt["phase"] = "restoration"
    with (directory / name).open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    if blocked:
        raise RuntimeError("Qt runtime coverage " + status + ": " + ", ".join(
            f"{name}={checks[name]['status']}({checks[name]['reason']})" for name in blocked))


def run(*, nonce, wayland_socket=None, weston=None, phase="replacement"):
    """Transaction callback. Write every outcome, return None only on complete PASS.

    The caller supplies an already running disposable compositor's in-chroot
    socket when selected. It must be in /run and owned by UID 65534. An omitted
    socket produces explicit Wayland and QRhi skips. Any skip or failure causes
    the transaction actor to record a probe hold and proceed to Qt restoration.
    """
    if os.geteuid() != 0 or os.uname().machine != "aarch64" or os.sysconf("SC_PAGE_SIZE") != 16384:
        raise ValueError("Expected the owned AArch64 16 KiB guest")
    mounts = {fields[4]: (set(fields[5].split(",")), fields[fields.index("-") + 1])
              for row in Path("/proc/self/mountinfo").read_text().splitlines() if (fields := row.split())}
    for path, mode, fstype in ((Path("/"), "ro", "ext4"), (TARGET, "rw", "ext4"), (TARGET / "run", "rw", "tmpfs"),
                               (WORK, "rw", "tmpfs")):
        flags, actual = mounts.get(str(path), (set(), None))
        if mode not in flags or actual != fstype:
            raise ValueError(f"Unexpected probe guest mount: {path}")
    if set(os.listdir("/sys/class/net")) != {"lo"}:
        raise ValueError("Expected an offline guest")
    if phase not in REPORTS:
        raise ValueError("Unknown Qt runtime checkpoint")
    selection = f"cachy_overlay583_nonce={nonce}"
    if type(nonce) is not str or not re.fullmatch(r"[0-9a-f]{32}", nonce) or [word for word in Path("/proc/cmdline").read_text().split()
                                                   if word.partition("=")[0] == "cachy_overlay583_nonce"] != [selection]:
        raise ValueError("Qt runtime probes require the selected guest boot nonce")
    scratch = TARGET / "tmp"
    evidence = WORK if phase == "vendor" else EVIDENCE
    if not scratch.is_dir() or scratch.resolve() != scratch or not evidence.is_dir() or evidence.resolve() != evidence:
        raise ValueError("Expected ordinary guest scratch and transaction evidence directories")
    with tempfile.TemporaryDirectory(prefix="qt629-probe-", dir=scratch) as directory:
        checks = collect(Guest(Path(directory)), wayland_socket, weston, phase=phase)
    write_result(evidence, checks, wayland_socket, nonce=nonce, name=REPORTS[phase])
