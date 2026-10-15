#!/usr/bin/env python3
"""Finite disposable ARM guest session; no Apple hardware claim."""
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import stat
import subprocess
import sys
import threading
import time

SHARE = Path('/usr/local/share/desktop574')
HOME = Path('/home/desktop574')
RUNTIME = Path('/run/desktop574/runtime')
EVENT_NAME = 'desktop574.events'
EVENTS = None
SEAT = '/run/seatd.sock'  # Pinned seatd 0.9.3 uses this compiled-in path inside the private VM.
MAX_LOG = 256 * 1024
ENV = {'PATH': '/usr/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def event_port(sysfs=Path('/sys/class/virtio-ports'), devices=Path('/dev')):
    """Join the fixed QEMU channel name to its kernel character-device number."""
    ports = list(sysfs.glob('vport*'))
    need(len(ports) <= 1, 'ambiguous event ports')
    if not ports:
        return None
    port = ports[0]
    try:
        need((port / 'name').read_text().strip() == EVENT_NAME, 'wrong event port name')
        major, minor = map(int, (port / 'dev').read_text().strip().split(':'))
        device = devices / port.name
        value = device.lstat()
    except FileNotFoundError:
        return None
    need(stat.S_ISCHR(value.st_mode) and value.st_rdev == os.makedev(major, minor),
         'event port character-device identity differs')
    return device


def wait_event_port():
    until = time.monotonic() + 20
    while time.monotonic() < until:
        device = event_port()
        if device is not None:
            return device
        time.sleep(.1)
    raise ValueError('event port readiness deadline')


def emit(event, **values):
    # A dedicated non-console port keeps printk out of structured records.
    need(EVENTS is not None, 'event port unavailable')
    fd = os.open(EVENTS, os.O_WRONLY | os.O_NOCTTY | os.O_NOFOLLOW)  # Never create a missing device.
    with os.fdopen(fd, 'w') as stream:
        stream.write('DESKTOP574_EVENT ' + json.dumps(dict(event=event, **values), sort_keys=True) + '\n')


def guard(root):
    words = Path('/proc/cmdline').read_text().split()
    need(platform.machine() == 'aarch64' and
         'cachy_asahi_desktop574=1' in words and 'cachy_asahi_virtual_proof=1' in words and
         os.environ.get('CACHY_ASAHI_VIRTUAL_GUEST') == '1', 'disposable ARM guest markers required')
    need(os.geteuid() == (0 if root else 23001), 'wrong guest identity')
    if not root:
        need(os.getegid() == 23001, 'wrong guest group')


def terminate(process):
    """Retire one owned process group; never signal an already reaped leader."""
    if process.poll() is not None:
        return process.returncode
    first = None
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except BaseException as error:
        first = error
    try:
        result = process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except BaseException as error:
            if first is None:
                first = error
        try:
            result = process.wait(timeout=3)
        except BaseException:
            if first is not None:
                raise first
            raise
    except BaseException:
        if first is not None:
            raise first
        raise
    if first is not None:
        raise first
    return result


class Logged:
    """Separate capped stdout/stderr, drained continuously to prevent deadlock."""
    def __init__(self, argv, name, logs, env, stdin=None):
        self.paths = [logs / (name + '.stdout'), logs / (name + '.stderr')]
        self.errors = []
        self.overflow = False
        self.process = subprocess.Popen(argv, env=env, stdin=stdin or subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        start_new_session=True, close_fds=True)
        self.threads = []
        for pipe, path in zip((self.process.stdout, self.process.stderr), self.paths):
            thread = threading.Thread(target=self.drain, args=(pipe, path), daemon=True)
            thread.start()
            self.threads.append(thread)

    def drain(self, pipe, path):
        try:
            count = 0
            with path.open('xb') as output, pipe:
                while raw := pipe.read(65536):
                    output.write(raw[:max(0, MAX_LOG - count)])
                    count += len(raw)
                    if count > MAX_LOG:
                        self.overflow = True
        except BaseException as error:
            self.errors.append(error)

    def healthy(self):
        need(not self.overflow and not self.errors, 'process log overflow/failure')
        need(self.process.poll() is None, 'process exited before readiness/capture')

    def finish(self):
        need(self.process.poll() is not None, 'process not reaped')
        for thread in self.threads:
            thread.join(timeout=2)
        need(all(not t.is_alive() for t in self.threads), 'log drain incomplete')
        emit('process_exit', name=self.paths[0].name.removesuffix('.stdout'),
             returncode=self.process.returncode,
             logs=[dict(path=str(p), bytes=p.stat().st_size,
                        sha256=hashlib.sha256(p.read_bytes()).hexdigest(),
                        tail_base64=base64.b64encode(p.read_bytes()[-4096:]).decode()) for p in self.paths])
        need(not self.errors and not self.overflow, 'process log overflow/failure')


def command(argv, env, logs, name, timeout=20, *, retry_timeout=False):
    logged = Logged(argv, name, logs, env)
    first = None
    cleanup_ok = True
    try:
        logged.process.wait(timeout=timeout)
    except BaseException as error:
        first = error
    finally:
        for cleanup in (lambda: terminate(logged.process), logged.finish):
            try:
                cleanup()
            except BaseException as error:
                cleanup_ok = False
                if first is None:
                    first = error
    if first is not None:
        if retry_timeout and cleanup_ok and isinstance(first, subprocess.TimeoutExpired):
            return None  # Only a fully retired probe can become a readiness retry.
        raise first
    need(logged.process.returncode == 0, 'command failed: ' + name)
    return logged.paths[0].read_text()


def ready_seat():
    try:
        value = Path(SEAT).lstat()
    except FileNotFoundError:
        return False
    return (stat.S_ISSOCK(value.st_mode) and value.st_uid == value.st_gid == 23001 and
            value.st_mode & 0o777 == 0o770)


def ready_config(value):
    return type(value) is list and (value == [] or value == [''])


def usable_monitors(value):
    return type(value) is list and any(type(row) is dict and
        type(row.get('width')) is int and row['width'] > 0 and
        type(row.get('height')) is int and row['height'] > 0 for row in value)


def mapped_client(value, pid):
    return type(value) is list and any(type(row) is dict and row.get('pid') == pid and
        row.get('mapped') is True and type(row.get('size')) is list and len(row['size']) == 2 and
        all(type(n) is int and n > 0 for n in row['size']) for row in value)


def ipc(stage, compositor, env, logs):
    deadline = time.monotonic() + 90
    for attempt in range(30):
        compositor.healthy()
        sockets = list(RUNTIME.glob('hypr/*/.socket.sock'))
        need(len(sockets) <= 1, 'ambiguous compositor instances')
        remaining = deadline - time.monotonic()
        need(remaining > 0, 'IPC readiness deadline')
        if sockets:
            need(sockets[0].is_socket(), 'invalid IPC socket')
            selected = dict(env, HYPRLAND_INSTANCE_SIGNATURE=sockets[0].parent.name)
            probe = Logged(['/usr/bin/hyprctl', '-j', 'configerrors'],
                           stage + '-ipc-' + str(attempt), logs, selected)
            try:
                probe.process.wait(timeout=min(3, remaining))
            except subprocess.TimeoutExpired:
                terminate(probe.process)
            probe.finish()
            compositor.healthy()
            if probe.process.returncode == 0:
                need(ready_config(json.loads(probe.paths[0].read_text())), 'Hyprland config errors')
                need(not probe.paths[1].read_bytes(), 'IPC error output')
                return selected
        time.sleep(.5)
    raise ValueError('IPC readiness attempts exhausted')


def phase(stage, config, env, logs):
    compositor = client = None
    first = None
    try:
        need(not any(p.is_socket() for p in RUNTIME.glob('wayland-*')), 'stale Wayland socket')
        compositor = Logged(['/usr/bin/Hyprland', '--config', str(config)], stage, logs, env)
        selected = ipc(stage, compositor, env, logs)
        monitors = json.loads(command(['/usr/bin/hyprctl', '-j', 'monitors'], selected, logs, stage + '-monitors'))
        need(usable_monitors(monitors), 'no usable monitor')
        sockets = [p for p in RUNTIME.glob('wayland-*') if p.is_socket()]
        need(len(sockets) == 1, 'one private Wayland socket required')
        selected['WAYLAND_DISPLAY'] = sockets[0].name
        client = Logged(['/usr/bin/wofi', '--normal-window', '--show', 'dmenu', '--prompt',
                         'Generic ARM desktop574', '--width', '420', '--height', '220'],
                        stage + '-wofi', logs, selected, stdin=subprocess.PIPE)
        client.process.stdin.write(b'574 packages: generic ARM software session\nNo Apple hardware claim\n')
        client.process.stdin.close()
        for attempt in range(20):
            client.healthy(); compositor.healthy()
            response = command(['/usr/bin/hyprctl', '-j', 'clients'], selected, logs,
                               stage + '-clients-' + str(attempt), timeout=3, retry_timeout=True)
            if response is None:
                continue
            clients = json.loads(response)
            if mapped_client(clients, client.process.pid):
                break
            time.sleep(.5)
        else:
            raise ValueError('Wofi mapping deadline')
        emit('frame_ready', stage=stage, monitors=monitors, clients=clients)
        until = time.monotonic() + 8
        while time.monotonic() < until:
            client.healthy(); compositor.healthy()
            time.sleep(.2)
        terminate(client.process)
        command(['/usr/bin/hyprctl', 'dispatch', 'exit'], selected, logs, stage + '-exit', timeout=5)
        compositor.process.wait(timeout=10)
        need(compositor.process.returncode == 0, 'unclean Hyprland exit')
    except BaseException as error:
        first = error
    finally:
        for logged in (client, compositor):
            if logged is None:
                continue
            try:
                terminate(logged.process)
                logged.finish()
            except BaseException as error:
                if first is None:
                    first = error
    if first is not None:
        raise first
    emit('phase_pass', stage=stage)


def user():
    global EVENTS
    guard(False)
    EVENTS = event_port()
    need(EVENTS is not None, 'event port unavailable')
    event_stat = EVENTS.lstat()
    need(event_stat.st_uid == event_stat.st_gid == 23001 and event_stat.st_mode & 0o777 == 0o600,
         'private user event port required')
    need(HOME.stat().st_uid == RUNTIME.stat().st_uid == 23001 and
         HOME.stat().st_mode & 0o777 == RUNTIME.stat().st_mode & 0o777 == 0o700,
         'private home/runtime required')
    logs = HOME / 'logs'
    logs.mkdir(mode=0o700)
    for name in ('config', 'cache'):
        (HOME / name).mkdir(mode=0o700)
    env = dict(ENV, HOME=str(HOME), XDG_RUNTIME_DIR=str(RUNTIME),
               XDG_CONFIG_HOME=str(HOME / 'config'), XDG_CACHE_HOME=str(HOME / 'cache'),
               XDG_SESSION_TYPE='wayland', SEATD_SOCK=SEAT, LIBSEAT_BACKEND='seatd',
               LIBGL_ALWAYS_SOFTWARE='1', GBM_ALWAYS_SOFTWARE='1', GALLIUM_DRIVER='llvmpipe',
               LP_NUM_THREADS='2', CACHY_ASAHI_VIRTUAL_GUEST='1',
               DBUS_SESSION_BUS_ADDRESS=os.environ['DBUS_SESSION_BUS_ADDRESS'])
    cards = list(Path('/dev/dri').glob('card*'))
    need(len(cards) == 1, 'one virtio DRM card required')
    probe = json.loads(command(['/usr/local/bin/gbm-probe', str(cards[0])], env, logs, 'gbm', timeout=30))
    need(probe.get('status') == 'PASS', 'GBM software probe failed')
    emit('gbm_pass', probe=probe)
    for stage, config in [('minimal', SHARE / 'minimal.lua'),
                          ('overlay', Path('/usr/share/cachy-asahi/hyprland/hyprland.lua'))]:
        phase(stage, config, env, logs)
    emit('session_pass', status='PASS', waybar='NOT_RUN', mako='NOT_RUN', hardware='NOT_RUN')


def boot():
    global EVENTS
    guard(True)  # Never power off a host that failed the guest guard.
    seatd = session = None
    first = None
    logs = Path('/run/desktop574/root-logs')
    env = dict(ENV, CACHY_ASAHI_VIRTUAL_GUEST='1', SEATD_VTBOUND='0')
    try:
        EVENTS = wait_event_port()
        os.chown(EVENTS, 23001, 23001)
        EVENTS.chmod(0o600)
        os.umask(0o077)
        logs.parent.mkdir(mode=0o755, exist_ok=True)
        need(not logs.parent.is_symlink(), 'guest runtime parent symlink')
        logs.parent.chmod(0o755)  # Traverse seatd socket/private runtime despite umask077.
        logs.mkdir(mode=0o700)
        for path in (HOME, RUNTIME):
            path.mkdir(mode=0o700, exist_ok=True)
            need(not path.is_symlink(), 'private directory symlink')
            path.chmod(0o700)
            os.chown(path, 23001, 23001)
        kernel, page_size = platform.release(), os.sysconf('SC_PAGE_SIZE')
        emit('boot', architecture=platform.machine(), kernel=kernel, page_size=page_size, hardware='NOT_RUN')
        need(kernel == '7.2.10-1-aarch64-ARCH' and page_size == 4096, 'expected generic 4K guest kernel required')
        actual = command(['/usr/bin/pacman', '-Q'], env, logs, 'inventory')
        need(sorted(actual.splitlines()) == sorted((SHARE / 'expected.lock').read_text().splitlines()),
             'installed package inventory differs')
        command(['/usr/bin/modprobe', 'virtio_gpu'], env, logs, 'virtio-gpu')
        cards = list(Path('/dev/dri').glob('card*'))
        need(len(cards) == 1, 'one virtio DRM card required')
        command(['/usr/bin/udevadm', 'wait', '--timeout=20', '--initialized=yes', str(cards[0])],
                env, logs, 'udev')
        os.chown(cards[0], 23001, 23001)
        cards[0].chmod(0o600)
        need(not os.path.lexists(SEAT), 'preexisting seatd socket path')
        seatd = Logged(['/usr/bin/seatd', '-u', 'desktop574', '-g', 'desktop574', '-l', 'info'],
                       'seatd', logs, env)
        until = time.monotonic() + 10
        while not ready_seat():
            seatd.healthy()
            need(time.monotonic() < until, 'seatd readiness deadline')
            time.sleep(.1)
        # Root and user emit sequentially to the dedicated event port; child logs are capped.
        session = subprocess.Popen(['/usr/bin/runuser', '-u', 'desktop574', '--',
            '/usr/bin/dbus-run-session', '--', '/usr/bin/python3', '-I', '-B', str(SHARE / 'guest.py'), 'user'],
            env=env, stdin=subprocess.DEVNULL, start_new_session=True, close_fds=True)
        code = session.wait(timeout=480)
        need(code == 0, 'desktop user session failed')
    except BaseException as error:
        first = error
    finally:
        for child in (session, seatd.process if seatd else None):
            if child is not None:
                try:
                    terminate(child)
                except BaseException as error:
                    if first is None:
                        first = error
        if seatd:
            try:
                seatd.finish()
            except BaseException as error:
                if first is None:
                    first = error
        try:
            if first is None:
                emit('complete', status='PASS', software_session='PASS', waybar='NOT_RUN', mako='NOT_RUN', hardware='NOT_RUN')
            else:
                emit('failed', error_type=type(first).__name__, reason=str(first)[:512], hardware='NOT_RUN')
        except BaseException as error:
            if first is None:
                first = error
        try:
            subprocess.run(['/usr/bin/systemctl', 'poweroff'], env=env, timeout=10, check=True)
        except BaseException as error:
            if first is None:
                first = error
    if first is not None:
        raise first
    return 0


def main():
    need(len(sys.argv) == 2 and sys.argv[1] in ('boot', 'user'), 'boot or user required')
    try:
        return boot() if sys.argv[1] == 'boot' else user()
    except Exception as error:
        # boot() emits guarded failures; keep guard/transport refusals on the console.
        print(type(error).__name__ + ': ' + str(error)[:512], file=sys.stderr, flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
