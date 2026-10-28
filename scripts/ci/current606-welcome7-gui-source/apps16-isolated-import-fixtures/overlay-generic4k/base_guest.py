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
import post_session
import management_root
import doctor_lifetime as DL

SHARE = Path('/usr/local/share/desktop574')
HOME = Path('/home/desktop574')
RUNTIME = Path('/run/user/23001')
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


def drm_card(sysfs=Path('/sys/class/drm'), devices=Path('/dev/dri')):
    """Match one primary DRM node to its kernel device number, without udev DB."""
    def primary(path):
        suffix = path.name.removeprefix('card')
        return path.name.startswith('card') and suffix.isascii() and suffix.isdecimal()
    cards = [path for path in sysfs.glob('card*') if primary(path)]
    nodes = [path for path in devices.glob('card*') if primary(path)]
    need(len(cards) <= 1 and len(nodes) <= 1, 'ambiguous DRM cards')
    if not cards or not nodes:
        return None
    card = cards[0]
    device = devices / card.name
    try:
        major, minor = map(int, (card / 'dev').read_text().strip().split(':'))
        # Linux7.2.10 attaches this DRM minor to the virtio GPU's PCI parent.
        parent = card / 'device'
        need((parent / 'vendor').read_text().strip() == '0x1af4' and
             (parent / 'device').read_text().strip() == '0x1050' and
             Path(os.readlink(parent / 'driver')).name == 'virtio-pci',
             'wrong DRM PCI transport')
        children = list(parent.glob('virtio[0-9]*'))
        need(len(children) <= 1, 'ambiguous DRM virtio devices')
        if not children:
            return None
        need(Path(os.readlink(children[0] / 'driver')).name == 'virtio_gpu',
             'wrong DRM virtio driver')
        value = device.lstat()
    except FileNotFoundError:
        return None
    need(nodes == [device] and stat.S_ISCHR(value.st_mode) and major == 226 and
         0 <= minor < 64 and minor == int(card.name[4:]) and value.st_rdev == os.makedev(major, minor),
         'DRM character-device identity differs')
    return device


def wait_drm_card():
    until = time.monotonic() + 20
    while time.monotonic() < until:
        device = drm_card()
        if device is not None and drm_render_node(device) is not None:
            return device
        time.sleep(.1)
    raise ValueError('DRM readiness deadline')


def drm_render_node(card, sysfs=Path('/sys/class/drm'), devices=Path('/dev/dri')):
    """Required render node of the already verified sole virtio GPU, or not ready."""
    def render(path):
        suffix = path.name.removeprefix('renderD')
        return path.name.startswith('renderD') and suffix.isascii() and suffix.isdecimal()
    entries = list(sysfs.glob('renderD*'))
    nodes = list(devices.glob('renderD*'))
    need(all(render(path) for path in entries + nodes), 'invalid DRM render node name')
    need(len(entries) <= 1 and len(nodes) <= 1, 'ambiguous DRM render nodes')
    if not entries or not nodes:
        return None
    entry = entries[0]
    device = devices / entry.name
    try:
        major, minor = map(int, (entry / 'dev').read_text().strip().split(':'))
        value = device.lstat()
        primary_parent = (sysfs / card.name / 'device').stat()
        render_parent = (entry / 'device').stat()
    except FileNotFoundError:
        return None
    need((primary_parent.st_dev, primary_parent.st_ino) == (render_parent.st_dev, render_parent.st_ino),
         'DRM render node belongs to another GPU')
    need(nodes == [device] and stat.S_ISCHR(value.st_mode) and major == 226 and
         minor >= 128 and minor == int(entry.name[7:]) and value.st_rdev == os.makedev(major, minor),
         'DRM render character-device identity differs')
    return device


def render_access(card):
    identity = dict(device=None)
    try:
        device = drm_render_node(card)
        need(device is not None, 'required DRM render node unavailable')
        before = device.lstat()
        identity = dict(device=str(device), major=os.major(before.st_rdev), minor=os.minor(before.st_rdev),
                        uid=before.st_uid, gid=before.st_gid, mode=stat.S_IMODE(before.st_mode))
        need(stat.S_ISCHR(before.st_mode) and before.st_uid == before.st_gid == 23001 and
             before.st_mode & 0o777 == 0o600, 'private user renderer node required')
        descriptor = os.open(device, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        first = None
        try:
            opened = os.fstat(descriptor)
            need(all(getattr(before, field) == getattr(opened, field) for field in
                     ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_rdev')),
                 'opened renderer node identity differs')
        except BaseException as error:
            first = error
        try:
            os.close(descriptor)
        except BaseException as error:
            if first is None:
                first = error
        if first is not None:
            raise first
    except (OSError, ValueError) as error:
        try:
            emit('render_access', status='FAIL', errno=error.errno if isinstance(error, OSError) else None, **identity)
        except BaseException:
            pass
        raise
    emit('render_access', status='PASS', errno=0, **identity)


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
        name = self.paths[0].name.removesuffix('.stdout')
        logs = [dict(path=str(p), bytes=p.stat().st_size,
                     sha256=hashlib.sha256(p.read_bytes()).hexdigest(),
                     tail_base64=base64.b64encode(p.read_bytes()[-4096:]).decode()) for p in self.paths]
        wofi = name in ('minimal-wofi', 'overlay-wofi')
        if wofi:
            logs[1].update(content_base64=base64.b64encode(self.paths[1].read_bytes()).decode(),
                           capture_complete=not self.errors and not self.overflow)
        emit('process_exit', name=name, returncode=self.process.returncode, logs=logs,
             **(dict(pid=self.process.pid) if wofi else {}))
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


def diagnostic_directory(path):
    """Open the fixed guest diagnostic parents without following any symlinks."""
    need(path.is_absolute() and '..' not in path.parts, 'invalid diagnostic parent')
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=descriptor)
            old, descriptor = descriptor, child
            os.close(old)
        need(os.fstat(descriptor).st_uid == 23001, 'unowned diagnostic parent')
        result, descriptor = descriptor, None
        return result
    finally:
        if descriptor is not None:
            os.close(descriptor)


def diagnostic_file(directory, name):
    need(type(name) is str and name not in ('', '.', '..') and '/' not in name and '\0' not in name,
         'invalid diagnostic filename')
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         dir_fd=directory)
    try:
        before = os.fstat(descriptor)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 23001 and before.st_nlink == 1,
             'unsupported diagnostic file')
        size = before.st_size
        need(size >= 0, 'invalid diagnostic size')
        spans = [(0, size)] if size <= MAX_LOG else [(0, MAX_LOG // 2), (size - MAX_LOG // 2, MAX_LOG // 2)]
        chunks = []
        for offset, length in spans:
            os.lseek(descriptor, offset, os.SEEK_SET)
            data = os.read(descriptor, length)
            need(len(data) == length, 'short diagnostic read')
            chunks.append(data)
        def identity(value):
            return tuple(getattr(value, field) for field in ('st_dev', 'st_ino', 'st_mode', 'st_uid',
                'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))
        try:
            named = os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            raise ValueError('diagnostic file changed') from None
        need(identity(before) == identity(os.fstat(descriptor)) == identity(named), 'diagnostic file changed')
        raw = b''.join(chunks)
        digest = hashlib.sha256(raw).hexdigest()
        result = dict(status='present', source_bytes=size, retained_bytes=len(raw), truncated=size > MAX_LOG,
                      segments=[dict(offset=offset, bytes=length) for offset, length in spans],
                      retained_sha256=digest, content_base64=base64.b64encode(raw).decode())
        if size <= MAX_LOG:
            result['full_sha256'] = digest
        return result
    finally:
        os.close(descriptor)


def collect_phase_diagnostics(stage, pid):
    need(stage in ('minimal', 'overlay') and type(pid) is int and pid > 0, 'invalid diagnostic phase')
    for kind in ('crash', 'compositor'):
        directory = None
        name = 'hyprlandCrashReport' + str(pid) + '.txt'
        path = str(HOME / 'cache/hyprland' / name) if kind == 'crash' else None
        try:
            parent = HOME / 'cache/hyprland' if kind == 'crash' else RUNTIME / 'hypr'
            directory = diagnostic_directory(parent)
            if kind == 'compositor':
                with os.scandir(directory) as entries:
                    names = []
                    for entry in entries:
                        names.append(entry.name)
                        if len(names) == 2:
                            break
                if not names:
                    raise FileNotFoundError()
                need(len(names) == 1, 'ambiguous diagnostic instances')
                child = os.open(names[0], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=directory)
                old, directory = directory, child
                os.close(old)
                need(os.fstat(directory).st_uid == 23001, 'unowned diagnostic instance')
                name = 'hyprland.log'
                path = str(parent / names[0] / name)
            record = diagnostic_file(directory, name)
        except FileNotFoundError:
            record = dict(status='absent')
        except (OSError, ValueError):
            record = dict(status='error', reason='diagnostic collection failed')
        finally:
            if directory is not None:
                try:
                    os.close(directory)
                except OSError:
                    record = dict(status='error', reason='diagnostic close failed')
        emit('diagnostic_file', stage=stage, pid=pid, name=kind, path=path, **record)


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


def owned_thread_state(process, deadline, proc=Path('/proc')):
    """Read only this parent's owned child; an unfinished daemon is never a sample."""
    deadline = min(deadline, time.monotonic() + .5)
    if time.monotonic() >= deadline:
        return dict(status='incomplete', pid=process.pid, reason='thread observation deadline')
    result = {}
    def observe():
        row = dict(status='incomplete', pid=process.pid, threads=[], bytes_read=0,
                   started=time.monotonic(), thread_limit=32, file_limit=4096, byte_limit=128 * 1024)
        def read(directory, name):
            need(time.monotonic() < deadline, 'thread observation deadline')
            left = row['byte_limit'] - row['bytes_read']
            need(left > 0, 'thread observation byte limit')
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            try:
                raw = os.read(fd, min(4096, left))
            finally:
                os.close(fd)
            row['bytes_read'] += len(raw)
            need(time.monotonic() < deadline, 'thread observation deadline')
            need(len(raw) < min(4096, left), 'thread observation file/byte limit')
            return raw.decode('ascii').strip()
        def state(directory, pid):
            raw = read(directory, 'stat')
            prefix, fields = raw.rsplit(') ', 1)
            fields = fields.split()
            need(int(prefix.split(' ', 1)[0]) == pid, 'thread identity differs')
            return dict(pid=pid, state=fields[0], ppid=int(fields[1]), utime=int(fields[11]),
                        stime=int(fields[12]), starttime=int(fields[19]))
        def identity(directory):
            need(os.fstat(directory).st_uid == os.geteuid(), 'owned process uid differs')
            value = state(directory, process.pid)
            need(value['ppid'] == os.getpid(), 'owned process parent differs')
            return dict(pid=value['pid'], starttime=value['starttime'], uid=os.geteuid())
        try:
            need(type(process.pid) is int and process.pid > 0 and process.returncode is None,
                 'owned process unavailable')
            directory = os.open(str(proc / str(process.pid)), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                row['identity_before'] = identity(directory)
                tasks = os.open('task', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                try:
                    tids = []
                    with os.scandir(tasks) as entries:
                        for entry in entries:
                            need(time.monotonic() < deadline, 'thread observation deadline')
                            need(entry.name.isascii() and entry.name.isdecimal(), 'invalid owned thread id')
                            if len(tids) == 32:
                                row['threads_truncated'] = True
                                break
                            tids.append(int(entry.name))
                    for tid in sorted(tids):
                        item = dict(tid=tid, status='unavailable')
                        row['threads'].append(item)
                        thread = None
                        try:
                            thread = os.open(str(tid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=tasks)
                            need(os.fstat(thread).st_uid == row['identity_before']['uid'], 'thread uid differs')
                            item['before'] = state(thread, tid)
                            for name in ('wchan', 'syscall'):
                                try:
                                    value = read(thread, name)
                                    need(bool(value), 'empty thread observation')
                                    if name == 'syscall':
                                        item[name] = dict(status='running') if value == 'running' else dict(
                                            status='observed', values=[int(x, 0) for x in value.split()])
                                    else:
                                        item[name] = dict(status='unavailable' if value in ('', '0') else 'observed', value=value)
                                except (OSError, ValueError, UnicodeError) as error:
                                    item[name] = dict(status='unavailable', error_type=type(error).__name__,
                                                      errno=getattr(error, 'errno', None), reason=str(error)[:128])
                            item['after'] = state(thread, tid)
                            need(item['before']['starttime'] == item['after']['starttime'], 'thread identity changed')
                            item['status'] = 'observed'
                        except (OSError, ValueError, UnicodeError, IndexError) as error:
                            item.update(error_type=type(error).__name__, errno=getattr(error, 'errno', None), reason=str(error)[:128])
                        finally:
                            if thread is not None:
                                os.close(thread)
                finally:
                    os.close(tasks)
                row['identity_after'] = identity(directory)
                need(row['identity_before'] == row['identity_after'], 'owned process identity changed')
                row['status'] = 'observed' if not row.get('threads_truncated') and all(
                    x['status'] == 'observed' and all(x[k]['status'] != 'unavailable' for k in ('wchan', 'syscall'))
                    for x in row['threads']) else 'incomplete'
            finally:
                os.close(directory)
        except (OSError, ValueError, UnicodeError, IndexError) as error:
            row.update(error_type=type(error).__name__, errno=getattr(error, 'errno', None), reason=str(error)[:128])
        row['finished'] = time.monotonic()
        result['row'] = row
    try:
        worker = threading.Thread(target=observe, daemon=True)
        worker.start()
        worker.join(timeout=max(0, min(.5, deadline - time.monotonic())))
    except Exception as error:
        return dict(status='unavailable', pid=process.pid, error_type=type(error).__name__)
    if worker.is_alive():
        return dict(status='incomplete', pid=process.pid, reason='thread observation deadline', worker_unjoined=True)
    return result.get('row', dict(status='unavailable', pid=process.pid, reason='thread observation failed'))


def capture_window(stage, monitors, client, compositor, env, logs):
    # Let normal animations run before the fresh capture query. The normal
    # command timeout and post-event live interval are separate from settling;
    # all of this still consumes the root's existing 480-second session ceiling.
    start = time.monotonic()
    until = start + 5
    while time.monotonic() < until:
        client.healthy(); compositor.healthy()
        time.sleep(min(.2, max(0, until - time.monotonic())))
    client.healthy(); compositor.healthy()
    clients = json.loads(command(['/usr/bin/hyprctl', '-j', 'clients', '-a'], env, logs,
                                 stage + '-capture-clients', timeout=20))
    need(type(clients) is list, 'invalid capture clients reply')
    client.healthy(); compositor.healthy()
    owned = [row for row in clients if type(row) is dict and
             type(row.get('pid')) is int and row['pid'] == client.process.pid]
    need(len(owned) == 1 and mapped_client(owned, client.process.pid) and
         owned[0]['size'] == [420, 220] and owned[0].get('visible') is True and
         owned[0].get('hidden') is False and owned[0].get('xwayland') is False,
         'owned Wofi not fully mapped/visible at capture')
    emit('frame_ready', stage=stage, monitors=monitors, clients=clients,
         capture_after_ms=int((time.monotonic() - start) * 1000))
    until = time.monotonic() + 8
    while time.monotonic() < until:
        client.healthy(); compositor.healthy()
        time.sleep(min(.2, max(0, until - time.monotonic())))


def phase(stage, config, env, logs):
    compositor = client = None
    first = None
    observation_started = False
    observations = []
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
                        stage + '-wofi', logs, dict(selected, WAYLAND_DEBUG='client'), stdin=subprocess.PIPE)
        client.process.stdin.write(b'574 packages: generic ARM software session\nNo Apple hardware claim\n')
        client.process.stdin.close()
        observation_started = True
        observations.append(dict(point='mapping_start', **owned_thread_state(compositor.process, time.monotonic() + .5)))
        for attempt in range(20):
            client.healthy(); compositor.healthy()
            response = command(['/usr/bin/hyprctl', '-j', 'clients', '-a'], selected, logs,
                               stage + '-clients-' + str(attempt), timeout=3, retry_timeout=True)
            if response is None:
                continue
            clients = json.loads(response)
            if mapped_client(clients, client.process.pid):
                break
            time.sleep(.5)
        else:
            raise ValueError('Wofi mapping deadline')
        capture_window(stage, monitors, client, compositor, selected, logs)
        terminate(client.process)
        command(['/usr/bin/hyprctl', 'dispatch', 'hl.dsp.exit()'], selected, logs, stage + '-exit', timeout=5)
        compositor.process.wait(timeout=10)
        need(compositor.process.returncode == 0, 'unclean Hyprland exit')
    except BaseException as error:
        first = error
        if observation_started:
            try:
                snapshot = owned_thread_state(compositor.process, time.monotonic() + .5)
                initial = observations[0].get('identity_before') if observations else None
                if initial is not None and snapshot.get('identity_before') not in (None, initial):
                    snapshot.update(status='incomplete', reason='owned process identity changed between samples')
                observations.append(dict(point='pre_cleanup_failure', **snapshot))
            except BaseException:
                observations.append(dict(point='pre_cleanup_failure', status='unavailable'))
    finally:
        before_cleanup = 'unavailable'
        if compositor is not None:
            try:
                before_cleanup = compositor.process.poll()
            except BaseException:
                pass  # Diagnostic metadata must not interfere with retiring owned processes.
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
        if compositor is not None:
            try:
                emit('phase_diagnostic', stage=stage, pid=compositor.process.pid,
                     error_type=type(first).__name__, reason=str(first)[:512],
                     returncode_before_cleanup=before_cleanup, thread_states=observations)
                collect_phase_diagnostics(stage, compositor.process.pid)
            except BaseException:
                pass  # The original phase failure remains primary even if diagnostics fail.
        raise first
    emit('phase_pass', stage=stage, thread_states=observations)


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
               LP_NUM_THREADS='0', GALLIVM_PERF='nopt', CACHY_ASAHI_VIRTUAL_GUEST='1',
               DBUS_SESSION_BUS_ADDRESS=os.environ['DBUS_SESSION_BUS_ADDRESS'])
    managed_session.validate_user(managed_base, logs, env)
    card = drm_card()
    need(card is not None, 'DRM card unavailable')
    card_stat = card.lstat()
    need(card_stat.st_uid == card_stat.st_gid == 23001 and card_stat.st_mode & 0o777 == 0o600,
         'private user DRM card required')
    probe = json.loads(command(['/usr/local/bin/gbm-probe', str(card)], env, logs, 'gbm', timeout=30))
    need(probe.get('status') == 'PASS', 'GBM software probe failed')
    emit('gbm_pass', probe=probe)
    import importlib.util
    product_spec=importlib.util.spec_from_file_location('current606_actual_products',SHARE/'current_products.py')
    product=importlib.util.module_from_spec(product_spec)
    product_spec.loader.exec_module(product)
    emit('current606_products',receipt=product.run(SHARE,HOME,env))
    render_access(card)  # Hyprland may open this distinct node after its GBM fallback.
    for stage, config in [('overlay', Path('/usr/share/cachy-asahi/hyprland/hyprland.lua'))]:
        phase(stage, config, env, logs)
    emit('session_pass', status='PASS', waybar='NOT_RUN', mako='NOT_RUN', hardware='NOT_RUN')


def boot():
    global EVENTS
    guard(True)  # Never power off a host that failed the guest guard.
    DL.service()
    seatd = session = None
    manager = None
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
        for path in (HOME,):
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
        manager = managed_session.ManagedSession(managed_base, logs, env)
        env.update(manager.start())
        command(['/usr/bin/modprobe', 'virtio_gpu'], env, logs, 'virtio-gpu')
        card = wait_drm_card()
        os.chown(card, 23001, 23001)
        card.chmod(0o600)
        render = drm_render_node(card)
        need(render is not None, 'required DRM render node unavailable')
        os.chown(render, 23001, 23001)
        render.chmod(0o600)
        need(not os.path.lexists(SEAT), 'preexisting seatd socket path')
        seatd = Logged(['/usr/bin/seatd', '-u', 'desktop574', '-g', 'desktop574', '-l', 'info'],
                       'seatd', logs, env)
        until = time.monotonic() + 10
        while not ready_seat():
            seatd.healthy()
            need(time.monotonic() < until, 'seatd readiness deadline')
            time.sleep(.1)
        # Root and user emit sequentially to the dedicated event port; child logs are capped.
        session = subprocess.Popen(managed_session.SETPRIV +
            ['/usr/bin/python3', '-I', '-B', str(SHARE / 'guest.py'), 'user'],
            env=env, stdin=subprocess.DEVNULL, start_new_session=True, close_fds=True)
        code = management_root.serve(managed_base, session, env, logs, DL.service_lease()['deadline_ns'])
        need(code == 0, 'desktop user session failed')
        post_session.mark(emit,'installed606_verify_begin')
        proof=command(['/usr/bin/python3','-I','-B',str(SHARE/'installed606.py'),'verify','/',str(SHARE/'alpm_reader.py'),str(SHARE/'expected.lock'),str(SHARE/'installed606.json')],env,logs,'installed606-preserved',timeout=600)
        post_session.mark(emit,'installed606_verify_end')
        emit('installed606_preserved',status='PASS',receipt=json.loads(proof),hardware='NOT_RUN')
    except BaseException as error:
        first = error
    finally:
        if first is not None and manager is not None:
            try:
                manager.diagnose()
            except BaseException:
                pass  # Original failure stays primary.
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
        if manager is not None:
            post_session.mark(emit,'manager_cleanup_begin')
            try:
                manager.stop()
                post_session.mark(emit,'manager_cleanup_end')
            except BaseException as error:
                if first is None:
                    first = error
                try:
                    manager.diagnose()
                except BaseException:
                    pass  # Cleanup remains failed.
        try:
            if first is None:
                post_session.mark(emit,'complete_boundary')
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
