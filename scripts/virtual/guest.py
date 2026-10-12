#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One finite generic guest software session; never an Asahi hardware validator."""
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import sys
import time
from common import bounded, LoggedProcess

PREFIX = 'CACHY_ASAHI_EVENT '
MAX_LOG = 1024 ** 2
IPC_ARGV = ['/usr/bin/hyprctl', '-j', 'configerrors']
IPC_TIMEOUT_REPLY = "Hyprland IPC didn't respond in time\n\nCouldn't read (6)\n"
IPC_ATTEMPTS = 24


def require(ok, message):
    if not ok:
        raise ValueError(message)


def guest_guard(root=False):
    require(platform.machine() == 'aarch64' and (os.geteuid() == 0) == root and
            os.getenv('CACHY_ASAHI_VIRTUAL_GUEST') == '1' and
            'cachy_asahi_virtual_proof=1' in Path('/proc/cmdline').read_text().split(),
            'explicit generic ARM guest required; host execution refused')


def emit(event, **data):
    print(PREFIX + json.dumps({'event': event, **data}, sort_keys=True), flush=True)


def command(argv, env=None, timeout=30):
    result = bounded(argv, env=env, timeout=timeout, limit=MAX_LOG)
    emit('command', argv=argv, **result)
    require(result['error'] is None and result['returncode'] == 0, 'command failed/overflowed: ' + argv[0])
    return result['stdout']


def retained(path, stage):
    retained_data(log_bytes(path), path.name, stage)


def retained_data(data, filename, stage):
    emit('session_log', stage=stage, filename=filename,
         sha256=hashlib.sha256(data[:MAX_LOG]).hexdigest(), base64=base64.b64encode(data[:MAX_LOG]).decode())
    require(len(data) <= MAX_LOG, 'session log overflow')


def log_bytes(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'regular session log required')
        return stream.read(MAX_LOG + 1)


def no_reported_config_error_text(value):
    return type(value) is list and (value == [] or
            len(value) == 1 and type(value[0]) is str and value[0] == '')


def wait_for_ipc(stage, compositor, env, log, check_logs):
    """A bound/listening socket precedes Hyprland's event loop; require a reply."""
    start = time.monotonic()
    deadline, attempt = start + 180, 0
    while time.monotonic() < deadline:
        require(compositor.poll() is None, 'compositor exited before IPC readiness')
        require(log.stat().st_size <= MAX_LOG, 'compositor log overflow')
        check_logs()
        sockets = list(Path(env['XDG_RUNTIME_DIR']).glob('hypr/*/.socket.sock'))
        require(len(sockets) <= 1, 'ambiguous compositor IPC sockets')
        if sockets:
            require(sockets[0].is_socket(), 'compositor IPC path is not a socket')
            probe_env = dict(env, HYPRLAND_INSTANCE_SIGNATURE=sockets[0].parent.name)
            remaining = deadline - time.monotonic()
            require(remaining > 0 and attempt < IPC_ATTEMPTS, 'compositor IPC probe deadline/attempt limit')
            attempt += 1
            result = bounded(IPC_ARGV, env=probe_env, timeout=min(30, remaining), limit=MAX_LOG)
            require(type(result['returncode']) is int and result['error'] in (None, 'timeout', 'output overflow') and
                    isinstance(result['stdout'], str) and isinstance(result['stderr'], str) and
                    len(result['stdout'].encode('utf-8')) + len(result['stderr'].encode('utf-8')) <= MAX_LOG,
                    'invalid bounded IPC probe result')
            elapsed_ms = int((time.monotonic() - start) * 1000)
            emit('ipc_probe', stage=stage, attempt=attempt, elapsed_ms=elapsed_ms, **result)
            require(time.monotonic() < deadline, 'compositor IPC deadline')
            require(compositor.poll() is None, 'compositor exited during IPC readiness')
            check_logs()
            require(log.stat().st_size <= MAX_LOG, 'compositor log overflow')
            if result['error'] is None and result['returncode'] == 0:
                require(result['stderr'] == '' and no_reported_config_error_text(json.loads(result['stdout'])),
                        'runtime config errors')
                emit('command', argv=IPC_ARGV, **result)
                return probe_env
            require(result == {'returncode': 6, 'error': None, 'stdout': IPC_TIMEOUT_REPLY, 'stderr': ''},
                    'compositor IPC probe failed/overflowed')
        time.sleep(min(.5, max(0, deadline - time.monotonic())))
    raise ValueError('compositor IPC deadline')


def terminate(process):
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)


def phase(stage, config, env, root):
    log = root / (stage + '.log')
    compositor, client = None, None
    collectors = []
    instances = Path(env['XDG_RUNTIME_DIR']) / 'hypr'
    previous = set(instances.glob('*'))
    private_log = None
    def check_logs(check_size=True):
        nonlocal private_log
        created = set(instances.glob('*')) - previous
        require(len(created) <= 1, 'ambiguous private compositor instance')
        if created:
            instance = created.pop()
            require(instance.is_dir() and not instance.is_symlink(), 'private compositor instance required')
            private_log = instance / 'hyprland.log'
            if private_log.exists():
                require(not private_log.is_symlink() and private_log.is_file() and
                        (not check_size or private_log.stat().st_size <= MAX_LOG), 'private compositor log invalid/overflowed')
    try:
        collector = LoggedProcess(['/usr/bin/Hyprland', '--config', str(config)], log, env=env)
        collectors.append(collector)
        compositor = collector.process
        env = wait_for_ipc(stage, compositor, env, log, check_logs)
        monitors = json.loads(command(['/usr/bin/hyprctl', '-j', 'monitors'], env))
        require(any(m.get('width', 0) > 0 and m.get('height', 0) > 0 for m in monitors), 'no usable virtual output')
        wayland = list(Path(env['XDG_RUNTIME_DIR']).glob('wayland-*'))
        wayland = [p for p in wayland if p.is_socket()]
        require(len(wayland) == 1, 'expected one private Wayland socket')
        env['WAYLAND_DISPLAY'] = wayland[0].name
        client_log = root / (stage + '-client.log')
        collector = LoggedProcess(['/usr/bin/wofi', '--normal-window', '--show', 'dmenu', '--prompt', 'Generic ARM software proof', '--width', '420', '--height', '220'],
                                  client_log, env=env, stdin=subprocess.PIPE)
        collectors.append(collector)
        client = collector.process
        client.stdin.write(b'cachy-asahi software proof\nNo Apple hardware claim\n')
        client.stdin.close()
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            check_logs()
            require(client.poll() is None and compositor.poll() is None, 'client/compositor exited before frame')
            require(log.stat().st_size <= MAX_LOG and client_log.stat().st_size <= MAX_LOG, 'session/client log overflow')
            clients = json.loads(command(['/usr/bin/hyprctl', '-j', 'clients'], env))
            if any(c.get('pid') == client.pid and c.get('mapped') is True and
                   all(x > 0 for x in c.get('size', [0, 0])) for c in clients):
                break
            time.sleep(.5)
        else:
            raise ValueError('Wayland client mapping deadline')
        emit('frame_ready', stage=stage, monitors=monitors, clients=clients)
        # Fixed window for outer QMP capture; no network or host IPC.
        until = time.monotonic() + 15
        while time.monotonic() < until:
            check_logs()
            require(client.poll() is None and compositor.poll() is None and
                    log.stat().st_size <= MAX_LOG and client_log.stat().st_size <= MAX_LOG,
                    'session failed/overflowed during capture window')
            time.sleep(.25)
        terminate(client)
        client = None
        collectors[-1].finish()
        retained(client_log, stage)
        command(['/usr/bin/hyprctl', 'dispatch', 'exit'], env)
        compositor.wait(timeout=15)
        require(compositor.returncode == 0, 'unclean compositor shutdown')
        emit('phase_pass', stage=stage)
    finally:
        failure = sys.exc_info()[1]
        cleanup_errors = []
        if client and client.poll() is None:
            try:
                terminate(client)
            except Exception as exc:
                cleanup_errors.append(exc)
        if compositor and compositor.poll() is None:
            try:
                terminate(compositor)
            except Exception as exc:
                cleanup_errors.append(exc)
        for collector in collectors:
            try:
                collector.finish()
            except Exception as exc:
                cleanup_errors.append(exc)
        if log.exists():
            try:
                retained(log, stage)
            except Exception as exc:
                cleanup_errors.append(exc)
        # Fixed file only, after reaping. Never export an instance directory.
        private_retained = False
        try:
            require(compositor is None or compositor.poll() is not None, 'compositor reaping incomplete')
            check_logs(check_size=False)
            destination = root / (stage + '-compositor.log')
            data = log_bytes(private_log) if private_log and private_log.exists() else b'private compositor log unavailable\n'
            destination.write_bytes(data[:MAX_LOG])
            retained(destination, stage)
            private_retained = True
            require(len(data) <= MAX_LOG, 'private compositor log overflow')
        except Exception as exc:
            cleanup_errors.append(exc)
            if not private_retained:
                try:
                    retained_data(('private compositor log retention failed: ' + type(exc).__name__ + '\n').encode(),
                                  stage + '-compositor.log', stage)
                except Exception as diagnostic_error:
                    cleanup_errors.append(diagnostic_error)
        if cleanup_errors:
            try:
                print('guest secondary cleanup failures: ' + ','.join(type(exc).__name__ for exc in cleanup_errors), flush=True)
            except Exception as diagnostic_error:
                cleanup_errors.append(diagnostic_error)
        if cleanup_errors and failure is None:
            raise cleanup_errors[0]


def run_user():
    guest_guard()
    nonce = json.loads(Path('/usr/local/share/virtual-proof/contract.json').read_text())['nonce']
    require(re.fullmatch('[0-9a-f]{32}', nonce), 'invalid guest nonce')
    root = Path('/home/virtual-proof/evidence')
    root.mkdir(mode=0o700)
    env = {'PATH': '/usr/bin', 'HOME': '/home/virtual-proof', 'LANG': 'C.UTF-8',
           'XDG_RUNTIME_DIR': '/run/virtual-proof', 'XDG_CONFIG_HOME': '/home/virtual-proof/config',
           'XDG_CACHE_HOME': '/home/virtual-proof/cache', 'XDG_SESSION_TYPE': 'wayland',
           'SEATD_SOCK': '/run/seatd.sock', 'LIBSEAT_BACKEND': 'seatd',
           'GBM_ALWAYS_SOFTWARE': '1', 'LIBGL_ALWAYS_SOFTWARE': '1', 'GALLIUM_DRIVER': 'llvmpipe',
           'LP_NUM_THREADS': '2', 'CACHY_ASAHI_VIRTUAL_GUEST': '1',
           'DBUS_SESSION_BUS_ADDRESS': os.environ['DBUS_SESSION_BUS_ADDRESS']}
    for name in ('config', 'cache'):
        (Path(env['HOME']) / name).mkdir(mode=0o700)
    card = sorted(Path('/dev/dri').glob('card*'))
    require(len(card) == 1, 'expected one guest DRM card')
    probe = json.loads(command(['/usr/local/bin/gbm-probe', str(card[0])], env))
    require(probe.get('status') == 'PASS', 'GBM software render probe did not pass')
    emit('gbm_pass', nonce=nonce, probe=probe)
    for stage, config in [('minimal', '/usr/local/share/virtual-proof/minimal.lua'),
                          ('overlay', '/usr/share/cachy-asahi/hyprland/hyprland.lua')]:
        runtime = Path(env['XDG_RUNTIME_DIR'])
        require(not any(runtime.glob('wayland-*')), 'stale Wayland output from earlier phase')
        phase(stage, Path(config), env, root)
    emit('guest_pass', nonce=nonce, software_session='PASS', hardware_validation='NOT RUN', graphics_acceleration='NOT RUN')


def boot():
    guest_guard(root=True)
    contract = json.loads(Path('/usr/local/share/virtual-proof/contract.json').read_text())
    emit('boot', nonce=contract['nonce'], arch=platform.machine(), page_size=os.sysconf('SC_PAGE_SIZE'),
         kernel=platform.release(), execution='qemu-tcg-generic-aarch64', hardware_validation='NOT RUN')
    require(platform.release() == '7.2.10-1-aarch64-ARCH' and os.sysconf('SC_PAGE_SIZE') == 4096, 'wrong guest kernel/page size')
    command(['/usr/bin/modprobe', 'virtio_gpu'])
    command(['/usr/bin/udevadm', 'settle', '--timeout=30'])
    command(['/usr/bin/dmesg'])
    actual = command(['/usr/bin/pacman', '-Q'])
    expected = Path('/usr/local/share/virtual-proof/runtime.lock').read_text()
    require(actual.strip() == expected.strip(), 'guest installed inventory differs from prepared full image')
    for row in contract['baseline']:
        for name, value in row['payload_sha256'].items():
            require(hashlib.sha256((Path('/') / name).read_bytes()).hexdigest() == value, 'guest original overlay payload differs')
    uid = 23001
    for p in [Path('/run/virtual-proof'), Path('/home/virtual-proof')]:
        p.mkdir(mode=0o700, exist_ok=True)
        os.chown(p, uid, uid)
    cards = sorted(Path('/dev/dri').glob('card*'))
    require(len(cards) == 1, 'one virtual guest GPU required')
    os.chown(cards[0], uid, uid)
    cards[0].chmod(0o600)
    emit('guest_runtime_changes', paths=['/run/virtual-proof', '/home/virtual-proof', str(cards[0])], owner=uid)
    env = dict(os.environ, SEATD_VTBOUND='0', LIBSEAT_BACKEND='seatd', CACHY_ASAHI_VIRTUAL_GUEST='1')
    seatd = subprocess.Popen(['/usr/bin/seatd', '-u', 'virtual-proof', '-g', 'virtual-proof', '-l', 'debug'], env=env, start_new_session=True)
    try:
        until = time.monotonic() + 15
        while not Path('/run/seatd.sock').is_socket():
            require(time.monotonic() < until and seatd.poll() is None, 'guest seatd readiness failed')
            time.sleep(.1)
        result = subprocess.run(['/usr/bin/runuser', '-u', 'virtual-proof', '--', '/usr/bin/dbus-run-session', '--', '/usr/bin/python', __file__, 'user'], env=env, timeout=600)
        require(result.returncode == 0, 'guest software proof failed')
    finally:
        terminate(seatd)


if __name__ == '__main__':
    try:
        require(len(sys.argv) == 2 and sys.argv[1] in ('boot', 'user'), 'explicit guest stage required')
        boot() if sys.argv[1] == 'boot' else run_user()
    except Exception as exc:
        emit('guest_failed', error=str(exc), hardware_validation='NOT RUN')
        sys.exit(1)
