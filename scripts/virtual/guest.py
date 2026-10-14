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
from common import bounded, inventory, LoggedProcess
from image_decode_report import (ASSET_PATH, ASSET_SHA256, MAX_REPORT,
                                 decode, inventory_sha256, parse_report, validate_guest_contract, validate_event)

PREFIX = 'CACHY_ASAHI_EVENT '
MAX_LOG = 1024 ** 2
IPC_ARGV = ['/usr/bin/hyprctl', '-j', 'configerrors']
IPC_TIMEOUT_REPLY = "Hyprland IPC didn't respond in time\n\nCouldn't read (6)\n"
IPC_ATTEMPTS = 24
DECODE_ROOT = Path('/usr/local/share/virtual-proof')


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


def identity_bytes(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= maximum and
                not metadata.st_mode & 0o022, 'protected bounded probe identity required')
        data = stream.read(maximum + 1)
        require(len(data) <= maximum, 'probe identity overflow')
        return data


def image_decode_identity(nonce, *, installed=Path('/'), actual_inventory=None):
    """Check the prepared installed files; the outer image binding stays external."""
    prefix = installed / DECODE_ROOT.relative_to('/')
    path = prefix / 'image-decode-contract.json'
    contract = validate_guest_contract(decode(identity_bytes(path, MAX_REPORT)))
    require(contract['nonce'] == nonce, 'probe nonce identity differs')
    files = {'helper_sha256': (installed / 'usr/local/bin/image-decode-probe', 16 * 1024**2),
             'parser_sha256': (prefix / 'image_decode_report.py', MAX_LOG),
             'guest_sha256': (prefix / 'guest.py', MAX_LOG),
             'runtime_sha256': (prefix / 'common.py', MAX_LOG)}
    for key, (source, maximum) in files.items():
        require(hashlib.sha256(identity_bytes(source, maximum)).hexdigest() == contract[key],
                'probe installed identity differs')
    require(stat.S_IMODE(files['helper_sha256'][0].stat().st_mode) == 0o755,
            'probe executable mode differs')
    require(hashlib.sha256(identity_bytes(installed / ASSET_PATH.lstrip('/'), 256 * 1024)).hexdigest() ==
            ASSET_SHA256 == contract['asset_sha256'], 'probe fixed asset identity differs')
    prepared_inventory = inventory(identity_bytes(prefix / 'runtime.lock', MAX_LOG).decode('ascii'))
    require(inventory_sha256(prepared_inventory) == contract['package_inventory_sha256'],
            'probe prepared inventory identity differs')
    if actual_inventory is not None:
        require(inventory_sha256(actual_inventory) == contract['package_inventory_sha256'],
                'probe installed inventory identity differs')
    return contract


def image_decode_preflight(env, root, nonce):
    """One observation before Wofi, with cleanup included in the acceptance deadline."""
    start = time.monotonic()
    deadline = start + 20
    row = {'event': 'image_decode_probe', 'nonce': nonce, 'stage': 'minimal',
           'elapsed_ms': None, 'returncode': None, 'error': None,
           'report_sha256': None, 'report_base64': None}
    require(type(nonce) is str and re.fullmatch('[0-9a-f]{32}', nonce), 'probe nonce required')
    # Refuse a second attempt before launching anything, including after a failure.
    with (root / 'image-decode-attempt').open('xb') as marker:
        marker.write(b'one fixed probe attempt\n')
    error = 'identity'
    try:
        require(os.geteuid() == os.getegid() == 23001, 'probe fixture UID/GID required')
        image_decode_identity(nonce)
        remaining = deadline - time.monotonic()
        error = 'deadline'
        require(remaining > 6, 'probe acceptance deadline')
        error = 'launch'
        try:
            result = bounded(['/usr/local/bin/image-decode-probe'], env=env,
                             timeout=min(14, remaining - 6), limit=MAX_REPORT)
        except subprocess.TimeoutExpired:
            error = 'cleanup'
            raise
        except OSError:
            raise
        except BaseException:
            error = 'cleanup'
            raise
        error = 'protocol'
        require(type(result) is dict and set(result) == {'returncode', 'error', 'stdout', 'stderr'} and
                type(result['returncode']) is int and -64 <= result['returncode'] <= 255 and
                type(result['stdout']) is type(result['stderr']) is str and
                (result['error'] is None or type(result['error']) is str and
                 result['error'] in ('timeout', 'output overflow')), 'invalid bounded probe result')
        row['returncode'] = result['returncode']
        error = 'output-overflow'
        require(len(result['stdout'].encode('utf-8')) + len(result['stderr'].encode('utf-8')) <= MAX_REPORT,
                'probe output overflow')
        transport_error = {'timeout': 'timeout', 'output overflow': 'output-overflow'}.get(result['error'])
        if transport_error is None:
            error = 'deadline'
            require(time.monotonic() < deadline, 'probe acceptance deadline')
        error = transport_error or 'cleanup'
        # Stderr stays in the owned private evidence directory, never an event.
        with (root / 'image-decode-stderr.log').open('x', encoding='utf-8') as stream:
            stream.write(result['stderr'])
        if transport_error is not None:
            raise ValueError('bounded probe failed')
        error = 'protocol'
        require(result['returncode'] == 0 and result['stdout'].isascii(), 'invalid probe transport')
        raw = result['stdout'].encode('ascii')
        observation = parse_report(raw)
        error = 'identity'
        require(observation['asset']['status'] == 'ok' and
                observation['asset']['sha256'] == ASSET_SHA256 and observation['asset']['size'] == 1042,
                'probe reported fixed asset differs')
        row.update(report_sha256=hashlib.sha256(raw).hexdigest(),
                   report_base64=base64.b64encode(raw).decode('ascii'))
        error = 'deadline'
        elapsed = time.monotonic() - start
        require(0 <= elapsed < 20, 'probe acceptance deadline')
        row['elapsed_ms'] = int(elapsed * 1000)
        validate_event(row, nonce)
        require(time.monotonic() < deadline, 'probe acceptance deadline')
    except BaseException as failure:
        row.update(error=error, elapsed_ms=None, report_sha256=None, report_base64=None)
        try:
            emit('image_decode_probe', **{key: value for key, value in row.items() if key != 'event'})
        except BaseException:
            # A closed diagnostic channel cannot replace the first probe refusal.
            pass
        if not isinstance(failure, Exception):
            raise  # Preserve cancellation/exit identity after bounded diagnostics.
        raise ValueError('image decode preflight failed: ' + error) from None
    emit('image_decode_probe', **{key: value for key, value in row.items() if key != 'event'})
    return observation


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


def process_observation(process, collector, errors, finished=None):
    row = {'state': 'unavailable', 'returncode': None, 'logging': 'unavailable'}
    if process is not None:
        try:
            code = process.poll()
            require(code is None or type(code) is int and -64 <= code <= 255, 'invalid process observation')
            row.update(state='alive' if code is None else 'exited', returncode=code)
        except BaseException as exc:
            errors.append(exc)
    if collector is not None:
        try:
            error = collector.error
            if error is None or type(error) is str:
                row['logging'] = ('output_overflow' if error == 'output overflow' else
                                  'ok' if error is None and finished is not False else 'drain_error')
        except BaseException as exc:
            errors.append(exc)
    return row


def phase(stage, config, env, root, *, nonce=None):
    log = root / (stage + '.log')
    compositor, client = None, None
    collectors = []
    compositor_collector = client_collector = None
    before_cleanup = None
    cleanup_errors = []
    client_retained = False
    instances = Path(env['XDG_RUNTIME_DIR']) / 'hypr'
    previous = set(instances.glob('*'))
    private_log = None
    def observations(errors, finished=None):
        return {role: process_observation(process, collector, errors,
                                         None if finished is None else finished.get(id(collector), False))
                for role, process, collector in (('client', client, client_collector),
                                                 ('compositor', compositor, compositor_collector))}
    def alive():
        nonlocal before_cleanup
        errors = []
        rows = observations(errors)
        if errors or any(row['state'] != 'alive' for row in rows.values()):
            before_cleanup = rows
            if errors:
                raise errors[0]
            return False
        return True
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
        compositor_collector = collector
        compositor = collector.process
        env = wait_for_ipc(stage, compositor, env, log, check_logs)
        monitors = json.loads(command(['/usr/bin/hyprctl', '-j', 'monitors'], env))
        require(any(m.get('width', 0) > 0 and m.get('height', 0) > 0 for m in monitors), 'no usable virtual output')
        wayland = list(Path(env['XDG_RUNTIME_DIR']).glob('wayland-*'))
        wayland = [p for p in wayland if p.is_socket()]
        require(len(wayland) == 1, 'expected one private Wayland socket')
        env['WAYLAND_DISPLAY'] = wayland[0].name
        if stage == 'minimal':
            image_decode_preflight(env, root, nonce)
        client_log = root / (stage + '-client.log')
        collector = LoggedProcess(['/usr/bin/wofi', '--normal-window', '--show', 'dmenu', '--prompt', 'Generic ARM software proof', '--width', '420', '--height', '220'],
                                  client_log, env=env, stdin=subprocess.PIPE)
        collectors.append(collector)
        client_collector = collector
        client = collector.process
        client.stdin.write(b'cachy-asahi software proof\nNo Apple hardware claim\n')
        client.stdin.close()
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            check_logs()
            require(alive(), 'client/compositor exited before frame')
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
            require(alive() and
                    log.stat().st_size <= MAX_LOG and client_log.stat().st_size <= MAX_LOG,
                    'session failed/overflowed during capture window')
            time.sleep(.25)
        terminate(client)
        client = None
        collectors[-1].finish()
        retained(client_log, stage)
        client_retained = True
        command(['/usr/bin/hyprctl', 'dispatch', 'exit'], env)
        compositor.wait(timeout=15)
        require(compositor.returncode == 0, 'unclean compositor shutdown')
        emit('phase_pass', stage=stage)
    finally:
        failure = sys.exc_info()[1]
        diagnostic = failure is not None and client is not None
        before_emitted = False
        if diagnostic:
            if before_cleanup is None:
                before_cleanup = observations(cleanup_errors)
            try:
                emit('process_state', stage=stage, boundary='before_cleanup', **before_cleanup)
                before_emitted = True
            except BaseException as exc:
                cleanup_errors.append(exc)
        for role, process in (('client', client), ('compositor', compositor)):
            if process is None:
                continue
            try:
                running = before_cleanup[role]['state'] != 'exited' if diagnostic else process.poll() is None
                if running:
                    terminate(process)
            except BaseException as exc:
                cleanup_errors.append(exc)
        finished = {}
        for collector in collectors:
            try:
                collector.finish()
                finished[id(collector)] = True
            except BaseException as exc:
                finished[id(collector)] = False
                cleanup_errors.append(exc)
        if diagnostic:
            after_cleanup = observations(cleanup_errors, finished)
            if before_emitted:
                try:
                    emit('process_state', stage=stage, boundary='after_cleanup', **after_cleanup)
                except BaseException as exc:
                    cleanup_errors.append(exc)
            if not client_retained:
                try:
                    require(after_cleanup['client']['state'] == 'exited' and finished.get(id(client_collector)),
                            'client log reaping/drain incomplete')
                    data = log_bytes(client_log)
                    require(len(data) <= MAX_LOG, 'client log overflow')
                    retained_data(data, client_log.name, stage)
                except BaseException as exc:
                    cleanup_errors.append(exc)
                    try:
                        retained_data(b'client log unavailable\n', stage + '-client.log', stage)
                    except BaseException as diagnostic_error:
                        cleanup_errors.append(diagnostic_error)
        if log.exists():
            try:
                retained(log, stage)
            except BaseException as exc:
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
        except BaseException as exc:
            cleanup_errors.append(exc)
            if not private_retained:
                try:
                    retained_data(('private compositor log retention failed: ' + type(exc).__name__ + '\n').encode(),
                                  stage + '-compositor.log', stage)
                except BaseException as diagnostic_error:
                    cleanup_errors.append(diagnostic_error)
        if cleanup_errors:
            try:
                print('guest secondary cleanup failures: ' + ','.join(type(exc).__name__ for exc in cleanup_errors), flush=True)
            except BaseException as diagnostic_error:
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
        phase(stage, Path(config), env, root, nonce=nonce)
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
    image_decode_identity(contract['nonce'], actual_inventory=inventory(actual))
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
