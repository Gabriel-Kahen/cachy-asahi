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
import socket
import stat
import subprocess
import sys
import time
from common import (bounded, inventory, LoggedProcess, BARRIER_PURPOSE, BARRIER_TEST,
                    BARRIER_FILES, BARRIER_SOURCE, BARRIER_FRAME_LINES, barrier_contract, barrier_event, json_load, TRANSACTION_PURPOSE, TRANSACTION_FILES, TRANSACTION_TESTS,
                    TRANSACTION_SELECTORS, TRANSACTION_FRAME_LINES, transaction_contract, transaction_launcher, transaction_event, transaction_method, transaction_call, TRANSACTION_CASES)
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


def mapped_client(row, pid):
    size = row.get('size')
    return (row.get('pid') == pid and row.get('mapped') is True and
            row.get('visible') is True and row.get('hidden') is False and
            type(size) is list and len(size) == 2 and
            all(type(value) is int and value > 0 for value in size))


def private_ipc(env, request, deadline, check, deadline_message):
    """Only the two fixed proof requests, within their caller's existing budget."""
    require(request in (b'j/clients', b'/dispatch hl.dsp.exit()'), 'unsupported private IPC request')
    runtime = Path(env['XDG_RUNTIME_DIR'])
    instance = env['HYPRLAND_INSTANCE_SIGNATURE']
    require(type(instance) is str and re.fullmatch(r'[A-Za-z0-9_.-]+', instance),
            'invalid private compositor instance')
    path = runtime / 'hypr' / instance / '.socket.sock'
    require(list(runtime.glob('hypr/*/.socket.sock')) == [path] and path.is_socket() and
            all(not p.is_symlink() for p in (path, *path.parents)), 'private compositor socket required')
    reply = bytearray()
    def remaining():
        check()
        value = deadline - time.monotonic()
        require(value > 0, deadline_message)
        return value
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(min(.25, remaining()))
        connection.connect(str(path))
        connection.settimeout(min(.25, remaining()))
        connection.sendall(request)
        while True:
            connection.settimeout(min(.25, remaining()))
            try:
                block = connection.recv(min(65536, MAX_LOG + 1 - len(reply)))
            except TimeoutError:
                continue
            require(len(reply) + len(block) <= MAX_LOG, 'private IPC reply overflow')
            if not block:
                break
            reply.extend(block)
        remaining()
    return bytes(reply)


def query_clients(env, deadline, check, *, deadline_message='Wayland client mapping deadline'):
    start = time.monotonic()
    reply = private_ipc(env, b'j/clients', deadline, check, deadline_message)
    clients = json.loads(reply.decode('utf-8'))
    require(type(clients) is list and all(type(row) is dict for row in clients), 'invalid clients IPC reply')
    check()
    require(time.monotonic() < deadline, deadline_message)
    emit('client_ipc', transport='private-unix-socket', request='j/clients',
         elapsed_ms=int((time.monotonic() - start) * 1000), stdout=reply.decode('utf-8'))
    return clients


def capture_window(stage, monitors, pid, env, check):
    # Spend the first 5s of the existing 15s live window before QMP capture.
    # Mapping alone does not mean a queued output update is already visible.
    start = time.monotonic()
    until, emitted = start + 15, False
    while time.monotonic() < until:
        check()
        now = time.monotonic()
        require(now < until, 'capture window expired before snapshot')
        if not emitted and now >= start + 5:
            clients = query_clients(env, until, check,
                                    deadline_message='capture window expired before snapshot')
            require(time.monotonic() < until, 'capture window expired before snapshot')
            require(any(mapped_client(row, pid) for row in clients),
                    'own client not mapped/visible at capture')
            emit('frame_ready', stage=stage, monitors=monitors, clients=clients)
            emitted = True
        time.sleep(min(.25, max(0, until - time.monotonic())))
    require(emitted, 'capture window expired before snapshot')


def shutdown_compositor(env, compositor, check):
    deadline = time.monotonic() + 15
    reply = private_ipc(env, b'/dispatch hl.dsp.exit()', deadline, check, 'compositor shutdown deadline')
    require(reply == b'ok', 'compositor exit acknowledgement differs')
    remaining = deadline - time.monotonic()
    require(remaining > 0, 'compositor shutdown deadline')
    compositor.wait(timeout=remaining)
    require(compositor.returncode == 0 and time.monotonic() < deadline, 'unclean compositor shutdown')


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
        # Isolate the failed AT-SPI startup dependency in this disposable client.
        # Protocol diagnostics share the existing bounded, reaped client log.
        collector = LoggedProcess(['/usr/bin/wofi', '--normal-window', '--show', 'dmenu', '--prompt', 'Generic ARM software proof', '--width', '420', '--height', '220'],
                                  client_log, env=dict(env, NO_AT_BRIDGE='1', WAYLAND_DEBUG='client'), stdin=subprocess.PIPE)
        collectors.append(collector)
        client_collector = collector
        client = collector.process
        client.stdin.write(b'cachy-asahi software proof\nNo Apple hardware claim\n')
        client.stdin.close()
        deadline = time.monotonic() + 45
        def check_client():
            check_logs()
            require(alive(), 'client/compositor exited before frame')
            require(log.stat().st_size <= MAX_LOG and client_log.stat().st_size <= MAX_LOG, 'session/client log overflow')
        while time.monotonic() < deadline:
            clients = query_clients(env, deadline, check_client)
            require(time.monotonic() < deadline, 'Wayland client mapping deadline')
            if any(mapped_client(row, client.pid) for row in clients):
                break
            time.sleep(.5)
        else:
            raise ValueError('Wayland client mapping deadline')
        def check_capture():
            check_logs()
            require(alive() and
                    log.stat().st_size <= MAX_LOG and client_log.stat().st_size <= MAX_LOG,
                    'session failed/overflowed during capture window')
        capture_window(stage, monitors, client.pid, env, check_capture)
        terminate(client)
        client = None
        collectors[-1].finish()
        retained(client_log, stage)
        client_retained = True
        def check_shutdown():
            check_logs()
            require(log.stat().st_size <= MAX_LOG, 'compositor log overflow during shutdown')
        shutdown_compositor(env, compositor, check_shutdown)
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
           'LP_NUM_THREADS': '0', 'GALLIVM_PERF': 'nopt', 'CACHY_ASAHI_VIRTUAL_GUEST': '1',
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


def barrier_failure(error, source_paths, frame_lines=BARRIER_FRAME_LINES):
    """Closed fixture diagnostics: no traceback, text, private path or hash output."""
    kind, value, trace = error
    known = (AssertionError, OSError, PermissionError, FileNotFoundError,
             subprocess.TimeoutExpired, ValueError, RuntimeError, KeyboardInterrupt, SystemExit)
    name = next((item.__name__ for item in known if kind is item), 'OTHER')
    number = value.errno if any(kind is item for item in (OSError, PermissionError, FileNotFoundError)) else None
    if type(number) is not int or not 1 <= number <= 4095:
        number = None
    frames = []
    while trace is not None:
        label = source_paths.get(trace.tb_frame.f_code.co_filename)
        if label in frame_lines and len(frames) < 8 and 1 <= trace.tb_lineno <= frame_lines[label]:
            frames.append({'source': label, 'line': trace.tb_lineno})
        trace = trace.tb_next
    tool = {'stage': 'UNRECOGNIZED_OR_ABSENT', 'errno': 'UNAVAILABLE'}
    # Exact existing P0 util-linux suffix vocabulary; never emit the input string.
    if kind is AssertionError and type(value.args) is tuple and value.args and type(value.args[0]) is str:
        lines = value.args[0].splitlines()
        message = lines[0] if len(lines) == 1 else ''
        child = re.match(r'(-?[0-9]{1,3}) != 0 :(?: |$)', message)
        if child and -64 <= int(child[1]) <= 255 and int(child[1]) != 0:
            stages = {'unshare failed': 'UNSHARE_CALL',
                      'cannot change root filesystem propagation': 'ROOT_PROPAGATION',
                      'mount /proc failed': 'PROC_MOUNT'}
            errors = {'Operation not permitted': 1, 'Permission denied': 13, 'Invalid argument': 22,
                      'Function not implemented': 38, 'Cannot allocate memory': 12,
                      'Resource temporarily unavailable': 11, 'No such file or directory': 2}
            # unittest's selected assertEqual strips the subprocess stderr newline.
            suffix = message[child.end():]
            for text, stage in stages.items():
                for text_error, code in errors.items():
                    if suffix == 'unshare: ' + text + ': ' + text_error:
                        tool = {'stage': stage, 'errno': code}
    return {'exception': name, 'errno': number, 'frames': frames, 'unshare_tool_error': tool}


def barrier_test(module, source_paths, nonce, selection):
    import unittest
    class Result(unittest.TestResult):
        first_failure = None
        def failed(self, error):
            if self.first_failure is None:
                self.first_failure = barrier_failure(error, source_paths)
        def addFailure(self, test, error):
            self.failed(error)
            self.failures.append((test, 'closed failure'))
        def addError(self, test, error):
            self.failed(error)
            if error[0] is KeyboardInterrupt or error[0] is SystemExit:
                raise error[1]
            self.errors.append((test, 'closed error'))
    result = Result()
    # Exactly one selected method; no discovery, TextTestRunner or signing class.
    case = module.BarrierTests(BARRIER_TEST)
    try:
        case.run(result)
    except BaseException:
        result.failed(sys.exc_info())
        raise
    finally:
        row = {'event': 'barrier_result', 'nonce': nonce, 'selection_sha256': selection,
               'fixture_source': BARRIER_SOURCE, 'uid': os.geteuid(), 'gid': os.getegid(),
               'tests': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
               'skips': len(result.skipped), 'status': 'FAIL', 'report': None,
               'first_failure': result.first_failure}
        if result.testsRun == 1 and result.wasSuccessful() and not result.skipped and result.first_failure is None:
            row.update(status='PASS_BARRIER_ONLY', report=getattr(module.BarrierTests, 'last_report', None))
        barrier_event(row, nonce, selection)
        emit('barrier_result', **{k: v for k, v in row.items() if k != 'event'})
    require(row['status'] == 'PASS_BARRIER_ONLY', 'selected barrier fixture failed')
    return row


def barrier_user():
    import types
    guest_guard()
    require(os.geteuid() == os.getegid() == 23001, 'ordinary fixture account required')
    root = DECODE_ROOT
    small = json_load(root / 'contract.json')
    raw = identity_bytes(root / 'virtual-contract.json', MAX_LOG)
    selection = hashlib.sha256(raw).hexdigest()
    require(selection == small['proof_contract_sha256'], 'barrier selection differs')
    c = json_load(root / 'virtual-contract.json')
    require(barrier_contract(c, root / 'barrier-source') and c['nonce'] == small['nonce'], 'barrier purpose differs')
    sources = root / 'barrier-source'
    test = sources / 'scripts/install/test_local_transaction.py'
    module = types.ModuleType('_selected_barrier_test')
    module.__file__ = str(test)
    exec(compile(test.read_bytes(), str(test), 'exec'), module.__dict__)
    module.REVIEWED_WORKER_SHA256 = BARRIER_FILES['scripts/install/local_transaction.py']['sha256']
    module.FIXTURE_SELECTION_SHA256 = selection  # Generic guest architecture routing only.
    labels = {str(sources / name): label for name, label in zip(BARRIER_FILES,
              ('SELECTED_WORKER', 'SELECTED_TEST', 'SELECTED_RUNTIME'))}
    labels[str(Path(__file__))] = 'GUEST'
    return barrier_test(module, labels, c['nonce'], selection)


def boot_barrier(contract):
    require(contract.get('purpose') == BARRIER_PURPOSE, 'barrier purpose required')
    env = {'PATH': '/usr/bin', 'HOME': '/home/virtual-proof', 'LANG': 'C.UTF-8',
           'CACHY_ASAHI_VIRTUAL_GUEST': '1', 'PYTHONDONTWRITEBYTECODE': '1'}
    for path in (Path('/home/virtual-proof'), Path('/run/virtual-proof')):
        path.mkdir(mode=0o700, exist_ok=True)
        os.chown(path, 23001, 23001)
    result = bounded(['/usr/bin/runuser', '-u', 'virtual-proof', '--', '/usr/bin/python', '-B',
                      __file__, 'barrier-user'], env=env, timeout=600, limit=16384)
    # Forward only one parsed/validated event; never raw command stderr/stdout.
    lines = result['stdout'].splitlines()
    require(len(lines) == 1 and lines[0].startswith(PREFIX), 'one closed barrier event required')
    event = json.loads(lines[0][len(PREFIX):])
    barrier_event(event, contract['nonce'], contract['proof_contract_sha256'])
    emit('barrier_result', **{k: v for k, v in event.items() if k != 'event'})
    require(result['error'] is None and result['returncode'] == 0 and result['stderr'] == '' and
            event['status'] == 'PASS_BARRIER_ONLY', 'barrier child did not naturally succeed')
    emit('barrier_child_exit', nonce=contract['nonce'], selection_sha256=contract['proof_contract_sha256'],
         returncode=0, error=None)


def transaction_execution(record, index, hop=0):
    """Project only fixed facts from the selected test's already retained worker result."""
    require(type(record) is dict and record.get('test') == TRANSACTION_TESTS[index] and
            record.get('worker_sha256') == record.get('worker_after_sha256') ==
            TRANSACTION_FILES['scripts/install/local_transaction.py']['sha256'], 'selected worker record differs')
    body = record.get('report')
    require(type(body) is dict, 'worker report absent')
    pattern=TRANSACTION_CASES[index][2][hop]
    row = dict(returncode=record.get('returncode'), worker_status=body.get('status'),
               phase=body.get('phase','NOT_REPORTED'),commit_started=body.get('commit_started'),committed=body.get('committed'))
    transaction_call(row,pattern)
    if pattern in ('PAIR','ADD','REMOVE','UPGRADE','PROTECTED_ADD'):
        a,b='caa-install-fixture-a','caa-install-fixture-b'
        before,after = ({},{a:'1.0-1',b:'1.0-1'}) if pattern=='PAIR' else ({},{a:'1.0-1'}) if pattern=='ADD' else (
            {a:'1.0-1'}, {}) if pattern=='REMOVE' else ({a:'1.0-1'},{a:'2.0-1'}) if pattern=='UPGRADE' else (
            {a:'1.0-1'},{a:'1.0-1',b:'1.0-1'})
        require(body.get('installed_payload_verified') is True and body.get('parent_export_verified') is True and
                body.get('before')==before and body.get('after')==after, 'positive transaction export differs')
    elif pattern in ('INVALID','SIGNER','ESCAPE'):
        path=Path(record['retained_evidence'])/'evidence/authentication-command.json'
        auth=json.loads(identity_bytes(path,MAX_LOG));argv=auth.get('argv');code=auth.get('returncode')
        require(type(argv) is list and len(argv)<=32 and argv[:2]==['/usr/bin/gpg','--batch'] and
                argv[-3:-2]==['--verify'] and type(code) is int and
                (1<=code<=255 if pattern=='INVALID' else code==0), 'original signature verification boundary differs')
        if pattern!='INVALID':
            require(body.get('error')==('signature signer/status refused' if pattern=='SIGNER' else 'noncanonical payload path'),
                    'fixed signer/archive refusal differs')

    return row


def transaction_test(module, source_paths, nonce, selection, source):
    import unittest
    class Result(unittest.TestResult):
        def __init__(self):
            super().__init__(); self.first_failure = None; self.methods = []; self.cancellation = None; self.cursor = 0; self.active = None; self.collected = False
        def history(self):
            value=getattr(cls,'execution_history',[])
            require(type(value) is list and len(value)<=22, 'finite exact worker history required')
            return value
        def startTest(self,test):
            require(test._testMethodName==TRANSACTION_TESTS[len(self.methods)] and
                    len(self.history())==sum(len(row['calls']) for row in self.methods), 'method/history cursor differs')
            self.cursor=len(self.history());self.active=test;self.collected=False;super().startTest(test)
        def collect(self,test,complete):
            if test is not self.active or self.collected:return
            index=len(self.methods);entries=self.history()[self.cursor:]
            require(index<17 and test._testMethodName==TRANSACTION_TESTS[index] and
                    len(entries)<=len(TRANSACTION_CASES[index][2]), 'selected method/history scope differs')
            calls=[]
            for hop,record in enumerate(entries):
                try:calls.append(transaction_execution(record,index,hop))
                except BaseException as error:
                    if type(error) in (KeyboardInterrupt,SystemExit) and self.cancellation is None:self.cancellation=error
                    if complete:raise
                    break
            if calls:
                row=dict(method=TRANSACTION_SELECTORS[index],calls=calls)
                transaction_method(row,index,complete=complete);self.methods.append(row);self.collected=True
            elif complete:require(False,'selected method has no worker history')
        def failed(self, error):
            if self.first_failure is None: self.first_failure = barrier_failure(error, source_paths, TRANSACTION_FRAME_LINES)
            if (error[0] is KeyboardInterrupt or error[0] is SystemExit) and self.cancellation is None: self.cancellation = error[1]
            self.stop()
        def addFailure(self, test, error):
            self.failed(error); self.failures.append((test,'closed failure'))
            try:self.collect(test,False)
            except BaseException as error:
                if type(error) in (KeyboardInterrupt,SystemExit) and self.cancellation is None:self.cancellation=error
        def addError(self, test, error):
            self.failed(error); self.errors.append((test,'closed error'))
            try:self.collect(test,False)
            except BaseException as error:
                if type(error) in (KeyboardInterrupt,SystemExit) and self.cancellation is None:self.cancellation=error
        def addSkip(self, test, reason):
            self.skipped.append((test,'closed skip')); self.stop()
        def addSuccess(self, test):
            try:self.collect(test,True)
            except BaseException:self.addError(test,sys.exc_info())
    result = Result(); cls = module.ActualTransactionTests
    cases = [cls(name) for name in TRANSACTION_TESTS]
    suite = unittest.TestSuite(cases)
    try:
        require(not result.history(), 'stale worker history refused')
        suite.run(result)  # Real class setup/registered class cleanups, no direct method invocation.
    except BaseException:
        result.addError(None, sys.exc_info())
    finally:
        # KeyboardInterrupt can bypass unittest's remaining instance/class cleanup stacks.
        # Retain the seventeen cases; finish each pending pinned duty once, independently.
        stacks = [(case, getattr(case, '_cleanups', [])) for case in cases]
        stacks.append((None, getattr(cls, '_class_cleanups', [])))
        for case, pending in stacks:
            if len(pending) > 4:
                try: require(False, 'unexpected fixture cleanup count')
                except ValueError: result.addError(case, sys.exc_info())
                continue
            while pending:
                function, args, kwargs = pending.pop()
                try: function(*args, **kwargs)
                except BaseException: result.addError(case, sys.exc_info())
        row = {'event':'transaction_result','nonce':nonce,'selection_sha256':selection,'fixture_source':source,
               'uid':os.geteuid(),'gid':os.getegid(),'tests':result.testsRun,'failures':len(result.failures),
               'errors':len(result.errors),'skips':len(result.skipped),'status':'FAIL','methods':result.methods,
               'first_failure':result.first_failure,'class_cleanups_returned':not any(stack for case,stack in stacks) and not result.errors,
               'cancelled':result.cancellation is not None}
        if result.testsRun == 17 and result.wasSuccessful() and not result.skipped and result.first_failure is None and len(result.history()) == 22:
            row['status'] = 'PASS_TRANSACTION_ONLY'
        transaction_event(row, nonce, selection, source)
        emit('transaction_result', **{k:v for k,v in row.items() if k!='event'})
    if result.cancellation is not None: raise result.cancellation
    require(row['status'] == 'PASS_TRANSACTION_ONLY', 'selected transaction fixture failed')
    return row


def transaction_user():
    import types
    guest_guard()
    root = DECODE_ROOT; sources = root / 'transaction-source'
    labels = {str(sources/name):label for name,label in zip(TRANSACTION_FILES,
              ('SELECTED_WORKER','SELECTED_TEST','SELECTED_RUNTIME'))}; labels[str(Path(__file__))] = 'GUEST'
    small = json_load(root / 'contract.json'); raw = identity_bytes(root / 'virtual-contract.json', MAX_LOG)
    selection = hashlib.sha256(raw).hexdigest(); c = json.loads(raw)
    require(selection == small['proof_contract_sha256'] and c['nonce'] == small['nonce'] and
            transaction_contract(c, sources), 'transaction selection differs')
    entered = False
    try:
        worker = sources / 'scripts/install/local_transaction.py'; code = identity_bytes(worker, 128*1024)
        require(hashlib.sha256(code).hexdigest() == TRANSACTION_FILES['scripts/install/local_transaction.py']['sha256'], 'worker capture differs')
        module = types.ModuleType('_selected_generic_worker'); module.__file__ = str(worker)
        exec(compile(code, str(worker), 'exec'), module.__dict__)
        # Genuine status/NNP/capabilities and all Root-protected Source/profile/tool bytes before any signing.
        module.generic_preflight(root/'virtual-contract.json', selection, TRANSACTION_FILES['scripts/install/local_transaction.py']['sha256'])
        test = sources / 'scripts/install/test_local_transaction.py'; code = identity_bytes(test,128*1024)
        require(hashlib.sha256(code).hexdigest() == TRANSACTION_FILES['scripts/install/test_local_transaction.py']['sha256'], 'test capture differs')
        tests = types.ModuleType('_selected_transaction_tests'); tests.__file__ = str(test)
        exec(compile(code, str(test), 'exec'), tests.__dict__)
        tests.REVIEWED_WORKER_SHA256 = TRANSACTION_FILES['scripts/install/local_transaction.py']['sha256']
        tests.GENERIC_VM_CONTRACT = root/'virtual-contract.json'; tests.GENERIC_VM_CONTRACT_SHA256 = selection
        require(tests.FIXTURE_SELECTION_SHA256 is None, 'native selection must remain absent')
        evidence = Path('/run/virtual-proof/transaction-evidence'); info = evidence.stat()
        require(not evidence.is_symlink() and stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 23001 and
                stat.S_IMODE(info.st_mode) == 0o700 and not any(evidence.iterdir()), 'fresh private fixture evidence required')
        tests.ARTIFACTS = evidence
        entered = True
        return transaction_test(tests, labels, c['nonce'], selection, c['source_commit'])
    except BaseException:
        if not entered:
            failure = barrier_failure(sys.exc_info(), labels, TRANSACTION_FRAME_LINES)
            row = dict(event='transaction_result',nonce=c['nonce'],selection_sha256=selection,fixture_source=c['source_commit'],
                       uid=os.geteuid(),gid=os.getegid(),tests=0,failures=0,errors=1,skips=0,status='FAIL',methods=[],
                       first_failure=failure,class_cleanups_returned=True,cancelled=sys.exc_info()[0] is KeyboardInterrupt or sys.exc_info()[0] is SystemExit)
            transaction_event(row,c['nonce'],selection,c['source_commit'])
            emit('transaction_result', **{k:v for k,v in row.items() if k!='event'})
        raise


def boot_transaction(contract):
    require(contract.get('purpose') == TRANSACTION_PURPOSE, 'transaction purpose required')
    transaction_launcher(Path('/'))  # Fixed signed-archive-derived launcher bytes, not learned boot hashes.
    env = {'PATH':'/usr/bin','HOME':'/home/virtual-proof','LANG':'C.UTF-8',
           'CACHY_ASAHI_VIRTUAL_GUEST':'1','PYTHONDONTWRITEBYTECODE':'1'}
    for path in (Path('/home/virtual-proof'),Path('/run/virtual-proof')):
        path.mkdir(mode=0o700,exist_ok=True); os.chown(path,23001,23001); path.chmod(0o700)
    evidence=Path('/run/virtual-proof/transaction-evidence'); evidence.mkdir(mode=0o700)
    os.chown(evidence,23001,23001)
    argv=['/usr/lib/ld-linux-aarch64.so.1','--inhibit-cache','--glibc-hwcaps-mask','','--library-path','/usr/lib',
          '/usr/bin/setpriv','--reuid=23001','--regid=23001','--clear-groups',
          '--inh-caps=-all','--ambient-caps=-all','--bounding-set=-all','--no-new-privs','--',
          '/usr/bin/python3','-B',__file__,'transaction-user']
    result=bounded(argv,env=env,timeout=900,limit=16384)
    lines=result['stdout'].splitlines()
    require(len(lines)==1 and lines[0].startswith(PREFIX), 'one closed transaction event required')
    event=json.loads(lines[0][len(PREFIX):]); source=contract['fixture_source']
    transaction_event(event,contract['nonce'],contract['proof_contract_sha256'],source)
    emit('transaction_result', **{k:v for k,v in event.items() if k!='event'})
    require(result['error'] is None and result['returncode']==0 and result['stderr']=='' and
            event['status']=='PASS_TRANSACTION_ONLY', 'transaction child did not naturally succeed')
    emit('transaction_child_exit',nonce=contract['nonce'],selection_sha256=contract['proof_contract_sha256'],returncode=0,error=None)


def boot():
    guest_guard(root=True)
    contract = json.loads(Path('/usr/local/share/virtual-proof/contract.json').read_text())
    emit('boot', nonce=contract['nonce'], arch=platform.machine(), page_size=os.sysconf('SC_PAGE_SIZE'),
         kernel=platform.release(), execution='qemu-tcg-generic-aarch64', hardware_validation='NOT RUN')
    require(platform.release() == '7.2.10-1-aarch64-ARCH' and os.sysconf('SC_PAGE_SIZE') == 4096, 'wrong guest kernel/page size')
    if contract.get('purpose', 'desktop') not in (BARRIER_PURPOSE, TRANSACTION_PURPOSE):
        command(['/usr/bin/modprobe', 'virtio_gpu'])
    command(['/usr/bin/udevadm', 'settle', '--timeout=30'])
    command(['/usr/bin/dmesg'])
    actual = command(['/usr/bin/pacman', '-Q'])
    expected = Path('/usr/local/share/virtual-proof/runtime.lock').read_text()
    require(actual.strip() == expected.strip(), 'guest installed inventory differs from prepared full image')
    if contract.get('purpose', 'desktop') not in (BARRIER_PURPOSE, TRANSACTION_PURPOSE):
        image_decode_identity(contract['nonce'], actual_inventory=inventory(actual))
    for row in contract['baseline']:
        for name, value in row['payload_sha256'].items():
            require(hashlib.sha256((Path('/') / name).read_bytes()).hexdigest() == value, 'guest original overlay payload differs')
    if contract.get('purpose') == TRANSACTION_PURPOSE:
        boot_transaction(contract)
        return
    if contract.get('purpose') == BARRIER_PURPOSE:
        boot_barrier(contract)
        return
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
        require(len(sys.argv) == 2 and sys.argv[1] in ('boot', 'user', 'barrier-user', 'transaction-user'), 'explicit guest stage required')
        {'boot': boot, 'user': run_user, 'barrier-user': barrier_user, 'transaction-user': transaction_user}[sys.argv[1]]()
    except Exception as exc:
        if sys.argv[1:] not in (['barrier-user'], ['transaction-user']):
            try:
                purpose = json_load(DECODE_ROOT / 'contract.json').get('purpose')
                barrier = purpose == BARRIER_PURPOSE
            except Exception:
                barrier = True
                purpose = BARRIER_PURPOSE
            emit('guest_failed', error='BARRIER_ENTRY_FAILED' if barrier else 'TRANSACTION_ENTRY_FAILED' if purpose == TRANSACTION_PURPOSE else str(exc), hardware_validation='NOT RUN')
        sys.exit(1)
