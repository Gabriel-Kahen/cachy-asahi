#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run one hash-selected staged desktop Exec in an explicit private context.

This is a trusted-application workflow, not a sandbox. No shell or desktop/D-Bus
activation is used. Output readiness does not establish mapped-window readiness.
"""
import argparse
import configparser
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import re
import signal
import socket
import stat
import subprocess
import struct
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import desktop_applications as desktop
import desktop_application_inputs as inputs


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


owned = module('_desktop_owned', HERE.parent / 'virtual/owned_process.py')
CAP = 128 * 1024


class NotRun(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def read_file(path, cap, *, nofollow=False):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | (os.O_NOFOLLOW if nofollow else 0))
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_size <= cap, 'bounded regular file required: ' + str(path))
        chunks, size = [], 0
        while True:
            block = os.read(fd, min(65536, cap + 1 - size))
            if not block:
                return b''.join(chunks)
            size += len(block)
            require(size <= cap, 'file read cap exceeded: ' + str(path))
            chunks.append(block)
    finally:
        os.close(fd)


def data(path):
    raw = read_file(path, desktop.TEXT_CAP, nofollow=True)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def private(path):
    path = Path(path)
    require(path.is_absolute(), 'absolute private directory required')
    require(all(not part.is_symlink() for part in (path, *path.parents)), 'private path symlink refused')
    info = path.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and
            stat.S_IMODE(info.st_mode) == 0o700, 'owned mode-0700 private directory required')
    return path


def context(value):
    require(type(value) is dict and set(value) <= {'mode', 'work', 'display', 'wayland_display'}, 'unknown context field')
    mode = value.get('mode')
    require(mode in ('fixture', 'guest', 'native-container'), 'explicit supported context mode required')
    work = private(value['work'])
    if mode == 'guest':
        require(platform.machine() == 'aarch64' and os.geteuid() != 0 and
                os.environ.get('CACHY_ASAHI_VIRTUAL_GUEST') == '1' and
                'cachy_asahi_virtual_proof=1' in Path('/proc/cmdline').read_text().split(),
                'explicit ordinary-user generic ARM guest required')
    elif mode == 'native-container':
        guard = module('_desktop_container', HERE.parent / 'integration/desktop.py')
        guard.isolation_guard()
    require(value.get('display') in ('none', 'wayland'), 'explicit display policy required')
    if value['display'] == 'wayland' and mode == 'fixture':
        raise NotRun('GUI fixture execution unsupported; provision a guarded guest/container')
    for endpoint in ('no-session-bus', 'no-system-bus', 'no-pulse'):
        require(not os.path.lexists(work / endpoint), 'disabled endpoint already exists: ' + endpoint)
    env = {'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1',
           'DBUS_SESSION_BUS_ADDRESS': 'unix:path=' + str(work / 'no-session-bus'),
           'DBUS_SYSTEM_BUS_ADDRESS': 'unix:path=' + str(work / 'no-system-bus'),
           'PULSE_SERVER': 'unix:' + str(work / 'no-pulse'), 'PIPEWIRE_REMOTE': 'no-pipewire'}
    for key, child in (('HOME', 'home'), ('XDG_CONFIG_HOME', 'config'), ('XDG_DATA_HOME', 'data'),
                       ('XDG_CACHE_HOME', 'cache'), ('XDG_RUNTIME_DIR', 'runtime'), ('TMPDIR', 'tmp')):
        path = work / child
        path.mkdir(mode=0o700, exist_ok=True)
        env[key] = str(private(path))
    require(not os.path.lexists(Path(env['XDG_RUNTIME_DIR']) / 'no-pipewire'), 'disabled PipeWire endpoint exists')
    if value['display'] == 'none':
        require(not any(Path(env['XDG_RUNTIME_DIR']).iterdir()), 'headless runtime directory must be empty')
    if value['display'] == 'wayland':
        name = value.get('wayland_display')
        require(type(name) is str and re.fullmatch(r'[A-Za-z0-9_.-]+', name) and name not in ('.', '..'),
                'private Wayland socket basename required')
        path = Path(env['XDG_RUNTIME_DIR']) / name
        try:
            info = path.lstat()
        except FileNotFoundError:
            raise NotRun('private Wayland display missing') from None
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.geteuid(), 'owned private Wayland socket required')
        env['WAYLAND_DISPLAY'] = name
    return mode, work, env


def runtime_file(record, prefix):
    """Compare the actual execution namespace to the staged audit record."""
    path = Path(prefix) / record['path'].lstrip('/')
    raw = read_file(path, desktop.FILE_CAP)
    require(len(raw) <= desktop.FILE_CAP and desktop.pin(raw) == {key: record[key] for key in ('bytes', 'sha256')},
            'runtime bytes differ from staged audit: ' + str(path))
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_mode & 0o111 and os.access(path, os.X_OK),
            'runtime executable inaccessible: ' + str(path))
    require(not info.st_mode & (stat.S_ISUID | stat.S_ISGID), 'privileged executable refused')
    return str(path)


def check_launcher(resolution):
    require(desktop.command_ok(resolution), 'audited executable unavailable')
    require(all(Path(resolution['file'][key]).name not in ('env', 'sh', 'bash', 'zsh', 'fish')
                for key in ('path', 'resolved')), 'direct env/shell launcher unsupported')


def command_files(resolution, prefix, fixture):
    require(desktop.command_ok(resolution), 'audited executable unavailable')
    result = [runtime_file(resolution['file'], prefix)]
    # Kernel shebang/PT_INTERP absolute paths are in the running namespace even
    # when a fixture application's primary executable lives below a staged root.
    if 'interpreter' in resolution:
        result += command_files(resolution['interpreter'], '/' if fixture else prefix, fixture)
    if 'env_target' in resolution:
        result += command_files(resolution['env_target'], prefix, fixture)
    return result


class Observer:
    """Observation only: never waits for or signals an application process."""
    def __init__(self, receiver, marker, deadline):
        self.receiver, self.marker, self.deadline = receiver, marker, deadline
        self.ready_at = None
        self.problem = None
        self.done = threading.Event()
        self.thread = threading.Thread(target=self.read, name='desktop-output-observer', daemon=True)

    def read(self):
        tail, count = b'', 0
        try:
            self.receiver.settimeout(.02)
            while not self.done.is_set():
                try:
                    block = self.receiver.recv(65536)
                except socket.timeout:
                    continue
                if not block:
                    return
                count += len(block)
                require(count <= CAP, 'observer output cap')
                tail += block
                now = time.monotonic()
                if self.ready_at is None and self.marker in tail and now <= self.deadline:
                    self.ready_at = now
                tail = tail[-max(0, len(self.marker) - 1):] if len(self.marker) > 1 else b''
        except Exception as exc:
            self.problem = type(exc).__name__ + ': ' + str(exc)

    def finish(self):
        self.thread.join(.5)  # Sender closes first; EOF drains the final marker.
        self.done.set()
        self.thread.join(.1)
        if self.thread.is_alive():
            self.problem = 'observer retirement deadline'


def launch(argv, cwd, env, run_seconds, ready_seconds, marker):
    owned.prepare()
    require(signal.getsignal(signal.SIGPIPE) == signal.SIG_IGN, 'SIGPIPE must be ignored before launch')
    receiver, sender = socket.socketpair()
    sender.setblocking(False)
    observer = Observer(receiver, marker.encode(), time.monotonic() + ready_seconds)
    observer.thread.start()
    child = None
    result = None
    cancelled = []
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    def cancel(sig, frame):
        # No second signaling/wait owner. The already frozen run deadline
        # bounds cancellation latency; supervise alone retires the group.
        cancelled.append(signal.Signals(sig).name)
    for sig in previous:
        signal.signal(sig, cancel)
    try:
        child = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 start_new_session=True, close_fds=True)
        result = owned.supervise(child, cap=run_seconds + 1, retirement=1, grace=.15,
                                 max_output=CAP, log_fd=sender.fileno())
    except OSError as exc:
        if child is not None:
            raise
        return {'status': 'START_FAILED', 'error': str(exc), 'exit': None,
                'retirement': 'NOT_LAUNCHED', 'signals_received': cancelled}
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        sender.close()
        observer.finish()
        receiver.close()
    result['output'] = result['output'].decode('utf-8', errors='replace')
    result['readiness'] = {'kind': 'output-marker', 'observed': observer.ready_at is not None,
                           'deadline_seconds': ready_seconds, 'observer_error': observer.problem}
    result['signals_received'] = cancelled
    result['retirement'] = 'OBSERVED_EMPTY_GROUP' if result['reaped'] and result['group_census'] == 'EMPTY_TWICE' else 'UNKNOWN'
    result['status'] = ('CANCELLED' if cancelled or (result['error'] or '').startswith('KeyboardInterrupt:') else
                        'OUTPUT_LIMIT' if 'output cap' in (result['error'] or '') else
                        'RETIREMENT_UNKNOWN' if not result['reaped'] or result['group_census'] != 'EMPTY_TWICE' else
                        'RUN_TIMEOUT' if result['timeout'] else
                        'SUPERVISOR_FAILED' if result['error'] else
                        'START_FAILED' if result['exit'] != 0 else
                        'READINESS_NOT_OBSERVED' if observer.ready_at is None or observer.problem else
                        'PASS_EXEC_WORKFLOW' if result['passed'] else 'SUPERVISOR_FAILED')
    return result


def run(args, launcher=None):
    require(re.fullmatch('[0-9a-f]{64}', args.entry_sha256) is not None, 'entry SHA256 required')
    for value in (args.run_seconds, args.ready_seconds):
        require(math.isfinite(value) and .05 <= value <= 30, 'deadlines must be finite in [0.05, 30] seconds')
    require(args.ready_seconds <= args.run_seconds, 'readiness deadline exceeds run deadline')
    require(type(args.ready_marker) is str and 1 <= len(args.ready_marker.encode()) <= 1024 and '\0' not in args.ready_marker,
            'bounded nonempty readiness output marker required')
    mode, work, env = context(data(args.context))
    audit = desktop.Audit(args.root, data(args.environment))
    try:
        app = audit.entry(args.select)
        require('error' not in app and not app.get('hidden') and app.get('desktop_eligible'),
                'selected desktop entry unavailable: ' + str(app.get('error', app.get('visibility'))))
        require(app['file']['sha256'] == args.entry_sha256, 'selected desktop hash differs')
        require('exec' in app, 'explicit Exec fallback missing')
        require(not app['dbus_activatable'] or args.exec_fallback, 'DBusActivatable requires explicit --exec-fallback')
        require('try_exec' not in app or desktop.command_ok(app['try_exec']), 'TryExec unavailable')
        prefix = audit.stage.root if mode == 'fixture' else '/'
        entry_path = str(Path(prefix) / app['path'].lstrip('/'))
        require(hashlib.sha256(read_file(entry_path, desktop.TEXT_CAP)).hexdigest() == args.entry_sha256, 'runtime desktop entry differs')
        raw, _ = audit.stage.read(app['path'])
        entry = desktop.ini(raw)['Desktop Entry']
        selected_inputs = inputs.prepare(getattr(args, 'inputs', None) or (), getattr(args, 'allow_uri_scheme', ()))
        argv = inputs.expand(entry['Exec'], app['name'], desktop.unescape(entry.get('Icon', '')), entry_path, selected_inputs)
        check_launcher(app['exec']['resolution'])
        files = command_files(app['exec']['resolution'], prefix, mode == 'fixture')
        argv[0] = files[0]
        if 'try_exec' in app:
            files += command_files(app['try_exec'], prefix, mode == 'fixture')
        if app['terminal']:
            terminal = audit.env['terminal_argv']
            if not terminal:
                raise NotRun('Terminal=true but no explicit terminal argv configured')
            require(terminal[-1] in ('--', '-e'), 'terminal argv must end with reviewed -- or -e separator')
            terminal = list(terminal)
            check_launcher(app['terminal_command'])
            term_files = command_files(app['terminal_command'], prefix, mode == 'fixture')
            terminal[0] = term_files[0]
            files += term_files
            argv = terminal + argv
        env['PATH'] = ':'.join(str(Path(prefix) / item.lstrip('/')) for item in audit.env['PATH'].split(':'))
        env['XDG_DATA_DIRS'] = ':'.join(str(Path(prefix) / item.lstrip('/')) for item in audit.env['XDG_DATA_DIRS'].split(':'))
        env['XDG_CONFIG_DIRS'] = ':'.join(str(Path(prefix) / item.lstrip('/')) for item in audit.env['XDG_CONFIG_DIRS'].split(':'))
        env['XDG_CURRENT_DESKTOP'] = audit.env['XDG_CURRENT_DESKTOP']
        cwd = work
        if 'working_directory' in app:
            cwd = Path(prefix) / app['working_directory']['resolved'].lstrip('/')
            require(cwd.is_dir(), 'runtime working directory missing')
        require(all(row['state'] in ('UNCHANGED', 'URI_PASSED_WITHOUT_FETCH') for row in inputs.verify(selected_inputs)),
                'local input changed before launch')
        result = (launch if launcher is None else launcher)(argv, cwd, env, args.run_seconds, args.ready_seconds, args.ready_marker)
        input_receipts = inputs.verify(selected_inputs)
        if any(row['state'] in ('CHANGED', 'UNVERIFIED') for row in input_receipts):
            result['application_status'] = result['status']
            if result['status'] == 'PASS_EXEC_WORKFLOW':
                result['status'] = 'INPUT_CHANGED'
        result.update(schema=1, context=mode, desktop_id=args.select, desktop_sha256=args.entry_sha256,
                      argv=argv, cwd=str(cwd), executable_files=sorted(set(files)), inputs=input_receipts,
                      audit_pins=audit.stage.pins, evidence='HOST_FIXTURE_ONLY' if mode == 'fixture' else 'ISOLATED_APPLICATION_EXEC_ONLY',
                      gui=result.get('gui', 'NOT_RUN (output marker does not prove window mapping)'), native_arm='NOT_RUN' if mode == 'fixture' else platform.machine(),
                      m2='NOT_RUN', performance='NOT_MEASURED', release='NOT_ADMITTED')
        return result
    finally:
        audit.stage.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'environment', 'context'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--select', required=True)
    parser.add_argument('--entry-sha256', required=True)
    parser.add_argument('--exec-fallback', action='store_true')
    parser.add_argument('--file', dest='inputs', action=inputs.InputAction, help='local regular file; repeat in input order')
    parser.add_argument('--uri', dest='inputs', action=inputs.InputAction, help='URI; repeat in input order, explicit scheme policy required')
    parser.add_argument('--allow-uri-scheme', action='append', choices=sorted(inputs.SCHEMES), default=[])
    parser.add_argument('--ready-marker', required=True)
    parser.add_argument('--ready-seconds', type=float, default=2)
    parser.add_argument('--run-seconds', type=float, default=5)
    args = parser.parse_args(argv)
    try:
        report = run(args)
    except NotRun as exc:
        report = {'schema': 1, 'status': 'NOT_RUN', 'error': str(exc), 'gui': 'NOT_RUN'}
    except (ValueError, OSError, KeyError, TypeError, configparser.Error, UnicodeError, struct.error) as exc:
        report = {'schema': 1, 'status': 'REFUSED', 'error': str(exc)}
    print(json.dumps(report, sort_keys=True, indent=2, allow_nan=False))
    return 0 if report['status'] == 'PASS_EXEC_WORKFLOW' else 2 if report['status'] in ('REFUSED', 'NOT_RUN') else 1


if __name__ == '__main__':
    sys.exit(main())
