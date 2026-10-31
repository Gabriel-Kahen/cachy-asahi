#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Opt-in single-window lifecycle in a proven private managed ARM guest.

Retain exclusive unreaped launch custody through all window control. Transfer
once to owned_process for final signals/reap; no IPC control follows transfer.
"""
import argparse
import json
import math
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
from types import SimpleNamespace

import desktop_application_runtime as runtime
import desktop_application_inputs as inputs

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/virtual'))
guest = runtime.module('_application_window_guest', ROOT / 'scripts/virtual/guest.py')
base574 = runtime.module('_application_window_base', ROOT / 'scripts/ci/desktop574_guest.py')
managed = runtime.module('_application_window_managed', ROOT / 'scripts/ci/welcome-managed-gui/managed_session.py')
owned = runtime.owned
require = runtime.require
MAX_REPLY = 64 * 1024


class LostOwnership(ValueError):
    pass


class Cancelled(ValueError):
    pass


def lua_string(value):
    require(type(value) is str and len(value.encode('utf-8')) <= 4096 and '\0' not in value, 'bounded Lua data string required')
    return '"' + ''.join('\\x' + format(byte, '02x') for byte in value.encode('utf-8')) + '"'


def window_identity(row, pid):
    require(type(row) is dict and type(row.get('pid')) is int and guest.mapped_client(row, pid) and row.get('xwayland') is False,
            'visible direct Wayland window required')
    address = row.get('address')
    require(type(address) is str and re.fullmatch(r'0x[0-9a-f]{1,16}', address) and int(address, 16), 'window address required')
    result = dict(pid=pid, address=address)
    for key in ('class', 'title', 'initialClass', 'initialTitle'):
        value = row.get(key)
        lua_string(value)
        result[key] = value
    return result


def scripts(identity, key):
    require(re.fullmatch(r'CAA_WINDOW_[0-9a-f]{32}', key) is not None, 'private window nonce required')
    names = {'initialClass': 'initial_class', 'initialTitle': 'initial_title'}
    checks = ['w ~= nil', 'w.pid == ' + str(identity['pid']), 'w.xwayland == false',
              'w.mapped == true', 'w.visible == true', 'w.hidden == false']
    checks += ['w.' + names.get(name, name) + ' == ' + lua_string(value)
               for name, value in identity.items() if name != 'pid']
    guard = 'assert(' + ' and '.join(checks) + ',"owned window identity changed");'
    slot = '_G[' + lua_string(key) + ']'
    bind = ('assert(' + slot + ' == nil,"window nonce already bound");local w=hl.get_window(' +
            lua_string('address:' + identity['address']) + ');' + guard + slot + '=w')
    close = ('local w=' + slot + ';' + guard +
             'local r=hl.dispatch(hl.dsp.window.close({window=w}));assert(type(r)=="table" and r.ok==true,"close refused");' + slot + '=nil')
    return bind.encode(), close.encode(), (slot + '=nil').encode()


def read_only_command(argv, env, logs, label, timeout=5):
    require(argv[:5] == ['/usr/bin/busctl', '--address=' + managed.ADDRESS, '--auto-start=no', '--timeout=3s', 'call'],
            'fixed managed bus query required')
    owned.prepare()
    child = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, close_fds=True, start_new_session=True)
    result = owned.supervise(child, cap=timeout + .5, retirement=.5, grace=.1, max_output=8192)
    require(result['passed'], 'managed identity query failed')
    return result['output'].decode('utf-8')


class PrivateIPC:
    """Pinned socket/peer identity, fixed clients query and generated Lua only."""
    evidence = 'PRIVATE_MANAGED_GUEST'

    def __init__(self, contract, env):
        self.contract, self.env = contract, env
        self.path = Path(env['XDG_RUNTIME_DIR']) / 'hypr' / env['HYPRLAND_INSTANCE_SIGNATURE'] / '.socket.sock'
        self.identity = self.socket_identity()
        self.calls = 0

    def socket_identity(self):
        require(all(not part.is_symlink() for part in (self.path, *self.path.parents)), 'private IPC symlink refused')
        require(list(self.path.parents[2].glob('hypr/*/.socket.sock')) == [self.path], 'exactly one private IPC socket required')
        info = self.path.lstat()
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.geteuid(), 'owned private IPC socket required')
        return info.st_dev, info.st_ino, info.st_uid

    def request(self, payload, deadline, check):
        require(payload == b'j/clients' or payload.startswith(b'/eval '), 'unsupported application IPC request')
        require(len(payload) <= 128 * 1024, 'IPC request cap')
        self.calls += 1
        require(self.calls <= 256, 'IPC request count cap')
        def budget():
            check()
            require(self.socket_identity() == self.identity, 'private IPC path replaced')
            row = owned._stat(self.contract['compositor_pid'])
            require(row[4] == self.contract['compositor_start_ticks'] and row[1] not in (b'Z', b'X'), 'compositor identity changed')
            left = deadline - time.monotonic()
            require(left > 0, 'private IPC deadline')
            return left
        chunks, count = [], 0
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(min(.1, budget()))
            connection.connect(str(self.path))
            peer = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(peer == (self.contract['compositor_pid'], os.geteuid(), os.getegid()), 'private IPC peer differs')
            connection.settimeout(min(.1, budget()))
            connection.sendall(payload)
            while True:
                connection.settimeout(min(.1, budget()))
                try:
                    chunk = connection.recv(min(8192, MAX_REPLY + 1 - count))
                except TimeoutError:
                    continue
                if not chunk:
                    break
                count += len(chunk)
                require(count <= MAX_REPLY, 'private IPC reply cap')
                chunks.append(chunk)
            budget()
        return b''.join(chunks)

    def clients(self, deadline, check):
        value = json.loads(self.request(b'j/clients', deadline, check))
        require(type(value) is list and len(value) <= 256 and all(type(row) is dict for row in value), 'bounded clients array required')
        return value

    def evaluate(self, script, deadline, check):
        reply = self.request(b'/eval ' + script, deadline, check)
        if b'eval is only supported' in reply or b'unknown request' in reply.lower() or b'unsupported window API' in reply:
            raise runtime.NotRun('required private Lua window IPC unsupported')
        require(reply == b'ok', 'guarded window eval refused: ' + reply.decode('utf-8', errors='replace')[:160])


def protected_contract(path):
    path = inputs.local_path(str(path))
    fd = inputs.open_input(path)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and not before.st_mode & 0o022 and
                before.st_size <= runtime.desktop.TEXT_CAP, 'root-provisioned bounded lifecycle contract required')
        chunks, count = [], 0
        while True:
            block = os.read(fd, min(65536, runtime.desktop.TEXT_CAP + 1 - count))
            if not block:
                break
            count += len(block)
            require(count <= runtime.desktop.TEXT_CAP, 'lifecycle contract byte cap')
            chunks.append(block)
        require(inputs.metadata(before) == inputs.metadata(os.fstat(fd)) and count == before.st_size,
                'lifecycle contract changed during descriptor read')
        current = inputs.open_input(path)
        try:
            require(inputs.metadata(os.fstat(current)) == inputs.metadata(before), 'lifecycle contract pathname replaced')
        finally:
            os.close(current)
        raw = b''.join(chunks)
    finally:
        os.close(fd)
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'duplicate lifecycle contract key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique), runtime.desktop.pin(raw)


def admit(contract_path, env):
    """Refuse the live host before any bus/compositor socket connection."""
    try:
        managed.guard(base574, False)
        require(os.geteuid() == os.getegid() == managed.UID, 'ordinary managed fixture UID required')
        status = dict(line.split(':', 1) for line in runtime.read_file('/proc/self/status', 65536).decode().splitlines() if ':' in line)
        require(status['NoNewPrivs'].strip() == '1' and all(int(status[key].strip(), 16) == 0
                for key in ('CapEff', 'CapPrm', 'CapBnd')), 'dropped capabilities and no-new-privileges required')
    except (ValueError, OSError) as exc:
        raise runtime.NotRun('private managed ARM guest prerequisite: ' + str(exc)) from None
    c, contract_pin = protected_contract(contract_path)
    require(set(c) == {'schema', 'api', 'compositor_pid', 'compositor_start_ticks', 'compositor_sha256', 'instance', 'wayland_display'}, 'closed lifecycle contract required')
    require(c['schema'] == 1 and c['api'] == 'hyprland-lua-weak-window-v1', 'unsupported private window API')
    require(type(c['compositor_pid']) is int and c['compositor_pid'] > 1 and type(c['compositor_start_ticks']) is int and c['compositor_start_ticks'] > 0,
            'exact compositor process identity required')
    require(re.fullmatch('[0-9a-f]{64}', c['compositor_sha256']) is not None and
            runtime.desktop.pin(runtime.read_file('/proc/' + str(c['compositor_pid']) + '/exe', runtime.desktop.FILE_CAP))['sha256'] == c['compositor_sha256'], 'compositor binary bytes differ')
    require(type(c['instance']) is str and re.fullmatch('[A-Za-z0-9_.-]+', c['instance']) and c['instance'] not in ('.', '..'), 'private compositor instance required')
    require(type(c['wayland_display']) is str and re.fullmatch(r'wayland-[0-9]+', c['wayland_display']), 'private Wayland display required')
    selected = dict(env, XDG_RUNTIME_DIR=str(managed.RUNTIME), DBUS_SESSION_BUS_ADDRESS=managed.ADDRESS,
                    HYPRLAND_INSTANCE_SIGNATURE=c['instance'], WAYLAND_DISPLAY=c['wayland_display'])
    base = SimpleNamespace(guard=base574.guard, command=read_only_command, emit=lambda *a, **k: None)
    identity = dict(managed.validate_user(base, None, selected), contract=contract_pin)
    node = managed.RUNTIME / c['wayland_display']
    info = node.lstat()
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid == managed.UID, 'owned managed Wayland socket required')
    ipc = PrivateIPC(c, selected)
    ipc.evaluate(b'assert(type(_G)=="table" and type(hl)=="table" and type(hl.get_window)=="function" and type(hl.dispatch)=="function" and type(hl.dsp)=="table" and type(hl.dsp.window)=="table" and type(hl.dsp.window.close)=="function","unsupported window API")', time.monotonic() + 2, lambda: None)
    return ipc, selected, identity


def launch(argv, cwd, env, run_seconds, ready_seconds, marker, *, contract_path, close_seconds=2):
    require(all(type(value) in (int, float) and math.isfinite(value) and .05 <= value <= 30
                for value in (run_seconds, ready_seconds)) and ready_seconds <= run_seconds, 'bounded mapping/run deadlines required')
    require(type(close_seconds) in (int, float) and math.isfinite(close_seconds) and .05 <= close_seconds <= 10, 'bounded close deadline required')
    ipc, selected, managed_identity = admit(contract_path, env)
    owned.prepare()
    require(signal.getsignal(signal.SIGPIPE) == signal.SIG_IGN, 'SIGPIPE must be ignored before launch')
    started = time.monotonic()
    run_end, deadline = started + run_seconds, started + run_seconds + 1
    output, cancelled, identity = bytearray(), [], None
    child = None
    custody = True
    bound = False
    cleanup_script = None
    record = dict(status='NOT_MAPPED', mapped=False, close_requested=False, unmapped=False,
                  evidence=ipc.evidence, managed_identity=managed_identity)
    first = None
    transferred = False
    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    def cancel(sig, frame):
        if len(cancelled) < 8:
            cancelled.append(signal.Signals(sig).name)
    def check(alive=True):
        nonlocal identity, custody
        if not custody:
            raise LostOwnership('launch custody unavailable')
        try:
            terminal = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
        except ChildProcessError:
            custody = False
            raise LostOwnership('ECHILD: launch custody lost; no further PID operations') from None
        if terminal is not None and (terminal.si_pid != child.pid or terminal.si_code not in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED)):
            custody = False
            raise LostOwnership('unexpected reserved child status')
        row = owned._stat(child.pid)
        current = row[0], row[2], row[3], row[4]
        if current[:3] != (child.pid, child.pid, child.pid) or (identity is not None and current != identity):
            custody = False
            raise LostOwnership('reserved launch identity changed')
        identity = current
        if cancelled:
            raise Cancelled('window lifecycle cancelled')
        if alive:
            require(terminal is None, 'application exited before window control completed')
        require(time.monotonic() < run_end, 'window lifecycle run deadline')
    def drain():
        for pipe in (child.stdout, child.stderr):
            try:
                block = os.read(pipe.fileno(), min(65536, runtime.CAP + 1 - len(output)))
            except BlockingIOError:
                continue
            room = runtime.CAP - len(output)
            output.extend(block[:room])
            require(len(block) <= room, 'combined output cap exceeded')
    try:
        for sig in handlers:
            signal.signal(sig, cancel)
        child = subprocess.Popen(argv, cwd=cwd, env=selected, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, start_new_session=True)
        for pipe in (child.stdout, child.stderr):
            os.set_blocking(pipe.fileno(), False)
        until = min(run_end, started + ready_seconds)
        while time.monotonic() < until:
            check();drain()
            clients = ipc.clients(until, check)
            matches = [row for row in clients if row.get('pid') == child.pid and row.get('mapped') is True]
            require(len(matches) <= 1, 'multiple owned windows unsupported')
            if matches:
                window = window_identity(matches[0], child.pid)
                key = 'CAA_WINDOW_' + secrets.token_hex(16)
                bind_script, close_script, cleanup_script = scripts(window, key)
                ipc.evaluate(bind_script, until, check)
                bound = True
                record.update(mapped=True, identity=window, mapping_seconds=time.monotonic() - started)
                break
            time.sleep(min(.02, max(0, until - time.monotonic())))
        require(bound, 'owned window mapping deadline')
        until = min(run_end, time.monotonic() + close_seconds)
        check();drain()
        ipc.evaluate(close_script, until, check)
        record['close_requested'] = True
        bound = False  # Successful atomic close also cleared only this nonce.
        while time.monotonic() < until:
            check(False);drain()
            clients = ipc.clients(until, lambda: check(False))
            if not any(row.get('pid') == child.pid and row.get('address') == window['address'] and
                       (row.get('mapped') is True or row.get('visible') is True) for row in clients):
                record.update(status='MAPPED_CLOSED_UNMAPPED', unmapped=True)
                break
            time.sleep(min(.02, max(0, until - time.monotonic())))
        require(record['unmapped'], 'owned window retirement deadline')
    except Exception as exc:
        first = exc
        record['status'] = 'NOT_RUN' if isinstance(exc, runtime.NotRun) else 'CANCELLED' if isinstance(exc, Cancelled) else 'FAILED'
        record['error'] = type(exc).__name__ + ': ' + str(exc)[:300]
    finally:
        if bound and custody and cleanup_script is not None:
            try:
                ipc.evaluate(cleanup_script, min(run_end, time.monotonic() + .2), lambda: check(False))
            except Exception as exc:
                record['binding_cleanup'] = type(exc).__name__ + ': ' + str(exc)[:160]
        remaining = deadline - time.monotonic()
        if child is not None and custody:
            if remaining <= 0:
                record['deadline_overrun'] = True
                remaining = 1.0  # Separate, failed emergency cleanup; never a renewed run.
            if first is not None:
                remaining = min(remaining, 1.1)
            retirement = min(1, remaining * .8)
            transferred = True
            result = owned.supervise(child, cap=remaining, retirement=retirement, grace=min(.15, retirement / 2),
                                     max_output=max(0, runtime.CAP - len(output)))
            output.extend(result.pop('output'))
        elif child is not None:
            child._child_created = False
            for pipe in (child.stdout, child.stderr):
                pipe.close()
            result = dict(exit=None, reaped=False, ownership='UNKNOWN', passed=False, signals=[],
                          timeout=False, group_census='UNKNOWN', error='launch wait ownership lost' if not custody else 'final retirement budget exhausted', output_complete=False)
        else:
            result = dict(exit=None, reaped=False, ownership='NOT_LAUNCHED', passed=False, signals=[],
                          timeout=False, group_census='NOT_OBSERVED', error=str(first), output_complete=False)
        custody = False  # No child PID/proc access or IPC follows final transfer.
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
    record.update(launch_identity=dict(pid=identity[0], group=identity[1], session=identity[2], start_ticks=identity[3]) if identity else None,
                  custody_transfer='OWNED_PROCESS_SUPERVISE' if transferred else 'NOT_TRANSFERRED',
                  run_seconds_limit=run_seconds, mapping_seconds_limit=ready_seconds, close_seconds_limit=close_seconds)
    result['seconds_total'] = time.monotonic() - started
    result.update(output=bytes(output).decode('utf-8', errors='replace'), window=record, signals_received=cancelled,
                  readiness=dict(kind='owned-window-mapping', observed=record['mapped']),
                  retirement='OBSERVED_EMPTY_GROUP' if result['reaped'] and result['group_census'] == 'EMPTY_TWICE' else 'UNKNOWN')
    passed = result['passed'] and record['status'] == 'MAPPED_CLOSED_UNMAPPED' and not cancelled and not record.get('deadline_overrun')
    result['supervisor_passed'] = result['passed']
    result['passed'] = passed and ipc.evidence == 'PRIVATE_MANAGED_GUEST'
    result['model_protocol_passed'] = passed if ipc.evidence != 'PRIVATE_MANAGED_GUEST' else None
    result['status'] = ('CANCELLED' if cancelled else 'NOT_RUN' if isinstance(first, runtime.NotRun) else
                        'PASS_EXEC_WORKFLOW' if passed and ipc.evidence == 'PRIVATE_MANAGED_GUEST' else
                        'PASS_MODEL_WINDOW_PROTOCOL' if passed else 'START_FAILED' if child is None else 'WINDOW_WORKFLOW_FAILED')
    result['gui'] = 'PASS_PRIVATE_GUEST_WINDOW_LIFECYCLE' if passed and ipc.evidence == 'PRIVATE_MANAGED_GUEST' else 'NOT_RUN (model or incomplete lifecycle)'
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'environment', 'context', 'private-contract'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('select', 'entry-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--ready-marker', default='WINDOW', help='compatibility value; readiness is observed window mapping')
    parser.add_argument('--exec-fallback', action='store_true')
    parser.add_argument('--file', dest='inputs', action=inputs.InputAction)
    parser.add_argument('--uri', dest='inputs', action=inputs.InputAction)
    parser.add_argument('--allow-uri-scheme', action='append', choices=sorted(inputs.SCHEMES), default=[])
    parser.add_argument('--ready-seconds', type=float, default=2)
    parser.add_argument('--run-seconds', type=float, default=5)
    parser.add_argument('--close-seconds', type=float, default=2)
    args = parser.parse_args(argv)
    try:
        try:
            managed.guard(base574, False)
        except (ValueError, OSError) as exc:
            raise runtime.NotRun('private managed ARM guest prerequisite: ' + str(exc)) from None
        require(runtime.data(args.context).get('mode') == 'guest', 'window entrypoint requires installed guest runtime mode')
        report = runtime.run(args, launcher=lambda *values: launch(*values, contract_path=args.private_contract, close_seconds=args.close_seconds))
    except runtime.NotRun as exc:
        report = dict(schema=1, status='NOT_RUN', gui='NOT_RUN', error=str(exc))
    except (ValueError, OSError, KeyError, TypeError, UnicodeError) as exc:
        report = dict(schema=1, status='REFUSED', gui='NOT_RUN', error=str(exc))
    print(json.dumps(report, sort_keys=True, indent=2, allow_nan=False))
    return 0 if report['status'] == 'PASS_EXEC_WORKFLOW' else 2 if report['status'] in ('NOT_RUN', 'REFUSED') else 1


if __name__ == '__main__':
    sys.exit(main())
