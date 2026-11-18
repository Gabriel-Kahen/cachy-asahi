# SPDX-License-Identifier: MIT
"""Opt-in disposable VM user manager; no private bus or PAM bypass."""
import base64
import os
from pathlib import Path
import re
import stat
import time
from types import SimpleNamespace

UID = 23001
RUNTIME = Path('/run/user/23001')
ADDRESS = 'unix:path=/run/user/23001/bus'
USER = 'user@23001.service'
DIRECTORY = 'user-runtime-dir@23001.service'
SESSIONS = 'systemd-user-sessions.service'
PROPERTIES = ('Id', 'LoadState', 'ActiveState', 'SubState', 'Result', 'MainPID',
              'ExecMainCode', 'ExecMainStatus')
SETPRIV = ['/usr/bin/setpriv', '--reuid=23001', '--regid=23001', '--clear-groups',
           '--inh-caps=-all', '--ambient-caps=-all', '--bounding-set=-all', '--no-new-privs']


def bind(base):
    """Bind a transformed guest; composes with another adapter's phase/emit hooks."""
    original = base.guard
    def selected(root):
        original(root)
        need('cachy_asahi_managed_user=1' in Path('/proc/cmdline').read_text().split(),
             'explicit managed-user VM marker required')
    base.guard = selected
    base.managed_base = base
    base.managed_session = SimpleNamespace(ManagedSession=ManagedSession,
                                           validate_user=validate_user, SETPRIV=SETPRIV)
    return base


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def guard(base, root):
    base.guard(root)
    need('cachy_asahi_managed_user=1' in Path('/proc/cmdline').read_text().split(),
         'explicit managed-user VM marker required')
    need(Path('/proc/1/comm').read_text().strip() == 'systemd' and not Path('/.dockerenv').exists(),
         'booted systemd VM required')


def uint(text):
    match = re.fullmatch(r'u ([0-9]{1,10})\s*', text)
    need(match is not None and int(match[1]) < 2**32, 'typed D-Bus uint required')
    return int(match[1])


def properties(text, unit):
    need(type(text) is str and len(text) <= 8192, 'bounded unit properties required')
    rows = [line.split('=', 1) for line in text.splitlines()]
    need(all(len(row) == 2 for row in rows) and len(rows) == len(PROPERTIES)
         and len(dict(rows)) == len(rows) and set(dict(rows)) == set(PROPERTIES),
         'complete unique unit properties required')
    value = dict(rows)
    need(value['Id'] == unit and value['LoadState'] == 'loaded', 'loaded exact unit required')
    for key in ('MainPID', 'ExecMainCode', 'ExecMainStatus'):
        need(re.fullmatch('[0-9]{1,10}', value[key]) is not None and int(value[key]) < 2**32,
             'typed unit process fields required')
        value[key] = int(value[key])
    return value


def active(value, substate, *, process):
    need(value['ActiveState'] != 'failed', 'managed unit failed: ' + value['Id'])
    if value['ActiveState'] != 'active':
        return False
    need(value['SubState'] == substate and value['Result'] == 'success'
         and value['ExecMainStatus'] == 0 and value['ExecMainCode'] in (0, 1)
         and (value['MainPID'] > 0 if process else value['MainPID'] == 0),
         'managed unit active without successful expected state: ' + value['Id'])
    return True


def runtime_nodes():
    """Never create/chmod a systemd runtime directory or follow an alias."""
    parent = RUNTIME.parent.lstat()
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0
         and not stat.S_IMODE(parent.st_mode) & 0o022, 'runtime parent identity differs')
    info = RUNTIME.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == UID
         and stat.S_IMODE(info.st_mode) == 0o700, 'systemd runtime directory identity differs')
    manager = (RUNTIME / 'systemd').lstat()
    need(stat.S_ISDIR(manager.st_mode) and manager.st_uid == UID
         and not stat.S_IMODE(manager.st_mode) & 0o022, 'systemd socket parent identity differs')
    for path in (RUNTIME / 'bus', RUNTIME / 'systemd/private'):
        value = path.lstat()
        need(stat.S_ISSOCK(value.st_mode) and value.st_uid == UID, 'managed socket identity differs')


def bus_owner_ready(command):
    """Only typed name absence is pending; transport/parse failures still refuse."""
    reply = command(['/usr/bin/busctl', '--address=' + ADDRESS, '--auto-start=no', '--timeout=3s',
        'call', 'org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus',
        'NameHasOwner', 's', 'org.freedesktop.systemd1'])
    match = re.fullmatch(r'b (true|false)\s*', reply)
    need(match is not None, 'typed D-Bus name-owner reply required')
    return match[1] == 'true'


def bus_probe(command, expected_pid):
    need(type(expected_pid) is int and 0 < expected_pid < 2**32, 'expected manager PID required')
    prefix = ['/usr/bin/busctl', '--address=' + ADDRESS, '--auto-start=no', '--timeout=3s', 'call']
    call = lambda method: command(prefix + ['org.freedesktop.DBus', '/org/freedesktop/DBus',
        'org.freedesktop.DBus', method, 's', 'org.freedesktop.systemd1'])
    need(uint(call('GetConnectionUnixUser')) == UID, 'user manager bus owner UID differs')
    need(uint(call('GetConnectionUnixProcessID')) == expected_pid, 'user manager bus owner PID differs')
    target = command(prefix + ['org.freedesktop.systemd1', '/org/freedesktop/systemd1',
        'org.freedesktop.systemd1.Manager', 'GetUnit', 's', 'default.target'])
    need(target.strip() == 'o "/org/freedesktop/systemd1/unit/default_2etarget"',
         'systemd user D-Bus GetUnit reply differs')
    return dict(address=ADDRESS, uid=UID, manager_pid=expected_pid, default_target='GetUnit-PASS')


def validate_user(base, logs, env):
    guard(base, False)
    need(env.get('DBUS_SESSION_BUS_ADDRESS') == ADDRESS and env.get('XDG_RUNTIME_DIR') == str(RUNTIME),
         'managed user environment differs')
    raw = os.environ.get('CACHY_MANAGED_MANAGER_PID', '')
    need(re.fullmatch('[0-9]{1,10}', raw) is not None, 'root-joined manager PID required')
    runtime_nodes()
    count = 0
    def command(argv):
        nonlocal count
        count += 1
        return base.command(argv, env, logs, 'managed-user-probe-' + str(count), timeout=5)
    result = bus_probe(command, int(raw))
    base.emit('managed_user_ready', status='PASS', **result)
    return result


class ManagedSession:
    def __init__(self, base, logs, env, *, seconds=60):
        guard(base, True)
        need(type(seconds) is int and 1 <= seconds <= 120, 'finite managed readiness budget required')
        self.base, self.logs, self.env, self.seconds = base, Path(logs), dict(env), seconds
        self.sequence, self.owned, self.diagnosed = 0, False, False
        self.deadline = None
        self.states = {}
        self.user_env = dict(env, HOME='/home/desktop574', XDG_RUNTIME_DIR=str(RUNTIME),
                             DBUS_SESSION_BUS_ADDRESS=ADDRESS)

    def command(self, argv, *, user=False, timeout=5):
        if self.deadline is not None:
            timeout = min(timeout, self.deadline - time.monotonic())
            need(timeout > 0, 'managed command deadline')
        self.sequence += 1
        return self.base.command((SETPRIV if user else []) + argv,
            self.user_env if user else self.env, self.logs, 'managed-' + str(self.sequence), timeout=timeout)

    def show(self, unit):
        argv = ['/usr/bin/systemctl', 'show', '--no-pager', unit]
        argv += ['--property=' + key for key in PROPERTIES]
        value = properties(self.command(argv), unit)
        self.states[unit] = value
        return value

    def wait(self, probe, seconds):
        deadline = time.monotonic() + seconds
        previous, self.deadline = self.deadline, deadline
        try:
            while time.monotonic() < deadline:
                result = probe()
                need(time.monotonic() < deadline, 'managed readiness deadline')
                if result:
                    return result
                time.sleep(.25)
            raise ValueError('managed readiness deadline')
        finally:
            self.deadline = previous

    def start(self):
        need(active(self.show(SESSIONS), 'exited', process=False)
             and not os.path.lexists('/run/nologin'), 'permit-user-sessions prerequisite not ready')
        for unit in (USER, DIRECTORY):
            value = self.show(unit)
            need(value['ActiveState'] == 'inactive' and value['MainPID'] == 0,
                 'preexisting user manager/runtime unit refused')
        need(not os.path.lexists(RUNTIME), 'preexisting user runtime directory refused')
        self.owned = True  # A failed/unknown start still requires exact unit disposal.
        self.command(['/usr/bin/systemctl', '--no-block', 'start', DIRECTORY, USER])
        def ready():
            directory, manager = self.show(DIRECTORY), self.show(USER)
            if not (active(directory, 'exited', process=False) and active(manager, 'running', process=True)):
                return None
            try:
                runtime_nodes()
            except FileNotFoundError:
                return None
            # Socket activation is permitted only on the systemd-managed endpoint.
            command = lambda argv: self.command(argv, user=True)
            if not bus_owner_ready(command):
                return None
            reply = bus_probe(command, manager['MainPID'])
            self.user_env['CACHY_MANAGED_MANAGER_PID'] = str(manager['MainPID'])
            self.base.emit('managed_session_ready', status='PASS', units=dict(self.states), **reply)
            return dict(self.user_env)
        return self.wait(ready, self.seconds)

    def diagnose(self):
        """At most one finite journal capture; diagnostics never replace failure."""
        if self.diagnosed:
            return
        self.diagnosed = True
        row = dict(status='FAIL', units=dict(self.states), journal_status='UNAVAILABLE')
        try:
            text = self.command(['/usr/bin/journalctl', '--boot', '--no-pager', '--output=short-monotonic',
                '--lines=80', '--unit=' + USER, '--unit=' + DIRECTORY, '--unit=' + SESSIONS,
                '--unit=systemd-logind.service'], timeout=8)
            raw = text.encode()
            row.update(journal_status='CAPTURED', journal_bytes=len(raw), journal_truncated=len(raw) > 12288,
                       journal_tail_base64=base64.b64encode(raw[-12288:]).decode())
        except BaseException as error:
            row['diagnostic_error'] = type(error).__name__
        self.base.emit('managed_session_diagnostic', **row)

    def stop(self):
        if not self.owned:
            return
        self.command(['/usr/bin/systemctl', '--no-block', 'stop', USER, DIRECTORY])
        def stopped():
            rows = [self.show(unit) for unit in (USER, DIRECTORY)]
            return all(v['ActiveState'] == 'inactive' and v['SubState'] == 'dead' and v['MainPID'] == 0 for v in rows)
        self.wait(stopped, 30)
        need(not os.path.lexists(RUNTIME), 'managed runtime/socket remained after unit stop')
        self.owned = False
        self.base.emit('managed_session_cleanup', status='PASS', units=[USER, DIRECTORY],
                       unit_states={unit:self.states[unit] for unit in (USER,DIRECTORY)},
                       runtime_absent=True, owned_units_stopped=True)
