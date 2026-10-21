# SPDX-License-Identifier: MIT
"""Data-only source and managed-session result gates."""
import hashlib
import json
from pathlib import Path


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def verify_source(source):
    pins = json.loads(Path(__file__).with_name('source-pins.json').read_text())
    for name, pin in pins.items():
        path = Path(source) / name
        need(path.is_file() and not path.is_symlink()
             and hashlib.sha256(path.read_bytes()).hexdigest() == pin, 'managed profile source drift: ' + name)


def verify_result(events):
    need(type(events) is list and len(events) <= 4096, 'bounded managed events required')
    selected = {}
    for name in ('managed_session_ready', 'managed_user_ready', 'session_pass', 'managed_session_cleanup', 'complete'):
        rows = [(i, row) for i, row in enumerate(events) if row.get('event') == name]
        need(len(rows) == 1 and rows[0][1].get('status') == 'PASS', 'one successful ' + name + ' required')
        selected[name] = rows[0]
    positions = [selected[name][0] for name in selected]
    need(positions == sorted(positions) and not any(row.get('event') in
         ('managed_session_diagnostic', 'failed', 'failure') for row in events), 'managed lifecycle failed or unordered')
    root, user = selected['managed_session_ready'][1], selected['managed_user_ready'][1]
    units = root.get('units')
    expected = {'systemd-user-sessions.service': 'exited',
                'user-runtime-dir@23001.service': 'exited', 'user@23001.service': 'running'}
    need(type(units) is dict and set(units) == set(expected), 'managed unit readiness evidence missing')
    for unit, substate in expected.items():
        value = units[unit]
        need(type(value) is dict and value.get('Id') == unit and value.get('LoadState') == 'loaded'
             and value.get('ActiveState') == 'active' and value.get('SubState') == substate
             and value.get('Result') == 'success' and type(value.get('ExecMainStatus')) is int
             and value['ExecMainStatus'] == 0 and type(value.get('MainPID')) is int
             and value['MainPID'] == (root.get('manager_pid') if unit == 'user@23001.service' else 0),
             'managed unit readiness differs')
    for row in (root, user):
        need(row.get('address') == 'unix:path=/run/user/23001/bus'
             and type(row.get('uid')) is int and row['uid'] == 23001
             and type(row.get('manager_pid')) is int and 0 < row['manager_pid'] < 2**32
             and row.get('default_target') == 'GetUnit-PASS', 'managed bus identity missing')
    need(root['manager_pid'] == user['manager_pid'], 'manager identity changed between root and user')
    cleanup = selected['managed_session_cleanup'][1]
    need(cleanup.get('runtime_absent') is True and cleanup.get('owned_units_stopped') is True
         and cleanup.get('units') == ['user@23001.service', 'user-runtime-dir@23001.service'],
         'managed disposal evidence missing')
    stopped = cleanup.get('unit_states')
    need(type(stopped) is dict and set(stopped) == set(cleanup['units']), 'stopped unit states missing')
    for unit, value in stopped.items():
        need(type(value) is dict and value.get('Id') == unit and value.get('LoadState') == 'loaded'
             and value.get('ActiveState') == 'inactive' and value.get('SubState') == 'dead'
             and type(value.get('MainPID')) is int and value['MainPID'] == 0, 'managed unit still active')
    for stage in ('minimal', 'overlay'):
        rows = [row for row in events if row.get('event') == 'phase_pass' and row.get('stage') == stage]
        need(len(rows) == 1, 'original desktop phase missing')
    return {'status': 'PASS', 'scope': 'managed-systemd-user-generic-VM', 'hardware': 'NOT RUN'}
