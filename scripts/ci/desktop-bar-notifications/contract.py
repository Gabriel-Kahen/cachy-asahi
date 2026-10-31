# SPDX-License-Identifier: MIT
"""Source/data gates; no build, package, VM or service operations."""
import hashlib
import json
import re
from pathlib import Path
from session import owned_layer, notifications, MAKO_NAMESPACE, environment_values, SESSION_ENV
from capture import request_digest
import managed_contract


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify_source(source, pins=None):
    source = Path(source)
    if pins is None:
        pins = json.loads(Path(__file__).with_name('source-pins.json').read_text())
    for relative, expected in pins.items():
        path = source / relative
        if path.is_symlink() or not path.is_file() or digest(path) != expected:
            raise ValueError('source dependency differs: ' + relative)


def verify_result(events):
    managed = managed_contract.verify_result(events)
    user = next(e for e in events if e.get('event') == 'managed_user_ready')
    for stage in ('minimal', 'overlay'):
        frames = [e for e in events if e.get('event') == 'frame_ready' and e.get('stage') == stage]
        phases = [e for e in events if e.get('event') == 'phase_pass' and e.get('stage') == stage]
        if len(frames) != 1 or len(phases) != 1:
            raise ValueError('both distinct client phase/capture pairs required')
        if phases[0].get('config_preserved') is not True or any(phases[0].get(k) != 'PASS'
                                                               for k in ('waybar', 'mako')):
            raise ValueError('bar/notification/config phase acceptance absent')
        for key in ('bar', 'mako', 'notification', 'waybar_pid', 'mako_pid'):
            if key not in frames[0]:
                raise ValueError('bar/notification capture evidence absent')
        frame = frames[0]
        identity = {key: user[key] for key in ('address', 'uid', 'manager_pid', 'default_target')}
        if frame.get('managed_identity') != identity or frame.get('activation') != 'normal-shipped-config-no-reload':
            raise ValueError('normal managed activation evidence absent')
        activation=frame.get('activation_environment')
        if (type(activation) is not dict or set(activation)!={'values','manager_pid','systemd_verified','dbus_updated'} or
            activation['manager_pid']!=identity['manager_pid'] or activation['systemd_verified'] is not True or
            activation['dbus_updated'] is not True or type(activation['values']) is not dict or
            set(activation['values'])!=set(SESSION_ENV) or environment_values(activation['values'])!=activation['values']):
            raise ValueError('verified owned activation environment absent')
        if type(frame.get('notification_timeout_ms')) is not int or frame['notification_timeout_ms'] != 0:
            raise ValueError('nonexpiring visual fixture must be explicit')
        pids = [frame.get(key) for key in ('waybar_pid', 'mako_pid', 'compositor_pid')]
        if any(type(pid) is not int or pid <= 0 for pid in pids) or len(set(pids)) != 3:
            raise ValueError('distinct owned compositor/client identities required')
        captures = [e for e in events if e.get('event') == 'frame_captured' and e.get('stage') == stage]
        if len(captures) != 1:
            raise ValueError('one first QMP observation required')
        observed = captures[0]
        if observed.get('request_sha256') != request_digest(frame) or observed.get('managed_identity') != identity:
            raise ValueError('capture request/managed identity mismatch')
        if (observed.get('first_capture') is not True or type(observed.get('capture_ms')) is not int or
            not 0 <= observed['capture_ms'] <= 5000 or observed.get('visual_review') != 'NOT_RUN' or
            type(observed.get('sha256')) is not str or re.fullmatch('[0-9a-f]{64}', observed['sha256']) is None):
            raise ValueError('bounded first capture receipt absent')
        positions = [events.index(row) for row in (frame, observed, phases[0])]
        if positions != sorted(positions):
            raise ValueError('capture observation order differs')
        if type(frame.get('capture_after_ms')) is not int or frame['capture_after_ms'] < 5000:
            raise ValueError('capture settle evidence absent')
        if frame['waybar_pid'] == frame['mako_pid']:
            raise ValueError('distinct client owners required')
        for key, namespace, pid in (('bar', 'waybar', frame['waybar_pid']),
                                    ('mako', MAKO_NAMESPACE, frame['mako_pid'])):
            row = frame[key]
            if type(pid) is not int or pid <= 0 or type(row) is not dict:
                raise ValueError('invalid captured client identity')
            value = {row['monitor']: {'levels': {row['level']: [row]}}}
            if owned_layer(value, namespace, pid) is None:
                raise ValueError('captured client not visible')
        notifications([frame['notification']], frame['notification']['id'])
    sessions = [e for e in events if e.get('event') == 'session_pass']
    if len(sessions) != 1 or any(sessions[0].get(k) != 'PASS' for k in ('waybar', 'mako', 'status')):
        raise ValueError('bar/notification session acceptance absent')
    return managed


def verify_package_input(proposal, installed):
    expected = {r['name']: r['version'] for r in proposal['closure_packages']}
    if len(expected) != len(proposal['closure_packages']):
        raise ValueError('duplicate closure package')
    if any(installed.get(name) != version for name, version in expected.items()):
        raise ValueError('bar/notification dependency inventory differs')
    if proposal['additional_packages'] or proposal['replacement_packages']:
        raise ValueError('unreviewed additive/replacement delta')
