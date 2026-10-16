# SPDX-License-Identifier: MIT
"""Source/data gates; no build, package, VM or service operations."""
import hashlib
import json
from pathlib import Path
from session import owned_layer, notifications, MAKO_NAMESPACE


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


def verify_package_input(proposal, installed):
    expected = {r['name']: r['version'] for r in proposal['closure_packages']}
    if len(expected) != len(proposal['closure_packages']):
        raise ValueError('duplicate closure package')
    if any(installed.get(name) != version for name, version in expected.items()):
        raise ValueError('bar/notification dependency inventory differs')
    if proposal['additional_packages'] or proposal['replacement_packages']:
        raise ValueError('unreviewed additive/replacement delta')
