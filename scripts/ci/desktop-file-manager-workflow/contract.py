# SPDX-License-Identifier: MIT
"""Source, inventory and file-manager workflow event acceptance gates."""
import hashlib
import json
from pathlib import Path
import file_manager as T


def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify_source(source):
    pins = json.loads(Path(__file__).with_name('source-pins.json').read_text())
    for relative, pin in pins.items():
        path = source / relative
        T.need(not path.is_symlink() and path.is_file() and digest(path) == pin,
               'source dependency differs: ' + relative)


def verify_package_input(proposal, installed):
    rows = proposal['closure_packages']
    T.need(len({r['name'] for r in rows}) == len(rows), 'duplicate closure package')
    T.need(not proposal['additional_packages'] and not proposal['replacement_packages'], 'unreviewed package delta')
    T.need(all(installed.get(r['name']) == r['version'] for r in rows), 'file-manager dependency inventory differs')


def verify_result(events):
    for stage in ('minimal', 'overlay'):
        def one(name):
            rows = [e for e in events if e.get('event') == name and e.get('stage') == stage]
            T.need(len(rows) == 1, 'one file-manager event required: ' + name)
            return rows[0]
        result, frame, phase = (one(n) for n in ('file_manager_result', 'frame_ready', 'phase_pass'))
        T.need(events.index(result) < events.index(frame) < events.index(phase), 'file-manager event order differs')
        proof = result['proof'];pid = frame['thunar_pid']
        T.validate(proof, stage, pid)
        raw = (json.dumps(proof, sort_keys=True, indent=2) + '\n').encode()
        T.need(T.sha(raw) == result['proof_sha256'] == frame['workflow_proof_sha256'], 'file-manager digest join differs')
        T.need(T.window([frame['thunar']], pid, 'Files') is not None and
               type(frame.get('capture_after_ms')) is int and frame['capture_after_ms'] >= 5000,
               'visible settled Thunar frame required')
        T.need(phase.get('config_preserved') is True and all(phase.get(k) == 'PASS' for k in
               ('thunar', 'dbus_copy', 'gio_rename', 'text_launch')), 'file-manager phase acceptance absent')
        T.need(phase.get('rename_ui') == phase.get('editor_ui') == 'NOT_RUN', 'UI attribution differs')
    sessions = [e for e in events if e.get('event') == 'session_pass']
    T.need(len(sessions) == 1 and all(sessions[0].get(k) == 'PASS' for k in
           ('status', 'thunar', 'dbus_copy', 'gio_rename', 'text_launch')), 'file-manager session acceptance absent')
    T.need(sessions[0].get('managed_session') == 'UNSELECTED_NOT_RUN' and
           sessions[0].get('physical_keyboard') == sessions[0].get('rename_ui') ==
           sessions[0].get('editor_ui') == 'NOT_RUN', 'file-manager scope differs')
