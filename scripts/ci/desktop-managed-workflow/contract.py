# SPDX-License-Identifier: MIT
"""Source, inventory and file-manager workflow event acceptance gates."""
import hashlib
import json
from pathlib import Path
import file_manager as T
import terminal_workflow as A
import combined as C
import managed_contract as M
import re


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
    managed = M.verify_result(events)
    user = next(e for e in events if e.get('event') == 'managed_user_ready')
    session = next(e for e in events if e.get('event') == 'session_pass')
    for stage in ('minimal', 'overlay'):
        def one(name):
            rows = [e for e in events if e.get('event') == name and e.get('stage') == stage]
            T.need(len(rows) == 1, 'one combined event required: ' + name)
            return rows[0]
        terminal, files, frame, phase = (one(n) for n in
            ('terminal_workflow_result','file_manager_result','frame_ready','phase_pass'))
        indices = [events.index(e) for e in (user,terminal,files,frame,phase,session)]
        T.need(indices == sorted(indices), 'managed combined event order differs')
        a,f = terminal['proof'],files['proof']
        ap,fp = frame['terminal_pid'],frame['thunar_pid']
        A.validate_result(a,stage,a['nonce'],ap);T.validate(f,stage,fp)
        T.need(a['nonce'] == f['nonce'], 'both app proofs must share phase nonce')
        for proof,result,key in ((a,terminal,'terminal_proof_sha256'),(f,files,'workflow_proof_sha256')):
            raw = (json.dumps(proof,sort_keys=True,indent=2)+'\n').encode()
            T.need(T.sha(raw) == result['proof_sha256'] == frame[key], 'combined proof digest join differs')
        C.together([frame['terminal'],frame['thunar']],ap,fp)
        T.need(frame.get('worker') == dict(pid=a['worker_pid'],parent_pid=ap,uid=23001), 'owned worker join differs')
        T.need(frame.get('co_resident') is True and frame.get('bus_address') == user['address'] and
               frame.get('manager_pid') == user['manager_pid'] and
               frame.get('managed_identity') == {k:user[k] for k in ('address','uid','manager_pid','default_target')} and
               type(frame.get('compositor_pid')) is int and frame['compositor_pid'] > 0 and
               frame['compositor_pid'] not in (ap,fp) and
               type(frame.get('wayland_display')) is str and re.fullmatch('wayland-[0-9]+',frame['wayland_display']),
               'single managed bus/compositor identity absent')
        T.need(type(frame.get('capture_after_ms')) is int and frame['capture_after_ms'] >= 5000,
               'combined capture settle absent')
        T.need(phase.get('config_preserved') is True and phase.get('co_resident') is True and
               all(phase.get(k) == 'PASS' for k in
                   ('terminal','vim_edit','native_c','unicode_clipboard','thunar','dbus_copy','gio_rename','text_launch')),
               'combined phase acceptance absent')
        T.need(phase.get('rename_ui') == phase.get('editor_ui') == 'NOT_RUN', 'app UI attribution differs')
    T.need(session.get('co_resident') is True and all(session.get(k) == 'PASS' for k in
           ('terminal','vim_edit','native_c','unicode_clipboard','thunar','dbus_copy','gio_rename','text_launch')),
           'combined session acceptance absent')
    T.need(session.get('managed_session') == 'SELECTED_REAL_USER_MANAGER' and
           session.get('physical_keyboard') == session.get('rename_ui') == session.get('editor_ui') == 'NOT_RUN',
           'managed combined scope differs')
    return managed
