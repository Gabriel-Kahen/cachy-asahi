# SPDX-License-Identifier: MIT
"""Source, inventory and terminal workflow event acceptance gates."""
import hashlib
import json
from pathlib import Path
import terminal_workflow as T


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
    T.need(all(installed.get(r['name']) == r['version'] for r in rows), 'terminal dependency inventory differs')


def verify_result(events):
    for stage in ('minimal', 'overlay'):
        def one(name):
            found = [e for e in events if e.get('event') == name and e.get('stage') == stage]
            T.need(len(found) == 1, 'one terminal workflow event required: ' + name)
            return found[0]
        result, frame, phase = (one(name) for name in ('terminal_workflow_result', 'frame_ready', 'phase_pass'))
        T.need(events.index(result) < events.index(frame) < events.index(phase), 'terminal workflow/capture order differs')
        proof = result['proof'];pid = frame['terminal_pid']
        T.validate_result(proof, stage, proof['nonce'], pid)
        raw = (json.dumps(proof, sort_keys=True, indent=2) + '\n').encode()
        T.need(T.sha(raw) == result['proof_sha256'] == frame['workflow_proof_sha256'], 'terminal proof digest join differs')
        T.need(type(frame.get('capture_after_ms')) is int and frame['capture_after_ms'] >= 5000,
               'terminal capture settle absent')
        T.need(T.window([frame['terminal']], pid) is not None, 'terminal capture not visible')
        T.need(frame['worker'] == dict(pid=proof['worker_pid'], parent_pid=pid, uid=23001),
               'terminal worker process join differs')
        T.need(phase.get('config_preserved') is True and all(phase.get(k) == 'PASS' for k in
               ('terminal', 'vim_edit', 'native_c', 'unicode_clipboard')), 'terminal phase acceptance absent')
    sessions = [e for e in events if e.get('event') == 'session_pass']
    T.need(len(sessions) == 1 and all(sessions[0].get(k) == 'PASS' for k in
           ('status', 'terminal', 'vim_edit', 'native_c', 'unicode_clipboard')), 'terminal session acceptance absent')
    T.need(sessions[0].get('managed_session') == 'UNSELECTED_NOT_RUN' and
           sessions[0].get('physical_keyboard') == 'NOT_RUN', 'standalone/input scope qualification absent')
