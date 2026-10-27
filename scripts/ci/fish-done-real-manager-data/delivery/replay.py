# SPDX-License-Identifier: MIT
"""Independently replay retained raw bus/PTY and process receipts; no actors."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import observation as O

CASES = ('foreground-success', 'foreground-exit7', 'watched-success-duplicate-registration',
         'short-and-watch-refusals', 'excluded-command', 'invalid-user-threshold', 'disabled-module',
         'repeat-source-custom-bindings-unrelated-hook', 'existing-namespace-yields',
         'missing-bus-variable', 'noninteractive-noop', 'unavailable-manager-bounded-caller')
POSITIVE = {'foreground-success': (0, 'Foreground command'),
            'foreground-exit7': (7, 'Foreground command'),
            'watched-success-duplicate-registration': (0, 'Watched job'),
            'repeat-source-custom-bindings-unrelated-hook': (0, 'Foreground command')}


def validate(value):
    O.need(value['status'] == 'PASS_PRIVATE_REAL_MAKO_TRIAL' and not value['errors'] and
           [row['name'] for row in value['cases']] == list(CASES), 'complete ordered twelve-case trial required')
    O.need(value['package_context'] in ('archive-staged', 'alpm-installed') and
           value['hardware'] == 'NOT_RUN' and value['release'] == 'NOT_ADMITTED' and
           value['visual_display'] == 'NOT_QUALIFIED', 'evidence boundary differs')
    daemon = value['daemon']
    O.need(type(daemon['pid']) is int and daemon['pid'] > 0 and daemon['uid'] > 0 and
           re.fullmatch(r':[0-9]+\.[0-9]+', daemon['owner']) and
           re.fullmatch('[0-9a-f]{64}', daemon['sha256']), 'actual selected daemon identity required')
    for row in value['cases']:
        O.need(row['status'] == 'PASS' and row['fish']['exit'] == 0, 'normal case/Fish completion required')
        pty = base64.b64decode(row['fish']['pty_base64'], validate=True)
        O.need(len(pty) == row['fish']['pty_bytes'] and hashlib.sha256(pty).hexdigest() == row['fish']['pty_sha256'],
               'original PTY byte binding differs')
        transport = row['monitor']
        raw = base64.b64decode(transport['raw_base64'], validate=True)
        O.need(len(raw) == transport['bytes'] and hashlib.sha256(raw).hexdigest() == transport['sha256'] and
               transport['exit'] in (0, -2) and transport['stop_signal'] == 'SIGINT', 'raw monitor byte/stop binding differs')
        rows = O.messages(raw)
        calls = [r for r in rows if r.get('type') == 'method_call' and r.get('member') == 'Notify']
        O.need(row['notify_calls'] == len(calls), 'actual Notify count differs')
        if row['name'] in POSITIVE:
            outcome, kind = POSITIVE[row['name']]
            wire = O.notify(rows, daemon['owner'], outcome, kind)
            O.need(wire == row['wire'] and O.listing([row['daemon_listing']], wire) == row['daemon_listing'],
                   'real wire reply/Mako list join differs')
            closed = O.closure_facts(raw, wire)
            O.need(closed == row['closed'] and len(closed['matching_closed_signals']) == 1 and
                   closed['matching_closed_signals'][0]['signal']['payload']['data'] == [wire['id'], 1],
                   'actual Mako reason1 expiry differs')
            if row['name'].startswith('foreground-'):
                O.need(('FDM_CONT_'+str(outcome)).encode() in pty and row['caller_status'] == outcome,
                       'actual foreground caller continuation missing')
            if kind == 'Watched job':
                import fish_terminal as F
                F.verify_background(row['caller']['watch'], row['caller']['pid'], pty,
                                    row['fish']['watch_retirement'])
        else:
            O.need(not calls and 'wire' not in row, 'suppressed/refused case has a Notify')
    for actor in ('mako', 'bus', 'sway'):
        matches = [row for row in value['cleanup'] if row.get('name') == actor]
        O.need(len(matches) == 1 and matches[0]['exit'] == 0 and matches[0]['group_absent'] is True,
               'normal owned actor retirement differs')
    O.need(any(row.get('name') == 'private-runtime-nodes' and row.get('empty') is True
               for row in value['cleanup']), 'private socket files not retired')
    return dict(status='PASS_INDEPENDENT_RAW_REPLAY', cases=len(CASES),
                real_notifications=len(POSITIVE), package_context=value['package_context'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('work', type=Path)
    args = parser.parse_args()
    result = json.loads((args.work/'result.json').read_bytes())
    summary = validate(result)
    outer = json.loads((args.work/'outer.json').read_bytes())
    O.need(outer['exit'] == 0 and outer['process_group_absent'] is True, 'outer namespace/process group remained')
    print(json.dumps(summary, sort_keys=True))


if __name__ == '__main__':
    main()
