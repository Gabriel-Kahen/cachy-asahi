# SPDX-License-Identifier: MIT
"""Owned build completion and stopped-container cleanup; no operations on import."""
import json
import re
from common import LABEL, need

DOCKER = ('/usr/bin/docker', '--host=unix:///var/run/docker.sock')


def build_operation(role, command, rows, before):
    row = rows[-1] if len(rows) == before + 1 and rows[-1].get('argv') == list(command) else None
    terminal = type(row) is dict and type(row.get('exit')) is int and 0 <= row['exit'] <= 255 and all(row.get(key) is value for key, value in
        [('natural_exit', True), ('group_absent', True), ('exit_observed_via_waitpid', True),
         ('leader_held_until_group_inspection', True), ('ownership_lost', False), ('forced_cleanup', False)]) \
        and row.get('retirement') == 'REAPED'
    return dict(role=role, terminal=bool(terminal), actor=row)


def retire_created_containers(actor, own, created, base_image, probe_rows, records=None):
    ids = actor.docker('ps', '-aq', '--no-trunc', '--filter', 'label=' + LABEL + '=' + own['token']).split()
    need(len(ids) <= 2 and len(ids) == len(set(ids)), 'finite exact owned container set')
    result = [] if records is None else records
    for ident in ids:
        need(re.fullmatch('[0-9a-f]{64}', ident), 'exact cleanup container ID')
        rows = json.loads(actor.docker('inspect', ident)); inspect_actor = actor.rows[-1]
        need(type(rows) is list and len(rows) == 1, 'sole cleanup inspection')
        row = rows[0]; labels = row['Config']['Labels']
        need(row['Id'] == ident and labels.get(LABEL) == own['token'] and labels.get(LABEL + '.source') == own['source'], 'exact owned cleanup container')
        if ident == created:
            need(row['Name'] == '/developer-' + own['token'], 'source-created developer container')
            creation = dict(kind='developer-id', proof=created)
        else:
            expected = [*DOCKER, 'run', '--name', 'probe-' + own['token'], '--label', LABEL + '=' + own['token'],
                '--label', LABEL + '.source=' + own['source'], '--cpus=1', '--memory=128m', '--pids-limit=32',
                '--rm', '--pull=never', '--network=none', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                '--read-only', '--entrypoint=/bin/cat', base_image, '/builder-packages.lock']
            matches = [item for item in probe_rows if item.get('argv') == expected]
            need(base_image is not None and row['Name'] == '/probe-' + own['token'] and len(matches) == 1
                 and row['Image'] == base_image, 'source-created bounded probe only')
            creation = dict(kind='probe-command', proof=matches[0])
        need(row['State']['Running'] is False, 'running container remains UNKNOWN; no blind force removal')
        entry = dict(container=ident, name=row['Name'], before=row, inspect_actor=inspect_actor,
                     remove_actor=None, creation=creation)
        result.append(entry)
        before = len(actor.rows)
        try:
            actor.docker('rm', ident, timeout=30)
        finally:
            if len(actor.rows) == before + 1:
                entry['remove_actor'] = actor.rows[-1]
    return result
