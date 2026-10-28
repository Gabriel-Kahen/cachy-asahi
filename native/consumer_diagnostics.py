# SPDX-License-Identifier: MIT
"""Bounded original start-attached actor DATA, emitted before capsule retention."""
import json
from pathlib import Path
import re

from common import need, pin, save
from capsule import _ordinary
from public_projection import PRIVATE_MARKER

DOCKER = ['/usr/bin/docker', '--host=unix:///var/run/docker.sock']
LOG_CAP = 16 * 1024**2
WINDOW_CAP = 64 * 1024
FIELDS = ('status', 'exit', 'natural_exit', 'group_absent', 'retirement',
          'exit_observed_via_waitpid', 'ownership_lost', 'forced_cleanup',
          'leader_held_until_group_inspection')
PRIVATE = (b'-----BEGIN', b'PRIVATE KEY', b'OPENSSH PRIVATE', b'CACHY_OLD_FOUR_',
           b'CACHY_RETAINED_', b'Authorization:', b'authorization:', b'ghp_', b'github_pat_')


def safe_text(raw):
    need(not any(marker in raw for marker in PRIVATE) and not PRIVATE_MARKER.search(raw), 'PRIVATE_MARKER_REFUSED')
    text = raw.decode('utf-8')
    need(not any(ord(c) < 32 and c not in '\n\r\t' for c in text), 'CONTROL_TEXT_REFUSED')
    return text


def capture(work, own, map_hash, rows, index, container, error):
    """No actor calls. Read only the exact indexed original source start log."""
    need(type(index) is int and 0 <= index < len(rows) and len(rows) == index + 1,
         'EXACT_START_ROW_REQUIRED')
    need(re.fullmatch('[0-9a-f]{64}', container or ''), 'EXACT_CONTAINER_REQUIRED')
    row = rows[index]
    argv = [*DOCKER, 'start', '-a', container]
    need(row['argv'] == argv, 'EXACT_START_COMMAND_REQUIRED')
    path = Path(work) / 'actors' / ('%04d.log' % index)
    need(Path(row['log']) == path, 'EXACT_START_LOG_REQUIRED')
    raw = _ordinary(path, LOG_CAP)
    safe_text(raw)  # Validate the whole original before selecting any public window.
    offset = max(0, len(raw) - WINDOW_CAP)
    while offset < len(raw) and raw[offset] & 0xc0 == 0x80:
        offset += 1  # Start the exact suffix at a UTF-8 boundary.
    window = raw[offset:]
    failure = None if error is None else dict(type=type(error).__name__, message=str(error)[:2048])
    if failure is not None:
        safe_text(failure['message'].encode('utf-8'))
    return dict(schema=1, status='ORIGINAL_CONSUMER_ACTOR_DATA_ONLY', binding=own,
        source_map_sha256=map_hash, actor_index=index, container=container, argv=argv,
        actor={name: row.get(name) for name in FIELDS}, original_error=failure,
        log=dict(original_pin=pin(raw), offset=offset, complete=offset == 0,
                 **pin(window), text=window.decode('utf-8')),
        native='NOT_ADMITTED', physical_M2='NOT_RUN')


def retain(work, output, own, map_hash, rows, index, container, error, emit=print):
    """A refused diagnostic is explicit; never replace the original actor error."""
    try:
        value = capture(work, own, map_hash, rows, index, container, error)
    except Exception:
        value = dict(schema=1, status='REFUSED_CONSUMER_ACTOR_DATA_GUARD', binding=own,
            source_map_sha256=map_hash, actor_index=index, container=container,
            reason='ORIGINAL_CONSUMER_DIAGNOSTIC_UNAVAILABLE_OR_PRIVATE',
            native='NOT_ADMITTED', physical_M2='NOT_RUN')
    try:
        save(Path(output) / 'consumer-diagnostic.json', value)
        emit('NATIVE_CONSUMER_DIAGNOSTIC ' + json.dumps(value, ensure_ascii=True, sort_keys=True, allow_nan=False), flush=True)
    except Exception:
        return dict(status='REFUSED_CONSUMER_DIAGNOSTIC_EMISSION')
    return value
