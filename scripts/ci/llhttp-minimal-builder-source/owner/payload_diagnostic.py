# SPDX-License-Identifier: MIT
"""Finite phase and one-way exception diagnostics; never emit exception text."""
import hashlib
import json

PHASES=('entry','launch-data','environment','admission','owner-AS','marker-wait','marker-read',
        'owner-observation','owner-kernel','dispatch-context','daemon-identity','daemon-kernel',
        'socket-identity','readonly-filesystem','held-entry','inner-pair')
DECLARATION=dict(kind='LLHTTP_PAYLOAD_PHASE_HASH_ONLY_V3',phase_ids=list(PHASES),
                 max_record_bytes=512,message_prefix_bytes=8192,raw_message=False,
                 raw_environment=False,raw_paths=False)
CURRENT='entry'
TYPES=frozenset(('ValueError','OSError','FileNotFoundError','PermissionError','TimeoutError',
                 'KeyError','TypeError','RuntimeError','JSONDecodeError','Exception','MemoryError'))

def phase(value):
    global CURRENT
    if value not in PHASES:raise ValueError('fixed diagnostic phase required')
    CURRENT=value

def record(error):
    raw=str(error).encode('utf-8','backslashreplace');prefix=raw[:8192]
    value=dict(kind=DECLARATION['kind'],phase=CURRENT,exception=type(error).__name__ if type(error).__name__ in TYPES else 'OTHER',
               message_bytes=len(raw),message_prefix_bytes=len(prefix),message_prefix_sha256=hashlib.sha256(prefix).hexdigest(),truncated=len(raw)>len(prefix))
    text=json.dumps(value,sort_keys=True,separators=(',',':'))
    if len(('HOLD_PAYLOAD: '+text+'\n').encode())>512:raise ValueError('finite hash-only diagnostic record')
    return 'HOLD_PAYLOAD: '+text
