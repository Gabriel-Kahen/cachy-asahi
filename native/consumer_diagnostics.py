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


# Versioned overlay failure scalars. Original consumer capture/privacy functions held.
OVERLAY_MARKER_V1=b'NATIVE_INSTALLED_ALPM_DIAGNOSTIC_V1 '
OVERLAY_PHASES_V1=frozenset(['UNKNOWN', 'PAIR_ENTRY', 'PAIR_SOURCE_VERIFY', 'PAIR_INPUT_CONTRACT', 'PAIR_MAKEPKG_ONE', 'PAIR_MAKEPKG_TWO', 'PAIR_ARCHIVE_ONE', 'PAIR_ARCHIVE_TWO', 'PAIR_COMPARE', 'PAIR_COMPLETE', 'ALPM_ENTRY', 'ALPM_SOURCE_VERIFY', 'ALPM_BASELINE', 'OFFICIAL_GIT_INPUTS', 'ALPM_TEST_KEY', 'ALPM_TEST_FINGERPRINT', 'ALPM_EXPORT_TEST_PUBLIC', 'ALPM_SIGN_ARCHIVE', 'ALPM_UNTRUSTED_CONTROL', 'ALPM_IMPORT_TEST_PUBLIC', 'ALPM_TRUST_MEMBERSHIP', 'ALPM_OWNERTRUST', 'ALPM_VERIFY_TEST_SIGNATURE', 'ALPM_INSTALL', 'ALPM_INSTALLED_INVENTORY', 'ALPM_OWNER_CHECK', 'ALPM_VERSION', 'ALPM_RUNTIME_VERIFY', 'USR_JOURNEYS', 'MOVED_JOURNEYS', 'ALPM_REMOVE', 'ALPM_REMOVED_INVENTORY', 'ALPM_KEY_HOME_RETIREMENT', 'ALPM_AGENT_ABSENCE', 'ALPM_OTHER_STEP', 'ALPM_PRESERVATION', 'ALPM_COMPLETE'])
OVERLAY_CODES_V1=frozenset(['FILE_NOT_FOUND', 'PERMISSION', 'TIMEOUT', 'OS_ERROR', 'VALUE_GUARD', 'RUNTIME_GUARD', 'UNCLASSIFIED'])
BUILD_PREFIX_V1=re.compile(rb'#[1-9][0-9]{0,3} (?:0|[1-9][0-9]{0,4})\.[0-9]{1,6} ')

def overlay_inner_v1(raw,map_hash):
    """Full anchored canonical enum records only; never raw values or excerpts."""
    need(type(raw) is bytes and len(raw)<=LOG_CAP,'bounded original overlay log')
    records=[];bad=False
    for line in raw.split(b'\n'):
        prefix=BUILD_PREFIX_V1.match(line)
        selected=line[prefix.end():] if prefix else line
        if not selected.startswith(OVERLAY_MARKER_V1):continue
        payload=selected[len(OVERLAY_MARKER_V1):]
        if len(records)>=64 or not 0<len(payload)<=4096:bad=True;continue
        try:
            def pairs(items):
                value={}
                for key,item in items:
                    need(key not in value,'duplicate diagnostic field');value[key]=item
                return value
            value=json.loads(payload,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite')))
            need(type(value) is dict and set(value)=={'schema','status','source_map_sha256','phase','error_code'}
                 and type(value['schema']) is int and value['schema']==1
                 and value['status']=='INSTALLED_IMAGE_FAILURE_STAGE_DATA_ONLY_V1'
                 and value['source_map_sha256']==map_hash
                 and type(value['phase']) is str and value['phase'] in OVERLAY_PHASES_V1
                 and type(value['error_code']) is str and value['error_code'] in OVERLAY_CODES_V1
                 and json.dumps(value,sort_keys=True,separators=(',',':')).encode()==payload,'canonical source-bound finite diagnostic')
            records.append(value)
        except Exception:bad=True
    if bad or len(records)>1:return dict(status='REFUSED',phase='UNKNOWN',error_code='UNKNOWN')
    if not records:return dict(status='NOT_OBSERVED',phase='UNKNOWN',error_code='UNKNOWN')
    return dict(status='SOURCE_BOUND_ENUM_ONLY',phase=records[0]['phase'],error_code=records[0]['error_code'])

def capture_overlay_failure_v1(work,own,map_hash,rows,index,operation):
    from safe_diagnostic import check_binding
    check_binding(own,map_hash)
    need(operation in ('source184','installed-v1','installed-alpm-v1') and type(index) is int and 0<=index<=1000 and len(rows)==index+1,'exact failed overlay actor position')
    work=Path(work);row=rows[index];label='org.cachy-asahi.native-developer'
    expected=[*DOCKER,'build','--network=none','--pull=false','--no-cache','--platform=linux/arm64','--tag','native-developer-tools:'+own['token'],'--label',label+'='+own['token'],'--label',label+'.source='+own['source'],'--iidfile',str(work/'overlay/image-id'),str(work/'overlay/context')]
    path=work/'actors'/('%04d.log'%index)
    need(row['argv']==expected and Path(row['log'])==path,'exact owned tools-build command/log')
    actor={name:row.get(name)for name in FIELDS}
    need(actor['status'] in ('PASS','FAIL') and (actor['exit'] is None or type(actor['exit']) is int and -255<=actor['exit']<=255)
         and actor['retirement'] in (None,'REAPED','UNKNOWN')
         and all(actor[n] is None or type(actor[n]) is bool for n in FIELDS if n not in ('status','exit','retirement')),'original canonical actor fields only')
    raw=_ordinary(path,LOG_CAP)
    try:safe_text(raw);privacy='GUARDED_TEXT_NOT_EXPORTED'
    except Exception:privacy='RAW_NOT_EXPORTABLE'
    inner=overlay_inner_v1(raw,map_hash) if operation=='installed-alpm-v1' else dict(status='NOT_OBSERVED',phase='UNKNOWN',error_code='UNKNOWN')
    return dict(schema=1,status='OVERLAY_BUILD_FAILURE_SCALARS_ONLY_V1',binding=own,source_map_sha256=map_hash,
                operation=operation,actor_index=index,actor=actor,original_log_pin=pin(raw),raw_body='NOT_EXPORTED',
                raw_guard=privacy,inner=inner,native='NOT_ADMITTED',physical_M2='NOT_RUN',release='NOT_ADMITTED')

def retain_overlay_failure_v1(work,own,map_hash,rows,index,operation,emit=print):
    from safe_diagnostic import check_binding
    try:check_binding(own,map_hash)
    except Exception:return dict(status='REFUSED_OVERLAY_DIAGNOSTIC_UNBOUND')
    try:value=capture_overlay_failure_v1(work,own,map_hash,rows,index,operation)
    except Exception:
        value=dict(schema=1,status='REFUSED_OVERLAY_BUILD_DIAGNOSTIC_V1',binding=own,source_map_sha256=map_hash,
                   reason='BOUNDED_SOURCE_BOUND_SCALARS_UNAVAILABLE',native='NOT_ADMITTED',physical_M2='NOT_RUN',release='NOT_ADMITTED')
    try:
        raw=json.dumps(value,sort_keys=True,ensure_ascii=True,allow_nan=False).encode();safe_text(raw)
        need(len(raw)<=16384,'finite overlay diagnostic envelope')
    except Exception:return dict(status='REFUSED_OVERLAY_DIAGNOSTIC_EMISSION')
    # Independent sinks: a private disk failure must not suppress direct-log DATA.
    try:save(Path(work)/'overlay-build-diagnostic-v1.json',value)
    except Exception:pass
    try:emit('NATIVE_OVERLAY_BUILD_DIAGNOSTIC_V1 '+raw.decode(),flush=True)
    except Exception:return dict(status='REFUSED_OVERLAY_DIAGNOSTIC_EMISSION')
    return value
