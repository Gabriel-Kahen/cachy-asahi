# SPDX-License-Identifier: MIT
"""Fresh finite failure DATA after a refused public projection. No tree walks."""
import hashlib
import os
import re
import capsule as C
from consumer_diagnostics import DOCKER, FIELDS, safe_text

CAP = 1024 * 1024
INPUTS = {'meson-diagnostic.json': ('public/meson-diagnostic.json', 512*1024),
          'consumer-diagnostic.json': ('public/consumer-diagnostic.json', 512*1024),
          'build-summary.json': ('public/build-summary.json', 512*1024),
          'projection-refusal.json': ('projection-refusal.json', 32*1024)}


def check_binding(own, map_hash):
    C.need(type(own) is dict and set(own) == {'source','ref','run','attempt','token'}
        and type(own['source']) is str and re.fullmatch('[0-9a-f]{40}', own['source'])
        and type(own['ref']) is str and own['ref'].startswith('refs/heads/codex/')
        and type(own['run']) is str and re.fullmatch('[1-9][0-9]*', own['run'])
        and type(own['attempt']) is int and own['attempt'] == 1
        and own['token'] == hashlib.sha256((own['source']+':'+own['ref']+':'+own['run']).encode()).hexdigest()[:24]
        and type(map_hash) is str and re.fullmatch('[0-9a-f]{64}', map_hash), 'safe diagnostic actual binding required')
    safe_text(C._json(own))


def _pin(value, cap):
    C.need(type(value) is dict and set(value) == {'bytes','sha256'}
        and type(value['bytes']) is int and 0 <= value['bytes'] <= cap
        and type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['sha256']), 'safe diagnostic typed original pin')
    return value


def check_consumer(value, own, map_hash):
    """Only the prior source-qualified bounded original frame, no other receipt."""
    C.need(type(value) is dict and value.get('schema') == 1 and type(value['schema']) is int
        and value.get('binding') == own and value.get('source_map_sha256') == map_hash
        and value.get('native') == 'NOT_ADMITTED' and value.get('physical_M2') == 'NOT_RUN', 'safe original consumer binding')
    C.need(type(value.get('actor_index')) is int and 0 <= value['actor_index'] <= 1000
        and type(value.get('container')) is str and re.fullmatch('[0-9a-f]{64}', value['container']), 'safe original consumer selection')
    common = {'schema','status','binding','source_map_sha256','actor_index','container','native','physical_M2'}
    if value.get('status') == 'REFUSED_CONSUMER_ACTOR_DATA_GUARD':
        C.need(set(value) == common | {'reason'} and value['reason'] == 'ORIGINAL_CONSUMER_DIAGNOSTIC_UNAVAILABLE_OR_PRIVATE', 'fixed consumer refusal metadata')
        safe_text(C._json(value))
        return value
    C.need(value.get('status') == 'ORIGINAL_CONSUMER_ACTOR_DATA_ONLY'
        and set(value) == common | {'argv','actor','original_error','log'}
        and value['argv'] == [*DOCKER,'start','-a',value['container']], 'safe exact original consumer frame')
    actor = value['actor']
    C.need(type(actor) is dict and set(actor) == set(FIELDS) and actor['status'] in ('PASS','FAIL')
        and (actor['exit'] is None or type(actor['exit']) is int and -255 <= actor['exit'] <= 255)
        and actor['retirement'] in (None,'REAPED','UNKNOWN')
        and all(actor[name] is None or type(actor[name]) is bool for name in FIELDS if name not in ('status','exit','retirement')), 'safe finite original actor scalars')
    error = value['original_error']
    C.need(error is None or type(error) is dict and set(error) == {'type','message'}
        and type(error['type']) is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,127}', error['type'])
        and type(error['message']) is str and len(error['message']) <= 2048, 'safe bounded original actor error')
    if error is not None:
        safe_text(error['message'].encode('utf-8'))
    log = value['log']
    C.need(type(log) is dict and set(log) == {'original_pin','offset','complete','bytes','sha256','text'}
        and type(log['text']) is str and type(log['offset']) is int and log['offset'] >= 0
        and type(log['complete']) is bool, 'safe bounded original log frame')
    raw = log['text'].encode('utf-8'); safe_text(raw)
    original = _pin(log['original_pin'], 16*1024**2)
    expected = max(0, original['bytes'] - 64*1024)
    C.need(log['offset'] == 0 if expected == 0 else expected <= log['offset'] <= expected + 3,
        'safe original UTF-8 suffix offset required')
    C.need(len(raw) <= 64*1024 and _pin({k:log[k] for k in ('bytes','sha256')},64*1024) == C.pin(raw)
        and log['offset'] + len(raw) == original['bytes'] and log['complete'] is (log['offset'] == 0)
        and (not log['complete'] or original == C.pin(raw)), 'safe exact original log window pin')
    safe_text(C._json(value))
    return value


def check_leaf(name, value, own, map_hash):
    if name == 'consumer-diagnostic.json':
        return check_consumer(value, own, map_hash)
    if name == 'meson-diagnostic.json':
        from meson_diagnostics import validate_bound
        return validate_bound(value, own, map_hash)
    if name == 'build-summary.json':
        from build_summary import validate_bound
        return validate_bound(value, own, map_hash)
    C.need(name == 'projection-refusal.json', 'fixed safe diagnostic role required')
    C.need(type(value) is dict and set(value) == {'schema','binding','source_map_sha256','diagnostic'}
        and type(value['schema']) is int and value['schema'] == 1 and value['binding'] == own
        and value['source_map_sha256'] == map_hash, 'safe projection refusal binding')
    from privacy_diagnostics import validate_refusal
    return validate_refusal(value['diagnostic'])


def create(work, own, map_hash):
    """Read three fixed optional files; leave original public/projected trees intact."""
    check_binding(own, map_hash)
    work = C._absolute(work); dest = work / 'safe-diagnostic'
    rows = {}; selected = {}
    for name, (relative, limit) in INPUTS.items():
        try:
            raw = C._ordinary(work / relative, limit)
        except FileNotFoundError:
            rows[name] = dict(status='ABSENT', code='SOURCE_DIAGNOSTIC_NOT_PRESENT')
            continue
        except Exception:
            rows[name] = dict(status='REFUSED', code='SOURCE_DIAGNOSTIC_UNAVAILABLE_OR_ALIASED')
            continue
        try:
            value = C._load(raw); check_leaf(name, value, own, map_hash)
        except Exception:
            rows[name] = dict(status='REFUSED', code='SOURCE_DIAGNOSTIC_SCHEMA_OR_PRIVACY_REFUSED')
            continue
        selected[name] = raw
        rows[name] = dict(status='RETAINED', **C.pin(raw))
    authority = dict(schema=1, status='NATIVE_FAILURE_SAFE_DIAGNOSTIC_DATA_ONLY', binding=own,
        source_map_sha256=map_hash, native='NOT_ADMITTED', physical_M2='NOT_RUN', release='NOT_ADMITTED',
        original_public='PRESERVED_UNTRAVERSED', original_projection='PRESERVED_UNTRAVERSED',
        reason='EXISTING_PUBLIC_WITHOUT_COMPLETED_PROJECTION',
        original_result_and_feature_logs='NOT_AVAILABLE_PIN_VERIFICATION_NOT_PERFORMED', files=rows)
    selected['safe-diagnostic.json'] = C._json(authority)
    manifest = dict(schema=1,binding=own,source_map_sha256=map_hash,
        files={name:dict(kind='file',mode=0o600,**C.pin(raw)) for name,raw in selected.items()})
    selected['artifacts.json'] = C._json(manifest)
    C.need(sum(map(len,selected.values())) <= CAP, 'safe diagnostic aggregate cap')
    with C._directory(work, mutable=True) as fd:
        os.mkdir(dest.name, 0o700, dir_fd=fd)  # Fresh fixed sibling; never overwrite.
    for name, raw in selected.items():
        with C._directory(dest, mutable=True) as fd:
            target = os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=fd)
            try:
                os.fchmod(target,0o600)
                offset = 0
                while offset < len(raw):
                    count=os.write(target,raw[offset:]);C.need(count>0,'safe diagnostic write progress');offset+=count
                os.fsync(target)
            finally:
                os.close(target)
        C.need(C._ordinary(dest/name,CAP) == raw, 'safe diagnostic exact copy required')
    return authority
