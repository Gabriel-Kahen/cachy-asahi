# SPDX-License-Identifier: MIT
"""Fresh finite failure DATA after a refused public projection. No tree walks."""
import hashlib
import os
import re
import capsule as C
from consumer_diagnostics import DOCKER, FIELDS, safe_text

CAP = 1024 * 1024
INPUTS = {'consumer-diagnostic.json': ('public/consumer-diagnostic.json', 512*1024),
          'build-summary.json': ('public/build-summary.json', 512*1024),
          'projection-refusal.json': ('projection-refusal.json', 32*1024),
          'developer-failure.json': ('developer-failure.json',32*1024)}


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
    if name == 'developer-failure.json':
        return check_developer(value,own,map_hash)
    if name == 'consumer-diagnostic.json':
        return check_consumer(value, own, map_hash)
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
    """Read four fixed optional files; leave original public/projected trees intact."""
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

# Only source-derived labels are emitted. All other original strings are hashed.
DEVELOPER_PHASES = frozenset(('initialize','build-a','build-b','compare','final-export','cleanup',
    'baseline-inventory','baseline-reasons-explicit','baseline-reasons-dependencies',
    'archive-a','archive-b','generate-test-key','test-primary-fingerprint','export-only-test-public',
    'sign-a','sign-b','untrusted-signature-control','import-only-test-public','trust-key-membership',
    'trust-only-test-primary','verify-a','verify-b','tampered-signature-control','required-signature-config',
    'install','installed-inventory','owner-cachy-asahi-developer-tools','owned-files-cachy-asahi-developer-tools',
    'system-help','system-version','system-verify','system-workflow','system-build-systems','system-debugger','system-python',
    'moved-help','moved-version','moved-verify','moved-workflow','moved-build-systems','moved-debugger','moved-python',
    'remove','removed-inventory','restored-reasons-explicit','restored-reasons-dependencies',
    'cleanup-inventory','cleanup-remove','cleanup-restored-inventory','retire-signing','no-autostart-signing',
    'retire-trust','no-autostart-trust'))
DEVELOPER_TYPES = frozenset(('ValueError','TypeError','KeyError','OSError','FileNotFoundError',
    'FileExistsError','PermissionError','NotADirectoryError','IsADirectoryError','UnicodeDecodeError',
    'TimeoutError','KeyboardInterrupt','Failure','RuntimeError','AttributeError','OverflowError'))
DEVELOPER_STAGES = ('build-a','build-b','compare','sign','install','commands-system','commands-moved','remove','restore','cleanup')
DEVELOPER_CAP = 32*1024

def _hashed_label(value, allowed):
    C.need(type(value) is str and len(value.encode('utf-8'))<=8192,'bounded original diagnostic string')
    return dict(label=value if value in allowed else 'UNLISTED', sha256=hashlib.sha256(value.encode('utf-8')).hexdigest())

def developer_context(raw, own, map_hash):
    """Reduce one fixed image-result DATA leaf; no raw message, argv or log output."""
    check_binding(own,map_hash)
    C.need(type(raw)is bytes and 0<len(raw)<=4*1024**2,'held image-result DATA cap')
    result=C._load(raw)
    C.need(type(result)is dict and type(result.get('schema_version'))is int and result['schema_version']==1
        and result.get('operation')=='developer-tools-alpm-v1' and result.get('source_map_sha256')==map_hash
        and result.get('status')=='FAIL','same-map actual failed image-result only')
    commands=result.get('commands');C.need(type(commands)is list and len(commands)<=160,'held command history bound')
    failure=result.get('first_failure');first=None;command=None
    if failure is not None:
        C.need(type(failure)is dict and set(failure)=={'phase','type','message','command_index'}
            and type(failure['message'])is str and len(failure['message'].encode('utf-8'))<=4096,
            'original first-failure identity fields')
        index=failure['command_index'];C.need(index is None or type(index)is int and -1<=index<160,'original bounded failure index')
        first=dict(identity=C.pin(C._json(failure)),phase=_hashed_label(failure['phase'],DEVELOPER_PHASES),
            error_type=_hashed_label(failure['type'],DEVELOPER_TYPES),message=C.pin(failure['message'].encode('utf-8')),
            command_index=index)
        if type(index)is int and 0<=index<len(commands):
            row=commands[index];C.need(type(row)is dict,'typed selected original command')
            state=row.get('supervision');state=state if type(state)is dict else {}
            code=state.get('exit');code=code if type(code)is int and -255<=code<=255 else None
            command=dict(step=_hashed_label(row.get('step'),DEVELOPER_PHASES),
                success=row.get('success') if type(row.get('success'))is bool else None,
                log=_pin(row.get('log_pin'),1024**2),exit=code,
                retirement=state.get('ownership') if state.get('ownership')in('REAPED','UNKNOWN')else 'UNKNOWN',
                census=state.get('group_census') if state.get('group_census')in('EMPTY_TWICE','UNKNOWN')else 'UNKNOWN',
                reaped=state.get('reaped') if type(state.get('reaped'))is bool else None,
                output_complete=state.get('output_complete') if type(state.get('output_complete'))is bool else None,
                timeout=state.get('timeout') if type(state.get('timeout'))is bool else None)
    stages=result.get('stages');C.need(type(stages)is list and len(stages)<=10 and all(s in DEVELOPER_STAGES for s in stages),'fixed completed stage context')
    cleanup=result.get('cleanup');C.need(type(cleanup)is dict,'source cleanup context object')
    value=dict(schema=1,status='DEVELOPER_FIRST_FAILURE_CONTEXT_DATA_ONLY',binding=own,source_map_sha256=map_hash,
        operation='developer-tools-alpm-v1',component_status='FAIL',original_result=C.pin(raw),
        first_failure=first,selected_command=command,command_count=len(commands),completed_stages=stages,
        cleanup={key:cleanup.get(key) if type(cleanup.get(key))is bool else None for key in
            ('homes_retired','no_sockets','private_directory_absent')},
        original_body_verification='NOT_PERFORMED_UNAVAILABLE_IN_SAFE_CAPSULE',
        raw_message_and_command_output='OMITTED_HASHES_ONLY',native='NOT_ADMITTED',physical_M2='NOT_RUN',release='NOT_ADMITTED')
    check_developer(value,own,map_hash)
    return value

def check_developer(value,own,map_hash):
    """Closed scalar/hash grammar; this cannot validate missing original bodies."""
    check_binding(own,map_hash)
    keys={'schema','status','binding','source_map_sha256','operation','component_status','original_result','first_failure',
        'selected_command','command_count','completed_stages','cleanup','original_body_verification',
        'raw_message_and_command_output','native','physical_M2','release'}
    C.need(type(value)is dict and set(value)==keys and type(value['schema'])is int and value['schema']==1
        and value['status']=='DEVELOPER_FIRST_FAILURE_CONTEXT_DATA_ONLY' and value['binding']==own
        and value['source_map_sha256']==map_hash and value['operation']=='developer-tools-alpm-v1'
        and value['component_status']=='FAIL' and value['native']=='NOT_ADMITTED' and value['physical_M2']=='NOT_RUN'
        and value['release']=='NOT_ADMITTED' and value['original_body_verification']=='NOT_PERFORMED_UNAVAILABLE_IN_SAFE_CAPSULE'
        and value['raw_message_and_command_output']=='OMITTED_HASHES_ONLY','exact failure-DATA-only context')
    _pin(value['original_result'],4*1024**2)
    def label(row,allowed):
        C.need(type(row)is dict and set(row)=={'label','sha256'} and row['label']in allowed|{'UNLISTED'}
            and type(row['sha256'])is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),'closed source label/hash')
        C.need(row['label']=='UNLISTED' or row['sha256']==hashlib.sha256(row['label'].encode('utf-8')).hexdigest(),'known source label/hash identity')
    first=value['first_failure'];command=value['selected_command']
    C.need(type(value['command_count'])is int and 0<=value['command_count']<=160,'held original command count')
    if first is not None:
        C.need(type(first)is dict and set(first)=={'identity','phase','error_type','message','command_index'},'fixed first-failure identity summary')
        _pin(first['identity'],16*1024);_pin(first['message'],4096);label(first['phase'],DEVELOPER_PHASES);label(first['error_type'],DEVELOPER_TYPES)
        index=first['command_index'];C.need(index is None or type(index)is int and -1<=index<160,'original failure index, not a replacement')
    if command is not None:
        C.need(first is not None and type(first['command_index'])is int and 0<=first['command_index']<value['command_count']
            and type(command)is dict and set(command)=={'step','success','log','exit','retirement','census','reaped','output_complete','timeout'},'selected original failing command context')
        label(command['step'],DEVELOPER_PHASES);_pin(command['log'],1024**2)
        C.need(command['exit']is None or type(command['exit'])is int and -255<=command['exit']<=255,'bounded original exit')
        C.need(command['retirement']in('REAPED','UNKNOWN')and command['census']in('EMPTY_TWICE','UNKNOWN')
            and all(command[k]is None or type(command[k])is bool for k in('success','reaped','output_complete','timeout')),'bounded original command scalars')
    C.need(type(value['completed_stages'])is list and len(value['completed_stages'])<=10
        and all(s in DEVELOPER_STAGES for s in value['completed_stages']) and type(value['cleanup'])is dict
        and set(value['cleanup'])=={'homes_retired','no_sockets','private_directory_absent'}
        and all(v is None or type(v)is bool for v in value['cleanup'].values()),'fixed stage/cleanup diagnostic context')
    raw=C._json(value);C.need(len(raw)<=DEVELOPER_CAP,'bounded developer summary');safe_text(raw)
    return value

def retain_developer(work,output,own,map_hash):
    """One fixed pre-projection read; no walks, other actor logs or second actor."""
    try:
        raw=C._ordinary(C._absolute(output)/'journey/developer-tools-alpm-v1/result.json',4*1024**2)
        value=developer_context(raw,own,map_hash);body=C._json(value)
        with C._directory(C._absolute(work),mutable=True)as fd:
            target=os.open('developer-failure.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=fd)
            try:
                os.fchmod(target,0o600)
                with os.fdopen(target,'wb',closefd=False)as stream:stream.write(body);stream.flush();os.fsync(target)
            finally:os.close(target)
        return dict(status='RETAINED_DEVELOPER_FIRST_FAILURE_CONTEXT',**C.pin(body))
    except Exception:
        return dict(status='ABSENT_OR_REFUSED_DEVELOPER_FIRST_FAILURE_CONTEXT')
