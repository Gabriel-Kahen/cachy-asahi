# SPDX-License-Identifier: MIT
"""Bounded original tools-build failure DATA; never launch or retire actors."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

OPERATION = 'image-tools-alpm-v1'
LOG_CAP = 16 * 1024**2
JSON_CAP = 1024**2
LABEL = 'org.cachy-asahi.native-developer'
DOCKER = ['/usr/bin/docker', '--host=unix:///var/run/docker.sock']
PRIVATE = re.compile(br'-----BEGIN[^\r\n]{0,100}PRIVATE KEY|BEGIN PGP PRIVATE|ssh-(?:rsa|ed25519)|ecdsa-sha2-|(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]+|authorization\s*:\s*(?:bearer|token)|(?:access[_-]?token|password|secret)\s*[=:]|CACHY_(?:OLD_FOUR|RETAINED_BUBBLEWRAP)|PRIVATE_KEY|(?:_TOKEN|_SECRET|_PASSWORD)\b', re.I)
FIELDS = ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')
NAME = 'image-first-failure.json'
LOG = 'image-diagnostics/tools-build.log'


class Guard(ValueError):
    pass


def need(value, code):
    if not value:
        raise Guard(code)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def decode(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'NONFINITE_JSON'))


def directory(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'DIRECTORY_PATH')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def read(path, cap):
    path = Path(path)
    parent = directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= cap, 'ORDINARY_BOUNDED_FILE')
            with os.fdopen(os.dup(fd), 'rb') as stream:
                raw = stream.read(cap + 1)
            after = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            need(len(raw) == before.st_size and all(getattr(before, key) == getattr(os.fstat(fd), key)
                 == getattr(after, key) for key in FIELDS), 'FILE_DRIFT')
            current = directory(path.parent)
            try:
                need((os.fstat(parent).st_dev, os.fstat(parent).st_ino) ==
                     (os.fstat(current).st_dev, os.fstat(current).st_ino), 'DIRECTORY_DRIFT')
            finally:
                os.close(current)
            return raw, stat.S_IMODE(before.st_mode)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def public(raw):
    need(not PRIVATE.search(raw), 'PRIVATE_MARKER_REFUSED')
    text = raw.decode('utf-8')
    need(not any(ord(c) < 32 and c not in '\t\r\n' for c in text), 'CONTROL_TEXT_REFUSED')
    return raw


def binding_check(binding, map_hash):
    need(type(binding) is dict and set(binding) == {'source','ref','run','attempt','token'}, 'BINDING_SCHEMA')
    need(type(binding['source']) is str and re.fullmatch('[0-9a-f]{40}', binding['source'])
         and type(binding['ref']) is str and re.fullmatch(r'refs/heads/codex/[A-Za-z0-9._/-]+', binding['ref'])
         and type(binding['run']) is str and re.fullmatch('[1-9][0-9]*', binding['run'])
         and type(binding['attempt']) is int and binding['attempt'] == 1
         and binding['token'] == hashlib.sha256((binding['source'] + ':' + binding['ref'] + ':' + binding['run']).encode()).hexdigest()[:24]
         and type(map_hash) is str and re.fullmatch('[0-9a-f]{64}', map_hash), 'BINDING_VALUE')
    public(encoded(binding))


def new_file(path, raw):
    path = Path(path)
    parent = directory(path.parent)
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(parent)
    finally:
        os.close(parent)


def capture(work, binding, map_hash, rows, index, error):
    binding_check(binding, map_hash)
    need(error is not None and isinstance(error, BaseException), 'ORIGINAL_ERROR_REQUIRED')
    need(type(rows) is list and type(index) is int and 0 <= index < len(rows)
         and len(rows) == index + 1, 'EXACT_TOOLS_BUILD_ROW_REQUIRED')
    work = Path(work)
    row = rows[index]
    need(type(row) is dict, 'ACTOR_ROW_REQUIRED')
    argv = [*DOCKER, 'build', '--network=none', '--pull=false', '--no-cache', '--platform=linux/arm64',
            '--tag', 'native-developer-tools:' + binding['token'], '--label', LABEL + '=' + binding['token'],
            '--label', LABEL + '.source=' + binding['source'], '--iidfile', str(work/'overlay/image-id'), str(work/'overlay/context')]
    path = work/'actors'/('%04d.log' % index)
    need(row.get('argv') == argv and row.get('log') == str(path), 'EXACT_TOOLS_BUILD_COMMAND_LOG')
    actor_raw = encoded(row)
    need(len(actor_raw) <= JSON_CAP, 'ACTOR_JSON_BOUND')
    public(actor_raw)
    actor = decode(actor_raw)
    need(type(actor.get('status')) is str and actor['status'] in ('FAIL','PASS')
         and type(actor.get('owned_child')) is dict, 'ORIGINAL_SUPERVISION_REQUIRED')
    raw, mode = read(path, LOG_CAP)
    public(raw)
    failure = dict(type=type(error).__name__, message=str(error)[:2048])
    need(re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,127}', failure['type']), 'ERROR_TYPE')
    public(encoded(failure))
    return actor, raw, mode, failure


def retain(work, output, binding, map_hash, rows, index, error):
    """Called before the outer build exception guard; never replace its error."""
    base = dict(schema=1, operation=OPERATION, binding=None, source_map_sha256=None,
        phase='tools-overlay-build', actor_index=index if type(index) is int else None,
        lifecycle='UNKNOWN_NOT_OBSERVED', native='NOT_ACCEPTED', physical_M2='NOT_RUN',
        cleanup=dict(status='PENDING'), actor=None, error=None,
        raw_log=dict(status='UNKNOWN', code='ORIGINAL_LOG_NOT_RETAINED'))
    try:
        binding_check(binding, map_hash)
        base.update(binding=decode(encoded(binding)), source_map_sha256=map_hash)
        output = Path(output)
        if os.path.lexists(output/NAME):
            existing = decode(public(read(output/NAME, JSON_CAP)[0]))
            need(existing.get('binding') == binding and existing.get('source_map_sha256') == map_hash
                 and existing.get('operation') == OPERATION, 'EXISTING_FAILURE_BINDING')
            return existing
        actor, raw, mode, failure = capture(work, binding, map_hash, rows, index, error)
        fd = directory(output)
        try:
            os.mkdir('image-diagnostics', 0o700, dir_fd=fd)
        finally:
            os.close(fd)
        new_file(output/LOG, raw)
        base.update(status='RETAINED_BOUNDED_TOOLS_BUILD_FAILURE_DATA', actor=actor, error=failure,
            raw_log=dict(status='RETAINED', public_path=LOG, source_mode=mode, **pin(raw)))
    except BaseException as refused:
        base.update(status='REFUSED_BOUNDED_TOOLS_BUILD_FAILURE_DATA', guard_code=str(refused) if isinstance(refused, Guard) else 'DIAGNOSTIC_UNAVAILABLE',
                    actor=None, error=None, raw_log=dict(status='REFUSED', code='ORIGINAL_DATA_UNAVAILABLE_OR_PRIVATE'))
    try:
        raw = public(encoded(base))
        need(len(raw) <= JSON_CAP, 'DIAGNOSTIC_JSON_BOUND')
        new_file(Path(output)/NAME, raw)
    except BaseException:
        return dict(status='REFUSED_BOUNDED_TOOLS_BUILD_FAILURE_DATA', guard_code='DIAGNOSTIC_PUBLICATION_UNAVAILABLE',
                    operation=OPERATION, native='NOT_ACCEPTED')
    return base


def finalize(output, cleanup):
    """Append a pin to final original cleanup DATA; do not change raw log bytes."""
    try:
        output = Path(output)
        if not os.path.lexists(output/NAME):
            return dict(status='NO_TOOLS_BUILD_FAILURE_RECORDED')
        raw, _ = read(output/NAME, JSON_CAP)
        value = decode(public(raw))
        need(value.get('operation') == OPERATION and value.get('schema') == 1, 'FIRST_FAILURE_SCHEMA')
        try:
            cleanup_raw, _ = read(output/'cleanup.json', JSON_CAP)
            public(cleanup_raw)
            need(decode(cleanup_raw) == cleanup and type(cleanup) is dict and type(cleanup.get('status')) is str,
                 'EXACT_CLEANUP_DATA_REQUIRED')
            value['cleanup'] = dict(status='BOUND_CLEANUP_DATA_ONLY', path='cleanup.json', result_status=cleanup['status'], **pin(cleanup_raw))
        except BaseException:
            value['cleanup'] = dict(status='UNKNOWN_NOT_ACCEPTED', code='ORIGINAL_CLEANUP_UNAVAILABLE_OR_PRIVATE')
        revised = public(encoded(value))
        need(len(revised) <= JSON_CAP, 'DIAGNOSTIC_JSON_BOUND')
        pending = output/(NAME+'.pending')
        new_file(pending, revised)
        need(read(output/NAME, JSON_CAP)[0] == raw, 'FIRST_FAILURE_DRIFT')
        fd = directory(output)
        try:
            os.replace(pending.name, NAME, src_dir_fd=fd, dst_dir_fd=fd)
            os.fsync(fd)
        finally:
            os.close(fd)
        return value
    except BaseException:
        return dict(status='REFUSED_FIRST_FAILURE_CLEANUP_BINDING', operation=OPERATION, native='NOT_ACCEPTED')


SAFE_CAP = 1024**2
SAFE_LIMITS = {'image-first-failure.json':128*1024, 'image-cleanup.json':512*1024,
               'image-tools-build-tail.json':64*1024, 'consumer-diagnostic.json':128*1024,
               'projection-refusal.json':32*1024}
TAIL_WINDOW = 30*1024
SUP_FIELDS = {'pid','exit','natural_exit','group_absent','leader_held_until_group_inspection',
    'exit_observed_via_waitpid','ownership_lost','retirement','forced_cleanup','cleanup_member_uids',
    'ownership_error','cleanup_error','elapsed_seconds'}


def typed_pin(value, cap):
    need(type(value) is dict and set(value) == {'bytes','sha256'} and type(value['bytes']) is int
         and 0 <= value['bytes'] <= cap and type(value['sha256']) is str
         and re.fullmatch('[0-9a-f]{64}', value['sha256']), 'TYPED_ORIGINAL_PIN')
    return value


def check_failure(value, own, map_hash):
    """Image-only versioned diagnostic schema; never qualifies actor success."""
    binding_check(own,map_hash)
    base={'schema','operation','binding','source_map_sha256','phase','actor_index','lifecycle',
          'native','physical_M2','cleanup','actor','error','raw_log','status'}
    need(type(value) is dict and type(value.get('schema')) is int and value['schema']==1
         and value.get('operation')==OPERATION and value.get('binding')==own
         and value.get('source_map_sha256')==map_hash and value.get('phase')=='tools-overlay-build'
         and value.get('lifecycle')=='UNKNOWN_NOT_OBSERVED' and value.get('native')=='NOT_ACCEPTED'
         and value.get('physical_M2')=='NOT_RUN', 'IMAGE_FAILURE_BINDING')
    index=value['actor_index']
    need(index is None or type(index) is int and 0<=index<=1000,'IMAGE_FAILURE_INDEX')
    cleanup=value['cleanup']
    need(type(cleanup) is dict,'IMAGE_FAILURE_CLEANUP')
    if cleanup.get('status')=='PENDING':
        need(set(cleanup)=={'status'},'IMAGE_FAILURE_CLEANUP')
    elif cleanup.get('status')=='UNKNOWN_NOT_ACCEPTED':
        need(cleanup==dict(status='UNKNOWN_NOT_ACCEPTED',code='ORIGINAL_CLEANUP_UNAVAILABLE_OR_PRIVATE'),'IMAGE_FAILURE_CLEANUP')
    else:
        need(set(cleanup)=={'status','path','result_status','bytes','sha256'}
             and cleanup['status']=='BOUND_CLEANUP_DATA_ONLY' and cleanup['path']=='cleanup.json'
             and type(cleanup['result_status']) is str and 0<len(cleanup['result_status'])<=128,'IMAGE_FAILURE_CLEANUP')
        typed_pin({k:cleanup[k] for k in ('bytes','sha256')},JSON_CAP)
    if value['status']=='REFUSED_BOUNDED_TOOLS_BUILD_FAILURE_DATA':
        need(set(value)==base|{'guard_code'} and type(value['guard_code']) is str
             and re.fullmatch('[A-Z][A-Z0-9_]{0,127}',value['guard_code'])
             and value['actor'] is value['error'] is None
             and value['raw_log']==dict(status='REFUSED',code='ORIGINAL_DATA_UNAVAILABLE_OR_PRIVATE'),'IMAGE_FAILURE_REFUSAL')
    else:
        need(set(value)==base and value['status']=='RETAINED_BOUNDED_TOOLS_BUILD_FAILURE_DATA'
             and type(index) is int,'IMAGE_FAILURE_STATUS')
        actor=value['actor'];need(type(actor) is dict and {'argv','log','status','owned_child'}<=set(actor)
             and set(actor)<={'argv','log','status','owned_child'}|SUP_FIELDS
             and actor['status'] in ('PASS','FAIL') and type(actor['log']) is str,'IMAGE_FAILURE_ACTOR')
        log=Path(actor['log']);work=log.parent.parent
        need(log.is_absolute() and '..' not in log.parts and log.parent.name=='actors'
             and log.name=='%04d.log'%index,'IMAGE_FAILURE_ACTOR_LOG')
        expected=[*DOCKER,'build','--network=none','--pull=false','--no-cache','--platform=linux/arm64',
             '--tag','native-developer-tools:'+own['token'],'--label',LABEL+'='+own['token'],
             '--label',LABEL+'.source='+own['source'],'--iidfile',str(work/'overlay/image-id'),str(work/'overlay/context')]
        need(actor['argv']==expected,'IMAGE_FAILURE_ACTOR_COMMAND')
        child=actor['owned_child'];need(type(child) is dict and set(child)<=SUP_FIELDS,'IMAGE_FAILURE_SUPERVISION')
        for data in (actor,child):
            for key,item in data.items():
                if key not in SUP_FIELDS:continue
                if key=='pid':need(type(item) is int and 0<item<2**31,'IMAGE_FAILURE_SUPERVISION')
                elif key=='exit':need(item is None or type(item) is int and -255<=item<=255,'IMAGE_FAILURE_SUPERVISION')
                elif key=='retirement':need(item in ('REAPED','UNKNOWN'),'IMAGE_FAILURE_SUPERVISION')
                elif key in ('ownership_error','cleanup_error'):need(type(item) is str and len(item)<=2048,'IMAGE_FAILURE_SUPERVISION')
                elif key=='cleanup_member_uids':need(type(item) is list and len(item)<=256 and all(type(uid) is int and 0<=uid<2**32 for uid in item),'IMAGE_FAILURE_SUPERVISION')
                elif key=='elapsed_seconds':need(type(item) in (int,float) and 0<=item<=3602,'IMAGE_FAILURE_SUPERVISION')
                else:need(type(item) is bool,'IMAGE_FAILURE_SUPERVISION')
        need(all(actor[key]==item for key,item in child.items() if key in actor),'IMAGE_FAILURE_SUPERVISION_JOIN')
        error=value['error'];need(type(error) is dict and set(error)=={'type','message'} and type(error['type']) is str
             and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,127}',error['type']) and type(error['message']) is str
             and len(error['message'])<=2048,'IMAGE_FAILURE_ERROR')
        raw=value['raw_log'];need(type(raw) is dict and set(raw)=={'status','public_path','source_mode','bytes','sha256'}
             and raw['status']=='RETAINED' and raw['public_path']==LOG and type(raw['source_mode']) is int
             and 0<=raw['source_mode']<=0o777,'IMAGE_FAILURE_RAW_LOG')
        typed_pin({k:raw[k] for k in ('bytes','sha256')},LOG_CAP)
    public(encoded(value))
    return value


def build_tail(raw, diagnostic_raw, own, map_hash):
    public(raw)
    start=max(0,len(raw)-TAIL_WINDOW)
    while start<len(raw) and raw[start]&0xc0==0x80:start+=1
    window=raw[start:]
    value=dict(schema=1,status='IMAGE_TOOLS_BUILD_LOG_TAIL_DATA_ONLY',operation=OPERATION,binding=own,
        source_map_sha256=map_hash,failure_diagnostic_pin=pin(diagnostic_raw),native='NOT_ADMITTED',physical_M2='NOT_RUN',
        log=dict(original_pin=pin(raw),offset=start,complete=start==0,text=window.decode('utf-8'),**pin(window)))
    body=(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode()
    need(len(body)<=SAFE_LIMITS['image-tools-build-tail.json'],'IMAGE_TAIL_JSON_BOUND')
    return body


def create_safe(work, own, map_hash):
    """Image-specific fixed fallback; historical safe_diagnostic stays byte-held."""
    import safe_diagnostic as prior
    binding_check(own,map_hash)
    need(prior.CAP==SAFE_CAP,'HISTORICAL_SAFE_CAP_HELD')
    work=Path(work);fd=directory(work);os.close(fd)
    dest=work/'safe-diagnostic';rows={};selected={}
    def refused(name,code,status='REFUSED'):
        rows[name]=dict(status=status,code=code,evidence='UNKNOWN')
    def add(name,raw):
        need(len(raw)<=SAFE_LIMITS[name],'IMAGE_SAFE_LEAF_BOUND');public(raw)
        need(sum(map(len,selected.values()))+len(raw)+16384<=SAFE_CAP,'IMAGE_SAFE_AGGREGATE_BOUND')
        selected[name]=raw;rows[name]=dict(status='RETAINED',**pin(raw))
    diagnostic=None
    try:
        diagnostic_raw=read(work/'public'/NAME,SAFE_LIMITS[NAME])[0]
        diagnostic=check_failure(decode(diagnostic_raw),own,map_hash);add(NAME,diagnostic_raw)
    except FileNotFoundError:refused(NAME,'SOURCE_DIAGNOSTIC_NOT_PRESENT','ABSENT')
    except BaseException:refused(NAME,'IMAGE_DIAGNOSTIC_SCHEMA_OR_PRIVACY_REFUSED')
    if NAME in selected and diagnostic['cleanup'].get('status')=='BOUND_CLEANUP_DATA_ONLY':
        try:
            raw=read(work/'public/cleanup.json',SAFE_LIMITS['image-cleanup.json'])[0]
            need(pin(raw)=={k:diagnostic['cleanup'][k] for k in ('bytes','sha256')},'IMAGE_CLEANUP_PIN')
            need(decode(raw).get('status')==diagnostic['cleanup']['result_status'],'IMAGE_CLEANUP_STATUS')
            add('image-cleanup.json',raw)
        except FileNotFoundError:refused('image-cleanup.json','SOURCE_DIAGNOSTIC_NOT_PRESENT','ABSENT')
        except BaseException:refused('image-cleanup.json','IMAGE_CLEANUP_PIN_OR_PRIVACY_REFUSED')
    else:refused('image-cleanup.json','IMAGE_DIAGNOSTIC_CLEANUP_UNBOUND')
    if NAME in selected and diagnostic['raw_log'].get('status')=='RETAINED':
        try:
            raw=read(work/'public'/LOG,LOG_CAP)[0]
            need(pin(raw)=={k:diagnostic['raw_log'][k] for k in ('bytes','sha256')},'IMAGE_BUILD_LOG_PIN')
            add('image-tools-build-tail.json',build_tail(raw,diagnostic_raw,own,map_hash))
        except FileNotFoundError:refused('image-tools-build-tail.json','SOURCE_DIAGNOSTIC_NOT_PRESENT','ABSENT')
        except BaseException:refused('image-tools-build-tail.json','IMAGE_BUILD_LOG_PIN_OR_PRIVACY_REFUSED')
    else:refused('image-tools-build-tail.json','IMAGE_DIAGNOSTIC_BUILD_LOG_UNBOUND')
    for name,relative in [('consumer-diagnostic.json','public/consumer-diagnostic.json'),('projection-refusal.json','projection-refusal.json')]:
        try:
            raw=read(work/relative,SAFE_LIMITS[name])[0]
            prior.check_leaf(name,decode(raw),own,map_hash);add(name,raw)
        except FileNotFoundError:refused(name,'SOURCE_DIAGNOSTIC_NOT_PRESENT','ABSENT')
        except BaseException:refused(name,'SOURCE_DIAGNOSTIC_SCHEMA_OR_PRIVACY_REFUSED')
    authority=dict(schema=1,status='IMAGE_TOOLS_FAILURE_SAFE_DIAGNOSTIC_DATA_ONLY',operation=OPERATION,binding=own,
        source_map_sha256=map_hash,native='NOT_ADMITTED',physical_M2='NOT_RUN',release='NOT_ADMITTED',
        original_public='PRESERVED_UNTRAVERSED',original_projection='PRESERVED_UNTRAVERSED',
        lifecycle='UNKNOWN_NOT_OBSERVED',reason='IMAGE_PUBLIC_WITHOUT_COMPLETED_PROJECTION',files=rows)
    selected['safe-diagnostic.json']=encoded(authority)
    manifest=dict(schema=1,binding=own,source_map_sha256=map_hash,
        files={name:dict(kind='file',mode=0o600,**pin(raw)) for name,raw in selected.items()})
    selected['artifacts.json']=encoded(manifest)
    need(set(rows)==set(SAFE_LIMITS) and sum(map(len,selected.values()))<=SAFE_CAP,'IMAGE_SAFE_FINAL_BOUND')
    fd=directory(work)
    try:os.mkdir(dest.name,0o700,dir_fd=fd)
    finally:os.close(fd)
    for name,raw in selected.items():
        new_file(dest/name,raw)
        need(read(dest/name,SAFE_CAP)[0]==raw,'IMAGE_SAFE_COPY_JOIN')
    return authority
