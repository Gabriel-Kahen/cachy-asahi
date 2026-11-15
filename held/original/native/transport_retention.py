# SPDX-License-Identifier: MIT
"""Bounded original canonical Git failure DATA. No actors, tracing, or retries."""
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import secrets
import urllib.parse

PUBLIC = 'https://github.com/Gabriel-Kahen/cachy-asahi.git'
SOURCE = 'ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad'
PROFILE = '4089fd798849cafda23d03c0dd95ac896a83fd63ad21e331ae420c147535586c'
NETWORK = {'metadata_fetch', 'required_blobs_fetch'}
PHASES = NETWORK | {'setup', 'metadata_proof', 'complete_object_proof', 'all_required_materialization', 'final_namespace_proof'}
LOG_CAP = 4*1024**2
WINDOW = 64*1024
RECEIPT_CAP = 8*1024**2
OUTPUT_CAP = 1024**2
PRIVATE = re.compile(br'-----BEGIN|PRIVATE KEY|OPENSSH PRIVATE|BEGIN PGP PRIVATE|ssh-(?:rsa|ed25519)|ecdsa-sha2-|(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]+|authorization\s*:\s*(?:bearer|token)|(?:access[_-]?token|password|secret)\s*[=:]|CACHY_(?:OLD_FOUR|RETAINED_)|PRIVATE_KEY|(?:_TOKEN|_SECRET|_PASSWORD)\b|https?://[^\s/]*@|https?://[^\s]*[?#]', re.I)
SUPERVISION = {'exit','reaped','ownership','timeout','signals','output_complete','group_census','error','seconds','passed'}


class Guard(ValueError):
    pass


def need(ok, code):
    if not ok:raise Guard(code)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def wire(value):return (json.dumps(value,sort_keys=True,ensure_ascii=True,separators=(',',':'),allow_nan=False)+'\n').encode('ascii')


def public(raw):
    need(type(raw) is bytes and not PRIVATE.search(raw), 'PRIVATE_TRANSPORT_DATA_REFUSED')
    text=raw.decode('utf-8')
    need(not any(ord(c)<32 and c not in '\n\r\t' or ord(c)==127 for c in text),'CONTROL_TRANSPORT_DATA_REFUSED')
    return text


def logical(path):
    path=Path(path)
    need(path.is_absolute() and '..' not in path.parts and not str(path).startswith('//'),'TRANSPORT_PATH_REFUSED')
    public(str(path).encode());return path


def binding(own,map_hash):
    need(type(own) is dict and set(own)=={'source','ref','run','attempt','token'}
        and type(own['source']) is str and re.fullmatch('[0-9a-f]{40}',own['source'])
        and type(own['ref']) is str and re.fullmatch(r'refs/heads/codex/[A-Za-z0-9._/-]{1,200}',own['ref'])
        and '..' not in own['ref'] and '//' not in own['ref'] and not own['ref'].endswith('/')
        and type(own['run']) is str and re.fullmatch('[1-9][0-9]{0,19}',own['run'])
        and type(own['attempt']) is int and own['attempt']==1
        and own['token']==hashlib.sha256((own['source']+':'+own['ref']+':'+own['run']).encode()).hexdigest()[:24]
        and type(map_hash) is str and re.fullmatch('[0-9a-f]{64}',map_hash),'TRANSPORT_BINDING_REFUSED')
    public(wire(own))


def identity(info):return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


@contextmanager
def directory(path):
    path=logical(path);fds=[];parts=[]
    try:
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC);fds.append(fd)
        for part in path.parts[1:]:
            parent=fd;fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            fds.append(fd);parts.append((parent,part,fd))
        info=os.fstat(fd);need(info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o700,'PRIVATE_TRANSPORT_DIRECTORY_REQUIRED')
        yield fd
        for parent,part,child in parts:
            a=os.stat(part,dir_fd=parent,follow_symlinks=False);b=os.fstat(child)
            need((a.st_dev,a.st_ino,a.st_mode,a.st_uid)==(b.st_dev,b.st_ino,b.st_mode,b.st_uid),'TRANSPORT_DIRECTORY_CHANGED')
    finally:
        for fd in reversed(fds):os.close(fd)


def read_file(path,cap):
    path=logical(path)
    with directory(path.parent) as parent:
        info=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
        need(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1
             and stat.S_IMODE(info.st_mode)==0o600 and 0<=info.st_size<=cap,'BOUNDED_ORDINARY_TRANSPORT_FILE_REQUIRED')
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
        try:
            need(identity(os.fstat(fd))==identity(info),'TRANSPORT_FILE_CHANGED');chunks=[];size=0
            while True:
                raw=os.read(fd,min(1024**2,cap+1-size))
                if not raw:break
                chunks.append(raw);size+=len(raw);need(size<=cap,'TRANSPORT_FILE_CAP')
            need(identity(os.fstat(fd))==identity(info)==identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False)),'TRANSPORT_FILE_CHANGED')
            return b''.join(chunks)
        finally:os.close(fd)

def _load(raw):
    def pairs(rows):
        result={}
        for key,value in rows:
            need(key not in result,'DUPLICATE_TRANSPORT_JSON_KEY');result[key]=value
        return result
    return json.loads(raw.decode('utf-8'),object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(Guard('NONFINITE_TRANSPORT_JSON')))


def _typed_pin(value,cap):
    need(type(value) is dict and set(value)=={'bytes','sha256'} and type(value['bytes']) is int
         and 0<=value['bytes']<=cap and type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}',value['sha256']),'TRANSPORT_PIN_REFUSED')


def _error(error):
    try:
        name=type(error).__name__;text=str(error);raw=text.encode('utf-8')
        need(re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,127}',name) and len(raw)<=16*1024,'TRANSPORT_ERROR_CAP');public(raw);public(name.encode())
        return dict(status='RETAINED',type=name,message=text[:2048],original_message_pin=pin(raw),truncated=len(text)>2048)
    except BaseException:return dict(status='REFUSED',code='ORIGINAL_ERROR_TEXT_UNAVAILABLE_OR_PRIVATE')


def _prefix(carrier,fixture):
    values=['/usr/bin/git','--no-replace-objects']
    for item in ('credential.helper=','http.extraHeader=','http.sslVerify=true','http.followRedirects=false','http.proxy=',
                 'core.hooksPath=/dev/null','core.attributesFile=/dev/null','core.fsmonitor=false','gc.auto=0',
                 'maintenance.auto=false','fetch.writeCommitGraph=false','protocol.allow=never',
                 'protocol.'+('file' if fixture else 'https')+'.allow=always'):values+=['-c',item]
    return values


def _argv(row,report,carrier):
    argv=row.get('argv');need(type(argv) is list and 0<len(argv)<=1200 and all(type(v) is str and len(v)<=4096 for v in argv),'TRANSPORT_ARGV_REFUSED')
    for value in argv:public(value.encode())
    base=_prefix(carrier,report['fixture']);phase=row['phase'];source=report['source']
    if phase=='setup':
        need(argv==base+['init','--bare','--object-format=sha1','--template=',str(carrier/'.git')],'TRANSPORT_SETUP_COMMAND_REFUSED');return
    prefix=base+['--git-dir='+str(carrier/'.git')]
    need(argv[:len(prefix)]==prefix,'TRANSPORT_GIT_PREFIX_REFUSED');tail=argv[len(prefix):]
    if phase in NETWORK:
        fixed=['-c','http.lowSpeedLimit=65536','-c','http.lowSpeedTime=60','-c','fetch.fsckObjects=true','fetch','--progress','--no-tags','--no-recurse-submodules','--no-auto-maintenance','--filter=blob:none']
        fixed+=['--depth=1'] if phase=='metadata_fetch' else ['--no-write-fetch-head']
        need(tail[:len(fixed)+1]==fixed+[report['url']],'TRANSPORT_FETCH_COMMAND_REFUSED');wants=tail[len(fixed)+1:]
        if phase=='metadata_fetch':need(wants==[source],'TRANSPORT_METADATA_WANT_REFUSED')
        else:
            need(type(report.get('required_blob_oids')) is list and wants==report['required_blob_oids']
                 and 0<len(wants)<=1154 and wants==sorted(set(wants)) and all(re.fullmatch('[0-9a-f]{40}',v) for v in wants),'TRANSPORT_REQUIRED_WANTS_REFUSED')
    elif phase=='all_required_materialization':
        need(len(tail)==3 and tail[:2]==['cat-file','blob'] and re.fullmatch('[0-9a-f]{40}',tail[2]),'TRANSPORT_MATERIAL_COMMAND_REFUSED')
    else:
        allowed=[['rev-parse','--verify','FETCH_HEAD'],['cat-file','commit',source],['ls-tree','-rz','--full-tree',source],
            ['cat-file','--batch-all-objects','--batch-check=%(objectname) %(objecttype)'],['update-ref','--no-deref','HEAD',source],['rev-parse','--verify','HEAD']]
        need(tail in allowed,'TRANSPORT_LOCAL_COMMAND_REFUSED')


def _supervision(value):
    need(type(value) is dict and set(value)==SUPERVISION and (value['exit'] is None or type(value['exit']) is int and -255<=value['exit']<=255)
        and all(type(value[k]) is bool for k in ('reaped','timeout','output_complete','passed'))
        and value['ownership'] in {'OWNED','REAPED','UNKNOWN'}
        and value['group_census'] in {'NOT_OBSERVED','RESERVED_LEADER_ONLY','RESERVED_MEMBERS_REMAIN','UNKNOWN','PRESENT_OR_REUSED','EMPTY_ONCE','EMPTY_TWICE'}
        and type(value['signals']) is list and len(value['signals'])<=4 and all(v in {'SIGTERM','SIGKILL','SIGINT','SIGHUP'} for v in value['signals'])
        and type(value['seconds']) in (int,float) and math.isfinite(value['seconds']) and value['seconds']>=0
        and (value['error'] is None or type(value['error']) is str and len(value['error'])<=4096),'TRANSPORT_SUPERVISION_REFUSED')
    if value['error'] is not None:public(value['error'].encode())


def _header(work,report):
    need(type(report) is dict and type(report.get('data_path')) is str,'ORIGINAL_CANONICAL_RECEIPT_REFUSED')
    evidence=work/'retained-transport-evidence';carrier=logical(report['data_path'])
    need(type(report) is dict and report.get('schema_version')==1 and type(report['schema_version']) is int
         and report.get('status') in {'FAIL_RETAINED_GIT_DATA','PASS_EXACT_RETAINED_GIT_DATA_ONLY'}
         and report.get('destination')==str(evidence) and type(report.get('fixture')) is bool
         and type(report.get('source')) is str and re.fullmatch('[0-9a-f]{40}',report['source'])
         and type(report.get('profile_sha256')) is str and re.fullmatch('[0-9a-f]{64}',report['profile_sha256'])
         and report.get('retry') is False and report.get('source_code_execution')=='NOT_RUN','ORIGINAL_CANONICAL_RECEIPT_REFUSED')
    need(type(report.get('file_count')) is int and 0<report['file_count']<=1154,'ORIGINAL_PROFILE_COUNT_REFUSED')
    policy=report.get('policy');need(type(policy) is dict and set(policy)=={'fetch_seconds','transport_seconds','outer_seconds','reason'}
         and all(type(policy[k]) in (int,float) and math.isfinite(policy[k]) and policy[k]>0 for k in ('fetch_seconds','transport_seconds','outer_seconds'))
         and policy['fetch_seconds']<policy['transport_seconds']<policy['outer_seconds']<=3600
         and type(policy['reason']) is str and 0<len(policy['reason'])<=4096
         and all(ord(c)>=32 for c in policy['reason']),'ORIGINAL_TRANSPORT_POLICY_REFUSED')
    public(policy['reason'].encode())
    url=report.get('url');need(type(url) is str and len(url)<=4096,'TRANSPORT_URL_REFUSED');parsed=urllib.parse.urlsplit(url)
    need(not parsed.query and not parsed.fragment and not parsed.username and not parsed.password,'TRANSPORT_URL_REFUSED');public(url.encode())
    if report['fixture']:
        need(parsed.scheme=='file' and not parsed.netloc and '%' not in parsed.path,'TRANSPORT_FIXTURE_URL_REFUSED');logical(parsed.path)
    else:
        need(url==PUBLIC and report['source']==SOURCE and report['profile_sha256']==PROFILE
             and report.get('file_count')==1154 and carrier==work.parent/'pgo-hosted-retained'
             and [policy[k] for k in ('fetch_seconds','transport_seconds','outer_seconds')]==[400,480,500],'EXACT_NATIVE_CARRIER_REFUSED')
    need(not carrier.is_relative_to(evidence) and not evidence.is_relative_to(carrier),'TRANSPORT_DATA_EVIDENCE_OVERLAP')
    need(report.get('failed_phase') is None or report['failed_phase'] in PHASES,'TRANSPORT_PHASE_REFUSED')
    if 'required_blob_oids' in report:
        wants=report['required_blob_oids'];need(type(wants) is list and 0<len(wants)<=1154 and all(type(v) is str and re.fullmatch('[0-9a-f]{40}',v) for v in wants)
             and wants==sorted(set(wants)),'TRANSPORT_REQUIRED_WANTS_REFUSED')
    return evidence,carrier

def _snapshot(row,report,evidence,carrier):
    required={'number','argv','raw_stdout','raw_stderr','passed','phase','role','evidence_root','data_root'}
    optional={'supervision','stdout_streams','stdout_pin','stderr_pin','stdout_material'}
    need(type(row) is dict and required<=set(row)<=required|optional and type(row['number']) is int
         and 0<=row['number']<1200 and row['phase'] in PHASES and type(row['passed']) is bool
         and row['evidence_root']==str(evidence) and row['data_root']==str(carrier),'ORIGINAL_COMMAND_SCHEMA_REFUSED')
    network=row['phase'] in NETWORK
    need(row['role']==('NETWORK' if network else 'LOCAL_PROOF_OR_MATERIALIZATION'),'ORIGINAL_COMMAND_ROLE_REFUSED')
    stem='logs/%04d'%row['number'];need(row['raw_stderr']==stem+'.stderr','ORIGINAL_STDERR_PATH_REFUSED')
    if network:need(row['raw_stdout']==stem+'.stdout' and 'stdout_material' not in row,'NETWORK_MATERIAL_STDOUT_REFUSED')
    else:need(type(row['raw_stdout']) is str and (row['raw_stdout']==stem+'.stdout' or row['phase']=='all_required_materialization' and row['raw_stdout'].startswith('data/')),'ORIGINAL_STDOUT_PATH_REFUSED')
    if 'stdout_streams' in row:
        need(row['stdout_streams'] in {'STDOUT_AND_STDERR_MERGED_AT_SPAWN','BLOB_STDOUT; SEPARATE_STDERR'}
             and (not network or row['stdout_streams']=='STDOUT_AND_STDERR_MERGED_AT_SPAWN'),'ORIGINAL_CHANNEL_SEMANTICS_REFUSED')
    if 'supervision' in row:_supervision(row['supervision'])
    for channel in ('stdout','stderr'):
        if channel+'_pin' in row:_typed_pin(row[channel+'_pin'],LOG_CAP)
    if 'stdout_material' in row:
        material=row['stdout_material'];need(type(material) is dict and set(material)=={'bytes','sha256','git_blob','mode'}
            and type(material['bytes']) is int and 0<=material['bytes']<=128*1024**2 and type(material['sha256']) is str
            and re.fullmatch('[0-9a-f]{64}',material['sha256']) and type(material['git_blob']) is str
            and re.fullmatch('[0-9a-f]{40}',material['git_blob']) and material['mode'] in (0o644,0o755),'ORIGINAL_MATERIAL_METADATA_REFUSED')
    _argv(row,report,carrier);encoded=wire(row);need(len(encoded)<=256*1024,'ORIGINAL_COMMAND_METADATA_CAP');public(encoded)
    return _load(encoded)


def _stream(evidence,row,field):
    relative='logs/%04d.%s'%(row['number'],'stdout' if field=='raw_stdout' else 'stderr')
    need(row[field]==relative,'ORIGINAL_STREAM_PATH_REFUSED')
    try:raw=read_file(evidence/relative,LOG_CAP)
    except FileNotFoundError:return dict(status='ABSENT',relative=relative,code='ORIGINAL_STREAM_NOT_CREATED')
    except BaseException:return dict(status='REFUSED',relative=relative,code='ORIGINAL_STREAM_FILE_GUARD_REFUSED')
    try:public(raw)
    except BaseException:return dict(status='REFUSED',relative=relative,code='ORIGINAL_STREAM_PRIVACY_OR_ENCODING_REFUSED')
    source_pin=row.get('stdout_pin' if field=='raw_stdout' else 'stderr_pin');original=pin(raw)
    if source_pin is not None and source_pin!=original:return dict(status='REFUSED',relative=relative,code='ORIGINAL_STREAM_PIN_MISMATCH')
    offset=max(0,len(raw)-WINDOW)
    while offset<len(raw) and raw[offset]&0xc0==0x80:offset+=1
    window=raw[offset:]
    return dict(status='RETAINED',relative=relative,original_pin=original,window=dict(offset=offset,complete=offset==0,**pin(window),text=window.decode('utf-8')))


def capture(work,own,map_hash,canonical_receipt,error):
    """Read the exact receipt and selected bounded original streams; no actors."""
    binding(own,map_hash);need(isinstance(error,BaseException),'FAILURE_CONTEXT_REQUIRED');work=logical(work)
    need(work.name=='native-developer-work','FIXED_TRANSPORT_WORK_REQUIRED')
    raw=read_file(work/'retained-transport-evidence/receipt.json',RECEIPT_CAP)
    report=_load(raw);need(report==canonical_receipt,'UNCHANGED_CANONICAL_RECEIPT_REQUIRED');evidence,carrier=_header(work,report)
    rows=report.get('commands');need(type(rows) is list and len(rows)<=1200,'CANONICAL_COMMAND_COUNT_REFUSED')
    chosen=[];network=[]
    for index,row in enumerate(rows):
        need(type(row) is dict and type(row.get('number')) is int and row['number']==index and row.get('phase') in PHASES
             and row.get('role') in {'NETWORK','LOCAL_PROOF_OR_MATERIALIZATION'},'CANONICAL_COMMAND_ORDER_REFUSED')
        if row['role']=='NETWORK' or row['phase'] in NETWORK:
            need(row['phase'] in NETWORK and row['role']=='NETWORK','CANONICAL_NETWORK_ROLE_REFUSED');network.append(row['phase']);chosen.append((row,'NETWORK_STREAMS'))
    need(len(network)<=2 and len(set(network))==len(network),'NETWORK_ROLE_REPLAY_REFUSED')
    if rows and rows[-1]['role']!='NETWORK':chosen.append((rows[-1],'LAST_LOCAL_STDERR_ONLY'))
    commands=[]
    for row,selection in sorted(chosen,key=lambda pair:pair[0]['number']):
        item=dict(number=row['number'],phase=row['phase'],role=row['role'],selection=selection)
        try:original=_snapshot(row,report,evidence,carrier)
        except BaseException:
            commands.append(dict(item,status='REFUSED',code='ORIGINAL_COMMAND_SCHEMA_OR_PRIVACY_REFUSED'));continue
        fields=('raw_stdout','raw_stderr') if selection=='NETWORK_STREAMS' else ('raw_stderr',)
        commands.append(dict(item,status='RETAINED',original_command=original,streams={field:_stream(evidence,row,field) for field in fields}))
    keys=('schema_version','status','fixture','source','url','profile_sha256','destination','data_path','file_count','retry','source_code_execution','policy')
    original={key:report[key] for key in keys};original.update(original_pin=pin(raw),relative='retained-transport-evidence/receipt.json')
    for key in ('failed_phase','required_blob_oids'):
        if key in report:original[key]=report[key]
    value=dict(schema=1,status='RETAINED_GIT_TRANSPORT_FAILURE_DATA_ONLY',binding=own,source_map_sha256=map_hash,work=str(work),
        canonical_receipt=original,commands=commands,original_error=_error(error),retry=False,acceptance=False,
        original_stream_scope='STABLE_BOUNDED_SNAPSHOTS; FRAME_ALONE_DOES_NOT_REVERIFY_WHOLE_ORIGINAL',
        channel_semantics='UNCHANGED_CANONICAL_STDOUT_STREAMS; NO_RECONSTRUCTION',native='NOT_RUN',GPG='NOT_RUN',ALPM='NOT_RUN',physical_M2='NOT_RUN',release='NOT_ADMITTED')
    validate(value,own,map_hash,work);return value

def _validate(value,own,map_hash,work=None):
    """Pure frame validation. Does not authenticate missing original stream bodies."""
    binding(own,map_hash)
    base={'schema','status','binding','source_map_sha256','work','retry','acceptance','native','GPG','ALPM','physical_M2','release'}
    need(type(value) is dict and base<=set(value) and type(value['schema']) is int and value['schema']==1
         and value['binding']==own and value['source_map_sha256']==map_hash and value['retry'] is False and value['acceptance'] is False
         and value['native']==value['GPG']==value['ALPM']==value['physical_M2']=='NOT_RUN' and value['release']=='NOT_ADMITTED','TRANSPORT_DIAGNOSTIC_BINDING_REFUSED')
    actual_work=logical(value['work']);need(actual_work.name=='native-developer-work' and (work is None or actual_work==logical(work)),'TRANSPORT_DIAGNOSTIC_WORK_REFUSED')
    if value['status']=='REFUSED_GIT_TRANSPORT_FAILURE_DATA_GUARD':
        need(set(value)==base|{'reason','original_error'} and value['reason'] in {'ORIGINAL_CANONICAL_TRANSPORT_DATA_UNAVAILABLE_OR_PRIVATE','DIAGNOSTIC_PERSISTENCE_REFUSED'},'FIXED_TRANSPORT_REFUSAL_REQUIRED')
    else:
        need(value['status']=='RETAINED_GIT_TRANSPORT_FAILURE_DATA_ONLY'
             and set(value)==base|{'canonical_receipt','commands','original_error','original_stream_scope','channel_semantics'}
             and value['original_stream_scope']=='STABLE_BOUNDED_SNAPSHOTS; FRAME_ALONE_DOES_NOT_REVERIFY_WHOLE_ORIGINAL'
             and value['channel_semantics']=='UNCHANGED_CANONICAL_STDOUT_STREAMS; NO_RECONSTRUCTION','TRANSPORT_DIAGNOSTIC_SCHEMA_REFUSED')
        report=value['canonical_receipt'];required={'schema_version','status','fixture','source','url','profile_sha256','destination','data_path','file_count','retry','source_code_execution','policy','original_pin','relative'}
        need(type(report) is dict and required<=set(report)<=required|{'failed_phase','required_blob_oids'},'CANONICAL_RECEIPT_FRAME_REFUSED')
        evidence,carrier=_header(actual_work,report)
        _typed_pin(report['original_pin'],RECEIPT_CAP);need(report.get('relative')=='retained-transport-evidence/receipt.json','CANONICAL_RECEIPT_PATH_REFUSED')
        need(type(value['commands']) is list and len(value['commands'])<=3,'SELECTED_TRANSPORT_COMMAND_CAP');seen=set();network=set();local=0
        for item in value['commands']:
            basic={'number','phase','role','selection','status'}
            need(type(item) is dict and basic<=set(item) and type(item['number']) is int and 0<=item['number']<1200
                 and item['number'] not in seen and item['phase'] in PHASES,'SELECTED_TRANSPORT_COMMAND_REFUSED');seen.add(item['number'])
            if item['selection']=='NETWORK_STREAMS':
                need(item['role']=='NETWORK' and item['phase'] in NETWORK and item['phase'] not in network,'SELECTED_NETWORK_ROLE_REFUSED');network.add(item['phase']);fields={'raw_stdout','raw_stderr'}
            else:
                need(item['selection']=='LAST_LOCAL_STDERR_ONLY' and item['role']=='LOCAL_PROOF_OR_MATERIALIZATION' and item['phase'] not in NETWORK,'SELECTED_LOCAL_ROLE_REFUSED');local+=1;fields={'raw_stderr'}
            if item['status']=='REFUSED':
                need(set(item)==basic|{'code'} and item['code']=='ORIGINAL_COMMAND_SCHEMA_OR_PRIVACY_REFUSED','FIXED_COMMAND_REFUSAL_REQUIRED');continue
            need(set(item)==basic|{'original_command','streams'} and item['status']=='RETAINED','ORIGINAL_COMMAND_FRAME_REFUSED')
            row=item['original_command'];_snapshot(row,report,evidence,carrier)
            need(all(row[k]==item[k] for k in ('number','phase','role')) and type(item['streams']) is dict and set(item['streams'])==fields,'ORIGINAL_COMMAND_SELECTION_MISMATCH')
            for field,stream in item['streams'].items():
                need(type(stream) is dict and stream.get('relative')==row[field],'ORIGINAL_STREAM_REFERENCE_REFUSED')
                if stream.get('status') in {'ABSENT','REFUSED'}:
                    codes={'ORIGINAL_STREAM_NOT_CREATED'} if stream['status']=='ABSENT' else {'ORIGINAL_STREAM_FILE_GUARD_REFUSED','ORIGINAL_STREAM_PRIVACY_OR_ENCODING_REFUSED','ORIGINAL_STREAM_PIN_MISMATCH'}
                    need(set(stream)=={'status','relative','code'} and stream['code'] in codes,'FIXED_STREAM_REFUSAL_REQUIRED');continue
                need(set(stream)=={'status','relative','original_pin','window'} and stream['status']=='RETAINED','ORIGINAL_STREAM_WINDOW_REFUSED')
                original=stream['original_pin'];_typed_pin(original,LOG_CAP);window=stream['window']
                need(type(window) is dict and set(window)=={'offset','complete','bytes','sha256','text'} and type(window['text']) is str
                     and type(window['offset']) is int and window['offset']>=0 and type(window['complete']) is bool,'BOUNDED_ORIGINAL_WINDOW_REQUIRED')
                raw=window['text'].encode('utf-8');public(raw);_typed_pin({k:window[k] for k in ('bytes','sha256')},WINDOW)
                expected=max(0,original['bytes']-WINDOW)
                need((window['offset']==0 if expected==0 else expected<=window['offset']<=expected+3)
                     and pin(raw)=={k:window[k] for k in ('bytes','sha256')} and window['offset']+len(raw)==original['bytes']
                     and window['complete'] is (window['offset']==0) and (not window['complete'] or original==pin(raw)),'EXACT_ORIGINAL_SUFFIX_REQUIRED')
                declared=row.get('stdout_pin' if field=='raw_stdout' else 'stderr_pin')
                need(declared is None or declared==original,'ORIGINAL_STREAM_DECLARED_PIN_MISMATCH')
        need(len(network)<=2 and local<=1 and [v['number'] for v in value['commands']]==sorted(seen),'SELECTED_COMMAND_ORDER_REFUSED')
    error=value['original_error']
    need(type(error) is dict,'ORIGINAL_ERROR_RECORD_REQUIRED')
    if error.get('status')=='REFUSED':need(error==dict(status='REFUSED',code='ORIGINAL_ERROR_TEXT_UNAVAILABLE_OR_PRIVATE'),'FIXED_ERROR_REFUSAL_REQUIRED')
    else:
        need(set(error)=={'status','type','message','original_message_pin','truncated'} and error['status']=='RETAINED'
             and type(error['type']) is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,127}',error['type'])
             and type(error['message']) is str and len(error['message'])<=2048 and type(error['truncated']) is bool,'BOUNDED_ORIGINAL_ERROR_REQUIRED')
        public(error['type'].encode());public(error['message'].encode());_typed_pin(error['original_message_pin'],16*1024)
        need((len(error['message'])==2048 and error['original_message_pin']['bytes']>len(error['message'].encode()))
             if error['truncated'] else error['original_message_pin']==pin(error['message'].encode()),'ORIGINAL_ERROR_PIN_MISMATCH')
    need(len(wire(value))<=OUTPUT_CAP,'TRANSPORT_DIAGNOSTIC_OUTPUT_CAP');public(wire(value));return True


def validate(value,own,map_hash,work=None):
    try:return _validate(value,own,map_hash,work)
    except Guard:raise
    except (ValueError,TypeError,KeyError,UnicodeError,OverflowError,RecursionError):
        raise Guard('TRANSPORT_DIAGNOSTIC_FRAME_REFUSED') from None

def publish(work,value):
    """Atomic no-replace publication; no existing evidence is overwritten."""
    raw=wire(value);need(len(raw)<=OUTPUT_CAP,'TRANSPORT_DIAGNOSTIC_OUTPUT_CAP')
    with directory(work) as parent:
        name='.transport-diagnostic-'+secrets.token_hex(12)+'.tmp';fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent);before=os.fstat(fd)
        try:
            os.fchmod(fd,0o600);offset=0
            while offset<len(raw):
                count=os.write(fd,raw[offset:]);need(count>0,'TRANSPORT_DIAGNOSTIC_WRITE_REFUSED');offset+=count
            os.fsync(fd);os.lseek(fd,0,os.SEEK_SET);need(os.read(fd,OUTPUT_CAP+1)==raw,'TRANSPORT_DIAGNOSTIC_WRITE_REFUSED')
            os.link(name,'transport-diagnostic.json',src_dir_fd=parent,dst_dir_fd=parent,follow_symlinks=False)
        finally:
            try:
                current=os.stat(name,dir_fd=parent,follow_symlinks=False)
                if (current.st_dev,current.st_ino)==(before.st_dev,before.st_ino):os.unlink(name,dir_fd=parent)
            finally:os.close(fd)
        os.fsync(parent)
    need(read_file(Path(work)/'transport-diagnostic.json',OUTPUT_CAP)==raw,'TRANSPORT_DIAGNOSTIC_PUBLICATION_REFUSED')


def retain(work,own,map_hash,canonical_receipt,error,emit=print):
    """Failure-only best effort. Never changes the original error or a success."""
    if error is None:return None
    valid=False;actual_work=None
    try:
        binding(own,map_hash);actual_work=logical(work);need(actual_work.name=='native-developer-work','FIXED_TRANSPORT_WORK_REQUIRED');valid=True
        value=capture(actual_work,own,map_hash,canonical_receipt,error)
    except BaseException:
        value=dict(schema=1,status='REFUSED_GIT_TRANSPORT_FAILURE_DATA_GUARD',binding=own if valid else None,
            source_map_sha256=map_hash if valid else None,work=str(actual_work) if valid else None,
            reason='ORIGINAL_CANONICAL_TRANSPORT_DATA_UNAVAILABLE_OR_PRIVATE',original_error=_error(error),retry=False,
            acceptance=False,native='NOT_RUN',GPG='NOT_RUN',ALPM='NOT_RUN',physical_M2='NOT_RUN',release='NOT_ADMITTED')
    if valid:
        try:publish(actual_work,value)
        except BaseException:
            value=dict(schema=1,status='REFUSED_GIT_TRANSPORT_FAILURE_DATA_GUARD',binding=own,source_map_sha256=map_hash,
                work=str(actual_work),reason='DIAGNOSTIC_PERSISTENCE_REFUSED',original_error=_error(error),retry=False,
                acceptance=False,native='NOT_RUN',GPG='NOT_RUN',ALPM='NOT_RUN',physical_M2='NOT_RUN',release='NOT_ADMITTED')
    try:emit('NATIVE_GIT_TRANSPORT_DIAGNOSTIC '+wire(value).decode('ascii').rstrip('\n'),flush=True)
    except BaseException:pass
    return value
