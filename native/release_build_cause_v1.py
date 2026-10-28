# SPDX-License-Identifier: MIT
"""Finite failed makepkg DATA; no actors and no acceptance authority."""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat

MARKER='RELEASE_BUILD_FIRST_CAUSE_V1 '
MAX_LINE=32*1024
ROW_CAP=16*1024
LOG_CAP=1024*1024
SUFFIX_CAP=2048
PREFIX=Path('/opt/native-release-tools-alpm-v1')
SCOPE=PREFIX/'evidence/journey/release-alpm-v1'
CONFIG=PREFIX/'source/native/release-makepkg-v1.conf'
OPERATION='release-alpm-upgrade-v1'
UNKNOWN='UNKNOWN'
_LOCATION=re.compile(r'https?://[^\s"<>]+|/(?:home|root)/[^\s"<>]+|/tmp/release-tools-test-[^\s"<>]+',re.I)
_ANSI=re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')

def need(ok,why):
    if not ok:raise ValueError(why)

def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def private(raw):
    from release_projection_v1 import PRIVATE_MARKER
    return bool(PRIVATE_MARKER.search(raw))

def _text(raw,cap):
    text=_ANSI.sub('',raw.decode('utf-8','replace'))
    text=_LOCATION.sub('[REDACTED_PATH_OR_URL]',text)
    text=''.join(c if c in '\n\t' or c.isprintable() else '?' for c in text)
    return text.encode('utf-8')[-cap:].decode('utf-8','ignore')

def argv(stage):
    directory=PREFIX/'build-inputs'/stage.removeprefix('build-')
    return ['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','HOME='+str(directory),
        'PKGDEST='+str(directory),'SRCDEST='+str(directory),'BUILDDIR='+str(directory),
        '/usr/bin/makepkg','--cleanbuild','--nodeps','--nosign','--noconfirm','--config',str(CONFIG)]

def _pin(value):
    need(type(value)is dict and set(value)=={'bytes','sha256'} and type(value['bytes'])is int
         and 0<=value['bytes']<=LOG_CAP and type(value['sha256'])is str
         and re.fullmatch('[0-9a-f]{64}',value['sha256']),'bounded pin')

def _row(row,stage):
    keys={'step','argv','cwd','expected','success','log','log_pin','supervision','channels'}
    need(type(row)is dict and set(row)in(keys,keys|{'launch_error'}),'original command fields')
    need(row['step']==stage and row['argv']==argv(stage) and row['cwd']==str(PREFIX/'build-inputs'/stage[6:])
         and type(row['expected'])is int and row['expected']==0 and row['success']is False
         and row['channels']=='stdout+stderr combined in pipe order','exact failed source-owned build command')
    need(type(row['log'])is str and re.fullmatch(r'[0-9]{3}-'+stage+r'\.log',row['log']),'fixed command log role')
    _pin(row['log_pin'])
    if 'launch_error'in row:need(type(row['launch_error'])is str and len(row['launch_error'].encode())<=2048,'bounded launch error')
    s=row['supervision']
    if s is not None:
        need(type(s)is dict and set(s)=={'exit','reaped','ownership','timeout','signals','output_complete','group_census','error','seconds','passed'},'original non-RSS supervision fields')
        need(s['exit']is None or type(s['exit'])is int and -255<=s['exit']<=255,'observed exit only')
        need(all(type(s[k])is bool for k in('reaped','timeout','output_complete','passed')),'observed booleans')
        need(s['ownership']in('OWNED','UNKNOWN','REAPED')and type(s['signals'])is list and len(s['signals'])<=8
             and all(x in('SIGTERM','SIGKILL')for x in s['signals']),'finite supervision ownership/signals')
        need(s['group_census']in('NOT_OBSERVED','RESERVED_LEADER_ONLY','RESERVED_MEMBERS_REMAIN','UNKNOWN','PRESENT_OR_REUSED','EMPTY_ONCE','EMPTY_TWICE'),'observed census')
        need(s['error']is None or type(s['error'])is str and len(s['error'].encode())<=2048,'bounded supervisor error')
        need(type(s['seconds'])in(int,float)and math.isfinite(s['seconds'])and 0<=s['seconds']<=610,'bounded observed time')
    raw=encoded(row);need(len(raw)<=ROW_CAP,'command row cap')
    need(not private(raw)and not _LOCATION.search(raw.decode()),'command privacy refusal')
    return raw

def _read_log(scope,name):
    need(Path(scope)==SCOPE and not any(p.is_symlink()for p in (SCOPE,*SCOPE.parents)),'fixed ordinary scope')
    need(type(name)is str and re.fullmatch(r'[0-9]{3}-build-v[12]\.log',name),'fixed failed build log name')
    path=SCOPE/name;fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<=before.st_size<=LOG_CAP,'ordinary bounded original log')
        raw=bytearray()
        while block:=os.read(fd,min(65536,before.st_size+1-len(raw))):
            raw.extend(block);need(len(raw)<=before.st_size,'log growth refused')
        identity=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))
        need(len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'stable complete original FD/path log')
        return bytes(raw)
    finally:os.close(fd)

def _cleanup(report):
    report=report if type(report)is dict else {}
    source=report.get('cleanup',{});source=source if type(source)is dict else {}
    out={k:source.get(k)if type(source.get(k))is bool else UNKNOWN for k in('homes_retired','no_sockets','private_directory_absent')}
    out.update({k:report.get(k)if type(report.get(k))is bool else UNKNOWN for k in('global_config_unchanged','global_trust_unchanged')})
    failures=source.get('failures');out['failure_types']=UNKNOWN
    if type(failures)is list and len(failures)<=16:
        out['failure_types']=[x if type(x)is str and re.fullmatch(r'(?:[A-Za-z][A-Za-z0-9_+-]{0,63}:[A-Za-z][A-Za-z0-9_]{0,63}|global-policy-drift)',x)else UNKNOWN for x in failures]
    return out

def build(scope,records,report,map_hash,primary):
    value=dict(schema=1,operation=OPERATION,source_map_sha256=map_hash,role='image-stage-release-build',
        status='DIAGNOSTIC_ONLY',stage=UNKNOWN,command=dict(status=UNKNOWN,row=None,pin=None),
        output=dict(status=UNKNOWN,pin=None,suffix=None),observed_exit=UNKNOWN,
        primary=dict(type=UNKNOWN,message=UNKNOWN,message_pin=None),inner_cleanup=_cleanup(report),
        native='NOT_ADMITTED',physical_M2='NOT_RUN',release='NOT_ADMITTED')
    try:
        message=str(primary).encode();kind=type(primary).__name__
        value['primary']=dict(type=kind if re.fullmatch('[A-Za-z][A-Za-z0-9_]{0,63}',kind)else UNKNOWN,
            message=_text(message,1024)if len(message)<=4096 and not private(message)else UNKNOWN,message_pin=pin(message)if len(message)<=LOG_CAP else None)
    except BaseException:pass
    candidates=[r for r in records if type(r)is dict and r.get('step')in('build-v1','build-v2')and r.get('success')is False]if type(records)is list and len(records)<=160 else []
    if len(candidates)==1:
        row=candidates[0];value['stage']=row['step']
        try:
            raw=_row(row,value['stage']);value['command']=dict(status='OBSERVED',row=json.loads(raw),pin=pin(raw))
        except BaseException:value['command']['status']='REFUSED_COMMAND'
        if value['command']['status']=='OBSERVED':
            s=row['supervision'];value['observed_exit']=s['exit']if s is not None and type(s['exit'])is int else UNKNOWN
            try:
                raw=_read_log(scope,row['log']);need(type(raw)is bytes and len(raw)<=LOG_CAP,'whole captured log bound');value['output']['pin']=pin(raw)
                if pin(raw)!=row['log_pin']:value['output']['status']='REFUSED_PIN'
                elif private(raw):value['output']['status']='REFUSED_PRIVACY'
                else:value['output'].update(status='OBSERVED_SUFFIX',suffix=_text(raw,SUFFIX_CAP))
            except BaseException:value['output']=dict(status='UNAVAILABLE_OR_REFUSED_READ',pin=None,suffix=None)
    validate(value,map_hash)
    return value

def validate(value,map_hash):
    keys={'schema','operation','source_map_sha256','role','status','stage','command','output','observed_exit','primary','inner_cleanup','native','physical_M2','release'}
    need(type(value)is dict and set(value)==keys and type(value['schema'])is int and value['schema']==1
         and value['operation']==OPERATION and type(map_hash)is str and re.fullmatch('[0-9a-f]{64}',map_hash)
         and value['source_map_sha256']==map_hash and value['role']=='image-stage-release-build'
         and value['status']=='DIAGNOSTIC_ONLY'and value['stage']in(UNKNOWN,'build-v1','build-v2')
         and value['native']==value['release']=='NOT_ADMITTED'and value['physical_M2']=='NOT_RUN','fixed nonaccepting diagnostic envelope')
    command=value['command'];need(type(command)is dict and set(command)=={'status','row','pin'},'command fields')
    if command['status']=='OBSERVED':
        need(value['stage']!=UNKNOWN,'observed fixed stage');raw=_row(command['row'],value['stage']);need(pin(raw)==command['pin'],'exact original canonical command row pin')
        s=command['row']['supervision'];exit_value=s['exit']if s is not None and type(s['exit'])is int else UNKNOWN
        need(type(value['observed_exit'])is type(exit_value)and value['observed_exit']==exit_value,'observed return crossjoin')
    else:need(command['status']in(UNKNOWN,'REFUSED_COMMAND')and command['row']is command['pin']is None and value['observed_exit']==UNKNOWN,'unavailable/refused command stays unknown')
    out=value['output'];need(type(out)is dict and set(out)=={'status','pin','suffix'},'output fields')
    need(out['status']in(UNKNOWN,'OBSERVED_SUFFIX','REFUSED_PIN','REFUSED_PRIVACY','UNAVAILABLE_OR_REFUSED_READ'),'output availability')
    if out['pin']is not None:_pin(out['pin'])
    if command['status']!='OBSERVED':need(out==dict(status=UNKNOWN,pin=None,suffix=None),'no log DATA without observed fixed command')
    if out['status']in(UNKNOWN,'UNAVAILABLE_OR_REFUSED_READ'):need(out['pin']is None,'unavailable log pin remains unknown')
    if out['status']=='UNAVAILABLE_OR_REFUSED_READ':need(command['status']=='OBSERVED','unavailable read requires observed fixed command')
    if out['status']=='REFUSED_PIN':need(command['status']=='OBSERVED'and out['pin']is not None and out['pin']!=command['row']['log_pin'],'pin mismatch must be observed')
    if out['status']=='REFUSED_PRIVACY':need(command['status']=='OBSERVED'and out['pin']==command['row']['log_pin'],'privacy refusal joins exact original log pin')
    if out['status']=='OBSERVED_SUFFIX':
        need(command['status']=='OBSERVED'and out['pin']==command['row']['log_pin']and type(out['suffix'])is str and len(out['suffix'].encode())<=SUFFIX_CAP and not private(out['suffix'].encode())and not _LOCATION.search(out['suffix']),'bounded sanitized suffix from exact whole log')
    else:need(out['suffix']is None,'refused output carries no text')
    primary=value['primary'];need(type(primary)is dict and set(primary)=={'type','message','message_pin'}and type(primary['type'])is str and re.fullmatch('[A-Za-z][A-Za-z0-9_]{0,63}',primary['type'])and type(primary['message'])is str and len(primary['message'].encode())<=1024 and not private(primary['message'].encode())and not _LOCATION.search(primary['message']),'finite safe original failure')
    if primary['message_pin']is not None:_pin(primary['message_pin'])
    cleanup=value['inner_cleanup'];need(type(cleanup)is dict and set(cleanup)=={'homes_retired','no_sockets','private_directory_absent','global_config_unchanged','global_trust_unchanged','failure_types'},'finite cleanup projection')
    need(all(type(cleanup[k])is bool or cleanup[k]==UNKNOWN for k in cleanup if k!='failure_types'),'observed cleanup booleans only')
    tags=cleanup['failure_types'];need(tags==UNKNOWN or type(tags)is list and len(tags)<=16 and all(type(x)is str and (x==UNKNOWN or re.fullmatch(r'(?:[A-Za-z][A-Za-z0-9_+-]{0,63}:[A-Za-z][A-Za-z0-9_]{0,63}|global-policy-drift)',x))for x in tags),'fixed cleanup failure class tags')
    raw=encoded(value);need(len(MARKER.encode())+len(raw)+1<=MAX_LINE and not private(raw),'complete diagnostic privacy/cap')
    return value

def emit(scope,records,report,map_hash,primary):
    """Failure diagnostics can never replace the original rejection."""
    try:
        value=build(scope,records,report,map_hash,primary)
        print(MARKER+encoded(value).decode(),flush=True)
        return value
    except BaseException:return None

def preserve_primary(primary,action):
    try:result=action()
    except BaseException as error:
        if primary is None:return error
        try:primary.add_note('later cleanup failure: '+type(error).__name__)
        except BaseException:pass
        return primary
    return primary if primary is not None else result
