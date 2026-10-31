# SPDX-License-Identifier: MIT
"""Finite failed build or exact install-v1 DATA; no actors or acceptance."""
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
INSTALL_PRIMARY='command failed or retirement unknown: install-v1'
INSTALL_WORK='[REDACTED_INSTALL_WORK]'
INSTALL_REDACTION=dict(scheme='install-v1-work-root-v1',role='FAILED_INSTALL_V1_ORIGINAL_COMMAND',
    fields=['cwd','argv[2]'],replacement=INSTALL_WORK)
INSTALL_ARCHIVE=str(PREFIX/'build-inputs/v1/cachy-asahi-release-tools-0.1.0-1-any.pkg.tar.zst')
PRIOR_BUILD_ROLE='SOURCE_SUCCESSFUL_BUILD_COMMAND_RETIREMENT_V1'
ABSENCE_OUTPUT=b'gpg-connect-agent: no gpg-agent running in this session\n'
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

def _group_retirement(value):
    """Finite pre-reap DATA only; a snapshot never grants process authority."""
    if value is None:return
    need(type(value)is dict and set(value)in({'phase','reserved_leader','wait_owner_pid','wait_owner_subreaper','member_count','members','truncated'},
            {'phase','reserved_leader','wait_owner_pid','wait_owner_subreaper','member_count','members','truncated','adopted_child'})
         and value['phase']=='PRE_REAP'
         and type(value['wait_owner_pid'])is int and 0<value['wait_owner_pid']<2**31
         and value['wait_owner_subreaper']=='NOT_OBSERVED','fixed pre-reap snapshot schema')
    leader=value['reserved_leader']
    need(type(leader)is dict and set(leader)=={'pid','start_ticks'}
         and type(leader['pid'])is int and 0<leader['pid']<2**31
         and type(leader['start_ticks'])is int and 0<=leader['start_ticks']<2**64,'bounded reserved leader DATA')
    rows=value['members'];count=value['member_count']
    need(type(count)is int and 0<=count<=512 and type(rows)is list and len(rows)<=min(32,count)
         and type(value['truncated'])is bool and value['truncated']is(count>len(rows)),'bounded snapshot count/truncation')
    seen=[]
    for row in rows:
        need(type(row)is dict and set(row)=={'pid','state','group','session','start_ticks','ppid','parent_relation'}
             and type(row['pid'])is int and 0<row['pid']<2**31
             and type(row['start_ticks'])is int and 0<=row['start_ticks']<2**64
             and type(row['state'])is str and row['state']in('R','S','D','Z','T','t','X','x','K','W','P','I')
             and type(row['group'])is int and type(row['session'])is int
             and row['group']==row['session']==leader['pid']
             and type(row['ppid'])is int and 0<=row['ppid']<2**31,'finite original group member DATA')
        relation=('WAIT_OWNER_PID' if row['ppid']==value['wait_owner_pid'] else
            'RESERVED_LEADER_PID' if row['ppid']==leader['pid'] else
            'PID1' if row['ppid']==1 else 'OTHER')
        need(row['parent_relation']==relation,'numeric parent relation DATA is not wait authority')
        seen.append(row['pid'])
    need(seen==sorted(set(seen)),'ordered unique bounded member DATA')
    if 'adopted_child'in value:_adopted_child(value['adopted_child'],value)

def _adopted_child(value,snapshot,positive=False):
    """One owned child's evidence only; PPID alone never grants wait authority."""
    keys={'schema','status','candidate','initial_member_count','initial_scan_complete','waitid',
        'identity_reverified','leader_reserved_before_reap','raw_reap','ownership','target_queries_closed',
        'before_leader_reap','final_scan_complete','final_census','refusal'}
    need(type(value)is dict and set(value)==keys and type(value['schema'])is int and value['schema']==1
        and value['status']in('QUALIFIED_ONE_ADOPTED_CHILD_REAPED','REFUSED_ONE_ADOPTED_CHILD'),'fixed one-child receipt')
    need(type(value['initial_member_count'])is int and 0<=value['initial_member_count']<=512
        and value['initial_scan_complete']is True,'observed complete initial census')
    need(all(type(value[k])is bool for k in('identity_reverified','leader_reserved_before_reap','target_queries_closed','before_leader_reap','final_scan_complete'))
        and value['target_queries_closed']is True and value['before_leader_reap']is True,'closed target queries before leader consuming wait')
    need(value['ownership']in('NOT_ACQUIRED','WNOWAIT_RESERVED','UNKNOWN','REAPED')
        and value['final_census']in('NOT_REACHED','UNKNOWN','RESERVED_LEADER_ONLY','RESERVED_MEMBERS_REMAIN'),'bounded child ownership/census state')
    refusals={'NONE','INELIGIBLE_MEMBER_SET','EXTRA_NOT_OWN_ZOMBIE','LEADER_RESERVATION_UNQUALIFIED','DEADLINE',
        'EXTRA_ECHILD','EXTRA_NOT_TERMINAL','EXTRA_STATUS_MISMATCH','EXTRA_IDENTITY_UNQUALIFIED',
        'EXTRA_RAW_WAIT_UNQUALIFIED','EXTRA_NONZERO','FINAL_CENSUS_UNAVAILABLE','FINAL_NOT_SOLE'}
    need(value['refusal']in refusals,'fixed refusal code')
    candidate=value['candidate'];leader=snapshot['reserved_leader'];owner=snapshot['wait_owner_pid']
    if candidate is not None:
        need(type(candidate)is dict and set(candidate)=={'pid','state','group','session','start_ticks','ppid','parent_relation'}
            and value['initial_member_count']==2 and type(candidate['pid'])is int and 0<candidate['pid']<2**31
            and candidate['pid']!=leader['pid'] and type(candidate['start_ticks'])is int and 0<=candidate['start_ticks']<2**64
            and type(candidate['group'])is int and type(candidate['session'])is int and candidate['group']==candidate['session']==leader['pid']
            and candidate['state']in('R','S','D','Z','T','t','X','x','K','W','P','I')
            and type(candidate['ppid'])is int and 0<=candidate['ppid']<2**31,'exact initial original-group candidate DATA')
        relation=('WAIT_OWNER_PID'if candidate['ppid']==owner else 'RESERVED_LEADER_PID'if candidate['ppid']==leader['pid']else 'PID1'if candidate['ppid']==1 else 'OTHER')
        need(candidate['parent_relation']==relation,'candidate numeric PPID relation')
    wait=value['waitid'];raw=value['raw_reap']
    need(type(wait)is dict and set(wait)=={'observed','pid','code','status'}and type(wait['observed'])is bool,'exact WNOWAIT observation fields')
    need(type(raw)is dict and set(raw)=={'attempted','pid','exit','status_matches'}and type(raw['attempted'])is bool and type(raw['status_matches'])is bool,'exact raw observation fields')
    if wait['observed']:
        need(candidate is not None and candidate['state']=='Z'and candidate['ppid']==owner
            and type(wait['pid'])is int and wait['pid']==candidate['pid']and wait['code']in('CLD_EXITED','CLD_KILLED','CLD_DUMPED')
            and type(wait['status'])is int and 0<=wait['status']<=255 and (wait['code']=='CLD_EXITED'or wait['status']>0),'exact owned terminal WNOWAIT observation')
    else:need(wait==dict(observed=False,pid=None,code='NOT_OBSERVED',status=None),'unobserved status stays unavailable')
    if value['identity_reverified']:need(wait['observed']is True,'identity cannot substitute for WNOWAIT')
    if value['leader_reserved_before_reap']:need(value['identity_reverified']is True,'leader and candidate reverified before consuming')
    if raw['attempted']:
        need(wait['observed']is True and value['identity_reverified']is True and value['leader_reserved_before_reap']is True,'raw wait requires both reserved identities')
        need(raw['pid']is None or type(raw['pid'])is int and 0<=raw['pid']<2**31,'observed raw PID only')
        need(raw['exit']is None or type(raw['exit'])is int and -255<=raw['exit']<=255,'observed raw exit only')
        if raw['exit']is not None:need(raw['pid']==candidate['pid']and value['ownership']=='REAPED','exact consumed candidate')
    else:need(raw==dict(attempted=False,pid=None,exit=None,status_matches=False),'no invented consuming wait')
    expected=wait['status']if wait['code']=='CLD_EXITED'else -wait['status']if wait['observed']else None
    matches=bool(wait['observed']and raw['attempted']and raw['pid']==candidate['pid']and type(raw['exit'])is int and raw['exit']==expected)
    need(raw['status_matches']is matches,'raw/reserved status crossjoin')
    if value['ownership']=='REAPED':need(raw['attempted']is True and raw['pid']==candidate['pid'],'reaped ownership requires exact consuming wait')
    if value['final_scan_complete']:need(value['ownership']=='REAPED'and raw['exit']==0 and raw['status_matches']is True,'fresh final scan follows qualified zero reap')
    if value['status']=='QUALIFIED_ONE_ADOPTED_CHILD_REAPED':
        need(value['initial_member_count']==2 and wait['observed']is True and wait['code']=='CLD_EXITED'and wait['status']==0
            and value['identity_reverified']is True and value['leader_reserved_before_reap']is True
            and raw['attempted']is True and raw['pid']==candidate['pid']and type(raw['exit'])is int and raw['exit']==0
            and raw['status_matches']is True and value['ownership']=='REAPED'and value['final_scan_complete']is True
            and value['final_census']=='RESERVED_LEADER_ONLY'and value['refusal']=='NONE'
            and snapshot['member_count']==1 and snapshot['truncated']is False and len(snapshot['members'])==1
            and snapshot['members'][0]['pid']==leader['pid']and snapshot['members'][0]['start_ticks']==leader['start_ticks']
            and snapshot['members'][0]['state']in('Z','X'),'qualified zero adopted reap plus fresh sole-leader census required')
    else:need(value['refusal']!='NONE','refused receipt cannot claim qualification')
    if positive:need(value['status']=='QUALIFIED_ONE_ADOPTED_CHILD_REAPED','positive reader requires qualified adopted-child receipt')
    return value

def _supervision(s):
    if s is not None:
        need(type(s)is dict and set(s)in({'exit','reaped','ownership','timeout','signals','output_complete','group_census','error','seconds','passed'},{'exit','reaped','ownership','timeout','signals','output_complete','group_census','error','seconds','passed','group_retirement'}),'original non-RSS supervision fields')
        need(s['exit']is None or type(s['exit'])is int and -255<=s['exit']<=255,'observed exit only')
        need(all(type(s[k])is bool for k in('reaped','timeout','output_complete','passed')),'observed booleans')
        need(s['ownership']in('OWNED','UNKNOWN','REAPED')and type(s['signals'])is list and len(s['signals'])<=8
             and all(x in('SIGTERM','SIGKILL')for x in s['signals']),'finite supervision ownership/signals')
        need(s['group_census']in('NOT_OBSERVED','RESERVED_LEADER_ONLY','RESERVED_MEMBERS_REMAIN','UNKNOWN','PRESENT_OR_REUSED','EMPTY_ONCE','EMPTY_TWICE'),'observed census')
        need(s['error']is None or type(s['error'])is str and len(s['error'].encode())<=2048,'bounded supervisor error')
        need(type(s['seconds'])in(int,float)and math.isfinite(s['seconds'])and 0<=s['seconds']<=610,'bounded observed time')
        if 'group_retirement'in s:_group_retirement(s['group_retirement'])

def _row(row,stage):
    if stage=='install-v1':return _install_public_row(row)
    keys={'step','argv','cwd','expected','success','log','log_pin','supervision','channels'}
    need(type(row)is dict and set(row)in(keys,keys|{'launch_error'}),'original command fields')
    need(row['step']==stage and row['argv']==argv(stage) and row['cwd']==str(PREFIX/'build-inputs'/stage[6:])
         and type(row['expected'])is int and row['expected']==0 and row['success']is False
         and row['channels']=='stdout+stderr combined in pipe order','exact failed source-owned build command')
    need(type(row['log'])is str and re.fullmatch(r'[0-9]{3}-'+stage+r'\.log',row['log']),'fixed command log role')
    _pin(row['log_pin'])
    if 'launch_error'in row:need(type(row['launch_error'])is str and len(row['launch_error'].encode())<=2048,'bounded launch error')
    _supervision(row['supervision'])
    raw=encoded(row);need(len(raw)<=ROW_CAP,'command row cap')
    need(not private(raw)and not _LOCATION.search(raw.decode()),'command privacy refusal')
    return raw

def _install_metadata(row):
    need(row['step']=='install-v1' and type(row['expected'])is int and row['expected']==0
         and row['success']is False and row['channels']=='stdout+stderr combined in pipe order',
         'exact failed install-v1 command role')
    need(type(row['log'])is str and re.fullmatch(r'[0-9]{3}-install-v1\.log',row['log']),'fixed install-v1 log role')
    _pin(row['log_pin']);_supervision(row['supervision'])
    if 'launch_error'in row:
        need(type(row['launch_error'])is str and len(row['launch_error'].encode())<=2048,'bounded original install launch error')

def _install_argv(work):
    return ['/usr/bin/pacman','--config',work+'/pacman.conf','--noconfirm','--noscriptlet','-U',INSTALL_ARCHIVE]

def _install_public_row(row):
    keys={'step','argv','cwd','expected','success','log','log_pin','supervision','channels','original_row_pin','redaction'}
    need(type(row)is dict and set(row)in(keys,keys|{'launch_error'}),'fixed public install-v1 command fields')
    need(row['cwd']==INSTALL_WORK and row['argv']==_install_argv(INSTALL_WORK)
         and row['redaction']==INSTALL_REDACTION,'exact install-v1 work-root redaction scheme/role')
    _pin(row['original_row_pin']);need(0<row['original_row_pin']['bytes']<=ROW_CAP,'canonical original install row cap')
    _install_metadata(row)
    raw=encoded(row);need(len(raw)<=ROW_CAP,'public install row cap')
    need(not private(raw)and not _LOCATION.search(raw.decode()),'public install command privacy refusal')
    return raw

def _install_row(row):
    """Validate the raw source-owned row before replacing exactly two paths."""
    keys={'step','argv','cwd','expected','success','log','log_pin','supervision','channels'}
    need(type(row)is dict and set(row)in(keys,keys|{'launch_error'}),'original install-v1 command fields')
    work=row['cwd']
    need(type(work)is str and re.fullmatch(r'/tmp/release-tools-test-[A-Za-z0-9_-]{1,64}',work)
         and row['argv']==_install_argv(work),'exact original install-v1 argv/cwd join')
    _install_metadata(row)
    raw=encoded(row);need(len(raw)<=ROW_CAP,'canonical original install row cap')
    public=json.loads(raw)
    public.update(cwd=INSTALL_WORK,original_row_pin=pin(raw),redaction=dict(INSTALL_REDACTION))
    public['argv'][2]=INSTALL_WORK+'/pacman.conf'
    # Other values, including null supervision and optional launch_error, are
    # preserved verbatim. Any remaining private location refuses the whole row.
    return _install_public_row(public)

def _read_log(scope,name):
    need(Path(scope)==SCOPE and not any(p.is_symlink()for p in (SCOPE,*SCOPE.parents)),'fixed ordinary scope')
    need(type(name)is str and re.fullmatch(r'[0-9]{3}-(?:build-v[12]|install-v1|no-autostart-(?:signing|trust))\.log',name),'fixed build/install-v1 or absence-check log role')
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

def _absence_unknown(status=UNKNOWN):
    return dict(status=status,row_pin=None,expected=UNKNOWN,success=UNKNOWN,
        supervision=None,launch_error=None,log_pin=None,
        output=dict(status=UNKNOWN,pin=None,suffix=None,exact_output_match=UNKNOWN))

def _absence_row(row,role):
    step='no-autostart-'+role
    keys={'step','argv','cwd','expected','success','log','log_pin','supervision','channels'}
    need(type(row)is dict and set(row)in(keys,keys|{'launch_error'}),'original absence command fields')
    args=row['argv']
    need(type(args)is list and len(args)==5 and args[:2]==['/usr/bin/gpg-connect-agent','--homedir']
         and args[3:]==['--no-autostart','/bye'] and type(args[2])is str
         and re.fullmatch('/tmp/release-tools-test-[A-Za-z0-9_-]{1,64}/'+role,args[2]),'fixed owned absence command')
    need(row['step']==step and row['cwd']==str(Path(args[2]).parent)
         and type(row['expected'])is int and row['expected']==0 and type(row['success'])is bool
         and row['channels']=='stdout+stderr combined in pipe order','exact original absence command role')
    need(type(row['log'])is str and re.fullmatch(r'[0-9]{3}-'+step+r'\.log',row['log']),'fixed absence log role')
    _pin(row['log_pin']);_supervision(row['supervision'])
    if 'launch_error'in row:need(type(row['launch_error'])is str and len(row['launch_error'].encode())<=2048,'bounded absence launch error')
    raw=encoded(row);need(len(raw)<=ROW_CAP and not private(raw),'absence row cap/privacy refusal')
    return raw

def _absence_checks(scope,records):
    out={role:_absence_unknown()for role in ('signing','trust')}
    if type(records)is not list or len(records)>160:return out
    for role in out:
        rows=[r for r in records if type(r)is dict and r.get('step')=='no-autostart-'+role]
        if not rows:continue
        if len(rows)!=1:out[role]=_absence_unknown('REFUSED_COMMAND');continue
        row=rows[0]
        try:
            raw=_absence_row(row,role);state=row['supervision'];projected=None
            if state is not None:
                projected=json.loads(encoded(state));error=state['error']
                projected['error']=None if error is None else _text(error.encode(),256)
                projected['error_pin']=None if error is None else pin(error.encode())
            launch=row.get('launch_error')
            launch=None if launch is None else dict(pin=pin(launch.encode()),text=_text(launch.encode(),256))
            result=dict(status='OBSERVED',row_pin=pin(raw),expected=row['expected'],success=row['success'],
                supervision=projected,launch_error=launch,log_pin=dict(row['log_pin']),
                output=dict(status=UNKNOWN,pin=None,suffix=None,exact_output_match=UNKNOWN))
            out[role]=result
        except BaseException:out[role]=_absence_unknown('REFUSED_COMMAND');continue
        try:
            raw=_read_log(scope,row['log']);need(type(raw)is bytes and len(raw)<=LOG_CAP,'whole absence output cap')
            result['output']['pin']=pin(raw)
            if pin(raw)!=row['log_pin']:result['output']['status']='REFUSED_PIN'
            elif private(raw):result['output']['status']='REFUSED_PRIVACY'
            else:result['output'].update(status='OBSERVED_SUFFIX',suffix=_text(raw,512),exact_output_match=raw==ABSENCE_OUTPUT)
        except BaseException:result['output']=dict(status='UNAVAILABLE_OR_REFUSED_READ',pin=None,suffix=None,exact_output_match=UNKNOWN)
    return out

def _safe_error(value):
    need(type(value)is dict and set(value)=={'pin','text'},'projected error fields')
    _pin(value['pin']);text=value['text']
    need(type(text)is str and len(text.encode())<=256 and not private(text.encode())
         and not _LOCATION.search(text) and _text(text.encode(),256)==text,'sanitized bounded observed error')

def _validate_absence_checks(checks):
    need(type(checks)is dict and set(checks)=={'signing','trust'},'two fixed absence roles')
    for role,value in checks.items():
        need(type(value)is dict and set(value)=={'status','row_pin','expected','success','supervision','launch_error','log_pin','output'},'absence projection fields')
        if value['status']!='OBSERVED':
            need(value['status']in(UNKNOWN,'REFUSED_COMMAND')and value==_absence_unknown(value['status']),'unavailable absence state remains unknown');continue
        _pin(value['row_pin']);need(value['row_pin']['bytes']<=ROW_CAP,'original absence row cap');_pin(value['log_pin'])
        need(type(value['expected'])is int and value['expected']==0 and type(value['success'])is bool,'observed absence expectation/success only')
        state=value['supervision']
        if state is not None:
            need(type(state)is dict and 'error_pin'in state,'projected original supervision')
            copy=dict(state);error_pin=copy.pop('error_pin');_supervision(copy)
            if state['error']is None:need(error_pin is None,'no invented error pin')
            else:_safe_error(dict(pin=error_pin,text=state['error']))
        if value['launch_error']is not None:_safe_error(value['launch_error'])
        out=value['output'];need(type(out)is dict and set(out)=={'status','pin','suffix','exact_output_match'},'absence output fields')
        need(out['status']in(UNKNOWN,'OBSERVED_SUFFIX','REFUSED_PIN','REFUSED_PRIVACY','UNAVAILABLE_OR_REFUSED_READ'),'absence output status')
        if out['pin']is not None:_pin(out['pin'])
        if out['status']in(UNKNOWN,'UNAVAILABLE_OR_REFUSED_READ'):need(out['pin']is None,'unavailable absence log pin')
        if out['status']=='REFUSED_PIN':need(out['pin']is not None and out['pin']!=value['log_pin'],'observed absence pin mismatch')
        if out['status']=='REFUSED_PRIVACY':need(out['pin']==value['log_pin'],'whole original absence privacy pin')
        if out['status']=='OBSERVED_SUFFIX':
            text=out['suffix'];need(out['pin']==value['log_pin']and type(text)is str and len(text.encode())<=512
                and not private(text.encode())and not _LOCATION.search(text)and _text(text.encode(),512)==text,'bounded sanitized original absence suffix')
            need(type(out['exact_output_match'])is bool,'observed full-byte absence predicate')
            known=out['pin']==pin(ABSENCE_OUTPUT)
            need(out['exact_output_match']is known,'absence predicate joins complete known output pin')
            if known:need(text==ABSENCE_OUTPUT.decode(),'exact known full absence output text')
        else:need(out['suffix']is None and out['exact_output_match']==UNKNOWN,'refused absence output carries no text or predicate')

def _cleanup(report,scope=None,records=None):
    report=report if type(report)is dict else {}
    source=report.get('cleanup',{});source=source if type(source)is dict else {}
    out={k:source.get(k)if type(source.get(k))is bool else UNKNOWN for k in('homes_retired','no_sockets','private_directory_absent')}
    out.update({k:report.get(k)if type(report.get(k))is bool else UNKNOWN for k in('global_config_unchanged','global_trust_unchanged')})
    failures=source.get('failures');out['failure_types']=UNKNOWN
    if type(failures)is list and len(failures)<=16:
        out['failure_types']=[x if type(x)is str and re.fullmatch(r'(?:[A-Za-z][A-Za-z0-9_+-]{0,63}:[A-Za-z][A-Za-z0-9_]{0,63}|global-policy-drift)',x)else UNKNOWN for x in failures]
    out['absence_checks']=_absence_checks(scope,records)
    return out

def _prior_build_unknown(stage):
    return dict(status=UNKNOWN,role=PRIOR_BUILD_ROLE,step=stage,original_row_pin=None,log_pin=None,
        expected=UNKNOWN,success=UNKNOWN,supervision=None,pre_reap_snapshot_observation=UNKNOWN,
        adoption_observation=UNKNOWN,post_reap_group_absence=UNKNOWN)

def _prior_build_supervision(state):
    """Validate retained success observations without inventing post-reap DATA."""
    _supervision(state)
    need(type(state)is dict and type(state['exit'])is int and state['exit']==0
         and state['reaped']is True and state['ownership']=='REAPED' and state['passed']is True
         and state['timeout']is False and state['signals']==[] and state['error']is None
         and state['output_complete']is True and state['group_census']=='RESERVED_LEADER_ONLY'
         and 0<=state['seconds']<300,'exact retained successful prior-build supervision')
    snapshot=state.get('group_retirement')
    if snapshot is None:return UNKNOWN,UNKNOWN
    # _supervision already validates every retained snapshot field. A success
    # summary additionally requires its recorded census to be this one leader.
    leader=snapshot['reserved_leader'];members=snapshot['members']
    need(snapshot['member_count']==1 and len(members)==1 and snapshot['truncated']is False
         and members[0]['pid']==leader['pid'] and members[0]['start_ticks']==leader['start_ticks']
         and members[0]['state']in('Z','X'),'recorded successful build snapshot must be exact sole terminal leader')
    if 'adopted_child'not in snapshot:return 'OBSERVED','NOT_OBSERVED'
    _adopted_child(snapshot['adopted_child'],snapshot,positive=True)
    return 'OBSERVED','OBSERVED'

def _prior_build_row(row,stage):
    keys={'step','argv','cwd','expected','success','log','log_pin','supervision','channels'}
    need(type(row)is dict and set(row)==keys and stage in('build-v1','build-v2')
         and row['step']==stage and row['argv']==argv(stage)
         and row['cwd']==str(PREFIX/'build-inputs'/stage[6:])
         and type(row['expected'])is int and row['expected']==0 and row['success']is True
         and row['channels']=='stdout+stderr combined in pipe order','exact successful source-owned prior-build command')
    need(type(row['log'])is str and re.fullmatch(r'[0-9]{3}-'+stage+r'\.log',row['log']),'fixed successful prior-build log role')
    _pin(row['log_pin']);snapshot,adoption=_prior_build_supervision(row['supervision'])
    raw=encoded(row);need(len(raw)<=ROW_CAP and not private(raw)and not _LOCATION.search(raw.decode()),'original successful prior-build row cap/privacy')
    result=dict(status='OBSERVED',role=PRIOR_BUILD_ROLE,step=stage,original_row_pin=pin(raw),log_pin=dict(row['log_pin']),
        expected=row['expected'],success=row['success'],supervision=json.loads(encoded(row['supervision'])),
        pre_reap_snapshot_observation=snapshot,adoption_observation=adoption,post_reap_group_absence=UNKNOWN)
    public=encoded(result);need(len(public)<=ROW_CAP and not private(public)and not _LOCATION.search(public.decode()),'public prior-build summary cap/privacy')
    return result

def _prior_build_retirement(records,primary):
    result={stage:_prior_build_unknown(stage)for stage in('build-v1','build-v2')}
    try:eligible=type(primary).__name__=='Failure' and str(primary)==INSTALL_PRIMARY
    except BaseException:eligible=False
    if not eligible or type(records)is not list or len(records)>160:return result
    for stage in result:
        rows=[row for row in records if type(row)is dict and row.get('step')==stage]
        if len(rows)!=1:continue
        try:result[stage]=_prior_build_row(rows[0],stage)
        except BaseException:pass
    return result

def _validate_prior_build_retirement(value,primary):
    need(type(value)is dict and set(value)=={'build-v1','build-v2'},'two fixed prior-build retirement roles')
    for stage,item in value.items():
        unknown=_prior_build_unknown(stage)
        need(type(item)is dict and set(item)==set(unknown),'fixed prior-build summary fields')
        if item['status']==UNKNOWN:
            need(item==unknown,'missing/refused prior-build evidence remains wholly unknown');continue
        need(item['status']=='OBSERVED' and item['role']==PRIOR_BUILD_ROLE and item['step']==stage
             and type(item['expected'])is int and item['expected']==0 and item['success']is True
             and item['post_reap_group_absence']==UNKNOWN,'finite prior-build success DATA only')
        need(primary==dict(type='Failure',message=INSTALL_PRIMARY,message_pin=pin(INSTALL_PRIMARY.encode())),
             'prior-build observations require exact original install-v1 primary Failure')
        _pin(item['original_row_pin']);need(0<item['original_row_pin']['bytes']<=ROW_CAP,'original successful prior-build row pin/cap')
        _pin(item['log_pin']);snapshot,adoption=_prior_build_supervision(item['supervision'])
        need(item['pre_reap_snapshot_observation']==snapshot and item['adoption_observation']==adoption,
             'prior-build availability labels join retained snapshot/adoption fields')
        raw=encoded(item);need(len(raw)<=ROW_CAP and not private(raw)and not _LOCATION.search(raw.decode()),'public prior-build summary cap/privacy')

def build(scope,records,report,map_hash,primary):
    value=dict(schema=1,operation=OPERATION,source_map_sha256=map_hash,role='image-stage-release-build',
        status='DIAGNOSTIC_ONLY',stage=UNKNOWN,command=dict(status=UNKNOWN,row=None,pin=None),
        output=dict(status=UNKNOWN,pin=None,suffix=None),observed_exit=UNKNOWN,
        primary=dict(type=UNKNOWN,message=UNKNOWN,message_pin=None),inner_cleanup=_cleanup(report,scope,records),
        prior_build_retirement=_prior_build_retirement(records,primary),
        native='NOT_ADMITTED',physical_M2='NOT_RUN',release='NOT_ADMITTED')
    try:
        message=str(primary).encode();kind=type(primary).__name__
        value['primary']=dict(type=kind if re.fullmatch('[A-Za-z][A-Za-z0-9_]{0,63}',kind)else UNKNOWN,
            message=_text(message,1024)if len(message)<=4096 and not private(message)else UNKNOWN,message_pin=pin(message)if len(message)<=LOG_CAP else None)
    except BaseException:pass
    candidates=[r for r in records if type(r)is dict and r.get('step')in('build-v1','build-v2')and r.get('success')is False]if type(records)is list and len(records)<=160 else []
    if not candidates and type(primary).__name__=='Failure' and str(primary)==INSTALL_PRIMARY:
        candidates=[r for r in records if type(r)is dict and r.get('step')=='install-v1' and r.get('success')is False]if type(records)is list and len(records)<=160 else []
    if len(candidates)==1:
        row=candidates[0];value['stage']=row['step']
        try:
            raw=_install_row(row)if value['stage']=='install-v1'else _row(row,value['stage'])
            value['command']=dict(status='OBSERVED',row=json.loads(raw),pin=pin(raw))
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
    keys={'schema','operation','source_map_sha256','role','status','stage','command','output','observed_exit','primary','inner_cleanup','prior_build_retirement','native','physical_M2','release'}
    need(type(value)is dict and set(value)==keys and type(value['schema'])is int and value['schema']==1
         and value['operation']==OPERATION and type(map_hash)is str and re.fullmatch('[0-9a-f]{64}',map_hash)
         and value['source_map_sha256']==map_hash and value['role']=='image-stage-release-build'
         and value['status']=='DIAGNOSTIC_ONLY'and value['stage']in(UNKNOWN,'build-v1','build-v2','install-v1')
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
    if value['stage']=='install-v1':
        need(primary==dict(type='Failure',message=INSTALL_PRIMARY,message_pin=pin(INSTALL_PRIMARY.encode())),
             'install-v1 diagnostic requires exact original primary Failure')
    _validate_prior_build_retirement(value['prior_build_retirement'],primary)
    cleanup=value['inner_cleanup'];need(type(cleanup)is dict and set(cleanup)=={'homes_retired','no_sockets','private_directory_absent','global_config_unchanged','global_trust_unchanged','failure_types','absence_checks'},'finite cleanup projection')
    need(all(type(cleanup[k])is bool or cleanup[k]==UNKNOWN for k in cleanup if k not in ('failure_types','absence_checks')),'observed cleanup booleans only')
    tags=cleanup['failure_types'];need(tags==UNKNOWN or type(tags)is list and len(tags)<=16 and all(type(x)is str and (x==UNKNOWN or re.fullmatch(r'(?:[A-Za-z][A-Za-z0-9_+-]{0,63}:[A-Za-z][A-Za-z0-9_]{0,63}|global-policy-drift)',x))for x in tags),'fixed cleanup failure class tags')
    _validate_absence_checks(cleanup['absence_checks'])
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
