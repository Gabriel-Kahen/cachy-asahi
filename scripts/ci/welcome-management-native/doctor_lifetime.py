# SPDX-License-Identifier: MIT
"""Doctor's owned lifetime within fixed1080s profiles and the original global1200s service."""
import json
import os
from pathlib import Path
import signal
import select
import stat
import time

LEASE=Path('/run/desktop574-doctor-lifetime')
SERVICE=Path('/run/desktop574-service-lifetime.json')
SECONDS=1080
SERVICE_SECONDS=1200
CAP=8192


def need(value,reason):
    if not value:raise ValueError(reason)


def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()


def read(path,uid,mode):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid==uid and stat.S_IMODE(before.st_mode)==mode and before.st_nlink==1 and 0<before.st_size<=CAP,'private lifetime metadata differs')
        raw=os.read(fd,CAP+1);after=os.fstat(fd)
        need(tuple(before[i] for i in (0,1,2,3,4,5,6,8,9))==tuple(after[i] for i in (0,1,2,3,4,5,6,8,9)) and len(raw)==before.st_size,'lifetime metadata drift')
        return json.loads(raw)
    finally:os.close(fd)


def publish(path,value,mode):
    raw=encoded(value);need(len(raw)<=CAP,'lifetime receipt cap')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
    with os.fdopen(fd,'wb') as stream:os.fchmod(stream.fileno(),mode);stream.write(raw);stream.flush();os.fsync(stream.fileno())


def root_parent(path,uid):
    info=path.parent.lstat();need(stat.S_ISDIR(info.st_mode) and info.st_uid==uid and info.st_mode&0o022==0 and not path.parent.is_symlink(),'nonreplaceable parent lifetime required')


def service(path=SERVICE):
    root_parent(path,0);started=time.monotonic_ns()
    value=dict(schema_version=1,purpose='EXISTING_FIXTURE_SERVICE_1200S',parent_pid=os.getpid(),parent_nonce=os.urandom(16).hex(),started_ns=started,deadline_ns=started+SERVICE_SECONDS*10**9)
    publish(path,value,0o444);return value


def fixed(value,purpose,seconds):
    need(type(value) is dict and set(value)=={'schema_version','purpose','parent_pid','parent_nonce','started_ns','deadline_ns'},'closed fixed service lease required')
    need(value['schema_version']==1 and value['purpose']==purpose and type(value['parent_nonce']) is str and len(value['parent_nonce'])==32 and all(c in '0123456789abcdef' for c in value['parent_nonce']),'fixed parent nonce required')
    need(all(type(value[k]) is int and value[k]>0 for k in ('parent_pid','started_ns','deadline_ns')) and value['deadline_ns']-value['started_ns']==seconds*10**9,'fixed parent lifetime required')


def service_lease(path=SERVICE,uid=0):
    root_parent(path,uid);value=read(path,uid,0o444);fixed(value,'EXISTING_FIXTURE_SERVICE_1200S',SERVICE_SECONDS)
    need(value['started_ns']<=time.monotonic_ns()<value['deadline_ns'],'service lifetime expired');return value


def profile_path(stage):
    need(stage in ('minimal','overlay'),'fixed Doctor profile required');return LEASE.with_name(LEASE.name+'-'+stage+'.json')


def parent(stage,nonce,path=None,service_path=SERVICE):
    path=profile_path(stage) if path is None else path;root_parent(path,0);global_owner=service_lease(service_path)
    started=time.monotonic_ns();value=dict(schema_version=1,purpose='EXISTING_MANAGED_PROFILE_1080S',parent_pid=os.getpid(),parent_nonce=os.urandom(16).hex(),started_ns=started,deadline_ns=started+SECONDS*10**9,stage=stage,profile_nonce=nonce,service=global_owner)
    binding(value,stage,nonce);publish(path,value,0o444);return value


def binding(value,stage,nonce):
    need(type(value) is dict and set(value)=={'schema_version','purpose','parent_pid','parent_nonce','started_ns','deadline_ns','stage','profile_nonce','service'},'closed fixed profile lease required')
    fixed({k:v for k,v in value.items() if k not in ('stage','profile_nonce','service')},'EXISTING_MANAGED_PROFILE_1080S',SECONDS)
    fixed(value['service'],'EXISTING_FIXTURE_SERVICE_1200S',SERVICE_SECONDS)
    need(stage in ('minimal','overlay') and value['stage']==stage and value['profile_nonce']==nonce and type(nonce) is str and len(nonce)==32 and all(c in '0123456789abcdef' for c in nonce),'fixed Doctor profile/nonce differs')
    need(value['parent_pid']==value['service']['parent_pid'] and value['service']['started_ns']<=value['started_ns']<value['service']['deadline_ns'],'profile must belong to original service')


def deadline(value):return min(value['deadline_ns'],value['service']['deadline_ns'])


def lease(stage,nonce,path=None,uid=0):
    path=profile_path(stage) if path is None else path;root_parent(path,uid);value=read(path,uid,0o444);binding(value,stage,nonce)
    need(value['started_ns']<=time.monotonic_ns()<deadline(value),'parent lifetime expired');return value


def start(workspace,stage,nonce,terminal_pid):
    value=dict(nonce=nonce,terminal_pid=terminal_pid,parent=lease(stage,nonce))
    publish(workspace/'start.json',value,0o600)


def wait_marker(path,nonce,deadline_ns):
    while True:
        need(time.monotonic_ns()<deadline_ns,'Doctor parent lifetime deadline')
        if path.exists():
            value=read(path,23001,0o600)
            need(value==dict(nonce=nonce),'Doctor release marker identity differs')
            return value
        time.sleep(.1)


class Cancelled(Exception):pass


WRAPPER_PID=TERMINAL_PID=None


def worker(C,base,workspace,stage,nonce,exercise):
    begin=time.monotonic_ns();phase='START';outcome='ERROR';error=None;code=1;binding=None
    old={}
    def cancelled(signum,frame):raise Cancelled('owned Doctor signal '+str(signum))
    for signum in (signal.SIGTERM,signal.SIGINT):old[signum]=signal.signal(signum,cancelled)
    try:
        binding=lease(stage,nonce);until=min(deadline(binding),begin+120*10**9)
        while not (workspace/'start.json').exists():
            need(time.monotonic_ns()<until,'Doctor terminal start deadline');time.sleep(.1)
        value=read(workspace/'start.json',23001,0o600)
        need(value==dict(nonce=nonce,terminal_pid=TERMINAL_PID,parent=binding) and os.isatty(0) and os.isatty(1),'owned Doctor start/parent/PTY differs')
        phase='COMMANDS';result=exercise(base,workspace,stage,nonce,TERMINAL_PID,dict(os.environ))
        result.update(report_worker_pid=os.getpid(),worker_pid=WRAPPER_PID)
        C.publish(workspace/'result.json',result)
        phase='WAIT_RELEASE';wait_marker(workspace/'release.json',nonce,deadline(binding))
        outcome='RELEASED';code=0
    except BaseException as caught:
        error=caught
        outcome='CANCELLED' if isinstance(caught,Cancelled) else 'TIMEOUT' if isinstance(caught,ValueError) and 'deadline' in str(caught) else 'ERROR'
        if not (workspace/'result.json').exists():
            C.publish(workspace/'result.json',dict(status='FAIL',reason=str(caught)[:512],error_type=type(caught).__name__,processes=getattr(caught,'doctor_processes',[])))
    finally:
        receipt=dict(schema_version=1,stage=stage,nonce=nonce,terminal_pid=TERMINAL_PID,worker_pid=os.getpid(),wrapper_pid=WRAPPER_PID,parent=binding,
            started_ns=begin,finished_ns=time.monotonic_ns(),phase=phase,outcome=outcome,intended_exit=code,
            error_type=None if error is None else type(error).__name__,reason=None if error is None else str(error)[:512])
        try:publish(workspace/'lifetime.json',receipt,0o600)
        finally:
            for signum,handler in old.items():signal.signal(signum,handler)
    if error is not None:print('DOCTOR LIFETIME FAILED: '+str(error)[:512],flush=True)
    return code


def capture(workspace,stage,nonce,terminal_pid,terminal_exit):
    result=dict(stage=stage,nonce=nonce,terminal_pid=terminal_pid,terminal_exit=terminal_exit)
    result['status']='RECORDED';result['errors']=[]
    for name,key in (('lifetime.json','receipt'),('worker-exit.json','child_wait')):
        try:
            value=read(workspace/name,23001,0o600);result[key]=value
            if key=='receipt':result['receipt_bytes']=len(encoded(value))
        except BaseException as error:
            result['status']='UNKNOWN';result['errors'].append(dict(file=name,error_type=type(error).__name__,reason=str(error)[:256]))
    return result


def validate(value,stage,nonce,terminal_pid,worker_pid):
    need(not value.get('errors',[]) and value['status']=='RECORDED' and value['stage']==stage and value['nonce']==nonce and value['terminal_pid']==terminal_pid and value['terminal_exit']==0,'Doctor natural terminal retirement required')
    row=value['receipt'];need(set(row)=={'schema_version','stage','nonce','terminal_pid','worker_pid','wrapper_pid','parent','started_ns','finished_ns','phase','outcome','intended_exit','error_type','reason'},'closed Doctor worker receipt required')
    need(value['receipt_bytes']==len(encoded(row))<=CAP,'Doctor final receipt byte bound')
    need(row['schema_version']==1 and row['stage']==stage and row['nonce']==nonce and row['terminal_pid']==terminal_pid and row['wrapper_pid']==worker_pid and row['outcome']=='RELEASED' and row['phase']=='WAIT_RELEASE' and row['intended_exit']==0 and row['error_type'] is row['reason'] is None,'Doctor ordinary worker release/exit required')
    waited=value['child_wait'];need(set(waited)=={'schema_version','wrapper_pid','terminal_pid','child_pid','child_returncode','wait_status','reason','parent','finished_ns'},'closed actual child wait required')
    need(waited['schema_version']==1 and waited['wrapper_pid']==worker_pid and waited['child_pid']==row['worker_pid'] and waited['terminal_pid']==terminal_pid and waited['child_returncode']==0 and waited['wait_status']==0 and waited['reason']=='NATURAL_CHILD_EXIT' and waited['parent']==row['parent'],'actual Doctor child wait0 required')
    owner=row['parent'];binding(owner,stage,nonce)
    need(all(type(row[k]) is int and row[k]>0 for k in ('terminal_pid','worker_pid','wrapper_pid','started_ns','finished_ns')) and all(type(waited[k]) is int and waited[k]>0 for k in ('wrapper_pid','terminal_pid','child_pid','finished_ns')) and type(waited['child_returncode']) is type(waited['wait_status']) is int,'typed child/wrapper identity and actual wait required')
    need(owner['started_ns']<=row['started_ns']<=row['finished_ns']<deadline(owner) and row['finished_ns']<=waited['finished_ns']<deadline(owner),'Doctor fixed profile/global lifetime interval differs')
    return dict(status='PASS_RELEASED_NATURAL_DOCTOR_WORKER_AND_TERMINAL',stage=stage,terminal_pid=terminal_pid,worker_pid=worker_pid,parent=owner,finished_ns=waited['finished_ns'])


def validate_profiles(profiles):
    need([p['stage'] for p in profiles]==['minimal','overlay'],'two ordered independent Doctor profiles required')
    first,second=profiles;one=first['parent'];two=second['parent']
    need(one['service']==two['service'] and one['parent_pid']==two['parent_pid'] and one['parent_nonce']!=two['parent_nonce'] and one['profile_nonce']!=two['profile_nonce'] and first['finished_ns']<two['started_ns'],'profiles require distinct fixed owners after previous retirement within one service')



def supervise(main,workspace=None,stage=None,nonce=None):
    """One direct child; only waitpid status attests its actual process exit."""
    global WRAPPER_PID,TERMINAL_PID
    WRAPPER_PID=os.getpid();TERMINAL_PID=os.getppid()
    if workspace is None:
        import sys
        need(sys.argv.count('--workspace')==1,'fixed Doctor workspace operand')
        workspace=Path(sys.argv[sys.argv.index('--workspace')+1])
        need(sys.argv.count('--stage')==sys.argv.count('--nonce')==1,'fixed Doctor stage/nonce operands')
        stage=sys.argv[sys.argv.index('--stage')+1];nonce=sys.argv[sys.argv.index('--nonce')+1]
        need(stage in ('minimal','overlay') and len(nonce)==32 and all(c in '0123456789abcdef' for c in nonce),'fixed Doctor stage/nonce')
        info=workspace.lstat()
        need(os.geteuid()==23001 and workspace==Path('/home/desktop574')/('doctor-'+stage+'-'+nonce) and not workspace.is_symlink() and stat.S_ISDIR(info.st_mode) and info.st_uid==23001 and stat.S_IMODE(info.st_mode)==0o700 and Path.cwd()==workspace and os.isatty(0) and os.isatty(1),'owned Doctor wrapper workspace/identity/PTY required')
        need('cachy_asahi_welcome_gui=1' in Path('/proc/cmdline').read_text().split(),'Doctor wrapper VM marker required')
    binding=lease(stage,nonce)
    child=os.fork()
    if child==0:
        try:code=main()
        except BaseException:code=1
        os._exit(code)
    try:handle=os.pidfd_open(child)
    except BaseException:
        # An unreaped direct child cannot have its PID recycled. Retire it even
        # if this kernel refuses the preferred pidfd ownership primitive.
        os.kill(child,signal.SIGKILL);_,status=os.waitpid(child,0)
        publish(workspace/'worker-exit.json',dict(schema_version=1,wrapper_pid=WRAPPER_PID,terminal_pid=TERMINAL_PID,
            child_pid=child,child_returncode=os.waitstatus_to_exitcode(status),wait_status=status,
            reason='PIDFD_REFUSED',parent=binding,finished_ns=time.monotonic_ns()),0o600)
        return 1
    poller=select.poll();poller.register(handle,select.POLLIN)
    cancelled=[];old={};status=None;reason='NATURAL_CHILD_EXIT'
    def cancel(signum,frame):cancelled.append(signum)
    for signum in (signal.SIGTERM,signal.SIGINT):old[signum]=signal.signal(signum,cancel)
    try:
        while not poller.poll(100):
            if cancelled or time.monotonic_ns()>=deadline(binding):
                reason='PARENT_CANCELLED' if cancelled else 'PARENT_DEADLINE'
                signal.pidfd_send_signal(handle,signal.SIGTERM)
                if not poller.poll(1000):signal.pidfd_send_signal(handle,signal.SIGKILL)
                break
        _,status=os.waitpid(child,0)
    finally:
        os.close(handle)
        for signum,handler in old.items():signal.signal(signum,handler)
        publish(workspace/'worker-exit.json',dict(schema_version=1,wrapper_pid=WRAPPER_PID,terminal_pid=TERMINAL_PID,
            child_pid=child,child_returncode=None if status is None else os.waitstatus_to_exitcode(status),wait_status=status,
            reason=reason,parent=binding,finished_ns=time.monotonic_ns()),0o600)
    return 0 if status==0 and reason=='NATURAL_CHILD_EXIT' else 1
