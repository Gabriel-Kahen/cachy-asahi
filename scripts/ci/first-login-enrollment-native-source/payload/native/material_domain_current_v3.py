# SPDX-License-Identifier: MIT
"""Explicit material scope/storage caller. No import-time actor or Root issuance."""
import argparse
import copy
import fcntl
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import resource
import re
import stat
import subprocess
import sys
import time

API='CURRENT_ONBOARDING_MATERIAL_DOMAIN_V3'
CLOSE_SECONDS=90
EXECUTOR_PIN=dict(bytes=53735,sha256='aee41c0956f3249eef2e9c8974238b214622cb385e2d8f736109d9650ce7120a')
STAGER_PIN=dict(bytes=35550,sha256='58c5d0842c17a914239b5f24e9e1ac2987ad8ec9ce9e2a03e63a04f2e2e99282')
OWNED_SHA='83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f'
INPUT_METADATA={'staging_base_lock':dict(member='bootstrap/scripts/ci/inputs.lock.json',bytes=328101,sha256='beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'),
    'staging_bootstrap_profile':dict(member='native/input-profile.json',bytes=168201,sha256='2c42c705654d31e639f389f9a868dada0d9df76813d865e766be7b7c08f8404c')}
SCOPE={'memory.max':'536870912','memory.swap.max':'0','cpu.max':'100000 100000','pids.max':'64'}
FINAL=dict(Root_final_acceptance=None,independent_component_acceptance=False,hardware_acceptance=False,release_acceptance=False)
PROPOSAL=dict(kind=API,scope_seconds=3600,cleanup_seconds=CLOSE_SECONDS,whole_budget_seconds=7560,
    scope_limits=SCOPE,controller_AS_bytes=2147483648,controller_CPU_seconds=3600,
    storage_parent_base='/var/lib',storage_bytes=8*1024**3,filesystem_inodes=18432,maximum_inodes=20000,minimum_free_inodes=18000,
    administration_rows=32,administration_bytes=128*1024**2,administration_nodes=256,
    secret_bytes=1024**2,receipt_bytes=2*1024**2,retain_until_consumers_retired=True,Root_issuance=None)


def need(ok,why):
    if not ok:raise ValueError(why)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def decoded(raw):
    def pairs(rows):
        value={}
        for k,v in rows:need(k not in value,'duplicate JSON key');value[k]=v
        return value
    value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite DATA'))
    need(type(value)is dict,'DATA object');encoded(value);return value


# Failure-only public protocol. No exception text, raw output or request body.
FAILURE_KIND='CURRENT_MATERIAL_STAGE_FAILURE_V1'
FAILURE_BYTES=1024
FAILURE_PHASES=frozenset(('ENTRY','AUTHORIZE','SOURCE','NATIVE_CONTEXT','INPUTS','HELPERS','TOOLS','STORAGE','SCOPE','TRANSPORT_PUBLIC14','TRANSPORT_NATIVE248','PRIVATE_SEED','PUBLIC14_PREPARE','NATIVE248_PREPARE','DOWNLOAD','COMPLETE517','FINALIZE','CHILD'))
FAILURE_REASONS=frozenset(('PHASE_FAILED','COMMAND_FAILED'))

def failure_packet(raw):
    """Decode the entire canonical packet, or return unavailable without raising."""
    try:
        if type(raw)is not bytes or not 0<len(raw)<=FAILURE_BYTES:return None
        value=decoded(raw)
        if set(value)!={'schema','kind','phase','reason','command_ordinal'}or raw!=encoded(value):return None
        if type(value['schema'])is not int or value['schema']!=1 or value['kind']!=FAILURE_KIND:return None
        if type(value['phase'])is not str or value['phase']not in FAILURE_PHASES or type(value['reason'])is not str or value['reason']not in FAILURE_REASONS:return None
        index=value['command_ordinal']
        if index is not None and(type(index)is not int or not 0<=index<=26):return None
        return value
    except (ValueError,TypeError,KeyError,UnicodeError,RecursionError,OverflowError):return None


def emit_failure(diagnostic,error=None):
    """Best-effort fixed-domain fallback; never replace the original failure."""
    try:
        value=dict(schema=1,kind=FAILURE_KIND,phase=diagnostic['phase'],reason='PHASE_FAILED',command_ordinal=None)
        raw=encoded(value)
        if failure_packet(raw)is None:return False
        stream=getattr(sys.stderr,'buffer',None)
        written=stream.write(raw)if stream is not None else sys.stderr.write(raw.decode('ascii'))
        if written!=len(raw):return False
        (stream or sys.stderr).flush()
        if error is not None:setattr(error,'_current_material_failure_emitted',True)
        return True
    except BaseException:return False


def ordinary(path):
    path=Path(path);need(path.is_absolute()and path==path.resolve()and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary absolute ancestry');return path


def stable_identity(info):return tuple(getattr(info,k)for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))


def read(path,cap=2*1024**2):
    path=ordinary(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<a.st_size<=cap and not a.st_mode&0o022,'bounded single-link DATA')
        raw=b''
        while block:=os.read(fd,min(65536,cap+1-len(raw))):raw+=block;need(len(raw)<=cap,'DATA bound')
        need(stable_identity(a)==stable_identity(os.fstat(fd))==stable_identity(path.lstat())and len(raw)==a.st_size,'stable whole DATA');return raw
    finally:os.close(fd)


def write(path,value):
    raw=encoded(value);need(len(raw)<=PROPOSAL['receipt_bytes'],'bounded DATA receipt')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb')as stream:stream.write(raw)


def whole_pin(row,cap=128*1024**2):
    need(type(row)is dict and set(row)=={'bytes','sha256'}and type(row['bytes'])is int and 0<row['bytes']<=cap
         and type(row['sha256'])is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),'typed bounded whole pin');return row


def descriptor(row):
    need(type(row)is dict and set(row)=={'member','bytes','sha256'},'whole Source descriptor')
    member=Path(row['member']);need(not member.is_absolute()and '..'not in member.parts,'closed Source member')
    return whole_pin({k:row[k]for k in ('bytes','sha256')})


def load(root,row,name,expected=None):
    wanted=descriptor(row);need(expected is None or wanted==expected,'exact reviewed dependency basis')
    path=ordinary(Path(root)/row['member']);raw=read(path,128*1024);need(pin(raw)==wanted,'whole Source program')
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec)
    exec(compile(raw,str(path),'exec'),value.__dict__);return value


def boot_pin():return pin(read_kernel(Path('/proc/sys/kernel/random/boot_id')).encode())
def read_kernel(path):
    with path.open('rb')as stream:raw=stream.read(4097)
    need(len(raw)<=4096,'bounded kernel observation');return raw.decode()


def validate_timing(t,d,c,g):
    expected={'schema','kind','request_pin','delegation_pin','binding','policy_pin','boot_pin','started_monotonic','deadline_monotonic','expires_epoch','whole_budget_seconds',*FINAL}
    need(type(t)is dict and set(t)==expected and type(t['schema'])is int and t['schema']==3
         and t['kind']=='CURRENT_HOSTED_SHARED_7560_PREREQUISITE_TIMING_V3'and t['whole_budget_seconds']==7560,'same closed Root shared timing contract')
    expiry=min(d['expires_epoch'],g['expires_epoch'])
    need(t['delegation_pin']==c['delegation_pin']and t['binding']==c['binding']and t['policy_pin']==descriptor(d['policy'])
         and t['boot_pin']==boot_pin()and t['expires_epoch']==expiry,'actual same-boot Source/delegation/policy/deadline')
    whole_pin(t['request_pin'],49152)
    a,b=t['started_monotonic'],t['deadline_monotonic'];now=time.monotonic()
    need(all(type(v)in (int,float)and math.isfinite(v)for v in (a,b))and 0<a<=now<b<=a+7560
         and time.time()<expiry and b<=now+expiry-time.time()+.1,'no reset or extension of whole Root deadline')
    need(all(t[k]==v and type(t[k])is type(v)for k,v in FINAL.items()),'shared timing grants no acceptance');return b


def remaining(t):
    value=min(t['deadline_monotonic']-time.monotonic(),t['expires_epoch']-time.time())
    need(math.isfinite(value)and value>1,'shared Root deadline remains');return value


def staging_inputs(root,d):
    result={}
    for role,expected in INPUT_METADATA.items():
        row=d['materials'].get(role);need(row==expected,'exact closed material metadata role: '+role)
        raw=read(root/row['member']);need(pin(raw)==descriptor(row),'whole closed original material metadata')
        result['base_lock'if role=='staging_base_lock'else'bootstrap_profile']=dict(path=str(root/row['member']),**descriptor(row))
    return result


def authorize(r):
    raw=r['delegation_raw'].encode();grant_raw=r['grant_raw'].encode()
    need(pin(raw)['sha256']==r['delegation_sha256']and pin(grant_raw)['sha256']==r['grant_sha256'],'external Root hashes before selected imports')
    root=ordinary(r['source_root']);preview=decoded(raw)
    E=load(root,preview['programs']['image_executor'],'material_held_executor',EXECUTOR_PIN)
    E.context_contract(preview);C=load(root,preview['programs']['context'],'material_actual_context')
    d=C.validate_delegation(raw,r['delegation_sha256']);C.source(d,root);C.validate_context(d,r['context']);E.context_contract(d,r['context'],C,root)
    need(r['context']['source_root']==str(root),'actual Source workspace')
    policy_raw=read(root/d['policy']['member']);need(pin(policy_raw)==descriptor(d['policy']),'whole Root policy')
    policy=decoded(policy_raw);E.validate_policy(policy,d);S=load(root,d['programs']['materials_stager'],'material_actual_stager',STAGER_PIN)
    need(pin(read(Path(__file__).resolve(),128*1024))==descriptor(d['programs']['material_domain_executor']),'actual selected domain executor')
    assembler=d['programs']['inputs_assembler'];need(pin(read(root/assembler['member'],128*1024))==descriptor(assembler),'closed caller assembler role')
    need(policy.get('material_domain_executor_current_v3')==PROPOSAL and d['capability'].get('allow_material_staging')is True,'separate explicit unissued domain policy selection')
    g=S.validate_grant(grant_raw,r['grant_sha256'],d,r['context'],policy)
    validate_timing(r['shared_timing'],d,r['context'],g)
    need(type(r['runner_uid'])is int and type(r['runner_gid'])is int and r['runner_uid']>0 and r['runner_gid']>0,'explicit ordinary runner IDs')
    parent=ordinary(g['storage_parent']);need(parent.parent==Path('/var/lib'),'Root selected finite domain parent, no arbitrary host mount')
    control=ordinary(r['control_root']);need(not control.is_relative_to(root)and not root.is_relative_to(control),'disjoint caller control and closed Source')
    need(control.is_dir()and control.stat().st_uid==r['runner_uid']and stat.S_IMODE(control.stat().st_mode)==0o700,'actual caller-owned private control root')
    staging_inputs(root,d)
    O=load(root,d['programs']['owned_process'],'material_held_process')
    need(descriptor(d['programs']['owned_process'])['sha256']==OWNED_SHA,'exact held supervisor')
    return root,d,policy,g,E,S,O


def scope_name(nonce,closing=False):
    need(type(nonce)is str and re.fullmatch('[0-9a-f]{64}',nonce),'exact material scope nonce')
    return 'cachy-current-material'+('s-close-'if closing else's-')+nonce+'.scope'
def scope_path(nonce,closing=False):return Path('/sys/fs/cgroup/system.slice')/scope_name(nonce,closing)


def absent(nonce,deadline,closing=False):
    path=scope_path(nonce,closing);seen=0;end=min(deadline,time.monotonic()+10)
    while time.monotonic()<end:
        seen=0 if path.exists()else seen+1
        if seen==2:return dict(scope=path.name,absent_twice=True)
        time.sleep(.05)
    raise ValueError('actual material cgroup absence required')


def observed_tool(E,name):
    for candidate in E.CANDIDATES[name]:
        try:return E.inspect_tool(candidate)
        except FileNotFoundError:continue
    raise ValueError('missing fixed material tool: '+name)


def scope_tools(root,d,E):
    result={}
    for name in ('python3','systemd-run'):
        row=E.inspect_tool('/usr/bin/'+name);E.checked_tool(row);result[name]=row
    L=load(root,d['programs']['hosted_launcher'],'material_sudo_guard')
    result['sudo']=L.fixed_tool('/usr/bin/sudo')
    need(result['sudo']['path']=='/usr/bin/sudo','actual fixed caller sudo')
    return result


def scope_argv(module_path,request,sha,nonce,seconds,closing=False,*,python_path='/usr/bin/python3',systemd_run_path='/usr/bin/systemd-run'):
    need(type(seconds)is int and 1<seconds<=(CLOSE_SECONDS if closing else 3600),'finite scope inside remaining shared budget')
    return ['/usr/bin/sudo','-n',systemd_run_path,'--scope','--quiet','--unit='+scope_name(nonce,closing),
        '--description=current-material-domain-'+nonce,'--property=MemoryMax=536870912','--property=MemorySwapMax=0',
        '--property=CPUQuota=100%','--property=CPUQuotaPeriodSec=100ms','--property=TasksMax=64',
        '--property=RuntimeMaxSec='+str(seconds)+'s','--property=TimeoutStopSec=5s','--property=KillMode=control-group','--property=OOMPolicy=kill',
        '--',python_path,'-I','-B',str(module_path),'close-entry'if closing else'stage-entry','--request',str(request),'--request-sha256',sha]


def actual_scope(E,nonce,t,closing=False):
    actual=E.kernel_domain(os.getpid());group='/system.slice/'+scope_name(nonce,closing)
    need(actual['cgroup']==group and actual['limits']==SCOPE and actual['starttime']>0,'actual selected finite material scope identity')
    return actual


def decoded_scope_properties(raw):
    props={}
    for line in raw.decode().splitlines():
        k,v=line.split('=',1);need(k not in props,'duplicate actual scope property');props[k]=v
    need(set(props)=={'ControlGroup','RuntimeMaxUSec','ActiveEnterTimestampMonotonic'},'exact actual scope properties');return props


def check_scope_properties(E,props,scope,t,maximum):
    start=props['ActiveEnterTimestampMonotonic'];need(start.isdecimal()and int(start)>0,'actual scope activation time')
    runtime=E.runtime_microseconds(props['RuntimeMaxUSec']);end=(int(start)+runtime)/1000000
    need(props['ControlGroup']==scope['cgroup']and 0<runtime<=maximum*1000000
         and time.monotonic()<end+5<=t['deadline_monotonic']and end+5<=time.monotonic()+t['expires_epoch']-time.time()+.1,'actual finite scope cannot extend shared Root deadline')
    return end


def seals():
    names=('F_ADD_SEALS','F_GET_SEALS','F_SEAL_GROW','F_SEAL_SHRINK','F_SEAL_WRITE','F_SEAL_SEAL')
    need(hasattr(os,'memfd_create')and hasattr(os,'MFD_ALLOW_SEALING')and all(hasattr(fcntl,k)for k in names),'new-role sealed secret input API required')
    return fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_WRITE|fcntl.F_SEAL_SEAL


def sealed_secret_input(values,names):
    need(type(values)is dict and set(values)==set(names)and len(names)==22 and all(type(v)is str and 0<len(v)<=32768 for v in values.values()),'explicit exact22 one-shot values')
    raw=encoded(values);need(len(raw)<=PROPOSAL['secret_bytes'],'finite private input')
    mask=seals();fd=os.memfd_create('current-material-private-input',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    try:
        with os.fdopen(fd,'w+b')as stream:
            stream.write(raw);stream.flush();stream.seek(0);fcntl.fcntl(stream.fileno(),fcntl.F_ADD_SEALS,mask)
            yield stream
    finally:values.clear()


def secret_input(names):
    need(stat.S_ISREG(os.fstat(0).st_mode)and 0<os.fstat(0).st_size<=PROPOSAL['secret_bytes']and os.fstat(0).st_nlink==0 and fcntl.fcntl(0,fcntl.F_GET_SEALS)&seals()==seals(),'sealed anonymous private stdin, no secret file or environment')
    raw=b''
    while block:=os.read(0,65536):raw+=block;need(len(raw)<=PROPOSAL['secret_bytes'],'private input cap')
    values=decoded(raw);need(set(values)==set(names)and all(type(v)is str and 0<len(v)<=32768 for v in values.values()),'exact owned private input');return values


def identity(path):
    s=path.lstat();return dict(device=s.st_dev,inode=s.st_ino,mode=s.st_mode,uid=s.st_uid,gid=s.st_gid,links=s.st_nlink,bytes=s.st_size)


class RootStorage:
    """Only this nonce's root-created loop/ext4 domain. Never touches Docker."""
    def __init__(self,r,E,O,g,d):
        self.r,self.E,self.g,self.d=r,E,g,d;self.nonce=d['nonce'];self.mount=Path(g['storage_parent'])
        self.admin=Path('/var/lib')/('cachy-current-material-owner-'+self.nonce);self.backing=self.admin/'storage.img';self.state=self.admin/'custody.json'
        self.engine=None;self.O=O;self.created=False;self.closing=False;self.command_root=None
    def attach_engine(self):
        tools={}
        for name in ('systemctl','fallocate','losetup','mkfs.ext4','mount','umount','python3'):
            tools[name]=observed_tool(self.E,name)
        self.command_root=self.admin/('close-administration'if self.closing else'stage-administration')
        self.engine=self.E.CommandEngine(self.O,tools,self.command_root,time.monotonic()+remaining(self.r['shared_timing'])-1,PROPOSAL['administration_rows']//2)
    def run(self,name,args,seconds=15):
        need(self.engine is not None,'owned command engine initialized')
        row=self.engine.tools[name];return self.engine.run('material-admin-%03d'%len(self.engine.receipts),[row['path'],*args],min(seconds,remaining(self.r['shared_timing'])-1))['stdout']
    def save(self):
        raw=encoded(self.owned);need(len(raw)<=65536,'finite custody state')
        temporary=self.admin/'custody.next';fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb')as stream:stream.write(raw)
        os.replace(temporary,self.state)
    def loop_rows(self,device=None):
        args=['--json','--list',*(['--associated',str(self.backing)]if device is None else[device]),'--output','NAME,BACK-FILE']
        return decoded(self.run('losetup',args))['loopdevices']
    def same_loop(self,device):
        rows=self.loop_rows(device);need(len(rows)==1 and rows[0]['name']==device and rows[0]['back-file']==str(self.backing),'same newly owned backing/loop association')
    def begin(self):
        need(os.getuid()==os.geteuid()==0,'root storage entry only')
        need(not self.admin.exists()and not self.mount.exists(),'never adopt foreign/preexisting material storage')
        v=os.statvfs('/var/lib');minimum=self.policy['executor_current_v3']['minimum_disk_bytes']
        need(v.f_bavail*v.f_frsize>=minimum+PROPOSAL['storage_bytes']+PROPOSAL['administration_bytes']and v.f_favail>PROPOSAL['administration_nodes'],'aggregate retained8GiB plus later32GiB disk admission')
        self.attach_engine()
        self.admin.mkdir(mode=0o700);self.created=True;self.command_root.mkdir(mode=0o700)
        self.owned=dict(schema=3,kind=API,nonce=self.nonce,request_pin=pin(encoded(self.r)),mount=str(self.mount),backing=None,loop=None,mountpoint=None,mount_device=None,closed=False)
        self.save()
        for name in ('tmp','cache'):(self.command_root/name).mkdir(mode=0o700)
    def allocate(self):
        need(self.created and self.engine is not None,'fresh owned setup before allocation')
        fd=os.open(self.backing,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
        self.owned['backing']=identity(self.backing);self.save()
        self.run('fallocate',['--length',str(PROPOSAL['storage_bytes']),'--',str(self.backing)],60)
        need(self.backing.stat().st_size==PROPOSAL['storage_bytes']and self.backing.stat().st_blocks*512>=PROPOSAL['storage_bytes'],'physically allocated finite material backing')
        self.owned['backing']=identity(self.backing);self.save()
        device=self.run('losetup',['--find','--show','--nooverlap',str(self.backing)]).decode().strip()
        need(re.fullmatch('/dev/loop[0-9]+',device),'new exact allocated loop device');self.same_loop(device)
        self.owned['loop']=device;self.save()
        self.run('mkfs.ext4',['-q','-t','ext4','-m','0','-N',str(PROPOSAL['filesystem_inodes']),device],60)
        self.mount.mkdir(mode=0o700);self.owned['mountpoint']=identity(self.mount);self.save()
        self.run('mount',['-t','ext4','-o','nodev,nosuid',device,str(self.mount)])
        need(self.mount.is_mount()and self.mount.stat().st_dev==Path(device).stat().st_rdev,'same allocated mounted material filesystem')
        self.owned['mount_device']=self.mount.stat().st_dev;self.save()
        os.chown(self.mount,self.r['runner_uid'],self.r['runner_gid']);os.chmod(self.mount,0o700)
        v=os.statvfs(self.mount)
        need(0<v.f_blocks*v.f_frsize<=PROPOSAL['storage_bytes']and 18000<=v.f_favail<=v.f_files<=20000 and v.f_bavail*v.f_frsize>=6*1024**3,'actual finite material bytes/inodes/free capacity')
        return dict(path=str(self.mount),device=self.owned['mount_device'],total_bytes=v.f_blocks*v.f_frsize,total_nodes=v.f_files,free_nodes=v.f_favail,free_bytes=v.f_bavail*v.f_frsize,**FINAL)
    def reopen(self):
        need(os.getuid()==os.geteuid()==0 and ordinary(self.admin).is_dir()and self.admin.stat().st_uid==0 and stat.S_IMODE(self.admin.stat().st_mode)==0o700,'root-owned custody directory')
        need(self.state.stat().st_uid==0 and stat.S_IMODE(self.state.stat().st_mode)==0o600,'root-only custody receipt')
        self.owned=decoded(read(self.state));need(self.owned['schema']==3 and self.owned['kind']==API and self.owned['nonce']==self.nonce and self.owned['request_pin']==pin(encoded(self.r))and self.owned['mount']==str(self.mount),'same Root-selected material custody')
        if not self.owned['closed']:
            self.closing=True;self.attach_engine();need(not self.command_root.exists(),'preserve previous close-only failure; no blind retry')
            self.command_root.mkdir(mode=0o700)
            for name in ('tmp','cache'):(self.command_root/name).mkdir(mode=0o700)
    def close(self):
        if self.owned['closed']:
            need(not self.mount.exists()and not self.backing.exists(),'closed material paths remain absent');return self.owned['close_receipt']
        stage_absence=absent(self.nonce,time.monotonic()+min(5,remaining(self.r['shared_timing'])))
        need(stage_absence.get('scope')==scope_name(self.nonce)and stage_absence.get('absent_twice')is True,'actual staging absence before storage retirement')
        wanted=self.owned['backing']
        if wanted is not None:
            actual=identity(self.backing)
            need(all(actual[k]==wanted[k]for k in ('device','inode','mode','uid','gid','links'))and 0<=actual['bytes']<=PROPOSAL['storage_bytes'],'same root-created backing identity before cleanup')
        rows=self.loop_rows();need(len(rows)<=1 and all(v['back-file']==str(self.backing)for v in rows),'exclusive own loop association')
        device=rows[0]['name']if rows else None
        need(device is None or re.fullmatch('/dev/loop[0-9]+',device),'only exclusively allocated loop device cleanup')
        need(device is None or self.owned['loop']in (None,device),'same saved allocated loop')
        if self.mount.exists()and self.mount.is_mount():
            need(device is not None and self.mount.stat().st_dev==Path(device).stat().st_rdev
                 and self.owned['mount_device']in (None,self.mount.stat().st_dev),'owned mounted device before unmount')
            self.same_loop(device);self.run('umount',[str(self.mount)])
        if self.mount.exists():
            need(self.owned['mountpoint']is not None and identity(self.mount)==self.owned['mountpoint'],'same underlying empty mountpoint')
            self.mount.rmdir()
        if device:
            self.same_loop(device);self.run('losetup',['--detach',device]);need(not self.loop_rows(),'owned loop absence after detach')
        if self.backing.exists():need(wanted is not None,'no foreign backing removal');self.backing.unlink()
        need(not self.mount.exists()and not self.backing.exists(),'actual material storage paths absent')
        self.owned['closed']=True;self.owned['close_receipt']=dict(owned_storage_absent=not self.mount.exists()and not self.backing.exists(),scope_absent=stage_absence['absent_twice'],scope_absence=stage_absence,**FINAL);self.save();return self.owned['close_receipt']


def retained_storage(receipt,r,d,g,root,scope_absence):
    domain=receipt['domain'];storage=receipt['storage_domain'];parent=ordinary(g['storage_parent']);v=os.statvfs(parent)
    need(domain['cgroup']=='/system.slice/'+scope_name(d['nonce'])and domain['limits']==SCOPE
         and type(domain['pid'])is int and domain['pid']>0 and type(domain['starttime'])is int and domain['starttime']>0,'exact actual stager scope observation')
    need(parent.is_mount()and parent.stat().st_uid==r['runner_uid']and stat.S_IMODE(parent.stat().st_mode)==0o700
         and parent.stat().st_dev!=root.stat().st_dev and storage['path']==str(parent)and storage['device']==parent.stat().st_dev
         and storage['total_bytes']==v.f_blocks*v.f_frsize and storage['total_nodes']==v.f_files
         and 0<storage['total_bytes']<=PROPOSAL['storage_bytes']and 0<storage['total_nodes']<=20000,'same finite retained input filesystem before handoff')
    return dict(storage,retained_for_consumers=True,scope_absence=scope_absence)


def scope_retirement(E,row,nonce,closing=False):
    need(type(row)is dict and row.get('kind')==('CLOSE'if closing else'STAGE')and row.get('natural')is True,'actual natural physical caller receipt required')
    supervision=row.get('supervision');need(type(supervision)is dict,'actual held supervision required');E.natural(supervision)
    absence=row.get('scope_absence')
    need(type(absence)is dict and absence.get('scope')==scope_name(nonce,closing)and absence.get('absent_twice')is True,'actual twice-absent exact physical scope required')
    return dict(natural=row['natural'],scope_absent=absence['absent_twice'],scope=absence['scope'],
        supervision_pin=pin(encoded(supervision)),scope_absence_pin=pin(encoded(absence)),**FINAL)


def stderr_identity(stream):
    info=os.fstat(stream.fileno())
    return tuple(getattr(info,key)for key in('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size'))


def retired_stderr(stream,identity,supervision,E):
    """Freeze the held reservation, then read its written span, never its padding."""
    expected=supervision.get('exit');need(type(expected)is int,'actual child exit before stderr capture')
    E.natural(supervision,expected)
    fd=stream.fileno();need(stderr_identity(stream)==identity,'same held stderr reservation after child retirement')
    need(stat.S_ISREG(identity[2])and identity[3]==0 and identity[-1]==E.MAX_OUTPUT,'anonymous bounded stderr reservation')
    required=fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK
    need(fcntl.fcntl(fd,fcntl.F_GET_SEALS)&required==required,'fixed stderr capacity before capture')
    # The shared open-file offset advances on child writes; st_size is the
    # reserved capacity. Seal before observing either the span or its bytes.
    fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_SEAL)
    size=os.lseek(fd,0,os.SEEK_CUR);need(0<=size<E.MAX_OUTPUT,'complete bounded separate material stderr')
    raw=os.pread(fd,size,0)
    need(len(raw)==size and os.lseek(fd,0,os.SEEK_CUR)==size and stderr_identity(stream)==identity,
         'whole stable written stderr span')
    return raw


class MaterialSession:
    def __init__(self,r,dependencies):
        self.r=r;self.root,self.d,self.policy,self.g,self.E,self.S,self.O=dependencies
        self.control=Path(r['control_root']);self.request=self.control/'material-domain-request.json';self.state='OPEN';self.receipts=[];self.stage_submitted=False
        need(not self.request.exists(),'fresh caller request, no collision adoption');write(self.request,r)
    def retain_stage_failure(self,row,raw=None,stderr_complete=False):
        """Retain one fixed safe record before CLOSEONLY cleanup; no raw streams."""
        try:
            def stream_pin(value):
                if type(value)is not dict or set(value)!={'bytes','sha256'}:return None
                if type(value['bytes'])is not int or not 0<=value['bytes']<=self.E.MAX_OUTPUT:return None
                if type(value['sha256'])is not str or re.fullmatch('[0-9a-f]{64}',value['sha256'])is None:return None
                return dict(value)
            supervision=row.get('supervision');retirement_pin=pin(encoded(supervision))if type(supervision)is dict else None
            retired=(type(supervision)is dict and supervision.get('reaped')is True and supervision.get('ownership')=='REAPED'
                and supervision.get('output_complete')is True and type(supervision.get('exit'))is int
                and supervision.get('group_census')=='EMPTY_TWICE'and supervision.get('signals')==[]
                and supervision.get('timeout')is False and supervision.get('error')is None)
            complete=(stderr_complete is True and type(raw)is bytes and len(raw)<=self.E.MAX_OUTPUT
                and stream_pin(row.get('stderr_pin'))==pin(raw)and retired)
            packet=failure_packet(raw)if complete else None
            record=dict(schema=1,kind='CURRENT_MATERIAL_STAGE_FAILURE_RECORD_V1',status='DIAGNOSTIC_ONLY',
                availability='AVAILABLE'if packet is not None else'UNAVAILABLE',packet=packet,
                request_pin=pin(encoded(self.r)),context_pin=pin(encoded(self.r['context'])),
                stdout_pin=stream_pin(row.get('output_pin')),stderr_pin=stream_pin(row.get('stderr_pin'))if complete else None,
                retirement_pin=retirement_pin,**FINAL)
            write(self.control/'material-stage-failure.json',record)
        except BaseException:
            # A missing/colliding/unwritable diagnostic cannot change HOLD or close.
            pass

    def execute(self,closing=False,secrets=None):
        E=self.E;E.require_runtime_capabilities();need(not scope_path(self.d['nonce'],closing).exists(),'fresh exact material scope, no foreign cleanup')
        tools=scope_tools(self.root,self.d,E)
        seconds=min(CLOSE_SECONDS if closing else 3600,math.floor(min(remaining(self.r['shared_timing']),self.g['expires_epoch']-time.time()))-15)
        need(seconds>(1 if closing else 120),'whole scope and retirement fit same shared deadline')
        need(read(self.request)==encoded(self.r),'unchanged original caller request')
        argv=scope_argv(Path(__file__).resolve(),self.request,pin(encoded(self.r))['sha256'],self.d['nonce'],seconds,closing,python_path=tools['python3']['path'],systemd_run_path=tools['systemd-run']['path'])
        row=dict(kind='CLOSE'if closing else'STAGE',argv=argv,tools=tools,natural=False,scope_absence=None,**FINAL);self.receipts.append(row)
        stdin=None;generator=None;error_body=None;stderr_complete=False
        try:
            if not closing:
                generator=sealed_secret_input(secrets,self.S.secret_names());stdin=next(generator)
            with E.stderr_buffer()as errors:
                identity=stderr_identity(errors)
                self.O.prepare()
                if not closing:self.stage_submitted=True
                child=subprocess.Popen(argv,stdin=stdin if stdin is not None else subprocess.DEVNULL,
                    stdout=subprocess.PIPE,stderr=errors,cwd=self.control,env=dict(PATH='/usr/bin:/usr/sbin:/bin',HOME=str(self.control),LC_ALL='C'),start_new_session=True)
                result=self.O.supervise(child,cap=min(seconds+3,remaining(self.r['shared_timing'])-1),retirement=1,grace=.2,max_output=65536)
                raw=result.pop('output');row['supervision']=result;row['output_pin']=pin(raw)
                error_body=retired_stderr(errors,identity,result,E)
                row['stderr_pin']=pin(error_body);stderr_complete=True
            E.natural(result);need(raw==b'','no material control stdout or secret diagnostics')
            row['scope_absence']=absent(self.d['nonce'],self.r['shared_timing']['deadline_monotonic'],closing);row['natural']=True
            return row
        except BaseException as error:
            row['failure']=dict(reason='MATERIAL_SCOPE_FAILED')
            if not closing:self.retain_stage_failure(row,error_body,stderr_complete)
            raise
        finally:
            if generator is not None:generator.close()
            if secrets is not None:secrets.clear()
    def stage(self,*,secrets):
        prior=self.state
        try:
            need(self.state=='OPEN','one material stage only')
            need(type(secrets)is dict and set(secrets)==set(self.S.secret_names()),'caller owns exact22 secret mapping')
            for name in self.S.secret_names():os.environ.pop(name,None)
            self.execute(secrets=secrets)
            need(self.receipts,'recorded actual staging scope retirement required')
            retirement=scope_retirement(self.E,self.receipts[-1],self.d['nonce'])
            out=Path(self.g['storage_parent'])/('cachy-current-materials-'+self.d['nonce'])
            receipt=decoded(read(out/'staging-receipt.json'));refs=decoded(read(out/'complete517.json'));fields=decoded(read(out/'assembler-fields.json'))
            need(receipt['status']=='COMPLETE517_HOSTED_CACHE_DATA_ONLY'and receipt['binding']==self.r['context']['binding']and receipt['verified_files']==517
                 and receipt['Root_expires_epoch']==min(self.d['expires_epoch'],self.g['expires_epoch'],self.d['issued_epoch']+7560)
                 and receipt['whole_deadline_monotonic']<=self.r['shared_timing']['deadline_monotonic']+.1
                 and all(receipt.get(k)==v and type(receipt.get(k))is type(v)for k,v in FINAL.items()),'exact actual staging completion with no acceptance')
            need(refs['complete']is True and refs['verified_files']==517,'complete real provider result, never partial refs')
            self.storage_observation=retained_storage(receipt,self.r,self.d,self.g,self.root,self.receipts[-1]['scope_absence'])
            B=load(self.root,self.d['programs']['base_inputs'],'material_complete_provider')
            need(fields==B.assembler_fields(refs),'actual committed provider assembler field projection')
            self.state='RETAINED_FOR_CONSUMERS'
            return dict(receipt=receipt,references=refs,assembler_fields=fields,staging_scope_retirement=retirement)
        except BaseException:
            if prior=='OPEN':
                self.retain_stage_failure(self.receipts[-1]if self.receipts else{})
                self.state='HOLD_CLOSEONLY'
            raise
        finally:
            for name in self.S.secret_names():os.environ.pop(name,None)
            if type(secrets)is dict:secrets.clear()
    def close(self):
        if self.state=='CLOSED':return self.close_receipt
        if not self.stage_submitted:
            stage_absence=absent(self.d['nonce'],self.r['shared_timing']['deadline_monotonic'])
            close_absence=absent(self.d['nonce'],self.r['shared_timing']['deadline_monotonic'],True)
            need(stage_absence.get('scope')==scope_name(self.d['nonce'])and stage_absence.get('absent_twice')is True
                 and close_absence.get('scope')==scope_name(self.d['nonce'],True)and close_absence.get('absent_twice')is True,'actual unsubmitted scope absence')
            storage_absent=not Path(self.g['storage_parent']).exists()and not (Path('/var/lib')/('cachy-current-material-owner-'+self.d['nonce'])).exists()
            need(storage_absent,'unsubmitted session cannot attest foreign/preexisting input storage absence')
            self.state='CLOSED';self.close_receipt=dict(submitted=False,closed=storage_absent,owned_storage_absent=storage_absent,
                input_storage_absent=storage_absent,scope_absent=stage_absence['absent_twice']and close_absence['absent_twice'],
                scope_absence=stage_absence,close_scope_absence=close_absence,**FINAL);return self.close_receipt
        # Caller must have retired every later consumer first. No destructor or
        # stage-finally unmounts inputs while the assembler/image still needs them.
        try:
            self.execute(closing=True)
            need(self.receipts,'recorded actual close scope retirement required')
            retirement=scope_retirement(self.E,self.receipts[-1],self.d['nonce'],True)
            path=self.control/'material-domain-close.json';receipt=decoded(read(path))
            need(receipt['owned_storage_absent']is True and receipt['binding']==self.r['context']['binding']and receipt['nonce']==self.d['nonce']and receipt['request_pin']==pin(encoded(self.r))and all(receipt.get(k)==v for k,v in FINAL.items()),'actual close-only storage absence receipt')
            stage_absence=receipt.get('scope_absence')
            need(type(stage_absence)is dict and stage_absence.get('scope')==scope_name(self.d['nonce'])and stage_absence.get('absent_twice')is True,'actual staging scope absence from storage owner')
            scope_absent=retirement['scope_absent']and stage_absence['absent_twice'];storage_absent=receipt['owned_storage_absent']
            self.state='CLOSED';self.close_receipt=dict(receipt,closed=scope_absent and storage_absent,scope_absent=scope_absent,
                input_storage_absent=storage_absent,close_scope_retirement=retirement);return self.close_receipt
        except BaseException:self.state='HOLD_CLOSEONLY';raise


def open_material_session(*,source_root,delegation_raw,delegation_sha256,context,grant_raw,grant_sha256,shared_timing,control_root,runner_uid,runner_gid):
    need(os.getuid()==os.geteuid()==runner_uid and os.getgid()==runner_gid and runner_uid>0,'actual ordinary caller identity, no invented owner facts')
    r=dict(source_root=str(source_root),delegation_raw=delegation_raw.decode(),delegation_sha256=delegation_sha256,context=copy.deepcopy(context),
        grant_raw=grant_raw.decode(),grant_sha256=grant_sha256,shared_timing=copy.deepcopy(shared_timing),control_root=str(control_root),runner_uid=runner_uid,runner_gid=runner_gid)
    return MaterialSession(r,authorize(r))


def root_entry(request,expected,closing=False,_diagnostic=None):
    diagnostic={}if _diagnostic is None else _diagnostic;diagnostic['phase']='ENTRY'
    need(sys.flags.isolated and os.getuid()==os.geteuid()==0 and os.uname().sysname=='Linux'and os.uname().machine=='aarch64','isolated native ARM root material entry')
    diagnostic['phase']='SOURCE'
    raw=read(request);need(pin(raw)['sha256']==expected,'exact caller request before authorization');r=decoded(raw)
    diagnostic['phase']='AUTHORIZE'
    root,d,policy,g,E,S,O=authorize(r);E.require_runtime_capabilities();scope=actual_scope(E,d['nonce'],r['shared_timing'],closing)
    resource.setrlimit(resource.RLIMIT_AS,(PROPOSAL['controller_AS_bytes'],)*2);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    resource.setrlimit(resource.RLIMIT_CPU,(min(CLOSE_SECONDS if closing else 3600,math.floor(remaining(r['shared_timing']))),)*2)
    diagnostic['phase']='STORAGE'
    storage=RootStorage(r,E,O,g,d);storage.policy=policy
    if closing:
        if not storage.admin.exists():
            need(not storage.mount.exists(),'unknown storage parent without owned custody; never clean foreign volume')
            stage_absence=absent(d['nonce'],r['shared_timing']['deadline_monotonic'])
            need(stage_absence.get('scope')==scope_name(d['nonce'])and stage_absence.get('absent_twice')is True,'actual never-allocated staging scope absence')
            receipt=dict(owned_storage_absent=not storage.mount.exists()and not storage.backing.exists(),submitted_storage=False,scope_absence=stage_absence,**FINAL)
        else:
            storage.reopen()
            if not storage.owned['closed']:
                props=decoded_scope_properties(storage.run('systemctl',['show',scope_name(d['nonce'],True),'--no-pager','--property=ControlGroup,RuntimeMaxUSec,ActiveEnterTimestampMonotonic']))
                check_scope_properties(E,props,scope,r['shared_timing'],CLOSE_SECONDS)
            receipt=storage.close()
        target=Path(r['control_root'])/'material-domain-close.json'
        receipt.update(binding=r['context']['binding'],nonce=d['nonce'],request_pin=pin(encoded(r)))
        if target.exists():need(decoded(read(target))==receipt,'never overwrite a different close receipt')
        else:write(target,receipt);os.chown(target,r['runner_uid'],r['runner_gid'])
        return
    storage.begin()
    # Actual systemd activation/runtime observation must precede secret use.
    diagnostic['phase']='SCOPE'
    raw_props=storage.run('systemctl',['show',scope_name(d['nonce']),'--no-pager','--property=ControlGroup,RuntimeMaxUSec,ActiveEnterTimestampMonotonic'])
    props=decoded_scope_properties(raw_props)
    end=check_scope_properties(E,props,scope,r['shared_timing'],3600)
    need(time.monotonic()+30<end,'remaining physical staging scope budget')
    diagnostic['phase']='STORAGE'
    storage.allocate()
    diagnostic['phase']='NATIVE_CONTEXT'
    os.setgroups([]);os.setgid(r['runner_gid']);os.setuid(r['runner_uid'])
    need(os.getuid()==os.geteuid()==r['runner_uid']and os.getgid()==r['runner_gid'],'actual ordinary runner after one-way drop')
    os.environ.clear();os.environ.update(PATH='/usr/bin:/usr/sbin:/bin',HOME=str(g['storage_parent']),LC_ALL='C',LANG='C')
    diagnostic['phase']='INPUTS'
    metadata=staging_inputs(root,d);values=secret_input(S.secret_names())
    try:
        diagnostic['phase']='INPUTS'
        S.stage_materials(source_root=root,delegation_raw=r['delegation_raw'].encode(),delegation_sha256=r['delegation_sha256'],context=r['context'],
            grant_raw=r['grant_raw'].encode(),grant_sha256=r['grant_sha256'],output=Path(g['storage_parent'])/('cachy-current-materials-'+d['nonce']),
            secret_provider=S.OneShotSecrets(values),base_lock=metadata['base_lock'],bootstrap_profile=metadata['bootstrap_profile'])
    finally:values.clear()


def main():
    parser=argparse.ArgumentParser();parser.add_argument('mode',choices=('stage-entry','close-entry'))
    parser.add_argument('--request',type=Path,required=True);parser.add_argument('--request-sha256',required=True);args=parser.parse_args()
    diagnostic=dict(phase='ENTRY')
    try:root_entry(args.request,args.request_sha256,args.mode=='close-entry',_diagnostic=diagnostic)
    except BaseException as error:
        try:emitted=getattr(error,'_current_material_failure_emitted',False)is True
        except BaseException:emitted=False
        if args.mode=='stage-entry'and not emitted:emit_failure(diagnostic,error)
        raise SystemExit(2)from None


if __name__=='__main__':main()
