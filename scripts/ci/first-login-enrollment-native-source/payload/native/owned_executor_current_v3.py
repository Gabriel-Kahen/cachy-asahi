#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Unissued current-onboarding owned executor; import performs no host operation.

The controller owns finite systemd/storage domains. The ordinary owner exposes
facts/run only after replaying poststart context and kernel custody observations.
"""
import argparse
import copy
import fcntl
import grp
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import re
import resource
import select
import signal
import shutil
import stat
import subprocess
import sys
import time

API = 'CURRENT_ONBOARDING_IMAGE_EXECUTOR_V3'
OWNED_SHA = '83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f'
TOOL_RESOLVER_BASE = dict(commit='a645b938136fbc5106afc41e7e47882c2e260233', path='scripts/ci/fish-config02-native-source/successor_v2/host_tools.py')
NAMES = ('systemd-run','systemctl','dockerd','docker','fallocate','losetup','mkfs.ext4',
         'mount','umount','python3','gpg','gpgconf','gpg-connect-agent','bsdtar','zstd','env')
CANDIDATES = {name:('/usr/bin/'+name,'/usr/sbin/'+name) for name in NAMES}
MAX_BINARY = 256*1024**2
FIELDS = ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')
LIMIT_FILES = ('memory.max','memory.swap.max','pids.max','cpu.max')
MAX_OUTPUT = 1024**2
FINAL = dict(Root_final_acceptance=None,independent_component_acceptance=False,hardware_acceptance=False,release_acceptance=False)

def need(ok, why):
    if not ok:
        raise ValueError(why)


class UnsupportedRuntime(ValueError):
    pass


def runtime_capabilities():
    """Report interpreter exports only; this is never kernel qualification."""
    functions=((os,'os','memfd_create'),(os,'os','pidfd_open'))
    constants=((os,'os','MFD_CLOEXEC'),(os,'os','MFD_ALLOW_SEALING'),
               (fcntl,'fcntl','F_ADD_SEALS'),(fcntl,'fcntl','F_SEAL_GROW'),(fcntl,'fcntl','F_SEAL_SHRINK'))
    missing=[group+'.'+name for module,group,name in functions if not callable(getattr(module,name,None))]
    missing += [group+'.'+name for module,group,name in constants
                if type(getattr(module,name,None))is not int or getattr(module,name)<=0]
    return dict(kind='CURRENT_EXECUTOR_RUNTIME_API_EXPORTS_V3',missing=missing,
                api_exports_available=not missing,kernel_qualification=False)


def require_runtime_capabilities():
    observed=runtime_capabilities()
    if observed['missing']:
        raise UnsupportedRuntime('HOLD_UNSUPPORTED_EXECUTOR_RUNTIME: '+', '.join(observed['missing']))
    return observed


def stderr_buffer():
    """Create the real bounded sealed buffer, or refuse without a substitute."""
    require_runtime_capabilities()
    fd=os.memfd_create('current-executor-stderr',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    try:
        os.ftruncate(fd,MAX_OUTPUT)
        fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK)
        return os.fdopen(fd,'r+b',buffering=0)
    except BaseException:
        os.close(fd)
        raise


def tool_metadata(info):
    return {name: getattr(info, name) for name in FIELDS}


def tool_chain(path, root, uid):
    result = []
    for member in reversed((path, *path.parents)):
        if member != root and root not in member.parents:
            continue
        info = member.lstat()
        need(info.st_uid == uid, 'root-owned executable path chain')
        row = dict(path=str(member), metadata=tool_metadata(info))
        if stat.S_ISLNK(info.st_mode):
            row['link'] = os.readlink(member)
        else:
            need(not info.st_mode & 0o022, 'non-writable executable path chain')
        result.append(row)
    return result


def inspect_tool(candidate, *, root=Path('/'), trusted_uid=0):
    """Observe one fixed candidate; root/uid overrides are inert fixture seams.

    Operational callers use the default host root and uid 0, never input/env
    selected filesystem roots or owners.
    """
    need(candidate in {p for rows in CANDIDATES.values() for p in rows}, 'fixed host tool candidate')
    root = Path(root)
    need(root.is_absolute() and root == root.resolve(), 'canonical executable observation root')
    path = root/candidate.lstrip('/')
    path.lstat()  # Distinguish absent candidates from malformed/dangling aliases.
    try:
        target = path.resolve(strict=True)
    except FileNotFoundError as error:
        raise ValueError('present dangling executable alias') from error
    relative = target.relative_to(root)
    need(str(relative.parent) in ('usr/bin', 'usr/sbin'), 'canonical executable in finite host directories')
    name = Path(candidate).name
    aliases = {name}
    if name == 'mkfs.ext4':
        aliases.add('mke2fs')
    need(target.name in aliases or name == 'python3' and re.fullmatch(r'python3\.[0-9]{1,2}', target.name),
         'explicit executable alias only')
    chain = tool_chain(path, root, trusted_uid)
    target_chain = tool_chain(target, root, trusted_uid)
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == trusted_uid and before.st_nlink >= 1
             and 0 < before.st_size <= MAX_BINARY and before.st_mode & 0o111 and not before.st_mode & 0o022
             and os.access(target, os.X_OK), 'root-owned executable non-writable bounded ordinary binary')
        digest, size = hashlib.sha256(), 0
        while block := os.read(fd, min(65536, MAX_BINARY+1-size)):
            size += len(block)
            need(size <= MAX_BINARY, 'whole executable size cap')
            digest.update(block)
        need(size == before.st_size and tool_metadata(before) == tool_metadata(os.fstat(fd)) == tool_metadata(target.lstat())
             and chain == tool_chain(path, root, trusted_uid) and target_chain == tool_chain(target, root, trusted_uid)
             and target == path.resolve(strict=True), 'unchanged whole executable and alias chain')
        return dict(candidate=candidate, path=str(target), metadata=tool_metadata(before),
                    bytes=size, sha256=digest.hexdigest(), chain=chain, target_chain=target_chain)
    finally:
        os.close(fd)


def probe_tools(observer=None):
    observer = inspect_tool if observer is None else observer
    rows = {}
    for name, candidates in CANDIDATES.items():
        attempts, accepted, invalid = [], [], False
        for candidate in candidates:
            try:
                row = observer(candidate)
                accepted.append(row)
                attempts.append(dict(candidate=candidate, status='OBSERVED', observation=row))
            except FileNotFoundError:
                attempts.append(dict(candidate=candidate, status='MISSING'))
            except (OSError, ValueError, RuntimeError) as error:
                invalid = True
                attempts.append(dict(candidate=candidate, status='INVALID', error=type(error).__name__, message=str(error)[:240]))
        selected = accepted[0] if accepted and not invalid else None
        rows[name] = dict(status='OBSERVED' if selected else 'HOLD', selected=selected, candidates=attempts)
    return dict(kind='CURRENT_ONBOARDING_HOST_TOOL_OBSERVATIONS_V3', tools=rows,
                missing_or_invalid=[name for name in NAMES if rows[name]['selected'] is None])


def checked_tool(row):
    current = inspect_tool(row['candidate'])
    need(current == row, 'host executable/alias/metadata/body drift before use')
    return current['path']


def encoded(value):
    return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def pin(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def read_data(path,cap=2*1024**2):
    path=Path(path)
    need(path.is_absolute() and path==path.resolve() and all(not p.is_symlink() for p in (path,*path.parents)), 'ordinary absolute DATA')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=cap and not before.st_mode&0o022,'bounded ordinary DATA')
        raw=b''
        while block:=os.read(fd,min(65536,cap+1-len(raw))):
            raw+=block;need(len(raw)<=cap,'DATA cap')
        identity=lambda s:tuple(getattr(s,k)for k in FIELDS)
        need(len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'DATA changed')
        return raw
    finally:os.close(fd)


def write_data(path,value,uid=None,gid=None,mode=0o600):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb')as stream:stream.write(encoded(value))
    os.chmod(path,mode)
    if uid is not None:os.chown(path,uid,gid)


def load_pinned(root,row,name,expected=None):
    member=Path(row['member'])
    need(not member.is_absolute() and '..'not in member.parts,'closed Source program')
    path=Path(root)/member;raw=read_data(path,128*1024)
    need(pin(raw)=={k:row[k]for k in ('bytes','sha256')} and (expected is None or pin(raw)['sha256']==expected),'whole selected program pin')
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    exec(compile(raw,str(path),'exec'),module.__dict__)
    return module


def natural(row,expected=0):
    need(type(expected)is int and row['reaped']is True and row['ownership']=='REAPED'
         and row['group_census']=='EMPTY_TWICE' and row['output_complete']is True and row['signals']==[]
         and row['timeout']is False and row['error']is None and type(row['exit'])is int and row['exit']==expected,
         'natural complete owned command retirement')


def kernel_domain(pid):
    proc=Path('/proc')/str(pid);text=(proc/'stat').read_text();fields=text.rpartition(')')[2].split()
    raw=(proc/'cgroup').read_text().strip()
    need(len(text)<4096 and int(text.split('(',1)[0])==pid and raw.startswith('0::/') and '\n'not in raw,'actual unified process identity')
    group=raw[3:];need('..'not in Path(group).parts,'ordinary cgroup path')
    return dict(pid=pid,starttime=int(fields[19]),cgroup=group,
                limits={k:(Path('/sys/fs/cgroup'+group)/k).read_text().strip()for k in LIMIT_FILES},
                executable=str((proc/'exe').resolve()))


def alive(fd):
    poll=select.poll();poll.register(fd,select.POLLIN)
    return not poll.poll(0)


def check_domain(row,expected,cgroup=None):
    need(type(row['pid'])is int and row['pid']>0 and type(row['starttime'])is int and row['starttime']>0
         and row['limits']==expected and (cgroup is None or row['cgroup']==cgroup),'exact finite observed domain')


def validate_policy(policy,delegation):
    p=policy['executor_current_v3'];cap=delegation['capability']
    need(p['kind']=='CURRENT_ONBOARDING_OWNED_DOMAINS_PROPOSAL_V3' and p['Root_issuance']is None
         and p['review_state']=='PROPOSED_REQUIRES_SEPARATE_ROOT_DELEGATION' and p['shared_daemon']is False,
         'explicit unissued owned-domain proposal')
    for role in ('controller','owner','daemon'):
        limits=p['controller']if role=='controller'else policy['image_domains'][role]
        need(set(limits)==set(LIMIT_FILES) and all(type(limits[k])is str and limits[k].isdecimal() and int(limits[k])>0 for k in ('memory.max','pids.max'))
             and limits['memory.swap.max']=='0' and re.fullmatch('[1-9][0-9]* 100000',limits['cpu.max']), 'finite separately proposed domain ceilings')
    for key in ('controller_AS_bytes','owner_AS_bytes'):
        need(type(p[key])is int and 0<p[key]<=8*1024**3,'finite proposed interpreter address space')
    for key in ('setup_seconds','stage_seconds','cleanup_seconds','service_seconds','controller_seconds','controller_command_rows'):
        need(type(p[key])is int and 0<p[key]<=14400,'finite whole-stage policy')
    need(type(p['owner_poll_seconds'])is int and 5<=p['owner_poll_seconds']<=30
         and p['controller_command_rows']>=math.ceil(p['stage_seconds']/p['owner_poll_seconds'])+256,'finite polling fits controller receipt budget')
    need(p['stage_seconds']==cap['total_seconds'] and cap['max_command_seconds']>=1800
         and p['service_seconds']==p['stage_seconds']+p['cleanup_seconds']
         and p['controller_seconds']==p['setup_seconds']+p['service_seconds'],'explicit stage/bootstrap/cleanup budget')
    need(policy['image_steps']==dict(verification_seconds=60,bootstrap_seconds=1800,stage_seconds=180,inspect_seconds=15,cleanup_seconds=90), 'held image command bounds unchanged')
    need(cap['builder_cpus']==4 and cap['builder_memory_bytes']==4*1024**3 and cap['builder_pids']==512
         and cap['command_rows']<=512,'held builder caps unchanged')
    memory=sum(int((p['controller']if role=='controller'else policy['image_domains'][role])['memory.max'])for role in ('controller','owner','daemon'))
    need(p['minimum_available_bytes']>=memory+p['host_reserve_bytes']
         and p['controller_receipt_bytes']>=p['controller_command_rows']*(2*MAX_OUTPUT+65536)
         and p['minimum_disk_bytes']>=policy['image_storage_bytes']+p['host_reserve_bytes']+p['controller_receipt_bytes']+p['public_evidence_bytes'],'aggregate proposed admission inequalities')
    need(type(policy['image_storage_bytes'])is int and policy['image_storage_bytes']>0,'finite storage allocation')
    return p


class CommandEngine:
    """One held child at a time; stdout and separately bounded stderr stay distinct."""
    def __init__(self,owned,tools,work,deadline,rows):
        self.owned,self.tools,self.work,self.deadline,self.maximum=owned,tools,Path(work),deadline,rows
        self.receipts=[]
    def resolve(self,argv):
        need(type(argv)is list and 0<len(argv)<=256 and all(type(a)is str and '\0'not in a and len(a)<=8192 for a in argv)
             and sum(len(a.encode('utf-8'))for a in argv)<=65536,'bounded exact string argv')
        selected=[(name,row)for name,row in self.tools.items()if argv[0]in (row['path'],*CANDIDATES[name])]
        need(len(selected)==1,'one observed finite executable')
        name,row=selected[0];actual=[checked_tool(row),*argv[1:]];used={name:copy.deepcopy(row)}
        if name=='env':
            need(len(argv)>4 and argv[1]=='DOCKER_BUILDKIT=0' and argv[2]in CANDIDATES['docker'],'only explicit legacy Docker env wrapper')
            actual[2]=checked_tool(self.tools['docker']);used['docker']=copy.deepcopy(self.tools['docker'])
        return actual,used
    def run(self,step,argv,timeout_seconds,expected=0,*,_observe_exit=False):
        require_runtime_capabilities()
        need(type(step)is str and re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}',step)
             and all(r['step']!=step for r in self.receipts) and len(self.receipts)<self.maximum,'finite unique command step')
        need(type(timeout_seconds)in (int,float) and math.isfinite(timeout_seconds) and timeout_seconds>1 and type(expected)is int,'finite explicit command/exit')
        actual,tools=self.resolve(argv);remaining=self.deadline-time.monotonic();cap=min(timeout_seconds,remaining)
        need(cap>1,'whole-stage deadline before spawn')
        index=len(self.receipts);stderr=self.work/('stderr-%04d.bin'%index);started=time.monotonic()
        row=dict(step=step,argv=list(argv),executed_argv=actual,expected=expected,timeout_seconds=timeout_seconds,
                 supervision_cap_seconds=cap,tools=tools,exit=None,output_pin=None,stderr_pin=None,supervision=None)
        self.receipts.append(row)  # Failed submission remains associated with its exact intent.
        # A sealed-size memfd bounds stderr alone, without imposing a file-size
        # limit on legitimate Docker copy/archive outputs or daemon layers.
        primary=None
        try:
            with stderr_buffer()as error_stream:
                self.owned.prepare()
                child=subprocess.Popen(actual,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=error_stream,
                    cwd=self.work,env=self.environment(),start_new_session=True)
                # Transfer immediately, even if spawn consumed the budget. The
                # minimum is retirement only; it cannot become a successful run.
                left=cap-(time.monotonic()-started)
                supervision=self.owned.supervise(child,cap=max(.6,left),retirement=.5,grace=.1,max_output=MAX_OUTPUT)
                size=error_stream.tell();error_stream.seek(0);errors=error_stream.read(min(size,MAX_OUTPUT))
            stdout=supervision.pop('output')
            row.update(exit=supervision['exit'],output_pin=pin(stdout),stderr_pin=pin(errors),supervision=supervision)
            stderr.write_bytes(errors);stderr.chmod(0o600)
            (self.work/('stdout-%04d.bin'%index)).write_bytes(stdout)
            need(size<MAX_OUTPUT and left>1,'complete stderr and remaining command budget')
            if _observe_exit:
                need(type(supervision['exit'])is int and supervision['exit']>=0,'natural observed status exit')
                row['expected']=supervision['exit'];row['expected_policy']='OBSERVE_STATUS_ONLY'
            natural(supervision,row['expected'])
            return dict(stdout=stdout,stderr=errors,receipt=copy.deepcopy(row))
        except BaseException as error:
            primary=error;row['failure']=dict(type=type(error).__name__,message=str(error)[:240]);raise
        finally:
            try:write_data(self.work/('command-%04d.json'%index),row)
            except BaseException:
                if primary is None:raise
    def environment(self):
        return dict(PATH='/usr/bin:/usr/sbin:/bin',HOME=str(self.work),TMPDIR=str(self.work/'tmp'),
                    XDG_CACHE_HOME=str(self.work/'cache'),LC_ALL='C',LANG='C',DOCKER_BUILDKIT='0')


class Executor(CommandEngine):
    """Image executor, constructed only inside the actual ordinary owner service."""
    def __init__(self,delegation,context,policy,source_root,observation,work,context_program):
        require_runtime_capabilities()
        need(context['binding']['attempt']==1
             and all(type(context['binding'][k])is str and re.fullmatch('[1-9][0-9]{0,19}',context['binding'][k])for k in ('run','job')),'actual poststart run/job, never future IDs')
        context_contract(delegation,context,context_program,source_root)
        context_program.validate_context(delegation,context);validate_policy(policy,delegation)
        need(os.uname().sysname=='Linux' and os.uname().machine=='aarch64' and os.getuid()==os.geteuid()>0,'actual ordinary native ARM owner')
        self.context,self.policy,self.observation=copy.deepcopy(context),copy.deepcopy(policy),copy.deepcopy(observation)
        need(observation['binding']==context['binding'] and observation['nonce']==context['nonce'] and observation['stage']==context['stage']
             and observation['code_pin']=={k:delegation['programs']['image_executor'][k]for k in ('bytes','sha256')},'same poststart context/executor')
        self.pidfds={}
        need(observation['service_seconds']==policy['executor_current_v3']['service_seconds'] and type(observation['work_deadline'])in (int,float)
             and math.isfinite(observation['work_deadline']) and time.monotonic()<observation['work_deadline']<=time.monotonic()+policy['executor_current_v3']['controller_seconds']
             and all(type(observation['service_runtimes'][role])is int and 0<observation['service_runtimes'][role]<=observation['service_seconds']for role in ('owner','daemon')),'finite actual whole-stage observation')
        try:
            for role in ('owner','daemon'):
                expected=observation[role+'_domain'];fd=os.pidfd_open(expected['pid'],0);self.pidfds[role]=fd
                need(alive(fd),'live observed service PIDFD')
                actual=kernel_domain(expected['pid']);need(actual==expected,'same actual PID/start/cgroup/tool/limits')
                check_domain(actual,policy['image_domains'][role]);need(alive(fd),'same still-live PIDFD after observation')
            need(observation['owner_domain']['pid']==os.getpid(),'actual executing owner PID')
            parent=Path('/sys/fs/cgroup'+observation['daemon_domain']['cgroup']).parent
            need({key:(parent/key).read_text().strip()for key in LIMIT_FILES}==policy['image_domains']['daemon'],'actual aggregate daemon/container domain')
            need(observation['docker_endpoint']==policy['image_endpoint_template'].format(nonce=context['nonce'])
                 and observation['exclusive_daemon']is True,'explicit private daemon endpoint')
            self.check_storage(work)
            owned=load_pinned(source_root,delegation['programs']['owned_process'],'current_owned_process',OWNED_SHA)
            super().__init__(owned,observation['tools'],work,observation['work_deadline'],delegation['capability']['command_rows'])
            self.maximum_command_seconds=delegation['capability']['max_command_seconds']
            self.endpoint=observation['docker_endpoint']
            self._facts=dict(api=API,binding=copy.deepcopy(context['binding']),stage=context['stage'],nonce=context['nonce'],
                code_pin=observation['code_pin'],domain_policy_pin=context['policy_pin'],native_architecture='aarch64',
                owner_domain=observation['owner_domain'],daemon_domain=observation['daemon_domain'],
                uid=os.getuid(),gid=os.getgid(),daemon_pidfd_held=True,whole_owner_deadline_enforced=True,
                daemon_deadline_enforced=True,exclusive_daemon=True,docker_endpoint=observation['docker_endpoint'],
                storage=observation['storage'],engine_id=observation['engine_id'],tool_observations=observation['tools'],
                supervision_program_pin={k:delegation['programs']['owned_process'][k]for k in ('bytes','sha256')},**FINAL)
        except BaseException:
            self.close();raise
    @property
    def facts(self):return copy.deepcopy(self._facts)
    def check_storage(self,work):
        storage=self.observation['storage'];device=storage['device']
        need(storage['quota_bytes']==self.policy['image_storage_bytes'] and storage['kernel_enforced']is True
             and storage['scope']=='ALL_IMAGE_OWNER_CONTEXT_DAEMON_WRITES','whole allocated storage domain')
        need(all(Path(path).stat().st_dev==device for path in (work,'/tmp','/var/tmp')),'work and both temporary aliases use allocated filesystem')
        socket=Path(self.observation['docker_endpoint'][7:]).stat()
        need(stat.S_ISSOCK(socket.st_mode) and socket.st_uid==0 and socket.st_gid==os.getgid() and stat.S_IMODE(socket.st_mode)==0o660,'same private socket owner/mode')
    def live(self):
        for role,fd in self.pidfds.items():
            need(alive(fd),'owned service exited before command')
            need(kernel_domain(self.observation[role+'_domain']['pid'])==self.observation[role+'_domain'],'owned service identity drift')
            need(alive(fd),'owned service exited during observation')
    def run(self,step,argv,timeout_seconds,expected=0):
        self.live();need(type(timeout_seconds)in (int,float) and math.isfinite(timeout_seconds) and timeout_seconds<=self.maximum_command_seconds,'explicit delegated command bound')
        _,used=self.resolve(argv)
        need(set(used)<={'docker','env','gpg','gpgconf','gpg-connect-agent','bsdtar','zstd'},'image executor finite command roles')
        if 'docker'in used:
            index=2 if 'env'in used else 0
            need(argv[index+1]=='--host='+self.endpoint,'private explicit Docker endpoint before any command')
        return super().run(step,argv,timeout_seconds,expected)
    def environment(self):
        return dict(super().environment(),DOCKER_HOST=self.endpoint)
    def close(self):
        for fd in self.pidfds.values():os.close(fd)
        self.pidfds.clear()


def unit(nonce,role):
    need(re.fullmatch('[0-9a-f]{64}',nonce or '') and role in ('owner','daemon'),'nonce-bound owned unit')
    return 'cachy-current-'+nonce+'-'+role+'.service'


def runtime_microseconds(value):
    # systemctl show formats usec properties as human spans on systemd254.
    # Only exact integral units are accepted; infinity/rounding stays a HOLD.
    need(type(value)is str and 0<len(value)<=100,'bounded finite runtime property')
    if value.isdecimal():return int(value)
    units={'us':1,'ms':1000,'s':1000000,'min':60*1000000,'h':3600*1000000,'d':86400*1000000}
    parts=re.findall(r'([0-9]+)(min|us|ms|s|h|d)',value)
    need(parts and ''.join(number+unit for number,unit in parts)==re.sub(r'\s+','',value),'exact finite systemd runtime span')
    return sum(int(number)*units[unit]for number,unit in parts)


def service_args(tool,nonce,role,policy,volume,command,uid,gid,runtime_seconds=None):
    p=policy['executor_current_v3'];limits=policy['image_domains'][role]
    runtime_seconds=p['service_seconds']if runtime_seconds is None else runtime_seconds
    need(type(runtime_seconds)is int and 0<runtime_seconds<=p['service_seconds'],'finite service lifetime within proposal')
    parent='/system.slice/'+unit(nonce,role)
    args=[tool,'--quiet','--no-block','--unit='+unit(nonce,role),'--description=current-owned-'+nonce+'-'+role,
        '--property=Type=exec','--property=Restart=no','--property=OOMPolicy=kill','--property=KillMode=control-group',
        '--property=TimeoutStopSec=10s','--property=RuntimeMaxSec='+str(runtime_seconds)+'s',
        '--property=MemoryMax='+limits['memory.max'],'--property=MemorySwapMax=0',
        '--property=CPUQuota='+str(int(limits['cpu.max'].split()[0])/1000)+'%', '--property=CPUQuotaPeriodSec=100ms',
        '--property=TasksMax='+limits['pids.max'],'--property=LimitCORE=0',
        '--property=ProtectSystem=strict','--property=ReadOnlyPaths=/sys/fs/cgroup /dev/shm /proc/sys',
        '--property=StandardOutput=append:'+str(volume/(role+'.log')),
        '--property=StandardError=append:'+str(volume/(role+'.log'))]
    home=volume/'work'if role=='owner'else volume/'exec'
    args+=['--property=BindPaths='+str(home/'tmp')+':/tmp '+str(home/'var-tmp')+':/var/tmp',
           '--property=Environment=HOME='+str(home)+' TMPDIR='+str(home/'tmp')+' DOCKER_BUILDKIT=0'+(' DOCKER_TMPDIR='+str(home/'tmp')if role=='daemon'else'')]
    if role=='daemon':
        args+=['--property=Delegate=yes','--property=DelegateSubgroup=daemon',
               '--property=ReadWritePaths='+str(volume)+' /tmp /var/tmp /sys/fs/cgroup'+parent]
    else:
        args+=['--property=ReadWritePaths='+str(home)+' /tmp /var/tmp','--uid='+str(uid),'--gid='+str(gid),'--property=NoNewPrivileges=yes',
               '--property=RemainAfterExit=yes','--property=LimitAS='+str(p['owner_AS_bytes'])]
    return args+['--',*command]


class Controller:
    """Root-only setup/retirement; no command budget is treated as daemon custody."""
    def __init__(self,root,out,d,c,policy,owned,uid,gid):
        self.root,self.out,self.d,self.c,self.policy=Path(root),Path(out),d,c,policy
        self.uid,self.gid=uid,gid;self.p=validate_policy(policy,d);self.nonce=c['nonce']
        self.started=time.monotonic();self.setup_end=self.started+self.p['setup_seconds'];self.setup_complete=False;self.end=self.setup_end+self.p['stage_seconds']
        self.cleanup_end=self.end+self.p['cleanup_seconds'];self.units={};self.pidfds={};self.loop=None;self.mounted=False
        self.cleaning=False;self.O=owned;self.engine=None;self.output_created=False;self.storage_created=False
    def tool(self,name):return checked_tool(self.tools[name])
    def run(self,argv,seconds=30,expected=0,observe_exit=False):
        self.engine.deadline=self.cleanup_end if self.cleaning else (self.end if self.setup_complete else self.setup_end)
        return self.engine.run('admin-%04d'%len(self.engine.receipts),argv,seconds,expected,_observe_exit=observe_exit)['stdout']
    def preflight(self):
        require_runtime_capabilities()
        need(os.getuid()==os.geteuid()==0 and os.uname().sysname=='Linux' and os.uname().machine=='aarch64','actual native root controller')
        need(self.uid>0 and self.gid>0 and self.out==self.out.resolve() and not self.out.exists()
             and self.out==Path(self.policy['image_endpoint_template'].format(nonce=self.nonce)[7:]).parent.parent,
             'fresh exact policy-selected endpoint/storage parent')
        self.out.mkdir(mode=0o711);self.output_created=True;os.chmod(self.out,0o711);admin=self.out/'controller';admin.mkdir(mode=0o700)
        for name in ('tmp','cache'):(admin/name).mkdir(mode=0o700)
        observations=probe_tools();write_data(admin/'host-tools.json',observations)
        need(not observations['missing_or_invalid'],'finite /usr/bin and /usr/sbin tool observations required')
        self.tools={name:row['selected']for name,row in observations['tools'].items()}
        self.engine=CommandEngine(self.O,self.tools,admin,self.end,self.p['controller_command_rows'])
        actual=kernel_domain(os.getpid());expected='/system.slice/cachy-current-controller-'+self.nonce+'.scope'
        check_domain(actual,self.p['controller'],expected)
        properties=self.show_unit(expected.rsplit('/',1)[1]);runtime=runtime_microseconds(properties['RuntimeMaxUSec'])
        need(0<runtime<=self.p['controller_seconds']*1000000,'external hard finite controller scope')
        start=properties['ActiveEnterTimestampMonotonic']
        need(start.isdecimal() and int(start)>0,'actual controller activation monotonic clock')
        self.cleanup_end=min(self.cleanup_end,int(start)/1000000+runtime/1000000-1)
        self.end=min(self.end,self.cleanup_end-self.p['cleanup_seconds'])
        self.setup_end=min(self.setup_end,self.end)
        need(time.monotonic()<self.setup_end,'remaining external setup/stage budget')
        self.controller_domain=actual
        raw=self.run([self.tool('systemctl'),'--version'],10);match=re.match(rb'systemd ([0-9]+)\b',raw)
        need(match and int(match[1])>=254,'actual systemd254+ DelegateSubgroup support')
        need({'cpu','memory','pids'}<=set(Path('/sys/fs/cgroup/cgroup.controllers').read_text().split()),'actual unified controllers')
        available=int(next(line.split()[1]for line in Path('/proc/meminfo').read_text().splitlines()if line.startswith('MemAvailable:')))*1024
        need(available>=self.p['minimum_available_bytes'] and shutil.disk_usage(self.out).free>=self.p['minimum_disk_bytes'],'fresh aggregate memory/storage admission')
        need(stat.S_ISCHR(Path('/dev/loop-control').stat().st_mode),'existing kernel loop allocator')
        write_data(admin/'host-admission.json',dict(controller_domain=actual,systemd_version=int(match[1]),
            available_memory_bytes=available,available_disk_bytes=shutil.disk_usage(self.out).free,
            policy_pin=self.c['policy_pin'],binding=self.c['binding'],Root_final_acceptance=None))
    def show_unit(self,name):
        raw=self.run([self.tool('systemctl'),'show',name,'--no-pager',
            '--property=LoadState,ActiveState,SubState,Result,MainPID,ControlGroup,ExecMainCode,ExecMainStatus,Description,RuntimeMaxUSec,ActiveEnterTimestampMonotonic'],observe_exit=True)
        return dict(line.split('=',1)for line in raw.decode().splitlines()if '='in line)
    def start(self,role,argv):
        require_runtime_capabilities()
        name=unit(self.nonce,role);expected='/system.slice/'+name
        need(self.show_unit(name).get('LoadState')=='not-found','fresh exclusively named service')
        self.units[role]=dict(submitted=True,cgroup=expected,unit_cgroup=expected,pid=None)
        runtime=min(self.p['service_seconds'],math.floor(self.cleanup_end-time.monotonic()-10))
        need(runtime>1,'remaining common service and stop budget')
        self.units[role]['runtime_seconds']=runtime
        self.run(service_args(self.tool('systemd-run'),self.nonce,role,self.policy,self.out/'volume',argv,self.uid,self.gid,runtime))
        until=min(self.end,time.monotonic()+30)
        while time.monotonic()<until:
            row=self.show_unit(name)
            if row.get('ActiveState')=='active'and row.get('MainPID','0')!='0':
                need(row['Description']=='current-owned-'+self.nonce+'-'+role and row['ControlGroup']==expected
                     and runtime_microseconds(row['RuntimeMaxUSec'])==runtime*1000000,'same finite submitted service')
                pid=int(row['MainPID']);fd=os.pidfd_open(pid,0);self.pidfds[role]=fd
                need(alive(fd),'live submitted service PIDFD')
                self.units[role]['pid']=pid
                if role=='daemon':
                    parent=Path('/sys/fs/cgroup'+expected)
                    (parent/'cgroup.subtree_control').write_text('+cpu +memory +pids')
                    need({key:(parent/key).read_text().strip()for key in LIMIT_FILES}==self.policy['image_domains']['daemon'],'actual aggregate daemon/container ceiling')
                    for key,value in self.policy['image_domains']['daemon'].items():(parent/'daemon'/key).write_text(value)
                    containers=parent/'containers';containers.mkdir();(containers/'cgroup.subtree_control').write_text('+cpu +memory +pids')
                actual=kernel_domain(pid);cg=expected+'/daemon'if role=='daemon'else expected
                check_domain(actual,self.policy['image_domains'][role],cg)
                need(actual['executable']==self.tool('dockerd'if role=='daemon'else'python3') and alive(fd),'same executable and live custody before seed')
                self.units[role].update(actual)
                return actual
            need(row.get('ActiveState')not in ('failed','inactive'),'service failed before domain admission')
            time.sleep(.5)
        raise TimeoutError('owned service startup')
    def loop_identity(self):
        raw=self.run([self.tool('losetup'),'--json','--list','--output','NAME,BACK-FILE',self.loop])
        rows=json.loads(raw)['loopdevices']
        need(len(rows)==1 and rows[0]['name']==self.loop and rows[0]['back-file']==str(self.out/'storage.img'),'same exclusively allocated loop backing')
    def setup(self):
        self.preflight();quota=self.policy['image_storage_bytes'];image=self.out/'storage.img'
        fd=os.open(image,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);self.storage_created=True;os.close(fd)
        self.run([self.tool('fallocate'),'--length',str(quota),'--',str(image)],60)
        need(image.stat().st_size==quota and image.stat().st_blocks*512>=quota,'physical fixed-byte allocation')
        device=self.run([self.tool('losetup'),'--find','--show','--nooverlap',str(image)]).decode().strip()
        need(re.fullmatch('/dev/loop[0-9]+',device),'one newly allocated loop device');self.loop=device;self.loop_identity()
        self.run([self.tool('mkfs.ext4'),'-t','ext4','-q','-m','0',device],60)
        volume=self.out/'volume';volume.mkdir(mode=0o751);os.chmod(volume,0o751)
        self.run([self.tool('mount'),'-t','ext4','-o','nodev,nosuid',device,str(volume)]);self.mounted=True
        need(volume.stat().st_dev==Path(device).stat().st_rdev,'same allocated mounted block device')
        for name in ('work','data','exec'):
            folder=volume/name;folder.mkdir(mode=0o700)
            if name=='work':os.chown(folder,self.uid,self.gid)
            for temp in ('tmp','var-tmp','cache'):
                (folder/temp).mkdir(mode=0o700)
                if name=='work':os.chown(folder/temp,self.uid,self.gid)
        write_data(volume/'daemon.json',{})
        argv=[self.tool('dockerd'),'--config-file='+str(volume/'daemon.json'),
            '--host='+self.policy['image_endpoint_template'].format(nonce=self.nonce),
            '--data-root='+str(volume/'data'),'--exec-root='+str(volume/'exec'),'--pidfile='+str(volume/'docker.pid'),
            '--group='+grp.getgrgid(self.gid).gr_name,'--storage-driver=overlay2','--exec-opt=native.cgroupdriver=cgroupfs',
            '--cgroup-parent=/system.slice/'+unit(self.nonce,'daemon')+'/containers','--default-cgroupns-mode=private',
            '--bridge=none','--iptables=false','--ip6tables=false','--ip-forward=false','--ip-masq=false','--userland-proxy=false']
        daemon=self.start('daemon',argv);socket=volume/'docker.sock';until=min(self.end,time.monotonic()+30)
        while not socket.exists():
            need(time.monotonic()<until,'private daemon startup');time.sleep(.1)
        info=socket.stat();need(stat.S_ISSOCK(info.st_mode) and info.st_uid==0 and info.st_gid==self.gid and stat.S_IMODE(info.st_mode)==0o660,'private socket ownership/mode')
        raw=self.run([self.tool('docker'),'--host='+self.policy['image_endpoint_template'].format(nonce=self.nonce),'info','--format','{{json .}}'])
        info=json.loads(raw)
        need(info['DockerRootDir']==str(volume/'data') and info['CgroupDriver']=='cgroupfs' and info['Driver']=='overlay2'
             and info['OSType']=='linux' and info['Architecture']in ('aarch64','arm64') and info['CgroupVersion']=='2'
             and all(info[k]is True for k in ('MemoryLimit','SwapLimit','CpuCfsQuota','PidsLimit')),'actual dedicated bounded native daemon')
        self.setup_complete=True
        return daemon,info['ID']
    def stop(self,role):
        if role not in self.units:return dict(submitted=False)
        owned=self.units[role];name=unit(self.nonce,role);row=self.show_unit(name)
        group=Path('/sys/fs/cgroup/system.slice')/name
        owner_residue=role=='owner' and group.exists() and 'populated 0'not in(group/'cgroup.events').read_text()
        if row.get('LoadState')!='not-found':
            need(row.get('Description')=='current-owned-'+self.nonce+'-'+role and row.get('ControlGroup')in ('',owned['unit_cgroup']),'owned service before stop')
            if role in self.pidfds and alive(self.pidfds[role]):
                need(row.get('MainPID')==str(owned['pid']),'same held live service identity')
                fields=('pid','starttime','cgroup','limits','executable')
                if all(k in owned for k in fields):need(kernel_domain(owned['pid'])=={k:owned[k]for k in fields},'same owned process before stop')
            self.run([self.tool('systemctl'),'stop',name],20)
        for _ in range(2):
            row=self.show_unit(name)
            need(row.get('ActiveState')in ('inactive','failed')or row.get('LoadState')=='not-found','service inactive')
            need(not group.exists()or'populated 0'in(group/'cgroup.events').read_text(),'whole owned service cgroup empty')
            if role in self.pidfds:need(not alive(self.pidfds[role]),'original held service exited')
            time.sleep(.05)
        return dict(unit=name,empty_twice=True,pidfd_exited=role in self.pidfds,result=row.get('Result'),
                    owner_residue_before_stop=owner_residue,
                    natural=not owner_residue and (row.get('Result')in (None,'success')or row.get('LoadState')=='not-found'))
    def cleanup(self):
        if not self.output_created:
            return dict(services={},errors=[],owned_storage_absent=True,submitted=False)
        self.cleaning=True;self.cleanup_end=min(self.cleanup_end,time.monotonic()+self.p['cleanup_seconds']);errors=[];services={}
        for role in ('owner','daemon'):
            try:services[role]=self.stop(role)
            except BaseException as error:errors.append(dict(step=role,error=type(error).__name__,message=str(error)[:240]))
        if not errors:
            try:self.retain()
            except BaseException as error:errors.append(dict(step='retention',error=type(error).__name__,message=str(error)[:240]))
        if not errors:
            try:
                image=self.out/'storage.img'
                if image.exists():
                    need(self.storage_created,'foreign backing file is never adopted')
                    rows=json.loads(self.run([self.tool('losetup'),'--json','--list','--associated',str(image),'--output','NAME,BACK-FILE']))['loopdevices']
                    need(len(rows)<=1,'at most one owned loop association')
                    if rows:
                        need(rows[0]['back-file']==str(image) and re.fullmatch('/dev/loop[0-9]+',rows[0]['name']),'exact owned backing association')
                        self.loop=rows[0]['name']
                volume=self.out/'volume'
                self.mounted=volume.exists()and os.path.ismount(volume)
                if self.mounted:
                    need(self.loop is not None and volume.stat().st_dev==Path(self.loop).stat().st_rdev,'same storage before unmount')
                    self.run([self.tool('umount'),str(volume)],20);self.mounted=False
                if self.loop:
                    self.loop_identity();self.run([self.tool('losetup'),'--detach',self.loop]);self.loop=None
                    need(not json.loads(self.run([self.tool('losetup'),'--json','--list','--associated',str(image),'--output','NAME,BACK-FILE']))['loopdevices'],'owned loop absent after detach')
                if image.exists():image.unlink()
            except BaseException as error:errors.append(dict(step='storage',error=type(error).__name__,message=str(error)[:240]))
        for fd in self.pidfds.values():os.close(fd)
        self.pidfds.clear()
        return dict(services=services,errors=errors,owned_storage_absent=not self.mounted and self.loop is None and not(self.out/'storage.img').exists())

    def execute(self,request):
        daemon,engine_id=self.setup();volume=self.out/'volume';work=volume/'work'
        launch=dict(delegation=self.d,context=self.c,source_root=str(self.root),policy=self.policy,
                    observation=str(volume/'observation.json'),work=str(work),inputs=request)
        write_data(volume/'launch.json',launch,mode=0o644)
        owner=self.start('owner',[self.tool('python3'),'-I','-B',str(Path(__file__).resolve()),'owner',str(volume/'launch.json')])
        observation=dict(api=API,binding=self.c['binding'],nonce=self.nonce,stage=self.c['stage'],
            code_pin={k:self.d['programs']['image_executor'][k]for k in ('bytes','sha256')},
            owner_domain=owner,daemon_domain=daemon,tools=self.tools,engine_id=engine_id,exclusive_daemon=True,
            docker_endpoint=self.policy['image_endpoint_template'].format(nonce=self.nonce),work_deadline=self.end,
            storage=dict(quota_bytes=self.policy['image_storage_bytes'],kernel_enforced=True,
                         scope='ALL_IMAGE_OWNER_CONTEXT_DAEMON_WRITES',device=volume.stat().st_dev),
            controller_domain=self.controller_domain,service_seconds=self.p['service_seconds'],
            service_runtimes={role:self.units[role]['runtime_seconds']for role in ('owner','daemon')},
            common_cleanup_deadline=self.cleanup_end,**FINAL)
        write_data(volume/'observation.json',observation,mode=0o644)
        while time.monotonic()<self.end:
            row=self.show_unit(unit(self.nonce,'owner'))
            if row.get('SubState')=='exited' or row.get('ActiveState')in ('inactive','failed'):
                need(not alive(self.pidfds['owner']),'original owner exited before result')
                need(row.get('Result')=='success' and row.get('ExecMainCode')=='1' and row.get('ExecMainStatus')=='0','natural delegated owner completion')
                remaining=self.run([self.tool('docker'),'--host='+self.policy['image_endpoint_template'].format(nonce=self.nonce),'container','ls','--all','--quiet','--no-trunc'])
                need(not remaining.strip(),'no surviving containers in the exclusively owned daemon')
                result=json.loads(read_data(work/'owner-result.json'))
                need(result['binding']==self.c['binding'] and result['status']=='DELEGATED_OWNER_RETURNED_DATA_ONLY'
                     and result['Root_final_acceptance']is None,'same unaccepted delegated owner result')
                return result
            need(alive(self.pidfds['daemon']),'dedicated daemon lost during stage');time.sleep(self.p['owner_poll_seconds'])
        raise TimeoutError('finite whole owned stage expired')
    def retain(self):
        """Copy only bounded public callback output and receipts; never daemon data."""
        if not self.mounted:return
        target=self.out/'evidence';target.mkdir(mode=0o700);total=0;count=0
        roots=[(self.out/'volume/work/public','public')]
        for name in ('owner.log','daemon.log'):
            source=self.out/'volume'/name
            if source.exists():
                raw=read_data(source,64*1024**2);total+=len(raw);(target/name).write_bytes(raw)
        source=self.out/'volume/work/owner-result.json'
        if source.exists():
            raw=read_data(source);total+=len(raw);(target/'owner-result.json').write_bytes(raw)
        need(total<=self.p['public_evidence_bytes'],'finite public receipt bytes')
        for source,label in roots:
            if not source.exists():continue
            for path in source.rglob('*'):
                need(not path.is_symlink(),'ordinary selected public evidence')
                if path.is_dir():continue
                count+=1;need(count<=4096,'finite public evidence count');raw=read_data(path,64*1024**2);total+=len(raw)
                need(total<=self.p['public_evidence_bytes'],'finite selected public evidence bytes')
                dest=target/label/path.relative_to(source);dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(raw)
        for path in [*target.rglob('*'),target]:
            os.chown(path,self.uid,self.gid);path.chmod(0o700 if path.is_dir()else 0o600)


CONTEXT_PROGRAM_PINS={
    3:dict(bytes=21460,sha256='efa5a2687ac1504ef565763ac0828dd6c98c593563df97b2f540ccf4e0de9d2b'),
    4:dict(bytes=43482,sha256='2d08f9572b3f5f89d3ebac2b32e6d41a00ff4929739c35780c7c96a1d3d3b21d')}
CONTEXT_OPERATION='first-login-enrollment-ui-current-v2'


def context_contract(delegation,context=None,program=None,source_root=None):
    """Select one exact committed program and its schema/kind/issuer together."""
    row=delegation.get('programs',{}).get('context')
    need(type(row)is dict and set(row)=={'member','bytes','sha256'},'whole Source-selected context descriptor')
    descriptor={key:row[key]for key in ('bytes','sha256')}
    selected=[version for version,expected in CONTEXT_PROGRAM_PINS.items()if descriptor==expected]
    need(len(selected)==1,'exact committed context predecessor or v4 program')
    version=selected[0]
    delegation_kind='ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V'+str(version)
    context_kind='DELEGATED_CURRENT_ONBOARDING_CONTEXT_V'+str(version)
    issuer='DELEGATED_CONTEXT_PROGRAM_V'+str(version)
    need(type(delegation.get('schema'))is int and delegation['schema']==version
         and delegation.get('kind')==delegation_kind and delegation.get('issuer')=='Root','selected context program/delegation schema identity')
    if context is not None:
        need(type(context.get('schema'))is int and context['schema']==version and context.get('kind')==context_kind
             and context.get('issuer')==issuer and context.get('operation')==CONTEXT_OPERATION
             and context.get('program_pin')==descriptor,'selected program/context schema/kind/issuer/whole pin')
    if program is not None:
        need(program.OPERATION==CONTEXT_OPERATION and program.DELEGATION==delegation_kind
             and program.CONTEXT==context_kind and program.ISSUER==issuer,'actual context program API identity')
        member=Path(row['member'])
        need(not member.is_absolute() and '..'not in member.parts,'ordinary context Source member')
        path=Path(source_root)/member
        need(Path(program.__file__)==path and pin(read_data(path,128*1024))==descriptor,'executing exact Source-selected context body')
    return version


def admitted_inputs(source,delegation_raw,expected,context):
    need(type(delegation_raw)is bytes and pin(delegation_raw)['sha256']==expected,'external whole delegation pin before any Source import')
    preview=json.loads(delegation_raw);context_contract(preview)
    H=load_pinned(source,preview['programs']['context'],'executor_delegated_context')
    d=H.validate_delegation(delegation_raw,expected);context_contract(d,context,H,source)
    H.validate_context(d,context)
    need(context['binding']['run']is not None and context['binding']['job']is not None,'actual poststart context, never future IDs')
    body=read_data(Path(source)/d['policy']['member']);need(pin(body)=={k:d['policy'][k]for k in ('bytes','sha256')},'reviewed whole domain policy')
    own=read_data(Path(__file__).resolve(),128*1024)
    need(pin(own)=={k:d['programs']['image_executor'][k]for k in ('bytes','sha256')},'actual reviewed executor code')
    policy=json.loads(body);validate_policy(policy,d)
    owned=load_pinned(source,d['programs']['owned_process'],'current_executor_held_owner',OWNED_SHA)
    return d,H,policy,owned


def owner_main(launch_path):
    require_runtime_capabilities()
    need(sys.flags.isolated and __debug__ and os.getuid()==os.geteuid()>0,'isolated ordinary owner entry')
    launch=json.loads(read_data(launch_path));root=Path(launch['source_root']);d=launch['delegation'];c=launch['context']
    d,H,policy,_=admitted_inputs(root,encoded(d),c['delegation_pin']['sha256'],c)
    work=Path(launch['work']);os.umask(0o077)
    os.environ.clear();os.environ.update(PATH='/usr/bin:/usr/sbin:/bin',HOME=str(work),TMPDIR=str(work/'tmp'),LC_ALL='C',DOCKER_BUILDKIT='0')
    resource.setrlimit(resource.RLIMIT_AS,(policy['executor_current_v3']['owner_AS_bytes'],)*2)
    until=time.monotonic()+30;marker=Path(launch['observation'])
    while not marker.exists():
        need(time.monotonic()<until,'external owner observation required before seed');time.sleep(.05)
    observation=json.loads(read_data(marker));executor=None;result=dict(status='HOLD',binding=c['binding'],**FINAL)
    try:
        executor=Executor(d,c,policy,root,observation,work,H)
        os.environ['DOCKER_HOST']=executor.endpoint
        owner=load_pinned(root,d['programs']['owner'],'current_delegated_stage_owner')
        need(callable(getattr(owner,'run_owned_current_v3',None)),'reviewed owner must expose run_owned_current_v3 adapter')
        (work/'stage').mkdir(mode=0o700)
        value=owner.run_owned_current_v3(delegation_raw=encoded(d),delegation_sha256=c['delegation_pin']['sha256'],
            context=c,source_root=root,inputs=launch['inputs'],executor=executor,output=work/'stage',public_output=work/'public')
        need(type(value)is dict and value.get('completed')is True and value.get('binding')==c['binding']
             and 'Root_final_acceptance'in value and value['Root_final_acceptance']is None,'explicit delegated completion; no inferred stage success')
        result.update(status='DELEGATED_OWNER_RETURNED_DATA_ONLY',result=value,executor_facts=executor.facts)
    except BaseException as error:result['failure']=dict(type=type(error).__name__,message=str(error)[:1000])
    finally:
        if executor is not None:executor.close()
        write_data(work/'owner-result.json',result)
    return 0 if result['status']=='DELEGATED_OWNER_RETURNED_DATA_ONLY'else 2


def controller_main(args):
    require_runtime_capabilities()
    need(sys.flags.isolated and __debug__,'isolated unoptimized controller entry')
    root=Path(args.source_root);raw=read_data(args.delegation);context=json.loads(read_data(args.context))
    d,H,policy,owned=admitted_inputs(root,raw,args.delegation_sha256,context)
    resource.setrlimit(resource.RLIMIT_AS,(policy['executor_current_v3']['controller_AS_bytes'],)*2)
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    inputs=json.loads(read_data(args.inputs));controller=Controller(root,Path(args.output),d,context,policy,owned,args.uid,args.gid)
    report=dict(status='HOLD',binding=context['binding'],delegation_pin=pin(raw),policy_pin=context['policy_pin'],**FINAL)
    try:report['owner']=controller.execute(inputs);report['status']='DELEGATED_STAGE_RETURNED_PENDING_RETIREMENT'
    except BaseException as error:report['failure']=dict(type=type(error).__name__,message=str(error)[:1000])
    finally:
        try:report['cleanup']=controller.cleanup()
        except BaseException as error:report['cleanup']=dict(errors=[dict(type=type(error).__name__)],owned_storage_absent=False)
        if report['status']=='DELEGATED_STAGE_RETURNED_PENDING_RETIREMENT' and not report['cleanup']['errors'] and report['cleanup']['owned_storage_absent'] and 'retention_failure'not in report and all(row.get('natural',True)for row in report['cleanup']['services'].values()):
            report['status']='DELEGATED_OWNED_STAGE_RETIRED_DATA_ONLY'
        else:report['status']='HOLD'
        if controller.output_created:write_data(controller.out/'executor-report.json',report,args.uid,args.gid)
    return 0 if report['status']=='DELEGATED_OWNED_STAGE_RETIRED_DATA_ONLY'else 2


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='mode',required=True)
    owner=sub.add_parser('owner');owner.add_argument('launch',type=Path)
    controller=sub.add_parser('controller')
    for name in ('source-root','delegation','context','inputs','output'):controller.add_argument('--'+name,type=Path,required=True)
    controller.add_argument('--delegation-sha256',required=True)
    for name in ('uid','gid'):controller.add_argument('--'+name,type=int,required=True)
    args=parser.parse_args()
    return owner_main(args.launch)if args.mode=='owner'else controller_main(args)


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print('HOLD_EXECUTOR: '+type(error).__name__+': '+str(error)[:240],file=sys.stderr);raise SystemExit(2)
