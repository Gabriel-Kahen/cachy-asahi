"""Trusted precheckout launcher; execution requires Root-selected external pins.

The workflow must retain the entry before imports and forward it to the
registered controller early-entry bridge. Source registration alone does not
select a dispatch, runner, clock or execution grant.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import types
import urllib.request
from contextlib import contextmanager

REPOSITORY = 'Gabriel-Kahen/cachy-asahi'
REMOTE = 'https://github.com/' + REPOSITORY + '.git'
BOOTSTRAP_SHA = '1675fa4834f556f1eec5d10f2f53b20d0475dd1a922b4c80fb0adc38f95e9391'
ISSUER_SHA = '9e3271b8cb21e7be1940c2aa9f17f84357d0a438ed45a19ad34ae226ec9d4581'
CODE_PATHS = {'bootstrap':'.github/bootstrap/development-bootstrap.py',
              'issuer':'.github/bootstrap/development-clock-issuer.py'}
DATA_PATHS = {'selection':'.github/bootstrap/development-selection.json',
              'peer':'.github/bootstrap/development-source-peer.json'}
MODES = {'repository-svg-maintained-v1':259,'installer-preflight-maintained-v1':266}
BASELINE_ID = 'maintained-native-baseline-v1-vim-9.2.1178-1'
LINEAGE = 'SUCCESSOR_NOT_HISTORICAL_ORIGINAL'
CLOCK_KEYS = {'schema_version','purpose','source_commit','run_id','run_attempt','nonce',
    'issued_monotonic','deadline_monotonic','allowance_seconds','clock_domain',
    'issuer_source_sha256','issuer_workflow_commit'}
SIGNALS = {signal.SIGINT,signal.SIGTERM,signal.SIGALRM}


class Refused(ValueError):
    pass


class Interrupted(BaseException):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def check(end):
    need(type(end) in (int,float) and math.isfinite(end) and 0 < time.monotonic() < end,
         'launcher-deadline')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_bootstrap(bootstrap, path, end, **options):
    check(end)
    with defer_controls():
        result=bootstrap.read(path,end,**options)
    check(end)
    return result


@contextmanager
def defer_controls():
    previous=signal.pthread_sigmask(signal.SIG_BLOCK,SIGNALS)
    try:yield
    finally:
        cause=sys.exc_info()[1]
        try:signal.pthread_sigmask(signal.SIG_SETMASK,previous)
        except BaseException:
            if cause is None:raise


@contextmanager
def controls(preparation_end):
    need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'existing-timer-refused')
    previous={};started=time.monotonic()
    def interrupt(number,frame):raise Interrupted('launcher-interrupted')
    try:
        for number in SIGNALS:
            previous[number]=signal.getsignal(number)
            signal.signal(number,interrupt)
        check(preparation_end)
        signal.setitimer(signal.ITIMER_REAL,preparation_end-time.monotonic())
        yield
    finally:
        cause=sys.exc_info()[1];first=None
        try:signal.setitimer(signal.ITIMER_REAL,0)
        except BaseException as error:first=error
        for number,handler in previous.items():
            try:signal.signal(number,handler)
            except BaseException as error:first=first or error
        if cause is None and first is not None:raise first


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        raise Refused('redirect-refused')


def fetch(commit, path, pin, limit, end):
    """Only four fixed canonical paths; no auth, proxy, redirect or caller URL."""
    need(re.fullmatch('[0-9a-f]{40}',commit) and path in {*CODE_PATHS.values(),*DATA_PATHS.values()}
         and re.fullmatch('[0-9a-f]{64}',pin),'delivery-binding')
    check(end)
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    request=urllib.request.Request('https://raw.githubusercontent.com/'+REPOSITORY+'/'+commit+'/'+path)
    with opener.open(request,timeout=max(0.001,end-time.monotonic())) as reply:
        need(reply.status==200 and reply.geturl()==request.full_url,'delivery-origin')
        raw=bytearray()
        while True:
            check(end)
            block=reply.read1(min(65536,limit+1-len(raw)))
            if not block:break
            raw.extend(block);need(len(raw)<=limit,'delivery-byte-bound')
    check(end);raw=bytes(raw)
    need(digest(raw)==pin,'delivery-pin')
    return raw


def module(raw, pin, name):
    need(type(raw) is bytes and digest(raw)==pin,'code-pin')
    value=types.ModuleType(name)
    exec(compile(raw,'<Root-pinned-'+name+'>','exec'),value.__dict__)
    return value


def retire(owned):
    """Attempt every held FD once; retain files and report ambiguous close faults."""
    errors=[]
    for path,fd,before,is_directory in reversed(owned.nodes):
        if fd is None:continue
        try:
            row=os.fstat(fd)
            found=(row.st_dev,row.st_ino,row.st_mode,row.st_uid,row.st_gid,row.st_nlink)
            width=5 if is_directory else 6
            need(found[:width]==before[:width],'retirement-descriptor-foreign')
            os.close(fd)
        except BaseException as error:
            errors.append(type(error).__name__)
    owned.nodes.clear()
    return errors


def run(argv, environment, cwd, end, *, spawn_deadline=None, workspace_owner=None):
    """One owned process group, bounded pipes and cleanup inside retained end."""
    check(end)
    process=None;pipe=None;first=None;output=bytearray();code=None
    streaming=(len(argv)>4 and argv[:4]==[sys.executable,'-E','-s','-B'] and
        argv[4]==str(Path(environment.get('GITHUB_WORKSPACE',''))/'scripts/ci/development/controller.py') and
        cwd==environment.get('GITHUB_WORKSPACE'))
    work=end if streaming else end-10
    check(work)
    if spawn_deadline is not None:check(spawn_deadline)
    spawn_end=work if spawn_deadline is None else min(work,spawn_deadline)
    check(spawn_end)
    try:
        previous=signal.pthread_sigmask(signal.SIG_BLOCK,SIGNALS)
        try:
            argv=list(argv);environment=dict(environment);check(spawn_end)
            if workspace_owner is not None:workspace_owner.verify(spawn_end)
            check(spawn_end)
            process=subprocess.Popen(argv,env=environment,cwd=cwd,stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True,close_fds=True,
                preexec_fn=lambda:signal.pthread_sigmask(signal.SIG_SETMASK,previous))
            pipe=process.stdout
        finally:
            cause=sys.exc_info()[1]
            try:signal.pthread_sigmask(signal.SIG_SETMASK,previous)
            except BaseException:
                if cause is None:raise
        with selectors.DefaultSelector() as selector:
            selector.register(pipe,selectors.EVENT_READ)
            while selector.get_map() or process.poll() is None:
                check(work)
                for key,_ in selector.select(min(0.1,max(0,work-time.monotonic()))):
                    block=os.read(key.fd,65536)
                    if not block:selector.unregister(key.fileobj)
                    else:
                        if streaming:
                            # Preserve the controller's existing bounded publication
                            # stream; imposing a new total4MiB cap would truncate it.
                            position=0
                            while position<len(block):
                                check(work)
                                count=os.write(sys.stdout.fileno(),block[position:])
                                need(count>0,'publication-short-write');position+=count
                        else:
                            output.extend(block);need(len(output)<=4*1024**2,'command-output-bound')
            code=process.wait(timeout=max(0,min(1,work-time.monotonic())))
            check(work)
    except BaseException as error:
        first=error
    finally:
        if process is not None:
            for number in (signal.SIGTERM,signal.SIGKILL):
                try:os.killpg(process.pid,number)
                except ProcessLookupError:pass
                except BaseException as error:first=first or error
                try:process.wait(timeout=max(0,min(2,end-time.monotonic())))
                except subprocess.TimeoutExpired:pass
                except BaseException as error:first=first or error
            try:
                need(process.poll() is not None,'child-reap-unproved')
                try:os.killpg(process.pid,0)
                except ProcessLookupError:pass
                else:raise Refused('group-absence-unproved')
            except BaseException as error:first=first or error
        if pipe is not None:
            try:pipe.close()
            except BaseException as error:first=first or error
    if first is not None:raise first
    check(end)
    return code,bytes(output)


def git_environment(prepared):
    paths=prepared['paths']
    return {'PATH':'/usr/bin:/bin','HOME':str(paths['tools']/'home'),'LC_ALL':'C',
        'TMPDIR':str(paths['tools']/'tmp'),'GIT_TERMINAL_PROMPT':'0','GIT_CONFIG_NOSYSTEM':'1',
        'GIT_CONFIG_SYSTEM':'/dev/null','GIT_CONFIG_GLOBAL':'/dev/null','GIT_LFS_SKIP_SMUDGE':'1'}


def checkout(bootstrap, prepared, plan, end, runner=run):
    """Fixed public repository/revision; no hooks, credentials or submodule actors."""
    workspace=prepared['paths']['workspace'];check(end)
    owner=prepared.get('workspace_owner')
    if owner is None:need(not os.path.lexists(workspace),'fresh-workspace-required')
    else:
        need(owner.path==workspace,'workspace-owner-binding')
        owner.verify(end,empty=True)
    tool=Path('/usr/bin/git')
    raw,found,_=read_bootstrap(bootstrap,tool,end,limit=128*1024**2,owner=0,mode=0o755)
    need(digest(raw)==plan['git_sha256'],'git-pin')
    prefix=[str(tool),'-c','credential.helper=','-c','core.hooksPath=/dev/null',
        '-c','core.fsmonitor=false','-c','core.autocrlf=false','-c','submodule.recurse=false',
        '-c','protocol.file.allow=never','-c','protocol.ext.allow=never','-c','http.followRedirects=false']
    commands=[prefix+['init','--template=','--',str(workspace)],
        prefix+['-C',str(workspace),'fetch','--quiet','--depth=1','--no-tags','--no-recurse-submodules',
                '--',REMOTE,plan['root_pins']['source_commit']],
        prefix+['-C',str(workspace),'fetch','--quiet','--depth=1','--no-tags','--no-recurse-submodules',
                '--',REMOTE,plan['data_commit']],
        prefix+['-C',str(workspace),'diff','--name-only','--no-renames',plan['root_pins']['source_commit'],plan['data_commit'],'--'],
        prefix+['-C',str(workspace),'checkout','--quiet','--detach',plan['root_pins']['source_commit'],'--'],
        prefix+['-C',str(workspace),'rev-parse','--verify','HEAD']]
    for index,argv in enumerate(commands):
        check(end)
        if owner is not None:owner.verify(end)
        current,node,_=read_bootstrap(bootstrap,tool,end,limit=128*1024**2,owner=0,mode=0o755)
        need(node==found and digest(current)==plan['git_sha256'],'git-identity-drift')
        if owner is None:code,reply=runner(argv,git_environment(prepared),None,end)
        else:code,reply=runner(argv,git_environment(prepared),None,end,workspace_owner=owner)
        if owner is not None:owner.verify(end)
        need(type(code) is int and code==0,'checkout-command-failed')
        if index==3:
            names=reply.decode('ascii').splitlines()
            need(len(names)==2 and set(names)==set(DATA_PATHS.values()),'data-only-tree-required')
        if index==5:need(reply.strip()==plan['root_pins']['source_commit'].encode(),'checkout-head')
    check(end)


def clock(bootstrap, issuer, bindings, plan, environment, entry, end):
    raw,_,_=read_bootstrap(bootstrap,Path(bindings['DEVELOPMENT_CLOCK_PATH']),end,
        limit=16*1024,owner=os.getuid(),mode=0o600)
    need(digest(raw)==bindings['DEVELOPMENT_CLOCK_SHA256'],'clock-pin')
    value=json.loads(raw)
    need(type(value) is dict and set(value)==CLOCK_KEYS and type(value['schema_version'])is int and
         value['schema_version']==1 and value['purpose']=='development-workflow-clock' and
         type(value['allowance_seconds'])is int and value['allowance_seconds']==10800 and
         value['issuer_source_sha256']==ISSUER_SHA and re.fullmatch('[0-9a-f]{32}',value['nonce']), 'clock-contract')
    for field,name in (('source_commit','GITHUB_SHA'),('issuer_workflow_commit','GITHUB_WORKFLOW_SHA'),
                       ('run_id','GITHUB_RUN_ID'),('run_attempt','GITHUB_RUN_ATTEMPT')):
        need(value[field]==environment[name],'clock-job')
    issued,workflow_end=value['issued_monotonic'],value['deadline_monotonic']
    need(all(type(item) in (int,float)and math.isfinite(item)and item>0 for item in (issued,workflow_end,entry))
         and workflow_end==issued+10800 and issued<=entry<=time.monotonic()<workflow_end and
         value['clock_domain']==issuer.domain(),'clock-time-domain')
    cutoff=min(workflow_end-120,entry+10080);check(cutoff)
    return cutoff,workflow_end


def controller_bridge_cutoff(issued, workflow_end, supplied_entry, local_startup):
    """Source-only vector for the Root-owned optional CLI bridge, not authority."""
    need(all(type(value) in (int,float) and math.isfinite(value) and value>0
             for value in (issued,workflow_end,supplied_entry,local_startup)) and
         workflow_end==issued+10800 and issued<=supplied_entry<=local_startup<workflow_end,
         'controller-entry-refused')
    cutoff=min(workflow_end-120,supplied_entry+10080)
    need(cutoff<=min(workflow_end-120,local_startup+10080),'entry-cannot-extend')
    return cutoff


def _launch(plan, environment, preparation_entry, *, delivery, runner, workspace_owner=None):
    """Retain one controlling process and Owned FDs through verification/child exit."""
    preparation_end=preparation_entry+60
    need(type(plan)is dict and set(plan)=={'root_pins','code_commit','data_commit','composition','git_sha256',
        'development_sha256'} and plan['composition'] in MODES and
        type(plan['code_commit']) is str and re.fullmatch('[0-9a-f]{40}',plan['code_commit']) and
        re.fullmatch('[0-9a-f]{40}',plan['data_commit']) and
        plan['data_commit']!=plan['root_pins']['source_commit'] and
        all(re.fullmatch('[0-9a-f]{64}',plan[key])for key in ('git_sha256','development_sha256')),
        'Root-launch-plan')
    source=plan['root_pins']['source_commit'];code_source=plan['code_commit']
    need(environment.get('GITHUB_REPOSITORY')==REPOSITORY and
         environment.get('GITHUB_SHA')==environment.get('GITHUB_WORKFLOW_SHA')==source,'workflow-source')
    check(preparation_end)
    if workspace_owner is not None:
        need(environment.get('GITHUB_WORKSPACE')==str(workspace_owner.path),'workspace-environment-binding')
        workspace_owner.verify(preparation_end,empty=True)
    bootstrap=module(delivery(code_source,CODE_PATHS['bootstrap'],BOOTSTRAP_SHA,256*1024,preparation_end),BOOTSTRAP_SHA,'trusted_bootstrap')
    issuer=module(delivery(code_source,CODE_PATHS['issuer'],ISSUER_SHA,256*1024,preparation_end),ISSUER_SHA,'trusted_issuer')
    selection=delivery(plan['data_commit'],DATA_PATHS['selection'],plan['root_pins']['selection_sha256'],8*1024**2,preparation_end)
    peer=delivery(plan['data_commit'],DATA_PATHS['peer'],plan['root_pins']['peer_receipt_sha256'],8*1024**2,preparation_end)
    value=bootstrap.decode(selection)
    need(value.get('schema_version') == 3 and type(value.get('schema_version')) is int and
        value.get('purpose') == 'root-selected-maintained-v1-development-source' and
        value.get('composition') == plan['composition'] and value.get('baseline_id') == BASELINE_ID and
        value.get('lineage') == LINEAGE and value.get('source_packet_sha256') == plan['development_sha256'] and
        type(value.get('source_files')) is dict and len(value['source_files'])==MODES[plan['composition']],
        'composition-row-count')
    prepared=None;first=None;code=None;retirement=[]
    try:
        with defer_controls():
            prepared=bootstrap.prepare(selection,peer,plan['root_pins'],environment,preparation_deadline=preparation_end)
            if workspace_owner is not None:prepared['workspace_owner']=workspace_owner
        check(preparation_end)
        signal.setitimer(signal.ITIMER_REAL,0)
        issuer_entry=time.monotonic()
        with defer_controls():
            bindings=issuer.issue(environment,ISSUER_SHA,prepared['execution_grant'],prepared['runtime_contract'])
        entry=time.monotonic()
        # This conservative pre-call endpoint cannot renew the issuer's allowance.
        cutoff,workflow_end=clock(bootstrap,issuer,bindings,plan,environment,entry,issuer_entry+10800)
        signal.setitimer(signal.ITIMER_REAL,cutoff-time.monotonic())
        prepared['owned'].verify(cutoff)
        checkout(bootstrap,prepared,plan,cutoff,runner)
        if workspace_owner is not None:workspace_owner.verify(cutoff)
        with defer_controls():
            verified=bootstrap.verify_checkout(prepared,plan['root_pins'],environment,deadline=cutoff)
        check(cutoff)
        packet=prepared['paths']['workspace']/'scripts/ci/development/packet.lock.json'
        raw,_,_=read_bootstrap(bootstrap,packet,cutoff,mode=0o644)
        need(digest(raw)==plan['development_sha256'],'development-packet-pin')
        argv=[sys.executable,'-E','-s','-B',str(prepared['paths']['workspace']/'scripts/ci/development/controller.py'),
              '--composition',plan['composition'],'--development-sha256',plan['development_sha256'],
              '--controller-entry-monotonic',repr(entry),
              '--packet',str(packet),'--cache',str(prepared['paths']['cache']),'--output',str(prepared['paths']['output'])]
        for name in ('inputs','recipes','integration'):
            argv+=['--'+name+'-sha256',verified['metadata_pins']['scripts/ci/'+name+'.lock.json']]
        for flag,prefix in (('clock','CLOCK'),('execution-grant','EXECUTION_GRANT'),('runtime-contract','RUNTIME_CONTRACT')):
            argv+=['--'+flag,bindings['DEVELOPMENT_'+prefix+'_PATH'],
                   '--'+flag+'-sha256',bindings['DEVELOPMENT_'+prefix+'_SHA256']]
        child_environment={**environment,**bindings,'PYTHONDONTWRITEBYTECODE':'1'}
        prepared['owned'].verify(cutoff);check(cutoff)
        if workspace_owner is not None:workspace_owner.verify(cutoff)
        # The child retains J for Source/work. Its existing final publication
        # window belongs to the same workflow endpoint, not a renewed allowance.
        signal.setitimer(signal.ITIMER_REAL,workflow_end-time.monotonic())
        check(cutoff)
        options={'spawn_deadline':cutoff}
        if workspace_owner is not None:options['workspace_owner']=workspace_owner
        code,_=runner(argv,child_environment,str(prepared['paths']['workspace']),workflow_end,**options)
        if workspace_owner is not None:workspace_owner.verify(workflow_end)
        need(type(code)is int and 0<=code<=255,'controller-return-code')
        check(workflow_end)
    except BaseException as error:
        first=error
    finally:
        if prepared is not None:
            # No accepted Owned.close(): every descriptor retirement is attempted.
            retirement=retire(prepared['owned'])
    if first is not None:raise first
    need(not retirement,'bootstrap-retirement-uncertain')
    check(workflow_end)
    return {'controller_exit_code':code,'retained_cutoff':cutoff,'workflow_end':workflow_end,
            'code_commit':code_source,'source_commit':source,'data_commit':plan['data_commit'],
            'composition':plan['composition'],'baseline_id':BASELINE_ID,'lineage':LINEAGE,
            'scope':'maintained source proposal; actual Root registration and execution remain separate'}


def launch(plan, environment, *, delivery=fetch, runner=run):
    preparation_entry=time.monotonic()
    result=None
    with controls(preparation_entry+60):
        result=_launch(plan,environment,preparation_entry,delivery=delivery,runner=runner)
    # Mask/handler/timer restoration is part of successful completion.
    check(result['workflow_end'])
    return result


class Workspace:
    """Finite directory custody; retain paths, never remove original/foreign data."""
    def __init__(self):
        self.nodes=[]
        self.path=None
        self.environment=None
        self.leaf=None
        self.closed=False

    def hold(self,path,fd):
        try:
            row=os.fstat(fd)
            identity=(row.st_dev,row.st_ino,row.st_mode,row.st_uid,row.st_gid)
            self.nodes.append((path,fd,identity))
        except BaseException:
            cause=sys.exc_info()[1]
            try:os.close(fd)
            except BaseException:
                if cause is None:raise
            raise
        return fd

    def directory(self,path,end):
        flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
        check(end)
        current=Path('/')
        fd=self.hold(current,os.open(current,flags))
        for part in path.parts[1:]:
            check(end)
            current=current/part
            fd=self.hold(current,os.open(part,flags,dir_fd=fd))
        check(end)
        return fd

    def verify(self,end,*,empty=False):
        need(not self.closed and self.leaf is not None,'workspace-custody-closed')
        for path,fd,before in self.nodes:
            check(end)
            for row in (os.fstat(fd),os.stat(path,follow_symlinks=False)):
                found=(row.st_dev,row.st_ino,row.st_mode,row.st_uid,row.st_gid)
                need(found==before and stat.S_ISDIR(row.st_mode),'workspace-identity-drift')
        if empty:
            os.lseek(self.leaf,0,os.SEEK_SET)
            need(not os.listdir(self.leaf),'workspace-not-empty')
        check(end)

    def close(self):
        errors=[]
        for path,fd,before in reversed(self.nodes):
            try:
                row=os.fstat(fd)
                found=(row.st_dev,row.st_ino,row.st_mode,row.st_uid,row.st_gid)
                need(found==before,'workspace-retirement-foreign')
                os.close(fd)
            except BaseException as error:errors.append(type(error).__name__)
        self.nodes.clear();self.closed=True
        return errors


def workspace_path(value):
    need(type(value)is str and 0<len(value)<=4096 and '\0'not in value,'workspace-path')
    path=Path(value)
    need(path.is_absolute()and str(path)==value and
         len(path.parts)<=64 and all(part not in {'.','..'}for part in path.parts)and
         path!=Path('/'),'workspace-path')
    return path


def select_workspace(environment,end):
    """Reserve one closed-ID sibling under the held original workspace parent."""
    need(type(environment)is dict,'workspace-environment')
    run_id=environment.get('GITHUB_RUN_ID');attempt=environment.get('GITHUB_RUN_ATTEMPT')
    need(type(run_id)is str and re.fullmatch('[1-9][0-9]{0,19}',run_id)and
         type(attempt)is str and re.fullmatch('[1-9][0-9]{0,9}',attempt),'workspace-job-id')
    original=workspace_path(environment.get('GITHUB_WORKSPACE'))
    temporary=workspace_path(environment.get('RUNNER_TEMP'))
    selected=original.with_name(original.name+'.composed-'+run_id+'-'+attempt)
    need(all(not left.is_relative_to(right)and not right.is_relative_to(left)
             for left,right in ((original,temporary),(selected,temporary))),'workspace-temp-overlap')
    owner=Workspace()
    owner.path=selected
    try:
        # Register every allocated FD before a pending control can be delivered.
        with defer_controls():
            parent=owner.directory(original.parent,end)
            row=os.fstat(parent)
            need(row.st_uid==os.getuid()and not stat.S_IMODE(row.st_mode)&0o022,'workspace-parent-owner-mode')
            old=owner.directory(original,end)
            temp=owner.directory(temporary,end)
            need(os.fstat(old).st_uid==os.fstat(temp).st_uid==os.getuid(),'workspace-runner-owner')
            # Check named ancestors before changing the held parent directory.
            for path,fd,before in owner.nodes:
                row=os.stat(path,follow_symlinks=False)
                need((row.st_dev,row.st_ino,row.st_mode,row.st_uid,row.st_gid)==before,'workspace-identity-drift')
            check(end)
            try:os.stat(selected.name,dir_fd=parent,follow_symlinks=False)
            except FileNotFoundError:pass
            else:raise Refused('fresh-workspace-collision')
            os.mkdir(selected.name,0o700,dir_fd=parent)
            created=os.stat(selected.name,dir_fd=parent,follow_symlinks=False)
            flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
            owner.leaf=owner.hold(selected,os.open(selected.name,flags,dir_fd=parent))
            row=os.fstat(owner.leaf)
            need((row.st_dev,row.st_ino,row.st_mode,row.st_uid,row.st_gid)==
                 (created.st_dev,created.st_ino,created.st_mode,created.st_uid,created.st_gid)and
                 row.st_uid==os.getuid()and stat.S_IMODE(row.st_mode)==0o700,'workspace-created-owner-mode')
            owner.environment={**environment,'GITHUB_WORKSPACE':str(selected)}
        owner.verify(end,empty=True)
        return owner
    except BaseException:
        owner.close()
        raise


def launch_composed(plan,environment,*,preparation_entry=None,delivery=fetch,runner=run):
    """Fresh sibling selection and existing launcher share the original entry+60."""
    actual_entry=time.monotonic()
    if preparation_entry is None:preparation_entry=actual_entry
    need(type(preparation_entry)in(int,float)and math.isfinite(preparation_entry)and
         0<preparation_entry<=actual_entry,'workspace-preparation-entry')
    owner=None;result=None;first=None;retirement=[]
    with controls(preparation_entry+60):
        try:
            # Assignment precedes deferred-control restoration, so outer cleanup
            # also owns a selector that returned just as cancellation arrived.
            with defer_controls():owner=select_workspace(environment,preparation_entry+60)
            result=_launch(plan,owner.environment,preparation_entry,delivery=delivery,
                           runner=runner,workspace_owner=owner)
        except BaseException as error:first=error
        finally:
            if owner is not None:retirement=owner.close()
        if first is not None:raise first
        need(not retirement,'workspace-retirement-uncertain')
        check(result['workflow_end'])
    check(result['workflow_end'])
    return result
