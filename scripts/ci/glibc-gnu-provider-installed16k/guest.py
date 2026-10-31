#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only held bootstrap drives unchanged ALPM574 lifecycle in disk clones."""
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import sys
import threading
import time
import stat
import types
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C
import snapshot_progress as S
import observer_progress as O

def emit(nonce,value):
    raw=json.dumps(value,sort_keys=True,separators=(',',':'));C.need(len(raw)<=512*1024,'guest receipt bound')
    print('GNU_INSTALLED16K '+nonce+' '+raw,flush=True)

def inner_failure_report(row):
    """PID1 observes the original report only after its writer group is absent."""
    value=dict(status='UNAVAILABLE_UNRETIRED_CHILD',path='/out/result.json',read_cap=8*1024**2,
               acceptance='FORBIDDEN_DIAGNOSTIC_ONLY_NO_COMPLETION')
    if row.get('group_absence_verified') is not True:return value
    try:raw=C.read('/out/result.json',8*1024**2)
    except FileNotFoundError:
        value['status']='MISSING_ORIGINAL_INNER_REPORT';return value
    except Exception as error:
        value.update(status='UNREADABLE_OR_OVER_CAP_INNER_REPORT',read_error=dict(type=type(error).__name__,message=str(error)[:512]));return value
    preview=raw[:65536]
    value.update(status='INVALID_ORIGINAL_INNER_REPORT',raw=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
                 preview_base64=base64.b64encode(preview).decode('ascii'),preview_bytes=len(preview),truncated=len(preview)!=len(raw)))
    try:
        report=C.decode(raw);C.need(type(report) is dict,'original inner report must be an object')
    except Exception as error:
        value['parse_error']=dict(type=type(error).__name__,message=str(error)[:512]);return value
    fields={}
    for name in ('status','error_type','error'):
        if name not in report:
            fields[name]=dict(status='MISSING_FIELD');continue
        item=report[name]
        if type(item) is not str:
            fields[name]=dict(status='INVALID_FIELD_TYPE',type=type(item).__name__);continue
        try:data=item.encode('utf8')
        except UnicodeEncodeError:
            fields[name]=dict(status='INVALID_UTF8_FIELD');continue
        bounded=data[:4096]
        fields[name]=dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),preview_utf8=bounded.decode('utf8',errors='replace'),
                          preview_bytes=len(bounded),truncated=len(data)!=len(bounded))
    value.update(status='READ_ORIGINAL_INNER_REPORT_DIAGNOSTIC_ONLY',fields=fields);return value

def child_failure(row,stdout,stderr,error,phase):
    """UART-only diagnostic of original captured buffers; never a guest result."""
    C.need(type(stdout) is type(stderr) is bytes and len(stdout)+len(stderr)<=512*1024,'original child capture bound')
    def stream(raw):
        preview=raw[:65536]
        return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),preview_base64=base64.b64encode(preview).decode('ascii'),
                    preview_bytes=len(preview),truncated=len(preview)!=len(raw))
    C.need(type(row) is dict and len(json.dumps(row,sort_keys=True,allow_nan=False))<=32768,'bounded original supervisor record')
    message=str(error).encode('utf8') if error is not None else b''
    return dict(event='child-failure',status='FAIL',phase=phase,supervisor_record=row,
                stdout=stream(stdout),stderr=stream(stderr),
                error=None if error is None else dict(type=type(error).__name__,**stream(message)),
                capture='ORIGINAL_SUPERVISOR_CAPTURED_BUFFERS_MAY_BE_PARTIAL_ON_LIMIT_OR_INTERRUPTION',
                inner_report=inner_failure_report(row),
                acceptance='FORBIDDEN_DIAGNOSTIC_ONLY_NO_GUEST_FILES_OR_COMPLETION')

PROGRESS=Path('/out/pristine-guest-progress.log')
PHASES=('source-before','clone','before574','precommit-refused','provider574','reinstalled574','held574','source-after')

def progress_value(raw,selection):
    C.need(len(raw)<=65536,'finite progress receipt');value=C.decode(raw)
    C.need(type(value) is dict and set(value)=={'status','nonce','source_sha','records','omitted_records'} and value['status']=='DIAGNOSTIC_CALL_BOUNDARIES_NO_ACCEPTANCE' and value['nonce']==selection['nonce'] and value['source_sha']==selection['source_sha'],'source/nonce-bound diagnostic only')
    rows=value['records'];C.need(type(rows) is list and 1<=len(rows)<=256 and type(value['omitted_records']) is int and 0<=value['omitted_records']<=2**63-1 and rows[-1]['sequence']==len(rows)+value['omitted_records'],'finite stage records and explicit omissions')
    for n,row in enumerate(rows):
        C.need(type(row) is dict and set(row) in ({'sequence','stage','edge','case','phase'},{'sequence','stage','edge','case','phase','postwalk'},{'sequence','stage','edge','case','phase','observer'},{'sequence','stage','edge','case','phase','copy_context'}) and type(row['sequence']) is int and 0<row['sequence']<=2**63-1 and (n==0 or row['sequence']>rows[n-1]['sequence']) and row['stage'] in ('worker','lifecycle','case','snapshot','observer','alpm','runtime','cache','initialization','configuration','postwalk','copy') and row['edge'] in ('enter','leave','sample','failure') and row['case'] in ('none','pristine','modified') and row['phase'] in ('none',*PHASES),'closed public progress labels')
        C.need((row['stage']=='copy')==('copy_context'in row) and (row['edge']!='failure' or row['stage']=='copy'),'copy phase DATA exclusive schema')
        if 'copy_context' in row:
            C.need(row['stage']=='copy' and row['edge'] in ('enter','leave','sample','failure'),'closed copy context DATA');S.validate_copy(row['copy_context'])
        if 'postwalk' in row:
            C.need(row['stage']=='postwalk','closed postwalk stage');S.validate(row['postwalk'])
        if 'observer' in row:
            C.need(row['stage']=='observer','closed inner observer stage');O.validate(row['observer'])
    return value

def install_progress():
    selection=C.decode(C.read('/installed16k/selection.json'));C.need(re.fullmatch('[0-9a-f]{32}',selection['nonce']) and re.fullmatch('[0-9a-f]{40}',selection['source_sha']),'exact progress source/nonce')
    journal=S.Journal(selection);lock=threading.Lock();context=dict(case='none',phase='none');disabled=False;observer_pending=True
    def record(stage,edge,metrics=None):
        nonlocal disabled
        if disabled:return
        try:
            with lock:
                raw=journal.push(stage,edge,context,metrics);progress_value(raw,selection)
                temporary=PROGRESS.with_name('pristine-guest-progress-pending.log');fd=os.open(temporary,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
                with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
                if PROGRESS.exists():
                    info=PROGRESS.lstat();C.need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600,'owned progress replacement')
                temporary.replace(PROGRESS)
        except Exception:disabled=True # Diagnostic failure never changes original supervision/worker outcome.
    def wrap(function,stage):
        def called(*args,**kwargs):
            old=dict(context)
            if stage=='case':
                selected=kwargs.get('case',args[6] if len(args)>6 else None)
                if selected in ('pristine','modified'):context.update(case=selected,phase='none')
            if stage=='snapshot':
                label=kwargs.get('label',args[2] if len(args)>2 else None)
                if type(label) is str and label in {context['case']+'-'+p for p in PHASES}:context['phase']=label[len(context['case'])+1:]
            record(stage,'enter')
            try:return function(*args,**kwargs)
            finally:record(stage,'leave');context.update(old)
        return called
    original=C.load
    def load(name,path):
        module=original(name,path)
        if name=='guest_worker' and str(path)=='/installed16k/container16k.py':
            module.snapshot=S.snapshot(module,record)
            for function,stage in (('main','lifecycle'),('run_case','case'),('snapshot','snapshot'),('transaction','alpm'),('smoke','runtime'),('caches','cache'),('copy_probes','initialization'),('config_handoff','configuration')):setattr(module,function,wrap(getattr(module,function),stage))
            helpers=module.C.helpers
            def observed_helpers(*args,**kwargs):
                api=helpers(*args,**kwargs);roots=api['roots']
                query_path=C.ref(Path('/source'),dict(path='scripts/ci/expanded600-installer-vm/observer600.py',bytes=2784,sha256='c3d804e7f2927c7889835ad187a39a3d7c618a4651700f57b0c5413c46612607'))
                query=C.load('gnu_installed_fresh_mount_query',query_path)
                api['caps']=S.capability_facade(api['caps'],record,mount_query=query._mount600)
                api['capabilities']=_copy_capability_bridge(api['capabilities'],Path('/source'),record=record)
                def first_observation(*args,**kwargs):
                    nonlocal observer_pending
                    if observer_pending:
                        observer_pending=False
                        measured=O.facade(roots,lambda metrics:record('observer','sample',metrics),mount_query=query._mount600)
                        return measured.observe(*args,**kwargs)
                    return query._observer600(roots,*args,**kwargs)
                api['roots']=types.SimpleNamespace(**dict(vars(roots),observe=wrap(first_observation,'observer')));return api
            module.C.helpers=observed_helpers
        return module
    C.load=load;record('worker','enter')

_COPY_ROOT_SHA='cece1c597b2e2eb98b0e3087cc7e7c148b54332f8a1c4f18e04e4552a71fb51d'
_COPY_AUX_SHA='bff93c029e21f9fce0868c80566396984443c8d3438264fac8a91c985175f05b'
_COPY_QUERY_SHA='c3d804e7f2927c7889835ad187a39a3d7c618a4651700f57b0c5413c46612607'
_COPY_CHECKPOINT_SHA='d51179ca24c981bafd817d7db082c0ceb3b2f5deb922004bfe97d1e2007edda7'

def _copy_clone(function,**replacements):
    namespace=dict(function.__globals__,**replacements)
    value=types.FunctionType(function.__code__,namespace,function.__name__,function.__defaults__,function.__closure__)
    value.__kwdefaults__=function.__kwdefaults__
    return value

def _copy_relative(value):
    # Equivalent canonical POSIX Path roundtrip; the lone '.' remains valid.
    if not (type(value) is str and value and '\0' not in value and not value.startswith('/') and
            (value=='.' or all(part not in ('','.','..') for part in value.split('/')))):
        raise ValueError('noncanonical payload path')
    return value

def _copy_path_roots(roots,query):
    # Only private globals change. Every observer/graph/copy code object and
    # filesystem operation remains original; no descriptor/hash identity cache.
    fresh=types.SimpleNamespace(**vars(roots))
    fresh.installer=types.SimpleNamespace(**dict(vars(roots.installer),relative=_copy_relative))
    fresh._mount_id=query._mount600(roots._mount_id)
    fresh.observe=_copy_clone(roots.observe,_mount_id=fresh._mount_id,installer=fresh.installer)
    fresh._projected_paths=_copy_clone(roots._projected_paths,installer=fresh.installer)
    fresh._group_graph=_copy_clone(roots._group_graph,installer=fresh.installer,_projected_paths=fresh._projected_paths)
    fresh.check_hardlink_preservation=_copy_clone(roots.check_hardlink_preservation,_group_graph=fresh._group_graph)
    return fresh

def _copy_context_limits(original,record=None):
    # CI-only whole-copy allocation: three full observations plus copy work.
    # The600 copy-work share is accounting, NOT a separate phase deadline.
    import dataclasses,time
    now=time.monotonic()
    if not 0<original.deadline-now<=600:raise ValueError('fresh bounded original copy context required')
    window=[None];active=[None];sequence=[0];emitted=[0];disabled=[False]
    work_ticks=[0];work_samples=[0];work_last=[now];work_disabled=[False]
    def emit(state,edge,expiry='NONE'):
        if record is None or disabled[0] or state is None or emitted[0]>=64:return
        try:
            current=time.monotonic()
            metrics=dict(schema_version=1,operation=state['operation'],ordinal=state['ordinal'],
                elapsed_ms=max(0,int((current-now)*1000)),phase_elapsed_ms=max(0,int((current-state['started'])*1000)),
                shared_remaining_ms=max(0,int((original.deadline+1800-current)*1000)),
                window_remaining_ms=None if window[0] is None else max(0,int((window[0]-current)*1000)),
                expiry=expiry,acceptance=False)
            if 'work' in state:metrics['work']=dict(state['work'])
            S.validate_copy(metrics);emitted[0]+=1;record('copy',edge,metrics)
        except Exception:disabled[0]=True # Optional DATA cannot change any original guard/outcome.
    def sample_work():
        # Piggyback original ticks; no timer actor, scan, added FS operation or
        # state cache. Reserve32 of the existing64 rows for phase boundaries.
        state=active[0]
        if record is None or disabled[0] or work_disabled[0] or state is None or state['operation']!='COPY_DATA':return
        work_ticks[0]+=1
        if work_ticks[0]%256:return
        try:
            current=time.monotonic()
            work=S.copy_work()
            if work is None:return
            prior=state.get('work',{});due=work['phase']!=prior.get('phase') or current-work_last[0]>=120
            omitted=prior.get('omitted_samples',0)+(1 if due and work_samples[0]>=32 else 0)
            work.update(sampled_at_ms=max(0,int((current-now)*1000)),omitted_samples=omitted)
            S.validate_copy_work(work);state['work']=work
            if due:
                work_last[0]=current
                if work_samples[0]<32:work_samples[0]+=1;emit(state,'sample')
        except Exception:work_disabled[0]=True # Optional DATA never changes the workload.
    parent=type(original)
    class CopyContextLimits(parent):
        def tick(self):
            try:parent.tick(self)
            except ValueError:
                if active[0] is not None:
                    active[0]['expiry']='PARENT2400';active[0]['failed']=True;emit(active[0],'failure','PARENT2400')
                raise
            if window[0] is not None and not time.monotonic()<window[0]:
                if active[0] is not None:
                    active[0]['expiry']='WINDOW600';active[0]['failed']=True;emit(active[0],'failure','WINDOW600')
                raise ValueError('root observation deadline')
            sample_work()
        def _copy_call(self,operation,function,*args,**kwargs):
            sequence[0]+=1
            if sequence[0]>64:return function(*args,**kwargs) # Bounded optional DATA only.
            state=dict(operation=operation,ordinal=sequence[0],started=time.monotonic(),expiry='NONE',failed=False)
            previous=active[0];active[0]=state;emit(state,'enter')
            try:return function(*args,**kwargs)
            except BaseException:
                if not state['failed']:emit(state,'failure',state['expiry'])
                raise
            finally:emit(state,'leave',state['expiry']);active[0]=previous
        def _copy_observe(self,function,*args,_phase='SELECTED_OBSERVE',**kwargs):
            if kwargs.get('limits') is not self or window[0] is not None:
                raise ValueError('one exact private copy observation context required')
            self.tick();window[0]=min(self.deadline,time.monotonic()+600)
            try:return self._copy_call(_phase,function,*args,**kwargs)
            finally:window[0]=None
    # One instance for ALL passes; no per-pass limits/counter reset. Retain
    # original absolute start accounting and every non-time field by identity.
    values={field.name:getattr(original,field.name) for field in dataclasses.fields(original)}
    values['deadline']=original.deadline+1800
    return CopyContextLimits(**values)

def _copy_context_api(api,limits):
    # The capability bridge has one additional complete tree observation and
    # restore after the three copier observations. Keep both original600 caps.
    value=dict(api);roots=types.SimpleNamespace(**vars(api['roots']))
    original_observe=roots.observe
    def observe(*args,**kwargs):return limits._copy_observe(original_observe,*args,_phase='COPIED_TREE',**kwargs)
    observe.__wrapped__=original_observe;roots.observe=observe;value['roots']=roots
    caps=types.SimpleNamespace(**vars(api['caps']));original_restore=caps.restore
    def restore(root,nodes,mapping,subject):
        return limits._copy_observe(lambda **options:original_restore(root,nodes,mapping,options['limits']),limits=subject,_phase='CAPABILITY_RESTORE')
    restore.__wrapped__=original_restore;caps.restore=restore;value['caps']=caps
    return value

def _copy_path_checkpoint(aux,source,roots):
    # A private exact-source Reader; only its pure constructor path predicate
    # uses the already-equivalent copy predicate. Every read/identity/aux gate
    # and the complete original constructor code object remain unchanged.
    module=aux._isolated(source/'scripts/update/aux_checkpoint.py',_COPY_CHECKPOINT_SHA)
    original=module.Reader
    namespace=types.SimpleNamespace(**dict(vars(module.roots),installer=roots.installer))
    initializer=_copy_clone(original.__init__,roots=namespace)
    module.Reader=type('_CopyPathReader',(original,),{'__init__':initializer})
    return module

def _copy_scoped_aux(aux,source):
    # Existing reader verifies bounded/noalias source bytes/identities before exec.
    roots=aux._isolated(source/'scripts/update/full_root.py',_COPY_ROOT_SHA)
    query=aux._isolated(source/'scripts/ci/expanded600-installer-vm/observer600.py',_COPY_QUERY_SHA)
    original=aux._isolated(source/'scripts/update/aux_copy.py',_COPY_AUX_SHA)
    fresh=_copy_path_roots(roots,query)
    binding=_copy_clone(original._copy_binding,roots=fresh,aux=_copy_path_checkpoint(aux,source,fresh))
    original_binding=binding
    def binding(limits):
        module=original_binding(limits)
        module.roots=types.SimpleNamespace(**vars(module.roots))
        original_observe=module.roots.observe
        def observe(*args,**kwargs):return limits._copy_observe(original_observe,*args,**kwargs)
        observe.__wrapped__=original_observe
        module.roots.observe=observe
        return module
    binding.__wrapped__=original_binding
    value=types.SimpleNamespace(**vars(aux));value._copy_binding=binding
    return value,fresh

def _copy_capability_bridge(original,source,record=None):
    """Keep original generator/cleanup and receipt; bind only this copy instance."""
    from contextlib import contextmanager
    scope=original.scope
    aux,roots=_copy_scoped_aux(scope.aux_copy,source)
    def qualified():
        module=scope.qualified()
        module.aux_copy=aux;module.roots=roots
        original_copy=module.copy_data
        def copy_data(*args,**kwargs):return kwargs['limits']._copy_call('COPY_DATA',original_copy,*args,**kwargs)
        copy_data.__wrapped__=original_copy;module.copy_data=copy_data
        return module
    private_scope=types.SimpleNamespace(**vars(scope))
    private_scope.copied_root=_copy_clone(scope.copied_root,qualified=qualified)
    result=types.SimpleNamespace(**vars(original))
    result.copied_root=contextmanager(_copy_clone(original.copied_root.__wrapped__,scope=private_scope))
    original_context=result.copied_root
    def copied_root(api,source,workspace,index,evidence=None,**kwargs):
        limits=_copy_context_limits(kwargs['limits'],record=record);kwargs['limits']=limits
        return original_context(_copy_context_api(api,limits),source,workspace,index,evidence=evidence,**kwargs)
    copied_root.__wrapped__=original_context.__wrapped__
    result.copied_root=copied_root
    return result

def supervised_progress(runtime,selection,nonce):
    stop=threading.Event()
    def poll():
        last=0
        while not stop.wait(.25):
            try:
                info=PROGRESS.lstat();C.need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600,'owned progress reader');value=progress_value(C.read(PROGRESS,65536),selection);row=value['records'][-1]
                if row['sequence']>last:
                    last=row['sequence'];print('GNU_INSTALLED16K_PROGRESS '+nonce+' '+json.dumps(dict(source_sha=selection['source_sha'],acceptance='FORBIDDEN_DIAGNOSTIC_ONLY',**row),sort_keys=True,separators=(',',':')),flush=True)
            except Exception:pass # Missing/partial/replaced receipt cannot interrupt original child supervision.
    thread=threading.Thread(target=poll,name='bounded-phase-observer',daemon=True);thread.start()
    try:return runtime.run_command(['/usr/bin/python3','-I','-B','/installed16k/guest.py','worker'],Path('/tmp'),dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',HOME='/tmp',TMPDIR='/tmp',PYTHONDONTWRITEBYTECODE='1'),10500,512*1024)
    finally:stop.set();thread.join(timeout=1)

def worker():
    selection=C.decode(C.read('/installed16k/selection.json'));nonce=selection['nonce']
    C.need(re.fullmatch('[0-9a-f]{32}',nonce) and os.getpid()!=1 and os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64' and os.sysconf('SC_PAGE_SIZE')==16384 and os.uname().release==selection['kernel']['release'],'fixed actual16K child required')
    C.need('caa_gnu_installed16k=1' in Path('/proc/cmdline').read_text().split(),'dedicated guest marker required')
    profile=C.read('/installed16k/container16k.py');C.need(C.sha(profile)==selection['adapter_sha256'],'exact generated lifecycle executable required')
    import sandbox
    isolation=sandbox.apply();C.save('/out/isolation.json',isolation)
    os.environ.update(CACHY_GNU_PROVIDER_LIFECYCLE='1',INPUT_INDEX_SHA256=selection['input_index_sha256'],OUTPUT_UID='0',OUTPUT_GID='0',PYTHONDONTWRITEBYTECODE='1')
    worker=C.load('guest_worker','/installed16k/container16k.py')
    code=worker.main();native=worker.C;index,_,_,_=native.configuration(Path('/inputs'),selection['input_index_sha256']);api=native.helpers(Path('/source'))
    report=C.decode(C.read('/out/result.json',8*1024**2))
    C.need(code==0 and report['status']=='PASS_GENERIC_ARM_SYSTEM_PROVIDER_LIFECYCLE','actual full installed lifecycle failed')
    stages=('source-before','clone','before574','precommit-refused','provider574','reinstalled574','held574','source-after')
    caps=api['capabilities'].records(index,report['cases'],stages)
    C.need(not any(Path('/work').iterdir()),'guest clones remain')
    for case in native.CASES:
        row=report['cases'][case]
        C.need(row['status']=='PASS_NORMAL_DISPOSABLE_PROVIDER_SEQUENCE' and row['source_before']==row['source_after']==index['source_nodes_sha256'] and row['copy_lifetime']['cleanup']=='PASS-owned-workspace-removed','full574 complete source/copy/cleanup checks required')
        for phase in ('before_runtime','provider_runtime','reinstalled_runtime','held_runtime'):
            C.need(row[phase]['result']['page_size']==16384 and row[phase]['normal_parent_and_child'] is True,'all eight normal-interpreter runtime observations actual16K')
    files={};total=0
    for path in sorted(Path('/out').iterdir()):
        C.need(re.fullmatch(r'(result\.json|isolation\.json|command-[0-9]{3}\.(stdout|stderr)|(pristine|modified)-[a-z0-9-]+(-root\.json\.gz|\.log))',path.name),'closed native evidence filename')
        C.read(path,64*1024**2);files[path.name]=C.row(path);total+=path.stat().st_size
    C.need(len(files)<=256 and total<=512*1024**2,'complete guest evidence bound')
    value=dict(event='result',status=C.PASS,page_size=16384,source_nodes_sha256=index['source_nodes_sha256'],capabilities=caps,isolation=isolation,files=files,bytes=total,source_readback='COMPLETE574_PAYLOAD_DB_METADATA_CAPABILITY_HARDLINK_CHECKS',normal_runtime_observations=8,interrupted_lane='NOT_IMPLEMENTED_SEPARATE_FUTURE_CASE',hardware='NOT_RUN',release='NOT_ADMITTED')
    emit(nonce,value)

def observer_file_limit():
    """Match native trial's finite descriptor budget before authority reduction."""
    before=resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE,(8192,8192))
    after=resource.getrlimit(resource.RLIMIT_NOFILE)
    C.need(after==(8192,8192),'exact inherited native observer descriptor limit')
    return dict(before=list(before),after=list(after),scope='NATIVE_TRIAL_8192_BOTH_INHERITED_BY_LIFECYCLE_CHILD')

def run():
    C.need(os.getpid()==1 and os.getuid()==os.geteuid()==0,'root guest bootstrap only')
    selection=C.decode(C.read('/installed16k/selection.json'));nonce=selection['nonce']
    nofile=observer_file_limit()
    # The worker cannot inspect a more privileged bootstrap's memory or FDs.
    libc=ctypes.CDLL(None,use_errno=True);C.need(libc.prctl(4,0,0,0,0)==0,'protect root bootstrap')
    C.need(os.sysconf('SC_PAGE_SIZE')==16384 and os.uname().release==selection['kernel']['release'],'actual16K boot identity')
    emit(nonce,dict(event='boot',page_size=16384,kernel=os.uname().release,architecture='aarch64',kernel_profile_sha256=selection['kernel_profile_sha256'],observer_nofile=nofile))
    runtime=C.load('guest_supervisor','/source/scripts/ci/glibc-owned-runtime/runner.py')
    row,stdout,stderr,error=supervised_progress(runtime,selection,nonce)
    if not (error is None and row['exit_code']==0 and row['group_absence_verified']):
        emit(nonce,child_failure(row,stdout,stderr,error,'exit-or-retirement'))
    C.need(error is None and row['exit_code']==0 and row['group_absence_verified'],'lifecycle child exit/group retirement failed')
    lines=stdout.splitlines();closed=len(lines)==1 and lines[0].startswith(('GNU_INSTALLED16K '+nonce+' ').encode()) and not stderr
    if not closed:emit(nonce,child_failure(row,stdout,stderr,error,'closed-worker-result'))
    C.need(closed,'one closed worker result only')
    print(lines[0].decode(),flush=True)
    # Only PID1 retains authority to retire mount topology and power off.
    import subprocess
    for point in ('/out','/work','/held','/source','/inputs'):
        result=subprocess.run(['/usr/bin/umount',point],stdin=subprocess.DEVNULL,capture_output=True,timeout=15)
        C.need(result.returncode==0 and not os.path.ismount(point),'guest mount retirement failed')
    emit(nonce,dict(event='exit',status=C.PASS,cleanup='PASS_OWNED_CLONES_REMOVED'))

if __name__=='__main__':
    if sys.argv[1:]==['worker']:
        install_progress();worker();raise SystemExit(0)
    try:run()
    except BaseException as error:print('GNU_INSTALLED16K_ERROR '+type(error).__name__+' '+str(error)[:512],flush=True)
    finally:
        sys.stdout.flush();sys.stderr.flush();os.sync()
        libc=ctypes.CDLL(None,use_errno=True);libc.reboot(0x4321fedc)
        raise RuntimeError('guest poweroff failed')
