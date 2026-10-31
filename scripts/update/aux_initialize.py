#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One declared copied-root cache initialization, before any update baseline."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time

import aux_checkpoint as aux
import full_root as roots
import measure_copy as copy
import scale_update as scale
import supervision

CACHES = {aux.MAIN_CACHE, aux.AUX_CACHE}


def observe(root, limits):
    value = roots.observe(root, limits=limits, hardlinks='generic-development-internal')
    aux.need(value['complete'] is True and set(value['unsupported_counts']) <= {'absolute-symlink','auxiliary-present'}, 'initialization-root-shape')
    return value


def limits_from(config):
    value = config['limits']
    return roots.Limits(deadline=time.monotonic()+value['seconds'],max_nodes=value['root_nodes'],
        max_bytes=value['root_bytes'],max_file_bytes=value['file_bytes'],max_package_files=value['package_files'])


def exec_helper(root, workspace):
    """Worker only: pin static ELF, chroot through retained FD, then exec by FD."""
    scale.bound.guard(root, workspace)
    aux.need(os.execve in os.supports_fd, 'fd-exec-unavailable')
    limits = roots.Limits(deadline=time.monotonic()+150)
    observation = observe(root, limits)
    _initializer_phase('WORKER_CHECKPOINT',limits)
    aux.checkpoint(root, observation, limits)  # Includes exact helper/config/scan closure.
    _initializer_phase('WORKER_HELPER_PIN',limits)
    rootfd = roots._open_root(root)
    helper = None
    try:
        root_id, mount = roots._identity(os.fstat(rootfd)), roots._mount_id(rootfd, limits)
        with copy._parent(rootfd, aux.HELPER_NODE, mount, {}, limits, observation['nodes']) as (parent, base):
            helper = os.open(base, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            info = os.fstat(helper)
            aux.need(info.st_nlink == 1 and info.st_size == aux.HELPER[1]
                     and roots._file_hash(helper,info,limits) == aux.HELPER[0], 'initialization-helper-pin')
            copy._metadata_equal(info, observation['nodes'][aux.HELPER_NODE])
            aux.need(roots._mount_id(helper,limits) == mount, 'initialization-helper-mount')
        copy._root_check(root,rootfd,root_id,mount,limits)
        # No -r fallback: failure to chroot is terminal. No source-root FD is open.
        os.fchdir(rootfd); os.chroot('.'); os.chdir('/')
        os.close(rootfd); rootfd = None
        _initializer_phase('WORKER_EXEC',limits)
        os.execve(helper, ['/usr/bin/ldconfig'], {'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C','HOME':'/','TMPDIR':'/tmp'})
    finally:
        if helper is not None: os.close(helper)
        if rootfd is not None: os.close(rootfd)


def _initializer_initialize_body(args, source, *, comparator_path):
    """Source is the complete supplied pre-copy tree, never a command target."""
    result = dict(status='FAIL',phase='configuration',initialization_started=False,root_initialized=False,
        source_preserved='NOT CHECKED',copy_byte_identical_after_initialization=False,
        transaction_acceptance='NOT ESTABLISHED',hardware='NOT RUN')
    original = None
    try:
        root,workspace,source = Path(args.root),Path(args.workspace),Path(source)
        scale.bound.guard(root,workspace)
        aux.need(source.is_absolute() and not root.is_relative_to(source) and not source.is_relative_to(workspace), 'disjoint-initialization-source')
        config = scale.configuration(args.scale,args.scale_sha256); limits = limits_from(config)
        comparator = aux.load_comparator(comparator_path,limits)
        original = observe(source,limits)
        result['phase'] = 'before-initialization'
        before = observe(root,limits); old = aux.checkpoint(root,before,limits)
        # One exclusive marker prevents a failed/unknown attempt from being retried.
        with copy._descriptors() as held:
            fd = roots._open_root(workspace); held.append(fd)
            marker = os.open(_initializer_marker_name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=fd); held.append(marker)
        result.update(phase='initialization-worker',initialization_started=True,root_initialized='UNKNOWN')
        remaining = limits.deadline-time.monotonic(); aux.need(remaining > 0,'initialization-deadline')
        row = supervision.run([sys.executable,'-B',str(Path(__file__).absolute()),'--worker','--root',str(root),'--workspace',str(workspace)],
            env={'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C','HOME':str(workspace),'TMPDIR':str(workspace),
                 'PYTHONDONTWRITEBYTECODE':'1','CACHY_ASAHI_BOUND_UPDATE':os.environ.get('CACHY_ASAHI_BOUND_UPDATE','')},
            cwd=str(workspace),timeout=min(180,remaining),output_limit=65536)
        result['helper_exit_status'] = 0 if row['termination'] is None and row['returncode'] == 0 else 'NOT OBSERVED'
        result['worker'] = {key:row[key] for key in ('returncode','termination','direct_child_reaped','group_kill_sent')}
        aux.need(row['termination'] is None and row['returncode'] == 0 and row['direct_child_reaped'] is True,'initialization-worker-failed')
        result['phase'] = 'after-initialization'
        after = observe(root,limits); new = aux.checkpoint(root,after,limits)
        aux.need({k:v for k,v in before['nodes'].items() if k not in CACHES}
                 == {k:v for k,v in after['nodes'].items() if k not in CACHES}
                 and before['hardlink_groups'] == after['hardlink_groups'],'initialization-unrelated-root-change')
        # Only generated cache bytes/size/inodes may differ in this preparation.
        for name,mode in ((aux.MAIN_CACHE,0o644),(aux.AUX_CACHE,0o600)):
            node = new['caches'][name]['node']
            aux.need(node['type']=='file' and (node['uid'],node['gid'],node['mode'])==(0,0,mode),'initialized-cache-metadata')
        for field in ('helper','configs','aliases','scan','targets','closure','scan_directories'):
            aux.need(old[field] == new[field],'initialization-'+field+'-changed')
        # Cache parent inode/metadata and both temporary absences stay fixed.
        for name in set(old['caches'])-CACHES:
            aux.need(old['caches'][name] == new['caches'][name],'initialization-cache-parent-or-temp')
        result.update(status='PASS',phase='completed',root_initialized=True,helper_exit_status=0,
            scope='one-copied-root-cache-initialization-before-update-baseline',
            cache_hashes={name:dict(before=old['caches'][name]['node']['sha256'],after=new['caches'][name]['node']['sha256']) for name in sorted(CACHES)},
            live_cache_keys=aux.live_keys(new,comparator))
    except BaseException as error:
        result.update(status='FAIL',error_type=type(error).__name__,error=str(error)[:256])
    finally:
        if original is not None:
            try:
                current = observe(source,limits)
                result['source_preserved'] = (original['nodes']==current['nodes'] and original['hardlink_groups']==current['hardlink_groups'])
                aux.need(result['source_preserved'],'initialization-source-changed')
            except BaseException as error:
                if result['source_preserved'] == 'NOT CHECKED': result['source_preserved'] = 'UNKNOWN'
                result.update(status='FAIL',source_check_error=type(error).__name__)
    return result



_INITIALIZER_PHASES = ('WORKER_OBSERVE', 'WORKER_CHECKPOINT', 'WORKER_HELPER_PIN', 'WORKER_EXEC', 'PARENT_SOURCE_BEFORE', 'PARENT_ROOT_BEFORE', 'PARENT_ROOT_AFTER', 'PARENT_SOURCE_AFTER')
_INITIALIZER_PROFILE = 'I16K_STATX_V1'
_INITIALIZER_PREFIX = b'UPDATER607_INITIALIZER_TELEMETRY '
_INITIALIZER_MAX = 2**63-1

def _initializer_valid(value, nonce=None):
    if type(value) is not dict or set(value) != {'v','profile','nonce','lane','seq','phase','state','elapsed_ns','remaining_ns','ops','saturated'}:return False
    if type(value['v'])is not int or value['v']!=1 or value['profile']!=_INITIALIZER_PROFILE:return False
    n=value['nonce']
    if type(n)is not str or len(n)!=32 or any(c not in '0123456789abcdef'for c in n)or(nonce is not None and n!=nonce):return False
    lane=value['lane']
    if lane not in ('WORKER','PARENT')or type(value['seq'])is not int or not 0<=value['seq']<(6 if lane=='WORKER'else 8):return False
    if value['phase']not in _INITIALIZER_PHASES or not value['phase'].startswith(lane+'_')or value['state']not in ('STARTED','PROGRESS','RETURNED','REFUSED'):return False
    if type(value['elapsed_ns'])is not int or not 0<=value['elapsed_ns']<=_INITIALIZER_MAX:return False
    r=value['remaining_ns']
    if r is not None and(type(r)is not int or not -_INITIALIZER_MAX<=r<=_INITIALIZER_MAX):return False
    if type(value['ops'])is not list or len(value['ops'])!=8 or any(type(x)is not int or not 0<=x<=_INITIALIZER_MAX for x in value['ops'])or type(value['saturated'])is not bool:return False
    return len(_INITIALIZER_PREFIX)+len(json.dumps(value,sort_keys=True,separators=(',',':')).encode())+1<=768

def _initializer_capture(raw, nonce, complete=True):
    if type(raw)is not bytes or len(raw)>1024**2:return None,0
    lines=[line[len(_INITIALIZER_PREFIX):]for line in raw.splitlines()if line.startswith(_INITIALIZER_PREFIX)]
    if not 1<=len(lines)<=(6 if complete else 128):return None,0
    records=[]
    try:
        for i,line in enumerate(lines):
            if len(line)+len(_INITIALIZER_PREFIX)+1>768:return None,0
            def pairs(items):
                value={}
                for key,item in items:
                    if key in value:raise ValueError('duplicate initializer telemetry key')
                    value[key]=item
                return value
            value=json.loads(line,object_pairs_hook=pairs)
            if not _initializer_valid(value,nonce)or value['lane']!='WORKER'or(complete and value['seq']!=i):return None,0
            if complete and records and(value['elapsed_ns']<records[-1]['elapsed_ns']or any(a<b for a,b in zip(value['ops'],records[-1]['ops']))):return None,0
            records.append(value)
    except(ValueError,TypeError,KeyError,UnicodeError,RecursionError):return None,0
    return records[-1],len(records)

def _initializer_emit(value):
    if not _initializer_valid(value,os.environ.get('CACHY_ASAHI_BOUND_UPDATE','')):return
    raw=_INITIALIZER_PREFIX+json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n'
    try:os.write(2,raw)
    except OSError as error:
        # Ordinary diagnostic IO loss is not an acceptance predicate. The held
        # phase alarm raises TimeoutError without errno and must still propagate.
        if error.errno is None:raise

def _initializer_wrapper_valid(value,nonce):
    if type(value)is not dict or set(value)!={'v','profile','history','saturated','worker'}or type(value['v'])is not int or value['v']!=1 or value['profile']!=_INITIALIZER_PROFILE or type(value['saturated'])is not bool:return False
    history=value['history']
    if type(history)is not list or len(history)>8:return False
    for i,record in enumerate(history):
        if not _initializer_valid(record,nonce)or record['lane']!='PARENT'or record['seq']!=i:return False
        if i and(record['elapsed_ns']<history[i-1]['elapsed_ns']or any(a<b for a,b in zip(record['ops'],history[i-1]['ops']))):return False
    worker=value['worker']
    if worker is not None:
        if type(worker)is not dict or set(worker)!={'last','records','stderr','returncode','termination','direct_child_reaped','capture_scope'}or worker['capture_scope']!='ORIGINAL_SUPERVISOR_CAPTURE_MAY_BE_PARTIAL':return False
        if type(worker['records'])is not int or not 0<=worker['records']<=6 or type(worker['direct_child_reaped'])is not bool or worker['termination']not in(None,'timeout','output-limit','interrupted'):return False
        if worker['returncode']is not None and(type(worker['returncode'])is not int or not -255<=worker['returncode']<=255):return False
        last=worker['last']
        if worker['records']==0:
            if last is not None:return False
        elif not _initializer_valid(last,nonce)or last['lane']!='WORKER'or last['seq']!=worker['records']-1:return False
        pin=worker['stderr']
        if type(pin)is not dict or set(pin)!={'bytes','sha256'}or type(pin['bytes'])is not int or not 0<=pin['bytes']<=65536 or type(pin['sha256'])is not str or len(pin['sha256'])!=64 or any(c not in '0123456789abcdef'for c in pin['sha256']):return False
    return len(json.dumps(value,sort_keys=True,separators=(',',':')).encode())<=8192

def _initializer_final_emit(result, fallback):
    value=fallback
    driver=result.get('driver')
    if type(driver)is dict:
        initialization=driver.get('initialization')
        if type(initialization)is dict:
            telemetry=initialization.get('initializer_telemetry')
            if _initializer_wrapper_valid(telemetry,os.environ.get('CACHY_ASAHI_BOUND_UPDATE','')):
                worker=telemetry.get('worker')
                if type(worker)is dict and _initializer_valid(worker.get('last'),os.environ.get('CACHY_ASAHI_BOUND_UPDATE','')):value=worker['last']
    _initializer_emit(value)


def _initializer_mount600(original):
    import ctypes
    import errno
    import os
    import sys
    # Linux statx UAPI: mask offset0, mnt_id offset144, fixed256-byte record.
    # Request ordinary STATX_MNT_ID, never the distinct MNT_ID_UNIQUE namespace.
    class Statx600(ctypes.Structure):
        _fields_=[('mask',ctypes.c_uint32),('prefix',ctypes.c_ubyte*140),
                  ('mnt_id',ctypes.c_uint64),('reserved',ctypes.c_ubyte*104)]
    supported=(sys.platform=='linux' and sys.byteorder=='little' and ctypes.sizeof(ctypes.c_void_p)==8 and
               os.uname().machine in ('aarch64','x86_64') and ctypes.sizeof(Statx600)==256 and Statx600.mnt_id.offset==144)
    libc=ctypes.CDLL(None,use_errno=True) if supported else None
    call=getattr(libc,'statx',None)
    if call is not None:
        call.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_uint,ctypes.POINTER(Statx600))
        call.restype=ctypes.c_int
    empty_path=ctypes.c_char_p(b'');empty_flags=ctypes.c_int(0x1000);mount_mask=ctypes.c_uint(0x1000)
    checked=False
    def query(descriptor,limits):
        nonlocal call,checked
        limits.tick()
        if call is None:_updater_copy_cost.mount('fallback');return original(descriptor,limits)
        result=Statx600()
        if call(descriptor,empty_path,empty_flags,mount_mask,ctypes.byref(result))!=0:
            error=ctypes.get_errno()
            if error in (errno.ENOSYS,errno.EINVAL,errno.EOPNOTSUPP,errno.EPERM):
                call=None;_updater_copy_cost.mount('fallback');return original(descriptor,limits)
            raise OSError(error,'descriptor statx mount query failed')
        if not result.mask&0x1000:
            call=None;_updater_copy_cost.mount('fallback');return original(descriptor,limits)
        if not result.mnt_id:raise ValueError('descriptor statx mount identity unavailable')
        _updater_copy_cost.mount('statx')
        if not checked:
            if result.mnt_id!=original(descriptor,limits):raise ValueError('descriptor mount identity APIs differ')
            checked=True
        return result.mnt_id
    return query


class _InitializerTelemetry:
    def __init__(self,lane,source=None):
        self.lane=lane;self.source=None if source is None else str(source)
        self.nonce=os.environ.get('CACHY_ASAHI_BOUND_UPDATE','');self.ops=[0]*8
        self.started=time.monotonic_ns();self.next_progress=self.started+30*10**9;self.deadline=None;self.seq=0;self.history=[];self.saturated=False
        self.phase='WORKER_OBSERVE'if lane=='WORKER'else'PARENT_SOURCE_BEFORE';self.terminal=False
        self.source_calls=0;self.root_calls=0;self.worker=None
    def add(self,index,value=1):
        total=self.ops[index]+value
        if total>_INITIALIZER_MAX:self.saturated=True;total=_INITIALIZER_MAX
        self.ops[index]=total
    def mount(self,kind):
        if kind=='statx':self.add(1)
        elif kind=='fallback':self.add(2)
    def limits(self,value):self.deadline=value.deadline
    def snapshot(self,state,now=None):
        if now is None:now=time.monotonic_ns()
        elapsed=max(0,now-self.started)
        if elapsed>_INITIALIZER_MAX:self.saturated=True;elapsed=_INITIALIZER_MAX
        remaining=None
        if self.deadline is not None:
            remaining=int(self.deadline*10**9)-now
            if not -_INITIALIZER_MAX<=remaining<=_INITIALIZER_MAX:self.saturated=True;remaining=max(-_INITIALIZER_MAX,min(_INITIALIZER_MAX,remaining))
        return dict(v=1,profile=_INITIALIZER_PROFILE,nonce=self.nonce,lane=self.lane,seq=self.seq,phase=self.phase,state=state,elapsed_ns=elapsed,remaining_ns=remaining,ops=list(self.ops),saturated=self.saturated)
    def event(self,state,now=None):
        cap=6 if self.lane=='WORKER'else 8
        if self.seq>=cap:self.saturated=True;return
        if self.lane=='WORKER'and self.seq==5 and state not in ('RETURNED','REFUSED'):self.saturated=True;return
        value=self.snapshot(state,now)
        if self.lane=='WORKER':_initializer_emit(value)
        if len(self.history)<8:self.history.append(value)
        else:self.saturated=True
        self.seq+=1
    def progress(self,now):
        if self.lane=='WORKER'and self.phase=='WORKER_OBSERVE'and not self.terminal and now>=self.next_progress:
            self.next_progress=now+30*10**9;self.event('PROGRESS',now)
    def phase_start(self,phase,limits=None):
        self.phase=phase
        if limits is not None:self.limits(limits)
        if self.lane=='WORKER':self.event('STARTED'if self.seq==0 else'PROGRESS')
    def finish(self,state):
        if not self.terminal:self.event(state);self.terminal=True
    def observed(self,root,limits,function):
        if self.lane=='PARENT':
            if str(root)==self.source:
                phase='PARENT_SOURCE_BEFORE'if self.source_calls==0 else'PARENT_SOURCE_AFTER';self.source_calls+=1
            else:phase='PARENT_ROOT_BEFORE'if self.root_calls==0 else'PARENT_ROOT_AFTER';self.root_calls+=1
            self.phase=phase;self.limits(limits);self.event('STARTED')
        else:self.phase_start('WORKER_OBSERVE',limits)
        try:value=function(root,limits)
        except BaseException:
            if self.lane=='WORKER':self.finish('REFUSED')
            else:self.event('REFUSED')
            raise
        if self.lane=='WORKER':self.event('PROGRESS')
        else:self.event('RETURNED')
        return value
    def worker_row(self,row):
        if type(row)is not dict:return
        raw=row.get('stderr')
        if type(raw)is not bytes or len(raw)>65536 or type(row.get('direct_child_reaped'))is not bool or row.get('termination')not in(None,'timeout','output-limit','interrupted'):return
        code=row.get('returncode')
        if code is not None and(type(code)is not int or not -255<=code<=255):return
        last,count=_initializer_capture(raw,self.nonce)
        self.worker=dict(last=last,records=count,stderr=None if type(raw)is not bytes else dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()),returncode=row.get('returncode'),termination=row.get('termination'),direct_child_reaped=row.get('direct_child_reaped'),capture_scope='ORIGINAL_SUPERVISOR_CAPTURE_MAY_BE_PARTIAL')
        # Preserve exact validated worker DATA before later source rereads/JSON loss.
        _initializer_emit(last)
    def result(self):return dict(v=1,profile=_INITIALIZER_PROFILE,history=list(self.history),saturated=self.saturated,worker=self.worker)

def _initializer_clone(function,namespace):
    import types
    cloned=types.FunctionType(function.__code__,namespace,function.__name__,function.__defaults__,function.__closure__)
    cloned.__kwdefaults__=function.__kwdefaults__;return cloned

def _initializer_facade(namespace,state,marker):
    import types,contextlib
    original_roots=namespace['roots'];original_copy=namespace['copy'];original_aux=namespace['aux']
    root=types.SimpleNamespace(**vars(original_roots));copy_private=types.SimpleNamespace(**vars(original_copy))
    factory=_initializer_clone(_initializer_mount600,dict(_initializer_mount600.__globals__,_updater_copy_cost=types.SimpleNamespace(mount=state.mount)))
    def fdinfo(fd,limits):
        state.add(3);return original_roots._mount_id(fd,limits)
    query=factory(fdinfo)
    def mount(fd,limits):
        state.limits(limits);state.add(0);start=time.monotonic_ns()
        try:return query(fd,limits)
        finally:
            end=time.monotonic_ns();state.add(6,max(0,end-start))
            if sys.exception()is None:state.progress(end)
    hash_os=types.SimpleNamespace(**vars(os))
    def read(fd,maximum):
        value=os.read(fd,maximum);state.add(5,len(value));return value
    hash_os.read=read
    pure_hash=_initializer_clone(original_roots._file_hash,dict(original_roots._file_hash.__globals__,os=hash_os))
    def file_hash(fd,expected,limits):
        state.add(4);start=time.monotonic_ns()
        try:return pure_hash(fd,expected,limits)
        finally:
            end=time.monotonic_ns();state.add(7,max(0,end-start))
            if sys.exception()is None:state.progress(end)
    root._mount_id=mount;root._file_hash=file_hash
    root_space=dict(vars(original_roots),_mount_id=mount,_file_hash=file_hash)
    for name in ('observe','_projected_paths','_path_set','_group_graph','check_hardlink_preservation'):
        if hasattr(original_roots,name):root_space[name]=_initializer_clone(getattr(original_roots,name),root_space)
    for name in ('observe','_projected_paths','_path_set','_group_graph','check_hardlink_preservation'):
        if name in root_space:setattr(root,name,root_space[name])
    copy_space=dict(vars(original_copy),roots=root)
    for name in ('_parent','_root_check','_source_alias'):
        function=getattr(original_copy,name)
        copy_space[name]=contextlib.contextmanager(_initializer_clone(function.__wrapped__,copy_space))if name=='_parent'else _initializer_clone(function,copy_space)
    copy_private=types.SimpleNamespace(**copy_space)
    aux_space=dict(vars(original_aux),roots=root,copy=copy_private)
    methods={name:_initializer_clone(value,aux_space)if isinstance(value,types.FunctionType)else value for name,value in vars(original_aux.Reader).items()if name not in ('__dict__','__weakref__')}
    aux_space['Reader']=type('_InitializerPrivateReader',(),methods)
    for name in ('checkpoint','load_comparator'):aux_space[name]=_initializer_clone(getattr(original_aux,name),aux_space)
    auxiliary=types.SimpleNamespace(**aux_space)
    supervision_private=types.SimpleNamespace(**vars(namespace['supervision']))
    def run(*args,**kwargs):
        row=namespace['supervision'].run(*args,**kwargs);state.worker_row(row);return row
    supervision_private.run=run
    private=dict(namespace,roots=root,copy=copy_private,aux=auxiliary,supervision=supervision_private,_initializer_phase=state.phase_start,_initializer_marker_name=marker)
    for name,function in _initializer_original.items():private[name]=_initializer_clone(function,private)
    held_observe=private['observe']
    def observe(root,limits):return state.observed(root,limits,held_observe)
    private['observe']=observe
    return types.SimpleNamespace(**private)

_initializer_original=dict(observe=observe,limits_from=limits_from,exec_helper=exec_helper,initialize=_initializer_initialize_body)

def _initializer_exec_helper(root,workspace):
    state=_InitializerTelemetry('WORKER');api=_initializer_facade(globals(),state,None)
    try:value=api.exec_helper(root,workspace)
    except BaseException:state.finish('REFUSED');raise
    state.finish('RETURNED');return value

def _initializer_initialize(args,source,*,comparator_path,marker):
    if marker not in ('aux-'+'initialization-started','aux-recovery-'+'initialization-started'):raise ValueError('finite initializer marker required')
    state=_InitializerTelemetry('PARENT',source);api=_initializer_facade(globals(),state,marker)
    result=api.initialize(args,source,comparator_path=comparator_path)
    result['initializer_telemetry']=state.result();return result

exec_helper=_initializer_exec_helper

def initialize(args,source,*,comparator_path):
    return _initializer_initialize(args,source,comparator_path=comparator_path,marker='aux-initialization-started')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker',action='store_true',required=True)
    parser.add_argument('--root',type=Path,required=True); parser.add_argument('--workspace',type=Path,required=True)
    args=parser.parse_args(); exec_helper(args.root,args.workspace)
