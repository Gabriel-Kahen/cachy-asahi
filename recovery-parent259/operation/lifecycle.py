# SPDX-License-Identifier: MIT
"""Actual Apps16 reinstall interruption; private copy retained for original outer scrub."""
import ast,gzip,hashlib,io,json,math,os,re,signal,stat,sys,time,types
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common as X
SOURCE=Path('/source');WORK=Path('/work');OUT=Path('/out');INPUTS=Path('/inputs')


ORIGINAL_INTERRUPTED=dict(bytes=2966,sha256='b7623212c76c7717aa7df1a11bf141d1e1c81e3a4a69f89e65f014f0619f8506')
DERIVED_INTERRUPTED={'bytes': 3291, 'sha256': '26dff8fc6ce9ebd37f1b6dcdf47a7916c591208fea95e4d8b8106cb41168adad'}
MAX_MAP_GZIP=64*1024**2
MAX_MAP_RAW=256*1024**2
LOCK_FIELDS=('device','inode','mode','uid','gid','nlink','bytes','mtime_ns','ctime_ns')
LOCK_STAGES=('before-stop','after-stop','post-kill','after-negative-inspect','after-negative-retry')
WORKER_EVENTS=('spawn','sigstop-sent','kernel-stop-observed','sigkill-sent','direct-child-reaped','group-absent')
INTERRUPTION_SEAMS=(
 (";started=time.monotonic()", ";started=time.monotonic();export_evidence.capture('begin',started)"),
 ("start_new_session=True)\n", "start_new_session=True);export_evidence.capture('spawn',process)\n"),
 ("    os.killpg(process.pid,signal.SIGSTOP);seen=", "    export_evidence.capture('before_stop',process,lock)\n    os.killpg(process.pid,signal.SIGSTOP);export_evidence.capture('stopped',process);seen="),
 ("   try:os.killpg(process.pid,signal.SIGKILL)", "   export_evidence.capture('before_kill',process)\n   try:os.killpg(process.pid,signal.SIGKILL)"),
 ("   process.wait(timeout=5)", "   process.wait(timeout=5);export_evidence.capture('reaped',process)"),
 (" value=dict(status='FAIL_INTERRUPTED_OWNED_COPY_RETAINED'", " export_evidence.capture('complete',process,absent)\n value=dict(status='FAIL_INTERRUPTED_OWNED_COPY_RETAINED'"),
)


def derive_interrupted(raw):
    """Exact complete original function, six additive seams, reversible byte ledger."""
    node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='interrupted')
    before=ast.get_source_segment(raw,node)+'\n';X.need(X.pin(before.encode())==ORIGINAL_INTERRUPTED,'entire original interrupted body hash')
    derived=before;seams=[]
    for old,new in INTERRUPTION_SEAMS:
        X.need(derived.count(old)==1,'one exact additive worker export seam')
        derived=derived.replace(old,new,1);seams.append(dict(before=X.pin(old.encode()),after=X.pin(new.encode())))
    inverse=derived
    for old,new in reversed(INTERRUPTION_SEAMS):
        X.need(inverse.count(new)==1,'one exact inverse worker export seam');inverse=inverse.replace(new,old,1)
    X.need(inverse==before,'whole original worker inverse bytes')
    ledger=dict(schema_version=1,status='EXACT_ORIGINAL_INTERRUPTED_WITH_ADDITIVE_EXPORTS',source_path=X.LANE+'/base_lifecycle.py',function='interrupted',original=X.pin(before.encode()),derived=X.pin(derived.encode()),seams=seams,inverse='BYTE_IDENTICAL_COMPLETE_ORIGINAL_FUNCTION',original_budget_seconds=600,original_reap_seconds=5,original_combined_output_bytes=1024**2)
    X.need(ledger['derived']==DERIVED_INTERRUPTED,'whole fixed derived worker body')
    return derived,ledger


def interruption_ledger_check(value):
    expected=dict(schema_version=1,status='EXACT_ORIGINAL_INTERRUPTED_WITH_ADDITIVE_EXPORTS',source_path=X.LANE+'/base_lifecycle.py',function='interrupted',original=ORIGINAL_INTERRUPTED,derived=DERIVED_INTERRUPTED,seams=[dict(before=X.pin(old.encode()),after=X.pin(new.encode()))for old,new in INTERRUPTION_SEAMS],inverse='BYTE_IDENTICAL_COMPLETE_ORIGINAL_FUNCTION',original_budget_seconds=600,original_reap_seconds=5,original_combined_output_bytes=1024**2)
    X.need(value==expected,'whole exact original/additive/inverse worker derivation ledger')
    return value


def lock_metadata(info):
    return dict(zip(LOCK_FIELDS,(info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)))


def lock_metadata_check(value,uid=0):
    X.need(type(value)is dict and set(value)==set(LOCK_FIELDS)and all(type(v)is int for v in value.values()),'whole typed ALPM lock identity')
    X.need(value['device']>=0 and value['inode']>0 and stat.S_ISREG(value['mode'])and value['mode']&~(stat.S_IFREG|0o7777)==0 and value['uid']==uid and value['gid']==uid and value['nlink']==1 and value['bytes']==0 and value['mtime_ns']>=0 and value['ctime_ns']>=0,'ordinary untouched zero-byte singlelink ALPM lock metadata')
    return value


def worker_identity(pid):
    with open('/proc/'+str(pid)+'/stat','rb')as stream:raw=stream.read(65537)
    X.need(len(raw)<=65536,'bounded actual worker proc stat');parts=raw[raw.rfind(b')')+2:].split()
    return dict(pid=pid,pgid=int(parts[2]),sid=int(parts[3]),start=int(parts[19]),uid=Path('/proc/'+str(pid)).stat().st_uid),parts[0].decode('ascii')


class WorkerEvidence:
    """Only this owned Popen leader/group; instrumentation cannot bypass original cleanup."""
    def __init__(self,workspace,owner,argv):
        self.workspace=Path(workspace);self.owner=owner;self.argv=[*map(str,argv),'--worker'];self.started=None
        self.value=dict(schema_version=1,kind='RAW_OWNED_INTERRUPTED_WORKER_KERNEL_TRACE',argv=self.argv,workspace=str(workspace),ownership_sha256=owner,events=[],locks={},errors=[],time_limit=600,reap_limit=5,combined_output_limit=1024**2)
    def capture(self,name,*args):
        try:getattr(self,name)(*args)
        except Exception as error:self.value['errors'].append(dict(stage=name,type=type(error).__name__,message=str(error)[:512]))
    def begin(self,started):self.started=started
    def event(self,name,**fields):
        X.need(self.started is not None,'original worker clock bound')
        self.value['events'].append(dict(event=name,seconds=round(time.monotonic()-self.started,6),**fields))
    def identity(self,process):
        value,state=worker_identity(process.pid);X.need(value==self.value['identity'],'same owned unreaped worker identity');return value,state
    def spawn(self,process):
        identity,state=worker_identity(process.pid);X.need(identity['pid']==identity['pgid']==identity['sid']and identity['uid']==os.geteuid(),'fresh actual worker session identity')
        with open('/proc/'+str(process.pid)+'/cmdline','rb')as stream:raw=stream.read(1024**2+1)
        X.need(len(raw)<=1024**2 and raw.endswith(b'\0'),'bounded complete actual worker cmdline');argv=[n.decode('utf-8')for n in raw[:-1].split(b'\0')]
        X.need(argv==self.argv,'actual exec argv equals exact original directly supervised --worker')
        self.value['identity']=identity;self.event('spawn',identity=identity,proc_state=state,cmdline=argv)
    def checkpoint(self,stage,expected=None):
        path=self.workspace/'root/var/lib/pacman/db.lck';a=lock_metadata(path.lstat());b=lock_metadata(path.lstat())
        X.need(a==b and(expected is None or a==expected),'stable original lock metadata checkpoint')
        self.value['locks'][stage]=a
        return a
    def before_stop(self,process,lock):
        identity,state=self.identity(process);self.checkpoint('before-stop',lock_metadata(lock))
        self.event('sigstop-sent',identity=identity,signal=int(signal.SIGSTOP),leader_unreaped=True)
    def stopped(self,process):
        while True:
            X.need(time.monotonic()-self.started<600,'original600s kernel stop observation bound')
            event=os.waitid(os.P_PID,process.pid,os.WSTOPPED|os.WNOHANG|os.WNOWAIT)
            if event is not None:break
            time.sleep(.001)
        identity,state=self.identity(process)
        X.need(event.si_pid==process.pid and event.si_code==os.CLD_STOPPED and event.si_status==signal.SIGSTOP and state in ('T','t'),'actual kernel SIGSTOP before final kill')
        self.checkpoint('after-stop',self.value['locks']['before-stop'])
        self.event('kernel-stop-observed',identity=identity,proc_state=state,waitid=dict(pid=event.si_pid,uid=event.si_uid,signo=event.si_signo,status=event.si_status,code=event.si_code),leader_unreaped=True)
    def before_kill(self,process):
        identity,state=self.identity(process);self.event('sigkill-sent',identity=identity,signal=int(signal.SIGKILL),leader_unreaped=True,proc_state=state)
    def reaped(self,process):self.event('direct-child-reaped',returncode=process.returncode,direct_child_reaped=True)
    def complete(self,process,absent):
        X.need(absent and process.returncode==-signal.SIGKILL,'original direct reap and killed outcome')
        try:os.killpg(process.pid,0)
        except ProcessLookupError:pass
        else:raise ValueError('owned worker group still present')
        self.checkpoint('post-kill',self.value['locks']['before-stop'])
        self.event('group-absent',group_absent=True)
        self.value.update(status='PASS_RAW_OWNED_WORKER_STOP_KILL_REAP_AND_GROUP_ABSENCE',worker_seconds=round(time.monotonic()-self.started,6),direct_child_reaped=True,group_absent=True,returncode=process.returncode)


def worker_trace_check(value,partial=False,uid=0):
    X.need(value['schema_version']==1 and value['kind']=='RAW_OWNED_INTERRUPTED_WORKER_KERNEL_TRACE'and value['status']=='PASS_RAW_OWNED_WORKER_STOP_KILL_REAP_AND_GROUP_ABSENCE'and not value['errors'],'complete raw worker trace without instrumentation errors')
    identity=value['identity'];X.need(set(identity)=={'pid','pgid','sid','start','uid'}and all(type(v)is int for v in identity.values())and identity['pid']>1 and identity['pid']==identity['pgid']==identity['sid']and identity['start']>0 and identity['uid']==uid,'exact owned native worker PID/PGID/SID/start/UID')
    argv=value['argv'];X.need(type(argv)is list and 1<len(argv)<=256 and all(type(a)is str and '\0'not in a for a in argv)and sum(len(a.encode())+1 for a in argv)<=1024**2 and argv[-1]=='--worker','complete directly supervised worker argv')
    X.need(value['time_limit']==600 and value['reap_limit']==5 and value['combined_output_limit']==1024**2 and value['direct_child_reaped']is True and value['group_absent']is True and value['returncode']==-signal.SIGKILL and type(value['worker_seconds'])in(int,float)and 0<value['worker_seconds']<=605,'exact600+5 worker reap/output bounds')
    events=value['events'];X.need([r['event']for r in events]==list(WORKER_EVENTS),'complete ordered raw worker event sequence')
    previous=-1
    for row in events:
        seconds=row['seconds'];X.need(type(seconds)in(int,float)and math.isfinite(seconds)and previous<=seconds<=value['worker_seconds']<=605,'finite original worker event clock');previous=seconds
        if 'identity'in row:X.need(row['identity']==identity,'unreaped worker identity continuity')
    X.need(events[0]['cmdline']==argv and events[1]['signal']==signal.SIGSTOP and events[1]['leader_unreaped']is True and events[2]['leader_unreaped']is True and events[2]['proc_state']in('T','t'),'actual spawn and stopped-kernel observations')
    event=events[2]['waitid'];X.need(event==dict(pid=identity['pid'],uid=uid,signo=signal.SIGCHLD,status=signal.SIGSTOP,code=os.CLD_STOPPED),'raw kernel stopped child event')
    X.need(events[3]['signal']==signal.SIGKILL and events[3]['leader_unreaped']is True and events[3]['proc_state']in('T','t')and events[4]['returncode']==-signal.SIGKILL and events[4]['direct_child_reaped']is True and events[5]['group_absent']is True,'final group signal before direct leader reap and absence')
    stages=LOCK_STAGES[:3]if partial else LOCK_STAGES;X.need(set(value['locks'])==set(stages),'all original ALPM lock checkpoints')
    locks=[lock_metadata_check(value['locks'][n],uid)for n in stages];X.need(all(row==locks[0]for row in locks),'whole original ALPM lock identity remains unchanged')
    return value


def interrupted_export(C,H,calls,workspace,owner,argv):
    raw=C.read(SOURCE/X.LANE/'base_lifecycle.py',2*1024**2).decode();derived,ledger=derive_interrupted(raw)
    C.save(OUT/'worker-derivation.json',ledger);evidence=WorkerEvidence(workspace,owner,argv)
    scope=dict(vars(H),export_evidence=evidence);exec(compile(derived,str(SOURCE/X.LANE/'base_lifecycle.py')+':additive-worker-evidence','exec'),scope)
    try:
        result=scope['interrupted'](calls,workspace,owner,argv)
        worker_trace_check(evidence.value,partial=True)
        result['worker_trace']=dict(path='worker-trace.json',**X.pin(X.encoded(evidence.value)))
        result['worker_derivation']=C.ref(OUT,OUT/'worker-derivation.json')
        C.save(OUT/'interruption.json',result)
        return result,evidence
    finally:C.save(OUT/'worker-trace.json',evidence.value)


def clone_function(function,namespace=None,closure=None):
    value=types.FunctionType(function.__code__,function.__globals__ if namespace is None else namespace,function.__name__,function.__defaults__,function.__closure__ if closure is None else closure)
    value.__kwdefaults__=function.__kwdefaults__;value.__dict__.update(function.__dict__)
    X.need(value.__code__ is function.__code__,'entire original observer function code retained')
    return value


def original_inner(function):
    while hasattr(function,'__wrapped__'):function=function.__wrapped__
    return function


def rebind_function(function,key,value):
    if hasattr(function,'__wrapped__'):
        old=function.__wrapped__;new=rebind_function(old,key,value)
        def cell(value):return(lambda:value).__closure__[0]
        X.need(function.__closure__ is not None and sum(c.cell_contents is old for c in function.__closure__)==1,'one original traced-function closure')
        closure=tuple(cell(new)if c.cell_contents is old else c for c in function.__closure__)
        result=clone_function(function,closure=closure);result.__wrapped__=new;return result
    if key not in function.__globals__ and key=='_file_hash':
        X.need(function.__closure__ is not None and function.__code__.co_freevars.count('private_roots')==1,'one original private observer roots closure')
        at=function.__code__.co_freevars.index('private_roots');old=function.__closure__[at].cell_contents
        X.need(hasattr(old,'observe'),'closed private observer facade')
        new=types.SimpleNamespace(**dict(vars(old),observe=rebind_function(old.observe,key,value)))
        def cell(value):return(lambda:value).__closure__[0]
        closure=tuple(cell(new)if i==at else c for i,c in enumerate(function.__closure__))
        return clone_function(function,closure=closure)
    X.need(key in function.__globals__,'one explicit existing observer dependency')
    return clone_function(function,dict(function.__globals__,**{key:value}))


def observer_hash(function):
    function=original_inner(function)
    if '_file_hash'in function.__globals__:return function.__globals__['_file_hash']
    X.need(function.__closure__ is not None and function.__code__.co_freevars.count('private_roots')==1,'one source-owned native observer path facade')
    at=function.__code__.co_freevars.index('private_roots');return observer_hash(function.__closure__[at].cell_contents.observe)


def metadata_lock_measure(adapter,root,limits,expected):
    """Whole original observer; only exact zero lock descriptor avoids content reads."""
    lock_metadata_check(expected);lock_path=Path(root)/'var/lib/pacman/db.lck';X.need(lock_metadata(lock_path.lstat())==expected,'exact stable lock path before private observer');measure=adapter.measure
    measured=original_inner(measure).__globals__['_measure'];roots=original_inner(measured).__globals__['roots'];observe=roots.observe
    original_hash=observer_hash(observe);hits=[]
    def hash_without_lock_read(fd,before,budget):
        if before.st_dev==expected['device']and before.st_ino==expected['inode']:
            budget.tick();X.need(lock_metadata(before)==expected==lock_metadata(os.fstat(fd)),'exact zero-byte original lock descriptor before metadata-only hash')
            hits.append(1);budget.tick();X.need(lock_metadata(os.fstat(fd))==expected,'exact original lock descriptor after metadata-only hash')
            return hashlib.sha256(b'').hexdigest()
        return original_hash(fd,before,budget)
    private_observe=rebind_function(observe,'_file_hash',hash_without_lock_read)
    private_roots=types.SimpleNamespace(**dict(vars(roots),observe=private_observe))
    private_measured=rebind_function(measured,'roots',private_roots)
    private_measure=rebind_function(measure,'_measure',private_measured)
    result=private_measure(root,limits);X.need(lock_metadata(lock_path.lstat())==expected,'exact stable lock path after private observer');X.need(len(hits)==1,'one exact metadata-only ALPM lock hash operand')
    ledger=dict(schema_version=1,status='WHOLE_ORIGINAL_OBSERVER_CODE_PRIVATE_ZERO_LOCK_HASH_DEPENDENCY',bindings=['observe._file_hash','_measure.roots','measure._measure'],all_original_function_code_objects_held=True,all_other_descriptor_hashes='ORIGINAL_UNCHANGED',lock_content='NOT_READ_OR_MUTATED',lock=expected,lock_descriptor_visits=1,derived_hash='SHA256_EMPTY_FROM_STABLE_ZERO_BYTE_STAT')
    return result,ledger


def map_path(name):
    X.need(type(name)is str and name and len(name.encode('utf-8','surrogateescape'))<=4096 and '\0'not in name and not name.startswith('/')and all(p not in('','.','..')for p in name.split('/')),'safe complete POSIX node path')
    return name


def root_map_check(value,phase):
    X.need(value['schema_version']==1 and value['kind']=='RAW_COMPLETE_COPIED_ROOT_NODES_AND_CAPABILITIES'and value['phase']==phase,'exact copied-root raw export role')
    observed=value['observation'];nodes=observed['nodes'];caps=value['capabilities']
    X.need(observed['complete']is True and set(observed['unsupported_counts'])<={'absolute-symlink','auxiliary-present'}and type(nodes)is dict and 0<len(nodes)<=500000 and observed['footprint']['nodes']==len(nodes)and type(observed['footprint']['bytes'])is int and 0<=observed['footprint']['bytes']<=8*1024**3,'complete bounded copied-root observation')
    total=0
    for name,row in nodes.items():
        map_path(name);X.need(type(row)is dict and row['type']in('file','directory','symlink')and all(type(row[k])is int and 0<=row[k]<=(0o7777 if k=='mode'else 0xffffffff)for k in('mode','uid','gid')),'ordinary complete node metadata')
        parent=name.rpartition('/')[0];X.need(not parent or nodes.get(parent,{}).get('type')=='directory','complete ordinary parent directory chain')
        if row['type']=='file':X.need(type(row['bytes'])is int and 0<=row['bytes']<=1024**3 and re.fullmatch('[0-9a-f]{64}',row['sha256']),'whole ordinary file hash/bytes');total+=row['bytes']
        elif row['type']=='symlink':X.need(type(row['target'])is str and '\0'not in row['target']and len(row['target'].encode('utf-8','surrogateescape'))<=4096,'complete literal symlink target')
    X.need(total==observed['footprint']['bytes'],'full copied-root logical byte accounting')
    groups=observed.get('hardlink_groups',{});X.need(type(groups)is dict and len(groups)<=4096,'bounded whole copied hardlink groups');aliases=0
    for name,row in groups.items():
        map_path(name);members=row['members'];X.need(type(members)in(list,tuple)and list(members)==sorted(set(members))and 1<len(members)==row['nlink']<=4096 and name==members[0],'closed complete copied hardlink group')
        aliases+=len(members);X.need(aliases<=16384,'bounded complete hardlink aliases')
        for member in members:X.need(member in nodes and nodes[member].get('hardlink_group')==name and all(nodes[member][k]==row[k]for k in('bytes','mode','uid','gid','sha256')),'whole hardlink member metadata equality')
    X.need(all('hardlink_group'not in row or row['hardlink_group']in groups and name in groups[row['hardlink_group']]['members']for name,row in nodes.items()),'complete hardlink group reverse closure')
    X.need(type(caps)is dict and len(caps)<=4096 and len(X.encoded(caps))<=1024**2 and all(n in nodes and nodes[n]['type']=='file'and type(v)is str and re.fullmatch('[0-9a-f]{40}|[0-9a-f]{48}',v)for n,v in caps.items()),'whole bounded capability map on observed ordinary files')
    X.need(value['nodes_sha256']==X.pin(X.encoded(nodes))['sha256']and value['capabilities_sha256']==X.pin(X.encoded(caps))['sha256'],'raw complete nodes/capability map digest')
    return value


def compare_copied_maps(healthy,after,payload,version):
    root_map_check(healthy,'healthy');root_map_check(after,'post-interruption')
    X.need(version==X.VERSION and type(payload)is dict and len([n for n,v in payload.items()if v['type']=='file'])==8,'exact complete selected Apps16 eight ordinary payload leaves')
    left=protected(healthy['observation']['nodes'],payload,version);right=protected(after['observation']['nodes'],payload,version)
    X.need(left==right,'independent full nonselected/config/user/trust/base/other-three node comparison')
    X.need(healthy['capabilities']==after['capabilities'],'independent complete copied-root capability preservation')
    X.need(healthy['observation'].get('hardlink_groups',{})==after['observation'].get('hardlink_groups',{}),'complete copied-root hardlink identity topology preserved')
    return dict(status='PASS_RAW_COMPLETE_PROTECTED_NODES_AND_CAPABILITIES_EQUAL',protected_nodes=len(left),selected_file_exclusions=sorted(n for n,v in payload.items()if v['type']=='file'),selected_database_exclusion='var/lib/pacman/local/'+X.APPS+'-'+version,lock_exclusion='var/lib/pacman/db.lck',capabilities_sha256=healthy['capabilities_sha256'],commit_started='UNKNOWN',packages_committed='UNKNOWN',rollback='NOT_CLAIMED')


def export_root_map(C,phase,observed,caps):
    value=dict(schema_version=1,kind='RAW_COMPLETE_COPIED_ROOT_NODES_AND_CAPABILITIES',phase=phase,observation=observed,capabilities=caps,nodes_sha256=X.pin(X.encoded(observed['nodes']))['sha256'],capabilities_sha256=X.pin(X.encoded(caps))['sha256'])
    root_map_check(value,phase);path=OUT/('copied-root-'+phase+'.json.gz');digest=hashlib.sha256();size=0
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb')as target:
        with gzip.GzipFile(filename='',mode='wb',fileobj=target,mtime=0,compresslevel=6)as stream:
            encoder=json.JSONEncoder(sort_keys=True,indent=2,ensure_ascii=True,allow_nan=False)
            for text in encoder.iterencode(value):
                raw=text.encode();size+=len(raw);X.need(size<=MAX_MAP_RAW,'bounded raw full copied-root map');digest.update(raw);stream.write(raw);X.need(target.tell()<=MAX_MAP_GZIP,'bounded gzip full copied-root map')
            digest.update(b'\n');size+=1;X.need(size<=MAX_MAP_RAW,'bounded raw full copied-root map');stream.write(b'\n')
        target.flush();os.fsync(target.fileno());X.need(target.tell()<=MAX_MAP_GZIP,'bounded complete gzip copied-root map')
    compressed=C.read(path,MAX_MAP_GZIP)
    return dict(path=path.name,**X.pin(compressed),raw_bytes=size,raw_sha256=digest.hexdigest(),nodes=len(observed['nodes']),nodes_sha256=value['nodes_sha256'],capabilities_sha256=value['capabilities_sha256'],phase=phase)


def decode_root_export(C,raw,ref,phase):
    X.need(type(raw)is bytes and 0<len(raw)<=MAX_MAP_GZIP and X.pin(raw)=={k:ref[k]for k in('bytes','sha256')},'whole bounded gzip copied-root body pin')
    with gzip.GzipFile(fileobj=io.BytesIO(raw))as stream:unpacked=stream.read(MAX_MAP_RAW+1)
    X.need(len(unpacked)<=MAX_MAP_RAW and len(unpacked)==ref['raw_bytes']and X.pin(unpacked)['sha256']==ref['raw_sha256'],'bounded exact full raw copied-root bytes/hash')
    value=C.decode(unpacked);root_map_check(value,phase)
    X.need(ref['phase']==phase and ref['nodes']==len(value['observation']['nodes'])and ref['nodes_sha256']==value['nodes_sha256']and ref['capabilities_sha256']==value['capabilities_sha256'],'full copied map export reference joins')
    return value


def retained_evidence(C,life,directory,filepins,selected_payload=None):
    """Pure retained-byte replay; caller may supply independently native-derived payload."""
    interrupted=life['interruption'];trace_ref=interrupted['worker_trace'];ledger_ref=interrupted['worker_derivation']
    X.need(trace_ref['path']=='worker-trace.json'and ledger_ref['path']=='worker-derivation.json','fixed worker raw evidence roles')
    objects=[]
    for ref in(trace_ref,ledger_ref):
        raw=C.read(directory/ref['path'],1024**2);X.need(X.pin(raw)=={k:ref[k]for k in('bytes','sha256')}==filepins['lifecycle-public/'+ref['path']],'exact worker raw export/hash/retention joins');objects.append(C.decode(raw))
    trace,ledger=objects;worker_trace_check(trace)
    X.need(trace['workspace']==interrupted['workspace']and trace['ownership_sha256']==interrupted['ownership_sha256']and trace['worker_seconds']<=interrupted['seconds']+.1,'raw worker/original interruption identity and timing joins')
    interruption_ledger_check(ledger)
    old=interrupted['real_lock_observed'];lock=trace['locks']['before-stop'];X.need(old==dict(device=lock['device'],inode=lock['inode'],mode=stat.S_IMODE(lock['mode']),bytes=lock['bytes']),'original limited lock receipt joins complete raw metadata')
    commands=C.decode(C.read(directory/'commands.json',4*1024**2));X.need(len(commands)==10 and trace['argv']==commands[-1]['argv']+['--worker'],'actual stopped worker argv joins exact original negative retry argv')
    exports=life['copied_root_exports'];X.need(exports['schema_version']==1 and exports['kind']=='RAW_FULL_COPIED_ROOT_MAPS','complete pair of raw copied-root exports')
    payload=exports['selected_payload'];X.need(selected_payload is None or payload==selected_payload,'independent native selected payload matches exported exclusion operand')
    observer_ref=exports['lock_observer'];X.need(observer_ref['path']=='lock-observer-derivation.json','fixed metadata-only observer derivation role')
    observer_raw=C.read(directory/observer_ref['path'],1024**2);X.need(X.pin(observer_raw)=={k:observer_ref[k]for k in('bytes','sha256')}==filepins['lifecycle-public/'+observer_ref['path']],'exact raw zero-lock observer dependency ledger')
    observer=C.decode(observer_raw);expected_observer=dict(schema_version=1,status='WHOLE_ORIGINAL_OBSERVER_CODE_PRIVATE_ZERO_LOCK_HASH_DEPENDENCY',bindings=['observe._file_hash','_measure.roots','measure._measure'],all_original_function_code_objects_held=True,all_other_descriptor_hashes='ORIGINAL_UNCHANGED',lock_content='NOT_READ_OR_MUTATED',lock=lock,lock_descriptor_visits=1,derived_hash='SHA256_EMPTY_FROM_STABLE_ZERO_BYTE_STAT');X.need(observer==expected_observer,'whole observer unchanged except exact zero-lock content-read dependency')
    maps=[]
    for key,phase in(('healthy','healthy'),('post_interruption','post-interruption')):
        ref=exports[key];X.need(ref['path']=='copied-root-'+phase+'.json.gz','fixed full copied-root raw role')
        raw=C.read(directory/ref['path'],MAX_MAP_GZIP);X.need(filepins['lifecycle-public/'+ref['path']]=={k:ref[k]for k in('bytes','sha256')},'full copied-root retention pin')
        maps.append(decode_root_export(C,raw,ref,phase))
    lock_name='var/lib/pacman/db.lck';X.need(lock_name not in maps[0]['observation']['nodes'] and maps[1]['observation']['nodes'][lock_name]==dict(type='file',mode=stat.S_IMODE(lock['mode']),uid=lock['uid'],gid=lock['gid'],bytes=0,sha256=hashlib.sha256(b'').hexdigest()),'raw complete after-map zero lock node matches metadata-only observer operand')
    comparison=compare_copied_maps(*maps,payload,X.VERSION);X.need(comparison==exports['comparison']and comparison['capabilities_sha256']==life['source_capabilities_sha256'],'independent complete copied-root comparison/source capability join')
    return dict(status='PASS_RAW_WORKER_STOP_REAP_LOCK_AND_FULL_PROTECTED_COPIED_MAP_REPLAY',worker=trace,derivation=ledger,comparison=comparison,selected_payload_authority='INDEPENDENT_NATIVE_DATA'if selected_payload is not None else'EXPORTED_SOURCE_DERIVED_METADATA',repair_success=False,commit_started='UNKNOWN',packages_committed='UNKNOWN',rollback='NOT_CLAIMED')


def protected(nodes,payload,version):
    # Only selected ordinary payload bytes and its exact ALPM record can be
    # uncertain. Shared directories and all user/config/trust/base nodes stay exact.
    selected={n for n,v in payload.items()if v['type']=='file'}
    package='var/lib/pacman/local/'+X.APPS+'-'+version
    return {n:v for n,v in nodes.items()if n not in selected and n!='var/lib/pacman/db.lck'
            and n!=package and not n.startswith(package+'/')}


def validate(C,value):
    C.need(value['status']==X.LIFECYCLE and value['operation']==X.OPERATION and value['case']=='repair-bytes','separate recovery operation')
    C.need(value['base_count']==574 and value['installed_count']==578 and value['full_current607']=='PENDING_SEPARATE_EXACT_ROUTE','exact component scope; no607 admission')
    C.need(value['hardware']=='NOT_RUN'and value['release']=='NOT_ADMITTED'and value['rollback']=='NOT_CLAIMED','no hardware/release/rollback inference')
    C.need(value['commit_started']is True and value['packages_committed']=='UNKNOWN','actual interrupted commit evidence without completion inference')
    C.need(value['repair_success']is True and value['restoration']['repair_success']is True and value['restoration']['database']=='EXACT_RAW_HEALTHY_BYTES','only full exact restoration qualifies this case')
    C.load('recovery_install_checks',C.HERE/'checks.py').preserved(C,value['install'],value['source_capabilities_sha256'])
    C.need(value['install']['prepared_add']==C.VERSIONS and not value['install']['prepared_remove'],'signed installed578')
    X.selected_plan(value['plan']);X.interruption(value['interruption'],value['plan_sha256'],value['preparations']['repair-bytes']['before'])
    C.need(value['inspection_refusal']['status']=='FAIL'and 'before'not in value['inspection_refusal'],'ordinary inspection refused pending root')
    C.need(value['retry_refusal']['status']=='FAIL'and value['retry_refusal']['commit_started']is False and value['retry_refusal']['packages_committed']is False,'ordinary retry refused uncertain root')
    C.need(value['recovery_admission']['repair_success']is False and value['recovery_admission']['normal_apply']=='NOT_RUN','admission alone never repair authority')
    checks=C.load('recovery_normal_checks',C.HERE/'checks.py')
    checks.inspection(C,value['preparations']['repair-bytes'],value['plan_sha256'])
    fresh_inspection(C,value['recovery_inspection'],value['plan_sha256'],value['copied_root_exports']['selected_payload'])
    repair=value['normal_repair'];C.need(repair['status']=='PASS_OWNED_DISPOSABLE_APPS_TRANSACTION'and repair['operation']=='reinstall'and repair['commit_started']is True and repair['packages_committed']is True and repair['prepared_add']=={X.APPS:X.VERSION}and not repair['prepared_remove'],'actual separate normal repair commit')
    fresh=value['recovery_inspection'];proof=repair['full574_closure']['repair']
    C.need(repair['before']==fresh['before']and repair['plan_sha256']==value['plan_sha256']and repair['full574_binding']==fresh['full574_binding'],'normal repair bound to fresh normal inspection and plan')
    C.need(proof['status']=='SELECTED_SIGNED_ORDINARY_LEAVES_RESTORED'and proof['selected']==[X.APPS]and proof['before_damage']==fresh['damage']and proof['archives']==fresh['archives']and proof['plan_sha256']==value['plan_sha256'],'normal source-owned repair proof joins fresh damage/archive/plan')
    checks.preserved(C,repair,value['source_capabilities_sha256'])
    C.need(value['source_preserved']is True and value['user_trust_protected_preserved']is True and value['workspaces_disposed']is False and value['workspaces_retained_for_outer_disposal']is True,'original readonly source and ordered outer disposal')
    C.need(value['root_map_replay']=='RAW_COMPLETE_BEFORE_PARTIAL_AFTER_MAPS','three complete raw maps')
    return value


def retained(C,value,directory,files):
    """Data recheck only: never imports or executes a retained artifact source."""
    import boundary,recovery
    validate(C,value)
    roles={'plan':'repair-bytes-plan.json','interruption':'interruption.json','inspection_refusal':'post-interruption-inspection.json','retry_refusal':'post-interruption-retry.json','transaction_boundary':'transaction-boundary.json','recovery_admission':'recovery-admission.json','recovery_inspection':'recovery-inspection.json','normal_repair':'normal-repair.json','restoration':'restoration-comparison.json'}
    # The negative receipts are captured before any backend admission can mutate markers.
    for field,name in roles.items():
        raw=C.read(directory/name,4*1024**2);C.need(C.decode(raw)==value[field]and files['lifecycle-public/'+name]==X.pin(raw),'exact raw retained recovery role: '+name)
    trace=retained_worker(C,value,directory,files)
    b=boundary.validate(value['transaction_boundary'],trace,value['plan'],value['preparations']['repair-bytes'])
    C.need(b['commit_started']is True and b['packages_committed']=='UNKNOWN','retained genuine partial commit, never completed-package inference')
    maps={}
    for field,phase in(('healthy','healthy'),('post_interruption','post-interruption'),('restored','restored')):
        ref=value['copied_root_exports'][field];raw=C.read(directory/ref['path'],MAX_MAP_GZIP)
        C.need(files['lifecycle-public/'+ref['path']]=={k:ref[k]for k in('bytes','sha256')},'original complete raw map pin')
        maps[field]=decode_root_export(C,raw,ref,phase)
    payload=value['copied_root_exports']['selected_payload']
    compare_copied_maps(maps['healthy'],maps['post_interruption'],payload,X.VERSION)
    lock=trace['locks']['before-stop'];node=dict(type='file',mode=stat.S_IMODE(lock['mode']),uid=lock['uid'],gid=lock['gid'],bytes=0,sha256=hashlib.sha256(b'').hexdigest())
    C.need(maps['post_interruption']['observation']['nodes'].get('var/lib/pacman/db.lck')==node and all('var/lib/pacman/db.lck'not in maps[k]['observation']['nodes']for k in('healthy','restored')),'complete raw lock node joins exact worker lock identity')
    inventory_raw=C.read(directory/'repair-bytes-inventory.json',16*1024**2)
    C.need(X.pin(inventory_raw)==files['lifecycle-public/repair-bytes-inventory.json']and X.pin(inventory_raw)['sha256']==value['preparations']['repair-bytes']['before']['inventory_sha256'],'physical original before-lock inventory and normal inspection pin')
    selected={n for n,r in payload.items()if r['type']=='file'}
    held=lambda nodes:{n:r for n,r in nodes.items()if n not in selected and n!='var/lib/pacman/db.lck'}
    C.need(held(maps['healthy']['observation']['nodes'])==held(maps['post_interruption']['observation']['nodes']),'retained partial raw DB/config/unselected bytes held')
    pending_raw=C.read(directory/'interrupted-pending.json',65536)
    C.need(C.decode(pending_raw)==value['interruption']['pending']and files['lifecycle-public/interrupted-pending.json']==X.pin(pending_raw),'exact original pending retained before release')
    markers=value['recovery_admission']['markers']
    C.need(markers['lock']==trace['locks']['before-stop']and markers['pending']==X.pin(pending_raw),'admission only released exact retired writer markers')
    fresh=value['recovery_inspection'];initial=value['preparations']['repair-bytes']['before'];repair=value['normal_repair']
    before_nodes={n:r for n,r in maps['post_interruption']['observation']['nodes'].items()if n!='var/lib/pacman/db.lck'}
    after_nodes=maps['restored']['observation']['nodes']
    actual_damage={n:before_nodes.get(n)for n in selected if before_nodes.get(n)!=payload[n]}
    C.need(fresh['damage']==actual_damage,'fresh normal damage joins exact raw partial selected leaves')
    for actual,nodes in((fresh['before'],before_nodes),(repair['after'],after_nodes)):
        db={n:r for n,r in nodes.items()if n=='var/lib/pacman'or n.startswith('var/lib/pacman/')}
        C.need(actual['tree_sha256']==X.pin(X.encoded(nodes))['sha256']and actual['database_sha256']==X.pin(X.encoded(db))['sha256'],'normal full before/after pins join raw copied-root maps')
        C.need(all(actual[k]==initial[k]for k in('packages_sha256','inventory_sha256')),'unchanged578 normalized metadata across exact raw DB restoration')
    restored=recovery.restored(None,sys.modules[__name__],maps['healthy'],maps['restored'],value['copied_root_exports']['selected_payload'],value['normal_queries']['healthy'],value['normal_queries']['restored'])
    C.need(restored==value['restoration'],'retained full healthy/restored raw bytes and queries')
    rows=C.decode(C.read(directory/'commands.json',4*1024**2));C.need(len(rows)<=64,'original command count')
    command_outputs=[]
    for i,row in enumerate(rows):
        C.need(row['group_absence_verified']is True and 0<row['time_limit']<=610 and row['seconds']<=row['time_limit']+6 and row['output_limit']==1024**2,'all original command timing/output/reap gates')
        sides={}
        for side in('stdout','stderr'):
            name='command-%02d.%s'%(i,side);raw=C.read(directory/name,1024**2);sides[side]=raw
            C.need(files['lifecycle-public/'+name]==X.pin(raw)==dict(bytes=row[side+'_bytes'],sha256=row[side+'_sha256']),'complete original command output bytes')
        command_outputs.append(sides)
    normal=value['transaction_boundary']['normal_argv']
    C.need(sum(row['argv']==normal[:-1]and row['exit_code']==1 for row in rows)==1,'raw negative retry exact normal worker argv inverse')
    for field in('install','inspection_refusal','retry_refusal','recovery_inspection','normal_repair'):
        matches=[]
        for i,sides in enumerate(command_outputs):
            try:decoded=C.decode(sides['stdout'])
            except(ValueError,UnicodeError):continue
            if decoded==value[field]:matches.append(i)
        C.need(len(matches)==1,'one exact normal command stdout for '+field)
    for phase in('healthy','restored'):
        queries=value['normal_queries'][phase]
        raw=C.read(directory/('normal-query-'+phase+'.json'),65536)
        C.need(C.decode(raw)==queries and files['lifecycle-public/normal-query-'+phase+'.json']==X.pin(raw),'raw normal loader/query summary')
        for q in queries.values():
            matches=[i for i,row in enumerate(rows)if row['argv']==['/usr/bin/chroot',value['interruption']['workspace']+'/root',*q['argv_tail']]and row['exit_code']==0 and row['group_absence_verified']is True and X.pin(command_outputs[i]['stdout'])==q['stdout']and X.pin(command_outputs[i]['stderr'])==q['stderr']]
            C.need(len(matches)==2,'one healthy and one restored original loader/query command')
    return dict(status='RETAINED_COMPLETE_COMPONENT578_RECOVERY_DATA_NOT_ROOT_ACCEPTANCE',repair_success=True,commit_started=True,packages_committed='UNKNOWN',rollback='NOT_CLAIMED',Root_acceptance=None,hardware='NOT_RUN')


def execute(C,R,T,adapter,calls):
    """Component578 only; all mutation inside the original offline owned actor."""
    import boundary,recovery,route607
    H=R.H;seed=Path('/seed');workspace=WORK/'main'
    baseline=adapter.measure(seed,T.limits());source_sha=adapter.digest(baseline['nodes'])
    caps=adapter.capability_map(seed,baseline,T.limits());caps_sha=adapter.digest(caps)
    users={n:v for n,v in baseline['nodes'].items()if n.startswith('home/')and v['type']in('file','symlink')};C.need(users,'original user configuration required')
    prepared=calls.call([*H.backend('prepare-copy',workspace),'--source',str(seed)])
    C.need(prepared['status']=='OWNED_COPY_PREPARED'and prepared['source_preserved']is True,'original owned full574 copy')
    owner=prepared['ownership_sha256'];H.retain_copy(workspace,owner)
    path,plan=R.planned(calls,workspace,'install','install',['apps','cache','orphans'])
    installed=calls.call(H.apply_args(calls,workspace,owner,path,plan))
    C.need(installed['prepared_add']==C.VERSIONS and not installed['prepared_remove']and len(H.count(workspace))==578,'actual signed component install578')
    C.load('operation_install_checks',C.HERE/'checks.py').preserved(C,installed,caps_sha)
    healthy=adapter.measure(workspace/'root',T.limits());payload=adapter.current_payloads()[X.APPS]
    healthy_caps=adapter.capability_map(workspace/'root',healthy,T.limits(),caps)
    healthy_export=export_root_map(C,'healthy',healthy,healthy_caps)
    healthy_map=decode_root_export(C,C.read(OUT/healthy_export['path'],MAX_MAP_GZIP),healthy_export,'healthy')
    query_before=query_checks(C,calls,workspace,'healthy')
    path,plan=R.planned(calls,workspace,'repair-bytes','reinstall',['apps']);X.selected_plan(plan)
    R.damage(workspace,R.TARGET,False)
    inspection=R.inspected(T,calls,workspace,owner,path,plan,'repair-bytes')
    C.need(inspection['archives']=={X.APPS:X.ARCHIVE},'original signed Apps16 archive required')
    normal_attempts=R.argv(calls,workspace,owner,path,plan,inspection['before'])
    report=dict(status='FAIL',operation=X.OPERATION,case='repair-bytes',hardware='NOT_RUN',release='NOT_ADMITTED',repair_success=False,commit_started='UNKNOWN',packages_committed='UNKNOWN',rollback='NOT_CLAIMED',base_count=574,installed_count=578,full_current607='PENDING_SEPARATE_EXACT_ROUTE')
    try:
        interrupted,evidence,boundary_result=interrupted_recovery(C,H,calls,workspace,owner,normal_attempts,payload,inspection)
        C.save(OUT/'transaction-boundary.json',boundary_result)
        report.update(transaction_boundary=boundary_result,commit_started=boundary_result['commit_started'],packages_committed=boundary_result['packages_committed'],interruption=interrupted)
        X.interruption(interrupted,C.sha(C.read(path)),inspection['before'])
        pending_raw=C.read(workspace/'apps-pending.json',65536);C.need(C.decode(pending_raw)==interrupted['pending'],'physical durable pending marker')
        (OUT/'interrupted-pending.json').write_bytes(pending_raw)
        argv=['/usr/bin/python3','-I','-B',str(SOURCE/X.LANE/'inspection.py'),'inspect-reinstall',*H.common(workspace,owner),*H.credentials(),'--applications',*plan['plan']['requested_applications'],'--plan',str(path),'--plan-sha256',C.sha(C.read(path))]
        refused=calls.call(argv,expected=1);C.need(refused['status']=='FAIL'and 'before'not in refused,'pending state must not authorize ordinary inspection')
        evidence.checkpoint('after-negative-inspect',evidence.value['locks']['before-stop'])
        retry=calls.call(normal_attempts,expected=1);C.need(retry['status']=='FAIL'and retry['commit_started']is False and retry['packages_committed']is False,'ordinary negative retry cannot start commit')
        evidence.checkpoint('after-negative-retry',evidence.value['locks']['before-stop']);worker_trace_check(evidence.value)
        C.save(OUT/'post-interruption-inspection.json',refused);C.save(OUT/'post-interruption-retry.json',retry)
        C.save(OUT/'worker-trace.json',evidence.value);interrupted['worker_trace']=C.ref(OUT,OUT/'worker-trace.json');C.save(OUT/'interruption.json',interrupted)
        C.need(C.read(workspace/'apps-pending.json',65536)==pending_raw,'exact original pending until recovery admission')
        partial,lock_observer=metadata_lock_measure(adapter,workspace/'root',T.limits(),evidence.value['locks']['before-stop'])
        C.save(OUT/'lock-observer-derivation.json',lock_observer)
        partial_caps=adapter.capability_map(workspace/'root',partial,T.limits(),caps)
        partial_export=export_root_map(C,'post-interruption',partial,partial_caps)
        partial_map=decode_root_export(C,C.read(OUT/partial_export['path'],MAX_MAP_GZIP),partial_export,'post-interruption')
        compare_copied_maps(healthy_map,partial_map,payload,X.VERSION)
        P=C.load('recovery_normal_inspection',SOURCE/X.LANE/'inspection.py')
        args=P.parser().parse_args(argv[4:])
        context=dict(trace=evidence.value,interruption=interrupted,healthy=healthy_map,partial=partial_map,inspection=inspection,boundary=boundary_result,inventory_raw=C.read(OUT/'repair-bytes-inventory.json',16*1024**2))
        admission=normal_admission(C,recovery.admit,args,T,P,sys.modules[__name__],R,adapter,context,boundary)
        C.save(OUT/'recovery-admission.json',admission)
        # New full before-pins and normal authentication; no original pins are reused.
        fresh=calls.call(argv);fresh_inspection(C,fresh,C.sha(C.read(path)),payload)
        C.save(OUT/'recovery-inspection.json',fresh)
        report['recovery_inspection']=fresh
        repair_args=R.argv(calls,workspace,owner,path,plan,fresh['before'])
        repaired=R.repaired(calls.call(repair_args),fresh['damage'])
        C.save(OUT/'normal-repair.json',repaired)
        after=adapter.measure(workspace/'root',T.limits());after_caps=adapter.capability_map(workspace/'root',after,T.limits(),caps)
        after_export=export_root_map(C,'restored',after,after_caps)
        after_map=decode_root_export(C,C.read(OUT/after_export['path'],MAX_MAP_GZIP),after_export,'restored')
        query_after=query_checks(C,calls,workspace,'restored')
        restored=recovery.restored(T,sys.modules[__name__],healthy_map,after_map,payload,query_before,query_after)
        C.save(OUT/'restoration-comparison.json',restored)
        original=adapter.measure(seed,T.limits());adapter.capability_map(seed,original,T.limits(),caps);C.need(adapter.digest(original['nodes'])==source_sha,'complete readonly source preserved')
        report.update(status=X.LIFECYCLE,install=installed,plan=plan,plan_sha256=C.sha(C.read(path)),preparations={'repair-bytes':inspection},inspection_files={'repair-bytes':C.ref(OUT,OUT/'repair-bytes-inspection.json')},interruption=interrupted,inspection_refusal=refused,retry_refusal=retry,transaction_boundary=boundary_result,commit_started=boundary_result['commit_started'],packages_committed=boundary_result['packages_committed'],recovery_admission=admission,normal_repair=repaired,restoration=restored,repair_success=restored['repair_success'],source_preserved=True,source_tree_sha256=source_sha,source_capabilities_sha256=caps_sha,security_capabilities='EXACT_SOURCE_MAP_PRESERVED',user_trust_protected_preserved=True,original_user_nodes=len(users),workspaces_disposed=False,workspaces_retained_for_outer_disposal=True,disposal='ORIGINAL_ORDERED_OUTER_OWNER_ONLY_AFTER_ALL_CONSUMER_ABSENCE',root_map_replay='RAW_COMPLETE_BEFORE_PARTIAL_AFTER_MAPS',copied_root_exports=dict(healthy=healthy_export,post_interruption=partial_export,restored=after_export,selected_payload=payload,lock_observer=C.ref(OUT,OUT/'lock-observer-derivation.json')),normal_queries=dict(healthy=query_before,restored=query_after))
        return validate(C,report)
    except BaseException as error:report.update(error_type=type(error).__name__,error=str(error)[:1024]);raise
    finally:C.save(OUT/'lifecycle.json',report)



def query_checks(C,calls,workspace,phase):
    """Normal installed Python/Apps loader and full pacman query, original runner."""
    C.need(phase in ('healthy','restored')and workspace==WORK/'main','fixed owned query scope')
    result={}
    for role,tail in (('loader',['/usr/bin/python3','-I','-B','/usr/bin/cachy-asahi-apps','--help']),('query',['/usr/bin/pacman','-Q'])):
        argv=['/usr/bin/chroot',str(workspace/'root'),*tail];n=len(calls.rows);C.need(n<64,'original command count')
        row,out,err,error=calls.api.run_command(argv,WORK,dict(C.ENV,HOME='/tmp',CACHY_ASAHI_APPS_TRANSACTION=os.environ['OWNER_TOKEN']),45,1024**2)
        calls.rows.append(row);C.save(OUT/'commands.json',calls.rows)
        (OUT/('command-%02d.stdout'%n)).write_bytes(out);(OUT/('command-%02d.stderr'%n)).write_bytes(err)
        C.need(error is None and row['group_absence_verified']is True and row['exit_code']==0 and out and not err,'normal installed loader/query must succeed and retire')
        result[role]=dict(argv_tail=tail,exit_code=row['exit_code'],stdout=X.pin(out),stderr=X.pin(err),group_absence_verified=row['group_absence_verified'])
    C.save(OUT/('normal-query-'+phase+'.json'),result)
    return result


def derive_recovery_interrupted(raw):
    """Whole held600s worker supervisor; two explicit reversible recovery seams."""
    before,parent=derive_interrupted(raw);derived=before
    seams=[("if pending.exists() and (workspace/'root/var/lib/pacman/db.lck').exists():","if export_boundary.ready(process,workspace):"),("env=dict(C.ENV,HOME='/tmp',CACHY_ASAHI_APPS_TRANSACTION=os.environ['OWNER_TOKEN'])","env=dict(C.ENV,HOME='/tmp',CACHY_ASAHI_APPS_TRANSACTION=os.environ['OWNER_TOKEN'],APPS16_INTERRUPTION_PROFILE_SHA256=export_boundary.profile_sha)")]
    for old,new in seams:
        X.need(derived.count(old)==1,'one exact recovery supervisor seam');derived=derived.replace(old,new,1)
    inverse=derived
    for old,new in reversed(seams):inverse=inverse.replace(new,old,1)
    X.need(inverse==before,'complete held interruption supervisor inverse')
    return derived,dict(schema_version=1,status='EXACT_SOURCE_OWNED_BOUNDARY_GATE_AND_PROFILE_FORWARDING',original_worker=parent,original_additive=X.pin(before.encode()),derived=X.pin(derived.encode()),seams=[dict(before=old,after=new)for old,new in seams],worker_seconds=600,reap_seconds=5,combined_output_bytes=1024**2,normal_backend_wrapper='ONLY_TRANSACTION_SCRIPT_ARGV_INDEX3_CHANGED')


def interrupted_recovery(C,H,calls,workspace,owner,normal_argv,payload,inspection):
    """No valid raw mutation boundary means no interruption/repair qualification."""
    import boundary
    normal=[*map(str,normal_argv),'--worker'];wrapped=list(map(str,normal_argv))
    X.need(wrapped[3]=='/source/'+X.LANE+'/transaction.py','one normal backend worker entry')
    wrapped[3]='/operation/boundary.py';X.need(boundary.unwrap_argv([*wrapped,'--worker'])==normal,'whole worker argv inverse')
    profile_sha=os.environ['APPS16_INTERRUPTION_PROFILE_SHA256'];X.verify(SOURCE,profile_sha)
    target='usr/share/doc/cachy-asahi-apps/README.md'
    X.need(target in payload and target in inspection['damage'],'fixed independently authenticated damaged target')
    context=dict(schema_version=1,operation_profile_sha256=profile_sha,ownership_sha256=owner,plan_sha256=inspection['plan_sha256'],normal_argv=normal,before_target=inspection['damage'][target])
    path=workspace/'apps-boundary-context.json'
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb')as stream:stream.write(X.encoded(context));stream.flush();os.fsync(stream.fileno())
    raw=C.read(SOURCE/X.LANE/'base_lifecycle.py',2*1024**2).decode();derived,ledger=derive_recovery_interrupted(raw)
    C.save(OUT/'worker-derivation.json',ledger);evidence=WorkerEvidence(workspace,owner,wrapped)
    last=dict(status='NOT_OBSERVED',commit_started='UNKNOWN',packages_committed='UNKNOWN')
    def ready(process,current):
        nonlocal last
        X.need(Path(current)==workspace,'one source-owned boundary workspace')
        output_bytes=sum((OUT/('interrupted-'+side)).stat().st_size for side in('stdout','stderr'))
        last=boundary.probe_boundary(workspace,evidence.value['identity'],normal_argv=normal,deadline=evidence.started+600,output_bytes=output_bytes)
        if last['ready']is True:X.need(sum((OUT/('interrupted-'+side)).stat().st_size for side in('stdout','stderr'))+last['observer_output_bytes']<=1024**2,'combined worker streams and boundary capture bound')
        return last['ready']is True
    waiter=types.SimpleNamespace(ready=ready,profile_sha=profile_sha)
    scope=dict(vars(H),export_evidence=evidence,export_boundary=waiter);exec(compile(derived,str(SOURCE/X.LANE/'base_lifecycle.py')+':recovery-boundary-supervisor','exec'),scope)
    try:
        result=scope['interrupted'](calls,workspace,owner,wrapped)
        worker_trace_check(evidence.value,partial=True)
        result['worker_trace']=dict(path='worker-trace.json',**X.pin(X.encoded(evidence.value)))
        result['worker_derivation']=C.ref(OUT,OUT/'worker-derivation.json')
        C.save(OUT/'interruption.json',result)
        return result,evidence,last
    finally:
        C.save(OUT/'worker-trace.json',evidence.value);C.save(OUT/'transaction-boundary.json',last)
        for name in('apps-boundary-context.json','apps-boundary-capture.json'):
            if (workspace/name).is_file():(OUT/name).write_bytes(C.read(workspace/name,1024**2))


def normal_admission(C,function,*args):
    """The held normal-call environment, scoped to this actor process only."""
    saved=dict(os.environ);clean=dict(C.ENV,HOME='/tmp',CACHY_ASAHI_APPS_TRANSACTION=saved['OWNER_TOKEN'])
    try:
        os.environ.clear();os.environ.update(clean)
        return function(*args)
    finally:os.environ.clear();os.environ.update(saved)


def fresh_inspection(C,row,plan_sha256,payload):
    """Whole held readonly result gate, allowing the boundary-healed target."""
    raw=C.read(C.HERE.parent/'apps-full574-repair-native/checks.py',2*1024**2).decode()
    node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='inspection')
    before=ast.get_source_segment(raw,node)+'\n'
    X.need(X.pin(before.encode())==dict(bytes=1723,sha256='dfbfe34edb551c6678c152e93bfb3e11e613fe25c69cf1cd0e050416225173b5'),'whole held readonly inspection predicate')
    old="set(row['damage'])=={'usr/share/doc/cachy-asahi-apps/README.md'}";new="set(row['damage'])<=selected"
    X.need(before.count(old)==1,'one exact fresh damage-set predicate');derived=before.replace(old,new,1)
    X.need(derived.replace(new,old,1)==before,'whole fresh predicate inverse')
    selected={n for n,r in payload.items()if r['type']=='file'}
    X.need(len(selected)==8 and type(row['damage'])is dict,'finite genuine selected ordinary fresh damage map')
    scope=dict(re=re,selected=selected);exec(compile(derived,'<source-owned-fresh-inspection-case>','exec'),scope)
    return scope['inspection'](C,row,plan_sha256)


def retained_worker(C,life,directory,files):
    """Complete source-owned worker/stream/observer closure, data only."""
    interrupted=life['interruption'];objects=[]
    for key,name in(('worker_trace','worker-trace.json'),('worker_derivation','worker-derivation.json')):
        ref=interrupted[key];X.need(ref['path']==name,'fixed raw worker evidence role')
        raw=C.read(directory/name,1024**2);X.need(X.pin(raw)=={k:ref[k]for k in('bytes','sha256')}==files['lifecycle-public/'+name],'raw worker reference/body/retention pin')
        objects.append(C.decode(raw))
    trace,ledger=objects;worker_trace_check(trace)
    X.need(trace['workspace']==interrupted['workspace']and trace['ownership_sha256']==interrupted['ownership_sha256']and trace['worker_seconds']<=interrupted['seconds']+.1,'exact original worker/interruption identity and clock')
    raw=C.read(C.HERE/'base_lifecycle.py',2*1024**2).decode();unused,expected=derive_recovery_interrupted(raw)
    X.need(ledger==expected,'complete six additive plus two recovery seams and whole supervisor inverse')
    lock=trace['locks']['before-stop'];old=interrupted['real_lock_observed']
    X.need(old==dict(device=lock['device'],inode=lock['inode'],mode=stat.S_IMODE(lock['mode']),bytes=lock['bytes']),'limited original lock joins full unchanged identity')
    X.need(set(interrupted['outputs'])=={'stdout','stderr'},'closed raw interrupted streams')
    total=0
    for side in('stdout','stderr'):
        name='interrupted-'+side;ref=interrupted['outputs'][side];raw=C.read(directory/name,1024**2)
        X.need(ref['path']==name and X.pin(raw)=={k:ref[k]for k in('bytes','sha256')}==files['lifecycle-public/'+name],'exact interrupted raw stream body/reference')
        total+=len(raw)
    boundary=life['transaction_boundary'];X.need(type(boundary['observer_output_bytes'])is int and 0<boundary['observer_output_bytes']<=1024**2 and total+boundary['observer_output_bytes']<=1024**2,'combined streams and cumulative boundary publications1MiB')
    capture=C.read(directory/'apps-boundary-capture.json',1024**2)
    X.need(X.pin(capture)==boundary['source_capture']==files['lifecycle-public/apps-boundary-capture.json']and capture==__import__('base64').b64decode(boundary['capture_raw_base64'],validate=True),'physical source-owned callback capture joins its full raw proof')
    ref=life['copied_root_exports']['lock_observer'];X.need(ref['path']=='lock-observer-derivation.json','fixed metadata-only lock observer ledger')
    raw=C.read(directory/ref['path'],1024**2);X.need(X.pin(raw)=={k:ref[k]for k in('bytes','sha256')}==files['lifecycle-public/'+ref['path']],'whole raw lock observer ledger joins')
    expected=dict(schema_version=1,status='WHOLE_ORIGINAL_OBSERVER_CODE_PRIVATE_ZERO_LOCK_HASH_DEPENDENCY',bindings=['observe._file_hash','_measure.roots','measure._measure'],all_original_function_code_objects_held=True,all_other_descriptor_hashes='ORIGINAL_UNCHANGED',lock_content='NOT_READ_OR_MUTATED',lock=lock,lock_descriptor_visits=1,derived_hash='SHA256_EMPTY_FROM_STABLE_ZERO_BYTE_STAT')
    X.need(C.decode(raw)==expected,'exact zero-lock observer source derivation')
    return trace

def main():
    X.need(os.environ.get('CACHY_APPS574_OPERATION')==X.OPERATION,'explicit companion operation only')
    X.verify(SOURCE,os.environ.get('APPS16_INTERRUPTION_PROFILE_SHA256'))
    sys.path.insert(0,str(SOURCE/X.LANE));import contract as C
    C.need(os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64'and Path('/.dockerenv').is_file()and os.environ.get('CACHY_APPS574_LIFECYCLE')=='1'and os.environ.get('CACHY_APPS574_REPAIR_CASE')=='repair-bytes'and {p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'original owned native offline actor gate')
    C.source(SOURCE);C.need(Path('/seed').is_mount()and WORK.is_mount(),'original separate readonly seed/work mounts')
    C.need(C.VERSIONS[X.APPS]==X.VERSION,'actual Apps16 operation')
    os.chown(WORK,0,0);WORK.chmod(0o700)
    R=C.load('operation_original_repair',SOURCE/X.LANE/'lifecycle.py');R.C=C;R.H.C=C
    T=C.load('operation_original_transaction',SOURCE/X.LANE/'transaction.py');adapter=C.adapter(SOURCE)
    os.environ.update(C.ENV,CACHY_ASAHI_APPS_TRANSACTION=os.environ['OWNER_TOKEN'])
    try:execute(C,R,T,adapter,R.H.Calls())
    finally:
        for path in OUT.iterdir():
            if path.is_file()and not path.is_symlink():os.chown(path,int(os.environ['OUTPUT_UID']),int(os.environ['OUTPUT_GID']))

if __name__=='__main__':main()
