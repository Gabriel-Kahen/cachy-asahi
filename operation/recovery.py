# SPDX-License-Identifier: MIT
"""Normal-backend admission of one proved retired writer; no package/DB writes."""
import hashlib,json,os,stat,tempfile
from pathlib import Path

APPS='cachy-asahi-apps'
VERSION='0.1.0-16'
LOCK='var/lib/pacman/db.lck'
PENDING='apps-pending.json'
EVIDENCE_FIELDS={'trace','interruption','healthy','partial','inspection','boundary','inventory_raw'}
MAX_DB_NODES=8192
MAX_DB_BYTES=64*1024**2

def need(ok,why):
    if not ok:raise ValueError(why)
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def identity(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def same_observation(a,b):
    # statvfs free space describes the filesystem, including our authentication
    # temporary files outside root. It is not part of copied-root state.
    logical=lambda x:{k:v for k,v in x['footprint'].items()if not k.startswith('filesystem_')}
    return all(a.get(k)==b.get(k)for k in('nodes','hardlink_groups','complete','unsupported_counts'))and logical(a)==logical(b)

def retired(L,trace):
    """Original kernel-stop/reap evidence and fresh conservative PID/group absence."""
    L.worker_trace_check(trace)
    need(not os.path.lexists('/proc/'+str(trace['identity']['pid'])),'original writer PID exists or was reused')
    try:os.killpg(trace['identity']['pgid'],0)
    except ProcessLookupError:pass
    else:raise ValueError('original writer process group still exists')
    return dict(identity=trace['identity'],direct_reaped=True,group_absent=True)

def partial_check(T,L,healthy,partial,payload,inventory,inspection,pending,plan_sha):
    """Selected ordinary leaf bytes only; all raw DB/config bytes must be healthy."""
    L.compare_copied_maps(healthy,partial,payload,VERSION)
    before=healthy['observation']['nodes'];after=partial['observation']['nodes']
    selected={n for n,r in payload.items()if r['type']=='file'}
    need(len(selected)==8 and all(before.get(n)==r for n,r in payload.items()),'healthy exact signed Apps16 payload')
    keep=lambda nodes:{n:r for n,r in nodes.items()if n not in selected and n!=LOCK}
    need(keep(before)==keep(after),'recovery refuses changed database/config/unselected nodes')
    for n in selected:
        row=after.get(n);want=payload[n]
        if row is not None:need(set(row)=={'type','mode','uid','gid','bytes','sha256'}and row['type']=='file'and all(row[k]==want[k]for k in('mode','uid','gid')),'only selected ordinary leaf bytes or absence may differ')
    need(LOCK not in before and after.get(LOCK,{}).get('type')=='file'and after[LOCK]['bytes']==0,'exact additional zero-byte ALPM lock')
    need(set(pending)=={'status','plan_sha256','before'}and pending['status']=='ATTEMPT_STARTED_COMMIT_OUTCOME_NOT_RECORDED'and pending['plan_sha256']==plan_sha,'original durable pending/plan join')
    need(inspection['status']=='INSPECTED_AUTHENTICATED_OWNED_FULL574_REINSTALL'and inspection['operation']=='reinstall'and inspection['selected']==[APPS]and inspection['plan_sha256']==plan_sha,'normal original selected reinstall preparation')
    damaged=dict(before)
    for n,row in inspection['damage'].items():
        need(n in selected,'preparation damage outside selected ordinary leaves')
        if row is None:damaged.pop(n,None)
        else:damaged[n]=row
    need(T.pins(dict(nodes=damaged),inventory)==pending['before']==inspection['before'],'pending before pins reconstructed from healthy DB and inspected damage')
    need(healthy['capabilities']==partial['capabilities']and healthy['observation'].get('hardlink_groups',{})==partial['observation'].get('hardlink_groups',{}),'all capabilities and hardlink topology held')
    return dict(selected_leaves=sorted(selected),database='ALL_RAW_BYTES_EQUAL_HEALTHY',protected='ALL_OTHER_NODES_EQUAL_HEALTHY',commit_outcome='UNKNOWN')

def _database_stable(c,db,states,budget):
    """Recheck the complete descriptor/path namespace, including the retained lock."""
    children={n:set()for n,s in states.items()if stat.S_ISDIR(s[2])}
    for n in states:
        if n:children[n.rpartition('/')[0]].add(n.rpartition('/')[2])
    for n,want in states.items():
        budget.tick();path=db/n if n else db
        need(identity(path.lstat())==want,'projected source DB identity drift')
        if stat.S_ISDIR(want[2]):
            fd=c.directory(path)
            try:need(identity(os.fstat(fd))==want and set(os.listdir(fd))==children[n],'projected source DB namespace drift')
            finally:os.close(fd)

def locked_inventory(T,L,app,c,r,root,healthy,partial,raw,want_sha,expected_lock,projection,budget):
    """Parse metadata DATA copied from the proved DB; never waive its live lock.

    The ordinary collector runs on a private bounded DATA projection. Retained
    live-root inventory stays byte-identical and must be recollected normally
    only after admission releases the exact owned markers.
    """
    reader=app.inventory_reader();normalize=lambda row:app.package(row,r)
    need(type(raw)is bytes and 0<len(raw)<=reader.MAX_INSTALLED_JSON and pin(raw)['sha256']==want_sha,'exact retained inventory raw SHA256')
    inventory=T.I.decode(raw);need(T.encoded(inventory)==raw,'canonical retained inventory bytes')
    need(set(inventory)=={'schema_version','kind','target_arch','snapshot_id','packages','observation'}and type(inventory['schema_version'])is int and inventory['schema_version']==1 and inventory['kind']=='complete-installed-inventory'and inventory['target_arch']=='aarch64','complete retained inventory schema')
    reader.validate(inventory,normalize);db=Path(root)/T.DB
    need(inventory['observation']['dbpath']==str(db),'retained inventory actual owned DB path')
    need(len(inventory['packages'])<=budget.max_packages,'original package budget')
    L.root_map_check(healthy,'healthy');L.root_map_check(partial,'post-interruption')
    prefix=T.DB+'/';select=lambda v:{(''if n==T.DB else n[len(prefix):]):row for n,row in v['observation']['nodes'].items()if(n==T.DB or n.startswith(prefix))and n!=LOCK}
    wanted=select(healthy);need(wanted==select(partial)and wanted.get('',{}).get('type')=='directory','entire healthy/partial DB metadata map equality')
    need(0<len(wanted)+1<=MAX_DB_NODES and sum(v.get('bytes',0)for v in wanted.values())<=MAX_DB_BYTES,'bounded complete DB DATA projection')
    need(all(row['type']in('file','directory')and len(Path(n).parts)<=budget.max_depth for n,row in wanted.items()),'ordinary bounded ALPM metadata DATA')
    inputs={n:dict(bytes=row['bytes'],sha256=row['sha256'])for n,row in wanted.items()if n.startswith('local/')and row['type']=='file'}
    need(inputs==inventory['observation']['inputs'],'retained inventory inputs equal complete healthy/current local DB files')
    projection=Path(projection);need(projection==projection.resolve()and not os.path.lexists(projection)and projection.parent.is_dir()and projection.parent.stat().st_uid==os.geteuid()and stat.S_IMODE(projection.parent.stat().st_mode)==0o700,'fresh private canonical metadata DATA projection')
    need(not projection.is_relative_to(db)and not db.is_relative_to(projection),'metadata DATA projection disjoint from live DB')
    projection.mkdir(mode=0o700);states={};spent=0;children={n:[]for n,row in wanted.items()if row['type']=='directory'}
    for n in wanted:
        if n:children[n.rpartition('/')[0]].append(n.rpartition('/')[2])
    fd=c.directory(db);lock_fd=None
    try:
        lock_fd,ls,_=_open_bound(fd,'db.lck',cap=0,read_bytes=False);need(L.lock_metadata(ls)==expected_lock,'exact retired writer lock throughout metadata projection');states['db.lck']=identity(ls)
        def walk(parent,name):
            nonlocal spent
            budget.tick();s=os.fstat(parent);row=dict(type='directory',mode=stat.S_IMODE(s.st_mode),uid=s.st_uid,gid=s.st_gid)
            need(row==wanted[name],'current DB directory differs from healthy map');states[name]=identity(s)
            expected=set(children[name])|({'db.lck'}if not name else set());need(set(os.listdir(parent))==expected,'complete current DB DATA namespace differs')
            for leaf in sorted(children[name]):
                budget.tick();n=leaf if not name else name+'/'+leaf;want=wanted[n];target=projection/n
                if want['type']=='directory':
                    child=os.open(leaf,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
                    try:target.mkdir(mode=0o700);walk(child,n);need(identity(os.fstat(child))==identity(os.stat(leaf,dir_fd=parent,follow_symlinks=False))==states[n],'DB directory FD/path drift')
                    finally:os.close(child)
                else:
                    source=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
                    try:
                        info=os.fstat(source);need(stat.S_ISREG(info.st_mode)and info.st_nlink==1 and 0<=info.st_size<=MAX_DB_BYTES,'bounded ordinary singlelink DB DATA file')
                        before=identity(info);h=hashlib.sha256();size=0;out=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
                        with os.fdopen(out,'wb')as stream:
                            while block:=os.read(source,65536):
                                budget.tick();size+=len(block);spent+=len(block);need(size<=info.st_size and spent<=MAX_DB_BYTES,'bounded complete DB DATA bytes');h.update(block);stream.write(block)
                        actual=dict(type='file',mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid,bytes=size,sha256=h.hexdigest())
                        need(actual==want and size==info.st_size and before==identity(os.fstat(source))==identity(os.stat(leaf,dir_fd=parent,follow_symlinks=False)),'DB DATA bytes or FD/path metadata differ from healthy map');states[n]=before
                    finally:os.close(source)
            need(identity(os.fstat(parent))==states[name]and set(os.listdir(parent))==expected,'complete DB DATA directory drift')
        walk(fd,'');need(identity(os.fstat(fd))==identity(db.lstat())==states[''],'complete DB root FD/path drift')
        _database_stable(c,db,states,budget)
        # Unchanged normal reader: it still refuses an actual db.lck. This copy
        # contains DATA only, with no lock or authority to mutate the live root.
        projected=reader.collect(projection,c,normalize);reader.validate(projected,normalize);budget.tick()
        need(projected['observation']['dbpath']==str(projection),'normal metadata projection reader path')
        comparison=dict(projected,observation=dict(projected['observation'],dbpath=str(db)))
        need(T.encoded(comparison)==raw,'normal projection rows/inputs/format differ from retained inventory')
        _database_stable(c,db,states,budget)
        need(identity(os.fstat(lock_fd))==identity(os.stat('db.lck',dir_fd=fd,follow_symlinks=False))==states['db.lck'],'original ALPM lock held throughout DATA parsing')
    finally:
        if lock_fd is not None:os.close(lock_fd)
        os.close(fd)
    receipt=dict(status='PARSED_PRIVATE_DB_DATA_PROJECTION_NOT_UNLOCKED_LIVE_OBSERVATION',retained_inventory=pin(raw),projection_inventory=pin(T.encoded(projected)),source_db=str(db),projection_db=str(projection),nodes=len(states),bytes=spent,source_physical_sha256=pin(T.encoded(states))['sha256'],live_collector_before_release='NOT_CALLED_OR_WAIVED',normal_collector_code='UNCHANGED',lock=expected_lock)
    return inventory,receipt,states

def _open_bound(parent,name,cap=65536,read_bytes=True):
    fd=os.open(name,(os.O_RDONLY if read_bytes else os.O_PATH)|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=parent)
    try:
        s=os.fstat(fd)
        need(stat.S_ISREG(s.st_mode)and s.st_uid==os.geteuid()and s.st_nlink==1 and 0<=s.st_size<=cap,'owned bounded singlelink recovery marker')
        need(identity(s)==identity(os.stat(name,dir_fd=parent,follow_symlinks=False)),'recovery marker FD/path mismatch')
        raw=bytearray()
        if read_bytes:
            while b:=os.read(fd,65536):raw.extend(b);need(len(raw)<=s.st_size,'recovery marker grew')
            need(len(raw)==s.st_size,'recovery marker truncated')
        need(identity(s)==identity(os.fstat(fd))==identity(os.stat(name,dir_fd=parent,follow_symlinks=False)),'stable complete recovery marker identity')
        return fd,s,bytes(raw)
    except BaseException:os.close(fd);raise

def _release_owned_markers(workspace,root,L,expected_lock,pending_raw,before_unlink):
    """Internal backend primitive, only under normal flock after every admission gate.

    Failed second unlink/fsync remains explicit uncertainty, never rollback.
    """
    workspace=Path(workspace);root=Path(root)
    need(workspace==workspace.resolve()and root==workspace/'root'and root==root.resolve(),'canonical fixed owned recovery roots')
    parents=[workspace,root,root/'var',root/'var/lib',root/'var/lib/pacman']
    need(all(not p.is_symlink()and p.is_dir()for p in parents),'ordinary recovery parent chain')
    held={p:identity(p.lstat())for p in parents}
    wfd=os.open(workspace,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);dfd=lfd=pfd=None
    try:
        dfd=os.open(root/'var/lib/pacman',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        lfd,ls,_=_open_bound(dfd,'db.lck',cap=0,read_bytes=False)
        need(L.lock_metadata(ls)==expected_lock,'exact original retired-writer lock identity')
        pfd,ps,raw=_open_bound(wfd,PENDING)
        need(stat.S_IMODE(ps.st_mode)==0o600 and raw==pending_raw,'exact private retained durable pending bytes')
        before_unlink()
        need(all(identity(p.lstat())==s for p,s in held.items()),'recovery parent identity drift')
        need(identity(ls)==identity(os.fstat(lfd))==identity(os.stat('db.lck',dir_fd=dfd,follow_symlinks=False))and identity(ps)==identity(os.fstat(pfd))==identity(os.stat(PENDING,dir_fd=wfd,follow_symlinks=False)),'late recovery marker substitution')
        os.unlink('db.lck',dir_fd=dfd);os.fsync(dfd)
        need(identity(ps)==identity(os.fstat(pfd))==identity(os.stat(PENDING,dir_fd=wfd,follow_symlinks=False)),'pending replaced after exact lock release')
        os.unlink(PENDING,dir_fd=wfd);os.fsync(wfd)
        need(not os.path.lexists(root/LOCK)and not os.path.lexists(workspace/PENDING),'marker release incomplete')
        return dict(status='EXACT_OWNED_RETIRED_WRITER_MARKERS_RELEASED',lock=expected_lock,pending=pin(pending_raw),pending_identity=list(identity(ps)),workspace_identity=list(held[workspace]),root_identity=list(held[root]),mutation=['exact-owned-db.lck','exact-owned-apps-pending.json'],commit_started='UNKNOWN',packages_committed='UNKNOWN',rollback='NOT_CLAIMED',repair_success=False)
    finally:
        for fd in(pfd,lfd,dfd,wfd):
            if fd is not None:os.close(fd)

def admit(args,T,P,L,R,adapter,evidence,boundary):
    """Admit only this retired writer; fresh normal inspect/apply remains mandatory.

    P is the held normal inspection module. boundary is the independently bound
    source-owned ALPM callback module, never a caller boolean or sidecar success.
    """
    need(type(evidence)is dict and set(evidence)==EVIDENCE_FIELDS,'closed source-owned recovery evidence roles')
    need(args.operation=='reinstall'and args.applications==['apps'],'one explicit Apps same-version recovery')
    workspace,root,owner=T.root_guard(args);budget=T.limits(args)
    with T.locked(workspace):
        need(T.root_guard(args)==(workspace,root,owner),'copy ownership drift before recovery')
        closure=T.closure_for(args,budget);need(closure is not None,'normal explicit full574 policy/lease required');closure.owner(owner);closure.source_check()
        trace=evidence['trace'];retired(L,trace)
        need(trace['workspace']==str(workspace)and trace['ownership_sha256']==args.ownership_sha256,'writer belongs to this exact owned copy')
        original=evidence['interruption'];pending=original['pending'];pending_raw=T.encoded(pending)
        need(original['status']=='FAIL_INTERRUPTED_OWNED_COPY_RETAINED'and original['commit_started']==original['packages_committed']=='UNKNOWN'and original['rollback']=='NOT_CLAIMED','prior commit outcome remains unknown')
        need(original['direct_child_reaped']is True and original['worker_group_absent']is True,'original direct reap and group absence')
        plan_raw=T.B.client.read_path(Path(args.plan).absolute(),T.MAX_PLAN);need(pin(plan_raw)['sha256']==args.plan_sha256,'retained original caller plan pin')
        plan=T.I.decode(plan_raw);L.X.selected_plan(plan)
        expected=[*R.argv(None,workspace,args.ownership_sha256,Path(args.plan),plan,pending['before']),'--worker']
        boundary_receipt=boundary.validate(evidence['boundary'],trace,plan,evidence['inspection'])
        need(boundary_receipt['normal_argv']==expected and boundary_receipt['derived_argv']==trace['argv'],'exact source-bound worker-wrapper inverse to normal backend argv')
        app,c,r=T.app_source(args)
        with tempfile.TemporaryDirectory(prefix='apps-recovery-auth-',dir=workspace)as temporary:
            work=Path(temporary)
            inventory,projection,custody=locked_inventory(T,L,app,c,r,root,evidence['healthy'],evidence['partial'],evidence['inventory_raw'],evidence['inspection']['before']['inventory_sha256'],trace['locks']['before-stop'],work/'metadata-data',budget)
            need(len(inventory['packages'])==578,'exact retained component578 inventory')
            copied,fresh,raw=P.authenticated_plan(T,args,app,c,r,inventory,work)
            need(raw==plan_raw and fresh==plan,'fresh normal authenticated unchanged same-version plan')
            with app.authenticated(copied,c,r)as context:
                closure.authorize_reinstall(fresh['plan'],inventory,context,args.plan_sha256)
                payload=adapter.current_payloads()[APPS]
                observed,observer=L.metadata_lock_measure(adapter,root,budget,trace['locks']['before-stop'])
                caps=adapter.capability_map(root,observed,budget,closure.policy['source_capabilities'])
                closure.selection({APPS:VERSION},{},inventory,observed['nodes']);closure.capture(root,observed)
                partial=evidence['partial'];need(same_observation(observed,partial['observation'])and caps==partial['capabilities'],'current complete partial map/capabilities equal captured retired state')
                comparison=partial_check(T,L,evidence['healthy'],partial,payload,inventory,evidence['inspection'],pending,args.plan_sha256)
                need(evidence['inspection']['full574_binding']==closure.binding,'preparation current source policy/lease join')
                budget.tick();closure.source_check()
                def final():
                    budget.tick();retired(L,trace);need(T.root_guard(args)==(workspace,root,owner),'late recovery ownership drift')
                    now,unused=L.metadata_lock_measure(adapter,root,budget,trace['locks']['before-stop']);need(same_observation(now,observed),'late full partial-root drift')
                    need(adapter.capability_map(root,now,budget,closure.policy['source_capabilities'])==caps,'late capability drift')
                    _database_stable(c,root/T.DB,custody,budget)
                    need(T.B.client.read_path(Path(args.plan).absolute(),T.MAX_PLAN)==plan_raw,'late caller plan drift');closure.source_check()
                released=_release_owned_markers(workspace,root,L,trace['locks']['before-stop'],pending_raw,final)
            # The actual held collector now observes the actual unlocked DB.
            # A projection is never reported as this live observation.
            reader=app.inventory_reader();live=reader.collect(root/T.DB,c,lambda row:app.package(row,r));reader.validate(live,lambda row:app.package(row,r));budget.tick()
            need(T.encoded(live)==evidence['inventory_raw'],'normal live inventory after release differs from retained inventory')
            live_check=dict(status='NORMAL_LIVE_DB_COLLECTED_AFTER_EXACT_MARKER_RELEASE',inventory=pin(T.encoded(live)),dbpath=str(root/T.DB),normal_collector_code='UNCHANGED')
        need(T.root_guard(args)==(workspace,root,owner),'recovery ownership changed')
        P.no_pending(T,workspace,root)
    return dict(status='ADMITTED_EXACT_RETIRED_APPS16_REINSTALL_FOR_FRESH_NORMAL_INSPECTION',markers=released,comparison=comparison,observer=observer,boundary=boundary_receipt,inventory_projection=projection,live_inventory_after_release=live_check,prior_commit_started='UNKNOWN',prior_packages_committed='UNKNOWN',normal_reinspection='REQUIRED',normal_reauthentication='REQUIRED',normal_apply='NOT_RUN',repair_success=False,rollback='NOT_CLAIMED',hardware='NOT_RUN',release='NOT_ADMITTED')

def restored(T,L,healthy,after,payload,query_before,query_after):
    """No normalization of raw database bytes, including ALPM INSTALLDATE."""
    L.root_map_check(healthy,'healthy');L.root_map_check(after,'restored')
    need(healthy['observation']['nodes']==after['observation']['nodes'],'restoration full healthy payload/DB/config/user bytes differ')
    need(healthy['capabilities']==after['capabilities']and healthy['observation'].get('hardlink_groups',{})==after['observation'].get('hardlink_groups',{}),'restoration capability/hardlink maps differ')
    need(all(after['observation']['nodes'].get(n)==r for n,r in payload.items()),'actual signed selected payload not restored')
    need(type(query_before)is type(query_after)is dict and set(query_after)=={'loader','query'}and query_before==query_after,'normal loader/query raw return maps differ')
    tails={'loader':['/usr/bin/python3','-I','-B','/usr/bin/cachy-asahi-apps','--help'],'query':['/usr/bin/pacman','-Q']}
    for name,row in query_after.items():
        need(set(row)=={'argv_tail','exit_code','stdout','stderr','group_absence_verified'}and row['argv_tail']==tails[name]and type(row['exit_code'])is int and row['exit_code']==0 and row['group_absence_verified']is True,'original normal loader/query command success and group retirement')
        for side in('stdout','stderr'):
            p=row[side];need(type(p)is dict and set(p)=={'bytes','sha256'}and type(p['bytes'])is int and 0<=p['bytes']<=1024**2 and type(p['sha256'])is str and len(p['sha256'])==64 and all(c in'0123456789abcdef'for c in p['sha256']),'complete bounded raw normal query output pins')
        need(row['stdout']['bytes']+row['stderr']['bytes']<=1024**2,'combined normal query output bound')
        need(row['stdout']['bytes']>0,'normal loader/query must return substantive raw output')
    return dict(status='RESTORED_COMPLETE_HEALTHY_MAPS_AND_NORMAL_QUERIES',repair_success=True,database='EXACT_RAW_HEALTHY_BYTES',payload='EXACT_SIGNED_BYTES',configuration='ALL_HEALTHY_NODES_EQUAL',prior_commit_started='UNKNOWN',prior_packages_committed='UNKNOWN',rollback='NOT_CLAIMED',hardware='NOT_RUN',release='NOT_ADMITTED')
