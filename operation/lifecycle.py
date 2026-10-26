# SPDX-License-Identifier: MIT
"""Actual Apps16 reinstall interruption; private copy retained for original outer scrub."""
import os,re,sys
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common as X
SOURCE=Path('/source');WORK=Path('/work');OUT=Path('/out');INPUTS=Path('/inputs')


def protected(nodes,payload,version):
    # Only selected ordinary payload bytes and its exact ALPM record can be
    # uncertain. Shared directories and all user/config/trust/base nodes stay exact.
    selected={n for n,v in payload.items()if v['type']=='file'}
    package='var/lib/pacman/local/'+X.APPS+'-'+version
    return {n:v for n,v in nodes.items()if n not in selected and n!='var/lib/pacman/db.lck'
            and n!=package and not n.startswith(package+'/')}


def validate(C,value):
    C.need(value['status']==X.LIFECYCLE and value['operation']==X.OPERATION and value['case']=='repair-bytes','separate operation, no normal repair acceptance')
    C.need(value['hardware']=='NOT_RUN'and value['release']=='NOT_ADMITTED'and value['repair_success']is False and value['commit_started']==value['packages_committed']=='UNKNOWN'and value['rollback']=='NOT_CLAIMED','unknown selected reinstall outcome, never rollback')
    C.need(value['base_count']==574 and value['installed_count']==578 and value['workspaces_disposed']is False and value['workspaces_retained_for_outer_disposal']is True,'real578 installed copy retained until actor retirement')
    C.need(value['source_preserved']is True and value['user_trust_protected_preserved']is True and value['original_user_nodes']>0 and re.fullmatch('[0-9a-f]{64}',value['source_capabilities_sha256']),'complete original source/config/capability preservation')
    checks=C.load('operation_original_checks',C.HERE/'checks.py')
    checks.preserved(C,value['install'],value['source_capabilities_sha256'])
    C.need(value['install']['prepared_add']==C.VERSIONS and not value['install']['prepared_remove'],'actual signed four-candidate install578 required')
    X.selected_plan(value['plan'])
    inspection=value['preparations']['repair-bytes'];checks.inspection(C,inspection,value['plan_sha256'])
    C.need(inspection['archives']=={X.APPS:X.ARCHIVE}and inspection['source_tree_sha256']==value['source_tree_sha256']and inspection['capabilities_sha256']==value['source_capabilities_sha256'],'exact signed archive and original inspected source')
    X.interruption(value['interruption'],value['plan_sha256'],inspection['before'])
    C.need(value['inspection_refusal']['status']=='FAIL'and 'before'not in value['inspection_refusal']and value['inspection_refusal']['transaction']=='NOT_RUN','no usable before pins after uncertain attempt')
    retry=value['retry_refusal'];C.need(retry['status']=='FAIL'and retry['commit_started']is False and retry['packages_committed']is False,'explicit negative retry must not start a new commit')
    C.need(value['pending_unchanged']is True and value['original_lock_metadata_unchanged']is True,'no pending waiver or raw lock deletion')
    return value


def retained(C,value,directory,files):
    validate(C,value)
    for field,name in(('plan','repair-bytes-plan.json'),('interruption','interruption.json'),('inspection_refusal','post-interruption-inspection.json'),('retry_refusal','post-interruption-retry.json')):
        raw=C.read(directory/name,4*1024**2);C.need(C.decode(raw)==value[field]and files['lifecycle-public/'+name]==X.pin(raw),'exact original operation receipt/export join: '+name)
    plan=C.read(directory/'repair-bytes-plan.json',16*1024**2);C.need(C.sha(plan)==value['plan_sha256'],'raw original plan hash')
    raw=C.read(directory/'interrupted-pending.json',65536);C.need(C.decode(raw)==value['interruption']['pending']and files['lifecycle-public/interrupted-pending.json']==X.pin(raw),'raw durable intent retained exactly')
    for side,pin in value['interruption']['outputs'].items():
        C.need(pin['path']=='interrupted-'+side and files['lifecycle-public/'+pin['path']]=={k:pin[k]for k in('bytes','sha256')},'original interrupted stdout/stderr physical joins')
    rows=C.decode(C.read(directory/'commands.json',4*1024**2));C.need(len(rows)<=64,'original command count')
    for i,row in enumerate(rows):
        C.need(row['group_absence_verified']is True and type(row['time_limit'])in(int,float)and 0<row['time_limit']<=610 and row['seconds']<=row['time_limit']+6,'original command retirement and caller bounds')
        for side in('stdout','stderr'):
            name='command-%02d.%s'%(i,side);pin=files['lifecycle-public/'+name]
            C.need(pin==dict(bytes=row[side+'_bytes'],sha256=row[side+'_sha256']),'all actual caller raw output joins')
    # The retry/inspection must be the actual original command returns, not new summaries.
    for field in('install','inspection_refusal','retry_refusal'):
        matches=[i for i,row in enumerate(rows)if C.decode(C.read(directory/('command-%02d.stdout'%i),1024**2))==value[field]]
        C.need(len(matches)==1,'one original command stdout for '+field)


def execute(C,R,T,adapter,calls):
    H=R.H;seed=Path('/seed');workspace=WORK/'main'
    baseline=adapter.measure(seed,T.limits());source_sha=adapter.digest(baseline['nodes'])
    caps=adapter.capability_map(seed,baseline,T.limits());caps_sha=adapter.digest(caps)
    users={n:v for n,v in baseline['nodes'].items()if n.startswith('home/')and v['type']in('file','symlink')};C.need(users,'original user configuration required')
    prepared=calls.call([*H.backend('prepare-copy',workspace),'--source',str(seed)])
    C.need(prepared['status']=='OWNED_COPY_PREPARED'and prepared['source_preserved']is True,'original owned full574 copy')
    owner=prepared['ownership_sha256'];H.retain_copy(workspace,owner)
    path,plan=R.planned(calls,workspace,'install','install',['apps','cache','orphans'])
    installed=calls.call(H.apply_args(calls,workspace,owner,path,plan))
    C.need(installed['prepared_add']==C.VERSIONS and not installed['prepared_remove']and len(H.count(workspace))==578,'actual signed Apps16/Runtime/Cache/Orphans install578')
    C.load('operation_install_checks',C.HERE/'checks.py').preserved(C,installed,caps_sha)
    healthy=adapter.measure(workspace/'root',T.limits());payload=adapter.current_payloads()[X.APPS]
    path,plan=R.planned(calls,workspace,'repair-bytes','reinstall',['apps']);X.selected_plan(plan)
    R.damage(workspace,R.TARGET,False)
    inspection=R.inspected(T,calls,workspace,owner,path,plan,'repair-bytes')
    C.need(inspection['archives']=={X.APPS:X.ARCHIVE},'original signed Apps16 archive required')
    attempts=R.argv(calls,workspace,owner,path,plan,inspection['before'])
    report=dict(status='FAIL',operation=X.OPERATION,case='repair-bytes',hardware='NOT_RUN',release='NOT_ADMITTED',repair_success=False,commit_started='UNKNOWN',packages_committed='UNKNOWN',rollback='NOT_CLAIMED')
    try:
        # Execute the original directly supervised --worker, including all original
        # authentication, full574 policy/lease, archive and real ALPM lock gates.
        interrupted=H.interrupted(calls,workspace,owner,attempts)
        X.interruption(interrupted,C.sha(C.read(path)),inspection['before'])
        raw=C.read(workspace/'apps-pending.json',65536);C.need(C.decode(raw)==interrupted['pending'],'physical durable pending marker')
        (OUT/'interrupted-pending.json').write_bytes(raw)
        lock=workspace/'root/var/lib/pacman/db.lck';key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        lock_identity=key(lock.lstat())
        argv=['/usr/bin/python3','-I','-B',str(SOURCE/X.LANE/'inspection.py'),'inspect-reinstall',*H.common(workspace,owner),*H.credentials(),'--applications',*plan['plan']['requested_applications'],'--plan',str(path),'--plan-sha256',C.sha(C.read(path))]
        refused=calls.call(argv,expected=1);C.need(refused['status']=='FAIL'and 'before'not in refused,'uncertain state cannot authorize readonly before-pins')
        retry=calls.call(attempts,expected=1);C.need(retry['status']=='FAIL'and retry['commit_started']is False and retry['packages_committed']is False,'negative retry cannot commit')
        C.need(C.read(workspace/'apps-pending.json',65536)==raw and key(lock.lstat())==lock_identity,'pending and original lock remain untouched')
        after=adapter.measure(workspace/'root',T.limits());C.need(protected(healthy['nodes'],payload,X.VERSION)==protected(after['nodes'],payload,X.VERSION),'user/config/trust/base/unselected state changed')
        adapter.capability_map(workspace/'root',after,T.limits(),caps)
        original=adapter.measure(seed,T.limits());adapter.capability_map(seed,original,T.limits(),caps);C.need(adapter.digest(original['nodes'])==source_sha,'complete original readonly source preserved')
        C.save(OUT/'post-interruption-inspection.json',refused);C.save(OUT/'post-interruption-retry.json',retry)
        report.update(status=X.LIFECYCLE,base_count=574,installed_count=578,install=installed,plan=plan,plan_sha256=C.sha(C.read(path)),preparations={'repair-bytes':inspection},inspection_files={'repair-bytes':C.ref(OUT,OUT/'repair-bytes-inspection.json')},interruption=interrupted,inspection_refusal=refused,retry_refusal=retry,pending_unchanged=True,original_lock_metadata_unchanged=True,source_preserved=True,source_tree_sha256=source_sha,source_capabilities_sha256=caps_sha,security_capabilities='EXACT_SOURCE_MAP_PRESERVED',user_trust_protected_preserved=True,original_user_nodes=len(users),workspaces_disposed=False,workspaces_retained_for_outer_disposal=True,disposal='ORIGINAL_ORDERED_OUTER_OWNER_ONLY_AFTER_ALL_CONSUMER_ABSENCE',root_map_replay='SOURCE_ENFORCED_NOT_EXPORTED')
        return validate(C,report)
    except BaseException as error:report.update(error_type=type(error).__name__,error=str(error)[:1024]);raise
    finally:C.save(OUT/'lifecycle.json',report)


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
    try:execute(C,R,T,adapter,R.H.Calls())
    finally:
        for path in OUT.iterdir():
            if path.is_file()and not path.is_symlink():os.chown(path,int(os.environ['OUTPUT_UID']),int(os.environ['OUTPUT_GID']))

if __name__=='__main__':main()
