# SPDX-License-Identifier: MIT
"""Installed CLI against real575 and physically separate, readonly ALPM9 metadata."""
import ctypes
import json
import os
from pathlib import Path
import runpy
import stat

CLI='/usr/bin/cachy-asahi-orphans'


def module():
    from types import SimpleNamespace
    return SimpleNamespace(**runpy.run_path(CLI,run_name='installed_orphan_fixture'))


def package(db,name,reason=1,version='1-1',depends=(),optional=(),provides=()):
    path=db/'local'/(name+'-'+version);path.mkdir()
    fields={'NAME':[name],'VERSION':[version],'REASON':[str(reason)],'DEPENDS':list(depends),'OPTDEPENDS':list(optional),'PROVIDES':list(provides)}
    (path/'desc').write_text(''.join('%'+k+'%\n'+'\n'.join(v)+'\n\n' for k,v in fields.items() if v));(path/'files').write_bytes(b'')


def populate(db):
    package(db,'fixture-leaf');package(db,'fixture-manual',0)
    package(db,'fixture-provider',version='3-1',provides=['fixture-virtual=2'])
    package(db,'fixture-oldprovider',provides=['fixture-virtual=1'])
    package(db,'fixture-consumer',0,depends=['fixture-virtual>=2'])
    package(db,'fixture-optional',version='2-1');package(db,'fixture-app',0,optional=['fixture-optional>=2: retained feature','fixture-absent: absent is allowed'])
    package(db,'fixture-cycle-a',depends=['fixture-cycle-b']);package(db,'fixture-cycle-b',depends=['fixture-cycle-a'])
    for name in ('glibc','linux-asahi','fixture-user-protected'):package(db,name)


def protected_db(L,report,uid):
    # The actual ordinary CLI identity cannot write any observed DB node or create a lock.
    L.need(uid>0 and all(r['uid']==0 and not r['mode']&0o022 for r in report['database']['nodes'].values()),'root-owned nonwritable metadata required')


def observe(L,C,user,work,desired,base,uid):
    M=module();default=work/'default-assessment.json'
    real_before,_=M.database_snapshot(Path('/var/lib/pacman'))
    L.need(not Path('/var/lib/pacman/db.lck').exists(),'default DB already locked')
    # No --root or --dbpath: this is the actual installed CLI default lookup.
    user([CLI,'assess','--output',str(default)])
    report=json.loads(default.read_bytes());protected_db(L,report,uid)
    L.need(report['scope']==C.SCOPE and report['root']=='/' and report['dbpath']=='/var/lib/pacman' and report['apply_supported'] is False and
        {n:r['version'] for n,r in report['packages'].items()}==desired and all(report['packages'][n]['protected'] for n in base),
        'actual575 metadata/base reference-floor observation differs')
    real_after,_=M.database_snapshot(Path('/var/lib/pacman'))
    L.need(real_before==real_after==report['database'] and not Path('/var/lib/pacman/db.lck').exists(),'default readonly CLI changed database or created lock')
    user(['/usr/bin/python3','-I','-B','-c','import os; assert os.geteuid()>0 and not os.access("/var/lib/pacman",os.W_OK)'])
    fixture=work/'fixture-root';db=fixture/'var/lib/pacman';(db/'local').mkdir(parents=True);(db/'local/ALPM_DB_VERSION').write_text('9\n')
    populate(db)
    for path in (fixture,*fixture.rglob('*')):
        os.chown(path,0,0);path.chmod(0o755 if path.is_dir() else 0o644)
    # Reports remain caller-owned; all fixture DB nodes deny writes to that caller.
    user(['/usr/bin/python3','-I','-B','-c','import os,sys; assert not os.access(sys.argv[1],os.W_OK)',str(db)])
    before,_=M.database_snapshot(db);assessment=work/'fixture-assessment.json';plan=work/'fixture-plan.json'
    args=[CLI,'assess','--root',str(fixture),'--dbpath',str(db),'--protect','fixture-user-protected','--output',str(assessment)]
    user(args);raw=json.loads(assessment.read_bytes());protected_db(L,raw,uid);rows=raw['packages']
    L.need(raw['scope']==C.SCOPE and raw['apply_supported'] is False and raw['broken_dependencies']==[] and raw['candidates']==['fixture-leaf','fixture-oldprovider'] and
        rows['fixture-provider']['required_by']==['fixture-consumer'] and rows['fixture-consumer']['satisfiers']['depends']['fixture-virtual>=2']=='fixture-provider' and
        rows['fixture-optional']['optional_required_by']==['fixture-app'] and rows['fixture-cycle-a']['required_by']==['fixture-cycle-b'] and
        all(rows[n]['protected'] for n in ('glibc','linux-asahi','fixture-user-protected')),'real libalpm version/provision/optional/cycle/protection facts differ')
    user([CLI,'plan',str(assessment),'--select','fixture-leaf','--select','fixture-oldprovider','--output',str(plan)])
    selected=json.loads(plan.read_bytes());verified=json.loads(user([CLI,'verify',str(plan)]))
    L.need(selected['status']=='NOT_APPLIED' and selected['apply_supported'] is False and set(selected['selected'])=={'fixture-leaf','fixture-oldprovider'} and
        selected['simultaneous_remaining_dependencies']=='PASS_METADATA_ONLY' and verified==dict(status='NOT_APPLIED',verification='PASS_CURRENT_METADATA_ONLY',apply_supported=False),
        'explicit selected plan/verification differs')
    refusals=[]
    for name in ('glibc','linux-asahi','fixture-user-protected','fixture-provider','fixture-optional','fixture-cycle-a','fixture-manual','fixture-missing'):
        path=work/('refused-'+name+'.json');value=json.loads(user([CLI,'plan',str(assessment),'--select',name,'--output',str(path)],1))
        L.need(value['verification']=='REFUSED' and not path.exists(),'unsafe explicit selection accepted');refusals.append(name)
    after,_=M.database_snapshot(db);L.need(before==after and not (db/'db.lck').exists(),'fixture readonly CLI changed database or created transaction lock')
    # Only this test counterpart exposes transaction init/release on a separate temporary root.
    holder=M.Installed(fixture,db);owned=False
    try:
        for name in ('alpm_trans_init','alpm_trans_release'):
            function=getattr(holder.lib,name);function.argtypes=[ctypes.c_void_p,ctypes.c_int] if name.endswith('init') else [ctypes.c_void_p];function.restype=ctypes.c_int
        L.need(holder.lib.alpm_trans_init(holder.handle,0)==0,'separate fixture holder failed');owned=True
        lock=db/'db.lck';held=M.identity(lock.lstat());nonlock={n:r for n,r in after['nodes'].items() if n!='.'}
        refusal=json.loads(user([CLI,'assess','--root',str(fixture),'--dbpath',str(db)],1))
        L.need(refusal['verification']=='REFUSED' and 'ALPM lock' in refusal['reason'] and M.identity(lock.lstat())==held,'foreign lock refusal/release changed holder')
        for name,row in nonlock.items():
            path=db/name;info=path.lstat();L.need(M.identity(info)=={k:v for k,v in row.items() if k not in ('kind','sha256')},'foreign lock case changed nonlock metadata')
            if row['kind']=='file':L.need(M.digest(path.read_bytes())==row['sha256'],'foreign lock case changed nonlock bytes')
    finally:
        if owned:L.need(holder.lib.alpm_trans_release(holder.handle)==0,'fixture holder release failed')
        holder.close()
    L.need(not (db/'db.lck').exists(),'fixture holder did not release its own lock')
    evidence=dict(default_report_sha256=L.sha(default),fixture_report_sha256=L.sha(assessment),fixture_plan_sha256=L.sha(plan),verified=verified,
        rejected_selections=refusals,foreign_lock=refusal,scope=C.SCOPE,fixture_payload='NONE_HAND_AUTHORED_METADATA_ONLY',orphan_removal='NOT_IMPLEMENTED')
    receipt=work/'fixture-observation.json';receipt.write_bytes(C.encoded(evidence));receipt.chmod(0o600);os.chown(receipt,uid,default.stat().st_gid)
    return dict(default_database='PASS_EXACT575_METADATA_ONLY',base_protected=True,default_root='/',default_dbpath='/var/lib/pacman',
        readonly_enforced='UNPRIVILEGED_NO_DB_WRITE_ACCESS',fixture='PASS_VERSIONED_PROVIDED_OPTIONAL_CYCLE_PROTECTED',plan_verify='PASS_NOT_APPLIED',
        db_preserved=True,foreign_lock='PASS_REFUSAL_PRESERVED',apply_supported=False,reports={p.name:L.sha(p) for p in (default,assessment,plan,receipt)})
