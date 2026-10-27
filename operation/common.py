# SPDX-License-Identifier: MIT
"""Closed companion source, separately selected; no native result authority."""
import hashlib,json,os,re,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
OPERATION='recover-apps16-reinstall607'
LANE='scripts/ci/apps7-full574-repair-native'
APPS='cachy-asahi-apps'
VERSION='0.1.0-16'
ARCHIVE='319cc1db4738945ad3b146490ea0fabd80f8c8d89d8c41a11750dd0ba5d5b8af'
SOURCE='c14a8362e2cf9cda84c0b5c1a181658a8c9111a6'
STATUS='PASS_APPS16_INTERRUPTION_RECOVERY_AND_ORIGINAL_ORDERED_TEARDOWN'
LIFECYCLE='PASS_APPS16_GENUINE607_INTERRUPTION_AND_NORMAL_BACKEND_RECOVERY'

def need(ok,why):
    if not ok:raise ValueError(why)

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()

def decode(raw):
    def pairs(items):
        out={}
        for key,value in items:need(key not in out,'duplicate source key');out[key]=value
        return out
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite source JSON'))

def canonical(path):
    text=os.fspath(path);need(os.path.isabs(text)and text==os.path.normpath(text)and not text.startswith('//'),'absolute normalized path')
    path=Path(text);need(not any(p.is_symlink()for p in(path,*path.parents)),'ordinary source ancestry');return path

def read(path):
    path=canonical(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<=before.st_size<=16*1024**2,'bounded singlelink source')
        parts=[];size=0
        while raw:=os.read(fd,65536):parts.append(raw);size+=len(raw);need(size<=before.st_size,'source growth')
        key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        need(size==before.st_size and key(before)==key(os.fstat(fd))==key(path.lstat()),'source FD/path drift');return b''.join(parts)
    finally:os.close(fd)

def tree(root):
    root=canonical(root);need(root.is_dir(),'source directory required');out={};dirs=set()
    for p in sorted(root.rglob('*')):
        info=p.lstat();need(not p.is_symlink(),'source alias refused');name=p.relative_to(root).as_posix()
        if stat.S_ISDIR(info.st_mode):dirs.add(name)
        else:out[name]=pin(read(p))
    need(dirs=={q.as_posix()for name in out for q in Path(name).parents if str(q)!='.'},'closed source namespace')
    return out

def verify(source,want):
    need(type(want)is str and re.fullmatch('[0-9a-f]{64}',want),'explicit Root-bound operation profile SHA256 required')
    raw=read(HERE/'profile.json');need(pin(raw)['sha256']==want,'operation profile hash')
    p=decode(raw);need(p['schema_version']==1 and p['operation']==OPERATION and p['source']==SOURCE and p['actual']is None and p['Root_acceptance']is None,'source-only separate operation profile')
    need(tree(source)==p['source_files']and len(p['source_files'])==245,'entire unchanged public245 source')
    expected=dict(p['operation_files'],**{'profile.json':pin(raw)})
    need(tree(HERE)==expected,'complete separately pinned operation closure')
    return p

def selected_plan(value):
    need(value['status']=='PLANNED'and value['applied']=='NOT_APPLIED'and value['installer_authority']is False and value['synthetic']is True,'actual authenticated original TEST planner result')
    p=value['plan'];need(p['operation']=='reinstall'and p['requested_packages']==[APPS]and len(p['reinstalls'])==1,'one explicit Apps16 same-version reinstall')
    need(not any(p[k]for k in('additions','upgrades','removals','dependencies','conflicts','unchanged_selected'))and p['before_inventory_sha256']==p['after_inventory_sha256'],'no expansion or inventory change')
    need(p['requested_applications']==['apps']and p['repair_policy']=='EXPLICIT_SELECTED_SAME_VERSION_AND_METADATA_ONLY_NO_DEPENDENCY_EXPANSION','original exact same-version repair policy')
    row=p['reinstalls'][0]
    need(all(row[k]['name']==APPS and row[k]['version']==VERSION for k in('before','after'))and row['after']['release_archive_sha256']==ARCHIVE,'exact actual Apps16 archive/version, never a renamed synthetic fixture')
    return p

def interruption(value,plan_sha,before):
    need(value['status']=='FAIL_INTERRUPTED_OWNED_COPY_RETAINED'and value['commit_started']==value['packages_committed']=='UNKNOWN'and value['rollback']=='NOT_CLAIMED','original interrupted uncertainty only')
    need(value['worker_group_absent']is True and value['direct_child_reaped']is True and value['time_limit']==600 and value['reap_limit']==5 and 0<value['seconds']<=605,'original cancellation/reap bounds')
    pending=value['pending'];need(set(pending)=={'status','plan_sha256','before'}and pending['status']=='ATTEMPT_STARTED_COMMIT_OUTCOME_NOT_RECORDED'and pending['plan_sha256']==plan_sha and pending['before']==before,'original durable intent joins authenticated reinstall and exact before pins')
    need(set(value['outputs'])=={'stdout','stderr'}and sum(v['bytes']for v in value['outputs'].values())<=1024**2,'original combined worker output cap')
    return value
