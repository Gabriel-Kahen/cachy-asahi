#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact successful ALPM commit then child exit; dispose the whole owned copy."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from types import SimpleNamespace
import uuid

CASE='postcommit-exit87'
EXIT=87
LOCK='var/lib/pacman/db.lck'
NORMAL='scripts/ci/full-root-upgrade/root_upgrade.py'
SELF='scripts/ci/full-root-postcommit-failure/run.py'
PURPOSE='actual587-postcommit-failure-disposal-test'
CHILD_NOFILE=8192
BEFORE='2198942a546f4714587c810fe174d4457121960f3a7b1dbaa276e9f970f322c7'
AFTER='dbfe042f77bf61ce8e15a63c53391bcc4f04b94f18e99eeffdfdf85e68aa26ac'
PACKAGE='c817c01aad875fcf5a34073d4c9d0e830c577301189148b3c0e0969f001bea1a'
LOCK_NODE=dict(type='file',mode=0,uid=0,gid=0,bytes=0,sha256=hashlib.sha256(b'').hexdigest())


def need(ok,reason):
    if not ok: raise ValueError(reason)


def encoded(value):return (json.dumps(value,sort_keys=True)+'\n').encode()
def sha(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def read(path,maximum=1024**2):
    path=Path(path)
    need(path.is_absolute() and '..' not in path.parts and not any(p.is_symlink() for p in (path,*path.parents)), 'ordinary absolute input required')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=maximum,'bounded ordinary input required')
        data=stream.read(maximum+1);after=os.fstat(stream.fileno())
    identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mode,s.st_mtime_ns,s.st_ctime_ns)
    need(len(data)==before.st_size and identity(before)==identity(after)==identity(path.stat()),'input changed')
    return data


def write_new(path,value):
    data=encoded(value);need(len(data)<=128*1024,'bounded private receipt required')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        pending=memoryview(data)
        while pending:
            count=os.write(fd,pending);need(count>0,'receipt write stalled');pending=pending[count:]
        os.fsync(fd)
    finally:os.close(fd)
    parent=os.open(Path(path).parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(parent)
    finally:os.close(parent)


def load(name,path):
    spec=importlib.util.spec_from_file_location('failed_update_'+name,path)
    value=importlib.util.module_from_spec(spec);sys.modules[spec.name]=value;spec.loader.exec_module(value);return value


def identity(path):
    info=Path(path).lstat();need(stat.S_ISDIR(info.st_mode),'ordinary root required')
    return [info.st_dev,info.st_ino]


def process_binding(module):
    # The complete-root observer retains up to 4096 hardlink-group descriptors.
    # Bind only this private Runner module; other callers keep its 128-FD limit.
    original=module.resource
    hard=original.getrlimit(original.RLIMIT_NOFILE)[1]
    need(hard==original.RLIM_INFINITY or hard>=CHILD_NOFILE,'full-root child descriptor budget unavailable')
    def setrlimit(kind,bounds):
        if kind==original.RLIMIT_NOFILE:
            need(bounds==(128,128),'frozen child descriptor request differs')
            bounds=(CHILD_NOFILE,CHILD_NOFILE)
        return original.setrlimit(kind,bounds)
    module.resource=SimpleNamespace(**{**vars(original),'setrlimit':setrlimit})
    return module


def selected_api(args):
    root=Path(args.source_root)
    raw=read(args.lane_config);need(hashlib.sha256(raw).hexdigest()==args.lane_config_sha256,'lane configuration pin differs')
    config=json.loads(raw)
    need(config['purpose']==PURPOSE and config['failure']==dict(case=CASE,exit_code=EXIT,worker_seconds=1200,verify_seconds=600), 'closed failure selection required')
    need(args.failure_case==CASE and args.auxiliary_runtime is True,'explicit failed-update auxiliary lane required')
    for name,pin in config['code_pins'].items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts and re.fullmatch('[0-9a-f]{64}',pin),'code pin shape')
        need(hashlib.sha256(read(root/name)).hexdigest()==pin,'frozen source differs: '+name)
    for key,relative in (('runtime','scripts/update/linked_runtime.py'),('initializer','scripts/update/aux_initialize.py')):
        need(Path(getattr(args,key))==root/relative and getattr(args,key+'_sha256')==config['code_pins'][relative], 'selected existing API differs')
    need(Path(args.comparator)==root/'scripts/ci/full-development-composition/audio_aux.py','held comparator required')
    need(sha(Path(__file__))==config['code_pins'][SELF],'failed-update worker source differs')
    sys.path.insert(0,str(root/'scripts/update'))
    driver=load('normal_driver',root/NORMAL)
    linked=load('linked',root/'scripts/update/linked_runtime.py')
    initializer=load('initialize',root/'scripts/update/aux_initialize.py')
    copy=load('copy',root/'scripts/update/aux_copy.py')
    constructor=load('constructor',root/'scripts/ci/full-root-upgrade/construct_repository.py')
    process=process_binding(load('process',root/'scripts/port/kernel-native-job/runtime.py'))
    api,initialize=driver.connect(linked,initializer,Path(args.comparator),auxiliary_runtime=True)
    return SimpleNamespace(config=config,driver=driver,linked=linked,copy=copy,constructor=constructor,
                           process=process,normal=api,initialize=initialize)


def observe(api,path,scale):
    limits=scale['limits']; roots=api.linked.roots
    budget=roots.Limits(deadline=time.monotonic()+600,max_nodes=limits['root_nodes'],max_bytes=limits['root_bytes'],
                        max_file_bytes=limits['file_bytes'],max_package_files=limits['package_files'])
    value=roots.observe(path,limits=budget,hardlinks='generic-development-internal')
    api.linked.links.check(value,budget)
    api.linked.aux.checkpoint(path,value,budget)
    return value


def inventory_sha(value):
    return hashlib.sha256(''.join(n+' '+v+'\n' for n,v in sorted(value.items())).encode()).hexdigest()


def fault_class(base,arm):
    class ControlledExit(base):
        def precommit(self):
            super().precommit() # Keep all original capacity/config/helper checks.
            need(not hasattr(self,'commit_calls'),'one precommit arm only')
            alpm=self.alpm
            need(self.commit_ready is True and alpm is not None and alpm.started,'live prepared boundary required')
            need(inventory_sha(alpm.inventory())==self.config['before_lock_sha256']==BEFORE,'initial587 differs')
            need(alpm.packages(alpm.alpm_trans_get_add(alpm.handle))=={'cachy-asahi-setup':'0.1.0-4'} and
                 alpm.packages(alpm.alpm_trans_get_remove(alpm.handle))=={},'exact prepared setup change required')
            original=alpm.alpm_trans_commit;self.commit_calls=0;self.commit_return=None
            def commit(handle,details):
                need(handle is alpm.handle and self.commit_calls==0 and alpm.started,'one original live commit required')
                self.commit_calls+=1
                code=original(handle,details) # Real libalpm call, unchanged arguments/return.
                self.commit_return=code
                return code
            alpm.alpm_trans_commit=commit
        def observed_after(self,after):
            super().observed_after(after) # Existing exact after587 lock validation.
            need(getattr(self,'commit_calls',None)==1 and type(getattr(self,'commit_return',None)) is int and self.commit_return==0,
                 'successful original ALPM commit return required')
            arm(self,after)
            raise ValueError('controlled postcommit exit returned; checkpoint remains prohibited')
    return ControlledExit


def arm(runtime,after,spec,marker,*,exit_process=os._exit):
    need(runtime.commit_ready is True and runtime.commit_calls==1 and type(runtime.commit_return) is int and
         runtime.commit_return==0 and runtime.alpm is not None and runtime.alpm.started,'real successful commit required')
    need(len(after)==587 and inventory_sha(after)==runtime.config['after_lock_sha256']==AFTER and
         runtime.alpm.inventory()==after,'live after587 inventory differs')
    need(identity(runtime.root)==spec['root_identity'],'fault target identity changed')
    need(not os.listdir(runtime.args.state_dir),'checkpoint must remain unattempted at boundary')
    write_new(marker,dict(event='successful-postcommit-exit',case=CASE,nonce=spec['nonce'],exit_code=EXIT,
        pid=os.getpid(),root_identity=spec['root_identity'],spec_sha256=spec['spec_sha256'],
        worker_sha256=spec['worker_sha256'],prepared_add={'cachy-asahi-setup':'0.1.0-4'},prepared_remove={},
        commit_calls=1,commit_return=0,after_lock_sha256=AFTER,checkpoint_attempted=False))
    exit_process(EXIT)


def boundary(marker,spec):
    need(type(marker) is dict and set(marker)=={'event','case','nonce','exit_code','pid','root_identity','spec_sha256',
         'worker_sha256','prepared_add','prepared_remove','commit_calls','commit_return','after_lock_sha256','checkpoint_attempted'} and
         marker['event']=='successful-postcommit-exit' and marker['case']==CASE and marker['exit_code']==EXIT and
         marker['nonce']==spec['nonce'] and marker['root_identity']==spec['root_identity'] and
         marker['spec_sha256']==spec['spec_sha256'] and marker['worker_sha256']==spec['worker_sha256'] and
         type(marker['pid']) is int and marker['pid']>0 and type(marker['commit_calls']) is int and marker['commit_calls']==1 and
         type(marker['commit_return']) is int and marker['commit_return']==0 and marker['after_lock_sha256']==AFTER and
         marker['checkpoint_attempted'] is False and marker['prepared_add']=={'cachy-asahi-setup':'0.1.0-4'} and
         marker['prepared_remove']=={},'successful postcommit boundary witness differs')
    return dict(commit_started=True,packages_committed=True)


def assess(row,marker,spec,before,after,checkpoint_before,checkpoint_after):
    facts=boundary(marker,spec)
    need(row.get('termination') is None and row.get('returncode')==EXIT and row.get('direct_child_reaped') is True and
         row.get('group_retired') is True,'controlled postcommit child retirement not established')
    need(before['complete'] is True and after['complete'] is True and LOCK not in before['nodes'] and
         after['nodes'].get(LOCK)==LOCK_NODE,'complete copied root with exact retained lock required')
    need(checkpoint_before is None and checkpoint_after is None,'checkpoint changed or baseline not fresh')
    return dict(status='FAIL',phase='controlled-postcommit-child-exit',**facts,checkpoint_changed=False,
        controlled_failure_verified=True,prepared_add=marker['prepared_add'],prepared_remove={},worker=row,boundary=CASE,
        checkpoint_preserved=True,stale_lock_retained=True,
        recovery='DISPOSE-OWNED-COPY; committed copy is never reopened, retried or resumed')


def database_after(driver,root,observed):
    """Read locked desc/files directly; never open ALPM or relax database()."""
    need(observed['complete'] is True and observed['nodes'].get(LOCK)==LOCK_NODE,'exact observed stale lock required')
    with driver.directory(root,'var/lib/pacman') as parent:
        need(driver.read_record(parent,'db.lck',maximum=0,expected=LOCK_NODE)==b'','actual stale lock differs')
    records=[];spent=0;nodes=observed['nodes'];db='var/lib/pacman/local'
    with driver.directory(root,db) as local:
        initial=driver.identity(os.fstat(local));names=sorted(os.listdir(local))
        need(len(names)==588 and 'ALPM_DB_VERSION' in names,'exact587 database shape required')
        need(driver.read_record(local,'ALPM_DB_VERSION',expected=nodes[db+'/ALPM_DB_VERSION'])==b'9\n','database version differs')
        for name in names:
            if name=='ALPM_DB_VERSION':continue
            need('/' not in name and name not in ('.','..'),'unsafe database directory')
            fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=local)
            try:
                before=driver.identity(os.fstat(fd))
                desc=driver.fields(driver.read_record(fd,'desc',expected=nodes[db+'/'+name+'/desc']))
                raw=driver.read_record(fd,'files',expected=nodes[db+'/'+name+'/files']);files=driver.fields(raw)
                need(all(len(desc.get(key,[]))==1 for key in ('NAME','VERSION','ARCH')),'database identity missing')
                package,version,arch=(desc[key][0] for key in ('NAME','VERSION','ARCH'))
                need(driver.LABEL.fullmatch(package) and 0<len(version)<=128 and not any(c.isspace() or c=='\0' for c in version) and
                     name==package+'-'+version and arch in ('any','aarch64'),'database package identity differs')
                owned=files.get('FILES',[] if raw==b'' else None)
                need(type(owned) is list and len(owned)==len(set(owned)) and len(owned)<=500000,'database ownership shape differs')
                for path in owned:driver.relative(path[:-1] if path.endswith('/') else path)
                paths=[path for path in owned if not path.endswith('/')];spent+=len(paths);need(spent<=200000,'database ownership bound')
                records.append(dict(name=package,version=version,arch=arch,depend=desc.get('DEPENDS',[]),
                    provides=desc.get('PROVIDES',[]),conflict=desc.get('CONFLICTS',[]),files=paths,
                    owned_paths=[path[:-1] if path.endswith('/') else path for path in owned]))
                need(before==driver.identity(os.fstat(fd))==driver.identity(os.stat(name,dir_fd=local,follow_symlinks=False)),'database directory changed')
            finally:os.close(fd)
        need(initial==driver.identity(os.fstat(local)) and names==sorted(os.listdir(local)),'database changed')
    need(len({row['name'] for row in records})==587,'duplicate database package')
    return sorted(records,key=lambda row:row['name'])


def prepare_verifier(api,args,config,before):
    verifier=api.linked.Runtime(args,config,comparator_path=Path(args.comparator))
    need(verifier.tree(args.root)==before['nodes'],'verifier baseline differs')
    records=api.driver.database(args.root,max_files=500000,max_nodes=200000,observed=before['nodes'])
    need(len(records)==587 and inventory_sha({r['name']:r['version'] for r in records})==BEFORE,'initial database differs')
    prefix='var/lib/pacman/local/cachy-asahi-setup-0.1.0-3'
    with api.driver.directory(args.root,prefix) as fd:
        raw=api.driver.read_record(fd,'files',expected=before['nodes'][prefix+'/files'])
    verifier.old_paths={path.rstrip('/') for path in api.driver.fields(raw)['FILES']}
    verifier.database_changes=tuple('var/lib/pacman/local/cachy-asahi-setup-'+v for v in ('0.1.0-3','0.1.0-4'))
    need(sha(Path(args.package))==PACKAGE,'pinned setup4 archive differs')
    payload=verifier.archive_payload(Path(args.package),dict(bytes=0,nodes=0))
    verifier.projected_paths(before['nodes'],payload) # Held exact six-file/link/aux policy.
    verifier.projected[LOCK]=dict(LOCK_NODE)
    verifier.aux_precommit=verifier.aux_before;verifier.commit_ready=True
    return verifier,records,payload


def verify_after(api,args,config,verifier,records,payload):
    from dataclasses import replace
    verifier.root_limits=replace(verifier.root_limits,deadline=time.monotonic()+600)
    nodes=verifier.tree(args.root) # All nonselected bytes, hardlinks, links and aux transitions.
    after=verifier.observation
    actual=database_after(api.driver,args.root,after)
    need(len(actual)==587 and inventory_sha({r['name']:r['version'] for r in actual})==AFTER,'after587 database differs')
    old={r['name']:r for r in records};new={r['name']:{k:v for k,v in r.items() if k!='owned_paths'} for r in actual}
    selected='cachy-asahi-setup'
    owned=next(r['owned_paths'] for r in actual if r['name']==selected)
    need(set(owned)==set(payload),'setup4 complete ownership differs')
    need({n:r for n,r in old.items() if n!=selected}=={n:r for n,r in new.items() if n!=selected},'nonselected package database changed')
    need(set(new[selected]['files'])=={name for name,row in payload.items() if row['type']!='directory'},'setup4 ownership differs')
    protected,_=api.driver.ownership(records,verifier.baseline['nodes'],verifier)
    api.driver.preserved(verifier.baseline['nodes'],nodes,protected)
    return after,dict(after587_database_verified=True,postcommit_payload_verified=True,postcommit_preservation_verified=True,
                      selected_archive_sha256=PACKAGE,after_lock_sha256=AFTER,auxiliary_checks=verifier.auxiliary_checks)


def unsafe_retirement(path,error,*,exit_process=os._exit):
    # Do not unwind the copy lifetime while a failed supervisor cannot prove its
    # group retired. Leave disposal to the outer container/volume owner.
    value=dict(status='FAIL',phase='child-retirement-unknown',commit_started='UNKNOWN',packages_committed='UNKNOWN',
               checkpoint_changed='UNKNOWN',copy_cleanup='NOT ATTEMPTED-live-state-unknown',error=str(error)[:512])
    try:write_new(path,value)
    except BaseException:pass
    print(json.dumps(value,sort_keys=True),flush=True);exit_process(88)
    raise SystemExit(88)


def execute_case(args,api):
    holder={};invoked=False
    scale=api.normal.scale.configuration(args.scale,args.scale_sha256)
    source_before=observe(api,Path(args.source),scale)
    def apply(child_args):
        nonlocal invoked
        need(not invoked,'one child attempt only');invoked=True
        before=observe(api,Path(child_args.root),scale)
        need(not os.listdir(child_args.state_dir),'fresh checkpoint directory required')
        bound=api.normal.scale.bound
        with bound.client.state_directory(child_args.state_dir,False) as fd:checkpoint_before=bound.client.checkpoint(fd)
        nonce=uuid.uuid4().hex
        spec_path=Path(child_args.data)/'failure-worker.json';marker=Path(child_args.data)/'postcommit-witness.json'
        verifier,records,payload=prepare_verifier(api,child_args,scale,before)
        spec=dict(schema_version=1,case=CASE,nonce=nonce,
                  args={k:str(v) if isinstance(v,Path) else v for k,v in vars(child_args).items()},
                  root_identity=identity(child_args.root),
                  marker=str(marker),worker_sha256=sha(Path(__file__)))
        write_new(spec_path,spec);os.chmod(spec_path,0o400);spec_pin=sha(spec_path)
        witness_spec=dict(spec,spec_sha256=spec_pin)
        result=dict(status='FAIL',phase='controlled-child',commit_started='UNKNOWN',packages_committed='UNKNOWN',checkpoint_changed='UNKNOWN')
        holder['case']=result
        try:
            env=dict(os.environ);env.update(PATH='/usr/bin:/bin',LC_ALL='C',HOME=str(child_args.data),TMPDIR=str(child_args.workspace))
            try:
                with api.process.cancellation_handlers():
                    row=api.process.Runner(1200,env,Path(child_args.data)/'child-logs').run(
                        [sys.executable,'-I','-B',str(Path(__file__).resolve()),'--worker-spec',str(spec_path),'--worker-spec-sha256',spec_pin],
                        timeout=1200,limit=1024**2)
            except BaseException as error:
                unsafe_retirement(Path(child_args.data)/'supervisor-uncertain.json',error)
            # Held Runner returns only after reserved-group cleanup/output drain.
            worker=dict(returncode=row.returncode,termination=None,direct_child_reaped=True,group_retired=True)
            result['worker']=worker
            if row.stdout:
                try:
                    result['child_report']=json.loads(row.stdout)
                    report=result['child_report']
                    if type(report) is dict and report.get('status') in ('PASS','FAIL'):
                        for key in ('commit_started','packages_committed','checkpoint_changed'):
                            if type(report.get(key)) is bool:result[key]=report[key]
                except ValueError:result['child_report']='UNPARSEABLE-BOUNDED-OUTPUT'
            witness=json.loads(read(marker,16384));result.update(boundary(witness,witness_spec))
            with bound.client.state_directory(child_args.state_dir,False) as fd:checkpoint_after=bound.client.checkpoint(fd)
            need(not os.listdir(child_args.state_dir),'checkpoint directory changed')
            need(checkpoint_before is None and checkpoint_after is None,'checkpoint changed')
            result['checkpoint_changed']=False
            after,proof=verify_after(api,child_args,scale,verifier,records,payload)
            result=assess(worker,witness,witness_spec,before,after,checkpoint_before,checkpoint_after)
            result.update(proof)
            holder['case']=result
        except BaseException as error:
            result.update(error_type=type(error).__name__,error=str(error)[:512]);holder['case']=result
        return holder['case']
    wrapped=SimpleNamespace(scale=api.normal.scale,Runtime=api.normal.Runtime,apply=apply)
    result=dict(status='FAIL',scope='controlled-full587-postcommit-failure-disposal',case=CASE,
                commit_started=False,packages_committed=False,checkpoint_changed=False,hardware='NOT RUN',
                apple_acceptance='NOT ESTABLISHED',normal_upgrade_acceptance='NOT ESTABLISHED',failure_cases=0,
                original_source_preserved='UNKNOWN',copy_cleanup='NOT RUN')
    try:
        driver=api.driver.run(args,runtime_module=wrapped,copy_module=api.copy,constructor=api.constructor,prepare_copy=api.initialize)
        result['driver']=driver;result['copy_cleanup']=driver.get('copy_cleanup','UNKNOWN')
        case=holder.get('case',{});result['controlled_failure']=case
        for key in ('commit_started','packages_committed','checkpoint_changed'):result[key]=case.get(key,driver.get(key,'UNKNOWN'))
        if result['packages_committed'] is True:result['committed_transactions']=1
        need(driver['status']=='FAIL' and case.get('controlled_failure_verified') is True,'exact controlled boundary was not established')
        need(all(case.get(key) is True for key in ('after587_database_verified','postcommit_payload_verified',
             'postcommit_preservation_verified')),'independent committed-root proof incomplete')
        need(driver.get('copy_cleanup')=='PASS-owned-workspace-removed','owned copy disposal failed/uncertain')
        need(not Path(args.workspace).exists() and not Path(args.workspace).is_symlink(),'owned copy remains after disposal')
        result.update(copy_cleanup=driver['copy_cleanup'],failure_cases=1,committed_transactions=1,
                      after587_database_verified=True,postcommit_payload_verified=True,postcommit_preservation_verified=True,
                      recovery='DISPOSED-OWNED-COPY; outer container/volume retirement remains required')
    except BaseException as error:result.update(error_type=type(error).__name__,error=str(error)[:512])
    finally:
        try:
            after=observe(api,Path(args.source),scale)
            same=source_before['nodes']==after['nodes'] and source_before.get('hardlink_groups')==after.get('hardlink_groups')
            result['original_source_preserved']=same;need(same,'original source changed')
            if result.get('failure_cases')==1:result['status']='PASS'
        except BaseException as error:result.update(status='FAIL',source_check_error=str(error)[:512])
    return result


def worker(path,pin):
    raw=read(path,128*1024);need(hashlib.sha256(raw).hexdigest()==pin,'worker spec changed')
    spec=json.loads(raw);need(spec['schema_version']==1 and spec['case']==CASE and re.fullmatch('[0-9a-f]{32}',spec['nonce']),'worker selection differs')
    args=SimpleNamespace(**spec['args']);api=selected_api(args)
    need(spec['worker_sha256']==sha(Path(__file__)) and identity(args.root)==spec['root_identity'],'worker/root pin differs')
    need(Path(spec['marker'])==Path(args.data)/'postcommit-witness.json' and Path(path)==Path(args.data)/'failure-worker.json','fixed private witness paths required')
    api.normal.scale.bound.guard(Path(args.root),Path(args.workspace))
    config=api.normal.scale.configuration(args.scale,args.scale_sha256)
    callback=lambda runtime,after:arm(runtime,after,dict(spec,spec_sha256=pin),Path(spec['marker']))
    runtime=fault_class(api.linked.Runtime,callback)(args,config,comparator_path=Path(args.comparator))
    value=api.normal.scale.bound.apply(args,adapter=runtime)
    # Returning through any earlier refusal is an ordinary failure, never the
    # expected abrupt-exit outcome. No checkpoint success is accepted here.
    print(json.dumps(value,sort_keys=True));return 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker-spec');parser.add_argument('--worker-spec-sha256')
    for name in ('source-root','runtime','runtime-sha256','initializer','initializer-sha256','comparator',
                 'source','workspace','data','scale','scale-sha256','setup4-pair','package','provenance',
                 'gpg-home','signer','release-id','repo-name','namespace','issued-utc','expires-utc',
                 'lane-config','lane-config-sha256','failure-case'):parser.add_argument('--'+name)
    for name in ('copy-seconds','seconds','sequence'):parser.add_argument('--'+name,type=int)
    parser.add_argument('--supported-models',nargs='*',default=[])
    parser.add_argument('--auxiliary-runtime',action='store_true');parser.add_argument('--worker',action='store_true')
    args=parser.parse_args()
    if args.worker_spec:return worker(args.worker_spec,args.worker_spec_sha256)
    need(args.worker and args.source_root and args.lane_config,'explicit outer-owned worker invocation required')
    api=selected_api(args);value=execute_case(args,api);print(json.dumps(value,sort_keys=True));return int(value['status']!='PASS')


if __name__=='__main__':
    try:raise SystemExit(main())
    except SystemExit:raise
    except BaseException as error:
        print(json.dumps(dict(status='FAIL',phase='failed-update-worker',error_type=type(error).__name__,
            error=str(error)[:512],commit_started='UNKNOWN',packages_committed='UNKNOWN',checkpoint_changed='UNKNOWN'),sort_keys=True))
        raise SystemExit(1)
