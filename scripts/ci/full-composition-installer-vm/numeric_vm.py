#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Closed owned-VM numeric namespace bootstrap and independent root readback."""
import array
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import resource
from types import SimpleNamespace
import signal
import stat
import time

UID=23001
GIDS=((0,23001,1),(5,23005,1),(11,23011,1),(50,23050,1),(81,23081,1),(102,23102,1))
PURPOSE='full-installer-owned-vm-numeric-groups-v1'
SELECTION=dict(purpose=PURPOSE,uid_map=[[0,UID,1]],gid_map=[list(r) for r in GIDS])
USERNS=0x10000000
LEASE='namespace-lease.json'


def need(ok,reason):
    if not ok:raise ValueError(reason)


def selection(value):
    need(type(value) is dict and set(value)==set(SELECTION) and value==SELECTION and
         all(type(row) is list and len(row)==3 and all(type(n) is int for n in row)
             for row in value['uid_map']+value['gid_map']),'exact numeric fixture selection required')
    return value


def namespace_identity(fd):
    need(fcntl.ioctl(fd,0xb703)==USERNS,'user namespace FD required')
    info=os.fstat(fd);owner=array.array('I',[0]);fcntl.ioctl(fd,0xb704,owner,True)
    need(owner[0]==UID,'fixture namespace owner differs')
    return [info.st_dev,info.st_ino]


CHILD_NOFILE=8192


def process_binding(module):
    # Bind only this freshly loaded Runner; the shared resource module is unchanged.
    original=module.resource;hard=original.getrlimit(original.RLIMIT_NOFILE)[1]
    need(hard==original.RLIM_INFINITY or hard>=CHILD_NOFILE,'full-installer child descriptor budget unavailable')
    def setrlimit(kind,bounds):
        if kind==original.RLIMIT_NOFILE:
            need(bounds==(128,128),'frozen child descriptor request differs')
            bounds=(CHILD_NOFILE,CHILD_NOFILE)
        return original.setrlimit(kind,bounds)
    module.resource=SimpleNamespace(**{**vars(original),'setrlimit':setrlimit})
    return module


def observer_budget():
    soft,hard=resource.getrlimit(resource.RLIMIT_NOFILE)
    need(all(value==resource.RLIM_INFINITY or value>=CHILD_NOFILE for value in (soft,hard)),
         'root observer descriptor budget unavailable')


def root_guard():
    observer_budget()
    need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0 and os.uname().machine=='aarch64' and
         os.uname().release=='7.2.10-1-aarch64-ARCH' and os.sysconf('SC_PAGE_SIZE')==4096 and
         os.environ.get('CACHY_ASAHI_FULL_INSTALLER_GUEST')=='1' and
         'cachy_asahi_virtual_proof=1' in Path('/proc/cmdline').read_text().split(), 'owned generic4K root guest bootstrap required')
    used={int(line.split(':')[2]) for line in Path('/etc/group').read_text().splitlines() if line and not line.startswith('#')}
    need(not ({row[1] for row in GIDS}-{UID}) & used,'reserved fixture group IDs already in use')


def retire_creator(pid,seconds=5):
    # No exec/fork in this helper: reserve its exact PID until the final signal.
    try:os.kill(pid,signal.SIGKILL)
    except ProcessLookupError:pass
    end=time.monotonic()+seconds
    while os.waitid(os.P_PID,pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is None:
        need(time.monotonic()<end,'namespace creator retirement deadline');time.sleep(.01)
    os.waitpid(pid,0)


def bootstrap(p,c,profile):
    root_guard();selection(profile.get('numeric_vm'))
    ready_r=ready_w=hold_r=hold_w=None;pid=None;fd=None;created=False
    try:
        ready_r,ready_w=os.pipe();hold_r,hold_w=os.pipe()
        parent=os.getpid();pid=os.fork()
        if pid==0:
            try:
                os.close(ready_r);os.close(hold_w)
                libc=ctypes.CDLL(None,use_errno=True)
                os.setgroups([]);os.setgid(UID);os.setuid(UID)
                # setuid clears PDEATHSIG: arm it after changing credentials.
                need(libc.prctl(1,signal.SIGKILL,0,0,0)==0 and os.getppid()==parent,'creator parent binding failed')
                need(libc.prctl(38,1,0,0,0)==0,'creator NNP failed')
                os.unshare(USERNS)
                os.write(ready_w,b'R');os.close(ready_w)
                os.read(hold_r,1);os._exit(0)
            except BaseException:os._exit(91)
        os.close(ready_w);ready_w=None;os.close(hold_r);hold_r=None
        need(select.select([ready_r],[],[],10)[0] and os.read(ready_r,1)==b'R','namespace creator did not become ready')
        proc=Path('/proc')/str(pid)
        fd=os.open(proc/'ns/user',os.O_RDONLY|os.O_CLOEXEC)
        identity=namespace_identity(fd)
        (proc/'uid_map').write_text('0 23001 1\n')
        (proc/'gid_map').write_text(''.join('%d %d %d\n'%row for row in GIDS))
        rows=lambda name:[list(map(int,line.split())) for line in (proc/name).read_text().splitlines()]
        need(rows('uid_map')==SELECTION['uid_map'] and rows('gid_map')==SELECTION['gid_map'] and
             (proc/'setgroups').read_text().strip()=='allow','created namespace mappings differ')
        retire_creator(pid);pid=None
        lease=dict(schema_version=1,selection=SELECTION,namespace_identity=identity,nonce=c['nonce'],
                   profile_sha256=p.sha(p.SHARED/'installer-profile.json'),creator_retired=True)
        path=p.SHARED/LEASE
        with path.open('xb') as output:
            created=True;output.write(p.encoded(lease));output.flush();os.fsync(output.fileno())
        path.chmod(0o444)
        return fd,p.sha(path)
    except BaseException:
        if fd is not None:os.close(fd)
        if created:(p.SHARED/LEASE).unlink()
        raise
    finally:
        if pid is not None:retire_creator(pid)
        for item in (ready_r,ready_w,hold_r,hold_w):
            if item is not None:os.close(item)


def checked_lease(p,fd,pin,c,profile):
    path=p.SHARED/LEASE
    raw=p.checked(p.SHARED,LEASE,dict(bytes=path.stat().st_size,sha256=pin),maximum=16384,protected=True).read_bytes()
    value=p.decode(raw)
    selection(profile.get('numeric_vm'))
    need(type(value) is dict and set(value)=={'schema_version','selection','namespace_identity','nonce','profile_sha256','creator_retired'} and
         value['schema_version']==1 and value['selection']==profile.get('numeric_vm')==SELECTION and
         value['nonce']==c['nonce'] and value['profile_sha256']==p.sha(p.SHARED/'installer-profile.json') and
         value['creator_retired'] is True and value['namespace_identity']==namespace_identity(fd),'numeric namespace lease differs')
    return value


def normalize(observation):
    reverse={outer:inner for inner,outer,count in GIDS}
    result=dict(observation,nodes={})
    for name,node in observation['nodes'].items():
        need(node.get('uid')==UID and node.get('gid') in reverse,'unexpected exported numeric ownership: '+name)
        result['nodes'][name]=dict(node,uid=0,gid=reverse[node['gid']])
    return result


def evidence_directory(worker):
    path=worker.TRIAL/'work/evidence'
    need(not any(node.is_symlink() for node in (path,*path.parents)),'mapped evidence alias refused')
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    info=os.fstat(fd)
    if not (info.st_uid==info.st_gid==UID and stat.S_IMODE(info.st_mode)==0o700):
        os.close(fd);raise ValueError('mapped evidence owner differs')
    return fd


def read_evidence(fd,name,maximum=1024**2):
    node=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
    try:
        before=os.fstat(node)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==before.st_gid==UID and
             stat.S_IMODE(before.st_mode)==0o600 and before.st_size<=maximum,'mapped evidence node differs')
        raw=bytearray()
        while len(raw)<=maximum:
            data=os.read(node,min(65536,maximum+1-len(raw)))
            if not data:break
            raw.extend(data)
        after=os.fstat(node);named=os.stat(name,dir_fd=fd,follow_symlinks=False)
        fingerprint=lambda info:(info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,info.st_nlink,
                                 info.st_size,info.st_mtime_ns,info.st_ctime_ns)
        need(len(raw)==before.st_size<=maximum and fingerprint(before)==fingerprint(after)==fingerprint(named),
             'mapped evidence changed during read')
        return bytes(raw)
    finally:os.close(node)


def publish(p,worker,result,lock):
    # Actors are retired before entry. Publish the lock first, then atomically
    # replace the provisional result; publication errors revoke our new outputs.
    fd=evidence_directory(worker);lock_created=False;staged=False;replaced=False
    try:
        need(p.decode(read_evidence(fd,'result.json')).get('status')=='PROVISIONAL_MAPPED_PARENT','provisional result required')
        for name,data in (('installed-packages.lock',lock),('verified-result.tmp',p.encoded(result))):
            node=os.open(name,os.O_WRONLY|os.O_NOFOLLOW|os.O_CREAT|os.O_EXCL,0o600,dir_fd=fd)
            if name=='installed-packages.lock':lock_created=True
            else:staged=True
            try:
                os.fchown(node,UID,UID);pending=memoryview(data)
                while pending:
                    count=os.write(node,pending);need(count>0,'mapped publication stalled');pending=pending[count:]
                os.fsync(node)
            finally:os.close(node)
        os.fsync(fd)
        os.replace('verified-result.tmp','result.json',src_dir_fd=fd,dst_dir_fd=fd);staged=False;replaced=True
        os.fsync(fd)
    except BaseException:
        if staged:os.unlink('verified-result.tmp',dir_fd=fd)
        if lock_created:os.unlink('installed-packages.lock',dir_fd=fd)
        if replaced:os.unlink('result.json',dir_fd=fd) # Never retain an unacknowledged PASS.
        raise
    finally:os.close(fd)


def observation_summary(p,observation,payload,started):
    """Bounded metadata only; never export node contents or an arbitrary tree."""
    counts=observation.get('unsupported_counts',{})
    required={'var/lib/pacman/local/ALPM_DB_VERSION'}
    for name,version in payload['packages'].items():
        required.update('var/lib/pacman/local/'+name+'-'+version+'/'+part for part in ('desc','files'))
    missing=sorted(required-observation['nodes'].keys());footprint=observation.get('footprint',{})
    summary=dict(complete=observation.get('complete') is True,elapsed_ms=max(0,int((time.monotonic()-started)*1000)),
        deadline_seconds=600,observed_nodes=len(observation['nodes']),
        unsupported_counts={(str(reason) if len(str(reason))<=160 else str(reason)[:128]+'#'+hashlib.sha256(str(reason).encode()).hexdigest()[:16]):counts[reason]
                            for reason in sorted(counts)[:16]},
        unsupported_reasons_omitted=max(0,len(counts)-16),required_database_nodes=len(required),
        missing_database_nodes=len(missing),missing_database_samples=missing[:8],
        footprint={name:footprint[name] for name in ('nodes','bytes','database_files','database_bytes','hardlink_inodes') if name in footprint})
    need(len(p.encoded(summary))<=8192,'mapped observation diagnostic bound')
    return summary


def verify_export(p,worker,result,c):
    root_guard();need(result.get('status')=='PROVISIONAL_MAPPED_PARENT','mapped parent stage incomplete')
    need(all(result.get(key) is True for key in ('committed','namespace_barrier','payload_verified','ownership_verified',
         'database_verified','preservation_verified','private_trust_verified','parent_inventory_preserved',
         'source_cache_preserved','process_retirement','ordinary_parent_nnp_cap0','numeric_namespace_verified')) and
         result.get('phase')=='complete' and result.get('nonce')==c['nonce'] and
         result.get('profile_sha256')==p.sha(p.SHARED/'installer-profile.json'),'mapped parent proof incomplete')
    c2,profile,manifest,payload=worker.checked_inputs(protected=True)
    need(c2==c and profile.get('numeric_vm')==SELECTION,'mapped observer selection differs')
    roots,base,driver,aux=worker.source_modules(profile)
    target=worker.TRIAL/'work/evidence/target'
    need(not any(path.is_symlink() for path in (target,*target.parents)),'mapped target alias refused')
    info=target.stat();need([info.st_dev,info.st_ino]==result['target_identity'] and
         stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==UID and stat.S_IMODE(info.st_mode)==0o700,
         'mapped target identity differs')
    started=time.monotonic()
    limits=roots.Limits(deadline=started+600,max_nodes=200000,max_bytes=6*p.GIB,max_file_bytes=p.GIB,max_package_files=500000)
    observation=roots.observe(target,limits=limits,hardlinks='generic-development-internal')
    summary=observation_summary(p,observation,payload,started)
    try:
        # observe() returns partial nodes after a bounded traversal failure.
        # Never reinterpret that failure as a missing installed DB record.
        need(observation.get('complete') is True and set(observation['unsupported_counts'])<=
             {'absolute-symlink','auxiliary-present'},'mapped root observation incomplete/unsupported')
        worker.compare_payload(normalize(observation),payload,derived_output_binding=profile.get('derived_output_binding'))
        records=driver.database(target,max_packages=587,max_files=500000,max_nodes=1000000,observed=observation['nodes'])
        need({r['name']:r['version'] for r in records}==profile['expected'],'mapped observer installed inventory differs')
        for row in records:
            expected={n for n in payload['ownership'][row['name']] if payload['nodes'][n]['type']!='directory'}
            need(set(row['files'])==expected,'mapped observer package ownership differs: '+row['name'])
    except BaseException:
        result['root_guest_observation']=summary
        raise
    guest=driver.database(Path('/'),max_packages=1024,max_files=500000,max_nodes=1000000)
    need({r['name']:r['version'] for r in guest}==c['tooling_inventory'],'mapped observer parent inventory differs')
    fd=evidence_directory(worker)
    try:
        need(p.decode(read_evidence(fd,'result.json'))==result,'mapped parent result bytes changed')
        lock=read_evidence(fd,'candidate-packages.lock')
    finally:os.close(fd)
    need(hashlib.sha256(lock).hexdigest()==p.EXPECTED,'mapped candidate lock differs')
    worker.checked_inputs(protected=True)
    result=dict(result,status=worker.PASS,root_guest_observation=summary,root_guest_payload_verified=True,parent_payload_verified=True,
                numeric_ownership_verified=True,source_cache_preserved=True,parent_inventory_preserved=True)
    publish(p,worker,result,lock)
    return result
