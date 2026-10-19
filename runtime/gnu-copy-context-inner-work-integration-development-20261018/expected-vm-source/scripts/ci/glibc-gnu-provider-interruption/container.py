#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Future owned-container-only complete574 clones and external-root transactions."""
from contextlib import contextmanager
import ctypes
import gzip
import json
import os
from pathlib import Path
import platform
import signal
import shutil
import stat
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common as C

INPUTS=Path('/inputs');SOURCE=Path('/source');HELD=Path('/held');OUT=Path('/out');WORK=Path('/work')
FIXTURE='tmp/provider-lifecycle'
USER='home/provider-lifecycle-user'
CONFIGS=('etc/gai.conf','etc/gai.conf.pacnew','etc/gai.conf.pacsave','etc/locale.gen','etc/locale.gen.pacsave')


def limits(api,seconds=600):return api['roots'].Limits(deadline=time.monotonic()+seconds,max_packages=574,max_nodes=500000,max_bytes=8*1024**3,max_file_bytes=1024**3)


def snapshot(api,root,label):
    budget=limits(api);value=api['roots'].observe(root,limits=budget,hardlinks='generic-development-internal')
    if not (value['complete'] is True and set(value['unsupported_counts'])<={'absolute-symlink','auxiliary-present'}):
        # Failure facts only: no node/payload map, no changed eligibility gate.
        counts=value['unsupported_counts'];records=value['unsupported'];footprint=value['footprint']
        C.need(type(value['complete']) is bool and type(counts) is dict and len(counts)<=64 and all(type(k) is str and len(k)<=256 and type(v) is int and 0<=v<=500000 for k,v in counts.items()),'bounded original observation counts')
        C.need(type(records) is list and len(records)<=64 and all(type(r) is dict and set(r)=={'reason','path'} and all(type(r[k]) is str and len(r[k])<=(4096 if k=='path' else 256) for k in r) for r in records),'bounded original unsupported records')
        fields=('nodes','bytes','largest_file_bytes','hardlinks','hardlink_entries','hardlink_inodes','hardlink_declared_links','allocated_bytes','allocated_bytes_by_entry','symlinks','database_bytes','database_files','filesystem_free_bytes','filesystem_free_inodes','filesystem_inode_counts_known','filesystem_inode_source','filesystem_free_bytes_source')
        selected={k:footprint[k] for k in fields if k in footprint}
        C.need(all(v is None or type(v) in (bool,int) and (type(v) is bool or 0<=v<=2**64-1) or type(v) is str and v in ('statvfs','unknown','statvfs-f_bavail') for v in selected.values()),'finite original observation footprint')
        C.need(type(label) is str and len(label)<=128 and len(str(root))<=4096,'bounded original snapshot phase/root')
        facts=dict(snapshot_phase=label,root=str(root),observer_budget_seconds=600,complete=value['complete'],unsupported_counts=dict(counts),unsupported_records=[dict(r) for r in records],footprint=selected,scope='ORIGINAL_RETURNED_OBSERVATION_FAILURE_FACTS_ONLY_NO_NODE_MAP')
        C.need(len(json.dumps(facts,sort_keys=True,allow_nan=False).encode())<=2*1024**2,'observation failure facts bound')
        failures=api.setdefault('root_observation_failures',{});C.need(label not in failures and len(failures)<10,'finite unique observation failure phases');failures[label]=facts
    C.need(value['complete'] is True and set(value['unsupported_counts'])<={'absolute-symlink','auxiliary-present'},'complete bounded root observation')
    mapping=api['capabilities'].observe(api,root,value['nodes'],api['capability_index'],budget)
    api['capability_checks'][label]=dict(status='EXACT_SOURCE_MAP_PRESERVED',sha256=api['capabilities'].digest(mapping),paths=len(mapping))
    value['security_capabilities']=mapping
    raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode();C.need(len(raw)<=256*1024**2,'root snapshot bound')
    compressed=gzip.compress(raw,mtime=0);C.need(len(compressed)<=64*1024**2,'compressed root snapshot bound')
    C.need(sum(p.stat().st_size for p in OUT.iterdir())+len(compressed)<=512*1024**2,'aggregate lifecycle evidence bound')
    (OUT/(label+'-root.json.gz')).write_bytes(compressed)
    return value


def same(before,after):return before['nodes']==after['nodes'] and before.get('hardlink_groups')==after.get('hardlink_groups') and before.get('security_capabilities')==after.get('security_capabilities')


def database(api,root):return api['db'].database(root,max_packages=574,max_files=100000,max_nodes=500000)


def inventory(rows):return {p['name']:p['version'] for p in rows}


def ownership(rows):
    result={}
    for row in rows:
        for name in row['files']:
            C.need(name not in result,'unique installed file ownership');result[name]=row['name']
    return result


def collisions(candidate,rows):
    owners=ownership(rows);bad={n:owners[n] for n,r in candidate['nodes'].items() if r['type']!='directory' and n in owners and owners[n]!='glibc'}
    C.need(not bad,'unexpected candidate collision with held package: '+str(list(bad.items())[:8]))
    return {n:owners[n] for n,r in candidate['nodes'].items() if r['type']!='directory' and n in owners}


def payload(nodes,expected,except_files=()):
    for n,row in expected.items():
        if row['type']=='directory' or n in except_files:continue
        C.need(n in nodes and all(nodes[n].get(k)==v for k,v in row.items()),'installed payload differs: '+n)
    groups={}
    for n,row in expected.items():
        if 'hardlink_group' in row:groups.setdefault(row['hardlink_group'],set()).add(n)
    for key,members in groups.items():
        C.need(not members.intersection(except_files) and
               {n for n,row in nodes.items() if row.get('hardlink_group')==key}==members,
               'installed payload hardlink group differs: '+key)


def unchanged(before,after,old,new,old_version):
    # Entire unrelated DB/payload/source state remains exact, not only selected files.
    allowed=set(old['nodes'])|set(new['nodes'])|C.CACHES|set(CONFIGS)
    prefixes=(FIXTURE+'/',USER+'/', 'var/lib/pacman/local/glibc-'+old_version+'/',
              'var/lib/pacman/local/'+C.NAME+'-'+C.VERSION+'/')
    allowed|={FIXTURE,USER,'var/lib/pacman/local/glibc-'+old_version,'var/lib/pacman/local/'+C.NAME+'-'+C.VERSION}
    changed=[n for n in set(before['nodes'])|set(after['nodes']) if before['nodes'].get(n)!=after['nodes'].get(n)]
    unexpected=[n for n in changed if n not in allowed and not n.startswith(prefixes)]
    C.need(not unexpected,'unrelated complete-root mutation: '+str(sorted(unexpected)[:16]))
    return dict(changed_nodes=len(changed),unrelated_preserved=True)


class Commands:
    def __init__(self,api,report):self.api=api;self.report=report
    def call(self,argv,seconds=90,expect=0):
        row,out,err,error=self.api['runtime'].run_command(argv,WORK,dict(C.ENV,HOME='/tmp',TMPDIR='/tmp'),seconds,1024**2)
        number=len(self.report['commands']);C.need(number<128 and sum(p.stat().st_size for p in OUT.iterdir())+len(out)+len(err)<=512*1024**2,'command count/aggregate evidence bound');self.report['commands'].append(row)
        (OUT/('command-%03d.stdout'%number)).write_bytes(out);(OUT/('command-%03d.stderr'%number)).write_bytes(err)
        if error:raise error
        C.need(row['exit_code']==expect and row['group_absence_verified'],'normal command exit/process-group retirement')
        return out
    def inside(self,root,argv,unprivileged=False):
        args=['/usr/bin/chroot']+(['--userspec=65534:65534'] if unprivileged else [])+[str(root),*argv]
        return self.call(args)


def transaction(api,root,archive,remove,add,log,prepare_only=False,progress=None):
    """Intact observer libc/ALPM remains outside root, including on rollback."""
    alpm=api['roots'].Alpm(root,WORK,log,'aarch64',limits=limits(api,120))
    try:
        before=alpm.inventory();C.need((remove in before and add not in before) or (remove==add and add in before),'exact transaction starting provider')
        alpm.ok(alpm.alpm_trans_init(alpm.handle,(1<<7)|(1<<10)),'initialize NOHOOKS/NOSCRIPTLET');alpm.started=True
        if progress is not None:progress.bind(alpm)
        loaded=ctypes.c_void_p()
        alpm.ok(alpm.alpm_pkg_load(alpm.handle,os.fsencode(archive),1,0,ctypes.byref(loaded)),'load bound archive')
        if remove!=add:
            old=alpm.alpm_db_get_pkg(alpm.alpm_get_localdb(alpm.handle),remove.encode());C.need(old,'held provider exists')
            alpm.ok(alpm.alpm_remove_pkg(alpm.handle,old),'declare removal in same transaction')
        alpm.ok(alpm.alpm_add_pkg(alpm.handle,loaded),'declare replacement in same transaction')
        error=api['roots'].installer.Ptr();alpm.ok(alpm.alpm_trans_prepare(alpm.handle,ctypes.byref(error)),'full dependency/conflict prepare')
        prepared_add=alpm.packages(alpm.alpm_trans_get_add(alpm.handle));prepared_remove=alpm.packages(alpm.alpm_trans_get_remove(alpm.handle))
        C.need(set(prepared_add)=={add} and set(prepared_remove)==({remove} if remove!=add else set()),'exact prepared replacement sets')
        result=dict(prepared_add=prepared_add,prepared_remove=prepared_remove,dependencies='PASS_ALPM_PREPARE',commit_started=False,
                    observer_root='INTACT_OUTER_HELD574',hooks='DISABLED',scriptlets='DISABLED_EXPLICIT_HELD_POST_UPGRADE_LATER')
        if prepare_only:return dict(result,status='CONTROLLED_PRECOMMIT_REFUSAL_RELEASE_WITHOUT_COMMIT')
        result['commit_started']=True
        if progress is not None:progress.prepared=dict(result);progress.armed=True
        alpm.ok(alpm.alpm_trans_commit(alpm.handle,ctypes.byref(error)),'ordinary complete libalpm commit')
        return dict(result,status='PASS_COMMITTED_REPLACEMENT')
    finally:alpm.close()


@contextmanager
def runtime_mounts(commands,root):
    # Shared exact proc15/dev-null4096/umount0 helper; no utility API fallback.
    with commands.api['proc_probe'].runtime_mounts(root,commands.report):
        yield


def configs(root):
    return {n:(C.sha(C.read(root/n,2*1024**2)) if (root/n).is_file() else None) for n in CONFIGS}


def config_handoff(root,before,new,old,wanted_gai,wanted_locale,phase,evidence=None):
    """Explicit owned-clone policy, separate from ALPM's remove/add backup behavior."""
    C.need(phase in ('provider','rollback_prepare','rollback_finish'),'finite configuration handoff phase')
    C.need(root==WORK/'modified/root' and not any(p.is_symlink() for p in (root,*root.parents)), 'exact modified owned clone only')
    for path,mode in ((root,0o755),(root.parent,0o700)):
        info=path.lstat();C.need(stat.S_ISDIR(info.st_mode) and info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==mode,'owned searchable clone/private parent')
    gai='etc/gai.conf';locale='etc/locale.gen';saved=gai+'.pacsave';fresh=gai+'.pacnew';locale_saved=locale+'.pacsave';stash=FIXTURE+'/gai-pacsave-before-rollback'
    signature=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    descriptors=[];observations={};operations=[];directories=[]
    value={} if evidence is None else evidence;C.need(type(value) is dict and not value,'fresh configuration handoff evidence');value.update(status='STARTED_EXPLICIT_CLONE_CONFIG_HANDOFF',phase=phase,ALPM_active_configuration_preservation='NOT_CLAIMED',operations=operations)
    def directory_identity(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid)
    def directories_stable():
        for path,fd,info in directories:C.need(directory_identity(os.fstat(fd))==info==directory_identity(path.lstat()),'owned configuration directory identity unchanged')
    def observe(name,row,data):
        path=root/name;C.need(not any(p.is_symlink() for p in (path,*path.parents)),'ordinary configuration path')
        fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC);descriptors.append(fd);a=os.fstat(fd)
        C.need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_uid==os.geteuid() and a.st_size<=2*1024**2 and not os.listxattr(fd),'owned single-link bounded plain configuration')
        raw=os.pread(fd,2*1024**2+1,0);b=os.fstat(fd)
        actual=dict(type='file',bytes=len(raw),sha256=C.sha(raw),mode=stat.S_IMODE(b.st_mode),uid=b.st_uid,gid=b.st_gid)
        C.need(signature(a)==signature(b) and actual==row and raw==data and (path.lstat().st_dev,path.lstat().st_ino)==(b.st_dev,b.st_ino),'exact configuration bytes/metadata/identity')
        observations[name]=dict(actual,device=b.st_dev,inode=b.st_ino);return fd,a
    def absent(name):C.need(not os.path.lexists(root/name),'fresh configuration destination required: '+name)
    def stable():
        directories_stable()
        for fd,info in held.values():C.need(signature(os.fstat(fd))==signature(info),'configuration changed during handoff')
        for name,(fd,info) in held.items():C.need(signature((root/name).lstat())==signature(info),'configuration path changed during handoff')
    def write(fd,row,data):
        offset=0
        while offset<len(data):
            size=os.pwrite(fd,data[offset:],offset);C.need(size>0,'complete bounded configuration write');offset+=size
        os.ftruncate(fd,len(data))
        info=os.fstat(fd)
        if (info.st_uid,info.st_gid)!=(row['uid'],row['gid']):os.fchown(fd,row['uid'],row['gid'])
        os.fchmod(fd,row['mode']);os.fsync(fd)
    def create(name,row,data):
        absent(name);fd=os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:write(fd,row,data)
        finally:os.close(fd)
        observe(name,row,data);operations.append(dict(operation='CREATE_EXCLUSIVE_KNOWN_COPY',path=name))
    try:
        for path in (root.parent,root,root/'etc',root/FIXTURE):
            C.need(not any(p.is_symlink() for p in (path,*path.parents)),'ordinary configuration directory path')
            fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);descriptors.append(fd);s=os.fstat(fd)
            C.need(s.st_uid==os.geteuid() and not stat.S_IMODE(s.st_mode)&0o022,'owned nonwritable-by-others configuration directory')
            directories.append((path,fd,directory_identity(s)))
        directories_stable()
        allowed={saved,fresh,locale_saved};C.need(all('etc/'+p.name in allowed for p in (root/'etc').iterdir() if p.name.startswith(('gai.conf.','locale.gen.'))),'no unknown configuration sidecars')
        specs={saved:(before['nodes'][gai],wanted_gai),locale_saved:(before['nodes'][locale],wanted_locale)}
        specs[gai]=(new['nodes'][gai],new['data'][gai]) if phase=='provider' else ((old['nodes'][gai],old['data'][gai]) if phase=='rollback_finish' else (before['nodes'][gai],wanted_gai))
        if phase!='provider':specs[fresh]=(new['nodes'][gai],new['data'][gai])
        if phase=='rollback_finish':specs.update({stash:(before['nodes'][gai],wanted_gai),locale:(old['nodes'][locale],old['data'][locale])})
        else:absent(locale)
        if phase=='provider':absent(fresh)
        if phase!='rollback_finish':absent(stash)
        held={name:observe(name,*spec) for name,spec in specs.items()};C.need(len({(s.st_dev,s.st_ino) for _,s in held.values()})==len(held),'configuration paths must not alias');stable();initial=dict(observations);value['before']=initial
        if phase=='rollback_prepare':
            create(stash,before['nodes'][gai],wanted_gai);stable()
            os.unlink(root/saved);absent(saved);operations.append(dict(operation='UNLINK_PROVEN_BACKUP_AFTER_EXACT_STASH',path=saved,retained=stash))
        else:
            if phase=='provider':create(fresh,new['nodes'][gai],new['data'][gai]);stable()
            write(held[gai][0],before['nodes'][gai],wanted_gai);operations.append(dict(operation='RESTORE_ORIGINAL_ACTIVE_FROM_PROVEN_PACSAVE',path=gai,source=saved))
        final_specs=dict(specs)
        if phase=='rollback_prepare':del final_specs[saved];final_specs[stash]=(before['nodes'][gai],wanted_gai)
        else:
            final_specs[gai]=(before['nodes'][gai],wanted_gai)
            if phase=='provider':final_specs[fresh]=(new['nodes'][gai],new['data'][gai])
        observations={};value['after']=observations
        for name,spec in final_specs.items():observe(name,*spec)
        directories_stable();C.need(len({(r['device'],r['inode']) for r in observations.values()})==len(observations),'final configuration paths must not alias')
        value['status']='PASS_EXPLICIT_CLONE_CONFIG_HANDOFF';return value
    finally:
        for fd in reversed(descriptors):os.close(fd)


def copy_probes(root,index):
    # Only the new clone's '/' becomes searchable, after exact copy proof.
    C.need(root in (WORK/'pristine/root',WORK/'modified/root') and not any(p.is_symlink() for p in (root,*root.parents)), 'exact owned cloned chroot root only')
    descriptors=[]
    metadata=lambda info:dict(device=info.st_dev,inode=info.st_ino,mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid)
    try:
        for path in (root,root.parent,HELD):descriptors.append(os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC))
        before=[metadata(os.fstat(fd)) for fd in descriptors]
        C.need(all(stat.S_ISDIR(os.fstat(fd).st_mode) and row['uid']==os.geteuid() and row['mode']==0o700 and metadata(path.lstat())==row for fd,row,path in zip(descriptors,before,(root,root.parent,HELD))) and len({(r['device'],r['inode']) for r in before})==3,'original private clone/source/parent identities and modes')
        os.fchmod(descriptors[0],0o755)
        after=[metadata(os.fstat(fd)) for fd in descriptors]
        expected=[dict(before[0],mode=0o755),*before[1:]]
        C.need(after==expected and all(metadata(path.lstat())==row for path,row in zip((root,root.parent,HELD),after)),'only owned cloned root search metadata changed; source/parent unchanged')
        root_initialization=dict(status='PASS_CLONE_ROOT_ONLY_0700_TO_0755_AFTER_COPY_PROOF',path=str(root),before=before[0],after=after[0],parent_before=before[1],parent_after=after[1],source_before=before[2],source_after=after[2],source_mutation='NONE',payload_nodes_mutation='NONE_FOR_ROOT_MODE_INITIALIZATION')
    finally:
        for fd in reversed(descriptors):os.close(fd)
    directory=root/FIXTURE;directory.mkdir(mode=0o755,parents=True)
    for name,row in index['probes'].items():
        destination=directory/name;shutil.copyfile(INPUTS/row['path'],destination);destination.chmod(0o755 if name!='plugin.so' else 0o644)
    (directory/'latin1').write_bytes(b'A\xe9')
    (directory/'held.install').write_bytes(C.archive(INPUTS/index['held']['path'])['data']['.INSTALL'])
    user=root/USER;user.mkdir(mode=0o700,parents=True)
    for name in ('config','history','sentinel'):(user/name).write_bytes(('preserve '+name+'\n').encode())
    return root_initialization


def role_identities(root,expected):
    result={}
    for role,path in C.ROLES.items():
        file=root/path;actual=file.resolve(strict=True);C.need(actual.is_relative_to(root),'runtime role remains within owned root')
        s=actual.stat();row=expected['nodes'][actual.relative_to(root).as_posix()]
        C.need(C.sha(C.read(actual,64*1024**2))==row['sha256'],'actual installed role byte identity')
        result[role]=dict(path='/'+actual.relative_to(root).as_posix(),sha256=row['sha256'],inode=s.st_ino,device_major=os.major(s.st_dev),device_minor=os.minor(s.st_dev))
    return result


def validate_runtime(records,root,roles,expected):
    tests=[r for r in records if r.get('kind')=='test'];results=[r for r in records if r.get('kind')=='result'];identities=[r for r in records if r.get('kind')=='identity']
    C.need(len(records)==12 and len(tests)==9 and {r['name'] for r in tests if r['process']=='parent'}=={'allocation','dlopen_dlsym','pthread_tls_join','utf8_iconv_locale','numeric_math','fd_stat_clock_random','numeric_address_lookup','fork_exec_wait'} and all(r['status']=='PASS' for r in tests) and [r['name'] for r in tests if r['process']=='child']==['exec_child'],'all eight runtime cases and child')
    C.need(len(results)==1 and results[0]['status']=='PASS' and results[0]['cases']==8 and results[0]['page_size']==4096 and results[0]['glibc_version']=='2.43','actual generic4K runtime result')
    C.need(len(identities)==2 and {r['process'] for r in identities}=={'parent','child'},'parent/child identities')
    verified={}
    for group in identities:
        desired='/'+FIXTURE+'/'+('smoke-normal' if group['process']=='parent' else 'exec-child')
        C.need(group['executable']==desired,'normal executable, no explicit loader fallback')
        for field in ('objects','mapped_files'):
            C.need(1<=len(group[field])<=128,'bounded runtime maps')
            for item in group[field]:
                name=C.relative(item['path'].removeprefix('/'));file=(root/name).resolve(strict=True)
                C.need(file.is_relative_to(root) and '/opt/' not in item['path'],'normal rooted mapped path')
                s=file.stat();C.need(all(item[k]==v for k,v in [('inode',s.st_ino),('device_major',os.major(s.st_dev)),('device_minor',os.minor(s.st_dev))]),'actual mapping device/inode')
                digest=C.sha(C.read(file,64*1024**2));relative=file.relative_to(root).as_posix()
                if relative in expected['nodes'] and expected['nodes'][relative]['type']=='file':C.need(digest==expected['nodes'][relative]['sha256'],'mapped provider bytes')
                verified['/'+relative]=dict(sha256=digest,inode=s.st_ino,device_major=os.major(s.st_dev),device_minor=os.minor(s.st_dev))
        mapped={r['path'] for r in group['mapped_files']};objects={r['path'] for r in group['objects']}
        C.need({r['path'] for r in roles.values()}<=objects,'actual loader/libc/libm all loaded')
        C.need(len(group['providers'])==8,'exact eight symbol providers')
        for provider in group['providers']:C.need(provider['path']==roles['libm' if provider['symbol']=='cos' else 'libc']['path'],'actual symbol provider')
        C.need({p['symbol'] for p in group['providers']}=={'malloc','pthread_create','iconv_open','snprintf','getaddrinfo','clock_gettime','getrandom','cos'},'complete symbol providers')
        if group['process']=='parent':
            C.need(any(p.startswith('/usr/lib/gconv/') for p in mapped),'actual normal gconv mapping')
            C.need(any(p.startswith('/usr/lib/locale/') for p in mapped),'actual normal C.utf8 mapping')
    return dict(result=results[0],verified_mappings=verified,roles=roles,normal_parent_and_child=True)


def smoke(commands,root,index,expected,label):
    roles=role_identities(root,expected)
    C.need((root/'lib').is_symlink() and os.readlink(root/'lib')=='usr/lib','filesystem-owned conventional /lib link')
    for name in ('smoke-normal','exec-child'):C.interpreter(C.read(root/FIXTURE/name,4*1024**2))
    commands.inside(root,['/usr/bin/bash','--noprofile','--norc','-c','printf normal-system-shell'])
    actual=commands.inside(root,['/usr/bin/pacman','-Q']);C.need(len(actual.decode().splitlines())==574,'normal installed pacman574')
    locale=commands.inside(root,['/usr/bin/locale','-a']).decode();C.need(any(v.lower()=='c.utf8' for v in locale.splitlines()),'normal C.utf8 availability')
    C.need(commands.inside(root,['/usr/bin/iconv','-f','ISO-8859-1','-t','UTF-8','/'+FIXTURE+'/latin1'])==b'A\xc3\xa9','normal iconv conversion')
    work=root/FIXTURE/label;work.mkdir(mode=0o700);os.chown(work,65534,65534)
    output=commands.inside(root,['/'+FIXTURE+'/smoke-normal',roles['loader']['path'],'/usr/lib','/'+FIXTURE+'/plugin.so','/'+FIXTURE+'/exec-child','/'+FIXTURE+'/'+label],True)
    return validate_runtime([json.loads(l) for l in output.splitlines()],root,roles,expected)


def caches(commands,root):
    commands.inside(root,['/usr/bin/ldconfig']);commands.inside(root,['/usr/bin/iconvconfig'])
    result={}
    for name in sorted(C.CACHES):
        if name=='var/cache/ldconfig/aux-cache' and not (root/name).exists():continue
        raw=C.read(root/name,16*1024**2);C.need(raw,'nonempty explicit generated cache');result[name]=dict(bytes=len(raw),sha256=C.sha(raw))
    listing=commands.inside(root,['/usr/bin/ldconfig','-p']).decode()
    C.need('libc.so.6' in listing and '/usr/lib/libc.so.6' in listing and '/opt/' not in listing,'normal installed-provider cache listing')
    return result


def guard():
    C.need(os.geteuid()==os.getuid()==0 and platform.machine()=='aarch64' and Path('/.dockerenv').is_file() and os.environ.get('CACHY_GNU_PROVIDER_INTERRUPTION')=='1','explicit disposable native lifecycle container only')
    C.need({p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'offline namespace required')
    mounts=Path('/proc/self/mountinfo').read_text().splitlines()
    for path in ('/','/held','/source','/inputs'):
        matching=[line.split()[5].split(',') for line in mounts if line.split()[4]==path]
        C.need(matching and 'ro' in matching[-1],'read-only intact observer/source/input mount')


def run_case(api,commands,index,base,new,old,case,report):
    C.need(case in C.CASES,'exact configuration case')
    api['capability_checks']={};report['capability_checks']=api['capability_checks']
    api['root_observation_failures']={};report['root_observation_failures']=api['root_observation_failures']
    report['source_before']=C.sha(json.dumps(snapshot(api,HELD,case+'-source-before')['nodes'],sort_keys=True).encode())
    C.need(report['source_before']==index['source_nodes_sha256'],'frozen original574 source node snapshot')
    C.need(inventory(database(api,HELD))==base,'exact source574 database')
    lifetime=None;primary=None
    try:
        with api['capabilities'].copied_root(api,HELD,WORK/case,index,evidence=report.setdefault('copy_evidence',{}),limits=limits(api),cleanup_seconds=120) as (root,lifetime):
            initial=snapshot(api,root,case+'-clone');rows=database(api,root);C.need(inventory(rows)==base,'before574 clone')
            report['intersections']=collisions(new,rows)
            C.need(ownership(rows).get('lib')=='filesystem' and ownership(rows).get('usr/bin/tzselect')=='tzdata','filesystem/tzdata owners preserved')
            payload(initial['nodes'],old['nodes'],C.CACHES)
            for n in CONFIGS:C.need(not (root/n).exists() or n in ('etc/gai.conf','etc/locale.gen'),'fresh backup fixture sidecars')
            pristine_gai=C.read(root/'etc/gai.conf');pristine_locale=C.read(root/'etc/locale.gen')
            if case=='modified':
                (root/'etc/gai.conf').write_bytes(pristine_gai+b'\n# preserve modified gai\n')
                (root/'etc/locale.gen').write_bytes(pristine_locale+b'\n# preserve modified locale settings\n')
            wanted_gai=C.read(root/'etc/gai.conf');wanted_locale=C.read(root/'etc/locale.gen')
            C.need(lifetime['copy']['copy_byte_identical_before_initialization'] is True,'complete clone byte identity before deliberate runtime root initialization')
            report['root_initialization']=copy_probes(root,index);before=snapshot(api,root,case+'-before574')
            # Prepared add/remove is deliberately released without commit. No sole-provider removal.
            report['precommit_refusal']=transaction(api,root,INPUTS/index['archives']['a']['path'],'glibc',C.NAME,OUT/(case+'-prepare.log'),True)
            C.need(same(before,snapshot(api,root,case+'-precommit-refused')),'precommit refusal preserves complete DB/payload')
            with runtime_mounts(commands,root):report['before_runtime']=smoke(commands,root,index,old,'before')
            import interruption
            report['interruption']={}
            interruption.exercise(api,sys.modules[__name__],root,index,base,new,old,before,case,report['interruption'])
            with runtime_mounts(commands,root):
                output=commands.inside(root,['/usr/bin/bash','--noprofile','--norc','-e','-x','-c','source /'+FIXTURE+'/held.install; post_upgrade "$1" "$2"','held-recovery-post-upgrade',base['glibc'],base['glibc']])
                report['recovered_post_upgrade']=dict(status='PASS_EXPLICIT_RETAINED_POST_UPGRADE_AFTER_INTERRUPTED_REINSTALL',sha256=C.sha(old['data']['.INSTALL']),stdout_sha256=C.sha(output))
                report['recovered_cache']=caches(commands,root)
                report['recovered_runtime']=smoke(commands,root,index,old,'recovered')
            report['replace']=transaction(api,root,INPUTS/index['archives']['a']['path'],'glibc',C.NAME,OUT/(case+'-replace.log'))
            expected=dict(base);del expected['glibc'];expected[C.NAME]=C.VERSION
            C.need(inventory(database(api,root))==expected and len(expected)==574,'provider574 exact inventory')
            if case=='modified':report['provider_config_handoff']=config_handoff(root,before,new,old,wanted_gai,wanted_locale,'provider',evidence=report.setdefault('provider_config_handoff',{}))
            after=snapshot(api,root,case+'-provider574');payload(after['nodes'],new['nodes'],('etc/gai.conf',))
            for name,row in old['nodes'].items():
                if name not in new['nodes'] and row['type']!='directory' and name not in C.CACHES:
                    C.need(name not in after['nodes'],'held-only file removed before provider runtime: '+name)
            C.need(not (root/'usr/bin/locale-gen').exists() and not (root/'etc/locale.gen').exists(),'provider intentionally excludes locale-gen and old locale.gen')
            if case=='modified':
                C.need(C.read(root/'etc/gai.conf')==wanted_gai and C.read(root/'etc/locale.gen.pacsave')==wanted_locale,'modified gai preservation/locale.gen pacsave')
                C.need(after['nodes']['etc/gai.conf']==before['nodes']['etc/gai.conf'] and after['nodes']['etc/locale.gen.pacsave']==before['nodes']['etc/locale.gen'],'backup contents/mode/uid/gid preserved')
                if new['data']['etc/gai.conf']!=pristine_gai:C.need(C.read(root/'etc/gai.conf.pacnew')==new['data']['etc/gai.conf'],'new default gai.pacnew')
            else:
                C.need(C.read(root/'etc/gai.conf')==new['data']['etc/gai.conf'] and not (root/'etc/locale.gen.pacsave').exists(),'pristine backup behavior')
            stable_configs=configs(root)
            with runtime_mounts(commands,root):
                report['provider_cache']=caches(commands,root);report['provider_runtime']=smoke(commands,root,index,new,'provider')
            report['reinstall']=transaction(api,root,INPUTS/index['archives']['b']['path'],C.NAME,C.NAME,OUT/(case+'-reinstall.log'))
            C.need(inventory(database(api,root))==expected and configs(root)==stable_configs,'byte-identical reinstall preserves provider574 and config backups')
            with runtime_mounts(commands,root):
                report['reinstalled_cache']=caches(commands,root);report['reinstalled_runtime']=smoke(commands,root,index,new,'reinstalled')
            reinstalled=snapshot(api,root,case+'-reinstalled574');report['provider_preservation']=unchanged(before,reinstalled,old,new,base['glibc'])
            # Recovery is performed from intact OUTER libc/ALPM, never target loader.
            if case=='modified':report['rollback_config_prepare']=config_handoff(root,before,new,old,wanted_gai,wanted_locale,'rollback_prepare',evidence=report.setdefault('rollback_config_prepare',{}))
            report['external_rollback']=transaction(api,root,INPUTS/index['held']['path'],C.NAME,'glibc',OUT/(case+'-rollback.log'))
            C.need(inventory(database(api,root))==base,'held574 database restored')
            if case=='modified':report['rollback_config_handoff']=config_handoff(root,before,new,old,wanted_gai,wanted_locale,'rollback_finish',evidence=report.setdefault('rollback_config_handoff',{}))
            with runtime_mounts(commands,root):
                C.need((root/'usr/bin/locale-gen').is_file(),'held locale-gen restored before actual held scriptlet')
                output=commands.inside(root,['/usr/bin/bash','--noprofile','--norc','-e','-x','-c','source /'+FIXTURE+'/held.install; post_upgrade "$1" "$2"','held-post-upgrade',base['glibc'],C.VERSION])
                report['held_post_upgrade']=dict(status='PASS_EXPLICIT_RETAINED_POST_UPGRADE_AFTER_CONFLICT_RESTORE',sha256=C.sha(old['data']['.INSTALL']),stdout_sha256=C.sha(output),automatic_post_install='NOT_DEFINED_BY_HELD_SCRIPTLET')
                report['held_cache']=caches(commands,root);report['held_runtime']=smoke(commands,root,index,old,'held')
            final=snapshot(api,root,case+'-held574');payload(final['nodes'],old['nodes'],C.CACHES|{'etc/gai.conf','etc/locale.gen'})
            for name,row in new['nodes'].items():
                if name not in old['nodes'] and row['type']!='directory' and name not in C.CACHES:
                    C.need(name not in final['nodes'],'candidate-only file removed after restoration: '+name)
            C.need(C.read(root/'etc/gai.conf')==(wanted_gai if case=='modified' else pristine_gai),'gai restored/preserved')
            C.need(C.read(root/'etc/locale.gen')==pristine_locale,'held locale.gen default restored')
            if case=='modified':C.need(C.read(root/'etc/locale.gen.pacsave')==wanted_locale,'original modified locale.gen retained in pacsave')
            report['final_preservation']=unchanged(before,final,old,new,base['glibc'])
            C.need(ownership(database(api,root)).get('lib')=='filesystem' and ownership(database(api,root)).get('usr/bin/tzselect')=='tzdata','final platform-neutral held ownership')
            C.need({n:v for n,v in before['nodes'].items() if n.startswith(USER+'/')}=={n:v for n,v in final['nodes'].items() if n.startswith(USER+'/')},'all seeded user data preserved')
            report['status']='PASS_INTERRUPTED_RECOVERED_NORMAL_PROVIDER_SEQUENCE'
    except BaseException as error:
        primary=error;report['primary_failure']=api['capabilities'].failure(error)
        raise
    finally:
        if lifetime is None:lifetime=report.get('copy_evidence',{}).get('lifetime')
        report['copy_lifetime']=lifetime
        try:
            after=snapshot(api,HELD,case+'-source-after')
            report['source_after']=C.sha(json.dumps(after['nodes'],sort_keys=True).encode())
            C.need(report['source_before']==report['source_after'],'original readonly source node map preserved')
            C.need(lifetime is not None and lifetime['cleanup']=='PASS-owned-workspace-removed' and not (WORK/case).exists(),'complete clone cleanup verified')
            report['clone_cleanup_check']='PASS'
        except BaseException as error:
            report['clone_cleanup_check']='FAIL_OR_UNESTABLISHED'
            report['cleanup_failure']=api['capabilities'].failure(error)
            if primary is None:raise
            primary.add_note('source/clone cleanup verification also failed; see cleanup_failure; acceptance refused')


def main():
    guard();index,base,new,old=C.configuration(INPUTS,os.environ['INPUT_INDEX_SHA256']);api=C.helpers(SOURCE)
    api['capability_index']=index;api['capabilities'].disjoint(index,old,new)
    os.chown(WORK,0,0);WORK.chmod(0o700)
    report=dict(status='FAIL',scope='OWNED_CONVENTIONAL_GNU_PROVIDER_GENERIC_ARM_ONLY',commands=[],cases={},hardware='NOT_RUN',security_release_admission=False,Asahi='NOT_RUN',generic16K_provider='NOT_RUN',interrupted_in_progress_replacement='REMOVE_PHASE_ONLY_CANDIDATE_EXTRACTION_NOT_TESTED')
    commands=Commands(api,report)
    try:
        if os.environ.get('GNU_TRIAL_APPARMOR_PROFILE'):
            apparmor=C.load('trial_apparmor_inside',SOURCE/'scripts/ci/glibc-gnu-trial-apparmor/profile.py')
            report['apparmor']=apparmor.inside(index['token'],'interruption')
        report['proc_preflight']=api['proc_probe'].check(commands,WORK)
        C.need(report['proc_preflight']['status']=='PASS_READONLY_PROC_PREFLIGHT' and report['proc_preflight']['cleanup']=='PASS_OWNED_EMPTY_PROBE_REMOVED','readonly proc preflight failed; see proc_preflight')
        for case in C.CASES:
            report['cases'][case]={};run_case(api,commands,index,base,new,old,case,report['cases'][case])
        C.need(not any(WORK.iterdir()),'no lifecycle root remains')
        report['status']='PASS_GENERIC_ARM_PROVIDER_INTERRUPTION_RECOVERY'
    except BaseException as error:report.update(error_type=type(error).__name__,error=str(error)[:512])
    finally:
        (OUT/'result.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
        uid,gid=int(os.environ['OUTPUT_UID']),int(os.environ['OUTPUT_GID'])
        for path in OUT.iterdir():
            C.need(path.is_file() and not path.is_symlink(),'closed ordinary evidence files');os.chown(path,uid,gid)
        os.chown(WORK,uid,gid)
    return int(report['status']!='PASS_GENERIC_ARM_PROVIDER_INTERRUPTION_RECOVERY')

if __name__=='__main__':
    def cancelled(*_):raise KeyboardInterrupt()
    for sig in (signal.SIGINT,signal.SIGTERM):signal.signal(sig,cancelled)
    raise SystemExit(main())
