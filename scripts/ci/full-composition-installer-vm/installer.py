#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generic-VM-only fresh initial587 transaction through the held installer barrier."""
import argparse
import ctypes as C
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

sys.path.insert(0,str(Path(__file__).absolute().parent))
import profile as p
import numeric_vm as numeric

SHARED=p.SHARED
TRIAL=Path('/var/lib/full-installer/trial')
FIXTURES={'home/installer-user/.config/preservation.txt':b'full-installer-user-fixture-v1\n',
          'etc/cachy-asahi-installer-preserve.fixture':b'full-installer-config-fixture-v1\n'}
PASS='PASS_FULL_COMPOSITION_INSTALLER'


def source_modules(profile):
    code=SHARED/'code'; sys.path.insert(0,str(code/'scripts/update'))
    roots=p.load('full_root',code/'scripts/update/full_root.py')
    driver=p.load('_installer_database',code/'scripts/ci/full-root-upgrade/root_upgrade.py')
    aux=p.load('aux_checkpoint',code/'scripts/update/aux_checkpoint.py')
    return roots,roots.installer,driver,aux


def checked_inputs(*, protected):
    contract_path=SHARED/'contract.json'
    p.need(contract_path.stat().st_size<=1024**2,'VM contract byte bound')
    p.checked(SHARED,'contract.json',p.reference(contract_path),maximum=1024**2,protected=protected)
    c=p.decode(contract_path.read_bytes())
    p.need(c['schema_version']==1 and c['purpose']=='full-composition-installer-vm' and
           re.fullmatch('[0-9a-f]{32}',c['nonce']) and re.fullmatch('[0-9a-f]{40}',c['source_commit']), 'VM contract identity differs')
    for name in ('guest.py','installer.py','profile.py','numeric_vm.py','installer-profile.json','payload.json'):
        p.checked(SHARED,name,c['runner_files'][name],maximum=p.MAX_JSON,protected=protected)
    profile=p.decode((SHARED/'installer-profile.json').read_bytes())
    p.need(profile['schema_version']==1 and profile['purpose']==c['purpose'] and profile['architecture']=='aarch64'
           and profile['expected_lock_sha256']==p.EXPECTED and profile['limits']==dict(packages=587,nodes=200000,
               bytes=6*p.GIB,file_bytes=p.GIB,seconds=4500), 'full profile selection differs')
    p.need(profile['code_files']==c['code_files'],'guest source closure differs')
    for name,row in profile['code_files'].items(): p.checked(SHARED/'code',name,row,maximum=2*1024**2,protected=protected)
    p.checked(SHARED/'input','manifest.json',profile['manifest'],maximum=1024**2,protected=protected)
    value,_,expected=p.manifest(SHARED/'input',protected=protected)
    p.need(profile['expected']==expected,'profile/package map differs')
    p.checked(SHARED,'payload.json',profile['payload'],maximum=p.MAX_JSON,protected=protected)
    payload=p.decode((SHARED/'payload.json').read_bytes())
    p.need(payload['schema_version']==1 and len(payload['nodes'])<=200000 and
           set(payload['ownership'])==set(expected) and payload['packages']==expected,'payload map/count differs')
    held=p.constants(SHARED/'code/scripts/virtual/common.py',{'TRANSACTION_PROFILE_BYTES'})['TRANSACTION_PROFILE_BYTES']
    p.need(p.encoded(profile.get('derived_output_binding'))==p.encoded(p.soname_selection(value,payload,SHARED/'code')),'held SONAME output selection differs')
    p.validate_tools(profile,value,payload,c['builder_inventory'],held)
    p.need(c['tooling_inventory'].get('sqlite')=='3.54.0-1','preserved tooling SQLite inventory differs')
    return c,profile,value,payload


def ordinary_preflight(namespace_fd=None,lease_sha256=None):
    p.need(sys.platform=='linux' and os.uname().machine=='aarch64' and
           os.uname().release=='7.2.10-1-aarch64-ARCH' and os.sysconf('SC_PAGE_SIZE')==4096 and
           os.getuid()==os.geteuid()==os.getgid()==os.getegid()==23001 and os.getgroups()==[],
           'ordinary generic4K guest required')
    p.need('cachy_asahi_virtual_proof=1' in Path('/proc/cmdline').read_text().split(),'actual VM marker missing')
    p.need(not any(os.getenv(k) for k in ('LD_PRELOAD','LD_LIBRARY_PATH','PYTHONPATH','DISPLAY','WAYLAND_DISPLAY',
                'DBUS_SESSION_BUS_ADDRESS','PULSE_SERVER','PIPEWIRE_REMOTE')),'external execution environment refused')
    status={k:v.strip() for k,v in (line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)}
    p.need(status.get('NoNewPrivs')=='1' and all(int(status.get(k,'-1'),16)==0 for k in
           ('CapEff','CapPrm','CapInh','CapAmb','CapBnd')),'ordinary parent NNP/cap0 required')
    c,profile,value,payload=checked_inputs(protected=True)
    if namespace_fd is None:
        p.require_single_id_backend(payload)
        p.need('numeric_vm' not in profile and lease_sha256 is None,'selected numeric backend requires its retained namespace')
    else:
        p.need(type(namespace_fd) is int and namespace_fd>=3 and type(lease_sha256) is str and
               re.fullmatch('[0-9a-f]{64}',lease_sha256),'numeric namespace descriptor/lease required')
        numeric.checked_lease(p,namespace_fd,lease_sha256,c,profile)
    roots,base,driver,aux=source_modules(profile)
    tools=profile['tools']
    # JSON formatting is not reinterpreted as authority: compare its semantic map
    # with the source-held exact bytes before examining the actual tools.
    held=p.constants(SHARED/'code/scripts/virtual/common.py',{'TRANSACTION_PROFILE_BYTES','TRANSACTION_LAUNCHER'})
    p.need(p.coherent_tools(held['TRANSACTION_PROFILE_BYTES'])==tools and
           hashlib.sha256(held['TRANSACTION_PROFILE_BYTES']).hexdigest()==base.NATIVE_PROFILE_SHA==profile['base_tool_profile_sha256'] and
           profile['tool_profile_sha256']==p.COHERENT_TOOL_PROFILE_SHA, 'held tool profile differs')
    p.need(tools['architecture']=='aarch64' and tools['libalpm_expected_abi']=='16.0.1' and len(tools['files'])==136,'tool roles differ')
    for alias,target in tools['aliases'].items(): p.need(str(Path(alias).resolve(strict=True))==target,'tool alias differs')
    for row in tools['files']:
        raw=base.generic_readonly(row['path'],row['size'],row['sha256'],64*1024**2,single=False)
        if row['path']==p.NEW_SQLITE['path']:p.sqlite_elf(raw)
    for alias,target in profile['launcher']['aliases'].items(): p.need(str(Path(alias).resolve(strict=True))==target,'launcher alias differs')
    for name,row in profile['launcher']['files'].items():
        p.checked(Path('/'),name.lstrip('/'),row,maximum=64*1024**2,protected=True)
    p.need(not Path('/etc/ld.so.preload').exists() and not Path('/etc/ld.so.preload').is_symlink(),'preload refused')
    return c,profile,value,payload,roots,base,driver,aux


FD_LOADER = r"""import os,sys,stat,fcntl,json
parent=int(sys.argv[1]); refs=json.loads(sys.argv[2]); args=sys.argv[3:]
assert os.getppid()==parent
for row in refs:
 fd=os.open('/proc/%d/fd/%d'%(parent,row['fd']),os.O_RDONLY|os.O_CLOEXEC)
 info=os.fstat(fd)
 assert (info.st_dev,info.st_ino)==tuple(row['identity'])
 if row['kind']=='sealed':
  assert stat.S_ISREG(info.st_mode) and fcntl.fcntl(fd,fcntl.F_GET_SEALS)&15==15
 elif row['kind']=='directory': assert stat.S_ISDIR(info.st_mode)
 else:
  import array
  owner=array.array('I',[0]); assert row['kind']=='namespace' and fcntl.ioctl(fd,0xb703)==0x10000000
  fcntl.ioctl(fd,0xb704,owner,True); assert owner[0]==23001
 os.set_inheritable(fd,True); args[args.index(row['token'])]=str(fd)
os.execve(args[0],args,dict(os.environ))
"""


def fd_transfer(argv, descriptors, namespace_fd=None):
    p.need(len(descriptors)==2 and len(set(descriptors))==2,'exact spec/evidence FD pair required')
    refs=list(zip(descriptors,('sealed','directory'),('SPEC_FD','EVIDENCE_FD')))
    if namespace_fd is not None:
        p.need(namespace_fd not in descriptors,'distinct numeric namespace descriptor required')
        numeric.namespace_identity(namespace_fd);refs.append((namespace_fd,'namespace','NAMESPACE_FD'))
    return transfer_refs(argv,refs)


def namespace_transfer(argv,fd):
    numeric.namespace_identity(fd)
    return transfer_refs(argv,[(fd,'namespace','NAMESPACE_FD')])


def transfer_refs(argv,refs):
    rows=[]; args=list(argv)
    for fd,kind,token in refs:
        info=os.fstat(fd)
        p.need((kind=='sealed' and stat.S_ISREG(info.st_mode) and fcntl.fcntl(fd,fcntl.F_GET_SEALS)&15==15) or
               (kind=='directory' and stat.S_ISDIR(info.st_mode)) or
               (kind=='namespace' and numeric.namespace_identity(fd)==[info.st_dev,info.st_ino]),'FD transfer shape/seal differs')
        p.need(args.count(str(fd))==1,'exact one descriptor argument required')
        args[args.index(str(fd))]=token
        rows.append(dict(fd=fd,kind=kind,token=token,identity=[info.st_dev,info.st_ino]))
    return ['/usr/bin/python3','-I','-B','-c',FD_LOADER,str(os.getpid()),json.dumps(rows),*args]


def supervise(argv, *, env, timeout, pass_fds=(), namespace_fd=None, limit=1024**2):
    """Reuse the held cancellation, subreaper, group cleanup and output bounds.

    Its closed-FD worker borrows only the parent's retained exact spec/evidence
    descriptions through the same proc-FD transfer used by the tiny installer.
    """
    p.need(0<timeout<=4800,'finite guest child deadline')
    runtime_path=SHARED/'code/scripts/port/kernel-native-job/runtime.py'
    c=p.decode((SHARED/'contract.json').read_bytes())
    ref=c['code_files']['scripts/port/kernel-native-job/runtime.py']
    p.checked(SHARED/'code','scripts/port/kernel-native-job/runtime.py',ref,maximum=128*1024,protected=True)
    runtime=numeric.process_binding(p.load('_full_installer_process_runtime',runtime_path))
    if pass_fds: argv=fd_transfer(argv,pass_fds,namespace_fd)
    elif namespace_fd is not None: argv=namespace_transfer(argv,namespace_fd)
    logs=Path(env['TMPDIR'])/('guest-supervisor' if os.getuid()==0 else 'engine-supervisor')
    with runtime.cancellation_handlers():
        row=runtime.Runner(timeout,env,logs).run(argv,timeout=timeout,limit=limit)
    # The held Runner returns only after reserved-group cleanup and output drain.
    return dict(returncode=row.returncode,termination=None,direct_child_reaped=True,
                group_retired=True,output=row.stdout)


# The retained namespace is owned by the ordinary UID. Joining it creates no
# authority in the initial VM namespace; the held mount/proc/seccomp barrier still follows.
NAMESPACE_ENTRY = """import os,sys
fd=int(sys.argv[1]); os.setns(fd,0x10000000); os.close(fd)
os.execve(sys.argv[2],sys.argv[2:],dict(os.environ))
"""


def engine_argv(spec_fd,pin,evidence_fd,namespace_fd=None):
    flags=['--mount','--pid','--mount-proc','--net','--fork','--kill-child=SIGKILL','--']
    inner=['/usr/bin/unshare']+([] if namespace_fd is not None else ['--user','--map-root-user'])+flags+[
        '/usr/bin/python3','-I','-B',str(SHARED/'installer.py'),'engine','--spec-fd',str(spec_fd),
        '--spec-sha256',pin,'--evidence-fd',str(evidence_fd)]
    if namespace_fd is not None:
        return ['/usr/bin/python3','-I','-B','-c',NAMESPACE_ENTRY,str(namespace_fd),*inner]
    return inner


def soname_observation(observation):
    # One exact known pathname; no file content or arbitrary tree dump is exported.
    value={name:observation['nodes'].get(name,{'type':'absent'}) for name in p.SONAME_OUTPUTS}
    p.need(len(p.encoded(value))<=8192,'SONAME observation diagnostic byte bound')
    return value


def compare_payload(observation,payload,*,derived_output_binding=None):
    p.need(observation['complete'] and set(observation['unsupported_counts']) <= {'absolute-symlink','auxiliary-present'}, 'full root observation incomplete/unsupported')
    nodes=observation['nodes']
    for name,expected in payload['nodes'].items():
        actual=nodes.get(name)
        p.need(actual is not None and {k:v for k,v in actual.items() if k!='hardlink_group'}==expected,'installed payload differs: '+name)
    actual_groups=sorted(sorted(row['members']) for row in observation.get('hardlink_groups',{}).values())
    p.need(actual_groups==payload['hardlinks'],'installed hardlink groups differ')
    for name,data in FIXTURES.items():
        p.need(nodes.get(name)==dict(type='file',mode=0o600,uid=0,gid=0,bytes=len(data),sha256=hashlib.sha256(data).hexdigest()), 'preservation fixture differs')
    derived={}
    if derived_output_binding is not None:
        p.need(p.encoded(derived_output_binding)==p.encoded(p.soname_binding(payload)),'explicit held SONAME selection required')
        derived=derived_output_binding['outputs']
        for name,expected in derived.items():
            p.need(nodes.get(name)==expected,'derived installed output differs: '+name)
    generated=set(derived) | {'etc/ld.so.cache','var/cache/ldconfig/aux-cache','var/lib/pacman/local/ALPM_DB_VERSION'}
    for name,version in payload.get('packages',{}).items():
        generated.update('var/lib/pacman/local/'+name+'-'+version+'/'+part for part in ('desc','files','mtree','install'))
    directories=set()
    for name in set(payload['nodes']) | set(FIXTURES) | generated:
        parent=name.rpartition('/')[0]
        while parent:
            directories.add(parent); parent=parent.rpartition('/')[0]
    # The default still admits only DB/cache products. This lane may additionally
    # select the exact preprojected SONAME map after full typed-node equality.
    for name,node in nodes.items():
        if name in payload['nodes'] or name in FIXTURES: continue
        if node['type']=='directory':
            p.need(name in directories,'unexpected installed directory: '+name); continue
        p.need(name in generated,'unexpected installed output: '+name)
    return True


def engine(spec_fd,spec_pin,evidence_fd):
    fd=int(spec_fd)
    p.need(fcntl.fcntl(fd,fcntl.F_GET_SEALS)&15==15,'sealed engine spec required')
    os.lseek(fd,0,os.SEEK_SET); raw=os.read(fd,1024**2+1); os.close(fd)
    p.need(len(raw)<=1024**2 and hashlib.sha256(raw).hexdigest()==spec_pin,'sealed engine spec differs')
    spec=p.decode(raw); c,profile,value,payload=checked_inputs(protected=False)
    p.need(spec['profile_sha256']==p.sha(SHARED/'installer-profile.json') and spec['nonce']==c['nonce'] and
           0 < spec['deadline']-time.monotonic() <= 4500,'engine selection/deadline differs')
    roots,base,driver,aux=source_modules(profile)
    if profile.get('numeric_vm') is not None:
        p.need(spec.get('fixture_identity_map')==profile['numeric_vm']==numeric.SELECTION and
               spec.get('namespace_identity')==[Path('/proc/self/ns/user').stat().st_dev,Path('/proc/self/ns/user').stat().st_ino],
               'actual engine numeric namespace differs')
    else:p.need('fixture_identity_map' not in spec,'unselected engine numeric mapping')
    base.INHERITED_EVIDENCE_FD=int(evidence_fd); base.TASK_DEADLINE=spec['deadline']
    workspace=base.isolate(spec); evidence=base.OWNED_OUTPUT
    result=dict(status='FAIL',phase='isolated',commit_started=False,committed=False,hardware='NOT RUN',
        production_installation='NOT RUN',native_container_P0='UNCHANGED-FAILED',namespace_barrier=True,
        hooks='DISABLED',scriptlets='DISABLED',auxiliary_execution='ALPM may invoke pinned target ldconfig; exit NOT OBSERVED',
        expected_lock_sha256=p.EXPECTED,package_count=587,nonce=c['nonce'],profile_sha256=spec['profile_sha256'])
    evidence.save('result.json',result)
    base.reduce_capabilities(fixture_identity_map=spec.get('fixture_identity_map'))
    root=evidence.path/'target'; keys=workspace/'gpg'; keys.mkdir(mode=0o700)
    env=base.environment(HOME=str(workspace),GNUPGHOME=str(keys),TMPDIR=str(workspace))
    runner=base.runtime().Runner(spec['deadline']-time.monotonic(),env,workspace/'logs')
    def command(argv):
        row=runner.run(argv,timeout=60,limit=1024**2)
        p.need(row.returncode==0,'private authentication command failed'); return row.stdout
    alpm=None
    try:
        p.need(not root.exists(),'fresh target required'); root.mkdir(mode=0o700)
        info=root.stat();result['target_identity']=[info.st_dev,info.st_ino]
        for name,data in FIXTURES.items():
            p.need(name not in payload['nodes'],'preservation fixture intersects package payload')
            target=root/name; target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes(data); target.chmod(0o600)
        reserve=sum(row.get('bytes',0) for row in payload['nodes'].values())+512*1024**2
        fs=os.statvfs(evidence.path)
        p.need(fs.f_bavail*fs.f_frsize>=reserve and fs.f_favail>=len(payload['nodes'])+10000,'measured target capacity insufficient')
        result['capacity']=dict(required_bytes=reserve,free_bytes=fs.f_bavail*fs.f_frsize,free_inodes=fs.f_favail)
        gpg=['/usr/bin/gpg','--batch','--no-options','--no-autostart','--homedir',str(keys),'--no-auto-key-retrieve']
        for key in value['keyrings']: command(gpg+['--import',str(SHARED/'input'/key['path'])])
        base.public_keyring_only(command(gpg+['--with-colons','--list-secret-keys']),keys)
        trust=workspace/'ownertrust'; trust.write_text(''.join(s+':6:\n' for s in sorted({r['signer'] for r in value['packages']})))
        command(gpg+['--import-ownertrust',str(trust)])
        for row in value['packages']:
            base.tick(); status=command(gpg+['--status-fd','1','--verify',str(SHARED/'input'/row['signature']),str(SHARED/'input'/row['archive'])]).decode()
            valid=[line.split()[2:] for line in status.splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
            p.need(len(valid)==1 and len(valid[0])==10 and base.FPR.fullmatch(valid[0][0]) and
                   valid[0][-1]==row['signer'] and valid[0][7] in {'8','9','10','11'} and not
                   re.search(r'\[GNUPG:\] (BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG|KEYREVOKED|NO_PUBKEY|NODATA|FAILURE|ERROR)',status),'package signature refused')
        limits=roots.Limits(deadline=spec['deadline'],max_nodes=200000,max_bytes=6*p.GIB,max_file_bytes=p.GIB,max_package_files=500000)
        alpm=roots.Alpm(root,keys,evidence.path/'alpm.log','aarch64',limits=limits)
        p.need(alpm.inventory()=={},'fresh target inventory must be empty')
        alpm.ok(alpm.alpm_trans_init(alpm.handle,base.FLAGS),'transaction init'); alpm.started=True
        result['phase']='prepare'; evidence.save('result.json',result)
        for row in value['packages']:
            base.tick(); package=C.c_void_p()
            alpm.ok(alpm.alpm_pkg_load(alpm.handle,os.fsencode(SHARED/'input'/row['archive']),1,1,C.byref(package)),'signed package load')
            p.need(alpm.alpm_pkg_get_name(package).decode()==row['name'] and alpm.alpm_pkg_get_version(package).decode()==row['version'] and
                   alpm.alpm_pkg_get_arch(package) in (b'any',b'aarch64'),'loaded package identity differs')
            alpm.ok(alpm.alpm_add_pkg(alpm.handle,package),'add package')
        details=base.Ptr(); alpm.ok(alpm.alpm_trans_prepare(alpm.handle,C.byref(details)),'actual prepare')
        p.need(alpm.packages(alpm.alpm_trans_get_add(alpm.handle))==profile['expected'] and
               alpm.packages(alpm.alpm_trans_get_remove(alpm.handle))=={},'prepared package map differs')
        result.update(phase='commit',commit_started=True); evidence.save('result.json',result)
        details=base.Ptr(); alpm.ok(alpm.alpm_trans_commit(alpm.handle,C.byref(details)),'actual commit')
        result['committed']=True; alpm.close(); alpm=roots.Alpm(root,keys,evidence.path/'alpm.log','aarch64',limits=limits)
        p.need(alpm.inventory()==profile['expected'],'reopened installed package map differs')
        for name,paths in payload['ownership'].items(): p.need(alpm.owned_files([name])==set(paths),'installed package ownership differs: '+name)
        observed=roots.observe(root,limits=limits,hardlinks='generic-development-internal')
        result['derived_output_observation']=soname_observation(observed);evidence.save('result.json',result)
        compare_payload(observed,payload,derived_output_binding=profile.get('derived_output_binding'))
        db=driver.database(root,max_packages=587,max_files=500000,max_nodes=1000000,observed=observed['nodes'])
        p.need({r['name']:r['version'] for r in db}==profile['expected'],'real installed database differs')
        for row in db:
            files={n for n in payload['ownership'][row['name']] if payload['nodes'][n]['type']!='directory'}
            p.need(set(row['files'])==files,'database ownership differs: '+row['name'])
        state=aux.checkpoint(root,observed,limits)
        comparator=aux.load_comparator(SHARED/'code/scripts/ci/full-development-composition/audio_aux.py',limits)
        live=aux.live_keys(state,comparator)
        lock=''.join(n+' '+v+'\n' for n,v in sorted(alpm.inventory().items())).encode()
        p.need(hashlib.sha256(lock).hexdigest()==p.EXPECTED,'actual installed lock hash differs')
        evidence.write('candidate-packages.lock',lock)
        result.update(status='PROVISIONAL_FULL_COMPOSITION_INSTALLER',phase='complete',payload_verified=True,
            ownership_verified=True,database_verified=True,preservation_verified=True,private_trust_verified=True,derived_outputs_verified=True,
            target_footprint=observed['footprint'],live_cache_keys=live)
    except BaseException as error:
        result.update(status='FAIL',error_type=type(error).__name__,error=str(error)[:512],
                      committed=result['committed'] if not result['commit_started'] or result['committed'] else 'UNKNOWN')
    finally:
        if alpm is not None: alpm.close()
        evidence.save('result.json',result); evidence.close()
    return int(result['status']!='PROVISIONAL_FULL_COMPOSITION_INSTALLER')


def execute(namespace_fd=None,lease_sha256=None):
    c,profile,value,payload,roots,base,driver,aux=ordinary_preflight(namespace_fd,lease_sha256)
    p.need(TRIAL.is_dir() and TRIAL.stat().st_uid==23001 and stat.S_IMODE(TRIAL.stat().st_mode)==0o700,'guest disk workspace differs')
    workspace=TRIAL/'work'; workspace.mkdir(mode=0o700); output=workspace/'evidence'; output.mkdir(mode=0o700)
    evidence=base.Evidence(output); spec_fd=None
    result=dict(status='FAIL',phase='parent',committed=False,hardware='NOT RUN')
    try:
        evidence.save('result.json',result); evidence.write('candidate-packages.lock',b'')
        before=driver.database(Path('/'),max_packages=1024,max_files=500000,max_nodes=1000000)
        p.need({r['name']:r['version'] for r in before}==c['tooling_inventory'],'guest builder/tooling inventory differs')
        spec=dict(contract=dict(architecture='aarch64',workspace=str(workspace)),host_uid=os.getuid(),
            host_namespaces=base.namespaces(),evidence_identity=list(evidence.identity),
            evidence_nodes={name:evidence.node_identity(name) for name in ('result.json','candidate-packages.lock')},
            deadline=time.monotonic()+4500,nonce=c['nonce'],profile_sha256=p.sha(SHARED/'installer-profile.json'))
        if namespace_fd is not None:
            lease=numeric.checked_lease(p,namespace_fd,lease_sha256,c,profile)
            spec.update(fixture_identity_map=profile['numeric_vm'],namespace_identity=lease['namespace_identity'])
            spec['contract']['purpose']=numeric.PURPOSE
        raw=p.encoded(spec); spec_fd=os.memfd_create('full-installer-spec',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
        p.need(os.write(spec_fd,raw)==len(raw),'engine spec short write'); os.fchmod(spec_fd,0o400)
        fcntl.fcntl(spec_fd,fcntl.F_ADD_SEALS,15)
        argv=engine_argv(spec_fd,hashlib.sha256(raw).hexdigest(),evidence.fd,namespace_fd)
        receipt=supervise(argv,env=base.environment(HOME=str(TRIAL),TMPDIR=str(TRIAL)),timeout=4550,
                          pass_fds=(spec_fd,evidence.fd),namespace_fd=namespace_fd)
        evidence.check(); result=p.decode((evidence.view()/'result.json').read_bytes())
        p.need(receipt['returncode']==0 and receipt['termination'] is None and receipt['direct_child_reaped'] and
               receipt['group_retired'] and result['status']=='PROVISIONAL_FULL_COMPOSITION_INSTALLER' and
               result['nonce']==c['nonce'] and result['profile_sha256']==spec['profile_sha256'],'guarded engine incomplete')
        candidate=(evidence.view()/'candidate-packages.lock').read_bytes()
        p.need(hashlib.sha256(candidate).hexdigest()==p.EXPECTED,'candidate lock differs')
        if namespace_fd is None:
            # Parent independently checks the exported disk target after namespace exit.
            # Its one-ID mapping renders the engine's uid/gid0 as guest23001.
            target=evidence.path/'target'
            parent_limits=roots.Limits(deadline=time.monotonic()+600,max_nodes=200000,max_bytes=6*p.GIB,
                max_file_bytes=p.GIB,max_package_files=500000)
            observed=roots.observe(target,limits=parent_limits,hardlinks='generic-development-internal')
            p.need(all(n.get('uid')==n.get('gid')==23001 for n in observed['nodes'].values()),'exported target ownership mapping differs')
            target_db=driver.database(target,max_packages=587,max_files=500000,max_nodes=1000000,observed=observed['nodes'])
            for node in observed['nodes'].values(): node.update(uid=0,gid=0)
            compare_payload(observed,payload,derived_output_binding=profile.get('derived_output_binding'))
            p.need({r['name']:r['version'] for r in target_db}==profile['expected'],'parent target database differs')
        after=driver.database(Path('/'),max_packages=1024,max_files=500000,max_nodes=1000000)
        p.need(before==after,'guest parent package database changed')
        # Rehash exact protected source and package/signature input after all actors.
        checked_inputs(protected=True)
        if namespace_fd is None:evidence.write('installed-packages.lock',candidate,exclusive=True)
        # The signed 04110 node needs independent readback by the root guest
        # after this entire ordinary-parent process group has retired.
        result.update(status=PASS if namespace_fd is None else 'PROVISIONAL_MAPPED_PARENT',
            parent_inventory_preserved=True,source_cache_preserved=True,
            process_retirement=True,ordinary_parent_nnp_cap0=True,
            numeric_namespace_verified=namespace_fd is not None,root_guest_payload_verified=False)
        evidence.save('result.json',result)
    except BaseException as error:
        result.update(status='FAIL',parent_error_type=type(error).__name__,parent_error=str(error)[:512])
        evidence.save('result.json',result)
    finally:
        if spec_fd is not None: os.close(spec_fd)
        evidence.close()
    print(json.dumps(result,sort_keys=True),flush=True)
    return int(result['status'] not in (PASS,'PROVISIONAL_MAPPED_PARENT'))


def main():
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('mode',choices=('run','engine'))
    parser.add_argument('--spec-fd'); parser.add_argument('--spec-sha256'); parser.add_argument('--evidence-fd')
    parser.add_argument('--namespace-fd',type=int);parser.add_argument('--lease-sha256')
    args=parser.parse_args()
    return execute(args.namespace_fd,args.lease_sha256) if args.mode=='run' else engine(args.spec_fd,args.spec_sha256,args.evidence_fd)


if __name__=='__main__':
    try: sys.exit(main())
    except BaseException as error:
        if isinstance(error,SystemExit): raise
        print(json.dumps(dict(status='FAIL',phase='preflight',error_type=type(error).__name__,error=str(error)[:512])),flush=True)
        sys.exit(1)
