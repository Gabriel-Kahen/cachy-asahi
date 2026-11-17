#!/usr/bin/env -S python3 -I -B
"""Existing Root limiter/controller pattern, fixed read-only policy metadata operation."""
import argparse, fcntl, hashlib, importlib.util, json, math, os, re, resource, select, signal, stat, sys, time, types
from pathlib import Path
HERE = Path(__file__).resolve().parent
M = 1024**2


def need(ok, why):
    if not ok:
        raise ValueError(why)


def encoded(v):
    return (json.dumps(v, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def decode(raw):
    def pairs(rows):
        d = {}
        for k, v in rows:
            need(k not in d, 'duplicate field'); d[k] = v
        return d
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: need(False, 'finite JSON only'))


def ordinary(value):
    need(type(value) is str and value.startswith('/') and str(Path(value)) == value
         and '..' not in Path(value).parts and not any(c in value for c in '\0\n\r,'), 'literal ordinary path')
    p = Path(value)
    need(not any(q.is_symlink() for q in (p, *p.parents)), 'unaliased path chain')
    return p


def identity(s):
    return tuple(getattr(s, n) for n in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))


def whole(path, cap=M, deadline=None):
    p = ordinary(str(path)); fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= cap, 'bounded ordinary single-link DATA')
        h = hashlib.sha256(); size = 0
        while True:
            need(deadline is None or time.monotonic() < deadline, 'whole DATA deadline')
            b = os.read(fd, min(M, cap + 1 - size))
            if not b: break
            size += len(b); need(size <= cap, 'whole DATA byte cap'); h.update(b)
        need(size == before.st_size and identity(before) == identity(os.fstat(fd)) == identity(p.lstat()), 'stable whole DATA')
        return dict(bytes=size, sha256=h.hexdigest()), identity(before)
    finally:
        os.close(fd)


def read(path, cap=M):
    expected, _ = whole(path, cap)
    b = Path(path).read_bytes(); need(len(b) == expected['bytes'] and hashlib.sha256(b).hexdigest() == expected['sha256'], 'stable small control DATA')
    return b


def kernel(path, cap=4096):
    p=ordinary(str(path));fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode),'ordinary public kernel metadata')
        b=bytearray()
        while part:=os.read(fd,min(4096,cap+1-len(b))):b.extend(part);need(len(b)<=cap,'bounded public kernel metadata')
        after=os.fstat(fd);need((before.st_dev,before.st_ino,before.st_mode)==(after.st_dev,after.st_ino,after.st_mode),'same public kernel control descriptor')
        return bytes(b)
    finally:os.close(fd)


def check_ref(r, cap=M):
    need(type(r) is dict and set(r) == {'path','bytes','sha256'}, 'whole reference')
    need(whole(r['path'], cap)[0] == {k:r[k] for k in ('bytes','sha256')}, 'external whole reference differs')


def module(name, path):
    s = importlib.util.spec_from_file_location(name, path); m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m


def fixed():
    return decode(read(HERE / 'fixed-inputs.DATA.json'))


def require_issued(c, f):
    keys = {'kind','issued_by','accepted','allow_outer','phase','outer_capsule','runtime_profile','controller_scope','outer_output','nonce','Main','issued_at','expires_at','resources','custody','once','retry','actual','Root_acceptance','next_boot_stability','qualification_authority','transport'}
    need(type(c) is dict and set(c) == keys, 'closed existing Root outer derivative schema')
    need(c['issued_by'] == 'Root' and c['accepted'] is c['allow_outer'] is True, 'fresh explicit Root outer grant required before helper import or lease access')
    need(c['kind'] == 'ROOT_R86_PUBLIC_LDCACHE_RECOVERY_OUTER_V1' and c['phase'] == 'readonly-r86-cache-and-etc-only' and c['once'] is True and c['retry'] is False, 'one fixed opaque decoder operation')
    need(c['resources'] == f['resources'] and c['custody'] == f['custody'], 'unchanged exact declared resource/custody bounds')
    need(type(c['nonce']) is str and re.fullmatch('[0-9a-f]{32}', c['nonce']) and type(c['Main']) is str and re.fullmatch('[0-9a-f]{40}', c['Main']), 'fresh Root nonce and independently selected Main')
    now = int(time.time())
    need(type(c['issued_at']) is type(c['expires_at']) is int and c['issued_at'] <= now and now+f['resources']['outer_seconds'] <= c['expires_at'] <= c['issued_at'] + 1800, 'fresh finite Root selection')
    need(c['actual'] == dict(runtime=None,nonce=None,scope=None,output=None,approval=None) and c['Root_acceptance'] is c['next_boot_stability'] is None, 'runtime observations/acceptance are not issued in template')
    for n in ('runtime_profile','outer_capsule','qualification_authority'):
        need(type(c[n]) is dict and set(c[n]) == {'path','bytes','sha256'}, 'explicit whole current Root input')
    need(type(c['controller_scope']) is dict and c['outer_output'] is not None, 'separate live scope and fresh output selected')


def labels(c, authority_sha):
    return {'org.cachy-asahi.warm-owner':'1000','org.cachy-asahi.warm-nonce':c['nonce'],'org.cachy-asahi.warm-authority':authority_sha}


def name(c):
    return 'cachy-ldcache-read-' + c['nonce'][:24]


def deadline_text(deadline):
    need(type(deadline) in (int,float) and math.isfinite(deadline) and deadline>0, 'finite fixed decoder deadline')
    return format(math.floor(deadline*10**6)/10**6,'.6f')


def helper_argv(c, authority_sha, deadline):
    return ['-I','-B','/limiter/exec_limiter.py','--fixed-ldcache-recovery','--nonce',c['nonce'],
        '--authority-sha256',authority_sha,'--qualification-authority-sha256',c['qualification_authority']['sha256'],'--deadline-monotonic',deadline_text(deadline)]


def ready_bytes(c, authority_sha, deadline):
    return encoded(dict(kind='FIXED_LDCACHE_RECOVERY_LIMITS_READY_V1',nonce=c['nonce'],authority_sha256=authority_sha,
        deadline_monotonic=deadline_text(deadline),namespace_pid=1,
        limits=dict(AS=[4294967296,4294967296],FSIZE=[1610612736,1610612736],CORE=[0,0])))


def go_bytes(c, authority_sha, ready_raw):
    return encoded(dict(kind='ROOT_GO_FIXED_LDCACHE_RECOVERY_V1',nonce=c['nonce'],authority_sha256=authority_sha,
        ready_sha256=hashlib.sha256(ready_raw).hexdigest()))


def rename_go_noreplace(directory_fd):
    # One fixed Linux atomic publication; never overwrite an existing final token.
    import ctypes
    libc=ctypes.CDLL(None,use_errno=True);rename=getattr(libc,'renameat2',None)
    need(rename is not None,'atomic no-replace GO rename supported')
    rename.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint];rename.restype=ctypes.c_int
    if rename(directory_fd,b'.decoder.go.staging',directory_fd,b'decoder.go.json',1)!=0:
        error=ctypes.get_errno();raise OSError(error,os.strerror(error),'decoder.go.json')


def publish_go(root, raw):
    need(type(raw) is bytes and 0<len(raw)<=4096,'bounded complete GO bytes')
    root=ordinary(str(root));directory_fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        owner=os.fstat(directory_fd)
        need(owner.st_uid==owner.st_gid==os.getuid()==os.geteuid()==os.getgid()==os.getegid()==1000 and stat.S_IMODE(owner.st_mode)==0o700,'same private owned GO directory')
        def absent_final():
            try:os.stat('decoder.go.json',dir_fd=directory_fd,follow_symlinks=False)
            except FileNotFoundError:return
            raise ValueError('fresh final GO must remain absent until atomic publication')
        absent_final()
        fd_go=os.open('.decoder.go.staging',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory_fd)
        try:
            before=os.fstat(fd_go)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==before.st_gid==1000 and stat.S_IMODE(before.st_mode)==0o600,'fresh private single-link staging GO')
            written=0
            while written<len(raw):
                count=os.write(fd_go,raw[written:]);need(type(count) is int and 0<count<=len(raw)-written,'complete staging GO write');written+=count
            os.fsync(fd_go);after=os.fstat(fd_go)
            need(stat.S_ISREG(after.st_mode) and after.st_uid==after.st_gid==1000 and stat.S_IMODE(after.st_mode)==0o600 and after.st_nlink==1 and after.st_size==len(raw) and (after.st_dev,after.st_ino)==(before.st_dev,before.st_ino),'same complete private staged GO inode')
        finally:os.close(fd_go)
        st=os.stat('.decoder.go.staging',dir_fd=directory_fd,follow_symlinks=False)
        need(identity(st)==identity(after) and read(root/'.decoder.go.staging',4096)==raw,'whole complete stable staging GO before publication')
        absent_final();rename_go_noreplace(directory_fd);os.fsync(directory_fd)
        final=os.stat('decoder.go.json',dir_fd=directory_fd,follow_symlinks=False)
        need((final.st_dev,final.st_ino,final.st_uid,final.st_gid,stat.S_IMODE(final.st_mode),final.st_nlink,final.st_size)==(after.st_dev,after.st_ino,1000,1000,0o600,1,len(raw)),'same complete private final GO inode after atomic publication')
    finally:os.close(directory_fd)


def parse_decoder_limits(raw):
    need(type(raw) is bytes and 0<len(raw)<=16384,'bounded actual decoder limits table')
    text=raw.decode('ascii');values={}
    for key,label,wanted in (('AS','Max address space',4294967296),('FSIZE','Max file size',1610612736),('CORE','Max core file size',0)):
        found=re.findall(r'^'+label+r'\s+([0-9]+)\s+([0-9]+)\s+bytes\s*$',text,re.M)
        need(len(found)==1 and [int(n) for n in found[0]]==[wanted,wanted],'actual same-process hard/soft decoder limit '+key)
        values[key]=[wanted,wanted]
    return values


def create_argv(c, f, output, authority_sha, deadline):
    args = ['container','create','--pull=never','--name',name(c),'--read-only','--network','none',
        '--cap-drop','ALL','--security-opt','no-new-privileges','--user','0:0','--init=false',
        '--memory','536870912','--memory-swap','536870912','--cpus','1','--pids-limit','64',
        '--ulimit','fsize=1610612736:1610612736',
        '--ulimit','core=0:0','--restart','no','--log-driver','none']
    for k, v in labels(c, authority_sha).items(): args += ['--label',k+'='+v]
    for src, dest, ro in ((f['input_raw']['path'],'/prepared/guest.raw',True),(f['input_prepared']['path'],'/inputs/overlay.qcow2',True),(str(output),'/output',False),
            (str(HERE/'exec_limiter.py'),'/limiter/exec_limiter.py',True),
            (str(Path(f['prior_packet']['path']).parent),'/draft',True),
            (c['qualification_authority']['path'],'/authority/Root-qualification.ACTUAL.json',True)):
        args += ['--mount','type=bind,src='+src+',dst='+dest+(',readonly' if ro else '')]
    return args + ['--entrypoint','/usr/bin/python3',f['image'],*helper_argv(c,authority_sha,deadline)]


# A finite projection deliberately excludes Config.Env and every unrelated Config field.
INSPECT_FIELDS = {'Id':'.Id','Name':'.Name','Image':'.Image','Path':'.Path','Args':'.Args','State':'.State',
    'Entrypoint':'.Config.Entrypoint','Cmd':'.Config.Cmd','User':'.Config.User','Labels':'.Config.Labels',
    'ReadonlyRootfs':'.HostConfig.ReadonlyRootfs','NetworkMode':'.HostConfig.NetworkMode',
    'CapDrop':'.HostConfig.CapDrop','CapAdd':'.HostConfig.CapAdd','Privileged':'.HostConfig.Privileged',
    'Devices':'.HostConfig.Devices','DeviceCgroupRules':'.HostConfig.DeviceCgroupRules','DeviceRequests':'.HostConfig.DeviceRequests','Init':'.HostConfig.Init',
    'SecurityOpt':'.HostConfig.SecurityOpt','Memory':'.HostConfig.Memory','MemorySwap':'.HostConfig.MemorySwap',
    'NanoCpus':'.HostConfig.NanoCpus','PidsLimit':'.HostConfig.PidsLimit','Ulimits':'.HostConfig.Ulimits',
    'AutoRemove':'.HostConfig.AutoRemove','RestartPolicy':'.HostConfig.RestartPolicy',
    'LogConfig':'.HostConfig.LogConfig','PidMode':'.HostConfig.PidMode','UTSMode':'.HostConfig.UTSMode','Mounts':'.Mounts'}
INSPECT = '{' + ','.join(json.dumps(k)+':{{json '+v+'}}' for k,v in INSPECT_FIELDS.items()) + '}'


SERVER_FIELDS = ('ID','DockerRootDir','SecurityOptions','CgroupVersion','CgroupDriver','OSType','Architecture')
SERVER = '{'+','.join(json.dumps(k)+':{{json .'+k+'}}' for k in SERVER_FIELDS)+'}'


def check_rootless_server(row, f):
    r=f['rootless_server']
    need(type(r) is dict and set(r)=={'member','image','bytes','sha256'}
         and r['member']=='rootless-server.DATA.json' and r['image']==f['image'], 'whole exact image/rootless-server binding')
    raw=read(HERE/r['member'])
    need(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())=={k:r[k] for k in ('bytes','sha256')}, 'actual rootless-server whole pin')
    v=decode(raw)
    need(type(v) is dict and set(v)=={'Config_Env_read','Root_acceptance','host_owner_uid','image','image_default_user','info','namespace_user_required'}
         and v['Config_Env_read'] is False and v['Root_acceptance'] is None and v['host_owner_uid']==1000
         and v['image']==f['image'] and v['image_default_user']=='' and v['namespace_user_required']=='0:0',
         'Root-bound ordinary host owner and namespace root only; no Env or acceptance')
    need(type(row) is dict and set(row)==set(SERVER_FIELDS) and row==v['info']
         and 'name=rootless' in row['SecurityOptions'] and row['CgroupVersion']=='2'
         and row['CgroupDriver']=='systemd' and row['OSType']=='linux', 'same exact seven-fact rootless daemon projection')
    return row


def expected_inspect_labels(c, f, authority_sha):
    r=f['inherited_image_labels']
    need(type(r) is dict and set(r)=={'member','image','bytes','sha256'}
         and r['member']=='inherited-image-labels.DATA.json' and r['image']==f['image'], 'whole exact image/inherited-label map binding')
    raw=read(HERE/r['member'])
    need(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())=={k:r[k] for k in ('bytes','sha256')}, 'actual inherited-label whole pin')
    v=decode(raw)
    need(type(v) is dict and set(v)=={'Config_Env_read','Root_acceptance','image','inherited_labels'}
         and v['image']==f['image'] and v['Config_Env_read'] is False and v['Root_acceptance'] is None,
         'selected actual image labels only; no Env or acceptance')
    inherited=v['inherited_labels'];fresh=labels(c,authority_sha)
    need(type(inherited) is dict and len(inherited)==14
         and all(type(k) is type(value) is str for k,value in inherited.items())
         and not set(inherited)&set(fresh), 'exact fourteen parent labels and no warm namespace collision')
    return inherited|fresh


def inspect_bound(row, cid, c, f, output, authority_sha, deadline):
    need(type(row) is dict and set(row) == set(INSPECT_FIELDS), 'closed inspect projection only')
    need(row['Id'] == cid and row['Name'] == '/'+name(c) and row['Image'] == f['image']
         and row['Path'] == '/usr/bin/python3' and row['Args'] == helper_argv(c,authority_sha,deadline)
         and row['Entrypoint'] == ['/usr/bin/python3'] and row['Cmd'] == helper_argv(c,authority_sha,deadline)
         and row['User'] == '0:0' and row['Labels'] == expected_inspect_labels(c, f, authority_sha), 'exact decoder/CID/image/argv/user/labels')
    need(row['ReadonlyRootfs'] is True and row['NetworkMode'] == 'none' and row['CapDrop'] == ['ALL']
         and not row['CapAdd'] and row['Privileged'] is row['Init'] is row['AutoRemove'] is False
         and not row['Devices'] and not row['DeviceCgroupRules'] and not row['DeviceRequests'] and row['SecurityOpt'] == ['no-new-privileges']
         and row['Memory'] == row['MemorySwap'] == 536870912 and row['NanoCpus'] == 10**9
         and row['PidsLimit'] == 64 and row['PidMode'] == row['UTSMode'] == ''
         and row['RestartPolicy'] == dict(Name='no',MaximumRetryCount=0) and row['LogConfig']['Type'] == 'none', 'separate bounded decoder envelope')
    wanted = {('fsize',1610612736,1610612736),('core',0,0)}
    need(type(row['Ulimits']) is list and len(row['Ulimits']) == 2 and {(v['Name'],v['Soft'],v['Hard']) for v in row['Ulimits']} == wanted, 'supported exact Docker file/core limits; AS proved on the live helper')
    mounts = {('bind',src,dest,not ro) for src,dest,ro in ((f['input_raw']['path'],'/prepared/guest.raw',True),(f['input_prepared']['path'],'/inputs/overlay.qcow2',True),(str(output),'/output',False),(str(HERE/'exec_limiter.py'),'/limiter/exec_limiter.py',True),(str(Path(f['prior_packet']['path']).parent),'/draft',True),(c['qualification_authority']['path'],'/authority/Root-qualification.ACTUAL.json',True))}
    need(type(row['Mounts']) is list and len(row['Mounts']) == 6 and {(v['Type'],v['Source'],v['Destination'],v['RW']) for v in row['Mounts']} == mounts, 'exact read-only raw/code/authority and one writable metadata output')
    return row['State']


def check_prior_packet(f):
    check_ref(f['prior_packet']);root=Path(f['prior_packet']['path']).parent;manifest=decode(read(root/'packet-seal.DATA.json'))
    need({p.relative_to(root).as_posix()for p in root.rglob('*')if p.is_file()}==set(manifest['files'])|{'packet-seal.DATA.json'},'closed fixed public recovery code only')
    for name,row in manifest['files'].items():
        p=root/name;need(dict(**whole(p,4*M)[0],mode=stat.S_IMODE(p.lstat().st_mode))==row,'whole exact operation byte/mode closure')
    check_ref(f['operation_entry'])


def validate_observation(v,c,f):
    need(type(v)is dict and len(encoded(v))<=16384,'bounded public recovery summary')
    need(v.get('kind')=='OBSERVED_R86_PUBLIC_LDCACHE_RECOVERY_DATA_V1'and v.get('status')=='PUBLIC_CACHE_PARENT_DATA_NOT_LIFECYCLE_ACCEPTANCE'and v.get('Source_lock')==f['source_lock'],'exact public-only recovery identity')
    need(v.get('request')=={n:c['qualification_authority'][n]for n in('bytes','sha256')}and v.get('tools_reverified')is True and v.get('commands')==7 and v.get('all_tools_naturally_reaped')is True,'same Root request/tools/seven natural commands')
    need(all(v.get(n)is None for n in('Root_acceptance','VM_acceptance','lifecycle_acceptance','M2','release')),'no lifecycle/runtime acceptance')
    names={label+suffix for label in('chain','convert','cache-before','etc-before','cache-body','cache-after','etc-after')for suffix in('.log','.retirement.json')}|{'cache.bin','observation.raw'}
    need(type(v.get('files'))is dict and set(v['files'])==names,'fixed public artifact membership')
    for name,row in v['files'].items():
        cap=1610612736 if name=='observation.raw'else 1048576 if name=='cache.bin'else 16384
        need(type(row)is dict and set(row)=={'bytes','sha256'}and type(row['bytes'])is int and 0<=row['bytes']<=cap and type(row['sha256'])is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),'bounded exact artifact pin')
    need(v['files']['observation.raw']['bytes']==1610612736,'exact disposable raw geometry')
    return {n:v[n]for n in('kind','status','request','Source_lock','cache_observation','tools_reverified','commands','all_tools_naturally_reaped','Root_acceptance','VM_acceptance','lifecycle_acceptance','M2','release')}


def retain_artifact_descriptors(directory,summary,deadline):
    directory=ordinary(str(directory));expected=set(summary['files'])|{'observation.DATA.json'}
    need({p.name for p in directory.iterdir()}==expected,'complete fixed public artifacts')
    rows={};total=0
    for name in sorted(expected):
        p=directory/name;st=p.lstat();need(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and st.st_uid==1000 and stat.S_IMODE(st.st_mode)==0o600,'fresh private owned recovery artifact')
        cap=1610612736 if name=='observation.raw'else 1048576 if name=='cache.bin'else 16384
        value,_=whole(p,cap,deadline);total+=value['bytes'];need(total<=1610612736+4*M,'exact raw plus bounded public artifacts')
        if name!='observation.DATA.json':need(value==summary['files'][name],'whole opaque artifact pin matches child')
        rows[name]=dict(path=str(p),**value,mode=0o600)
    return rows,total


def run(config_path, config_sha):
    # Rejected/unissued drafts cannot import primitives, query Docker or access the lease.
    need(whole(config_path)[0]['sha256'] == config_sha, 'external exact Root outer SHA')
    c = decode(read(config_path)); f = fixed(); require_issued(c, f)
    need(c['outer_capsule']['path'] == str(HERE/'seal.json'), 'exact externally reviewed capsule')
    check_ref(c['outer_capsule']); seal = decode(read(HERE/'seal.json'))
    need({p.name for p in HERE.iterdir()} == set(seal['files']) | {'seal.json'}, 'closed capsule namespace')
    for n, row in seal['files'].items():
        need(whole(HERE/n)[0] == {k:row[k] for k in ('bytes','sha256')} and stat.S_IMODE((HERE/n).lstat().st_mode) == row['mode'], 'whole sealed code/DATA/mode')
    check_prior_packet(f)
    check_ref(c['qualification_authority'])
    request=decode(read(c['qualification_authority']['path']));Q=module('pure_ldcache_request',Path(f['prior_packet']['path']).parent/'recovery.py');Q.require_issued(request)
    need(type(c['transport'])is dict and set(c['transport'])=={'docker_cli','docker_endpoint'}and c['transport']['docker_endpoint']=='unix:///run/user/1000/docker.sock','Root-selected exact ordinary rootless transport')
    need(set(c['transport']['docker_cli'])=={'path','bytes','sha256','device','inode','uid','gid','mode','nlink'},'Root whole CLI identity')
    need(request['output']==str(Path(c['outer_output'])/'decoder-output')and request['overlay']['path']==f['input_prepared']['path']and request['backing']['path']==f['input_raw']['path'],'exact r86 Root request/input/output joins')
    f=dict(f,input_raw=dict(path=request['backing']['path'],**request['backing']['pin']),input_prepared=dict(path=request['overlay']['path'],**request['overlay']['pin']),docker_cli=c['transport']['docker_cli'],docker_endpoint=c['transport']['docker_endpoint'])
    refs = decode(read(HERE/'primitive-references.DATA.json'))['maintained']
    for r in refs.values(): check_ref(r)
    check_ref(f['runtime_contract']); check_ref(c['runtime_profile'],65536)
    E = module('warm_exact_live_scope', HERE/'live_scope.py'); E.validate(c['controller_scope'])
    need(c['controller_scope']['unit'] == 'cachy-no-package-'+c['nonce']+'.scope', 'fresh exact maintained scope identity')
    initial_scope = E.observe(c['controller_scope'])
    out = ordinary(c['outer_output']); base = Path('/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114')
    need(out.is_relative_to(base) and not out.exists() and out.parent.is_dir() and out.parent.stat().st_uid == os.getuid() == os.geteuid() == 1000 and not out.parent.stat().st_mode & 0o022, 'fresh own-UID private output under existing Root artifact parent')
    need(not any(out.is_relative_to(Path(f[k]['path'])) or Path(f[k]['path']).is_relative_to(out) for k in ('input_raw','input_prepared')) and not out.is_relative_to(HERE) and not HERE.is_relative_to(out), 'disjoint opaque originals/capsule/output')
    os.umask(0o077); out.mkdir(mode=0o700); records = out/'records'; records.mkdir(mode=0o700)
    data = out/'decoder-output'; data.mkdir(mode=0o700); docker_config = out/'empty-docker-config'; docker_config.mkdir(mode=0o700)
    O = module('warm_exact_root_operator',refs['operator']['path'])
    C,U,S,L = O.modules(types.SimpleNamespace(runtime54_profile=c['runtime_profile']['path'],runtime54_profile_sha256=c['runtime_profile']['sha256']), records)
    end = time.monotonic()+480; work_end=end-90; fd=pfd=None; held=False; create_intent=False; cid=None; stream_index=0; inputs_before={}; decoder_end=None; decoder_pidfd=None
    result=dict(status='HOLD',nonce=c['nonce'],Main=c['Main'],Root_acceptance=None,next_boot_stability=None,VM_acceptance=None,Perl_preservation=None,signals=[],cleanup_errors=[],close_only=False,owned_container_absent=False,owned_children_reaped=True,forced_owned_cleanup=False,initial_controller_scope=initial_scope,decoder_retirement=None,observation_summary=None,artifact_descriptors=None,artifact_bytes=None,policy_exit_code=None,live_child_guard_samples=0,tool_image=f['image'],image_tools_reverified_here=False)
    class Cancel(Exception): pass
    def cancel(sig,frame): result['signals'].append(sig); raise Cancel('Root outer cancellation')
    handlers={n:signal.signal(n,cancel) for n in (signal.SIGINT,signal.SIGTERM)}
    def meta_usage():
        total=16*M+8192; files=list(records.iterdir()); need(len(files)<=256,'finite metadata namespace')
        for p in files:
            s=p.lstat(); need(stat.S_ISREG(s.st_mode) and s.st_uid==1000 and s.st_nlink==1,'ordinary owned metadata leaf');total+=s.st_size
        need(total<=32*M,'aggregate metadata/stream cap');return total
    def put(label,value):
        b=encoded(value); need(len(b)<=M and meta_usage()+len(b)<=32*M,'finite receipt/aggregate cap')
        with (records/label).open('xb') as stream: stream.write(b);stream.flush();os.fsync(stream.fileno())
    def proof():
        v=C.held(U,L,fd,os.getpid()); pair=tuple(int(n,16) for n in v['proof']['kernel_device'].split(':'))
        need(v['identity']['dev']==54 and pair==(0,33) and v['identity']['inode']==59258250,'same independently pinned canonical fstat/kernel identity');return v
    def capacity(initial=False,with_child=False):
        if with_child:
            E.validate(c['controller_scope']);expected={'memory.max':'536870912\n','memory.swap.max':'0\n','pids.max':'64\n','cpu.max':'100000 100000\n'}
            need({n:kernel(Path(c['controller_scope']['path'])/n).decode('ascii') for n in expected}==expected,'live controller limits while maintained supervisor owns child')
        else:E.observe(c['controller_scope'])
        mem={line.split(':')[0]:int(line.split()[1])*1024 for line in Path('/proc/meminfo').read_text().splitlines()}
        st=os.statvfs(out); free=st.f_bavail*st.f_frsize
        need(mem['MemAvailable'] >= (3221225472 if initial else 2147483648) and free >= (10737418240 if initial else 2147483648),'actual host memory/physical reserve')
        need(time.monotonic()<end and int(time.time())<c['expires_at'],'shared outer/fresh Root deadline')
        return dict(MemAvailable=mem['MemAvailable'],physical_available_bytes=free,quota_availability='UNCLAIMED',capacity_reservation=False)
    def cli():
        d=f['docker_cli'];p=ordinary(d['path']);s=p.lstat()
        need((s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode),s.st_nlink,s.st_size)==tuple(d[k] for k in ('device','inode','uid','gid','mode','nlink','bytes')) and whole(p,128*M,end)[0]=={k:d[k] for k in ('bytes','sha256')},'exact historical rootless Docker CLI whole identity');return str(p)
    def docker(args, deadline, cap=8, expected=0):
        nonlocal stream_index
        proof();capacity(); need(time.monotonic()<deadline,'shared command/cleanup tail')
        allowance=min(M,(32*M-meta_usage()-65536)//2);need(allowance>0,'finite streams reserved before launch')
        stem='command-'+str(stream_index).zfill(3);stream_index+=1
        argv=[cli(),'--host='+f['docker_endpoint'],*args]
        budget=min(cap,deadline-time.monotonic());need(budget>5,'S retirement reserve remains inside actual shared tail')
        original_limit=S._limit
        def limited():
            original_limit();resource.setrlimit(resource.RLIMIT_FSIZE,(allowance,allowance));resource.setrlimit(resource.RLIMIT_AS,(4294967296,4294967296));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        S._limit=limited;original_time=S.time;sampled=[0.0];guard_failed=[False]
        def guarded_sleep(seconds):
            if not guard_failed[0] and time.monotonic()-sampled[0]>=1:
                try:proof();capacity(with_child=True);result['live_child_guard_samples']+=1;sampled[0]=time.monotonic()
                except BaseException:guard_failed[0]=True;raise
            time.sleep(seconds)
        S.time=types.SimpleNamespace(monotonic=time.monotonic,sleep=guarded_sleep)
        try:
            with (records/(stem+'.stdout')).open('xb') as so,(records/(stem+'.stderr')).open('xb') as se:
                ret=S.supervise(argv,cwd=out,env=dict(PATH='/usr/bin:/bin',HOME='/home/gabe',XDG_RUNTIME_DIR='/run/user/1000',DOCKER_CONFIG=str(docker_config),LC_ALL='C',LANG='C'),stdout=so,stderr=se,lock_fd=fd,cap=budget)
        finally: S._limit=original_limit;S.time=original_time
        put(stem+'.retirement.json',dict(argv=argv,cap=budget,retirement=ret))
        if args[:2]==['container','wait']:result['decoder_wait_retirement']=ret
        result['owned_children_reaped'] &= ret.get('reaped') is True and ret.get('group_absent') is True
        C.natural(ret);need(ret['exit']==expected,'exact command exit');meta_usage();proof();capacity()
        return read(records/(stem+'.stdout'),allowance)
    def census(deadline, role):
        args=['container','ls','-a','--no-trunc']
        if role=='labels':
            for k,v in labels(c,config_sha).items():args+=['--filter','label='+k+'='+v]
        elif role=='name':args+=['--filter','name=^/'+name(c)+'$']
        else:args+=['--filter','id='+cid]
        args+=['--format','{{.ID}}'];raw=docker(args,deadline);ids=raw.decode('ascii').splitlines()
        need(len(ids)<=1 and all(re.fullmatch('[0-9a-f]{64}',v) for v in ids),'single exact owned-ID census');return ids
    def inspection(selected, deadline):
        row=decode(docker(['container','inspect','--format',INSPECT,selected],deadline))
        return inspect_bound(row,selected,c,f,data,config_sha,decoder_end)
    def decoder_kernel_scope(state):
        pid=state['Pid'];need(state['Running'] is True and type(pid) is int and pid>0,'live decoder needed for separate kernel cap proof')
        started=S._read_stat(pid)[4];pidfd=os.pidfd_open(pid,0)
        try:
            need(not select.select([pidfd],[],[],0)[0],'same actual decoder PIDFD alive')
            membership=kernel('/proc/'+str(pid)+'/cgroup',4096).decode('ascii')
            need(membership.startswith('0::/') and membership.count('\n')==1,'actual unified decoder cgroup')
            relative=membership[3:].strip();path=ordinary('/sys/fs/cgroup'+relative)
            need(cid in relative and str(path)!=c['controller_scope']['path'],'separate exact owned-CID decoder cgroup')
            expected={'memory.max':'536870912\n','memory.swap.max':'0\n','pids.max':'64\n','cpu.max':'100000 100000\n'}
            values={n:kernel(path/n,4096).decode('ascii') for n in expected}
            need(values==expected and kernel(path/'cgroup.procs',4096).decode('ascii')==str(pid)+'\n','actual decoder kernel512MiB/swap0/1CPU/64PID limits and sole decoder process')
            need(kernel('/proc/'+str(pid)+'/cgroup',4096).decode('ascii')==membership and S._read_stat(pid)[4]==started and not select.select([pidfd],[],[],0)[0],'same live decoder PIDFD/start/cgroup through cap observation')
            need(values=={n:kernel(path/n,4096).decode('ascii') for n in expected},'stable exact decoder kernel limits')
            limits=parse_decoder_limits(kernel('/proc/'+str(pid)+'/limits',16384))
            need(S._read_stat(pid)[4]==started and not select.select([pidfd],[],[],0)[0], 'same live helper PIDFD/start through actual rlimits')
            return dict(status='PASS_SEPARATE_LIVE_DECODER_KERNEL_CAPS_DATA_ONLY',pid=pid,start=started,path=str(path),limits=values,pidfd_alive=True),pidfd,limits
        except BaseException:
            os.close(pidfd);raise
    def wait_ready():
        expected=ready_bytes(c,config_sha,decoder_end);path=data/'decoder.ready.json'
        until=min(decoder_end,time.monotonic()+10)
        while not path.exists():
            need(time.monotonic()<until,'bounded ready within unchanged decoder phase');proof();capacity();time.sleep(.025)
        st=path.lstat();need(st.st_uid==1000 and stat.S_IMODE(st.st_mode)==0o600, 'private host-owned ready metadata')
        actual=read(path,4096);need(actual==expected,'exact ready nonce/authority/deadline/limit body')
        return actual
    def permit_decoder(receipt,pidfd,ready_raw):
        pid=receipt['pid'];need(S._read_stat(pid)[4]==receipt['start'] and not select.select([pidfd],[],[],0)[0], 'same live original helper PIDFD/start immediately before GO')
        need(kernel('/proc/'+str(pid)+'/cgroup',4096).decode('ascii')=='0::'+receipt['path'].removeprefix('/sys/fs/cgroup')+'\n','same helper cgroup immediately before GO')
        limits=parse_decoder_limits(kernel('/proc/'+str(pid)+'/limits',16384))
        proof();capacity();need(time.monotonic()<decoder_end,'shared decoder deadline before GO')
        raw=go_bytes(c,config_sha,ready_raw);need(len(raw)<=4096,'bounded exact GO token')
        publish_go(data,raw)
        result['decoder_exec_limits']=limits
        put('decoder-GO.json',dict(ready_sha256=hashlib.sha256(ready_raw).hexdigest(),go_sha256=hashlib.sha256(raw).hexdigest(),same_helper_PIDFD_start=True,fixed_pipeline_parent_keeps_PID_start_and_limits=True))
    def cleanup():
        nonlocal cid
        tail=min(time.monotonic()+90,end-2)
        ids=census(tail,'labels')
        if ids:
            if cid is not None:need(ids==[cid],'exact issued CID/labels agree')
            cid=ids[0];state=inspection(cid,tail)
            force=state['Running'] is True; result['forced_owned_cleanup'] |= force
            docker(['container','rm',*(['--force'] if force else []),cid],tail)
        need(not census(tail,'labels') and not census(tail,'name') and (cid is None or not census(tail,'id')),'independent owned-label/name/ID absence')
        result['owned_container_absent']=True
    try:
        fd=os.open(U.canonical(U.LOCK),os.O_RDWR|os.O_CLOEXEC|os.O_NOFOLLOW);U.lock_identity(fd);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);held=True
        C.OWNER_START=S._read_stat(os.getpid())[4];pfd=os.pidfd_open(os.getpid(),0);C.OWNER_PIDFD=pfd
        result['initial_lease']=proof();result['initial_capacity']=capacity(True)
        check_prior_packet(f);check_ref(c['qualification_authority']);need(Path(f['input_prepared']['path']).stat().st_blocks*512<=268435456,'Root-reviewed overlay allocated cap distinct from EOF')
        for role in ('input_raw','input_prepared'):
            r=f[role];p,i=whole(r['path'],4*1024**3,work_end);need(p=={k:r[k] for k in ('bytes','sha256')},'whole original opaque input pin');inputs_before[role]=dict(pin=p,identity=i)
        put('once-intent.json',dict(authority_sha256=config_sha,nonce=c['nonce'],once=True,retry=False,inputs=inputs_before))
        image=decode(docker(['image','inspect','--format','{{json .Id}}',f['image']],work_end));need(image==f['image'],'exact existing immutable local tool image')
        server=check_rootless_server(decode(docker(['info','--format',SERVER],work_end)),f)
        result['rootless_server_projection']=server;put('rootless-server-observed.json',server)
        need(not census(work_end,'labels') and not census(work_end,'name'),'unused exact owner nonce/name before create')
        decoder_end=float(deadline_text(min(time.monotonic()+180,work_end-60)))
        helper=f['exec_limiter'];need(helper['member']=='exec_limiter.py' and whole(HERE/helper['member'])[0]=={k:helper[k] for k in ('bytes','sha256')},'sealed exact fixed exec limiter')
        create_intent=True
        created=docker(create_argv(c,f,data,config_sha,decoder_end),decoder_end).decode('ascii').strip();need(re.fullmatch('[0-9a-f]{64}',created),'exact created CID');cid=created
        put('created-cid.json',dict(cid=cid,authority_sha256=config_sha,labels=labels(c,config_sha)))
        state=inspection(cid,decoder_end);need(state['Running'] is False and state['Status']=='created','exact inspect joins BEFORE start')
        put('before-start.json',dict(cid=cid,authority_sha256=config_sha,exact_envelope=True,input_pins=inputs_before))
        docker(['container','start',cid],decoder_end)
        ready_raw=wait_ready()
        receipt,decoder_pidfd,limits=decoder_kernel_scope(inspection(cid,decoder_end))
        result['decoder_kernel_scope']=receipt;result['decoder_exec_limits']=limits
        put('decoder-kernel-scope.json',dict(kernel=receipt,actual_host_rlimits=limits,ready_sha256=hashlib.sha256(ready_raw).hexdigest()))
        permit_decoder(receipt,decoder_pidfd,ready_raw)
        waited=docker(['container','wait',cid],decoder_end,cap=180)
        need(waited.strip()==b'0' and time.monotonic()<decoder_end and select.select([decoder_pidfd],[],[],0)[0], 'same bounded helper PIDFD naturally terminated with readonly observer exit0')
        state=inspection(cid,work_end);need(state['Running'] is False and state['ExitCode']==0 and state['Status']=='exited','natural initialized observer exit before cleanup')
        need({p.name for p in data.iterdir()}=={'decoder.ready.json','decoder.go.json','scan'},'only fixed complete scan directory and maintained handshake')
        summary=decode(read(data/'scan/observation.DATA.json',16384));result['observation_summary']=validate_observation(summary,c,f)
        result['artifact_descriptors'],result['artifact_bytes']=retain_artifact_descriptors(data/'scan',summary,work_end)
        result['policy_exit_code']=0
        put('observation-summary.DATA.json',result['observation_summary']);put('artifact-descriptors.DATA.json',dict(files=result['artifact_descriptors'],total_bytes=result['artifact_bytes']))
    except BaseException as error:
        result['error']=dict(type=type(error).__name__,message=str(error)[:700])
    finally:
        mask=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
        try:
            if held:
                if create_intent:
                    try:cleanup()
                    except BaseException as error:result['cleanup_errors'].append('owned CID cleanup: '+str(error)[:500])
                else:result['owned_container_absent']=True
                try:
                    for role,before in inputs_before.items():
                        r=f[role];p,i=whole(r['path'],4*1024**3,end)
                        need(p==before['pin'] and list(i)==list(before['identity']),'whole original input/stat unchanged after operation')
                    result['original_inputs_unchanged']=len(inputs_before)==2
                    need(Path(f['input_prepared']['path']).stat().st_blocks*512<=268435456,'same final overlay allocated cap')
                    result['final_controller_scope']=E.observe(c['controller_scope']);result['final_lease']=proof();result['final_capacity']=capacity()
                except BaseException as error:result['cleanup_errors'].append('final inputs/scope/custody: '+str(error)[:500])
            result['close_only']=True
            ready=held and result.get('original_inputs_unchanged') and result['owned_container_absent'] and result['owned_children_reaped'] and result['observation_summary'] is not None and result['artifact_descriptors'] is not None and result['live_child_guard_samples']>0 and result.get('decoder_kernel_scope',{}).get('status')=='PASS_SEPARATE_LIVE_DECODER_KERNEL_CAPS_DATA_ONLY' and result.get('decoder_wait_retirement',{}).get('passed') is True and not result['forced_owned_cleanup'] and not result.get('error') and not result['cleanup_errors'] and not result['signals'] and time.monotonic()<end
            result['status']='COMPLETE_PUBLIC_LDCACHE_RECOVERY_ONLY' if ready else 'HOLD'
            need(len(encoded(result))<=16384,'controller summary plus opaque descriptors stays16KiB');put('Root-outer-result.json',result)
        finally:
            if decoder_pidfd is not None:os.close(decoder_pidfd)
            if pfd is not None:os.close(pfd)
            if fd is not None:os.close(fd)
            for n,h in handlers.items():signal.signal(n,h)
            signal.pthread_sigmask(signal.SIG_SETMASK,mask)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--execute-root-issued-outer',action='store_true');p.add_argument('--authority',type=Path,required=True);p.add_argument('--authority-sha256',required=True);a=p.parse_args()
    need(a.execute_root_issued_outer and sys.flags.isolated and sys.dont_write_bytecode and __debug__,'explicit isolated fresh Root outer entry')
    value=run(a.authority,a.authority_sha256);print(json.dumps(value,sort_keys=True));return 0 if value['status']=='COMPLETE_PUBLIC_LDCACHE_RECOVERY_ONLY' else 1


if __name__=='__main__':raise SystemExit(main())
