# SPDX-License-Identifier: MIT
"""Future Root-gated Rust actor entry; imports perform no operational work."""
import hashlib
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import sys
import time
import uuid

SOURCE=Path('/source');INPUTS=Path('/inputs');WORK=Path('/work');OUT=WORK/'output'
OPERATION='rust199-source-reference-native-v1';MIB=1024**2;LOG_LIMIT=64*MIB
TRUST=('ROOT_ADMISSION_SHA256','SOURCE_MAP_SHA256','CONTRACT_SHA256','WORK_VOLUME_ADMISSION_SHA256')
PACKAGE='cachy-asahi-rust199-source-reference-1.99.0-1-aarch64.pkg.tar.zst'


def need(value,why):
    if not value:raise ValueError(why)


def encode(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def sha(value):return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None


def decode(raw):
    need(type(raw) is bytes and len(raw)<=4*MIB,'bounded actor JSON')
    def pairs(rows):
        out={}
        for key,value in rows:need(key not in out,'duplicate actor JSON key');out[key]=value
        return out
    def invalid(_):raise ValueError('noninteger/nonfinite actor JSON')
    return json.loads(raw,object_pairs_hook=pairs,parse_float=invalid,parse_constant=invalid)


def relative(name):
    need(type(name) is str and len(name)<=4096 and re.fullmatch('[A-Za-z0-9._+/-]+',name) and all(x not in ('','.','..') for x in name.split('/')),'ordinary source-relative leaf')
    return name


def read(path,cap=4*MIB):
    path=Path(path);need(path.is_absolute() and '..' not in path.parts and all(not p.is_symlink() for p in (path,*path.parents)),'ordinary absolute actor input')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=cap,'bounded ordinary single-link actor input')
        chunks=[];size=0
        while block:=os.read(fd,min(65536,cap+1-size)):size+=len(block);need(size<=cap,'actor input cap');chunks.append(block)
        identity=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
        need(size==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'actor input changed')
        return b''.join(chunks)
    finally:os.close(fd)


def load(name,path,raw):
    spec=importlib.util.spec_from_file_location(name,path);result=importlib.util.module_from_spec(spec);sys.modules[name]=result
    exec(compile(raw,str(path),'exec'),result.__dict__);return result


def source_gate(root,expected_map,expected_contract):
    need(sha(expected_map) and sha(expected_contract),'external actual Source map/contract pins')
    map_raw=read(root/'source-map.json');need(pin(map_raw)['sha256']==expected_map,'whole Source map differs')
    data=decode(map_raw);need(data['schema']==1 and data['operation']==OPERATION and type(data['files']) is dict and len(data['files'])<=512 and
        all(value is None for value in data['actual'].values()),'closed Source-only schema/NULL selectors')
    rows=data['files'];found=set();directories=set();total=0
    for directory,dirs,files in os.walk(root,followlinks=False):
        if Path(directory)==root and '.git' in dirs:
            need(not (root/'.git').is_symlink(),'Source Git alias refused');dirs.remove('.git')
        for name in dirs:
            path=Path(directory)/name;need(not path.is_symlink(),'Source directory alias refused');directories.add(str(path.relative_to(root)))
        for name in files:
            path=Path(directory)/name;name=str(path.relative_to(root))
            if name=='source-map.json':continue
            relative(name);need(name in rows,'unmapped Source leaf: '+name);body=read(path,64*MIB);total+=len(body)
            need(total<=96*MIB and dict(**pin(body),mode=stat.S_IMODE(path.stat().st_mode))==rows[name],'whole Source byte/mode differs: '+name);found.add(name)
    expected_dirs={str(p) for name in rows for p in Path(relative(name)).parents if str(p)!='.'}
    need(found==set(rows) and directories==expected_dirs,'complete Source file/directory membership differs')
    contract_raw=read(root/'contract.json');need(pin(contract_raw)['sha256']==expected_contract,'whole actor contract differs')
    contract=decode(contract_raw);candidate=decode(read(root/'candidate-map.json'))
    need(contract['schema']==1 and contract['operation']==OPERATION and candidate['schema']==1 and
        candidate['commit']==contract['candidate']['commit']=='dd6871d566661c4fe9eba055ae19e1e017e0b69d' and
        candidate['files']==contract['candidate']['files'] and len(candidate['files'])==11,'exact eleven-file notice successor candidate contract')
    raw=read(root/'notice_binding.py');need(pin(raw)['sha256']=='e763ffd24c97e425b0065c0f2fe0c7bdb20a6524dab3129c0987b370000c2dce','exact notice successor binding program')
    binding=load('rust199_actor_notice_binding',root/'notice_binding.py',raw)
    need(candidate['notice_binding']==contract['candidate']['notice_binding']==binding.validate(root),'same complete effective candidate binding')
    binding.source_marker(root,candidate['notice_binding'])
    names=set()
    for path in (INPUTS/'candidate').rglob('*'):
        need(not path.is_symlink(),'candidate input alias refused')
        if path.is_file():names.add(str(path.relative_to(INPUTS/'candidate')))
    need(names==set(candidate['files']),'complete actor candidate membership')
    for name,row in candidate['files'].items():
        relative(name);path=INPUTS/'candidate'/name;body=read(path)
        need(body==read(root/'packages/port/rust199-source-reference'/name) and dict(**pin(body),mode=stat.S_IMODE(path.stat().st_mode))==row,'exact copied candidate leaf: '+name)
    return rows,contract


def normalized_fields(a):
    """Pure path projection of declarations already gated by the host/actor."""
    return dict(candidate_admission={k:a['candidate_admission'][k] for k in ('path','sha256')},stage0_tree_sha256=a['stage0_tree_sha256'],
        image_id=a['image']['id'],image_root=a['image_root'],rootfs_tree_sha256=a['image']['rootfs_tree_sha256'],qualified_llvm_tree_sha256=a['image']['qualified_llvm_tree_sha256'],
        materials={row['name']:dict(path='/materials/'+row['name'],bytes=row['bytes'],sha256=row['sha256']) for row in a['materials']})


def normalize(a):
    return dict(schema=1,operation=OPERATION,root_admission_sha256=pin(encode(a))['sha256'],**normalized_fields(a))


def descriptors(value):
    if type(value) is dict:
        if {'path','local_path','bytes','sha256'}<=set(value):yield value
        else:
            for child in value.values():yield from descriptors(child)
    elif type(value) is list:
        for child in value:yield from descriptors(child)


def actor_projection(a):
    remapped=copy.deepcopy(a);seen=set()
    for row in descriptors(remapped):
        need(row['path'].startswith('/inputs/') and row['path'] not in seen,'unique Root actor proof path');seen.add(row['path']);row['local_path']=row['path']
    need(len(seen)==16,'complete sixteen Root/provider/native proof operands')
    for row in remapped['materials']:row['local_path']='/materials/'+row['name']
    return remapped


def local_inputs(a,n,admission):
    """Verify each host-qualified operand at its fixed read-only actor path."""
    mapped=actor_projection(a);admission.external_proofs(mapped)
    for row in descriptors(mapped):admission.read_file(row['local_path'],max(8*MIB,row['bytes']),row)
    for row in mapped['materials']:
        need(row['transport']=='LOCAL_READONLY','no acquisition by an actor');admission.read_file(row['local_path'],row['bytes'],row)
    expected={'root-admission.json','actor-admission.json','volume-admission.json','volume-initialization.json'}|{'candidate/'+name for name in decode(read(SOURCE/'candidate-map.json'))['files']}
    for row in descriptors(mapped):
        name=relative(row['path'][len('/inputs/'):]);need(name not in expected,'Root proof cannot alias candidate or admission');expected.add(name)
    found=set()
    for path in INPUTS.rglob('*'):
        need(not path.is_symlink(),'actor input alias refused')
        if path.is_file():found.add(str(path.relative_to(INPUTS)))
        else:need(path.is_dir(),'actor input special node refused')
    need(found==expected,'closed actor readonly input namespace')


def installed_inventory(a):
    packages={}
    for path in Path('/var/lib/pacman/local').glob('*/desc'):
        need(len(packages)<600,'bounded actual ALPM inventory');rows=read(path,MIB).decode().splitlines()
        name,version=(rows[rows.index(key)+1] for key in ('%NAME%','%VERSION%'))
        need(name not in packages and re.fullmatch('[A-Za-z0-9@._+-]+',name) and re.fullmatch('[A-Za-z0-9:._+~-]+',version),'actual literal unique ALPM package')
        packages[name]=version
    raw=''.join(name+' '+version+'\n' for name,version in sorted(packages.items())).encode();row=a['image']['qualified_inventory']
    need(len(packages)==row['count'] and pin(raw)=={k:row[k] for k in ('bytes','sha256')} and raw==read(Path(row['path']),MIB),'actual installed normal image inventory differs')
    return pin(raw)


def gate(trust):
    need(set(trust)==set(TRUST) and all(sha(value) for value in trust.values()),'external host-provided actor trust pins')
    rows,contract=source_gate(SOURCE,trust['SOURCE_MAP_SHA256'],trust['CONTRACT_SHA256'])
    raw=read(INPUTS/'root-admission.json');need(pin(raw)['sha256']==trust['ROOT_ADMISSION_SHA256'],'raw externally admitted Root JSON differs')
    a=decode(raw);need(raw==encode(a),'canonical original Root JSON required')
    admission=load('rust199_root_admission',SOURCE/'admission.py',read(SOURCE/'admission.py'))
    admission.validate(a,check_files=False)
    need(a['source']['map_sha256']==trust['SOURCE_MAP_SHA256'] and a['candidate']['commit']==contract['candidate']['commit'] and a['candidate']['notice_binding']==contract['candidate']['notice_binding'],'actual Root Source/effective candidate joins')
    n=normalize(a);need(read(INPUTS/'actor-admission.json')==encode(n),'deterministic whole actor normalization differs')
    local_inputs(a,n,admission)
    installed_inventory(a)
    phase=load('rust199_actor_phase',SOURCE/'actor/phase.py',read(SOURCE/'actor/phase.py'))
    need(phase.CANDIDATE==INPUTS/'candidate','fixed frozen phase candidate location')
    owned=load('rust199_actor_owned_child',SOURCE/'helpers/owned_child.py',read(SOURCE/'helpers/owned_child.py'))
    volume=load('rust199_work_volume',SOURCE/'hosted/volume.py',read(SOURCE/'hosted/volume.py'))
    volume_raw=read(INPUTS/'volume-admission.json',16384)
    need(pin(volume_raw)['sha256']==trust['WORK_VOLUME_ADMISSION_SHA256'],'exact separately bound work-volume admission')
    value=decode(volume_raw);binding=volume.binding(a['source'],a['image']['id'],trust['ROOT_ADMISSION_SHA256'])
    need(value==volume.admission(binding),'work volume joins actual Source/image/Root admission')
    initialized=decode(read(INPUTS/'volume-initialization.json',16384));volume.verify_receipt(initialized,binding)
    return a,n,phase,owned,volume,value,initialized


def natural(row):
    return (row.get('natural_exit') is True and row.get('forced_cleanup') is False and row.get('retirement')=='REAPED' and row.get('group_absent') is True and
        row.get('leader_held_until_group_inspection') is True and row.get('exit_observed_via_waitpid') is True and row.get('ownership_lost') is False and not row.get('cleanup_error') and type(row.get('exit')) is int and row['exit']==0)


def command_environment(env,trust):
    need(set(trust)==set(TRUST) and all(sha(value) for value in trust.values()),'exact four inherited Root and work-volume pins')
    result=dict(env);result.update(trust);result['PYTHONDONTWRITEBYTECODE']='1';return result


def project_recipe(raw):
    for action in ('prepare','build','package'):
        suffix=' --destination "$pkgdir"' if action=='package' else ''
        old=f'  python -I "$srcdir/reference.py" {action} --work "$srcdir"{suffix} || return'.encode()
        new=f'  /usr/bin/python -I -B /source/actor/entry.py {action} || return'.encode()
        need(raw.count(old)==1 and new not in raw,'exact one frozen '+action+' hook')
        projected=raw.replace(old,new);need(projected.replace(new,old)==raw,'whole recipe hook inverse '+action);raw=projected
    return raw


def prepare_layout(n):
    need(not (WORK/'build').exists() and not (WORK/'recipe').exists(),'fresh prepare actor layout')
    (WORK/'build').mkdir(mode=0o700);recipe=WORK/'recipe';recipe.mkdir(mode=0o700)
    rows=decode(read(SOURCE/'candidate-map.json'))['files']
    for name,row in rows.items():
        source=SOURCE/'packages/port/rust199-source-reference'/relative(name);body=read(source)
        if name=='PKGBUILD':
            body=project_recipe(body);need(body==read(SOURCE/'recipe/PKGBUILD'),'exact Root-published effective recipe')
        target=recipe/name;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        with target.open('xb') as stream:stream.write(body);os.fchmod(stream.fileno(),row['mode'])
    for name,row in n['materials'].items():(recipe/relative(name)).symlink_to(row['path'])


def output_watch():
    total=logs=count=0
    for path in OUT.iterdir():
        info=path.lstat();count+=1;need(count<=256 and stat.S_ISREG(info.st_mode) and info.st_nlink==1 and not info.st_mode&0o111,'flat finite non-executable evidence output')
        total+=info.st_size
        if path.name.endswith(('.stdout','.stderr')) or '.log' in path.name:logs+=info.st_size
        need(total<=4*1024**3 and logs<=LOG_LIMIT and info.st_size<=2*1024**3,'aggregate evidence/log/package bound')


def retain(name,raw):
    target=OUT/name
    if target.exists():need(read(target,64*MIB)==raw,'existing immutable evidence differs: '+name)
    else:
        with target.open('xb') as stream:stream.write(raw)
    return dict(file=name,**pin(raw))


def execute(action,trust):
    need(action in ('prepare','build','package','makepkg'),'fixed actor action')
    a,n,phase,owned,volume,value,initialized=gate(trust)
    token=str(os.getpid())+'-'+uuid.uuid4().hex
    mount=load('rust199_actor_kernel_mount_proof',SOURCE/'actor/mount_proof.py',read(SOURCE/'actor/mount_proof.py'))
    mount_context=dict(source=a['source'],dispatch_sha256=a['authorization']['dispatch']['sha256'],input_admission_sha256=trust['ROOT_ADMISSION_SHA256'],image_id=a['image']['id'],volume_token=value['binding']['token'],phase=action)
    mount_raw,mount_receipt=mount.observe(mount_context,'kernel-mountinfo-'+action+'-'+token+'.raw')
    phase.kernel_guard('build' if action=='makepkg' else action);phase.readonly_inputs('build' if action=='makepkg' else action)
    observation=None
    if action in ('prepare','makepkg'):
        initial=WORK.lstat();initial_node=dict(device=initial.st_dev,inode=initial.st_ino,uid=initial.st_uid,gid=initial.st_gid,mode=stat.S_IMODE(initial.st_mode))
        print(json.dumps(dict(status='OBSERVED_WORK_ROOT_BEFORE_ENTRY',binding=value['binding'],actual=initial_node,uid=os.getuid(),gid=os.getgid(),phase=action),sort_keys=True),file=sys.stderr,flush=True)
        fd=os.open(WORK,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            info=os.fstat(fd);actual=dict(device=info.st_dev,inode=info.st_ino,uid=info.st_uid,gid=info.st_gid,mode=stat.S_IMODE(info.st_mode))
            need(stat.S_ISDIR(info.st_mode) and not WORK.is_symlink() and Path.cwd()==WORK and
                 (info.st_dev,info.st_ino)==(WORK.lstat().st_dev,WORK.lstat().st_ino),'same ordinary opened work root')
            need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==1001,'actual nonroot outer entry')
            writable=os.access(WORK,os.W_OK|os.X_OK,effective_ids=True) and not os.statvfs(WORK).f_flag&os.ST_RDONLY
            empty=not os.listdir(fd)
            print(json.dumps(dict(status='OBSERVED_OPEN_WORK_ROOT_BEFORE_VERIFICATION',binding=value['binding'],actual=actual,uid=os.getuid(),gid=os.getgid(),writable=writable,empty=empty,phase=action),sort_keys=True),file=sys.stderr,flush=True)
            observation=volume.verify_work(value,initialized,actual,os.getuid(),os.getgid(),writable,empty,action)
        finally:os.close(fd)
    need(WORK.is_dir() and not WORK.is_symlink(),'ordinary owned work volume');OUT.mkdir(mode=0o700,exist_ok=True)
    # fakeroot changes stat ownership to zero; kernel_guard has already checked
    # actual UID/GID1001. The parent makepkg entry established this same /work.
    info=OUT.lstat();need(stat.S_ISDIR(info.st_mode) and (info.st_uid==1001 or (action=='package' and info.st_uid==0)) and not info.st_mode&0o022,'owned protected append-only evidence directory; fakeroot package still requires kernel1001')
    mount_name='kernel-mount-proof-'+action+'-'+token+'.json';mount_body=encode(mount_receipt)
    mount_envelope=dict(receipt=retain(mount_name,mount_body),mountinfo=retain(mount_receipt['mountinfo']['file'],mount_raw))
    receipt=OUT/('phase-'+action+'-'+token+'.json')
    deadline=time.monotonic()+{'prepare':900,'build':14500,'package':600,'makepkg':16200}[action];cancelled=[False]
    previous={number:signal.getsignal(number) for number in (signal.SIGINT,signal.SIGTERM)}
    def cancel(number,frame):cancelled[0]=True
    def tick():need(not cancelled[0] and time.monotonic()<deadline,'actor cancellation/deadline');output_watch()
    def call(argv,*,timeout,cwd,env,capture=False):
        tick();need(type(argv) is list and all(type(x) is str for x in argv) and type(capture) is bool and type(timeout) in (int,float) and 0<timeout<=16200,'finite fixed callback operands')
        environment=command_environment(env,trust)
        name='cmd-'+str(os.getpid())+'-'+uuid.uuid4().hex;stdout,stderr=OUT/(name+'.stdout'),OUT/(name+'.stderr');record=OUT/(name+'.json')
        row=dict(kernel_mount_proof_sha256=mount_envelope['receipt']['sha256'],schema=1,phase=action,argv=argv,cwd=str(cwd),environment_sha256=pin(encode(environment))['sha256'],capture=capture,lifecycle={},returncode=None)
        record.write_bytes(encode(row))
        try:
            with stdout.open('xb') as out,stderr.open('xb') as error:
                result=owned.run(argv,timeout=min(timeout,deadline-time.monotonic()),cwd=cwd,env=environment,stdout=out,stderr=error,
                    stdout_limit=LOG_LIMIT//2,stderr_limit=LOG_LIMIT//2,lifecycle=row['lifecycle'],allowed_uids={1001},on_tick=tick)
            row['returncode']=result.returncode;need(type(result.returncode) is int and result.returncode==0 and natural(row['lifecycle']),'actual owned command natural-zero retirement required')
            if capture:result.stdout=read(stdout,MIB);result.stderr=read(stderr,MIB)
            tick();return result
        finally:
            for label,path in (('stdout',stdout),('stderr',stderr)):
                if path.exists():row[label]=dict(file=path.name,**pin(read(path,LOG_LIMIT)))
            record.write_bytes(encode(row))
    result=dict(kernel_mount_proof=mount_envelope,schema=1,status='FAIL',action=action,root_admission_sha256=trust['ROOT_ADMISSION_SHA256'],native_acceptance=False,holds_preserved=True)
    old_fsize=resource.getrlimit(resource.RLIMIT_FSIZE)
    try:
        for number in previous:signal.signal(number,cancel)
        if observation is not None:result['work_preentry']=retain('work-preentry-'+action+'.json',encode(observation))
        if action=='prepare':prepare_layout(n)
        if action=='makepkg':
            need((WORK/'build/prepared.json').is_file() and (WORK/'recipe/PKGBUILD').read_bytes()==read(SOURCE/'recipe/PKGBUILD'),'only the successfully prepared fixed recipe')
            soft=2*1024**3 if old_fsize[0]==resource.RLIM_INFINITY else min(old_fsize[0],2*1024**3);resource.setrlimit(resource.RLIMIT_FSIZE,(soft,old_fsize[1]))
            inventory=call(['/usr/bin/pacman','-Q'],timeout=30,cwd=WORK/'recipe',env=phase.environment(n['candidate_admission']['sha256'],n['stage0_tree_sha256']),capture=True).stdout
            lines=inventory.decode().splitlines();need(1<=len(lines)<=600 and len(set(lines))==len(lines),'actual finite complete pacman query')
            inventory=('\n'.join(sorted(lines))+'\n').encode();need(inventory==read(Path(a['image']['qualified_inventory']['path']),MIB),'actual pacman query differs from qualified image')
            result['inventory']=retain('actual-packages.txt',inventory)
            result['command']=call(['/usr/bin/makepkg','--noextract','--noprepare','--nosign','--noconfirm','--log','--config','/source/actor/makepkg.conf'],timeout=16200,cwd=WORK/'recipe',env=phase.environment(n['candidate_admission']['sha256'],n['stage0_tree_sha256'])).returncode
            package=OUT/PACKAGE;info=package.lstat();need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and 0<info.st_size<=2*1024**3,'actual bounded exact Rust package')
            with package.open('rb') as stream:result['package']=dict(file=PACKAGE,bytes=info.st_size,sha256=hashlib.file_digest(stream,'sha256').hexdigest())
            need(all((WORK/'build'/name).is_file() for name in ('prepared.json','built.json')),'actual candidate prepare/build records required')
        else:result['phase']=phase.run_phase(action,n,call)
        tick();result['status']='COMPLETED_ACTOR_ACTION_DATA';return result
    except BaseException as error:result['error']=type(error).__name__+': '+str(error);raise
    finally:
        try:
            resource.setrlimit(resource.RLIMIT_FSIZE,old_fsize)
            if action=='makepkg':
                for name in ('prepared.json','built.json'):
                    if (WORK/'build'/name).exists():result[name]=retain(name,read(WORK/'build'/name))
            output_watch()
        except BaseException as error:
            result.update(status='FAIL',finalization_error=type(error).__name__+': '+str(error));raise
        finally:
            for number,handler in previous.items():signal.signal(number,handler)
            with receipt.open('xb') as stream:stream.write(encode(result))


if __name__=='__main__':
    need(sys.flags.isolated and not sys.flags.optimize and len(sys.argv)==2,'isolated unoptimized fixed actor CLI required')
    execute(sys.argv[1],{key:os.environ.get(key) for key in TRUST})
