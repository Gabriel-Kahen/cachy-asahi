"""Owned software-ARM guest for original341 exact private check only."""
import argparse,ast,base64,fcntl,hashlib,importlib.util,json,os,re,shlex,shutil,stat,subprocess,sys,time,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
M=1024**2
PURPOSE='SUPPORT_ORIGINAL341_GUEST_CHECK_V1'
PUBLIC={'guest.json','guest-child.log','proof/proof-input.json','proof/proof-result.json','proof/check.log','proof/commands.json','proof/logs/inventory.log'}
LABEL='org.cachy-asahi.support-native'
CAPS=['CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETFCAP']
RUNTIME={'proc','sys','dev','run','tmp'}
INFRA={'source','workspace','measurement'}
MOUNT_FILES={'etc/hosts','etc/hostname','etc/resolv.conf'}
def need(v,s):
    if not v:raise ValueError(s)
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(v):return dict(bytes=len(v),sha256=hashlib.sha256(v).hexdigest())
def decode(v):
    def pairs(rows):
        d={}
        for k,x in rows:need(k not in d,'duplicate JSON');d[k]=x
        return d
    return json.loads(v,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite JSON'))
def relative(v):
    need(type(v)is str and 0<len(v)<=4096 and not v.startswith('/')and all(re.fullmatch('[A-Za-z0-9_.+-]+',p)for p in v.split('/')),'portable relative DATA');return v
def identity(s):return(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(path,cap=8*M):
    path=Path(path);need(not any(p.is_symlink()for p in(path,*path.parents)),'ordinary ancestry');a=path.lstat()
    need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded regular DATA');raw=path.read_bytes();need(len(raw)==a.st_size and identity(path.lstat())==identity(a),'stable whole DATA');return raw
def save(path,v):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb')as f:f.write(encoded(v))
    path.chmod(0o600)
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);v=importlib.util.module_from_spec(spec);sys.modules[name]=v;spec.loader.exec_module(v);return v
def config():return decode(read(HERE/'guest_inputs.json',2*M))
def serial(nonce,role):
    need(re.fullmatch('[0-9a-f]{32}',nonce or'')and role in('boot','data'),'nonce disk role')
    return base64.b85encode(hashlib.sha256(b'cachy-asahi/core7/virtio-blk/serial-v1\0'+role.encode()+b'\0'+bytes.fromhex(nonce)).digest()[:16]).decode()
def tree_id(rows,bodies):
    def visit(prefix):
        raw=b'';names={n[len(prefix):].split('/')[0]for n in rows if n.startswith(prefix)}
        for name in sorted(names,key=lambda n:(n+('/'if prefix+n not in rows else'')).encode()):
            key=prefix+name
            if key in rows:mode=b'100755'if rows[key]['mode']==493 else b'100644';body=bodies[key];digest=hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).digest()
            else:mode=b'40000';digest=visit(key+'/')
            raw+=mode+b' '+name.encode()+b'\0'+digest
        return hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).digest()
    return visit('').hex()
def providers():
    rows=config()['providers'];base=HERE/'guest-providers';actual={p.relative_to(base).as_posix()for p in base.rglob('*')if p.is_file()}
    need(len(rows)==45 and actual==set(rows)and not any(p.is_symlink()for p in base.rglob('*')),'complete45 provider namespace')
    for n,r in rows.items():need(dict(pin(read(base/relative(n),r['bytes'])),mode=stat.S_IMODE((base/n).stat().st_mode))==r,'whole pinned provider')
    return base
def kernel_inputs(root,work,temp):
    p=config()['kernel'];carrier=temp/'support-guest-kernel';rows=p['carrier_files'];bodies={};actual={}
    for folder,dirs,files in os.walk(carrier):
        if Path(folder)==carrier and '.git'in dirs:dirs.remove('.git')
        need(not any((Path(folder)/n).is_symlink()for n in(*dirs,*files)),'ordinary carrier paths')
        for n in files:actual[(Path(folder)/n).relative_to(carrier).as_posix()]=Path(folder)/n
    need(set(actual)==set(rows)and len(rows)==28,'exact complete28 kernel carrier')
    for n,r in rows.items():
        raw=read(actual[n],r['bytes']);need(dict(pin(raw),mode=stat.S_IMODE(actual[n].stat().st_mode))==r,'exact kernel bytes/mode');bodies[n]=raw
    need(tree_id(rows,bodies)==p['carrier_tree'],'whole kernel carrier tree')
    target=work/'kernel-inputs';payload=target/'kernel';payload.mkdir(parents=True)
    for n,raw in bodies.items():need(n.startswith('payload/')and'/'not in n[8:],'flat kernel leaves');(payload/n[8:]).write_bytes(raw)
    base=providers();old=sys.path[:]
    try:
        need('contract'not in sys.modules,'no foreign kernel contract');sys.path.insert(0,str(base));K=module('_support_pinned_kernel',base/'kernel_input.py')
        need(Path(K.C.__file__).resolve()==base/'contract.py','original Core kernel contract')
        profile,receipt,image,conf=K.imported(p['kernel'],target,base)
    finally:sys.path[:]=old;sys.modules.pop('contract',None)
    need(profile==p['kernel']['profile']and pin(read(image,16*M))==profile['Image']and pin(read(conf,M))==profile['config'],'original imported build authority')
    shutil.copyfile(image,work/'Image');save(work/'kernel.json',dict(status='PINNED_CORE_BUILD_DATA_ONLY',profile=profile,import_receipt=receipt,carrier_source=p['carrier_source'],carrier_tree=p['carrier_tree'],acceptance=False))
    return dict(release=profile['release'],Image=profile['Image'],config=profile['config'])
def qemu(image,boot,data,s):
    n=s['nonce'];epoch=s['launcher_epoch_s'];need(re.fullmatch('[0-9a-f]{32}',n)and type(epoch)is int and 1700000000<=epoch<2**32,'actual launch binding')
    cmdline='console=ttyAMA0 root=/dev/vda rw rootwait devtmpfs.mount=1 init=/init-support panic=1 arm64.nomops support_vm='+n+' caa_core_vm='+n+' caa_core_phase=1 caa_core_realtime='+str(epoch)+' support_kernel_sha256='+s['kernel']['Image']['sha256']
    return ['/usr/bin/qemu-system-aarch64','-nodefaults','-machine','virt','-accel','tcg,thread=multi','-cpu','max','-smp','2','-m','4096','-nic','none','-display','none','-monitor','none','-no-reboot','-kernel',str(image),'-append',cmdline,'-drive','if=none,id=boot,format=raw,file='+str(boot),'-device','virtio-blk-pci,drive=boot,serial='+serial(n,'boot'),'-drive','if=none,id=data,format=raw,file='+str(data),'-device','virtio-blk-pci,drive=data,serial='+serial(n,'data'),'-serial','stdio']
def bootstrap(s):
    n=s['nonce'];lines=['#!/usr/bin/bash','set -euo pipefail','export PATH=/usr/bin:/bin LC_ALL=C LANG=C','test "$(id -u)" = 0','mount -t proc -o nosuid,nodev,noexec proc /proc','grep -qw "support_vm='+n+'" /proc/cmdline','mount -t sysfs -o nosuid,nodev,noexec sysfs /sys','test "$(cat /sys/class/block/vda/serial)" = '+shlex.quote(serial(n,'boot')),'test "$(cat /sys/class/block/vdb/serial)" = '+shlex.quote(serial(n,'data')),'mount -o remount,nosuid /dev','mkdir -p /dev/pts','mount -t devpts -o nosuid,noexec,gid=5,mode=620 devpts /dev/pts','mount -t tmpfs -o nosuid,nodev,size=512m,mode=1777 tmpfs /tmp','mount -t tmpfs -o nosuid,nodev,size=128m,mode=755 tmpfs /run','mkdir -p /sys/fs/cgroup','mount -t cgroup2 -o nosuid,nodev,noexec cgroup2 /sys/fs/cgroup','mkdir /volume','mount -t ext4 -o rw,nosuid,nodev /dev/vdb /volume','mount --bind /volume/support /support','umount /volume','rmdir /volume']
    for name in('source','proof-root'):lines+=['mount --bind /support/'+name+' /support/'+name,'mount -o remount,bind,ro /support/'+name]
    return ('\n'.join(lines+['exec /usr/bin/python3 -I -B /support/source/native/guest_check.py'])+'\n').encode()
def media_guard(s):
    need(os.getpid()==1 and os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0 and os.uname().machine=='aarch64'and Path('/.dockerenv').is_file(),'ordinary owned ARM media PID1')
    need(os.environ.get('SUPPORT_VM_NONCE')==s['nonce']and os.environ.get('SUPPORT_VM_IMAGE')==s['image']and {p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'same-image nonce offline media')
    fields=dict(line.split(':',1)for line in Path('/proc/self/status').read_text().splitlines()if':'in line);mask=0x8000001b
    need(all(int(fields[k],16)==mask for k in('CapEff','CapPrm','CapBnd'))and int(fields['CapInh'],16)==int(fields['CapAmb'],16)==0 and fields['NoNewPrivs'].strip()=='1','exact five-cap metadata copy only')
def media_apis():
    base=providers()/'media-source';update=base/'scripts/update';c=types.ModuleType('contract');c.__dict__.update(need=need,read=read,decode=decode,encoded=encoded,pin=pin,sha=lambda b:pin(b)['sha256'],row=lambda p:pin(read(p)),relative=relative,save=save);sys.modules['contract']=c
    for n in('capacity','supervision','full_root','measure_copy','root_path'):module(n,update/(n+'.py'))
    scope=module('_support_scope',base/'scripts/ci/full-root-upgrade-caller/persistent_scope.py');scope.RUNTIME=RUNTIME;scope.INFRASTRUCTURE=INFRA;scope.MOUNT_FILES=MOUNT_FILES
    caps=module('_support_caps',base/'scripts/ci/current604-public-pair-updater16k/cap_scope.py');audit=module('_support_elf',base/'scripts/ci/managed-gui-generic16k/elf_audit.py');reader=module('_support_reader',base/'scripts/virtual/generic16k/fixture.py')
    raw=read(base/'scripts/ci/current604-public-pair-updater16k/disk.py');nodes=[n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name in('image_directory','formatter_recovery_directory')];need(len(nodes)==2,'whole two original formatter helpers');ns=dict(C=c,Path=Path,stat=stat,os=os,command=command);exec(compile(ast.Module(body=nodes,type_ignores=[]),'pinned-original-formatters','exec'),ns)
    return types.SimpleNamespace(scope=scope,roots=sys.modules['full_root'],copier=sys.modules['measure_copy'],caps=caps,audit=audit,reader=reader,formatter=ns['formatter_recovery_directory'],image_directory=ns['image_directory'])
_COMMAND_COUNTER=0
def command(argv,seconds=600):
    global _COMMAND_COUNTER
    _COMMAND_COUNTER+=1;need(_COMMAND_COUNTER<=256 and 0<seconds<=1200,'finite media commands')
    root=Path('/source');owned=module('_support_media_owned',root/'bootstrap/scripts/ci/zlib-pgo-native-hosted/owned_child.py');state={}
    result=owned.run(list(map(str,argv)),timeout=seconds,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,stdout_limit=2*M,stderr_limit=2*M,lifecycle=state,allowed_uids={0})
    need(result.returncode==0 and state.get('exit')==0 and state.get('natural_exit')is True and state.get('group_absent')is True and state.get('retirement')=='REAPED'and state.get('forced_cleanup')is False and state.get('ownership_lost')is False,'natural owned media command')
    need(len(result.stdout)<=2*M,'bounded complete media log');return result.stdout
def mount_policy(rows):
    need(type(rows)is list and rows and len(rows)<=4096,'bounded mount rows');d={r['path']:r for r in rows};need(len(d)==len(rows)and'/'in d and all('/'+n in d for n in INFRA),'exact media infrastructure')
    root=d['/']['id'];out=d['/measurement'];need(out['id']!=root and out['fs']not in{'tmpfs','ramfs','proc','sysfs','devtmpfs','overlay'},'separate persistent media output')
    observed=[]
    for row in rows:
        n=row['path'].lstrip('/')
        if not n:continue
        need(n.split('/')[0]in RUNTIME or n in INFRA or n in MOUNT_FILES,'unlisted persistent media mount');observed.append(n)
    return dict(source_mount=root,target_mount=out['id'],observed_mounts=sorted(observed))
def inventory(root,nodes):
    values=[]
    for name,node in nodes.items():
        if not re.fullmatch(r'var/lib/pacman/local/[^/]+/desc',name):continue
        raw=read(Path(root)/name,65536);need(pin(raw)=={k:node[k]for k in('bytes','sha256')},'installed DB body');lines=raw.decode().splitlines();pair=[]
        for key in('NAME','VERSION'):
            positions=[i for i,line in enumerate(lines)if line=='%'+key+'%'];need(len(positions)==1,'unique installed DB field');pair.append(lines[positions[0]+1])
        need(all(v and not any(c.isspace()for c in v)for v in pair),'finite installed identity');values.append(' '.join(pair))
    need(len(values)==341 and len({v.split()[0]for v in values})==341,'complete original341');return ('\n'.join(sorted(values))+'\n').encode()
def role_copy(source,target,rows):
    actual=set()
    for folder,dirs,files in os.walk(source):
        if Path(folder)==source and '.git'in dirs:dirs.remove('.git')
        need(not any((Path(folder)/n).is_symlink()for n in(*dirs,*files)),'ordinary source role')
        actual.update((Path(folder)/n).relative_to(source).as_posix()for n in files)
    need(actual==set(rows),'complete source role closure')
    for name,row in rows.items():
        raw=read(source/relative(name),row['bytes']);need(pin(raw)=={k:row[k]for k in('bytes','sha256')},'source role pin');path=target/name;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb')as f:f.write(raw)
        path.chmod(row['mode'])
def inode_time_commands(prefix,nodes):
    rows=[]
    for name,node in sorted(nodes.items()):
        path=prefix+'/'+name;need(not any(c in path for c in('\n','\r','\0','"','\\')),'literal debugfs metadata path')
        ns=node['mtime_ns'];need(type(ns)is int and 0<=ns<2**64,'finite original mtime')
        sec,nano=divmod(ns,10**9);extra=(nano<<2)|((sec>>32)&3)
        rows+=['set_inode_field "'+path+'" mtime '+str(sec&0xffffffff),'set_inode_field "'+path+'" mtime_extra '+str(extra)]
    return rows
def proof_placeholders(root,snapshot):
    original_nodes,original_caps=snapshot(root);overlay={}
    for name in('dev','proc','sys','run','home','root','tmp','source','work','etc/pacman.d/gnupg'):
        path=root/name
        if os.path.lexists(path):
            need(path.is_dir()and not path.is_symlink(),'ordinary held proof mountpoint')
            if name in('source','work'):need(not any(path.iterdir()),'empty source/work bind destination')
        else:path.mkdir(parents=True,mode=0o755);need(not any(path.iterdir()),'fresh empty proof mountpoint');overlay[name]=dict(before=None,after='EMPTY_DIRECTORY_0755_ROOT')
    for name,node in original_nodes.items():
        if node['kind']=='directory':
            path=root/name;os.utime(path,ns=(path.stat().st_atime_ns,node['mtime_ns']),follow_symlinks=False)
    nodes,caps=snapshot(root);need(all(nodes[name]==row and caps[name]==original_caps[name]for name,row in original_nodes.items())and all(caps[name]=={}for name in overlay)and set(nodes)-set(original_nodes)==set(overlay),'only exact fresh empty mountpoint overlay')
    return nodes,caps,overlay,original_nodes
def media_prepare(s):
    out=Path('/measurement');need(not any(out.iterdir())and shutil.disk_usage(out).free>=48*1024**3,'fresh bounded48GiB media area');a=media_apis();stage=out/'stage';stage.mkdir(mode=0o700);st=stage.lstat();save(out/'stage-owner.json',dict(nonce=s['nonce'],device=st.st_dev,inode=st.st_ino));data=stage/'data';support=data/'support';support.mkdir(parents=True)
    def limits():return a.roots.Limits(deadline=time.monotonic()+900,max_nodes=500000,max_bytes=8*1024**3,max_file_bytes=1024**3,max_package_files=100000)
    policy=mount_policy(a.scope.mounts(a.scope._mount_table()));before,_=a.scope.source_manifest(Path('/'),limits(),a.roots,policy)
    capability=a.caps.derive(read(providers()/'media-source/scripts/apps/file_capabilities.py'),set(policy['observed_mounts'])|RUNTIME);caps=capability.observe(Path('/'),a.caps.nodes(before),limits())
    roots={'boot':stage/'boot','proof':support/'proof-root'}
    for target in roots.values():
        copied=a.copier.copy_data(Path('/'),target,limits=limits(),excluded=RUNTIME|(INFRA&set(policy['observed_mounts']))|MOUNT_FILES,absolute_paths=True)
        need(not copied['unsupported_counts'],'complete original341 copy');a.scope._restore_boundaries(Path('/'),target,before,a.roots,a.copier,limits())
        result=a.roots.observe(target,limits=limits(),hardlinks='generic-development-internal',absolute_paths=True);need(result['complete']is True and result['nodes']==before,'all original341 nodes/content/hardlinks')
        capability.restore(target,a.caps.nodes(before),caps,limits())
    after,_=a.scope.source_manifest(Path('/'),limits(),a.roots,policy);need(before==after and caps==capability.observe(Path('/'),a.caps.nodes(after),limits()),'source original341 unchanged')
    expected=read(Path('/source/native/original341.lock'));need(pin(expected)['sha256']=='fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'and inventory(Path('/'),before)==inventory(roots['proof'],before)==expected,'complete byte-bound original341 DB')
    guest=module('_support_media_snapshot',Path('/source/native/guest_check.py'));nodes,capabilities,placeholder_overlay,original_nodes=proof_placeholders(roots['proof'],guest.root_snapshot)
    s=dict(s,root_nodes_sha256=pin(encoded(nodes))['sha256'],capabilities_sha256=pin(encoded(capabilities))['sha256'])
    save(support/'baseline-nodes.json',nodes);save(support/'capabilities.json',capabilities);role_copy(Path('/source'),support/'source',s['source_manifest'])
    (support/'work').mkdir(mode=0o700);(support/'public').mkdir(mode=0o700)
    proof=dict(schema=1,binding=s['binding'],source_map_sha256=s['source_map_sha256'],image=s['image'],recipe_root=s['recipe_root'],recipe_sha256=s['recipe_sha256'],source_files=s['proof_files'],original341_sha256=pin(expected)['sha256']);save(support/'work/proof-input.json',proof)
    for path in [support/'proof-root',support/'source',support/'work',support/'work/proof-input.json']:os.chown(path,s['uid'],s['gid'])
    save(support/'selection.json',s);boot=roots['boot'];need(not any(os.path.lexists(boot/n)for n in('support','init-support','volume')),'fresh guest overlay')
    (boot/'support').mkdir(mode=0o700);init=bootstrap(s);(boot/'init-support').write_bytes(init);(boot/'init-support').chmod(0o755)
    overlay={'init-support':dict(type='file',mode=0o755,uid=0,gid=0,**pin(init)),'support':dict(type='directory',mode=0o700,uid=0,gid=0)}
    marker=boot/'.dockerenv'
    if os.path.lexists(marker):need(marker.is_file()and not marker.is_symlink()and marker.stat().st_size==0,'empty original Docker marker');marker.unlink();overlay['.dockerenv']=None
    machine=boot/'etc/machine-id';need(machine.is_file()and not machine.is_symlink(),'ordinary machine-id overlay');overlay['etc/machine-id']=dict(before=pin(read(machine,128)),after=pin((s['nonce']+'\n').encode()));machine.write_text(s['nonce']+'\n')
    save(out/'overlay.json',overlay);save(out/'elf16k.json',a.audit.audit(boot,a.reader));save(out/'root-snapshot.json',dict(schema=1,status='MEDIA_SOURCE_COPY_READBACK_ONLY_NOT_GUEST_PROOF',image=s['image'],binding=s['binding'],nonce=s['nonce'],source_map_sha256=s['source_map_sha256'],nodes_sha256=s['root_nodes_sha256'],capabilities_sha256=s['capabilities_sha256'],node_count=len(nodes),capability_count=len(capabilities),original_provider_nodes_before=pin(encoded(before)),original_provider_nodes_after=pin(encoded(after)),original_snapshot=pin(encoded(original_nodes)),placeholder_overlay=placeholder_overlay,copied_readback_equal=True,original_preserved=True,inventory=dict(count=341,pin=pin(expected)),root_directory_owner_overlay=[s['uid'],s['gid']],guest_actual_snapshot='REQUIRED_NOT_INFERRED_FROM_MEDIA'))
    for name,size in [('boot',16*1024**3),('data',24*1024**3)]:
        target=stage/name;allocated=sum(p.lstat().st_blocks*512 for p in target.rglob('*'));need(allocated<=10*1024**3 and shutil.disk_usage(out).free>=allocated+8*1024**3,'finite media allocation')
        image=out/(name+'.raw')
        with image.open('xb')as f:f.truncate(size)
        image.chmod(0o600)
        command(['/usr/bin/mkfs.ext4','-F','-b','4096','-m','0','-L','SUPPORT_'+name.upper(),'-d',target,image],1200)
        if name=='boot':a.formatter(image,before,out)
        else:
            rows=inode_time_commands('/support/proof-root',nodes)
            for offset in range(0,len(rows),4000):
                batch=out/'times.batch';batch.write_text('\n'.join(rows[offset:offset+4000])+'\n');command(['/usr/bin/debugfs','-w','-f',batch,image],120);batch.unlink()
    current=stage.lstat();need((current.st_dev,current.st_ino)==(st.st_dev,st.st_ino)and not stage.is_mount()and shutil.rmtree.avoids_symlink_attacks,'exact stage inode cleanup');shutil.rmtree(stage)
    save(out/'selection-final.json',s);save(out/'prepared.json',dict(status='PREPARED_ORIGINAL341_GUEST_MEDIA_NOT_BOOTED',nonce=s['nonce'],image=s['image'],kernel=s['kernel'],source_map_sha256=s['source_map_sha256'],root_nodes_sha256=s['root_nodes_sha256'],capabilities_sha256=s['capabilities_sha256'],serials={n:serial(s['nonce'],n)for n in('boot','data')},boot_bytes=16*1024**3,data_bytes=24*1024**3,metadata_readback='ACTUAL_GUEST_SNAPSHOT_REQUIRED',acceptance=False))
    for p in out.iterdir():os.chown(p,s['uid'],s['gid'])
def public_index(index,s):
    fields={'schema','purpose','nonce','binding','status','result_status','files','bytes','acceptance'}
    need(type(index)is dict and set(index)==fields and index['schema']==1 and index['purpose']=='SUPPORT_GUEST_PUBLIC_INDEX_V1'and index['nonce']==s['nonce']and index['binding']==s['binding']and index['status']=='GUEST_PUBLIC_DATA_ONLY'and index['acceptance']is False,'closed exact public index')
    need(type(index['files'])is dict and 0<len(index['files'])<=len(PUBLIC)and set(index['files'])<=PUBLIC and type(index['result_status'])is str,'finite proof public roles')
    total=0
    for name,row in index['files'].items():
        relative(name);need(type(row)is dict and set(row)=={'bytes','sha256'}and type(row['bytes'])is int and 0<=row['bytes']<=8*M and re.fullmatch('[a-f0-9]{64}',row['sha256']or''),'bounded public pin');total+=row['bytes']
    need(type(index['bytes'])is int and index['bytes']==total and total<=24*M,'exact public aggregate');return index
def media_export(s):
    out=Path('/measurement');a=media_apis();image=out/'data.raw';held=image.lstat();need(stat.S_ISREG(held.st_mode)and held.st_nlink==1 and held.st_uid==s['uid']and held.st_size==24*1024**3,'exact original data inode')
    target=out/'guest-export';target.mkdir(mode=0o700);cache={};seen={}
    def listing(parent):
        if parent not in cache:cache[parent]=a.image_directory(command(['/usr/bin/debugfs','-R','ls -p /support/public'+('/'+parent if parent else''),image],60))
        return cache[parent]
    def entry(name):
        parent='';parts=relative(name).split('/')
        for component in parts[:-1]:
            node=listing(parent).get(component);need(node is not None and stat.S_ISDIR(node['mode'])and node['uid']==node['gid']==0,'ordinary root-owned public parent');parent=parent+'/'+component if parent else component
        node=listing(parent).get(parts[-1]);need(node is not None and stat.S_ISREG(node['mode'])and node['uid']==node['gid']==0 and 0<=node['size']<=8*M,'ordinary bounded root-owned public leaf');need(node['inode']not in seen or seen[node['inode']]==name,'public inode aliases refused');seen[node['inode']]=name;return node
    def get(name):
        node=entry(name);path=target/name;need(re.fullmatch('[A-Za-z0-9_./+-]+',str(path))is not None,'literal debugfs destination');path.parent.mkdir(parents=True,exist_ok=True)
        command(['/usr/bin/debugfs','-R','dump /support/public/'+name+' '+str(path),image],120);raw=read(path);need(len(raw)==node['size'],'whole original public leaf');return raw
    need(entry('index.json')['size']<=65536,'bounded public index');index=public_index(decode(get('index.json')),s);files={'index.json':pin(read(target/'index.json'))}
    for name,row in sorted(index['files'].items()):
        need(entry(name)['size']==row['bytes'],'exact indexed leaf size');raw=get(name);need(pin(raw)==row,'exact public original leaf pin');files[name]=row
    need(identity(image.lstat())==identity(held),'data inode unchanged through export');save(out/'guest-export.json',dict(status='EXACT_SUPPORT_GUEST_PUBLIC_DATA_ONLY',nonce=s['nonce'],binding=s['binding'],files=files,result_status=index['result_status'],acceptance=False))
    for path in sorted(target.rglob('*'),reverse=True):os.chown(path,s['uid'],s['gid'])
    os.chown(target,s['uid'],s['gid']);os.chown(out/'guest-export.json',s['uid'],s['gid'])
def media_scrub(s):
    out=Path('/measurement');path=out/'stage';owner=decode(read(out/'stage-owner.json'));st=path.lstat();need(owner==dict(nonce=s['nonce'],device=st.st_dev,inode=st.st_ino)and stat.S_ISDIR(st.st_mode)and not path.is_symlink()and not path.is_mount()and shutil.rmtree.avoids_symlink_attacks,'same nonce/inode stage cleanup');shutil.rmtree(path)
def media_main(role):
    s=decode(read(Path('/workspace/selection.json'),2*M));need(s['schema']==1 and s['purpose']==PURPOSE and re.fullmatch('[a-f0-9]{32}',s['nonce'])and re.fullmatch('sha256:[a-f0-9]{64}',s['image'])and s['budgets']==config()['budgets'],'explicit finite media selection');media_guard(s)
    {'prepare':media_prepare,'export':media_export,'scrub':media_scrub}[role](s)
def tool_identity(path):
    path=Path(path);raw=read(path,64*M);st=path.stat();need(st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o755,'ordinary exact root0755 host tool')
    try:os.getxattr(path,'security.capability',follow_symlinks=False)
    except OSError as error:need(error.errno in(__import__('errno').ENODATA,__import__('errno').ENOTSUP),'observed file capability absence only');observation=__import__('errno').errorcode[error.errno]
    else:raise ValueError('host tool file capability present')
    return dict(path=str(path),**pin(raw),mode=0o755,uid=0,gid=0,file_capabilities=dict(status='ABSENT',observation=observation))
def disk_pin(path,size,deadline):
    path=Path(path);st=path.lstat();need(not any(p.is_symlink()for p in(path,*path.parents))and stat.S_ISREG(st.st_mode)and st.st_nlink==1 and st.st_uid==os.getuid()and stat.S_IMODE(st.st_mode)==0o600 and st.st_size==size,'exact owned disk')
    digest=hashlib.sha256()
    with path.open('rb')as stream:
        while block:=stream.read(M):need(time.monotonic()<deadline,'whole disk hash deadline');digest.update(block)
    need(identity(path.stat())==identity(st),'whole disk hash inode held');return dict(bytes=size,sha256=digest.hexdigest(),device=st.st_dev,inode=st.st_ino,uid=st.st_uid,mode=0o600)
def helper_check(row,s,role,root,workspace,disks):
    h=row['HostConfig'];c=row['Config'];need(row['Image']==s['image']and row['Name']=='/support-guest-'+s['nonce']+'-'+role and c['User']=='0:0'and c['Labels'].get(LABEL)==s['token']and c['Labels'].get(LABEL+'.guest')==s['nonce'],'exact helper identity')
    need(h['NetworkMode']=='none'and h['ReadonlyRootfs']is True and h['Privileged']is False and set(h['CapDrop'])=={'ALL'}and {v.removeprefix('CAP_')for v in h.get('CapAdd')or[]}==set(CAPS)and h['SecurityOpt']==['no-new-privileges']and h['Memory']==2*1024**3 and h['NanoCpus']==2_000_000_000 and h['PidsLimit']==256,'exact fivecap offline helper')
    need(not h.get('Devices')and not h.get('DeviceRequests')and not h.get('VolumesFrom')and not h.get('PortBindings'),'no host devices or extra authority')
    binds={(m['Source'],m['Destination'],m['RW'])for m in row['Mounts']if m['Type']=='bind'}
    need(binds=={(str(root),'/source',False),(str(workspace),'/workspace',False),(str(disks),'/measurement',True)}and set(h['Tmpfs'])=={'/tmp'}and all(m['Type']=='bind'or(m['Type']=='tmpfs'and m['Destination']=='/tmp')for m in row['Mounts']),'exact media roles')
    need(c['Entrypoint']==['/usr/bin/python3']and c['Cmd']==['-I','-B','/source/native/guest_vm.py','--media',role]and h.get('PidMode')in('',None)and h.get('UTSMode')in('',None)and h.get('UsernsMode')in('',None),'exact helper entry/no host namespaces')
def helper_create(actor,s,role,root,workspace,disks,record):
    record.update(role=role,name='support-guest-'+s['nonce']+'-'+role,cid=None,absent=False)
    args=['create','--name',record['name'],'--pull=never','--platform=linux/arm64','--user=0:0','--cap-drop=ALL','--security-opt=no-new-privileges','--read-only','--network=none','--pids-limit=256','--memory=2g','--cpus=2','--tmpfs=/tmp:rw,nosuid,nodev,size=512m','--label',LABEL+'='+s['token'],'--label',LABEL+'.guest='+s['nonce'],'--env','SUPPORT_VM_NONCE='+s['nonce'],'--env','SUPPORT_VM_IMAGE='+s['image']]
    for cap in CAPS:args+=['--cap-add='+cap]
    for source,target,readonly in[(root,'/source',True),(workspace,'/workspace',True),(disks,'/measurement',False)]:args+=['--mount','type=bind,src='+str(source)+',dst='+target+(',readonly'if readonly else'')]
    args+=['--entrypoint=/usr/bin/python3',s['image'],'-I','-B','/source/native/guest_vm.py','--media',role]
    cid=actor.docker(*args,timeout=60);need(re.fullmatch('[a-f0-9]{64}',cid),'actual helper CID');record['cid']=cid
    before=json.loads(actor.docker('inspect',cid))[0];need(before['Id']==cid,'same actual helper CID');helper_check(before,s,role,root,workspace,disks);record['before']=before;actor.docker('start','--attach',cid,timeout=config()['budgets']['media']if role=='prepare'else config()['budgets']['export'])
    row=json.loads(actor.docker('inspect',cid))[0];record['after']=row;need(row['Id']==cid,'same actual stopped CID');helper_check(row,s,role,root,workspace,disks);need(row['State']['Running']is False and row['State']['ExitCode']==0 and row['State'].get('OOMKilled')is False,'actual stopped successful helper');actor.docker('rm',cid,timeout=30)
    need(not actor.docker('ps','-aq','--no-trunc','--filter','id='+cid,timeout=30),'exact helper absent');record['absent']=True
def natural(state):
    return state.get('exit')==0 and state.get('natural_exit')is True and state.get('group_absent')is True and state.get('retirement')=='REAPED'and state.get('leader_held_until_group_inspection')is True and state.get('exit_observed_via_waitpid')is True and state.get('ownership_lost')is False and state.get('forced_cleanup')is False
def owned_qemu(root,actor,argv,log,timeout,state):
    owned=module('_support_vm_owned',root/'bootstrap/scripts/ci/zlib-pgo-native-hosted/owned_child.py');row=dict(argv=argv,log=str(log),status='FAIL',exit=None);actor.rows.append(row)
    raw_log=actor.directory/'qemu-private-original.log'
    try:
        with raw_log.open('xb')as f:result=owned.run(argv,timeout=min(timeout,actor.deadline-time.monotonic()),stdin=subprocess.DEVNULL,stdout=f,stderr=subprocess.STDOUT,stdout_limit=8*M,stderr_limit=8*M,lifecycle=state,allowed_uids={os.getuid()})
        need(result.returncode==0 and natural(state),'actual natural QEMU zero exit');row['status']='PASS'
    finally:
        if raw_log.exists():
            with raw_log.open('rb')as f:raw=f.read(8*M)
            with log.open('xb')as f:f.write(raw)
            row['prefix_only']=raw_log.stat().st_size>8*M
        row.update({k:v for k,v in state.items()if k!='status'});row['owned_child']=dict(state)
    return row
def bind_clock(actor,s,workspace,disks):
    path=workspace/'selection.json';before=disks.joinpath('data.raw').lstat();s=dict(s,launcher_epoch_s=int(time.time()));path.write_bytes(encoded(s));path.chmod(0o600)
    for p in(path,disks/'data.raw',disks/'selection-readback.json'):need(re.fullmatch('[A-Za-z0-9_./+-]+',str(p)),'literal debugfs host path')
    for query in ['rm /support/selection.json','write '+str(path)+' /support/selection.json','set_inode_field /support/selection.json uid 0','set_inode_field /support/selection.json gid 0','set_inode_field /support/selection.json mode 0100600','dump /support/selection.json '+str(disks/'selection-readback.json')]:actor.run(['/usr/sbin/debugfs',*(['-w']if not query.startswith('dump ')else[]),'-R',query,str(disks/'data.raw')],timeout=30)
    need(read(disks/'selection-readback.json',2*M)==encoded(s),'actual launch selection exact readback');after=(disks/'data.raw').lstat();need((before.st_dev,before.st_ino,before.st_uid,before.st_size)==(after.st_dev,after.st_ino,after.st_uid,after.st_size),'same original data inode clock bind');return s
def retire_helpers(actor,records,s,root,workspace,disks):
    for record in reversed(records):
        if record['absent']:continue
        need(record['cid']is not None,'unknown helper create outcome')
        cid=record['cid'];row=json.loads(actor.docker('inspect',cid))[0];need(row['Id']==cid,'owned retirement same CID');helper_check(row,s,record['role'],root,workspace,disks)
        if row['State']['Running']:actor.docker('stop','--time=10',cid,timeout=30)
        row=json.loads(actor.docker('inspect',cid))[0];need(row['State']['Running']is False,'owned helper stopped');actor.docker('rm',cid,timeout=30)
        need(not actor.docker('ps','-aq','--no-trunc','--filter','id='+cid,timeout=30),'owned helper absence');record['absent']=True
def proof_gate(proof,check_log,inventory_log,s,lock,methods):
    need(proof['status']=='PASS_EXTERNAL_EXACT_CHECK_FUNCTION'and proof['binding']==s['binding']and proof['source_map_sha256']==s['source_map_sha256']and proof['image']==s['image']and proof['architecture']=='aarch64'and proof['page_size']==16384 and proof['uid']==s['uid'],'actual EMU16K proof identity')
    need(proof['source_files']==s['proof_files']and proof['recipe_sha256']==s['recipe_sha256']and proof['inventory']==pin(lock),'exact source341 proof identity')
    checks=proof['checks'];need(checks['count']==6 and checks['skips']==0 and checks['exit']==0 and sorted(checks['methods'])==sorted(methods)and len(set(methods))==6 and checks['log_pin']==pin(check_log),'exact six raw check outcomes')
    lines=check_log.decode().splitlines()
    for name in methods:need(sum(bool(re.fullmatch(re.escape(name)+r' \([^\n]+\) \.\.\. ok',line))for line in lines)==1,'each exact named frozen check passed')
    need(sum(bool(re.fullmatch(r'Ran 6 tests in [0-9.]+s',line))for line in lines)==1 and lines[-1]=='OK'and not any('skipped'in line.lower()or line.startswith(('ERROR:','FAIL:','FAILED'))for line in lines),'no skipped checks')
    need(b''.join(sorted(inventory_log.splitlines(keepends=True)))==lock,'actual exact341 inventory')
    commands=proof['commands'];shell='set -euo pipefail\nsrcdir=$1\nstartdir=$1\nsource "$1/PKGBUILD"\ncheck\n'
    need(len(commands)==2 and commands[0]['argv']==['/usr/bin/pacman','-Q']and commands[1]['argv']==['/usr/bin/bash','--noprofile','--norc','-c',shell,'support-external-exact-check','/source/'+s['recipe_root']]and all(row['status']=='PASS'and row['expected_exit']==0 and natural(row['supervision'])for row in commands),'real unchanged check command and natural retirement')
def run(root,args,public,actor,image,binding,token,policy,exported=None,inspection=None,package_files=None):
    root=Path(root);vm=args.work/'guest-check';vm.mkdir(mode=0o700);vm_owner=vm.lstat();actor.support_guest_outer_cleanup_safe=False;target=public/'private-check';target.mkdir(mode=0o700)
    workspace=vm/'workspace';workspace.mkdir(mode=0o700);disks=vm/'media';disks.mkdir(mode=0o700);held=disks.lstat();records=[];fds=[];state={};launched=False;pending=None;success=False
    s=dict(schema=1,purpose=PURPOSE,binding=binding,nonce=os.urandom(16).hex(),image=image,token=token,source_map_sha256=args.map_sha256,uid=os.getuid(),gid=os.getgid(),kernel=None,budgets=config()['budgets'],source_manifest={},proof_files=package_files,recipe_root=policy['selected_package']['recipe_root'],recipe_sha256=policy['selected_package']['recipe_sha256'],launcher_epoch_s=None,root_nodes_sha256=None,capabilities_sha256=None)
    report=dict(schema=1,status='FAIL_GUEST_CHECK',execution='EMU16K_AARCH64',binding=binding,source_map_sha256=args.map_sha256,nonce=s['nonce'],image=image,kernel=None,selection=None,media=None,qemu=None,helpers=records,retirement=None,native_pair='NATIVE4K_SEPARATE_NOT_RUN',physical_M2='NOT_RUN',acceptance=False)
    try:
        tools_before={n:tool_identity(p)for n,p in [('qemu','/usr/bin/qemu-system-aarch64'),('debugfs','/usr/sbin/debugfs')]};s['kernel']=kernel_inputs(root,vm,Path(os.environ['RUNNER_TEMP']));report['kernel']=s['kernel']
        manifest=decode(read(root/'native/source-map.json',2*M));names=set(manifest['files'])|{'native/source-map.json','.github/workflows/native-arm-build.yml','.github/workflows/native-arm-support.yml'}
        s['source_manifest']={n:dict(pin(read(root/n,64*M)),mode=stat.S_IMODE((root/n).stat().st_mode))for n in names};need(0<len(names)<=200 and len(package_files or{})==17,'whole source and sealed17')
        save(workspace/'selection.json',s);records.append({});helper_create(actor,s,'prepare',root,workspace,disks,records[-1]);prepared=decode(read(disks/'prepared.json',2*M));s=decode(read(disks/'selection-final.json',2*M))
        need(prepared['status']=='PREPARED_ORIGINAL341_GUEST_MEDIA_NOT_BOOTED'and prepared['nonce']==s['nonce']and prepared['image']==image,'same-nonce prepared source image')
        for name in('boot','data'):
            fd=os.open(disks/(name+'.raw'),os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);fds.append(fd)
        s=bind_clock(actor,s,workspace,disks);before={n:disk_pin(disks/(n+'.raw'),config()['geometry'][n],actor.deadline)for n in('boot','data')};need(0<=int(time.time())-s['launcher_epoch_s']<=120,'fresh actual launch binding')
        argv=qemu(vm/'Image',disks/'boot.raw',disks/'data.raw',s);launched=True;owned_qemu(root,actor,argv,target/'uart.log',config()['budgets']['qemu'],state)
        after={n:disk_pin(disks/(n+'.raw'),config()['geometry'][n],actor.deadline)for n in('boot','data')};need(all([after[n][k]for k in('device','inode','uid','bytes')]==[before[n][k]for k in('device','inode','uid','bytes')]for n in before),'same owned media inodes after QEMU')
        report.update(selection=pin(encoded(s)),media=dict(prepared=pin(read(disks/'prepared.json')),before=before,after=after),qemu=dict(argv=argv,log_pin=pin(read(target/'uart.log')),supervision=dict(state)))
        records.append({});helper_create(actor,s,'export',root,workspace,disks,records[-1]);export=decode(read(disks/'guest-export.json',M));need(export['nonce']==s['nonce']and export['binding']==binding,'same actual guest export')
        for name,row in export['files'].items():
            raw=read(disks/'guest-export'/relative(name));need(pin(raw)==row,'export original byte pin');dest=target/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(raw)
        guest=decode(read(target/'guest.json'));proof=decode(read(target/'proof/proof-result.json'));need(export['result_status']=='PASS_EMU16K_ORIGINAL341_PRIVATE_CHECK'and guest['status']=='PASS_EMU16K_ORIGINAL341_PRIVATE_CHECK','actual guest success required')
        prefix=('SUPPORT135_VM '+s['nonce']+' ').encode();frames=[decode(line[len(prefix):])for line in read(target/'uart.log').splitlines()if line.startswith(prefix)];need(frames==[dict(status=guest['status'],acceptance=False)],'one actual same-nonce guest UART success frame')
        tree=ast.parse(read(root/s['recipe_root']/'test_package.py'));methods=[n.name for n in ast.walk(tree)if isinstance(n,ast.FunctionDef)and n.name.startswith('test_')]
        proof_gate(proof,read(target/'proof/check.log'),read(target/'proof/logs/inventory.log'),s,read(root/'native/original341.lock'),methods)
        need(tools_before=={n:tool_identity(p)for n,p in [('qemu','/usr/bin/qemu-system-aarch64'),('debugfs','/usr/sbin/debugfs')]},'host tool identities held');report['status']='PASS_OWNED_EMU16K_ORIGINAL341_GUEST_CHECK';success=True
        save(target/'kernel.json',decode(read(vm/'kernel.json',2*M)))
        for name in('prepared.json','root-snapshot.json'):save(target/name,decode(read(disks/name,2*M)))
        save(target/'export.json',dict(schema=1,execution='EMU16K_AARCH64',image=image,binding=binding,source_map_sha256=args.map_sha256,source_files=package_files,rootfs_export_public=False,guest_export=export,kernel=s['kernel'],host_tools=tools_before,prepared=pin(read(disks/'prepared.json')),root_snapshot=pin(read(disks/'root-snapshot.json'))))
    except BaseException as error:pending=error;report['error']=dict(type=type(error).__name__,message=str(error)[:1024])
    finally:
        if launched:
            report['qemu']=dict(argv=argv,log_pin=pin(read(target/'uart.log'))if(target/'uart.log').exists()else None,supervision=dict(state))
        try:
            need(not launched or state.get('group_absent')is True,'QEMU group absence unknown; backing and producer retained')
            retire_helpers(actor,records,s,root,workspace,disks)
            if (disks/'stage').exists():records.append({});helper_create(actor,s,'scrub',root,workspace,disks,records[-1])
            need(all(r['absent']for r in records),'all exact helper CIDs absent');current=vm.lstat();need((current.st_dev,current.st_ino)==(vm_owner.st_dev,vm_owner.st_ino)and not vm.is_mount()and shutil.rmtree.avoids_symlink_attacks,'exact backing directory ownership')
            for fd in reversed(fds):os.close(fd)
            fds.clear();shutil.rmtree(vm);actor.support_guest_outer_cleanup_safe=True;report['retirement']=dict(status='PASS_OWNED_QEMU_HELPERS_BACKING_RETIRED',qemu_started=launched,qemu_group_absent=True if launched else None,helpers_absent=True,backing_absent=not vm.exists())
        except BaseException as error:report['retirement']=dict(status='UNKNOWN_RETAINED',error=type(error).__name__+': '+str(error)[:512]);report['status']='FAIL_GUEST_RETIREMENT_UNKNOWN';success=False
        for fd in reversed(fds):os.close(fd)
        save(target/'vm.json',report)
    if pending:raise pending
    need(success and actor.support_guest_outer_cleanup_safe,'guest proof and owned retirement required')
    return dict(status='PASS_GUEST_EMU16K_EXACT_CHECK_FUNCTION',receipt=pin(read(target/'proof/proof-result.json')),export=pin(read(target/'export.json')),guest=pin(read(target/'guest.json')),vm=pin(read(target/'vm.json')),exact_check=True,in_makepkg=False,execution='EMU16K_AARCH64')
TOOLS={'qemu':'/usr/bin/qemu-system-aarch64','debugfs':'/usr/sbin/debugfs'}
def tool_gate(execute,observe,provision):
    receipt=dict(schema=1,status='FAIL_GUEST_HOST_TOOLS',commands=[],tools={},error=None,VM='NOT_RUN',namespace='NOT_RUN_HOST_POLICY_UNCHANGED',acceptance=False)
    try:
        apt=['-o','Acquire::Retries=0','-o','Acquire::http::Timeout=30','-o','Acquire::https::Timeout=30','-o','Dpkg::Use-Pty=0'];plan=[]
        if provision:plan=[(['/usr/bin/sudo','-n','--','/usr/bin/apt-get',*apt,'update'],180,True),(['/usr/bin/sudo','-n','--','/usr/bin/apt-get',*apt,'install','--yes','--no-install-recommends','qemu-system-arm','e2fsprogs'],180,True)]
        for argv,seconds,privileged in plan:
            raw,row=execute(argv,seconds,privileged);receipt['commands'].append(row);need(row.get('complete')is True and natural(row['supervision'])and row.get('error')is None,'bounded naturally retired apt provisioning')
        for name,path in TOOLS.items():
            before=observe(path);need(before['path']==path and before['uid']==before['gid']==0 and before['mode']==0o755 and 0<before['bytes']<=64*M and re.fullmatch('[a-f0-9]{64}',before['sha256'])and before['file_capabilities']['status']=='ABSENT'and before['file_capabilities']['observation']in('ENODATA','ENOTSUP'),'root0755 tool without filecaps')
            raw,row=execute([path,'--version'if name=='qemu'else'-V'],20,False);receipt['commands'].append(row);need(row.get('complete')is True and natural(row['supervision'])and row.get('error')is None and len(raw)<=65536 and(name=='qemu'and b'QEMU'in raw or name=='debugfs'and b'debugfs'in raw),'bounded actual version')
            need(observe(path)==before,'tool identity bracket');receipt['tools'][name]=dict(before,version_pin=pin(raw))
        receipt['status']='PASS_GUEST_HOST_TOOLS_ONLY'
    except Exception as error:receipt['error']=dict(type=type(error).__name__,errno=getattr(error,'errno',None),message=str(error)[:512])
    return receipt
def tools_only(map_sha256,provision):
    root=Path.cwd();sys.path.insert(0,str(root/'native'));from common import verify_source
    verify_source(root,map_sha256);need(os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted'and os.uname().machine in('aarch64','arm64')and os.getuid()==os.geteuid()!=0 and re.fullmatch('[a-f0-9]{40}',os.environ.get('SOURCE_SHA','')),'GitHub hosted ARM source gate')
    temp=Path(os.environ['RUNNER_TEMP']);need(not any(p.is_symlink()for p in(temp,*temp.parents))and not temp.is_relative_to(root),'ordinary disjoint runner temp');out=temp/'support-guest-host-preflight';out.mkdir(mode=0o700);(out/'logs').mkdir(mode=0o700);private=temp/'support-guest-host-preflight-private';private.mkdir(mode=0o700)
    owned=module('_support_guest_tools_owned',root/'bootstrap/scripts/ci/zlib-pgo-native-hosted/owned_child.py');count=0;deadline=time.monotonic()+480
    def execute(argv,seconds,privileged):
        nonlocal count
        count+=1;need(count<=4 and time.monotonic()<deadline,'finite host commands');state={};error=None;path=private/(str(count)+'.log')
        with path.open('xb')as f:
            try:owned.run(argv,timeout=min(seconds,deadline-time.monotonic()),stdin=subprocess.DEVNULL,stdout=f,stderr=subprocess.STDOUT,stdout_limit=M,stderr_limit=M,lifecycle=state,allowed_uids={os.getuid(),0}if privileged else{os.getuid()},env=dict(PATH='/usr/bin:/usr/sbin:/bin',HOME=os.environ['HOME'],LANG='C',LC_ALL='C',TZ='UTC',DEBIAN_FRONTEND='noninteractive'))
            except Exception as e:error=dict(type=type(e).__name__,errno=getattr(e,'errno',None),message=str(e)[:512])
        with path.open('rb')as f:raw=f.read(M)
        name='logs/%02d.log'%count;(out/name).write_bytes(raw);return raw,dict(argv=argv,supervision=state,error=error,log=name,log_pin=pin(raw),complete=path.stat().st_size<=M,prefix_only=path.stat().st_size>M)
    result=tool_gate(execute,tool_identity,provision);result.update(binding=dict(source_sha=os.environ['SOURCE_SHA'],source_map_sha256=map_sha256));need(len(encoded(result))<=65536,'bounded tool receipt');save(out/'receipt.json',result);print(json.dumps(dict(status=result['status'],VM='NOT_RUN')));return 0 if result['status']=='PASS_GUEST_HOST_TOOLS_ONLY'else 2
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--media',choices=('prepare','export','scrub'));parser.add_argument('--tools-only',action='store_true');parser.add_argument('--provision-tools',action='store_true');parser.add_argument('--map-sha256');args=parser.parse_args();need(bool(args.media)!=args.tools_only,'one explicit guest mode')
    if args.media:need(not args.provision_tools,'no provisioning in media');media_main(args.media)
    else:raise SystemExit(tools_only(args.map_sha256,args.provision_tools))
