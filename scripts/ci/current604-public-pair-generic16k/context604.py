# SPDX-License-Identifier: MIT
"""Signed604 guest preparation and separate owned QEMU tooling construction."""
import hashlib
import importlib.util
import json
import os
import stat
from pathlib import Path
import shutil
import sys

def preserve_capture(fixture,output):
    """Copy only the bounded actual capture receipt before owned fixture disposal."""
    fixture,output=Path(fixture),Path(output)
    def need(ok,why):
        if not ok:raise ValueError(why)
    need(output.is_absolute()and fixture==output/'fixture'and '..'not in output.parts and not any(p.is_symlink()for p in(fixture,output,*output.parents)),'fixed ordinary capture custody paths')
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
    parent=os.open(output,flags);source=None;fd=None;target=None
    try:
        info=os.fstat(parent);need(info.st_uid==os.geteuid()and stat.S_IMODE(info.st_mode)==0o700,'private caller-owned runtime output')
        source=os.open('fixture',flags,dir_fd=parent)
        fd=os.open('installed604-capture.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=source)
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=65536,'bounded ordinary capture receipt')
        raw=bytearray()
        while len(raw)<=before.st_size:
            block=os.read(fd,min(65536,before.st_size-len(raw)+1))
            if not block:break
            raw.extend(block)
        identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        need(len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(os.stat('installed604-capture.json',dir_fd=source,follow_symlinks=False)),'actual capture receipt drift')
        target=os.open('installed604-capture.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
        view=memoryview(raw)
        while view:
            count=os.write(target,view);need(count>0,'complete capture custody write');view=view[count:]
        os.fsync(target)
        return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    finally:
        for descriptor in(target,fd,source,parent):
            if descriptor is not None:os.close(descriptor)

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

def verify(source,runner):
    C=load('_managed604_cache_contract',source/'scripts/ci/expanded604-apps6-public-pairs/contract.py')
    manifest,ref,expected=C.target_manifest(runner/'ready604')
    receipt=C.read(runner/'context604.json')
    C.need(receipt['manifest']==ref and receipt['expected604_sha256']==C.TARGET_SHA,'staged604 cache binding differs')
    context=runner/'install-context'
    C.need({p.relative_to(context).as_posix() for p in context.rglob('*') if not p.is_dir()}=={r['path'] for r in receipt['context_files']},'closed install context differs')
    for row in receipt['context_files']:C.checked(context,row,256*1024**2)
    return manifest,expected

def selection(base,expected):
    """Keep573 original packages; replace only the pinned upstream FDK provider."""
    def need(ok,why):
        if not ok:raise ValueError(why)
    raw=lambda rows:''.join(n+' '+v+'\n' for n,v in sorted(rows.items())).encode()
    need(len(base)==574 and hashlib.sha256(raw(base)).hexdigest()=='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac','exact original574 inventory required')
    need(len(expected)==604 and hashlib.sha256(raw(expected)).hexdigest()=='7bc6caa51301bf076aeda4d137277a128c53a16e5bfd25f02e7309c4b3a408c3','exact Apps6 target604 inventory required')
    need(base.keys()-expected.keys()=={'libfdk-aac'} and base['libfdk-aac']=='3.0.0-1' and expected.get('cachy-asahi-fdk-aac')=='3.0.0-1' and all(expected.get(n)==v for n,v in base.items() if n!='libfdk-aac'),'sole FDK replacement and573 unchanged packages required')
    incoming=expected.keys()-base.keys();need(len(incoming)==31,'exact31 incoming packages required')
    return incoming

def prepare(source,runner,ready):
    C=load('_managed604_staging_contract',source/'scripts/ci/expanded604-apps6-public-pairs/contract.py')
    manifest,ref,expected=C.target_manifest(ready)
    original=C.read(source/'scripts/ci/maintained-desktop574-inputs.json')
    base={r['name']:r['version'] for r in original['packages']}
    selected=selection(base,expected)
    incoming=[r for r in manifest['packages'] if r['name'] in selected];C.need(len(incoming)==31,'finite31 incoming packages required')
    C.need(not (runner/'ready604').exists(),'fresh owned604 bundle location required')
    shutil.move(str(ready),runner/'ready604');ready=runner/'ready604'
    context=runner/'install-context';context.mkdir(mode=0o700);bundle=context/'bundle';(bundle/'packages').mkdir(parents=True);(bundle/'keys').mkdir()
    for name in ('manifest.json','expected-installed.lock'):shutil.copyfile(ready/name,bundle/name)
    for row in manifest['keyrings']:shutil.copyfile(ready/row['path'],bundle/row['path'])
    checks=load('_managed604_package_checks',source/'scripts/checks/package_checks.py');payload=[]
    for row in incoming:
        for key in ('archive','signature'):shutil.copyfile(ready/row[key],bundle/row[key])
        report=checks.package(ready/row['archive']);C.need(report['sha256']==row['sha256'],'actual incoming archive identity differs')
        # Full604 materializer has independently validated each official/project archive;
        # retain every original member including complete numeric owner/mode/hash metadata.
        payload.append(dict(name=row['name'],version=row['version'],payload={n:r for n,r in report['members'].items() if r['type']!='5' and n not in ('.PKGINFO','.BUILDINFO','.MTREE')}))
    (context/'incoming.json').write_bytes(C.encoded(payload))
    for name in ('contract.py','lifecycle.py'):
        target=context/'code/scripts/ci/expanded604-apps6-public-pairs'/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source/'scripts/ci/expanded604-apps6-public-pairs'/name,target)
    target=context/'code/scripts/ci/full-root-upgrade/root_upgrade.py';target.parent.mkdir(parents=True);shutil.copyfile(source/'scripts/ci/full-root-upgrade/root_upgrade.py',target)
    for name in ('install604.py','context604.py'):shutil.copyfile(Path(__file__).with_name(name),context/name)
    admission=dict(schema_version=1,purpose='OWNED_OFFLINE_SIGNED604_BUILD',nonce=os.urandom(16).hex(),installer_sha256=hashlib.sha256((context/'install604.py').read_bytes()).hexdigest(),context_sha256=hashlib.sha256((context/'context604.py').read_bytes()).hexdigest(),manifest_sha256=hashlib.sha256((bundle/'manifest.json').read_bytes()).hexdigest(),expected604_sha256=C.TARGET_SHA)
    (context/'build-authorization.json').write_bytes(C.encoded(admission))
    rows=[]
    for p in sorted(context.rglob('*')):
        if p.is_file():rows.append(dict(path=p.relative_to(context).as_posix(),bytes=p.stat().st_size,sha256=C.sha(p)))
    C.need(len(rows)<=128,'finite604 context file count')
    (runner/'context604.json').write_bytes(C.encoded(dict(schema_version=1,manifest=ref,expected604_sha256=C.TARGET_SHA,context_files=rows)))
    desktop=next(r for r in incoming if r['name']=='cachy-asahi-hyprland-settings')
    (runner/'desktop-archive.json').write_bytes(C.encoded(dict(name=Path(desktop['archive']).name,sha256=desktop['sha256'])))
    verify(source,runner)

def dockerfile(base_reference,context):
    digest=hashlib.sha256((context/'build-authorization.json').read_bytes()).hexdigest()
    return 'FROM '+base_reference+'\nUSER 0:0\nCOPY . /tmp/managed604/\nRUN --network=none --mount=type=bind,source=build-authorization.json,target=/run/cachy-asahi-managed604-build.json,ro python3 -I -B /tmp/managed604/install604.py --owned-buildkit-context '+digest+' && rm -rf /tmp/managed604\n'

def tooling_packet(packet,lock,raw):
    """Exact original retained45; no URL fallback or package/signature waiver."""
    import stat
    def need(ok,why):
        if not ok:raise ValueError(why)
    need(packet.is_absolute() and packet.is_dir() and not any(p.is_symlink()for p in (packet,*packet.parents)),'ordinary retained tooling packet')
    need(lock['schema_version']==1 and lock['base_package_count']==341 and len(lock['packages'])==21 and lock['expected_package_count']==362,'exact original21 tooling lock')
    rows=lock['keyring_files']+[v for r in lock['packages']for v in(r,dict(filename=r['filename']+'.sig',size=r['signature_size'],sha256=r['signature_sha256']))]
    files={r['filename']:dict(bytes=r['size'],sha256=r['sha256'])for r in rows};need(len(rows)==len(files)==45 and all(Path(n).name==n for n in files),'exact flat45 original tooling inputs')
    expected=dict(schema_version=1,purpose='installer-full26-generic-vm-tooling-inputs',tooling_lock_sha256=hashlib.sha256(raw).hexdigest(),files=files)
    need({p.name for p in packet.iterdir()}=={'index.json',*files},'exact retained tooling closure')
    for name in ('index.json',*files):
        p=packet/name;info=p.lstat();need(not p.is_symlink() and stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=16*1024**2,'ordinary bounded tooling file')
        data=p.read_bytes();need(len(data)==info.st_size,'tooling length drift')
        if name=='index.json':need(json.loads(data)==expected,'exact original tooling lock/index')
        else:need(dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())==files[name],'retained tooling byte/hash differs: '+name)
    return dict(source='9c1fa9e6674ce24edb9655a56436d4c5c0985c54',index_sha256=hashlib.sha256((packet/'index.json').read_bytes()).hexdigest(),files=45,network='NOT_USED')

def tooling_dockerfile(reference):
    return 'FROM '+reference+'\nUSER 0:0\nCOPY tooling/ /tmp/tooling/\nCOPY expected.lock /expected-qemu-tooling.lock\nRUN pacman -U --noconfirm --noscriptlet /tmp/tooling/*.pkg.tar.xz && ldconfig && pacman -Q | LC_ALL=C sort > /qemu-tooling-packages.lock && cmp /expected-qemu-tooling.lock /qemu-tooling-packages.lock && qemu-system-aarch64 --version && rm -rf /tmp/tooling\n'

def tooling_image(source,base,base_image,reference,out,images,packet,execute):
    """Original pinned tooling, isolated from the immutable604 guest image."""
    import re,stat
    def need(ok,why):
        if not ok:raise ValueError(why)
    need(len(base)==574 and re.fullmatch('sha256:[0-9a-f]{64}',base_image) and re.fullmatch('cachy-asahi-desktop574-base:[0-9a-f]{32}',reference),'exact owned original574 tooling base')
    raw=(source/'scripts/virtual/tooling.lock.json').read_bytes();need(len(raw)<=1024**2,'finite original tooling lock');tooling=json.loads(raw)
    rows=tooling['packages'];need(len({r['name'] for r in rows})==len(rows),'duplicate original tooling')
    extra=[r for r in rows if r['name']not in base];need(len(extra)==16 and {'qemu-system-aarch64','qemu-common','qemu-hw-display-virtio-gpu','qemu-hw-display-virtio-gpu-pci'}<=set(r['name']for r in extra),'original16 QEMU tooling extension required')
    retained=tooling_packet(packet,tooling,raw)
    context=out/'qemu-tooling-context';context.mkdir();packages=context/'tooling';packages.mkdir()
    for row in extra:
        for sig in (False,True):
            name=row['filename']+('.sig'if sig else'')
            data=(packet/name).read_bytes();need(len(data)==row['signature_size'if sig else'size'] and hashlib.sha256(data).hexdigest()==row['signature_sha256'if sig else'sha256'],'tooling input changed before copy');(packages/name).write_bytes(data)
    expected=base|{r['name']:r['version']for r in extra};need(len(expected)==590,'exact574 plus16 tooling only')
    (context/'expected.lock').write_text(''.join(f'{n} {v}\n'for n,v in sorted(expected.items())))
    # Same original signed offline pacman extension; no guest fixture is made
    # from this image and no installed604 inventory/payload is changed.
    dockerfile=tooling_dockerfile(reference)
    (context/'Dockerfile').write_text(dockerfile);iid=out/'qemu-tooling-image-id'
    execute(['docker','build','--network=none','--pull=false','--iidfile',str(iid),str(context)],'qemu-tooling-image',300)
    info=iid.lstat();need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and not iid.is_symlink() and info.st_size<=128,'ordinary exact tooling image id');image=iid.read_text().strip()
    need(re.fullmatch('sha256:[0-9a-f]{64}',image) and image!=base_image and image not in images,'distinct owned QEMU tooling image required');images.append(image)
    return dict(status='ORIGINAL_PINNED_SIGNED16_TOOLING_IMAGE_ONLY',retained_inputs=retained,image=image,base_image=base_image,base_reference=reference,tooling_lock_sha256=hashlib.sha256(raw).hexdigest(),tooling_packages={r['name']:dict(version=r['version'],sha256=r['sha256'],signature_sha256=r['signature_sha256'])for r in extra},package_count=590,guest_inventory='UNCHANGED604_FROM_SEPARATE_RUNTIME_IMAGE',build=dict(argv=['docker','build','--network=none','--pull=false','--iidfile',str(iid),str(context)],seconds=300,dockerfile_sha256=hashlib.sha256(dockerfile.encode()).hexdigest()))

def launcher_retired(report,source):
    """Require the extra owned image receipt in addition to all original roles."""
    import re
    q=report.get('qemu_launcher',{});image=q.get('image')
    if not(type(image)is str and re.fullmatch('sha256:[0-9a-f]{64}',image) and image not in (report.get('runtime_image'),report.get('base_image')) and q.get('base_image')==report.get('base_image') and q.get('base_reference')==report.get('base_reference') and q.get('status')=='ORIGINAL_PINNED_SIGNED16_TOOLING_IMAGE_ONLY' and q.get('package_count')==590 and q.get('guest_inventory')=='UNCHANGED604_FROM_SEPARATE_RUNTIME_IMAGE' and q.get('retained_inputs',{}).get('source')=='9c1fa9e6674ce24edb9655a56436d4c5c0985c54' and q.get('retained_inputs',{}).get('files')==45 and q.get('tooling_lock_sha256')=='c18afc5bde9868594d41bd576a956960a7b01b190d148ba03ca4c41d4394e1b0'):return False
    try:
        raw=(source/'scripts/virtual/tooling.lock.json').read_bytes();lock=json.loads(raw);base={r['name']for r in json.loads((source/'scripts/ci/maintained-desktop574-inputs.json').read_bytes())['packages']};extra=[r for r in lock['packages']if r['name']not in base]
        packages={r['name']:dict(version=r['version'],sha256=r['sha256'],signature_sha256=r['signature_sha256'])for r in extra}
        if len(packages)!=16 or q['tooling_packages']!=packages or q['tooling_lock_sha256']!=hashlib.sha256(raw).hexdigest():return False
        blobs=lock['keyring_files']+[v for r in lock['packages']for v in(r,dict(filename=r['filename']+'.sig',size=r['signature_size'],sha256=r['signature_sha256']))]
        index=dict(schema_version=1,purpose='installer-full26-generic-vm-tooling-inputs',tooling_lock_sha256=q['tooling_lock_sha256'],files={r['filename']:dict(bytes=r['size'],sha256=r['sha256'])for r in blobs})
        index_sha=hashlib.sha256((json.dumps(index,sort_keys=True,indent=2)+'\n').encode()).hexdigest()
        if q['retained_inputs']!=dict(source='9c1fa9e6674ce24edb9655a56436d4c5c0985c54',index_sha256=index_sha,files=45,network='NOT_USED'):return False
        build=q['build'];argv=build['argv'];iid=Path(argv[5]);context=Path(argv[6])
        if set(build)!={'argv','seconds','dockerfile_sha256'} or len(argv)!=7 or argv[:5]!=['docker','build','--network=none','--pull=false','--iidfile'] or build['seconds']!=300 or not iid.is_absolute() or iid.name!='qemu-tooling-image-id' or context!=iid.parent/'qemu-tooling-context' or build['dockerfile_sha256']!=hashlib.sha256(tooling_dockerfile(q['base_reference']).encode()).hexdigest():return False
    except (OSError,ValueError,KeyError,TypeError,IndexError):return False
    expected='remove-image:'+image;rows=report.get('cleanup',[]);selected=[r for r in rows if r.get('action')==expected]
    return len(rows)==15 and len(selected)==1 and selected[0]==dict(action=expected,exit=0) and len([r for r in rows if r.get('action','').startswith('remove-image:')])==2

def _producer_input(path,maximum):
    import stat
    path=Path(path)
    if any(p.is_symlink() for p in (path,*path.parents)):raise ValueError('producer receipt alias')
    before=path.lstat()
    if not(stat.S_ISREG(before.st_mode) and before.st_uid==os.getuid() and before.st_nlink==1 and 0<before.st_size<=maximum):raise ValueError('owned ordinary producer receipt required')
    raw=path.read_bytes();after=path.lstat()
    identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    if len(raw)!=before.st_size or identity(before)!=identity(after):raise ValueError('producer receipt drift')
    return raw

def _producer_image(reference):
    import re,subprocess
    if not re.fullmatch(r'(sha256:[0-9a-f]{64}|cachy-asahi-desktop574-producer:[0-9a-f]{32})',reference):raise ValueError('fixed owned producer image operand')
    row=subprocess.run(['docker','image','inspect','--format','{{.Id}}',reference],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
    if len(row.stdout)+len(row.stderr)>65536:raise ValueError('bounded producer image observation')
    if row.returncode==0:
        image=row.stdout.decode('ascii').strip()
        if not re.fullmatch(r'sha256:[0-9a-f]{64}',image):raise ValueError('exact immutable producer image readback')
        return image
    if row.returncode!=1 or row.stdout.strip() or b'No such image' not in row.stderr:raise ValueError('producer image absence unknown')
    return None

def _producer_preservation(receipt):
    import re
    keys={'schema_version','status','image','reference','token','producer_owner_sha256','image_receipt_sha256'}
    if not(type(receipt)is dict and set(receipt)==keys and receipt['schema_version']==1 and receipt['status']=='PINNED_UNTIL_ORIGINAL_PRODUCER_CLEANUP' and re.fullmatch('[0-9a-f]{32}',receipt['token']) and receipt['reference']=='cachy-asahi-desktop574-producer:'+receipt['token'] and re.fullmatch('sha256:[0-9a-f]{64}',receipt['image']) and all(re.fullmatch('[0-9a-f]{64}',receipt[k])for k in('producer_owner_sha256','image_receipt_sha256'))):raise ValueError('exact producer preservation receipt')
    return receipt

def preserve_producer_image(output,report):
    """Keep a new, unborrowed producer image alive until its ORIGINAL cleanup."""
    import re,subprocess
    output=Path(output)
    if not(output.is_absolute() and output.parent==Path('/tmp') and output.is_dir() and output.stat().st_uid==os.getuid() and not any(p.is_symlink()for p in(output,*output.parents)) and 'producer_image_preservation' not in report):raise ValueError('fresh owned producer image preservation')
    owner_raw=_producer_input(output/'producer-owner.json',1024**2);owner=json.loads(owner_raw)
    image_raw=_producer_input(output/'private/desktop574/image-id',128);image=image_raw.decode('ascii').strip()
    if not(type(owner)is dict and owner.get('schema_version')==1 and re.fullmatch('[0-9a-f]{32}',owner.get('token','')) and re.fullmatch('sha256:[0-9a-f]{64}',image) and re.fullmatch('sha256:[0-9a-f]{64}',owner.get('core_image','')) and type(owner.get('images_preexisting'))is list and len(owner['images_preexisting'])<=10000 and all(type(v)is str and re.fullmatch('sha256:[0-9a-f]{64}',v)for v in owner['images_preexisting']) and image!=owner['core_image'] and image not in owner['images_preexisting']):raise ValueError('only new exact producer-owned image, never borrowed')
    reference='cachy-asahi-desktop574-producer:'+owner['token']
    if _producer_image(image)!=image or _producer_image(reference)is not None:raise ValueError('producer image must exist and new owned reference must be absent')
    receipt=dict(schema_version=1,status='RESERVED_NOT_YET_PINNED',image=image,reference=reference,token=owner['token'],producer_owner_sha256=hashlib.sha256(owner_raw).hexdigest(),image_receipt_sha256=hashlib.sha256(image_raw).hexdigest());report['producer_image_preservation']=receipt
    row=subprocess.run(['docker','image','tag',image,reference],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
    if row.returncode!=0 or len(row.stdout)+len(row.stderr)>65536:raise ValueError('owned producer preservation tag failed')
    if _producer_image(reference)!=image or _producer_image(image)!=image:raise ValueError('preservation tag exact producer image join failed')
    receipt['status']='PINNED_UNTIL_ORIGINAL_PRODUCER_CLEANUP';return receipt

def require_producer_image_preserved(runtime,receipt):
    receipt=_producer_preservation(receipt)
    if not(runtime.get('base_image')==receipt['image'] and runtime.get('base_reference')!=receipt['reference'] and runtime.get('base_reference_cleanup')==dict(ok=True,base_image_present=True)):raise ValueError('producer image must survive consumer alias retirement')
    if _producer_image(receipt['image'])!=receipt['image'] or _producer_image(receipt['reference'])!=receipt['image']:raise ValueError('exact producer image/reference lost before original cleanup')
    return True

def producer_image_retired(receipt,cleanup):
    """Observe original cleanup; never remove tags or accept a missing image early."""
    receipt=_producer_preservation(receipt)
    if not(type(cleanup)is dict and cleanup.get('status')=='PASS' and cleanup.get('failures')==[]):raise ValueError('unchanged original producer cleanup must pass first')
    if _producer_image(receipt['image'])is not None or _producer_image(receipt['reference'])is not None:raise ValueError('original producer image/preservation reference remains')
    return dict(status='PASS_ORIGINAL_PRODUCER_IMAGE_AND_PRESERVATION_REFERENCE_ABSENT',image=receipt['image'],reference=receipt['reference'],original_cleanup_canonical_sha256=hashlib.sha256((json.dumps(cleanup,sort_keys=True,indent=2)+'\n').encode()).hexdigest(),removed_by='UNCHANGED_ORIGINAL_PRODUCER_IMAGE_ID_CLEANUP')
