#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Owned offline container: complete full574 boot/source disks, never host mounts."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C
import adapter

INIT='''#!/usr/bin/bash
set -euo pipefail
export PATH=/usr/bin:/bin LANG=C LC_ALL=C
mount -t proc -o ro,nosuid,nodev,noexec proc /proc
mount -t sysfs -o ro,nosuid,nodev,noexec sysfs /sys
mount -t devtmpfs -o nosuid devtmpfs /dev
mount -t tmpfs -o nosuid,nodev,size=256m tmpfs /tmp
mount -t tmpfs -o nosuid,nodev,size=64m tmpfs /run
mount -t ext4 -o rw,nosuid,nodev /dev/vdb /volume
mount --bind /volume/held /held
mount -o remount,bind,ro /held
mount --bind /volume/work /work
mount --bind /volume/out /out
umount /volume
# Source remains reachable only through its readonly bind. The trial receives no
# raw disk nodes; SYS_ADMIN may mount only readonly/nodev filesystems under its
# inherited syscall filter, and cannot remount or use the new mount APIs.
umount /dev
mount -t tmpfs -o nosuid,size=1m tmpfs /dev
mknod -m 666 /dev/null c 1 3
mknod -m 666 /dev/zero c 1 5
mknod -m 666 /dev/random c 1 8
mknod -m 666 /dev/urandom c 1 9
for point in /source /inputs; do mount --bind "$point" "$point"; mount -o remount,bind,ro "$point"; done
exec /usr/bin/python3 -I -B /installed16k/guest.py
'''

def command(argv):
    result=subprocess.run(list(map(str,argv)),stdin=subprocess.DEVNULL,capture_output=True,timeout=900)
    C.need(len(result.stdout)+len(result.stderr)<=2*1024**2 and result.returncode==0,'disk preparation command failed: '+str(argv[0]))

def copy_tree(source,target):
    C.need(source.is_dir() and not target.exists(),'fresh complete data-copy target')
    target.mkdir(mode=0o700)
    command(['/usr/bin/cp','-a','--reflink=never','--',str(source)+'/.',target])

def copy_guest_sources(source,target,native_dependencies):
    # The guest hook has one lane-only dependency outside the native runner's
    # historical dependency map. Keep both roles pinned; never shadow a row.
    query='scripts/ci/expanded600-installer-vm/observer600.py'
    C.need(query not in native_dependencies,'lane-only observer query source overlap')
    pin=C.decode(C.read(C.HERE/'dependencies.json'))['files'][query]
    C.ref(source,dict(path=query,**pin))
    for name,row in (*native_dependencies.items(),(query,pin)):
        origin=C.ref(source,dict(path=name,**row));destination=target/name
        C.need(not destination.exists() and not destination.is_symlink(),'fresh guest source leaf required')
        destination.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(origin,destination)
    C.ref(target,dict(path=query,**pin))

def prepare():
    C.need(os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64' and Path('/.dockerenv').is_file() and os.environ.get('CAA_INSTALLED16K_PREPARE')=='1','owned native preparation container only')
    C.need({p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'offline preparation required')
    for name in ('/held','/source','/inputs','/runner','/installed16k'):
        rows=[r.split()[5].split(',') for r in Path('/proc/self/mountinfo').read_text().splitlines() if r.split()[4]==name]
        C.need(rows and 'ro' in rows[-1],'readonly preparation inputs')
    C.need(Path('/out').is_mount() and not any(Path('/out').iterdir()) and shutil.disk_usage('/out').free>=48*C.GIB,'fresh48GiB owned preparation output')
    C.check_source(Path('/source'))
    native=C.load('native_prepare',Path('/runner/common.py'))
    index,base,_,_=native.configuration(Path('/inputs'),os.environ['INPUT_INDEX_SHA256'])
    C.need(index['provider_pair_archive_sha256']=='b852e3fc647d63699c5f42003a748cbd2268991dc2615a494dc3cdda4d757d12','exact accepted provider pair')
    # Same full-source copy mechanism as the existing disk-backed VM preparer:
    # cp -a to ordinary staged data, then mkfs.ext4 -d. Guest readback MUST match
    # native node and capability maps; mkfs support alone cannot establish that.
    stage=Path('/out/stage');stage.mkdir();info=stage.stat()
    C.save('/out/preparation-owner.json',dict(nonce=C.decode(C.read('/selection/selection.json'))['nonce'],stage=[info.st_dev,info.st_ino]))
    boot=stage/'boot';volume=stage/'volume'
    copy_tree(Path('/held'),boot);volume.mkdir();copy_tree(Path('/held'),volume/'held')
    for n in ('work','out'):(volume/n).mkdir(mode=0o700)
    for n in ('volume','held','work','out','source','inputs','runner','installed16k'):
        C.need(not (boot/n).exists() and not (boot/n).is_symlink(),'reserved boot namespace occupied: '+n);(boot/n).mkdir(mode=0o755)
    copy_guest_sources(Path('/source'),boot/'source',C.decode(C.read(Path('/runner/dependencies.json')))['files'])
    # The exact original copy-scope helper finds its source root through this marker.
    marker=boot/'source/manifests/packages.toml';marker.parent.mkdir(parents=True);shutil.copyfile('/source/manifests/packages.toml',marker)
    for folder in ('inputs','runner'):
        for source in sorted((Path('/')/folder).rglob('*')):
            C.need(not source.is_symlink(),'ordinary frozen input tree')
            target=boot/folder/source.relative_to(Path('/')/folder)
            if source.is_dir():target.mkdir(mode=0o755)
            else:C.read(source,256*1024**2);shutil.copyfile(source,target)
    text,receipt=adapter.derive(Path('/source'))
    for name in ('guest.py','contract.py','sandbox.py','snapshot_progress.py','observer_progress.py'):shutil.copyfile(C.HERE/name,boot/'installed16k'/name)
    (boot/'installed16k/container16k.py').write_text(text)
    C.save(boot/'installed16k/adapter.json',receipt)
    C.save(boot/'installed16k/selection.json',C.decode(C.read('/selection/selection.json')))
    (boot/'init-installed16k').write_text(INIT);(boot/'init-installed16k').chmod(0o755)
    for directory,size in ((boot,16*C.GIB),(volume,24*C.GIB)):
        allocated=sum(p.lstat().st_blocks*512 for p in directory.rglob('*'))
        C.need(allocated<=10*C.GIB and shutil.disk_usage('/out').free>=allocated+8*C.GIB,'finite disk staging capacity')
        image=Path('/out')/(directory.name+'.raw')
        with image.open('xb') as stream:stream.truncate(size)
        command(['/usr/bin/mkfs.ext4','-F','-b','4096','-m','0','-L','GNU16K_'+directory.name.upper(),'-d',directory,image])
    shutil.rmtree(stage)
    C.save('/out/prepared.json',dict(status='PREPARED_FULL574_DISKS_NOT_EXECUTED',boot=C.row('/out/boot.raw'),volume=C.row('/out/volume.raw'),adapter=receipt,source_nodes_sha256=index['source_nodes_sha256'],capabilities_sha256=index['source_capabilities_sha256'],base_packages=len(base),hardware='NOT_RUN'))
    uid,gid=int(os.environ['OUTPUT_UID']),int(os.environ['OUTPUT_GID'])
    for path in Path('/out').iterdir():os.chown(path,uid,gid)

if __name__=='__main__':prepare()
