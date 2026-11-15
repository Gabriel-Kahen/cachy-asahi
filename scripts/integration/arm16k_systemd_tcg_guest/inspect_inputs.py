#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Bounded read-only ARM rootfs/kernel discovery; never execute guest code."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import struct
import tarfile
import time

ROOTFS_SHA='42a4eeaa038994ffd31fa173256ef2f0ef511358eeb41b9ea1f8626391b9b319'
ROOTFS_BYTES=829367415
KERNEL_SHA='cd8053ebdb83302015efbad97ab1cc53fcd5a2353bf3f37ba208f4e6360946ec'
CONFIG_SHA='e97d54d4852eceb6cba28c38f78d4a00aacbfdb0c1523cb96366590f7eaa915b'
REQUIRED='ARM64 ARM64_16K_PAGES CGROUPS INOTIFY_USER SIGNALFD TIMERFD EPOLL UNIX NET FHANDLE SYSFS PROC_FS NET_NS USER_NS PID_NS IPC_NS UTS_NS SECCOMP SECCOMP_FILTER FILE_LOCKING UNIX98_PTYS TTY SERIAL_AMBA_PL011 SERIAL_AMBA_PL011_CONSOLE VIRTIO_MMIO VIRTIO_BLK EXT4_FS DEVTMPFS DEVTMPFS_MOUNT BINFMT_ELF BINFMT_SCRIPT FUTEX SHMEM TMPFS MULTIUSER POSIX_TIMERS ARM_PSCI_FW'.split()


def pin(path):
    if path.is_symlink() or not path.is_file():raise ValueError('ordinary material required')
    with path.open('rb')as f:digest=hashlib.file_digest(f,'sha256').hexdigest()
    return {'bytes':path.stat().st_size,'sha256':digest}


def kernel(image,config):
    if pin(image)!={'bytes':9019400,'sha256':KERNEL_SHA} or pin(config)!={'bytes':68789,'sha256':CONFIG_SHA}:
        raise ValueError('retained kernel/config pin differs')
    with image.open('rb')as f:head=f.read(64)
    flags=struct.unpack_from('<Q',head,24)[0]
    if head[56:60]!=b'ARM\x64' or flags&1 or (flags>>1)&3!=2:
        raise ValueError('little-endian ARM64 16K header required')
    values=dict(l.split('=',1)for l in config.read_text().splitlines()if l.startswith('CONFIG_'))
    missing=[k for k in REQUIRED if values.get('CONFIG_'+k)!='y']
    if missing:raise ValueError('kernel baseline missing '+','.join(missing))
    if values.get('CONFIG_MODULES','n')!='n':raise ValueError('built-in-only profile required')
    return {'Image':pin(image),'config':pin(config),'release':'7.1.13-generic16k-managed-gui',
        'page_size_header':16384,'required_config':'PASS read-only baseline only; boot compatibility NOT RUN',
        'limits':{k:values.get('CONFIG_'+k,'n')for k in ('CFS_BANDWIDTH','AUDIT','FANOTIFY')},'boot':'NOT RUN'}


def fields(raw):
    data={}
    for part in raw.decode().split('\n\n'):
        lines=part.splitlines()
        if lines and lines[0].startswith('%'):data[lines[0].strip('%')]=lines[1:]
    return data


def rootfs(path):
    if pin(path)!={'bytes':ROOTFS_BYTES,'sha256':ROOTFS_SHA}:raise ValueError('exact ALARM rootfs required')
    end=time.monotonic()+180;nodes={};packages={};accounts={};total=0
    with tarfile.open(path,'r|gz')as archive:
        for item in archive:
            if time.monotonic()>end or len(nodes)>200000:raise ValueError('archive discovery bound')
            name=item.name.removeprefix('./').rstrip('/')
            if not name:continue
            pure=PurePosixPath(name)
            if pure.is_absolute()or'..'in pure.parts or any(ord(c)<32 for c in name):raise ValueError('unsafe archive path')
            if item.size>512*1024**2:raise ValueError('oversized rootfs member')
            total+=item.size
            if total>8*1024**3:raise ValueError('rootfs logical cap')
            if name in nodes:raise ValueError('duplicate rootfs node')
            nodes[name]={'bytes':item.size,'mode':item.mode,'uid':item.uid,'gid':item.gid,
                         'type':item.type.decode('ascii'),'link':item.linkname}
            if name.startswith('var/lib/pacman/local/')and name.endswith(('/desc','/files')):
                if item.size>2*1024**2:raise ValueError('package metadata cap')
                package=name.split('/')[4];packages.setdefault(package,{})[name.rsplit('/',1)[1]]=fields(archive.extractfile(item).read())
            if name in ('etc/passwd','etc/group'):
                if item.size>131072:raise ValueError('account metadata cap')
                accounts[name]=archive.extractfile(item).read().decode()
    return {'schema':1,'rootfs':pin(path),'logical_file_bytes':total,'nodes':nodes,'packages':packages,
            'accounts':accounts,'guest_execution':'NOT RUN','signature':'NOT VERIFIED by discovery; preparation requires detached signature'}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--rootfs',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();report=rootfs(args.rootfs)
    with args.output.open('x')as f:json.dump(report,f,sort_keys=True)
    print(json.dumps({'nodes':len(report['nodes']),'packages':len(report['packages']),
                      'logical_file_bytes':report['logical_file_bytes'],'guest_execution':'NOT RUN'}))
