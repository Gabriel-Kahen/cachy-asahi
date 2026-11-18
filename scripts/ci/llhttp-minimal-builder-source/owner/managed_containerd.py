# SPDX-License-Identifier: MIT
"""Observe only Moby's private managed containerd inside its existing daemon service."""
import os
from pathlib import Path
import re
import socket
import stat
import struct

HOST_RUNTIME = '/run/containerd'
MANAGED_MODE = 'MANAGED_CONTAINERD_SAME_NAMESPACE_V1'
CONTAINERD_PATHS = ('/usr/bin/containerd', '/usr/sbin/containerd')


def managed_need(ok, guard):
    if not ok:
        raise ValueError(guard)


def project_managed_containerd(argv, kind):
    """Apply only after the lane's unchanged service namespace validation."""
    managed_need(kind in ('owner','daemon') and argv.count('--')==1, 'exact managed runtime service boundary')
    boundary=argv.index('--')
    managed_need(not any(part.startswith('--property=InaccessiblePaths=') for part in argv[:boundary]),
                 'no pre-existing hidden service path')
    if kind == 'owner':
        return argv
    managed_need(not any(part=='--containerd' or part.startswith('--containerd=') for part in argv[boundary+1:]),
                 'no pre-existing explicit containerd address')
    return [*argv[:boundary],'--property=InaccessiblePaths=-'+HOST_RUNTIME,*argv[boundary:]]


def managed_identity(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)


def managed_read(path, maximum, *, root_file=False):
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
        before=os.fstat(stream.fileno())
        if root_file:
            managed_need(stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_nlink==1 and not before.st_mode&0o022,
                         'ordinary root-owned managed runtime metadata')
        data=stream.read(maximum+1)
        managed_need(len(data)<=maximum and managed_identity(before)==managed_identity(path.lstat()), 'bounded same managed runtime metadata')
        return data


def managed_proc(root, pid):
    item=root/str(pid)
    raw=managed_read(item/'stat',4096)
    identity,_,parts=raw.rpartition(b')')
    fields=parts.split()
    managed_need(identity.split(b' ',1)[0]==str(pid).encode() and len(fields)>19 and fields[0] not in (b'Z',b'X'),
                 'same live managed runtime proc identity')
    cg=managed_read(item/'cgroup',4096).decode('ascii').splitlines()
    managed_need(len(cg)==1 and cg[0].startswith('0::/'),'one managed runtime unified cgroup')
    namespace=(item/'ns/mnt').stat()
    return (int(fields[1]),int(fields[19]),cg[0][3:],(namespace.st_dev,namespace.st_ino))


def managed_selection(raw, expected):
    addresses=[]
    for line in raw.splitlines():
        if b'msg="Creating a containerd client"' in line:
            matches=re.findall(rb'(?:^|[ \t])address=(?:"([^"\r\n]+)"|([^ \t\r\n]+))(?=$|[ \t])',line)
            managed_need(len(matches)==1, 'one exact managed runtime address in daemon startup')
            addresses.append(matches[0][0] or matches[0][1])
    managed_need(bool(addresses) and set(addresses)=={os.fsencode(expected)},'dockerd selected only the private managed socket')


def managed_receipt(value, daemon_pid, daemon_start, daemon_group):
    """Rejoin the existing controller-issued proof before the ordinary payload runs."""
    fields={'kind','pid','starttime','parent_pid','cgroup','executable','mount_namespace','socket',
            'same_mount_namespace','default_socket_hidden','selected_private_socket'}
    managed_need(type(value) is dict and set(value)==fields and value.get('kind')==MANAGED_MODE and value.get('parent_pid')==daemon_pid
                 and value.get('cgroup')==daemon_group and type(value.get('pid')) is int and value['pid']>0 and value['pid']!=daemon_pid
                 and type(value.get('starttime')) is int and value['starttime']>=daemon_start
                 and value.get('executable') in CONTAINERD_PATHS and value.get('same_mount_namespace') is True
                 and value.get('default_socket_hidden') is True and value.get('selected_private_socket') is True,
                 'managed runtime proof bound to exact observed daemon')
    for name,keys in (('mount_namespace',{'device','inode'}),('socket',{'device','inode','uid','gid'})):
        identity=value.get(name)
        managed_need(type(identity) is dict and set(identity)==keys and all(type(identity.get(k)) is int and identity[k]>0 for k in ('device','inode')),
                     'observed managed runtime socket or mount identity')
    managed_need(all(type(value['socket'][k]) is int and value['socket'][k]==0 for k in ('uid','gid')),
                 'observed root-owned managed runtime socket')
    return value


def observe_managed_containerd(volume, daemon_pid, daemon_start, daemon_group):
    """No protocol requests, filesystem mutation, new service or global socket access."""
    managed_need(volume.is_absolute() and volume==volume.resolve() and volume.name=='volume' and type(daemon_pid) is int
                 and daemon_pid>0 and type(daemon_start) is int and daemon_start>0
                 and re.fullmatch(r'/system\.slice/[A-Za-z0-9-]+-daemon\.service/daemon',daemon_group), 'exact owned managed runtime context')
    proc=Path('/proc')
    daemon_before=managed_proc(proc,daemon_pid)
    own_ns=(proc/'self/ns/mnt').stat()
    managed_need(daemon_before[1:3]==(daemon_start,daemon_group)
                 and daemon_before[3]!=(own_ns.st_dev,own_ns.st_ino),'same admitted daemon in its private mount namespace')
    visible_default=proc/str(daemon_pid)/'root/run/containerd/containerd.sock'
    try:
        visible_default.lstat()
    except FileNotFoundError:
        pass
    else:
        raise ValueError('system containerd socket still visible to dedicated daemon')
    path=volume/'exec/containerd/containerd.sock'
    managed_need(path==path.resolve() and len(os.fsencode(path))<=107,'exact managed Unix socket pathname')
    info=path.lstat()
    managed_need(stat.S_ISSOCK(info.st_mode) and info.st_nlink==1 and info.st_uid==info.st_gid==0 and not info.st_mode&0o002,
                 'exact root-owned private managed Unix socket')
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as peer:
        peer.settimeout(3)
        peer.connect(str(path))
        pid,uid,gid=struct.unpack('3i',peer.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i')))
        managed_need(pid>0 and pid!=daemon_pid and uid==gid==0,'live root-owned managed containerd peer')
        child=managed_proc(proc,pid)
        managed_need(child[0]==daemon_pid and child[1]>=daemon_start and child[2:]==daemon_before[2:],
                     'containerd child in the same daemon cgroup and mount namespace')
        executable=(proc/str(pid)/'exe').resolve(strict=True)
        executable_info=(proc/str(pid)/'exe').stat()
        managed_need(str(executable) in CONTAINERD_PATHS and executable_info.st_uid==0
                     and stat.S_ISREG(executable_info.st_mode) and executable_info.st_mode&0o111 and not executable_info.st_mode&0o022
                     and managed_identity(executable_info)==managed_identity(executable.stat()), 'same root-owned existing containerd executable')
        managed_need(managed_read(path.parent/'containerd.pid',32,root_file=True).strip()==str(pid).encode(), 'same managed containerd PID file and socket peer')
        managed_selection(managed_read(volume/'daemon.log',256*1024,root_file=True),path)
        managed_need(managed_proc(proc,pid)==child and managed_proc(proc,daemon_pid)==daemon_before
                     and managed_identity(path.lstat())==managed_identity(info), 'stable admitted daemon, managed peer and socket')
    return managed_receipt(dict(kind=MANAGED_MODE,pid=pid,starttime=child[1],parent_pid=daemon_pid,cgroup=daemon_group,
                                executable=str(executable),mount_namespace=dict(device=child[3][0],inode=child[3][1]),
                                socket=dict(device=info.st_dev,inode=info.st_ino,uid=info.st_uid,gid=info.st_gid),
                                same_mount_namespace=True,default_socket_hidden=True,selected_private_socket=True),
                           daemon_pid,daemon_start,daemon_group)
