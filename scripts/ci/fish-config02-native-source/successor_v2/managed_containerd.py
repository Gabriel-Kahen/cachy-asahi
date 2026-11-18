# SPDX-License-Identifier: MIT
"""Observe only Moby's private managed containerd inside its existing daemon service."""
import os
from pathlib import Path
import re
import socket
import stat
import struct
import sys

HOST_RUNTIME = '/run/containerd'
SHIM_TMPFS_BYTES = 4*1024**2
SHIM_TMPFS_PROPERTY = '--property=TemporaryFileSystem='+HOST_RUNTIME+':rw,nosuid,nodev,noexec,size=4M,mode=0755'
MANAGED_MODE = 'MANAGED_CONTAINERD_SAME_NAMESPACE_V3'
CONTAINERD_PATHS = ('/usr/bin/containerd', '/usr/sbin/containerd')
DOCKERD_PATHS = ('/usr/bin/dockerd', '/usr/sbin/dockerd')
CGROUP_VIEW = '/sys/fs/cgroup'
CONTAINER_GROUP = '/containers'
CGROUP_CONTROLLERS = {b'cpu',b'memory',b'pids'}
OWNED_GROUP = re.compile(r'/system\.slice/[A-Za-z0-9-]+-daemon\.service')
# Linux include/uapi/linux/sched.h. Python 3.12 exposes unshare without this constant.
CLONE_NEWCGROUP = getattr(os,'CLONE_NEWCGROUP',0x02000000)


def managed_need(ok, guard):
    if not ok:
        raise ValueError(guard)


def project_managed_containerd(argv, kind):
    """Apply only after the lane's unchanged service namespace validation."""
    managed_need(kind in ('owner','daemon') and argv.count('--')==1, 'exact managed runtime service boundary')
    boundary=argv.index('--')
    managed_need(not any(part.startswith(('--property=InaccessiblePaths=','--property=TemporaryFileSystem='))
                         for part in argv[:boundary]), 'no pre-existing hidden or temporary service path')
    if kind == 'owner':
        return argv
    managed_need(not any(part=='--containerd' or part.startswith('--containerd=') for part in argv[boundary+1:]),
                 'no pre-existing explicit containerd address')
    return [*argv[:boundary],SHIM_TMPFS_PROPERTY,*argv[boundary:]]


def project_delegated_cgroup(argv, volume, group, launcher, program):
    """Expose exactly the owned delegation at the runtime's canonical cgroup path."""
    managed_need(OWNED_GROUP.fullmatch(group) and argv.count('--')==1, 'exact delegated service boundary')
    boundary=argv.index('--')
    properties=argv[:boundary]
    replacements={
        '--property=ReadOnlyPaths=/tmp /var/tmp /sys/fs/cgroup':'--property=ReadOnlyPaths=/tmp /var/tmp',
        '--property=ReadWritePaths='+volume+' '+CGROUP_VIEW+group:'--property=ReadWritePaths='+volume,
        '--property=DelegateSubgroup=daemon':None,
    }
    managed_need(all(properties.count(key)==1 for key in replacements)
                 and [p for p in properties if p.startswith('--property=Delegate')]==
                     ['--property=Delegate=yes','--property=DelegateSubgroup=daemon']
                 and not any(p.startswith('--property=BindPaths=') for p in properties),
                 'exact original delegated cgroup permissions')
    command=argv[boundary+1:]
    original='--cgroup-parent='+group+CONTAINER_GROUP
    managed_need(command and command[0] in DOCKERD_PATHS
                 and [arg for arg in command[1:] if arg.startswith('--cgroup-parent')]==[original],
                 'exact original delegated OCI parent')
    command=[('--cgroup-parent='+CONTAINER_GROUP if arg==original else arg) for arg in command]
    projected=[replacements.get(p,p) for p in properties if p not in replacements or replacements[p] is not None]
    bind='--property=BindPaths='+CGROUP_VIEW+group+':'+CGROUP_VIEW+':norbind'
    return [*projected,bind,'--property=MountFlags=slave','--',launcher,'-I','-B',str(program),
            '--start-delegated-daemon',group,*command]


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


def delegated_mountinfo(raw, group, active_mount):
    """Reject stacked submounts and alternate cgroup2 paths in the runtime view."""
    rows={}
    for line in raw.splitlines():
        left,separator,right=line.partition(b' - ')
        fields=left.split()
        fs=right.split()
        managed_need(separator and len(fields)>=6 and len(fs)==3, 'complete bounded runtime mountinfo row')
        if fields[4].startswith(os.fsencode(CGROUP_VIEW+'/')):
            raise ValueError('no nested mount in owned cgroup view')
        if fields[4]==os.fsencode(CGROUP_VIEW) or fs[0]==b'cgroup2':
            managed_need(re.fullmatch(rb'[1-9][0-9]{0,19}',fields[0])
                         and re.fullmatch(rb'[1-9][0-9]{0,19}',fields[1])
                         and re.fullmatch(rb'[0-9]{1,10}:[0-9]{1,10}',fields[2])
                         and fields[4]==os.fsencode(CGROUP_VIEW) and fs[0]==b'cgroup2',
                         'cgroup2 only at the canonical runtime mount point')
            mount_id=int(fields[0])
            managed_need(mount_id not in rows,'unique cgroup2 mount identities')
            rows[mount_id]=(fields,fs)
    managed_need(active_mount in rows and 1<=len(rows)<=2,'one exposed owned cgroup2 mount')
    fields,fs=rows.pop(active_mount)
    flags={b'rw',b'nosuid',b'nodev',b'noexec'}
    managed_need(fields[3]==os.fsencode(group) and flags<=set(fields[5].split(b','))
                 and b'ro' not in fields[5].split(b',') and b'rw' in fs[2].split(b',')
                 and not any(flag.startswith(b'shared:') for flag in fields[6:]),
                 'owned cgroup root is writable hardened and cannot propagate back')
    if rows:
        covered=rows.get(int(fields[1]))
        managed_need(covered is not None and covered[0][2:4]==[fields[2],b'/'],
                     'only the same underlying host cgroup mount is covered')
    return tuple(map(int,fields[2].split(b':')))


def delegated_view(proc, process, path, group):
    fd=os.open(path,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        fdinfo=managed_read(proc/'self/fdinfo'/str(fd),4096)
        mounts=re.findall(rb'^mnt_id:[ \t]*([1-9][0-9]{0,19})$',fdinfo,re.M)
        managed_need(len(mounts)==1,'exact live cgroup view mount ID from fdinfo')
        mount_id=int(mounts[0])
        device=delegated_mountinfo(managed_read(process/'mountinfo',256*1024),group,mount_id)
        managed_need(device==(os.major(before.st_dev),os.minor(before.st_dev))
                     and before.st_uid==before.st_gid==0 and not before.st_mode&0o022
                     and managed_identity(path.lstat())==managed_identity(before),
                     'same stable root-owned cgroup view')
        return dict(path=CGROUP_VIEW,root=group,filesystem='cgroup2',mount_id=mount_id,
                    device=before.st_dev,inode=before.st_ino,container_parent=CONTAINER_GROUP)
    finally:
        os.close(fd)


def delegated_namespace(process):
    info=(process/'ns/cgroup').stat()
    return (info.st_dev,info.st_ino)


def delegated_write(path, value):
    with os.fdopen(os.open(path,os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC),'wb',buffering=0) as stream:
        managed_need(stream.write(value)==len(value),'complete exact delegated cgroup update')


def start_delegated_daemon(group, command):
    """Enter the exact delegation before in-place exec of qualified dockerd."""
    managed_need(sys.flags.isolated and sys.flags.dont_write_bytecode and __debug__
                 and os.getuid()==os.geteuid()==0 and OWNED_GROUP.fullmatch(group)
                 and command and command[0] in DOCKERD_PATHS
                 and [arg for arg in command if arg.startswith('--cgroup-parent')]==['--cgroup-parent='+CONTAINER_GROUP],
                 'exact existing systemd-owned delegated daemon launch')
    proc=Path('/proc')
    process=proc/'self'
    path=Path(CGROUP_VIEW)
    self_pid=os.getpid()
    membership=lambda:managed_read(process/'cgroup',4096)
    managed_need(membership()==os.fsencode('0::'+group+'\n')
                 and managed_read(path/'cgroup.procs',4096).split()==[str(self_pid).encode()],
                 'same single trusted launcher at exact systemd delegation root')
    view=delegated_view(proc,process,path,group)
    managed_need(CGROUP_CONTROLLERS<=set(managed_read(path/'cgroup.controllers',4096).split())
                 and managed_read(path/'memory.swap.max',32).strip()==b'0',
                 'delegated controllers and unchanged zero-swap ceiling before launch')
    namespace=delegated_namespace(process)
    os.unshare(CLONE_NEWCGROUP)
    managed_need(delegated_namespace(process)!=namespace and membership()==b'0::/\n',
                 'private cgroup namespace rooted at the exact delegation')
    daemon=path/'daemon'
    daemon.mkdir(mode=0o755)
    delegated_write(daemon/'cgroup.procs',str(self_pid).encode())
    managed_need(membership()==b'0::/daemon\n','same trusted launcher joined delegated daemon leaf')
    enable=b'+cpu +memory +pids'
    delegated_write(path/'cgroup.subtree_control',enable)
    containers=path/CONTAINER_GROUP.lstrip('/')
    containers.mkdir(mode=0o755)
    delegated_write(containers/'cgroup.subtree_control',enable)
    for item in (path,containers):
        managed_need(CGROUP_CONTROLLERS<=set(managed_read(item/'cgroup.subtree_control',4096).split()),
                     'required delegates enabled before dockerd probes its resource view')
    managed_need(bool(managed_read(daemon/'memory.swap.max',32).strip())
                 and view['inode']==path.lstat().st_ino and membership()==b'0::/daemon\n',
                 'daemon discovers its local swap control on the same owned mount')
    os.execv(command[0],command)


def observe_delegated_view(proc, pid, group):
    process=proc/str(pid)
    host=Path(CGROUP_VIEW+group)
    before=host.lstat()
    view=delegated_view(proc,process,process/'root'/CGROUP_VIEW.lstrip('/'),group)
    namespace=delegated_namespace(process)
    managed_need(stat.S_ISDIR(before.st_mode) and (view['device'],view['inode'])==(before.st_dev,before.st_ino)
                 and managed_identity(host.lstat())==managed_identity(before)
                 and namespace!=delegated_namespace(proc/'self'), 'exact host delegation and private runtime cgroup namespace')
    view['namespace']=dict(device=namespace[0],inode=namespace[1])
    return view


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


def managed_shim_mountinfo(raw):
    rows=[]
    for line in raw.splitlines():
        left,separator,right=line.partition(b' - ')
        fixed=left.split()
        if len(fixed)>=5 and fixed[4]==os.fsencode(HOST_RUNTIME):
            managed_need(separator and len(fixed)>=6 and re.fullmatch(rb'[1-9][0-9]{0,19}',fixed[0])
                         and re.fullmatch(rb'[0-9]{1,10}:[0-9]{1,10}',fixed[2]) and fixed[3]==b'/',
                         'exact private shim mountinfo shape')
            filesystem=right.split()
            flags=set(fixed[5].split(b','))
            managed_need(len(filesystem)==3 and filesystem[:2]==[b'tmpfs',b'tmpfs']
                         and {b'rw',b'nosuid',b'nodev',b'noexec'}<=flags and b'ro' not in flags
                         and b'rw' in filesystem[2].split(b',') and b'ro' not in filesystem[2].split(b','),
                         'private shim mount is writable hardened tmpfs')
            rows.append((int(fixed[0]),tuple(map(int,fixed[2].split(b':')))))
    managed_need(len(rows)==1,'one exact shim tmpfs in daemon mount namespace')
    return rows[0]


def managed_shim_host():
    """Require an existing host mount point before systemd can apply the private overlay."""
    path=Path(HOST_RUNTIME)
    info=path.lstat()
    managed_need(path==path.resolve() and stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0
                 and not info.st_mode&0o022, 'existing trusted host shim mount point')
    return managed_identity(info)


def managed_shim_mount(proc, pid):
    process=proc/str(pid)
    mount_id,device=managed_shim_mountinfo(managed_read(process/'mountinfo',256*1024))
    path=process/'root'/HOST_RUNTIME.lstrip('/')
    before=path.lstat()
    outside=managed_shim_host()
    managed_need(stat.S_ISDIR(before.st_mode) and before.st_uid==before.st_gid==0
                 and stat.S_IMODE(before.st_mode)==0o755 and (os.major(before.st_dev),os.minor(before.st_dev))==device
                 and before.st_dev!=outside[0],'private root-owned shim mount identity')
    vfs=os.statvfs(path)
    total=vfs.f_frsize*vfs.f_blocks
    flags=os.ST_NOSUID|os.ST_NODEV|os.ST_NOEXEC
    managed_need(total==SHIM_TMPFS_BYTES and vfs.f_flag&(flags|os.ST_RDONLY)==flags
                 and managed_identity(path.lstat())==managed_identity(before), 'stable writable 4 MiB shim tmpfs and exact flags')
    return dict(path=HOST_RUNTIME,filesystem='tmpfs',mode=0o755,mount_id=mount_id,device=before.st_dev,inode=before.st_ino,
                bytes=total,writable=True,nosuid=True,nodev=True,noexec=True)


def managed_receipt(value, daemon_pid, daemon_start, daemon_group):
    """Rejoin the existing controller-issued proof before the ordinary payload runs."""
    fields={'kind','pid','starttime','parent_pid','cgroup','executable','mount_namespace','socket','shim_mount','delegated_cgroup',
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
    shim=value['shim_mount']
    fixed=dict(path=HOST_RUNTIME,filesystem='tmpfs',mode=0o755,bytes=SHIM_TMPFS_BYTES,
               writable=True,nosuid=True,nodev=True,noexec=True)
    ids={'mount_id','device','inode'}
    managed_need(type(shim) is dict and set(shim)==fixed.keys()|ids
                 and all(type(shim[k]) is type(v) and shim[k]==v for k,v in fixed.items())
                 and all(type(shim[k]) is int and shim[k]>0 for k in ids), 'exact admitted private writable shim receipt')
    group=value['delegated_cgroup']
    fixed=dict(path=CGROUP_VIEW,root=daemon_group.removesuffix('/daemon'),filesystem='cgroup2',container_parent=CONTAINER_GROUP)
    namespace=group.get('namespace') if type(group) is dict else None
    managed_need(type(group) is dict and set(group)==fixed.keys()|ids|{'namespace'}
                 and all(group[k]==v for k,v in fixed.items()) and all(type(group[k]) is int and group[k]>0 for k in ids)
                 and type(namespace) is dict and set(namespace)=={'device','inode'}
                 and all(type(v) is int and v>0 for v in namespace.values()),'exact admitted private delegated cgroup receipt')
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
    shim=managed_shim_mount(proc,daemon_pid)
    delegated_group=daemon_group.removesuffix('/daemon')
    delegated=observe_delegated_view(proc,daemon_pid,delegated_group)
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
        managed_need(managed_shim_mount(proc,pid)==shim,'dockerd and managed child see the same private writable shim mount')
        managed_need(observe_delegated_view(proc,pid,delegated_group)==delegated,
                     'dockerd and managed child share the same exact delegated cgroup view')
        executable=(proc/str(pid)/'exe').resolve(strict=True)
        executable_info=(proc/str(pid)/'exe').stat()
        managed_need(str(executable) in CONTAINERD_PATHS and executable_info.st_uid==0
                     and stat.S_ISREG(executable_info.st_mode) and executable_info.st_mode&0o111 and not executable_info.st_mode&0o022
                     and managed_identity(executable_info)==managed_identity(executable.stat()), 'same root-owned existing containerd executable')
        managed_need(managed_read(path.parent/'containerd.pid',32,root_file=True).strip()==str(pid).encode(), 'same managed containerd PID file and socket peer')
        managed_selection(managed_read(volume/'daemon.log',256*1024,root_file=True),path)
        managed_need(managed_proc(proc,pid)==child and managed_proc(proc,daemon_pid)==daemon_before and managed_shim_mount(proc,daemon_pid)==shim
                     and observe_delegated_view(proc,daemon_pid,delegated_group)==delegated
                     and managed_identity(path.lstat())==managed_identity(info), 'stable admitted daemon, managed peer and socket')
    return managed_receipt(dict(kind=MANAGED_MODE,pid=pid,starttime=child[1],parent_pid=daemon_pid,cgroup=daemon_group,
                                executable=str(executable),mount_namespace=dict(device=child[3][0],inode=child[3][1]),
                                socket=dict(device=info.st_dev,inode=info.st_ino,uid=info.st_uid,gid=info.st_gid),
                                same_mount_namespace=True,default_socket_hidden=True,selected_private_socket=True,shim_mount=shim,
                                delegated_cgroup=delegated),
                           daemon_pid,daemon_start,daemon_group)


if __name__=='__main__':
    managed_need(len(sys.argv)>4 and sys.argv[1]=='--start-delegated-daemon','only the exact owned daemon launch entry')
    start_delegated_daemon(sys.argv[2],sys.argv[3:])
