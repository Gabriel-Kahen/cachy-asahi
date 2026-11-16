# SPDX-License-Identifier: MIT
"""Readonly own-UID Linux quota and sparse allocation guards. No quota writes."""
import os
import platform
from pathlib import Path
import shutil
import stat
import time


def quota_fd(fd, uid):
    import ctypes
    class Dqblk(ctypes.Structure):
        _fields_=[(n,ctypes.c_uint64)for n in ('bhard','bsoft','curspace','ihard','isoft','curinodes','btime','itime')]+[('valid',ctypes.c_uint32)]
    if type(uid)is not int or uid!=os.getuid() or not 0<=uid<2**32 or not stat.S_ISDIR(os.fstat(fd).st_mode):raise ValueError('readonly own-UID quota directory FD required')
    if not(platform.system()=='Linux' and platform.machine()=='x86_64' and ctypes.sizeof(ctypes.c_long)==ctypes.sizeof(ctypes.c_void_p)==8 and ctypes.sizeof(Dqblk)==72 and Dqblk.valid.offset==64 and all(getattr(Dqblk,n).offset==i*8 for i,(n,_)in enumerate(Dqblk._fields_[:-1]))):raise ValueError('reviewed Linux x86_64 syscall443 if_dqblk ABI required')
    libc=ctypes.CDLL(None,use_errno=True);q=Dqblk()
    libc.syscall.restype=ctypes.c_long
    ctypes.set_errno(0)
    if libc.syscall(ctypes.c_long(443),ctypes.c_int(fd),ctypes.c_uint(0x80000700),ctypes.c_uint(uid),ctypes.byref(q))!=0:
        raise OSError(ctypes.get_errno()or 5,'readonly quotactl_fd Q_GETQUOTA unavailable; HOLD')
    # Both finite limits matter. Refuse unknown/infinite-only quota state.
    limits=[n*1024 for n in (q.bhard,q.bsoft) if n]
    if q.valid & 3 != 3 or not limits: raise ValueError('finite observed block quota/headroom required')
    return max(0,min(limits)-q.curspace)


def quota(device, uid):
    # A mount directory (not a block-device special file), as required by
    # quotactl_fd. Walk every component read-only without following aliases.
    if type(device)is not str or not device.startswith('/dev/') or '\0'in device or any(p in('','.','..')for p in device[1:].split('/')):raise ValueError('literal quota mount directory under /dev required')
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC;fd=os.open('/',flags)
    try:
        for part in device[1:].split('/'):
            child=os.open(part,flags,dir_fd=fd);os.close(fd);fd=child
        return quota_fd(fd,uid)
    finally:os.close(fd)


class Guard:
    def __init__(self, root, resources, device, deadline, allocation, initial=False, query=quota, source=None, phase=None):
        self.root,self.r,self.device,self.deadline,self.allocation,self.query=Path(root),resources,device,deadline,allocation,query
        self.last=0;self.initial=initial;self.samples=0
        self.home=None;self.last_snapshot=None;self.source,self.phase=source,phase
        if resources['quota_guard']['method']=='READ_ONLY_HOME_BTRFS_ENOSYS_FSTATVFS':
            import importlib.util
            spec=importlib.util.spec_from_file_location('perl_budget_home',Path(__file__).resolve().parent/'home_btrfs.py');self.home=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.home)
            if source is None or phase not in('prepare','boot'):raise ValueError('explicit HOME controller Source and phase required')
            self.home.profile(resources['quota_guard'],resources,source,phase,self.root,int(time.time()))
            if device is not None:raise ValueError('HOME FD syscall mode has no device-path quota operand')
    def __call__(self, force=False):
        now=time.monotonic()
        if now>=self.deadline: raise TimeoutError('whole actor deadline')
        if not force and now-self.last<.5:return
        r=self.r
        if self.root.stat().st_dev!=r['output_device'] or os.getuid()!=r['host_uid']:raise ValueError('actual quota UID/device differs')
        if self.home is not None:
            self.last_snapshot=self.home.sample(self.root,r,self.source,self.phase,self.initial,self.deadline,self.allocation)
        else:
            reserve=r['quota_initial_headroom_bytes'] if self.initial else r['quota_live_reserve_bytes']
            if self.query(self.device,os.getuid())<reserve:raise ValueError('own-UID quota reserve exhausted')
            free=shutil.disk_usage(self.root).free
            if self.initial and free<r['physical_free_bytes']:raise ValueError('initial actual free bytes below Root physical plan')
            if free<r['reserve_bytes']:raise ValueError('physical free reserve exhausted')
            cap=sum(r[n] for n in ('clone_allocated_cap_bytes','overlay_cap_bytes','readback_allocated_cap_bytes','logs_cap_bytes'))
            if self.allocation(self.root,deadline=self.deadline)>cap:raise ValueError('simultaneous allocated blocks exceed budget')
        mem={row.split(':')[0]:int(row.split()[1])*1024 for row in Path('/proc/meminfo').read_text().splitlines()}
        if self.initial and mem['MemAvailable']<r['owner_memory_bytes']+r['host_reserve_bytes']:raise ValueError('initial actor plus host RAM reserve')
        if mem['MemAvailable']<r['host_reserve_bytes']:raise ValueError('host RAM reserve exhausted')
        self.last=now;self.initial=False;self.samples+=1
