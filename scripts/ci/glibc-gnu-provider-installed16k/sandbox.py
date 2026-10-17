# SPDX-License-Identifier: MIT
"""Exact native trial caps plus a finite AArch64 mount-topology syscall fence."""
import ctypes
import errno
import os
from pathlib import Path
import stat
import contract as C

# Same ten --cap-add entries as native run.py's trial actor. No MKNOD,
# SYS_PTRACE, SYS_BOOT, DAC_READ_SEARCH, NET_ADMIN, BPF or SETPCAP survives.
CAPS=(0,1,3,4,5,6,7,18,21,31)
MASK=sum(1<<n for n in CAPS)
ENOSYS_CALLS=(428,429,430,431,432,433,442)  # New mount API; old mount fallback only.
EPERM_CALLS=(33,41,97,117,268,271,280)  # mknodat,pivot_root,unshare,ptrace,setns,process_vm_writev,bpf.

def filter_rows():
    rows=[(0x20,0,0,4),(0x15,1,0,0xc00000b7),(0x06,0,0,0x80000000),(0x20,0,0,0)]
    for numbers,error in ((ENOSYS_CALLS,errno.ENOSYS),(EPERM_CALLS,errno.EPERM)):
        for nr in numbers:rows.extend(((0x15,0,1,nr),(0x06,0,0,0x50000|error)))
    # mount(source,target,type,flags,data): permit ONLY flags15 (readonly,
    # nosuid,nodev,noexec) or MS_BIND4096. No remount, propagation or move.
    rows.extend(((0x15,0,6,40),(0x20,0,0,44),(0x15,0,3,0),(0x20,0,0,40),(0x15,2,0,15),(0x15,1,0,4096),(0x06,0,0,0x50000|errno.EPERM),(0x06,0,0,0x7fff0000)))
    return rows

def apply():
    C.need(os.uname().machine=='aarch64' and os.getpid()!=1 and os.geteuid()==0 and os.sysconf('SC_PAGE_SIZE')==16384,'only actual16K lifecycle child may reduce authority')
    C.need(not Path('/volume/held').exists() and not Path('/volume/work').exists(),'writable original disk alias remains')
    C.need(all(not stat.S_ISBLK(p.lstat().st_mode) for p in Path('/dev').iterdir()) and {p.name for p in Path('/dev').iterdir()}=={'null','zero','random','urandom'},'no raw devices in lifecycle namespace')
    for path in Path('/proc/self/fd').iterdir():
        try:info=os.stat(path)
        except FileNotFoundError:continue
        C.need(not stat.S_ISBLK(info.st_mode),'raw block descriptor inherited by lifecycle child')
    # Reuse the existing native IPC filter and complete capability readback body.
    # Its capability-mask policy alone is specialized to the original GNU actor.
    held=C.load('held_isolation','/source/scripts/install/local_transaction.py')
    held.block_service_ipc(architecture='aarch64')
    held.capability_mask=lambda fixture_identity_map=None:MASK
    held.reduce_capabilities()
    class Filter(ctypes.Structure):_fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
    class Program(ctypes.Structure):_fields_=[('length',ctypes.c_ushort),('filters',ctypes.POINTER(Filter))]
    rows=filter_rows();filters=(Filter*len(rows))(*(Filter(*r) for r in rows));program=Program(len(rows),filters)
    libc=ctypes.CDLL(None,use_errno=True);C.need(libc.prctl(22,2,ctypes.byref(program),0,0)==0,'mount topology seccomp fence refused')
    status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    C.need(status['NoNewPrivs'].strip()=='1' and status['Seccomp'].strip()=='2' and all(int(status[k].strip(),16)==MASK for k in ('CapEff','CapPrm','CapBnd')),'actual worker authority differs')
    return dict(status='PASS_OBSERVED_NATIVE_CAPS_AND_MOUNT_FENCE',mask=MASK,no_new_privs=1,seccomp=2,raw_block_devices=[],writable_source_alias=False,mount_flags=[15,4096],filter_sha256=C.sha(repr(rows).encode()),held_capability_helper='UNCHANGED_REDUCE_CAPABILITIES_BODY_WITH_EXPLICIT_GNU_MASK',held_ipc_helper='UNCHANGED_AARCH64_BLOCK_SERVICE_IPC')
