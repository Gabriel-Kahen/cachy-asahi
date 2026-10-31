# SPDX-License-Identifier: MIT
"""Block every later helper exec after signed prepare in the isolated ALPM child.

The selected configuration-only commit has NOHOOKS|NOSCRIPTLET and a closed
prepared package set. Required explicit GPG and signed package loading precede
this irreversible child-only filter. It prevents libalpm's built-in ldconfig
from rewriting the copied source's protected inode-dependent auxiliary cache.
It neither changes an ALPM flag nor exempts any readback node or metadata.
"""
import ctypes, errno, os, platform

def deny_exec():
 class Filter(ctypes.Structure):
  _fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
 class Program(ctypes.Structure):
  _fields_=[('length',ctypes.c_ushort),('filters',ctypes.POINTER(Filter))]
 profiles={'aarch64':(0xc00000b7,(221,281)),'x86_64':(0xc000003e,(59,322,0x40000000|59,0x40000000|322,0x40000000|520,0x40000000|545))}
 machine=platform.machine()
 if machine not in profiles:raise ValueError('unsupported native seccomp ABI')
 arch,numbers=profiles[machine]
 libc=ctypes.CDLL(None,use_errno=True);prctl=libc.prctl
 prctl.argtypes=[ctypes.c_int,*([ctypes.c_ulong]*4)];prctl.restype=ctypes.c_int
 if prctl(39,0,0,0,0)!=1:raise ValueError('existing NoNewPrivs required')
 # seccomp_data: nr@0, arch@4. Unknown ABI kills; exact exec syscalls get EPERM.
 rows=[(0x20,0,0,4),(0x15,1,0,arch),(0x06,0,0,0x80000000),(0x20,0,0,0)]
 for nr in numbers:rows.extend(((0x15,0,1,nr),(0x06,0,0,0x00050000|errno.EPERM)))
 rows.append((0x06,0,0,0x7fff0000));filters=(Filter*len(rows))(*(Filter(*r)for r in rows));program=Program(len(rows),filters)
 if prctl(22,2,ctypes.addressof(program),0,0)!=0:raise OSError(ctypes.get_errno(),'install no-helper-exec seccomp filter')
 return dict(status='KERNEL_ENFORCED_NO_POST_PREPARE_EXEC',architecture=machine,execve='EPERM',execveat='EPERM',unknown_arch='KILL_PROCESS',NoNewPrivs=1)
