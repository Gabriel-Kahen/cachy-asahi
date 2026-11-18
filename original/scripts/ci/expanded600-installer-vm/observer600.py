# SPDX-License-Identifier: MIT
"""Dedicated600 descriptor mount query; the complete held walker stays unchanged."""

def _mount600(original):
    import ctypes
    import errno
    import os
    import sys
    # Linux statx UAPI: mask offset0, mnt_id offset144, fixed256-byte record.
    # Request ordinary STATX_MNT_ID, never the distinct MNT_ID_UNIQUE namespace.
    class Statx600(ctypes.Structure):
        _fields_=[('mask',ctypes.c_uint32),('prefix',ctypes.c_ubyte*140),
                  ('mnt_id',ctypes.c_uint64),('reserved',ctypes.c_ubyte*104)]
    supported=(sys.platform=='linux' and sys.byteorder=='little' and ctypes.sizeof(ctypes.c_void_p)==8 and
               os.uname().machine in ('aarch64','x86_64') and ctypes.sizeof(Statx600)==256 and Statx600.mnt_id.offset==144)
    libc=ctypes.CDLL(None,use_errno=True) if supported else None
    call=getattr(libc,'statx',None)
    if call is not None:
        call.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_uint,ctypes.POINTER(Statx600))
        call.restype=ctypes.c_int
    checked=False
    def query(descriptor,limits):
        nonlocal call,checked
        limits.tick()
        if call is None:return original(descriptor,limits)
        result=Statx600()
        if call(descriptor,b'',0x1000,0x1000,ctypes.byref(result))!=0:
            error=ctypes.get_errno()
            if error in (errno.ENOSYS,errno.EINVAL,errno.EOPNOTSUPP,errno.EPERM):
                call=None;return original(descriptor,limits)
            raise OSError(error,'descriptor statx mount query failed')
        if not result.mask&0x1000:
            call=None;return original(descriptor,limits)
        if not result.mnt_id:raise ValueError('descriptor statx mount identity unavailable')
        if not checked:
            if result.mnt_id!=original(descriptor,limits):raise ValueError('descriptor mount identity APIs differ')
            checked=True
        return result.mnt_id
    return query


def _observer600(roots,root,**kwargs):
    import hashlib
    from pathlib import Path
    import types
    raw=Path(roots.__file__).read_bytes()
    if len(raw)!=35970 or hashlib.sha256(raw).hexdigest()!='cece1c597b2e2eb98b0e3087cc7e7c148b54332f8a1c4f18e04e4552a71fb51d':
        raise ValueError('dedicated600 held root observer source differs')
    # Clone only this call's global dictionary. Do not mutate full_root or its
    # walker/hash/identity implementations, caller limits, or another observer.
    namespace=dict(roots.observe.__globals__,_mount_id=_mount600(roots._mount_id))
    observer=types.FunctionType(roots.observe.__code__,namespace,roots.observe.__name__,roots.observe.__defaults__,roots.observe.__closure__)
    observer.__kwdefaults__=roots.observe.__kwdefaults__
    return observer(root,**kwargs)
