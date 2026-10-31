# SPDX-License-Identifier: MIT
"""Fresh descriptor mount query; exact original graph/hash/identity/security walks held."""
import ast,hashlib,types
HELD={'bytes':18177,'sha256':'7fa40199aedb245b9060de46995e74205dff5b88ee8ec52da4f8697b2c2cd4cf'}
PROFILE='LATEST607_FRESH_DESCRIPTOR_GRAPH_QUERY_V1'
def need(ok,why):
 if not ok:raise ValueError(why)

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

def mount_query(original,tick):
 budget=types.SimpleNamespace(tick=tick)
 query=_mount600(lambda descriptor,limits:original(descriptor))
 return lambda descriptor:query(descriptor,budget)

def bind(module,raw):
 need(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())==HELD,'entire original graph before private descriptor binding')
 text=raw.decode();tree=ast.parse(text);nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='capture'];need(len(nodes)==1,'one complete original graph capture')
 before=ast.get_source_segment(text,nodes[0]);inner=[n for n in ast.walk(nodes[0])if isinstance(n,ast.FunctionDef)and n.name=='mount'];need(len(inner)==1,'one original descriptor mount-query seam');old=ast.get_source_segment(text,inner[0]);need(before.count(old)==1,'whole original nested mount query')
 new=old.replace('def mount(fd):','def fdinfo_mount(fd):',1)+'\n    mount = _mount_query(fdinfo_mount,tick)';after=before.replace(old,new,1);need(after.replace(new,old,1)==before,'whole original capture/security/hash/identity inverse')
 space=dict(vars(module),_mount_query=mount_query);exec(compile(after,'<latest607-exact-private-descriptor-capture>','exec'),space);return space['capture']
