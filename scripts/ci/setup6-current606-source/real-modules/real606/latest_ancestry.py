# SPDX-License-Identifier: MIT
"""Fresh no-alias parent resolution; every original node observation remains fresh."""
import ctypes,errno,fcntl,os,sys

def parent_query(original,rootfd,flags,tick):
 class How(ctypes.Structure):
  _fields_=[('flags',ctypes.c_uint64),('mode',ctypes.c_uint64),('resolve',ctypes.c_uint64)]
 supported=sys.platform=='linux'and sys.byteorder=='little'and ctypes.sizeof(ctypes.c_void_p)==8 and os.uname().machine in('aarch64','x86_64')and ctypes.sizeof(How)==24
 libc=ctypes.CDLL(None,use_errno=True)if supported else None;call=getattr(libc,'syscall',None)
 if call is not None:
  call.argtypes=(ctypes.c_long,ctypes.c_int,ctypes.c_char_p,ctypes.POINTER(How),ctypes.c_size_t);call.restype=ctypes.c_long
 checked=False
 def query(name):
  nonlocal call,checked
  tick();parent=name.rpartition('/')[0]
  if not parent:return rootfd()
  encoded=os.fsencode(parent)
  if call is None or len(encoded)>=4096:return original(name)
  base=rootfd();result=None
  try:
   # NO_SYMLINKS includes every ancestry component. No NO_XDEV: original
   # native graphs permit mount crossings and independently observe mount IDs.
   how=How(flags,0,0x08|0x04|0x02)
   result=call(437,base,encoded,ctypes.byref(how),ctypes.sizeof(how))
   if result<0:
    error=ctypes.get_errno();result=None
    if error in(errno.ENOSYS,errno.EINVAL,errno.E2BIG,errno.EPERM):call=None;return original(name)
    if error in(errno.ENAMETOOLONG,errno.EAGAIN):return original(name)
    raise OSError(error,'fresh no-alias ancestry resolution failed')
   if not checked:
    prior=original(name)
    try:
     key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
     if key(os.fstat(result))!=key(os.fstat(prior))or fcntl.fcntl(result,fcntl.F_GETFL)!=fcntl.fcntl(prior,fcntl.F_GETFL)or fcntl.fcntl(result,fcntl.F_GETFD)!=fcntl.fcntl(prior,fcntl.F_GETFD):raise ValueError('fresh ancestry APIs differ')
    finally:os.close(prior)
    checked=True
   fd=result;result=None;return fd
  finally:
   if result is not None:os.close(result)
   os.close(base)
 return query
