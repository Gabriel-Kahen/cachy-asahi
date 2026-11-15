# SPDX-License-Identifier: MIT
"""Read-only own-UID kernel quota observation; no quota mutation or import calls."""
import ctypes,os,stat,time
from pathlib import Path
Q_GETQUOTA=(0x800007<<8)  # linux/quota.h QCMD(Q_GETQUOTA, USRQUOTA)
class Dqblk(ctypes.Structure):
 _fields_=[(n,ctypes.c_uint64)for n in('bhard','bsoft','space','ihard','isoft','inodes','btime','itime')]+[('valid',ctypes.c_uint32)]
def read(parent,uid):
 """quotactl_fd reads only; unsupported/unknown quota cannot admit an actor."""
 if uid!=os.getuid()or uid==0:raise ValueError('ordinary current own UID only')
 p=Path(parent);fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  before=os.fstat(fd);lib=ctypes.CDLL(None,use_errno=True)
  if not hasattr(lib,'quotactl_fd'):raise OSError('readonly quotactl_fd unavailable')
  fn=lib.quotactl_fd;fn.argtypes=[ctypes.c_int,ctypes.c_uint,ctypes.c_int,ctypes.c_void_p];fn.restype=ctypes.c_int;row=Dqblk()
  if fn(fd,Q_GETQUOTA,uid,ctypes.byref(row))!=0:raise OSError(ctypes.get_errno(),'readonly own-UID Q_GETQUOTA refused')
  if not stat.S_ISDIR(before.st_mode)or before.st_dev!=p.stat().st_dev:raise ValueError('quota filesystem changed')
  return dict(uid=uid,device=before.st_dev,hard_bytes=row.bhard*1024,soft_bytes=row.bsoft*1024,used_bytes=row.space,valid=row.valid,observed_monotonic_ns=time.monotonic_ns())
 finally:os.close(fd)
def headroom(row,uid,device):
 if row.get('uid')!=uid or row.get('device')!=device or type(row.get('valid'))is not int or row['valid']&3!=3:raise ValueError('unknown own-UID quota observation')
 limits=[row[n]for n in('hard_bytes','soft_bytes')if type(row.get(n))is int and row[n]>0]
 used=row.get('used_bytes')
 if not limits or type(used)is not int or used<0:raise ValueError('finite genuine quota limit and usage required')
 return min(limits)-used
