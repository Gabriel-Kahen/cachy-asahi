"""Original offline preparer with one explicit new-purpose staging call."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import inputs,disk_adapter,stage,runtime_policy
P,_,_,_=inputs.broker()
def load(value):
 original=inputs.original('_immutable_native_original_prepare','scripts/ci/glibc-debian-maintained-installed16k/prepare.py');raw=Path(original.__file__).read_bytes();space=dict(vars(original),runtime_stage=stage,runtime_policy=value)
 text=disk_adapter.preparer(raw)
 exec(compile(text,original.__file__,'exec'),space);space['INIT']=disk_adapter.init(raw)[0];return space
def media_handoff(parent,uid,gid):
 # Fixed descriptor ownership handback, no traversal, content/mode edit or deletion.
 import os,stat
 parent=Path(parent)
 P.need(parent.is_absolute()and not any(p.is_symlink()for p in(parent,*parent.parents)),'ordinary anchored media parent')
 flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
 pfd=os.open(parent,flags);fd=None
 identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_uid,s.st_gid,s.st_mtime_ns,s.st_ctime_ns)
 try:
  base=os.fstat(pfd);P.need(stat.S_IMODE(base.st_mode)==0o700 and (base.st_uid,base.st_gid)==(uid,gid)and identity(base)==identity(parent.lstat()),'exact original private output owner')
  try:fd=os.open('immutable-media',flags,dir_fd=pfd)
  except FileNotFoundError:return
  before=os.fstat(fd)
  P.need(before.st_dev==base.st_dev and before.st_uid in(os.geteuid(),uid)and stat.S_IMODE(before.st_mode)==0o700 and before.st_nlink==2,'ordinary original media directory')
  caps={'source.raw':8*1024**3,'source.hash':128*1024**2,'source-before.json':96*1024**2,'source-after.json':96*1024**2,'source-image.json':4*1024**2}
  names=os.listdir(fd);P.need(set(names)<=set(caps),'finite exact media child paths')
  entries={}
  for name in names:
   info=os.stat(name,dir_fd=fd,follow_symlinks=False)
   P.need(stat.S_ISREG(info.st_mode)and info.st_nlink==1 and info.st_uid in(os.geteuid(),uid)and not(info.st_mode&0o022)and info.st_dev==before.st_dev and 0<=info.st_size<=caps[name],'ordinary bounded single-link media child')
   entries[name]=identity(info)
  P.need(set(os.listdir(fd))==set(names)and all(identity(os.stat(n,dir_fd=fd,follow_symlinks=False))==v for n,v in entries.items())and identity(os.fstat(fd))==identity(before)==identity(os.stat('immutable-media',dir_fd=pfd,follow_symlinks=False)),'same anchored media directory and children before handoff')
  # Only the two exact QEMU drive files need host-caller access (hash is0600).
  for name in ('source.raw','source.hash'):
   if name not in entries:continue
   child=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=fd)
   try:
    held=os.fstat(child);P.need(identity(held)==entries[name]and stat.S_IMODE(held.st_mode)in(0o600,0o644),'same exact ordinary drive descriptor')
    os.fchown(child,uid,gid);now=os.fstat(child)
    P.need((now.st_uid,now.st_gid)==(uid,gid)and (now.st_dev,now.st_ino,now.st_mode,now.st_nlink,now.st_size,now.st_mtime_ns)==(held.st_dev,held.st_ino,held.st_mode,held.st_nlink,held.st_size,held.st_mtime_ns)and identity(now)==identity(os.stat(name,dir_fd=fd,follow_symlinks=False)),'same drive bytes/metadata handed only to output owner')
    entries[name]=identity(now)
   finally:os.close(child)
  os.fchown(fd,uid,gid)
  after=os.fstat(fd)
  P.need((after.st_uid,after.st_gid)==(uid,gid)and (after.st_dev,after.st_ino,after.st_mode,after.st_nlink,after.st_size,after.st_mtime_ns)==(before.st_dev,before.st_ino,before.st_mode,before.st_nlink,before.st_size,before.st_mtime_ns)and identity(after)==identity(os.stat('immutable-media',dir_fd=pfd,follow_symlinks=False)),'same media inode handed only to original parent owner')
  P.need(set(os.listdir(fd))==set(names)and all(identity(os.stat(n,dir_fd=fd,follow_symlinks=False))==v for n,v in entries.items()),'media child metadata held through handoff')
 finally:
  if fd is not None:os.close(fd)
  os.close(pfd)

def execute(value):
 runtime_policy.gate(value,preparing=True)
 try:return load(value)['prepare']()
 finally:
  import os
  media_handoff(Path('/out'),int(os.environ['OUTPUT_UID']),int(os.environ['OUTPUT_GID']))

if __name__=='__main__':
 value=P.decode(runtime_policy.read(Path('/runtime-selection/policy.json'),1024**2));execute(value)
