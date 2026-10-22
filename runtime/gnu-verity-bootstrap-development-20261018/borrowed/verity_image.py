"""Bounded dm-verity v1 SHA256 tree over ordinary owned DATA files only."""
import hashlib,json,os,stat,tempfile
from pathlib import Path
BLOCK=4096;DIGEST=32;PER_BLOCK=BLOCK//DIGEST

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(path):
 with Path(path).open('rb')as stream:return dict(bytes=os.fstat(stream.fileno()).st_size,sha256=hashlib.file_digest(stream,'sha256').hexdigest())
def ordinary(path,flags):
 path=Path(path);need(path.is_absolute()and all(not p.is_symlink()for p in(path,*path.parents)),'ordinary absolute data path')
 fd=os.open(path,flags|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK,0o600);info=os.fstat(fd)
 if not(stat.S_ISREG(info.st_mode)and info.st_nlink==1 and info.st_uid==os.geteuid()):os.close(fd);raise ValueError('owned singlelink regular data required')
 return fd

def format(data,tree,*,salt,max_data_bytes,tick=lambda:None):
 """No device activation/mount/ioctl; constant block buffers, bounded temp tree."""
 need(type(salt)is bytes and len(salt)==32,'exact32-byte salt');need(type(max_data_bytes)is int and 2*BLOCK<=max_data_bytes<=16*1024**3,'bounded data image')
 data,tree=Path(data),Path(tree);need(not tree.exists()and not tree.is_symlink(),'fresh hash tree');source=ordinary(data,os.O_RDONLY)
 try:
  before=os.fstat(source);need(2*BLOCK<=before.st_size<=max_data_bytes and before.st_size%BLOCK==0,'whole aligned bounded data image')
  levels=[];count=before.st_size//BLOCK;data_hash=hashlib.sha256()
  with tempfile.TemporaryDirectory(prefix='verity-levels-',dir=tree.parent)as td:
   src=os.fdopen(os.dup(source),'rb');first=True
   try:
    while count>1:
     tick();level=Path(td)/('level%d'%len(levels));need(len(levels)<8,'bounded hash levels');out_count=0
     with level.open('xb')as out:
      for group in range(0,count,PER_BLOCK):
       hashes=[]
       for _ in range(min(PER_BLOCK,count-group)):
        tick();raw=src.read(BLOCK);need(len(raw)==BLOCK,'short data/hash block')
        if first:data_hash.update(raw)
        hashes.append(hashlib.sha256(salt+raw).digest())
       out.write(b''.join(hashes).ljust(BLOCK,b'\0'));out_count+=1
      need(src.read(1)==b'','unexpected trailing data')
     src.close();src=level.open('rb');levels.append(level);count=out_count;first=False
    root_block=src.read(BLOCK);need(len(root_block)==BLOCK and src.read(1)==b'','one root hash block');root_hash=hashlib.sha256(salt+root_block).hexdigest()
   finally:src.close()
   target=ordinary(tree,os.O_WRONLY|os.O_CREAT|os.O_EXCL)
   try:
    for level in reversed(levels):
     with level.open('rb')as src:
      while raw:=src.read(BLOCK):
       tick();view=memoryview(raw)
       while view:
        n=os.write(target,view);need(0<n<=len(view),'hash write progress');view=view[n:]
   finally:os.close(target)
  after=os.fstat(source);need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'data image changed during format')
  need(os.stat(data,follow_symlinks=False).st_ino==before.st_ino,'data image rebound')
  return dict(schema_version=1,status='OFFLINE_TREE_ONLY_NOT_KERNEL_VERIFIED',algorithm='sha256',version=1,data_block_bytes=BLOCK,hash_block_bytes=BLOCK,data_blocks=before.st_size//BLOCK,hash_start_block=0,root_hash=root_hash,salt=salt.hex(),data=dict(bytes=before.st_size,sha256=data_hash.hexdigest()),tree=pin(tree),kernel_activation=None)
 finally:os.close(source)
