# SPDX-License-Identifier: MIT
"""Private complete inode readback without rereading payload or following links."""
import os,stat
import contract as C
import full_root as R

def capture(root,nodes,limits):
 result={};children={'':[]}
 for name in nodes:
  parent,_,leaf=name.rpartition('/');children.setdefault(parent,[]).append(leaf)
  if nodes[name]['type']=='directory':children.setdefault(name,[])
 fd=R._open_root(root)
 try:
  root_identity=R._identity(os.fstat(fd));result['']=list(root_identity)
  mount=R._mount_id(fd,limits)
  def walk(directory,prefix=''):
   limits.tick();C.need(R._mount_id(directory,limits)==mount,'physical mount crossing')
   C.need(sorted(os.listdir(directory))==sorted(children[prefix]),'physical complete graph differs')
   for leaf in sorted(children[prefix]):
    limits.tick();name=prefix+'/'+leaf if prefix else leaf;info=os.stat(leaf,dir_fd=directory,follow_symlinks=False);row=nodes[name]
    kind='directory'if stat.S_ISDIR(info.st_mode)else'file'if stat.S_ISREG(info.st_mode)else'symlink'if stat.S_ISLNK(info.st_mode)else'special'
    C.need(kind==row['type']and stat.S_IMODE(info.st_mode)==row['mode']and info.st_uid==row['uid']and info.st_gid==row['gid'],'physical/logical metadata differs')
    result[name]=list(R._identity(info))
    if kind=='directory':
     child=os.open(leaf,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
     try:C.need(R._identity(os.fstat(child))==R._identity(info),'physical directory rebound');walk(child,name)
     finally:os.close(child)
    C.need(R._identity(os.stat(leaf,dir_fd=directory,follow_symlinks=False))==R._identity(info),'physical node changed')
  walk(fd)
  C.need(R._identity(os.fstat(fd))==root_identity,'physical root identity drift')
  rebound=R._open_root(root)
  try:C.need(R._identity(os.fstat(rebound))==root_identity and R._mount_id(rebound,limits)==mount,'physical named root/mount rebound')
  finally:os.close(rebound)
 finally:os.close(fd)
 C.need(len(result)==len(nodes)+1,'complete physical identity count');return result

def protected(before,after,before_nodes,after_nodes,selected,lock_witness=None):
 changed={n for n in before.keys()|after.keys()if before.get(n)!=after.get(n)}
 parents={n.rpartition('/')[0]for n in changed if selected(n)}
 for name in before.keys()|after.keys():
  if selected(name):continue
  a,b=before.get(name),after.get(name);C.need(a is not None and b is not None,'protected inode missing/extra')
  # roots._identity: dev,ino,mode,uid,gid,nlink,size,mtime_ns,ctime_ns.
  if name=='var/lib/pacman'and lock_witness is not None:
   C.need(lock_witness.get('path')==name and lock_witness.get('lock_created')is True and lock_witness.get('lock_removed')is True and a[:6]==b[:6]and lock_witness['before'][:6]==lock_witness['after'][:6]==a[:6],'actual transient lock parent witness/structural identity')
   continue
  if name in parents and before_nodes[name]['type']==after_nodes[name]['type']=='directory':
   C.need(a[:5]==b[:5],'selected parent inode/mode/owner changed')
   child_dirs=lambda nodes:sum(v['type']=='directory'for n,v in nodes.items()if n.rpartition('/')[0]==name and selected(n))
   C.need(b[5]-a[5]==child_dirs(after_nodes)-child_dirs(before_nodes),'selected parent link-count delta differs')
   # Only the exact parent of an actually changed selected directory entry may
   # change directory size/mtime/ctime; complete names/modes are checked above.
  else:C.need(a==b,'protected full inode metadata changed')
 return True
