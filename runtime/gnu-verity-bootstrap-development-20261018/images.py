"""Ordinary unmounted ext4+verity files; no mount/device/host system mutation."""
import hashlib,os,shutil,stat,subprocess,time
from pathlib import Path
from unittest.mock import patch
import common as C,recovery,source_snapshot
from borrowed import verity_image as V


def tool(name):
 p=shutil.which(name);C.need(p is not None,'required real offline image tool: '+name);p=Path(p).resolve();s=p.stat();C.need(stat.S_ISREG(s.st_mode)and os.access(p,os.X_OK),'ordinary executable tool');return p


def prepare(tree,out,*,snapshot,limits,size=8*C.GIB):
 """Caller supplies original complete observer/capability/DB snapshot function.

 snapshot must invoke the unchanged source-pinned GNU APIs. This image receipt
 is never a replacement for mandatory complete guest readback against that map.
 """
 tree=Path(tree);out=Path(out);C.need(tree.is_absolute()and out.is_absolute()and not tree.is_relative_to(out)and not out.is_relative_to(tree),'disjoint ordinary tree/output')
 C.need(not any(p.is_symlink()for p in(tree,*tree.parents,out,*out.parents))and tree.is_dir()and not out.exists(),'fresh ordinary output and source');info=tree.stat();C.need(info.st_uid==os.geteuid()and not stat.S_IMODE(info.st_mode)&0o022,'owned source tree; no foreign writer authority')
 C.need(type(size)is int and 64*1024**2<=size<=8*C.GIB and size%4096==0,'bounded aligned source file');mkfs,debugfs=tool('mkfs.ext4'),tool('debugfs');before=snapshot(tree,limits);C.need(type(before)is dict and type(before.get('nodes'))is dict,'complete original source nodes required');limits.tick();out.mkdir(mode=0o700);image=out/'source.raw';hashed=out/'source.hash';commands=[]
 def command(argv,seconds=900):
  limits.tick();actual=[str(debugfs)if i==0 and str(x)=='/usr/bin/debugfs'else str(x)for i,x in enumerate(argv)];row=subprocess.run(actual,stdin=subprocess.DEVNULL,capture_output=True,timeout=seconds);C.need(len(row.stdout)+len(row.stderr)<=2*1024**2 and row.returncode==0,'real bounded offline image command failed');commands.append(dict(argv=actual,exit=row.returncode,stdout=C.pin(row.stdout),stderr=C.pin(row.stderr)));limits.tick();return row.stdout
 with image.open('xb')as stream:stream.truncate(size)
 command([mkfs,'-F','-b','4096','-m','0','-E',f'root_owner={info.st_uid}:{info.st_gid}','-d',tree,image])
 with patch.object(recovery,'command',command):
  recovery.formatter_recovery_directory(image,before['nodes'],out)
  command([debugfs,'-w','-R','set_inode_field / mode 0'+oct(info.st_mode)[2:],image],60)
  root=recovery.image_directory(command([debugfs,'-R','ls -p /',image],60))['.'];C.need(root['mode']==info.st_mode and(root['uid'],root['gid'])==(info.st_uid,info.st_gid),'exact original source root metadata readback')
 after=snapshot(tree,limits);source_snapshot.same(before,after);C.need(C.stable(tree.stat())==C.stable(info),'original complete source root identity held through image preparation');(out/'source-before.json').write_bytes(C.encoded(before));(out/'source-after.json').write_bytes(C.encoded(after))
 value=V.format(image,hashed,salt=os.urandom(32),max_data_bytes=size,tick=limits.tick);limits.tick();C.need(value['data']==V.pin(image),'whole image hash joined streaming formatter')
 receipt=dict(status='OFFLINE_SOURCE_EXT4_AND_VERITY_FILES_ONLY_NOT_GUEST_READBACK',format=value,original_snapshot=C.pin(C.encoded(before)),source_after=C.pin(C.encoded(after)),fresh_capacity='BOTH_RAW_ORIGINAL_COUNTERS_RETAINED_ONLY_TWO_VOLATILE_COUNTERS_NOT_EQUALIZED',source_root_identity=list(C.stable(info)),tools={str(p):V.pin(p)for p in(mkfs,debugfs)},commands=commands,guest_complete_nodes_caps_DB_hardlinks_users_trust='REQUIRED_NOT_RUN',kernel_DM='NOT_RUN',immutable_context='NOT_ACTIVATED',hardware='NOT_RUN',release='NOT_ADMITTED')
 (out/'source-image.json').write_bytes(C.encoded(receipt));return receipt

def prepare_original(tree,out,*,size=8*C.GIB):
 modules=source_snapshot.api();F=modules['full_root'];budget=F.Limits(deadline=time.monotonic()+600,max_packages=574,max_nodes=500000,max_bytes=8*C.GIB,max_file_bytes=C.GIB)
 return prepare(tree,out,snapshot=lambda root,limits:source_snapshot.observe(modules,root,limits),limits=budget,size=size)
