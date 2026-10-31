# SPDX-License-Identifier: MIT
"""Initialize only genuine packaged-kernel indexes in the disposable media copy."""
import os,re,stat,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import case as C
KERNEL='7.2.10-1-aarch64-ARCH'
PREFIX='usr/lib/modules/'+KERNEL+'/'
INDEXES=tuple(PREFIX+n for n in ('modules.alias','modules.alias.bin','modules.builtin.alias.bin','modules.builtin.bin','modules.dep','modules.dep.bin','modules.devname','modules.softdep','modules.symbols','modules.symbols.bin','modules.weakdep'))
ARTIFACT='boot/initramfs-linux.img'
GENERATE=('/usr/bin/mkinitcpio','-p','linux-aarch64')

def nodes(root):
 base=Path(root)/PREFIX;C.need(base.is_dir()and not any(p.is_symlink()for p in(base,*base.parents)),'ordinary exact packaged module tree');out={}
 for p in sorted(base.rglob('*')):
  s=p.lstat();C.need(stat.S_ISDIR(s.st_mode)or stat.S_ISREG(s.st_mode)and s.st_nlink==1,'only original ordinary packaged module nodes')
  name=p.relative_to(root).as_posix();row=dict(type='directory'if stat.S_ISDIR(s.st_mode)else'file',mode=stat.S_IMODE(s.st_mode),uid=s.st_uid,gid=s.st_gid)
  if stat.S_ISREG(s.st_mode):row.update(C.pin(C.read(p,128*1024**2)))
  C.need(C.identity(s)==C.identity(p.lstat()),'stable complete packaged module node');out[name]=row
 return out

def initialize(root,command):
 root=Path(root).absolute();C.need(root.name=='boot'and root.parent.name=='stage'and root!=Path('/')and not any(p.is_symlink()for p in(root,*root.parents)),'only owned disposable media staging root')
 before=nodes(root);C.need(not any(n in before for n in INDEXES)and len([n for n in before if n.endswith('.ko')])==3655,'exact uninitialized original packaged7.2.10 module tree, no foreign index overwrite')
 argv=['/usr/bin/depmod','-b',str(root),'-a',KERNEL];command(argv,60);after=nodes(root)
 C.need(set(after)-set(before)==set(INDEXES)and all(after[n]==row for n,row in before.items()),'only eleven exact dependency indexes added, all original module nodes held')
 for n in INDEXES:C.need(after[n]['type']=='file'and after[n]['mode']==0o644 and after[n]['uid']==after[n]['gid']==0 and after[n]['bytes']<=8*1024**2,'bounded root-owned dependency cache')
 command(argv,60);C.need(nodes(root)==after,'original depmod complete output byte idempotence')
 return {n:dict(before=None,after=after[n])for n in INDEXES}

def validate_overlay(overlay):
 for name in INDEXES:
  row=overlay[name];C.need(set(row)=={'before','after'}and row['before']is None,'only fresh exact dependency index overlay')
  node=row['after'];C.need(set(node)=={'type','mode','uid','gid','bytes','sha256'}and node['type']=='file'and node['mode']==0o644 and node['uid']==node['gid']==0 and type(node['bytes'])is int and 0<=node['bytes']<=8*1024**2 and re.fullmatch('[0-9a-f]{64}',node['sha256']or''),'whole bounded root-owned module index node')
 return overlay

# Source-owned VM-only compression profile. No hook, module, preset or deadline
# is replaced; generated image and whole graph/idempotence guards stay active.
COMPRESSION_PATH='etc/mkinitcpio.conf.d/99-caa-core-vm-compression.conf'
COMPRESSION_DATA=b'# Owned disposable generic16K VM fixture only; original hooks/modules/preset held.\nCOMPRESSION="gzip"\nCOMPRESSION_OPTIONS=(-1 -n)\n'
def compression_profile():
 value=C.decode(C.read(C.HERE/'compression-profile.json',65536))
 C.need(value['scope']=='OWNED_DISPOSABLE_VM_GZIP1_ONLY'and value['path']==COMPRESSION_PATH and value['data']==C.pin(COMPRESSION_DATA)and value['options']==['-1','-n']and value['algorithm']=='gzip','exact source-owned compression profile')
 return value
def compression_inputs(root):
 root=Path(root).absolute();C.need(root.name=='boot'and root.parent.name=='stage'and root!=Path('/')and not any(p.is_symlink()for p in(root,*root.parents)),'owned disposable compression staging root')
 profile=compression_profile()
 for name,wanted in profile['original_files'].items():C.need(C.pin(C.read(root/name,1024**2))==wanted,'whole original mkinitcpio/gzip/main-config input '+name)
 folder=root/'etc/mkinitcpio.conf.d';C.need(folder.is_dir()and not folder.is_symlink()and not list(folder.iterdir()),'original empty ordinary config drop-in directory; no override')
 return dict(mode=0o644,data=COMPRESSION_DATA)
def validate_compression_overlay(overlay):
 row=overlay[COMPRESSION_PATH];C.need(row==dict(before=None,after=dict(type='file',mode=0o644,uid=0,gid=0,**compression_profile()['data'])),'exact complete source-owned gzip1 VM overlay')
 return row
