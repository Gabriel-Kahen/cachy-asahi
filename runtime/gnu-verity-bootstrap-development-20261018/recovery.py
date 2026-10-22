"""Exact prior formatter recovery guards; only fixed filename boot.raw→source.raw."""
import os,stat
from pathlib import Path
import common as C
# Bound by the private image preparer to its actual pinned-tool command.
command=None

def image_directory(raw):
 """Strict bounded debugfs -p directory DATA; formatter free slots only."""
 C.need(type(raw)is bytes and 0<len(raw)<=65536,'bounded image directory listing');result={};slots=0
 for line in raw.splitlines():
  if not line:continue
  fields=line.split(b'/');C.need(len(fields)==8 and fields[0]==fields[-1]==b'','typed image directory row')
  ino,mode,uid,gid,name,size=fields[1:-1]
  if ino==b'0':
   C.need((mode,uid,gid,name,size)==(b'000000',b'0',b'0',b'',b'0'),'only zero formatter free slots');slots+=1;C.need(slots<=64,'finite formatter free slots');continue
  C.need(ino.isdigit()and 0<int(ino)<2**32 and len(mode)==6 and all(c in b'01234567'for c in mode)and uid.isdigit()and gid.isdigit()and int(uid)<2**32 and int(gid)<2**32,'typed image inode metadata')
  C.need(name and len(name)<=255 and not any(c<32 or c==127 for c in name)and(size==b''or size.isdigit())and len(result)<256,'bounded image entry name/size')
  key=name.decode('utf8');C.need(key not in result,'unique image entry names');result[key]=dict(inode=int(ino),mode=int(mode,8),uid=int(uid),gid=int(gid),size=None if size==b''else int(size))
 C.need(set(result)>={'.','..'},'complete image directory dot entries');return result

def formatter_recovery_directory(image,baseline,parent):
 """Remove only new mkfs empty recovery inode, never omit it from observation."""
 image=Path(image);parent=Path(parent)
 C.need(image==parent/'source.raw'and parent.is_dir()and not any(p.is_symlink()for p in(image,*image.parents)),'fixed owned unmounted boot-image path')
 held=image.lstat();identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size)
 C.need(stat.S_ISREG(held.st_mode)and held.st_nlink==1 and held.st_uid==os.geteuid()and not(held.st_mode&0o022),'owned single-link non-writable-by-others image')
 C.need(type(baseline)is dict,'complete original baseline required')
 if 'lost+found'in baseline:return # Original data is never removed or normalized.
 C.need(not any(n.startswith('lost+found/')for n in baseline),'complete absent recovery subtree')
 def listing(path):return image_directory(command(['/usr/bin/debugfs','-R','ls -p '+path,image],60))
 before=listing('/');entry=before.get('lost+found')
 expected=dict(inode=11,mode=0o40700,uid=0,gid=0,size=None)
 C.need(entry==expected and before['.']['inode']==before['..']['inode']==2 and stat.S_ISDIR(before['.']['mode']),'exact new formatter recovery directory')
 children=listing('/lost+found');C.need(set(children)=={'.','..'}and children['.']==dict(entry)and children['..']==before['.'],'only empty formatter directory under original root')
 C.need(identity(image.lstat())==identity(held),'same owned image before fixed removal')
 command(['/usr/bin/debugfs','-w','-R','rmdir /lost+found',image],60)
 after=listing('/');C.need(after=={n:r for n,r in before.items()if n!='lost+found'},'exact recovery removal readback; zero debugfs exit alone is insufficient')
 C.need(identity(image.lstat())==identity(held),'same owned image after fixed removal')
