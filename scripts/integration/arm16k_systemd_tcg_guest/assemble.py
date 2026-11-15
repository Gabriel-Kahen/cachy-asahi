#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline selected ALARM data assembly under fakeroot; never launch ARM code."""
import base64,hashlib,json,os,secrets,shutil,socket,stat,struct,subprocess,tarfile,time
from pathlib import Path,PurePosixPath

I=Path('/inputs');W=Path('/work');R=Path('/tmp/arm16k-systemd-root')
CAPABILITIES={'usr/bin/newuidmap':'0100000280000000000000000000000000000000',
              'usr/bin/newgidmap':'0100000240000000000000000000000000000000'}
JOURNAL_ACLS={'SCHILY.acl.access':'user::rwx,group::r-x,other::r-x,group:wheel:r-x:998,group:adm:r-x:999,mask::r-x',
              'SCHILY.acl.default':'user::rwx,group::r-x,group:wheel:r-x:998,group:adm:r-x:999,mask::r-x,other::r-x'}
# Linux POSIX ACL xattr v2, sorted numeric entries; names are never host-resolved.
JOURNAL_ACL_BYTES=struct.pack('<I',2)+b''.join(struct.pack('<HHI',tag,perms,ident)for tag,perms,ident in ((1,7,0xffffffff),(4,5,0xffffffff),(8,5,998),(8,5,999),(16,5,0xffffffff),(32,5,0xffffffff)))


def acl_entries(raw):
 if len(raw)!=52 or struct.unpack_from('<I',raw)[0]!=2:raise ValueError('POSIX ACL v2 layout differs')
 rows=[struct.unpack_from('<HHI',raw,offset)for offset in range(4,len(raw),8)]
 if [tag for tag,_,_ in rows]!=[1,4,8,8,16,32]:raise ValueError('POSIX ACL entry kinds differ')
 # ext4 stores IDs only for named entries; e2fsprogs exports ignored IDs as0.
 if any(perms>7 or(tag!=8 and ident not in (0,0xffffffff))for tag,perms,ident in rows):raise ValueError('POSIX ACL field differs')
 return [(tag,perms,ident if tag==8 else None)for tag,perms,ident in rows]


def digest(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()


def command(name,argv,timeout=120,input=None):
 with (W/(name+'.log')).open('wb')as f:
  result=subprocess.run(argv,input=input,stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
 assert result.returncode==0,(name,result.returncode)


def parents(path):
 current=R
 for part in PurePosixPath(path).parts[:-1]:
  current/=part
  if current.is_symlink():raise ValueError('guest path has symlink ancestor')
  current.mkdir(mode=0o755,exist_ok=True)
 return R/path


def capability(item,name):
 attrs={k:v for k,v in item.pax_headers.items()if 'xattr' in k or '.acl.'in k}
 if not attrs:return None
 keys={'LIBARCHIVE.xattr.security.capability','SCHILY.xattr.security.capability'}
 if set(attrs)!=keys or not item.isfile()or name not in CAPABILITIES:raise ValueError('unsupported archive xattr/ACL')
 # The exact signed rootfs redundantly stores raw and unpadded-base64 copies.
 raw=attrs['SCHILY.xattr.security.capability'].encode('utf-8','surrogateescape')
 encoded=attrs['LIBARCHIVE.xattr.security.capability'];decoded=base64.b64decode(encoded+'='*(-len(encoded)%4),validate=True)
 if raw.hex()!=CAPABILITIES[name]or decoded!=raw:raise ValueError('original capability copies differ')
 return raw


def extended_metadata(item,name):
 attrs={k:v for k,v in item.pax_headers.items()if 'xattr'in k or '.acl.'in k}
 if name=='var/log/journal'and attrs:
  if not item.isdir()or attrs!=JOURNAL_ACLS:raise ValueError('original journal ACL differs')
  return {'system.posix_acl_access':JOURNAL_ACL_BYTES,'system.posix_acl_default':JOURNAL_ACL_BYTES}
 raw=capability(item,name)
 return {}if raw is None else{'security.capability':raw}


def extract(selection):
 selected=set(selection['paths']);seen=set();attrs={};hard=[];xattrs={};total=0;deadline=time.monotonic()+240
 with tarfile.open(I/'rootfs.tar.gz','r|gz')as archive:
  for item in archive:
   assert time.monotonic()<deadline
   name=item.name.removeprefix('./').rstrip('/')
   if name not in selected:continue
   assert name not in seen and not name.startswith('/')and'..'not in PurePosixPath(name).parts
   seen.add(name);target=parents(name);attrs[name]=(item.uid,item.gid,item.mode,item.mtime)
   if item.isdir():target.mkdir(mode=0o755,exist_ok=True)
   elif item.isfile():
    assert item.size<=128*1024**2;total+=item.size;assert total<=1024**3
    with target.open('xb')as out:
     source=archive.extractfile(item);copied=0
     while block:=source.read(1024**2):out.write(block);copied+=len(block)
     assert copied==item.size
   elif item.issym():
    assert '\0'not in item.linkname
    target.symlink_to(item.linkname)
   elif item.islnk():hard.append((name,item.linkname.removeprefix('./')))
   else:raise ValueError('selected package contains unsupported special file')
   value=extended_metadata(item,name)
   if value:xattrs[name]=value
 for name,link in hard:
  assert link in selected and not Path(link).is_absolute()and'..'not in Path(link).parts
  source=parents(link);target=parents(name)
  assert source.exists()and not source.is_symlink()
  os.link(source,target,follow_symlinks=False)
 for name,(uid,gid,mode,mtime)in sorted(attrs.items(),key=lambda row:row[0].count('/'),reverse=True):
  path=R/name;os.chown(path,uid,gid,follow_symlinks=False)
  if not path.is_symlink():os.chmod(path,mode)
  os.utime(path,(mtime,mtime),follow_symlinks=False)
 assert set(xattrs)==set(CAPABILITIES)|{'var/log/journal'},'complete original extended metadata required'
 for name,values in xattrs.items():
  for key,value in values.items():os.setxattr(R/name,key,value,follow_symlinks=False)
 missing=selected-seen
 assert all((R/p).is_dir()for p in missing),'selected original payload not extracted'
 return {'original_nodes':len(seen),'logical_regular_bytes':total,'original_extended_metadata':{p:{k:v.hex()for k,v in values.items()}for p,values in xattrs.items()}}


def write(path,data,mode=0o644,uid=0,gid=0):
 target=parents(path)
 if target.is_symlink():target.unlink()
 target.write_text(data);target.chmod(mode);os.chown(target,uid,gid)


def symlink(path,target):
 p=parents(path)
 if p.is_symlink():p.unlink()
 assert not p.exists();p.symlink_to(target)


def main():
 assert __debug__ and os.environ.get('CACHY_ALLOW_ARM16K_PREPARE')=='1'and Path('/.dockerenv').is_file()
 assert os.environ.get('FAKEROOTKEY')and {v[1]for v in socket.if_nameindex()}=={'lo'}
 status=dict(l.split(':',1)for l in Path('/proc/self/status').read_text().splitlines()if ':'in l)
 assert all(int(status[k].strip(),16)==0 for k in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb'))and status['NoNewPrivs'].strip()=='1'
 assert not R.exists()and not any(W.iterdir());R.mkdir(mode=0o700)
 manifest=json.loads((I/'input-manifest.json').read_text());selection=json.loads((I/'selection.json').read_text())
 for name,ref in manifest['material_files'].items():
  p=I/name;assert p.is_file()and not p.is_symlink()and p.stat().st_size==ref['bytes']and digest(p)==ref['sha256']
 extracted=extract(selection);nonce=secrets.token_hex(16)
 for folder in ('dev','proc','sys','run','tmp','root','home/builder','etc/systemd/system/getty.target.wants','etc/systemd/system/sockets.target.wants','usr/local/libexec'):(R/folder).mkdir(parents=True,exist_ok=True)
 (R/'tmp').chmod(0o1777);(R/'root').chmod(0o700);(R/'home/builder').chmod(0o700);os.chown(R/'home/builder',1000,1000)
 passwd=(R/'etc/passwd').read_text().splitlines();legacy=[x for x in passwd if x.split(':')[2]=='1000'];assert len(legacy)==1 and legacy[0].startswith('alarm:')
 passwd=[x for x in passwd if x.split(':')[0]!='alarm'];passwd.append('builder:x:1000:1000:Emulated ARM16K TEST user:/home/builder:/usr/bin/bash')
 write('etc/passwd','\n'.join(passwd)+'\n')
 group=[]
 for line in (R/'etc/group').read_text().splitlines():
  fields=line.split(':');assert len(fields)==4
  if fields[2]=='1000':assert fields[0]=='alarm';continue
  fields[3]=','.join(x for x in fields[3].split(',')if x not in ('alarm','builder'));group.append(':'.join(fields))
 group.append('builder:x:1000:');write('etc/group','\n'.join(group)+'\n')
 password=secrets.token_urlsafe(24).encode()
 hashed=subprocess.run(['openssl','passwd','-6','-stdin'],input=password,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=10).stdout.decode().strip();assert hashed.startswith('$6$')
 shadow=[]
 for line in (R/'etc/shadow').read_text().splitlines():
  fields=line.split(':')
  if fields[0]=='alarm':continue
  if fields[0]=='root':fields[1]='!'
  shadow.append(':'.join(fields))
 shadow.append('builder:'+hashed+':20771:0:99999:7:::');write('etc/shadow','\n'.join(shadow)+'\n',0o600)
 write('etc/hostname','arm16k-systemd-reference\n');write('etc/hosts','127.0.0.1 localhost arm16k-systemd-reference\n::1 localhost\n')
 write('etc/resolv.conf','# Offline emulated fixture: no NIC.\n');write('etc/machine-id',nonce+'\n');write('etc/locale.conf','LANG=C.UTF-8\n')
 write('etc/arm16k-systemd-nonce',nonce+'\n')
 write('home/builder/.bash_profile',"printf '\\nARM16K_SHELL_READY "+nonce+"\\n'\nPS1='arm16k$ '\n",uid=1000,gid=1000)
 write('etc/fstab','/dev/vda / ext4 defaults 0 1\n')
 symlink('etc/systemd/system/default.target','/usr/lib/systemd/system/multi-user.target')
 symlink('etc/systemd/system/getty.target.wants/serial-getty@ttyAMA0.service','/usr/lib/systemd/system/serial-getty@.service')
 symlink('etc/systemd/system/sockets.target.wants/dbus.socket','/usr/lib/systemd/system/dbus.socket')
 write('usr/local/libexec/arm16k-login-proof',Path('/opt/arm16k/guest-proof.sh').read_text(),0o755)
 credentials=W/'credentials.json';credentials.write_text(json.dumps({'username':'builder','password':password.decode()},indent=2)+'\n');credentials.chmod(0o600)
 required=('usr/lib/systemd/systemd','usr/lib/systemd/systemd-logind','usr/bin/login','usr/bin/agetty','usr/bin/bash','usr/bin/pacman','etc/pam.d/login','etc/pam.d/system-login')
 for name in required:
  path=R/name;assert path.is_file()
  if name.startswith('usr/'):
   with path.open('rb')as f:head=f.read(20)
   assert head[:6]==b'\x7fELF\x02\x01'and int.from_bytes(head[18:20],'little')==183
 image=W/'guest.raw'
 R.chmod(0o755);os.chown(R,0,0)
 with image.open('xb')as f:f.truncate(1536*1024**2)
 command('ext4-build',['mkfs.ext4','-F','-L','ARM16K_SYSTEMD','-U',nonce[:8]+'-'+nonce[8:12]+'-'+nonce[12:16]+'-'+nonce[16:20]+'-'+nonce[20:],'-d',str(R),str(image)],180)
 command('ext4-readonly-check',['e2fsck','-fn',str(image)])
 command('guest-home-ownership',['debugfs','-R','stat /home/builder',str(image)])
 ownership=(W/'guest-home-ownership.log').read_text();assert 'User:  1000'in ownership and'Group:  1000'in ownership
 observed_xattrs={}
 for name,values in extracted['original_extended_metadata'].items():
  observed_xattrs[name]={}
  for key,expected in values.items():
   label=Path(name).name+'-'+key;output=W/(label+'.xattr')
   command(label+'-image-xattr',['debugfs','-R','ea_get -f '+str(output)+' /'+name+' '+key,str(image)])
   actual=output.read_bytes();observed_xattrs[name][key]=actual.hex()
   if key.startswith('system.posix_acl_'):assert acl_entries(actual)==acl_entries(bytes.fromhex(expected)),'ext4 ACL semantics differ'
   else:assert actual.hex()==expected,'ext4 capability differs; no silent metadata loss'
 shutil.copyfile(I/'Image',W/'Image');shutil.copyfile(I/'kernel.config',W/'kernel.config')
 report={'schema_version':1,'status':'PREPARED_NOT_BOOTED','VM_boot':'NOT RUN','native16K':'NOT RUN','M2':'NOT RUN',
  'scope':'emulated aarch64/16K stock systemd login reference only','nonce':nonce,'kernel_version':'7.1.13-generic16k-managed-gui',
  'guest_user':'builder','guest_user_uid':1000,'original_alarm_account':'replaced in fixture only; no wheel grant; root locked',
  'base_packages':[{k:p[k]for k in ('name','version','directory','inherited_validation')}for p in selection['packages']],
  'guest_package_registration':selection['package_registration'],'extraction':extracted,'ext4_extended_metadata':observed_xattrs,'ACL_encoding_note':'e2fsprogs exports ignored non-named IDs as0; named IDs/permissions/tags verified exactly','provenance':manifest,
  'disk_logical_bytes':image.stat().st_size,'disk_allocated_bytes':image.stat().st_blocks*512,
  'files':{p.name:{'bytes':p.stat().st_size,'sha256':digest(p)}for p in (image,W/'Image',W/'kernel.config')},
  'guest_required_pins':{p:digest(R/p)for p in required},'source_legal_release':'HOLD/NOT RUN'}
 (W/'prepared.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
 for p in W.iterdir():
  if p.is_file():p.chmod(0o600)
 shutil.rmtree(R)
 print(json.dumps({'status':report['status'],'files':report['files'],'VM_boot':'NOT RUN'}),flush=True)


if __name__=='__main__':main()
