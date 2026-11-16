# SPDX-License-Identifier: MIT
"""Reader5-only storage admission; Btrfs unreported inode counts need Root proof."""
import hashlib,math,os,re,stat,time
from pathlib import Path
GIB=1024**3
IDENTITY=dict(bytes=372,sha256='cae374f1b05465b53e2f2d1efb6dc9171d30756e67fbdb5a84549bc7e6d60781')

def need(ok,why):
 if not ok:raise ValueError(why)

def mount(line):
 left,sep,right=line.partition(' - ');a,b=left.split(),right.split();need(sep and len(a)>=6 and len(b)==3,'complete kernel mountinfo row')
 return dict(id=int(a[0]),device=a[2],root=a[3],target=a[4],flags=a[5].split(','),fstype=b[0],super_options=b[2].split(','))

def validate(profile,identity,parent,uid,live,now):
 need(profile['kind']=='ROOT_REVIEWED_LLVM_READER5_BTRFS_STORAGE_V1'and profile['issued_by']=='Root'and profile['accepted']is True,'separate Root-reviewed Btrfs storage profile')
 stamp=profile['observed_epoch'];need(type(stamp)in(int,float)and math.isfinite(stamp)and 0<=now-stamp<=120,'fresh genuine storage observation')
 need(profile['output_parent']==str(parent)and type(profile['uid'])is int and profile['uid']==uid==1000 and profile['inode_accounting']=='UNREPORTED_ALL_ZERO'and profile['reservation']is False,'exact output/UID/unreported inode semantics; no reservation')
 need(identity['issued_by']=='Root'and identity['query_root']=='/home/gabe'and identity['identity_domains_distinct']is True and identity['fstat_device']==54 and identity['kernel_mount_device']=='0:33'and identity['mount_id']==62,'whole independently pinned Root identity domains')
 expected=mount(identity['mountinfo']);actual=mount(live['mountinfo'])
 for row in(expected,actual):need(row['id']==62 and row['device']=='0:33'and row['root']=='/@home'and row['target']=='/home'and row['fstype']=='btrfs'and 'rw'in row['flags']and 'ro'not in row['flags']and {'subvolid=257','subvol=/@home'}<=set(row['super_options']),'exact reviewed Btrfs HOME/subvolume domain')
 need(parent.is_relative_to('/home/gabe')and type(live['fd_device'])is type(live['fd_mount_id'])is int and live['fd_device']==54 and live['fd_mount_id']==62 and live['fd_path_stable']is True,'actual held FD/path/device/mount join, domains never numerically conflated')
 need(all(type(live[k])is int and live[k]>=0 for k in('available_bytes','files','ffree','favail'))and live['files']==live['ffree']==live['favail']==0,'all-zero inode counters unreported, not a low-capacity waiver')
 need(live['available_bytes']>=20*GIB,'unchanged20GiB Reader byte reserve')
 return dict(mode='ROOT_REVIEWED_BTRFS_UNREPORTED_INODES',available_bytes=live['available_bytes'],inode_accounting='UNREPORTED',fstat_device=54,kernel_mount_device='0:33',mount_id=62,reservation=False,quota_claim=None)

def check(parent,reference,v):
 parent=v.path(parent)
 if reference is None:
  fs=os.statvfs(parent);need(fs.f_bavail*fs.f_frsize>=20*GIB and fs.f_favail>=10000,'strict Reader bytes/reported inode reserve');return dict(mode='STRICT_REPORTED_INODES',reservation=False)
 need(set(reference)=={'path','bytes','sha256'}and type(reference['bytes'])is int and 0<reference['bytes']<=16384,'whole external Root storage profile')
 raw=v.read(v.path(reference['path']),16384);need(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())=={k:reference[k]for k in('bytes','sha256')},'external storage profile whole pin');profile=v.decode(raw)
 row=profile['mount_identity'];need(set(row)=={'path','bytes','sha256'}and {k:row[k]for k in('bytes','sha256')}==IDENTITY,'exact independently Root-observed mount identity pin')
 data=v.read(v.path(row['path']),16384);need(dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())==IDENTITY,'mount identity unchanged');identity=v.decode(data)
 fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid)
  before=os.fstat(fd);need(stat.S_ISDIR(before.st_mode)and before.st_uid==1000 and not stat.S_IMODE(before.st_mode)&0o022 and key(before)==key(parent.stat()),'owned stable directory FD')
  with Path('/proc/self/fdinfo/'+str(fd)).open('rb')as stream:info=stream.read(4097)
  need(len(info)<=4096,'bounded complete current fdinfo');info=info.decode();m=re.findall(r'^mnt_id:\s*([0-9]+)$',info,re.M);need(len(m)==1,'one actual FD mount identity')
  with Path('/proc/self/mountinfo').open('rb')as stream:table=stream.read(1024**2+1)
  need(len(table)<=1024**2,'bounded complete current mountinfo');matches=[line for line in table.decode().splitlines()if line.split(' ',1)[0]==m[0]];need(len(matches)==1,'one matching current kernel mountinfo row')
  fs=os.fstatvfs(fd);live=dict(fd_device=before.st_dev,fd_mount_id=int(m[0]),fd_path_stable=key(before)==key(os.fstat(fd))==key(parent.stat()),mountinfo=matches[0],available_bytes=fs.f_bavail*fs.f_frsize,files=fs.f_files,ffree=fs.f_ffree,favail=fs.f_favail)
  return validate(profile,identity,parent,os.getuid(),live,time.time())
 finally:os.close(fd)
