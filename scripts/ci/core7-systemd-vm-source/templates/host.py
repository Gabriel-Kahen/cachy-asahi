# SPDX-License-Identifier: MIT
"""Two source-bound natural QEMU exits, on the same exact owned disk inodes."""
import fcntl,hashlib,json,os,re,stat,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import case as C

def qemu(image,boot,data,nonce,phase):
 C.need(re.fullmatch('[a-f0-9]{32}',nonce or'')and phase in(1,2),'finite QEMU argv')
 return ['/usr/bin/qemu-system-aarch64','-nodefaults','-machine','virt','-accel','tcg,thread=multi','-cpu','max','-smp','2','-m','4096','-nic','none','-display','none','-monitor','none','-no-reboot','-kernel',str(image),'-append','console=ttyAMA0 root=/dev/vda rw rootwait init=/init-core7 arm64.nomops caa_core_vm='+nonce+' caa_core_phase='+str(phase),'-drive','if=none,id=boot,format=raw,file='+str(boot),'-device','virtio-blk-pci,drive=boot,serial=core7-'+nonce,'-drive','if=none,id=data,format=raw,file='+str(data),'-device','virtio-blk-pci,drive=data,serial=core7-data-'+nonce,'-serial','stdio']

def disk(path,size):
 path=Path(path);C.need(not any(p.is_symlink()for p in(path,*path.parents)),'ordinary owned disk path');st=path.lstat();C.need(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and st.st_uid==os.getuid()and stat.S_IMODE(st.st_mode)&0o022==0 and st.st_size==size,'exact owned fixed disk')
 with path.open('rb')as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
 after=path.lstat();C.need(C.identity(st)==C.identity(after),'whole image hash stable');return dict(identity=[st.st_dev,st.st_ino,st.st_uid,st.st_size],bytes=size,sha256=digest)

def two_boots(selected,media,image,output,runtime,expected):
 C.selection(selected);media=Path(media);output=Path(output);C.need(not output.exists()and output.parent.is_dir(),'fresh explicit boot output')
 lease=C.decode(C.read(media/'core-media.json'));C.need(lease['status']=='PREPARED_CORE7_REAL_SYSTEMD_MEDIA_NOT_BOOTED'and lease['nonce']==selected['nonce']and lease['budgets']==C.BUDGET,'same-nonce full prepared media')
 before={n:disk(media/n,size)for n,size in(('boot.raw',16*1024**3),('data.raw',24*1024**3))}
 C.need(all({k:r[k]for k in('bytes','sha256')}==lease['files'][n]for n,r in before.items()),'whole sealed image bytes before first boot')
 fds=[];output.mkdir(mode=0o700);rows=[];end=time.monotonic()+C.BUDGET['vm_shared']
 try:
  for name in before:
   fd=os.open(media/name,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);fds.append(fd)
  for phase in(1,2):
   C.need(time.monotonic()<end,'explicit new shared7200 envelope')
   argv=qemu(image,media/'boot.raw',media/'data.raw',selected['nonce'],phase)
   row,out,err,error=runtime.run_command(argv,output,dict(PATH='/usr/bin:/bin',HOME=str(output),LANG='C'),min(C.BUDGET['boot'],end-time.monotonic()),1024**2)
   for suffix,raw in(('stdout',out),('stderr',err),('json',C.encoded(row))):(output/('boot-'+str(phase)+'.'+suffix)).write_bytes(raw)
   C.command(row,C.BUDGET['boot']);C.need(error is None,'natural owned QEMU exit, no timeout/forced retirement')
   value=C.protocol(out,selected,phase,expected);after={n:disk(media/n,r['bytes'])for n,r in before.items()};C.need(all(after[n]['identity']==before[n]['identity']for n in before),'same original owned media inodes on both boots')
   record=dict(phase=phase,qemu=row,result=value,media_before=before,media_after=after);rows.append(record);(output/'boots.json').write_bytes(C.encoded(rows));before=after
   if phase==2:
    C.need(rows[0]['result']['pid1']['root']==value['pid1']['root']and rows[0]['result']['pid1']['boot_id']!=value['pid1']['boot_id'],'same persistent root, genuinely distinct second kernel boot')
    C.need(value['previous']==C.pin(C.encoded(rows[0]['result']['custody'])),'second boot opens exact first boot source-owned custody')
 finally:
  for fd in reversed(fds):os.close(fd)
 return dict(status='PASS_TWO_ACTUAL_SYSTEMD_BOOTS_PENDING_MEDIA_PRODUCER_RETIREMENT',boots=rows,hardware='NOT_RUN',Asahi='NOT_RUN',release='NOT_ADMITTED')
