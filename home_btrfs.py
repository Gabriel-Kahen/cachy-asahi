# SPDX-License-Identifier: MIT
"""Explicit HOME Btrfs capacity trial; no observation or syscall on import."""
import errno,os,platform,re,stat,time
from pathlib import Path,PurePosixPath
METHOD='READ_ONLY_HOME_BTRFS_ENOSYS_FSTATVFS'
FS=dict(root='/home/gabe',device=54,kernel_mount_device='0:33',fstype='btrfs',subvolume='/@home',subvolid=257)
QUERY=dict(syscall=443,command=0x80000700,uid=1000,result=-1,errno=38,status='UNSUPPORTED_NOT_UNLIMITED')
FIELDS={'issued_by','method','whole_actor','read_only','uid','device','filesystem','quota_query','inode_counters','output_node_cap','initial_inode_headroom','live_inode_headroom','other_quota_availability','capacity_reservation','outputs','source_lock','created_utc','expires_utc','on_unknown_or_exhausted'}

def need(ok,why):
 if not ok:raise ValueError(why)


def profile(q,resources,source=None,phase=None,output=None,now=None):
 need(type(q)is dict and set(q)==FIELDS,'closed explicit HOME Btrfs guard profile')
 need(q['issued_by']=='Root' and q['method']==METHOD and q['whole_actor']is q['read_only']is True and type(q['uid'])is type(q['device'])is int and q['uid']==resources['host_uid']==1000 and q['device']==resources['output_device']==54,'exact HOME Btrfs own-UID/device guard')
 need(q['filesystem']==FS and all(type(q['filesystem'][n])is int for n in('device','subvolid')) and q['quota_query']==QUERY and all(type(q['quota_query'][n])is int for n in('syscall','command','uid','result','errno')),'exact HOME mount and syscall443 ENOSYS declaration')
 need(q['inode_counters']=='ZERO_FILES_FFREE_FAVAIL_MEANS_UNREPORTED' and q['other_quota_availability']=='UNCLAIMED' and q['capacity_reservation']is False and q['on_unknown_or_exhausted']=='HOLD_AND_OWNED_CLEANUP','explicit unreported inode/no other quota/no reservation semantics')
 need(type(q['output_node_cap'])is int and q['output_node_cap']==150000 and type(q['initial_inode_headroom'])is type(q['live_inode_headroom'])is int and q['initial_inode_headroom']==16384 and q['live_inode_headroom']==4096,'fixed finite node and reported-inode bounds')
 need(type(q['source_lock'])is dict and set(q['source_lock'])=={'bytes','sha256'} and type(q['source_lock']['bytes'])is int and q['source_lock']['bytes']>0 and type(q['source_lock']['sha256'])is str and re.fullmatch('[0-9a-f]{64}',q['source_lock']['sha256']),'exact reviewed closed Source lock')
 need(type(q['outputs'])is dict and set(q['outputs'])=={'prepare','boot'} and q['outputs']['prepare']!=q['outputs']['boot'],'separate exact HOME phase outputs')
 for name in q['outputs'].values():
  need(type(name)is str and 0<len(name)<=4096 and name.startswith('/home/gabe/') and not any(ord(c)<32 or ord(c)==127 for c in name) and all(p not in('','.','..')for p in name[1:].split('/')),'literal ordinary HOME output descendant')
 need(type(q['created_utc'])is type(q['expires_utc'])is int and 0<q['created_utc']<q['expires_utc']<=q['created_utc']+3600,'finite Root HOME profile validity')
 if now is not None:need(type(now)is int and q['created_utc']<=now<q['expires_utc'],'fresh HOME capacity profile required')
 if source is not None:need(q['source_lock']==source,'HOME exact controller Source join')
 if phase is not None:need(phase in('prepare','boot') and q['outputs'][phase]==str(output),'HOME exact phase/output join')
 need(resources['quota_initial_headroom_bytes']is resources['quota_live_reserve_bytes']is None,'HOME unsupported quota has no invented quota headroom')
 return q


def open_directory(path):
 p=PurePosixPath(path);need(p.is_absolute() and all(n not in('','.','..')for n in str(p)[1:].split('/')),'literal directory path')
 flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC;fd=os.open('/',flags)
 try:
  for part in p.parts[1:]:
   child=os.open(part,flags,dir_fd=fd);os.close(fd);fd=child
  return fd
 except BaseException:os.close(fd);raise


def query_enosys(fd):
 # The only quota boundary; called only after accepted resource/authority/Source
 # gates and repeated exact HOME FD/profile checks. No dqblk values invented.
 import ctypes
 need(os.getuid()==os.geteuid()==1000 and platform.system()=='Linux' and platform.machine()=='x86_64' and ctypes.sizeof(ctypes.c_long)==ctypes.sizeof(ctypes.c_void_p)==8 and os.fstat(fd).st_dev==54,'reviewed own-UID Linux x86_64 syscall443 ABI')
 lib=ctypes.CDLL(None,use_errno=True);lib.syscall.restype=ctypes.c_long;buf=ctypes.create_string_buffer(72);ctypes.set_errno(0)
 result=lib.syscall(ctypes.c_long(443),ctypes.c_int(fd),ctypes.c_uint(0x80000700),ctypes.c_uint(1000),ctypes.byref(buf))
 return result,ctypes.get_errno()


def proc_read(path,cap):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  need(stat.S_ISREG(os.fstat(fd).st_mode),'ordinary kernel metadata');raw=bytearray()
  while block:=os.read(fd,min(65536,cap+1-len(raw))):
   raw.extend(block);need(len(raw)<=cap,'bounded kernel metadata')
  need(raw,'kernel metadata present');return raw.decode('utf-8','strict')
 finally:os.close(fd)


def mountinfo(body,mount_id):
 need(type(body)is str and 0<len(body.encode())<=1024**2 and type(mount_id)is int and mount_id>0,'bounded held-FD mount selection')
 entries={}
 def unescape(value):
  need(not re.search(r'\\(?!040|011|012|134)',value),'known mountinfo escape')
  return re.sub(r'\\(040|011|012|134)',lambda m:chr(int(m[1],8)),value)
 lines=body.splitlines();need(len(lines)<=16384,'mountinfo row bound')
 for line in lines:
  halves=line.split(' - ');need(len(halves)==2,'mountinfo separator');a,b=halves[0].split(),halves[1].split()
  need(len(a)>=6 and len(b)==3 and a[0].isdigit() and a[1].isdigit() and re.fullmatch('[0-9]+:[0-9]+',a[2]),'mountinfo shape');i=int(a[0]);need(0<i<=2**32-1 and i not in entries,'unique mount ID');entries[i]=(a,b)
 need(mount_id in entries,'held FD mount exists');a,b=entries[mount_id];mountpoint=PurePosixPath(unescape(a[4]))
 # fstat st_dev54 and kernel mountinfo0:33 are independently reviewed identity
 # domains. Never derive one from os.major/minor of the other.
 need(a[2]==FS['kernel_mount_device'] and b[0]=='btrfs' and unescape(a[3])=='/@home' and mountpoint.is_absolute() and (str(mountpoint)=='/home/gabe' or mountpoint in PurePosixPath('/home/gabe').parents),'held FD is on separately reviewed kernel Btrfs @home mount')
 options={}
 for item in b[2].split(','):
  if '='in item:
   k,v=item.split('=',1);need(k not in options,'unique mount super option');options[k]=v
 need(options.get('subvolid')=='257' and unescape(options.get('subvol',''))=='/@home','exact reviewed @home subvolume')
 return dict(mount_id=mount_id,device=54,kernel_mount_device=a[2],fstype='btrfs',subvolume='/@home',subvolid=257,mountpoint=str(mountpoint))


def mounted(fd):
 ids=[line.split(':',1)[1].strip()for line in proc_read('/proc/self/fdinfo/'+str(fd),4096).splitlines()if line.startswith('mnt_id:')]
 need(len(ids)==1 and ids[0].isdigit() and len(ids[0])<=10,'one bounded held-FD mount ID');return mountinfo(proc_read('/proc/self/mountinfo',1024**2),int(ids[0]))


def filesystem(fd):
 v=os.fstatvfs(fd);return {n:getattr(v,'f_'+n)for n in('blocks','bfree','bavail','frsize','files','ffree','favail')}


def capacity(fs,r,initial):
 need(type(fs)is dict and set(fs)=={'blocks','bfree','bavail','frsize','files','ffree','favail'} and all(type(v)is int and 0<=v<2**64 for v in fs.values()) and fs['frsize']>0 and fs['blocks']>0 and fs['bavail']<=fs['bfree']<=fs['blocks'],'finite consistent fstatvfs facts')
 counters=[fs[n]for n in('files','ffree','favail')];state='UNREPORTED'if counters==[0,0,0]else'REPORTED'
 if state=='REPORTED':need(fs['files']>0 and fs['favail']<=fs['ffree']<=fs['files'] and fs['favail']>=(16384 if initial else 4096),'finite reported filesystem inode headroom')
 need(fs['bavail']*fs['frsize']>=(r['physical_free_bytes']if initial else r['reserve_bytes']),'live HOME filesystem available byte reserve')
 return state


def sample(root,r,source,phase,initial,deadline,allocation,*,query=query_enosys,fs_query=filesystem,mount_query=mounted,opener=open_directory):
 need(source is not None and phase in('prepare','boot') and type(initial)is bool,'explicit HOME Source/phase/sampling mode')
 q=profile(r['quota_guard'],r,source,phase,root,int(time.time()));need(os.getuid()==os.geteuid()==1000,'actual ordinary HOME UID')
 fds=[]
 def guard():need(time.monotonic()<deadline,'HOME sampling deadline');profile(q,r,source,phase,root,int(time.time()))
 try:
  home=opener('/home/gabe');fds.append(home);out=opener(str(root));fds.append(out)
  home_st,out_st=os.fstat(home),os.fstat(out);need(home_st.st_dev==out_st.st_dev==54 and stat.S_ISDIR(out_st.st_mode) and out_st.st_uid==1000 and not out_st.st_mode&0o077,'private own-UID HOME output FD')
  mount=mount_query(home);need(mount_query(out)==mount,'HOME and output on same reviewed mount')
  guard();need(query(home)==(-1,errno.ENOSYS),'HOME Q_GETQUOTA must return exact ENOSYS38; other result/error HOLD');before=fs_query(home);state=capacity(before,r,initial)
  used=allocation(root,deadline=deadline);cap=sum(r[n]for n in('clone_allocated_cap_bytes','overlay_cap_bytes','readback_allocated_cap_bytes','logs_cap_bytes'));need(type(used)is int and 0<=used<=cap,'HOME finite simultaneous allocated-byte/node census')
  guard();need(query(home)==(-1,errno.ENOSYS),'HOME Q_GETQUOTA changed/unknown; HOLD');after=fs_query(home);need(capacity(after,r,initial)==state and after['frsize']==before['frsize'],'stable filesystem inode model/block units');need(mount_query(home)==mount_query(out)==mount,'stable reviewed HOME mount')
  current=Path(root).lstat();need((current.st_dev,current.st_ino,current.st_mode,current.st_uid,current.st_gid)==(out_st.st_dev,out_st.st_ino,out_st.st_mode,out_st.st_uid,out_st.st_gid),'same output inode/type/owner/mode after census');guard()
  return dict(status='PASS_FILESYSTEM_CAPACITY_ONLY',own_uid_quota='UNSUPPORTED_NOT_UNLIMITED',quota_errno=38,quota_syscall=443,other_quota_availability='UNCLAIMED',capacity_reservation=False,filesystem_inode_counters=state,filesystem_available_bytes=min(before['bavail']*before['frsize'],after['bavail']*after['frsize']),allocated_bytes=used,output_node_cap=150000,mount=mount)
 finally:
  for fd in reversed(fds):os.close(fd)
